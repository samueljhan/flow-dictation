// Claude via the Anthropic FIRST-PARTY API for Flow Dictation. Mirrors
// gemini.js's generate() contract — same inputs (Gemini-shaped contents),
// same outputs ({text, usage, finishReason, served}) — so the server's call
// layer routes by model prefix without caring which provider answers.
//
// THE CONTRACT THIS CLIENT ENFORCES: Claude is outside the GCP BAA boundary,
// so it must NEVER receive PHI, dates, or any report section beyond findings,
// impression, and the study type. The server's pipeline extracts those
// sections and reversibly redacts identifiers BEFORE calling here; this
// module is the last line of defense, not the pipeline:
//   1. Callers must pass deidentified: true — set only by the redaction
//      pipeline (and the selftest). Any other call path throws.
//   2. Every user-message text is scanned before sending: a non-findings
//      section heading (EXAMINATION, CLINICAL HISTORY, TECHNIQUE, COMPARISON,
//      ...) or anything the scrub patterns still match (dates, MRNs, phones)
//      means redaction was skipped or failed — the call throws PHI_GUARD and
//      the caller falls back to Gemini, which the BAA covers.
// System prompts are exempt from the heading check (exemplar reports
// legitimately show report structure; the server pattern-scrubs them), but
// not from the identifier-pattern check.
//
// Auth: ANTHROPIC_API_KEY (Secret Manager in production, injected as an env
// var). No Google credentials involved.
const Anthropic = require('@anthropic-ai/sdk');
const scrub = require('./scrub');

const configured = !!process.env.ANTHROPIC_API_KEY;
const client = configured ? new Anthropic() : null;

// Report sections that must never reach Claude. FINDINGS/IMPRESSION are
// absent on purpose — they are the two sections the pipeline sends. The
// colon is required so heading-like prose at a line start ("Comparison with
// prior shows...") doesn't trip the guard — real headings take "WORD:" form.
const FORBIDDEN_HEADINGS = /^[ \t]*(?:\*\*)?[ \t]*(EXAMINATION|EXAM|CLINICAL HISTORY|CLINICAL INDICATION|INDICATION|HISTORY|TECHNIQUE|COMPARISON|PROCEDURE|PATIENT|DOB|MRN|ACCESSION)[ \t]*(?:\*\*)?[ \t]*:/im;

function guardError(detail) {
  const err = new Error(`De-identification guard refused this Claude call (${detail}) — falling back is the caller's job`);
  err.code = 'PHI_GUARD';
  return err;
}

// Throws unless the text is plausibly de-identified. checkHeadings is off for
// system prompts (see above).
function assertDeidentified(text, { checkHeadings }) {
  if (typeof text !== 'string' || !text) return;
  if (checkHeadings && FORBIDDEN_HEADINGS.test(text)) {
    throw guardError('payload contains a report section outside findings/impression');
  }
  const counts = scrub.patternScrub(text).counts;
  const types = Object.keys(counts);
  if (types.length) {
    // Types only — never the matched text
    throw guardError(`identifier patterns still present: ${types.join(', ')}`);
  }
}

function refusal(detail) {
  const err = new Error('This request was declined by the model’s safety filters. Try rephrasing it.');
  err.isRefusal = true;
  err.detail = detail;
  return err;
}

// Effort is the same latency lever as on Gemini, expressed Claude's way:
// adaptive thinking + output_config.effort. Thinking is never disabled —
// disabling it on opus-5 has known failure modes (tool-call text leakage);
// 'low' effort is the sanctioned cheap/fast setting. opus-5 runs adaptive by
// default when `thinking` is omitted; sonnet-4-6 needs it set explicitly.
function requestConfig(model, effort) {
  const cfg = {};
  if (!/opus-5/.test(model)) cfg.thinking = { type: 'adaptive' };
  if (effort === 'low' || effort === 'medium' || effort === 'high') {
    cfg.output_config = { effort };
  }
  return cfg;
}

// Gemini finish reasons are the server's lingua franca ('STOP', 'MAX_TOKENS');
// map Claude's stop reasons onto them so downstream checks work unchanged.
function toFinishReason(stopReason) {
  switch (stopReason) {
    case 'end_turn':
    case 'stop_sequence': return 'STOP';
    case 'max_tokens': return 'MAX_TOKENS';
    default: return String(stopReason || 'STOP').toUpperCase();
  }
}

/**
 * One Claude call, gemini.generate-shaped.
 *   model          claude-* id (bare first-party id)
 *   system         system instruction text (string)
 *   contents       Gemini-shaped [{role:'user'|'model', parts:[{text}]}]
 *   maxTokens      output ceiling hint — floored at 16000 (see below)
 *   effort         'low' | 'medium' | 'high' | undefined
 *   deidentified   REQUIRED true — only the redaction pipeline sets it
 *   responseSchema ACCEPTED BUT UNUSED: Claude paths rely on prompt-for-JSON
 *                  + fence-strip + the server's substring validation (the
 *                  real guarantee)
 *   grounding      not supported — grounded search is Gemini-only; the server
 *                  routes grounded calls to Gemini before here
 * Returns { text, usage, finishReason, served, grounding: null }.
 * Throws PHI_GUARD when the payload fails the de-identification checks,
 * and an error with isRefusal=true when Claude declines.
 */
async function generate({ model, system, contents, maxTokens, effort, deidentified }) {
  if (!configured) throw new Error('ANTHROPIC_API_KEY is not set — Claude routing unavailable');
  if (deidentified !== true) {
    throw guardError('caller did not assert a de-identified payload');
  }
  const messages = (contents || []).map(c => ({
    role: c.role === 'model' ? 'assistant' : 'user',
    content: (c.parts || []).map(p => p.text).join('')
  }));
  // Claude requires the first message to be 'user'
  while (messages.length && messages[0].role !== 'user') messages.shift();

  for (const m of messages) assertDeidentified(m.content, { checkHeadings: true });
  assertDeidentified(system, { checkHeadings: false });

  const r = await client.messages.create({
    model,
    // Thinking tokens count toward max_tokens on Claude (unlike Gemini's
    // separate budget), so the Gemini-sized ceilings would truncate mid-answer.
    // max_tokens is a cap, not spend — floor it well clear of any real output.
    max_tokens: Math.max(maxTokens || 0, 16000),
    // cache_control restores prompt caching for the static knowledge-layer
    // block: the composed system prompt is byte-stable per action + study type
    // (memoised server-side), so caching the whole block as the prefix works.
    // 5m ephemeral TTL; cache writes bill at 1.25x and reads at 0.1x input.
    ...(system ? { system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }] } : {}),
    messages,
    ...requestConfig(model, effort)
  });

  if (r.stop_reason === 'refusal') {
    throw refusal(`stop_reason refusal${r.stop_details && r.stop_details.category ? `: ${r.stop_details.category}` : ''}`);
  }
  const text = (r.content || [])
    .filter(b => b.type === 'text' && typeof b.text === 'string')
    .map(b => b.text)
    .join('');

  const u = r.usage || {};
  const cacheRead = u.cache_read_input_tokens || 0;
  const cacheWrite = u.cache_creation_input_tokens || 0;
  return {
    text,
    finishReason: toFinishReason(r.stop_reason),
    served: r.model || model,
    usage: {
      // prompt_tokens is the TOTAL prompt (cached portions included), matching
      // Gemini's promptTokenCount semantics — the cost layer rebates from it.
      prompt_tokens: (u.input_tokens || 0) + cacheRead + cacheWrite,
      cached_tokens: cacheRead,
      cache_write_tokens: cacheWrite,
      // Claude's output_tokens already include thinking — no separate figure
      output_tokens: u.output_tokens || 0,
      thought_tokens: 0,
      tool_prompt_tokens: 0
    },
    grounding: null
  };
}

module.exports = { generate, configured };
