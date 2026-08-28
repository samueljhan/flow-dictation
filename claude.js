// Claude on Vertex AI (Anthropic partner models) for Flow Dictation. Mirrors
// gemini.js's generate() contract exactly — same inputs (Gemini-shaped
// contents), same outputs ({text, usage, finishReason, served}) — so the
// server's call layer can route by model prefix without caring which provider
// answers. The Gemini client stays fully intact; this is additive.
//
// Auth is Application Default Credentials only, like gemini.js: the Cloud Run
// service account in production, `gcloud auth application-default login`
// locally. No Anthropic API keys anywhere — the AnthropicVertex client nulls
// them out by design and authenticates with Google OAuth.
//
// Region: the current Claude generation (opus-5, sonnet-4-6) serves from the
// GLOBAL Vertex endpoint only — regional endpoints (us-east5 etc.) 404 on
// these ids. Vertex region is independent of the Cloud Run/SQL region
// (us-east1), so this changes nothing about where the app runs.
const { AnthropicVertex } = require('@anthropic-ai/vertex-sdk');

const PROJECT = process.env.GOOGLE_CLOUD_PROJECT || process.env.VERTEX_PROJECT || '';
const REGION = process.env.VERTEX_CLAUDE_REGION || 'global';

const client = new AnthropicVertex({ projectId: PROJECT, region: REGION });

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

function refusal(detail) {
  const err = new Error('This request was declined by the model’s safety filters. Try rephrasing it.');
  err.isRefusal = true;
  err.detail = detail;
  return err;
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
 *   model          bare Vertex Claude id (e.g. claude-opus-5)
 *   system         system instruction text (string)
 *   contents       Gemini-shaped [{role:'user'|'model', parts:[{text}]}]
 *   maxTokens      output ceiling hint — floored at 16000 (see below)
 *   effort         'low' | 'medium' | 'high' | undefined
 *   responseSchema ACCEPTED BUT UNUSED: Claude paths rely on prompt-for-JSON
 *                  + fence-strip + the server's substring validation (the
 *                  real guarantee), per the routing design
 *   grounding      not supported — Google Search grounding is Gemini-only;
 *                  the server routes grounded calls to Gemini before here
 * Returns { text, usage, finishReason, served, grounding: null }.
 * Throws an error with isRefusal=true when Claude declines (stop 'refusal').
 */
async function generate({ model, system, contents, maxTokens, effort }) {
  const messages = (contents || []).map(c => ({
    role: c.role === 'model' ? 'assistant' : 'user',
    content: (c.parts || []).map(p => p.text).join('')
  }));
  // Claude requires the first message to be 'user'; the token-budgeted history
  // window can open on an assistant turn — drop leaders rather than fail.
  while (messages.length && messages[0].role !== 'user') messages.shift();

  const r = await client.messages.create({
    model,
    // Thinking tokens count toward max_tokens on Claude (unlike Gemini's
    // separate budget), so the Gemini-sized ceilings would truncate mid-answer.
    // max_tokens is a cap, not spend — floor it well clear of any real output.
    max_tokens: Math.max(maxTokens || 0, 16000),
    // cache_control restores prompt caching for the static knowledge-layer
    // block: the composed system prompt is byte-stable per action + study type
    // (memoised server-side), so caching the whole block as the prefix works.
    // 5m ephemeral TTL; Vertex bills writes at 1.25x and reads at 0.1x input.
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

module.exports = { generate, PROJECT, REGION };
