const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

app.set('trust proxy', 1); // Railway terminates TLS upstream
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

// Claude API configuration — models are env-configurable
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
// Detection is a trivial classification that runs on nearly every action —
// Haiku handles it at ~1/10 the price of the frontier models.
// Every task routes independently so any one can be A/B'd from a Railway
// variable without touching code. Deliberately NO cross-inheritance: setting
// MODEL_REPORT must not silently drag review or impression along with it.
const MODEL_DETECT = process.env.MODEL_DETECT || 'claude-haiku-4-5';      // study-type classification
const MODEL_REPORT = process.env.MODEL_REPORT || 'claude-sonnet-4-6';     // proofread · reword · describe · full report structure
const MODEL_REVIEW = process.env.MODEL_REVIEW || 'claude-opus-5';         // draft review + integrate-notes
const MODEL_IMPRESSION = process.env.MODEL_IMPRESSION || 'claude-opus-5'; // Generate Impression + the full report's impression
// Quick Rad Question is the most token-heavy path — a single search puts ~14k
// tokens of results in context — so the per-token rate is what decides its
// cost, not the tool or the search budget. Measured on one question: identical
// searches cost $0.21 on Fable and $0.11 on Opus 5.
const MODEL_RADQA = process.env.MODEL_RADQA || 'claude-opus-5';          // Quick Rad Question (references on)
const MODEL_CHAT = process.env.MODEL_CHAT || 'claude-opus-5';            // plain free text (no references)
const MODEL_SYNTHESIZE = process.env.MODEL_SYNTHESIZE || 'claude-opus-5'; // prior report + new info → merged report
// Used on every path when safety classifiers decline a benign radiology request
const MODEL_FALLBACK = process.env.MODEL_FALLBACK || 'claude-opus-4-8';

// Supabase (server-side only — service role key, never sent to the browser)
const supabase = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false }
    })
  : null;

function requireSupabase(res) {
  if (!supabase) {
    res.status(503).json({ error: 'Supabase not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.' });
    return false;
  }
  return true;
}

// Gmail OAuth configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.NODE_ENV === 'production'
    ? 'https://flowdictation.com/auth/google/callback'
    : 'http://localhost:8080/auth/google/callback'
);

// Simple in-memory token storage (for single user)
let userTokens = null;

// ============ Authentication (single-user) ============
// Two ways in: Google sign-in restricted to an email allowlist, or a shared
// password. Everything except the login routes and /api/health is gated.

const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || 'samueljhan@gmail.com')
  .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const APP_PASSWORD = process.env.APP_PASSWORD || '';
// Username for password sign-in; defaults to the first allowed email
const APP_USERNAME = (process.env.APP_USERNAME || ALLOWED_EMAILS[0] || '').toLowerCase();
// Sessions survive restarts only if this is set explicitly.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('⚠ SESSION_SECRET not set — sessions will be invalidated on every restart/redeploy.');
}
const SESSION_DAYS = 30;
const COOKIE_NAME = 'fd_session';
const googleLoginConfigured = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

function hmac(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function makeSession(subject) {
  const payload = `${subject}|${Date.now() + SESSION_DAYS * 86400000}`;
  return Buffer.from(payload).toString('base64url') + '.' + hmac(payload);
}

function readSession(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  let payload;
  try { payload = Buffer.from(body, 'base64url').toString(); } catch { return null; }
  const expected = hmac(payload);
  // Constant-time compare; lengths must match first or timingSafeEqual throws
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const [subject, expiry] = payload.split('|');
  if (!subject || !expiry || Number(expiry) < Date.now()) return null;
  return subject;
}

function getCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return decodeURIComponent(part.slice(idx + 1));
  }
  return null;
}

function setSessionCookie(res, subject) {
  res.cookie(COOKIE_NAME, makeSession(subject), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_DAYS * 86400000
  });
}

const PUBLIC_PATHS = new Set(['/login', '/auth/login/google', '/auth/password', '/auth/logout', '/api/health']);

app.use((req, res, next) => {
  if (PUBLIC_PATHS.has(req.path) || req.path === '/auth/google/callback') return next();
  const subject = readSession(getCookie(req, COOKIE_NAME));
  if (subject) {
    req.user = subject;
    return next();
  }
  // API calls get JSON so the frontend can react; page loads get the login screen
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not signed in', login_required: true });
  }
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (readSession(getCookie(req, COOKIE_NAME))) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Google sign-in — reuses the already-registered callback URL, distinguished by `state`
app.get('/auth/login/google', (req, res) => {
  if (!googleLoginConfigured) return res.redirect('/login?error=google_unconfigured');
  const url = oauth2Client.generateAuthUrl({
    scope: ['openid', 'email'],
    state: 'login',
    prompt: 'select_account'
  });
  res.redirect(url);
});

// Compare via fixed-length digests so length differences don't leak and
// timingSafeEqual never throws on mismatched buffer sizes.
function secretMatches(supplied, expected) {
  const a = crypto.createHash('sha256').update(String(supplied)).digest();
  const b = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

app.post('/auth/password', (req, res) => {
  if (!APP_PASSWORD) return res.redirect('/login?error=password_unconfigured');
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  // Always evaluate both so a wrong username costs the same as a wrong password
  const okUser = secretMatches(username, APP_USERNAME);
  const okPass = secretMatches(password, APP_PASSWORD);
  if (!okUser || !okPass) return res.redirect('/login?error=bad_credentials');
  setSessionCookie(res, APP_USERNAME || 'password-user');
  res.redirect('/');
});

app.get('/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/login');
});

app.get('/api/me', (req, res) => res.json({ user: req.user }));

// Static files are served only after the auth gate above
app.use(express.static('public'));

console.log('=== Environment Check ===');
console.log('Anthropic:', !!process.env.ANTHROPIC_API_KEY ? '✓' : '✗');
console.log('Supabase:', !!supabase ? '✓' : '✗');
console.log('Google Client ID:', !!process.env.GOOGLE_CLIENT_ID ? '✓' : '✗');
console.log('Google Client Secret:', !!process.env.GOOGLE_CLIENT_SECRET ? '✓' : '✗');
console.log('Models:');
console.log(`  detect=${MODEL_DETECT} report=${MODEL_REPORT} review=${MODEL_REVIEW} impression=${MODEL_IMPRESSION} radqa=${MODEL_RADQA}`);
console.log(`  synthesize=${MODEL_SYNTHESIZE} chat=${MODEL_CHAT} fallback=${MODEL_FALLBACK}`);
console.log('========================');

// ============ Claude helpers ============

// Only the Fable/Opus-5 tier accepts the server-side `fallbacks` parameter;
// Haiku and Sonnet reject it with a 400. Those models also don't exhibit the
// classifier refusals fallbacks exist to rescue.
const FALLBACK_CAPABLE = /fable|mythos|opus-5/i;

// output_config.effort is the latency lever: low/medium for mechanical tasks,
// default (high) for complex ones. Haiku 4.5 rejects the parameter.
const EFFORT_CAPABLE = /fable|mythos|opus|sonnet-5|sonnet-4-6/i;

// ============ Cost accounting ============

// US list price per million tokens. Longest-prefix matched against the model
// the API says served the request, so a dated snapshot or a transparent
// fallback swap still prices correctly.
const PRICING = {
  'claude-opus-5':     { input: 5,  output: 25 },
  'claude-opus-4-8':   { input: 5,  output: 25 },
  'claude-opus-4-7':   { input: 5,  output: 25 },
  'claude-sonnet-5':   { input: 3,  output: 15 },
  'claude-sonnet-4-6': { input: 3,  output: 15 },
  'claude-haiku-4-5':  { input: 1,  output: 5 },
  'claude-fable-5':    { input: 10, output: 50 }
};
// Cache writes are 1.25x input at the 5-minute TTL but 2x at the 1-hour TTL,
// and every cached block here is written with ttl:'1h' (see CACHE_1H). Using
// 1.25 would quietly understate the cost of exactly the blocks we cache.
const CACHE_WRITE_MULTIPLIER = 2.0;
const CACHE_READ_MULTIPLIER = 0.1;

const unpricedModels = new Set();
function priceFor(model) {
  const id = String(model || '');
  let best = null;
  for (const key of Object.keys(PRICING)) {
    if (id.startsWith(key) && (!best || key.length > best.length)) best = key;
  }
  if (!best) {
    if (id && !unpricedModels.has(id)) {
      unpricedModels.add(id);
      console.warn(`⚠ [cost] no price for "${id}" — est_cost will read 0 for it. Add it to PRICING.`);
    }
    return null;
  }
  return PRICING[best];
}

// Dollars for one call, from the usage block the API returns.
function costFor(model, u) {
  const p = priceFor(model);
  if (!p) return 0;
  const inTok = u.input_tokens || 0;
  const write = u.cache_creation_input_tokens || 0;
  const read = u.cache_read_input_tokens || 0;
  const out = u.output_tokens || 0;
  return (
    inTok * p.input +
    write * p.input * CACHE_WRITE_MULTIPLIER +
    read * p.input * CACHE_READ_MULTIPLIER +
    out * p.output
  ) / 1e6;
}

// In-process tally, keyed by model AND label so per-task cost is visible.
// Resets on restart/redeploy — this is a live read-out, not a ledger.
const usageTally = new Map();   // "<model>|<label>" -> totals
let usageSince = new Date().toISOString();

// Returns the call's cost so the caller can log it.
function recordUsage({ model, label, usage, injected }) {
  const u = usage || {};
  const cost = costFor(model, u);
  const key = `${model || 'unknown'}|${label || 'unlabelled'}`;
  const t = usageTally.get(key) || {
    model: model || 'unknown', label: label || 'unlabelled',
    calls: 0, input_tokens: 0, output_tokens: 0,
    cache_write_tokens: 0, cache_read_tokens: 0, injected_tokens: 0, est_cost: 0
  };
  t.calls += 1;
  t.input_tokens += u.input_tokens || 0;
  t.output_tokens += u.output_tokens || 0;
  t.cache_write_tokens += u.cache_creation_input_tokens || 0;
  t.cache_read_tokens += u.cache_read_input_tokens || 0;
  t.injected_tokens += injected || 0;
  t.est_cost += cost;
  usageTally.set(key, t);
  return cost;
}

const usd = n => '$' + n.toFixed(4);

// withFallbacks: request server-side refusal fallbacks where the model supports it.
async function claudeText({ model, system, message, messages, maxTokens, withFallbacks, effort, injected, label }) {
  const params = {
    model,
    max_tokens: maxTokens,
    system,
    messages: messages || [{ role: 'user', content: message }]
  };
  if (effort && EFFORT_CAPABLE.test(model)) {
    params.output_config = { effort };
  }
  let response;
  if (withFallbacks && FALLBACK_CAPABLE.test(model)) {
    try {
      response = await anthropic.beta.messages.create({
        ...params,
        betas: ['server-side-fallback-2026-07-01'],
        fallbacks: 'default'
      });
    } catch (e) {
      // Self-heal if a model's fallback support differs from the pattern above
      if (!/does not support the .?fallbacks/i.test(e.message || '')) throw e;
      console.warn(`[claude] ${model} rejected fallbacks — retrying without`);
      response = await anthropic.messages.create(params);
    }
  } else {
    response = await anthropic.messages.create(params);
  }
  const u = response.usage || {};
  const served = response.model || model;
  const cost = recordUsage({ model: served, label, usage: u, injected });
  console.log(`[claude] ${served} label=${label || '-'} injected=${injected || 0} in=${u.input_tokens} out=${u.output_tokens} cache_write=${u.cache_creation_input_tokens || 0} cache_read=${u.cache_read_input_tokens || 0} est_cost=${usd(cost)}`);
  // The server-side `fallbacks` param swaps models transparently — surface it
  // so a primary that keeps getting declined doesn't stay invisible.
  if ((u.iterations || []).some(i => i.type === 'fallback_message')) {
    console.warn(`⚠ [fallback] ${model} was declined by safety classifiers — served by ${response.model || 'fallback model'} instead`);
  }
  // Safety classifiers (e.g. on claude-fable-5) can decline a request with a 200 +
  // stop_reason "refusal" and empty content — surface that instead of returning ''.
  if (response.stop_reason === 'refusal') {
    const err = new Error('This request was declined by the model’s safety filters. Try rephrasing it.');
    err.isRefusal = true;
    throw err;
  }
  // Fable returns thinking blocks alongside text; only text blocks carry the answer.
  return response.content
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('')
    .trim();
}

// Every Claude path: run on the primary model, and if safety classifiers decline
// a benign radiology request, transparently retry on the fallback model.
async function claudeTextFallback(opts) {
  try {
    return await claudeText({ ...opts, withFallbacks: true });
  } catch (e) {
    const fallback = opts.fallbackModel || MODEL_FALLBACK;
    if (e.isRefusal && fallback && fallback !== opts.model) {
      console.warn(`⚠ [fallback] ${opts.model} refused — retrying on ${fallback}. Reason: ${e.message}`);
      return await claudeText({ ...opts, model: fallback, withFallbacks: true });
    }
    throw e;
  }
}

// Claude is instructed to return JSON only, but strip markdown fences defensively.
function parseClaudeJson(text) {
  let cleaned = text
    .replace(/^\s*```(?:json)?\s*/i, '')
    .replace(/\s*```\s*$/, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch (e) {
    // Fall back to the outermost {...} or [...] block
    const start = Math.min(
      ...['{', '['].map(c => { const i = cleaned.indexOf(c); return i === -1 ? Infinity : i; })
    );
    const end = Math.max(cleaned.lastIndexOf('}'), cleaned.lastIndexOf(']'));
    if (start !== Infinity && end > start) {
      return JSON.parse(cleaned.slice(start, end + 1));
    }
    throw e;
  }
}

const ASSIST_SYSTEM = `You are an expert radiologist's writing assistant inside Flow Dictation, a radiology reporting tool.

Rules:
- Less is more. Keep responses short and to the point, in short sentences. Lead with the answer; no preamble, no commentary, no elaboration beyond what was asked. Expand only when explicitly asked for detail. This governs your own prose — never drop or shorten clinical content in text you were asked to transform.
- Write in standard radiology reporting register: precise, concise, formal, third person, present tense for current findings.
- Output plain text only. Never use markdown formatting (no **, no #, no bullets with -) unless explicitly told to return JSON.
- Preserve the clinical meaning of anything you rewrite. Never invent findings, measurements, or comparisons that were not provided.
- Preserve line breaks where they exist in the user's text.
- Never include patient names, MRNs, dates of birth, or other PHI.
- No preamble, no commentary, no sign-off — return only the requested content.
- You may be given recent conversation history. Judge for yourself whether each new message continues the previous exchange or starts something new. Follow-ups — "make it shorter", "more formal", "now do the impression", "same but for the left side", "what about on the left?" — refer to your previous answer; interpret them against it. A message that introduces a new report, a new finding, or an unrelated question is a fresh task: answer it on its own terms and do not carry over wording, findings, or structure from earlier answers. When it is genuinely ambiguous, prefer treating it as a follow-up, since the user can always restate.`;

const ASSIST_ACTIONS = {
  describe: `The user is describing an imaging finding they are struggling to word. Suggest professional report wording for it.
Return JSON only — no markdown fences, no commentary — in exactly this shape:
{"findings": "<suggested wording for the Findings section>", "impression": "<matching wording for the Impression section>"}

User's description of the finding:`,
  reword: `Reword the following text. Keep the exact meaning, improve clarity and flow, and use standard radiology reporting register. It may be a sentence, a section, or an entire report — preserve its structure and line breaks. Return only the reworded text.

Text to reword:`,
  proofread: `Proofread the following text. Correct spelling, grammar, punctuation, and obvious speech-recognition/dictation errors. Do not otherwise change wording, meaning, or style. Return only the fully corrected text, preserving line breaks exactly.

The style guide and word list in your instructions are REFERENCE ONLY here, to help you recognise a dictation error that happens to be a real word. They are NOT a licence to restyle. If a phrase is correctly spelled and grammatical, leave it exactly as written even when the style guide would phrase it differently — filler constructions ("is seen", "is noted", "is identified"), discouraged words, and long-winded phrasing all stay. Changing them is a bug, not an improvement: the reader is shown a word-level diff of your output, and every unnecessary change buries the real corrections.

Text to proofread:`,
  impression: `Generate an IMPRESSION for the following radiology report body. Rules:
- Be selective. Include only findings that change patient management or answer the clinical question. Omit incidental and chronic findings, stable/unchanged benign findings, and normal statements — those stay in the findings.
- Include a pertinent negative only when it directly answers the clinical question.
- If nothing meets that bar, say so in a single line rather than padding the impression with minor findings.
- Order by clinical significance, most important first; the first line answers the clinical question.
- One item per line, separated by a single newline. Do NOT number, letter, bullet, or otherwise label the lines — plain text only, so lines can be edited and reordered freely.
- Keep each item to one or two sentences in standard radiology register; detail belongs in the findings.
- Return only the impression lines, nothing else.

Report body:`,
  fullreport: `Generate a complete radiology report from the user's dictated or summarized findings. Use standard report structure — EXAMINATION, CLINICAL HISTORY, TECHNIQUE, COMPARISON, FINDINGS, IMPRESSION — matching the structure and phrasing of any exemplar reports provided for this study type. Rules:
- Include every finding the user stated, worded in standard radiology register. Never alter laterality, measurements, or meaning.
- For structures the user did not mention, use the standard normal statements appropriate to this study type.
- Use [bracketed placeholders] for details the user did not provide (e.g. [clinical history], [comparison date]) rather than inventing them.
- Keep the IMPRESSION selective: only findings that change patient management or answer the clinical question — no incidental or chronic findings. Order by clinical significance, one item per line, unnumbered and unbulleted.
- Return only the report text, nothing else.

User's findings / dictation:`,
  synthesize: `Rewrite the PRIOR REPORT so it incorporates the NEW INFORMATION, in the user's own reporting voice.

Rules:
- Start from the prior report and keep its structure, section headings, ordering, and phrasing conventions. This is an edit, not a fresh report.
- Apply everything the new information states: change, add, or remove content accordingly. Where the two conflict, the new information wins.
- Leave untouched anything the new information doesn't address — do not re-word, re-order, or "improve" it.
- Update the impression so it stays consistent with the findings you changed.
- Never invent findings, measurements, or comparisons that appear in neither input.
- Use [bracketed placeholders] for details neither input supplies.
- Match the style guide, language reference, and exemplar reports provided — they are the user's own conventions.
- Return only the finished report, with no commentary about what you changed.`
};

// Speed: mechanical transformations run at low effort, moderate tasks at
// medium; only full report generation keeps the default (high) depth.
// Undefined = model default.
const ACTION_EFFORT = {
  reword: 'low',
  proofread: 'low',
  describe: 'medium',
  impression: 'medium',
  fullreport: 'high',
  synthesize: 'high'
};
const DRAFT_REVIEW_EFFORT = 'medium';  // typo/essential-edit review
// Free text is the most-used path, so it is also the most latency-sensitive.
// Env-overridable to retune without a code change.
const FREEFORM_EFFORT = process.env.FREEFORM_EFFORT || 'medium';

// Per-action model routing; anything unlisted uses MODEL_REPORT.
const ACTION_MODEL = { impression: MODEL_IMPRESSION, synthesize: MODEL_SYNTHESIZE };

const DRAFT_REVIEW_SYSTEM = `You review radiology report drafts for a radiologist. Flag ONLY essential corrections: obvious typos (spelling, grammar, punctuation) and clear speech-recognition/dictation errors, plus wording that is factually wrong or genuinely confusing.

Return JSON only — no markdown fences, no commentary — in exactly this shape:
{"edits": [{"original_text": "...", "suggested_text": "...", "reason": "...", "category": "typo"}]}

Rules:
- SCOPE: review only the body of the report — the FINDINGS section and everything after it (including the IMPRESSION). Everything above FINDINGS is off limits: exam/study type, clinical history or indication, technique, comparison, protocol, patient or accession headers. Never propose an edit there, even for an obvious typo. If a report has no FINDINGS heading, review the whole thing.
- Essential changes only. Do NOT suggest optional stylistic polish, preference rewording, tightening, or restructuring. If a sentence is acceptable as written, leave it alone — even if you would phrase it differently.
- Fewer, high-confidence edits beat many marginal ones. When unsure whether an edit is essential, omit it.
- "category" must be exactly "typo" or "style". Use "typo" for spelling/grammar/punctuation/dictation errors; reserve "style" for wording that is clearly wrong or confusing, not preferences.
- "original_text" must be an EXACT character-for-character substring of the report so it can be located, and must be unique enough to find (include a few surrounding words if needed).
- Keep each edit small and local: a word, phrase, or at most one sentence. Do not rewrite the whole report.
- Never change medical meaning, laterality, measurements, or findings.
- "reason" is one short sentence.
- If nothing needs changing, return {"edits": []}.`;

const READOUT_INTEGRATE_SYSTEM = `You convert an attending radiologist's verbal read-out feedback into targeted edits to a resident's draft report. This is NOT a rewrite: change only what the feedback calls for.

Return JSON only — no markdown fences, no commentary — in exactly this shape:
{"edits": [{"original_text": "...", "suggested_text": "...", "reason": "...", "category": "readout"}]}

Rules:
- Make only the changes the feedback requires, plus anything strictly needed to keep the report internally consistent with those changes (e.g. a matching impression item). Leave everything else exactly as written — no polish, no restructuring.
- "category" is always exactly "readout".
- "original_text" must be an EXACT character-for-character substring of the draft so it can be located, and must be unique enough to find (include a few surrounding words if needed).
- Keep each edit small and local: a word, phrase, or sentence. To ADD a new sentence, use an adjacent existing sentence as the anchor: original_text = that sentence, suggested_text = that sentence plus the addition.
- Never introduce findings, measurements, or comparisons the feedback did not state.
- "reason" is one short sentence tying the edit to the specific feedback point it implements.
- If the feedback requires no changes to the report, return {"edits": []}.`;

const STUDY_TYPE_SYSTEM = `You identify the study type of a radiology report: modality plus body part, normalized in the style "MRI knee", "CT abdomen pelvis", "US thyroid", "XR chest", "PET/CT whole body", "CT head".
Return JSON only — no markdown fences, no commentary: {"study_type": "..."}`;

// Free text is the main way in — there are no modes to pick, so this prompt has
// to work out for itself what the user wants. The quick-action chips exist only
// as shortcuts; every one of their jobs is described here too, because a typed
// request ("tidy this up", "impression?", "what's the Bosniak cutoff") has to
// land in the same place as the chip would.
const FREEFORM_SYSTEM = `You are an expert academic radiologist and writing assistant inside Flow Dictation, a radiology reporting tool. The user types freely — there are no modes and no buttons to tell you what they want. Work that out yourself from the message and the recent conversation, then follow the matching playbook below.

FIRST — continuation or new task? You may be given recent conversation history. Judge whether the new message continues the previous exchange or starts something new. Follow-ups — "make it shorter", "more formal", "now do the impression", "same but for the left side", "what about on the left?", "why?" — refer to your previous answer; interpret them against it, and apply the playbook to the text or topic already in the conversation rather than to the literal words of the follow-up. A message that introduces a new report, a new finding, or an unrelated question is a fresh task: answer it on its own terms and carry over no wording, findings, or structure from earlier answers. When it is genuinely ambiguous, prefer treating it as a follow-up — the user can always restate.

THEN — which kind of request is it?

QUESTION (anatomy, physics, protocols, differentials, pitfalls, staging/classification systems, guidelines, management, "what is", "how do I", "when should"). This is the most common thing typed here. Answer it:
- Directly and precisely at resident-to-fellow teaching level; assume medical vocabulary.
- Anatomic precision matters — name specific structures, attachments, and relationships.
- Proactively flag imaging pitfalls, mimics, and pseudolesions relevant to the question.
- For protocol questions, reason about the clinical question first, then the acquisition.
- When asked for report language, give drop-in ready phrasing with bracketed [placeholders].
- Note genuine controversy or institutional variation briefly.
- Keep it tight: a few short paragraphs, shorter still for simple questions. Lead with the direct answer, then only the detail that changes what the reader would do next. Skip preamble, restating the question, exhaustive differentials, and report templates unless asked. Prefer prose over stacked headers and bullet lists; a brief list only for truly parallel items. The user can ask a follow-up for depth.
- No generic safety disclaimers or "consult your attending" filler — this is education between professionals, not patient advice.

TEXT WORK — the user supplied text (or is referring to text already in the conversation) and wants it transformed. Identify which and do only that:
- Reword / tidy up / improve: keep the exact meaning, improve clarity and flow, preserve structure and line breaks. Return only the reworded text.
- Proofread: correct spelling, grammar, punctuation, and speech-recognition/dictation errors. Change nothing else — not wording, not meaning, not style. Return only the corrected text, line breaks preserved.
- Impression: include only findings that change patient management or answer the clinical question. Omit incidental and chronic findings, stable benign findings, and normals; a pertinent negative only when it directly answers the clinical question. If nothing meets that bar, say so in one line rather than padding. Order by clinical significance, most important first. One item per line, separated by a single newline, with NO numbering, lettering, or bullets. One or two sentences per item.
- Wording for a finding they are struggling to describe: give the Findings sentence, then the matching Impression wording, labelled FINDINGS: and IMPRESSION:.
- Full report from dictated findings: use standard structure (EXAMINATION, CLINICAL HISTORY, TECHNIQUE, COMPARISON, FINDINGS, IMPRESSION). Include every finding stated, standard normal statements for structures not mentioned, and [bracketed placeholders] for details not provided — never invented ones.
For all text work: standard radiology register (precise, concise, formal, third person, present tense for current findings); preserve clinical meaning exactly; never invent findings, measurements, or comparisons; never alter laterality; return only the requested text with no preamble or commentary.

ANYTHING ELSE — answer briefly and directly.

SOURCES — this applies to every answer, whether or not you searched. Never write a URL that did not come back from a search in this same turn. A link recalled from memory cannot be checked, and a citation that 404s or points at the wrong paper is worse for a radiologist than no citation at all. If you are asked for references and no search results are in front of you, say plainly that you cannot cite sources you have not retrieved and that the Quick Rad Question option searches and cites — then stop. Do not offer a remembered list "to get them started". When you do have search results, cite at most three.

Always: never include patient names, MRNs, dates of birth, or other PHI. Plain text only — no markdown headers, no bullet characters, no code fences. **Bold** is allowed for emphasis in answers to questions, never inside report text.`;

// Appended only when the "Include references" toggle is on (tools provided)
const REFERENCES_ADDENDUM = `When a reference would genuinely help (classification systems, management guidelines, follow-up criteria, entities the user may want to read further on), use web search to find the specific relevant page and end your answer with a short 'References' line listing the best 1-3 links with one-phrase descriptions. Three is a hard ceiling — pick the most useful sources and drop the rest rather than listing everything you found.

Radiopaedia (radiopaedia.org) is the preferred source. Search it first, and include the relevant Radiopaedia article whenever one exists — list it first in the References. Add other sources only when they cover something Radiopaedia does not: ACR Appropriateness Criteria for protocol/appropriateness questions, and RadioGraphics for in-depth reviews.

You are only given this tool when the user has explicitly asked for a sourced answer, so search before you answer even when you already know the answer cold, and even when the question repeats one you just answered — being sure is not the same as being able to cite. The one exception is text work: rewording, proofreading, impressions and report generation need no references, so do not search for those. Never fabricate a URL: only include links returned by search.`;

function buildFreeformSystem(searchEnabled, knowledgeBlock) {
  let s = FREEFORM_SYSTEM;
  if (searchEnabled) s += '\n\n' + REFERENCES_ADDENDUM;
  if (knowledgeBlock) s += knowledgeBlock;
  return s;
}

const REFERENCE_SEARCH_TOOL = {
  type: 'web_search_20250305',
  name: 'web_search',
  allowed_domains: [
    'radiopaedia.org',
    'radiologyassistant.nl',
    'acsearch.acr.org',        // ACR Appropriateness Criteria
    'www.acr.org',
    'pubs.rsna.org',           // RadioGraphics, Radiology
    'ajronline.org',
    'statdx.com',
    'radiology.wisc.edu'
  ],
  max_uses: 3
};

// Answers cite at most this many sources — enforced in the prompt, in what the
// API returns, and again when the client renders a fallback list.
const MAX_REFERENCES = 3;

const VALID_RPR = /^RPR[1-4]$/;

// ============ Knowledge layer (style guide, language library, exemplars) ============

// Rough size estimate at ~4 chars/token. Used only to compare injected payloads
// between actions and to budget conversation history — never for billing.
function estimateTokens(text) {
  return Math.ceil((text || '').length / 4);
}

// Prompt caching is a prefix match, so the static block is cached on a 1-hour
// TTL: a shift's worth of dictation has long gaps between actions, and the
// 5-minute default expires across nearly all of them. Writes cost 2x instead of
// 1.25x, so a block needs ~3 reads within the hour to pay for itself.
const CACHE_1H = { type: 'ephemeral', ttl: '1h' };

// What each action actually needs injected. Everything-everywhere was costing
// full style guide + full language library + 3 exemplars on every call, most of
// which no single action can use: Proofread must not change wording, so phrasing
// guidance and exemplars can only mislead it.
//   style: include the style guide · language: 'all' or a category allowlist
//   exemplars: how many report exemplars · impressionPairs: prefer stored
//   findings/impression pairs, injecting the impression text alone
const DEFAULT_EXEMPLARS = 2;
const KNOWLEDGE_PROFILES = {
  proofread:  { style: true,  language: ['words_to_avoid'], exemplars: 0 },
  reword:     { style: true,  language: 'all',              exemplars: 1 },
  describe:   { style: false, language: 'all',              exemplars: 2 },
  impression: { style: true,  language: 'all',              exemplars: 2, impressionPairs: true },
  fullreport: { style: true,  language: 'all',              exemplars: 2 },
  synthesize: { style: true,  language: 'all',              exemplars: 2 },
  review:     { style: true,  language: ['words_to_avoid'], exemplars: 1 },
  readout:    { style: true,  language: ['words_to_avoid'], exemplars: 1 },
  freeform:   { style: true,  language: 'all',              exemplars: 2 }
};
const DEFAULT_PROFILE = { style: true, language: 'all', exemplars: DEFAULT_EXEMPLARS };
const profileFor = key => KNOWLEDGE_PROFILES[key] || DEFAULT_PROFILE;

// The style guide + language library form a static system-prompt block that is
// prompt-cached. Rows are cached in memory and each action's composed block is
// memoised, so the bytes stay identical across requests — any drift would miss
// the cache. Both are invalidated when the library is edited.
let knowledgeRows = { rules: null, lang: null, loadedAt: 0 };
const knowledgeBlockCache = new Map();   // profile key -> composed block text
const KNOWLEDGE_TTL_MS = 5 * 60 * 1000;
function invalidateKnowledge() {
  knowledgeRows = { rules: null, lang: null, loadedAt: 0 };
  knowledgeBlockCache.clear();
}

// Supabase caps selects at 1000 rows — page through everything.
async function fetchAllRows(table, columns) {
  const out = [];
  const page = 1000;
  for (let from = 0; ; from += page) {
    const { data, error } = await supabase
      .from(table)
      .select(columns)
      .order('created_at', { ascending: true })
      .range(from, from + page - 1);
    if (error) throw error;
    out.push(...data);
    if (data.length < page) break;
  }
  return out;
}

function groupLines(rows, keyField, valueField, fallbackKey) {
  const grouped = {};
  for (const r of rows) {
    const k = (r[keyField] || fallbackKey).trim();
    (grouped[k] = grouped[k] || []).push(r[valueField]);
  }
  let text = '';
  for (const [k, list] of Object.entries(grouped)) {
    text += `\n[${k}]\n` + list.map(v => '- ' + v).join('\n') + '\n';
  }
  return text;
}

async function getKnowledgeRows() {
  if (knowledgeRows.rules && Date.now() - knowledgeRows.loadedAt < KNOWLEDGE_TTL_MS) {
    return knowledgeRows;
  }
  const [rules, lang] = await Promise.all([
    fetchAllRows('style_guide', 'section, rule, created_at'),
    fetchAllRows('rad_language', 'category, content, created_at')
  ]);
  knowledgeRows = { rules, lang, loadedAt: Date.now() };
  knowledgeBlockCache.clear();   // rows changed, so every composed block is stale
  return knowledgeRows;
}

// The static block for one action, composed from its profile.
async function getKnowledgeBlock(profileKey) {
  if (!supabase) return '';
  const memo = knowledgeBlockCache.get(profileKey);
  if (memo !== undefined && Date.now() - knowledgeRows.loadedAt < KNOWLEDGE_TTL_MS) return memo;
  try {
    const profile = profileFor(profileKey);
    const { rules, lang } = await getKnowledgeRows();
    let block = '';
    if (profile.style && rules.length) {
      block += '\n\nSTYLE GUIDE — follow these reporting rules:\n' +
        groupLines(rules, 'section', 'rule', 'general');
    }
    const langRows = profile.language === 'all'
      ? lang
      : lang.filter(r => profile.language.includes((r.category || '').trim()));
    if (langRows.length) {
      block += '\nRADIOLOGY LANGUAGE REFERENCE — preferred register and phrasing:\n' +
        groupLines(langRows, 'category', 'content', 'general');
    }
    knowledgeBlockCache.set(profileKey, block);
    return block;
  } catch (e) {
    console.error('Knowledge load failed:', e.message);
    return '';
  }
}

// Exemplars for the study type: user rows first, PARROT fills the rest; fall
// back to modality-level matches, then general exemplars. Two is the default —
// a third full report rarely teaches voice the first two haven't already.
// 'user' > 'parrot' alphabetically, so order source DESC puts user rows first.
const EXEMPLAR_COLS = 'id, study_type, title, body, source';

// Exemplar lookup is 1-4 sequential round trips, on the critical path of every
// report action. Cached per study type + count on the knowledge block's TTL.
const exemplarCache = new Map();   // "<count>:<study type>" -> { rows, loadedAt }
function invalidateExemplars() { exemplarCache.clear(); }

async function selectExemplars(studyType, limit = DEFAULT_EXEMPLARS) {
  if (!supabase || limit <= 0) return [];
  const cacheKey = limit + ':' + (studyType || '').trim().toLowerCase();
  const hit = exemplarCache.get(cacheKey);
  if (hit && Date.now() - hit.loadedAt < KNOWLEDGE_TTL_MS) return hit.rows;
  const rows = await selectExemplarsUncached(studyType, limit);
  exemplarCache.set(cacheKey, { rows, loadedAt: Date.now() });
  return rows;
}

async function selectExemplarsUncached(studyType, limit) {
  const chosen = [];
  const seen = new Set();
  const add = rows => {
    for (const r of rows || []) {
      if (chosen.length >= limit) break;
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      chosen.push(r);
    }
  };
  try {
    if (studyType && studyType.trim()) {
      const st = studyType.trim();
      const { data: userRows } = await supabase.from('exemplar_reports')
        .select(EXEMPLAR_COLS).ilike('study_type', st).eq('source', 'user').limit(limit);
      add(userRows);
      if (chosen.length < limit) {
        const { data: parrotRows } = await supabase.from('exemplar_reports')
          .select(EXEMPLAR_COLS).ilike('study_type', st).neq('source', 'user').limit(limit);
        add(parrotRows);
      }
      if (chosen.length === 0) {
        const modality = st.split(/\s+/)[0];
        if (modality) {
          const { data: modRows } = await supabase.from('exemplar_reports')
            .select(EXEMPLAR_COLS).ilike('study_type', modality + ' %')
            .order('source', { ascending: false }).limit(limit);
          add(modRows);
        }
      }
    }
    if (chosen.length === 0) {
      const { data: anyRows } = await supabase.from('exemplar_reports')
        .select(EXEMPLAR_COLS).order('source', { ascending: false }).limit(limit);
      add(anyRows);
    }
  } catch (e) {
    console.error('Exemplar selection failed:', e.message);
  }
  return chosen;
}

function exemplarBlockText(exemplars) {
  if (!exemplars.length) return '';
  return '\n\nEXEMPLAR REPORTS — match their structure, register, and phrasing style. Do not copy their content or findings:\n' +
    exemplars.map((e, i) =>
      `\n--- Exemplar ${i + 1} (${e.study_type || 'general'}) ---\n${e.body.slice(0, 6000)}`
    ).join('\n');
}

// ---- Impression exemplars, for impression work only ----
// A whole prior report is mostly findings the impression task can't use. The
// stored findings/impression pairs let us inject the impression alone: same
// voice, a fraction of the tokens.
const impressionExemplarCache = new Map();
function invalidateImpressionExemplars() { impressionExemplarCache.clear(); }

// Stored impressions predate the no-numbering rule, so their leading "1." /
// "2." markers would re-teach exactly what the style guide forbids.
function stripEnumeration(impression) {
  return impression
    .split('\n')
    .map(line => line.replace(/^\s*(?:\d+[.)]|[a-z][.)]|[-•*])\s*/i, '').trim())
    .filter(Boolean)
    .join('\n');
}

async function selectImpressionExemplars(studyType, limit) {
  if (!supabase || limit <= 0) return [];
  const cacheKey = limit + ':' + (studyType || '').trim().toLowerCase();
  const hit = impressionExemplarCache.get(cacheKey);
  if (hit && Date.now() - hit.loadedAt < KNOWLEDGE_TTL_MS) return hit.rows;
  let rows = [];
  try {
    const base = () => supabase.from('report_sections')
      .select('study_type, impression')
      .not('impression', 'is', null)
      .order('created_at', { ascending: false });
    const st = (studyType || '').trim();
    if (st) {
      const { data } = await base().ilike('study_type', st).limit(limit);
      rows = data || [];
      if (rows.length === 0) {
        const modality = st.split(/\s+/)[0];
        if (modality) {
          const { data: mod } = await base().ilike('study_type', modality + '%').limit(limit);
          rows = mod || [];
        }
      }
    }
  } catch (e) {
    console.error('Impression exemplar selection failed:', e.message);
    rows = [];
  }
  impressionExemplarCache.set(cacheKey, { rows, loadedAt: Date.now() });
  return rows;
}

function impressionBlockText(rows) {
  const items = rows
    .map(r => ({ studyType: r.study_type, text: stripEnumeration(r.impression || '') }))
    .filter(r => r.text);
  if (!items.length) return '';
  return '\n\nPRIOR IMPRESSIONS — your own past impressions for this study type. Match their register and level of detail; the current report\'s findings are the only source of content:\n' +
    items.map((e, i) =>
      `\n--- Impression ${i + 1} (${e.studyType || 'general'}) ---\n${e.text.slice(0, 2000)}`
    ).join('\n');
}

// The varying half of the system prompt: exemplars for this study type, drawn
// from whichever source the profile calls for.
async function buildExemplarText(studyType, profile) {
  if (!profile.exemplars) return '';
  if (profile.impressionPairs) {
    const pairs = await selectImpressionExemplars(studyType, profile.exemplars);
    const text = impressionBlockText(pairs);
    if (text) return text;      // fall through to full reports when none stored yet
  }
  return exemplarBlockText(await selectExemplars(studyType, profile.exemplars));
}

// System prompt as content blocks: [static block (cached 1h), exemplar block
// (varies by study type)]. Returns the injected token estimate for logging.
async function buildKnowledgeSystem(baseSystem, studyType, profileKey) {
  const profile = profileFor(profileKey);
  // Independent lookups — fetched together, not one after the other
  const [knowledge, exText] = await Promise.all([
    getKnowledgeBlock(profileKey),
    buildExemplarText(studyType, profile)
  ]);
  const blocks = [];
  if (knowledge) {
    blocks.push({ type: 'text', text: baseSystem + knowledge, cache_control: CACHE_1H });
  } else {
    blocks.push({ type: 'text', text: baseSystem });
  }
  if (exText) blocks.push({ type: 'text', text: exText });
  return { system: blocks, injected: estimateTokens(knowledge) + estimateTokens(exText) };
}

// Heuristic: pasted report content is long; short inputs (finding descriptions,
// questions) skip the study-type detection call.
function looksLikeReport(text) {
  return text.trim().length >= 200;
}

// A long typed question is not report content — no style guide or exemplar can
// improve the answer, so it skips detection and the knowledge fetch entirely.
const QUESTION_OPENERS = /^(what|why|how|when|which|who|where|is|are|was|were|do|does|did|can|could|should|would|will|any|explain|tell me|difference)\b/i;
function looksLikeQuestion(text) {
  const t = text.trim();
  return t.endsWith('?') || QUESTION_OPENERS.test(t);
}

// Generate Full Report writes the whole report on MODEL_REPORT, then rewrites
// just the IMPRESSION on MODEL_IMPRESSION — the section where model judgement
// matters most. Returns the original text unchanged if anything doesn't line up.
const IMPRESSION_HEADING = /^[ \t]*(?:\*\*)?\s*IMPRESSION\b[^\n]*$/im;
const FINDINGS_HEADING = /^[ \t]*(?:\*\*)?\s*FINDINGS\b[^\n]*$/im;

// Where the reviewable body starts: the FINDINGS heading. Everything above it
// (exam, history, technique, comparison) is off limits to the review pass.
// No heading found -> the whole report is reviewable.
function reviewableFrom(report) {
  const m = report.match(FINDINGS_HEADING);
  return m ? m.index : 0;
}

async function upgradeImpression(reportText, studyType) {
  if (MODEL_IMPRESSION === MODEL_REPORT) return reportText;
  const m = reportText.match(IMPRESSION_HEADING);
  if (!m) return reportText;
  const body = reportText.slice(0, m.index).trimEnd();
  if (!body) return reportText;
  const { system, injected } = await buildKnowledgeSystem(ASSIST_SYSTEM, studyType, 'impression');
  const impression = (await claudeTextFallback({
    model: MODEL_IMPRESSION,
    label: 'fullreport:impression',
    system,
    injected,
    message: `${ASSIST_ACTIONS.impression}\n\n${body}`,
    maxTokens: 2000,
    effort: ACTION_EFFORT.impression
  })).trim();
  if (!impression) return reportText;
  return `${body}\n\n${m[0]}\n${impression}`;
}

// ============ Page 1: Assist ============

// Shared by the buffered and streaming endpoints, so both build exactly the
// same request and only differ in how the answer is delivered.

function assistValidate(req, res) {
  const { action, message, template } = req.body;
  if (!message || !message.trim()) {
    res.status(400).json({ error: 'Message is required' });
    return false;
  }
  if (action === 'synthesize' && (!template || !template.trim())) {
    res.status(400).json({ error: 'A prior/template report is required for Synthesize Report' });
    return false;
  }
  return true;
}

// Searching costs the better part of ten seconds, so it is opt-in: the Quick
// Rad Question action, which exists for exactly that. 'radqa' is deliberately
// NOT in ASSIST_ACTIONS — it runs the ordinary free-text prompt, with search on.
function wantsReferences({ action, references }) {
  return references === true || action === 'radqa';
}

// History is carried for follow-ups ("shorter", "now the impression"), and a
// fixed count of exchanges is a poor proxy for what that costs: twelve one-line
// turns are free, while two pasted reports are most of a prompt. Budget it in
// tokens instead, dropping the oldest first.
const HISTORY_TOKEN_BUDGET = 1500;
const HISTORY_MSG_TOKEN_CAP = 600;   // above this, a pasted report is elided
const ELIDE_HEAD_WORDS = 150;
const ELIDE_TAIL_WORDS = 50;

// A pasted report kept for context only needs its shape: the header and
// opening findings, and the impression it ends on.
function elideMessage(text) {
  const words = text.trim().split(/\s+/);
  const dropped = words.length - ELIDE_HEAD_WORDS - ELIDE_TAIL_WORDS;
  if (dropped <= 0) return text;
  return words.slice(0, ELIDE_HEAD_WORDS).join(' ') +
    `\n\n[… ${dropped} words omitted …]\n\n` +
    words.slice(-ELIDE_TAIL_WORDS).join(' ');
}

function budgetHistory(history) {
  if (!Array.isArray(history)) return [];
  const kept = [];
  let used = 0;
  // Newest first, so what survives is always the most recent context
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i];
    if (!h || (h.role !== 'user' && h.role !== 'assistant')) continue;
    if (typeof h.content !== 'string' || !h.content.trim()) continue;
    let content = h.content.slice(0, 20000);
    if (estimateTokens(content) > HISTORY_MSG_TOKEN_CAP && looksLikeReport(content)) {
      content = elideMessage(content);
    }
    const cost = estimateTokens(content);
    if (used + cost > HISTORY_TOKEN_BUDGET) break;   // this and everything older
    used += cost;
    kept.push({ role: h.role, content });
  }
  return kept.reverse();
}

function assistMessages({ action, instruction, message, template, history }) {
  // Synthesize is the one two-part action: prior report + the new information
  const userMessage = action === 'synthesize'
    ? `${instruction}\n\nPRIOR REPORT:\n${template}\n\nNEW INFORMATION:\n${message}`
    : (instruction ? `${instruction}\n\n${message}` : message);

  const messages = budgetHistory(history);
  messages.push({ role: 'user', content: userMessage });
  return messages;
}

// Free text: style guide and exemplars matter when the message is report content
// to work on; a typed question doesn't need them, and detection costs ~1s.
// Resolved once per turn — runFreeform's loop can re-send several times.
async function freeformSystemFactory(message) {
  const profile = profileFor('freeform');
  let knowledgeBlock = '';
  let exemplarText = '';
  if (looksLikeReport(message) && !looksLikeQuestion(message)) {
    try {
      // Detection and the style guide are independent — overlap them
      const [studyType, block] = await Promise.all([
        detectStudyType(message).catch(() => null),
        getKnowledgeBlock('freeform')
      ]);
      knowledgeBlock = block;
      exemplarText = await buildExemplarText(studyType, profile);
    } catch (e) {
      console.error('Knowledge load failed for free text:', e.message);
    }
  }
  const systemFor = (searchOn) => {
    const blocks = [{
      type: 'text',
      text: buildFreeformSystem(searchOn, knowledgeBlock),
      ...(knowledgeBlock ? { cache_control: CACHE_1H } : {})
    }];
    if (exemplarText) blocks.push({ type: 'text', text: exemplarText });
    return blocks;
  };
  return { systemFor, injected: estimateTokens(knowledgeBlock) + estimateTokens(exemplarText) };
}

// An armed quick action: its dedicated prompt plus whatever its knowledge
// profile calls for (see KNOWLEDGE_PROFILES).
async function actionSystemFor(action, message, template) {
  const profile = profileFor(action);
  // Detection only buys anything when exemplars will be pulled — for a profile
  // with none (Proofread), it is a ~1s round trip for nothing. fullreport
  // inputs are often short dictations, but knowing the study type is what pulls
  // in the right exemplars — always try to detect it there. For synthesize, the
  // prior report is the reliable source.
  const detectFrom = action === 'synthesize' ? template : message;
  const needsDetect = profile.exemplars > 0 &&
    (action === 'fullreport' || action === 'synthesize' || looksLikeReport(detectFrom));
  // Detection and the static block are independent — overlap them; the block is
  // memoised, so buildKnowledgeSystem's own lookup is free after this
  const [studyType] = await Promise.all([
    needsDetect ? detectStudyType(detectFrom).catch(() => null) : Promise.resolve(null),
    getKnowledgeBlock(action)
  ]);
  const { system, injected } = await buildKnowledgeSystem(ASSIST_SYSTEM, studyType, action);
  return { system, injected, studyType };
}

// One free-text turn. The answer is returned whole; nothing is emitted until
// the final message is in hand, so a mid-flight retry or a server-side model
// fallback can never leave partial text behind.
async function runFreeform({ messages, systemFor, injected, label, useRefs }) {
  let msgs = messages;
  let text = '';
  // Quick Rad Question (references on) and plain free text are the same prompt
  // but route separately, so each can be tuned without moving the other.
  let model = useRefs ? MODEL_RADQA : MODEL_CHAT;
  let searchEnabled = useRefs;
  let triedFallbackModel = false;
  let refsDropped = false;
  let truncated = false;
  const citations = [];
  const seenUrls = new Set();

  // Search-enabled responses interleave text / server_tool_use /
  // web_search_tool_result blocks, and the server-side tool loop can pause
  // (stop_reason "pause_turn") — resume by appending the turn and re-sending.
  const restart = () => {
    msgs = messages;
    text = '';
    citations.length = 0;
    seenUrls.clear();
  };

  for (let attempt = 0; attempt < 8; attempt++) {
    const params = {
      model,
      // Referenced answers run long, and the References line comes last —
      // too low a ceiling truncates it away.
      max_tokens: 8000,
      system: systemFor(searchEnabled),
      messages: msgs,
      ...(FREEFORM_EFFORT && EFFORT_CAPABLE.test(model)
        ? { output_config: { effort: FREEFORM_EFFORT } }
        : {}),
      // Only the Fable/Opus-5 tier accepts these; both models are overridable
      ...(FALLBACK_CAPABLE.test(model)
        ? { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' }
        : {}),
      ...(searchEnabled ? { tools: [REFERENCE_SEARCH_TOOL] } : {})
    };

    const response = await anthropic.beta.messages.create(params);

    const u = response.usage || {};
    const viaServerFallback = (u.iterations || []).some(i => i.type === 'fallback_message');
    const freeformLabel = label || (searchEnabled ? 'radqa' : 'freeform');
    const cost = recordUsage({ model: response.model, label: freeformLabel, usage: u, injected });
    console.log(`[claude] ${response.model} label=${freeformLabel}${viaServerFallback ? ' (server-fallback)' : ''} injected=${injected || 0} in=${u.input_tokens} out=${u.output_tokens} cache_write=${u.cache_creation_input_tokens || 0} cache_read=${u.cache_read_input_tokens || 0} est_cost=${usd(cost)} stop=${response.stop_reason}`);

    if (response.stop_reason === 'refusal') {
      // Safety classifiers occasionally decline benign radiology questions
      // (bone/soft-tissue tumors especially), usually only once web search
      // results are in context. Degrade in the order that preserves the most:
      //   1. same question on the fallback model, references intact
      //   2. fallback model without search (answer from knowledge, no refs)
      if (!triedFallbackModel && MODEL_FALLBACK && MODEL_FALLBACK !== model) {
        triedFallbackModel = true;
        model = MODEL_FALLBACK;
        restart();
        continue;
      }
      if (searchEnabled) {
        searchEnabled = false;
        refsDropped = true;
        restart();
        continue;
      }
      throw new Error('This question was declined by the model’s safety filters. Try rephrasing it.');
    }
    for (const block of response.content) {
      if (block.type === 'text') {
        text += block.text;
        for (const c of block.citations || []) {
          if (c.url && !seenUrls.has(c.url)) {
            seenUrls.add(c.url);
            citations.push({ url: c.url, title: c.title || '' });
          }
        }
      }
    }
    if (response.stop_reason === 'pause_turn') {
      msgs = [...msgs, { role: 'assistant', content: response.content }];
      continue;
    }
    truncated = response.stop_reason === 'max_tokens';
    break;
  }
  // Radiopaedia first in any citation list we render, then keep only the top
  // few: a search can collect a dozen sources, and a wall of links buries the
  // one worth opening. The model's own References list is capped in the prompt;
  // this bounds the fallback list the client renders when it didn't write one.
  citations.sort((a, b) =>
    (b.url.includes('radiopaedia.org') ? 1 : 0) - (a.url.includes('radiopaedia.org') ? 1 : 0));
  return {
    text: text.trim(),
    citations: citations.slice(0, MAX_REFERENCES),
    refs_dropped: refsDropped,
    truncated
  };
}

app.post('/api/assist', async (req, res) => {
  try {
    if (!assistValidate(req, res)) return;
    const { action, message, history, template } = req.body;
    const instruction = action && ASSIST_ACTIONS[action] ? ASSIST_ACTIONS[action] : null;
    const messages = assistMessages({ action, instruction, message, template, history });

    // Free text (no quick action armed): one prompt that works out for itself
    // whether this is a question, text work, or a follow-up.
    if (!instruction) {
      const { systemFor, injected } = await freeformSystemFactory(message);
      const useRefs = wantsReferences(req.body);
      const out = await runFreeform({
        messages, systemFor, injected, useRefs, label: useRefs ? 'radqa' : 'freeform'
      });
      return res.json({ type: 'text', ...out });
    }

    const { system, injected, studyType } = await actionSystemFor(action, message, template);
    let text = await claudeTextFallback({
      model: ACTION_MODEL[action] || MODEL_REPORT,
      label: action,
      system,
      injected,
      messages,
      maxTokens: action === 'synthesize' ? 8000 : 4000,
      effort: ACTION_EFFORT[action]
    });

    // Second pass: rewrite the full report's IMPRESSION on MODEL_IMPRESSION
    if (action === 'fullreport') {
      try {
        text = await upgradeImpression(text, studyType);
      } catch (e) {
        console.error('Impression pass failed — keeping original impression:', e.message);
      }
    }

    if (action === 'describe') {
      try {
        const parsed = parseClaudeJson(text);
        return res.json({
          type: 'describe',
          findings: String(parsed.findings || '').trim(),
          impression: String(parsed.impression || '').trim()
        });
      } catch (e) {
        // If JSON parsing fails, fall back to plain text so the user still gets an answer
        return res.json({ type: 'text', text });
      }
    }

    res.json({ type: 'text', text });
  } catch (error) {
    console.error('Assist error:', error);
    res.status(500).json({ error: 'Assist request failed', details: error.message });
  }
});

app.post('/api/assist/feedback', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { action_type, user_input, model_response, rating, comment } = req.body;
    if (rating !== 'up' && rating !== 'down') {
      return res.status(400).json({ error: 'rating must be "up" or "down"' });
    }
    const { error } = await supabase.from('assist_feedback').insert({
      action_type: action_type || 'freeform',
      user_input: user_input || '',
      model_response: model_response || '',
      rating,
      comment: comment || null
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Failed to save feedback', details: error.message });
  }
});

// ============ Assist chat history (persistent, cross-device) ============

// Last N messages, returned oldest-first for rendering. History lives in
// Supabase so it follows the login across browsers/computers and is never
// cleared by the app.
app.get('/api/assist/messages', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 300, 1000);
    const { data, error } = await supabase
      .from('assist_messages')
      .select('id, role, content, action_type, created_at')
      .order('id', { ascending: false })
      .limit(limit);
    if (error) throw error;
    res.json({ messages: (data || []).reverse() });
  } catch (error) {
    console.error('Assist history error:', error);
    res.status(500).json({ error: 'Failed to load chat history', details: error.message });
  }
});

// Save one user+assistant exchange. Array insert preserves order, so the
// identity ids keep the pair in sequence.
app.post('/api/assist/messages', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { user_text, assistant_text, action_type } = req.body;
    if (!user_text || !assistant_text) {
      return res.status(400).json({ error: 'user_text and assistant_text are required' });
    }
    const at = action_type || 'freeform';
    const { error } = await supabase.from('assist_messages').insert([
      { role: 'user', content: user_text, action_type: at },
      { role: 'assistant', content: assistant_text, action_type: at }
    ]);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error('Assist history save error:', error);
    res.status(500).json({ error: 'Failed to save chat history', details: error.message });
  }
});

// ============ Page 2: Draft ============

app.post('/api/draft/review', async (req, res) => {
  try {
    const { report, study_type } = req.body;
    if (!report || !report.trim()) {
      return res.status(400).json({ error: 'Report text is required' });
    }

    // Use the selected study type when provided; otherwise detect it
    let studyType = (study_type || '').trim() || null;
    if (!studyType) {
      try { studyType = await detectStudyType(report); } catch (e) { /* non-fatal */ }
    }
    const { system, injected } = await buildKnowledgeSystem(DRAFT_REVIEW_SYSTEM, studyType, 'review');

    const text = await claudeTextFallback({
      model: MODEL_REVIEW,
      label: 'review',
      system,
      injected,
      message: `Review this radiology report draft:\n\n${report}`,
      maxTokens: 8000,
      effort: DRAFT_REVIEW_EFFORT
    });

    let parsed;
    try {
      parsed = parseClaudeJson(text);
    } catch (e) {
      console.error('Review JSON parse failed:', text.slice(0, 500));
      return res.json({ edits: [] });
    }

    const bodyStart = reviewableFrom(report);
    const rawEdits = Array.isArray(parsed) ? parsed : (parsed.edits || []);
    const edits = rawEdits
      .filter(e => e && typeof e.original_text === 'string' && typeof e.suggested_text === 'string')
      .map(e => ({
        original_text: e.original_text,
        suggested_text: e.suggested_text,
        reason: String(e.reason || ''),
        category: e.category === 'typo' ? 'typo' : 'style'
      }))
      // Drop edits whose original_text can't be located in the report
      .filter(e => report.includes(e.original_text) && e.original_text !== e.suggested_text)
      // Enforce the scope rule: an edit that only ever lands in the header
      // block is dropped, whatever the model proposed
      .filter(e => report.lastIndexOf(e.original_text) >= bodyStart);

    // body_start lets the client anchor each edit inside the body too, so a
    // phrase that also appears in the header can't be highlighted up there
    res.json({ edits, body_start: bodyStart });
  } catch (error) {
    console.error('Draft review error:', error);
    res.status(500).json({ error: 'Review failed', details: error.message });
  }
});

async function detectStudyType(report) {
  const text = await claudeTextFallback({
    model: MODEL_DETECT,
    label: 'detect',
    system: STUDY_TYPE_SYSTEM,
    message: `Identify the study type of this radiology report:\n\n${report.slice(0, 4000)}`,
    maxTokens: 100
  });
  const parsed = parseClaudeJson(text);
  const studyType = String(parsed.study_type || '').trim();
  if (!studyType) throw new Error('Empty study type from model');
  return studyType;
}

app.post('/api/study-type/detect', async (req, res) => {
  try {
    const { report } = req.body;
    if (!report || !report.trim()) {
      return res.status(400).json({ error: 'Report text is required' });
    }
    const study_type = await detectStudyType(report);
    res.json({ study_type });
  } catch (error) {
    console.error('Study type detection error:', error);
    res.status(500).json({ error: 'Detection failed', details: error.message });
  }
});

app.get('/api/study-types', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('study_types')
      .select('id, name, last_used_at')
      .order('last_used_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json({ study_types: data });
  } catch (error) {
    console.error('Study types error:', error);
    res.status(500).json({ error: 'Failed to load study types', details: error.message });
  }
});

async function touchStudyType(name) {
  const { data: existing, error: selErr } = await supabase
    .from('study_types')
    .select('id')
    .ilike('name', name)
    .limit(1);
  if (selErr) throw selErr;
  if (existing && existing.length > 0) {
    await supabase.from('study_types')
      .update({ last_used_at: new Date().toISOString() })
      .eq('id', existing[0].id);
  } else {
    await supabase.from('study_types').insert({ name, last_used_at: new Date().toISOString() });
  }
}

// ============ Shifts ============

app.get('/api/shifts', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('shifts')
      .select('*')
      .order('started_at', { ascending: false });
    if (error) throw error;
    res.json({ shifts: data });
  } catch (error) {
    console.error('Shifts error:', error);
    res.status(500).json({ error: 'Failed to load shifts', details: error.message });
  }
});

// The active shift is server state, so every browser/device agrees on it.
// supabase-js has no transactions; deactivate-then-activate is safe because the
// one_active_shift partial unique index makes two active shifts impossible —
// a lost race surfaces as an error here rather than corrupt state.
async function activateShift(id) {
  const { error: deactErr } = await supabase
    .from('shifts')
    .update({ is_active: false })
    .eq('is_active', true)
    .neq('id', id);
  if (deactErr) throw deactErr;
  const { data, error } = await supabase
    .from('shifts')
    .update({ is_active: true })
    .eq('id', id)
    .select()
    .single();
  if (error) throw error;
  return data;
}

app.get('/api/shifts/active', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('shifts')
      .select('*')
      .eq('is_active', true)
      .limit(1);
    if (error) throw error;
    res.json({ shift: data && data.length ? data[0] : null });
  } catch (error) {
    console.error('Active shift error:', error);
    res.status(500).json({ error: 'Failed to load active shift', details: error.message });
  }
});

app.post('/api/shifts', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Shift name is required' });
    }
    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from('shifts')
      .insert({ name: name.trim(), started_at: now, last_activity_at: now })
      .select()
      .single();
    if (error) throw error;
    // A newly started shift is always the active one
    const shift = await activateShift(data.id);
    res.json({ shift });
  } catch (error) {
    console.error('Create shift error:', error);
    res.status(500).json({ error: 'Failed to create shift', details: error.message });
  }
});

// Delete a shift — empty shifts only (the accidental-duplicate case). Reports
// reference shifts by FK, so this is also the only deletion that could succeed.
app.delete('/api/shifts/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { count, error: cntErr } = await supabase
      .from('reports')
      .select('id', { count: 'exact', head: true })
      .eq('shift_id', req.params.id);
    if (cntErr) throw cntErr;
    if (count > 0) {
      return res.status(400).json({
        error: `Shift has ${count} report${count === 1 ? '' : 's'} — only empty shifts can be deleted`
      });
    }
    const { data: deleted, error } = await supabase
      .from('shifts').delete().eq('id', req.params.id).select();
    if (error) throw error;
    if (!deleted || deleted.length === 0) {
      return res.status(404).json({ error: 'Shift not found' });
    }
    // Deleting the active shift promotes the most recent remaining one
    if (deleted[0].is_active) {
      const { data: latest, error: latestErr } = await supabase
        .from('shifts').select('id').order('started_at', { ascending: false }).limit(1);
      if (!latestErr && latest && latest.length) await activateShift(latest[0].id);
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Delete shift error:', error);
    res.status(500).json({ error: 'Failed to delete shift', details: error.message });
  }
});

// Manually switch the active shift (e.g. resuming an older shift)
app.put('/api/shifts/:id/activate', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const shift = await activateShift(req.params.id);
    res.json({ shift });
  } catch (error) {
    // .single() on an update that matched no rows → PGRST116
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Shift not found' });
    }
    console.error('Activate shift error:', error);
    res.status(500).json({ error: 'Failed to activate shift', details: error.message });
  }
});

// ============ Reports ============

app.post('/api/reports', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { proposed_id, shift_id, study_type, study_id_label, report_type, raw_text, draft_text, edits_json, finalized } = req.body;
    if (!proposed_id || !/^\d{12}$/.test(proposed_id)) {
      return res.status(400).json({ error: 'proposed_id must be a yyyymmddhhmm timestamp' });
    }
    if (!shift_id) return res.status(400).json({ error: 'shift_id is required' });
    if (!raw_text || !raw_text.trim()) return res.status(400).json({ error: 'raw_text is required' });

    // Auto-detect study type if left blank
    let finalStudyType = (study_type || '').trim();
    if (!finalStudyType) {
      try {
        finalStudyType = await detectStudyType(raw_text);
      } catch (e) {
        console.error('Study type auto-detect failed:', e.message);
        finalStudyType = 'Unknown';
      }
    }
    if (finalStudyType && finalStudyType !== 'Unknown') {
      try { await touchStudyType(finalStudyType); } catch (e) { console.error('touchStudyType failed:', e.message); }
    }

    // Collision handling: yyyymmddhhmm, then -2, -3, ...
    const { data: existing, error: existErr } = await supabase
      .from('reports')
      .select('id')
      .like('id', `${proposed_id}%`);
    if (existErr) throw existErr;
    const taken = new Set((existing || []).map(r => r.id));
    let id = proposed_id;
    for (let n = 2; taken.has(id); n++) {
      id = `${proposed_id}-${n}`;
    }

    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from('reports')
      .insert({
        id,
        shift_id,
        study_type: finalStudyType,
        study_id_label: (study_id_label || '').trim() || null,
        report_type: report_type === 'prelim' ? 'prelim' : 'complete',
        raw_text,
        draft_text: draft_text || raw_text,
        edits_json: edits_json || [],
        created_at: now,
        finalized_at: finalized ? now : null
      })
      .select()
      .single();
    if (error) throw error;

    // last_activity_at drives the 4-hour shift check only
    await supabase.from('shifts').update({ last_activity_at: now }).eq('id', shift_id);

    res.json({ report: data });
  } catch (error) {
    console.error('Save report error:', error);
    res.status(500).json({ error: 'Failed to save report', details: error.message });
  }
});

// ---- Full-text search over report content (Review page) ----

// Columns a keyword search looks in: the report itself in all three of its
// states, plus what was said about it.
const SEARCH_COLUMNS = ['raw_text', 'draft_text', 'final_text', 'readout_notes', 'rpr_note', 'study_id_label'];

// "a phrase in quotes" stays one term; bare words are separate terms that must
// ALL appear somewhere in the report.
function parseSearchTerms(q) {
  const terms = [];
  const re = /"([^"]+)"|(\S+)/g;
  let m;
  while ((m = re.exec(q)) !== null) {
    const t = (m[1] || m[2]).trim();
    if (t) terms.push(t.slice(0, 200));
  }
  return terms.slice(0, 8);   // a sane ceiling; each term is its own AND clause
}

// % and _ are LIKE wildcards — a search for "50%" must mean "50%", not
// "50 followed by anything". Backslash is LIKE's default escape character.
function escapeLike(term) {
  return term.replace(/([\\%_])/g, '\\$1');
}

// PostgREST splits or() on commas and parentheses, so every value is
// double-quoted with inner quotes and backslashes escaped.
function pgrstQuoted(value) {
  return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// ~150 characters of context around the first hit, so a result shows WHY it matched
function buildSnippet(row, terms) {
  for (const col of SEARCH_COLUMNS) {
    const text = row[col];
    if (typeof text !== 'string' || !text) continue;
    for (const term of terms) {
      const at = text.toLowerCase().indexOf(term.toLowerCase());
      if (at === -1) continue;
      const start = Math.max(0, at - 60);
      const end = Math.min(text.length, at + term.length + 90);
      return (start > 0 ? '…' : '') +
             text.slice(start, end).replace(/\s+/g, ' ').trim() +
             (end < text.length ? '…' : '');
    }
  }
  return '';
}

app.get('/api/reports', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    // Filters combine (Review page): any subset of shift, grade, study type, and
    // a keyword/phrase search of the report text. This only ever searches the
    // user's own drafted reports — PARROT exemplars live in exemplar_reports
    // and cannot appear here.
    const { shift_id, grade, study_type, q } = req.query;
    const terms = parseSearchTerms((q || '').trim());
    const LIST_COLUMNS = 'id, shift_id, study_type, study_id_label, report_type, created_at, final_saved_at, rpr_grade, rpr_note, readout_notes, notes_integrated_at, read_out_at, finalized_at';
    let query = supabase
      .from('reports')
      // Searching needs the text columns to build snippets; they are stripped
      // from the response below rather than shipped to the browser
      .select(terms.length ? LIST_COLUMNS + ', raw_text, draft_text, final_text' : LIST_COLUMNS)
      .order('created_at', { ascending: false });
    if (shift_id) query = query.eq('shift_id', shift_id);
    if (grade === 'ungraded') query = query.is('rpr_grade', null);
    else if (VALID_RPR.test(grade || '')) query = query.eq('rpr_grade', grade);
    if (study_type && study_type.trim()) query = query.ilike('study_type', '%' + study_type.trim() + '%');
    // Each term is its own or() across the searchable columns; consecutive
    // or() calls are ANDed, so every term must match somewhere in the report.
    for (const term of terms) {
      const value = pgrstQuoted('%' + escapeLike(term) + '%');
      query = query.or(SEARCH_COLUMNS.map(c => `${c}.ilike.${value}`).join(','));
    }
    const { data, error } = await query;
    if (error) throw error;

    const reports = terms.length
      ? data.map(row => {
          const { raw_text, draft_text, final_text, ...rest } = row;
          return { ...rest, snippet: buildSnippet(row, terms) };
        })
      : data;
    res.json({ reports, terms });
  } catch (error) {
    console.error('List reports error:', error);
    res.status(500).json({ error: 'Failed to load reports', details: error.message });
  }
});

app.get('/api/reports/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('reports')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;
    res.json({ report: data });
  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({ error: 'Failed to load report', details: error.message });
  }
});

app.put('/api/reports/:id/final', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { final_text } = req.body;
    if (!final_text || !final_text.trim()) {
      return res.status(400).json({ error: 'final_text is required' });
    }
    const { data, error } = await supabase
      .from('reports')
      .update({ final_text, final_saved_at: new Date().toISOString() })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;

    // Harvest the findings/impression pair for training. Never block the save.
    let sections = { stored: false, reason: 'not attempted' };
    try {
      sections = await saveReportSections(data, 'final');
    } catch (e) {
      console.error('Section extraction failed:', e.message);
      sections = { stored: false, reason: e.message };
    }
    res.json({ report: data, sections });
  } catch (error) {
    console.error('Save final error:', error);
    res.status(500).json({ error: 'Failed to save final', details: error.message });
  }
});

// ============ Findings / impression pairs (training data) ============

// Locate a section heading at the start of a line, tolerating "**FINDINGS**",
// "FINDINGS:", and headings with content on the same line.
function findHeading(text, words) {
  const re = new RegExp('^[ \\t]*(?:\\*\\*)?[ \\t]*(?:' + words.join('|') + ')\\b[ \\t]*:?[ \\t]*(?:\\*\\*)?', 'im');
  const m = re.exec(text);
  return m ? { start: m.index, after: m.index + m[0].length } : null;
}

const IMPRESSION_WORDS = ['IMPRESSION', 'IMPRESSIONS', 'CONCLUSION', 'ASSESSMENT'];

// Split a report into findings and impression. The full text is always
// returned; either section may come back null (an impression-only prelim, or a
// report whose headings don't parse) — those reports are still stored whole.
// A section is only claimed when its heading is found, since a wrong split
// would be worse than a missing one for training data.
function splitReportSections(text) {
  const t = String(text || '').replace(/\r\n?/g, '\n').trim();
  if (!t) return null;
  const f = findHeading(t, ['FINDINGS', 'FINDING']);
  // The impression heading must follow the findings heading when both exist
  let imp = null;
  if (f) {
    const m = findHeading(t.slice(f.after), IMPRESSION_WORDS);
    if (m) imp = { start: f.after + m.start, after: f.after + m.after };
  } else {
    const m = findHeading(t, IMPRESSION_WORDS);
    if (m) imp = m;
  }
  const findings = f ? (t.slice(f.after, imp ? imp.start : t.length).trim() || null) : null;
  const impression = imp ? (t.slice(imp.after).trim() || null) : null;
  return { full_text: t, findings, impression };
}

// Store (or refresh) one report's row. The whole report is always kept; the
// sections are recorded when detected. Never throws away the report.
async function saveReportSections(report, source = 'final') {
  const text = source === 'final' ? report.final_text : report.draft_text;
  const parts = splitReportSections(text);
  if (!parts) return { stored: false, reason: 'report text is empty' };
  const { error } = await supabase.from('report_sections').upsert({
    report_id: report.id,
    source,
    study_type: report.study_type || null,
    full_text: parts.full_text,
    findings: parts.findings,
    impression: parts.impression,
    updated_at: new Date().toISOString()
  }, { onConflict: 'report_id,source' });
  if (error) throw error;
  // These rows are what impression work is exemplified from — a newly stored
  // impression should be reachable without waiting out the TTL
  invalidateImpressionExemplars();
  return {
    stored: true,
    findings: !!parts.findings,
    impression: !!parts.impression,
    paired: !!(parts.findings && parts.impression)
  };
}

// Paired export for training/fine-tuning. ?format=jsonl returns one JSON object
// per line, which is what most training pipelines expect.
app.get('/api/training/impression-pairs', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { study_type, format } = req.query;
    let q = supabase
      .from('report_sections')
      .select('report_id, source, study_type, full_text, findings, impression, created_at')
      .order('created_at', { ascending: false })
      .limit(Math.min(parseInt(req.query.limit, 10) || 1000, 5000));
    if (study_type && study_type.trim()) q = q.ilike('study_type', '%' + study_type.trim() + '%');
    // Training reads complete pairs by default; ?include_partial=true returns
    // impression-only prelims and unparsed reports as well.
    if (req.query.include_partial !== 'true') {
      q = q.not('findings', 'is', null).not('impression', 'is', null);
    }
    const { data, error } = await q;
    if (error) throw error;
    if (format === 'jsonl') {
      res.type('application/x-ndjson');
      return res.send(data.map(r => JSON.stringify(r)).join('\n'));
    }
    res.json({ count: data.length, pairs: data });
  } catch (error) {
    console.error('Training pairs error:', error);
    res.status(500).json({ error: 'Failed to load pairs', details: error.message });
  }
});

// Backfill: parse every finalized report that doesn't have a pair yet
app.post('/api/training/extract-sections', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const reports = await fetchAllRows('reports', 'id, study_type, final_text, final_saved_at, created_at');
    const finals = reports.filter(r => r.final_text && r.final_text.trim());
    let stored = 0, paired = 0;
    const impressionOnly = [], findingsOnly = [], neither = [];
    for (const r of finals) {
      const out = await saveReportSections(r, 'final');
      if (!out.stored) continue;
      stored++;
      if (out.paired) paired++;
      else if (out.impression) impressionOnly.push(r.id);
      else if (out.findings) findingsOnly.push(r.id);
      else neither.push(r.id);
    }
    res.json({
      examined: finals.length, stored, paired,
      impression_only: impressionOnly, findings_only: findingsOnly, unparsed: neither
    });
  } catch (error) {
    console.error('Extract sections error:', error);
    res.status(500).json({ error: 'Extraction failed', details: error.message });
  }
});

// ============ Read-out workflow ============

// Jot/replace the attending's verbal feedback for one study
app.put('/api/reports/:id/notes', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const notes = typeof req.body.readout_notes === 'string' ? req.body.readout_notes : '';
    const { data, error } = await supabase
      .from('reports')
      .update({ readout_notes: notes.trim() ? notes : null })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ report: data });
  } catch (error) {
    console.error('Save notes error:', error);
    res.status(500).json({ error: 'Failed to save notes', details: error.message });
  }
});

// Current draft vs. the one saved immediately before it
app.get('/api/reports/:id/changes', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data: report, error: repErr } = await supabase
      .from('reports').select('id, draft_text, raw_text').eq('id', req.params.id).single();
    if (repErr) throw repErr;
    const { data: revs, error: revErr } = await supabase
      .from('report_revisions')
      .select('draft_text, created_at')
      .eq('report_id', req.params.id)
      .order('id', { ascending: false })
      .limit(1);
    if (revErr) throw revErr;

    const prior = revs && revs.length ? revs[0] : null;
    res.json({
      current: report.draft_text || '',
      previous: prior ? prior.draft_text : null,
      previous_at: prior ? prior.created_at : null
    });
  } catch (error) {
    console.error('Changes error:', error);
    res.status(500).json({ error: 'Failed to load changes', details: error.message });
  }
});

// Manually mark a study as read out with the attending — independent of whether
// any read-out notes were typed.
app.put('/api/reports/:id/read-out', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('reports')
      .update({ read_out_at: req.body.read_out ? new Date().toISOString() : null })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ report: data });
  } catch (error) {
    console.error('Read-out flag error:', error);
    res.status(500).json({ error: 'Failed to set read-out status', details: error.message });
  }
});

// Turn read-out notes into targeted edit proposals (same shape as /api/draft/review;
// the client renders the same accept/reject cards). Never rewrites the draft.
app.post('/api/reports/:id/integrate-notes', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data: report, error: repErr } = await supabase
      .from('reports').select('*').eq('id', req.params.id).single();
    if (repErr) throw repErr;

    // The client sends the live textarea contents so unsaved tweaks are honored;
    // stored values are the fallback.
    const draft = (typeof req.body.draft_text === 'string' && req.body.draft_text.trim())
      ? req.body.draft_text : report.draft_text;
    const notes = (typeof req.body.readout_notes === 'string' && req.body.readout_notes.trim())
      ? req.body.readout_notes : (report.readout_notes || '');
    if (!notes.trim()) {
      return res.status(400).json({ error: 'No read-out notes to integrate' });
    }

    const { system, injected } = await buildKnowledgeSystem(READOUT_INTEGRATE_SYSTEM, report.study_type, 'readout');
    const text = await claudeTextFallback({
      model: MODEL_REVIEW,
      label: 'readout',
      system,
      injected,
      message: `Attending read-out feedback:\n${notes}\n\nResident's current draft:\n${draft}`,
      maxTokens: 8000
    });

    let parsed;
    try {
      parsed = parseClaudeJson(text);
    } catch (e) {
      console.error('Integrate JSON parse failed:', text.slice(0, 500));
      return res.json({ edits: [] });
    }
    const rawEdits = Array.isArray(parsed) ? parsed : (parsed.edits || []);
    const edits = rawEdits
      .filter(e => e && typeof e.original_text === 'string' && typeof e.suggested_text === 'string')
      .map(e => ({
        original_text: e.original_text,
        suggested_text: e.suggested_text,
        reason: String(e.reason || ''),
        category: 'readout'
      }))
      .filter(e => draft.includes(e.original_text) && e.original_text !== e.suggested_text);

    res.json({ edits });
  } catch (error) {
    console.error('Integrate notes error:', error);
    res.status(500).json({ error: 'Integration failed', details: error.message });
  }
});

// Re-save a reopened draft: new draft_text, edits appended to the audit trail.
// raw_text is never touched; notes stay stored after integration.
app.put('/api/reports/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { draft_text, append_edits, notes_integrated, study_type, study_id_label, report_type, finalized } = req.body;
    if (!draft_text || !draft_text.trim()) {
      return res.status(400).json({ error: 'draft_text is required' });
    }
    const { data: existing, error: exErr } = await supabase
      .from('reports').select('edits_json, draft_text').eq('id', req.params.id).single();
    if (exErr) throw exErr;

    // Snapshot the outgoing draft so "See recent changes" has something to diff
    // against. Skipped when the text is unchanged (metadata-only saves).
    if (existing.draft_text && existing.draft_text !== draft_text) {
      const { error: revErr } = await supabase
        .from('report_revisions')
        .insert({ report_id: req.params.id, draft_text: existing.draft_text });
      if (revErr) console.error('Revision snapshot failed:', revErr.message);
    }

    // 'edited' = the reviewer wrote their own wording; keep it in the trail
    const cleanAppend = (Array.isArray(append_edits) ? append_edits : [])
      .filter(e => e && typeof e.original_text === 'string' && typeof e.suggested_text === 'string')
      .map(e => {
        const status = ['accepted', 'edited'].includes(e.status) ? e.status : 'rejected';
        return {
          original_text: e.original_text,
          suggested_text: e.suggested_text,
          reason: String(e.reason || ''),
          category: String(e.category || 'style'),
          status,
          ...(status === 'edited' ? { user_text: String(e.user_text || '') } : {})
        };
      });

    const update = {
      draft_text,
      edits_json: (existing.edits_json || []).concat(cleanAppend)
    };
    if (typeof study_type === 'string' && study_type.trim()) update.study_type = study_type.trim();
    if (typeof study_id_label === 'string') update.study_id_label = study_id_label.trim() || null;
    if (report_type === 'prelim' || report_type === 'complete') update.report_type = report_type;
    // Only ever set forward — a later plain re-save must not clear the marker
    if (notes_integrated) update.notes_integrated_at = new Date().toISOString();
    // "Save Final" marks it done; a plain "Save Draft" reopens it (clears the mark)
    if (typeof finalized === 'boolean') {
      update.finalized_at = finalized ? new Date().toISOString() : null;
    }

    const { data, error } = await supabase
      .from('reports').update(update).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ report: data });
  } catch (error) {
    console.error('Update report error:', error);
    res.status(500).json({ error: 'Failed to update report', details: error.message });
  }
});

// Record the grade the attending/QA actually assigned. Manual documentation only —
// Flow Dictation never generates or suggests RPR grades.
app.post('/api/reports/:id/grade', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { manual_grade, grade_note } = req.body || {};
    const grade = String(manual_grade || '').toUpperCase().trim();
    if (!VALID_RPR.test(grade)) {
      return res.status(400).json({ error: 'manual_grade must be RPR1–RPR4' });
    }
    const { data, error } = await supabase
      .from('reports')
      .update({
        rpr_grade: grade,
        rpr_note: typeof grade_note === 'string' && grade_note.trim() ? grade_note.trim() : null
      })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ report: data });
  } catch (error) {
    console.error('Grade error:', error);
    res.status(500).json({ error: 'Failed to save grade', details: error.message });
  }
});

// ============ Library CRUD (exemplars, style guide, language) ============

app.get('/api/library/exemplars/counts', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const rows = await fetchAllRows('exemplar_reports', 'study_type, source, created_at');
    const counts = {};
    for (const r of rows) {
      const k = r.study_type || '(untyped)';
      counts[k] = counts[k] || { total: 0, user: 0, parrot: 0 };
      counts[k].total++;
      if (r.source === 'user') counts[k].user++; else counts[k].parrot++;
    }
    res.json({ counts, total: rows.length });
  } catch (error) {
    console.error('Exemplar counts error:', error);
    res.status(500).json({ error: 'Failed to load counts', details: error.message });
  }
});

app.get('/api/library/exemplars', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { query, limit } = req.query;
    let q = supabase
      .from('exemplar_reports')
      .select('id, study_type, title, notes, source, created_at')
      .order('created_at', { ascending: false })
      .limit(Math.min(parseInt(limit, 10) || 50, 200));
    if (query && query.trim()) {
      const like = '%' + query.trim() + '%';
      q = q.or(`study_type.ilike.${like},title.ilike.${like}`);
    }
    const { data, error } = await q;
    if (error) throw error;
    res.json({ exemplars: data });
  } catch (error) {
    console.error('Exemplars list error:', error);
    res.status(500).json({ error: 'Failed to load exemplars', details: error.message });
  }
});

app.get('/api/library/exemplars/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('exemplar_reports').select('*').eq('id', req.params.id).single();
    if (error) throw error;
    res.json({ exemplar: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load exemplar', details: error.message });
  }
});

app.post('/api/library/exemplars', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { study_type, title, body, notes } = req.body;
    if (!body || !body.trim()) return res.status(400).json({ error: 'Report body is required' });

    let finalStudyType = (study_type || '').trim();
    if (!finalStudyType) {
      try { finalStudyType = await detectStudyType(body); } catch (e) { finalStudyType = null; }
    }
    const { data, error } = await supabase
      .from('exemplar_reports')
      .insert({
        study_type: finalStudyType,
        title: (title || '').trim() || (finalStudyType ? finalStudyType + ' exemplar' : 'Exemplar'),
        body,
        notes: (notes || '').trim() || null,
        source: 'user'
      })
      .select()
      .single();
    if (error) throw error;
    invalidateExemplars();
    res.json({ exemplar: data });
  } catch (error) {
    console.error('Exemplar create error:', error);
    res.status(500).json({ error: 'Failed to save exemplar', details: error.message });
  }
});

app.put('/api/library/exemplars/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { study_type, title, body, notes } = req.body;
    const { data, error } = await supabase
      .from('exemplar_reports')
      .update({
        study_type: (study_type || '').trim() || null,
        title: (title || '').trim() || null,
        body,
        notes: (notes || '').trim() || null
      })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    invalidateExemplars();
    res.json({ exemplar: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update exemplar', details: error.message });
  }
});

app.delete('/api/library/exemplars/:id', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { error } = await supabase.from('exemplar_reports').delete().eq('id', req.params.id);
    if (error) throw error;
    invalidateExemplars();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete exemplar', details: error.message });
  }
});

// Generic CRUD for the two simple knowledge tables (both feed the cached prompt block)
function knowledgeCrud(route, table, fields) {
  app.get(`/api/library/${route}`, async (req, res) => {
    if (!requireSupabase(res)) return;
    try {
      const rows = await fetchAllRows(table, 'id, ' + fields.join(', ') + ', created_at');
      res.json({ entries: rows });
    } catch (error) {
      res.status(500).json({ error: `Failed to load ${route}`, details: error.message });
    }
  });

  app.post(`/api/library/${route}`, async (req, res) => {
    if (!requireSupabase(res)) return;
    try {
      const record = {};
      for (const f of fields) {
        const v = (req.body[f] || '').trim();
        if (!v) return res.status(400).json({ error: `${f} is required` });
        record[f] = v;
      }
      const { data, error } = await supabase.from(table).insert(record).select().single();
      if (error) throw error;
      invalidateKnowledge();
      res.json({ entry: data });
    } catch (error) {
      res.status(500).json({ error: `Failed to save`, details: error.message });
    }
  });

  app.put(`/api/library/${route}/:id`, async (req, res) => {
    if (!requireSupabase(res)) return;
    try {
      const record = {};
      for (const f of fields) {
        const v = (req.body[f] || '').trim();
        if (!v) return res.status(400).json({ error: `${f} is required` });
        record[f] = v;
      }
      const { data, error } = await supabase.from(table).update(record).eq('id', req.params.id).select().single();
      if (error) throw error;
      invalidateKnowledge();
      res.json({ entry: data });
    } catch (error) {
      res.status(500).json({ error: `Failed to update`, details: error.message });
    }
  });

  app.delete(`/api/library/${route}/:id`, async (req, res) => {
    if (!requireSupabase(res)) return;
    try {
      const { error } = await supabase.from(table).delete().eq('id', req.params.id);
      if (error) throw error;
      invalidateKnowledge();
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: `Failed to delete`, details: error.message });
    }
  });
}

knowledgeCrud('style-guide', 'style_guide', ['section', 'rule']);
knowledgeCrud('language', 'rad_language', ['category', 'content']);

// ============ Gmail OAuth Routes ============

app.get('/auth/google', (req, res) => {
  const scopes = ['https://www.googleapis.com/auth/gmail.send'];
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent'
  });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  try {
    const { tokens } = await oauth2Client.getToken(code);

    // Sign-in flow: verify the Google identity and check it against the allowlist
    if (state === 'login') {
      if (!tokens.id_token) return res.redirect('/login?error=no_identity');
      const ticket = await oauth2Client.verifyIdToken({
        idToken: tokens.id_token,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      const payload = ticket.getPayload() || {};
      const email = String(payload.email || '').toLowerCase();
      if (!payload.email_verified || !ALLOWED_EMAILS.includes(email)) {
        console.warn(`Denied sign-in for ${email || '(unknown)'}`);
        return res.redirect('/login?error=not_allowed');
      }
      setSessionCookie(res, email);
      console.log(`✅ Signed in: ${email}`);
      return res.redirect('/');
    }

    // Gmail connect flow (separate from sign-in)
    oauth2Client.setCredentials(tokens);
    userTokens = tokens;
    console.log('✅ Gmail OAuth successful');
    res.redirect('/?gmail=connected');
  } catch (error) {
    console.error('OAuth error:', error);
    res.redirect(state === 'login' ? '/login?error=oauth_failed' : '/?gmail=error');
  }
});

app.get('/api/gmail/status', (req, res) => {
  res.json({
    connected: !!userTokens,
    email: userTokens ? 'Connected' : null
  });
});

app.get('/api/gmail/disconnect', (req, res) => {
  userTokens = null;
  oauth2Client.revokeCredentials();
  res.json({ success: true });
});

app.post('/api/gmail/send', async (req, res) => {
  if (!userTokens) {
    return res.status(401).json({ error: 'Gmail not connected. Please connect first.' });
  }
  try {
    const { to, subject, report } = req.body;
    if (!to || !subject || !report) {
      return res.status(400).json({ error: 'Missing required fields: to, subject, report' });
    }
    oauth2Client.setCredentials(userTokens);
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const emailContent = [
      `To: ${to}`,
      `Subject: ${subject}`,
      'Content-Type: text/plain; charset=utf-8',
      '',
      report
    ].join('\n');
    const encodedEmail = Buffer.from(emailContent)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw: encodedEmail }
    });
    console.log(`✅ Email sent to ${to}`);
    res.json({ success: true, message: `Email sent to ${to}` });
  } catch (error) {
    console.error('Email send error:', error);
    if (error.code === 401) {
      userTokens = null;
      return res.status(401).json({ error: 'Gmail session expired. Please reconnect.' });
    }
    res.status(500).json({ error: 'Failed to send email', details: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Flow Dictation API',
    llm: {
      detect: MODEL_DETECT, report: MODEL_REPORT, review: MODEL_REVIEW,
      impression: MODEL_IMPRESSION, radqa: MODEL_RADQA, synthesize: MODEL_SYNTHESIZE,
      chat: MODEL_CHAT,
      fallback: MODEL_FALLBACK
    },
    auth: { google: googleLoginConfigured, password: !!APP_PASSWORD, allowed_emails: ALLOWED_EMAILS.length },
    supabase: supabase ? 'configured' : 'not configured'
  });
});

// Per-task cost read-out. Rows are grouped by model AND label, so the same task
// running on two models (an A/B) shows up as two rows to compare.
// In-process only: it starts empty on every restart and redeploy.
app.get('/api/usage/summary', (req, res) => {
  const rows = [...usageTally.values()].sort((a, b) => b.est_cost - a.est_cost);
  const sum = field => rows.reduce((acc, r) => acc + r[field], 0);
  const round = r => ({ ...r, est_cost: Number(r.est_cost.toFixed(6)) });

  // Same rows rolled up each way, for "which model costs most" vs "which task"
  const rollUp = (keyField) => {
    const m = new Map();
    for (const r of rows) {
      const t = m.get(r[keyField]) || { [keyField]: r[keyField], calls: 0, est_cost: 0 };
      t.calls += r.calls;
      t.est_cost += r.est_cost;
      m.set(r[keyField], t);
    }
    return [...m.values()]
      .sort((a, b) => b.est_cost - a.est_cost)
      .map(t => ({ ...t, est_cost: Number(t.est_cost.toFixed(6)) }));
  };

  res.json({
    since: usageSince,
    pricing_note: `per-MTok list price; cache writes x${CACHE_WRITE_MULTIPLIER} (1h TTL), cache reads x${CACHE_READ_MULTIPLIER}`,
    totals: {
      calls: sum('calls'),
      input_tokens: sum('input_tokens'),
      output_tokens: sum('output_tokens'),
      cache_write_tokens: sum('cache_write_tokens'),
      cache_read_tokens: sum('cache_read_tokens'),
      injected_tokens: sum('injected_tokens'),
      est_cost: Number(sum('est_cost').toFixed(6))
    },
    by_model_and_label: rows.map(round),
    by_model: rollUp('model'),
    by_label: rollUp('label')
  });
});

// One-time backfill: if shifts exist but none is active (first deploy after
// the is_active migration), activate the most recently started one. The SQL
// migration also does this; this covers the case where the code deploys first.
async function backfillActiveShift() {
  if (!supabase) return;
  try {
    const { data: active, error: activeErr } = await supabase
      .from('shifts').select('id').eq('is_active', true).limit(1);
    if (activeErr) throw activeErr;
    if (active && active.length) return;
    const { data: latest, error: latestErr } = await supabase
      .from('shifts').select('id, name').order('started_at', { ascending: false }).limit(1);
    if (latestErr) throw latestErr;
    if (latest && latest.length) {
      await activateShift(latest[0].id);
      console.log(`✅ Backfilled active shift: ${latest[0].name}`);
    }
  } catch (e) {
    // Expected until the is_active migration has been run in Supabase
    console.error('Active shift backfill skipped:', e.message);
  }
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`✨ Claude: ${MODEL_REPORT} (reports), fallback ${MODEL_FALLBACK}`);
  console.log(`🗄️  Supabase: ${supabase ? 'connected' : 'NOT CONFIGURED'}`);
  backfillActiveShift();
});
