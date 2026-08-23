const express = require('express');
const { google } = require('googleapis');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();
const db = require('./db');
const gemini = require('./gemini');
const scrub = require('./scrub');

const app = express();
const PORT = process.env.PORT || 8080;

app.set('trust proxy', 1); // Cloud Run terminates TLS upstream
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

// Vertex AI Gemini — models are env-configurable.
// Detection is a trivial classification that runs on nearly every action —
// Flash-Lite handles it at a fraction of the price of the frontier models.
// Every task routes independently so any one can be A/B'd from a Cloud Run
// variable without touching code. Deliberately NO cross-inheritance: setting
// MODEL_REPORT must not silently drag review or impression along with it.
const MODEL_DETECT = process.env.MODEL_DETECT || 'gemini-2.5-flash-lite';   // study-type classification
const MODEL_REPORT = process.env.MODEL_REPORT || 'gemini-2.5-flash';        // proofread · reword · describe · full report structure
const MODEL_REVIEW = process.env.MODEL_REVIEW || 'gemini-2.5-pro';          // draft review + integrate-notes
const MODEL_IMPRESSION = process.env.MODEL_IMPRESSION || 'gemini-2.5-pro';  // Generate Impression + the full report's impression
// Quick Rad Question is the most token-heavy path — grounded search results
// land in context — so the per-token rate is what decides its cost.
const MODEL_RADQA = process.env.MODEL_RADQA || 'gemini-2.5-pro';            // Quick Rad Question (references on)
const MODEL_CHAT = process.env.MODEL_CHAT || MODEL_RADQA;                   // plain free text (no references)
const MODEL_SYNTHESIZE = process.env.MODEL_SYNTHESIZE || 'gemini-2.5-pro';  // prior report + new info → merged report
const MODEL_SCRUB = process.env.MODEL_SCRUB || 'gemini-2.5-flash-lite';     // PHI scrub model pass (at finalization)

// Postgres (Cloud SQL). db.configured is false only when no connection
// variables are set at all; a wrong password surfaces on the first query.
function requireDb(res) {
  if (!db.configured) {
    res.status(503).json({ error: 'Database not configured. Set INSTANCE_CONNECTION_NAME or PGHOST plus PGUSER/PGPASSWORD/PGDATABASE.' });
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
console.log('Vertex AI:', gemini.PROJECT ? `✓ project=${gemini.PROJECT} location=${gemini.LOCATION}` : '✗ (set GOOGLE_CLOUD_PROJECT)');
console.log('Database:', db.configured ? `✓ ${db.describe()}` : '✗');
console.log('Google Client ID:', !!process.env.GOOGLE_CLIENT_ID ? '✓' : '✗');
console.log('Google Client Secret:', !!process.env.GOOGLE_CLIENT_SECRET ? '✓' : '✗');
console.log('Models:');
console.log(`  detect=${MODEL_DETECT} report=${MODEL_REPORT} review=${MODEL_REVIEW} impression=${MODEL_IMPRESSION} radqa=${MODEL_RADQA}`);
console.log(`  synthesize=${MODEL_SYNTHESIZE} chat=${MODEL_CHAT}`);
console.log('========================');

// ============ Gemini helpers ============

// ============ Cost accounting ============

// Vertex AI US list price per million tokens (standard tier, prompts ≤200k
// tokens). Longest-prefix matched against the model version the API says
// served the request, so a dated snapshot still prices correctly.
const PRICING = {
  'gemini-2.5-pro':        { input: 1.25, output: 10 },
  'gemini-2.5-flash':      { input: 0.30, output: 2.50 },
  'gemini-2.5-flash-lite': { input: 0.10, output: 0.40 }
};
// Implicit cache hits are billed at a quarter of the input rate on Gemini 2.5.
// There are no cache writes to price — implicit caching is free to populate.
const CACHE_READ_MULTIPLIER = 0.25;
// Grounding with Google Search is a flat per-request charge on Vertex AI
// ($35 per 1,000 grounded prompts), billed on top of the tokens.
const GROUNDING_COST_PER_CALL = 0.035;

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

// Dollars for one call, from the usage Gemini returns. promptTokenCount
// includes the cached portion, so cached tokens are rebated down to the
// cache-read rate rather than added. Thinking tokens bill as output.
function costFor(model, u, grounded) {
  const p = priceFor(model);
  if (!p) return 0;
  const prompt = u.prompt_tokens || 0;
  const cached = Math.min(u.cached_tokens || 0, prompt);
  const tool = u.tool_prompt_tokens || 0;
  const out = (u.output_tokens || 0) + (u.thought_tokens || 0);
  return (
    (prompt - cached) * p.input +
    cached * p.input * CACHE_READ_MULTIPLIER +
    tool * p.input +
    out * p.output
  ) / 1e6 + (grounded ? GROUNDING_COST_PER_CALL : 0);
}

// In-process tally, keyed by model AND label so per-task cost is visible.
// Resets on restart/redeploy — this is a live read-out, not a ledger.
const usageTally = new Map();   // "<model>|<label>" -> totals
let usageSince = new Date().toISOString();

// Returns the call's cost so the caller can log it.
function recordUsage({ model, label, usage, injected, grounded }) {
  const u = usage || {};
  const cost = costFor(model, u, grounded);
  const key = `${model || 'unknown'}|${label || 'unlabelled'}`;
  const t = usageTally.get(key) || {
    model: model || 'unknown', label: label || 'unlabelled',
    calls: 0, grounded_calls: 0, input_tokens: 0, output_tokens: 0, thought_tokens: 0,
    cache_read_tokens: 0, tool_prompt_tokens: 0, injected_tokens: 0, est_cost: 0
  };
  t.calls += 1;
  if (grounded) t.grounded_calls += 1;
  t.input_tokens += u.prompt_tokens || 0;
  t.output_tokens += u.output_tokens || 0;
  t.thought_tokens += u.thought_tokens || 0;
  t.cache_read_tokens += u.cached_tokens || 0;
  t.tool_prompt_tokens += u.tool_prompt_tokens || 0;
  t.injected_tokens += injected || 0;
  t.est_cost += cost;
  usageTally.set(key, t);
  return cost;
}

const usd = n => '$' + n.toFixed(4);

// Only IDs and counts ever reach the logs — never prompt or answer text.
function logCall({ served, label, injected, u, cost, grounded, finishReason }) {
  console.log(`[gemini] ${served} label=${label || '-'}${grounded ? ' grounded' : ''} injected=${injected || 0} in=${u.prompt_tokens} cached=${u.cached_tokens} tool=${u.tool_prompt_tokens} out=${u.output_tokens} thoughts=${u.thought_tokens} est_cost=${usd(cost)} finish=${finishReason}`);
}

// Conversation history for Gemini: the assistant's turns are role "model".
function toContents(messages) {
  return messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }]
  }));
}

// One text completion. `system` is a string; `messages` (or a single
// `message`) become the contents. `schema` switches on JSON mode with that
// response schema. A safety block throws an error with isRefusal=true.
async function geminiText({ model, system, message, messages, maxTokens, effort, injected, label, schema }) {
  const contents = toContents(messages || [{ role: 'user', content: message }]);
  const r = await gemini.generate({ model, system, contents, maxTokens, effort, responseSchema: schema });
  const cost = recordUsage({ model: r.served, label, usage: r.usage, injected });
  logCall({ served: r.served, label, injected, u: r.usage, cost, finishReason: r.finishReason });
  return r.text.trim();
}

// Gemini's JSON mode returns bare JSON, but strip markdown fences defensively.
function parseModelJson(text) {
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

// Response schemas for the structured calls — Gemini's JSON mode guarantees
// the shape, so the prompts' "JSON only" instructions become belt-and-braces.
// These mirror exactly what the frontend consumes.
const STUDY_TYPE_SCHEMA = {
  type: 'OBJECT',
  properties: { study_type: { type: 'STRING' } },
  required: ['study_type']
};
const DESCRIBE_SCHEMA = {
  type: 'OBJECT',
  properties: { findings: { type: 'STRING' }, impression: { type: 'STRING' } },
  required: ['findings', 'impression']
};
const editsSchema = categories => ({
  type: 'OBJECT',
  properties: {
    edits: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          original_text: { type: 'STRING' },
          suggested_text: { type: 'STRING' },
          reason: { type: 'STRING' },
          category: { type: 'STRING', enum: categories }
        },
        required: ['original_text', 'suggested_text', 'reason', 'category']
      }
    }
  },
  required: ['edits']
});
const REVIEW_EDITS_SCHEMA = editsSchema(['typo', 'style']);
const READOUT_EDITS_SCHEMA = editsSchema(['readout']);

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

// Appended only when the "Include references" toggle is on (Google Search
// grounding attached). Grounding has no domain allowlist, so the preferred
// sources are steered from the prompt instead; and the model never sees the
// URLs of what it retrieved, so the References line is written by the server
// from the grounding metadata rather than by the model.
const REFERENCES_ADDENDUM = `You have Google Search available and the user has explicitly asked for a sourced answer, so search before you answer even when you already know the answer cold, and even when the question repeats one you just answered — being sure is not the same as being able to cite. The one exception is text work: rewording, proofreading, impressions and report generation need no references, so do not search for those.

Radiopaedia (radiopaedia.org) is the preferred source: search it first and draw on the relevant Radiopaedia article whenever one exists. Use other sources only when they cover something Radiopaedia does not — ACR Appropriateness Criteria (acr.org) for protocol/appropriateness questions, RadioGraphics and Radiology (pubs.rsna.org) for in-depth reviews, Radiology Assistant (radiologyassistant.nl) for pattern-based teaching. Prefer these over forums, commercial sites, and general medical portals.

Do NOT write a 'References' section or any URLs yourself: the sources you actually used are attached to your answer automatically, with their links. Just answer the question.`;

function buildFreeformSystem(searchEnabled, knowledgeBlock) {
  let s = FREEFORM_SYSTEM;
  if (searchEnabled) s += '\n\n' + REFERENCES_ADDENDUM;
  if (knowledgeBlock) s += knowledgeBlock;
  return s;
}

// Answers cite at most this many sources — enforced in what the server
// appends, and again when the client renders a fallback list.
const MAX_REFERENCES = 3;

// Which grounded sources to surface, in order: the radiology references the
// old domain allowlist named, then anything else the answer actually drew on.
const PREFERRED_SOURCES = [
  'radiopaedia.org',
  'radiologyassistant.nl',
  'acsearch.acr.org',        // ACR Appropriateness Criteria
  'acr.org',
  'pubs.rsna.org',           // RadioGraphics, Radiology
  'ajronline.org',
  'statdx.com',
  'radiology.wisc.edu'
];
function sourceRank(url) {
  const i = PREFERRED_SOURCES.findIndex(d => url.includes(d));
  return i === -1 ? PREFERRED_SOURCES.length : i;
}

const VALID_RPR = /^RPR[1-4]$/;

// ---- Report ids ----
// Random, non-identifying: "R-" + 6 chars of A-Z2-9 (no 0/O/1/I). Nothing
// about when a study was read can be recovered from its id; created_at stays
// the ordering/shift-grouping mechanism.
const REPORT_ID_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // 32 chars
const REPORT_ID_RE = /^R-[A-Z2-9]{6}$/;
function randomReportId() {
  // 256 % 32 === 0, so a byte modulo 32 is unbiased
  return 'R-' + [...crypto.randomBytes(6)].map(b => REPORT_ID_ALPHABET[b % 32]).join('');
}

// ---- PHI scrub (see scrub.js) ----
// Pattern pass + one model pass over all of a report's texts together, so the
// same name found anywhere is replaced everywhere. Model failures degrade to
// the pattern pass alone — the caller decides what that means for scrubbed_at.
async function modelFindPhi(text) {
  const out = await geminiText({
    model: MODEL_SCRUB,
    label: 'scrub',
    system: scrub.SCRUB_SYSTEM,
    message: text,
    // A date-heavy multi-document input can produce a long replacement list;
    // too low a ceiling truncates the JSON mid-string
    maxTokens: 8000,
    effort: 'low',
    schema: scrub.SCRUB_SCHEMA
  });
  const parsed = parseModelJson(out);
  return Array.isArray(parsed.replacements) ? parsed.replacements : [];
}

// texts: {key: string|null|undefined}. Returns {texts, replacements, counts,
// modelOk, modelApplied} — counts by TYPE only; matched text is never logged.
async function scrubTexts(texts) {
  const counts = {};
  const out = {};
  for (const [k, v] of Object.entries(texts)) {
    if (typeof v !== 'string' || !v) { out[k] = v; continue; }
    const r = scrub.patternScrub(v);
    out[k] = r.text;
    for (const [t, n] of Object.entries(r.counts)) counts[t] = (counts[t] || 0) + n;
  }
  let modelOk = true;
  let modelApplied = 0;
  let replacements = [];
  const joined = Object.values(out).filter(t => typeof t === 'string' && t.trim()).join('\n\n----- NEXT DOCUMENT -----\n\n');
  if (joined.trim()) {
    try {
      replacements = await modelFindPhi(joined);
      for (const k of Object.keys(out)) {
        if (typeof out[k] !== 'string' || !out[k]) continue;
        const r = scrub.applyReplacements(out[k], replacements);
        out[k] = r.text;
        modelApplied += r.applied;
      }
    } catch (e) {
      modelOk = false;
      console.warn(`[scrub] model pass failed — pattern pass only: ${e.message}`);
    }
  }
  return { texts: out, replacements, counts, modelOk, modelApplied };
}

// The audit trail quotes report text, so it is scrubbed with the same passes
function scrubEditsJson(edits, replacements) {
  return (Array.isArray(edits) ? edits : []).map(e => {
    if (!e || typeof e !== 'object') return e;
    const clean = { ...e };
    for (const f of ['original_text', 'suggested_text', 'user_text', 'reason']) {
      if (typeof clean[f] === 'string' && clean[f]) {
        clean[f] = scrub.applyReplacements(scrub.patternScrub(clean[f]).text, replacements).text;
      }
    }
    return clean;
  });
}

// ---- Sections (subspecialties) ----
// Manual only, set once per shift: the shift carries the current section
// (shifts.subspecialty) and every report save stamps it onto the report at
// that moment. reports.subspecialty stays the source of truth for filtering —
// the stamp is written once, so changing the shift mid-way never rewrites
// earlier cases. Writers of the report column: the save-time stamp and the
// bulk action. Nothing derives, maps, or backfills; no shift section = null.
const STANDARD_SECTIONS = [
  'Neuroradiology',
  'Musculoskeletal Radiology',
  'Body / Abdominal Imaging',
  'Cardiothoracic Radiology',
  'Breast Imaging',
  'Pediatric Radiology',
  'Nuclear Radiology',
  'Interventional Radiology',
  'On-Call'
];
// Free text from the "Other" path is stored verbatim (trimmed); ''/absent -> null
function cleanSubspecialty(v) {
  if (typeof v !== 'string') return null;
  return v.trim().slice(0, 120) || null;
}

// The value a save stamps: the shift's section AT THIS MOMENT. Read fresh on
// every save rather than trusted from the client, so two devices on one shift
// can never stamp different values than the shift shows.
async function shiftSubspecialty(shiftId) {
  if (!shiftId) return null;
  try {
    const row = await db.one(`select subspecialty from shifts where id = $1`, [shiftId]);
    return row ? (row.subspecialty || null) : null;
  } catch (error) {
    console.error('Shift section lookup failed:', error.message);
    return null;   // a failed lookup must not block the save — stamp null
  }
}

// ============ Knowledge layer (style guide, language library, exemplars) ============

// Rough size estimate at ~4 chars/token. Used only to compare injected payloads
// between actions and to budget conversation history — never for billing.
function estimateTokens(text) {
  return Math.ceil((text || '').length / 4);
}

// Gemini caches prompt prefixes implicitly, so the static block is kept
// byte-identical across requests (memoised below) and placed first in the
// system instruction — that is all the cache needs; there is no TTL to manage.

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

// Every row of a knowledge table, oldest first. Table and column names come
// from code constants only (never from a request), so they are interpolated;
// the allowlist keeps that true.
const KNOWLEDGE_TABLES = new Set(['style_guide', 'rad_language', 'exemplar_reports', 'reports']);
async function fetchAllRows(table, columns) {
  if (!KNOWLEDGE_TABLES.has(table)) throw new Error(`fetchAllRows: unexpected table ${table}`);
  return db.many(`select ${columns} from ${table} order by created_at asc`);
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
  if (!db.configured) return '';
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
  if (!db.configured || limit <= 0) return [];
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
  // ILIKE with no wildcard is a case-insensitive equality match on the study
  // type; the modality fallback adds its own trailing wildcard.
  try {
    if (studyType && studyType.trim()) {
      const st = studyType.trim();
      add(await db.many(
        `select ${EXEMPLAR_COLS} from exemplar_reports where study_type ilike $1 and source = 'user' limit $2`,
        [st, limit]));
      if (chosen.length < limit) {
        add(await db.many(
          `select ${EXEMPLAR_COLS} from exemplar_reports where study_type ilike $1 and source <> 'user' limit $2`,
          [st, limit]));
      }
      if (chosen.length === 0) {
        const modality = st.split(/\s+/)[0];
        if (modality) {
          add(await db.many(
            `select ${EXEMPLAR_COLS} from exemplar_reports where study_type ilike $1 order by source desc limit $2`,
            [modality + ' %', limit]));
        }
      }
    }
    if (chosen.length === 0) {
      add(await db.many(
        `select ${EXEMPLAR_COLS} from exemplar_reports order by source desc limit $1`, [limit]));
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
  if (!db.configured || limit <= 0) return [];
  const cacheKey = limit + ':' + (studyType || '').trim().toLowerCase();
  const hit = impressionExemplarCache.get(cacheKey);
  if (hit && Date.now() - hit.loadedAt < KNOWLEDGE_TTL_MS) return hit.rows;
  let rows = [];
  try {
    const sql = `select study_type, impression from report_sections
                 where impression is not null and study_type ilike $1
                 order by created_at desc limit $2`;
    const st = (studyType || '').trim();
    if (st) {
      rows = await db.many(sql, [st, limit]);
      if (rows.length === 0) {
        const modality = st.split(/\s+/)[0];
        if (modality) rows = await db.many(sql, [modality + '%', limit]);
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

// System instruction: static block first (identical bytes every call, so the
// implicit cache can hit on it), then the exemplar block that varies by study
// type. Returns the injected token estimate for logging.
async function buildKnowledgeSystem(baseSystem, studyType, profileKey) {
  const profile = profileFor(profileKey);
  // Independent lookups — fetched together, not one after the other
  const [knowledge, exText] = await Promise.all([
    getKnowledgeBlock(profileKey),
    buildExemplarText(studyType, profile)
  ]);
  return { system: baseSystem + knowledge + exText, injected: estimateTokens(knowledge) + estimateTokens(exText) };
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
  const impression = (await geminiText({
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
  const systemFor = (searchOn) => buildFreeformSystem(searchOn, knowledgeBlock) + exemplarText;
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
  // Quick Rad Question (references on) and plain free text are the same prompt
  // but route separately, so each can be tuned without moving the other.
  const model = useRefs ? MODEL_RADQA : MODEL_CHAT;
  let searchEnabled = useRefs;
  let refsDropped = false;
  const contents = toContents(messages);

  let r;
  for (;;) {
    try {
      r = await gemini.generate({
        model,
        // Referenced answers run long — too low a ceiling truncates them.
        maxTokens: 8000,
        system: systemFor(searchEnabled),
        contents,
        effort: FREEFORM_EFFORT,
        grounding: searchEnabled
      });
      break;
    } catch (e) {
      // Safety classifiers occasionally decline benign radiology questions
      // (bone/soft-tissue tumors especially), usually only once search results
      // are in context. Degrade once: answer from knowledge, without search.
      if (e.isRefusal && searchEnabled) {
        console.warn(`⚠ [refusal] ${model} declined a grounded question (${e.detail}) — retrying without search`);
        searchEnabled = false;
        refsDropped = true;
        continue;
      }
      if (e.isRefusal) throw new Error('This question was declined by the model’s safety filters. Try rephrasing it.');
      throw e;
    }
  }

  const freeformLabel = label || (searchEnabled ? 'radqa' : 'freeform');
  const cost = recordUsage({ model: r.served, label: freeformLabel, usage: r.usage, injected, grounded: searchEnabled });
  logCall({ served: r.served, label: freeformLabel, injected, u: r.usage, cost, grounded: searchEnabled, finishReason: r.finishReason });

  // The model never sees the URLs of what it retrieved, so the References
  // line is the server's to write: preferred radiology sources first, then by
  // how much of the answer drew on each, capped — a wall of links buries the
  // one worth opening. The client renders the same line as links.
  let text = r.text.trim();
  let citations = [];
  if (searchEnabled) {
    citations = (await gemini.citationsFrom(r.grounding))
      .sort((a, b) => sourceRank(a.url) - sourceRank(b.url))
      .slice(0, MAX_REFERENCES)
      .map(c => ({ url: c.url, title: c.title }));
    if (citations.length) {
      text += '\n\nReferences:\n' +
        citations.map(c => c.url + (c.title && c.title !== c.url ? ' — ' + c.title : '')).join('\n');
    }
  }
  return {
    text,
    citations,
    refs_dropped: refsDropped,
    truncated: r.finishReason === 'MAX_TOKENS'
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
    let text = await geminiText({
      model: ACTION_MODEL[action] || MODEL_REPORT,
      label: action,
      system,
      injected,
      messages,
      maxTokens: action === 'synthesize' ? 8000 : 4000,
      effort: ACTION_EFFORT[action],
      schema: action === 'describe' ? DESCRIBE_SCHEMA : undefined
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
        const parsed = parseModelJson(text);
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
    console.error('Assist error:', error.message);
    res.status(500).json({ error: 'Assist request failed', details: error.message });
  }
});

app.post('/api/assist/feedback', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { action_type, user_input, model_response, rating, comment } = req.body;
    if (rating !== 'up' && rating !== 'down') {
      return res.status(400).json({ error: 'rating must be "up" or "down"' });
    }
    await db.query(
      `insert into assist_feedback (action_type, user_input, model_response, rating, comment)
       values ($1, $2, $3, $4, $5)`,
      [action_type || 'freeform', user_input || '', model_response || '', rating, comment || null]);
    res.json({ success: true });
  } catch (error) {
    console.error('Feedback error:', error.message);
    res.status(500).json({ error: 'Failed to save feedback', details: error.message });
  }
});

// ============ Assist chat history (persistent, cross-device) ============

// Last N messages, returned oldest-first for rendering. History lives in
// Supabase so it follows the login across browsers/computers and is never
// cleared by the app.
app.get('/api/assist/messages', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 300, 1000);
    const rows = await db.many(
      `select id, role, content, action_type, created_at from assist_messages order by id desc limit $1`,
      [limit]);
    res.json({ messages: rows.reverse() });
  } catch (error) {
    console.error('Assist history error:', error.message);
    res.status(500).json({ error: 'Failed to load chat history', details: error.message });
  }
});

// Save one user+assistant exchange. Array insert preserves order, so the
// identity ids keep the pair in sequence.
app.post('/api/assist/messages', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { user_text, assistant_text, action_type } = req.body;
    if (!user_text || !assistant_text) {
      return res.status(400).json({ error: 'user_text and assistant_text are required' });
    }
    const at = action_type || 'freeform';
    // One statement, two rows, in order — the identity ids keep the pair in sequence
    await db.query(
      `insert into assist_messages (role, content, action_type)
       values ('user', $1, $3), ('assistant', $2, $3)`,
      [user_text, assistant_text, at]);
    res.json({ success: true });
  } catch (error) {
    console.error('Assist history save error:', error.message);
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

    const text = await geminiText({
      model: MODEL_REVIEW,
      label: 'review',
      system,
      injected,
      message: `Review this radiology report draft:\n\n${report}`,
      maxTokens: 8000,
      effort: DRAFT_REVIEW_EFFORT,
      schema: REVIEW_EDITS_SCHEMA
    });

    let parsed;
    try {
      parsed = parseModelJson(text);
    } catch (e) {
      // Never log the payload — it quotes the report
      console.error(`Review JSON parse failed (${text.length} chars): ${e.message}`);
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
    console.error('Draft review error:', error.message);
    res.status(500).json({ error: 'Review failed', details: error.message });
  }
});

async function detectStudyType(report) {
  const text = await geminiText({
    model: MODEL_DETECT,
    label: 'detect',
    system: STUDY_TYPE_SYSTEM,
    message: `Identify the study type of this radiology report:\n\n${report.slice(0, 4000)}`,
    maxTokens: 100,
    effort: 'low',
    schema: STUDY_TYPE_SCHEMA
  });
  const parsed = parseModelJson(text);
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
    console.error('Study type detection error:', error.message);
    res.status(500).json({ error: 'Detection failed', details: error.message });
  }
});

app.get('/api/study-types', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const rows = await db.many(
      `select id, name, last_used_at from study_types order by last_used_at desc limit 200`);
    res.json({ study_types: rows });
  } catch (error) {
    console.error('Study types error:', error.message);
    res.status(500).json({ error: 'Failed to load study types', details: error.message });
  }
});

async function touchStudyType(name) {
  const existing = await db.one(`select id from study_types where name ilike $1 limit 1`, [name]);
  if (existing) {
    await db.query(`update study_types set last_used_at = $2 where id = $1`, [existing.id, new Date().toISOString()]);
  } else {
    await db.query(`insert into study_types (name, last_used_at) values ($1, $2)`, [name, new Date().toISOString()]);
  }
}

// ============ Shifts ============

app.get('/api/shifts', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const rows = await db.many(`select * from shifts order by started_at desc`);
    res.json({ shifts: rows });
  } catch (error) {
    console.error('Shifts error:', error.message);
    res.status(500).json({ error: 'Failed to load shifts', details: error.message });
  }
});

// The active shift is server state, so every browser/device agrees on it.
// Deactivate-then-activate runs in one transaction, and the one_active_shift
// partial unique index makes two active shifts impossible regardless.
// Throws NOT_FOUND when no shift has that id.
async function activateShift(id) {
  return db.tx(async client => {
    await client.query(`update shifts set is_active = false where is_active and id <> $1`, [id]);
    const { rows } = await client.query(`update shifts set is_active = true where id = $1 returning *`, [id]);
    if (!rows.length) {
      const err = new Error('Shift not found');
      err.code = 'NOT_FOUND';
      throw err;
    }
    return rows[0];
  });
}

app.get('/api/shifts/active', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const shift = await db.one(`select * from shifts where is_active limit 1`);
    res.json({ shift });
  } catch (error) {
    console.error('Active shift error:', error.message);
    res.status(500).json({ error: 'Failed to load active shift', details: error.message });
  }
});

app.post('/api/shifts', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Shift name is required' });
    }
    // The section stays from shift to shift unless the user changes it. The
    // dialog always sends an explicit value (null = deliberately cleared);
    // a create that never mentions subspecialty — the auto-created shift on a
    // first save — inherits the most recent shift's section.
    let subspecialty;
    if ('subspecialty' in req.body) {
      subspecialty = cleanSubspecialty(req.body.subspecialty);
    } else {
      const prev = await db.one(`select subspecialty from shifts order by started_at desc limit 1`);
      subspecialty = (prev && prev.subspecialty) || null;
    }
    const now = new Date().toISOString();
    const created = await db.one(
      `insert into shifts (name, subspecialty, started_at, last_activity_at) values ($1, $2, $3, $3) returning *`,
      [name.trim(), subspecialty, now]);
    // A newly started shift is always the active one
    const shift = await activateShift(created.id);
    res.json({ shift });
  } catch (error) {
    console.error('Create shift error:', error.message);
    res.status(500).json({ error: 'Failed to create shift', details: error.message });
  }
});

// Change a shift's section. Affects FUTURE saves only — reports already
// stamped keep their value (the bulk action below is the way to correct a
// whole shift after the fact).
app.put('/api/shifts/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const shift = await db.one(
      `update shifts set subspecialty = $2 where id = $1 returning *`,
      [req.params.id, cleanSubspecialty(req.body && req.body.subspecialty)]);
    if (!shift) return res.status(404).json({ error: 'Shift not found' });
    res.json({ shift });
  } catch (error) {
    console.error('Update shift error:', error.message);
    res.status(500).json({ error: 'Failed to update shift', details: error.message });
  }
});

// Bulk-assign a section to every report in a shift — whole shifts are usually
// a single section. Passing null/empty clears it. The already-written
// report_sections rows are kept in step so the training export never disagrees
// with the reports table.
app.post('/api/shifts/:id/set-subspecialty', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const value = cleanSubspecialty(req.body && req.body.subspecialty);
    // All three writes in one transaction — a half-update would drift
    const updated = await db.tx(async client => {
      const { rows } = await client.query(
        `update reports set subspecialty = $2 where shift_id = $1 returning id`, [req.params.id, value]);
      const ids = rows.map(r => r.id);
      if (ids.length) {
        await client.query(
          `update report_sections set subspecialty = $2 where report_id = any($1::text[])`, [ids, value]);
      }
      // The shift carries the setting going forward too, so future saves in this
      // shift stamp the corrected value
      await client.query(`update shifts set subspecialty = $2 where id = $1`, [req.params.id, value]);
      return ids.length;
    });
    res.json({ subspecialty: value, updated });
  } catch (error) {
    console.error('Set shift subspecialty error:', error.message);
    res.status(500).json({ error: 'Failed to set section for shift', details: error.message });
  }
});

// Custom section names previously typed via "Other", most recently used first —
// these become selectable options on future drafts. Derived by reading reports,
// so it never writes anything and stays in step with what was actually saved.
app.get('/api/subspecialties', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    // Shifts are included so a custom section chosen for a brand-new shift is
    // offered again before its first report ever saves
    const [reps, shs] = await Promise.all([
      db.many(`select subspecialty, created_at from reports where subspecialty is not null
               order by created_at desc limit 500`),
      db.many(`select subspecialty, started_at from shifts where subspecialty is not null
               order by started_at desc limit 200`)
    ]);
    const rows = [
      ...reps.map(r => ({ v: r.subspecialty, t: r.created_at })),
      ...shs.map(r => ({ v: r.subspecialty, t: r.started_at }))
    ].sort((a, b) => (a.t < b.t ? 1 : -1));
    const seen = new Set(STANDARD_SECTIONS.map(x => x.toLowerCase()));
    const custom = [];
    for (const r of rows) {
      const v = (r.v || '').trim();
      if (!v || seen.has(v.toLowerCase())) continue;
      seen.add(v.toLowerCase());
      custom.push(v);
    }
    res.json({ standard: STANDARD_SECTIONS, custom });
  } catch (error) {
    console.error('Subspecialties list error:', error);
    res.status(500).json({ error: 'Failed to load sections', details: error.message });
  }
});

// Delete a shift — empty shifts only (the accidental-duplicate case). Reports
// reference shifts by FK, so this is also the only deletion that could succeed.
app.delete('/api/shifts/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { count } = await db.one(
      `select count(*)::int as count from reports where shift_id = $1`, [req.params.id]);
    if (count > 0) {
      return res.status(400).json({
        error: `Shift has ${count} report${count === 1 ? '' : 's'} — only empty shifts can be deleted`
      });
    }
    const deleted = await db.one(`delete from shifts where id = $1 returning *`, [req.params.id]);
    if (!deleted) {
      return res.status(404).json({ error: 'Shift not found' });
    }
    // Deleting the active shift promotes the most recent remaining one
    if (deleted.is_active) {
      const latest = await db.one(`select id from shifts order by started_at desc limit 1`);
      if (latest) await activateShift(latest.id);
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Delete shift error:', error.message);
    res.status(500).json({ error: 'Failed to delete shift', details: error.message });
  }
});

// Manually switch the active shift (e.g. resuming an older shift)
app.put('/api/shifts/:id/activate', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const shift = await activateShift(req.params.id);
    res.json({ shift });
  } catch (error) {
    if (error.code === 'NOT_FOUND') {
      return res.status(404).json({ error: 'Shift not found' });
    }
    console.error('Activate shift error:', error.message);
    res.status(500).json({ error: 'Failed to activate shift', details: error.message });
  }
});

// ============ Reports ============

app.post('/api/reports', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { shift_id, study_type, study_id_label, report_type, raw_text, draft_text, edits_json, finalized } = req.body;
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

    // Random id; regenerate on the (1-in-a-billion) collision
    let id;
    do { id = randomReportId(); } while (await db.one(`select 1 from reports where id = $1`, [id]));

    const now = new Date().toISOString();
    const report = await db.one(
      `insert into reports (id, shift_id, study_type, study_id_label, subspecialty, report_type, raw_text,
                            draft_text, edits_json, created_at, finalized_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11) returning *`,
      [
        id,
        shift_id,
        finalStudyType,
        (study_id_label || '').trim() || null,
        // Stamped from the shift, not the request — see shiftSubspecialty()
        await shiftSubspecialty(shift_id),
        report_type === 'prelim' ? 'prelim' : 'complete',
        raw_text,
        draft_text || raw_text,
        JSON.stringify(edits_json || []),
        now,
        finalized ? now : null
      ]);

    // last_activity_at drives the 4-hour shift check only
    await db.query(`update shifts set last_activity_at = $2 where id = $1`, [shift_id, now]);

    res.json({ report });
  } catch (error) {
    console.error('Save report error:', error.message);
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
  if (!requireDb(res)) return;
  try {
    // Filters combine (Review page): any subset of shift, grade, study type, and
    // a keyword/phrase search of the report text. This only ever searches the
    // user's own drafted reports — PARROT exemplars live in exemplar_reports
    // and cannot appear here.
    const { shift_id, grade, study_type, q } = req.query;
    const terms = parseSearchTerms((q || '').trim());
    const LIST_COLUMNS = 'id, shift_id, study_type, study_id_label, subspecialty, report_type, created_at, final_saved_at, rpr_grade, rpr_note, readout_notes, notes_integrated_at, read_out_at, finalized_at';
    // Searching needs the text columns to build snippets; they are stripped
    // from the response below rather than shipped to the browser
    const columns = terms.length ? LIST_COLUMNS + ', raw_text, draft_text, final_text' : LIST_COLUMNS;
    const where = [];
    const params = [];
    const param = v => { params.push(v); return '$' + params.length; };
    if (shift_id) where.push(`shift_id = ${param(shift_id)}`);
    if (grade === 'ungraded') where.push('rpr_grade is null');
    // Same precedence as before: a section filter takes the place of a graded
    // filter in this else-chain
    const wantSection = (req.query.subspecialty || '').trim();
    if (wantSection === 'unassigned') where.push('subspecialty is null');
    else if (wantSection) where.push(`subspecialty = ${param(wantSection)}`);
    else if (VALID_RPR.test(grade || '')) where.push(`rpr_grade = ${param(grade)}`);
    if (study_type && study_type.trim()) where.push(`study_type ilike ${param('%' + study_type.trim() + '%')}`);
    // Each term is its own OR across the searchable columns; the terms are
    // ANDed, so every term must match somewhere in the report.
    for (const term of terms) {
      const p = param('%' + escapeLike(term) + '%');
      where.push('(' + SEARCH_COLUMNS.map(c => `${c} ilike ${p}`).join(' or ') + ')');
    }
    const rows = await db.many(
      `select ${columns} from reports${where.length ? ' where ' + where.join(' and ') : ''} order by created_at desc`,
      params);

    const reports = terms.length
      ? rows.map(row => {
          const { raw_text, draft_text, final_text, ...rest } = row;
          return { ...rest, snippet: buildSnippet(row, terms) };
        })
      : rows;
    res.json({ reports, terms });
  } catch (error) {
    console.error('List reports error:', error.message);
    res.status(500).json({ error: 'Failed to load reports', details: error.message });
  }
});

app.get('/api/reports/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const report = await db.one(`select * from reports where id = $1`, [req.params.id]);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report });
  } catch (error) {
    console.error('Get report error:', error.message);
    res.status(500).json({ error: 'Failed to load report', details: error.message });
  }
});

app.put('/api/reports/:id/final', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { final_text } = req.body;
    if (!final_text || !final_text.trim()) {
      return res.status(400).json({ error: 'final_text is required' });
    }
    const existing = await db.one(`select * from reports where id = $1`, [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Report not found' });

    // Finalization is THE de-identification trigger: scrub every stored text
    // for this report and drop its study id, in one transaction with the
    // final. A report already scrubbed only needs the incoming final scrubbed.
    // The scrub can degrade (model pass fails -> pattern pass only,
    // scrubbed_at stays null so a later save retries) but never blocks.
    const revisions = existing.scrubbed_at
      ? []
      : await db.many(`select id, draft_text from report_revisions where report_id = $1`, [req.params.id]);
    const input = existing.scrubbed_at
      ? { final_text }
      : {
          final_text,
          raw_text: existing.raw_text,
          draft_text: existing.draft_text,
          readout_notes: existing.readout_notes,
          ...Object.fromEntries(revisions.map(r => ['rev_' + r.id, r.draft_text]))
        };
    const s = await scrubTexts(input);
    const now = new Date().toISOString();

    const report = await db.tx(async client => {
      const sets = [`final_text = $2`, `final_saved_at = $3`, `study_id_label = null`,
                    `scrubbed_at = ${s.modelOk ? '$3' : (existing.scrubbed_at ? 'scrubbed_at' : 'null')}`];
      const params = [req.params.id, s.texts.final_text, now];
      if (!existing.scrubbed_at) {
        params.push(s.texts.raw_text, s.texts.draft_text, s.texts.readout_notes,
                    JSON.stringify(scrubEditsJson(existing.edits_json, s.replacements)));
        sets.push(`raw_text = $4`, `draft_text = $5`, `readout_notes = $6`, `edits_json = $7::jsonb`);
      }
      const { rows } = await client.query(
        `update reports set ${sets.join(', ')} where id = $1 returning *`, params);
      for (const rev of revisions) {
        await client.query(`update report_revisions set draft_text = $2 where id = $1`,
          [rev.id, s.texts['rev_' + rev.id]]);
      }
      return rows[0];
    });
    // Counts by type only — never the matched text
    console.log(`[scrub] report=${report.id} pattern=${JSON.stringify(s.counts)} model_applied=${s.modelApplied} model_ok=${s.modelOk}`);

    // Harvest the findings/impression pair for training (from the scrubbed
    // final, so the mirror is clean by construction). Never block the save.
    let sections = { stored: false, reason: 'not attempted' };
    try {
      sections = await saveReportSections(report, 'final');
    } catch (e) {
      console.error('Section extraction failed:', e.message);
      sections = { stored: false, reason: e.message };
    }
    res.json({ report, sections });
  } catch (error) {
    console.error('Save final error:', error.message);
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
  // Re-saving a final refreshes its row (unique on report_id, source)
  await db.query(
    `insert into report_sections (report_id, source, study_type, subspecialty, full_text, findings, impression, updated_at)
     values ($1, $2, $3, $4, $5, $6, $7, $8)
     on conflict (report_id, source) do update set
       study_type = excluded.study_type,
       subspecialty = excluded.subspecialty,
       full_text = excluded.full_text,
       findings = excluded.findings,
       impression = excluded.impression,
       updated_at = excluded.updated_at`,
    [report.id, source, report.study_type || null, report.subspecialty || null, parts.full_text,
     parts.findings, parts.impression, new Date().toISOString()]);
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
  if (!requireDb(res)) return;
  try {
    const { study_type, format } = req.query;
    const where = [];
    const params = [];
    if (study_type && study_type.trim()) {
      params.push('%' + study_type.trim() + '%');
      where.push(`study_type ilike $${params.length}`);
    }
    // Training reads complete pairs by default; ?include_partial=true returns
    // impression-only prelims and unparsed reports as well.
    if (req.query.include_partial !== 'true') {
      where.push('findings is not null', 'impression is not null');
    }
    params.push(Math.min(parseInt(req.query.limit, 10) || 1000, 5000));
    const rows = await db.many(
      `select s.report_id, s.source, s.study_type, s.full_text, s.findings, s.impression, s.created_at,
              r.scrubbed_at
       from report_sections s left join reports r on r.id = s.report_id
       ${where.length ? ' where ' + where.map(w => 's.' + w).join(' and ') : ''}
       order by s.created_at desc limit $${params.length}`,
      params);

    // Export safety net: anything not yet scrubbed in storage is scrubbed
    // IN THE OUTPUT (the stored row is not touched — it may still be worked
    // on); and no export carries a precise service date, only the year.
    const out = [];
    for (const row of rows) {
      let { full_text, findings, impression } = row;
      if (!row.scrubbed_at) {
        const s = await scrubTexts({ full_text, findings, impression });
        ({ full_text, findings, impression } = s.texts);
        console.log(`[scrub] export-time scrub report=${row.report_id} pattern=${JSON.stringify(s.counts)} model_applied=${s.modelApplied} model_ok=${s.modelOk}`);
      }
      out.push({
        report_id: row.report_id,
        source: row.source,
        study_type: row.study_type,
        full_text, findings, impression,
        year: new Date(row.created_at).getUTCFullYear()
      });
    }
    if (format === 'jsonl') {
      res.type('application/x-ndjson');
      return res.send(out.map(r => JSON.stringify(r)).join('\n'));
    }
    res.json({ count: out.length, pairs: out });
  } catch (error) {
    console.error('Training pairs error:', error.message);
    res.status(500).json({ error: 'Failed to load pairs', details: error.message });
  }
});

// Backfill: parse every finalized report that doesn't have a pair yet
app.post('/api/training/extract-sections', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    // subspecialty included so a batch re-harvest can't null the mirror
    const reports = await fetchAllRows('reports', 'id, study_type, subspecialty, final_text, final_saved_at, created_at');
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
    console.error('Extract sections error:', error.message);
    res.status(500).json({ error: 'Extraction failed', details: error.message });
  }
});

// ============ Read-out workflow ============

// Jot/replace the attending's verbal feedback for one study
app.put('/api/reports/:id/notes', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const notes = typeof req.body.readout_notes === 'string' ? req.body.readout_notes : '';
    const report = await db.one(
      `update reports set readout_notes = $2 where id = $1 returning *`,
      [req.params.id, notes.trim() ? notes : null]);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report });
  } catch (error) {
    console.error('Save notes error:', error.message);
    res.status(500).json({ error: 'Failed to save notes', details: error.message });
  }
});

// Current draft vs. the one saved immediately before it
app.get('/api/reports/:id/changes', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const report = await db.one(`select id, draft_text, raw_text from reports where id = $1`, [req.params.id]);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const prior = await db.one(
      `select draft_text, created_at from report_revisions where report_id = $1 order by id desc limit 1`,
      [req.params.id]);

    res.json({
      current: report.draft_text || '',
      previous: prior ? prior.draft_text : null,
      previous_at: prior ? prior.created_at : null
    });
  } catch (error) {
    console.error('Changes error:', error.message);
    res.status(500).json({ error: 'Failed to load changes', details: error.message });
  }
});

// Manually mark a study as read out with the attending — independent of whether
// any read-out notes were typed.
app.put('/api/reports/:id/read-out', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const report = await db.one(
      `update reports set read_out_at = $2 where id = $1 returning *`,
      [req.params.id, req.body.read_out ? new Date().toISOString() : null]);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report });
  } catch (error) {
    console.error('Read-out flag error:', error.message);
    res.status(500).json({ error: 'Failed to set read-out status', details: error.message });
  }
});

// Turn read-out notes into targeted edit proposals (same shape as /api/draft/review;
// the client renders the same accept/reject cards). Never rewrites the draft.
app.post('/api/reports/:id/integrate-notes', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const report = await db.one(`select * from reports where id = $1`, [req.params.id]);
    if (!report) return res.status(404).json({ error: 'Report not found' });

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
    const text = await geminiText({
      model: MODEL_REVIEW,
      label: 'readout',
      system,
      injected,
      message: `Attending read-out feedback:\n${notes}\n\nResident's current draft:\n${draft}`,
      maxTokens: 8000,
      schema: READOUT_EDITS_SCHEMA
    });

    let parsed;
    try {
      parsed = parseModelJson(text);
    } catch (e) {
      // Never log the payload — it quotes the draft and the notes
      console.error(`Integrate JSON parse failed (${text.length} chars): ${e.message}`);
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
    console.error('Integrate notes error:', error.message);
    res.status(500).json({ error: 'Integration failed', details: error.message });
  }
});

// Re-save a reopened draft: new draft_text, edits appended to the audit trail.
// raw_text is never touched; notes stay stored after integration.
app.put('/api/reports/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { draft_text, append_edits, notes_integrated, study_type, study_id_label, report_type, finalized } = req.body;
    if (!draft_text || !draft_text.trim()) {
      return res.status(400).json({ error: 'draft_text is required' });
    }
    const existing = await db.one(
      `select edits_json, draft_text, subspecialty, shift_id from reports where id = $1`, [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Report not found' });

    // Snapshot the outgoing draft so "See recent changes" has something to diff
    // against. Skipped when the text is unchanged (metadata-only saves).
    if (existing.draft_text && existing.draft_text !== draft_text) {
      try {
        await db.query(`insert into report_revisions (report_id, draft_text) values ($1, $2)`,
          [req.params.id, existing.draft_text]);
      } catch (revErr) {
        console.error('Revision snapshot failed:', revErr.message);
      }
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

    // Only the columns the request touches are updated — the SET list is
    // assembled from fixed column names, the values are all parameters.
    const sets = [];
    const params = [req.params.id];
    const set = (col, v, cast = '') => { params.push(v); sets.push(`${col} = $${params.length}${cast}`); };
    set('draft_text', draft_text);
    set('edits_json', JSON.stringify((existing.edits_json || []).concat(cleanAppend)), '::jsonb');
    if (typeof study_type === 'string' && study_type.trim()) set('study_type', study_type.trim());
    if (typeof study_id_label === 'string') set('study_id_label', study_id_label.trim() || null);
    // The stamp is written once: a report saved before the shift had a section
    // picks it up on its next save, but an already-stamped report keeps its
    // value — changing the shift mid-way never rewrites earlier cases.
    if (!existing.subspecialty) {
      const stamped = await shiftSubspecialty(existing.shift_id);
      if (stamped) set('subspecialty', stamped);
    }
    if (report_type === 'prelim' || report_type === 'complete') set('report_type', report_type);
    // Only ever set forward — a later plain re-save must not clear the marker
    if (notes_integrated) set('notes_integrated_at', new Date().toISOString());
    // "Save Final" marks it done; a plain "Save Draft" reopens it (clears the mark)
    if (typeof finalized === 'boolean') {
      set('finalized_at', finalized ? new Date().toISOString() : null);
    }

    const report = await db.one(
      `update reports set ${sets.join(', ')} where id = $1 returning *`, params);
    res.json({ report });
  } catch (error) {
    console.error('Update report error:', error.message);
    res.status(500).json({ error: 'Failed to update report', details: error.message });
  }
});

// Record the grade the attending/QA actually assigned. Manual documentation only —
// Flow Dictation never generates or suggests RPR grades.
app.post('/api/reports/:id/grade', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { manual_grade, grade_note } = req.body || {};
    const grade = String(manual_grade || '').toUpperCase().trim();
    if (!VALID_RPR.test(grade)) {
      return res.status(400).json({ error: 'manual_grade must be RPR1–RPR4' });
    }
    const report = await db.one(
      `update reports set rpr_grade = $2, rpr_note = $3 where id = $1 returning *`,
      [req.params.id, grade, typeof grade_note === 'string' && grade_note.trim() ? grade_note.trim() : null]);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json({ report });
  } catch (error) {
    console.error('Grade error:', error.message);
    res.status(500).json({ error: 'Failed to save grade', details: error.message });
  }
});

// ============ Library CRUD (exemplars, style guide, language) ============

app.get('/api/library/exemplars/counts', async (req, res) => {
  if (!requireDb(res)) return;
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
    console.error('Exemplar counts error:', error.message);
    res.status(500).json({ error: 'Failed to load counts', details: error.message });
  }
});

app.get('/api/library/exemplars', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { query, limit } = req.query;
    const max = Math.min(parseInt(limit, 10) || 50, 200);
    const cols = 'id, study_type, title, notes, source, created_at';
    const rows = query && query.trim()
      ? await db.many(
          `select ${cols} from exemplar_reports where study_type ilike $1 or title ilike $1
           order by created_at desc limit $2`,
          ['%' + query.trim() + '%', max])
      : await db.many(`select ${cols} from exemplar_reports order by created_at desc limit $1`, [max]);
    res.json({ exemplars: rows });
  } catch (error) {
    console.error('Exemplars list error:', error.message);
    res.status(500).json({ error: 'Failed to load exemplars', details: error.message });
  }
});

app.get('/api/library/exemplars/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const exemplar = await db.one(`select * from exemplar_reports where id = $1`, [req.params.id]);
    if (!exemplar) return res.status(404).json({ error: 'Exemplar not found' });
    res.json({ exemplar });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load exemplar', details: error.message });
  }
});

app.post('/api/library/exemplars', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { study_type, title, body, notes } = req.body;
    if (!body || !body.trim()) return res.status(400).json({ error: 'Report body is required' });

    let finalStudyType = (study_type || '').trim();
    if (!finalStudyType) {
      try { finalStudyType = await detectStudyType(body); } catch (e) { finalStudyType = null; }
    }
    const exemplar = await db.one(
      `insert into exemplar_reports (study_type, title, body, notes, source)
       values ($1, $2, $3, $4, 'user') returning *`,
      [
        finalStudyType,
        (title || '').trim() || (finalStudyType ? finalStudyType + ' exemplar' : 'Exemplar'),
        body,
        (notes || '').trim() || null
      ]);
    invalidateExemplars();
    res.json({ exemplar });
  } catch (error) {
    console.error('Exemplar create error:', error.message);
    res.status(500).json({ error: 'Failed to save exemplar', details: error.message });
  }
});

app.put('/api/library/exemplars/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    const { study_type, title, body, notes } = req.body;
    const exemplar = await db.one(
      `update exemplar_reports set study_type = $2, title = $3, body = $4, notes = $5
       where id = $1 returning *`,
      [req.params.id, (study_type || '').trim() || null, (title || '').trim() || null, body,
       (notes || '').trim() || null]);
    if (!exemplar) return res.status(404).json({ error: 'Exemplar not found' });
    invalidateExemplars();
    res.json({ exemplar });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update exemplar', details: error.message });
  }
});

app.delete('/api/library/exemplars/:id', async (req, res) => {
  if (!requireDb(res)) return;
  try {
    await db.query(`delete from exemplar_reports where id = $1`, [req.params.id]);
    invalidateExemplars();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete exemplar', details: error.message });
  }
});

// Generic CRUD for the two simple knowledge tables (both feed the cached prompt
// block). `table` and `fields` are code constants, so they are interpolated
// into the SQL; every request value is a parameter.
function knowledgeCrud(route, table, fields) {
  // Required text fields from the body, or the 400 that was sent
  const readFields = (req, res) => {
    const values = [];
    for (const f of fields) {
      const v = (req.body[f] || '').trim();
      if (!v) { res.status(400).json({ error: `${f} is required` }); return null; }
      values.push(v);
    }
    return values;
  };

  app.get(`/api/library/${route}`, async (req, res) => {
    if (!requireDb(res)) return;
    try {
      const rows = await fetchAllRows(table, 'id, ' + fields.join(', ') + ', created_at');
      res.json({ entries: rows });
    } catch (error) {
      res.status(500).json({ error: `Failed to load ${route}`, details: error.message });
    }
  });

  app.post(`/api/library/${route}`, async (req, res) => {
    if (!requireDb(res)) return;
    try {
      const values = readFields(req, res);
      if (!values) return;
      const entry = await db.one(
        `insert into ${table} (${fields.join(', ')}) values (${fields.map((_, i) => '$' + (i + 1)).join(', ')}) returning *`,
        values);
      invalidateKnowledge();
      res.json({ entry });
    } catch (error) {
      res.status(500).json({ error: `Failed to save`, details: error.message });
    }
  });

  app.put(`/api/library/${route}/:id`, async (req, res) => {
    if (!requireDb(res)) return;
    try {
      const values = readFields(req, res);
      if (!values) return;
      const entry = await db.one(
        `update ${table} set ${fields.map((f, i) => `${f} = $${i + 2}`).join(', ')} where id = $1 returning *`,
        [req.params.id, ...values]);
      if (!entry) return res.status(404).json({ error: 'Entry not found' });
      invalidateKnowledge();
      res.json({ entry });
    } catch (error) {
      res.status(500).json({ error: `Failed to update`, details: error.message });
    }
  });

  app.delete(`/api/library/${route}/:id`, async (req, res) => {
    if (!requireDb(res)) return;
    try {
      await db.query(`delete from ${table} where id = $1`, [req.params.id]);
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
    console.error('OAuth error:', error.message);
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
    console.error('Email send error:', error.message);
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
      provider: 'vertex-ai', project: gemini.PROJECT, location: gemini.LOCATION,
      detect: MODEL_DETECT, report: MODEL_REPORT, review: MODEL_REVIEW,
      impression: MODEL_IMPRESSION, radqa: MODEL_RADQA, synthesize: MODEL_SYNTHESIZE,
      chat: MODEL_CHAT
    },
    auth: { google: googleLoginConfigured, password: !!APP_PASSWORD, allowed_emails: ALLOWED_EMAILS.length },
    database: db.configured ? 'configured' : 'not configured'
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
    pricing_note: `Vertex AI per-MTok list price; implicit cache reads x${CACHE_READ_MULTIPLIER}; thinking billed as output; Google Search grounding +$${GROUNDING_COST_PER_CALL}/call`,
    totals: {
      calls: sum('calls'),
      grounded_calls: sum('grounded_calls'),
      input_tokens: sum('input_tokens'),
      output_tokens: sum('output_tokens'),
      thought_tokens: sum('thought_tokens'),
      cache_read_tokens: sum('cache_read_tokens'),
      tool_prompt_tokens: sum('tool_prompt_tokens'),
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
  if (!db.configured) return;
  try {
    const active = await db.one(`select id from shifts where is_active limit 1`);
    if (active) return;
    const latest = await db.one(`select id from shifts order by started_at desc limit 1`);
    if (latest) {
      await activateShift(latest.id);
      console.log(`✅ Backfilled active shift: ${latest.id}`);
    }
  } catch (e) {
    console.error('Active shift backfill skipped:', e.message);
  }
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`✨ Gemini on Vertex AI: ${MODEL_REPORT} (reports), ${MODEL_REVIEW} (review)`);
  console.log(`🗄️  Database: ${db.configured ? db.describe() : 'NOT CONFIGURED'}`);
  backfillActiveShift();
});
