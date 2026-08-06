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
const MODEL_DETECT = process.env.MODEL_DETECT || 'claude-haiku-4-5';      // study type detection
const MODEL_REPORT = process.env.MODEL_REPORT || 'claude-sonnet-4-6';     // describe / reword / proofread / full report
const MODEL_CHAT = process.env.MODEL_CHAT || 'claude-fable-5';            // free-form Assist chat
const MODEL_RADQA = process.env.MODEL_RADQA || 'claude-fable-5';          // Quick Rad Question
// Judgement-heavy paths default to Fable. Explicit env wins; otherwise an
// explicitly-set MODEL_REPORT is inherited, and the Fable default applies only
// when neither is configured.
const MODEL_REVIEW = process.env.MODEL_REVIEW || process.env.MODEL_REPORT || 'claude-fable-5';        // draft review + read-out integration
const MODEL_IMPRESSION = process.env.MODEL_IMPRESSION || process.env.MODEL_REPORT || 'claude-fable-5'; // impression generation
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
console.log(`  detect     = ${MODEL_DETECT}`);
console.log(`  report     = ${MODEL_REPORT}   (describe · reword · proofread · full report)`);
console.log(`  review     = ${MODEL_REVIEW}   (draft review · read-out integration)`);
console.log(`  impression = ${MODEL_IMPRESSION}`);
console.log(`  radqa      = ${MODEL_RADQA}`);
console.log(`  chat       = ${MODEL_CHAT}`);
console.log(`  fallback   = ${MODEL_FALLBACK}   (on classifier refusal)`);
console.log('========================');

// ============ Claude helpers ============

// Only the Fable/Opus-5 tier accepts the server-side `fallbacks` parameter;
// Haiku and Sonnet reject it with a 400. Those models also don't exhibit the
// classifier refusals fallbacks exist to rescue.
const FALLBACK_CAPABLE = /fable|mythos|opus-5/i;

// output_config.effort is the latency lever: low/medium for mechanical tasks,
// default (high) for complex ones. Haiku 4.5 rejects the parameter.
const EFFORT_CAPABLE = /fable|mythos|opus|sonnet-5|sonnet-4-6/i;

// withFallbacks: request server-side refusal fallbacks where the model supports it.
async function claudeText({ model, system, message, messages, maxTokens, withFallbacks, effort }) {
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
  console.log(`[claude] ${response.model || model} in=${u.input_tokens} out=${u.output_tokens} cache_write=${u.cache_creation_input_tokens || 0} cache_read=${u.cache_read_input_tokens || 0}`);
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
- You may be given recent conversation history. Use it to interpret follow-ups naturally: "make it shorter", "more formal", "now do the impression", "same but for the left side" all refer to your previous answer. When the user moves on to a new, unrelated request, treat it as a fresh task and do not carry over earlier content.`;

const ASSIST_ACTIONS = {
  describe: `The user is describing an imaging finding they are struggling to word. Suggest professional report wording for it.
Return JSON only — no markdown fences, no commentary — in exactly this shape:
{"findings": "<suggested wording for the Findings section>", "impression": "<matching wording for the Impression section>"}

User's description of the finding:`,
  reword: `Reword the following text. Keep the exact meaning, improve clarity and flow, and use standard radiology reporting register. It may be a sentence, a section, or an entire report — preserve its structure and line breaks. Return only the reworded text.

Text to reword:`,
  proofread: `Proofread the following text. Correct spelling, grammar, punctuation, and obvious speech-recognition/dictation errors. Do not otherwise change wording, meaning, or style. Return only the fully corrected text, preserving line breaks exactly.

Text to proofread:`,
  impression: `Generate a numbered IMPRESSION for the following radiology report body. Order items by clinical significance, keep each item concise, and use standard radiology register. Return only the numbered impression lines (1. ... 2. ...), nothing else.

Report body:`,
  fullreport: `Generate a complete radiology report from the user's dictated or summarized findings. Use standard report structure — EXAMINATION, CLINICAL HISTORY, TECHNIQUE, COMPARISON, FINDINGS, IMPRESSION — matching the structure and phrasing of any exemplar reports provided for this study type. Rules:
- Include every finding the user stated, worded in standard radiology register. Never alter laterality, measurements, or meaning.
- For structures the user did not mention, use the standard normal statements appropriate to this study type.
- Use [bracketed placeholders] for details the user did not provide (e.g. [clinical history], [comparison date]) rather than inventing them.
- Number the IMPRESSION by clinical significance.
- Return only the report text, nothing else.

User's findings / dictation:`
};

// Speed: mechanical transformations run at low effort, moderate tasks at
// medium; only full report generation keeps the default (high) depth.
// Undefined = model default.
const ACTION_EFFORT = {
  reword: 'low',
  proofread: 'low',
  describe: 'medium',
  impression: 'medium',
  fullreport: 'high'
};
const CHAT_EFFORT = 'medium';          // free-form Assist chat
const DRAFT_REVIEW_EFFORT = 'medium';  // typo/essential-edit review

// Per-action model routing; anything unlisted uses MODEL_REPORT.
const ACTION_MODEL = { impression: MODEL_IMPRESSION };

const DRAFT_REVIEW_SYSTEM = `You review radiology report drafts for a radiologist. Flag ONLY essential corrections: obvious typos (spelling, grammar, punctuation) and clear speech-recognition/dictation errors, plus wording that is factually wrong or genuinely confusing.

Return JSON only — no markdown fences, no commentary — in exactly this shape:
{"edits": [{"original_text": "...", "suggested_text": "...", "reason": "...", "category": "typo"}]}

Rules:
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

const RAD_QA_SYSTEM_PROMPT = `You are an expert academic radiologist answering quick questions from a radiology resident. Style:
- Answer directly and precisely at resident-to-fellow teaching level; assume medical vocabulary
- Anatomic precision matters — name specific structures, attachments, and relationships
- Proactively flag imaging pitfalls, mimics, and pseudolesions relevant to the question
- For protocol questions, reason about the clinical question first, then the acquisition
- When asked for report language, give drop-in ready phrasing with bracketed [placeholders]
- Concise but substantive: typically a few short paragraphs; use a brief list only when enumerating truly parallel items
- If a question has genuine controversy or institutional variation, say so briefly
- No generic safety disclaimers or 'consult your attending' filler; this is education between professionals, not patient advice`;

// Appended only when the "Include references" toggle is on (tools provided)
const RAD_QA_REFERENCES_ADDENDUM = `When a reference would genuinely help (classification systems, management guidelines, follow-up criteria, entities the resident may want to read further on), use web search to find the specific relevant page and end your answer with a short 'References' line listing 1-3 links with one-phrase descriptions.

Radiopaedia (radiopaedia.org) is the preferred source. Search it first, and include the relevant Radiopaedia article whenever one exists — list it first in the References. Add other sources only when they cover something Radiopaedia does not: ACR Appropriateness Criteria for protocol/appropriateness questions, and RadioGraphics for in-depth reviews.

Do not search for questions you can answer completely from knowledge (basic anatomy, simple definitions) — in those cases include no references rather than padding. Never fabricate a URL: only include links returned by search.`;

// Length responds to prompting, not to max_tokens or effort — applied on every
// model ("less is more": short first answers, detail on request).
const RAD_QA_BREVITY_ADDENDUM = `Keep this answer tight — a few short paragraphs, and shorter still for simple questions. Short sentences. Lead with the direct answer, then only the detail that changes what the reader would do next. Skip preamble, restating the question, exhaustive differentials, and drop-in report templates unless the resident explicitly asks for them. Prefer prose over stacked headers and bullet lists. The resident can always ask a follow-up for depth.`;

function buildRadQaSystem(model, searchEnabled) {
  let s = RAD_QA_SYSTEM_PROMPT + '\n' + RAD_QA_BREVITY_ADDENDUM;
  if (searchEnabled) s += '\n' + RAD_QA_REFERENCES_ADDENDUM;
  return s;
}

const RAD_QA_SEARCH_TOOL = {
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

const VALID_RPR = /^RPR[1-4]$/;

// ============ Knowledge layer (style guide, language library, exemplars) ============

// The style guide + language library form a static system-prompt block that is
// prompt-cached (cache_control: ephemeral). Cached in memory so the block stays
// byte-identical across requests; invalidated when the library is edited.
let knowledgeCache = { block: null, loadedAt: 0 };
const KNOWLEDGE_TTL_MS = 5 * 60 * 1000;
function invalidateKnowledge() { knowledgeCache = { block: null, loadedAt: 0 }; }

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

async function getKnowledgeBlock() {
  if (!supabase) return '';
  if (knowledgeCache.block !== null && Date.now() - knowledgeCache.loadedAt < KNOWLEDGE_TTL_MS) {
    return knowledgeCache.block;
  }
  try {
    const [rules, lang] = await Promise.all([
      fetchAllRows('style_guide', 'section, rule, created_at'),
      fetchAllRows('rad_language', 'category, content, created_at')
    ]);
    let block = '';
    if (rules.length) {
      block += '\n\nSTYLE GUIDE — follow these reporting rules:\n' +
        groupLines(rules, 'section', 'rule', 'general');
    }
    if (lang.length) {
      block += '\nRADIOLOGY LANGUAGE REFERENCE — preferred register and phrasing:\n' +
        groupLines(lang, 'category', 'content', 'general');
    }
    knowledgeCache = { block, loadedAt: Date.now() };
    return block;
  } catch (e) {
    console.error('Knowledge load failed:', e.message);
    return '';
  }
}

// Up to 3 exemplars for the study type: user rows first, PARROT fills the rest;
// fall back to modality-level matches, then up to 2 general exemplars.
// 'user' > 'parrot' alphabetically, so order source DESC puts user rows first.
const EXEMPLAR_COLS = 'id, study_type, title, body, source';

async function selectExemplars(studyType) {
  if (!supabase) return [];
  const chosen = [];
  const seen = new Set();
  const add = rows => {
    for (const r of rows || []) {
      if (chosen.length >= 3) break;
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      chosen.push(r);
    }
  };
  try {
    if (studyType && studyType.trim()) {
      const st = studyType.trim();
      const { data: userRows } = await supabase.from('exemplar_reports')
        .select(EXEMPLAR_COLS).ilike('study_type', st).eq('source', 'user').limit(3);
      add(userRows);
      if (chosen.length < 3) {
        const { data: parrotRows } = await supabase.from('exemplar_reports')
          .select(EXEMPLAR_COLS).ilike('study_type', st).neq('source', 'user').limit(3);
        add(parrotRows);
      }
      if (chosen.length === 0) {
        const modality = st.split(/\s+/)[0];
        if (modality) {
          const { data: modRows } = await supabase.from('exemplar_reports')
            .select(EXEMPLAR_COLS).ilike('study_type', modality + ' %')
            .order('source', { ascending: false }).limit(3);
          add(modRows);
        }
      }
    }
    if (chosen.length === 0) {
      const { data: anyRows } = await supabase.from('exemplar_reports')
        .select(EXEMPLAR_COLS).order('source', { ascending: false }).limit(2);
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

// System prompt as content blocks: [static block (cached), exemplar block (varies)]
async function buildKnowledgeSystem(baseSystem, studyType) {
  const knowledge = await getKnowledgeBlock();
  const blocks = [];
  if (knowledge) {
    blocks.push({ type: 'text', text: baseSystem + knowledge, cache_control: { type: 'ephemeral' } });
  } else {
    blocks.push({ type: 'text', text: baseSystem });
  }
  const exText = exemplarBlockText(await selectExemplars(studyType));
  if (exText) blocks.push({ type: 'text', text: exText });
  return blocks;
}

// Heuristic: pasted report content is long; short inputs (finding descriptions,
// questions) skip the study-type detection call.
function looksLikeReport(text) {
  return text.trim().length >= 200;
}

// Generate Full Report writes the whole report on MODEL_REPORT, then rewrites
// just the IMPRESSION on MODEL_IMPRESSION — the section where model judgement
// matters most. Returns the original text unchanged if anything doesn't line up.
const IMPRESSION_HEADING = /^[ \t]*(?:\*\*)?\s*IMPRESSION\b[^\n]*$/im;

async function upgradeImpression(reportText, studyType) {
  if (MODEL_IMPRESSION === MODEL_REPORT) return reportText;
  const m = reportText.match(IMPRESSION_HEADING);
  if (!m) return reportText;
  const body = reportText.slice(0, m.index).trimEnd();
  if (!body) return reportText;
  const system = await buildKnowledgeSystem(ASSIST_SYSTEM, studyType);
  const impression = (await claudeTextFallback({
    model: MODEL_IMPRESSION,
    system,
    message: `${ASSIST_ACTIONS.impression}\n\n${body}`,
    maxTokens: 2000,
    effort: ACTION_EFFORT.impression
  })).trim();
  if (!impression) return reportText;
  return `${body}\n\n${m[0]}\n${impression}`;
}

// ============ Page 1: Assist ============

app.post('/api/assist', async (req, res) => {
  try {
    const { action, message, history } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const instruction = action && ASSIST_ACTIONS[action] ? ASSIST_ACTIONS[action] : null;
    const userMessage = instruction ? `${instruction}\n\n${message}` : message;

    // Recent conversation history so follow-ups ("shorter", "now the impression") work
    const messages = [];
    if (Array.isArray(history)) {
      for (const h of history.slice(-12)) {
        if ((h.role === 'user' || h.role === 'assistant') &&
            typeof h.content === 'string' && h.content.trim()) {
          messages.push({ role: h.role, content: h.content.slice(0, 20000) });
        }
      }
    }
    messages.push({ role: 'user', content: userMessage });

    // Quick Rad Question: dedicated teaching prompt, lean context (no knowledge
    // injection). Optionally search a whitelist of radiology references.
    if (action === 'radqa') {
      const useRefs = req.body.references !== false; // default ON

      let msgs = messages;
      let text = '';
      let model = MODEL_RADQA;
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
        const response = await anthropic.beta.messages.create({
          model,
          // Referenced answers run long, and the References line comes last —
          // too low a ceiling truncates it away.
          max_tokens: 8000,
          system: buildRadQaSystem(model, searchEnabled),
          messages: msgs,
          // Only the Fable/Opus-5 tier accepts these; MODEL_RADQA is overridable
          ...(FALLBACK_CAPABLE.test(model)
            ? { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' }
            : {}),
          ...(searchEnabled ? { tools: [RAD_QA_SEARCH_TOOL] } : {})
        });
        const u = response.usage || {};
        const viaServerFallback = (u.iterations || []).some(i => i.type === 'fallback_message');
        console.log(`[claude] ${response.model} radqa${searchEnabled ? '+search' : ''}${viaServerFallback ? ' (server-fallback)' : ''} in=${u.input_tokens} out=${u.output_tokens} stop=${response.stop_reason}`);

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
      // Radiopaedia first in any citation list we render
      citations.sort((a, b) =>
        (b.url.includes('radiopaedia.org') ? 1 : 0) - (a.url.includes('radiopaedia.org') ? 1 : 0));
      return res.json({ type: 'text', text: text.trim(), citations, refs_dropped: refsDropped, truncated });
    }

    // The four report actions get the knowledge layer (style guide + language +
    // matched exemplars). Free-form chat keeps the lean base prompt.
    let system = ASSIST_SYSTEM;
    let studyType = null;
    if (instruction) {
      // fullreport inputs are often short dictations, but knowing the study type
      // is what pulls in the right exemplars — always try to detect it.
      if (action === 'fullreport' || looksLikeReport(message)) {
        try { studyType = await detectStudyType(message); } catch (e) { /* non-fatal */ }
      }
      system = await buildKnowledgeSystem(ASSIST_SYSTEM, studyType);
    }

    // Quick actions run on their routed model with the knowledge layer;
    // free-form chat runs on MODEL_CHAT.
    const chatModel = instruction ? (ACTION_MODEL[action] || MODEL_REPORT) : MODEL_CHAT;
    let text = await claudeTextFallback({
      model: chatModel,
      system,
      messages,
      maxTokens: 4000,
      effort: instruction ? ACTION_EFFORT[action] : CHAT_EFFORT
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
    const system = await buildKnowledgeSystem(DRAFT_REVIEW_SYSTEM, studyType);

    const text = await claudeTextFallback({
      model: MODEL_REVIEW,
      system,
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
      .filter(e => report.includes(e.original_text) && e.original_text !== e.suggested_text);

    res.json({ edits });
  } catch (error) {
    console.error('Draft review error:', error);
    res.status(500).json({ error: 'Review failed', details: error.message });
  }
});

async function detectStudyType(report) {
  const text = await claudeTextFallback({
    model: MODEL_DETECT,
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

app.get('/api/reports', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    // Filters combine (Review page): any subset of shift, grade, study type.
    // This only ever searches the user's own drafted reports — PARROT exemplars
    // live in exemplar_reports and cannot appear here.
    const { shift_id, grade, study_type } = req.query;
    let query = supabase
      .from('reports')
      .select('id, shift_id, study_type, study_id_label, report_type, created_at, final_saved_at, rpr_grade, rpr_note, readout_notes, notes_integrated_at, read_out_at, finalized_at')
      .order('created_at', { ascending: false });
    if (shift_id) query = query.eq('shift_id', shift_id);
    if (grade === 'ungraded') query = query.is('rpr_grade', null);
    else if (VALID_RPR.test(grade || '')) query = query.eq('rpr_grade', grade);
    if (study_type && study_type.trim()) query = query.ilike('study_type', '%' + study_type.trim() + '%');
    const { data, error } = await query;
    if (error) throw error;
    res.json({ reports: data });
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
    res.json({ report: data });
  } catch (error) {
    console.error('Save final error:', error);
    res.status(500).json({ error: 'Failed to save final', details: error.message });
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

    const system = await buildKnowledgeSystem(READOUT_INTEGRATE_SYSTEM, report.study_type);
    const text = await claudeTextFallback({
      model: MODEL_REVIEW,
      system,
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
      impression: MODEL_IMPRESSION, radqa: MODEL_RADQA, chat: MODEL_CHAT,
      fallback: MODEL_FALLBACK
    },
    auth: { google: googleLoginConfigured, password: !!APP_PASSWORD, allowed_emails: ALLOWED_EMAILS.length },
    supabase: supabase ? 'configured' : 'not configured'
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
