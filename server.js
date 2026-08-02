const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

// Claude API configuration — models are env-configurable
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const MODEL_DETECT = process.env.MODEL_DETECT || 'claude-haiku-4-5';  // study type detection
const MODEL_REPORT = process.env.MODEL_REPORT || 'claude-sonnet-4-6'; // report actions + draft review
const MODEL_RADQA = process.env.MODEL_RADQA || 'claude-fable-5';      // Quick Rad Question

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

console.log('=== Environment Check ===');
console.log('Anthropic:', !!process.env.ANTHROPIC_API_KEY ? '✓' : '✗');
console.log('Supabase:', !!supabase ? '✓' : '✗');
console.log('Google Client ID:', !!process.env.GOOGLE_CLIENT_ID ? '✓' : '✗');
console.log('Google Client Secret:', !!process.env.GOOGLE_CLIENT_SECRET ? '✓' : '✗');
console.log(`Models: detect=${MODEL_DETECT} report=${MODEL_REPORT} radqa=${MODEL_RADQA}`);
console.log('========================');

// ============ Claude helpers ============

async function claudeText({ model, system, message, messages, maxTokens }) {
  const response = await anthropic.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages: messages || [{ role: 'user', content: message }]
  });
  const u = response.usage || {};
  console.log(`[claude] ${model} in=${u.input_tokens} out=${u.output_tokens} cache_write=${u.cache_creation_input_tokens || 0} cache_read=${u.cache_read_input_tokens || 0}`);
  // Safety classifiers (e.g. on claude-fable-5) can decline a request with a 200 +
  // stop_reason "refusal" and empty content — surface that instead of returning ''.
  if (response.stop_reason === 'refusal') {
    const why = response.stop_details && response.stop_details.explanation;
    throw new Error('The model declined this request' + (why ? ': ' + why : '.'));
  }
  return response.content
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('')
    .trim();
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

Report body:`
};

const DRAFT_REVIEW_SYSTEM = `You review radiology report drafts for a radiologist. Identify typo corrections (spelling, grammar, punctuation, dictation/speech-recognition errors) and small stylistic improvements (clarity, flow, standard radiology phrasing).

Return JSON only — no markdown fences, no commentary — in exactly this shape:
{"edits": [{"original_text": "...", "suggested_text": "...", "reason": "...", "category": "typo"}]}

Rules:
- "category" must be exactly "typo" or "style".
- "original_text" must be an EXACT character-for-character substring of the report so it can be located, and must be unique enough to find (include a few surrounding words if needed).
- Keep each edit small and local: a word, phrase, or at most one sentence. Do not rewrite the whole report.
- Never change medical meaning, laterality, measurements, or findings.
- "reason" is one short sentence.
- If nothing needs changing, return {"edits": []}.`;

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
const RAD_QA_REFERENCES_ADDENDUM = `When a reference would genuinely help (classification systems, management guidelines, follow-up criteria, entities the resident may want to read further on), use web search to find the specific relevant page and end your answer with a short 'References' line listing 1-3 links with one-phrase descriptions. Prefer Radiopaedia for general entities, ACR Appropriateness Criteria for protocol/appropriateness questions, and RadioGraphics for in-depth reviews. Do not search for questions you can answer completely from knowledge (basic anatomy, simple definitions) — in those cases include no references rather than padding. Never fabricate a URL: only include links returned by search.`;

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
// questions) skip the Haiku study-type call.
function looksLikeReport(text) {
  return text.trim().length >= 200;
}

const NUCLEAR_MEDICINE_SYSTEM_PROMPT = `You are an expert nuclear medicine radiologist creating structured PET/CT and nuclear medicine reports.

CRITICAL FORMATTING RULES:
1. Use EXACTLY this structure with proper spacing:

TECHNIQUE: [Generate appropriate technique based on study type - see examples below]

FINDINGS:

HEAD AND NECK: [findings or "There is no increased uptake within lymphadenopathy seen."]

SKULL BASE: [findings or "There is no abnormal increased uptake. There is physiologic uptake within the salivary and thyroid glands."]

CHEST

LUNGS: [findings or "There is no increased uptake within lung nodules visualized."]

MEDIASTINUM: [findings or "There is no increased uptake within lymphadenopathy seen."]

ABDOMEN/PELVIS

LIVER/SPLEEN: [findings or "No abnormal increased uptake is seen."]

ADRENALS: [findings or "No abnormal hypermetabolism is seen."]

LYMPH NODES: [findings or "There is no hypermetabolic lymphadenopathy seen."]

GI TRACT: [findings or "There is physiologic metabolic activity throughout the gastrointestinal tract with no focal abnormal hypermetabolism."]

BONES/BONE MARROW: [findings or "There is no abnormal increased uptake seen."]

EXTREMITIES: [findings or "No abnormal increased uptake seen."]

OTHER: [additional findings or "There are no other abnormal foci of increased uptake."]

NON-PET FINDINGS: [CT findings like "Atherosclerotic calcifications..." or omit if none]


CONCLUSION:

1. [First conclusion point]
2. [Second conclusion point]
[etc.]

IMPORTANT GUIDELINES:
- Only include POSITIVE findings in each section
- Use exact phrasing for negative findings: "There is no increased uptake within..." or "No abnormal increased uptake..."
- Use "increased uptake" terminology (not "hypermetabolic") to match standard nuclear medicine phrasing
- Include SUV values when mentioned (e.g., "max SUV of 12.4")
- Describe lesion locations precisely (e.g., "right lower lobe", "left posterior peripheral zone")
- Compare to prior studies when mentioned (e.g., "increased from prior", "new since...")
- Use proper anatomical terminology
- Keep tone clinical and objective
- Number all conclusion points
- Include size measurements when provided (e.g., "3.2 cm lesion")
- Mention any sclerotic/lytic changes in bones
- Note any interval changes explicitly
- Present tense for current findings
- Past tense for comparisons ("previously seen", "was noted")

DO NOT include: Patient names, MRNs, dates of birth, exam dates, physician names, or any PHI.`;

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
      const system = useRefs
        ? RAD_QA_SYSTEM_PROMPT + '\n' + RAD_QA_REFERENCES_ADDENDUM
        : RAD_QA_SYSTEM_PROMPT;

      let msgs = messages;
      let text = '';
      const citations = [];
      const seenUrls = new Set();

      // Search-enabled responses interleave text / server_tool_use /
      // web_search_tool_result blocks, and the server-side tool loop can pause
      // (stop_reason "pause_turn") — resume by appending the turn and re-sending.
      for (let attempt = 0; attempt < 4; attempt++) {
        const response = await anthropic.messages.create({
          model: MODEL_RADQA,
          max_tokens: 4000,
          system,
          messages: msgs,
          ...(useRefs ? { tools: [RAD_QA_SEARCH_TOOL] } : {})
        });
        const u = response.usage || {};
        console.log(`[claude] ${MODEL_RADQA} radqa${useRefs ? '+search' : ''} in=${u.input_tokens} out=${u.output_tokens} stop=${response.stop_reason}`);
        if (response.stop_reason === 'refusal') {
          const why = response.stop_details && response.stop_details.explanation;
          throw new Error('The model declined this request' + (why ? ': ' + why : '.'));
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
        break;
      }
      return res.json({ type: 'text', text: text.trim(), citations });
    }

    // The four report actions get the knowledge layer (style guide + language +
    // matched exemplars). Free-form chat keeps the lean base prompt.
    let system = ASSIST_SYSTEM;
    if (instruction) {
      let studyType = null;
      if (looksLikeReport(message)) {
        try { studyType = await detectStudyType(message); } catch (e) { /* non-fatal */ }
      }
      system = await buildKnowledgeSystem(ASSIST_SYSTEM, studyType);
    }

    const text = await claudeText({
      model: MODEL_REPORT,
      system,
      messages,
      maxTokens: 4000
    });

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

    const text = await claudeText({
      model: MODEL_REPORT,
      system,
      message: `Review this radiology report draft:\n\n${report}`,
      maxTokens: 8000
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
  const text = await claudeText({
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

app.get('/api/shifts/current', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from('shifts')
      .select('*')
      .order('started_at', { ascending: false })
      .limit(1);
    if (error) throw error;
    res.json({ shift: data && data.length ? data[0] : null });
  } catch (error) {
    console.error('Current shift error:', error);
    res.status(500).json({ error: 'Failed to load current shift', details: error.message });
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
    res.json({ shift: data });
  } catch (error) {
    console.error('Create shift error:', error);
    res.status(500).json({ error: 'Failed to create shift', details: error.message });
  }
});

// ============ Reports ============

app.post('/api/reports', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { proposed_id, shift_id, study_type, study_id_label, report_type, raw_text, draft_text, edits_json } = req.body;
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
        created_at: now
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
      .select('id, shift_id, study_type, study_id_label, report_type, created_at, final_saved_at, rpr_grade, rpr_note')
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
  const { code } = req.query;
  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    userTokens = tokens;
    console.log('✅ Gmail OAuth successful');
    res.redirect('/?gmail=connected');
  } catch (error) {
    console.error('OAuth error:', error);
    res.redirect('/?gmail=error');
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

// ============ Legacy Report Generation (nuclear medicine) ============

app.post('/api/generate-report', async (req, res) => {
  try {
    const { findings } = req.body;
    if (!findings) {
      return res.status(400).json({ error: 'Findings are required' });
    }
    const userMessage = `Generate a nuclear medicine PET/CT report based on these dictated findings. Only include the sections and findings that were mentioned. Use standard negative phrasing for unremarkable areas:\n\n${findings}`;
    const text = await claudeText({
      model: MODEL_REPORT,
      system: NUCLEAR_MEDICINE_SYSTEM_PROMPT,
      message: userMessage,
      maxTokens: 2000
    });
    res.json({ report: text });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to generate report', details: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Flow Dictation API',
    llm: `${MODEL_REPORT} + ${MODEL_DETECT}`,
    supabase: supabase ? 'configured' : 'not configured'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`✨ Claude: ${MODEL_REPORT} (reports) + ${MODEL_DETECT} (lightweight)`);
  console.log(`🗄️  Supabase: ${supabase ? 'connected' : 'NOT CONFIGURED'}`);
});
