const express = require('express');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const { TranscribeStreamingClient, StartMedicalStreamTranscriptionCommand } = require("@aws-sdk/client-transcribe-streaming");
const { PassThrough } = require('stream');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const upload = multer({ dest: 'uploads/' });
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

// Claude API configuration
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const SONNET = 'claude-sonnet-4-6';   // report editing / generation
const HAIKU = 'claude-haiku-4-5';     // lightweight tasks (study type detection)

// Supabase (server-side only — service role key, never sent to the browser)
const supabase = (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
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

// AWS Transcribe Medical configuration
const transcribeClient = new TranscribeStreamingClient({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

console.log('=== Environment Check ===');
console.log('Anthropic:', !!process.env.ANTHROPIC_API_KEY ? '✓' : '✗');
console.log('Supabase:', !!supabase ? '✓' : '✗');
console.log('Google Client ID:', !!process.env.GOOGLE_CLIENT_ID ? '✓' : '✗');
console.log('Google Client Secret:', !!process.env.GOOGLE_CLIENT_SECRET ? '✓' : '✗');
console.log('AWS Access Key:', !!process.env.AWS_ACCESS_KEY_ID ? '✓' : '✗');
console.log('AWS Secret Key:', !!process.env.AWS_SECRET_ACCESS_KEY ? '✓' : '✗');
console.log('AWS Region:', process.env.AWS_REGION || 'us-east-1');
console.log('========================');

// ============ Claude helpers ============

async function claudeText({ model, system, message, maxTokens }) {
  const response = await anthropic.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages: [{ role: 'user', content: message }]
  });
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
- No preamble, no commentary, no sign-off — return only the requested content.`;

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

const RPR_GRADE_SYSTEM = `You grade a radiology preliminary (draft) report against the attending's final report, assessing how significant the attending's changes were.

Grades:
- RPR1: Concordant. No changes, or trivial changes only (formatting, dictation cleanup, punctuation) with no change in meaning.
- RPR2: Minor discrepancy. Wording/style edits, small additions or clarifications with little or no clinical significance. Findings and impression are substantively unchanged.
- RPR3: Moderate discrepancy. Findings or impression were changed, added, or removed in a way that could have clinical significance (e.g., a finding upgraded/downgraded, a differential changed, a recommendation altered).
- RPR4: Major discrepancy. A clinically significant miss or change that alters the diagnosis or patient management (e.g., a missed fracture, missed hemorrhage, wrong laterality on a significant finding).

Judge only the substantive clinical differences — ignore formatting, section reordering, boilerplate, and pure style. When in doubt between two grades, choose based on whether the change could plausibly alter management.

Return JSON only — no markdown fences, no commentary — exactly:
{"grade": "RPR1", "rationale": "<one or two sentences citing the key difference(s), or noting concordance>"}`;

const VALID_RPR = /^RPR[1-4]$/;

async function gradeReport(draftText, finalText) {
  const text = await claudeText({
    model: SONNET,
    system: RPR_GRADE_SYSTEM,
    message: `PRELIMINARY (resident draft):\n${draftText}\n\nFINAL (attending):\n${finalText}`,
    maxTokens: 500
  });
  const parsed = parseClaudeJson(text);
  const grade = String(parsed.grade || '').toUpperCase().trim();
  if (!VALID_RPR.test(grade)) throw new Error('Model returned invalid grade: ' + grade);
  return { grade, rationale: String(parsed.rationale || '').trim() };
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
    const { action, message } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const instruction = action && ASSIST_ACTIONS[action] ? ASSIST_ACTIONS[action] : null;
    const userMessage = instruction ? `${instruction}\n\n${message}` : message;

    const text = await claudeText({
      model: SONNET,
      system: ASSIST_SYSTEM,
      message: userMessage,
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
    const { report } = req.body;
    if (!report || !report.trim()) {
      return res.status(400).json({ error: 'Report text is required' });
    }

    const text = await claudeText({
      model: SONNET,
      system: DRAFT_REVIEW_SYSTEM,
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
    model: HAIKU,
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
    const { shift_id } = req.query;
    let query = supabase
      .from('reports')
      .select('id, shift_id, study_type, study_id_label, report_type, created_at, final_saved_at, rpr_grade')
      .order('created_at', { ascending: false });
    if (shift_id) query = query.eq('shift_id', shift_id);
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

    // Auto-grade against the draft. Grading failure must not fail the save.
    let report = data;
    try {
      const { grade, rationale } = await gradeReport(data.draft_text, final_text);
      const { data: graded, error: gradeErr } = await supabase
        .from('reports')
        .update({ rpr_grade: grade, rpr_rationale: rationale })
        .eq('id', req.params.id)
        .select()
        .single();
      if (gradeErr) throw gradeErr;
      report = graded;
    } catch (e) {
      console.error('Auto-grade failed (final still saved):', e.message);
    }

    res.json({ report });
  } catch (error) {
    console.error('Save final error:', error);
    res.status(500).json({ error: 'Failed to save final', details: error.message });
  }
});

// Re-run auto-grading, or set a manual override with {manual_grade: "RPR1".."RPR4"}
app.post('/api/reports/:id/grade', async (req, res) => {
  if (!requireSupabase(res)) return;
  try {
    const { manual_grade } = req.body || {};

    if (manual_grade !== undefined) {
      const grade = String(manual_grade).toUpperCase().trim();
      if (!VALID_RPR.test(grade)) {
        return res.status(400).json({ error: 'manual_grade must be RPR1–RPR4' });
      }
      const { data, error } = await supabase
        .from('reports')
        .update({ rpr_grade: grade, rpr_rationale: 'Manually set' })
        .eq('id', req.params.id)
        .select()
        .single();
      if (error) throw error;
      return res.json({ report: data });
    }

    const { data: report, error: getErr } = await supabase
      .from('reports')
      .select('draft_text, final_text')
      .eq('id', req.params.id)
      .single();
    if (getErr) throw getErr;
    if (!report.final_text) {
      return res.status(400).json({ error: 'Save a final report before grading' });
    }

    const { grade, rationale } = await gradeReport(report.draft_text, report.final_text);
    const { data, error } = await supabase
      .from('reports')
      .update({ rpr_grade: grade, rpr_rationale: rationale })
      .eq('id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ report: data });
  } catch (error) {
    console.error('Grade error:', error);
    res.status(500).json({ error: 'Grading failed', details: error.message });
  }
});

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

// ============ WebSocket for Transcription (PowerMic / dictation) ============

wss.on('connection', async (clientWs) => {
  console.log('Client connected for AWS Transcribe Medical');

  let transcribeStream = null;
  let audioStream = null;
  let isTranscribing = false;
  let sessionCount = 0;

  clientWs.on('message', async (message) => {
    if (!Buffer.isBuffer(message)) return;

    if (!isTranscribing && !transcribeStream) {
      try {
        isTranscribing = true;
        sessionCount++;
        console.log(`Starting session #${sessionCount}`);

        audioStream = new PassThrough();
        audioStream.setMaxListeners(0);

        const sessionId = crypto.randomBytes(16).toString('hex');

        const audioBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
        audioStream.write(audioBuffer);

        const command = new StartMedicalStreamTranscriptionCommand({
          LanguageCode: 'en-US',
          MediaSampleRateHertz: 16000,
          MediaEncoding: 'pcm',
          Specialty: 'RADIOLOGY',
          Type: 'DICTATION',
          AudioStream: (async function* () {
            for await (const chunk of audioStream) {
              yield { AudioEvent: { AudioChunk: chunk } };
            }
          })()
        });

        const response = await transcribeClient.send(command);
        transcribeStream = response.TranscriptResultStream;

        console.log('✅ AWS Transcribe Medical session started:', sessionId);

        (async () => {
          try {
            for await (const event of transcribeStream) {
              if (event.TranscriptEvent) {
                const results = event.TranscriptEvent.Transcript.Results;
                for (const result of results) {
                  if (!result.IsPartial) {
                    const transcript = result.Alternatives[0].Transcript;
                    if (transcript && transcript.trim()) {
                      console.log('Final transcript:', transcript);
                      if (clientWs.readyState === WebSocket.OPEN) {
                        clientWs.send(JSON.stringify({
                          type: 'transcript',
                          text: transcript,
                          is_final: true,
                          confidence: result.Alternatives[0].Items?.[0]?.Confidence
                        }));
                      }
                    }
                  } else {
                    const transcript = result.Alternatives[0].Transcript;
                    if (transcript && transcript.trim()) {
                      if (clientWs.readyState === WebSocket.OPEN) {
                        clientWs.send(JSON.stringify({
                          type: 'transcript',
                          text: transcript,
                          is_final: false
                        }));
                      }
                    }
                  }
                }
              }
            }
          } catch (error) {
            if (error.name !== 'AbortError') {
              console.error('Transcription stream error:', error.message);
            }
          } finally {
            console.log('Transcription stream ended');
            isTranscribing = false;
            transcribeStream = null;
          }
        })();

      } catch (error) {
        console.error('Error starting AWS Transcribe Medical:', error);
        isTranscribing = false;
        transcribeStream = null;
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(JSON.stringify({
            type: 'error',
            message: 'Transcription error: ' + error.message
          }));
        }
      }
    } else if (audioStream && isTranscribing) {
      try {
        const audioBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
        audioStream.write(audioBuffer);
      } catch (error) {
        console.error('Error sending audio to AWS:', error);
      }
    }
  });

  clientWs.on('close', () => {
    console.log('Client disconnected');
    isTranscribing = false;
    if (audioStream) {
      audioStream.end();
      audioStream = null;
    }
    transcribeStream = null;
  });

  clientWs.on('error', (error) => {
    console.error('WebSocket error:', error);
    isTranscribing = false;
    if (audioStream) {
      audioStream.end();
      audioStream = null;
    }
    transcribeStream = null;
  });
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
      model: SONNET,
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
    transcription: 'AWS Transcribe Medical',
    llm: `${SONNET} + ${HAIKU}`,
    supabase: supabase ? 'configured' : 'not configured',
    gmail: userTokens ? 'connected' : 'not connected'
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🩺 AWS Transcribe Medical enabled`);
  console.log(`✨ Claude: ${SONNET} (reports) + ${HAIKU} (lightweight)`);
  console.log(`🗄️  Supabase: ${supabase ? 'connected' : 'NOT CONFIGURED'}`);
  console.log(`📧 Gmail integration ready`);
});
