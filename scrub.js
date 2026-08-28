// PHI scrub layer. Two passes:
//   1. patternScrub  — deterministic regexes for identifiers with a shape
//                      (MRNs, accessions, dates, phones, SSNs, titled names)
//   2. a model pass  — run by the caller (server.js owns the Gemini plumbing);
//                      this module supplies the prompt, the response schema,
//                      and applyReplacements() to apply what the model found
// Both passes substitute typed placeholders ([MRN], [DATE], [PHONE],
// [PHYSICIAN NAME], ...). Clinical content is never touched by the patterns
// below — every regex requires an identifier shape no measurement has.
//
// Logging rule: counts by type only. Never log matched text.

// A capitalized or ALL-CAPS word as it appears in a name
const NAME_WORD = "(?:[A-Z][a-z][a-zA-Z'’-]*|[A-Z][A-Z'’-]+|[A-Z]\\.?)";

// Order matters: more specific shapes run first so a phone number is [PHONE],
// not two fragments of [MRN].
const PATTERNS = [
  // Dr./Doctor + 1-3 name words ("Dr. Smith", "Dr. JOHN A SMITH", "Doctor Jane Doe")
  { type: 'PHYSICIAN NAME', re: new RegExp(`\\b(?:Dr\\.?|Doctor)\\s+${NAME_WORD}(?:\\s+${NAME_WORD}){0,2}`, 'g') },
  // SSN
  { type: 'SSN', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  // Phone: 555-123-4567, (555) 123-4567, 555.123.4567
  { type: 'PHONE', re: /(?:\+1[-. ]?)?\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b/g },
  // Accession-style labels: ACC#/Accession/ACCESSION NO followed by an identifier
  { type: 'ACCESSION', re: /\b(?:ACC(?:ESSION)?|Accession)(?:\s*(?:#|No\.?|Number|:))?\s*[A-Za-z0-9][A-Za-z0-9-]{4,}\b/g },
  // Dates: 3/14/2024, 03-14-24, 2024-03-14
  { type: 'DATE', re: /\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/g },
  { type: 'DATE', re: /\b\d{4}-\d{2}-\d{2}\b/g },
  // Dates: March 14, 2024 · Mar 14 2024 · 14 March 2024
  { type: 'DATE', re: /\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b/gi },
  { type: 'DATE', re: /\b\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?,?\s+\d{4}\b/gi },
  // MRN-like: a standalone run of 6-10 digits. Runs last so dates/phones/SSNs
  // have already been replaced. Guards: not part of a longer number or a
  // decimal (a sentence-ending period after the digits is still a match —
  // only ".<digit>" marks a decimal), and not followed by a unit
  // (a "6.5 x 4.2 cm" mass never has 6+ contiguous digits anyway).
  { type: 'MRN', re: /(?<![\d.\-])\d{6,10}(?!\d|\.\d|\s?(?:mm|cm|mL|cc|HU)\b)/g }
];

// One text -> { text, counts } where counts is {TYPE: n} for types that hit
function patternScrub(text) {
  const counts = {};
  let out = String(text);
  for (const { type, re } of PATTERNS) {
    out = out.replace(re, () => {
      counts[type] = (counts[type] || 0) + 1;
      return `[${type}]`;
    });
  }
  return { text: out, counts };
}

// ---- Model pass (executed by the caller) ----

const SCRUB_SCHEMA = {
  type: 'OBJECT',
  properties: {
    replacements: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          original: { type: 'STRING' },
          replacement: { type: 'STRING' }
        },
        required: ['original', 'replacement']
      }
    }
  },
  required: ['replacements']
};

const SCRUB_SYSTEM = `You are a HIPAA de-identification pass for radiology report text. Earlier deterministic filters already replaced obvious identifiers with placeholders like [MRN], [DATE], [PHONE], [PHYSICIAN NAME] — leave those placeholders exactly as they are.

Find what remains of these identifier classes and return replacements:
- Person names: patients, physicians, referring providers, technologists, family members. Include names WITHOUT titles, lowercase names, and ALL-CAPS names ("MARIA E CABRERA", "smith, john"). Patients -> "[PATIENT NAME]", physicians/providers -> "[PHYSICIAN NAME]", anyone else -> "[NAME]".
- Remaining dates in any format, including partial dates with a year -> "[DATE]". A bare age ("67-year-old") is NOT a date — leave ages under 90 alone; ages 90 and over -> "[AGE 90+]".
- Locations more specific than a US state: hospital and clinic names, street addresses, cities, ZIP codes -> "[LOCATION]".
- Any other HIPAA identifier: medical record / accession / device serial numbers, email addresses, URLs, insurance or account numbers -> a matching placeholder in square brackets ("[MRN]", "[ACCESSION]", "[EMAIL]", "[ID]").

NEVER touch clinical content. These are NOT identifiers and must not appear in your replacements:
- Anatomy and eponymous anatomy or signs ("circle of Willis", "foramen of Monro", "Morison pouch", "Chance fracture")
- Named classifications, scores, and criteria ("Bosniak", "Fleischner", "LI-RADS", "Fazekas grade 3", "Glasgow Coma Scale")
- Findings, diagnoses, measurements, laterality, device SIZES and types ("8 French catheter", "5 mm nodule", "L4-L5")
- Modality, technique, contrast agents, drug names and doses
- Section headings and report structure

Rules for each replacement:
- "original" must be an EXACT substring of the text, long enough to be unambiguous (include surrounding words if a short name also appears as a common word).
- "replacement" is the placeholder alone, or the original with only the identifier swapped for the placeholder.
- If nothing remains to remove, return {"replacements": []}.`;

// Apply model-proposed replacements defensively: the original must actually
// occur, and the replacement must be nothing but placeholder(s) plus text
// drawn from the original (no new content can be injected).
function applyReplacements(text, replacements) {
  let out = String(text);
  let applied = 0;
  for (const r of replacements || []) {
    if (!r || typeof r.original !== 'string' || typeof r.replacement !== 'string') continue;
    if (r.original.length < 2 || !out.includes(r.original)) continue;
    if (!/\[[A-Z][A-Z0-9+ ]*\]/.test(r.replacement)) continue;   // must introduce a placeholder
    if (r.replacement.length > r.original.length + 40) continue; // no essays
    out = out.split(r.original).join(r.replacement);
    applied++;
  }
  return { text: out, applied };
}

// ---- Reversible redaction (the de-identified Claude pipeline) ----
// Same DETECTION as the destructive scrub — the pattern pass above plus the
// model pass the caller runs — but a different REPLACEMENT strategy: each
// distinct identifier string becomes a UNIQUE INDEXED token ([NAME_1],
// [DATE_2], [MRN_1], ...) and the token -> original map is returned so the
// server can deterministically restore the text later. The map never leaves
// the server. Identical identifier strings share one token within a redaction.

// Token stems are a small closed set so restoreRedaction's regex can be exact.
const TOKEN_RE = /\[(?:NAME|DATE|AGE|MRN|PHONE|SSN|ACCESSION|LOCATION|EMAIL|ID)_\d+\]/g;

// Appended to SCRUB_SYSTEM when the model pass runs in reversible-redaction
// mode, where the earlier pass emits INDEXED tokens the base prompt's
// placeholder examples don't cover.
const REDACT_TOKENS_NOTE = `

Indexed tokens like [NAME_1], [DATE_2], [MRN_1] are ALREADY-REDACTED placeholders from the earlier deterministic pass — leave them exactly as written and never include them in your replacements.`;

function tokenStem(type) {
  const t = String(type || '').toUpperCase();
  if (t.includes('NAME')) return 'NAME';
  if (t.includes('DATE')) return 'DATE';
  if (t.includes('AGE')) return 'AGE';
  for (const s of ['MRN', 'PHONE', 'SSN', 'ACCESSION', 'LOCATION', 'EMAIL']) {
    if (t.includes(s)) return s;
  }
  return 'ID';
}

// One redaction's shared state, threaded across every text it covers so the
// same name found in findings, impression, and notes gets the same token.
function newRedaction() {
  return { map: {}, byIdentifier: new Map(), counters: {} };
}

function tokenFor(state, type, identifier) {
  const stem = tokenStem(type);
  const key = stem + ' ' + identifier;
  let token = state.byIdentifier.get(key);
  if (!token) {
    state.counters[stem] = (state.counters[stem] || 0) + 1;
    token = `[${stem}_${state.counters[stem]}]`;
    state.byIdentifier.set(key, token);
    state.map[token] = identifier;
  }
  return token;
}

// Pattern pass, reversible flavor: same PATTERNS, indexed tokens instead of
// bare placeholders.
function patternRedact(text, state) {
  let out = String(text);
  for (const { type, re } of PATTERNS) {
    out = out.replace(re, m => tokenFor(state, type, m));
  }
  return out;
}

// Apply model-pass replacements reversibly. The model returns {original,
// replacement} where replacement is a placeholder alone or the original with
// just the identifier swapped for a placeholder; recover the identifier by
// peeling the shared prefix/suffix so only the identifier itself is tokenized.
// When that derivation fails (multiple placeholders, mismatched context), the
// whole original is tokenized — coarser, but still exactly reversible.
function applyReplacementsReversible(text, replacements, state) {
  let out = String(text);
  let applied = 0;
  for (const r of replacements || []) {
    if (!r || typeof r.original !== 'string' || typeof r.replacement !== 'string') continue;
    if (r.original.length < 2 || !out.includes(r.original)) continue;
    const m = /\[([A-Z][A-Z0-9+ ]*)\]/.exec(r.replacement);
    if (!m) continue;                                          // must introduce a placeholder
    if (r.replacement.length > r.original.length + 40) continue;
    const prefix = r.replacement.slice(0, m.index);
    const suffix = r.replacement.slice(m.index + m[0].length);
    let identifier = r.original, pre = '', post = '';
    const singlePlaceholder = !/\[[A-Z][A-Z0-9+ ]*\]/.test(prefix + suffix);
    if (singlePlaceholder &&
        r.original.startsWith(prefix) && r.original.endsWith(suffix) &&
        r.original.length > prefix.length + suffix.length) {
      identifier = r.original.slice(prefix.length, r.original.length - suffix.length);
      pre = prefix;
      post = suffix;
    }
    // Never re-token our own tokens: the model occasionally "normalizes" an
    // indexed token it doesn't recognize ([NAME_1] → [PHYSICIAN NAME]);
    // applying that would chain tokens ([NAME_2] → "[NAME_1]") and leave a
    // literal token behind after the single-pass restoration.
    TOKEN_RE.lastIndex = 0;
    if (TOKEN_RE.test(identifier)) continue;
    const token = tokenFor(state, m[1], identifier);
    out = out.split(pre + identifier + post).join(pre + token + post);
    // The model anchors identifiers in context; other occurrences of the same
    // identifier may sit outside that context. This payload leaves the BAA
    // boundary, so sweep the remaining occurrences too — but only when the
    // identifier is unambiguous enough that a bare global replace can't touch
    // clinical prose (multi-word, or a single long word).
    const unambiguous = /\s/.test(identifier.trim()) || identifier.trim().length >= 6;
    if (unambiguous && out.includes(identifier)) {
      out = out.split(identifier).join(token);
    }
    applied++;
  }
  return { text: out, applied };
}

// Deterministic reverse substitution — no model call. Unknown tokens (a
// bracketed string the model happened to write) are left as-is.
function restoreRedaction(text, map) {
  return String(text).replace(new RegExp(TOKEN_RE.source, 'g'),
    t => (map && t in map ? map[t] : t));
}

module.exports = {
  patternScrub, applyReplacements, SCRUB_SCHEMA, SCRUB_SYSTEM, REDACT_TOKENS_NOTE,
  newRedaction, patternRedact, applyReplacementsReversible, restoreRedaction
};
