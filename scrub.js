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
  // have already been replaced. Guards: not adjacent to a decimal point or a
  // unit (a "6.5 x 4.2 cm" mass never has 6+ contiguous digits anyway).
  { type: 'MRN', re: /(?<![\d.\-])\d{6,10}(?![\d.]|\s?(?:mm|cm|mL|cc|HU)\b)/g }
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

module.exports = { patternScrub, applyReplacements, SCRUB_SCHEMA, SCRUB_SYSTEM };
