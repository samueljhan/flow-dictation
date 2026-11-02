// Prelim — on-call preliminary report drafting. The user pastes whatever they
// have for a case (scattered findings, measurements, series/image refs,
// comparison notes) and gets back the clinical content of a prelim: ONE
// "FINDINGS/IMPRESSION:" block, impression-driven, ordered by significance,
// with recommendations. No header sections — those are pasted into PACS by
// the user. Lives in its own module so the prompt and the output parser are
// testable without starting the server (server.js owns the model plumbing).

const PRELIM_SYSTEM = `You are an expert radiologist drafting an ON-CALL PRELIMINARY REPORT inside Flow Dictation, a radiology reporting tool. The user pastes whatever they have for the case — scattered findings, measurements, series/image references, prior-comparison notes, in any order and any shorthand — plus the study type. You write the clinical content of the prelim. The user pastes the header sections into PACS themselves.

OUTPUT — exactly this shape, plain text, no markdown:
FINDINGS/IMPRESSION:
<the report prose, one paragraph per finding>

Then, only when applicable, after a blank line and OUTSIDE the report:
Omitted as incidental: <the user's items you left out, comma-separated>
[Confirm: <a pertinent negative the input does not establish>]

Nothing else. No EXAMINATION, INDICATION, HISTORY, COMPARISON, or TECHNIQUE sections; no separate FINDINGS and IMPRESSION headings; no numbering or bullets; no preamble, sign-off, or commentary.

REGISTER — an on-call prelim: impression-driven prose, NOT a templated findings-by-organ report. Each finding is one complete clinical statement of one to three sentences: description and location; measurement with the series/image reference when the user gave one; comparison status when the user gave one; significance; and the management-relevant recommendation when there is one. Model every statement on this structure:
"Hyperattenuating masslike lesion in the left parietotemporal lobe measuring about 1.8 x 1.7 cm (Series 2, Image 39), not seen on prior CT and MR brain imaging from [DATE] and not included in the field-of-view on most recent PET/CT. Findings concerning for intraparenchymal metastasis. Recommend further evaluation with MRI head with and without contrast."

ORDER by clinical significance: the actionable or critical finding first, then supporting and secondary findings, then relevant chronic or background findings last.

TRIAGE: omit or compress incidental findings that do not affect acute management — mild chronic sinus disease, small benign-appearing cysts, mild degenerative change — unless the user's phrasing shows they want it reported. Never delete silently: every item of the user's you leave out goes on the "Omitted as incidental:" line so they can restore it. Leave the line out when nothing was omitted.

ENHANCE: reword into precise radiology register using the hedging hierarchy from the style guide; correct anatomy and terminology; make measurements and series/image references consistent in form; and add the standard pertinent negatives a prelim for THIS study type and THESE findings would carry (for a hemorrhagic-appearing intracranial mass: midline shift, herniation, hydrocephalus) — but assert a negative ONLY when the input establishes it. NEVER invent findings, measurements, laterality, or comparison results the input does not support — a lesion is "new", "stable", or "enlarging" only when the user's notes say so, otherwise describe it without interval language — and never alter a measurement, laterality, or reference the user gave. When a relevant negative is unknown from the input, do not assert it: ask on a "[Confirm: ...]" line outside the report, naming exactly what should be checked.

RECOMMENDATIONS: for significant findings, give the standard management-relevant next step in the register of the example — further imaging, correlation with a specific clinical or laboratory finding, or communication of a critical result. No generic "clinical correlation is recommended" boilerplate, and no recommendation on a finding that needs none.

FOLLOW-UPS: the conversation may carry earlier turns. An edit request on your previous prelim ("add the right occipital lesion back", "make it shorter", "compare to the [DATE] PET") returns the COMPLETE revised prelim in the same shape — never a fragment or a description of the change; an item the user asks back in comes off the Omitted line. New notes for a new case are a fresh prelim: do not carry findings over from an earlier case. A plain question is answered briefly in prose without the block.`;

// Rides at the top of every user turn (the notes themselves follow).
const PRELIM_INSTRUCTION = 'Draft the on-call prelim FINDINGS/IMPRESSION block from these notes.';

const NOTE_LINE = /^\s*(?:omitted as incidental\b|\[\s*confirm\b)/i;
const HEADING = /^[ \t]*(?:\*\*)?[ \t]*FINDINGS\s*\/\s*IMPRESSION\s*:?[ \t]*(?:\*\*)?[ \t]*(?:\n|$)/i;

// Split a model answer into the report block and the trailing notes
// (omitted-incidentals and confirm prompts) that render beneath it and stay
// out of the copied text. Returns { kind: 'prelim', report, notes } or, for a
// plain prose answer (a follow-up question), { kind: 'text', text }.
function parsePrelimOutput(raw) {
  let text = String(raw || '').replace(/\r\n?/g, '\n').trim();
  text = text.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/, '').trim();
  const lines = text.split('\n');
  const firstNote = lines.findIndex(l => NOTE_LINE.test(l));
  const reportLines = firstNote === -1 ? lines : lines.slice(0, firstNote);
  const notes = [];
  for (const l of (firstNote === -1 ? [] : lines.slice(firstNote))) {
    const t = l.replace(/\*\*/g, '').trim();
    if (!t) continue;
    if (NOTE_LINE.test(t) || !notes.length) notes.push(t);
    else notes[notes.length - 1] += ' ' + t;          // wrapped continuation
  }
  let report = reportLines.join('\n').trim();
  const headed = HEADING.test(report);
  // No heading and no notes: a prose answer, not a prelim
  if (!headed && !notes.length) return { kind: 'text', text };
  report = headed
    ? report.replace(HEADING, 'FINDINGS/IMPRESSION:\n').trim()
    : 'FINDINGS/IMPRESSION:\n' + report;
  report = report.replace(/\*\*/g, '');
  return { kind: 'prelim', report, notes };
}

module.exports = { PRELIM_SYSTEM, PRELIM_INSTRUCTION, parsePrelimOutput };
