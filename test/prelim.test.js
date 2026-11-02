const test = require('node:test');
const assert = require('node:assert/strict');
const { parsePrelimOutput } = require('../prelim');

const REPORT = 'Hyperattenuating masslike lesion in the left parietotemporal lobe measuring about 1.8 x 1.7 cm (Series 2, Image 39), not seen on prior CT and MR brain imaging from 2018. Findings concerning for intraparenchymal metastasis. Recommend MRI head with and without contrast.\n\n' +
  'Chronic left MCA territory infarct.';

test('splits the report block from omitted/confirm notes', () => {
  const p = parsePrelimOutput('FINDINGS/IMPRESSION:\n' + REPORT +
    '\n\nOmitted as incidental: mild paranasal sinus mucosal thickening.\n' +
    '[Confirm: midline shift, herniation, and hydrocephalus — not stated in the notes.]');
  assert.equal(p.kind, 'prelim');
  assert.equal(p.report, 'FINDINGS/IMPRESSION:\n' + REPORT);
  assert.deepEqual(p.notes, [
    'Omitted as incidental: mild paranasal sinus mucosal thickening.',
    '[Confirm: midline shift, herniation, and hydrocephalus — not stated in the notes.]'
  ]);
});

test('no notes when nothing was omitted', () => {
  const p = parsePrelimOutput('FINDINGS/IMPRESSION:\n' + REPORT);
  assert.equal(p.kind, 'prelim');
  assert.deepEqual(p.notes, []);
  assert.equal(p.report, 'FINDINGS/IMPRESSION:\n' + REPORT);
});

test('normalizes a bold or spaced heading and strips markdown', () => {
  const p = parsePrelimOutput('**FINDINGS / IMPRESSION**\n' + REPORT);
  assert.equal(p.kind, 'prelim');
  assert.ok(p.report.startsWith('FINDINGS/IMPRESSION:\n' + REPORT.slice(0, 20)));
  assert.ok(!p.report.includes('**'));
});

test('a block without the heading but with notes is still a prelim', () => {
  const p = parsePrelimOutput(REPORT + '\n\nOmitted as incidental: small arachnoid cyst.');
  assert.equal(p.kind, 'prelim');
  assert.equal(p.report, 'FINDINGS/IMPRESSION:\n' + REPORT);
  assert.deepEqual(p.notes, ['Omitted as incidental: small arachnoid cyst.']);
});

test('a plain prose answer to a follow-up question stays text', () => {
  const p = parsePrelimOutput('The lesion\'s hyperattenuation most likely reflects hemorrhage within the metastasis.');
  assert.equal(p.kind, 'text');
  assert.match(p.text, /^The lesion/);
});

test('wrapped note lines join their note', () => {
  const p = parsePrelimOutput('FINDINGS/IMPRESSION:\n' + REPORT +
    '\n\nOmitted as incidental: mild sinus disease,\nsmall renal cyst.');
  assert.deepEqual(p.notes, ['Omitted as incidental: mild sinus disease, small renal cyst.']);
});
