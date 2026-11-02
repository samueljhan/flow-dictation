// Outbound reversible redaction: bare years tied to events tokenize and
// restore exactly (the Prelim harness case), while measurements that happen
// to be four digits pass through untouched.
const test = require('node:test');
const assert = require('node:assert/strict');
const scrub = require('../scrub');

test('bare years tokenize outbound and restore exactly', () => {
  const state = scrub.newRedaction();
  const input = '1.8x1.7 hyperdense L parietotemporal s2 i39, not on 2018 CT/MR, not in PET FOV; ' +
    'resected in 2019; compare to the 2024 PET and the 03/14/2026 MRI.';
  const out = scrub.patternRedact(input, state);
  assert.doesNotMatch(out, /\b(?:2018|2019|2024|2026)\b/, 'every year should be a token');
  assert.match(out, /not on \[DATE_\d+\] CT\/MR/);
  assert.match(out, /in \[DATE_\d+\];/);
  assert.match(out, /the \[DATE_\d+\] PET/);
  assert.match(out, /the \[DATE_\d+\] MRI/);          // the full date, via the DATE pattern
  assert.ok(out.includes('1.8x1.7'), 'measurements untouched');
  assert.ok(out.includes('s2 i39'), 'series/image refs untouched');
  assert.equal(scrub.restoreRedaction(out, state.map), input);
});

test('same year twice shares one token', () => {
  const state = scrub.newRedaction();
  const out = scrub.patternRedact('new since 2018; the 2018 CT was unremarkable', state);
  const tokens = out.match(/\[DATE_\d+\]/g);
  assert.equal(tokens.length, 2);
  assert.equal(tokens[0], tokens[1]);
});

test('four-digit measurements and parts of larger numbers are not years', () => {
  const state = scrub.newRedaction();
  const text = 'volume 2000 mL, TR 2000 ms, density 1900 HU, 2.2019 cm, MRN 20190423 noted';
  const out = scrub.patternRedact(text, state);
  assert.ok(out.includes('2000 mL'));
  assert.ok(out.includes('2000 ms'));
  assert.ok(out.includes('1900 HU'));
  assert.ok(out.includes('2.2019 cm'));
  assert.match(out, /MRN \[MRN_1\] noted/);
  assert.doesNotMatch(out, /\[DATE_/);
});

test('destructive scrub is unchanged: bare years are left to its model pass', () => {
  assert.equal(scrub.patternScrub('not on 2018 CT').text, 'not on 2018 CT');
});
