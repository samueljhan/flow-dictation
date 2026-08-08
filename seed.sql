-- Flow Dictation — knowledge layer seed data
-- Review, edit to taste, then run ONCE in the Supabase SQL editor
-- (running twice will duplicate rows — these tables have no unique constraints).

-- ==================== STYLE GUIDE ====================

insert into style_guide (section, rule) values
-- general
('general', 'Write findings as concise declarative statements in present tense.'),
('general', 'Omit filler constructions: "is seen", "is noted", "is identified", "is visualized" — state the finding directly.'),
('general', 'One finding per sentence where practical; do not stack unrelated findings in a single sentence.'),
('general', 'Localize precisely: name the segment, lobe, level, or compartment rather than a vague region.'),
('general', 'Avoid "significant" without a qualifier — state the size, degree, or clinical relevance explicitly.'),
('general', 'Avoid ambiguous split grading such as "grade 2/3" — commit to a grade, or give a range and say why.'),
('general', 'Comment on image quality only when it limits interpretation, and then state exactly what is limited.'),
-- findings
('findings', 'Report organ by organ in a consistent anatomic order for cross-sectional studies.'),
('findings', 'Use standard one-line negative statements for normal organs; avoid multi-sentence normals.'),
('findings', 'For each index lesion give measurement, precise location, and series/image reference.'),
('findings', 'Scope statements to what is imaged: "The visualized lung bases are clear."'),
-- impressions
('impressions', 'Do not number, letter, or bullet impression items — put each item on its own line, ordered by clinical significance, most important first.'),
('impressions', 'The first impression item answers the clinical question directly.'),
('impressions', 'Never introduce a finding in the impression that is not described in the report body.'),
('impressions', 'Include only findings that change patient management or answer the clinical question; leave incidental, chronic, and stable benign findings in the body.'),
('impressions', 'Do not restate normals in the impression; include a pertinent negative only when it answers the clinical question.'),
('impressions', 'Keep each impression item to one or two sentences — detail belongs in the findings.'),
('impressions', 'State recommendations explicitly with modality and interval (e.g., "Recommend follow-up CT in 6 months").'),
-- hedging
('hedging', 'Use the hedging hierarchy deliberately (diagnostic of > consistent with > compatible with > suspicious for > concerning for > may represent > cannot be excluded); choose the weakest hedge the evidence supports.'),
('hedging', 'Never double-hedge ("may possibly represent", "could potentially be compatible with").'),
-- measurements
('measurements', 'Report measurements in centimeters with one decimal (2.3 cm), except structures conventionally measured in millimeters (e.g., pulmonary nodules).'),
('measurements', 'Give multi-axis measurements in a consistent order (AP × transverse × craniocaudal).'),
-- comparison
('comparison', 'Name the comparison study and date; describe interval change explicitly ("unchanged", "interval increase", "new from prior").');

-- ==================== RADIOLOGY LANGUAGE REFERENCE ====================

insert into rad_language (category, content) values
-- findings_phrasing
('findings_phrasing', 'Declarative present tense with size and location up front: "There is a 2.3 cm rim-enhancing collection in the right hepatic lobe."'),
('findings_phrasing', 'Organ-level normal statement: "The liver is normal in size and attenuation."'),
('findings_phrasing', 'Scope-limited statement for partially imaged anatomy: "The visualized lung bases are clear."'),
('findings_phrasing', '"Unremarkable" is for organ systems without findings ("The pancreas is unremarkable") — do not apply it to the whole study when a clinical question exists.'),
('findings_phrasing', 'Lead with laterality when it disambiguates: "Right lower lobe consolidation", not "Consolidation in the lower lobe on the right".'),
('findings_phrasing', 'Prefer a direct statement or "demonstrates" over "shows evidence of".'),
('findings_phrasing', 'Characterize masses by enhancement pattern, margin, and internal architecture — not "complex lesion" alone.'),
('findings_phrasing', 'Lines and tubes: name the device, course, and tip position: "Endotracheal tube tip 3.2 cm above the carina."'),
-- impression_phrasing
('impression_phrasing', 'Lead with the diagnosis that answers the clinical question: "Acute uncomplicated appendicitis."'),
('impression_phrasing', 'Pertinent negative phrasing when it answers the referrer: "No drainable fluid collection."'),
('impression_phrasing', 'Refer to the body rather than repeating detail: "Findings are compatible with [diagnosis], as described above."'),
('impression_phrasing', 'Direct recommendation: "Recommend contrast-enhanced MRI for further characterization."'),
('impression_phrasing', 'Optional-recommendation register: "Short-interval follow-up ultrasound in 6 weeks can be considered."'),
('impression_phrasing', 'Closure language for benign findings: "No follow-up is required for this finding."'),
('impression_phrasing', 'Cite guidelines for surveillance intervals when applicable: "Recommend follow-up CT in 6-12 months per Fleischner Society guidelines."'),
-- hedging (hierarchy, strongest to weakest, with when-to-use)
('hedging', '"Diagnostic of" — pathognomonic appearance; no realistic alternative exists.'),
('hedging', '"Consistent with" — imaging strongly supports the stated diagnosis in this clinical context.'),
('hedging', '"Compatible with" — imaging supports the diagnosis but alternatives are not excluded.'),
('hedging', '"Suspicious for" — features favor the diagnosis and workup or action is warranted.'),
('hedging', '"Concerning for" — features raise a serious diagnosis that must be addressed even if less likely.'),
('hedging', '"May represent" — one of several reasonable possibilities; pair with a short differential.'),
('hedging', '"Cannot be excluded" — reserve for clinically important diagnoses the study cannot rule out; use sparingly and never as the primary conclusion.'),
-- negatives (standard normal statements by region/modality)
('negatives', 'Head CT: "No acute intracranial hemorrhage, mass effect, or midline shift."'),
('negatives', 'Chest radiograph: "No focal consolidation, pleural effusion, or pneumothorax."'),
('negatives', 'MSK radiograph: "No acute fracture or dislocation."'),
('negatives', 'Abdominal CT: "No free air or free fluid in the abdomen or pelvis."'),
('negatives', 'Cervical spine CT: "No acute fracture or malalignment of the cervical spine."'),
('negatives', 'Closing catch-all, used once per report: "The remaining visualized structures are unremarkable."'),
-- measurements
('measurements', 'Centimeters with one decimal: "2.3 cm", not "23 mm" — except sub-centimeter structures conventionally reported in mm (pulmonary nodules: "6 mm nodule").'),
('measurements', 'Axes order: AP × transverse × craniocaudal, e.g., "5.2 × 3.1 × 4.4 cm".'),
('measurements', 'Reference index lesions to acquisition: "(series 4, image 52)".'),
('measurements', 'Interval comparison convention: "now 2.3 cm, previously measuring 1.8 cm".'),
('measurements', 'Use conventional dimensions per organ (spleen craniocaudal length, prostate volume, aortic diameter perpendicular to flow lumen).'),
-- comparison
('comparison', 'Header convention: "Comparison: CT abdomen pelvis dated [date]." or "No prior studies available for comparison."'),
('comparison', 'Stability: "Unchanged from prior." / "Stable compared with [date]."'),
('comparison', 'Change with numbers: "Interval increase in size of the right adnexal cyst, now 4.1 cm, previously 2.9 cm."'),
('comparison', 'New findings: "New from the prior examination."'),
('comparison', 'Resolution: "Previously seen left pleural effusion has resolved."'),
-- modality_conventions
('modality_conventions', 'CT: give attenuation in HU where it changes management: "fluid attenuation (8 HU)", "macroscopic fat (-40 HU)".'),
('modality_conventions', 'MRI: describe signal per sequence: "T2 hyperintense, T1 hypointense, with restricted diffusion and avid enhancement."'),
('modality_conventions', 'Ultrasound: echogenicity relative to a reference organ ("hyperechoic relative to liver parenchyma") and Doppler vascularity.'),
('modality_conventions', 'Radiographs: note technique when it affects reading: "AP supine technique; the cardiomediastinal silhouette is magnified."'),
('modality_conventions', 'PET/CT: report SUVmax with a reference: "SUVmax 8.4, above hepatic background."'),
-- words_to_avoid
('words_to_avoid', '"is seen" / "is noted" / "is identified" — delete; state the finding directly.'),
('words_to_avoid', '"evidence of" — usually deletable: "No evidence of fracture" → "No fracture."'),
('words_to_avoid', '"significant" without a qualifier — say how big, how severe, or why it matters.'),
('words_to_avoid', '"prominent" without a measurement or comparison — ambiguous between normal variant and pathology.'),
('words_to_avoid', 'Reflexive "cannot rule out" — use only for actionable, clinically important diagnoses.'),
('words_to_avoid', '"Unremarkable study" as the entire impression when a specific clinical question was asked — answer the question.'),
('words_to_avoid', '"grossly" ("grossly normal", "grossly stable") — vague; state the scope or limitation instead.');
