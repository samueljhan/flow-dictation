const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

const app = express();
const upload = multer({ dest: 'uploads/' });
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

console.log('=== Environment Check ===');
console.log('OpenAI API Key:', !!process.env.OPENAI_API_KEY ? '✓ Set' : '✗ Missing');
console.log('========================');

// Common radiology term corrections
const RADIOLOGY_VOCABULARY = {
  'new motor thorax': 'pneumothorax',
  'plural effusion': 'pleural effusion',
  'consolidation': 'consolidation',
  'atelectasis': 'atelectasis',
  'infiltrate': 'infiltrate',
  'lymphadenopathy': 'lymphadenopathy',
  'adenopathy': 'adenopathy',
  'calcification': 'calcification',
  'nodule': 'nodule',
  'mass': 'mass',
  'lesion': 'lesion',
  'opacity': 'opacity',
  'lucency': 'lucency',
  'air bronchogram': 'air bronchogram',
  'bronchiectasis': 'bronchiectasis',
  'emphysema': 'emphysema',
  'fibrosis': 'fibrosis',
  'edema': 'edema',
  'hemorrhage': 'hemorrhage',
  'infarct': 'infarct',
  'ischemia': 'ischemia',
};

const RADIOLOGY_SYSTEM_PROMPT = `You are an expert radiologist assistant helping residents write structured radiology reports.

CRITICAL RULES:
1. Generate reports in this EXACT structure with these headers:
   - CLINICAL HISTORY
   - TECHNIQUE
   - COMPARISON
   - FINDINGS
   - IMPRESSION

2. Use standard radiology terminology and ACR guidelines
3. Be concise but complete
4. Number impression points (1., 2., etc.)
5. If findings are normal, state "No acute abnormality"
6. Always include relevant negatives
7. Use present tense for findings
8. Format for easy copying into PACS

IMPORTANT: Do not include patient names, MRNs, dates of birth, or any identifiers.`;

const MEDICAL_CORRECTION_PROMPT = `You are a medical transcription specialist. Fix any medical terminology errors in the following dictation while preserving the speaker's intended meaning.

Common errors to fix:
- "new motor thorax" → "pneumothorax"
- "plural effusion" → "pleural effusion"
- "infiltrate" misheard as "in filtrate"
- "atelectasis" misheard as "at electric basis"
- "lymphadenopathy" misheard as "limb adenopathy"
- "consolidation" misheard as "console a dashin"
- "bronchiectasis" misheard as "bronco ectasis"
- Anatomical terms (ileum vs ilium, mucosa vs mucous)
- Drug names and dosages
- Measurement units (cm, mm, Hounsfield units)

Rules:
1. ONLY fix obvious medical terminology errors
2. Do NOT change the meaning or add information
3. Do NOT reformat or restructure
4. Keep all measurements, laterality (right/left), and anatomical descriptions exact
5. Return ONLY the corrected text, nothing else

Dictation to correct:`;

// Enhanced Whisper transcription with medical context
app.post('/api/transcribe', upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Audio file is required' });
    }

    console.log('Transcribing audio file...');
    const audioFile = fs.createReadStream(req.file.path);
    
    // Step 1: Transcribe with Whisper using medical prompt
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
      language: 'en',
      prompt: 'This is a radiology report dictation including medical terms like pneumothorax, pleural effusion, consolidation, atelectasis, infiltrate, lymphadenopathy, bronchiectasis, mass, nodule, lesion, opacity, calcification, adenopathy.', // Vocabulary hints
    });

    fs.unlinkSync(req.file.path);
    
    let correctedText = transcription.text;
    
    // Step 2: Post-process with GPT-4o to fix medical terms
    console.log('Post-processing with medical correction...');
    const correction = await openai.chat.completions.create({
      model: 'gpt-4o-mini', // Faster and cheaper for corrections
      messages: [
        { role: 'system', content: MEDICAL_CORRECTION_PROMPT },
        { role: 'user', content: transcription.text }
      ],
      temperature: 0.1, // Low temperature for consistent corrections
      max_tokens: 500
    });

    correctedText = correction.choices[0].message.content.trim();
    
    console.log('Original:', transcription.text);
    console.log('Corrected:', correctedText);
    
    res.json({ 
      text: correctedText,
      original: transcription.text // Include original for debugging
    });
    
  } catch (error) {
    console.error('Transcription error:', error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Transcription failed', details: error.message });
  }
});

// Enhanced report generation
app.post('/api/generate-report', async (req, res) => {
  try {
    const { findings, specialty } = req.body;
    
    if (!findings) {
      return res.status(400).json({ error: 'Findings are required' });
    }

    console.log(`Generating ${specialty} report...`);
    
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: RADIOLOGY_SYSTEM_PROMPT },
        { role: "user", content: `Generate a radiology report for these findings: ${findings}` }
      ],
      temperature: 0.3,
      max_tokens: 1000
    });

    res.json({ report: completion.choices[0].message.content });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to generate report', details: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'Flow Dictation API',
    features: ['whisper-transcription', 'medical-correction', 'report-generation']
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🎤 Enhanced Whisper + Medical Post-Processing enabled`);
});
