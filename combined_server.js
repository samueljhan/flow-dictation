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

// Text-based report generation endpoint
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

// Audio transcription endpoint
app.post('/api/transcribe', upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Audio file is required' });
    }

    const audioFile = fs.createReadStream(req.file.path);
    
    const transcription = await openai.audio.transcriptions.create({
      file: audioFile,
      model: 'whisper-1',
    });

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);
    
    res.json({ text: transcription.text });
  } catch (error) {
    console.error('Transcription error:', error);
    // Clean up file if it exists
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Transcription failed', details: error.message });
  }
});

// Process transcribed text into formatted report
app.post('/api/process', async (req, res) => {
  try {
    const { text, template } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        {
          role: 'system',
          content: template === 'radiology' 
            ? RADIOLOGY_SYSTEM_PROMPT
            : `You are a medical transcription assistant. Format the following transcription according to the ${template} template. Maintain medical accuracy and proper formatting.`
        },
        {
          role: 'user',
          content: text
        }
      ],
      temperature: 0.3,
      max_tokens: 1000
    });

    res.json({ formatted: completion.choices[0].message.content });
  } catch (error) {
    console.error('Processing error:', error);
    res.status(500).json({ error: 'Processing failed', details: error.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'Flow Dictation API',
    features: ['text-generation', 'audio-transcription', 'text-processing']
  });
});

// Start server - bind to 0.0.0.0 for Railway
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
});
