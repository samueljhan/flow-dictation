const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const { AssemblyAI } = require('assemblyai');
const http = require('http');
const WebSocket = require('ws');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const upload = multer({ dest: 'uploads/' });
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const assemblyai = new AssemblyAI({
  apiKey: process.env.ASSEMBLYAI_API_KEY
});

console.log('=== Environment Check ===');
console.log('OpenAI:', !!process.env.OPENAI_API_KEY ? '✓' : '✗');
console.log('AssemblyAI:', !!process.env.ASSEMBLYAI_API_KEY ? '✓' : '✗');
console.log('========================');

const NUCLEAR_MEDICINE_SYSTEM_PROMPT = `You are an expert nuclear medicine radiologist creating structured PET/CT and nuclear medicine reports.

CRITICAL FORMATTING RULES:
1. Use EXACTLY this structure with proper spacing:

FINDINGS:

HEAD AND NECK: [findings or "There is no hypermetabolic lymphadenopathy seen."]

SKULL BASE: [findings or "No abnormal hypermetabolism seen."]

CHEST

LUNGS: [findings or "There are no hypermetabolic lung nodules visualized."]

MEDIASTINUM: [findings or "There is no hypermetabolic lymphadenopathy seen."]

ABDOMEN/PELVIS

LIVER/SPLEEN: [findings or "No abnormal hypermetabolism is seen."]

KIDNEY/ADRENALS: [findings or "No abnormal hypermetabolism is seen."]

LYMPH NODES: [findings or "There is no hypermetabolic lymphadenopathy seen."]

GI TRACT: [findings or "There is physiologic metabolic activity throughout the gastrointestinal tract with no focal abnormal hypermetabolism."]

BONES/BONE MARROW: [findings or "There is no abnormal hypermetabolism seen."]

EXTREMITIES: [findings or "No abnormal hypermetabolism seen."]

OTHER: [additional findings or "There are no other abnormal foci of hypermetabolic activity."]

NON-PET FINDINGS: [CT findings like "Atherosclerotic calcifications..." or omit if none]


CONCLUSION:

1. [First conclusion point]
2. [Second conclusion point]
[etc.]

IMPORTANT GUIDELINES:
- Only include POSITIVE findings in each section
- Use "no/without" for negative findings in standard phrasing
- Include SUV values when mentioned (e.g., "max SUV of 12.4")
- Describe lesion locations precisely (e.g., "right lower lobe", "left posterior peripheral zone")
- Compare to prior studies when mentioned (e.g., "increased from prior", "new since...")
- Use proper anatomical terminology
- Keep tone clinical and objective
- Number all conclusion points
- Include size measurements when provided (e.g., "3.2 cm lesion")
- Mention any sclerotic/lytic changes in bones
- Note any interval changes explicitly

STYLE NOTES:
- Present tense for current findings
- Past tense for comparisons ("previously seen", "was noted")
- Be concise but complete
- Use medical abbreviations appropriately (SUV, FDG, PET/CT)
- Maintain professional radiologist voice

DO NOT include: Patient names, MRNs, dates of birth, exam dates, physician names, or any PHI.`;

wss.on('connection', async (clientWs) => {
  console.log('Client connected for AssemblyAI transcription');
  
  let transcriber = null;
  let isReady = false;
  let audioBuffer = [];
  const SAMPLE_RATE = 16000;
  const BUFFER_SIZE = SAMPLE_RATE / 20;

  try {
    transcriber = assemblyai.streaming.transcriber({
      sampleRate: SAMPLE_RATE,
    });

    transcriber.on('open', ({ sessionId }) => {
      console.log('✅ AssemblyAI session opened:', sessionId);
      isReady = true;
    });

    transcriber.on('turn', (turn) => {
      console.log('Transcript:', turn.transcript);
      
      clientWs.send(JSON.stringify({
        type: 'transcript',
        text: turn.transcript,
        is_final: turn.end_of_turn
      }));
    });

    transcriber.on('error', (error) => {
      console.error('AssemblyAI error:', error);
      isReady = false;
      clientWs.send(JSON.stringify({
        type: 'error',
        message: error.message
      }));
    });

    transcriber.on('close', (code, reason) => {
      console.log('AssemblyAI closed:', code, reason);
      isReady = false;
    });

    await transcriber.connect();
    await new Promise(resolve => setTimeout(resolve, 100));

    clientWs.on('message', (message) => {
      if (!Buffer.isBuffer(message) || !isReady || !transcriber) return;

      const samples = new Int16Array(message.buffer, message.byteOffset, message.byteLength / 2);
      audioBuffer.push(...samples);

      while (audioBuffer.length >= BUFFER_SIZE) {
        const chunk = audioBuffer.slice(0, BUFFER_SIZE);
        audioBuffer = audioBuffer.slice(BUFFER_SIZE);
        
        const buffer = Buffer.from(new Int16Array(chunk).buffer);
        
        try {
          transcriber.sendAudio(buffer);
        } catch (err) {
          console.error('Error sending audio:', err.message);
        }
      }
    });

    clientWs.on('close', async () => {
      console.log('Client disconnected');
      isReady = false;
      audioBuffer = [];
      if (transcriber) {
        await transcriber.close();
      }
    });

  } catch (error) {
    console.error('Error setting up AssemblyAI:', error);
    clientWs.send(JSON.stringify({
      type: 'error',
      message: 'Failed to initialize: ' + error.message
    }));
  }
});

app.post('/api/transcribe', upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Audio file is required' });
    }

    const webmPath = req.file.path + '.webm';
    fs.renameSync(req.file.path, webmPath);
    
    const transcript = await assemblyai.transcripts.transcribe({
      audio: webmPath
    });

    fs.unlinkSync(webmPath);
    
    res.json({ 
      text: transcript.text,
      confidence: transcript.confidence
    });
    
  } catch (error) {
    console.error('Transcription error:', error);
    if (req.file) {
      const webmPath = req.file.path + '.webm';
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      if (fs.existsSync(webmPath)) fs.unlinkSync(webmPath);
    }
    res.status(500).json({ error: 'Transcription failed', details: error.message });
  }
});

app.post('/api/generate-report', async (req, res) => {
  try {
    const { findings, specialty } = req.body;
    
    if (!findings) {
      return res.status(400).json({ error: 'Findings are required' });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: NUCLEAR_MEDICINE_SYSTEM_PROMPT },
        { role: "user", content: `Generate a nuclear medicine PET/CT report based on these dictated findings. Only include the sections and findings that were mentioned. Use standard negative phrasing for unremarkable areas:\n\n${findings}` }
      ],
      temperature: 0.2,
      max_tokens: 2000
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
    service: 'Flow Dictation API'
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🎤 AssemblyAI Universal-Streaming enabled`);
  console.log(`☢️  Nuclear Medicine/PET reporting mode active`);
});
