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

// AssemblyAI Streaming via WebSocket
wss.on('connection', async (clientWs) => {
  console.log('Client connected for AssemblyAI transcription');
  
  let transcriber = null;
  let isTranscriberReady = false;

  try {
    transcriber = assemblyai.streaming.transcriber({
      sampleRate: 16_000,
    });

    // Wait for socket to open
    transcriber.on('open', ({ sessionId }) => {
      console.log('✅ AssemblyAI session opened:', sessionId);
      isTranscriberReady = true;
    });

    // Handle 'turn' events
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
      clientWs.send(JSON.stringify({
        type: 'error',
        message: error.message
      }));
    });

    transcriber.on('close', (code, reason) => {
      console.log('AssemblyAI transcriber closed:', code, reason);
      isTranscriberReady = false;
    });

    // Connect
    await transcriber.connect();
    console.log('Connecting to AssemblyAI...');

    // Forward audio only when ready
    clientWs.on('message', (message) => {
      if (Buffer.isBuffer(message) && transcriber && isTranscriberReady) {
        transcriber.sendAudio(message);
      }
    });

    clientWs.on('close', async () => {
      console.log('Client disconnected');
      isTranscriberReady = false;
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
    service: 'Flow Dictation API'
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🎤 AssemblyAI Universal-Streaming enabled`);
});
