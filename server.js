const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const { createClient } = require('@deepgram/sdk');
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

// Debug: Check environment variables
console.log('Environment check:');
console.log('- OpenAI key present:', !!process.env.OPENAI_API_KEY);
console.log('- Deepgram key present:', !!process.env.DEEPGRAM_API_KEY);
console.log('- Deepgram key value:', process.env.DEEPGRAM_API_KEY ? 'exists' : 'MISSING');

const deepgram = createClient(process.env.DEEPGRAM_API_KEY);

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

// WebSocket handler for Deepgram streaming
wss.on('connection', async (ws) => {
  console.log('Client connected for streaming transcription');
  
  let deepgramLive = null;
  
  try {
    deepgramLive = deepgram.listen.live({
      model: 'nova-2-medical',
      language: 'en-US',
      smart_format: true,
      punctuate: true,
      interim_results: true,
      endpointing: 300,
      utterance_end_ms: 1000,
      encoding: 'opus',
      sample_rate: 48000,
    });

    deepgramLive.on('open', () => {
      console.log('✅ Deepgram connection opened successfully');
      
      deepgramLive.on('transcript', (data) => {
        console.log('📝 Received transcript data:', JSON.stringify(data));
        const transcript = data.channel.alternatives[0].transcript;
        console.log('📝 Transcript text:', transcript);
        
        if (transcript && transcript.trim().length > 0) {
          console.log('✅ Sending transcript to client:', transcript);
          ws.send(JSON.stringify({
            type: 'transcript',
            text: transcript,
            is_final: data.is_final,
            speech_final: data.speech_final
          }));
        } else {
          console.log('⚠️ Empty transcript, skipping');
        }
      });

      deepgramLive.on('error', (error) => {
        console.error('❌ Deepgram error:', error);
        ws.send(JSON.stringify({
          type: 'error',
          message: error.message
        }));
      });

      deepgramLive.on('close', () => {
        console.log('🔴 Deepgram connection closed');
      });

      deepgramLive.on('warning', (warning) => {
        console.warn('⚠️ Deepgram warning:', warning);
      });

      deepgramLive.on('metadata', (metadata) => {
        console.log('📊 Deepgram metadata:', metadata);
      });
    });

    ws.on('message', (message) => {
      console.log('Received audio chunk:', message.length, 'bytes');
      if (deepgramLive && deepgramLive.getReadyState() === 1) {
        console.log('Forwarding to Deepgram...');
        deepgramLive.send(message);
      } else {
        console.log('Deepgram not ready, state:', deepgramLive ? deepgramLive.getReadyState() : 'null');
      }
    });

    ws.on('close', () => {
      console.log('Client disconnected');
      if (deepgramLive) {
        deepgramLive.finish();
      }
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      if (deepgramLive) {
        deepgramLive.finish();
      }
    });

  } catch (error) {
    console.error('Error setting up Deepgram:', error);
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Failed to initialize transcription service'
    }));
  }
});

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

// Audio transcription endpoint (fallback)
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

    fs.unlinkSync(req.file.path);
    
    res.json({ text: transcription.text });
  } catch (error) {
    console.error('Transcription error:', error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Transcription failed', details: error.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'Flow Dictation API',
    features: ['text-generation', 'deepgram-streaming', 'audio-transcription']
  });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🎤 Deepgram medical transcription enabled`);
});