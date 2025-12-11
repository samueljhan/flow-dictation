const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const { TranscribeStreamingClient, StartMedicalStreamTranscriptionCommand } = require("@aws-sdk/client-transcribe-streaming");
const { PassThrough } = require('stream');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const upload = multer({ dest: 'uploads/' });
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Gemini AI configuration
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// AWS Transcribe Medical configuration
const transcribeClient = new TranscribeStreamingClient({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

console.log('=== Environment Check ===');
console.log('Gemini:', !!process.env.GEMINI_API_KEY ? '✓' : '✗');
console.log('AWS Access Key:', !!process.env.AWS_ACCESS_KEY_ID ? '✓' : '✗');
console.log('AWS Secret Key:', !!process.env.AWS_SECRET_ACCESS_KEY ? '✓' : '✗');
console.log('AWS Region:', process.env.AWS_REGION || 'us-east-1');
console.log('========================');

const NUCLEAR_MEDICINE_SYSTEM_PROMPT = `You are an expert nuclear medicine radiologist creating structured PET/CT and nuclear medicine reports.

CRITICAL FORMATTING RULES:
1. Use EXACTLY this structure with proper spacing:

TECHNIQUE: [Generate appropriate technique based on study type - see examples below]

FINDINGS:

HEAD AND NECK: [findings or "There is no increased uptake within lymphadenopathy seen."]

SKULL BASE: [findings or "There is no abnormal increased uptake. There is physiologic uptake within the salivary and thyroid glands."]

CHEST

LUNGS: [findings or "There is no increased uptake within lung nodules visualized."]

MEDIASTINUM: [findings or "There is no increased uptake within lymphadenopathy seen."]

ABDOMEN/PELVIS

LIVER/SPLEEN: [findings or "No abnormal increased uptake is seen."]

ADRENALS: [findings or "No abnormal hypermetabolism is seen."]

LYMPH NODES: [findings or "There is no hypermetabolic lymphadenopathy seen."]

GI TRACT: [findings or "There is physiologic metabolic activity throughout the gastrointestinal tract with no focal abnormal hypermetabolism."]

BONES/BONE MARROW: [findings or "There is no abnormal increased uptake seen."]

EXTREMITIES: [findings or "No abnormal increased uptake seen."]

OTHER: [additional findings or "There are no other abnormal foci of increased uptake."]

NON-PET FINDINGS: [CT findings like "Atherosclerotic calcifications..." or omit if none]


CONCLUSION:

1. [First conclusion point]
2. [Second conclusion point]
[etc.]

IMPORTANT GUIDELINES:
- Only include POSITIVE findings in each section
- Use exact phrasing for negative findings: "There is no increased uptake within..." or "No abnormal increased uptake..."
- Use "increased uptake" terminology (not "hypermetabolic") to match standard nuclear medicine phrasing
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
  console.log('Client connected for AWS Transcribe Medical');
  
  let transcribeStream = null;
  let audioStream = null;
  let isTranscribing = false;
  let sessionCount = 0;
  
  clientWs.on('message', async (message) => {
    if (!Buffer.isBuffer(message)) return;

    // Start transcription on first audio message
    if (!isTranscribing && !transcribeStream) {
      try {
        isTranscribing = true;
        sessionCount++;
        console.log(`Starting session #${sessionCount}`);
        
        // Create audio stream first
        audioStream = new PassThrough();
        audioStream.setMaxListeners(0);
        
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        // Start sending audio immediately
        const audioBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
        audioStream.write(audioBuffer);
        
        const command = new StartMedicalStreamTranscriptionCommand({
          LanguageCode: 'en-US',
          MediaSampleRateHertz: 16000,
          MediaEncoding: 'pcm',
          Specialty: 'RADIOLOGY',
          Type: 'DICTATION',
          AudioStream: (async function* () {
            for await (const chunk of audioStream) {
              yield { AudioEvent: { AudioChunk: chunk } };
            }
          })()
        });

        const response = await transcribeClient.send(command);
        transcribeStream = response.TranscriptResultStream;
        
        console.log('✅ AWS Transcribe Medical session started:', sessionId);

        // Process transcription results in background
        (async () => {
          try {
            for await (const event of transcribeStream) {
              if (event.TranscriptEvent) {
                const results = event.TranscriptEvent.Transcript.Results;
                
                for (const result of results) {
                  if (!result.IsPartial) {
                    // Final transcription
                    const transcript = result.Alternatives[0].Transcript;
                    
                    if (transcript && transcript.trim()) {
                      console.log('Final transcript:', transcript);
                      
                      if (clientWs.readyState === WebSocket.OPEN) {
                        clientWs.send(JSON.stringify({
                          type: 'transcript',
                          text: transcript,
                          is_final: true,
                          confidence: result.Alternatives[0].Items?.[0]?.Confidence
                        }));
                      }
                    }
                  } else {
                    // Partial transcription
                    const transcript = result.Alternatives[0].Transcript;
                    
                    if (transcript && transcript.trim()) {
                      if (clientWs.readyState === WebSocket.OPEN) {
                        clientWs.send(JSON.stringify({
                          type: 'transcript',
                          text: transcript,
                          is_final: false
                        }));
                      }
                    }
                  }
                }
              }
            }
          } catch (error) {
            if (error.name !== 'AbortError') {
              console.error('Transcription stream error:', error.message);
            }
          } finally {
            console.log('Transcription stream ended');
            isTranscribing = false;
            transcribeStream = null;
          }
        })();
        
      } catch (error) {
        console.error('Error starting AWS Transcribe Medical:', error);
        isTranscribing = false;
        transcribeStream = null;
        
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(JSON.stringify({
            type: 'error',
            message: 'Transcription error: ' + error.message
          }));
        }
      }
    } else if (audioStream && isTranscribing) {
      // Continue sending audio
      try {
        const audioBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);
        audioStream.write(audioBuffer);
      } catch (error) {
        console.error('Error sending audio to AWS:', error);
      }
    }
  });

  clientWs.on('close', () => {
    console.log('Client disconnected');
    isTranscribing = false;
    
    if (audioStream) {
      audioStream.end();
      audioStream = null;
    }
    
    transcribeStream = null;
  });

  clientWs.on('error', (error) => {
    console.error('WebSocket error:', error);
    isTranscribing = false;
    
    if (audioStream) {
      audioStream.end();
      audioStream = null;
    }
    
    transcribeStream = null;
  });
});


app.post('/api/generate-report', async (req, res) => {
  try {
    const { findings, specialty } = req.body;
    
    if (!findings) {
      return res.status(400).json({ error: 'Findings are required' });
    }

    const model = genAI.getGenerativeModel({ 
      model: "gemini-1.5-flash",
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 2000,
      }
    });
    
    const prompt = `${NUCLEAR_MEDICINE_SYSTEM_PROMPT}\n\nGenerate a nuclear medicine PET/CT report based on these dictated findings. Only include the sections and findings that were mentioned. Use standard negative phrasing for unremarkable areas:\n\n${findings}`;

    const result = await model.generateContent(prompt);
    const response = await result.response;

    res.json({ report: response.text() });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to generate report', details: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'Flow Dictation API',
    transcription: 'AWS Transcribe Medical',
    llm: 'Gemini 1.5 Flash'
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🩺 AWS Transcribe Medical enabled`);
  console.log(`✨ Gemini 1.5 Flash for report generation`);
  console.log(`☢️  Nuclear Medicine/PET reporting mode active`);
  console.log(`📍 Region: ${process.env.AWS_REGION || 'us-east-1'}`);
});