const express = require('express');
const OpenAI = require('openai');
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

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// AWS Transcribe Medical configuration
const transcribeClient = new TranscribeStreamingClient({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

console.log('=== Environment Check ===');
console.log('OpenAI:', !!process.env.OPENAI_API_KEY ? '✓' : '✗');
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

  clientWs.on('message', async (message) => {
    if (!Buffer.isBuffer(message)) return;

    // First audio message - start transcription
    if (!isTranscribing) {
      try {
        audioStream = new PassThrough();
        // Fix the MaxListenersExceeded warning
        audioStream.setMaxListeners(0);
        
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        const command = new StartMedicalStreamTranscriptionCommand({
          LanguageCode: 'en-US',
          MediaSampleRateHertz: 16000,
          MediaEncoding: 'pcm',
          Specialty: 'RADIOLOGY', // Can be RADIOLOGY, CARDIOLOGY, NEUROLOGY, ONCOLOGY, PRIMARYCARE, UROLOGY
          Type: 'DICTATION', // DICTATION for single speaker, CONVERSATION for multiple
          // REMOVED EnableChannelIdentification - not needed for DICTATION
          // REMOVED NumberOfChannels - let AWS default handle it
          AudioStream: (async function* () {
            for await (const chunk of audioStream) {
              yield { AudioEvent: { AudioChunk: chunk } };
            }
          })()
        });

        const response = await transcribeClient.send(command);
        transcribeStream = response.TranscriptResultStream;
        isTranscribing = true;
        
        console.log('✅ AWS Transcribe Medical session started:', sessionId);

        // Process transcription results
        for await (const event of transcribeStream) {
          if (event.TranscriptEvent) {
            const results = event.TranscriptEvent.Transcript.Results;
            
            for (const result of results) {
              if (!result.IsPartial) {
                // Final transcription
                const transcript = result.Alternatives[0].Transcript;
                
                if (transcript && transcript.trim()) {
                  console.log('Final transcript:', transcript);
                  
                  clientWs.send(JSON.stringify({
                    type: 'transcript',
                    text: transcript,
                    is_final: true,
                    confidence: result.Alternatives[0].Items?.[0]?.Confidence
                  }));
                }
              } else {
                // Partial transcription
                const transcript = result.Alternatives[0].Transcript;
                
                if (transcript && transcript.trim()) {
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
      } catch (error) {
        console.error('Error starting AWS Transcribe Medical:', error);
        clientWs.send(JSON.stringify({
          type: 'error',
          message: 'Transcription error: ' + error.message
        }));
        isTranscribing = false;
      }
    }

    // Send audio to AWS Transcribe
    if (audioStream && isTranscribing) {
      try {
        // Convert Int16Array to Buffer if needed
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
  });
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
    service: 'Flow Dictation API',
    transcription: 'AWS Transcribe Medical'
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🩺 AWS Transcribe Medical enabled`);
  console.log(`☢️  Nuclear Medicine/PET reporting mode active`);
  console.log(`📍 Region: ${process.env.AWS_REGION || 'us-east-1'}`);
});
