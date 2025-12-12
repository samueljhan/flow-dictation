const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { google } = require('googleapis');
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

// Gmail OAuth configuration
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.NODE_ENV === 'production' 
    ? 'https://flowdictation.com/auth/google/callback'
    : 'http://localhost:8080/auth/google/callback'
);

// Simple in-memory token storage (for single user)
// For multi-user, you'd use a database
let userTokens = null;

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
console.log('Google Client ID:', !!process.env.GOOGLE_CLIENT_ID ? '✓' : '✗');
console.log('Google Client Secret:', !!process.env.GOOGLE_CLIENT_SECRET ? '✓' : '✗');
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

// ============ Gmail OAuth Routes ============

// Start OAuth flow
app.get('/auth/google', (req, res) => {
  const scopes = ['https://www.googleapis.com/auth/gmail.send'];
  
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent'
  });
  
  res.redirect(url);
});

// OAuth callback
app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  
  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    userTokens = tokens;
    
    console.log('✅ Gmail OAuth successful');
    
    // Redirect back to app with success message
    res.redirect('/?gmail=connected');
  } catch (error) {
    console.error('OAuth error:', error);
    res.redirect('/?gmail=error');
  }
});

// Check Gmail connection status
app.get('/api/gmail/status', (req, res) => {
  res.json({ 
    connected: !!userTokens,
    email: userTokens ? 'Connected' : null
  });
});

// Disconnect Gmail
app.get('/api/gmail/disconnect', (req, res) => {
  userTokens = null;
  oauth2Client.revokeCredentials();
  res.json({ success: true });
});

// Send email with report
app.post('/api/gmail/send', async (req, res) => {
  if (!userTokens) {
    return res.status(401).json({ error: 'Gmail not connected. Please connect first.' });
  }
  
  try {
    const { to, subject, report } = req.body;
    
    if (!to || !subject || !report) {
      return res.status(400).json({ error: 'Missing required fields: to, subject, report' });
    }
    
    // Refresh tokens if needed
    oauth2Client.setCredentials(userTokens);
    
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    
    // Get user's email for the From field
    const profile = await gmail.users.getProfile({ userId: 'me' });
    const fromEmail = profile.data.emailAddress;
    
    // Create email
    const emailContent = [
      `From: ${fromEmail}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      'Content-Type: text/plain; charset=utf-8',
      '',
      report
    ].join('\n');
    
    const encodedEmail = Buffer.from(emailContent)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    
    await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: encodedEmail
      }
    });
    
    console.log(`✅ Email sent to ${to}`);
    res.json({ success: true, message: `Email sent to ${to}` });
    
  } catch (error) {
    console.error('Email send error:', error);
    
    // If token expired, clear it
    if (error.code === 401) {
      userTokens = null;
      return res.status(401).json({ error: 'Gmail session expired. Please reconnect.' });
    }
    
    res.status(500).json({ error: 'Failed to send email', details: error.message });
  }
});

// ============ WebSocket for Transcription ============

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

// ============ Report Generation ============

app.post('/api/generate-report', async (req, res) => {
  try {
    const { findings, specialty } = req.body;
    
    if (!findings) {
      return res.status(400).json({ error: 'Findings are required' });
    }

    const model = genAI.getGenerativeModel({ 
      model: "gemini-2.5-flash",
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
    llm: 'Gemini 2.5 Flash',
    gmail: userTokens ? 'connected' : 'not connected'
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
  console.log(`🩺 AWS Transcribe Medical enabled`);
  console.log(`✨ Gemini 2.5 Flash for report generation`);
  console.log(`📧 Gmail integration ready`);
  console.log(`☢️  Nuclear Medicine/PET reporting mode active`);
  console.log(`📍 Region: ${process.env.AWS_REGION || 'us-east-1'}`);
});