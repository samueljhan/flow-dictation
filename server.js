const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080

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
  res.json({ status: 'ok', service: 'Flow Dictation API' });
});

app.listen(PORT, () => {
  console.log(`🏥 Flow Dictation running on port ${PORT}`);
});
