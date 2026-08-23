// Vertex AI Gemini access for Flow Dictation. One client, one generate()
// wrapper, and the handful of conversions the rest of the server needs:
// effort -> thinking budget, safety blocks -> a refusal error, grounding
// chunks -> citations with their real URLs.
//
// Auth is Application Default Credentials only: the Cloud Run service
// account in production, `gcloud auth application-default login` locally.
// There are no API keys anywhere in this app.
const { GoogleGenAI, HarmCategory, HarmBlockThreshold } = require('@google/genai');

const PROJECT = process.env.GOOGLE_CLOUD_PROJECT || process.env.VERTEX_PROJECT || '';
const LOCATION = process.env.VERTEX_LOCATION || 'us-east1';

const ai = new GoogleGenAI({ vertexai: true, project: PROJECT, location: LOCATION });

// Radiology text trips the default classifiers (tumours, trauma, "dangerous
// content") often enough that the defaults are unusable for this app. These
// are the most permissive thresholds Vertex allows; a block that survives them
// surfaces as a refusal error rather than as an empty answer.
const SAFETY_SETTINGS = [
  HarmCategory.HARM_CATEGORY_HATE_SPEECH,
  HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
  HarmCategory.HARM_CATEGORY_HARASSMENT,
  HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT
].map(category => ({ category, threshold: HarmBlockThreshold.BLOCK_ONLY_HIGH }));

// Effort is the latency lever, as before. Gemini 2.5 exposes it as a thinking
// token budget: 0 disables thinking (Flash/Flash-Lite only — Pro's floor is
// 128), -1 lets the model decide. Undefined effort leaves the model default.
function thinkingBudget(model, effort) {
  if (!effort) return undefined;
  const pro = /pro/i.test(model);
  switch (effort) {
    case 'low':    return pro ? 128 : 0;
    case 'medium': return 1024;
    case 'high':   return -1;
    default:       return undefined;
  }
}

// Why a response came back without usable text
const BLOCK_FINISH = new Set(['SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII', 'RECITATION', 'IMAGE_SAFETY']);

function refusal(detail) {
  const err = new Error('This request was declined by the model’s safety filters. Try rephrasing it.');
  err.isRefusal = true;
  err.detail = detail;
  return err;
}

// Text parts only — thought parts are never returned unless asked for, but
// filter defensively so a summary never leaks into report text.
function textOf(candidate) {
  const parts = (candidate && candidate.content && candidate.content.parts) || [];
  return parts.filter(p => typeof p.text === 'string' && !p.thought).map(p => p.text).join('');
}

/**
 * One Gemini call.
 *   model          Vertex model id
 *   system         system instruction text (string)
 *   contents       [{role:'user'|'model', parts:[{text}]}]
 *   maxTokens      output ceiling
 *   effort         'low' | 'medium' | 'high' | undefined
 *   responseSchema when set, JSON mode with this schema
 *   grounding      true -> Grounding with Google Search tool attached
 * Returns { text, usage, finishReason, served, grounding }.
 * Throws an error with isRefusal=true when the prompt or answer was blocked.
 */
async function generate({ model, system, contents, maxTokens, effort, responseSchema, grounding }) {
  const config = {
    systemInstruction: system || undefined,
    maxOutputTokens: maxTokens,
    safetySettings: SAFETY_SETTINGS
  };
  const budget = thinkingBudget(model, effort);
  if (budget !== undefined) config.thinkingConfig = { thinkingBudget: budget };
  if (responseSchema) {
    config.responseMimeType = 'application/json';
    config.responseSchema = responseSchema;
  }
  if (grounding) config.tools = [{ googleSearch: {} }];

  const response = await ai.models.generateContent({ model, contents, config });

  const pf = response.promptFeedback;
  if (pf && pf.blockReason) throw refusal(`prompt blocked: ${pf.blockReason}`);
  const candidate = (response.candidates || [])[0];
  if (!candidate) throw refusal('no candidates returned');
  const finishReason = candidate.finishReason || 'STOP';
  const text = textOf(candidate);
  if (BLOCK_FINISH.has(finishReason)) throw refusal(`finish_reason ${finishReason}`);

  const u = response.usageMetadata || {};
  return {
    text,
    finishReason,
    served: response.modelVersion || model,
    usage: {
      prompt_tokens: u.promptTokenCount || 0,
      cached_tokens: u.cachedContentTokenCount || 0,
      output_tokens: u.candidatesTokenCount || 0,
      thought_tokens: u.thoughtsTokenCount || 0,
      tool_prompt_tokens: u.toolUsePromptTokenCount || 0
    },
    grounding: candidate.groundingMetadata || null
  };
}

// Grounding returns vertexaisearch.cloud.google.com redirect URIs, not the
// pages themselves. One HEAD request each turns them into the real URL; if
// the redirect can't be followed in time, the redirect URI still works.
async function resolveRedirect(uri) {
  if (!/vertexaisearch\.cloud\.google\.com\/grounding-api-redirect\//.test(uri)) return uri;
  try {
    const r = await fetch(uri, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(3000) });
    const loc = r.headers.get('location');
    return loc && /^https?:\/\//.test(loc) ? loc : uri;
  } catch {
    return uri;
  }
}

// Citations from grounding metadata, most-used source first. Each chunk's
// support count is how many answer spans drew on it; that ranks sources the
// model actually leaned on above ones it merely retrieved.
async function citationsFrom(grounding) {
  if (!grounding) return [];
  const chunks = grounding.groundingChunks || [];
  const uses = new Array(chunks.length).fill(0);
  for (const s of grounding.groundingSupports || []) {
    for (const i of s.groundingChunkIndices || []) if (i < uses.length) uses[i]++;
  }
  const ranked = chunks
    .map((c, i) => ({ web: c.web, uses: uses[i], i }))
    .filter(c => c.web && c.web.uri)
    .sort((a, b) => b.uses - a.uses || a.i - b.i);
  const urls = await Promise.all(ranked.map(c => resolveRedirect(c.web.uri)));
  const out = [];
  const seen = new Set();
  ranked.forEach((c, k) => {
    const url = urls[k];
    if (seen.has(url)) return;
    seen.add(url);
    out.push({ url, title: c.web.title || c.web.domain || '', domain: c.web.domain || '' });
  });
  return out;
}

module.exports = { generate, citationsFrom, PROJECT, LOCATION };
