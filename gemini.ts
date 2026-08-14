import { GoogleGenAI } from "@google/genai";

export type ScanType = "url" | "email" | "phone" | "text";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface GeminiResult {
  isScam: boolean;
  score: number;
  summary: string;
  insights: string[];
}

export const analyzeWithGemini = async (
  type: ScanType,
  value: string,
  googleResult: unknown,
  virusTotalResult: unknown,
): Promise<GeminiResult> => {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    throw new Error("GEMINI_API_KEY is missing");
  }

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      apiVersion: "v1",
    },
  });

  const prompt = `
You are a professional cybersecurity risk-analysis engine.

Your task is to analyze the provided ${type} and determine its
SCAM / PHISHING / FRAUD / MALICIOUS RISK.

IMPORTANT:
Do NOT assume that an input is safe simply because VirusTotal
or Google Safe Browsing reports no known threats.

A new phishing or scam URL may not yet exist in threat databases.

Analyze BOTH:
1. External security intelligence
2. The actual content and behavior of the input

INPUT TYPE:
${type}

INPUT:
${value}

GOOGLE SAFE BROWSING RESULT:
${JSON.stringify(googleResult)}

VIRUSTOTAL RESULT:
${JSON.stringify(virusTotalResult)}

========================
RISK ANALYSIS GUIDELINES
========================

For URLs, look for:

- suspicious domain names
- misleading brand names
- fake login pages
- account verification requests
- unusual subdomains
- URL obfuscation
- excessive URL parameters
- suspicious redirects
- impersonation
- credential harvesting
- financial/payment requests
- urgency or threats
- newly suspicious-looking domains
- phishing patterns

For emails and messages, look for:

- urgency
- threats
- account suspension claims
- fake verification requests
- requests for passwords
- requests for OTP codes
- requests for banking information
- payment requests
- impersonation
- suspicious links
- reward/prize scams
- fear-based language
- social engineering

For phone numbers, consider:

- suspicious context
- scam-related messages
- requests for OTP
- financial requests
- impersonation
- unusual claims

========================
SCORING
========================

0-19   = Very Low Risk
20-39  = Low Risk
40-59  = Medium Risk
60-79  = High Risk
80-100 = Critical Risk

Important:

A VirusTotal result of zero detections does NOT mean the final
risk score must be zero.

A Google Safe Browsing result showing no known threat does NOT
mean the final risk score must be zero.

If the actual input contains strong phishing, scam, fraud,
impersonation, credential theft, urgency, or social-engineering
patterns, give it an appropriately high score even when external
databases have no detection.

Conversely, do not give a high score merely because an input
contains a URL, email address, or phone number.

The score must represent the OVERALL risk.

========================
OUTPUT
========================

Return ONLY valid JSON.

{
  "isScam": true,
  "score": 85,
  "summary": "Short explanation of the risk.",
  "insights": [
    "Important finding 1",
    "Important finding 2",
    "Important finding 3"
  ]
}

Rules:

- score must be an integer from 0 to 100
- isScam must be true when score >= 60
- isScam should normally be false when score < 60
- exactly 3 insights
- summary must be concise
- JSON only
- no markdown
- no code fences
`;

  console.log("Sending request to Gemini...");

  let interaction;
  let lastError: unknown;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      interaction = await ai.interactions.create({
        model: "gemini-3.6-flash",
        input: prompt,
        store: false,
      });
      break;
    } catch (error) {
      lastError = error;
      const status = (error as any)?.statusCode ?? (error as any)?.status;

      if (status === 429 && attempt < 3) {
        console.warn(
          `Gemini rate limited. Retrying in ${attempt * 2}s (attempt ${attempt}/3)...`,
        );
        await sleep(attempt * 2000);
        continue;
      }

      throw error;
    }
  }

  if (!interaction) {
    throw lastError ?? new Error("Gemini request failed");
  }

  const text = interaction.output_text?.trim();

  console.log("Gemini response:", text);

  if (!text) {
    throw new Error("Gemini returned empty response");
  }

  const cleanText = text
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  let result: GeminiResult;

  try {
    result = JSON.parse(cleanText);
  } catch {
    console.error("Invalid Gemini JSON:", cleanText);
    throw new Error("Gemini returned invalid JSON");
  }

  if (
    typeof result.isScam !== "boolean" ||
    typeof result.score !== "number" ||
    typeof result.summary !== "string" ||
    !Array.isArray(result.insights)
  ) {
    throw new Error("Invalid Gemini response");
  }

  const score = Math.max(0, Math.min(100, Math.round(result.score)));

  return {
    isScam: score >= 60,
    score,
    summary: result.summary,
    insights: result.insights.map(String).slice(0, 3),
  };
};
