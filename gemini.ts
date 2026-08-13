import { GoogleGenAI } from "@google/genai";

export type ScanType = "url" | "email" | "phone" | "text";

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
You are a cybersecurity expert.

Analyze this ${type} for scam, phishing, fraud, malicious behavior,
or suspicious behavior.

Input:
${value}

Google Safe Browsing:
${JSON.stringify(googleResult)}

VirusTotal:
${JSON.stringify(virusTotalResult)}

Return ONLY valid JSON:

{
  "isScam": true,
  "score": 85,
  "summary": "Short explanation",
  "insights": [
    "Insight 1",
    "Insight 2",
    "Insight 3"
  ]
}

Rules:
- score must be between 0 and 100
- 0 means very safe
- 100 means extremely dangerous
- exactly 3 insights
- JSON only
- no markdown
`;

  console.log("Sending request to Gemini...");

  const interaction = await ai.interactions.create({
    model: "gemini-3.6-flash",
    input: prompt,
    store: false,
  });

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

  const result = JSON.parse(cleanText);

  if (
    typeof result.isScam !== "boolean" ||
    typeof result.score !== "number" ||
    typeof result.summary !== "string" ||
    !Array.isArray(result.insights)
  ) {
    throw new Error("Invalid Gemini response");
  }

  return {
    isScam: result.isScam,
    score: Math.max(0, Math.min(100, result.score)),
    summary: result.summary,
    insights: result.insights.map(String).slice(0, 3),
  };
};