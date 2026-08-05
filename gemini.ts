import { GoogleGenAI } from "@google/genai";

export type ScanType = "url" | "email" | "phone" | "text";

export const analyzeWithGemini = async (
  type: ScanType,
  value: string,
  googleResult: unknown
) => {

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY!,
});


  const prompt = `
You are a cybersecurity expert.

Analyze this ${type}.

Input:
${value}

Google Safe Browsing Result:
${JSON.stringify(googleResult)}

Return ONLY valid JSON.

{
  "isScam": boolean,
  "score": number,
  "summary": "Short explanation",
  "insights": [
    "Insight 1",
    "Insight 2",
    "Insight 3"
  ]
}
`;

  const response = await ai.models.generateContent({
  model: "gemini-2.5-pro",
    contents: prompt,
  });

  const text = response.text
    ?.replace(/```json/g, "")
    .replace(/```/g, "")
    .trim();

  return JSON.parse(text!);
};