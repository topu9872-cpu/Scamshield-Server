import { GoogleGenAI } from "@google/genai";

export type ScanType = "url" | "phone" | "text";

const sleep = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

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
  context?: string,
): Promise<GeminiResult> => {
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    throw new Error("GEMINI_API_KEY is missing");
  }

  const ai = new GoogleGenAI({
    apiKey,
  });

  /*
   * Normalize external intelligence.
   *
   * We intentionally do NOT tell Gemini:
   * "VirusTotal = 0 => safe"
   *
   * Threat intelligence is only one part of the analysis.
   */

  const googleData = JSON.stringify(googleResult ?? {});
  const virusTotalData = JSON.stringify(virusTotalResult ?? {});

  const userContext =
    context?.trim() || "No additional user context provided.";

  const prompt = `
You are ScamShield, a professional cybersecurity risk-analysis engine.

Your job is to estimate the REAL-WORLD scam, phishing, fraud,
social-engineering, or malicious risk of the supplied input.

You MUST analyze the actual input itself.

Do NOT blindly trust external threat-intelligence databases.

A clean VirusTotal result does NOT mean the input is safe.
A clean Google Safe Browsing result does NOT mean the input is safe.

New scams may not yet exist in threat-intelligence databases.

==================================================
INPUT
==================================================

SCAN TYPE:
${type}

VALUE:
${value}

USER CONTEXT:
${userContext}

GOOGLE SAFE BROWSING:
${googleData}

VIRUSTOTAL:
${virusTotalData}

==================================================
GENERAL ANALYSIS RULES
==================================================

Analyze:

1. Direct evidence of scam behavior
2. Social engineering
3. Impersonation
4. Credential theft
5. Financial fraud
6. OTP/password requests
7. Urgency and fear tactics
8. Suspicious instructions
9. Threats or account suspension claims
10. Reward/prize scams
11. Fake authority claims
12. Suspicious links
13. External threat intelligence
14. Context supplied by the user

Do NOT mark something as a scam merely because:

- it is a URL
- it is a phone number
- it contains numbers
- it contains unusual words
- VirusTotal has no detections
- Google Safe Browsing has no detections

==================================================
URL ANALYSIS
==================================================

For URLs inspect:

- suspicious domain names
- brand impersonation
- typosquatting
- suspicious subdomains
- misleading domains
- URL obfuscation
- encoded characters
- suspicious query parameters
- credential harvesting
- fake login pages
- financial/payment pages
- suspicious redirects
- HTTP instead of HTTPS where relevant
- phishing keywords
- domain/brand mismatch
- suspicious path structure
- threat-intelligence detections

IMPORTANT:

A URL with zero VirusTotal detections can still be highly suspicious
if the URL itself contains strong phishing indicators.

Example:

https://paypal-login-security-example.com

should receive a significantly higher risk score than:

https://paypal.com

if there is no other contradictory evidence.

==================================================
PHONE NUMBER ANALYSIS
==================================================

Phone numbers require special treatment.

A phone number alone is NOT proof of a scam.

The number format should receive only a small amount of weight.

IMPORTANT:

The CONTEXT is extremely important for phone scanning.

Look for:

- caller claiming to be a bank
- caller claiming to be police/government
- OTP requests
- password requests
- PIN requests
- banking information requests
- card information requests
- mobile banking requests
- money transfer requests
- cryptocurrency requests
- suspicious payment requests
- account suspension threats
- urgent verification requests
- impersonation
- fake customer support
- prize/reward claims
- suspicious WhatsApp/SMS behavior
- pressure to install an application
- pressure to click a link
- remote-access requests
- social engineering

SCORING PHONE NUMBERS:

If there is ONLY a phone number and no suspicious context:

- normally 0-25 risk

If there is suspicious context:

- moderate suspicious behavior: 30-59
- strong scam indicators: 60-79
- very strong fraud/social-engineering indicators: 80-100

Example:

PHONE:
+8801700000001

CONTEXT:
"Caller said he was from my bank and asked me to provide
the OTP sent to my phone to verify my account."

This should receive a HIGH or CRITICAL risk score,
even if there are no threat-intelligence detections.

==================================================
TEXT / MESSAGE ANALYSIS
==================================================

Analyze the actual message.

Look for:

- urgency
- fear
- threats
- account suspension
- fake verification
- OTP requests
- password requests
- PIN requests
- banking information
- card information
- payment requests
- fake refunds
- fake prizes
- fake jobs
- fake investments
- cryptocurrency scams
- impersonation
- government impersonation
- bank impersonation
- customer-support impersonation
- suspicious links
- shortened URLs
- malicious-looking URLs
- requests to install software
- requests for remote access
- social engineering
- emotional manipulation

Strong combinations of these signals should produce a high score.

==================================================
EXTERNAL INTELLIGENCE
==================================================

VirusTotal and Google Safe Browsing are supporting signals.

If external intelligence detects a threat:

increase the risk score significantly.

If external intelligence reports no threat:

DO NOT automatically reduce the score to zero.

The input itself must still be analyzed.

==================================================
SCORING
==================================================

0-19   = Very Low Risk
20-39  = Low Risk
40-59  = Medium Risk
60-79  = High Risk
80-100 = Critical Risk

Use the FULL 0-100 range when appropriate.

Examples:

Completely ordinary URL:
5-15

Ordinary phone number without suspicious context:
5-20

Suspicious but weak message:
25-45

Suspicious URL with phishing indicators:
60-80

Message asking for OTP + impersonating a bank:
75-95

Confirmed threat intelligence + malicious indicators:
85-100

==================================================
IMPORTANT SCORING RULE
==================================================

Do NOT artificially keep scores low.

If there is strong evidence of scam behavior,
the score MUST normally be >= 60.

If there are multiple strong scam indicators,
the score should normally be >= 70.

If there is extremely strong evidence,
the score can be >= 85.

Conversely, do not increase the score simply because
the input is unfamiliar.

==================================================
FINAL DECISION
==================================================

isScam MUST be:

true  when score >= 60
false when score < 60

The score must represent the overall risk.

==================================================
OUTPUT
==================================================

Return ONLY valid JSON.

{
  "isScam": true,
  "score": 85,
  "summary": "The input shows strong indicators of social engineering and fraud.",
  "insights": [
    "The sender is impersonating a trusted organization.",
    "The message requests sensitive authentication information.",
    "The request uses urgency to pressure the recipient."
  ]
}

==================================================
OUTPUT RULES
==================================================

- score must be an integer from 0 to 100
- isScam must match score
- score >= 60 => isScam true
- score < 60 => isScam false
- exactly 3 insights
- insights must contain useful findings
- summary must be concise
- JSON only
- no markdown
- no code fences
- no additional text
`;

  console.log("Sending request to Gemini...");

  let response: any;
  let lastError: unknown;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      response = await ai.models.generateContent({
        model: "gemini-3.6-flash",
        contents: prompt,
      });

      break;
    } catch (error) {
      lastError = error;

      const status =
        (error as any)?.statusCode ??
        (error as any)?.status ??
        (error as any)?.code;

      console.error(
        `Gemini request failed on attempt ${attempt}:`,
        error,
      );

      if (status === 429 && attempt < 3) {
        const delay = attempt * 2000;

        console.warn(
          `Gemini rate limited. Retrying in ${delay / 1000}s...`,
        );

        await sleep(delay);
        continue;
      }

      throw error;
    }
  }

  if (!response) {
    throw lastError ?? new Error("Gemini request failed");
  }

  const text = response.text?.trim();

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
  } catch (error) {
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

  const score = Math.max(
    0,
    Math.min(100, Math.round(result.score)),
  );

  const insights = result.insights
    .map(String)
    .filter((item) => item.trim().length > 0)
    .slice(0, 3);

  while (insights.length < 3) {
    insights.push("No additional significant risk indicator found.");
  }

  return {
    isScam: score >= 60,
    score,
    summary: result.summary.trim(),
    insights,
  };
};