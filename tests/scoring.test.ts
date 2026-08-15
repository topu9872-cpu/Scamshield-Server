export type RiskScanType = "url" | "phone" | "text";

const suspiciousTokens = [
  "login",
  "verify",
  "verification",
  "confirm",
  "confirmation",
  "secure",
  "security",
  "update",
  "account",
  "payment",
  "bank",
  "otp",
  "password",
  "reset",
  "invoice",
  "claim",
  "reward",
  "winner",
  "urgent",
  "alert",
  "suspended",
  "suspicious",
  "wallet",
  "transfer",
  "cash",
];

const brandImpersonation = [
  "paypal",
  "apple",
  "google",
  "microsoft",
  "amazon",
  "netflix",
  "dropbox",
  "facebook",
  "instagram",
  "whatsapp",
  "stripe",
  "adobe",
  "bank",
];

const clamp = (value: number) =>
  Math.max(0, Math.min(100, Math.round(value)));

/* =========================================================
   URL RISK
========================================================= */

export const scoreUrlRisk = (
  type: RiskScanType,
  value: string,
  malicious: number,
  suspicious: number,
  googleMatches: number,
): number => {
  if (type !== "url") return 0;

  const text = value.trim().toLowerCase();

  if (!text) return 0;

  let score = 0;

  // Threat intelligence
  score += malicious * 18;
  score += suspicious * 8;
  score += googleMatches * 32;

  const normalized =
    text.startsWith("http://") || text.startsWith("https://")
      ? text
      : `https://${text}`;

  let parsed: URL;

  try {
    parsed = new URL(normalized);
  } catch {
    return clamp(score);
  }

  const host = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();

  if (
    host.includes("login") ||
    host.includes("verify") ||
    host.includes("confirm")
  ) {
    score += 28;
  }

  if (host.includes("-")) {
    score += 12;
  }

  if (/\d/.test(host.split(".")[0] || "")) {
    score += 10;
  }

  if (
    host.includes("bit.ly") ||
    host.includes("tinyurl") ||
    host.includes("t.co")
  ) {
    score += 18;
  }

  if (/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/.test(host)) {
    score += 20;
  }

  let keywordHits = 0;

  for (const token of suspiciousTokens) {
    if (
      host.includes(token) ||
      pathname.includes(token) ||
      search.includes(token)
    ) {
      keywordHits++;
    }
  }

  score += Math.min(keywordHits * 12, 40);

  let impersonationHits = 0;

  for (const brand of brandImpersonation) {
    if (
      host.includes(brand) ||
      pathname.includes(brand) ||
      search.includes(brand)
    ) {
      impersonationHits++;
    }
  }

  score += Math.min(impersonationHits * 10, 25);

  const params = parsed.searchParams.toString().toLowerCase();

  if (
    params.includes("token") ||
    params.includes("otp") ||
    params.includes("verify") ||
    params.includes("redirect")
  ) {
    score += 12;
  }

  if (
    pathname.includes("/login") ||
    pathname.includes("/verify") ||
    pathname.includes("/confirm")
  ) {
    score += 18;
  }

  if (host.split(".").length > 3) {
    score += 12;
  }

  return clamp(score);
};

/* =========================================================
   PHONE RISK
========================================================= */

export const scorePhoneRisk = (
  type: RiskScanType,
  value: string,
  malicious: number,
  suspicious: number,
  context = "",
): number => {
  if (type !== "phone") return 0;

  const phone = value.trim();
  const text = `${phone} ${context}`.toLowerCase();

  if (!phone) return 0;

  let score = 0;

  /*
   * Threat intelligence
   */
  score += malicious * 30;
  score += suspicious * 15;

  /*
   * Normalize phone number
   */
  const normalizedPhone = phone.replace(/[^\d+]/g, "");

  /*
   * International / Bangladesh number checks
   */
  if (normalizedPhone.startsWith("+880")) {
    // Valid Bangladesh international format
    const digits = normalizedPhone.replace(/\D/g, "");

    if (digits.length === 13) {
      score += 2;
    }
  } else if (normalizedPhone.startsWith("01")) {
    // Bangladesh local mobile format
    const digits = normalizedPhone.replace(/\D/g, "");

    if (digits.length === 11) {
      score += 2;
    }
  } else {
    /*
     * Unknown / unusual country format.
     * Do NOT automatically make it a scam.
     */
    score += 5;
  }

  /*
   * =====================================================
   * Context based scam indicators
   * =====================================================
   */

  const strongScamPatterns = [
    "otp",
    "one time password",
    "verification code",
    "verification code",
    "password",
    "pin",
    "cvv",
    "card number",
    "bank account",
    "banking",
    "send money",
    "transfer money",
    "payment",
    "pay now",
    "cash",
    "bikash",
    "bkash",
    "nagad",
    "rocket",
    "upay",
    "wallet",
    "crypto",
    "bitcoin",
    "investment",
    "loan",
    "prize",
    "winner",
    "lottery",
    "reward",
    "gift",
    "refund",
    "account suspended",
    "account blocked",
    "verify your account",
    "urgent",
    "emergency",
    "police",
    "arrest",
    "job offer",
    "send code",
    "share code",
    "give me the code",
  ];

  let strongHits = 0;

  for (const pattern of strongScamPatterns) {
    if (text.includes(pattern)) {
      strongHits++;
    }
  }

  /*
   * Strong contextual evidence
   */
  score += Math.min(strongHits * 15, 60);

  /*
   * =====================================================
   * Social engineering indicators
   * =====================================================
   */

  const socialEngineeringPatterns = [
    "don't tell anyone",
    "do not tell anyone",
    "keep this secret",
    "act now",
    "immediately",
    "within 10 minutes",
    "within 5 minutes",
    "limited time",
    "last chance",
    "otherwise",
    "otherwise your account",
    "click the link",
    "open this link",
    "call me back",
    "send it to me",
  ];

  let socialHits = 0;

  for (const pattern of socialEngineeringPatterns) {
    if (text.includes(pattern)) {
      socialHits++;
    }
  }

  score += Math.min(socialHits * 10, 30);

  /*
   * =====================================================
   * Impersonation
   * =====================================================
   */

  const impersonationPatterns = [
    "bank",
    "bkash",
    "bikash",
    "nagad",
    "police",
    "government",
    "tax",
    "customs",
    "courier",
    "delivery",
    "facebook",
    "google",
    "microsoft",
    "apple",
    "whatsapp",
    "paypal",
  ];

  let impersonationHits = 0;

  for (const pattern of impersonationPatterns) {
    if (text.includes(pattern)) {
      impersonationHits++;
    }
  }

  score += Math.min(impersonationHits * 12, 36);

  /*
   * =====================================================
   * Phone number itself should NEVER make a normal number
   * highly suspicious.
   * =====================================================
   */

  return clamp(score);
};

/* =========================================================
   TEXT RISK
========================================================= */

export const scoreTextRisk = (
  type: RiskScanType,
  value: string,
  malicious = 0,
  suspicious = 0,
): number => {
  if (type !== "text") return 0;

  const text = value.trim().toLowerCase();

  if (!text) return 0;

  let score = 0;

  score += malicious * 25;
  score += suspicious * 12;

  for (const token of suspiciousTokens) {
    if (text.includes(token)) {
      score += 8;
    }
  }

  for (const brand of brandImpersonation) {
    if (text.includes(brand)) {
      score += 10;
    }
  }

  const scamPatterns = [
    "send money",
    "send otp",
    "share otp",
    "verification code",
    "password",
    "bank account",
    "credit card",
    "debit card",
    "click this link",
    "claim your prize",
    "you have won",
    "account suspended",
    "account will be closed",
    "urgent action",
    "act immediately",
  ];

  for (const pattern of scamPatterns) {
    if (text.includes(pattern)) {
      score += 15;
    }
  }

  return clamp(score);
};