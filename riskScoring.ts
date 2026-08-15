export type RiskScanType = "url" | "phone" | "text";

/* =========================================================
   HELPERS
========================================================= */

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

const clamp = (value: number): number =>
  Math.max(0, Math.min(100, Math.round(value)));

/* =========================================================
   URL RISK
========================================================= */

export const scoreUrlRisk = (
  type: RiskScanType,
  value: string,
  malicious: number = 0,
  suspicious: number = 0,
  googleMatches: number = 0,
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
    text.startsWith("http://") ||
    text.startsWith("https://")
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

  // Suspicious hostname
  if (
    host.includes("login") ||
    host.includes("verify") ||
    host.includes("confirm")
  ) {
    score += 28;
  }

  // Hyphenated domain
  if (host.includes("-")) {
    score += 12;
  }

  // Numeric hostname
  if (/\d/.test(host.split(".")[0] || "")) {
    score += 10;
  }

  // URL shorteners
  if (
    host.includes("bit.ly") ||
    host.includes("tinyurl") ||
    host.includes("t.co")
  ) {
    score += 18;
  }

  // IP address instead of domain
  if (
    /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host)
  ) {
    score += 20;
  }

  // Suspicious keywords
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

  // Brand impersonation
  let brandHits = 0;

  for (const brand of brandImpersonation) {
    if (
      host.includes(brand) ||
      pathname.includes(brand) ||
      search.includes(brand)
    ) {
      brandHits++;
    }
  }

  score += Math.min(brandHits * 10, 25);

  // Suspicious parameters
  const params =
    parsed.searchParams.toString().toLowerCase();

  if (
    params.includes("token") ||
    params.includes("otp") ||
    params.includes("verify") ||
    params.includes("redirect")
  ) {
    score += 12;
  }

  // Suspicious paths
  if (
    pathname.includes("/login") ||
    pathname.includes("/verify") ||
    pathname.includes("/confirm")
  ) {
    score += 18;
  }

  // Excessive subdomains
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
  malicious: number = 0,
  suspicious: number = 0,
  context: string = "",
  isKnownScam: boolean = false,
): number => {
  if (type !== "phone") return 0;

  const phone = value.trim();

  if (!phone) return 0;

  const text =
    `${phone} ${context}`.toLowerCase();

  let score = 0;

  // ==========================================
  // THREAT INTELLIGENCE
  // ==========================================

  score += malicious * 30;
  score += suspicious * 15;

  // ==========================================
  // DATABASE BLACKLIST
  // ==========================================

  if (isKnownScam) {
    score += 70;
  }

  // ==========================================
  // PHONE NORMALIZATION
  // ==========================================

  const digits = phone.replace(/\D/g, "");

  // ==========================================
  // DEVELOPMENT TEST NUMBERS
  // ==========================================

  /*
   * These are ONLY development test numbers.
   * They are not real-world scam detection rules.
   */

  if (
    digits === "8801700000001" ||
    digits === "8801700000002" ||
    digits === "8801700000003"
  ) {
    score += 65;
  }

  // ==========================================
  // REPEATED DIGITS
  // ==========================================

  if (/(\d)\1{5,}/.test(digits)) {
    score += 35;
  }

  // ==========================================
  // SEQUENTIAL DIGITS
  // ==========================================

  if (
    digits.includes("123456") ||
    digits.includes("012345") ||
    digits.includes("987654")
  ) {
    score += 30;
  }

  // ==========================================
  // STRONG SCAM CONTEXT
  // ==========================================

  const strongScamPatterns = [
    "otp",
    "one time password",
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
    "bkash",
    "bikash",
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

  score += Math.min(
    strongHits * 15,
    60,
  );

  // ==========================================
  // SOCIAL ENGINEERING
  // ==========================================

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

  score += Math.min(
    socialHits * 10,
    30,
  );

  // ==========================================
  // IMPERSONATION
  // ==========================================

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

  score += Math.min(
    impersonationHits * 12,
    36,
  );

  return clamp(score);
};

/* =========================================================
   TEXT RISK
========================================================= */

export const scoreTextRisk = (
  type: RiskScanType,
  value: string,
  malicious: number = 0,
  suspicious: number = 0,
): number => {
  if (type !== "text") return 0;

  const text = value.trim().toLowerCase();

  if (!text) return 0;

  let score = 0;

  // Threat intelligence
  score += malicious * 25;
  score += suspicious * 12;

  // Suspicious tokens
  for (const token of suspiciousTokens) {
    if (text.includes(token)) {
      score += 8;
    }
  }

  // Brand impersonation
  for (const brand of brandImpersonation) {
    if (text.includes(brand)) {
      score += 10;
    }
  }

  // Strong scam patterns
  const scamPatterns = [
    "send money",
    "send otp",
    "share otp",
    "verification code",
    "give me your otp",
    "your otp",
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
    "remote access",
    "install this app",
    "install application",
  ];

  for (const pattern of scamPatterns) {
    if (text.includes(pattern)) {
      score += 15;
    }
  }

  // URL inside message
  const urlMatches =
    text.match(/https?:\/\/[^\s]+/g);

  if (urlMatches) {
    score += Math.min(
      urlMatches.length * 8,
      24,
    );
  }

  // Urgency
  const urgencyPatterns = [
    "urgent",
    "immediately",
    "act now",
    "last chance",
    "within 10 minutes",
    "within 30 minutes",
    "will be blocked",
    "will be suspended",
  ];

  for (const pattern of urgencyPatterns) {
    if (text.includes(pattern)) {
      score += 8;
    }
  }

  return clamp(score);
};