export type RiskScanType = "url" | "email" | "phone" | "text";

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
  "bank",
  "stripe",
  "n26",
  "adobe",
];

const clamp = (value: number) => Math.max(0, Math.min(100, value));

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

  if (host.startsWith("www.")) {
    score += 3;
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
      keywordHits += 1;
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
      impersonationHits += 1;
    }
  }
  score += Math.min(impersonationHits * 10, 25);

  if (parsed.searchParams && parsed.searchParams.toString()) {
    const params = parsed.searchParams.toString().toLowerCase();
    if (
      params.includes("token") ||
      params.includes("otp") ||
      params.includes("verify") ||
      params.includes("redirect")
    ) {
      score += 12;
    }
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

  return clamp(Math.round(score));
};
