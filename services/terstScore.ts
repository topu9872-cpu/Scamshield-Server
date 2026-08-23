export const calculateTrustScore = ({
  malicious,
  suspicious,
  googleMatches,
  https,
  hasMetadata,
}: {
  malicious: number;
  suspicious: number;
  googleMatches: number;
  https: boolean;
  hasMetadata: boolean;
}) => {
  let score = 100;

  score -= malicious * 35;
  score -= suspicious * 10;
  score -= googleMatches * 25;

  if (!https) score -= 15;
  if (!hasMetadata) score -= 10;

  return Math.max(0, Math.min(100, score));
};