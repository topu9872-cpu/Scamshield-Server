interface VirusTotalStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

interface VirusTotalResult {
  stats: VirusTotalStats;
  status: string;
  analysisId: string;
}

const EMPTY_STATS: VirusTotalStats = {
  malicious: 0,
  suspicious: 0,
  harmless: 0,
  undetected: 0,
};

const sleep = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * VirusTotal URL identifier
 * Base64 URL-safe encoding without '=' padding.
 */
const getUrlId = (url: string) => {
  return Buffer.from(url)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

export const checkUrlWithVirusTotal = async (
  url: string,
): Promise<VirusTotalResult> => {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    throw new Error("VIRUSTOTAL_API_KEY is missing");
  }

  let parsedUrl: URL;

  try {
    parsedUrl = new URL(
      url.startsWith("http://") || url.startsWith("https://")
        ? url
        : `https://${url}`,
    );
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  const normalizedUrl = parsedUrl.toString();
  const headers = {
    "x-apikey": apiKey,
    Accept: "application/json",
  };

  const urlId = getUrlId(normalizedUrl);

  const existingResponse = await fetch(
    `https://www.virustotal.com/api/v3/urls/${urlId}`,
    {
      method: "GET",
      headers,
    },
  );

  if (existingResponse.ok) {
    const existingData = await existingResponse.json();
    const stats =
      existingData?.data?.attributes?.last_analysis_stats ?? EMPTY_STATS;

    return {
      stats: {
        malicious: Number(stats.malicious ?? 0),
        suspicious: Number(stats.suspicious ?? 0),
        harmless: Number(stats.harmless ?? 0),
        undetected: Number(stats.undetected ?? 0),
      },
      status: "completed",
      analysisId: existingData?.data?.id ?? urlId,
    };
  }

  const formData = new URLSearchParams();
  formData.append("url", normalizedUrl);

  const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": apiKey,
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formData.toString(),
  });

  const submitData = await submitResponse.json();

  if (!submitResponse.ok) {
    throw new Error(`VirusTotal request failed: ${submitResponse.status}`);
  }

  const analysisId = submitData?.data?.id;

  if (!analysisId) {
    throw new Error("VirusTotal analysis ID not found");
  }

  const maxAttempts = 12;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    await sleep(3000);

    const analysisResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        method: "GET",
        headers,
      },
    );

    const analysisData = await analysisResponse.json();

    if (!analysisResponse.ok) {
      throw new Error(`VirusTotal analysis failed: ${analysisResponse.status}`);
    }

    const status = analysisData?.data?.attributes?.status ?? "unknown";

    if (status === "completed") {
      const stats = analysisData?.data?.attributes?.stats ?? EMPTY_STATS;

      return {
        stats: {
          malicious: Number(stats.malicious ?? 0),
          suspicious: Number(stats.suspicious ?? 0),
          harmless: Number(stats.harmless ?? 0),
          undetected: Number(stats.undetected ?? 0),
        },
        status,
        analysisId,
      };
    }
  }

  throw new Error("VirusTotal analysis timed out");
};