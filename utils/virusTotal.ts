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

export const checkUrlWithVirusTotal = async (
  url: string,
): Promise<VirusTotalResult> => {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    throw new Error("VIRUSTOTAL_API_KEY is missing");
  }

  if (!/^https?:\/\//i.test(url)) {
    throw new Error("Invalid URL");
  }

  // Submit URL
  const submitResponse = await fetch(
    "https://www.virustotal.com/api/v3/urls",
    {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ url }),
    },
  );

  const submitData = await submitResponse.json();

  console.log("VirusTotal submit status:", submitResponse.status);

  if (!submitResponse.ok) {
    console.error("VirusTotal submit error:", submitData);
    throw new Error(`VirusTotal request failed: ${submitResponse.status}`);
  }

  const analysisId = submitData?.data?.id;

  if (!analysisId) {
    throw new Error("VirusTotal analysis ID not found");
  }

  // Wait for analysis
  await new Promise((resolve) => setTimeout(resolve, 5000));

  // Get result
  const response = await fetch(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    {
      headers: {
        "x-apikey": apiKey,
      },
    },
  );

  const data = await response.json();

  console.log("VirusTotal analysis status:", response.status);

  if (!response.ok) {
    console.error("VirusTotal analysis error:", data);
    throw new Error(`VirusTotal analysis failed: ${response.status}`);
  }

  const stats = data?.data?.attributes?.stats ?? {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
  };

  return {
    stats,
    status: data?.data?.attributes?.status ?? "unknown",
    analysisId,
  };
};