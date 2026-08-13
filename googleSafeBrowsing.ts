const API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

export const checkUrlWithGoogle = async (url: string) => {
  if (!API_KEY) {
    console.warn("Google Safe Browsing API key not set");
    return null;
  }

  const payload = {
    client: {
      clientId: "scamshield",
      clientVersion: "1.0.0",
    },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  const response = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    },
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("Google Safe Browsing error:", data);
    return null;
  }

  return data;
};
