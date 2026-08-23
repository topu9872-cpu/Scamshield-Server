export const extractDomain = (value: string): string => {
  try {
    const url = value.startsWith("http")
      ? value
      : `https://${value}`;

    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
};

export const getCompanyNameFromDomain = (
  domain: string
): string => {
  const clean = domain
    .trim()
    .toLowerCase()
    .replace(/^www\./, "");

  const parts = clean.split(".").filter(Boolean);

  if (parts.length === 0) return "";

  let rawName = "";

  const multiPartTlds = [
    "co.uk",
    "com.au",
    "co.in",
    "gov.uk",
    "ac.uk",
  ];

  const endsWithTld = multiPartTlds.find((tld) =>
    clean.endsWith(tld)
  );

  if (endsWithTld && parts.length >= 3) {
    rawName =
      parts[parts.length - 3] ??
      parts[0] ??
      "";
  } else {
    rawName =
      parts.length >= 2
        ? parts[parts.length - 2] ?? ""
        : parts[0] ?? "";
  }

  return rawName
    .replace(/[-_]/g, " ")
    .split(" ")
    .filter(Boolean)
    .map(
      (word) =>
        word.charAt(0).toUpperCase() +
        word.slice(1)
    )
    .join(" ");
};

export const getWebsiteInfo = async (url: string) => {
  try {
    const websiteUrl = url.startsWith("http")
      ? url
      : `https://${url}`;

    const response = await fetch(websiteUrl, {
      headers: {
        "User-Agent": "ScamShield/1.0",
      },
    });

    if (!response.ok) {
      return null;
    }

    const html = await response.text();

    // Website title
    const titleMatch = html.match(
      /<title[^>]*>(.*?)<\/title>/is
    );

    const title = titleMatch?.[1]?.trim() ?? "";

    // Meta content helper
    const getMetaContent = (
      nameOrProp: string,
      attr: "name" | "property"
    ): string => {
      const regex = new RegExp(
        `<meta[^>]+${attr}=["']${nameOrProp}["'][^>]+content=["']([^"']*)["']|` +
          `<meta[^>]+content=["']([^"']*)["'][^>]+${attr}=["']${nameOrProp}["']`,
        "i"
      );

      const match = html.match(regex);

      if (!match) return "";

      return (
        match[1] ||
        match[2] ||
        ""
      ).trim();
    };

    const description = getMetaContent(
      "description",
      "name"
    );

    const image = getMetaContent(
      "og:image",
      "property"
    );

    return {
      title,
      description,
      image,
    };
  } catch {
    return null;
  }
};