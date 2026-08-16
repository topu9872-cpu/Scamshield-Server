
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
  const name = domain.split(".")[0] ?? "";

  return name
    .replace(/[-_]/g, " ")
    .split(" ")
    .map(
      (word) =>
        word.charAt(0).toUpperCase() +
        word.slice(1)
    )
    .join(" ");
};


export const getWebsiteInfo = async (url: string) => {
  try {
    const response = await fetch(
      url.startsWith("http") ? url : `https://${url}`,
      {
        headers: {
          "User-Agent": "ScamShield/1.0",
        },
      }
    );

    if (!response.ok) return null;

    const html = await response.text();

    const title =
      html.match(/<title[^>]*>(.*?)<\/title>/i)?.[1]?.trim() ?? "";

    const description =
      html
        .match(
          /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i
        )?.[1]
        ?.trim() ?? "";

    const image =
      html
        .match(
          /<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']/i
        )?.[1]
        ?.trim() ?? "";

    return {
      title,
      description,
      image,
    };
  } catch {
    return null;
  }
};