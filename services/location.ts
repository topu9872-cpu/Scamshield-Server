export interface CompanyLocationResult {
  address: string | null;
  city: string | null;
  state: string | null;
  country: string | null;
  lat: number | null;
  lon: number | null;
  image: string | null;
  summary: string | null;
  wikipedia: string | null;
}

interface WikipediaPage {
  pageid?: number;
  ns?: number;
  title?: string;
  missing?: boolean;

  coordinates?: Array<{
    lat: number;
    lon: number;
  }>;

  thumbnail?: {
    source: string;
    width: number;
    height: number;
  };

  extract?: string;
  fullurl?: string;
}

interface WikipediaQueryResponse {
  query?: {
    pages?: Record<string, WikipediaPage>;
  };
}

interface WikipediaSearchResponse {
  query?: {
    search?: Array<{
      title?: string;
      pageid?: number;
    }>;
  };
}

interface NominatimResult {
  lat?: string;
  lon?: string;
  display_name?: string;

  address?: {
    city?: string;
    town?: string;
    village?: string;
    municipality?: string;
    state?: string;
    country?: string;
  };
}

// ============================================================
// HEADERS
// ============================================================

const WIKIPEDIA_HEADERS = {
  "User-Agent":
    "ScamShield/1.0 (contact: topu9872@gmail.com)",
};

const NOMINATIM_HEADERS = {
  "User-Agent":
    "ScamShield/1.0 (contact: topu9872@gmail.com)",
  Accept: "application/json",
};

// ============================================================
// NORMALIZE COMPANY NAME
// ============================================================

const normalizeCompanyName = (
  value: string
): string => {
  return value
    .toLowerCase()
    .replace(
      /\b(inc|inc\.|corp|corp\.|corporation|company|co|co\.|ltd|ltd\.|llc|plc|group)\b/g,
      ""
    )
    .replace(/[^\w\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
};

// ============================================================
// WIKIPEDIA SEARCH
// ============================================================

const searchWikipedia = async (
  companyName: string
): Promise<string[]> => {
  try {
    const searchUrl =
      `https://en.wikipedia.org/w/api.php` +
      `?action=query` +
      `&list=search` +
      `&srsearch=${encodeURIComponent(companyName)}` +
      `&srlimit=8` +
      `&srnamespace=0` +
      `&format=json` +
      `&origin=*`;

    const response = await fetch(searchUrl, {
      headers: WIKIPEDIA_HEADERS,
    });

    if (!response.ok) {
      console.error(
        "Wikipedia search failed:",
        response.status
      );

      return [];
    }

    const data =
      (await response.json()) as WikipediaSearchResponse;

    const titles =
      data.query?.search
        ?.map((item) => item.title)
        .filter(
          (title): title is string =>
            typeof title === "string" &&
            title.trim().length > 0
        ) ?? [];

    return titles;
  } catch (error) {
    console.error(
      "Wikipedia search error:",
      error
    );

    return [];
  }
};

// ============================================================
// GET WIKIPEDIA PAGE
// ============================================================

const getWikipediaPage = async (
  title: string
): Promise<WikipediaPage | null> => {
  try {
    const pageUrl =
      `https://en.wikipedia.org/w/api.php` +
      `?action=query` +
      `&prop=coordinates|pageimages|extracts|info` +
      `&titles=${encodeURIComponent(title)}` +
      `&piprop=thumbnail` +
      `&pithumbsize=500` +
      `&exintro=1` +
      `&explaintext=1` +
      `&inprop=url` +
      `&format=json` +
      `&origin=*`;

    const response = await fetch(pageUrl, {
      headers: WIKIPEDIA_HEADERS,
    });

    if (!response.ok) {
      return null;
    }

    const data =
      (await response.json()) as WikipediaQueryResponse;

    const pages =
      data.query?.pages;

    if (!pages) {
      return null;
    }

    const page =
      Object.values(pages)[0];

    if (
      !page ||
      page.missing !== undefined
    ) {
      return null;
    }

    return page;
  } catch (error) {
    console.error(
      "Wikipedia page error:",
      error
    );

    return null;
  }
};

// ============================================================
// FIND HEADQUARTERS
// ============================================================

const findHeadquarters = (
  text: string
): string | null => {
  const patterns = [
    /headquartered\s+(?:in|at)\s+([^.;]+)/i,

    /headquarters\s+(?:is|are)?\s*(?:located\s+)?(?:in|at)\s+([^.;]+)/i,

    /headquarters\s*:\s*([^.;]+)/i,

    /corporate headquarters\s+(?:is|are)?\s*(?:located\s+)?(?:in|at)\s+([^.;]+)/i,

    /based\s+(?:in|at)\s+([^.;]+)/i,

    /located\s+(?:in|at)\s+([^.;]+)/i,

    /office\s+(?:is|are)?\s*(?:located\s+)?(?:in|at)\s+([^.;]+)/i,
  ];

  for (const pattern of patterns) {
    const match =
      text.match(pattern);

    if (match?.[1]) {
      const location =
        match[1]
          .trim()
          .replace(/\s+/g, " ");

      if (
        location.length >= 2 &&
        location.length <= 150
      ) {
        return location;
      }
    }
  }

  return null;
};

// ============================================================
// NOMINATIM GEOCODING
// ============================================================

const geocodeLocation = async (
  location: string
): Promise<{
  address: string | null;
  city: string | null;
  state: string | null;
  country: string | null;
  lat: number | null;
  lon: number | null;
}> => {
  try {
    console.log(
      "NOMINATIM SEARCH:",
      location
    );

    const url =
      `https://nominatim.openstreetmap.org/search` +
      `?q=${encodeURIComponent(location)}` +
      `&format=json` +
      `&addressdetails=1` +
      `&limit=1`;

    const response = await fetch(url, {
      headers: NOMINATIM_HEADERS,
    });

    if (!response.ok) {
      console.error(
        "Nominatim failed:",
        response.status
      );

      return {
        address: null,
        city: null,
        state: null,
        country: null,
        lat: null,
        lon: null,
      };
    }

    const data =
      (await response.json()) as NominatimResult[];

    const result = data?.[0];

    if (!result) {
      console.log(
        "NOMINATIM: No result"
      );

      return {
        address: null,
        city: null,
        state: null,
        country: null,
        lat: null,
        lon: null,
      };
    }

    const lat =
      Number(result.lat);

    const lon =
      Number(result.lon);

    if (
      !Number.isFinite(lat) ||
      !Number.isFinite(lon)
    ) {
      return {
        address: null,
        city: null,
        state: null,
        country: null,
        lat: null,
        lon: null,
      };
    }

    return {
      address:
        result.display_name ??
        location,

      city:
        result.address?.city ??
        result.address?.town ??
        result.address?.village ??
        result.address?.municipality ??
        null,

      state:
        result.address?.state ??
        null,

      country:
        result.address?.country ??
        null,

      lat,
      lon,
    };
  } catch (error) {
    console.error(
      "Nominatim error:",
      error
    );

    return {
      address: null,
      city: null,
      state: null,
      country: null,
      lat: null,
      lon: null,
    };
  }
};

// ============================================================
// CHECK IF WIKIPEDIA RESULT IS RELEVANT
// ============================================================

const isRelevantCompanyPage = (
  companyName: string,
  title: string,
  extract: string
): boolean => {
  const normalizedCompany =
    normalizeCompanyName(
      companyName
    );

  const normalizedTitle =
    normalizeCompanyName(title);

  const normalizedExtract =
    normalizeCompanyName(extract);

  // Exact title match gets highest confidence
  if (
    normalizedTitle ===
    normalizedCompany
  ) {
    return true;
  }

  // Company name must appear in title
  if (
    normalizedTitle.includes(
      normalizedCompany
    )
  ) {
    return true;
  }

  // Company name should appear in extract
  if (
    normalizedExtract.includes(
      normalizedCompany
    )
  ) {
    return true;
  }

  return false;
};

// ============================================================
// MAIN LOCATION FUNCTION
// ============================================================

export const getCompanyLocation = async (
  companyName?: string | null,
  domain?: string | null,
  websiteDescription?: string | null
): Promise<CompanyLocationResult> => {
  const safeName =
    companyName?.trim() ||
    domain?.split(".")[0] ||
    "Entity";

  console.log(
    "=========================================="
  );

  console.log(
    "LOCATION LOOKUP:",
    {
      companyName: safeName,
      domain,
    }
  );

  console.log(
    "=========================================="
  );

  let image: string | null =
    null;

  let summary: string | null =
    websiteDescription ||
    null;

  let wikipedia: string | null =
    null;

  try {
    // ========================================================
    // 1. SEARCH WIKIPEDIA
    // ========================================================

    const titles =
      await searchWikipedia(
        safeName
      );

    console.log(
      "WIKIPEDIA TITLES:",
      titles
    );

    if (!titles.length) {
      console.log(
        "NO WIKIPEDIA RESULTS:",
        safeName
      );

      return {
        address: null,
        city: null,
        state: null,
        country: null,
        lat: null,
        lon: null,
        image: null,
        summary,
        wikipedia: null,
      };
    }

    // ========================================================
    // 2. PUT EXACT MATCH FIRST
    // ========================================================

    const normalizedCompany =
      normalizeCompanyName(
        safeName
      );

    titles.sort(
      (a, b) => {
        const aName =
          normalizeCompanyName(a);

        const bName =
          normalizeCompanyName(b);

        if (
          aName ===
          normalizedCompany
        ) {
          return -1;
        }

        if (
          bName ===
          normalizedCompany
        ) {
          return 1;
        }

        return 0;
      }
    );

    // ========================================================
    // 3. CHECK WIKIPEDIA RESULTS
    // ========================================================

    for (const title of titles) {
      console.log(
        "CHECKING WIKIPEDIA:",
        title
      );

      const page =
        await getWikipediaPage(
          title
        );

      if (!page) {
        continue;
      }

      const pageTitle =
        page.title ||
        title;

      const pageSummary =
        page.extract ||
        "";

      // ======================================================
      // 4. VALIDATE COMPANY PAGE
      // ======================================================

      const relevant =
        isRelevantCompanyPage(
          safeName,
          pageTitle,
          pageSummary
        );

      if (!relevant) {
        console.log(
          "SKIPPING UNRELATED PAGE:",
          pageTitle
        );

        continue;
      }

      console.log(
        "WIKIPEDIA MATCH:",
        pageTitle
      );

      // ======================================================
      // SAVE BASIC WIKIPEDIA DATA
      // ======================================================

      if (
        typeof page.thumbnail
          ?.source === "string"
      ) {
        image =
          page.thumbnail.source;
      }

      if (pageSummary) {
        summary =
          pageSummary;
      }

      wikipedia =
        page.fullurl ??
        `https://en.wikipedia.org/wiki/${encodeURIComponent(
          pageTitle.replace(
            / /g,
            "_"
          )
        )}`;

      // ======================================================
      // 5. FIRST TRY WIKIPEDIA COORDINATES
      // ======================================================

      const coordinates =
        page.coordinates?.[0];

      if (
        coordinates &&
        Number.isFinite(
          coordinates.lat
        ) &&
        Number.isFinite(
          coordinates.lon
        )
      ) {
        console.log(
          "WIKIPEDIA COORDINATES:",
          coordinates
        );

        return {
          address: pageTitle,
          city: null,
          state: null,
          country: null,
          lat: coordinates.lat,
          lon: coordinates.lon,
          image,
          summary,
          wikipedia,
        };
      }

      // ======================================================
      // 6. TRY HEADQUARTERS TEXT
      // ======================================================

      const text =
        `${pageTitle}. ${pageSummary}`;

      const headquarters =
        findHeadquarters(text);

      console.log(
        "HEADQUARTERS:",
        headquarters
      );

      if (!headquarters) {
        continue;
      }

      // ======================================================
      // 7. GEOCODE HEADQUARTERS
      // ======================================================

      const location =
        await geocodeLocation(
          headquarters
        );

      if (
        location.lat === null ||
        location.lon === null
      ) {
        console.log(
          "HEADQUARTERS COULD NOT BE GEOCODED:",
          headquarters
        );

        continue;
      }

      console.log(
        "REAL COMPANY LOCATION:",
        location
      );

      return {
        address:
          location.address,

        city:
          location.city,

        state:
          location.state,

        country:
          location.country,

        lat:
          location.lat,

        lon:
          location.lon,

        image,

        summary,

        wikipedia,
      };
    }

    // ========================================================
    // 8. NOTHING FOUND
    // ========================================================

    console.log(
      "LOCATION NOT FOUND:",
      safeName
    );

    return {
      address: null,
      city: null,
      state: null,
      country: null,
      lat: null,
      lon: null,
      image: null,
      summary:
        websiteDescription ||
        null,
      wikipedia: null,
    };
  } catch (error) {
    console.error(
      "Company location error:",
      error
    );

    return {
      address: null,
      city: null,
      state: null,
      country: null,
      lat: null,
      lon: null,
      image: null,
      summary:
        websiteDescription ||
        null,
      wikipedia: null,
    };
  }
};