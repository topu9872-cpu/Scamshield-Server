export const getCompanyLocation = async (
  company: string
) => {
  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(
        company
      )}&format=json&limit=1`,
      {
        headers: {
          "User-Agent": "ScamShield/1.0",
        },
      }
    );

    const data = await response.json();

    if (!Array.isArray(data) || data.length === 0) {
      return null;
    }

    const place = data[0];

    return {
      address: place.display_name,
      lat: Number(place.lat),
      lon: Number(place.lon),
    };
  } catch {
    return null;
  }
};