export const SUPPORTED_LOCALES = ["en", "de"] as const;

export type Locale = (typeof SUPPORTED_LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "en";
export const LOCALE_COOKIE = "ipms_locale";

export function isLocale(value: unknown): value is Locale {
  return (
    typeof value === "string" &&
    SUPPORTED_LOCALES.includes(value.toLowerCase() as Locale)
  );
}

export function localeFromAcceptLanguage(value: string | null): Locale {
  if (!value) return DEFAULT_LOCALE;

  const preferences = value
    .split(",")
    .map((entry, index) => {
      const [tag, ...parameters] = entry.trim().split(";");
      const qualityParameter = parameters.find((parameter) =>
        parameter.trim().startsWith("q="),
      );
      const parsedQuality = qualityParameter
        ? Number.parseFloat(qualityParameter.trim().slice(2))
        : 1;
      return {
        tag: tag.toLowerCase(),
        quality: Number.isFinite(parsedQuality) ? parsedQuality : 0,
        index,
      };
    })
    .filter(({ tag, quality }) => tag && tag !== "*" && quality > 0)
    .sort(
      (left, right) => right.quality - left.quality || left.index - right.index,
    );

  for (const { tag } of preferences) {
    const language = tag.split("-")[0];
    if (isLocale(language)) return language;
  }

  return DEFAULT_LOCALE;
}

export function documentLocale(locale: Locale) {
  return locale === "de" ? "de-DE" : "en-GB";
}
