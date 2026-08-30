"use client";

import { type Locale, SUPPORTED_LOCALES } from "@/i18n/config";
import { useLocale } from "@/i18n/locale-provider";

export function LanguageSwitcher() {
  const { locale, dictionary } = useLocale();

  function changeLocale(nextLocale: Locale) {
    const url = new URL(window.location.href);
    const segments = url.pathname.split("/");
    segments[1] = nextLocale;
    url.pathname = segments.join("/");
    window.location.assign(`${url.pathname}${url.search}${url.hash}`);
  }

  return (
    <div className="language-switcher">
      <label>
        <span className="sr-only">{dictionary.language.label}</span>
        <select
          aria-label={dictionary.language.label}
          value={locale}
          onChange={(event) => changeLocale(event.target.value as Locale)}
        >
          {SUPPORTED_LOCALES.map((supportedLocale) => (
            <option key={supportedLocale} value={supportedLocale}>
              {supportedLocale.toUpperCase()}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
