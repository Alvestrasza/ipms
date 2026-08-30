"use client";

import { Languages } from "lucide-react";
import { useState } from "react";

import { type Locale, SUPPORTED_LOCALES } from "@/i18n/config";
import { useLocale } from "@/i18n/locale-provider";

export function LanguageSwitcher() {
  const { locale, dictionary } = useLocale();
  const [selectedLocale, setSelectedLocale] = useState(locale);
  const [error, setError] = useState("");

  async function changeLocale(nextLocale: Locale) {
    setSelectedLocale(nextLocale);
    setError("");
    try {
      const response = await fetch("/api/locale", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ locale: nextLocale }),
      });
      if (!response.ok) throw new Error("Locale update failed");
      window.location.reload();
    } catch {
      setSelectedLocale(locale);
      setError(dictionary.language.changeFailed);
    }
  }

  return (
    <div className="language-switcher">
      <label>
        <span className="sr-only">{dictionary.language.label}</span>
        <Languages aria-hidden="true" size={17} />
        <select
          aria-label={dictionary.language.label}
          value={selectedLocale}
          onChange={(event) => void changeLocale(event.target.value as Locale)}
        >
          {SUPPORTED_LOCALES.map((supportedLocale) => (
            <option key={supportedLocale} value={supportedLocale}>
              {supportedLocale === "de"
                ? dictionary.language.german
                : dictionary.language.english}
            </option>
          ))}
        </select>
      </label>
      {error ? (
        <span className="sr-only" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}
