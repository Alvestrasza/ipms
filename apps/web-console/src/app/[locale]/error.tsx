"use client";

import { useLocale } from "@/i18n/locale-provider";

export default function LocalizedErrorPage({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const { dictionary } = useLocale();
  return (
    <main className="state-page">
      <p className="eyebrow">{dictionary.state.errorEyebrow}</p>
      <h1>{dictionary.state.errorHeading}</h1>
      <p>{dictionary.state.errorDescription}</p>
      <button className="primary-button" type="button" onClick={reset}>
        {dictionary.state.tryAgain}
      </button>
    </main>
  );
}
