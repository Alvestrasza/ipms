import Link from "next/link";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";

export default async function NotFound() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  return (
    <main className="state-page">
      <p className="eyebrow">404</p>
      <h1>{dictionary.state.notFoundHeading}</h1>
      <p>{dictionary.state.notFoundDescription}</p>
      <Link className="primary-button" href={`/${locale}`}>
        {dictionary.state.returnOverview}
      </Link>
    </main>
  );
}
