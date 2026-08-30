import "server-only";

import { cookies, headers } from "next/headers";
import { cache } from "react";

import {
  DEFAULT_LOCALE,
  isLocale,
  LOCALE_COOKIE,
  type Locale,
  localeFromAcceptLanguage,
} from "./config";

export const resolveLocale = cache(async (): Promise<Locale> => {
  const cookieLocale = (await cookies()).get(LOCALE_COOKIE)?.value;
  if (isLocale(cookieLocale)) return cookieLocale.toLowerCase() as Locale;

  const acceptLanguage = (await headers()).get("accept-language");
  return localeFromAcceptLanguage(acceptLanguage) ?? DEFAULT_LOCALE;
});
