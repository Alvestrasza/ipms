import "server-only";

import { notFound } from "next/navigation";
import { locale as routeLocale } from "next/root-params";
import { cache } from "react";

import { isLocale, type Locale } from "./config";

export const resolveLocale = cache(async (): Promise<Locale> => {
  const locale = await routeLocale();
  if (!isLocale(locale)) notFound();
  return locale.toLowerCase() as Locale;
});
