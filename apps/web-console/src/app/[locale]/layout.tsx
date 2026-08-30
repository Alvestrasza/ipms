import type { Metadata } from "next";
import { Cinzel, Inter } from "next/font/google";
import { notFound } from "next/navigation";

import { isLocale, type Locale, SUPPORTED_LOCALES } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { LocaleProvider } from "@/i18n/locale-provider";

import "../globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-body",
  display: "swap",
});

const cinzel = Cinzel({
  subsets: ["latin"],
  variable: "--font-heading",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "IPMS Console",
    template: "%s | IPMS Console",
  },
  description: "Independent Platform Management System",
  icons: {
    icon: [{ url: "/brand/alvestrasza-emblem.png", type: "image/png" }],
    shortcut: "/brand/alvestrasza-emblem.png",
  },
  robots: { index: false, follow: false },
};

// A request-scoped CSP nonce requires dynamically rendered HTML.
export const dynamic = "force-dynamic";

export default async function RootLayout({
  children,
  params,
}: Readonly<{
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}>) {
  const { locale: routeLocale } = await params;
  if (!isLocale(routeLocale)) notFound();
  const locale = routeLocale.toLowerCase() as Locale;
  const dictionary = getDictionary(locale);
  return (
    <html lang={locale} data-theme="dark" suppressHydrationWarning>
      <body className={`${inter.variable} ${cinzel.variable}`}>
        <LocaleProvider locale={locale} dictionary={dictionary}>
          {children}
        </LocaleProvider>
      </body>
    </html>
  );
}

export function generateStaticParams() {
  return SUPPORTED_LOCALES.map((locale) => ({ locale }));
}
