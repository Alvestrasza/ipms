import type { Metadata } from "next";
import { Cinzel, Inter } from "next/font/google";
import { connection } from "next/server";

import { getDictionary } from "@/i18n/dictionaries";
import { LocaleProvider } from "@/i18n/locale-provider";
import { resolveLocale } from "@/i18n/server";

import "./globals.css";

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

export default async function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  await connection();
  const locale = await resolveLocale();
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
