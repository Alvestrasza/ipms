import type { Metadata } from "next";
import { Cinzel, Inter } from "next/font/google";
import { connection } from "next/server";

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
  robots: { index: false, follow: false },
};

export default async function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  await connection();
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body className={`${inter.variable} ${cinzel.variable}`}>{children}</body>
    </html>
  );
}
