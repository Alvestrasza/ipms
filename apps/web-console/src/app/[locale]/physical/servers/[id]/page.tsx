import type { Metadata } from "next";

import { WindowsServerDetailPage } from "@/components/windows-server-detail-page";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";

type PageProps = { params: Promise<{ id: string }> };

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.windowsServerDetail.title };
}

export default async function PhysicalSystemDetailPage({ params }: PageProps) {
  const { id } = await params;
  return <WindowsServerDetailPage id={id} expectedType="physical" />;
}
