import { LinuxSystemPage } from "@/components/linux-system-page";
export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  return <LinuxSystemPage id={(await params).id} expectedType="virtual" />;
}
