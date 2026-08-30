import Image from "next/image";

import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";

type BrandProps = {
  compact?: boolean;
};

export async function Brand({ compact = false }: BrandProps) {
  const dictionary = getDictionary(await resolveLocale());
  return (
    <div className={compact ? "brand brand--compact" : "brand"}>
      <Image
        className="brand__emblem"
        src="/brand/alvestrasza-emblem.png"
        alt={dictionary.brand.emblemAlt}
        width={56}
        height={56}
        priority
      />
      <div className="brand__wordmark">
        <span className="brand__title">IPMS</span>
        <span className="brand__subtitle">A-Corp</span>
      </div>
    </div>
  );
}
