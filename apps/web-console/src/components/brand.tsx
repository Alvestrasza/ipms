import Image from "next/image";

type BrandProps = {
  compact?: boolean;
};

export function Brand({ compact = false }: BrandProps) {
  return (
    <div className={compact ? "brand brand--compact" : "brand"}>
      <Image
        className="brand__emblem"
        src="/brand/alvestrasza-emblem.png"
        alt="Alvestrasza Corporation emblem"
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
