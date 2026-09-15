/**
 * File Name: security-baseline-details.tsx
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Open a newly selected baseline while retaining the chosen deployment domain.
 */
"use client";

import { type ReactNode, useEffect, useRef } from "react";

export function SecurityBaselineDetails({
  baselineId,
  className,
  children,
}: {
  baselineId: string;
  className: string;
  children: ReactNode;
}) {
  const details = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (baselineId && details.current) details.current.open = true;
  }, [baselineId]);

  return (
    <details
      ref={details}
      open
      className={className}
      aria-labelledby="baseline-details-heading"
    >
      {children}
    </details>
  );
}
