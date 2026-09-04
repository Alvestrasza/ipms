"use client";

import { Laptop, Minus, Plus } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import { useState } from "react";

import type { WindowsClientFamilySummary } from "@/lib/windows-server-types";

export function WindowsClientNavigation({
  active,
  activeFamily,
  collapseLabel,
  expandLabel,
  familyLabels,
  families,
  href,
  label,
  serverType,
}: {
  active: boolean;
  activeFamily?: string;
  collapseLabel: string;
  expandLabel: string;
  familyLabels: Record<string, string>;
  families: WindowsClientFamilySummary[];
  href: string;
  label: string;
  serverType: "physical" | "virtual";
}) {
  const visibleFamilies = families.filter((family) =>
    serverType === "physical"
      ? family.physical_count > 0
      : family.virtual_count > 0,
  );
  const [expanded, setExpanded] = useState(
    active && visibleFamilies.length > 0,
  );
  const treeId = `windows-${serverType}-client-families`;

  return (
    <>
      <div className="nav-subitem-branch">
        <Link
          className={`nav-subitem ${active ? "nav-subitem--active" : ""}`}
          href={href as Route}
          aria-current={active && !activeFamily ? "page" : undefined}
        >
          <Laptop aria-hidden="true" size={15} />
          <span>{label}</span>
        </Link>
        {visibleFamilies.length ? (
          <button
            className="nav-tree-toggle"
            type="button"
            aria-controls={treeId}
            aria-expanded={expanded}
            aria-label={`${expanded ? collapseLabel : expandLabel}: ${label}`}
            title={`${expanded ? collapseLabel : expandLabel}: ${label}`}
            onClick={() => setExpanded((current) => !current)}
          >
            {expanded ? (
              <Minus aria-hidden="true" size={14} />
            ) : (
              <Plus aria-hidden="true" size={14} />
            )}
          </button>
        ) : null}
      </div>
      {expanded && visibleFamilies.length ? (
        <ul className="nav-tree nav-tree--nested nav-role-tree" id={treeId}>
          {visibleFamilies.map((family) => {
            const count =
              serverType === "physical"
                ? family.physical_count
                : family.virtual_count;
            const selected = activeFamily === family.name;
            return (
              <li key={family.name}>
                <Link
                  className={`nav-subitem nav-role-item ${selected ? "nav-subitem--active" : ""}`}
                  href={
                    `${href}?family=${encodeURIComponent(family.name)}` as Route
                  }
                  aria-current={selected ? "page" : undefined}
                >
                  <span>{familyLabels[family.name] ?? family.name}</span>
                  <span className="nav-role-count">{count}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      ) : null}
    </>
  );
}
