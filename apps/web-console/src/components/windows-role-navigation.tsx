"use client";

import { Minus, MonitorCog, Plus } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import { useState } from "react";

import type { WindowsServerRoleSummary } from "@/lib/windows-server-types";

export function WindowsRoleNavigation({
  active,
  activeRole,
  collapseLabel,
  expandLabel,
  href,
  label,
  roles,
  serverType,
}: {
  active: boolean;
  activeRole?: string;
  collapseLabel: string;
  expandLabel: string;
  href: string;
  label: string;
  roles: WindowsServerRoleSummary[];
  serverType: "physical" | "virtual";
}) {
  const visibleRoles = roles.filter((role) =>
    serverType === "physical"
      ? role.physical_count > 0
      : role.virtual_count > 0,
  );
  const [expanded, setExpanded] = useState(active && visibleRoles.length > 0);
  const treeId = `windows-${serverType}-roles`;

  return (
    <>
      <div className="nav-subitem-branch">
        <Link
          className={`nav-subitem ${active ? "nav-subitem--active" : ""}`}
          href={href as Route}
          aria-current={active && !activeRole ? "page" : undefined}
        >
          <MonitorCog aria-hidden="true" size={15} />
          <span>{label}</span>
        </Link>
        {visibleRoles.length ? (
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
      {expanded && visibleRoles.length ? (
        <ul className="nav-tree nav-tree--nested nav-role-tree" id={treeId}>
          {visibleRoles.map((role) => {
            const count =
              serverType === "physical"
                ? role.physical_count
                : role.virtual_count;
            const roleHref = `${href}?role=${encodeURIComponent(role.name)}`;
            const selected = activeRole === role.name;
            return (
              <li key={role.name}>
                <Link
                  className={`nav-subitem nav-role-item ${selected ? "nav-subitem--active" : ""}`}
                  href={roleHref as Route}
                  aria-current={selected ? "page" : undefined}
                  title={`${role.display_name} (${role.name})`}
                >
                  <span>{role.display_name}</span>
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
