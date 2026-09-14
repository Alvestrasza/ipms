/**
 * File Name: logs-sort-heading.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Provide accessible URL-based ordering for job and BMC log tables.
 */
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import type { JobLogsCopy } from "@/i18n/job-logs-copy";
import { logUrl } from "@/lib/job-log-types";
import styles from "./logs-page.module.css";

export function LogsSortHeading({
  column,
  label,
  path,
  query,
  copy,
  defaultSort = "requested_at",
}: {
  column: string;
  label: string;
  path: string;
  query: URLSearchParams;
  copy: JobLogsCopy;
  defaultSort?: string;
}) {
  const active = (query.get("sort") || defaultSort) === column;
  const ascending = query.get("direction") === "asc";
  const direction = active && ascending ? "desc" : "asc";
  const Icon = active ? (ascending ? ArrowUp : ArrowDown) : ArrowUpDown;
  return (
    <th
      scope="col"
      aria-sort={active ? (ascending ? "ascending" : "descending") : undefined}
    >
      <Link
        className={styles.sort}
        href={
          logUrl(path, query, { sort: column, direction, page: null }) as Route
        }
        aria-label={(direction === "asc"
          ? copy.sortAscending
          : copy.sortDescending
        ).replace("{column}", label)}
      >
        {label}
        <Icon size={14} aria-hidden="true" />
      </Link>
    </th>
  );
}
