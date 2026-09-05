export type PlatformTenant = {
  id: string;
  slug: string;
  display_name: string;
  status: "active" | "suspended" | "decommissioned";
  created_at: string;
  updated_at: string;
  needs_administrator: boolean;
};
