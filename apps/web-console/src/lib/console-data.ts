export type OperationalStatus = "healthy" | "warning" | "critical" | "unknown";

export type InventoryRow = {
  id: string;
  name: string;
  kind: string;
  location: string;
  status: OperationalStatus;
  detail: string;
  updated: string;
};

export type DiscoveryJob = {
  id: string;
  connector: string;
  target: string;
  status: "succeeded" | "running" | "failed";
  started: string;
  duration: string;
};

export const summaryCards = [
  {
    label: "Physical systems",
    value: "14",
    detail: "13 reachable",
    status: "healthy" as const,
  },
  {
    label: "Virtual machines",
    value: "42",
    detail: "39 running",
    status: "healthy" as const,
  },
  {
    label: "Network devices",
    value: "8",
    detail: "1 requires attention",
    status: "warning" as const,
  },
  {
    label: "Restore points",
    value: "126",
    detail: "Latest 18 min ago",
    status: "healthy" as const,
  },
];

export const inventoryRows: InventoryRow[] = [
  {
    id: "inv-01",
    name: "HV-CLUSTER-01",
    kind: "Hyper-V cluster",
    location: "Primary site",
    status: "healthy",
    detail: "3 hosts · 24 VMs",
    updated: "2 min ago",
  },
  {
    id: "inv-02",
    name: "BMC-RACK-A-02",
    kind: "iLO Redfish",
    location: "Rack A",
    status: "warning",
    detail: "Storage health degraded",
    updated: "4 min ago",
  },
  {
    id: "inv-03",
    name: "HV-HOST-04",
    kind: "Hyper-V host",
    location: "Secondary site",
    status: "critical",
    detail: "Discovery unavailable",
    updated: "12 min ago",
  },
  {
    id: "inv-04",
    name: "CORE-SWITCH-01",
    kind: "Network switch",
    location: "Primary site",
    status: "unknown",
    detail: "Connector not configured",
    updated: "Never",
  },
];

export const discoveryJobs: DiscoveryJob[] = [
  {
    id: "job-51f8",
    connector: "Hyper-V",
    target: "HV-CLUSTER-01",
    status: "succeeded",
    started: "10:42 UTC",
    duration: "18 s",
  },
  {
    id: "job-51f7",
    connector: "iLO Redfish",
    target: "BMC-RACK-A-02",
    status: "succeeded",
    started: "10:38 UTC",
    duration: "7 s",
  },
  {
    id: "job-51f6",
    connector: "Hyper-V",
    target: "HV-HOST-04",
    status: "failed",
    started: "10:31 UTC",
    duration: "31 s",
  },
];
