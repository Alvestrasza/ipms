export type HyperVVirtualMachine = {
  id: string;
  tenant_id: string;
  host_id: string;
  host_fqdn: string;
  host_hostname: string;
  source_id: string;
  name: string;
  state:
    | "running"
    | "stopped"
    | "starting"
    | "stopping"
    | "paused"
    | "pausing"
    | "suspended"
    | "saving"
    | "resuming"
    | "quiesced"
    | "offline"
    | "unknown";
  vcpu_count: number | null;
  memory_bytes: number | null;
  uptime_seconds: number | null;
  configuration_version: string;
  ip_addresses: string[];
  observed_at: string;
};

export type HyperVAction = "start" | "stop" | "pause" | "resume";

export type HyperVActionJob = {
  id: string;
  action: HyperVAction;
  status:
    | "queued"
    | "delivered"
    | "running"
    | "succeeded"
    | "failed"
    | "cancelled";
  result_code: string;
};
