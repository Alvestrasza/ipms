export type WindowsNetworkAddress = {
  address: string;
  prefix_length: number;
};

export type WindowsNetworkInterface = {
  interface_id: string;
  name: string;
  description: string;
  mac_address: string;
  status:
    | "up"
    | "down"
    | "testing"
    | "dormant"
    | "not-present"
    | "lower-layer-down"
    | "unknown";
  transmit_link_speed_bps: number;
  receive_link_speed_bps: number;
  dhcp_enabled: boolean;
  dns_suffix: string;
  addresses: WindowsNetworkAddress[];
  gateways: string[];
  dns_servers: string[];
};

export type WindowsFixedVolume = {
  name: string;
  label: string;
  filesystem: string;
  total_bytes: number;
  free_bytes: number;
  used_percent: number;
};

export type WindowsInstalledRoleFeature = {
  name: string;
  display_name: string;
  parent_name: string;
  type: "role" | "role-service" | "feature";
};

export type WindowsServerRoleSummary = {
  name: string;
  display_name: string;
  physical_count: number;
  virtual_count: number;
};

export type WindowsServerTelemetry = {
  server_id: string;
  cpu_used_percent: number;
  memory_total_bytes: number;
  memory_available_bytes: number;
  memory_used_bytes: number;
  memory_used_percent: number;
  fixed_volumes: WindowsFixedVolume[];
  observed_at: string;
};

export type WindowsServer = {
  id: string;
  tenant_id: string;
  connector_id: string | null;
  source_id: string;
  inventory_source: "agent" | "hyper-v";
  server_type: "physical" | "virtual" | "unknown";
  hostname: string;
  fqdn: string;
  domain_name: string;
  operating_system: string;
  os_version: string;
  os_build: string;
  architecture: string;
  manufacturer: string;
  model: string;
  serial_number: string;
  system_uuid: string;
  logical_processors: number | null;
  memory_bytes: number | null;
  cluster_name: string;
  hypervisor_host: string;
  agent_version: string;
  agent_state: "not-enrolled" | "online" | "stale" | "offline" | "unknown";
  health: "healthy" | "warning" | "critical" | "unknown";
  management_packs: string[];
  installed_roles_features_status?:
    | "not-reported"
    | "collected"
    | "unavailable";
  installed_roles_features_error?:
    | "com_initialization_failed"
    | "com_security_failed"
    | "wmi_locator_failed"
    | "allocation_failed"
    | "server_manager_provider_unavailable"
    | "wmi_proxy_failed"
    | "server_manager_query_failed"
    | "server_manager_query_timeout"
    | "server_manager_result_invalid"
    | "server_feature_fallback_unavailable"
    | "server_feature_fallback_query_failed"
    | "server_feature_fallback_query_timeout"
    | "server_feature_fallback_result_invalid"
    | "item_limit_exceeded"
    | "value_limit_exceeded"
    | "payload_limit_exceeded"
    | "";
  installed_roles_features?: WindowsInstalledRoleFeature[];
  last_seen_at: string | null;
  discovered_at: string;
  network_interfaces?: WindowsNetworkInterface[];
  latest_telemetry?: WindowsServerTelemetry | null;
};
