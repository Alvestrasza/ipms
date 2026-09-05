export type ServiceAccount = {
  id: string;
  name: string;
  kind: "hyperv_console";
  username: string;
  domain: string;
  host_count: number;
  updated_at: string;
};

export type ServiceAccountHost = {
  id: string;
  fqdn: string;
  agent_version: string;
  service_account_id: string | null;
  legacy_configured: boolean;
  eligible: boolean;
  status: string;
};

export function serviceAccountDocument(
  fields: {
    name: string;
    username: string;
    domain: string;
    password: string;
  },
  editing: boolean,
  original?: Pick<ServiceAccount, "username" | "domain">,
): Record<string, string> {
  const name = fields.name.trim(),
    username = fields.username.trim(),
    domain = fields.domain.trim();
  if (
    !name ||
    name.length > 128 ||
    !username ||
    username.length > 256 ||
    domain.length > 256 ||
    fields.password.length > 1024 ||
    (!editing && !fields.password) ||
    Object.values(fields).some((value) => value.includes("\0"))
  )
    throw new Error("service_account_invalid");
  return {
    name,
    ...(!editing || username !== original?.username ? { username } : {}),
    ...(!editing || domain !== original?.domain ? { domain } : {}),
    ...(!editing ? { kind: "hyperv_console" } : {}),
    ...(fields.password ? { password: fields.password } : {}),
  };
}
