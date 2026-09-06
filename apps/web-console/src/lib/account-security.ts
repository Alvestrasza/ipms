export type IdentityAction = "rename" | "password";

export type AccountIdentity = {
  username: string;
  display_name: string;
  authentication_source: "local" | "oidc" | "hybrid";
  can_rename: boolean;
  can_change_password: boolean;
};

/** Fixed payload only; passwords are never trimmed or stored outside the form. */
export function identityActionDocument(
  action: IdentityAction,
  fields: Record<string, string>,
) {
  const current_password = fields.current_password ?? "";
  if (
    !current_password ||
    current_password.length > 1024 ||
    current_password.includes("\0")
  )
    throw new Error("invalid_request");
  if (action === "rename") {
    const username = (fields.username ?? "").trim();
    if (!username || username.length > 150 || username.includes("\0"))
      throw new Error("invalid_request");
    return { username, current_password };
  }
  const new_password = fields.new_password ?? "";
  if (
    new_password.length < 12 ||
    new_password.length > 1024 ||
    new_password.includes("\0")
  )
    throw new Error("invalid_request");
  if (new_password !== fields.confirm_password)
    throw new Error("password_mismatch");
  return { current_password, new_password };
}
