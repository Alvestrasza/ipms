import "server-only";
import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import type {
  ServiceAccount,
  ServiceAccountHost,
} from "./service-account-types";

export async function getServiceAccounts(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const responses = await Promise.all(
      ["", "hosts/"].map((suffix) =>
        fetch(`${CONTROL_PLANE_URL}/api/v1/service-accounts/${suffix}`, {
          cache: "no-store",
          headers,
          signal: AbortSignal.timeout(15_000),
        }),
      ),
    );
    if (responses.some((response) => !response.ok))
      return {
        sessionValid: !responses.some((response) => response.status === 401),
        authorized: !responses.some((response) => response.status === 403),
        available: false,
        accounts: [] as ServiceAccount[],
        hosts: [] as ServiceAccountHost[],
      };
    const [accounts, hosts] = await Promise.all(
      responses.map((response) => response.json()),
    );
    if (!Array.isArray(accounts.results) || !Array.isArray(hosts.results))
      throw new Error();
    return {
      sessionValid: true,
      authorized: true,
      available: true,
      accounts: accounts.results as ServiceAccount[],
      hosts: hosts.results as ServiceAccountHost[],
    };
  } catch {
    return {
      sessionValid: true,
      authorized: true,
      available: false,
      accounts: [] as ServiceAccount[],
      hosts: [] as ServiceAccountHost[],
    };
  }
}
