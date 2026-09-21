/**
 * File Name: hgs-portal.d.mts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Type the isolated HGS portal fixture shared with browser acceptance tests.
 */
import type { HgsDeployment } from "../../src/lib/hgs-types";

export const tenantId: string;
export const nodeId: string;
export const systemId: string;
export const deploymentId: string;
export function makePlan(status?: string): HgsDeployment;
