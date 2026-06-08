/**
 * Tenant ↔ host mapping types — surfaced by the host_mappings
 * router (P0-A3). Tenant admins use these to add/remove which
 * hosts their tenant sees compliance results for.
 *
 * Backed by the `tenant_host_mapping` table (migration 015).
 */

export interface HostMapping {
  id: string;
  tenant_id: string;
  hostname: string;
  /** null = all frameworks for this host */
  framework: string | null;
  created_at: string;
  created_by: string | null;
}

export interface CreateHostMapping {
  hostname: string;
  /** Omit or null = all frameworks */
  framework?: string | null;
}
