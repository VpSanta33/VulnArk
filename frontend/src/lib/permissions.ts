export function normalizePermission(permission: string): string {
  return permission.startsWith('vulnerability:') ? `vuln:${permission.slice('vulnerability:'.length)}` : permission;
}

/** Keep this equivalent to model.PermissionGranted on the server. */
export function permissionGranted(grants: readonly string[] | null | undefined, requested: string): boolean {
  const permission = normalizePermission(requested);
  return (grants || []).some(value => {
    const grant = normalizePermission(value);
    return grant === '*' || grant === permission || (grant.endsWith(':*') && permission.startsWith(grant.slice(0, -1)));
  });
}
