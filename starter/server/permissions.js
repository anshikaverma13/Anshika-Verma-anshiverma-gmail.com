// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs:
//   permissions                 the catalogue (read from table, never hardcoded)
//   role_permissions            the per-role baseline
//   memberships                 role + status
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// NOTE: the database is personalised — there is at least one role and one permission
// not mentioned in the prose. Always read from the tables.

import { forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// ---------------------------------------------------------------------------
// Wildcard expansion (D7 of PERMISSIONS.md is irrelevant here; this is about
// grant pattern expansion). Pure function — no DB access.
//
// Rules:
//   '*'        -> every key in catalogue
//   'foo:*'    -> every key whose prefix is 'foo:'
//   exact key  -> that key if present, nothing otherwise
// ---------------------------------------------------------------------------
function expand(pattern, catalogue) {
  if (pattern === '*') return catalogue.slice();
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // 'device:*' -> 'device:'
    return catalogue.filter((k) => k.startsWith(prefix));
  }
  return catalogue.includes(pattern) ? [pattern] : [];
}

// ---------------------------------------------------------------------------
// Pure calculation over already-loaded data. Called from both resolve() and
// resolveDevices() so there is exactly one implementation of the algorithm.
//
// Parameters:
//   catalogue  string[]             all permission keys from the `permissions` table
//   role       string               the membership's role key
//   baseline   Set<string>          permissions the role grants (from role_permissions)
//   grants     {grant_id, device_id, effect, permission}[]  applicable grant rows
//
// Returns the permissions object: { [key]: { effect, source, reason } }
// ---------------------------------------------------------------------------
function buildPermissions({ catalogue, role, baseline, grants }) {
  // Step 1: collect all explicit denies. Deny wins unconditionally (D1) —
  // process them first so nothing can remove an entry from the deny set.
  const denied = new Map(); // permission key -> grant_id that caused the deny

  for (const row of grants) {
    if (row.effect !== 'deny') continue;
    for (const key of expand(row.permission, catalogue)) {
      if (!denied.has(key)) denied.set(key, row.grant_id);
    }
  }

  // Step 2: collect allows — baseline first, then allow-grants for gaps.
  // Baseline gets provenance 'role:<role>'; grant provenance is 'grant:<id>'.
  const allowed = new Map(); // permission key -> source string

  for (const key of baseline) {
    allowed.set(key, `role:${role}`);
  }
  for (const row of grants) {
    if (row.effect !== 'allow') continue;
    for (const key of expand(row.permission, catalogue)) {
      if (!allowed.has(key)) allowed.set(key, `grant:${row.grant_id}`);
    }
  }

  // Step 3: build the final map for every catalogue entry.
  const permissions = {};
  for (const key of catalogue) {
    if (denied.has(key)) {
      permissions[key] = { effect: 'deny', source: `grant:${denied.get(key)}`, reason: 'explicit_deny' };
    } else if (allowed.has(key)) {
      permissions[key] = { effect: 'allow', source: allowed.get(key), reason: null };
    } else {
      permissions[key] = { effect: 'deny', source: null, reason: 'implicit' };
    }
  }

  return permissions;
}

// ---------------------------------------------------------------------------
// Database helpers — kept private, called by resolve() and resolveDevices().
// ---------------------------------------------------------------------------

function loadCatalogue(db) {
  return db.prepare('SELECT key FROM permissions').all().map((r) => r.key);
}

function loadBaseline(db, role) {
  return new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role).map((r) => r.permission)
  );
}

function membershipOf(db, orgId, userId) {
  return db.prepare('SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
}

// Collect applicable grants for a user in an org, within the half-open time window.
// deviceId === null  -> org-level: ALL grants (including device-scoped ones)
// deviceId === 'x'  -> exact check: org-wide grants PLUS grants for that specific device
function collectGrants(db, { userId, orgId, deviceId, at }) {
  const base = `
    SELECT g.id AS grant_id, g.device_id, g.effect, gp.permission
      FROM grants g
      JOIN grant_permissions gp ON gp.grant_id = g.id
     WHERE g.user_id  = ?
       AND g.org_id   = ?
       AND g.revoked_at IS NULL
       AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
       AND (g.expires_at IS NULL OR g.expires_at >  ?)`;

  if (deviceId === null) {
    return db.prepare(base).all(userId, orgId, at, at);
  }
  return db
    .prepare(`${base} AND (g.device_id IS NULL OR g.device_id = ?)`)
    .all(userId, orgId, at, at, deviceId);
}

// Return a denyAll permissions object — used when the identity gate fires.
function denyAll(catalogue, role, reason) {
  const permissions = {};
  for (const key of catalogue) {
    permissions[key] = { effect: 'deny', source: null, reason };
  }
  return { role, permissions };
}

// Map a membership status to the denial reason string, or null when the
// membership is live and resolution should proceed normally.
function gateReason(status) {
  if (status === 'suspended') return 'suspended';
  if (status !== 'active') return 'inactive_membership';
  return null;
}

// ---------------------------------------------------------------------------
// resolve() — the public single-user, single-(optional-)device entry point.
// ---------------------------------------------------------------------------
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const at = now.toISOString();
  const catalogue = loadCatalogue(db);

  const membership = membershipOf(db, orgId, userId);

  // Identity gate: no membership or inactive/suspended status short-circuits to deny.
  if (!membership) return denyAll(catalogue, null, 'not_a_member');
  const gate = gateReason(membership.status);
  if (gate) return denyAll(catalogue, membership.role, gate);

  const baseline = loadBaseline(db, membership.role);
  const grants = collectGrants(db, { userId, orgId, deviceId, at });

  return {
    role: membership.role,
    permissions: buildPermissions({ catalogue, role: membership.role, baseline, grants }),
  };
}

// ---------------------------------------------------------------------------
// resolveDevices() — batched form for list endpoints (avoids N+1).
//
// Loads catalogue, membership, and baseline ONCE. Fetches all grants for the
// user+org in a single query (no device filter), then filters per device in
// memory. Per-device work is pure in-memory — no additional DB round-trips.
// ---------------------------------------------------------------------------
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const at = now.toISOString();
  const catalogue = loadCatalogue(db);
  const membership = membershipOf(db, orgId, userId);

  const role = membership?.role ?? null;
  const gate = membership ? gateReason(membership.status) : 'not_a_member';

  if (gate) {
    // Short-circuit: build a deny-all map and apply it to every device.
    const { permissions: denied } = denyAll(catalogue, role, gate);
    const byDevice = {};
    for (const id of deviceIds) byDevice[id] = denied;
    return { role, byDevice };
  }

  const baseline = loadBaseline(db, role);

  // One grant query for ALL devices — device filtering happens below in memory.
  const allGrants = collectGrants(db, { userId, orgId, deviceId: null, at });

  const byDevice = {};
  for (const id of deviceIds) {
    // For each device, restrict to org-wide grants + grants scoped to this device.
    const grants = allGrants.filter((row) => row.device_id === null || row.device_id === id);
    byDevice[id] = buildPermissions({ catalogue, role, baseline, grants });
  }

  return { role, byDevice };
}

// ---------------------------------------------------------------------------
// can() — boolean convenience wrapper.
// ---------------------------------------------------------------------------
export function can(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: deviceId ?? null });
  return permissions[permission]?.effect === 'allow';
}

// ---------------------------------------------------------------------------
// assertCan() — throws 403 FORBIDDEN with a reason code when denied.
//
// Reason-code mapping (PERMISSIONS.md §5):
//   explicit_deny      -> 'explicit_deny'
//   suspended          -> 'suspended'
//   not_a_member /
//   inactive_membership-> 'not_a_member'
//   implicit           -> 'missing_permission'
// ---------------------------------------------------------------------------
export function assertCan(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: deviceId ?? null });
  const entry = permissions[permission];

  if (entry?.effect === 'allow') return;

  const reasonMap = {
    explicit_deny:        'explicit_deny',
    suspended:            'suspended',
    not_a_member:         'not_a_member',
    inactive_membership:  'not_a_member',
    implicit:             'missing_permission',
  };

  throw forbidden(
    `missing permission: ${permission}`,
    reasonMap[entry?.reason] ?? 'missing_permission'
  );
}

// ---------------------------------------------------------------------------
// assertMayGrant() — no privilege laundering (D9).
//
// The caller may only hand out authority they hold themselves, resolved at the
// SAME scope the proposed grant will have (org-wide if deviceId is null,
// device-scoped if not).
// ---------------------------------------------------------------------------
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const catalogue = Object.keys(permissions);

  for (const pattern of patterns) {
    for (const key of expand(pattern, catalogue)) {
      if (permissions[key]?.effect === 'allow') continue;
      const reason = permissions[key]?.reason === 'explicit_deny'
        ? 'explicit_deny'
        : 'missing_permission';
      throw forbidden(
        `you cannot grant a permission you do not hold at this scope: ${key}`,
        reason
      );
    }
  }
}

// ---------------------------------------------------------------------------
// assertCanStartSession() — compound check (BRIEF.md §5.1).
//
// Two independent permissions on the SAME device:
//   1. session:start     — failure reason: 'missing_permission'
//   2. mode permission   — failure reason: 'missing_device_permission'
//
// The distinction matters: the caller needs to know which one was missing.
// ---------------------------------------------------------------------------
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw forbidden('unknown session mode', 'validation');

  // Check session:start first.
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  if (permissions['session:start']?.effect !== 'allow') {
    throw forbidden('missing permission: session:start', 'missing_permission');
  }

  // Check the mode-specific device permission separately.
  if (permissions[modePermission]?.effect !== 'allow') {
    throw forbidden(`missing permission: ${modePermission}`, 'missing_device_permission');
  }
}
