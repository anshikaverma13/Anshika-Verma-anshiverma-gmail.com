// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// Rules that more than one route needs live here so "what ends a session" has
// exactly one implementation.
//
// Two traps called out explicitly:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them
//     is the modelling error the auditor role exists to catch.
//   - A permission change does NOT end a session in flight (grandfathering).
//     Suspension, membership removal, and device transfer DO cascade.
//     See PERMISSIONS.md §7.

import { badRequest, forbidden, lastOwner } from './http.js';
import { nowIso } from './db.js';

// ---------------------------------------------------------------------------
// roleRanks(db)
//
// Returns a role-key → rank mapping read from the DB.
// Must be read from the table — never hardcoded — because the personalized DB
// may contain additional roles.
// ---------------------------------------------------------------------------
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  return Object.fromEntries(rows.map((r) => [r.key, r.rank]));
}

// ---------------------------------------------------------------------------
// assertRoleExists(db, role)
//
// Validates that the supplied role string names a real role. An unknown role is
// a malformed request (400 VALIDATION), not a conflict, because the client
// submitted a value that the system never defined.
// ---------------------------------------------------------------------------
export function assertRoleExists(db, role) {
  const row = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!row) throw badRequest(`unknown role: ${role}`, 'unknown_role');
}

// ---------------------------------------------------------------------------
// assertCanModify(db, callerRole, targetRole)
//
// Modification authority (PERMISSIONS.md §6, D8):
//   owner  may modify anyone, including another owner
//   others may modify only users of strictly lower rank
//   equal rank or higher rank -> 403 FORBIDDEN/insufficient_rank
//
// This is the ONE place roles are compared numerically. It must never be used
// inside the permission resolution engine.
// ---------------------------------------------------------------------------
export function assertCanModify(db, callerRole, targetRole) {
  // Owners may modify anyone — no rank comparison needed.
  if (callerRole === 'owner') return;

  const ranks = roleRanks(db);
  if ((ranks[callerRole] ?? 0) > (ranks[targetRole] ?? 0)) return;

  throw forbidden(
    'you cannot modify a user at or above your own role',
    'insufficient_rank'
  );
}

// ---------------------------------------------------------------------------
// assertNotLastOwner(db, orgId, userId)
//
// The org must always have at least one owner (PERMISSIONS.md §6).
// Only active owners count — suspended or invited owners do not protect the org.
// ---------------------------------------------------------------------------
export function assertNotLastOwner(db, orgId, userId) {
  const target = db
    .prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);

  // If this user isn't an owner, the last-owner constraint doesn't apply.
  if (target?.role !== 'owner') return;

  const { n } = db
    .prepare(
      `SELECT count(*) AS n FROM memberships
        WHERE org_id = ? AND role = 'owner' AND status = 'active'`
    )
    .get(orgId);

  if (n <= 1) throw lastOwner();
}

// ---------------------------------------------------------------------------
// endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId })
//
// Ends all active sessions matching the supplied filters, in a single operation
// using a consistent timestamp. Called for account and tenancy cascade events:
//   - user suspended      -> reason: 'user_suspended'
//   - membership removed  -> reason: 'membership_removed'
//   - device transferred  -> reason: 'device_transferred'
//
// NOT called for role changes or grant changes — those are permission tweaks
// and sessions are grandfathered (PERMISSIONS.md §7).
//
// end_reason is a closed vocabulary enforced by a DB CHECK. Only use the
// values the schema defines — introducing a new string is a 500.
// ---------------------------------------------------------------------------
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const at = nowIso();

  // Build a dynamic WHERE clause based on which filters are supplied.
  const conditions = ["org_id = ?", "state = 'active'"];
  const params = [orgId];

  if (userId) {
    conditions.push('user_id = ?');
    params.push(userId);
  }
  if (deviceId) {
    conditions.push('device_id = ?');
    params.push(deviceId);
  }
  if (exceptSessionId) {
    conditions.push('id != ?');
    params.push(exceptSessionId);
  }

  const where = conditions.join(' AND ');

  // Collect IDs first so we can update individually and return them.
  const ids = db
    .prepare(`SELECT id FROM sessions WHERE ${where}`)
    .all(...params)
    .map((r) => r.id);

  if (ids.length === 0) return [];

  const stmt = db.prepare(
    `UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ? WHERE id = ?`
  );
  for (const id of ids) {
    stmt.run(at, reason, id);
  }

  return ids;
}

// ---------------------------------------------------------------------------
// snapshotAuthority(db, { userId, orgId, deviceId })
//
// Captures the authorization state at the moment a session is created.
// Sessions are grandfathered — this snapshot IS their authority for life,
// so it must be an accurate picture of "right now", including:
//   - the user's current role
//   - every active, applicable grant (org-wide + device-scoped, time-windowed)
//
// Returns a JSON string (sessions.authorized_by has CHECK(json_valid(...))).
// Shape mirrors seed/orgs.json authorizedBy: { role, grantIds, snapshotAt }
// ---------------------------------------------------------------------------
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const at = nowIso();

  const membership = db
    .prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?')
    .get(orgId, userId);
  const role = membership?.role ?? null;

  // Applicable grants: org-wide (device_id IS NULL) plus device-scoped if a
  // device is specified. Respects the half-open time window and revocation.
  const grantRows = db
    .prepare(
      `SELECT g.id FROM grants g
        WHERE g.user_id = ?
          AND g.org_id  = ?
          AND g.revoked_at IS NULL
          AND (g.starts_at  IS NULL OR g.starts_at  <= ?)
          AND (g.expires_at IS NULL OR g.expires_at >  ?)
          AND (g.device_id  IS NULL OR g.device_id  =  ?)`
    )
    .all(userId, orgId, at, at, deviceId ?? null);

  const grantIds = grantRows.map((r) => r.id);

  return JSON.stringify({ role, grantIds, snapshotAt: at });
}

// ---------------------------------------------------------------------------
// sessionExpiry(db, orgId)
//
// Computes the expires_at timestamp for a new session:
//   now + org.max_session_minutes (default 60)
//
// The TTL is what makes grandfathering safe: a revoked grant's authority
// cannot outlive the session, which expires within the hour at the latest.
// ---------------------------------------------------------------------------
export function sessionExpiry(db, orgId) {
  const row = db
    .prepare('SELECT max_session_minutes FROM organizations WHERE id = ?')
    .get(orgId);
  const minutes = row?.max_session_minutes ?? 60;
  return new Date(Date.now() + minutes * 60_000).toISOString();
}
