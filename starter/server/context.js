// Per-request context: turn a bearer token into an authenticated caller.
//
// What it does, in order (BRIEF.md §3, PERMISSIONS.md §6, AUTH-DATA-MODEL.md §10):
//   1. Read the bearer token from Authorization: Bearer <token>
//   2. Verify it with verifyAccessToken() — throws 401 on any failure
//   3. Look up the live membership + org (join so soft-deleted orgs are detectable)
//   4. Refuse removed memberships (401) and soft-deleted orgs (404)
//   5. Suspended memberships skip assertFresh — the permission layer owns the 403
//   6. Active memberships call assertFresh — stale pv -> 401 TOKEN_STALE
//   7. Enforce structural cross-org isolation: params.org != claims.org -> 404
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries
//   { userId, orgId, role, membership, claims }

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // Step 1: extract the bearer token from the Authorization header.
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw unauthenticated('missing bearer token');

    // Step 2: verify the token cryptographically.
    // verifyAccessToken throws 401 UNAUTHENTICATED for every invalid-token case.
    const claims = verifyAccessToken(token, secret);

    // Step 3: load the live membership row, joining organizations so we can detect
    // a soft-deleted org in a single query rather than two round-trips.
    const membership = db
      .prepare(
        `SELECT m.role, m.status, m.perm_version, m.org_id, m.user_id,
                m.id, m.invited_by, m.joined_at, m.created_at,
                o.deleted_at AS org_deleted_at
           FROM memberships m
           JOIN organizations o ON o.id = m.org_id
          WHERE m.org_id = ? AND m.user_id = ?`
      )
      .get(claims.org, claims.sub);

    // Step 4a: no membership row -> not a member of this org.
    if (!membership) throw unauthenticated('not a member of this org');

    // Step 4b: org was soft-deleted after the token was minted -> invisible (404, not 401).
    if (membership.org_deleted_at) throw notFound();

    // Step 4c: removed membership -> credentials are no longer valid for this org.
    if (membership.status === 'removed') throw unauthenticated('membership removed');

    // Step 5: suspended memberships intentionally skip the freshness check.
    // Suspension bumps perm_version, so assertFresh would throw TOKEN_STALE — masking the
    // real reason. We let the request proceed; permissions.js returns a full deny-all set
    // with reason 'suspended', which produces the correct 403 FORBIDDEN/suspended.
    if (membership.status !== 'suspended') {
      assertFresh(claims, membership);
    }

    // Step 6 / AUTH-DATA-MODEL.md D18: structural cross-org isolation.
    // The token is scoped to exactly one org (claims.org). A request that names a different
    // org in the path sees a 404 — not a 403 — because the resource is invisible rather
    // than forbidden. This runs after auth so the error doesn't leak which org the token
    // belongs to via a timing side-channel.
    if (params.org && params.org !== claims.org) throw notFound();

    // Step 7: return the caller context. Use membership.role, NOT claims.role, so that a
    // role change is reflected immediately on the next request rather than at token expiry.
    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
