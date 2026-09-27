// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever
// INSERTs. Two things the spec is explicit about (BRIEF.md §4, PERMISSIONS.md §8):
//
//   - DENIED attempts are recorded, not just successes. A log that only holds
//     successes cannot answer "who tried to change what".
//   - a single action produces a single row. Write the success row inside the same
//     transaction as the change it describes; do not also log the allow from a wrapper.
//
// Schema columns: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
// result ('allow'|'deny'), reason_code, request_id, at.

import { newId, nowIso } from './db.js';

export function audit(db, { orgId, actorId = null, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  db.prepare(
    `INSERT INTO audit_events
       (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId('aud'), orgId, actorId, action, targetType, targetId,
    result, reasonCode, requestId, nowIso()
  );
}

// Run fn(); if it refuses with a permission error, record the denial before rethrowing.
// Denials ONLY — the caller writes its own success row inside the same transaction as
// the change it describes, so writing one here as well would double-log every allowed
// action. All other error types pass through without an audit write.
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err?.code === 'FORBIDDEN') {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        result: 'deny',
        reasonCode: err.reason ?? 'missing_permission',
        requestId: ctx.requestId,
        ...meta,
      });
    }
    throw err;
  }
}
