import { json, err, can, audit } from '../../_lib.js';

export async function onRequestDelete({ env, data, params }) {
  const u = data.user;
  if (!can(u, 'links:manage')) return err('غير مصرّح', 403);
  const r = await env.DB.prepare('DELETE FROM links WHERE id=?').bind(params.id).run();
  if (!r.meta.changes) return err('غير موجود', 404);
  await audit(env, u.id, 'link:delete', params.id);
  return json({ ok: true });
}
