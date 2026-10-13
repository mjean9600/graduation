import { json, err, can, audit } from '../../_lib.js';

export async function onRequestDelete({ env, data, params }) {
  const u = data.user;
  if (!can(u, 'library:manage')) return err('غير مصرّح', 403);
  const row = await env.DB.prepare('SELECT id,file_key FROM library WHERE id=?').bind(params.id).first();
  if (!row) return err('غير موجود', 404);
  await env.FILES.delete(row.file_key);
  await env.DB.prepare('DELETE FROM library WHERE id=?').bind(row.id).run();
  await audit(env, u.id, 'library:delete', row.id);
  return json({ ok: true });
}
