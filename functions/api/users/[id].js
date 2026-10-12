import { json, err, can, hashPassword, genPassword, audit } from '../../_lib.js';

// body: {action:'reset'|'deactivate'|'activate'}
export async function onRequestPatch({ request, env, data, params }) {
  const u = data.user;
  if (!can(u, 'users:create_student')) return err('غير مصرّح', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const t = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(params.id).first();
  if (!t) return err('غير موجود', 404);
  if (t.role !== 'student' && !can(u, 'users:manage')) return err('غير مصرّح', 403);
  if (t.id === u.id && b.action === 'deactivate') return err('لا يمكنك إيقاف حسابك');

  if (b.action === 'reset') {
    const pw = genPassword();
    await env.DB.prepare('UPDATE users SET pass_hash=?, must_change=1 WHERE id=?').bind(await hashPassword(pw), t.id).run();
    await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(t.id).run();
    await audit(env, u.id, 'user:reset', t.id);
    return json({ tempPassword: pw });
  }
  if (b.action === 'deactivate' || b.action === 'activate') {
    await env.DB.prepare('UPDATE users SET active=? WHERE id=?').bind(b.action === 'activate' ? 1 : 0, t.id).run();
    if (b.action === 'deactivate') await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(t.id).run();
    await audit(env, u.id, 'user:' + b.action, t.id);
    return json({ ok: true });
  }
  return err('إجراء غير معروف');
}
