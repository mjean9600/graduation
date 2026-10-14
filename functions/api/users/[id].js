import { json, err, can, hashPassword, genPassword, audit } from '../../_lib.js';

// إدارة الحسابات: الإيقاف وإعادة التعيين متاحان وفق الدور، والحذف للإدارة فقط.
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

export async function onRequestDelete({ env, data, params }) {
  const u = data.user;
  const isRootAdmin = u?.role === 'admin' && u?.username === 'admin';
  const isCollegeAdmin = u?.role === 'admin' && can(u, 'users:manage') && !isRootAdmin;
  if (!isRootAdmin && !isCollegeAdmin) return err('غير مصرّح بحذف الحسابات', 403);

  const t = await env.DB.prepare('SELECT id,username,name,role FROM users WHERE id=?').bind(params.id).first();
  if (!t) return err('الحساب غير موجود', 404);
  if (String(t.id) === String(u.id)) return err('لا يمكنك حذف الحساب الذي تستخدمه حالياً');

  if (!isRootAdmin) {
    if (t.role !== 'staff') return err('إدارة الكلية تستطيع حذف حسابات المشرفين الأكاديميين فقط', 403);
    const supervisor = await env.DB.prepare('SELECT id FROM supervisors WHERE name=? LIMIT 1').bind(t.name).first();
    if (!supervisor) return err('هذا الحساب ليس مرتبطاً بمشرف أكاديمي', 403);
  }

  const owned = await env.DB.prepare('SELECT COUNT(*) AS n FROM researches WHERE owner_id=?').bind(t.id).first();
  const uploaded = await env.DB.prepare('SELECT COUNT(*) AS n FROM files WHERE uploaded_by=?').bind(t.id).first();
  const library = await env.DB.prepare('SELECT COUNT(*) AS n FROM library WHERE uploaded_by=?').bind(t.id).first();
  if (owned.n || uploaded.n || library.n)
    return err('هذا الحساب مرتبط بأبحاث أو ملفات محفوظة؛ أوقفه بدلاً من حذفه حتى لا تضيع السجلات.');

  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(t.id),
    env.DB.prepare('DELETE FROM users WHERE id=?').bind(t.id),
  ]);
  await audit(env, u.id, 'user:delete', t.id);
  return json({ ok: true });
}
