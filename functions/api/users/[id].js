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
    if (b.action === 'activate' && t.role === 'staff') {
      await env.DB.prepare('UPDATE supervisors SET active=1 WHERE name=(SELECT name FROM users WHERE id=?)').bind(t.id).run();
    }
    await audit(env, u.id, 'user:' + b.action, t.id);
    return json({ ok: true });
  }
  return err('إجراء غير معروف');
}

export async function onRequestDelete({ env, data, params }) {
  const u = data.user;
  const isRootAdmin = u?.role === 'admin' && u?.username === 'admin';
  const isCollegeAdmin = u?.role === 'admin' && can(u, 'users:manage') && !isRootAdmin;
  const isSupervisor = u?.role === 'staff' && can(u, 'users:create_student');
  if (!isRootAdmin && !isCollegeAdmin && !isSupervisor) return err('غير مصرّح بحذف الحسابات', 403);

  const t = await env.DB.prepare('SELECT id,username,name,role,active FROM users WHERE id=?').bind(params.id).first();
  if (!t) return err('الحساب غير موجود', 404);
  if (String(t.id) === String(u.id)) return err('لا يمكنك حذف الحساب الذي تستخدمه حالياً');
  if (!t.active) return json({ ok: true, preserved: true, message: 'الحساب موقوف مسبقاً، والسجلات محفوظة.' });

  if (isSupervisor) {
    if (t.role !== 'student') return err('يمكن للمشرف حذف حسابات الطلاب فقط', 403);
    const assigned = await env.DB.prepare(
      'SELECT 1 FROM researches WHERE owner_id=? AND supervisor=? LIMIT 1'
    ).bind(t.id, u.name).first();
    if (!assigned) return err('هذا الطالب ليس ضمن مجموعة أبحاثك', 403);
  } else if (isCollegeAdmin) {
    if (t.role === 'student') {
      // إدارة الكلية تستطيع إيقاف حساب الطالب مع الإبقاء على سجله البحثي.
    } else if (t.role === 'staff') {
      // إدارة الكلية تستطيع إيقاف أي حساب مشرف، حتى لو كان سجل المشرف الأكاديمي غير مكتمل.
    } else {
      return err('إدارة الكلية تستطيع حذف حسابات الطلاب والمشرفين فقط', 403);
    }
  }

  // الحذف منطقي: تعطيل الدخول فقط حتى تبقى الأبحاث والملفات مرتبطة بمعرّف المالك نفسه.
  const batch = [
    env.DB.prepare('UPDATE users SET active=0 WHERE id=?').bind(t.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(t.id),
  ];
  if (t.role === 'staff') {
    batch.push(env.DB.prepare('UPDATE supervisors SET active=0 WHERE name=?').bind(t.name));
  }
  await env.DB.batch(batch);
  await audit(env, u.id, 'user:delete_preserve_records', t.id);
  return json({
    ok: true,
    preserved: true,
    message: 'تم حذف الحساب من الحسابات الفعّالة مع الاحتفاظ بالأبحاث والملفات. يمكن استعادته عند إعادة التسجيل بنفس اسم المستخدم.'
  });
}
