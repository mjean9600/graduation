import { json, err, can, hashPassword, genPassword, audit, GENDERS, CAMPUSES } from '../../_lib.js';

const ROLES = ['student', 'staff', 'admin'];

export async function onRequestGet({ env, data }) {
  if (!can(data.user, 'users:create_student')) return err('غير مصرّح', 403);
  const cols = 'id,username,name,role,active,must_change,gender,campus';
  const u = data.user;
  if (can(u, 'users:manage')) {
    const q = `SELECT ${cols} FROM users ORDER BY id DESC`;
    return json({ users: (await env.DB.prepare(q).all()).results });
  }
  const q = `SELECT ${cols},
    EXISTS(SELECT 1 FROM researches r WHERE r.owner_id=users.id AND r.supervisor=?) AS assigned_to_me
    FROM users WHERE role='student' ORDER BY id DESC`;
  return json({ users: (await env.DB.prepare(q).bind(u.name).all()).results });
}

// {users:[{username,name,role?}], gender, campus} — الطلاب يحتاجون التصنيف ومكان الدراسة
export async function onRequestPost({ request, env, data }) {
  const u = data.user;
  if (!can(u, 'users:create_student')) return err('غير مصرّح', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const list = Array.isArray(b.users) ? b.users : [b];
  if (!list.length || list.length > 500) return err('أرسل من 1 إلى 500 حساب');

  const created = [], skipped = [];
  for (const x of list) {
    const username = String(x.username || '').trim().toLowerCase();
    const name = String(x.name || '').trim();
    const role = x.role || 'student';
    let gender = x.gender || b.gender || null, campus = x.campus || b.campus || null;
    if (!username || !name || !ROLES.includes(role)) { skipped.push({ username, reason: 'بيانات ناقصة' }); continue; }
    if (role !== 'student' && !can(u, 'users:manage')) { skipped.push({ username, reason: 'غير مصرّح بهذا الدور' }); continue; }
    if (role === 'student') {
      if (!GENDERS.includes(gender) || !CAMPUSES.includes(campus)) { skipped.push({ username, reason: 'حدد التصنيف ومكان الدراسة' }); continue; }
    } else { gender = null; campus = null; }
    const pw = genPassword();
    const existing = await env.DB.prepare('SELECT id,role,active FROM users WHERE username=?').bind(username).first();
    if (existing) {
      if (existing.active || existing.role !== 'student' || role !== 'student') {
        skipped.push({ username, reason: existing.active ? 'اسم المستخدم موجود وفعّال' : 'يوجد حساب سابق بهذا الاسم ليس حساب طالب قابلاً للاستعادة' });
        continue;
      }
      // استعادة الحساب السابق بدل إنشاء طالب مكرر، مع الاحتفاظ بمعرّف المالك والأبحاث والملفات.
      await env.DB.batch([
        env.DB.prepare('UPDATE users SET name=?,pass_hash=?,must_change=1,active=1,gender=?,campus=? WHERE id=?')
          .bind(name, await hashPassword(pw), gender, campus, existing.id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(existing.id),
      ]);
      created.push({ username, name, role, tempPassword: pw, restored: true });
      continue;
    }
    try {
      await env.DB.prepare('INSERT INTO users(username,name,role,pass_hash,must_change,gender,campus,created_at) VALUES(?,?,?,?,1,?,?,?)')
        .bind(username, name, role, await hashPassword(pw), gender, campus, Date.now()).run();
      created.push({ username, name, role, tempPassword: pw, restored: false });
    } catch { skipped.push({ username, reason: 'تعذر إنشاء الحساب' }); }
  }
  await audit(env, u.id, 'users:create', `${created.length} accounts`);
  return json({ created, skipped });
}
