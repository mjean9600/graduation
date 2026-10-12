import { json, err, hashPassword, verifyPassword } from '../_lib.js';

export async function onRequestPost({ request, env, data }) {
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const np = String(b.newPassword || '');
  if (np.length < 8) return err('كلمة المرور الجديدة 8 أحرف على الأقل');
  const row = await env.DB.prepare('SELECT pass_hash FROM users WHERE id=?').bind(data.user.id).first();
  if (!(await verifyPassword(String(b.oldPassword || ''), row.pass_hash))) return err('كلمة المرور الحالية غير صحيحة', 401);
  if (np === b.oldPassword) return err('اختر كلمة مرور مختلفة عن الحالية');
  await env.DB.prepare('UPDATE users SET pass_hash=?, must_change=0 WHERE id=?')
    .bind(await hashPassword(np), data.user.id).run();
  return json({ ok: true });
}
