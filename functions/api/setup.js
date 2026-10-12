// إنشاء أول حساب إدارة مرة واحدة فقط (يعمل فقط إذا لا يوجد أي مستخدم)
import { json, err, hashPassword } from '../_lib.js';

export async function onRequestPost({ request, env }) {
  if (!env.SETUP_TOKEN) return err('غير مفعّل', 404);
  const c = await env.DB.prepare('SELECT COUNT(*) c FROM users').first();
  if (c.c > 0) return err('تم الإعداد مسبقاً', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  if (b.token !== env.SETUP_TOKEN) return err('رمز غير صحيح', 403);
  const username = String(b.username || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (!username || password.length < 10) return err('اسم المستخدم مطلوب وكلمة المرور 10 أحرف على الأقل');
  await env.DB.prepare(
    'INSERT INTO users(username,name,role,pass_hash,must_change,created_at) VALUES(?,?,?,?,0,?)'
  ).bind(username, String(b.name || 'مدير النظام'), 'admin', await hashPassword(password), Date.now()).run();
  return json({ ok: true });
}
