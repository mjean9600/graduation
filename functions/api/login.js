import { json, err, verifyPassword, randomToken, sha256 } from '../_lib.js';

export async function onRequestPost({ request, env }) {
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const username = String(b.username || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (!username || !password) return err('أدخل اسم المستخدم وكلمة المرور');

  // قفل مؤقت بعد 5 محاولات فاشلة خلال 15 دقيقة
  const since = Date.now() - 15 * 60 * 1000;
  const f = await env.DB.prepare('SELECT COUNT(*) c FROM login_attempts WHERE username=? AND at>?')
    .bind(username, since).first();
  if (f.c >= 5) return err('محاولات كثيرة. حاول بعد 15 دقيقة', 429);

  const u = await env.DB.prepare('SELECT * FROM users WHERE username=? AND active=1').bind(username).first();
  const ok = u && (await verifyPassword(password, u.pass_hash));
  if (!ok) {
    await env.DB.prepare('INSERT INTO login_attempts(username,at) VALUES(?,?)').bind(username, Date.now()).run();
    return err('بيانات الدخول غير صحيحة', 401);
  }
  await env.DB.prepare('DELETE FROM login_attempts WHERE username=?').bind(username).run();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at<?').bind(Date.now()).run();

  const token = randomToken();
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)')
    .bind(await sha256(token), u.id, Date.now() + 8 * 3600 * 1000).run();
  return json(
    { user: { name: u.name, role: u.role, mustChange: !!u.must_change } }, 200,
    { 'set-cookie': `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800` });
}
