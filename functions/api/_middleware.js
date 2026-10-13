import { err, sha256 } from '../_lib.js';

const PUBLIC = ['/api/login', '/api/setup'];
const ALLOWED_WHEN_MUST_CHANGE = ['/api/change-password', '/api/logout', '/api/me'];

export async function onRequest(ctx) {
  const { request, env, next } = ctx;
  const url = new URL(request.url);

  // حماية CSRF: الطلبات المغيّرة يجب أن تأتي من نفس الموقع
  if (!['GET', 'HEAD'].includes(request.method)) {
    const o = request.headers.get('origin');
    if (o && o !== url.origin) return err('طلب مرفوض', 403);
  }
  if (PUBLIC.includes(url.pathname)) return next();

  const m = (request.headers.get('cookie') || '').match(/(?:^|; )sid=([a-f0-9]+)/);
  if (!m) return err('يجب تسجيل الدخول', 401);
  const u = await env.DB.prepare(
    `SELECT u.id,u.username,u.name,u.role,u.must_change,u.gender,u.campus
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`
  ).bind(await sha256(m[1]), Date.now()).first();
  if (!u) return err('انتهت الجلسة. سجّل الدخول من جديد', 401);

  ctx.data.user = u;
  if (u.must_change && !ALLOWED_WHEN_MUST_CHANGE.includes(url.pathname))
    return err('يجب تغيير كلمة المرور أولاً', 403);
  return next();
}
