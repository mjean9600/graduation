// أدوات مشتركة + مصفوفة الصلاحيات
const enc = new TextEncoder();

// ===== مصفوفة الصلاحيات: عدّلها هنا فقط =====
export const PERMS = {
  student: ['research:create_own', 'research:upload_own'],
  staff: [
    'research:view_all', 'research:create_any', 'research:edit_any',
    'research:update_status', 'research:grade', 'research:upload_any',
    'users:create_student',
  ],
  admin: [
    'research:view_all', 'research:create_any', 'research:edit_any',
    'research:update_status', 'research:grade', 'research:upload_any',
    'users:create_student', 'users:manage', 'file:download',
  ],
};
export const can = (u, p) => !!u && (PERMS[u.role] || []).includes(p);

export const STATUSES = ['جديد', 'قيد المراجعة', 'يحتاج إلى تعديل', 'معتمد', 'مؤرشف'];
export const STUDENT_EDITABLE = ['جديد', 'يحتاج إلى تعديل'];

export const json = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...h },
  });
export const err = (m, s = 400) => json({ error: m }, s);

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const same = (a, b) => {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
};

export async function hashPassword(pw, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
  return b64(salt) + ':' + b64(bits);
}
export async function verifyPassword(pw, stored) {
  const h = await hashPassword(pw, unb64(stored.split(':')[0]));
  return same(h, stored);
}
export async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export const randomToken = (n = 32) =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
export function genPassword() {
  const a = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(10)), (b) => a[b % a.length]).join('');
}

// الطالب لا يرى إلا بحثه، وأي بحث آخر يظهر له "غير موجود"
export async function getResearch(env, id, user) {
  const r = await env.DB.prepare('SELECT * FROM researches WHERE id=?').bind(id).first();
  if (!r) return null;
  if (user.role === 'student' && r.owner_id !== user.id) return null;
  return r;
}
export const audit = (env, userId, action, target) =>
  env.DB.prepare('INSERT INTO audit(user_id,action,target,at) VALUES(?,?,?,?)')
    .bind(userId, action, String(target ?? ''), Date.now()).run();
