import { json, err, can, audit } from '../../_lib.js';

// القائمة للجميع (الفعّالون فقط)، والإدارة ترى الكل مع ?all=1
export async function onRequestGet({ request, env, data }) {
  const all = can(data.user, 'supervisors:manage') && new URL(request.url).searchParams.get('all') === '1';
  const q = all
    ? 'SELECT id,name,active FROM supervisors ORDER BY name'
    : 'SELECT id,name,active FROM supervisors WHERE active=1 ORDER BY name';
  return json({ supervisors: (await env.DB.prepare(q).all()).results });
}

// إضافة مشرف أو عدة مشرفين: {names:["..",".."]} أو {name:".."} — للإدارة فقط
export async function onRequestPost({ request, env, data }) {
  const u = data.user;
  if (!can(u, 'supervisors:manage')) return err('إضافة المشرفين من صلاحية الإدارة', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const names = [...new Set((Array.isArray(b.names) ? b.names : [b.name]).map((n) => String(n || '').trim()).filter(Boolean))];
  if (!names.length || names.length > 100) return err('أرسل من 1 إلى 100 اسم');
  if (names.some((n) => n.length > 120)) return err('اسم أطول من المسموح');
  for (const n of names)
    await env.DB.prepare('INSERT INTO supervisors(name) VALUES(?) ON CONFLICT(name) DO UPDATE SET active=1').bind(n).run();
  await audit(env, u.id, 'supervisors:add', `${names.length} names`);
  return json({ added: names.length }, 201);
}
