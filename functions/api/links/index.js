import { json, err, can, audit } from '../../_lib.js';

export async function onRequestGet({ env, data }) {
  const rows = (await env.DB.prepare('SELECT id,title,url,description FROM links ORDER BY id DESC').all()).results;
  return json({ links: rows, canManage: can(data.user, 'links:manage') });
}

// {title,url,description} — للمشرف والإدارة. الرابط يجب أن يبدأ بـ http أو https
export async function onRequestPost({ request, env, data }) {
  const u = data.user;
  if (!can(u, 'links:manage')) return err('غير مصرّح', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const title = String(b.title || '').trim(), description = String(b.description || '').trim();
  let url = String(b.url || '').trim();
  if (!title || title.length > 200) return err('أدخل عنوان الرابط (حتى 200 حرف)');
  if (description.length > 1000) return err('المعلومات أطول من المسموح');
  try { const x = new URL(url); if (!['http:', 'https:'].includes(x.protocol)) throw 0; url = x.href; }
  catch { return err('الرابط غير صحيح. يجب أن يبدأ بـ https://'); }
  if (url.length > 500) return err('الرابط طويل جداً');
  const r = await env.DB.prepare('INSERT INTO links(title,url,description,created_at) VALUES(?,?,?,?)')
    .bind(title, url, description, Date.now()).run();
  await audit(env, u.id, 'link:add', r.meta.last_row_id);
  return json({ id: r.meta.last_row_id }, 201);
}
