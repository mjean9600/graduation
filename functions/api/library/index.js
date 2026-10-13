import { json, err, can, randomToken, audit, LIBRARY_SECTIONS, FILE_SIGS } from '../../_lib.js';

const MAX = 20 * 1024 * 1024;

// القائمة للجميع: ?section=bank|guide|template
export async function onRequestGet({ request, env, data }) {
  const section = new URL(request.url).searchParams.get('section');
  if (!LIBRARY_SECTIONS[section]) return err('قسم غير معروف');
  const items = (await env.DB.prepare(
    'SELECT id,section,title,description,original_name,size,uploaded_at FROM library WHERE section=? ORDER BY id DESC'
  ).bind(section).all()).results;
  return json({ items, canManage: can(data.user, 'library:manage') });
}

// رفع ملف (multipart: section,title,description,file) — للمشرف والإدارة
export async function onRequestPost({ request, env, data }) {
  const u = data.user;
  if (!can(u, 'library:manage')) return err('غير مصرّح', 403);
  let form; try { form = await request.formData(); } catch { return err('طلب غير صالح'); }
  const section = String(form.get('section') || '');
  if (!LIBRARY_SECTIONS[section]) return err('قسم غير معروف');
  const f = form.get('file');
  if (!f || typeof f === 'string') return err('اختر ملفاً');
  if (f.size === 0 || f.size > MAX) return err('حجم الملف يجب أن يكون أقل من 20 ميغابايت');
  const ext = (f.name.split('.').pop() || '').toLowerCase();
  if (!LIBRARY_SECTIONS[section].includes(ext)) return err('نوع الملف غير مسموح في هذا القسم');
  const head = new Uint8Array(await f.slice(0, 4).arrayBuffer());
  if (!FILE_SIGS[ext].every((b, i) => head[i] === b)) return err('محتوى الملف لا يطابق نوعه');
  const title = (String(form.get('title') || '').trim() || f.name.replace(/\.[^.]+$/, '')).slice(0, 200);
  const description = String(form.get('description') || '').trim().slice(0, 1000);

  const key = `library/${section}/${randomToken(8)}.${ext}`;
  await env.FILES.put(key, await f.arrayBuffer());
  const r = await env.DB.prepare(
    'INSERT INTO library(section,title,description,file_key,original_name,size,uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?)'
  ).bind(section, title, description, key, f.name.slice(0, 200), f.size, u.id, Date.now()).run();
  await audit(env, u.id, 'library:upload', `${section} ${r.meta.last_row_id}`);
  return json({ id: r.meta.last_row_id }, 201);
}
