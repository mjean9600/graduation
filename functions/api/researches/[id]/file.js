import { json, err, can, getResearch, randomToken, audit, STUDENT_EDITABLE } from '../../../_lib.js';

const MAX = 25 * 1024 * 1024;
const SIGS = { pdf: [0x25, 0x50, 0x44, 0x46], docx: [0x50, 0x4b, 3, 4], doc: [0xd0, 0xcf, 0x11, 0xe0] };
const TYPES = {
  pdf: 'application/pdf', doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
};

// رفع نسخة جديدة (الطالب لبحثه، الموظف لأي بحث). النسخ القديمة تبقى محفوظة.
export async function onRequestPost({ request, env, data, params }) {
  const u = data.user;
  const r = await getResearch(env, params.id, u);
  if (!r) return err('غير موجود', 404);
  const ok = u.role === 'student'
    ? can(u, 'research:upload_own') && STUDENT_EDITABLE.includes(r.status)
    : can(u, 'research:upload_any');
  if (!ok) return err('لا يمكن رفع ملف لهذا البحث في حالته الحالية', 403);

  let f; try { f = (await request.formData()).get('file'); } catch { return err('طلب غير صالح'); }
  if (!f || typeof f === 'string') return err('اختر ملفاً');
  if (f.size === 0 || f.size > MAX) return err('حجم الملف يجب أن يكون أقل من 25 ميغابايت');
  const ext = (f.name.split('.').pop() || '').toLowerCase();
  if (!SIGS[ext]) return err('الأنواع المسموحة: PDF أو Word');
  const head = new Uint8Array(await f.slice(0, 4).arrayBuffer());
  if (!SIGS[ext].every((b, i) => head[i] === b)) return err('محتوى الملف لا يطابق نوعه');

  const v = (await env.DB.prepare('SELECT COALESCE(MAX(version),0)+1 AS v FROM files WHERE research_id=?').bind(r.id).first()).v;
  const key = `researches/${r.id}/v${v}-${randomToken(8)}.${ext}`;
  await env.BUCKET.put(key, await f.arrayBuffer(), { httpMetadata: { contentType: TYPES[ext] } });
  await env.DB.prepare('INSERT INTO files(research_id,version,r2_key,original_name,size,uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?)')
    .bind(r.id, v, key, f.name.slice(0, 200), f.size, u.id, Date.now()).run();
  // إذا كان البحث "يحتاج إلى تعديل" وأعاد الطالب رفعه ينتقل لـ "قيد المراجعة"
  const next = u.role === 'student' && r.status === 'يحتاج إلى تعديل' ? 'قيد المراجعة' : r.status;
  await env.DB.prepare('UPDATE researches SET status=?, updated_at=? WHERE id=?').bind(next, Date.now(), r.id).run();
  await audit(env, u.id, 'file:upload', `${r.id} v${v}`);
  return json({ version: v }, 201);
}

// التنزيل لإدارة الكلية فقط، ويُسجَّل في سجل التدقيق. ?v=رقم النسخة (الافتراضي الأحدث)
export async function onRequestGet({ request, env, data, params }) {
  const u = data.user;
  if (!can(u, 'file:download')) return err('التنزيل لإدارة الكلية فقط', 403);
  const r = await getResearch(env, params.id, u);
  if (!r) return err('غير موجود', 404);
  const v = new URL(request.url).searchParams.get('v');
  const row = v
    ? await env.DB.prepare('SELECT * FROM files WHERE research_id=? AND version=?').bind(r.id, Number(v)).first()
    : await env.DB.prepare('SELECT * FROM files WHERE research_id=? ORDER BY version DESC LIMIT 1').bind(r.id).first();
  if (!row) return err('لا يوجد ملف', 404);
  const obj = await env.BUCKET.get(row.r2_key);
  if (!obj) return err('الملف غير موجود في التخزين', 404);
  await audit(env, u.id, 'file:download', `${r.id} v${row.version}`);
  return new Response(obj.body, { headers: {
    'content-type': obj.httpMetadata?.contentType || 'application/octet-stream',
    'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent(row.original_name)}`,
    'x-content-type-options': 'nosniff', 'cache-control': 'private, no-store',
  } });
}
