import { err, FILE_TYPES } from '../../../_lib.js';

// التحميل متاح لكل مستخدم مسجّل. ?inline=1 يعرض ملف PDF داخل الصفحة (لدليل البحث)
export async function onRequestGet({ request, env, params }) {
  const row = await env.DB.prepare('SELECT * FROM library WHERE id=?').bind(params.id).first();
  if (!row) return err('غير موجود', 404);
  const obj = await env.FILES.get(row.file_key, { type: 'stream' });
  if (!obj) return err('الملف غير موجود في التخزين', 404);
  const ext = (row.original_name.split('.').pop() || '').toLowerCase();
  const inline = new URL(request.url).searchParams.get('inline') === '1' && ext === 'pdf';
  return new Response(obj, { headers: {
    'content-type': FILE_TYPES[ext] || 'application/octet-stream',
    'content-disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(row.original_name)}`,
    'x-content-type-options': 'nosniff', 'cache-control': 'private, no-store',
  } });
}
