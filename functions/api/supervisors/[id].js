import { json, err, can, audit } from '../../_lib.js';

// {action:'deactivate'|'activate'} — الإيقاف يخفيه من القوائم والأبحاث القديمة تحتفظ بالاسم
export async function onRequestPatch({ request, env, data, params }) {
  const u = data.user;
  if (!can(u, 'supervisors:manage')) return err('غير مصرّح', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  if (!['activate', 'deactivate'].includes(b.action)) return err('إجراء غير معروف');
  const r = await env.DB.prepare('UPDATE supervisors SET active=? WHERE id=?').bind(b.action === 'activate' ? 1 : 0, params.id).run();
  if (!r.meta.changes) return err('غير موجود', 404);
  await audit(env, u.id, 'supervisor:' + b.action, params.id);
  return json({ ok: true });
}

// حذف مشرف نهائياً من القائمة (الأبحاث السابقة تحتفظ باسمه نصاً) — للإدارة فقط
export async function onRequestDelete({ env, data, params }) {
  const u = data.user;
  if (!can(u, 'supervisors:manage')) return err('غير مصرّح', 403);
  const r = await env.DB.prepare('DELETE FROM supervisors WHERE id=?').bind(params.id).run();
  if (!r.meta.changes) return err('غير موجود', 404);
  await audit(env, u.id, 'supervisor:delete', params.id);
  return json({ ok: true });
}
