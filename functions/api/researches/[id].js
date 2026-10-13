import { json, err, can, STATUSES, STUDENT_EDITABLE, CATEGORIES, GENDERS, CAMPUSES, getResearch, audit } from '../../_lib.js';

export async function onRequestGet({ env, data, params }) {
  const r = await getResearch(env, params.id, data.user);
  if (!r) return err('غير موجود', 404);
  const files = (await env.DB.prepare(
    'SELECT version,original_name,size,uploaded_at FROM files WHERE research_id=? ORDER BY version DESC'
  ).bind(r.id).all()).results;
  return json({ research: r, files, canDownload: can(data.user, 'file:download'), canDeleteFile: can(data.user, 'file:delete') });
}

export async function onRequestPatch({ request, env, data, params }) {
  const u = data.user;
  const r = await getResearch(env, params.id, u);
  if (!r) return err('غير موجود', 404);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const set = [], vals = [];

  if (b.status !== undefined) {
    if (!can(u, 'research:update_status')) return err('غير مصرّح بتغيير الحالة', 403);
    if (!STATUSES.includes(b.status)) return err('حالة غير صالحة');
    set.push('status=?'); vals.push(b.status);
  }
  if (b.grade !== undefined) {
    if (!can(u, 'research:grade')) return err('غير مصرّح بالتقييم', 403);
    const g = b.grade === '' || b.grade === null ? null : Number(b.grade);
    if (g !== null && !(g >= 0 && g <= 100)) return err('الدرجة من 0 إلى 100');
    set.push('grade=?'); vals.push(g);
  }
  if (['title', 'abstract', 'category', 'supervisor', 'gender', 'campus'].some((k) => b[k] !== undefined)) {
    const allowed = u.role === 'student' ? STUDENT_EDITABLE.includes(r.status) : can(u, 'research:edit_any');
    if (!allowed) return err('لا يمكن تعديل البحث في حالته الحالية', 403);
    if (b.title !== undefined) { const t = String(b.title).trim(); if (!t || t.length > 300) return err('العنوان غير صالح'); set.push('title=?'); vals.push(t); }
    if (b.abstract !== undefined) { const a = String(b.abstract).trim(); if (!a || a.length > 3000) return err('الملخص غير صالح'); set.push('abstract=?'); vals.push(a); }
    if (b.category !== undefined) { if (!CATEGORIES.includes(b.category)) return err('تصنيف غير صالح'); set.push('category=?'); vals.push(b.category); }
    if (b.supervisor !== undefined) {
      const s = String(b.supervisor).trim();
      if (s !== r.supervisor) {
        const ok = await env.DB.prepare('SELECT 1 FROM supervisors WHERE name=? AND active=1').bind(s).first();
        if (!ok) return err('اختر المشرف الأكاديمي من القائمة');
      }
      set.push('supervisor=?'); vals.push(s);
    }
    if (b.gender !== undefined || b.campus !== undefined) {
      if (!can(u, 'research:edit_any')) return err('غير مصرّح', 403);
      if (b.gender !== undefined) { if (!GENDERS.includes(b.gender)) return err('تصنيف الطلاب غير صالح'); set.push('gender=?'); vals.push(b.gender); }
      if (b.campus !== undefined) { if (!CAMPUSES.includes(b.campus)) return err('مكان الدراسة غير صالح'); set.push('campus=?'); vals.push(b.campus); }
    }
  }
  if (!set.length) return err('لا تغييرات');
  set.push('updated_at=?'); vals.push(Date.now());
  await env.DB.prepare(`UPDATE researches SET ${set.join(',')} WHERE id=?`).bind(...vals, r.id).run();
  await audit(env, u.id, 'research:update', r.id);
  return json({ ok: true });
}

// حذف بحث كاملاً مع كل نسخ ملفاته: للموظف والإدارة فقط، ويُسجَّل في سجل التدقيق
export async function onRequestDelete({ env, data, params }) {
  const u = data.user;
  if (!can(u, 'research:delete')) return err('غير مصرّح بحذف الأبحاث', 403);
  const r = await getResearch(env, params.id, u);
  if (!r) return err('غير موجود', 404);
  const files = (await env.DB.prepare('SELECT r2_key FROM files WHERE research_id=?').bind(r.id).all()).results;
  for (const f of files) await env.FILES.delete(f.r2_key);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM files WHERE research_id=?').bind(r.id),
    env.DB.prepare('DELETE FROM researches WHERE id=?').bind(r.id),
  ]);
  await audit(env, u.id, 'research:delete', `${r.id} ${String(r.title).slice(0, 60)}`);
  return json({ ok: true });
}
