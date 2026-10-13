import { json, err, can, CATEGORIES, GENDERS, CAMPUSES } from '../../_lib.js';

export async function onRequestGet({ request, env, data }) {
  const u = data.user;
  const q = (new URL(request.url).searchParams.get('q') || '').trim();
  const where = [], vals = [];
  if (!can(u, 'research:view_all')) { where.push('r.owner_id=?'); vals.push(u.id); }
  if (q) { where.push('(r.title LIKE ? OR r.students LIKE ? OR r.supervisor LIKE ? OR CAST(r.year AS TEXT) LIKE ?)'); vals.push(...Array(4).fill(`%${q}%`)); }
  const sql = `SELECT r.id,r.title,r.students,r.supervisor,r.year,r.status,r.grade,r.category,r.gender,r.campus,
    (SELECT COUNT(*) FROM files f WHERE f.research_id=r.id) AS files
    FROM researches r ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY r.id DESC LIMIT 500`;
  return json({ researches: (await env.DB.prepare(sql).bind(...vals).all()).results });
}

export async function onRequestPost({ request, env, data }) {
  const u = data.user;
  if (!can(u, 'research:create_own') && !can(u, 'research:create_any')) return err('غير مصرّح', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const title = String(b.title || '').trim(), students = String(b.students || '').trim();
  const supervisor = String(b.supervisor || '').trim(), abstract = String(b.abstract || '').trim();
  const category = String(b.category || '');
  const year = Number(b.year);
  if (!title || !students || !supervisor || !abstract) return err('أكمل جميع الحقول');
  if (title.length > 300 || abstract.length > 3000) return err('النص أطول من المسموح');
  if (!(year >= 2000 && year <= 2100)) return err('السنة غير صحيحة');
  if (!CATEGORIES.includes(category)) return err('اختر تصنيف البحث');
  const sup = await env.DB.prepare('SELECT 1 FROM supervisors WHERE name=? AND active=1').bind(supervisor).first();
  if (!sup) return err('اختر المشرف الأكاديمي من القائمة');

  // الطالب يرفع لنفسه دائماً، والموظف يستطيع الرفع باسم طالب
  let owner = u;
  if (u.role !== 'student') {
    if (!b.ownerUsername) return err('حدد الرقم الجامعي للطالب صاحب البحث');
    owner = await env.DB.prepare("SELECT id,gender,campus FROM users WHERE username=? AND role='student' AND active=1")
      .bind(String(b.ownerUsername).trim().toLowerCase()).first();
    if (!owner) return err('الطالب غير موجود');
  }
  // التصنيف ومكان الدراسة يؤخذان من حساب الطالب، وإن لم يوجدا فمن النموذج
  const gender = owner.gender || String(b.gender || '');
  const campus = owner.campus || String(b.campus || '');
  if (!GENDERS.includes(gender)) return err('حدد التصنيف: طلاب أو طالبات');
  if (!CAMPUSES.includes(campus)) return err('حدد مكان الدراسة');

  const now = Date.now();
  const r = await env.DB.prepare(
    'INSERT INTO researches(owner_id,title,students,supervisor,year,abstract,category,gender,campus,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(owner.id, title, students, supervisor, year, abstract, category, gender, campus, now, now).run();
  return json({ id: r.meta.last_row_id }, 201);
}
