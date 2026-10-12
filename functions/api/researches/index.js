import { json, err, can } from '../../_lib.js';

export async function onRequestGet({ request, env, data }) {
  const u = data.user;
  const q = (new URL(request.url).searchParams.get('q') || '').trim();
  const where = [], vals = [];
  if (!can(u, 'research:view_all')) { where.push('r.owner_id=?'); vals.push(u.id); }
  if (q) { where.push('(r.title LIKE ? OR r.students LIKE ? OR r.supervisor LIKE ? OR CAST(r.year AS TEXT) LIKE ?)'); vals.push(...Array(4).fill(`%${q}%`)); }
  const sql = `SELECT r.id,r.title,r.students,r.supervisor,r.year,r.status,r.grade,
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
  const year = Number(b.year);
  if (!title || !students || !supervisor || !abstract) return err('أكمل جميع الحقول');
  if (title.length > 300 || abstract.length > 3000) return err('النص أطول من المسموح');
  if (!(year >= 2000 && year <= 2100)) return err('السنة غير صحيحة');

  let owner = u.id; // الطالب يرفع لنفسه دائماً، والموظف يستطيع الرفع باسم طالب
  if (u.role !== 'student' && b.ownerUsername) {
    const o = await env.DB.prepare("SELECT id FROM users WHERE username=? AND role='student' AND active=1")
      .bind(String(b.ownerUsername).trim().toLowerCase()).first();
    if (!o) return err('الطالب غير موجود');
    owner = o.id;
  } else if (u.role !== 'student') return err('حدد الرقم الجامعي للطالب صاحب البحث');

  const now = Date.now();
  const r = await env.DB.prepare(
    'INSERT INTO researches(owner_id,title,students,supervisor,year,abstract,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)'
  ).bind(owner, title, students, supervisor, year, abstract, now, now).run();
  return json({ id: r.meta.last_row_id }, 201);
}
