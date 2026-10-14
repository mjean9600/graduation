import { json, err, can, audit, hashPassword, genPassword } from '../../_lib.js';

// القائمة للجميع (الفعّالون فقط)، والإدارة ترى الكل مع ?all=1
export async function onRequestGet({ request, env, data }) {
  const all = can(data.user, 'supervisors:manage') && new URL(request.url).searchParams.get('all') === '1';
  const q = all
    ? 'SELECT id,name,active FROM supervisors ORDER BY name'
    : 'SELECT id,name,active FROM supervisors WHERE active=1 ORDER BY name';
  return json({ supervisors: (await env.DB.prepare(q).all()).results });
}

// كل سطر: اسم المستخدم ثم الاسم الكامل. يُنشأ حساب موظف وكلمة مؤقتة تلقائياً.
export async function onRequestPost({ request, env, data }) {
  const u = data.user;
  if (!can(u, 'supervisors:manage') || u.role !== 'admin') return err('إضافة المشرفين من صلاحية إدارة الكلية فقط', 403);
  let b; try { b = await request.json(); } catch { return err('بيانات غير صالحة'); }
  const items = (Array.isArray(b.supervisors) ? b.supervisors : []).map((x) => ({
    username: String(x.username || '').trim().toLowerCase(),
    name: String(x.name || '').trim(),
  })).filter((x) => x.username && x.name);
  if (!items.length || items.length > 100) return err('أرسل من 1 إلى 100 مشرف مع اسم مستخدم واسم كامل');
  if (items.some((x) => !/^[a-z0-9._-]{3,40}$/.test(x.username) || x.name.length > 120))
    return err('اسم المستخدم يجب أن يكون بالإنجليزية من 3 إلى 40 حرفاً، والاسم الكامل حتى 120 حرفاً');
  if (new Set(items.map((x) => x.username)).size !== items.length) return err('توجد أسماء مستخدمين مكررة في القائمة');

  const created = [], skipped = [];
  for (const x of items) {
    try {
      const password = genPassword();
      const result = await env.DB.prepare('INSERT INTO users(username,name,role,pass_hash,must_change,created_at) VALUES(?,?,?,?,1,?)')
        .bind(x.username, x.name, 'staff', await hashPassword(password), Date.now()).run();
      await env.DB.prepare('INSERT INTO supervisors(name,active) VALUES(?,1) ON CONFLICT(name) DO UPDATE SET active=1').bind(x.name).run();
      created.push({ username: x.username, name: x.name, tempPassword: password });
    } catch {
      skipped.push({ username: x.username, name: x.name, reason: 'اسم المستخدم موجود أو تعذّر إنشاء الحساب' });
    }
  }
  await audit(env, u.id, 'supervisors:add_accounts', created.map((x) => x.username).join(','));
  return json({ created, skipped, added: created.length }, created.length ? 201 : 409);
}
