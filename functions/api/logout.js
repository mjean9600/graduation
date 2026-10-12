import { json, sha256 } from '../_lib.js';

export async function onRequestPost({ request, env }) {
  const m = (request.headers.get('cookie') || '').match(/(?:^|; )sid=([a-f0-9]+)/);
  if (m) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(m[1])).run();
  return json({ ok: true }, 200, { 'set-cookie': 'sid=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
}
