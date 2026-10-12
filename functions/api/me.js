import { json, PERMS } from '../_lib.js';

export async function onRequestGet({ data }) {
  const u = data.user;
  return json({ name: u.name, username: u.username, role: u.role, mustChange: !!u.must_change, perms: PERMS[u.role] });
}
