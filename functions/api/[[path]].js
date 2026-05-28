// TT-Training API — Cloudflare Pages Function
// Catch-all: handles all /api/* routes

// ============================================================
// CRYPTO HELPERS
// ============================================================
function uid() {
  return Date.now().toString(36) + crypto.getRandomValues(new Uint8Array(4)).reduce((s, b) => s + b.toString(36).padStart(2, '0'), '');
}

async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return arrayToBase64(salt) + ':' + arrayToBase64(new Uint8Array(bits));
}

async function verifyPassword(password, stored) {
  const [saltB64, hashB64] = stored.split(':');
  const salt = base64ToArray(saltB64);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return arrayToBase64(new Uint8Array(bits)) === hashB64;
}

function arrayToBase64(arr) { return btoa(String.fromCharCode(...arr)); }
function base64ToArray(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }

async function createJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const body = btoa(JSON.stringify({ ...payload, exp: Date.now() + 24 * 3600 * 1000 })).replace(/=/g, '');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  return `${header}.${body}.${arrayToBase64(new Uint8Array(sig)).replace(/=/g, '')}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigPadded = sig + '='.repeat((4 - sig.length % 4) % 4);
    const valid = await crypto.subtle.verify('HMAC', key, base64ToArray(sigPadded), enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const bodyPadded = body + '='.repeat((4 - body.length % 4) % 4);
    const payload = JSON.parse(atob(bodyPadded));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ============================================================
// RESPONSE HELPERS
// ============================================================
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json' }
  });
}
function err(message, status = 400) { return json({ error: message }, status); }

// ============================================================
// AUTH
// ============================================================
async function authenticate(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const payload = await verifyJWT(auth.slice(7), env.JWT_SECRET);
  if (!payload) return null;
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.userId).first();
  if (!user) return null;
  return { ...user, is_initial_admin: !!user.is_initial_admin, must_change_password: !!user.must_change_password };
}

function requireRole(user, ...roles) {
  if (!user) return err('Nicht angemeldet.', 401);
  if (!roles.includes(user.role)) return err('Keine Berechtigung.', 403);
  return null;
}

async function getSetting(env, vereinId, key, defaultValue) {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE verein_id=? AND key=?').bind(vereinId, key).first();
  return row ? row.value : defaultValue;
}

async function getInitialPasswords(env, vereinId) {
  return {
    spieler: await getSetting(env, vereinId, 'pw_spieler', 'TVB1912'),
    trainer: await getSetting(env, vereinId, 'pw_trainer', 'TVB1912admin'),
  };
}

// ============================================================
// SEED
// ============================================================
async function ensureInitialData(env) {
  const vereinName = env.INITIAL_VEREIN || 'Mein Verein';
  let verein = await env.DB.prepare('SELECT * FROM vereine LIMIT 1').first();
  if (!verein) {
    const vid = uid();
    await env.DB.prepare('INSERT INTO vereine (id, name) VALUES (?, ?)').bind(vid, vereinName).run();
    verein = { id: vid, name: vereinName };
  }
  const admin = await env.DB.prepare('SELECT * FROM users WHERE verein_id = ? AND is_initial_admin = 1').bind(verein.id).first();
  if (!admin) {
    const hash = await hashPassword('TT-Admin');
    await env.DB.prepare(
      'INSERT INTO users (id, verein_id, username, password_hash, role, display_name, is_initial_admin, must_change_password) VALUES (?,?,?,?,?,?,1,0)'
    ).bind(uid(), verein.id, 'TT-Admin', hash, 'admin', 'TT-Admin').run();
  }
  return verein;
}

// ============================================================
// PAGES FUNCTION ENTRY POINT
// ============================================================
export async function onRequest(context) {
  const { request, env, params } = context;
  const method = request.method;
  const path = (params.path || []).join('/');

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    }});
  }

  try {
    const verein = await ensureInitialData(env);
    const user = await authenticate(request, env);

    // --- AUTH ---
    if (path === 'auth/login' && method === 'POST') return handleLogin(request, env, verein);
    if (!user) return err('Nicht angemeldet.', 401);
    if (path === 'auth/change-password' && method === 'POST') return handleChangePassword(request, env, user);
    if (path === 'auth/me' && method === 'GET') return json({ user: sanitizeUser(user) });

    // --- PLAYERS ---
    if (path === 'players' && method === 'GET') return getPlayers(env, user);
    if (path === 'players' && method === 'POST') return savePlayer(request, env, user);
    if (path.startsWith('players/') && method === 'PUT') return updatePlayer(request, env, user, path.split('/')[1]);
    if (path.startsWith('players/') && method === 'DELETE') return deletePlayer(env, user, path.split('/')[1]);

    // --- ASSESSMENTS ---
    if (path === 'assessments' && method === 'GET') {
      const url = new URL(request.url);
      return getAssessments(env, user, url);
    }
    if (path === 'assessments' && method === 'POST') return saveAssessment(request, env, user);
    if (path.startsWith('assessments/') && method === 'PUT') return updateAssessment(request, env, user, path.split('/')[1]);
    if (path.startsWith('assessments/') && method === 'DELETE') return deleteAssessment(env, user, path.split('/')[1]);

    // --- TRAINERS ---
    if (path === 'trainers' && method === 'GET') return getTrainers(env, user);
    if (path === 'trainers' && method === 'POST') return saveTrainer(request, env, user);
    if (path.startsWith('trainers/') && method === 'PUT') return updateTrainer(request, env, user, path.split('/')[1]);
    if (path.startsWith('trainers/') && method === 'DELETE') return deleteTrainer(env, user, path.split('/')[1]);

    // --- LISTS ---
    if (path === 'lists' && method === 'GET') return getLists(env, user);
    if (path === 'lists' && method === 'POST') return addListItem(request, env, user);
    if (path === 'lists' && method === 'DELETE') return removeListItem(request, env, user);

    // --- SETTINGS ---
    if (path === 'settings' && method === 'GET') return getSettings(env, user);
    if (path === 'settings' && method === 'POST') return saveSettings(request, env, user);

    // --- USERS ---
    if (path === 'users' && method === 'GET') return getUsers(env, user);
    if (path.match(/^users\/.+\/reset-password$/) && method === 'POST') return resetPassword(env, user, path.split('/')[1]);

    // --- EXPORT/IMPORT ---
    if (path === 'export' && method === 'GET') return exportData(env, user);
    if (path === 'import' && method === 'POST') return importData(request, env, user);

    return err('Route nicht gefunden.', 404);
  } catch (e) {
    return err('Serverfehler: ' + e.message, 500);
  }
}

// ============================================================
// AUTH HANDLERS
// ============================================================
async function handleLogin(request, env, verein) {
  const { username, password } = await request.json();
  if (!username || !password) return err('Benutzername und Passwort erforderlich.');
  const user = await env.DB.prepare('SELECT * FROM users WHERE verein_id = ? AND LOWER(username) = LOWER(?)').bind(verein.id, username).first();
  if (!user) return err('Benutzername oder Passwort falsch.', 401);
  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) return err('Benutzername oder Passwort falsch.', 401);
  if (user.is_initial_admin) {
    const otherAdmin = await env.DB.prepare('SELECT id FROM users WHERE verein_id = ? AND role = ? AND is_initial_admin = 0').bind(verein.id, 'admin').first();
    if (otherAdmin) return err('TT-Admin-Zugang deaktiviert. Ein anderer Admin existiert.', 403);
  }
  const token = await createJWT({ userId: user.id, vereinId: verein.id, role: user.role }, env.JWT_SECRET);
  return json({ token, user: sanitizeUser(user), mustChangePassword: !!user.must_change_password });
}

async function handleChangePassword(request, env, user) {
  const { newPassword } = await request.json();
  if (!newPassword || newPassword.length < 4) return err('Passwort muss mindestens 4 Zeichen haben.');
  const hash = await hashPassword(newPassword);
  await env.DB.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').bind(hash, user.id).run();
  return json({ ok: true });
}

function sanitizeUser(u) {
  return { id: u.id, username: u.username, role: u.role, displayName: u.display_name, playerId: u.player_id, trainerId: u.trainer_id, isInitialAdmin: !!u.is_initial_admin };
}

// ============================================================
// PLAYERS
// ============================================================
async function getPlayers(env, user) {
  if (user.role === 'spieler') {
    const rows = await env.DB.prepare('SELECT * FROM players WHERE id = ? AND verein_id = ?').bind(user.player_id, user.verein_id).all();
    return json(rows.results.map(mapPlayer));
  }
  return json((await env.DB.prepare('SELECT * FROM players WHERE verein_id = ? ORDER BY name, vorname').bind(user.verein_id).all()).results.map(mapPlayer));
}

function mapPlayer(p) { return { ...p, mannschaft: safeJSON(p.mannschaft, []) }; }
function safeJSON(str, fb) { try { return JSON.parse(str); } catch { return fb; } }

function cleanName(s) { return s.toLowerCase().replace(/ä/g,'ae').replace(/ö/g,'oe').replace(/ü/g,'ue').replace(/ß/g,'ss').replace(/[^a-z0-9]/g,''); }

async function genUsername(env, vereinId, vorname, name) {
  const base = cleanName(vorname) + '.' + cleanName(name);
  let uname = base, i = 2;
  while (true) {
    const exists = await env.DB.prepare('SELECT id FROM users WHERE verein_id = ? AND LOWER(username) = LOWER(?)').bind(vereinId, uname).first();
    if (!exists) return uname;
    uname = base + i; i++;
  }
}

async function savePlayer(request, env, user) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  const data = await request.json();
  if (!data.name || !data.vorname) return err('Name und Vorname sind Pflicht.');
  const id = uid();
  const jahrgang = data.geburtsdatum ? data.geburtsdatum.slice(0, 4) : '';
  await env.DB.prepare(
    'INSERT INTO players (id,verein_id,name,vorname,geburtsdatum,jahrgang,mannschaft,gruppe,hand,trainer,vh_name,vh_typ,rh_name,rh_typ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(id, user.verein_id, data.name, data.vorname, data.geburtsdatum||'', jahrgang,
    JSON.stringify(data.mannschaft||[]), data.gruppe||'', data.hand||'', data.trainer||'',
    data.vhName||'', data.vhTyp||'', data.rhName||'', data.rhTyp||'').run();
  const uname = await genUsername(env, user.verein_id, data.vorname, data.name);
  const pws = await getInitialPasswords(env, user.verein_id);
  const hash = await hashPassword(pws.spieler);
  await env.DB.prepare(
    'INSERT INTO users (id,verein_id,username,password_hash,role,display_name,player_id,must_change_password) VALUES (?,?,?,?,?,?,?,1)'
  ).bind(uid(), user.verein_id, uname, hash, 'spieler', `${data.vorname} ${data.name}`, id).run();
  return json({ ok: true, id, username: uname });
}

async function updatePlayer(request, env, user, playerId) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  const data = await request.json();
  if (!data.name || !data.vorname) return err('Name und Vorname sind Pflicht.');
  const jahrgang = data.geburtsdatum ? data.geburtsdatum.slice(0, 4) : '';
  await env.DB.prepare(
    'UPDATE players SET name=?,vorname=?,geburtsdatum=?,jahrgang=?,mannschaft=?,gruppe=?,hand=?,trainer=?,vh_name=?,vh_typ=?,rh_name=?,rh_typ=? WHERE id=? AND verein_id=?'
  ).bind(data.name, data.vorname, data.geburtsdatum||'', jahrgang,
    JSON.stringify(data.mannschaft||[]), data.gruppe||'', data.hand||'', data.trainer||'',
    data.vhName||'', data.vhTyp||'', data.rhName||'', data.rhTyp||'', playerId, user.verein_id).run();
  await env.DB.prepare('UPDATE users SET display_name=? WHERE player_id=? AND verein_id=?')
    .bind(`${data.vorname} ${data.name}`, playerId, user.verein_id).run();
  return json({ ok: true });
}

async function deletePlayer(env, user, playerId) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  await env.DB.prepare('DELETE FROM assessments WHERE player_id=? AND verein_id=?').bind(playerId, user.verein_id).run();
  await env.DB.prepare('DELETE FROM users WHERE player_id=? AND verein_id=?').bind(playerId, user.verein_id).run();
  await env.DB.prepare('DELETE FROM players WHERE id=? AND verein_id=?').bind(playerId, user.verein_id).run();
  return json({ ok: true });
}

// ============================================================
// ASSESSMENTS
// ============================================================
async function getAssessments(env, user, url) {
  const pid = url.searchParams.get('player_id');
  if (user.role === 'spieler') {
    return json((await env.DB.prepare('SELECT * FROM assessments WHERE player_id=? AND verein_id=? ORDER BY date DESC').bind(user.player_id, user.verein_id).all()).results.map(mapAssessment));
  }
  if (pid) {
    return json((await env.DB.prepare('SELECT * FROM assessments WHERE player_id=? AND verein_id=? ORDER BY date DESC').bind(pid, user.verein_id).all()).results.map(mapAssessment));
  }
  return json((await env.DB.prepare('SELECT * FROM assessments WHERE verein_id=? ORDER BY date DESC').bind(user.verein_id).all()).results.map(mapAssessment));
}

function mapAssessment(a) {
  return { ...a, ratings: safeJSON(a.ratings, {}), staerken: a.staerken||'', nextStep: a.next_step||'', bemerkung: a.bemerkung||'' };
}

async function saveAssessment(request, env, user) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  const data = await request.json();
  if (!data.playerId || !data.date) return err('Spieler und Datum sind Pflicht.');
  const id = uid();
  await env.DB.prepare(
    'INSERT INTO assessments (id,verein_id,player_id,date,trainer,ratings,staerken,next_step,bemerkung) VALUES (?,?,?,?,?,?,?,?,?)'
  ).bind(id, user.verein_id, data.playerId, data.date, data.trainer||'',
    JSON.stringify(data.ratings||{}), data.staerken||'', data.nextStep||'', data.bemerkung||'').run();
  return json({ ok: true, id });
}

async function updateAssessment(request, env, user, aId) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  const data = await request.json();
  await env.DB.prepare(
    'UPDATE assessments SET date=?,trainer=?,ratings=?,staerken=?,next_step=?,bemerkung=? WHERE id=? AND verein_id=?'
  ).bind(data.date, data.trainer||'', JSON.stringify(data.ratings||{}),
    data.staerken||'', data.nextStep||'', data.bemerkung||'', aId, user.verein_id).run();
  return json({ ok: true });
}

async function deleteAssessment(env, user, aId) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  await env.DB.prepare('DELETE FROM assessments WHERE id=? AND verein_id=?').bind(aId, user.verein_id).run();
  return json({ ok: true });
}

// ============================================================
// TRAINERS
// ============================================================
async function getTrainers(env, user) {
  return json((await env.DB.prepare('SELECT * FROM trainers WHERE verein_id=? ORDER BY name,vorname').bind(user.verein_id).all()).results);
}

async function saveTrainer(request, env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const data = await request.json();
  if (!data.name || !data.vorname) return err('Name und Vorname sind Pflicht.');
  const tid = uid();
  await env.DB.prepare('INSERT INTO trainers (id,verein_id,name,vorname,role) VALUES (?,?,?,?,?)')
    .bind(tid, user.verein_id, data.name, data.vorname, data.role||'trainer').run();
  const uname = await genUsername(env, user.verein_id, data.vorname, data.name);
  const pws = await getInitialPasswords(env, user.verein_id);
  const hash = await hashPassword(pws.trainer);
  await env.DB.prepare(
    'INSERT INTO users (id,verein_id,username,password_hash,role,display_name,trainer_id,must_change_password) VALUES (?,?,?,?,?,?,?,1)'
  ).bind(uid(), user.verein_id, uname, hash, data.role||'trainer', `${data.vorname} ${data.name}`, tid).run();
  return json({ ok: true, id: tid, username: uname });
}

async function updateTrainer(request, env, user, tId) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const data = await request.json();
  await env.DB.prepare('UPDATE trainers SET name=?,vorname=?,role=? WHERE id=? AND verein_id=?')
    .bind(data.name, data.vorname, data.role||'trainer', tId, user.verein_id).run();
  await env.DB.prepare('UPDATE users SET display_name=?,role=? WHERE trainer_id=? AND verein_id=?')
    .bind(`${data.vorname} ${data.name}`, data.role||'trainer', tId, user.verein_id).run();
  return json({ ok: true });
}

async function deleteTrainer(env, user, tId) {
  const check = requireRole(user, 'admin'); if (check) return check;
  await env.DB.prepare('DELETE FROM users WHERE trainer_id=? AND verein_id=?').bind(tId, user.verein_id).run();
  await env.DB.prepare('DELETE FROM trainers WHERE id=? AND verein_id=?').bind(tId, user.verein_id).run();
  return json({ ok: true });
}

// ============================================================
// LISTS
// ============================================================
async function getLists(env, user) {
  const rows = await env.DB.prepare('SELECT list_key,value FROM lists WHERE verein_id=? ORDER BY value').bind(user.verein_id).all();
  const result = { mannschaften:[], trainingsgruppen:[], trainerNamen:[] };
  rows.results.forEach(r => { if (result[r.list_key] && r.list_key !== 'trainerNamen') result[r.list_key].push(r.value); });
  // Trainer-Namen kommen ausschließlich aus der Trainertabelle
  const trainers = await env.DB.prepare('SELECT vorname,name FROM trainers WHERE verein_id=?').bind(user.verein_id).all();
  trainers.results.forEach(t => { result.trainerNamen.push(`${t.vorname} ${t.name}`); });
  result.trainerNamen.sort((a,b) => a.localeCompare(b));
  return json(result);
}

async function addListItem(request, env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const { key, value } = await request.json();
  if (!key || !value) return err('Key und Value erforderlich.');
  try {
    await env.DB.prepare('INSERT INTO lists (verein_id,list_key,value) VALUES (?,?,?)').bind(user.verein_id, key, value.trim()).run();
  } catch (e) { if (e.message.includes('UNIQUE')) return err('Eintrag existiert bereits.'); throw e; }
  return json({ ok: true });
}

async function removeListItem(request, env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const { key, value } = await request.json();
  await env.DB.prepare('DELETE FROM lists WHERE verein_id=? AND list_key=? AND value=?').bind(user.verein_id, key, value).run();
  return json({ ok: true });
}

// ============================================================
// USERS
// ============================================================
async function getUsers(env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  return json((await env.DB.prepare(
    'SELECT id,username,role,display_name,player_id,trainer_id,is_initial_admin,must_change_password FROM users WHERE verein_id=? AND is_initial_admin=0 ORDER BY display_name'
  ).bind(user.verein_id).all()).results.map(u => ({ ...u, is_initial_admin:!!u.is_initial_admin, must_change_password:!!u.must_change_password })));
}

async function resetPassword(env, user, targetId) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND verein_id=?').bind(targetId, user.verein_id).first();
  if (!target) return err('Benutzer nicht gefunden.');
  const pws = await getInitialPasswords(env, user.verein_id);
  const pw = target.role === 'spieler' ? pws.spieler : pws.trainer;
  const hash = await hashPassword(pw);
  await env.DB.prepare('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?').bind(hash, targetId).run();
  return json({ ok: true });
}

// ============================================================
// SETTINGS
// ============================================================
async function getSettings(env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const pws = await getInitialPasswords(env, user.verein_id);
  return json({ pw_spieler: pws.spieler, pw_trainer: pws.trainer });
}

async function saveSettings(request, env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const data = await request.json();
  if (data.pw_spieler) {
    await env.DB.prepare('INSERT INTO settings (verein_id,key,value) VALUES (?,?,?) ON CONFLICT(verein_id,key) DO UPDATE SET value=excluded.value')
      .bind(user.verein_id, 'pw_spieler', data.pw_spieler).run();
  }
  if (data.pw_trainer) {
    await env.DB.prepare('INSERT INTO settings (verein_id,key,value) VALUES (?,?,?) ON CONFLICT(verein_id,key) DO UPDATE SET value=excluded.value')
      .bind(user.verein_id, 'pw_trainer', data.pw_trainer).run();
  }
  return json({ ok: true });
}

// ============================================================
// EXPORT / IMPORT
// ============================================================
async function exportData(env, user) {
  const check = requireRole(user, 'admin', 'trainer'); if (check) return check;
  const players = (await env.DB.prepare('SELECT * FROM players WHERE verein_id=?').bind(user.verein_id).all()).results.map(mapPlayer);
  const assessments = (await env.DB.prepare('SELECT * FROM assessments WHERE verein_id=?').bind(user.verein_id).all()).results.map(mapAssessment);
  const trainers = (await env.DB.prepare('SELECT * FROM trainers WHERE verein_id=?').bind(user.verein_id).all()).results;
  const lists = {};
  (await env.DB.prepare('SELECT list_key,value FROM lists WHERE verein_id=?').bind(user.verein_id).all()).results.forEach(r => { if(!lists[r.list_key])lists[r.list_key]=[];lists[r.list_key].push(r.value); });
  return json({ type:'backup', exportDate:new Date().toISOString().slice(0,10), players, assessments, trainers, lists });
}

async function importData(request, env, user) {
  const check = requireRole(user, 'admin'); if (check) return check;
  const data = await request.json();
  const vid = user.verein_id;
  if (data.players) {
    for (const p of data.players) {
      const existing = await env.DB.prepare('SELECT id FROM players WHERE id=? AND verein_id=?').bind(p.id, vid).first();
      const mannschaft = JSON.stringify(Array.isArray(p.mannschaft)?p.mannschaft:p.mannschaft?[p.mannschaft]:[]);
      const jahrgang = p.geburtsdatum?p.geburtsdatum.slice(0,4):(p.jahrgang||'');
      if (existing) {
        await env.DB.prepare('UPDATE players SET name=?,vorname=?,geburtsdatum=?,jahrgang=?,mannschaft=?,gruppe=?,hand=?,trainer=?,vh_name=?,vh_typ=?,rh_name=?,rh_typ=? WHERE id=? AND verein_id=?')
          .bind(p.name,p.vorname,p.geburtsdatum||'',jahrgang,mannschaft,p.gruppe||'',p.hand||'',p.trainer||'',p.vhName||p.vh_name||'',p.vhTyp||p.vh_typ||'',p.rhName||p.rh_name||'',p.rhTyp||p.rh_typ||'',p.id,vid).run();
      } else {
        await env.DB.prepare('INSERT INTO players (id,verein_id,name,vorname,geburtsdatum,jahrgang,mannschaft,gruppe,hand,trainer,vh_name,vh_typ,rh_name,rh_typ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
          .bind(p.id,vid,p.name,p.vorname,p.geburtsdatum||'',jahrgang,mannschaft,p.gruppe||'',p.hand||'',p.trainer||'',p.vhName||p.vh_name||'',p.vhTyp||p.vh_typ||'',p.rhName||p.rh_name||'',p.rhTyp||p.rh_typ||'').run();
        const uname = await genUsername(env, vid, p.vorname, p.name);
        const pws = await getInitialPasswords(env, vid);
        const hash = await hashPassword(pws.spieler);
        await env.DB.prepare('INSERT INTO users (id,verein_id,username,password_hash,role,display_name,player_id,must_change_password) VALUES (?,?,?,?,?,?,?,1)')
          .bind(uid(),vid,uname,hash,'spieler',`${p.vorname} ${p.name}`,p.id).run();
      }
    }
  }
  if (data.assessments) {
    for (const a of data.assessments) {
      const existing = await env.DB.prepare('SELECT id FROM assessments WHERE id=? AND verein_id=?').bind(a.id, vid).first();
      const ratings = typeof a.ratings==='string'?a.ratings:JSON.stringify(a.ratings||{});
      if (existing) {
        await env.DB.prepare('UPDATE assessments SET date=?,trainer=?,ratings=?,staerken=?,next_step=?,bemerkung=? WHERE id=? AND verein_id=?')
          .bind(a.date,a.trainer||'',ratings,a.staerken||'',a.nextStep||a.next_step||'',a.bemerkung||'',a.id,vid).run();
      } else {
        await env.DB.prepare('INSERT INTO assessments (id,verein_id,player_id,date,trainer,ratings,staerken,next_step,bemerkung) VALUES (?,?,?,?,?,?,?,?,?)')
          .bind(a.id,vid,a.playerId||a.player_id,a.date,a.trainer||'',ratings,a.staerken||'',a.nextStep||a.next_step||'',a.bemerkung||'').run();
      }
    }
  }
  if (data.lists) {
    for (const [key, values] of Object.entries(data.lists)) {
      if (Array.isArray(values)) {
        for (const v of values) {
          try { await env.DB.prepare('INSERT INTO lists (verein_id,list_key,value) VALUES (?,?,?)').bind(vid,key,v).run(); } catch {}
        }
      }
    }
  }
  return json({ ok: true });
}
