// ============================================================
//  تواصل - تطبيق مراسلة على Cloudflare Workers + قاعدة D1
//  ملف واحد: الخادم (API) + الواجهة
//  المطلوب فقط: ربط قاعدة D1 باسم  DB
// ============================================================

const APP_NAME = 'تواصل';
// عدد دورات تشفير كلمة المرور. إذا ظهر خطأ 1102 (تجاوز وقت المعالج) في الخطة المجانية قلله إلى 10000
// وفي الخطة المدفوعة يمكنك رفعه إلى 100000
const PBKDF2_ITER = 20000;
const SESSION_MS = 30 * 24 * 3600 * 1000;
const USERNAME_RE = /^[A-Za-z0-9_]{3,24}$/;
const MAX_MSG = 4000;
const MAX_MEMBERS = 200;

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const SEC = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'same-origin',
  'x-frame-options': 'DENY',
  'content-security-policy':
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

// ---------------- أدوات عامة ----------------
const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (s) => new Uint8Array((s.match(/../g) || []).map((h) => parseInt(h, 16)));
const randHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));
async function sha256(s) { return toHex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }

async function pbkdf2(pw, saltHex, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: iter }, key, 256);
  return toHex(bits);
}
async function makePass(pw) {
  const salt = randHex(16);
  return PBKDF2_ITER + '$' + salt + '$' + (await pbkdf2(pw, salt, PBKDF2_ITER));
}
async function checkPass(pw, stored) {
  const [iter, salt, hash] = String(stored).split('$');
  const got = await pbkdf2(pw, salt, parseInt(iter, 10));
  if (got.length !== hash.length) return false;
  let d = 0;
  for (let i = 0; i < got.length; i++) d |= got.charCodeAt(i) ^ hash.charCodeAt(i);
  return d === 0;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...SEC, ...headers },
  });
}

function cleanName(s, max) {
  return String(s == null ? '' : s)
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F\u200B\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}
function cleanBody(s) {
  return String(s == null ? '' : s)
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim();
}
const publicUser = (u) => ({ id: u.id, username: u.username, name: u.name, bio: u.bio || '' });

// ---------------- قاعدة البيانات ----------------
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  const S = (q) => env.DB.prepare(q);
  await env.DB.batch([
    S(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '', pass TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0)`),
    S(`CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL)`),
    S(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`),
    S(`CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, title TEXT, owner_id INTEGER, dm_key TEXT UNIQUE, dm_a INTEGER, dm_b INTEGER, created_at INTEGER NOT NULL)`),
    S(`CREATE TABLE IF NOT EXISTS members(chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'member', joined_at INTEGER NOT NULL, last_read_id INTEGER NOT NULL DEFAULT 0, hidden_before INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(chat_id, user_id))`),
    S(`CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id)`),
    S(`CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER NOT NULL, user_id INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT 'msg', body TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, edited_at INTEGER, deleted INTEGER NOT NULL DEFAULT 0, reply_to INTEGER)`),
    S(`CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, id)`),
    S(`CREATE TABLE IF NOT EXISTS attempts(k TEXT NOT NULL, ts INTEGER NOT NULL)`),
    S(`CREATE INDEX IF NOT EXISTS idx_attempts ON attempts(k, ts)`),
  ]);
  schemaReady = true;
}

async function rateCount(env, key, windowMs) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS c FROM attempts WHERE k=? AND ts>?').bind(key, Date.now() - windowMs).first();
  return r ? r.c : 0;
}
async function rateHit(env, key) {
  await env.DB.prepare('INSERT INTO attempts(k,ts) VALUES(?,?)').bind(key, Date.now()).run();
  if (Math.random() < 0.02) await env.DB.prepare('DELETE FROM attempts WHERE ts<?').bind(Date.now() - 86400000).run();
}

// ---------------- الجلسات ----------------
function cookieHeader(url, token, maxAge) {
  return 'sid=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + (url.protocol === 'https:' ? '; Secure' : '');
}
async function createSession(env, userId) {
  const token = randHex(32);
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,created_at) VALUES(?,?,?)').bind(await sha256(token), userId, Date.now()).run();
  return token;
}
async function getUser(request, env) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  if (!m) throw new HttpError(401, 'يجب تسجيل الدخول');
  const th = await sha256(m[1]);
  const row = await env.DB.prepare(
    'SELECT u.id,u.username,u.name,u.bio,u.last_seen FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.created_at>?'
  ).bind(th, Date.now() - SESSION_MS).first();
  if (!row) throw new HttpError(401, 'انتهت الجلسة، سجل الدخول مرة أخرى');
  const now = Date.now();
  if (now - (row.last_seen || 0) > 45000) {
    await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now, row.id).run();
    row.last_seen = now;
  }
  row.token_hash = th;
  return row;
}

// ---------------- التسجيل والدخول ----------------
async function register(request, env, url, body) {
  const ip = request.headers.get('CF-Connecting-IP') || '0';
  if ((await rateCount(env, 'r:' + ip, 3600000)) >= 10) throw new HttpError(429, 'محاولات كثيرة، حاول لاحقا');
  const username = String(body.username || '').trim();
  const name = cleanName(body.name, 40);
  const password = String(body.password || '');
  if (!USERNAME_RE.test(username)) throw new HttpError(400, 'اسم المستخدم: من 3 إلى 24 حرفا إنجليزيا أو أرقاما أو شرطة سفلية');
  if (!name) throw new HttpError(400, 'اكتب الاسم الظاهر');
  if (password.length < 6 || password.length > 100) throw new HttpError(400, 'كلمة المرور يجب أن تكون 6 أحرف على الأقل');
  const exists = await env.DB.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE').bind(username).first();
  if (exists) throw new HttpError(409, 'اسم المستخدم مستخدم من قبل');
  let id;
  try {
    const r = await env.DB.prepare('INSERT INTO users(username,name,pass,created_at,last_seen) VALUES(?,?,?,?,?)')
      .bind(username, name, await makePass(password), Date.now(), Date.now()).run();
    id = r.meta.last_row_id;
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'اسم المستخدم مستخدم من قبل');
    throw e;
  }
  await rateHit(env, 'r:' + ip);
  const token = await createSession(env, id);
  return json({ user: { id, username, name, bio: '' } }, 200, { 'set-cookie': cookieHeader(url, token, SESSION_MS / 1000) });
}

async function login(request, env, url, body) {
  const ip = request.headers.get('CF-Connecting-IP') || '0';
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!username || !password) throw new HttpError(400, 'أدخل اسم المستخدم وكلمة المرور');
  const uk = 'lu:' + username.toLowerCase().slice(0, 40);
  if ((await rateCount(env, 'l:' + ip, 900000)) >= 20 || (await rateCount(env, uk, 900000)) >= 8) {
    throw new HttpError(429, 'محاولات كثيرة، حاول بعد 15 دقيقة');
  }
  const user = await env.DB.prepare('SELECT id,username,name,bio,pass FROM users WHERE username=? COLLATE NOCASE').bind(username).first();
  let ok = false;
  if (user) ok = await checkPass(password, user.pass);
  else await pbkdf2(password, '00000000000000000000000000000000', PBKDF2_ITER);
  if (!ok) {
    await rateHit(env, 'l:' + ip);
    await rateHit(env, uk);
    throw new HttpError(401, 'اسم المستخدم أو كلمة المرور غير صحيحة');
  }
  await env.DB.prepare('DELETE FROM attempts WHERE k=?').bind(uk).run();
  const token = await createSession(env, user.id);
  return json({ user: publicUser(user) }, 200, { 'set-cookie': cookieHeader(url, token, SESSION_MS / 1000) });
}

// ---------------- الرسائل والمحادثات ----------------
const MSG_SELECT =
  'SELECT m.id,m.chat_id,m.user_id,m.kind,m.body,m.created_at,m.edited_at,m.deleted,m.reply_to,u.name,u.username,' +
  "CASE WHEN r.deleted=1 THEN '' ELSE substr(r.body,1,140) END AS reply_body, r.deleted AS reply_deleted, ru.name AS reply_name " +
  'FROM messages m JOIN users u ON u.id=m.user_id ' +
  'LEFT JOIN messages r ON r.id=m.reply_to LEFT JOIN users ru ON ru.id=r.user_id';

async function getMessage(env, id) {
  return env.DB.prepare(MSG_SELECT + ' WHERE m.id=?').bind(id).first();
}

async function requireMember(env, chatId, userId) {
  const row = await env.DB.prepare(
    'SELECT mem.chat_id,mem.user_id,mem.role,mem.last_read_id,mem.hidden_before,c.type,c.title,c.owner_id,c.dm_a,c.dm_b ' +
    'FROM members mem JOIN chats c ON c.id=mem.chat_id WHERE mem.chat_id=? AND mem.user_id=?'
  ).bind(chatId, userId).first();
  if (!row) throw new HttpError(404, 'المحادثة غير موجودة');
  return row;
}

async function sysMsg(env, chatId, userId, text) {
  await env.DB.prepare("INSERT INTO messages(chat_id,user_id,kind,body,created_at) VALUES(?,?,'system',?,?)").bind(chatId, userId, text, Date.now()).run();
}

async function listChats(env, me) {
  const rows = (await env.DB.prepare(
    `SELECT c.id,c.type,c.title,c.owner_id,mem.last_read_id,
      (SELECT COUNT(*) FROM messages x WHERE x.chat_id=c.id AND x.id>MAX(mem.last_read_id,mem.hidden_before) AND x.user_id!=?1 AND x.deleted=0 AND x.kind='msg') AS unread,
      lm.id AS last_id, lm.body AS last_body, lm.created_at AS last_at, lm.deleted AS last_deleted, lm.kind AS last_kind, lm.user_id AS last_uid, lu.name AS last_name,
      ou.id AS other_id, ou.name AS other_name, ou.username AS other_username, ou.last_seen AS other_seen,
      (SELECT COUNT(*) FROM members z WHERE z.chat_id=c.id) AS member_count,
      COALESCE(lm.created_at,c.created_at) AS sort_at
     FROM members mem
     JOIN chats c ON c.id=mem.chat_id
     LEFT JOIN messages lm ON lm.id=(SELECT x.id FROM messages x WHERE x.chat_id=c.id AND x.id>mem.hidden_before ORDER BY x.id DESC LIMIT 1)
     LEFT JOIN users lu ON lu.id=lm.user_id
     LEFT JOIN users ou ON ou.id=(CASE WHEN c.type='dm' THEN (CASE WHEN c.dm_a=?1 THEN c.dm_b ELSE c.dm_a END) END)
     WHERE mem.user_id=?1
     ORDER BY sort_at DESC, c.id DESC LIMIT 200`
  ).bind(me.id).all()).results;
  return json({ chats: rows });
}

async function startDM(env, me, body) {
  const uname = String(body.username || '').trim().replace(/^@/, '');
  if (!USERNAME_RE.test(uname)) throw new HttpError(400, 'اسم المستخدم غير صالح');
  const target = await env.DB.prepare('SELECT id,name,username FROM users WHERE username=? COLLATE NOCASE').bind(uname).first();
  if (!target) throw new HttpError(404, 'لا يوجد مستخدم بهذا الاسم');
  const a = Math.min(me.id, target.id), b = Math.max(me.id, target.id);
  const key = a + '_' + b;
  const now = Date.now();
  await env.DB.prepare("INSERT OR IGNORE INTO chats(type,title,owner_id,dm_key,dm_a,dm_b,created_at) VALUES('dm',NULL,NULL,?,?,?,?)").bind(key, a, b, now).run();
  const chat = await env.DB.prepare('SELECT id FROM chats WHERE dm_key=?').bind(key).first();
  await env.DB.prepare("INSERT OR IGNORE INTO members(chat_id,user_id,role,joined_at) VALUES(?,?,'member',?)").bind(chat.id, me.id, now).run();
  return json({ id: chat.id });
}

async function createGroup(env, me, body) {
  const title = cleanName(body.title, 60);
  if (!title) throw new HttpError(400, 'اكتب اسم المجموعة');
  const names = Array.isArray(body.usernames) ? body.usernames.slice(0, MAX_MEMBERS) : [];
  const uniq = [...new Set(names.map((n) => String(n).trim().replace(/^@/, '').toLowerCase()))].filter((n) => USERNAME_RE.test(n));
  let users = [];
  if (uniq.length) {
    const ph = uniq.map(() => '?').join(',');
    users = (await env.DB.prepare('SELECT id,name,username FROM users WHERE lower(username) IN (' + ph + ') AND id!=?').bind(...uniq, me.id).all()).results;
    const found = new Set(users.map((u) => u.username.toLowerCase()));
    const missing = uniq.filter((n) => !found.has(n) && n !== me.username.toLowerCase());
    if (missing.length) throw new HttpError(404, 'مستخدمون غير موجودين: ' + missing.join(', '));
  }
  const now = Date.now();
  const r = await env.DB.prepare("INSERT INTO chats(type,title,owner_id,created_at) VALUES('group',?,?,?)").bind(title, me.id, now).run();
  const chatId = r.meta.last_row_id;
  const P = (q) => env.DB.prepare(q);
  await env.DB.batch([
    P("INSERT INTO members(chat_id,user_id,role,joined_at) VALUES(?,?,'owner',?)").bind(chatId, me.id, now),
    ...users.map((u) => P("INSERT INTO members(chat_id,user_id,role,joined_at) VALUES(?,?,'member',?)").bind(chatId, u.id, now)),
    P("INSERT INTO messages(chat_id,user_id,kind,body,created_at) VALUES(?,?,'system',?,?)").bind(chatId, me.id, me.name + ' أنشأ المجموعة', now),
  ]);
  return json({ id: chatId });
}

async function chatInfo(env, me, chatId) {
  const mem = await requireMember(env, chatId, me.id);
  if (mem.type === 'group') {
    const members = (await env.DB.prepare(
      'SELECT u.id,u.username,u.name,u.bio,u.last_seen,mm.role FROM members mm JOIN users u ON u.id=mm.user_id WHERE mm.chat_id=? ' +
      "ORDER BY CASE mm.role WHEN 'owner' THEN 0 ELSE 1 END, mm.joined_at, u.id"
    ).bind(chatId).all()).results;
    return json({ chat: { id: chatId, type: 'group', title: mem.title, owner_id: mem.owner_id }, members, my_role: mem.role });
  }
  const otherId = mem.dm_a === me.id ? mem.dm_b : mem.dm_a;
  const user = await env.DB.prepare('SELECT id,username,name,bio,last_seen FROM users WHERE id=?').bind(otherId).first();
  return json({ chat: { id: chatId, type: 'dm' }, user });
}

async function renameChat(env, me, chatId, body) {
  const mem = await requireMember(env, chatId, me.id);
  if (mem.type !== 'group') throw new HttpError(400, 'غير متاح');
  if (mem.role !== 'owner') throw new HttpError(403, 'فقط مالك المجموعة يمكنه ذلك');
  const title = cleanName(body.title, 60);
  if (!title) throw new HttpError(400, 'اكتب اسم المجموعة');
  await env.DB.prepare('UPDATE chats SET title=? WHERE id=?').bind(title, chatId).run();
  await sysMsg(env, chatId, me.id, me.name + ' غير اسم المجموعة إلى ' + title);
  return json({ ok: true });
}

async function deleteGroup(env, me, chatId) {
  const mem = await requireMember(env, chatId, me.id);
  if (mem.type !== 'group' || mem.role !== 'owner') throw new HttpError(403, 'فقط مالك المجموعة يمكنه الحذف');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM messages WHERE chat_id=?').bind(chatId),
    env.DB.prepare('DELETE FROM members WHERE chat_id=?').bind(chatId),
    env.DB.prepare('DELETE FROM chats WHERE id=?').bind(chatId),
  ]);
  return json({ ok: true });
}

async function addMember(env, me, chatId, body) {
  const mem = await requireMember(env, chatId, me.id);
  if (mem.type !== 'group') throw new HttpError(400, 'غير متاح');
  if (mem.role !== 'owner') throw new HttpError(403, 'فقط مالك المجموعة يمكنه إضافة أعضاء');
  const uname = String(body.username || '').trim().replace(/^@/, '');
  if (!USERNAME_RE.test(uname)) throw new HttpError(400, 'اسم المستخدم غير صالح');
  const target = await env.DB.prepare('SELECT id,name FROM users WHERE username=? COLLATE NOCASE').bind(uname).first();
  if (!target) throw new HttpError(404, 'لا يوجد مستخدم بهذا الاسم');
  const exists = await env.DB.prepare('SELECT 1 AS x FROM members WHERE chat_id=? AND user_id=?').bind(chatId, target.id).first();
  if (exists) throw new HttpError(409, 'هذا المستخدم عضو بالفعل');
  const cnt = await env.DB.prepare('SELECT COUNT(*) AS c FROM members WHERE chat_id=?').bind(chatId).first();
  if (cnt.c >= MAX_MEMBERS) throw new HttpError(400, 'اكتمل عدد أعضاء المجموعة');
  await env.DB.prepare(
    "INSERT INTO members(chat_id,user_id,role,joined_at,last_read_id,hidden_before) VALUES(?,?,'member',?,(SELECT COALESCE(MAX(id),0) FROM messages WHERE chat_id=?),(SELECT COALESCE(MAX(id),0) FROM messages WHERE chat_id=?))"
  ).bind(chatId, target.id, Date.now(), chatId, chatId).run();
  await sysMsg(env, chatId, me.id, me.name + ' أضاف ' + target.name);
  return json({ ok: true });
}

async function removeMember(env, me, chatId, targetId) {
  const mem = await requireMember(env, chatId, me.id);
  if (mem.type !== 'group') throw new HttpError(400, 'غير متاح');
  const self = targetId === me.id;
  if (!self && mem.role !== 'owner') throw new HttpError(403, 'فقط مالك المجموعة يمكنه إزالة الأعضاء');
  const target = await env.DB.prepare('SELECT mm.role,u.name FROM members mm JOIN users u ON u.id=mm.user_id WHERE mm.chat_id=? AND mm.user_id=?').bind(chatId, targetId).first();
  if (!target) throw new HttpError(404, 'العضو غير موجود');
  await env.DB.prepare('DELETE FROM members WHERE chat_id=? AND user_id=?').bind(chatId, targetId).run();
  const next = await env.DB.prepare(
    "SELECT user_id FROM members WHERE chat_id=? ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END, joined_at, user_id LIMIT 1"
  ).bind(chatId).first();
  if (!next) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM messages WHERE chat_id=?').bind(chatId),
      env.DB.prepare('DELETE FROM chats WHERE id=?').bind(chatId),
    ]);
    return json({ ok: true });
  }
  if (self && target.role === 'owner') {
    await env.DB.batch([
      env.DB.prepare("UPDATE members SET role='owner' WHERE chat_id=? AND user_id=?").bind(chatId, next.user_id),
      env.DB.prepare('UPDATE chats SET owner_id=? WHERE id=?').bind(next.user_id, chatId),
    ]);
  }
  await sysMsg(env, chatId, me.id, self ? target.name + ' غادر المجموعة' : me.name + ' أزال ' + target.name);
  return json({ ok: true });
}

async function getMessages(env, me, chatId, url) {
  const mem = await requireMember(env, chatId, me.id);
  const hidden = mem.hidden_before;
  const after = parseInt(url.searchParams.get('after') || '', 10);
  const before = parseInt(url.searchParams.get('before') || '', 10);
  const since = parseInt(url.searchParams.get('since') || '0', 10) || 0;
  let rows, hasMore = false;
  const LIM = 50;
  if (!isNaN(after)) {
    rows = (await env.DB.prepare(MSG_SELECT + ' WHERE m.chat_id=?1 AND m.id>?2 AND (m.id>?3 OR m.edited_at>?4) ORDER BY m.id ASC LIMIT 200')
      .bind(chatId, hidden, after, since).all()).results;
  } else {
    const b = isNaN(before) ? 1e15 : before;
    const res = (await env.DB.prepare(MSG_SELECT + ' WHERE m.chat_id=?1 AND m.id>?2 AND m.id<?3 ORDER BY m.id DESC LIMIT ?4')
      .bind(chatId, hidden, b, LIM + 1).all()).results;
    hasMore = res.length > LIM;
    rows = res.slice(0, LIM).reverse();
  }
  let othersRead = 0;
  if (mem.type === 'dm') {
    const o = await env.DB.prepare('SELECT last_read_id FROM members WHERE chat_id=? AND user_id!=? LIMIT 1').bind(chatId, me.id).first();
    othersRead = o ? o.last_read_id : 0;
  }
  return json({ messages: rows, has_more: hasMore, now: Date.now(), others_read: othersRead });
}

async function postMessage(env, me, chatId, body) {
  const mem = await requireMember(env, chatId, me.id);
  const text = cleanBody(body.body);
  if (!text) throw new HttpError(400, 'الرسالة فارغة');
  if (text.length > MAX_MSG) throw new HttpError(400, 'الرسالة طويلة جدا');
  if ((await rateCount(env, 'm:' + me.id, 60000)) >= 40) throw new HttpError(429, 'ترسل بسرعة كبيرة، انتظر قليلا');
  let replyTo = null;
  const rt = Number(body.reply_to);
  if (Number.isInteger(rt) && rt > 0) {
    const r = await env.DB.prepare('SELECT id FROM messages WHERE id=? AND chat_id=?').bind(rt, chatId).first();
    if (r) replyTo = r.id;
  }
  const now = Date.now();
  const ins = await env.DB.prepare("INSERT INTO messages(chat_id,user_id,kind,body,created_at,reply_to) VALUES(?,?,'msg',?,?,?)").bind(chatId, me.id, text, now, replyTo).run();
  const id = ins.meta.last_row_id;
  const stmts = [
    env.DB.prepare('UPDATE members SET last_read_id=MAX(last_read_id,?) WHERE chat_id=? AND user_id=?').bind(id, chatId, me.id),
    env.DB.prepare('INSERT INTO attempts(k,ts) VALUES(?,?)').bind('m:' + me.id, now),
  ];
  if (mem.type === 'dm') {
    const other = mem.dm_a === me.id ? mem.dm_b : mem.dm_a;
    if (other !== me.id) stmts.push(env.DB.prepare("INSERT OR IGNORE INTO members(chat_id,user_id,role,joined_at) VALUES(?,?,'member',?)").bind(chatId, other, now));
  }
  await env.DB.batch(stmts);
  return json({ message: await getMessage(env, id) });
}

async function markRead(env, me, chatId, body) {
  await requireMember(env, chatId, me.id);
  const id = Number(body.id);
  if (Number.isInteger(id) && id > 0) {
    await env.DB.prepare('UPDATE members SET last_read_id=MAX(last_read_id,?) WHERE chat_id=? AND user_id=?').bind(id, chatId, me.id).run();
  }
  return json({ ok: true });
}

async function clearChat(env, me, chatId) {
  await requireMember(env, chatId, me.id);
  await env.DB.prepare(
    'UPDATE members SET hidden_before=(SELECT COALESCE(MAX(id),0) FROM messages WHERE chat_id=?1), last_read_id=(SELECT COALESCE(MAX(id),0) FROM messages WHERE chat_id=?1) WHERE chat_id=?1 AND user_id=?2'
  ).bind(chatId, me.id).run();
  return json({ ok: true });
}

async function editMessage(env, me, msgId, body) {
  const m = await env.DB.prepare('SELECT id,chat_id,user_id,kind,deleted FROM messages WHERE id=?').bind(msgId).first();
  if (!m) throw new HttpError(404, 'الرسالة غير موجودة');
  await requireMember(env, m.chat_id, me.id);
  if (m.user_id !== me.id || m.kind !== 'msg' || m.deleted) throw new HttpError(403, 'لا يمكنك تعديل هذه الرسالة');
  const text = cleanBody(body.body);
  if (!text) throw new HttpError(400, 'الرسالة فارغة');
  if (text.length > MAX_MSG) throw new HttpError(400, 'الرسالة طويلة جدا');
  await env.DB.prepare('UPDATE messages SET body=?, edited_at=? WHERE id=?').bind(text, Date.now(), msgId).run();
  return json({ message: await getMessage(env, msgId) });
}

async function deleteMessage(env, me, msgId) {
  const m = await env.DB.prepare('SELECT id,chat_id,user_id,kind FROM messages WHERE id=?').bind(msgId).first();
  if (!m) throw new HttpError(404, 'الرسالة غير موجودة');
  const mem = await requireMember(env, m.chat_id, me.id);
  const allowed = m.kind === 'msg' && (m.user_id === me.id || (mem.type === 'group' && mem.role === 'owner'));
  if (!allowed) throw new HttpError(403, 'لا يمكنك حذف هذه الرسالة');
  await env.DB.prepare("UPDATE messages SET deleted=1, body='', edited_at=? WHERE id=?").bind(Date.now(), msgId).run();
  return json({ ok: true });
}

// ---------------- الحساب والبحث ----------------
async function updateProfile(env, me, body) {
  const name = body.name !== undefined ? cleanName(body.name, 40) : me.name;
  if (!name) throw new HttpError(400, 'الاسم لا يمكن أن يكون فارغا');
  const bio = body.bio !== undefined ? cleanName(body.bio, 200) : me.bio;
  let username = me.username;
  if (body.username !== undefined && String(body.username).trim() !== me.username) {
    const u = String(body.username).trim().replace(/^@/, '');
    if (!USERNAME_RE.test(u)) throw new HttpError(400, 'اسم المستخدم: من 3 إلى 24 حرفا إنجليزيا أو أرقاما أو شرطة سفلية');
    const ex = await env.DB.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE AND id!=?').bind(u, me.id).first();
    if (ex) throw new HttpError(409, 'اسم المستخدم مستخدم من قبل');
    username = u;
  }
  try {
    await env.DB.prepare('UPDATE users SET name=?, bio=?, username=? WHERE id=?').bind(name, bio, username, me.id).run();
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'اسم المستخدم مستخدم من قبل');
    throw e;
  }
  return json({ user: { id: me.id, username, name, bio } });
}

async function changePassword(env, me, body) {
  const cur = String(body.current || ''), nw = String(body.password || '');
  if (nw.length < 6 || nw.length > 100) throw new HttpError(400, 'كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل');
  if ((await rateCount(env, 'lu:' + me.username.toLowerCase(), 900000)) >= 8) throw new HttpError(429, 'محاولات كثيرة، حاول لاحقا');
  const row = await env.DB.prepare('SELECT pass FROM users WHERE id=?').bind(me.id).first();
  if (!(await checkPass(cur, row.pass))) {
    await rateHit(env, 'lu:' + me.username.toLowerCase());
    throw new HttpError(403, 'كلمة المرور الحالية غير صحيحة');
  }
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pass=? WHERE id=?').bind(await makePass(nw), me.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash!=?').bind(me.id, me.token_hash),
  ]);
  return json({ ok: true });
}

async function searchUsers(env, me, url) {
  const q = (url.searchParams.get('q') || '').replace(/^@/, '').trim();
  if (!/^[A-Za-z0-9_]{2,24}$/.test(q)) return json({ users: [] });
  const like = q.replace(/[\\%_]/g, (c) => '\\' + c) + '%';
  const users = (await env.DB.prepare("SELECT id,username,name FROM users WHERE username LIKE ? ESCAPE '\\' AND id!=? ORDER BY username LIMIT 10").bind(like, me.id).all()).results;
  return json({ users });
}

// ---------------- الموجّه ----------------
async function handleApi(request, env, url) {
  const method = request.method, p = url.pathname;
  const write = method !== 'GET' && method !== 'HEAD';
  if (write) {
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) throw new HttpError(403, 'طلب مرفوض');
  }
  let body = {};
  if (write && (request.headers.get('content-type') || '').includes('application/json')) {
    const raw = await request.text();
    if (raw.trim()) {
      try { body = JSON.parse(raw); } catch { throw new HttpError(400, 'بيانات غير صالحة'); }
    }
    if (!body || typeof body !== 'object') body = {};
  }

  if (p === '/api/register' && method === 'POST') return register(request, env, url, body);
  if (p === '/api/login' && method === 'POST') return login(request, env, url, body);

  const me = await getUser(request, env);

  if (p === '/api/logout' && method === 'POST') {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(me.token_hash).run();
    return json({ ok: true }, 200, { 'set-cookie': cookieHeader(url, '', 0) });
  }
  if (p === '/api/me') {
    if (method === 'GET') return json({ user: publicUser(me) });
    if (method === 'PATCH') return updateProfile(env, me, body);
  }
  if (p === '/api/me/password' && method === 'POST') return changePassword(env, me, body);
  if (p === '/api/users/search' && method === 'GET') return searchUsers(env, me, url);
  if (p === '/api/chats' && method === 'GET') return listChats(env, me);
  if (p === '/api/chats/dm' && method === 'POST') return startDM(env, me, body);
  if (p === '/api/chats/group' && method === 'POST') return createGroup(env, me, body);

  let m;
  if ((m = p.match(/^\/api\/chats\/(\d+)$/))) {
    const id = Number(m[1]);
    if (method === 'GET') return chatInfo(env, me, id);
    if (method === 'PATCH') return renameChat(env, me, id, body);
    if (method === 'DELETE') return deleteGroup(env, me, id);
  }
  if ((m = p.match(/^\/api\/chats\/(\d+)\/messages$/))) {
    const id = Number(m[1]);
    if (method === 'GET') return getMessages(env, me, id, url);
    if (method === 'POST') return postMessage(env, me, id, body);
  }
  if ((m = p.match(/^\/api\/chats\/(\d+)\/read$/)) && method === 'POST') return markRead(env, me, Number(m[1]), body);
  if ((m = p.match(/^\/api\/chats\/(\d+)\/clear$/)) && method === 'POST') return clearChat(env, me, Number(m[1]));
  if ((m = p.match(/^\/api\/chats\/(\d+)\/members$/)) && method === 'POST') return addMember(env, me, Number(m[1]), body);
  if ((m = p.match(/^\/api\/chats\/(\d+)\/members\/(\d+)$/)) && method === 'DELETE') return removeMember(env, me, Number(m[1]), Number(m[2]));
  if ((m = p.match(/^\/api\/messages\/(\d+)$/))) {
    if (method === 'PATCH') return editMessage(env, me, Number(m[1]), body);
    if (method === 'DELETE') return deleteMessage(env, me, Number(m[1]));
  }
  throw new HttpError(404, 'غير موجود');
}

const SETUP_PAGE =
  '<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<title>' + APP_NAME + '</title><body style="font-family:system-ui,Tahoma,sans-serif;max-width:560px;margin:60px auto;padding:0 20px;line-height:1.9">' +
  '<h2>قاعدة البيانات غير مربوطة</h2><p>لم يتم ربط قاعدة D1 بهذا الـ Worker. من صفحة الـ Worker: الإعدادات، ثم الروابط (Bindings)، ثم إضافة، ثم قاعدة بيانات D1، واكتب اسم المتغير <b dir="ltr">DB</b> واختر قاعدتك، ثم احفظ وأعد النشر.</p></body></html>';

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (!env.DB) {
        return new Response(SETUP_PAGE, { status: 500, headers: { 'content-type': 'text/html; charset=utf-8', ...SEC } });
      }
      await ensureSchema(env);
      if (url.pathname.startsWith('/api/')) return await handleApi(request, env, url);
      if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method Not Allowed', { status: 405 });
      return new Response(HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...SEC } });
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error(e && e.stack ? e.stack : e);
      return json({ error: 'حدث خطأ في الخادم' }, 500);
    }
  },
};

// ============================================================
//  الواجهة (HTML + CSS + JS)
//  ملاحظة: لا تستخدم علامة الاقتباس المائلة ولا ${ داخل هذا الجزء
// ============================================================
const HTML = String.raw`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#2f7bf0">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>تواصل</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='9' fill='%232f7bf0'/%3E%3Cpath d='M8 22V11a3 3 0 0 1 3-3h10a3 3 0 0 1 3 3v7a3 3 0 0 1-3 3H13z' fill='white'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700&display=swap">
<script>
(function(){try{var p=localStorage.getItem('theme')||'auto';var d=p==='dark'||(p==='auto'&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.setAttribute('data-theme',d?'dark':'light');}catch(e){}})();
</script>
<style>
:root{color-scheme:light;--bg:#eef1f6;--panel:#ffffff;--panel2:#f3f5f9;--text:#0e1726;--muted:#6a778b;--line:#e4e8f0;--accent:#2f7bf0;--sel:rgba(47,123,240,.12);--in:#ffffff;--out:#2f7bf0;--outt:#ffffff;--chat:#e8edf4;--danger:#e5484d;--shadow:0 18px 50px rgba(10,20,40,.18)}
[data-theme=dark]{color-scheme:dark;--bg:#0a101c;--panel:#101827;--panel2:#172136;--text:#e8edf6;--muted:#8d9ab0;--line:#1e2a41;--accent:#4a90f5;--sel:rgba(74,144,245,.18);--in:#1b2639;--out:#2b6bd8;--outt:#ffffff;--chat:#0b1322;--danger:#f0585d;--shadow:0 18px 50px rgba(0,0,0,.55)}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:"Tajawal","Segoe UI",Tahoma,system-ui,-apple-system,"Noto Sans Arabic",sans-serif;background:var(--bg);color:var(--text);font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;-webkit-tap-highlight-color:transparent}
button,input,textarea{font:inherit;color:inherit}
button{cursor:pointer;border:0;background:none}
button:disabled{opacity:.55;cursor:default}
a{color:inherit;text-decoration:underline;text-underline-offset:2px}
#app{height:100vh;height:100dvh}
svg{display:block;flex:none}

.inp{width:100%;padding:12px 14px;border:1px solid var(--line);background:var(--panel2);border-radius:12px;outline:none;transition:border-color .15s,box-shadow .15s}
.inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--sel)}
textarea.inp{resize:none;line-height:1.6}
.btn{padding:11px 18px;border-radius:12px;background:var(--accent);color:#fff;font-weight:700;transition:filter .15s}
.btn:hover:not(:disabled){filter:brightness(1.07)}
.btn.block{width:100%}
.btn.ghost{background:var(--panel2);color:var(--text)}
.btn.danger{background:var(--danger)}
.btn.soft{background:var(--sel);color:var(--accent)}
.iconbtn{width:40px;height:40px;border-radius:50%;display:grid;place-items:center;color:var(--muted);flex:none;transition:background .15s}
.iconbtn:hover{background:var(--panel2)}
.av{--s:46px;width:var(--s);height:var(--s);border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:700;font-size:calc(var(--s)*.42);flex:none;user-select:none}

/* تسجيل الدخول */
.authwrap{min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:20px;background:radial-gradient(900px 500px at 85% -10%,var(--sel),transparent),var(--bg)}
.card{width:min(400px,100%);background:var(--panel);border-radius:24px;padding:30px 24px 26px;box-shadow:var(--shadow);display:flex;flex-direction:column;gap:14px}
.logo{width:58px;height:58px;border-radius:17px;background:var(--accent);color:#fff;display:grid;place-items:center;margin:0 auto}
.card h1{text-align:center;font-size:25px}
.card .sub{text-align:center;color:var(--muted);font-size:14px;margin-top:-8px}
.tabs{display:flex;background:var(--panel2);border-radius:12px;padding:4px}
.tabs button{flex:1;padding:9px;border-radius:9px;color:var(--muted);font-weight:700}
.tabs button.on{background:var(--panel);color:var(--text);box-shadow:0 1px 3px rgba(0,0,0,.12)}
.err{color:var(--danger);font-size:13.5px;min-height:20px;text-align:center}
.field{display:flex;flex-direction:column;gap:6px}

/* الهيكل */
.shell{display:grid;grid-template-columns:380px 1fr;height:100%;max-width:1600px;margin:0 auto;background:var(--panel);box-shadow:0 0 0 1px var(--line)}
.side{display:flex;flex-direction:column;min-height:0;border-inline-end:1px solid var(--line);background:var(--panel)}
.sh{display:flex;align-items:center;gap:8px;padding:12px 12px 6px}
.brand{flex:1;font-size:20px;font-weight:700}
.sb{position:relative;padding:8px 12px 10px;color:var(--muted)}
.sb svg{position:absolute;inset-inline-start:26px;top:50%;transform:translateY(-50%);pointer-events:none}
.sb .inp{padding-inline-start:42px;border-radius:999px}
.list{flex:1;overflow-y:auto;padding:4px 0 16px;overscroll-behavior:contain}
.sec{padding:12px 20px 6px;font-size:13px;color:var(--muted);font-weight:700}
.hint{padding:30px 20px;text-align:center;color:var(--muted)}
.item{display:flex;align-items:center;gap:12px;padding:10px 12px;margin:2px 8px;border-radius:14px;cursor:pointer;transition:background .12s}
.item:hover{background:var(--panel2)}
.item.active{background:var(--sel)}
.im{flex:1;min-width:0;display:flex;flex-direction:column;gap:3px}
.ir{display:flex;align-items:center;gap:8px;min-width:0}
.it{flex:1;min-width:0;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.itm{font-size:12px;color:var(--muted);flex:none}
.ip{flex:1;min-width:0;color:var(--muted);font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge{min-width:22px;height:22px;padding:0 7px;border-radius:999px;background:var(--accent);color:#fff;font-size:12px;font-weight:700;display:grid;place-items:center;flex:none}
.item .u2{color:var(--muted);font-size:13.5px;direction:ltr;text-align:right}

.main{display:flex;flex-direction:column;min-height:0;min-width:0;background:var(--chat);position:relative}
.empty{margin:auto;text-align:center;padding:30px;color:var(--muted);display:flex;flex-direction:column;align-items:center;gap:10px}
.empty .eb{width:84px;height:84px;border-radius:26px;background:var(--panel);color:var(--accent);display:grid;place-items:center;box-shadow:0 8px 24px rgba(10,20,40,.08)}
.empty .et{font-size:19px;font-weight:700;color:var(--text)}
.ch{display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--panel);border-bottom:1px solid var(--line);min-height:60px}
.ch .back{display:none}
.chi{flex:1;display:flex;align-items:center;gap:12px;min-width:0;cursor:pointer;padding:2px 4px;border-radius:12px}
.cht{min-width:0}
.chn{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chs{font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.msgs{flex:1;overflow-y:auto;padding:14px 12px;display:flex;flex-direction:column;gap:2px;overscroll-behavior:contain}
.day{align-self:center;margin:12px 0 8px;padding:3px 14px;border-radius:999px;background:var(--panel);color:var(--muted);font-size:12.5px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.sys{align-self:center;margin:8px 0;padding:3px 14px;border-radius:999px;background:var(--sel);color:var(--muted);font-size:12.5px;text-align:center;max-width:90%}
.row{display:flex;max-width:100%;margin-top:1px}
.row.first{margin-top:8px}
.row.me{justify-content:flex-start}
.row.them{justify-content:flex-end}
.row.flash .bubble{animation:flash 1.2s}
@keyframes flash{0%,60%{box-shadow:0 0 0 3px var(--accent)}100%{box-shadow:0 1px 1px rgba(0,0,0,.07)}}
.bubble{max-width:min(540px,84%);padding:7px 12px 5px;border-radius:17px;box-shadow:0 1px 1px rgba(0,0,0,.07);cursor:pointer;overflow-wrap:anywhere;word-break:break-word;min-width:64px}
.me .bubble{background:var(--out);color:var(--outt);border-bottom-right-radius:5px}
.them .bubble{background:var(--in);border-bottom-left-radius:5px}
.bubble .sn{font-size:13px;font-weight:700;margin-bottom:1px}
.bubble .txt{white-space:pre-wrap;unicode-bidi:plaintext}
.bubble.del .txt{font-style:italic;opacity:.65;cursor:default}
.meta{display:flex;align-items:center;justify-content:flex-end;gap:5px;font-size:11px;opacity:.72;margin-top:1px;line-height:1.2}
.quote{display:flex;flex-direction:column;gap:1px;border-inline-start:3px solid currentColor;padding:3px 9px;margin:2px 0 5px;border-radius:6px;background:rgba(127,140,160,.16);font-size:13px;cursor:pointer;min-width:0}
.quote b{font-size:12.5px}
.quote span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;opacity:.85;max-width:100%}
.bar{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--panel);border-top:1px solid var(--line)}
.bar .bi{color:var(--accent)}
.bar .bt{flex:1;min-width:0;display:flex;flex-direction:column;border-inline-start:3px solid var(--accent);padding:0 9px;font-size:13px}
.bar .bt b{color:var(--accent)}
.bar .bt span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted)}
.composer{display:flex;align-items:flex-end;gap:8px;padding:10px 12px;padding-bottom:max(10px,env(safe-area-inset-bottom));background:var(--panel);border-top:1px solid var(--line)}
.bar+.composer{border-top:0}
.ta{flex:1;resize:none;border:1px solid var(--line);background:var(--panel2);border-radius:22px;padding:10px 16px;max-height:140px;line-height:1.5;outline:none;overflow-y:auto}
.ta:focus{border-color:var(--accent)}
.sendbtn{width:44px;height:44px;border-radius:50%;background:var(--accent);color:#fff;display:grid;place-items:center;flex:none;transition:filter .15s}
.sendbtn:hover{filter:brightness(1.08)}
.sendbtn svg{transform:scaleX(-1)}

/* نوافذ */
.ov{position:fixed;inset:0;background:rgba(6,10,20,.55);display:grid;place-items:center;padding:16px;z-index:50;animation:fade .15s}
@keyframes fade{from{opacity:0}to{opacity:1}}
.modal{width:min(440px,100%);max-height:90vh;max-height:90dvh;display:flex;flex-direction:column;background:var(--panel);border-radius:22px;box-shadow:var(--shadow);animation:pop .18s}
@keyframes pop{from{transform:translateY(10px) scale(.98);opacity:0}to{transform:none;opacity:1}}
.mh{display:flex;align-items:center;justify-content:space-between;padding:14px 18px 6px 12px}
.mt{font-size:18px;font-weight:700;padding-inline-start:6px}
.mb{padding:8px 18px 20px;overflow-y:auto;display:flex;flex-direction:column;gap:14px}
.fl{display:flex;flex-direction:column;gap:6px;font-size:13.5px;color:var(--muted);font-weight:500}
.res{display:flex;flex-direction:column;gap:2px}
.urow{display:flex;align-items:center;gap:12px;padding:8px 8px;border-radius:12px;cursor:pointer}
.urow:hover{background:var(--panel2)}
.urow .un{font-weight:700}
.urow .ua{font-size:13px;color:var(--muted);direction:ltr;text-align:right}
.urow .grow{flex:1;min-width:0}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:6px;padding:4px 6px 4px 12px;border-radius:999px;background:var(--sel);color:var(--accent);font-size:13.5px;font-weight:700}
.chip button{display:grid;place-items:center;width:20px;height:20px;border-radius:50%;color:var(--accent)}
.chip button:hover{background:rgba(127,140,160,.25)}
.seg{display:flex;background:var(--panel2);border-radius:12px;padding:4px;gap:4px}
.seg button{flex:1;padding:8px;border-radius:9px;color:var(--muted);font-weight:700}
.seg button.on{background:var(--panel);color:var(--text);box-shadow:0 1px 3px rgba(0,0,0,.12)}
.hr{height:1px;background:var(--line);margin:2px 0}
.stitle{font-weight:700;font-size:14px}
.prof{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center}
.prof .pn{font-size:20px;font-weight:700}
.prof .pu{color:var(--muted);direction:ltr}
.prof .pb{color:var(--text);font-size:14.5px;white-space:pre-wrap}
.tag{font-size:11.5px;padding:2px 8px;border-radius:999px;background:var(--sel);color:var(--accent);font-weight:700}
.row2{display:flex;gap:8px}
.row2 .inp{flex:1}
.menu{position:fixed;z-index:60;min-width:170px;background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:5px;animation:pop .12s}
.mi{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border-radius:9px;text-align:start}
.mi:hover{background:var(--panel2)}
.mi.danger{color:var(--danger)}
.toast{position:fixed;bottom:28px;left:50%;transform:translate(-50%,20px);background:#17202f;color:#fff;padding:10px 18px;border-radius:12px;font-size:14px;opacity:0;pointer-events:none;transition:.22s;z-index:99;max-width:90%;text-align:center}
.toast.show{opacity:1;transform:translate(-50%,0)}

@media(max-width:820px){
  .shell{grid-template-columns:1fr;box-shadow:none}
  .main{display:none}
  .shell.open .side{display:none}
  .shell.open .main{display:flex}
  .ch .back{display:grid}
  .bubble{max-width:88%}
}
</style>
</head>
<body>
<div id="app"></div>
<script>
(function(){
'use strict';
var APP='تواصل';
var $app=document.getElementById('app');
var isTouch=!!(window.matchMedia&&window.matchMedia('(pointer:coarse)').matches);
var state={};
function resetState(){state={me:state.me||null,chats:[],sig:'',active:null,msgs:[],lastId:0,lastSync:0,hasMore:false,othersRead:0,reply:null,edit:null,query:'',userResults:[],sentRead:0,sending:false,loadingOlder:false,listEl:null,msgsEl:null,input:null,barEl:null,meHolder:null};}
resetState();

/* ---------- أدوات ---------- */
var PALETTE=['#e5656b','#ee9a45','#9b6bdf','#3fa56a','#2fa4b8','#4a8fe7','#d65d9e','#76879f'];
function hs(s){var h=0;for(var i=0;i<s.length;i++){h=(h*31+s.charCodeAt(i))|0;}return Math.abs(h);}
function color(k){return PALETTE[hs(String(k))%PALETTE.length];}
function add(el,c){if(c==null||c===false)return;if(Array.isArray(c)){c.forEach(function(x){add(el,x);});}else if(typeof c==='string'||typeof c==='number'){el.appendChild(document.createTextNode(String(c)));}else{el.appendChild(c);}}
function h(tag,props){
  var el=document.createElement(tag);
  if(props){for(var k in props){var v=props[k];if(v==null||v===false)continue;
    if(k==='class')el.className=v;
    else if(k==='text')el.textContent=v;
    else if(k==='style')el.style.cssText=v;
    else if(k.slice(0,2)==='on')el.addEventListener(k.slice(2),v);
    else el.setAttribute(k,v===true?'':v);}}
  for(var i=2;i<arguments.length;i++)add(el,arguments[i]);
  return el;
}
var ICONS={
  send:'<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  back:'<path d="M5 12h14M12 5l7 7-7 7"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  close:'<path d="M18 6L6 18M6 6l12 12"/>',
  reply:'<path d="M9 14L4 9l5-5"/><path d="M20 20v-7a4 4 0 0 0-4-4H4"/>',
  edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>',
  trash:'<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>',
  copy:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  check:'<path d="M20 6L9 17l-5-5"/>',
  checks:'<path d="M2 12l5 5L17 7"/><path d="M12 15l1.5 1.5L22 7"/>',
  users:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  userplus:'<path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6M23 11h-6"/>',
  logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
  info:'<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  bookmark:'<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>',
  msg:'<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'
};
function ic(name,size){
  var s=document.createElementNS('http://www.w3.org/2000/svg','svg');
  s.setAttribute('viewBox','0 0 24 24');s.setAttribute('width',size||20);s.setAttribute('height',size||20);
  s.setAttribute('fill','none');s.setAttribute('stroke','currentColor');s.setAttribute('stroke-width','2');
  s.setAttribute('stroke-linecap','round');s.setAttribute('stroke-linejoin','round');
  s.innerHTML=ICONS[name]||'';return s;
}
function avatar(name,key,size){
  var ch=Array.from(String(name||'?').trim())[0]||'?';
  return h('div',{class:'av',style:'--s:'+size+'px;background:'+color(key)},ch);
}
function sameDay(a,b){return a.getFullYear()===b.getFullYear()&&a.getMonth()===b.getMonth()&&a.getDate()===b.getDate();}
function fmtTime(ts){return new Date(ts).toLocaleTimeString('ar-IQ',{hour:'numeric',minute:'2-digit'});}
function dayLabel(ts){var d=new Date(ts),n=new Date();if(sameDay(d,n))return 'اليوم';var y=new Date(n.getTime()-864e5);if(sameDay(d,y))return 'أمس';var o={day:'numeric',month:'long'};if(d.getFullYear()!==n.getFullYear())o.year='numeric';return d.toLocaleDateString('ar-IQ',o);}
function listTime(ts){var d=new Date(ts),n=new Date();if(sameDay(d,n))return fmtTime(ts);if(n-d<6*864e5)return d.toLocaleDateString('ar-IQ',{weekday:'short'});return d.toLocaleDateString('ar-IQ',{day:'numeric',month:'numeric'});}
function seenText(ts){if(!ts)return 'غير متصل';var d=Date.now()-ts;if(d<100000)return 'متصل الآن';if(d<3600000)return 'آخر ظهور منذ '+Math.max(1,Math.round(d/60000))+' دقيقة';var dt=new Date(ts);if(sameDay(dt,new Date()))return 'آخر ظهور اليوم '+fmtTime(ts);return 'آخر ظهور '+dayLabel(ts);}
function linkify(text){
  var out=[],re=/(https?:\/\/[^\s<>"']+)/g,last=0,m;
  while((m=re.exec(text))){
    if(m.index>last)out.push(text.slice(last,m.index));
    var url=m[0],trail='',t=url.match(/[.,;:!?)\]،؛]+$/);
    if(t){trail=t[0];url=url.slice(0,url.length-trail.length);}
    out.push(h('a',{href:url,target:'_blank',rel:'noopener noreferrer',onclick:function(e){e.stopPropagation();}},url));
    if(trail)out.push(trail);
    last=m.index+m[0].length;
  }
  if(last<text.length)out.push(text.slice(last));
  return out;
}
var toastT;
function toast(msg){var t=document.getElementById('toast');if(!t){t=h('div',{id:'toast',class:'toast'});document.body.appendChild(t);}t.textContent=msg;t.classList.add('show');clearTimeout(toastT);toastT=setTimeout(function(){t.classList.remove('show');},3200);}

async function api(path,opt){
  opt=opt||{};var method=opt.method||'GET';var init={method:method,credentials:'same-origin',headers:{}};
  if(method!=='GET'){init.headers['content-type']='application/json';init.body=JSON.stringify(opt.body||{});}
  var res;
  try{res=await fetch(path,init);}catch(e){throw new Error('تعذر الاتصال بالخادم');}
  var data=null;try{data=await res.json();}catch(e){}
  if(res.status===401&&state.me){state.me=null;showAuth();throw new Error((data&&data.error)||'انتهت الجلسة');}
  if(!res.ok)throw new Error((data&&data.error)||'تعذر إكمال الطلب');
  return data;
}

function modal(title,body){
  var ov=h('div',{class:'ov'});
  function close(){if(ov.parentNode)ov.parentNode.removeChild(ov);document.removeEventListener('keydown',esc);}
  function esc(e){if(e.key==='Escape')close();}
  var box=h('div',{class:'modal',role:'dialog'},
    h('div',{class:'mh'},h('div',{class:'mt',text:title}),h('button',{class:'iconbtn','aria-label':'إغلاق',onclick:close},ic('close'))),
    h('div',{class:'mb'},body));
  ov.appendChild(box);
  ov.addEventListener('mousedown',function(e){if(e.target===ov)close();});
  document.addEventListener('keydown',esc);
  document.body.appendChild(ov);
  return {close:close};
}
function confirmBox(title,text,okLabel,fn){
  var m;
  m=modal(title,h('div',{class:'mb',style:'padding:0'},
    h('div',{text:text,style:'color:var(--muted)'}),
    h('div',{class:'row2'},
      h('button',{class:'btn danger',style:'flex:1',text:okLabel,onclick:function(){m.close();fn();}}),
      h('button',{class:'btn ghost',style:'flex:1',text:'إلغاء',onclick:function(){m.close();}}))));
}
function closeMenu(){var m=document.getElementById('menu');if(m&&m.parentNode)m.parentNode.removeChild(m);}
function popMenu(x,y,items){
  closeMenu();
  var m=h('div',{class:'menu',id:'menu'});
  items.forEach(function(it){if(!it)return;
    m.appendChild(h('button',{class:'mi'+(it.danger?' danger':''),onclick:function(e){e.stopPropagation();closeMenu();it.fn();}},ic(it.icon,18),h('span',{text:it.label})));});
  document.body.appendChild(m);
  var r=m.getBoundingClientRect();
  var left=Math.min(Math.max(8,x-r.width/2),window.innerWidth-r.width-8);
  var top=Math.max(8,Math.min(y,window.innerHeight-r.height-8));
  m.style.left=left+'px';m.style.top=top+'px';
  setTimeout(function(){document.addEventListener('click',closeMenu,{once:true});},0);
}
function applyTheme(){
  var p='auto';try{p=localStorage.getItem('theme')||'auto';}catch(e){}
  var dark=p==='dark'||(p==='auto'&&window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-theme',dark?'dark':'light');
}

/* ---------- شاشة الدخول ---------- */
function showAuth(){
  stopPolling();resetState();state.me=null;document.title=APP;$app.textContent='';
  var mode='login';
  var name=h('input',{class:'inp',placeholder:'الاسم الظاهر',maxlength:40,autocomplete:'name'});
  var user=h('input',{class:'inp',placeholder:'اسم المستخدم (بالإنجليزي)',autocomplete:'username',autocapitalize:'none',spellcheck:'false',dir:'ltr',maxlength:24});
  var pass=h('input',{class:'inp',type:'password',placeholder:'كلمة المرور',autocomplete:'current-password',dir:'ltr',maxlength:100});
  var pass2=h('input',{class:'inp',type:'password',placeholder:'أعد كتابة كلمة المرور',autocomplete:'new-password',dir:'ltr',maxlength:100});
  var err=h('div',{class:'err'});
  var nameF=h('div',{class:'field'},name),pass2F=h('div',{class:'field'},pass2);
  var btn=h('button',{class:'btn block',type:'submit'});
  var tLogin=h('button',{type:'button',text:'تسجيل الدخول',onclick:function(){setMode('login');}});
  var tReg=h('button',{type:'button',text:'حساب جديد',onclick:function(){setMode('register');}});
  function setMode(m){
    mode=m;tLogin.className=m==='login'?'on':'';tReg.className=m==='register'?'on':'';
    nameF.style.display=m==='register'?'':'none';pass2F.style.display=m==='register'?'':'none';
    btn.textContent=m==='login'?'دخول':'إنشاء الحساب';
    pass.setAttribute('autocomplete',m==='login'?'current-password':'new-password');err.textContent='';
  }
  var form=h('form',{class:'card',onsubmit:async function(e){
    e.preventDefault();err.textContent='';btn.disabled=true;
    try{
      if(mode==='register'&&pass.value!==pass2.value)throw new Error('كلمتا المرور غير متطابقتين');
      var r=await api(mode==='login'?'/api/login':'/api/register',{method:'POST',body:{username:user.value.trim(),password:pass.value,name:name.value.trim()}});
      state.me=r.user;showMain();
    }catch(ex){err.textContent=ex.message;}finally{btn.disabled=false;}
  }},
    h('div',{class:'logo'},ic('msg',28)),
    h('h1',{text:APP}),
    h('div',{class:'sub',text:'تواصل مع أصدقائك ومجموعاتك بسهولة'}),
    h('div',{class:'tabs'},tLogin,tReg),
    nameF,h('div',{class:'field'},user),h('div',{class:'field'},pass),pass2F,err,btn);
  $app.appendChild(h('div',{class:'authwrap'},form));
  setMode('login');
  setTimeout(function(){user.focus();},50);
}

/* ---------- الهيكل الرئيسي ---------- */
function showMain(){
  var me=state.me;resetState();state.me=me;document.title=APP;$app.textContent='';
  var shell=h('div',{class:'shell',id:'shell'});
  var side=h('aside',{class:'side'});
  var main=h('section',{class:'main',id:'main'});
  shell.appendChild(side);shell.appendChild(main);$app.appendChild(shell);
  buildSide(side);renderEmptyMain();renderList();kick();
}
function renderMeBtn(){
  var holder=state.meHolder;if(!holder)return;holder.textContent='';
  holder.appendChild(avatar(state.me.name,'u'+state.me.id,38));
}
function buildSide(side){
  var meBtn=h('button',{class:'iconbtn','aria-label':'الإعدادات',style:'width:46px;height:46px',onclick:openSettings});
  state.meHolder=meBtn;renderMeBtn();
  var newBtn=h('button',{class:'iconbtn','aria-label':'جديد',onclick:function(e){
    var r=e.currentTarget.getBoundingClientRect();
    popMenu(r.left+r.width/2,r.bottom+6,[{icon:'userplus',label:'رسالة جديدة',fn:openNewDM},{icon:'users',label:'مجموعة جديدة',fn:openNewGroup}]);
  }},ic('plus',24));
  var search=h('input',{class:'inp',placeholder:'بحث في المحادثات أو عن مستخدم',oninput:onSearch,autocomplete:'off',autocapitalize:'none'});
  state.listEl=h('div',{class:'list'});
  side.appendChild(h('div',{class:'sh'},meBtn,h('div',{class:'brand',text:APP}),newBtn));
  side.appendChild(h('div',{class:'sb'},ic('search',18),search));
  side.appendChild(state.listEl);
}
var searchT;
function onSearch(e){
  var q=e.target.value;state.query=q;clearTimeout(searchT);
  var u=q.trim().replace(/^@/,'');
  if(u.length<2||!/^[A-Za-z0-9_]+$/.test(u)){state.userResults=[];renderList();return;}
  renderList();
  searchT=setTimeout(async function(){
    try{var r=await api('/api/users/search?q='+encodeURIComponent(u));if(state.query!==q)return;state.userResults=r.users;renderList();}catch(ex){}
  },250);
}
function isSaved(c){return c.type==='dm'&&c.other_id===state.me.id;}
function chatTitle(c){if(c.type==='group')return c.title;if(isSaved(c))return 'الرسائل المحفوظة';return c.other_name||'مستخدم';}
function chatAvatar(c,size){
  if(isSaved(c))return h('div',{class:'av',style:'--s:'+size+'px;background:var(--accent)'},ic('bookmark',Math.round(size*0.46)));
  if(c.type==='group')return avatar(c.title,'g'+c.id,size);
  return avatar(c.other_name,'u'+c.other_id,size);
}
function subtitle(c){if(c.type==='group')return c.member_count+' عضو';if(isSaved(c))return 'مساحتك الخاصة';return seenText(c.other_seen);}
function curChat(){for(var i=0;i<state.chats.length;i++){if(state.chats[i].id===state.active)return state.chats[i];}return null;}
function oneLine(s){return String(s||'').replace(/\s+/g,' ');}
function chatItem(c){
  var prev;
  if(c.last_id){
    if(c.last_deleted)prev='رسالة محذوفة';
    else if(c.last_kind==='system')prev=c.last_body;
    else if(c.last_uid===state.me.id)prev='أنت: '+c.last_body;
    else if(c.type==='group')prev=c.last_name+': '+c.last_body;
    else prev=c.last_body;
  }else prev=c.type==='group'?'مجموعة جديدة':'ابدأ المحادثة';
  return h('div',{class:'item'+(state.active===c.id?' active':''),onclick:function(){openChat(c.id);}},
    chatAvatar(c,50),
    h('div',{class:'im'},
      h('div',{class:'ir'},h('div',{class:'it',text:chatTitle(c)}),c.last_at?h('div',{class:'itm',text:listTime(c.last_at)}):null),
      h('div',{class:'ir'},h('div',{class:'ip',text:oneLine(prev)}),c.unread>0?h('div',{class:'badge',text:c.unread>99?'99+':c.unread}):null)));
}
function userRow(u,fn){
  return h('div',{class:'urow',onclick:fn},avatar(u.name,'u'+u.id,42),
    h('div',{class:'grow'},h('div',{class:'un',text:u.name}),h('div',{class:'ua',text:'@'+u.username})));
}
function renderList(){
  var el=state.listEl;if(!el)return;
  var top=el.scrollTop;el.textContent='';
  var q=state.query.trim().toLowerCase().replace(/^@/,'');
  var chats=state.chats.filter(function(c){
    if(!q)return true;
    return chatTitle(c).toLowerCase().indexOf(q)>-1||(c.other_username||'').toLowerCase().indexOf(q)>-1;
  });
  chats.forEach(function(c){el.appendChild(chatItem(c));});
  if(q&&state.userResults.length){
    el.appendChild(h('div',{class:'sec',text:'مستخدمون'}));
    state.userResults.forEach(function(u){el.appendChild(userRow(u,function(){startDM(u.username);}));});
  }
  if(!chats.length&&!(q&&state.userResults.length)){
    el.appendChild(h('div',{class:'hint',text:q?'لا توجد نتائج':'لا توجد محادثات بعد. اضغط على زر الإضافة لبدء محادثة أو إنشاء مجموعة.'}));
  }
  el.scrollTop=top;
}
function renderEmptyMain(){
  var main=document.getElementById('main');if(!main)return;main.textContent='';state.msgsEl=null;state.input=null;state.barEl=null;
  main.appendChild(h('div',{class:'empty'},h('div',{class:'eb'},ic('msg',38)),h('div',{class:'et',text:'اختر محادثة للبدء'}),h('div',{text:'أو ابدأ محادثة جديدة بإدخال اسم المستخدم'})));
}
function updateTitle(){
  var n=0;state.chats.forEach(function(c){n+=c.unread||0;});
  document.title=(n>0?'('+n+') ':'')+APP;
}

/* ---------- المحادثة ---------- */
async function openChat(id){
  if(!state.chats.some(function(c){return c.id===id;})){try{await refreshChats();}catch(e){}}
  if(!state.chats.some(function(c){return c.id===id;}))return;
  state.active=id;state.msgs=[];state.lastId=0;state.lastSync=0;state.hasMore=false;state.reply=null;state.edit=null;state.sentRead=0;state.othersRead=0;
  document.getElementById('shell').classList.add('open');
  renderList();buildChat();
  await loadInitial();
}
function closeChat(){
  state.active=null;state.msgs=[];
  document.getElementById('shell').classList.remove('open');
  renderEmptyMain();renderList();
}
function buildChat(){
  var main=document.getElementById('main');main.textContent='';var c=curChat();
  var msgs=h('div',{class:'msgs',onscroll:onScroll});state.msgsEl=msgs;
  var input=h('textarea',{class:'ta',rows:1,placeholder:'اكتب رسالة',maxlength:4000,'aria-label':'الرسالة'});state.input=input;
  input.addEventListener('input',autosize);
  input.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey&&!isTouch&&!e.isComposing){e.preventDefault();send();}});
  var bar=h('div',{class:'bar'});state.barEl=bar;
  var sendBtn=h('button',{class:'sendbtn','aria-label':'إرسال',onclick:send},ic('send',20));
  main.appendChild(h('div',{class:'ch'},
    h('button',{class:'iconbtn back','aria-label':'رجوع',onclick:closeChat},ic('back',22)),
    h('div',{class:'chi',onclick:openInfo},chatAvatar(c,42),h('div',{class:'cht'},h('div',{class:'chn',id:'chn',text:chatTitle(c)}),h('div',{class:'chs',id:'chs',text:subtitle(c)}))),
    h('button',{class:'iconbtn','aria-label':'معلومات',onclick:openInfo},ic('info',22))));
  main.appendChild(msgs);main.appendChild(bar);
  main.appendChild(h('div',{class:'composer'},input,sendBtn));
  updateBar();
  if(!isTouch)input.focus();
}
function updateHeader(){
  var c=curChat();if(!c)return;
  var n=document.getElementById('chn'),s=document.getElementById('chs');
  if(n&&n.textContent!==chatTitle(c))n.textContent=chatTitle(c);
  if(s&&s.textContent!==subtitle(c))s.textContent=subtitle(c);
}
function autosize(){var t=state.input;if(!t)return;t.style.height='auto';t.style.height=Math.min(t.scrollHeight,140)+'px';}
function onScroll(){var b=state.msgsEl;if(b&&b.scrollTop<80&&state.hasMore&&!state.loadingOlder)loadOlder();}

function indexOfMsg(id){for(var i=0;i<state.msgs.length;i++){if(state.msgs[i].id===id)return i;}return -1;}
function applyMsgs(list){
  var changed=false;
  list.forEach(function(m){
    var i=indexOfMsg(m.id);
    if(i>-1){if(JSON.stringify(state.msgs[i])!==JSON.stringify(m)){state.msgs[i]=m;changed=true;}}
    else{state.msgs.push(m);changed=true;}
    if(m.id>state.lastId)state.lastId=m.id;
  });
  if(changed)state.msgs.sort(function(a,b){return a.id-b.id;});
  return changed;
}
async function loadInitial(){
  var id=state.active,r;
  try{r=await api('/api/chats/'+id+'/messages');}catch(ex){toast(ex.message);return;}
  if(state.active!==id)return;
  state.msgs=r.messages;state.hasMore=r.has_more;
  state.lastId=r.messages.length?r.messages[r.messages.length-1].id:0;
  state.lastSync=r.now;state.othersRead=r.others_read||0;
  renderMsgs(true);markRead();
}
async function loadOlder(){
  if(!state.msgs.length)return;
  state.loadingOlder=true;var id=state.active;
  try{
    var r=await api('/api/chats/'+id+'/messages?before='+state.msgs[0].id);
    if(state.active!==id)return;
    state.hasMore=r.has_more;
    if(applyMsgs(r.messages))renderMsgs(false);
  }catch(e){}finally{state.loadingOlder=false;}
}
async function refreshMessages(){
  var id=state.active;if(!id)return;
  var r=await api('/api/chats/'+id+'/messages?after='+state.lastId+'&since='+Math.max(0,state.lastSync-3000));
  if(state.active!==id)return;
  state.lastSync=r.now;var ch=false;var read=r.others_read||0;
  if(read!==state.othersRead){state.othersRead=read;ch=true;}
  if(r.messages.length&&applyMsgs(r.messages))ch=true;
  if(ch){renderMsgs(false);markRead();}
}
function markRead(){
  var c=curChat();if(!c||document.hidden)return;
  var last=0;state.msgs.forEach(function(m){if(m.user_id!==state.me.id&&m.kind==='msg'&&m.id>last)last=m.id;});
  if(last>state.sentRead){
    state.sentRead=last;c.unread=0;
    api('/api/chats/'+c.id+'/read',{method:'POST',body:{id:last}}).catch(function(){});
    renderList();updateTitle();
  }
}
function renderMsgs(stick){
  var box=state.msgsEl;if(!box)return;
  var fromBottom=box.scrollHeight-box.scrollTop;
  var near=stick||(box.scrollHeight-box.scrollTop-box.clientHeight<140);
  box.textContent='';
  var chat=curChat();if(!chat)return;
  var prev=null;
  state.msgs.forEach(function(m){
    if(!prev||!sameDay(new Date(prev.created_at),new Date(m.created_at)))box.appendChild(h('div',{class:'day'},dayLabel(m.created_at)));
    if(m.kind==='system'){box.appendChild(h('div',{class:'sys',text:m.body}));prev=m;return;}
    var mine=m.user_id===state.me.id;
    var first=!prev||prev.kind==='system'||prev.user_id!==m.user_id||(m.created_at-prev.created_at>300000);
    box.appendChild(msgRow(m,mine,first,chat));
    prev=m;
  });
  if(near)box.scrollTop=box.scrollHeight;else box.scrollTop=box.scrollHeight-fromBottom;
}
function msgRow(m,mine,first,chat){
  var bub=h('div',{class:'bubble'+(m.deleted?' del':'')});
  if(!mine&&chat.type==='group'&&first&&!m.deleted)bub.appendChild(h('div',{class:'sn',style:'color:'+color('u'+m.user_id),text:m.name}));
  if(m.reply_to&&!m.deleted){
    bub.appendChild(h('div',{class:'quote',onclick:function(e){e.stopPropagation();jumpTo(m.reply_to);}},
      h('b',{text:m.reply_name||''}),h('span',{text:m.reply_deleted?'رسالة محذوفة':oneLine(m.reply_body)})));
  }
  if(m.deleted)bub.appendChild(h('div',{class:'txt',text:'تم حذف هذه الرسالة'}));
  else bub.appendChild(h('div',{class:'txt',dir:'auto'},linkify(m.body)));
  var meta=h('div',{class:'meta'});
  if(m.edited_at&&!m.deleted)meta.appendChild(h('span',{text:'معدّلة'}));
  meta.appendChild(h('span',{text:fmtTime(m.created_at)}));
  if(mine&&!m.deleted&&chat.type==='dm'&&!isSaved(chat))meta.appendChild(ic(m.id<=state.othersRead?'checks':'check',14));
  bub.appendChild(meta);
  if(!m.deleted){
    bub.addEventListener('click',function(e){msgMenu(e,m,mine);});
    bub.addEventListener('contextmenu',function(e){e.preventDefault();msgMenu(e,m,mine);});
  }
  return h('div',{class:'row '+(mine?'me':'them')+(first?' first':''),'data-id':m.id},bub);
}
function jumpTo(id){
  var box=state.msgsEl;if(!box)return;
  var row=box.querySelector('[data-id="'+id+'"]');
  if(!row){toast('الرسالة الأصلية غير محملة');return;}
  row.scrollIntoView({block:'center',behavior:'smooth'});
  row.classList.add('flash');setTimeout(function(){row.classList.remove('flash');},1300);
}
function msgMenu(e,m,mine){
  var sel='';try{sel=String(window.getSelection());}catch(x){}
  if(sel)return;
  var c=curChat();if(!c)return;
  var canDel=mine||(c.type==='group'&&c.owner_id===state.me.id);
  popMenu(e.clientX,e.clientY,[
    {icon:'reply',label:'رد',fn:function(){startReply(m);}},
    {icon:'copy',label:'نسخ',fn:function(){copyText(m.body);}},
    mine?{icon:'edit',label:'تعديل',fn:function(){startEdit(m);}}:null,
    canDel?{icon:'trash',label:'حذف',danger:true,fn:function(){confirmBox('حذف الرسالة','سيتم حذف الرسالة للجميع.','حذف',function(){delMsg(m);});}}:null
  ]);
}
function copyText(t){
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(function(){toast('تم النسخ');},function(){toast('تعذر النسخ');});}
  else toast('تعذر النسخ');
}
function startReply(m){state.reply=m;state.edit=null;updateBar();if(state.input)state.input.focus();}
function startEdit(m){state.edit=m;state.reply=null;updateBar();if(state.input){state.input.value=m.body;autosize();state.input.focus();}}
function updateBar(){
  var b=state.barEl;if(!b)return;b.textContent='';
  var m=state.edit||state.reply;
  if(!m){b.style.display='none';return;}
  b.style.display='';
  var editing=!!state.edit;
  b.appendChild(h('div',{class:'bi'},ic(editing?'edit':'reply',20)));
  b.appendChild(h('div',{class:'bt'},h('b',{text:editing?'تعديل الرسالة':'الرد على '+m.name}),h('span',{text:oneLine(m.body)})));
  b.appendChild(h('button',{class:'iconbtn','aria-label':'إلغاء',onclick:function(){
    if(state.edit&&state.input){state.input.value='';autosize();}
    state.edit=null;state.reply=null;updateBar();}},ic('close',18)));
}
async function delMsg(m){
  try{await api('/api/messages/'+m.id,{method:'DELETE'});await refreshMessages();}catch(ex){toast(ex.message);}
}
async function send(){
  if(state.sending)return;
  var c=curChat();if(!c||!state.input)return;
  var txt=state.input.value.replace(/\s+$/,'');
  if(!txt.trim())return;
  state.sending=true;
  var editing=state.edit,replying=state.reply;
  state.input.value='';autosize();
  try{
    var r;
    if(editing){r=await api('/api/messages/'+editing.id,{method:'PATCH',body:{body:txt}});}
    else{r=await api('/api/chats/'+c.id+'/messages',{method:'POST',body:{body:txt,reply_to:replying?replying.id:null}});}
    state.edit=null;state.reply=null;updateBar();
    if(state.active===c.id){applyMsgs([r.message]);renderMsgs(true);}
    refreshChats().catch(function(){});
  }catch(ex){
    toast(ex.message);
    if(state.input){state.input.value=txt;autosize();}
  }finally{state.sending=false;if(state.input&&!isTouch)state.input.focus();}
}

/* ---------- القائمة والتحديث الدوري ---------- */
async function refreshChats(){
  var r=await api('/api/chats');
  var sig=JSON.stringify(r.chats);state.chats=r.chats;
  if(sig!==state.sig){state.sig=sig;renderList();}
  if(state.active&&!curChat()){toast('لم تعد عضوا في هذه المحادثة');closeChat();}
  updateHeader();updateTitle();
}
var pollT=null,busy=false,lastAct=Date.now();
['pointerdown','keydown','touchstart'].forEach(function(ev){document.addEventListener(ev,function(){lastAct=Date.now();},{passive:true});});
document.addEventListener('visibilitychange',function(){if(!document.hidden&&state.me){lastAct=Date.now();kick();}});
async function loop(){
  clearTimeout(pollT);
  if(!state.me)return;
  var wait=2500;
  if(!document.hidden){
    if(!busy){busy=true;try{await refreshChats();if(state.active)await refreshMessages();}catch(e){}busy=false;}
    if(Date.now()-lastAct>120000)wait=10000;
  }else wait=20000;
  pollT=setTimeout(loop,wait);
}
function kick(){clearTimeout(pollT);loop();}
function stopPolling(){clearTimeout(pollT);}

/* ---------- رسالة جديدة ---------- */
async function startDM(username,m){
  try{
    var r=await api('/api/chats/dm',{method:'POST',body:{username:username}});
    if(m)m.close();
    var inp=document.querySelector('.sb .inp');if(inp){inp.value='';}
    state.query='';state.userResults=[];
    await refreshChats();await openChat(r.id);
  }catch(ex){toast(ex.message);}
}
function userSearchBox(placeholder,onPick,onEnter){
  var inp=h('input',{class:'inp',placeholder:placeholder,dir:'ltr',autocapitalize:'none',spellcheck:'false',maxlength:25,autocomplete:'off'});
  var res=h('div',{class:'res'});var t;
  inp.addEventListener('input',function(){
    clearTimeout(t);
    t=setTimeout(async function(){
      var q=inp.value.trim().replace(/^@/,'');res.textContent='';
      if(!/^[A-Za-z0-9_]{2,24}$/.test(q))return;
      try{var r=await api('/api/users/search?q='+encodeURIComponent(q));
        if(inp.value.trim().replace(/^@/,'')!==q)return;res.textContent='';
        if(!r.users.length)res.appendChild(h('div',{class:'hint',style:'padding:14px',text:'لا يوجد مستخدم بهذا الاسم'}));
        r.users.forEach(function(u){res.appendChild(userRow(u,function(){onPick(u);}));});
      }catch(e){}
    },250);
  });
  inp.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();var q=inp.value.trim().replace(/^@/,'');if(q)onEnter(q,inp);}});
  return {inp:inp,res:res};
}
function openNewDM(){
  var m;
  var box=userSearchBox('اكتب اسم المستخدم',function(u){startDM(u.username,m);},function(q){startDM(q,m);});
  var saved=h('div',{class:'urow',onclick:function(){startDM(state.me.username,m);}},
    h('div',{class:'av',style:'--s:42px;background:var(--accent)'},ic('bookmark',20)),
    h('div',{class:'grow'},h('div',{class:'un',text:'الرسائل المحفوظة'}),h('div',{class:'ua',style:'direction:rtl;text-align:start',text:'احفظ ملاحظاتك وروابطك لنفسك'})));
  m=modal('رسالة جديدة',h('div',{class:'mb',style:'padding:0'},box.inp,box.res,h('div',{class:'hr'}),saved));
  setTimeout(function(){box.inp.focus();},60);
}
function openNewGroup(){
  var title=h('input',{class:'inp',placeholder:'اسم المجموعة',maxlength:60});
  var chips=h('div',{class:'chips'});var members=[];var m;
  function draw(){chips.textContent='';members.forEach(function(u,i){
    chips.appendChild(h('span',{class:'chip'},u.name,h('button',{type:'button','aria-label':'إزالة',onclick:function(){members.splice(i,1);draw();}},ic('close',13))));});}
  function addU(u){
    if(u.id===state.me.id)return;
    if(members.some(function(x){return x.username.toLowerCase()===u.username.toLowerCase();}))return;
    members.push(u);draw();box.inp.value='';box.res.textContent='';
  }
  var box=userSearchBox('أضف أعضاء بإدخال اسم المستخدم',addU,async function(q,inp){
    try{var r=await api('/api/users/search?q='+encodeURIComponent(q));
      var f=r.users.filter(function(u){return u.username.toLowerCase()===q.toLowerCase();})[0];
      if(f)addU(f);else toast('لا يوجد مستخدم بهذا الاسم');}catch(e){toast(e.message);}
  });
  var create=h('button',{class:'btn block',text:'إنشاء المجموعة',onclick:async function(){
    create.disabled=true;
    try{var r=await api('/api/chats/group',{method:'POST',body:{title:title.value,usernames:members.map(function(u){return u.username;})}});
      m.close();await refreshChats();await openChat(r.id);}
    catch(ex){toast(ex.message);}finally{create.disabled=false;}
  }});
  m=modal('مجموعة جديدة',h('div',{class:'mb',style:'padding:0'},title,box.inp,box.res,chips,create));
  setTimeout(function(){title.focus();},60);
}

/* ---------- معلومات المحادثة ---------- */
async function openInfo(){
  var c=curChat();if(!c)return;
  var d;try{d=await api('/api/chats/'+c.id);}catch(ex){toast(ex.message);return;}
  var body=h('div',{class:'mb',style:'padding:0'});
  var m=modal(c.type==='group'?'معلومات المجموعة':'معلومات الحساب',body);
  async function reload(){try{d=await api('/api/chats/'+c.id);render();refreshChats().catch(function(){});}catch(ex){m.close();}}
  function clearBtn(){
    return h('button',{class:'btn ghost block',text:'مسح سجل المحادثة عندي',onclick:function(){
      confirmBox('مسح المحادثة','سيتم مسح الرسائل الحالية من عندك فقط.','مسح',async function(){
        try{await api('/api/chats/'+c.id+'/clear',{method:'POST'});m.close();state.msgs=[];state.lastId=0;await loadInitial();await refreshChats();}catch(ex){toast(ex.message);}
      });}});
  }
  function render(){
    body.textContent='';
    if(d.chat.type==='dm'){
      var u=d.user;
      body.appendChild(h('div',{class:'prof'},avatar(u.name,'u'+u.id,84),h('div',{class:'pn',text:u.id===state.me.id?'الرسائل المحفوظة':u.name}),
        u.id===state.me.id?null:h('div',{class:'pu',text:'@'+u.username}),
        u.id===state.me.id?null:h('div',{class:'chs',text:seenText(u.last_seen)}),
        u.bio?h('div',{class:'pb',text:u.bio}):null));
      body.appendChild(clearBtn());return;
    }
    var owner=d.my_role==='owner';
    body.appendChild(h('div',{class:'prof'},avatar(d.chat.title,'g'+d.chat.id,84),h('div',{class:'pn',text:d.chat.title}),h('div',{class:'chs',text:d.members.length+' عضو'})));
    if(owner){
      var t=h('input',{class:'inp',value:d.chat.title,maxlength:60});
      body.appendChild(h('label',{class:'fl'},h('span',{text:'اسم المجموعة'}),
        h('div',{class:'row2'},t,h('button',{class:'btn soft',text:'حفظ',onclick:async function(){
          try{await api('/api/chats/'+c.id,{method:'PATCH',body:{title:t.value}});toast('تم تغيير الاسم');await reload();}catch(ex){toast(ex.message);}}}))));
    }
    body.appendChild(h('div',{class:'stitle',text:'الأعضاء'}));
    var list=h('div',{class:'res'});
    d.members.forEach(function(u){
      var row=h('div',{class:'urow',style:'cursor:default'},avatar(u.name,'u'+u.id,40),
        h('div',{class:'grow'},h('div',{class:'un',text:u.name+(u.id===state.me.id?' (أنت)':'')}),h('div',{class:'ua',text:'@'+u.username})),
        u.role==='owner'?h('span',{class:'tag',text:'المالك'}):null);
      if(owner&&u.id!==state.me.id){
        row.appendChild(h('button',{class:'iconbtn','aria-label':'إزالة',onclick:function(){
          confirmBox('إزالة عضو','هل تريد إزالة '+u.name+' من المجموعة؟','إزالة',async function(){
            try{await api('/api/chats/'+c.id+'/members/'+u.id,{method:'DELETE'});await reload();}catch(ex){toast(ex.message);}});}},ic('close',18)));
      }
      list.appendChild(row);
    });
    body.appendChild(list);
    if(owner){
      var a=h('input',{class:'inp',placeholder:'اسم مستخدم لإضافته',dir:'ltr',autocapitalize:'none',spellcheck:'false',maxlength:25});
      async function doAdd(){var v=a.value.trim();if(!v)return;try{await api('/api/chats/'+c.id+'/members',{method:'POST',body:{username:v}});a.value='';await reload();}catch(ex){toast(ex.message);}}
      a.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();doAdd();}});
      body.appendChild(h('div',{class:'row2'},a,h('button',{class:'btn soft',text:'إضافة',onclick:doAdd})));
    }
    body.appendChild(h('div',{class:'hr'}));
    body.appendChild(clearBtn());
    body.appendChild(h('button',{class:'btn ghost block',style:'color:var(--danger)',text:'مغادرة المجموعة',onclick:function(){
      confirmBox('مغادرة المجموعة','هل تريد مغادرة هذه المجموعة؟','مغادرة',async function(){
        try{await api('/api/chats/'+c.id+'/members/'+state.me.id,{method:'DELETE'});m.close();closeChat();await refreshChats();}catch(ex){toast(ex.message);}});}}));
    if(owner){
      body.appendChild(h('button',{class:'btn danger block',text:'حذف المجموعة للجميع',onclick:function(){
        confirmBox('حذف المجموعة','سيتم حذف المجموعة وكل رسائلها نهائيا لجميع الأعضاء.','حذف',async function(){
          try{await api('/api/chats/'+c.id,{method:'DELETE'});m.close();closeChat();await refreshChats();}catch(ex){toast(ex.message);}});}}));
    }
  }
  render();
}

/* ---------- الإعدادات ---------- */
function field(label,el){return h('label',{class:'fl'},h('span',{text:label}),el);}
function openSettings(){
  var u=state.me;
  var name=h('input',{class:'inp',value:u.name,maxlength:40});
  var user=h('input',{class:'inp',value:u.username,dir:'ltr',maxlength:24,autocapitalize:'none',spellcheck:'false'});
  var bio=h('textarea',{class:'inp',rows:2,maxlength:200,placeholder:'نبذة قصيرة (اختياري)'});bio.value=u.bio||'';
  var save=h('button',{class:'btn',text:'حفظ التغييرات',onclick:async function(){
    save.disabled=true;
    try{var r=await api('/api/me',{method:'PATCH',body:{name:name.value,username:user.value,bio:bio.value}});state.me=r.user;renderMeBtn();toast('تم الحفظ');}
    catch(ex){toast(ex.message);}finally{save.disabled=false;}
  }});
  var cur='auto';try{cur=localStorage.getItem('theme')||'auto';}catch(e){}
  var seg=h('div',{class:'seg'});
  [['auto','تلقائي'],['light','فاتح'],['dark','داكن']].forEach(function(o){
    var b=h('button',{type:'button',class:cur===o[0]?'on':'',text:o[1],onclick:function(){
      try{localStorage.setItem('theme',o[0]);}catch(e){}applyTheme();
      Array.prototype.forEach.call(seg.children,function(x){x.className='';});b.className='on';}});
    seg.appendChild(b);
  });
  var p1=h('input',{class:'inp',type:'password',dir:'ltr',autocomplete:'current-password',maxlength:100});
  var p2=h('input',{class:'inp',type:'password',dir:'ltr',autocomplete:'new-password',maxlength:100});
  var pbtn=h('button',{class:'btn ghost',text:'تغيير كلمة المرور',onclick:async function(){
    pbtn.disabled=true;
    try{await api('/api/me/password',{method:'POST',body:{current:p1.value,password:p2.value}});p1.value='';p2.value='';toast('تم تغيير كلمة المرور');}
    catch(ex){toast(ex.message);}finally{pbtn.disabled=false;}
  }});
  var m;
  m=modal('الإعدادات',h('div',{class:'mb',style:'padding:0'},
    h('div',{class:'prof'},avatar(u.name,'u'+u.id,76)),
    field('الاسم الظاهر',name),field('اسم المستخدم',user),field('النبذة',bio),save,
    h('div',{class:'hr'}),
    h('div',{class:'stitle',text:'المظهر'}),seg,
    h('div',{class:'hr'}),
    h('div',{class:'stitle',text:'كلمة المرور'}),field('الحالية',p1),field('الجديدة',p2),pbtn,
    h('div',{class:'hr'}),
    h('button',{class:'btn ghost block',style:'color:var(--danger);display:flex;align-items:center;justify-content:center;gap:8px',onclick:async function(){
      try{await api('/api/logout',{method:'POST'});}catch(e){}
      m.close();state.me=null;showAuth();}},ic('logout',18),h('span',{text:'تسجيل الخروج'}))));
}

/* ---------- البداية ---------- */
(async function boot(){
  applyTheme();
  try{
    var r=await fetch('/api/me',{credentials:'same-origin'});
    if(r.ok){var d=await r.json();state.me=d.user;showMain();return;}
  }catch(e){}
  showAuth();
})();
})();
</script>
</body>
</html>`;
