/* Vira server — بدون هیچ وابستگی (فقط Node 18 به بالا)
   اجرا:  node server.js
   متغیرهای اختیاری:
     PORT        پورت (پیش‌فرض 3000)
     DATA_DIR    پوشه ذخیره داده (پیش‌فرض کنار همین فایل، داخل data/)
     ADMIN_USER  نام کاربری مدیر (پیش‌فرض dev)
     ADMIN_PASS  رمز مدیر (پیش‌فرض 1 — حتماً عوض کنید)
*/
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'vira-data.json');
const INDEX_FILE = path.join(__dirname, 'index.html');
const MAX_BODY = 25 * 1024 * 1024;
const ENV_ADMIN_USER = (process.env.ADMIN_USER || 'dev').toLowerCase();
const ENV_ADMIN_PASS = process.env.ADMIN_PASS || '1';

/* ---------- ذخیره‌سازی (فایل JSON، نوشتن اتمی) ---------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { kv: {}, accounts: {}, tokens: {}, admin: null };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) { /* فایل جدید */ }
let saveTimer = null, saving = false, dirty = false;
function scheduleSave() {
  dirty = true;
  if (saveTimer) return;
  saveTimer = setTimeout(flush, 300);
}
function flush() {
  saveTimer = null;
  if (!dirty || saving) { if (dirty) scheduleSave(); return; }
  saving = true; dirty = false;
  const tmp = DB_FILE + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db), err => {
    if (err) { console.error('save failed:', err.message); dirty = true; saving = false; return scheduleSave(); }
    fs.rename(tmp, DB_FILE, err2 => { if (err2) { console.error('rename failed:', err2.message); dirty = true; } saving = false; if (dirty) scheduleSave(); });
  });
}
function flushSync() { try { fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db)); fs.renameSync(DB_FILE + '.tmp', DB_FILE); } catch (e) {} }
['SIGINT', 'SIGTERM'].forEach(s => process.on(s, () => { flushSync(); process.exit(0); }));

/* ---------- رمز و توکن ---------- */
function hashPass(pass, salt) { return crypto.scryptSync(String(pass), salt, 32).toString('hex'); }
function newPass(pass) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPass(pass, salt) }; }
function checkPass(pass, rec) {
  if (!rec) return false;
  const a = Buffer.from(hashPass(pass, rec.salt), 'hex'), b = Buffer.from(rec.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function issueToken(username, isAdmin) {
  const t = crypto.randomBytes(32).toString('hex');
  db.tokens[sha(t)] = { u: username, a: !!isAdmin, t: Date.now() };
  scheduleSave();
  return t;
}
const TOKEN_TTL = 180 * 24 * 3600 * 1000;
function authOf(req) {
  const h = req.headers['authorization'] || '';
  const t = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!t) return null;
  const rec = db.tokens[sha(t)];
  if (!rec) return null;
  if (Date.now() - rec.t > TOKEN_TTL) { delete db.tokens[sha(t)]; scheduleSave(); return null; }
  return { username: rec.u, isAdmin: rec.a };
}
function adminName() { return (db.admin && db.admin.username) || ENV_ADMIN_USER; }
function checkAdmin(user, pass) {
  if (user !== adminName()) return false;
  if (db.admin && db.admin.hash) return checkPass(pass, db.admin);
  return pass === ENV_ADMIN_PASS;
}

/* ---------- محدودیت تعداد تلاش ---------- */
const hits = new Map();
function limited(ip, bucket, max, windowMs) {
  const k = bucket + '|' + ip, now = Date.now();
  const arr = (hits.get(k) || []).filter(t => now - t < windowMs);
  arr.push(now); hits.set(k, arr);
  return arr.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();
function ipOf(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?'; }

/* ---------- ابزار پاسخ ---------- */
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(Object.assign(new Error('bad json'), { status: 400 })); } });
    req.on('error', reject);
  });
}

/* ---------- قوانین دسترسی به کلیدها ---------- */
function parseJSON(s) { try { return JSON.parse(s); } catch (e) { return null; } }
function isParticipant(msg, me) { return !!msg && (msg.from === me || msg.to === me); }
function canReadKey(key, value, auth) {
  if (key.startsWith('messages:')) return !!auth && (auth.isAdmin || isParticipant(parseJSON(value), auth.username));
  if (key === 'admin-profile') return true; // رمز در خروجی حذف می‌شود
  return true;
}
function publicValue(key, value, auth) {
  if (key === 'admin-profile' && !(auth && auth.isAdmin)) {
    const o = parseJSON(value); if (o && typeof o === 'object') { delete o.password; return JSON.stringify(o); }
  }
  return value;
}
function canWriteKey(key, newValue, auth) {
  if (auth.isAdmin) return true;
  if (key === 'admin-profile') return false;
  if (key.startsWith('messages:')) {
    const old = db.kv[key];
    if (old !== undefined) return isParticipant(parseJSON(old), auth.username);
    const m = parseJSON(newValue); return !!m && m.from === auth.username;
  }
  return true;
}
function suspended(username) {
  const u = parseJSON(db.kv['users:' + username]);
  return !!(u && u.suspended);
}

/* ---------- مسیرها ---------- */
async function handleApi(req, res, url) {
  const p = url.pathname;
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Max-Age': '86400' }); return res.end(); }
  if (p === '/api/health') return send(res, 200, { ok: true });

  if (p === '/api/register' && req.method === 'POST') {
    if (limited(ipOf(req), 'reg', 10, 3600e3)) return send(res, 429, { error: 'rate' });
    const b = await readBody(req);
    const username = String(b.username || '').trim().toLowerCase(), password = String(b.password || '');
    if (!/^[a-z0-9_]{3,20}$/.test(username) || password.length < 4 || password.length > 200) return send(res, 400, { error: 'invalid' });
    if (username === adminName() || db.accounts[username]) return send(res, 409, { error: 'taken' });
    db.accounts[username] = Object.assign(newPass(password), { created: Date.now() });
    const token = issueToken(username, false);
    return send(res, 200, { token, username });
  }

  if (p === '/api/login' && req.method === 'POST') {
    if (limited(ipOf(req), 'login', 20, 600e3)) return send(res, 429, { error: 'rate' });
    const b = await readBody(req);
    const username = String(b.username || '').trim().toLowerCase(), password = String(b.password || '');
    if (checkAdmin(username, password)) return send(res, 200, { token: issueToken(username, true), username, isAdmin: true });
    const acc = db.accounts[username];
    if (!acc || !checkPass(password, acc)) return send(res, 401, { error: 'bad credentials' });
    if (suspended(username)) return send(res, 403, { error: 'suspended' });
    return send(res, 200, { token: issueToken(username, false), username, isAdmin: false });
  }

  if (p === '/api/kv' && req.method === 'GET') {
    const auth = authOf(req);
    const prefix = url.searchParams.get('prefix') || '', withValues = url.searchParams.get('values') === '1';
    const keys = [], items = {};
    for (const k of Object.keys(db.kv)) {
      if (!k.startsWith(prefix) || !canReadKey(k, db.kv[k], auth)) continue;
      keys.push(k); if (withValues) items[k] = publicValue(k, db.kv[k], auth);
    }
    return send(res, 200, withValues ? { keys, items } : { keys });
  }

  if (p.startsWith('/api/kv/')) {
    const key = decodeURIComponent(p.slice(8));
    if (!key || key.length > 300) return send(res, 400, { error: 'bad key' });
    const auth = authOf(req);
    if (req.method === 'GET') {
      const v = db.kv[key];
      if (v === undefined || !canReadKey(key, v, auth)) return send(res, 404, { error: 'not found' });
      return send(res, 200, { value: publicValue(key, v, auth) });
    }
    if (!auth) return send(res, 401, { error: 'auth' });
    if (!auth.isAdmin && suspended(auth.username)) return send(res, 401, { error: 'suspended' });
    if (req.method === 'PUT') {
      const b = await readBody(req);
      if (typeof b.value !== 'string') return send(res, 400, { error: 'value must be string' });
      if (!canWriteKey(key, b.value, auth)) return send(res, 403, { error: 'forbidden' });
      if (key === 'admin-profile') { // رمز/نام مدیر از تنظیمات داخل اپ هم روی سرور اعمال شود
        const o = parseJSON(b.value);
        if (o && typeof o === 'object') {
          const next = { username: String(o.username || adminName()).toLowerCase() };
          if (o.password) Object.assign(next, newPass(o.password)); else if (db.admin && db.admin.hash) Object.assign(next, { salt: db.admin.salt, hash: db.admin.hash });
          db.admin = next;
          delete o.password; b.value = JSON.stringify(o);
        }
      }
      db.kv[key] = b.value; scheduleSave();
      return send(res, 200, { ok: true });
    }
    if (req.method === 'DELETE') {
      if (db.kv[key] !== undefined && !canWriteKey(key, db.kv[key], auth)) return send(res, 403, { error: 'forbidden' });
      delete db.kv[key]; scheduleSave();
      return send(res, 200, { ok: true });
    }
  }
  return send(res, 404, { error: 'not found' });
}

/* ---------- فایل اپ (فشرده‌شده) ---------- */
let indexRaw = null, indexGz = null;
function loadIndex() {
  try { indexRaw = fs.readFileSync(INDEX_FILE); indexGz = zlib.gzipSync(indexRaw, { level: 9 }); }
  catch (e) { indexRaw = Buffer.from('index.html پیدا نشد. آن را کنار server.js بگذارید.'); indexGz = null; }
}
loadIndex();
function serveIndex(req, res) {
  const gz = indexGz && /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  const h = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' };
  if (gz) h['Content-Encoding'] = 'gzip';
  res.writeHead(200, h);
  res.end(gz ? indexGz : indexRaw);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (url.pathname === '/' || url.pathname === '/index.html') return serveIndex(req, res);
    if (url.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('not found');
  } catch (e) {
    if (!res.headersSent) send(res, e.status || 500, { error: e.message || 'server error' }); else res.end();
    if (!e.status) console.error(e);
  }
});
server.requestTimeout = 60000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('Vira server on http://0.0.0.0:' + PORT + '  (data: ' + DB_FILE + ')');
  if (adminName() === 'dev' && !(db.admin && db.admin.hash) && ENV_ADMIN_PASS === '1') console.warn('!! رمز مدیر هنوز پیش‌فرض است (dev / 1). ADMIN_PASS را تنظیم کنید.');
});
