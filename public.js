const r = require('express').Router();
const bcrypt = require('bcryptjs');
const { getDb } = require('../db');
const { signToken, clearAuth } = require('../middleware/auth');
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;

function onlyDigits(s='') { return String(s).replace(/\D/g, ''); }

r.get('/', (req, res) => {
  const err = req.query.err || '';
  const ok = req.query.ok || '';
  const db = getDb();
  let banner='';
  try { banner = (db.prepare("SELECT value FROM settings WHERE key='landing_banner'").get() || {}).value || ''; } catch(e) { banner=''; }
  // fallback banner (keeps the landing page on-brand even before admin uploads one)
  if (!banner) banner = '/images/gzone-sign.jpeg';
  res.render('pages/landing', { title: res.locals.t('brand'), user: req.user, err, ok, banner });
});

r.post('/register', (req, res) => {
  const { first_name, last_name, phone, username, password } = req.body;
  if (!first_name || !last_name || !phone || !username || !password) {
    return res.redirect('/?err=' + encodeURIComponent('لطفاً همه فیلدها را کامل کنید.'));
  }

  const db = getDb();
  const u = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (u) return res.redirect('/?err=' + encodeURIComponent('این یوزرنیم قبلاً ثبت شده است.'));

  const phoneNorm = onlyDigits(phone).slice(0, 15);
  const hash = bcrypt.hashSync(password, 10);

  const info = db.prepare(`
    INSERT INTO users (first_name, last_name, phone, username, password_hash, credit, role)
    VALUES (?, ?, ?, ?, ?, 0, 'user')
  `).run(first_name.trim(), last_name.trim(), phoneNorm, username.trim(), hash);

  const token = signToken({ id: info.lastInsertRowid, tv: 0 });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', domain: COOKIE_DOMAIN, secure: process.env.COOKIE_SECURE === '1' });
  res.redirect('/dashboard');
});

r.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.redirect('/?err=' + encodeURIComponent('یوزرنیم و پسورد را وارد کنید.'));

  const db = getDb();
  const user = db.prepare('SELECT id, password_hash, role, token_version FROM users WHERE username=?').get(username.trim());
  if (!user) return res.redirect('/?err=' + encodeURIComponent('اطلاعات ورود نادرست است.'));

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.redirect('/?err=' + encodeURIComponent('اطلاعات ورود نادرست است.'));

  const token = signToken({ id: user.id, tv: Number(user.token_version || 0) });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', domain: COOKIE_DOMAIN, secure: process.env.COOKIE_SECURE === '1' });

  if (user.role === 'admin') return res.redirect('/admin/dashboard');
  res.redirect('/dashboard');
});

r.get('/logout', (req, res) => {
  clearAuth(res);
  res.redirect('/?ok=' + encodeURIComponent('خارج شدید.'));
});

module.exports = r;
