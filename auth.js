const jwt = require('jsonwebtoken');
const { getDb } = require('../db');

const DEFAULT_JWT_SECRET = 'CHANGE_ME_IN_LIARA_ENV';
const JWT_SECRET = process.env.JWT_SECRET || DEFAULT_JWT_SECRET;
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;

if (process.env.NODE_ENV === 'production' && JWT_SECRET === DEFAULT_JWT_SECRET) {
  console.warn('[SECURITY] JWT_SECRET is not set. Set it in environment variables to keep sessions secure.');
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '14d' });
}

function clearAuth(res) {
  res.clearCookie('token', { path: '/', domain: COOKIE_DOMAIN });
  res.clearCookie('lang', { path: '/', domain: COOKIE_DOMAIN });
}

function attachUser(req, res, next) {
  req.user = null;
  const token = req.cookies?.token;
  if (!token) return next();
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = getDb();
    const user = db.prepare('SELECT id, first_name, last_name, username, credit, role, token_version FROM users WHERE id=?').get(decoded.id);
    const tv = Number.isFinite(Number(decoded.tv)) ? Number(decoded.tv) : 0;
    if (user && Number(user.token_version || 0) === tv) {
      // Don't leak token_version to views.
      const { token_version, ...safe } = user;
      req.user = safe;
    }
  } catch (e) {}
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/?next=' + encodeURIComponent(req.originalUrl));
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/admin');
  if (req.user.role !== 'admin') return res.status(403).render('pages/error', { title: 'عدم دسترسی', message: 'دسترسی به این بخش مجاز نیست.' });
  next();
}

module.exports = { signToken, clearAuth, attachUser, requireAuth, requireAdmin };
