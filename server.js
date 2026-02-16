const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const compression = require('compression');

const { initDb } = require('./src/db');
const { attachUser } = require('./src/middleware/auth');
const { t: i18nT } = require('./src/i18n');

const app = express();

// Behind reverse proxies (Liara/Nginx), trust X-Forwarded-* so req.secure works.
app.set('trust proxy', 1);
app.disable('x-powered-by');

// Health check (for Liara/monitoring) - MUST NOT redirect.
// Liara may check over HTTP or with internal Host; return 200 regardless.
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
});


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src', 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Gzip responses (HTML/JSON/CSS/JS) to improve load speed.
app.use(compression());

// Force HTTPS + (optional) canonical host redirect.
// هدف: کاربر هرجوری وارد شد (http/https, www/بدون-www) به یک آدرس امن هدایت شود.
// نکته مهم: Healthcheck و درخواست‌های داخلی نباید ریدایرکت شوند، وگرنه پلتفرم برنامه را Kill می‌کند.
app.use((req, res, next) => {
  // Never redirect health checks.
  if (req.path === '/health') return next();

  const forceHttps = (process.env.FORCE_HTTPS === '1') ||
    (process.env.NODE_ENV === 'production' && process.env.FORCE_HTTPS !== '0');

  // Prefer forwarded headers (behind proxy). If missing, DON'T force redirects
  // (this keeps internal health checks working).
  const xfProto = (req.headers['x-forwarded-proto'] || '').toString().toLowerCase();
  const xfHostRaw = (req.headers['x-forwarded-host'] || '').toString().trim();

  // If x-forwarded-proto explicitly says http, then we know it's an insecure request.
  const isKnownHttp = xfProto === 'http';
  const isKnownHttps = xfProto === 'https';

  // Canonical host redirect only when we know the public host via x-forwarded-host/host.
  const canonical = String(process.env.CANONICAL_HOST || '').trim().toLowerCase().replace(/:\d+$/, '');

  const rawHost = (xfHostRaw || String(req.headers.host || '')).trim();
  const hostNoPort = rawHost.toLowerCase().replace(/:\d+$/, '');

  // HTTPS redirect (only when we are sure request came via http).
  if (forceHttps && isKnownHttp) {
    return res.redirect(301, 'https://' + hostNoPort + req.originalUrl);
  }

  // Canonical host redirect (only when canonical is set and we have a meaningful host).
  // We avoid redirecting if the host is empty or looks like an internal/localhost host.
  if (canonical && hostNoPort && hostNoPort !== 'localhost' && !/^(127\.0\.0\.1|0\.0\.0\.0)$/.test(hostNoPort)) {
    if (hostNoPort !== canonical) {
      // Keep protocol if known, otherwise default to https when in production and FORCE_HTTPS is enabled.
      const proto = isKnownHttps ? 'https' : (isKnownHttp ? 'http' : ((forceHttps) ? 'https' : 'http'));
      return res.redirect(301, proto + '://' + canonical + req.originalUrl);
    }
  }

  // HSTS: only send when request is known HTTPS (browser will enforce after first secure visit)
  if (forceHttps && isKnownHttps) {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }

  next();
});

// Public static assets (cache to improve performance)
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.STATIC_MAX_AGE || '7d',
  etag: true,
  lastModified: true
}));

// Persistent uploads (Liara Disk)
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/data/uploads';
app.use('/uploads', express.static(UPLOAD_DIR, {
  maxAge: process.env.UPLOADS_MAX_AGE || '1d',
  etag: true,
  lastModified: true
}));

// Attach user to request if token exists
app.use(attachUser);

// Language (fa/en) with RTL/LTR
app.use((req, res, next) => {
  const q = (req.query.lang || '').toString().toLowerCase();
  let lang = (req.cookies?.lang || 'fa').toString().toLowerCase();
  if (q === 'fa' || q === 'en') {
    lang = q;
    res.cookie('lang', lang, { httpOnly: false, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 365 });
  }
  res.locals.lang = (lang === 'en') ? 'en' : 'fa';
  res.locals.dir = (res.locals.lang === 'fa') ? 'rtl' : 'ltr';
  res.locals.isRTL = res.locals.lang === 'fa';
  res.locals.t = (key, vars) => i18nT(res.locals.lang, key, vars);
      res.locals.currentUrl = req.originalUrl;
  next();
});

// Language switcher endpoint
app.get('/lang/:code', (req, res) => {
  const code = (req.params.code || '').toLowerCase();
  const lang = (code === 'en') ? 'en' : 'fa';
  res.cookie('lang', lang, { httpOnly: false, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 365 });
  const nextUrl = (req.query.next || '/').toString();
  res.redirect(nextUrl);
});


// Init DB + seed menu/admin if needed (async for sql.js)
const startServer = async () => {
  await initDb();

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`G-Zone Cafe running on ${PORT}`));
};


// Routes
app.use('/', require('./src/routes/public'));
app.use('/', require('./src/routes/user'));
app.use('/admin', require('./src/routes/admin'));

// 404
app.use((req, res) => {
  res.status(404).render('pages/error', { title: res.locals.t('not_found_title'), message: res.locals.t('not_found_msg') });
});



/* error handler */
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  try {
    return res.status(500).render('pages/error', {
      title: res.locals.t('internal_error_title'),
      message: 'مشکلی در سرور رخ داد. لطفاً چند دقیقه بعد دوباره تلاش کنید.'
    });
  } catch (e) {
    return res.status(500).send('Internal Server Error');
  }
});

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
