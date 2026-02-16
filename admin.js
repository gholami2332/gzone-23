const r = require('express').Router();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { getDb, UPLOAD_DIR } = require('../db');
const { signToken, clearAuth, requireAdmin } = require('../middleware/auth');
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;

// Report timezone: default is Tehran (+03:30 => 210 minutes)
const REPORT_TZ_OFFSET_MINUTES = Number.isFinite(Number(process.env.REPORT_TZ_OFFSET_MINUTES))
  ? Number(process.env.REPORT_TZ_OFFSET_MINUTES)
  : 210;
const REPORT_TZ_SQL_MOD = `${REPORT_TZ_OFFSET_MINUTES >= 0 ? '+' : ''}${REPORT_TZ_OFFSET_MINUTES} minutes`;

// ---- Helpers: robust number parsing (supports Persian/Arabic digits + commas) ----
function toEnglishDigits(input = '') {
  return String(input)
    // Persian digits
    .replace(/[۰-۹]/g, (d) => String('0123456789'[d.charCodeAt(0) - 1776]))
    // Arabic digits
    .replace(/[٠-٩]/g, (d) => String('0123456789'[d.charCodeAt(0) - 1632]));
}

function parseMoney(input, fallback = 0) {
  const s = toEnglishDigits(input)
    .replace(/[\s,٬_]/g, '')
    .trim();
  const n = Number(s);
  if (!Number.isFinite(n)) return fallback;
  return n;
}

function parseIntSafe(input, fallback = 0) {
  const n = parseInt(toEnglishDigits(input).replace(/[\s,٬_]/g, ''), 10);
  return Number.isFinite(n) ? n : fallback;
}


function normalizeIsoDate(input = '') {
  const pad = (n) => String(n).padStart(2, '0');
  const s = toEnglishDigits(String(input || '')).trim();
  if (!s) return '';

  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (m) return `${m[1]}-${pad(m[2])}-${pad(m[3])}`;

  m = s.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})$/);
  if (m) return `${m[1]}-${pad(m[2])}-${pad(m[3])}`;

  // Safari sometimes shows "Dec 3, 2025" visually; accept it if it ever reaches the backend.
  if (/[A-Za-z]/.test(s)) {
    const d = new Date(s);
    if (!Number.isNaN(d.getTime())) return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }

  const d2 = new Date(s);
  if (!Number.isNaN(d2.getTime())) return `${d2.getFullYear()}-${pad(d2.getMonth() + 1)}-${pad(d2.getDate())}`;
  return '';
}

function parseDateRange(q) {
  const pad = (n) => String(n).padStart(2, '0');

  const fromIsoRaw = normalizeIsoDate(q.from);
  const toIsoRaw = normalizeIsoDate(q.to);

  // Default range = "today" in the configured report timezone
  const nowTz = new Date(Date.now() + (REPORT_TZ_OFFSET_MINUTES * 60 * 1000));
  const todayIso = `${nowTz.getUTCFullYear()}-${pad(nowTz.getUTCMonth() + 1)}-${pad(nowTz.getUTCDate())}`;

  let fromIso = fromIsoRaw || todayIso;
  let toIso = toIsoRaw || todayIso;

  // If only one side is provided, mirror the other side.
  if (fromIsoRaw && !toIsoRaw) toIso = fromIso;
  if (!fromIsoRaw && toIsoRaw) fromIso = toIso;

  // Guard: swap if inverted.
  if (fromIso > toIso) {
    const tmp = fromIso;
    fromIso = toIso;
    toIso = tmp;
  }

  return { fromIso, toIso };
}

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    const dir = path.join(UPLOAD_DIR, 'products');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function(req, file, cb) {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase();
    const safeExt = ['.jpg','.jpeg','.png','.webp'].includes(ext) ? ext : '.jpg';
    cb(null, `product_${req.params.id}_${Date.now()}${safeExt}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '').toLowerCase();
    cb(['.jpg','.jpeg','.png','.webp'].includes(ext) ? null : new Error('فرمت فایل مجاز نیست.'), ['.jpg','.jpeg','.png','.webp'].includes(ext));
  }
});

const iconStorage = multer.diskStorage({
  destination: function(req, file, cb) {
    const dir = path.join(UPLOAD_DIR, 'icons');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function(req, file, cb) {
    const ext = (path.extname(file.originalname) || '').toLowerCase();
    const safeExt = ['.svg','.jpg','.jpeg','.png','.webp'].includes(ext) ? ext : '.png';
    cb(null, `icon_${Date.now()}${safeExt}`);
  }
});

const iconUpload = multer({
  storage: iconStorage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '').toLowerCase();
    cb(['.svg','.jpg','.jpeg','.png','.webp'].includes(ext) ? null : new Error('فرمت فایل مجاز نیست.'), ['.svg','.jpg','.jpeg','.png','.webp'].includes(ext));
  }
});

r.get('/', (req, res) => {
  if (req.user && req.user.role === 'admin') return res.redirect('/admin/dashboard');
  const err = req.query.err || '';
  res.render('pages/admin_login', { title: res.locals.t('admin_login'), user: req.user, err });
});

r.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = getDb();
  const u = db.prepare('SELECT id, password_hash, role, token_version FROM users WHERE username=?').get(String(username||'').trim());
  if (!u || u.role !== 'admin') return res.redirect('/admin?err=' + encodeURIComponent('ادمین پیدا نشد.'));
  const ok = bcrypt.compareSync(String(password||''), u.password_hash);
  if (!ok) return res.redirect('/admin?err=' + encodeURIComponent('اطلاعات ورود نادرست است.'));
  const token = signToken({ id: u.id, tv: Number(u.token_version || 0) });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', domain: COOKIE_DOMAIN, secure: process.env.COOKIE_SECURE === '1' });
  res.redirect('/admin/dashboard');
});

r.get('/logout', (req, res) => {
  clearAuth(res);
  res.redirect('/admin');
});

// ---- Change password (admin) ----
r.get('/password', requireAdmin, (req, res) => {
  const err = req.query.err || '';
  const ok = req.query.ok || '';
  res.render('pages/admin_password', { title: res.locals.t('change_password'), user: req.user, err, ok });
});

r.post('/password', requireAdmin, (req, res) => {
  const oldPw = String(req.body.old_password || '');
  const newPw = String(req.body.new_password || '');
  const newPw2 = String(req.body.new_password2 || '');

  if (!oldPw || !newPw || !newPw2) {
    return res.redirect('/admin/password?err=' + encodeURIComponent('لطفاً همه فیلدها را کامل کنید.'));
  }
  if (newPw !== newPw2) {
    return res.redirect('/admin/password?err=' + encodeURIComponent('پسورد جدید و تکرار آن یکسان نیست.'));
  }
  if (newPw.length < 8) {
    return res.redirect('/admin/password?err=' + encodeURIComponent('پسورد جدید باید حداقل ۸ کاراکتر باشد.'));
  }

  const db = getDb();
  const row = db.prepare('SELECT id, password_hash, token_version FROM users WHERE id=?').get(req.user.id);
  if (!row) return res.redirect('/admin/logout');

  const okOld = bcrypt.compareSync(oldPw, row.password_hash);
  if (!okOld) {
    return res.redirect('/admin/password?err=' + encodeURIComponent('پسورد فعلی نادرست است.'));
  }

  const newHash = bcrypt.hashSync(newPw, 12);
  db.prepare('UPDATE users SET password_hash=?, token_version=token_version+1 WHERE id=?').run(newHash, req.user.id);
  const newTv = Number(row.token_version || 0) + 1;

  const token = signToken({ id: req.user.id, tv: newTv });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', domain: COOKIE_DOMAIN, secure: process.env.COOKIE_SECURE === '1' });

  return res.redirect('/admin/password?ok=' + encodeURIComponent('پسورد با موفقیت تغییر کرد.'));
});

r.get('/dashboard', requireAdmin, (req, res) => {
  try {
    const db = getDb();
    // If DB is from an old version and role column is missing, fall back gracefully.
    let usersCount = 0;
    try {
      usersCount = db.prepare("SELECT COUNT(1) c FROM users WHERE role='user'").get().c;
    } catch (e) {
      usersCount = db.prepare("SELECT COUNT(1) c FROM users").get().c;
    }
    const productsCount = db.prepare('SELECT COUNT(1) c FROM products').get().c;
    const ordersCount = db.prepare('SELECT COUNT(1) c FROM orders').get().c;
    res.render('pages/admin_dashboard', { title: res.locals.t('admin_dashboard'), user: req.user, usersCount, productsCount, ordersCount });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    return res.status(500).render('pages/error', { title: res.locals.t('admin_dashboard'), message: 'مشکلی در بارگذاری داشبورد رخ داد. لاگ‌ها را بررسی کنید.' });
  }
});

r.get('/products', requireAdmin, (req, res) => {
  const db = getDb();
  const q = String(req.query.q || '').trim();
  const categories = db.prepare('SELECT * FROM categories ORDER BY sort_order, id').all();
  const products = q
    ? db.prepare('SELECT p.*, c.title AS category_title, c.title_en AS category_title_en FROM products p JOIN categories c ON c.id=p.category_id WHERE (p.title LIKE ? OR p.title_en LIKE ?) ORDER BY p.id DESC').all('%'+q+'%','%'+q+'%')
    : db.prepare('SELECT p.*, c.title AS category_title, c.title_en AS category_title_en FROM products p JOIN categories c ON c.id=p.category_id ORDER BY p.category_id, p.sort_order, p.id').all();
  res.render('pages/admin_products', { title: res.locals.t('manage_menu'), user: req.user, categories, products, q, ok: req.query.ok||'', err: req.query.err||'' });
});

r.get('/products/new', requireAdmin, (req, res) => {
  const db = getDb();
  const categories = db.prepare('SELECT * FROM categories ORDER BY sort_order, id').all();
  res.render('pages/admin_product_edit', {
    title: res.locals.t('new_product'),
    user: req.user,
    categories,
    product: { id:null, title:'', description:'', price:0, category_id: categories[0]?.id, is_active:1, image:'/images/placeholder.png', sort_order: 1 },
    mode:'new',
    ok:'',
    err:''
  });
});

r.post('/products/new', requireAdmin, (req, res) => {
  const { title, title_en, description, description_en, price, category_id, is_active, sort_order } = req.body;
  const db = getDb();
  if (!title || !category_id) return res.redirect('/admin/products?err=' + encodeURIComponent('عنوان و دسته‌بندی الزامی است.'));

  try {
    const catId = parseIntSafe(category_id, 0);
    const p = Math.max(0, parseMoney(price, 0));
    const so = Math.max(0, parseIntSafe(sort_order, 1) || 1);

    db.prepare(`
      INSERT INTO products (category_id, title, title_en, description, description_en, price, image, is_active, sort_order)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      catId,
      String(title).trim(),
      String(title_en || '').trim(),
      String(description || '').trim(),
      String(description_en || '').trim(),
      p,
      '/images/placeholder.png',
      Number(is_active ? 1 : 0),
      so
    );

    res.redirect('/admin/products?ok=' + encodeURIComponent('محصول ایجاد شد.'));
  } catch (e) {
    console.error('Create product error:', e);
    res.redirect('/admin/products?err=' + encodeURIComponent('خطا در ساخت محصول. مقدار قیمت/دسته‌بندی را بررسی کنید.'));
  }
});

r.get('/products/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const db = getDb();
  const categories = db.prepare('SELECT * FROM categories ORDER BY sort_order, id').all();
  const product = db.prepare('SELECT * FROM products WHERE id=?').get(id);
  if (!product) return res.redirect('/admin/products?err=' + encodeURIComponent('محصول یافت نشد.'));
  res.render('pages/admin_product_edit', { title: res.locals.t('edit'), user:req.user, categories, product, mode:'edit', ok:req.query.ok||'', err:req.query.err||'' });
});

r.post('/products/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { title, title_en, description, description_en, price, category_id, is_active, sort_order } = req.body;
  const db = getDb();

  try {
    const catId = parseIntSafe(category_id, 0);
    const p = Math.max(0, parseMoney(price, 0));
    const so = Math.max(0, parseIntSafe(sort_order, 1) || 1);

    db.prepare(`
      UPDATE products
      SET category_id=?, title=?, title_en=?, description=?, description_en=?, price=?, is_active=?, sort_order=?
      WHERE id=?
    `).run(
      catId,
      String(title || '').trim(),
      String(title_en || '').trim(),
      String(description || '').trim(),
      String(description_en || '').trim(),
      p,
      Number(is_active ? 1 : 0),
      so,
      id
    );

    res.redirect(`/admin/products/${id}?ok=${encodeURIComponent('ذخیره شد.')}`);
  } catch (e) {
    console.error('Update product error:', e);
    res.redirect(`/admin/products/${id}?err=${encodeURIComponent('خطا در ذخیره. قیمت را بدون ویرگول/حروف وارد کنید.')}`);
  }
});

r.post('/products/:id/image', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  upload.single('image')(req, res, (err) => {
    if (err) return res.redirect(`/admin/products/${id}?err=${encodeURIComponent(err.message||'خطا در آپلود')}`);
    const file = req.file;
    if (!file) return res.redirect(`/admin/products/${id}?err=${encodeURIComponent('فایلی انتخاب نشده است.')}`);
    const imgPath = '/uploads/products/' + file.filename;
    const db = getDb();
    db.prepare('UPDATE products SET image=? WHERE id=?').run(imgPath, id);
    res.redirect(`/admin/products/${id}?ok=${encodeURIComponent('عکس آپلود شد.')}`);
  });
});

r.post('/products/:id/deactivate', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const db = getDb();
  db.prepare('UPDATE products SET is_active=0 WHERE id=?').run(id);
  res.redirect('/admin/products?ok=' + encodeURIComponent('محصول غیرفعال شد.'));
});

r.get('/users', requireAdmin, (req, res) => {
  const db = getDb();
  const users = db.prepare('SELECT id, first_name, last_name, phone, username, credit, created_at FROM users WHERE role=? ORDER BY id DESC').all('user');
  res.render('pages/admin_users', { title: res.locals.t('users'), user:req.user, users, ok:req.query.ok||'', err:req.query.err||'' });
});

r.get('/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const db = getDb();
  const u = db.prepare('SELECT id, first_name, last_name, phone, username, credit, created_at FROM users WHERE id=?').get(id);
  if (!u) return res.redirect('/admin/users?err=' + encodeURIComponent('کاربر یافت نشد.'));
  const orders = db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(id);
  res.render('pages/admin_user_edit', { title: res.locals.t('edit'), user:req.user, u, orders, ok:req.query.ok||'', err:req.query.err||'' });
});

r.post('/users/:id/credit', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const delta = Number(req.body.delta || 0);
  const reason = String(req.body.reason || 'تغییر دستی اعتبار');
  const db = getDb();

  db.transaction(() => {
    db.prepare('UPDATE users SET credit = credit + ? WHERE id=?').run(delta, id);
    db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      id,
      Math.abs(delta),
      delta >= 0 ? 'credit' : 'debit',
      reason
    );
  })();

  res.redirect(`/admin/users/${id}?ok=${encodeURIComponent('اعتبار بروزرسانی شد.')}`);
});

r.get('/orders', requireAdmin, (req, res) => {
  const db = getDb();
  const orders = db.prepare(`
    SELECT o.*, u.username, u.first_name, u.last_name
    FROM orders o
    JOIN users u ON u.id=o.user_id
    ORDER BY o.id DESC
    LIMIT 200
  `).all();
  res.render('pages/admin_orders', { title: res.locals.t('orders'), user:req.user, orders, ok:req.query.ok||'', err:req.query.err||'' });
});

r.get('/orders/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const db = getDb();
  const order = db.prepare(`
    SELECT o.*, u.username, u.first_name, u.last_name
    FROM orders o JOIN users u ON u.id=o.user_id
    WHERE o.id=?
  `).get(id);
  if (!order) return res.redirect('/admin/orders?err=' + encodeURIComponent('سفارش یافت نشد.'));
  const items = db.prepare('SELECT * FROM order_items WHERE order_id=? ORDER BY product_id').all(id);
  res.render('pages/admin_order_edit', { title: res.locals.t('orders'), user:req.user, order, items, ok:req.query.ok||'', err:req.query.err||'' });
});

r.post('/orders/:id/time', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const created_at = String(req.body.created_at || '').trim();
  if (!created_at) return res.redirect(`/admin/orders/${id}?err=` + encodeURIComponent('زمان خالی است.'));
  const db = getDb();
  db.prepare('UPDATE orders SET created_at=? WHERE id=?').run(created_at, id);
  res.redirect(`/admin/orders/${id}?ok=` + encodeURIComponent('زمان سفارش تغییر کرد.'));
});

r.post('/orders/:id/refund', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const db = getDb();
  const tx = db.transaction(() => {
    const order = db.prepare('SELECT * FROM orders WHERE id=?').get(id);
    if (!order) throw new Error('سفارش یافت نشد.');
    if (order.status === 'refunded') throw new Error('این سفارش قبلاً برگشت خورده است.');
    db.prepare('UPDATE users SET credit = credit + ? WHERE id=?').run(order.total, order.user_id);
    db.prepare('UPDATE orders SET status=? WHERE id=?').run('refunded', id);
    db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      order.user_id, order.total, 'credit', `بازگشت وجه سفارش #${id}`
    );
  });
  try {
    tx();
    res.redirect(`/admin/orders/${id}?ok=` + encodeURIComponent('سفارش برگشت داده شد و اعتبار اضافه شد.'));
  } catch (e) {
    res.redirect(`/admin/orders/${id}?err=` + encodeURIComponent(e.message || 'خطا'));
  }
});


/** Categories CRUD **/
r.get('/categories', requireAdmin, (req, res) => {
  const db = getDb();
  const categories = db.prepare('SELECT * FROM categories ORDER BY sort_order, id').all();
  res.render('pages/admin_categories', {
    title: res.locals.t('categories'),
    user: req.user,
    categories,
    ok: req.query.ok || '',
    err: req.query.err || ''
  });
});

r.get('/categories/new', requireAdmin, (req, res) => {
  res.render('pages/admin_category_edit', {
    title: res.locals.t('new_category'),
    user: req.user,
    category: { title: '', title_en: '', icon: '', sort_order: 10 },
    ok: req.query.ok || '',
    err: req.query.err || ''
  });
});

r.post('/categories/new', requireAdmin, iconUpload.single('icon'), (req, res) => {
  const db = getDb();
  const title = String(req.body.title || '').trim();
  const title_en = String(req.body.title_en || '').trim();
  const sort_order = Number(req.body.sort_order || 0) || 0;
  const icon = req.file ? ('/uploads/icons/' + req.file.filename) : '';

  if (!title) return res.redirect('/admin/categories/new?err=' + encodeURIComponent('عنوان اجباری است.'));

  try {
    db.prepare('INSERT INTO categories (title, title_en, icon, sort_order) VALUES (?, ?, ?, ?)').run(title, title_en, icon, sort_order);
    res.redirect('/admin/categories?ok=' + encodeURIComponent('دسته‌بندی اضافه شد.'));
  } catch (e) {
    res.redirect('/admin/categories/new?err=' + encodeURIComponent(e.message || 'خطا'));
  }
});

r.get('/categories/:id', requireAdmin, (req, res) => {
  const db = getDb();
  const id = Number(req.params.id);
  const category = db.prepare('SELECT * FROM categories WHERE id=?').get(id);
  if (!category) return res.redirect('/admin/categories?err=' + encodeURIComponent('یافت نشد.'));
  res.render('pages/admin_category_edit', {
    title: res.locals.t('edit'),
    user: req.user,
    category,
    ok: req.query.ok || '',
    err: req.query.err || ''
  });
});

r.post('/categories/:id', requireAdmin, iconUpload.single('icon'), (req, res) => {
  const db = getDb();
  const id = Number(req.params.id);
  const title = String(req.body.title || '').trim();
  const title_en = String(req.body.title_en || '').trim();
  const sort_order = Number(req.body.sort_order || 0) || 0;
  const existing = db.prepare('SELECT icon FROM categories WHERE id=?').get(id);
  const icon = req.file ? ('/uploads/icons/' + req.file.filename) : (existing?.icon || '');

  if (!title) return res.redirect(`/admin/categories/${id}?err=` + encodeURIComponent('عنوان اجباری است.'));

  try {
    db.prepare('UPDATE categories SET title=?, title_en=?, icon=?, sort_order=? WHERE id=?').run(title, title_en, icon, sort_order, id);
    res.redirect('/admin/categories?ok=' + encodeURIComponent('ویرایش شد.'));
  } catch (e) {
    res.redirect(`/admin/categories/${id}?err=` + encodeURIComponent(e.message || 'خطا'));
  }
});

r.post('/categories/:id/delete', requireAdmin, (req, res) => {
  const db = getDb();
  const id = Number(req.params.id);
  const used = db.prepare('SELECT COUNT(1) AS c FROM products WHERE category_id=?').get(id)?.c || 0;
  if (used > 0) return res.redirect('/admin/categories?err=' + encodeURIComponent('این دسته دارای محصول است و قابل حذف نیست.'));
  db.prepare('DELETE FROM categories WHERE id=?').run(id);
  res.redirect('/admin/categories?ok=' + encodeURIComponent('حذف شد.'));
});

/** Reports **/
// Branding / assets
r.get('/branding', requireAdmin, (req, res) => {
  const db = getDb();
  const banner = (db.prepare("SELECT value FROM settings WHERE key='landing_banner'").get() || {}).value || '';
  res.render('pages/admin_branding', { title: res.locals.t('brand') + ' — Branding', user: req.user, banner });
});

// Branding banner upload (saved directly under UPLOAD_DIR so it is served on: /uploads/<file>)
const brandingStorage = multer.diskStorage({
  destination: function(req, file, cb) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    cb(null, UPLOAD_DIR);
  },
  filename: function(req, file, cb) {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase();
    const safeExt = ['.jpg','.jpeg','.png','.webp'].includes(ext) ? ext : '.jpg';
    cb(null, `banner_${Date.now()}${safeExt}`);
  }
});

const brandingUpload = multer({
  storage: brandingStorage,
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '').toLowerCase();
    cb(['.jpg','.jpeg','.png','.webp'].includes(ext) ? null : new Error('فرمت فایل مجاز نیست.'), ['.jpg','.jpeg','.png','.webp'].includes(ext));
  }
});

r.post('/branding/banner', requireAdmin, brandingUpload.single('banner'), (req, res) => {
  const db = getDb();
  const filePath = req.file ? `/uploads/${req.file.filename}` : '';
  if (filePath) {
    db.prepare("INSERT INTO settings (key, value) VALUES ('landing_banner', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(filePath);
  }
  res.redirect('/admin/branding');
});

r.get('/reports', requireAdmin, (req, res) => {
  const db = getDb();
  const { fromIso, toIso } = parseDateRange(req.query);

  // Convert a LOCAL date-range (in the report timezone) into a UTC [start, end) range,
  // then compare it against created_at (which is typically SQLite CURRENT_TIMESTAMP => UTC).
  const UTC_FROM_LOCAL_MOD = `${-REPORT_TZ_OFFSET_MINUTES >= 0 ? '+' : ''}${-REPORT_TZ_OFFSET_MINUTES} minutes`;

  // Normalize created_at into a UTC datetime string (YYYY-MM-DD HH:MM:SS)
  // Supports: sqlite CURRENT_TIMESTAMP text, unix seconds, unix milliseconds.
  // Normalize Persian/Arabic digits -> ASCII so reports don't break if dates are entered with localized numbers.
  const normalizeDigitsSql = (expr) => {
    // Persian: ۰۱۲۳۴۵۶۷۸۹  | Arabic-Indic: ٠١٢٣٤٥٦٧٨٩
    return [
      ['۰','0'], ['۱','1'], ['۲','2'], ['۳','3'], ['۴','4'],
      ['۵','5'], ['۶','6'], ['۷','7'], ['۸','8'], ['۹','9'],
      ['٠','0'], ['١','1'], ['٢','2'], ['٣','3'], ['٤','4'],
      ['٥','5'], ['٦','6'], ['٧','7'], ['٨','8'], ['٩','9'],
    ].reduce((acc, [from,to]) => `replace(${acc}, '${from}', '${to}')`, expr);
  };

  const createdAtNorm = normalizeDigitsSql('created_at');
  const createdAtNormO = normalizeDigitsSql('o.created_at');

  const createdAtUtcExpr = `
    CASE
      WHEN ${createdAtNorm} LIKE '____-__-__%' THEN datetime(${createdAtNorm})
      WHEN (${createdAtNorm} NOT GLOB '*[^0-9]*' AND length(${createdAtNorm})=13) THEN datetime(CAST(${createdAtNorm} AS INTEGER)/1000, 'unixepoch')
      WHEN (${createdAtNorm} NOT GLOB '*[^0-9]*' AND length(${createdAtNorm})=10) THEN datetime(CAST(${createdAtNorm} AS INTEGER), 'unixepoch')
      ELSE datetime(${createdAtNorm})
    END
  `;

  const createdAtUtcExprO = `
    CASE
      WHEN ${createdAtNormO} LIKE '____-__-__%' THEN datetime(${createdAtNormO})
      WHEN (${createdAtNormO} NOT GLOB '*[^0-9]*' AND length(${createdAtNormO})=13) THEN datetime(CAST(${createdAtNormO} AS INTEGER)/1000, 'unixepoch')
      WHEN (${createdAtNormO} NOT GLOB '*[^0-9]*' AND length(${createdAtNormO})=10) THEN datetime(CAST(${createdAtNormO} AS INTEGER), 'unixepoch')
      ELSE datetime(${createdAtNormO})
    END
  `;

  const orders = db.prepare(`
    SELECT id, user_id, total, status, created_at
    FROM orders
    WHERE (${createdAtUtcExpr}) >= datetime(date(?), '${UTC_FROM_LOCAL_MOD}')
      AND (${createdAtUtcExpr}) < datetime(date(?), '+1 day', '${UTC_FROM_LOCAL_MOD}')
      AND COALESCE(status,'paid') != 'refunded'
    ORDER BY id DESC
  `).all(fromIso, toIso);

  const summary = db.prepare(`
    SELECT
      COUNT(*) AS orders_count,
      COALESCE(SUM(total), 0) AS total_sales,
      COALESCE(AVG(total), 0) AS avg_order
    FROM orders
    WHERE (${createdAtUtcExpr}) >= datetime(date(?), '${UTC_FROM_LOCAL_MOD}')
      AND (${createdAtUtcExpr}) < datetime(date(?), '+1 day', '${UTC_FROM_LOCAL_MOD}')
      AND COALESCE(status,'paid') != 'refunded'
  `).get(fromIso, toIso);

  const topItems = db.prepare(`
    SELECT
      oi.title AS title,
      COALESCE(SUM(oi.qty),0) AS qty,
      COALESCE(SUM(oi.qty * oi.price),0) AS revenue
    FROM order_items oi
    JOIN orders o ON o.id = oi.order_id
    WHERE (${createdAtUtcExprO}) >= datetime(date(?), '${UTC_FROM_LOCAL_MOD}')
      AND (${createdAtUtcExprO}) < datetime(date(?), '+1 day', '${UTC_FROM_LOCAL_MOD}')
      AND COALESCE(o.status,'paid') != 'refunded'
    GROUP BY oi.title
    ORDER BY revenue DESC, qty DESC
    LIMIT 200
  `).all(fromIso, toIso);

  res.render('pages/admin_reports', {
    title: res.locals.t('sales_report'),
    user: req.user,
    from: fromIso,
    to: toIso,
    summary,
    orders,
    topItems
  });
});


module.exports = r;
