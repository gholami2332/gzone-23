const r = require('express').Router();
const bcrypt = require('bcryptjs');
const { getDb } = require('../db');

function translateCheckoutError(lang, msg){
  if (lang !== 'en') return msg;
  const m = String(msg||'');
  if (m.includes('سبد خرید خالی')) return 'Your cart is empty.';
  if (m.includes('قیمت محصولات')) return 'Some items do not have prices yet.';
  if (m.includes('اعتبار شما کافی نیست')) return 'Insufficient credit.';
  return 'Checkout failed.';
}
const { requireAuth, signToken } = require('../middleware/auth');
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;

r.get('/dashboard', requireAuth, (req, res) => {
  const db = getDb();
  const categories = db.prepare('SELECT * FROM categories ORDER BY sort_order, id').all();
  const products = db.prepare('SELECT * FROM products WHERE is_active=1 ORDER BY category_id, sort_order, id').all();

  const cart = db.prepare(`
    SELECT ci.product_id, ci.qty, p.title, p.title_en, p.price, p.image, (ci.qty * p.price) AS subtotal
    FROM cart_items ci
    JOIN products p ON p.id = ci.product_id
    WHERE ci.user_id = ?
    ORDER BY p.title
  `).all(req.user.id);

  const total = cart.reduce((s, x) => s + (x.subtotal || 0), 0);

  const err = req.query.err || '';
  const ok = req.query.ok || '';
  const openCart = String(req.query.openCart || '') === '1';


  res.render('pages/user_dashboard', {
    title: res.locals.t('account'),
    user: req.user,
    categories,
    products,
    cart,
    total,
    err,
    ok,
    openCart
  });
});

// ---- Change password (user) ----
r.get('/account/password', requireAuth, (req, res) => {
  const err = req.query.err || '';
  const ok = req.query.ok || '';
  res.render('pages/user_password', { title: res.locals.t('change_password'), user: req.user, err, ok });
});

r.post('/account/password', requireAuth, (req, res) => {
  const oldPw = String(req.body.old_password || '');
  const newPw = String(req.body.new_password || '');
  const newPw2 = String(req.body.new_password2 || '');

  if (!oldPw || !newPw || !newPw2) {
    return res.redirect('/account/password?err=' + encodeURIComponent('لطفاً همه فیلدها را کامل کنید.'));
  }
  if (newPw !== newPw2) {
    return res.redirect('/account/password?err=' + encodeURIComponent('پسورد جدید و تکرار آن یکسان نیست.'));
  }
  if (newPw.length < 8) {
    return res.redirect('/account/password?err=' + encodeURIComponent('پسورد جدید باید حداقل ۸ کاراکتر باشد.'));
  }

  const db = getDb();
  const row = db.prepare('SELECT id, password_hash, token_version FROM users WHERE id=?').get(req.user.id);
  if (!row) return res.redirect('/logout');

  const okOld = bcrypt.compareSync(oldPw, row.password_hash);
  if (!okOld) {
    return res.redirect('/account/password?err=' + encodeURIComponent('پسورد فعلی نادرست است.'));
  }

  const newHash = bcrypt.hashSync(newPw, 12);
  db.prepare('UPDATE users SET password_hash=?, token_version=token_version+1 WHERE id=?').run(newHash, req.user.id);
  const newTv = Number(row.token_version || 0) + 1;

  // Issue a fresh token so the current session continues; old tokens become invalid via token_version.
  const token = signToken({ id: req.user.id, tv: newTv });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', domain: COOKIE_DOMAIN, secure: process.env.COOKIE_SECURE === '1' });

  return res.redirect('/account/password?ok=' + encodeURIComponent('پسورد با موفقیت تغییر کرد.'));
});

r.post('/cart/add', requireAuth, (req, res) => {
  const productId = Number(req.body.product_id || 0);
  if (!productId) return res.redirect('/dashboard?err=' + encodeURIComponent('محصول نامعتبر است.'));

  const db = getDb();
  const p = db.prepare('SELECT id, is_active FROM products WHERE id=?').get(productId);
  if (!p || p.is_active !== 1) return res.redirect('/dashboard?err=' + encodeURIComponent('محصول فعال نیست.'));

  const exists = db.prepare('SELECT qty FROM cart_items WHERE user_id=? AND product_id=?').get(req.user.id, productId);
  if (exists) {
    db.prepare('UPDATE cart_items SET qty = qty + 1 WHERE user_id=? AND product_id=?').run(req.user.id, productId);
  } else {
    db.prepare('INSERT INTO cart_items (user_id, product_id, qty) VALUES (?, ?, 1)').run(req.user.id, productId);
  }
  const wantOpen = String(req.body.open_cart || '') === '1';
  const q = wantOpen ? '&openCart=1' : '';
  res.redirect('/dashboard?ok=' + encodeURIComponent('به سبد خرید اضافه شد.') + q);
});

r.post('/cart/update', requireAuth, (req, res) => {
  const productId = Number(req.body.product_id || 0);
  const qty = Number(req.body.qty || 1);
  if (!productId) return res.redirect('/dashboard?err=' + encodeURIComponent('محصول نامعتبر است.'));
  const db = getDb();
  if (qty <= 0) {
    db.prepare('DELETE FROM cart_items WHERE user_id=? AND product_id=?').run(req.user.id, productId);
  } else {
    db.prepare('UPDATE cart_items SET qty=? WHERE user_id=? AND product_id=?').run(qty, req.user.id, productId);
  }
  res.redirect('/dashboard');
});

r.post('/cart/inc', requireAuth, (req, res) => {
  const db = getDb();
  const productId = Number(req.body.product_id);
  if (!productId) return res.redirect('/dashboard');

  const row = db.prepare('SELECT qty FROM cart_items WHERE user_id=? AND product_id=?')
    .get(req.user.id, productId);

  if (!row) {
    // cart_items table only has: user_id, product_id, qty
    // (older versions had extra columns; keep this compatible)
    const p = db.prepare('SELECT id, is_active FROM products WHERE id=?').get(productId);
    if (p && p.is_active === 1) {
      db.prepare('INSERT INTO cart_items (user_id, product_id, qty) VALUES (?, ?, 1)')
        .run(req.user.id, productId);
    }
  } else {
    db.prepare('UPDATE cart_items SET qty = qty + 1 WHERE user_id=? AND product_id=?')
      .run(req.user.id, productId);
  }

  res.redirect('/dashboard');
});

r.post('/cart/dec', requireAuth, (req, res) => {
  const db = getDb();
  const productId = Number(req.body.product_id);
  if (!productId) return res.redirect('/dashboard');

  db.prepare('UPDATE cart_items SET qty = qty - 1 WHERE user_id=? AND product_id=? AND qty > 0')
    .run(req.user.id, productId);

  db.prepare('DELETE FROM cart_items WHERE user_id=? AND product_id=? AND qty <= 0')
    .run(req.user.id, productId);

  res.redirect('/dashboard');
});

r.post('/cart/clear', requireAuth, (req, res) => {
  const db = getDb();
  db.prepare('DELETE FROM cart_items WHERE user_id=?').run(req.user.id);
  res.redirect('/dashboard?ok=' + encodeURIComponent('سبد خرید خالی شد.'));
});

r.post('/checkout', requireAuth, (req, res) => {
  const db = getDb();

  const tx = db.transaction(() => {
    const cart = db.prepare(`
      SELECT ci.product_id, ci.qty, p.title, p.title_en, p.price
      FROM cart_items ci
      JOIN products p ON p.id = ci.product_id
      WHERE ci.user_id = ?
    `).all(req.user.id);

    if (cart.length === 0) throw new Error('سبد خرید خالی است.');

    const total = cart.reduce((s, x) => s + (x.qty * x.price), 0);
    const user = db.prepare('SELECT id, credit FROM users WHERE id=?').get(req.user.id);

    if (total <= 0) throw new Error('قیمت محصولات هنوز تنظیم نشده است.');
    if (user.credit < total) throw new Error('اعتبار شما کافی نیست.');

    const orderInfo = db.prepare('INSERT INTO orders (user_id, total) VALUES (?, ?)').run(req.user.id, total);
    const orderId = orderInfo.lastInsertRowid;

    const insItem = db.prepare('INSERT INTO order_items (order_id, product_id, title, title_en, price, qty) VALUES (?, ?, ?, ?, ?, ?)');
    for (const it of cart) insItem.run(orderId, it.product_id, it.title, it.title_en || '', it.price, it.qty);

    db.prepare('UPDATE users SET credit = credit - ? WHERE id=?').run(total, req.user.id);
    db.prepare('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.id, total, 'debit', `خرید سفارش #${orderId}`
    );

    db.prepare('DELETE FROM cart_items WHERE user_id=?').run(req.user.id);
    return orderId;
  });

  try {
    const orderId = tx();
    const msg = (res.locals.lang==='en') ? `Order placed. Order ID: ${orderId}` : `سفارش ثبت شد. شماره سفارش: ${orderId}`;
    res.redirect('/orders?ok=' + encodeURIComponent(msg));
  } catch (e) {
    const errMsg = translateCheckoutError(res.locals.lang, e.message || '');
    res.redirect('/dashboard?err=' + encodeURIComponent(errMsg));
  }
});

r.get('/orders', requireAuth, (req, res) => {
  const db = getDb();
  const ok = req.query.ok || '';

  try {
    const orders = db.prepare(
      'SELECT id, user_id, total, status, created_at FROM orders WHERE user_id=? ORDER BY id DESC'
    ).all(req.user.id);

    const itemsByOrder = {};
    if (orders.length) {
      const ids = orders.map(o => o.id);
      const placeholders = ids.map(() => '?').join(',');
      const allItems = db.prepare(
        `SELECT order_id, product_id, title, title_en, price, qty
         FROM order_items
         WHERE order_id IN (${placeholders})
         ORDER BY order_id ASC, product_id ASC`
      ).all(...ids);

      for (const it of allItems) {
        (itemsByOrder[it.order_id] ||= []).push(it);
      }
    }

    return res.render('pages/user_orders', {
      title: res.locals.t('orders_title'),
      user: req.user,
      orders,
      itemsByOrder,
      ok
    });
  } catch (e) {
    console.error('Orders page error:', e);
    return res.redirect('/dashboard?err=' + encodeURIComponent('خطا در نمایش سفارش‌ها. لطفاً دوباره تلاش کنید.'));
  }
});

module.exports = r;
