// Liara build-timeout fix:
// - better-sqlite3 + bcrypt are native modules and may compile on install, causing long "npm install".
// - sql.js (WASM) + bcryptjs (pure JS) install fast and work reliably on most hosts.
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_DIR = chooseWritableDir(process.env.DB_DIR || '/data');
const DB_PATH = path.join(DB_DIR, 'database.sqlite');
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/data/uploads';

let db; // wrapper exposing a subset of better-sqlite3 API

// --- sql.js wrapper to mimic better-sqlite3 (prepare/get/all/run/exec/transaction) ---
class SqlJsStmt {
  constructor(wrapper, sql) {
    this.wrapper = wrapper;
    this.sql = sql;
  }

  _bind(stmt, params) {
    const arr = (params && params.length) ? Array.from(params) : [];
    stmt.bind(arr);
  }

  run(...params) {
    const w = this.wrapper;
    // Use db.run for non-select statements (more robust than stepping a prepared stmt)
    w._db.run(this.sql, params);
    const changes = w._db.getRowsModified();
    const row = w._getOne('SELECT last_insert_rowid() AS id');
    w._scheduleSave();
    return { changes, lastInsertRowid: row ? row.id : undefined };
  }

  get(...params) {
    const w = this.wrapper;
    const stmt = w._db.prepare(this.sql);
    try {
      this._bind(stmt, params);
      if (!stmt.step()) return undefined;
      return stmt.getAsObject();
    } finally {
      stmt.free();
    }
  }

  all(...params) {
    const w = this.wrapper;
    const stmt = w._db.prepare(this.sql);
    const rows = [];
    try {
      this._bind(stmt, params);
      while (stmt.step()) rows.push(stmt.getAsObject());
      return rows;
    } finally {
      stmt.free();
    }
  }
}

class SqlJsWrapper {
  constructor(sqlDb, dbPath) {
    this._db = sqlDb;
    this._dbPath = dbPath;
    this._saveTimer = null;
  }

  pragma(_) {
    // no-op in sql.js
  }

  prepare(sql) {
    return new SqlJsStmt(this, sql);
  }

  exec(sql) {
    this._db.run(sql);
    this._scheduleSave();
  }

  transaction(fn) {
    return (...args) => {
      this.exec('BEGIN');
      try {
        const res = fn(...args);
        this.exec('COMMIT');
        return res;
      } catch (e) {
        try { this.exec('ROLLBACK'); } catch (_) {}
        throw e;
      }
    };
  }

  _getOne(sql, params = []) {
    const stmt = this._db.prepare(sql);
    try {
      stmt.bind(params);
      if (!stmt.step()) return undefined;
      return stmt.getAsObject();
    } finally {
      stmt.free();
    }
  }

  _atomicWrite(filePath, buf) {
    const dir = path.dirname(filePath);
    ensureDir(dir);
    const tmp = filePath + '.tmp';
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, filePath);
  }

  _saveNow() {
    const bytes = this._db.export();
    this._atomicWrite(this._dbPath, Buffer.from(bytes));
  }

  _scheduleSave() {
    if (this._saveTimer) clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      try { this._saveNow(); } catch (e) { console.error('DB save failed:', e.message); }
    }, 400);
  }
}

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}


function isWritableDir(dir) {
  try {
    ensureDir(dir);
    const testFile = path.join(dir, '.writetest');
    fs.writeFileSync(testFile, 'ok');
    fs.unlinkSync(testFile);
    return true;
  } catch (e) {
    return false;
  }
}

function chooseWritableDir(preferred) {
  const candidates = [
    preferred,
    path.join(process.cwd(), 'data'),
    '/tmp/gzone-data'
  ];
  for (const c of candidates) {
    if (isWritableDir(c)) return c;
  }
  // last resort: current directory
  return process.cwd();
}

function columnExists(db, table, column) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    return cols.some(c => c.name === column);
  } catch (e) {
    return false;
  }
}

function tableExists(db, table) {
  const row = db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).get(table);
  return !!row;
}

function safeExec(db, sql) {
  try {
    db.exec(sql);
    return true;
  } catch (e) {
    console.error('MIGRATION SQL failed:', e.message, '\nSQL:', sql);
    return false;
  }
}

function safeRun(stmt, params=[]) {
  try { return stmt.run(...params); } catch (e) { console.error('MIGRATION RUN failed:', e.message); }
}

function migrateSchema(db) {
  // USERS: support older schema with `password` column
  if (tableExists(db, 'users')) {
    if (!columnExists(db, 'users', 'password_hash') && columnExists(db, 'users', 'password')) {
      safeExec(db, `ALTER TABLE users ADD COLUMN password_hash TEXT`);
      safeExec(db, `UPDATE users SET password_hash = COALESCE(password_hash, password) WHERE password_hash IS NULL`);
    }
    if (!columnExists(db, 'users', 'credit')) safeExec(db, `ALTER TABLE users ADD COLUMN credit INTEGER NOT NULL DEFAULT 0`);
    if (!columnExists(db, 'users', 'role')) safeExec(db, `ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`);
    if (!columnExists(db, 'users', 'token_version')) safeExec(db, `ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0`);
    if (!columnExists(db, 'users', 'created_at')) {
      safeExec(db, `ALTER TABLE users ADD COLUMN created_at TEXT`);
      safeExec(db, `UPDATE users SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE created_at IS NULL OR created_at=''`);
    }
    // first_name/last_name/phone columns might not exist in some early DBs
    if (!columnExists(db, 'users', 'first_name')) safeExec(db, `ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'users', 'last_name')) safeExec(db, `ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'users', 'phone')) safeExec(db, `ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''`);
  }

  // CATEGORIES
  if (tableExists(db, 'categories')) {
    if (!columnExists(db, 'categories', 'title_en')) safeExec(db, `ALTER TABLE categories ADD COLUMN title_en TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'categories', 'icon')) safeExec(db, `ALTER TABLE categories ADD COLUMN icon TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'categories', 'sort_order')) safeExec(db, `ALTER TABLE categories ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`);
  }

  // PRODUCTS
  if (tableExists(db, 'products')) {
    if (!columnExists(db, 'products', 'title_en')) safeExec(db, `ALTER TABLE products ADD COLUMN title_en TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'products', 'description')) safeExec(db, `ALTER TABLE products ADD COLUMN description TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'products', 'description_en')) safeExec(db, `ALTER TABLE products ADD COLUMN description_en TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'products', 'image')) safeExec(db, `ALTER TABLE products ADD COLUMN image TEXT NOT NULL DEFAULT '/images/placeholder.png'`);
    if (!columnExists(db, 'products', 'is_active')) safeExec(db, `ALTER TABLE products ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`);
    if (!columnExists(db, 'products', 'sort_order')) safeExec(db, `ALTER TABLE products ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`);
    if (!columnExists(db, 'products', 'created_at')) {
      safeExec(db, `ALTER TABLE products ADD COLUMN created_at TEXT`);
      safeExec(db, `UPDATE products SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE created_at IS NULL OR created_at=''`);
    }
    if (!columnExists(db, 'products', 'category_id')) safeExec(db, `ALTER TABLE products ADD COLUMN category_id INTEGER NOT NULL DEFAULT 1`);
  }

  // CART ITEMS
  if (!tableExists(db, 'cart_items')) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS cart_items (
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        qty INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (user_id, product_id)
      );
    `);
  }

  // ORDERS + ORDER_ITEMS
  if (!tableExists(db, 'orders')) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        total INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        status TEXT NOT NULL DEFAULT 'paid'
      );
    `);
  } else {
    if (!columnExists(db, 'orders', 'status')) safeExec(db, `ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'paid'`);
    if (!columnExists(db, 'orders', 'created_at')) {
      safeExec(db, `ALTER TABLE orders ADD COLUMN created_at TEXT`);
      safeExec(db, `UPDATE orders SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE created_at IS NULL OR created_at=''`);
    }
  }

  if (!tableExists(db, 'order_items')) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS order_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              order_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              title_en TEXT NOT NULL DEFAULT '',
              price INTEGER NOT NULL,
              qty INTEGER NOT NULL
      );
    `);
  } else {
    if (!columnExists(db, 'order_items', 'title_en')) safeExec(db, `ALTER TABLE order_items ADD COLUMN title_en TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'order_items', 'title')) safeExec(db, `ALTER TABLE order_items ADD COLUMN title TEXT NOT NULL DEFAULT ''`);
    if (!columnExists(db, 'order_items', 'price')) safeExec(db, `ALTER TABLE order_items ADD COLUMN price INTEGER NOT NULL DEFAULT 0`);
    if (!columnExists(db, 'order_items', 'qty')) safeExec(db, `ALTER TABLE order_items ADD COLUMN qty INTEGER NOT NULL DEFAULT 1`);
  }

  // SETTINGS
        if (!tableExists(db, 'settings')) {
          safeExec(db, `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
        }

        // TRANSACTIONS
  if (!tableExists(db, 'transactions')) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
  } else {
    if (!columnExists(db, 'transactions', 'created_at')) {
      safeExec(db, `ALTER TABLE transactions ADD COLUMN created_at TEXT`);
      safeExec(db, `UPDATE transactions SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE created_at IS NULL OR created_at=''`);
    }
  }
}


async function initDb() {
  ensureDir(DB_DIR);
  ensureDir(UPLOAD_DIR);
  ensureDir(path.join(UPLOAD_DIR, 'products'));

  // Initialize sql.js (WASM)
  const SQL = await initSqlJs({
    locateFile: (file) => {
      // Ensure the wasm file can be found in Node environments
      try {
        return require.resolve('sql.js/dist/' + file);
      } catch (e) {
        return file;
      }
    }
  });

  // Load existing DB file if available; otherwise create a new DB
  let sqlDb;
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    sqlDb = new SQL.Database(new Uint8Array(buf));
  } else {
    sqlDb = new SQL.Database();
  }

  db = new SqlJsWrapper(sqlDb, DB_PATH);

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      phone TEXT NOT NULL,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      credit INTEGER NOT NULL DEFAULT 0,
      role TEXT NOT NULL DEFAULT 'user',
      token_version INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL UNIQUE,
      title_en TEXT NOT NULL DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      title_en TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      description_en TEXT NOT NULL DEFAULT '',
      price INTEGER NOT NULL DEFAULT 0,
      image TEXT NOT NULL DEFAULT '/images/placeholder.png',
      is_active INTEGER NOT NULL DEFAULT 1,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(category_id) REFERENCES categories(id)
    );

    CREATE TABLE IF NOT EXISTS cart_items (
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      qty INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (user_id, product_id),
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      total INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      status TEXT NOT NULL DEFAULT 'paid',
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS order_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              order_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              title TEXT NOT NULL,
              title_en TEXT NOT NULL DEFAULT '',
              price INTEGER NOT NULL,
              qty INTEGER NOT NULL,
      FOREIGN KEY(order_id) REFERENCES orders(id)
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // Migrate old DBs safely (adds missing columns)
  migrateSchema(db);

  seedAdmin();
  seedMenuIfEmpty();

  // Persist after init/seed
  try { db._saveNow(); } catch (_) {}
}

function seedAdmin() {
  // SECURITY NOTE:
  // We no longer hardcode an admin password in the repository.
  // If the database already has an admin, do nothing.
  const anyAdmin = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
  if (anyAdmin) return;

  // Bootstrap admin only if env vars are provided.
  const adminUsername = String(process.env.ADMIN_USERNAME || '').trim();
  const adminPass = String(process.env.ADMIN_PASSWORD || '');

  if (!adminUsername || !adminPass) {
    console.warn('[SECURITY] No admin user exists. Set ADMIN_USERNAME and ADMIN_PASSWORD env vars to create the first admin.');
    return;
  }

  const hash = bcrypt.hashSync(adminPass, 12);

  // If a user with that username exists, promote them; otherwise create a new admin.
  const existing = db.prepare('SELECT id FROM users WHERE username=?').get(adminUsername);
  if (existing) {
    db.prepare("UPDATE users SET role='admin', password_hash=?, token_version=token_version+1 WHERE id=?")
      .run(hash, existing.id);
  } else {
    db.prepare(`
      INSERT INTO users (first_name, last_name, phone, username, password_hash, credit, role, token_version)
      VALUES (?, ?, ?, ?, ?, ?, 'admin', 0)
    `).run('G-Zone', 'Admin', '00000000000', adminUsername, hash, 0);
  }

  console.warn(`[SECURITY] Bootstrapped admin user "${adminUsername}". Please change the password after first login.`);
}

function seedMenuIfEmpty() {
  const count = db.prepare('SELECT COUNT(1) AS c FROM products').get().c;
  if (count > 0) return;

  const seedTx = db.transaction(() => {

  const menu = {"مورنينگ ريچوالز": ["آووكادو بيكن فرنچ تست", "ماچا پنكيك", "پرشين بركفست", "فلدد اگ", "بويلد اگ", "ساني سايد آپ", "پرو فرنچ تست", "كروك مادام"], "ريفايند كوزين": ["گرين پپركورن تندرلوين", "شريمپ گاردن", "امپريال چيكن بول", "پارمسان بيف فرش رپ", "چيكن والنات پاستا"], "سالاد": ["گريك", "سزار", "اسفناج بوست"], "وِلنِس بولز": ["چيا پودينگ", "گرانولا جار", "اوت ميل", "ناتز پك"], "بين اند بُرو": ["آمريكانو / آيس", "اسپرسو ( دبل/ سينگل )", "لاته / آيس", "كاپوچينو / كاپوچينو بروله", "دريپ كافي", "آفاگاتو  /  آفاگاتو  پسته", "فلت وايت", "موكا / آيس", "كارامل ماكياتو / آيس"], "وارم كاپ": ["بلك تي", "گرين تي", "هات كوكو", "گلدن ميلك", "زِن ماچا"], "نوشيدني": ["آب معدني", "لِمون فيز", "دايِت كوك"], "دايِت بايتز": ["براوني", "پرو كوكي", "كيك صبحانه", "پروتئين بار/ خرما بار", "مافين", "كيك هويج گردو", "توپك پروتئيني", "ماربل كيك"], "پرو شيكز": ["سانرايز بانانا", "پستشيو لاكس", "منگو تانگو", "كوكو پينات بليس", "اوشن گِلو", "واتال اسپرولينا", "كافئين كيك"]};

  const insertCategory = db.prepare('INSERT INTO categories (title, title_en, icon, sort_order) VALUES (?, ?, ?, ?)');
  const insertProduct = db.prepare(`
    INSERT INTO products (category_id, title, title_en, description, description_en, price, image, is_active, sort_order)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
  `);

  const catEn = {
    'مورنينگ ريچوالز': 'Morning Rituals',
    'ريفايند كوزين': 'Refined Cuisine',
    'سالاد': 'Salads',
    'وِلنِس بولز': 'Wellness Bowls',
    'بين اند بُرو': 'Bean & Brew',
    'وارم كاپ': 'Warm Cup',
    'نوشيدني': 'Drinks',
    'دايِت بايتز': 'Diet Bites',
    'پرو شيكز': 'Pro Shakes'
  };
const productEn = {
  'آووكادو بيكن فرنچ تست': 'Avocado Bacon French Toast',
  'ماچا پنكيك': 'Matcha Pancake',
  'پرشين بركفست': 'Persian Breakfast',
  'فلدد اگ': 'Folded Egg',
  'بويلد اگ': 'Boiled Egg',
  'ساني سايد آپ': 'Sunny Side Up',
  'پرو فرنچ تست': 'Protein French Toast',
  'كروك مادام': 'Croque Madame',

  'گرين پپركورن تندرلوين': 'Green Peppercorn Tenderloin',
  // keep both spellings (single/double space) to avoid mismatches
  'شريمپ گاردن': 'Shrimp Garden',
  'شريمپ  گاردن': 'Shrimp Garden',
  'امپريال چيكن بول': 'Imperial Chicken Bowl',
  'پارمسان بيف فرش رپ': 'Parmesan Beef Fresh Wrap',
  'چيكن والنات پاستا': 'Chicken Walnut Pasta',

  'گريك': 'Greek Salad',
  'سزار': 'Caesar Salad',
  'اسفناج بوست': 'Spinach Boost Salad',

  'چيا پودينگ': 'Chia Pudding',
  'گرانولا جار': 'Granola Jar',
  'اوت ميل': 'Oatmeal',
  'ناتز پك': 'Nuts Pack',

  'آمريكانو / آيس': 'Americano / Iced',
  'اسپرسو ( دبل/ سينگل )': 'Espresso (Double/Single)',
  'لاته / آيس': 'Latte / Iced',
  'كاپوچينو / كاپوچينو بروله': 'Cappuccino / Cappuccino Brulee',
  'دريپ كافي': 'Drip Coffee',
  'آفاگاتو  /  آفاگاتو  پسته': 'Affogato / Pistachio Affogato',
  'فلت وايت': 'Flat White',
  'موكا / آيس': 'Mocha / Iced',
  'كارامل ماكياتو / آيس': 'Caramel Macchiato / Iced',

  'بلك تي': 'Black Tea',
  'گرين تي': 'Green Tea',
  'هات كوكو': 'Hot Cocoa',
  'گلدن ميلك': 'Golden Milk',
  'زِن ماچا': 'Zen Matcha',

  'آب معدني': 'Mineral Water',
  'لِمون فيز': 'Lemon Fizz',
  'دايِت كوك': 'Diet Coke',

  'براوني': 'Brownie',
  'پرو كوكي': 'Protein Cookie',
  'كيك صبحانه': 'Breakfast Cake',
  'پروتئين بار/ خرما بار': 'Protein Bar / Date Bar',
  'مافين': 'Muffin',
  'كيك هويج گردو': 'Carrot Walnut Cake',
  'توپك پروتئيني': 'Protein Balls',
  'ماربل كيك': 'Marble Cake',

  'سانرايز بانانا': 'Sunrise Banana',
  'پستشيو لاكس': 'Pistachio Luxe',
  'منگو تانگو': 'Mango Tango',
  'كوكو پينات بليس': 'Cocoa Peanut Bliss',
  'اوشن گِلو': 'Ocean Glow',
  'واتال اسپرولينا': 'Vital Spirulina',
  'كافئين كيك': 'Caffeine Kick'
};


  let sortCat = 1;
  for (const [catTitle, items] of Object.entries(menu)) {
    insertCategory.run(catTitle, catEn[catTitle] || '', '', sortCat++);
    const catId = db.prepare('SELECT id FROM categories WHERE title=?').get(catTitle).id;

    let sortProd = 1;
    for (const itemTitle of items) {
      insertProduct.run(catId, itemTitle, productEn[itemTitle] || '', '', '', 0, '/images/placeholder.png', sortProd++);
    }
  }

  });

  seedTx();
}

function getDb() {
  if (!db) throw new Error('DB not initialized');
  return db;
}

module.exports = { initDb, getDb, DB_PATH, UPLOAD_DIR };
