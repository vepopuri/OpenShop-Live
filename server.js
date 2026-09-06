'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');

// ============================================================================
// OpenShop Live — vulnerable-by-design real-time e-commerce demo
//
// This app intentionally contains SQL injection, BOLA/IDOR, a websocket
// business-logic race condition, and stored XSS. It exists to teach and to
// test detection/exploitation tooling. Do NOT deploy this outside an
// isolated lab/CTF environment, and never reuse this code in production.
//
// Flip SECURE_MODE to `true` to see the same features implemented safely
// (parameterized queries, session-bound authorization, transactional
// stock/bid validation, and output escaping).
// ============================================================================
const SECURE_MODE = true;

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'ecommerce.db');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ----------------------------------------------------------------------------
// Database setup + seed data
// ----------------------------------------------------------------------------
const isFreshDb = !fs.existsSync(DB_PATH);
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      shipping_address TEXT NOT NULL,
      credit_card_last4 TEXT NOT NULL,
      raw_credit_card_full TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      description TEXT NOT NULL,
      stock_count INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bids (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      bid_amount REAL NOT NULL
    );
  `);

  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount === 0) {
    const insertUser = db.prepare(`
      INSERT INTO users (username, password, email, shipping_address, credit_card_last4, raw_credit_card_full)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const seedUsers = [
      ['alice99', 'password123', 'alice@example.com', '12 Baker Street, London, UK', '4242', '4242424242424242'],
      ['bobsmith', 'letmein', 'bob@example.com', '88 Elm Street, Austin, TX', '1881', '5555555555551881'],
      ['carla_v', 'sunshine1', 'carla@example.com', '4 Rue de Paris, Paris, France', '0007', '4111111111110007'],
      ['deepak.k', 'qwerty99', 'deepak@example.com', '221 Marine Drive, Mumbai, India', '3399', '6011000000013399'],
      ['emily_w', 'iloveshopping', 'emily@example.com', '9 Harbour Rd, Sydney, Australia', '7654', '4000000000007654'],
    ];
    const insertMany = db.transaction((rows) => rows.forEach((r) => insertUser.run(...r)));
    insertMany(seedUsers);
    console.log('Seeded 5 dummy users.');
  }

  const productCount = db.prepare('SELECT COUNT(*) AS c FROM products').get().c;
  if (productCount === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (name, price, description, stock_count) VALUES (?, ?, ?, ?)
    `);
    const seedProducts = [
      ['Wireless Noise-Cancelling Headphones', 129.99, 'Over-ear headphones with 30h battery life.', 42],
      ['Smart Fitness Watch', 89.5, 'Heart-rate, GPS and sleep tracking.', 30],
      ['4K Waterproof Action Camera', 199.0, 'Rugged action camera with image stabilization.', 15],
      ['Mechanical Keyboard RGB', 74.99, 'Hot-swappable switches, per-key RGB lighting.', 60],
      ['Portable Espresso Maker', 45.0, 'Manual espresso maker built for travel.', 25],
    ];
    const insertMany = db.transaction((rows) => rows.forEach((r) => insertProduct.run(...r)));
    insertMany(seedProducts);
    console.log('Seeded 5 dummy products.');
  }
}

initDb();

// ----------------------------------------------------------------------------
// Express app
// ----------------------------------------------------------------------------
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (req, res) => {
  res.json({ secureMode: SECURE_MODE });
});

app.get('/api/products', (req, res) => {
  const products = db.prepare('SELECT id, name, price, description, stock_count FROM products').all();
  res.json(products);
});

app.get('/api/bids/:productId', (req, res) => {
  const bids = db
    .prepare('SELECT id, product_id, username, bid_amount FROM bids WHERE product_id = ? ORDER BY bid_amount DESC')
    .all(req.params.productId);
  res.json(bids);
});

// ----------------------------------------------------------------------------
// VULNERABILITY #1 — SQL Injection (raw string concatenation)
//
// Vulnerable example payload against this endpoint:
//   /api/search?q=x' UNION SELECT id, username || ':' || password, email, shipping_address, raw_credit_card_full FROM users--
// dumps every user's credentials, address, and full card number through a
// product-search box.
// ----------------------------------------------------------------------------
app.get('/api/search', (req, res) => {
  const q = req.query.q || '';

  if (!SECURE_MODE) {
    const sql = `SELECT id, name, price, description, stock_count FROM products WHERE name LIKE '%${q}%'`;
    try {
      const rows = db.prepare(sql).all();
      res.json({ sql, results: rows });
    } catch (err) {
      res.status(500).json({ sql, error: err.message });
    }
  } else {
    const rows = db
      .prepare('SELECT id, name, price, description, stock_count FROM products WHERE name LIKE ?')
      .all(`%${q}%`);
    res.json({ results: rows });
  }
});

// ----------------------------------------------------------------------------
// Socket.io — real-time flash sale ticker, auctions, chat
// ----------------------------------------------------------------------------

// In-memory cache mirroring the current highest bid per product, used only
// to demonstrate the read-then-write race in vulnerable mode.
const highestBids = {};

function broadcastStock() {
  const products = db.prepare('SELECT id, name, price, description, stock_count FROM products').all();
  const updated = products.map((p) => {
    const delta = Math.floor(Math.random() * 5) - 2; // fluctuate stock by -2..+2
    const newStock = Math.max(0, p.stock_count + delta);
    db.prepare('UPDATE products SET stock_count = ? WHERE id = ?').run(newStock, p.id);
    return { ...p, stock_count: newStock };
  });
  io.emit('stock_update', updated);
}
setInterval(broadcastStock, 5000);

function escapeHtml(s = '') {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);
  socket.emit('config', { secureMode: SECURE_MODE });

  // A very simplified "session": the client tells us which demo user it is
  // logging in as. In SECURE_MODE this is the only identity get_order_details
  // will trust; in vulnerable mode it's ignored entirely by that handler.
  socket.on('login', ({ user_id }) => {
    socket.data.userId = user_id;
  });

  // --------------------------------------------------------------------
  // VULNERABILITY #2 — Real-time BOLA / IDOR
  //
  // Any connected client can request another shopper's full billing
  // profile (address + full card number) just by guessing/incrementing
  // user_id — there is no check that the caller owns that record.
  // --------------------------------------------------------------------
  socket.on('get_order_details', (payload) => {
    const userId = payload && payload.user_id;

    if (!SECURE_MODE) {
      const user = db
        .prepare(
          'SELECT id, username, email, shipping_address, credit_card_last4, raw_credit_card_full FROM users WHERE id = ?'
        )
        .get(userId);
      socket.emit('order_details', user || { error: 'Not found' });
    } else {
      const sessionUserId = socket.data.userId;
      if (!sessionUserId || Number(userId) !== Number(sessionUserId)) {
        socket.emit('order_details', { error: 'Forbidden: you may only view your own order details.' });
        return;
      }
      const user = db
        .prepare('SELECT id, username, email, shipping_address, credit_card_last4 FROM users WHERE id = ?')
        .get(sessionUserId);
      socket.emit('order_details', user || { error: 'Not found' });
    }
  });

  // --------------------------------------------------------------------
  // VULNERABILITY #3 — Auction race condition / no server-side validation
  //
  // No transaction guards the read-of-current-highest against the write
  // of the new bid, and bid_amount is never floored at zero, so a flood
  // of concurrent or negative bids can desync clients from the true
  // highest bid stored in the database.
  // --------------------------------------------------------------------
  socket.on('place_bid', ({ product_id, username, bid_amount }) => {
    const amount = Number(bid_amount);

    if (!SECURE_MODE) {
      const current = highestBids[product_id];
      db.prepare('INSERT INTO bids (product_id, username, bid_amount) VALUES (?, ?, ?)').run(
        product_id,
        username,
        amount
      );
      if (!current || amount > current.bid_amount) {
        highestBids[product_id] = { username, bid_amount: amount };
      }
      io.emit('bid_update', {
        product_id,
        username,
        bid_amount: amount,
        highest: highestBids[product_id],
      });
    } else {
      if (!Number.isFinite(amount) || amount <= 0) {
        socket.emit('bid_error', { error: 'Bid amount must be a positive number.' });
        return;
      }
      try {
        const highest = db.transaction(() => {
          const current = db
            .prepare('SELECT MAX(bid_amount) AS max FROM bids WHERE product_id = ?')
            .get(product_id);
          if (current.max && amount <= current.max) {
            throw new Error(`Bid must exceed the current highest bid of $${current.max.toFixed(2)}.`);
          }
          db.prepare('INSERT INTO bids (product_id, username, bid_amount) VALUES (?, ?, ?)').run(
            product_id,
            username,
            amount
          );
          return db
            .prepare('SELECT username, bid_amount FROM bids WHERE product_id = ? ORDER BY bid_amount DESC LIMIT 1')
            .get(product_id);
        })();
        highestBids[product_id] = highest;
        io.emit('bid_update', { product_id, username, bid_amount: amount, highest });
      } catch (err) {
        socket.emit('bid_error', { error: err.message });
      }
    }
  });

  // --------------------------------------------------------------------
  // VULNERABILITY #3b — Buy-now race condition + client-trusted price
  //
  // The server trusts the "price" the client submits instead of pricing
  // from the database, and decrements stock without checking it stays
  // non-negative or that the write is atomic — flooding this event buys
  // items for $0 and drives stock below zero.
  // --------------------------------------------------------------------
  socket.on('buy_item', ({ product_id, price, quantity }) => {
    const qty = Number(quantity) || 1;

    if (!SECURE_MODE) {
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
      if (!product) return;
      db.prepare('UPDATE products SET stock_count = stock_count - ? WHERE id = ?').run(qty, product_id);
      const updated = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
      io.emit('purchase_made', {
        product_id,
        quantity: qty,
        charged_price: price, // attacker-controlled, never validated against the DB price
        stock_count: updated.stock_count,
      });
    } else {
      try {
        const result = db.transaction(() => {
          const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
          if (!product) throw new Error('Product not found.');
          if (!Number.isInteger(qty) || qty <= 0) throw new Error('Invalid quantity.');
          if (product.stock_count < qty) throw new Error('Insufficient stock.');
          db.prepare('UPDATE products SET stock_count = stock_count - ? WHERE id = ?').run(qty, product_id);
          return { charged_price: product.price * qty, stock_count: product.stock_count - qty };
        })();
        io.emit('purchase_made', { product_id, quantity: qty, ...result });
      } catch (err) {
        socket.emit('purchase_error', { error: err.message });
      }
    }
  });

  // --------------------------------------------------------------------
  // VULNERABILITY #4 — Stored XSS in the live auction chat feed
  //
  // Messages are broadcast verbatim; the frontend renders them with
  // innerHTML, so a handle/message such as <img src=x onerror=alert(1)>
  // executes in every connected shopper's browser the moment it's sent.
  // --------------------------------------------------------------------
  socket.on('chat_message', ({ handle, message }) => {
    if (!SECURE_MODE) {
      io.emit('chat_message', { handle, message, ts: Date.now() });
    } else {
      io.emit('chat_message', { handle: escapeHtml(handle), message: escapeHtml(message), ts: Date.now() });
    }
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
  });
});

server.listen(PORT, () => {
  console.log(`\n  OpenShop Live listening on http://localhost:${PORT}`);
  console.log(
    `  SECURE_MODE = ${SECURE_MODE} (${
      SECURE_MODE ? 'secure implementation' : 'VULNERABLE — for authorized security research/testing only'
    })\n`
  );
  if (isFreshDb) console.log('  Created new ecommerce.db and seeded demo data.\n');
});
