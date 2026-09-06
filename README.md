# OpenShop Live

A deliberately vulnerable, real-time e-commerce demo built with **Node.js, Express, Socket.io, and SQLite**. It exists to teach and test detection/exploitation of common web/real-time vulnerabilities against a realistic-feeling storefront (flash sales, live stock ticker, live auction bidding, auction chat).

> ⚠️ **For authorized security research, testing, and education only.** This app stores plaintext passwords and full "credit card" numbers and ships with SQL injection, broken authorization, a business-logic race condition, and stored XSS *on purpose*. Never deploy it on a public network, never point it at real data, and never reuse this code as a starting point for a production app.

## Quick start

```bash
npm install
npm start
```

Then open **http://localhost:3000**. On first run the app creates `ecommerce.db` (SQLite, ignored by git) and seeds it with 5 demo users and 5 demo products automatically.

## Project layout

```
server.js        Express + Socket.io server, SQLite setup/seed, all API + socket handlers
public/
  index.html     Storefront markup (flash sale grid, auction panel, chat, search, IDOR demo)
  app.js         Frontend logic (Socket.io client, rendering, intentionally-unsafe chat sink)
  style.css      Styling
```

## The vulnerability toggle

Everything is gated by one flag at the top of `server.js`:

```js
const SECURE_MODE = false;
```

- `false` (default) — every vulnerability below is live.
- `true` — the same features run through parameterized queries, session-bound authorization checks, transactional stock/bid validation, and output escaping instead.

Flip it and restart the server (`npm start`) to compare behavior side by side. The frontend shows a **Vulnerable / Secure** badge reflecting the current mode (fetched from `/api/config`).

## Vulnerabilities included (vulnerable mode)

### 1. SQL Injection — `GET /api/search?q=`
The query string is concatenated directly into a SQL statement:

```js
const sql = `SELECT id, name, price, description, stock_count FROM products WHERE name LIKE '%${q}%'`;
```

Because the product query and the `users` table can be aligned to 5 columns, a `UNION`-based attack dumps every user's plaintext password and full card number through the storefront search box:

```
GET /api/search?q=x' UNION SELECT id, username || ':' || password, email, shipping_address, raw_credit_card_full FROM users--
```

The endpoint also echoes the exact SQL string it ran, which is convenient for testing/tooling but is itself an information-disclosure smell worth noting.

**Fix in secure mode:** parameterized query (`WHERE name LIKE ?`).

### 2. Real-time BOLA / IDOR — `get_order_details` socket event
The handler takes whatever `user_id` the client sends and returns that user's full billing profile (address, last 4, full card number) with no check that the caller is that user:

```js
socket.on('get_order_details', (payload) => {
  const user = db.prepare('SELECT ... FROM users WHERE id = ?').get(payload.user_id);
  socket.emit('order_details', user);
});
```

In the UI: "log in" as shopper #1, then request order details for `user_id=2` through `5` and watch their PII come back over the same socket. No authentication token or ownership check is ever consulted.

**Fix in secure mode:** the handler only returns data for `socket.data.userId` (the id set at `login`), rejecting mismatched requests with `Forbidden`.

### 3. WebSocket race condition / business-logic flaws — `place_bid` and `buy_item`
- `place_bid` reads the "current highest bid" and writes a new bid without a transaction, and never rejects non-positive amounts — flooding the event with concurrent or negative bids can desync the broadcast highest bid from the true database state.
- `buy_item` trusts a client-supplied `price` field instead of pricing from the database, and decrements `stock_count` without checking it stays non-negative or wrapping the read/decrement in a transaction — a fast client can buy for **$0** or drive stock **below zero**.

**Fix in secure mode:** both handlers run inside a `db.transaction(...)`, validate amounts/quantities server-side, price purchases from the database (never from client input), and enforce `stock_count >= quantity` atomically.

### 4. Stored XSS — live auction chat
The server broadcasts chat `handle`/`message` verbatim, and the frontend renders each message with `innerHTML`:

```js
row.innerHTML = `<span class="handle">${data.handle}</span>${data.message}`;
```

Sending a handle or message like `<img src=x onerror=alert(document.domain)>` executes instantly in every connected shopper's browser — no reload needed.

**Fix in secure mode:** the server HTML-escapes `handle` and `message` before broadcasting, so even though the frontend sink is unchanged, the payload that reaches it is neutralized.

## Seeded demo data

5 users (`alice99`, `bobsmith`, `carla_v`, `deepak.k`, `emily_w`) with plaintext passwords, addresses, and card numbers, and 5 products (headphones, fitness watch, action camera, keyboard, espresso maker) — all inserted automatically on first boot if the tables are empty.

## Notes for testers

- The live stock ticker fluctuates every 5 seconds via `setInterval` + `io.emit('stock_update', ...)`.
- Every socket event handler is annotated in `server.js` with a comment block explaining exactly which vulnerability it demonstrates and the equivalent secure implementation in the `else` branch.
