const socket = io();

let products = [];
let secureMode = false;

const productGrid = document.getElementById('productGrid');
const auctionSelect = document.getElementById('auctionProductSelect');
const activityLog = document.getElementById('activityLog');
const chatFeed = document.getElementById('chatFeed');
const modeBadge = document.getElementById('modeBadge');
const modeExplainer = document.getElementById('modeExplainer');

// ---------------------------------------------------------------------------
// Config / mode badge
// ---------------------------------------------------------------------------
fetch('/api/config')
  .then((r) => r.json())
  .then(({ secureMode: sm }) => applyMode(sm));

socket.on('config', ({ secureMode: sm }) => applyMode(sm));

function applyMode(sm) {
  secureMode = sm;
  modeBadge.textContent = sm ? 'Secure Mode' : 'Vulnerable Mode';
  modeBadge.className = 'mode-badge ' + (sm ? 'secure' : 'vulnerable');
  modeExplainer.textContent = sm
    ? 'SECURE_MODE = true — parameterized queries, session-bound authorization, transactional inventory checks, and output escaping are active.'
    : 'SECURE_MODE = false — SQL injection, IDOR, race conditions, and stored XSS are all live for testing purposes.';
}

// ---------------------------------------------------------------------------
// Products + flash sale stock
// ---------------------------------------------------------------------------
function renderProducts(list) {
  products = list;
  productGrid.innerHTML = '';
  auctionSelect.innerHTML = '';

  list.forEach((p) => {
    const pct = Math.min(100, Math.round((p.stock_count / 60) * 100));
    const stockClass = p.stock_count === 0 ? 'out' : p.stock_count <= 5 ? 'low' : '';
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <h3>${escapeText(p.name)}</h3>
      <p class="desc">${escapeText(p.description)}</p>
      <div class="price">$${Number(p.price).toFixed(2)}</div>
      <div class="stock-label ${stockClass}"><span>Stock</span><span>${p.stock_count} left</span></div>
      <div class="stock-bar"><div style="width:${pct}%"></div></div>
      <div class="card-actions">
        <input type="number" min="1" value="1" data-qty="${p.id}" />
        <button data-buy="${p.id}" data-price="${p.price}">Buy Now</button>
      </div>
    `;
    productGrid.appendChild(card);

    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = `${p.name} (#${p.id})`;
    auctionSelect.appendChild(opt);
  });

  document.querySelectorAll('[data-buy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = Number(btn.dataset.buy);
      const price = Number(btn.dataset.price);
      const qtyInput = document.querySelector(`[data-qty="${id}"]`);
      const quantity = Number(qtyInput.value) || 1;
      socket.emit('buy_item', { product_id: id, price, quantity });
    });
  });

  refreshHighestBidDisplay();
}

fetch('/api/products')
  .then((r) => r.json())
  .then(renderProducts);

socket.on('stock_update', (updated) => {
  updated.forEach((u) => {
    const existing = products.find((p) => p.id === u.id);
    if (existing) existing.stock_count = u.stock_count;
  });
  renderProducts(products);
  resetClock();
});

socket.on('purchase_made', (data) => {
  logActivity(
    `Order placed: product #${data.product_id} × ${data.quantity} — charged $${Number(data.charged_price).toFixed(2)}. Stock now ${data.stock_count}.`,
    'buy'
  );
});
socket.on('purchase_error', (data) => logActivity(`Purchase failed: ${data.error}`));

// ---------------------------------------------------------------------------
// Countdown clock (cosmetic, tracks the 5s server broadcast interval)
// ---------------------------------------------------------------------------
const clockEl = document.getElementById('clock');
let secondsLeft = 5;
function resetClock() { secondsLeft = 5; }
setInterval(() => {
  secondsLeft = secondsLeft > 0 ? secondsLeft - 1 : 5;
  clockEl.textContent = `00:0${secondsLeft}`;
}, 1000);

// ---------------------------------------------------------------------------
// Auctions
// ---------------------------------------------------------------------------
let currentHighest = {}; // productId -> {username, bid_amount}

function refreshHighestBidDisplay() {
  const pid = Number(auctionSelect.value);
  const h = currentHighest[pid];
  document.getElementById('highestBid').textContent = h ? `$${Number(h.bid_amount).toFixed(2)}` : '$0.00';
  document.getElementById('highestBidder').textContent = h ? `Leading bidder: ${h.username}` : 'No bids yet';
}

auctionSelect.addEventListener('change', () => {
  document.getElementById('bidError').textContent = '';
  fetch(`/api/bids/${auctionSelect.value}`)
    .then((r) => r.json())
    .then((bids) => {
      if (bids.length) currentHighest[auctionSelect.value] = { username: bids[0].username, bid_amount: bids[0].bid_amount };
      refreshHighestBidDisplay();
    });
});

document.getElementById('bidForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const product_id = Number(auctionSelect.value);
  const username = document.getElementById('bidUsername').value || 'anonymous';
  const bid_amount = Number(document.getElementById('bidAmount').value);
  socket.emit('place_bid', { product_id, username, bid_amount });
});

socket.on('bid_update', (data) => {
  currentHighest[data.product_id] = data.highest;
  if (Number(auctionSelect.value) === Number(data.product_id)) refreshHighestBidDisplay();
  logActivity(`${data.username} bid $${Number(data.bid_amount).toFixed(2)} on product #${data.product_id}.`);
});

socket.on('bid_error', (data) => {
  document.getElementById('bidError').textContent = data.error;
});

// ---------------------------------------------------------------------------
// Live auction chat — VULNERABLE: rendered with innerHTML on purpose so the
// stored-XSS demo (server broadcasts raw text in vulnerable mode) is visible
// end-to-end. Toggle SECURE_MODE server-side to see the server escape output
// before it ever reaches this innerHTML sink.
// ---------------------------------------------------------------------------
document.getElementById('chatForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const handle = document.getElementById('chatHandle').value || 'anonymous';
  const message = document.getElementById('chatMessage').value;
  if (!message) return;
  socket.emit('chat_message', { handle, message });
  document.getElementById('chatMessage').value = '';
});

socket.on('chat_message', (data) => {
  const row = document.createElement('div');
  row.className = 'msg';
  row.innerHTML = `<span class="handle">${data.handle}</span>${data.message}`; // intentionally unsanitized sink
  chatFeed.appendChild(row);
  chatFeed.scrollTop = chatFeed.scrollHeight;
});

// ---------------------------------------------------------------------------
// Product search (SQLi demo)
// ---------------------------------------------------------------------------
document.getElementById('searchBtn').addEventListener('click', runSearch);
document.getElementById('searchInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runSearch();
});

function runSearch() {
  const q = document.getElementById('searchInput').value;
  fetch(`/api/search?q=${encodeURIComponent(q)}`)
    .then((r) => r.json())
    .then((data) => {
      document.getElementById('searchResults').textContent = JSON.stringify(data, null, 2);
    });
}

// ---------------------------------------------------------------------------
// Order details (IDOR demo)
// ---------------------------------------------------------------------------
document.getElementById('loginBtn').addEventListener('click', () => {
  const user_id = Number(document.getElementById('userSelect').value);
  socket.emit('login', { user_id });
  document.getElementById('orderUserId').value = user_id;
  logActivity(`Logged in as user #${user_id}.`);
});

document.getElementById('fetchOrderBtn').addEventListener('click', () => {
  const user_id = Number(document.getElementById('orderUserId').value);
  socket.emit('get_order_details', { user_id });
});

socket.on('order_details', (data) => {
  document.getElementById('orderResults').textContent = JSON.stringify(data, null, 2);
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function logActivity(text, cls) {
  const entry = document.createElement('div');
  entry.className = 'entry' + (cls ? ' ' + cls : '');
  entry.textContent = text;
  activityLog.prepend(entry);
  while (activityLog.children.length > 12) activityLog.removeChild(activityLog.lastChild);
}

function escapeText(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}
