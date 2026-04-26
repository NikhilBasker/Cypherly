/**
 * Secure Chat Server
 * - Pure relay: never reads or stores message content
 * - All messages are E2EE encrypted on the client side
 * - No message persistence of any kind
 * - Helmet security headers
 * - Rate limiting per socket
 * - Room password (PBKDF2 hashed, server never stores plaintext)
 * - One-time invite tokens (expire after use or 24h)
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);

app.use(express.json());

// ── Security Headers ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "ws:", "wss:"],
      imgSrc: ["'none'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  hsts: false,
}));

app.disable('x-powered-by');

// ── Room registry ─────────────────────────────────────────────────────────────
// rooms: Map<roomId, { passwordHash, salt, peers: Map<socketId, publicKey> }>
const rooms = new Map();

// ── Invite tokens ─────────────────────────────────────────────────────────────
// tokens: Map<token, { room, expiresAt }>
const tokens = new Map();

const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Clean up expired tokens every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokens) {
    if (now > data.expiresAt) tokens.delete(token);
  }
}, 60 * 60 * 1000);

// ── Password hashing (PBKDF2) ─────────────────────────────────────────────────
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 310_000, 32, 'sha256').toString('hex');
}

function verifyPassword(password, salt, storedHash) {
  const hash = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

// ── REST: Create room ─────────────────────────────────────────────────────────
// POST /api/create-room  { room, password }
// Creates a room with a hashed password and returns a host invite token
app.post('/api/create-room', (req, res) => {
  const { room, password } = req.body;
  if (!room || !password || typeof room !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const safeRoom = room.replace(/[^a-zA-Z0-9\-]/g, '').slice(0, 64);
  if (!safeRoom) return res.status(400).json({ error: 'Invalid room name' });
  if (rooms.has(safeRoom)) return res.status(409).json({ error: 'Room already exists' });

  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(password, salt);

  rooms.set(safeRoom, { passwordHash, salt, peers: new Map() });

  // Generate first invite token for the host
  const token = crypto.randomBytes(32).toString('hex');
  tokens.set(token, { room: safeRoom, expiresAt: Date.now() + TOKEN_TTL_MS });

  res.json({ token, room: safeRoom });
});

// ── REST: Generate invite token ───────────────────────────────────────────────
// POST /api/invite  { room, password }
// Returns a one-time token to share with a friend
app.post('/api/invite', (req, res) => {
  const { room, password } = req.body;
  if (!room || !password) return res.status(400).json({ error: 'Invalid request' });

  const safeRoom = room.replace(/[^a-zA-Z0-9\-]/g, '').slice(0, 64);
  const roomData = rooms.get(safeRoom);
  if (!roomData) return res.status(404).json({ error: 'Room not found' });

  if (!verifyPassword(password, roomData.salt, roomData.passwordHash)) {
    return res.status(403).json({ error: 'Wrong password' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  tokens.set(token, { room: safeRoom, expiresAt: Date.now() + TOKEN_TTL_MS });

  res.json({ token, room: safeRoom });
});

// ── Socket.io ─────────────────────────────────────────────────────────────────
const io = new Server(server, {
  cors: { origin: false },
  pingTimeout: 30000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e5,
});

// ── Rate Limiter (per socket) ─────────────────────────────────────────────────
const RATE_LIMIT = { windowMs: 10_000, maxMessages: 20 };

function makeRateLimiter() {
  let count = 0;
  let windowStart = Date.now();
  return function isAllowed() {
    const now = Date.now();
    if (now - windowStart > RATE_LIMIT.windowMs) { count = 0; windowStart = now; }
    count++;
    return count <= RATE_LIMIT.maxMessages;
  };
}

// ── Socket Logic ──────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  const isAllowed = makeRateLimiter();
  let currentRoom = null;

  // Client sends: { room, publicKey, token }
  // token is a one-time invite token — consumed on use
  socket.on('join', ({ room, publicKey, token }) => {
    if (!room || !publicKey || !token ||
        typeof room !== 'string' || typeof token !== 'string') {
      socket.emit('auth-error', 'Missing credentials');
      return;
    }

    const safeRoom = room.replace(/[^a-zA-Z0-9\-]/g, '').slice(0, 64);
    if (!safeRoom) { socket.emit('auth-error', 'Invalid room'); return; }

    // Validate token
    const tokenData = tokens.get(token);
    if (!tokenData || tokenData.room !== safeRoom || Date.now() > tokenData.expiresAt) {
      socket.emit('auth-error', 'Invalid or expired invite token');
      return;
    }

    // Consume token — one-time use
    tokens.delete(token);

    // Room must exist (created via /api/create-room)
    const roomData = rooms.get(safeRoom);
    if (!roomData) { socket.emit('auth-error', 'Room not found'); return; }

    currentRoom = safeRoom;
    socket.join(safeRoom);
    roomData.peers.set(socket.id, publicKey);

    const peers = {};
    for (const [id, pk] of roomData.peers) {
      if (id !== socket.id) peers[id] = pk;
    }
    socket.emit('room-peers', peers);

    socket.to(safeRoom).emit('peer-joined', { id: socket.id, publicKey });
    io.to(safeRoom).emit('peer-count', roomData.peers.size);
  });

  // Relay encrypted message — server never decrypts, never stores
  socket.on('encrypted-message', (payload) => {
    if (!currentRoom) return;
    if (!isAllowed()) {
      socket.emit('error', 'Rate limit exceeded');
      return;
    }

    // Validate payload shape only — never inspect content
    if (
      typeof payload !== 'object' ||
      typeof payload.iv !== 'string' ||
      typeof payload.ciphertext !== 'string' ||
      typeof payload.recipientId !== 'string'
    ) {
      socket.emit('error', 'Malformed payload');
      return;
    }

    // Relay only to intended recipient (or broadcast if no specific recipient)
    const target = payload.recipientId;
    if (target && io.sockets.sockets.has(target)) {
      io.to(target).emit('encrypted-message', {
        from: socket.id,
        iv: payload.iv,
        ciphertext: payload.ciphertext,
      });
    } else {
      // Broadcast to room (each client decrypts with their own key)
      socket.to(currentRoom).emit('encrypted-message', {
        from: socket.id,
        iv: payload.iv,
        ciphertext: payload.ciphertext,
      });
    }
  });

  // Typing indicator relay — no content, just signal
  socket.on("typing", ({ recipientId, isTyping }) => {
    if (!currentRoom) return;
    if (typeof isTyping !== "boolean") return;
    if (recipientId && io.sockets.sockets.has(recipientId)) {
      io.to(recipientId).emit("typing", { from: socket.id, isTyping });
    } else {
      socket.to(currentRoom).emit("typing", { from: socket.id, isTyping });
    }
  });

  // Read receipt relay
  socket.on("read-receipt", ({ recipientId, msgId }) => {
    if (!currentRoom || typeof msgId !== "string") return;
    if (recipientId && io.sockets.sockets.has(recipientId)) {
      io.to(recipientId).emit("read-receipt", { from: socket.id, msgId });
    } else {
      socket.to(currentRoom).emit("read-receipt", { from: socket.id, msgId });
    }
  });

  // Disconnection — clean up, no logs
  socket.on('disconnect', () => {
    if (currentRoom && rooms.has(currentRoom)) {
      const roomData = rooms.get(currentRoom);
      roomData.peers.delete(socket.id);
      if (roomData.peers.size === 0) {
        rooms.delete(currentRoom); // clean up empty room
      } else {
        io.to(currentRoom).emit('peer-left', socket.id);
        io.to(currentRoom).emit('peer-count', roomData.peers.size);
      }
    }
  });
});

// ── Static Files ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,        // don't leak file metadata
  lastModified: false,
}));

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const HOST = '127.0.0.1'; // bind to localhost only — Tor proxies in from outside

server.listen(PORT, HOST, () => {
  console.log(`[secure-chat] Server listening on ${HOST}:${PORT}`);
  console.log('[secure-chat] Server is relay-only. No messages are stored.');
});
