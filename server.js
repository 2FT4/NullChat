const express = require('express');
const http = require('http');
const fs = require('fs');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

// ==========================================
// CONFIGURATION
// ==========================================
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const TOKEN_TTL_MS = Number(process.env.TOKEN_TTL_MS || 60 * 24 * 60 * 60 * 1000); // ~2 mois
const MAX_SESSIONS_PER_USER = Number(process.env.MAX_SESSIONS_PER_USER || 8);
const INDEX_FILE = process.env.INDEX_FILE || 'index_2.html';
const PUBLIC_DIR = path.join(__dirname, 'public');
// NB : l'ancienne route /api/upload + le dossier /uploads servi en statique
// ont été retirés. Le client n'appelle jamais /api/upload (les médias
// transitent uniquement chiffrés via les sockets dm:message/encrypted_message)
// — ce endpoint n'était donc que de la surface d'attaque inutile : fichiers
// écrits en clair sur disque et servis publiquement sans aucune vérification
// d'appartenance/amitié, ce qui contredisait le modèle E2E du reste de l'app.
// Config ICE pour les appels WebRTC (STUN par défaut, TURN optionnel via env).
const ICE_SERVERS = [{ urls: process.env.STUN_URL || 'stun:stun.l.google.com:19302' }];
if (process.env.TURN_URL) {
  ICE_SERVERS.push({
    urls: process.env.TURN_URL,
    username: process.env.TURN_USERNAME || undefined,
    credential: process.env.TURN_CREDENTIAL || undefined
  });
}

const LIMITS = {
  usernameMin: 3,
  usernameMax: 32,
  passwordMin: 8,
  passwordMax: 128,
  messageMax: 4000,
  ciphertextMaxBytes: 20000,
  mediaCiphertextMaxBytes: 25 * 1024 * 1024, // ~25 Mo
  ivBytes: 12,
  publicKeyMaxBytes: 200,
  mimeMax: 100,
  filenameMax: 200,
  allowedKinds: new Set(['text', 'image', 'video', 'audio']),
  nullIdRegex: /^[A-Z0-9][A-Z0-9-]{1,14}[A-Z0-9]$/,
  usernameRegex: /^[a-zA-Z0-9_.\-]+$/,
  avatarMaxDataUrlLength: 250 * 1024,
  offlineDmQueueMaxPerUser: 200,
  offlineDmQueueTtlMs: 14 * 24 * 60 * 60 * 1000,
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CORS_ORIGIN, methods: ['GET', 'POST'] },
  maxHttpBufferSize: LIMITS.mediaCiphertextMaxBytes + 2 * 1024 * 1024
});

app.disable('x-powered-by');
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}
if (NODE_ENV === 'production' && CORS_ORIGIN === '*') {
  console.error('⚠️ CORS_ORIGIN="*" en production : configure la variable d’environnement CORS_ORIGIN avec ton vrai domaine.');
}

app.use(express.json({ limit: '25MB' }));

// En-têtes de sécurité
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'microphone=(self), camera=(self)');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "img-src 'self' data: blob:",
      "media-src 'self' data: blob:",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self' ws: wss:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'"
    ].join('; ')
  );
  if (NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});

app.use(express.static(PUBLIC_DIR));

// ==========================================
// BASE DE DONNÉES EN MÉMOIRE
// ==========================================
const users = new Map();          
const nullIdToUser = new Map();   
const activeTokens = new Map();   
const usernameToTokens = new Map(); 
const connectedSockets = new Map(); 
const userSockets = new Map();    
const dmOfflineQueue = new Map(); 

const friends = new Map();          
const pendingRequests = new Map();  
const blocked = new Map();          

// ==========================================
// HYDRATATION DEPUIS LA BASE SQLITE (au démarrage)
// ==========================================
// users / friends / blocked / pending_requests survivent désormais à un
// redémarrage ; seules les sessions (activeTokens) et l'état de connexion
// restent volatiles, ce qui est le comportement attendu.
function loadStateFromDb() {
  for (const u of db.loadAllUsers()) {
    if (!u.nullId) continue; // ligne orpheline sans null_id, ignorée
    const key = u.username.toLowerCase();
    users.set(key, {
      username: u.username,
      passwordHash: u.passwordHash,
      nullId: u.nullId,
      publicKey: u.publicKey,
      avatarDataUrl: u.avatarDataUrl || null
    });
    nullIdToUser.set(u.nullId, u.username);
    if (!friends.has(u.nullId)) friends.set(u.nullId, new Set());
  }
  for (const f of db.loadAllFriends()) {
    if (!friends.has(f.userNullId)) friends.set(f.userNullId, new Set());
    friends.get(f.userNullId).add(f.friendNullId);
  }
  for (const b of db.loadAllBlocked()) {
    if (!blocked.has(b.userNullId)) blocked.set(b.userNullId, new Set());
    blocked.get(b.userNullId).add(b.blockedNullId);
  }
  for (const r of db.loadAllPendingRequests()) {
    pendingRequests.set(r.id, { id: r.id, fromNullId: r.fromNullId, toNullId: r.toNullId, createdAt: r.createdAt });
  }
  log(`Base chargée : ${users.size} compte(s), ${db.loadAllFriends().length} lien(s) d'amitié, ${pendingRequests.size} demande(s) en attente.`);
}
loadStateFromDb();

// ==========================================
// UTILITAIRES & VALIDATION
// ==========================================
function generateNullId() {
  let nullId;
  do {
    const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    nullId = `${part1}-${part2}`;
  } while (nullIdToUser.has(nullId));
  return nullId;
}

function generateRandomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

function logError(...args) {
  console.error(`[${new Date().toISOString()}]`, ...args);
}

function isNonEmptyString(v, max) {
  return typeof v === 'string' && v.trim().length > 0 && v.length <= (max || 100000);
}

function isValidUsername(username) {
  return (
    typeof username === 'string' &&
    username.length >= LIMITS.usernameMin &&
    username.length <= LIMITS.usernameMax &&
    LIMITS.usernameRegex.test(username)
  );
}

function isValidPassword(password) {
  if (
    typeof password !== 'string' ||
    password.length < LIMITS.passwordMin ||
    password.length > LIMITS.passwordMax
  ) {
    return false;
  }
  return Buffer.byteLength(password, 'utf8') <= 72;
}

function isValidNullId(nullId) {
  return typeof nullId === 'string' && LIMITS.nullIdRegex.test(nullId);
}

function isValidByteArray(arr, maxBytes) {
  return (
    Array.isArray(arr) &&
    arr.length > 0 &&
    arr.length <= maxBytes &&
    arr.every(n => Number.isInteger(n) && n >= 0 && n <= 255)
  );
}

function isValidPublicKey(publicKey) {
  if (publicKey === null || publicKey === undefined) return true;
  return isValidByteArray(publicKey, LIMITS.publicKeyMaxBytes);
}

function isValidKind(kind) {
  return kind === undefined || kind === null || LIMITS.allowedKinds.has(kind);
}

function isValidAvatarDataUrl(dataUrl) {
  if (dataUrl === null || dataUrl === undefined) return true;
  return (
    typeof dataUrl === 'string' &&
    dataUrl.length <= LIMITS.avatarMaxDataUrlLength &&
    /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/]+=*$/.test(dataUrl)
  );
}

function getUserByNullId(targetNullId) {
  const uname = nullIdToUser.get(targetNullId);
  return uname ? users.get(uname.toLowerCase()) : null;
}

function isValidMeta(str, max) {
  return str === undefined || str === null || (typeof str === 'string' && str.length <= max);
}

function ciphertextLimitFor(kind) {
  return kind && kind !== 'text' ? LIMITS.mediaCiphertextMaxBytes : LIMITS.ciphertextMaxBytes;
}

function createRateLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits.entries()) {
      if (entry.resetAt <= now) hits.delete(key);
    }
  }, windowMs).unref();

  return function check(key) {
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    return entry.count <= max;
  };
}

const authRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 20 });
const loginAccountRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 8 });
const friendRequestRateLimit = createRateLimiter({ windowMs: 60 * 1000, max: 10 });
const messageRateLimit = createRateLimiter({ windowMs: 10 * 1000, max: 40 });
const attachmentRateLimit = createRateLimiter({ windowMs: 60 * 1000, max: 10 });
const socketEventRateLimit = createRateLimiter({ windowMs: 5 * 1000, max: 120 });

function clientIp(req) {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

function authRateLimitMiddleware(req, res, next) {
  if (!authRateLimit(clientIp(req))) {
    return res.status(429).json({ error: 'Trop de tentatives, réessaie dans quelques minutes.' });
  }
  next();
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1] || req.body?.token;
  const session = token ? activeTokens.get(token) : null;
  if (!session || session.expiresAt <= Date.now()) {
    return res.status(401).json({ error: 'Non authentifié.' });
  }
  session.expiresAt = Date.now() + TOKEN_TTL_MS;
  req.session = session;
  req.currentToken = token;
  next();
}

// ==========================================
// ROUTES HTTP (API AUTH & MEDIAS)
// ==========================================

app.post('/api/register', authRateLimitMiddleware, async (req, res) => {
  try {
    const { username, password, publicKey, customNullId } = req.body || {};
    const cleanUsername = typeof username === 'string' ? username.trim() : '';

    if (!isValidUsername(cleanUsername)) {
      return res.status(400).json({
        error: `Nom d'utilisateur invalide (${LIMITS.usernameMin}-${LIMITS.usernameMax} caractères, lettres/chiffres/-/_/. uniquement).`
      });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: `Mot de passe invalide (${LIMITS.passwordMin} caractères minimum).` });
    }
    if (!isValidPublicKey(publicKey)) {
      return res.status(400).json({ error: 'Clé publique invalide.' });
    }
    if (users.has(cleanUsername.toLowerCase())) {
      return res.status(409).json({ error: "Ce nom d'utilisateur existe déjà." });
    }

    let nullId;
    if (customNullId) {
      const cleanCustomNullId = typeof customNullId === 'string' ? customNullId.trim().toUpperCase() : '';
      if (!isValidNullId(cleanCustomNullId)) {
        return res.status(400).json({
          error: 'NULLID invalide (3 à 16 caractères, lettres/chiffres, tiret(s) au milieu autorisé(s)).'
        });
      }
      if (nullIdToUser.has(cleanCustomNullId)) {
        return res.status(409).json({ error: 'Ce NULLID est déjà pris, choisis-en un autre.' });
      }
      nullId = cleanCustomNullId;
    } else {
      nullId = generateNullId();
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const newUser = {
      username: cleanUsername,
      passwordHash,
      nullId,
      publicKey: publicKey || null,
      avatarDataUrl: null
    };

    users.set(cleanUsername.toLowerCase(), newUser);
    nullIdToUser.set(nullId, cleanUsername);
    friends.set(nullId, new Set());
    db.createUser({
      username: newUser.username,
      passwordHash: newUser.passwordHash,
      nullId: newUser.nullId,
      publicKey: newUser.publicKey,
      avatarDataUrl: newUser.avatarDataUrl
    });

    // Auto-connexion directement après l'inscription
    const token = generateRandomToken();
    activeTokens.set(token, {
      username: newUser.username,
      nullId: newUser.nullId,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      createdAt: Date.now(),
      userAgent: (req.headers['user-agent'] || '').slice(0, 200)
    });
    
    const usernameKey = cleanUsername.toLowerCase();
    if (!usernameToTokens.has(usernameKey)) usernameToTokens.set(usernameKey, new Set());
    usernameToTokens.get(usernameKey).add(token);

    log('Nouveau compte créé :', cleanUsername, nullId);
    return res.status(201).json({
      success: true,
      message: 'Compte créé avec succès !',
      token,
      nullId: newUser.nullId,
      username: newUser.username
    });
  } catch (err) {
    logError("Erreur /api/register :", err);
    res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
  }
});

app.post('/api/login', authRateLimitMiddleware, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!isNonEmptyString(username, LIMITS.usernameMax) || !isNonEmptyString(password, LIMITS.passwordMax)) {
      return res.status(400).json({ error: 'Identifiants invalides.' });
    }

    const usernameKey = username.toLowerCase().trim();

    if (!loginAccountRateLimit(usernameKey)) {
      return res.status(429).json({ error: 'Trop de tentatives sur ce compte, réessaie dans quelques minutes.' });
    }

    const user = users.get(usernameKey);
    if (!user) {
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    const token = generateRandomToken();
    activeTokens.set(token, {
      username: user.username,
      nullId: user.nullId,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      createdAt: Date.now(),
      userAgent: (req.headers['user-agent'] || '').slice(0, 200)
    });
    if (!usernameToTokens.has(usernameKey)) usernameToTokens.set(usernameKey, new Set());
    usernameToTokens.get(usernameKey).add(token);

    const tokensForUser = usernameToTokens.get(usernameKey);
    if (tokensForUser.size > MAX_SESSIONS_PER_USER) {
      const oldestFirst = [...tokensForUser]
        .map(t => ({ t, createdAt: activeTokens.get(t)?.createdAt || 0 }))
        .sort((a, b) => a.createdAt - b.createdAt);
      oldestFirst
        .slice(0, tokensForUser.size - MAX_SESSIONS_PER_USER)
        .forEach(({ t }) => revokeToken(t));
    }

    return res.json({
      success: true,
      token,
      nullId: user.nullId,
      username: user.username,
      avatarDataUrl: user.avatarDataUrl || null
    });
  } catch (err) {
    logError('Erreur /api/login :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

// Nouvelle route pour l'envoi de fichier / média lourd chiffré
app.post('/api/upload', requireAuth, (req, res) => {
  try {
    const { fileData, fileName, mimeType } = req.body || {};
    if (!fileData || typeof fileData !== 'string') {
      return res.status(400).json({ error: 'Fichier invalide.' });
    }

    const fileId = crypto.randomBytes(16).toString('hex');
    const safeExt = path.extname(fileName || '').slice(0, 10) || '.bin';
    const savedName = `${fileId}${safeExt}`;
    const filePath = path.join(UPLOADS_DIR, savedName);

    // Extraction du buffer base64 si fourni sous forme de dataURL
    const base64Data = fileData.replace(/^data:.*;base64,/, '');
    fs.writeFile(filePath, base64Data, 'base64', (err) => {
      if (err) {
        logError("Erreur écriture fichier :", err);
        return res.status(500).json({ error: 'Impossible de sauvegarder le fichier.' });
      }
      res.json({
        success: true,
        fileUrl: `/uploads/${savedName}`,
        fileName: fileName || savedName,
        mimeType: mimeType || 'application/octet-stream'
      });
    });
  } catch (err) {
    logError("Erreur /api/upload :", err);
    res.status(500).json({ error: 'Erreur serveur lors de l\'upload.' });
  }
});

// Config ICE pour le client (permet d'ajouter un TURN sans toucher au front)
app.get('/api/ice-servers', requireAuth, (req, res) => {
  res.json({ iceServers: ICE_SERVERS });
});

function revokeToken(token) {
  const session = activeTokens.get(token);
  if (!session) return;
  activeTokens.delete(token);
  const key = session.username.toLowerCase();
  usernameToTokens.get(key)?.delete(token);
}

app.post('/api/logout', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.body?.token;
  if (token) revokeToken(token);
  res.json({ success: true });
});

app.get('/api/sessions', requireAuth, (req, res) => {
  const key = req.session.username.toLowerCase();
  const tokens = usernameToTokens.get(key) || new Set();
  const sessions = [...tokens]
    .map(t => {
      const s = activeTokens.get(t);
      if (!s || s.expiresAt <= Date.now()) return null;
      return {
        id: t.slice(0, 8),
        current: t === req.currentToken,
        createdAt: s.createdAt || null,
        expiresAt: s.expiresAt || null,
        userAgent: s.userAgent || null
      };
    })
    .filter(Boolean);
  res.json({ sessions });
});

app.delete('/api/sessions/:id', requireAuth, (req, res) => {
  const key = req.session.username.toLowerCase();
  const tokens = usernameToTokens.get(key) || new Set();
  const target = [...tokens].find(t => t.slice(0, 8) === req.params.id);
  if (!target) return res.status(404).json({ error: 'Session introuvable.' });
  revokeToken(target);
  res.json({ success: true });
});

// Purges automatiques
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of activeTokens.entries()) {
    if (session.expiresAt <= now) revokeToken(token);
  }
}, 15 * 60 * 1000).unref();

setInterval(() => {
  const now = Date.now();
  for (const [targetNullId, queue] of dmOfflineQueue.entries()) {
    const kept = queue.filter(entry => now - entry.queuedAt <= LIMITS.offlineDmQueueTtlMs);
    if (kept.length) dmOfflineQueue.set(targetNullId, kept);
    else dmOfflineQueue.delete(targetNullId);
  }
}, 60 * 60 * 1000).unref();

const PENDING_REQUEST_TTL_MS = 7 * 24 * 60 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, reqData] of pendingRequests.entries()) {
    if (now - reqData.createdAt > PENDING_REQUEST_TTL_MS) {
      pendingRequests.delete(id);
      db.removePendingRequest(id);
    }
  }
}, 60 * 60 * 1000).unref();

// Route SPA
app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  const indexPath = path.join(PUBLIC_DIR, INDEX_FILE);
  fs.access(indexPath, fs.constants.R_OK, (err) => {
    if (err) return res.status(404).send('Fichier introuvable.');
    res.sendFile(indexPath);
  });
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Corps de requête JSON invalide.' });
  }
  logError('Erreur HTTP non gérée :', err);
  res.status(500).json({ error: 'Erreur serveur.' });
});

// ==========================================
// MIDDLEWARE AUTHENTIFICATION SOCKET.IO
// ==========================================
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.split(' ')[1];

  if (!token) {
    socket.user = { username: `Guest_${socket.id.slice(0, 4)}`, nullId: null };
    return next();
  }

  const session = activeTokens.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    activeTokens.delete(token);
    return next(new Error('Token invalide ou expiré.'));
  }

  session.expiresAt = Date.now() + TOKEN_TTL_MS;
  socket.user = { username: session.username, nullId: session.nullId };
  next();
});

// ==========================================
// HELPERS MÉTIER
// ==========================================
function areFriends(nullIdA, nullIdB) {
  return !!friends.get(nullIdA)?.has(nullIdB);
}

function isBlocked(nullIdA, nullIdB) {
  return !!blocked.get(nullIdA)?.has(nullIdB) || !!blocked.get(nullIdB)?.has(nullIdA);
}

function sendFriendList(socket, nullId) {
  const userFriendsList = friends.get(nullId) || new Set();
  const list = [];

  for (const fNullId of userFriendsList) {
    const friendUsername = nullIdToUser.get(fNullId);
    if (friendUsername) {
      const isOnline = userSockets.has(fNullId);
      const friendUser = getUserByNullId(fNullId);
      list.push({
        nullId: fNullId,
        username: friendUsername,
        online: isOnline,
        socketId: isOnline ? userSockets.get(fNullId) : null,
        avatarDataUrl: friendUser?.avatarDataUrl || null
      });
    }
  }
  socket.emit('friend:list', { friends: list });
}

function sendPendingFriendRequests(socket, nullId) {
  const incoming = [...pendingRequests.values()]
    .filter(r => r.toNullId === nullId)
    .map(r => {
      const fromUsername = nullIdToUser.get(r.fromNullId);
      const fromUser = getUserByNullId(r.fromNullId);
      return {
        requestId: r.id,
        from: { nullId: r.fromNullId, username: fromUsername, avatarDataUrl: fromUser?.avatarDataUrl || null }
      };
    })
    .filter(r => r.from.username);
  if (incoming.length) socket.emit('friend:pending_list', { requests: incoming });
}

function flushOfflineDms(socket, nullId) {
  const queue = dmOfflineQueue.get(nullId);
  if (queue && queue.length) {
    socket.emit('dm:queued_messages', { messages: queue.map(e => e.payload) });
    dmOfflineQueue.delete(nullId);
  }
}

function notifyFriendsStatus(nullId, online) {
  const userFriendsList = friends.get(nullId) || new Set();
  for (const fNullId of userFriendsList) {
    const friendSocketId = userSockets.get(fNullId);
    if (friendSocketId) {
      io.to(friendSocketId).emit('friend:status', {
        nullId,
        online,
        socketId: online ? userSockets.get(nullId) : null
      });
    }
  }
}

function safeHandler(socket, handler) {
  return (data) => {
    if (!socketEventRateLimit(socket.id)) return;
    try {
      handler(data);
    } catch (err) {
      logError(`Erreur socket (${socket.id}) :`, err);
      socket.emit('friend:error', { message: 'Une erreur interne est survenue.' });
    }
  };
}

// ==========================================
// GESTION SOCKET.IO
// ==========================================
io.on('connection', (socket) => {
  const { username, nullId } = socket.user;
  connectedSockets.set(socket.id, { username, nullId });

  if (nullId) {
    userSockets.set(nullId, socket.id);
    notifyFriendsStatus(nullId, true);
    sendFriendList(socket, nullId);
    sendPendingFriendRequests(socket, nullId);
    flushOfflineDms(socket, nullId);
  }

  socket.broadcast.emit('user_joined', { username });

  socket.on('share_public_key', safeHandler(socket, (publicKey) => {
    if (!isValidPublicKey(publicKey)) return;
    socket.broadcast.emit('receive_public_key', {
      senderId: socket.id,
      publicKey,
      isNewUser: true
    });
  }));

  socket.on('share_public_key_reply', safeHandler(socket, (data) => {
    if (!data?.targetId || !isValidPublicKey(data.publicKey)) return;
    if (!connectedSockets.has(data.targetId)) return;
    io.to(data.targetId).emit('receive_public_key', {
      senderId: socket.id,
      publicKey: data.publicKey,
      isNewUser: false
    });
  }));

  socket.on('encrypted_message', safeHandler(socket, (data) => {
    const kind = data?.kind || 'text';
    if (!isValidKind(kind)) return;
    const isAttachment = kind !== 'text';

    if (!messageRateLimit(socket.id)) {
      return socket.emit('friend:error', { message: 'Tu envoies des messages trop vite, ralentis un peu.' });
    }
    if (isAttachment && !attachmentRateLimit(socket.id)) {
      return socket.emit('friend:error', { message: 'Trop de pièces jointes envoyées d’un coup, ralentis un peu.' });
    }
    if (!Array.isArray(data?.targets) || !isNonEmptyString(data?.author, LIMITS.usernameMax)) return;
    if (!isValidMeta(data.mime, LIMITS.mimeMax) || !isValidMeta(data.filename, LIMITS.filenameMax)) return;

    data.targets.slice(0, 500).forEach(t => {
      if (!t?.targetId || !connectedSockets.has(t.targetId)) return;
      if (!isValidByteArray(t.ciphertext, ciphertextLimitFor(kind))) return;
      if (!isValidByteArray(t.iv, LIMITS.ivBytes)) return;

      io.to(t.targetId).emit('encrypted_message', {
        senderId: socket.id,
        author: data.author,
        ciphertext: t.ciphertext,
        iv: t.iv,
        kind,
        mime: data.mime || null,
        filename: data.filename || null,
        timestamp: Date.now()
      });
    });
  }));

  socket.on('friend:request', safeHandler(socket, ({ targetNullId } = {}) => {
    if (!nullId) return socket.emit('friend:error', { message: 'Vous devez être connecté.' });
    if (!friendRequestRateLimit(nullId)) {
      return socket.emit('friend:error', { message: 'Trop de demandes envoyées, réessaie plus tard.' });
    }
    if (!isValidNullId(targetNullId)) {
      return socket.emit('friend:error', { message: 'NULLID invalide.' });
    }
    if (targetNullId === nullId) {
      return socket.emit('friend:error', { message: "Tu ne peux pas t'ajouter toi-même." });
    }
    if (!nullIdToUser.has(targetNullId)) {
      return socket.emit('friend:error', { message: 'NULLID inexistant.' });
    }
    if (areFriends(nullId, targetNullId)) {
      return socket.emit('friend:error', { message: 'Vous êtes déjà amis.' });
    }
    if (isBlocked(nullId, targetNullId)) {
      return socket.emit('friend:error', { message: 'Impossible d’envoyer une demande à cet utilisateur.' });
    }
    const alreadyPending = [...pendingRequests.values()].some(
      r => (r.fromNullId === nullId && r.toNullId === targetNullId) ||
           (r.fromNullId === targetNullId && r.toNullId === nullId)
    );
    if (alreadyPending) {
      return socket.emit('friend:error', { message: 'Une demande est déjà en attente avec cet utilisateur.' });
    }

    const requestId = crypto.randomUUID();
    const newRequest = { id: requestId, fromNullId: nullId, toNullId: targetNullId, createdAt: Date.now() };
    pendingRequests.set(requestId, newRequest);
    db.addPendingRequest(newRequest);

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      const senderUser = getUserByNullId(nullId);
      io.to(targetSocketId).emit('friend:request_received', {
        requestId,
        from: { nullId, username, avatarDataUrl: senderUser?.avatarDataUrl || null }
      });
    }
  }));

  socket.on('friend:accept', safeHandler(socket, ({ requestId } = {}) => {
    if (!nullId) return;
    const req = pendingRequests.get(requestId);
    if (!req) return;
    if (req.toNullId !== nullId) {
      return socket.emit('friend:error', { message: 'Action non autorisée.' });
    }

    const { fromNullId, toNullId } = req;
    if (!friends.has(fromNullId)) friends.set(fromNullId, new Set());
    if (!friends.has(toNullId)) friends.set(toNullId, new Set());
    friends.get(fromNullId).add(toNullId);
    friends.get(toNullId).add(fromNullId);
    db.addFriendPair(fromNullId, toNullId);

    pendingRequests.delete(requestId);
    db.removePendingRequest(requestId);

    const fromSocket = userSockets.get(fromNullId);
    const toSocket = userSockets.get(toNullId);
    const fromUsername = nullIdToUser.get(fromNullId);
    const toUsername = nullIdToUser.get(toNullId);
    if (!fromUsername || !toUsername) return;

    if (fromSocket) {
      io.to(fromSocket).emit('friend:added', {
        nullId: toNullId,
        username: toUsername,
        online: userSockets.has(toNullId),
        socketId: userSockets.get(toNullId) || null,
        avatarDataUrl: getUserByNullId(toNullId)?.avatarDataUrl || null
      });
    }
    if (toSocket) {
      io.to(toSocket).emit('friend:added', {
        nullId: fromNullId,
        username: fromUsername,
        online: userSockets.has(fromNullId),
        socketId: userSockets.get(fromNullId) || null,
        avatarDataUrl: getUserByNullId(fromNullId)?.avatarDataUrl || null
      });
    }
  }));

  socket.on('friend:decline', safeHandler(socket, ({ requestId } = {}) => {
    if (!nullId) return;
    const req = pendingRequests.get(requestId);
    if (!req) return;
    if (req.toNullId !== nullId) {
      return socket.emit('friend:error', { message: 'Action non autorisée.' });
    }
    pendingRequests.delete(requestId);
    db.removePendingRequest(requestId);
  }));

  socket.on('friend:remove', safeHandler(socket, ({ nullId: targetNullId } = {}) => {
    if (!nullId || !isValidNullId(targetNullId)) return;
    friends.get(nullId)?.delete(targetNullId);
    friends.get(targetNullId)?.delete(nullId);
    db.removeFriendPair(nullId, targetNullId);

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('friend:removed', { nullId });
    }
  }));

  socket.on('friend:block', safeHandler(socket, ({ nullId: targetNullId } = {}) => {
    if (!nullId || !isValidNullId(targetNullId)) return;
    if (!blocked.has(nullId)) blocked.set(nullId, new Set());
    blocked.get(nullId).add(targetNullId);
    db.addBlock(nullId, targetNullId);

    friends.get(nullId)?.delete(targetNullId);
    friends.get(targetNullId)?.delete(nullId);
    db.removeFriendPair(nullId, targetNullId);

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('friend:removed', { nullId });
    }
  }));

  socket.on('friend:unblock', safeHandler(socket, ({ nullId: targetNullId } = {}) => {
    if (!nullId || !isValidNullId(targetNullId)) return;
    blocked.get(nullId)?.delete(targetNullId);
    db.removeBlock(nullId, targetNullId);
  }));

  socket.on('profile:avatar', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const avatarDataUrl = data.avatarDataUrl ?? null;
    if (!isValidAvatarDataUrl(avatarDataUrl)) {
      return socket.emit('friend:error', { message: 'Avatar invalide ou trop volumineux (250 Ko max).' });
    }
    const user = getUserByNullId(nullId);
    if (!user) return;
    user.avatarDataUrl = avatarDataUrl;
    db.updateAvatar(nullId, avatarDataUrl);

    const userFriendsList = friends.get(nullId) || new Set();
    for (const fNullId of userFriendsList) {
      const friendSocketId = userSockets.get(fNullId);
      if (friendSocketId) {
        io.to(friendSocketId).emit('friend:avatar_updated', { nullId, avatarDataUrl });
      }
    }
  }));

  socket.on('dm:key_exchange', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    if (!data.targetSocketId || !isValidPublicKey(data.publicKey)) return;

    const target = connectedSockets.get(data.targetSocketId);
    if (!target?.nullId || !areFriends(nullId, target.nullId) || isBlocked(nullId, target.nullId)) return;

    io.to(data.targetSocketId).emit('dm:key_exchange', {
      senderNullId: nullId,
      senderSocketId: socket.id,
      publicKey: data.publicKey,
      isNewUser: !!data.isNewUser
    });
  }));

  socket.on('dm:message', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const kind = data.kind || 'text';
    if (!isValidKind(kind)) return;
    const isAttachment = kind !== 'text';

    if (!messageRateLimit(socket.id)) {
      return socket.emit('friend:error', { message: 'Tu envoies des messages trop vite, ralentis un peu.' });
    }
    if (isAttachment && !attachmentRateLimit(socket.id)) {
      return socket.emit('friend:error', { message: 'Trop de pièces jointes envoyées d’un coup, ralentis un peu.' });
    }
    const targetNullId = data.targetNullId || connectedSockets.get(data.targetSocketId)?.nullId;
    if (!isValidNullId(targetNullId)) return;
    if (!isValidByteArray(data.ciphertext, ciphertextLimitFor(kind))) return;
    if (!isValidByteArray(data.iv, LIMITS.ivBytes)) return;
    if (!isValidMeta(data.mime, LIMITS.mimeMax) || !isValidMeta(data.filename, LIMITS.filenameMax)) return;
    if (!areFriends(nullId, targetNullId) || isBlocked(nullId, targetNullId)) return;

    const messageId = crypto.randomUUID();
    const payload = {
      messageId,
      senderNullId: nullId,
      author: username,
      ciphertext: data.ciphertext,
      iv: data.iv,
      kind,
      mime: data.mime || null,
      filename: data.filename || null,
      timestamp: Date.now()
    };

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('dm:message', payload);
    } else {
      if (!dmOfflineQueue.has(targetNullId)) dmOfflineQueue.set(targetNullId, []);
      const queue = dmOfflineQueue.get(targetNullId);
      queue.push({ payload, queuedAt: Date.now() });
      while (queue.length > LIMITS.offlineDmQueueMaxPerUser) queue.shift();
      socket.emit('dm:pending', { messageId, targetNullId });
    }
  }));

  socket.on('dm:typing', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !areFriends(nullId, targetNullId) || isBlocked(nullId, targetNullId)) return;
    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('dm:typing', { nullId, isTyping: !!data.isTyping });
    }
  }));

  socket.on('dm:read', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !areFriends(nullId, targetNullId) || isBlocked(nullId, targetNullId)) return;
    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('dm:read', { nullId, messageId: data.messageId || null });
    }
  }));

  function resolveFriendTarget(targetSocketId) {
    if (!nullId || !targetSocketId) return null;
    const target = connectedSockets.get(targetSocketId);
    if (!target?.nullId || !areFriends(nullId, target.nullId) || isBlocked(nullId, target.nullId)) return null;
    return target;
  }

  socket.on('call:offer', safeHandler(socket, (data = {}) => {
    if (!resolveFriendTarget(data.targetSocketId)) return;
    io.to(data.targetSocketId).emit('call:incoming', {
      from: { nullId, username, socketId: socket.id, avatarDataUrl: getUserByNullId(nullId)?.avatarDataUrl || null },
      sdp: data.sdp
    });
  }));

  socket.on('call:answer', safeHandler(socket, (data = {}) => {
    if (!resolveFriendTarget(data.targetSocketId)) return;
    io.to(data.targetSocketId).emit('call:answer', { from: { nullId }, sdp: data.sdp });
  }));

  socket.on('call:ice', safeHandler(socket, (data = {}) => {
    if (!resolveFriendTarget(data.targetSocketId)) return;
    io.to(data.targetSocketId).emit('call:ice', { from: { nullId }, candidate: data.candidate });
  }));

  socket.on('call:end', safeHandler(socket, (data = {}) => {
    if (!data.targetSocketId || !connectedSockets.has(data.targetSocketId)) return;
    const eventName = data.reason === 'declined' ? 'call:declined' : 'call:ended';
    io.to(data.targetSocketId).emit(eventName, { nullId });
  }));

  socket.on('disconnect', () => {
    connectedSockets.delete(socket.id);
    if (nullId && userSockets.get(nullId) === socket.id) {
      userSockets.delete(nullId);
      notifyFriendsStatus(nullId, false);
    }
    socket.broadcast.emit('user_left', { username, senderId: socket.id });
  });
});

// ==========================================
// DÉMARRAGE
// ==========================================
server.listen(PORT, () => {
  log(`Serveur NullChat démarré sur http://localhost:${PORT} (${NODE_ENV})`);
});

function shutdown(signal) {
  log(`${signal} reçu, arrêt en cours...`);
  io.close();
  server.close(() => {
    log('Serveur arrêté proprement.');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => logError('unhandledRejection :', reason));
process.on('uncaughtException', (err) => logError('uncaughtException :', err));