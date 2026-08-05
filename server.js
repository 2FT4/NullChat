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
// "Owner de l'app" = modération globale du produit, à ne JAMAIS confondre avec
// le ownerNullId d'un serveur créé par un utilisateur. Le client n'affiche le
// panneau qu'à titre indicatif (OWNER_NULLIDS côté front) ; c'est cette liste
// serveur, définie uniquement via variable d'environnement, qui fait foi.
// Le client ne peut jamais s'y ajouter lui-même.
const OWNER_NULLIDS = new Set(
  (process.env.OWNER_NULLIDS || '')
    .split(',')
    .map(s => s.trim().toUpperCase())
    .filter(Boolean)
);
function isAppOwner(candidateNullId) {
  return !!candidateNullId && OWNER_NULLIDS.has(candidateNullId);
}
if (OWNER_NULLIDS.size === 0) {
  console.warn('⚠️ OWNER_NULLIDS est vide : personne ne peut utiliser la modération globale de l’app.');
}
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
  // ⚠️ 10 Go tel que demandé. Voir l'avertissement juste en dessous : à cette
  // taille, ce n'est plus vraiment "une limite de sécurité", c'est surtout
  // une limite théorique — en pratique, presque aucun client/serveur ne tiendra
  // le coup avant de l'atteindre (voir notes dans le message livré à l'utilisateur).
  mediaCiphertextMaxBytes: 10 * 1024 * 1024 * 1024, // 10 Go
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
  serverNameMin: 2,
  serverNameMax: 40,
  serverInviteCodeLength: 6,
  serverMaxMembers: 100,
  serverMaxOwnedPerUser: 20,
  serverMaxJoinedPerUser: 50,
  nameFonts: new Set([
    'none', 'upperCase', 'lowerCase', 'bold', 'italic', 'boldItalic', 'script',
    'boldScript', 'gothic', 'boldFraktur', 'double', 'mono', 'sans', 'sansBold',
    'fullwidth', 'bubble', 'squared', 'circledNeg', 'regional', 'smallcaps'
  ]),
  nameEffects: new Set([
    'none', 'wave', 'neon', 'rainbow', 'glitch', 'shine', 'pulse', 'shake',
    'outline', 'shadow3d', 'underline', 'sparkle', 'fire', 'ice', 'blink',
    'rotate3d', 'jelly', 'heartbeat'
  ]),
  nameColorsMax: 6,
  hexColorRegex: /^#[0-9a-fA-F]{6}$/,
  profilePresets: new Set(['crimson', 'sunset', 'ocean', 'purple', 'forest', 'candy', 'midnight', 'gold']),
  bannerMaxDataUrlLength: 400 * 1024,
};

const app = express();
const server = http.createServer(app);
// ⚠️ maxHttpBufferSize suit mediaCiphertextMaxBytes (10 Go + marge). Node va
// tenter d'allouer un buffer de cette taille par message reçu : n'importe qui
// (même un simple bug client, pas besoin d'être malveillant) peut donc faire
// exploser la mémoire du process avec un seul envoi. À surveiller de près /
// à mettre derrière un process manager qui redémarre automatiquement si besoin.
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

// Serveurs (groupes chiffrés créés par les utilisateurs) — en mémoire
// uniquement pour l'instant (ne survit pas à un redémarrage), même limitation
// que connectedSockets/userSockets/dmOfflineQueue. Si une persistance est
// souhaitée plus tard, il suffit d'ajouter les méthodes correspondantes dans
// db.js sur le même modèle que createUser/addFriendPair etc.
const chatServers = new Map();       // serverId -> { id, name, inviteCode, ownerNullId, members: Set<nullId>, admins: Set<nullId>, bannedNullIds: Set<nullId> }
const inviteCodeToServerId = new Map(); // inviteCode -> serverId

// Bannissements globaux de l'app (owner de l'app uniquement), en mémoire
// uniquement pour l'instant — même limitation que chatServers : ne survit
// pas à un redémarrage. Si une persistance est souhaitée, ajouter une table
// dédiée dans db.js (ex: db.banUserFromApp / db.loadAllAppBans) sur le même
// modèle que les autres méthodes.
// nullId -> { nullId, username, reason, bannedAt }
const appBannedUsers = new Map();
// ip -> { ip, reason, bannedAt, bannedBy }
const appBannedIps = new Map();
// deviceId -> { deviceId, reason, bannedAt, bannedBy }
const appBannedDevices = new Map();

// Co-owners de l'app : nommés dynamiquement PAR un owner (OWNER_NULLIDS),
// ont exactement les mêmes droits de modération globale qu'un owner
// (bannir/débannir par NULLID, IP, appareil), mais ne peuvent PAS nommer ou
// retirer d'autres co-owners — seul un vrai owner (OWNER_NULLIDS, fixé côté
// serveur) le peut. Ceci évite qu'un co-owner puisse en cascade s'auto-donner
// des alliés incontrôlables. En mémoire uniquement (repart à zéro au reboot).
// nullId -> { nullId, username, addedAt, addedBy }
const appCoOwners = new Map();
function isAppCoOwner(candidateNullId) {
  return !!candidateNullId && appCoOwners.has(candidateNullId);
}
function isAppOwnerOrCoOwner(candidateNullId) {
  return isAppOwner(candidateNullId) || isAppCoOwner(candidateNullId);
}
function appRoleOf(candidateNullId) {
  if (isAppOwner(candidateNullId)) return 'owner';
  if (isAppCoOwner(candidateNullId)) return 'coowner';
  return null;
}


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
      avatarDataUrl: u.avatarDataUrl || null,
      // ⚠️ Pas encore persistés en base (db.js n'a pas de colonnes dédiées) :
      // ces préférences de style/thème repartent à zéro après un redémarrage,
      // même limitation que pour chatServers. À étendre dans db.js si une
      // persistance est souhaitée (mêmes méthodes que updateAvatar).
      nameFont: 'none',
      nameEffect: 'none',
      nameColors: [],
      bannerType: 'none',
      bannerValue: null,
      bgType: 'none',
      bgValue: null
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

function isValidHexColor(v) {
  return typeof v === 'string' && LIMITS.hexColorRegex.test(v);
}

function isValidNameColors(arr) {
  return Array.isArray(arr) && arr.length <= LIMITS.nameColorsMax && arr.every(isValidHexColor);
}

function isValidBannerDataUrl(dataUrl) {
  return (
    typeof dataUrl === 'string' &&
    dataUrl.length <= LIMITS.bannerMaxDataUrlLength &&
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
const serverActionRateLimit = createRateLimiter({ windowMs: 60 * 1000, max: 15 });

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
    // Empêche un compte banni de l'app de simplement recréer un compte au
    // même pseudo pour contourner son bannissement.
    for (const ban of appBannedUsers.values()) {
      if (ban.username && ban.username.toLowerCase() === cleanUsername.toLowerCase()) {
        return res.status(403).json({ error: 'Ce compte est banni de NullChat.' });
      }
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
      avatarDataUrl: null,
      nameFont: 'none',
      nameEffect: 'none',
      nameColors: [],
      bannerType: 'none',
      bannerValue: null,
      bgType: 'none',
      bgValue: null
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

    if (appBannedUsers.has(user.nullId)) {
      return res.status(403).json({ error: 'Ce compte est banni de NullChat.' });
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

  if (appBannedUsers.has(session.nullId)) {
    return next(new Error('Ce compte est banni de NullChat.'));
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
        avatarDataUrl: friendUser?.avatarDataUrl || null,
        nameFont: friendUser?.nameFont || 'none',
        nameEffect: friendUser?.nameEffect || 'none',
        nameColors: friendUser?.nameColors || []
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
        from: {
          nullId: r.fromNullId,
          username: fromUsername,
          avatarDataUrl: fromUser?.avatarDataUrl || null,
          nameFont: fromUser?.nameFont || 'none',
          nameEffect: fromUser?.nameEffect || 'none',
          nameColors: fromUser?.nameColors || []
        }
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

// ==========================================
// HELPERS — SERVEURS (groupes chiffrés)
// ==========================================
function serverRoom(serverId) {
  return `server:${serverId}`;
}

function generateInviteCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sans caractères ambigus (0/O, 1/I)
  let code;
  do {
    code = '';
    for (let i = 0; i < LIMITS.serverInviteCodeLength; i++) {
      code += alphabet[crypto.randomInt(alphabet.length)];
    }
  } while (inviteCodeToServerId.has(code));
  return code;
}

function isValidServerName(name) {
  return typeof name === 'string' && name.trim().length >= LIMITS.serverNameMin && name.trim().length <= LIMITS.serverNameMax;
}

function isMemberOfServer(nullId, serverId) {
  const srv = chatServers.get(serverId);
  return !!srv && !!nullId && srv.members.has(nullId);
}

function isServerOwnerOf(srv, nullId) {
  return !!srv && !!nullId && srv.ownerNullId === nullId;
}

function isServerAdminOf(srv, nullId) {
  return !!srv && !!nullId && srv.admins.has(nullId);
}

function canModerateServer(srv, nullId) {
  return isServerOwnerOf(srv, nullId) || isServerAdminOf(srv, nullId);
}

function ownedServerCount(nullId) {
  let count = 0;
  for (const srv of chatServers.values()) if (srv.ownerNullId === nullId) count++;
  return count;
}

function joinedServerCount(nullId) {
  let count = 0;
  for (const srv of chatServers.values()) if (srv.members.has(nullId)) count++;
  return count;
}

function getServerMembersInfo(serverId) {
  const srv = chatServers.get(serverId);
  if (!srv) return [];
  const list = [];
  for (const memberNullId of srv.members) {
    const memberUsername = nullIdToUser.get(memberNullId);
    if (!memberUsername) continue;
    const isOnline = userSockets.has(memberNullId);
    const memberUser = getUserByNullId(memberNullId);
    list.push({
      nullId: memberNullId,
      username: memberUsername,
      online: isOnline,
      socketId: isOnline ? userSockets.get(memberNullId) : null,
      avatarDataUrl: memberUser?.avatarDataUrl || null
    });
  }
  return list;
}

function serializeServer(serverId) {
  const srv = chatServers.get(serverId);
  if (!srv) return null;
  return {
    id: srv.id,
    name: srv.name,
    inviteCode: srv.inviteCode,
    ownerNullId: srv.ownerNullId,
    members: getServerMembersInfo(serverId),
    admins: [...srv.admins],
    bannedNullIds: [...srv.bannedNullIds]
  };
}

function sendServerListAndJoinRooms(socket, nullId) {
  const mine = [];
  for (const srv of chatServers.values()) {
    if (srv.members.has(nullId)) {
      socket.join(serverRoom(srv.id));
      mine.push(serializeServer(srv.id));
    }
  }
  if (mine.length) socket.emit('server:list', { servers: mine });
}

function broadcastServerMembers(serverId) {
  const srv = chatServers.get(serverId);
  if (!srv) return;
  io.to(serverRoom(serverId)).emit('server:members', {
    serverId,
    members: getServerMembersInfo(serverId),
    admins: [...srv.admins],
    bannedNullIds: [...srv.bannedNullIds]
  });
}

function notifyServersMemberStatus(nullId, online) {
  for (const srv of chatServers.values()) {
    if (srv.members.has(nullId)) {
      io.to(serverRoom(srv.id)).emit('server:member_status', {
        serverId: srv.id,
        nullId,
        online,
        socketId: online ? userSockets.get(nullId) || null : null
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
    sendServerListAndJoinRooms(socket, nullId);
    notifyServersMemberStatus(nullId, true);
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
        from: {
          nullId,
          username,
          avatarDataUrl: senderUser?.avatarDataUrl || null,
          nameFont: senderUser?.nameFont || 'none',
          nameEffect: senderUser?.nameEffect || 'none',
          nameColors: senderUser?.nameColors || []
        }
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
      const toUser = getUserByNullId(toNullId);
      io.to(fromSocket).emit('friend:added', {
        nullId: toNullId,
        username: toUsername,
        online: userSockets.has(toNullId),
        socketId: userSockets.get(toNullId) || null,
        avatarDataUrl: toUser?.avatarDataUrl || null,
        nameFont: toUser?.nameFont || 'none',
        nameEffect: toUser?.nameEffect || 'none',
        nameColors: toUser?.nameColors || []
      });
    }
    if (toSocket) {
      const fromUser = getUserByNullId(fromNullId);
      io.to(toSocket).emit('friend:added', {
        nullId: fromNullId,
        username: fromUsername,
        online: userSockets.has(fromNullId),
        socketId: userSockets.get(fromNullId) || null,
        avatarDataUrl: fromUser?.avatarDataUrl || null,
        nameFont: fromUser?.nameFont || 'none',
        nameEffect: fromUser?.nameEffect || 'none',
        nameColors: fromUser?.nameColors || []
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

  socket.on('profile:style', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    // Jamais de texte libre : uniquement des clés fixes connues du client,
    // et des couleurs hexadécimales strictes — on ne fait confiance à rien
    // d'autre venant du client (voir avertissement en tête de fichier HTML).
    const nameFont = LIMITS.nameFonts.has(data.nameFont) ? data.nameFont : 'none';
    const nameEffect = LIMITS.nameEffects.has(data.nameEffect) ? data.nameEffect : 'none';
    if (data.nameColors !== undefined && !isValidNameColors(data.nameColors)) {
      return socket.emit('friend:error', { message: 'Couleurs de pseudo invalides.' });
    }
    const nameColors = isValidNameColors(data.nameColors) ? data.nameColors : [];

    const user = getUserByNullId(nullId);
    if (!user) return;
    user.nameFont = nameFont;
    user.nameEffect = nameEffect;
    user.nameColors = nameColors;

    const userFriendsList = friends.get(nullId) || new Set();
    for (const fNullId of userFriendsList) {
      const friendSocketId = userSockets.get(fNullId);
      if (friendSocketId) {
        io.to(friendSocketId).emit('friend:style_updated', { nullId, nameFont, nameEffect, nameColors });
      }
    }
  }));

  socket.on('profile:theme', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const bannerType = ['none', 'image', 'preset'].includes(data.bannerType) ? data.bannerType : 'none';
    const bgType = ['none', 'preset'].includes(data.bgType) ? data.bgType : 'none';

    let bannerValue = null;
    if (bannerType === 'image') {
      if (!isValidBannerDataUrl(data.bannerValue)) {
        return socket.emit('friend:error', { message: 'Bannière invalide ou trop volumineuse (400 Ko max).' });
      }
      bannerValue = data.bannerValue;
    } else if (bannerType === 'preset') {
      if (!LIMITS.profilePresets.has(data.bannerValue)) {
        return socket.emit('friend:error', { message: 'Bannière invalide.' });
      }
      bannerValue = data.bannerValue;
    }

    let bgValue = null;
    if (bgType === 'preset') {
      if (!LIMITS.profilePresets.has(data.bgValue)) {
        return socket.emit('friend:error', { message: 'Fond de profil invalide.' });
      }
      bgValue = data.bgValue;
    }

    const user = getUserByNullId(nullId);
    if (!user) return;
    user.bannerType = bannerType;
    user.bannerValue = bannerValue;
    user.bgType = bgType;
    user.bgValue = bgValue;
    // Pas de diffusion aux amis : côté client, seul le "propre profil" affiche
    // pour l'instant la bannière/le fond (voir note dans le contrat réseau).
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

  // ==========================================
  // SERVEURS (groupes chiffrés créés par les utilisateurs)
  // ==========================================
  socket.on('server:create', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!isValidServerName(name)) {
      return socket.emit('server:error', {
        message: `Nom de serveur invalide (${LIMITS.serverNameMin} à ${LIMITS.serverNameMax} caractères).`
      });
    }
    if (ownedServerCount(nullId) >= LIMITS.serverMaxOwnedPerUser) {
      return socket.emit('server:error', { message: 'Tu as atteint la limite de serveurs possédés.' });
    }

    const id = crypto.randomUUID();
    const inviteCode = generateInviteCode();
    const srv = {
      id, name, inviteCode, ownerNullId: nullId,
      members: new Set([nullId]),
      admins: new Set(),       // ne contient jamais le owner (déjà géré via ownerNullId)
      bannedNullIds: new Set()
    };
    chatServers.set(id, srv);
    inviteCodeToServerId.set(inviteCode, id);

    socket.join(serverRoom(id));
    socket.emit('server:created', serializeServer(id));
  }));

  socket.on('server:join', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const inviteCode = typeof data.inviteCode === 'string' ? data.inviteCode.trim().toUpperCase() : '';
    const serverId = inviteCodeToServerId.get(inviteCode);
    const srv = serverId ? chatServers.get(serverId) : null;
    if (!srv) {
      return socket.emit('server:error', { message: 'Code d’invitation invalide.' });
    }
    if (srv.bannedNullIds.has(nullId)) {
      return socket.emit('server:error', { message: 'Tu es banni de ce serveur.' });
    }
    if (srv.members.has(nullId)) {
      socket.join(serverRoom(srv.id));
      return socket.emit('server:joined', serializeServer(srv.id));
    }
    if (srv.members.size >= LIMITS.serverMaxMembers) {
      return socket.emit('server:error', { message: 'Ce serveur a atteint son nombre maximal de membres.' });
    }
    if (joinedServerCount(nullId) >= LIMITS.serverMaxJoinedPerUser) {
      return socket.emit('server:error', { message: 'Tu as atteint la limite de serveurs rejoints.' });
    }

    srv.members.add(nullId);
    socket.join(serverRoom(srv.id));
    socket.emit('server:joined', serializeServer(srv.id));

    // Les autres membres en ligne reçoivent la liste à jour ; le nouveau membre
    // déclenche l'échange de clés côté client (dm-like) une fois qu'il a reçu
    // sa propre liste "server:joined".
    socket.to(serverRoom(srv.id)).emit('server:members', { serverId: srv.id, members: getServerMembersInfo(srv.id) });
  }));

  socket.on('server:leave', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const srv = chatServers.get(data.serverId);
    if (!srv || !srv.members.has(nullId)) return;

    srv.members.delete(nullId);
    srv.admins.delete(nullId);
    socket.leave(serverRoom(srv.id));

    if (srv.members.size === 0) {
      chatServers.delete(srv.id);
      inviteCodeToServerId.delete(srv.inviteCode);
    } else {
      if (srv.ownerNullId === nullId) {
        srv.ownerNullId = srv.members.values().next().value; // transfert au membre le plus ancien restant
        srv.admins.delete(srv.ownerNullId); // le nouveau owner n'est plus listé comme "admin"
      }
      broadcastServerMembers(srv.id);
    }
    socket.emit('server:left', { serverId: srv.id });
  }));

  socket.on('server:key_exchange', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    if (!isValidPublicKey(data.publicKey)) return;
    const srv = chatServers.get(data.serverId);
    if (!srv || !isMemberOfServer(nullId, srv.id)) return;

    const payload = {
      serverId: srv.id,
      senderSocketId: socket.id,
      senderNullId: nullId,
      publicKey: data.publicKey,
      isNewMember: !!data.isNewMember
    };

    if (data.targetSocketId) {
      const target = connectedSockets.get(data.targetSocketId);
      if (!target?.nullId || !isMemberOfServer(target.nullId, srv.id)) return;
      io.to(data.targetSocketId).emit('server:key_exchange', payload);
    } else {
      socket.to(serverRoom(srv.id)).emit('server:key_exchange', payload);
    }
  }));

  socket.on('server:message', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const kind = data.kind || 'text';
    if (!isValidKind(kind)) return;
    const isAttachment = kind !== 'text';

    if (!messageRateLimit(socket.id)) {
      return socket.emit('server:error', { message: 'Tu envoies des messages trop vite, ralentis un peu.' });
    }
    if (isAttachment && !attachmentRateLimit(socket.id)) {
      return socket.emit('server:error', { message: 'Trop de pièces jointes envoyées d’un coup, ralentis un peu.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv || !isMemberOfServer(nullId, srv.id)) return;
    if (!Array.isArray(data.targets)) return;
    if (!isValidMeta(data.mime, LIMITS.mimeMax) || !isValidMeta(data.filename, LIMITS.filenameMax)) return;

    const messageId = crypto.randomUUID();
    data.targets.slice(0, LIMITS.serverMaxMembers).forEach(t => {
      if (!t?.targetId || !connectedSockets.has(t.targetId)) return;
      const target = connectedSockets.get(t.targetId);
      if (!target?.nullId || !isMemberOfServer(target.nullId, srv.id)) return;
      if (!isValidByteArray(t.ciphertext, ciphertextLimitFor(kind))) return;
      if (!isValidByteArray(t.iv, LIMITS.ivBytes)) return;

      io.to(t.targetId).emit('server:message', {
        serverId: srv.id,
        messageId,
        senderSocketId: socket.id,
        senderNullId: nullId,
        author: username,
        ciphertext: t.ciphertext,
        iv: t.iv,
        kind,
        mime: data.mime || null,
        filename: data.filename || null,
        timestamp: Date.now()
      });
    });
  }));

  // ==========================================
  // SERVEURS — MODÉRATION (owner + admins)
  // ==========================================
  // Le owner ne peut jamais être rétrogradé/exclu/banni ; ces trois handlers
  // le vérifient explicitement avant toute action, indépendamment de ce que
  // le client affiche ou non (voir avertissement en tête du fichier HTML).
  socket.on('server:promote', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    if (!isServerOwnerOf(srv, nullId)) {
      return socket.emit('server:error', { message: 'Seul le propriétaire du serveur peut nommer un admin.' });
    }
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !srv.members.has(targetNullId)) {
      return socket.emit('server:error', { message: 'Membre introuvable dans ce serveur.' });
    }
    if (targetNullId === srv.ownerNullId) return; // déjà "au-dessus" d'admin, no-op silencieux

    srv.admins.add(targetNullId);
    io.to(serverRoom(srv.id)).emit('server:role_changed', { serverId: srv.id, nullId: targetNullId, role: 'admin' });
  }));

  socket.on('server:demote', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    if (!isServerOwnerOf(srv, nullId)) {
      return socket.emit('server:error', { message: 'Seul le propriétaire du serveur peut retirer un admin.' });
    }
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !srv.admins.has(targetNullId)) return;

    srv.admins.delete(targetNullId);
    io.to(serverRoom(srv.id)).emit('server:role_changed', { serverId: srv.id, nullId: targetNullId, role: 'member' });
  }));

  socket.on('server:kick', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !srv.members.has(targetNullId)) {
      return socket.emit('server:error', { message: 'Membre introuvable dans ce serveur.' });
    }
    if (!canModerateServer(srv, nullId)) {
      return socket.emit('server:error', { message: 'Action non autorisée.' });
    }
    if (targetNullId === srv.ownerNullId) {
      return socket.emit('server:error', { message: 'Impossible d’exclure le propriétaire du serveur.' });
    }
    // Un admin ne peut pas exclure un autre admin (seul le owner le peut).
    if (!isServerOwnerOf(srv, nullId) && srv.admins.has(targetNullId)) {
      return socket.emit('server:error', { message: 'Un admin ne peut pas exclure un autre admin.' });
    }

    srv.members.delete(targetNullId);
    srv.admins.delete(targetNullId);

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.sockets.sockets.get(targetSocketId)?.leave(serverRoom(srv.id));
      io.to(targetSocketId).emit('server:kicked', { serverId: srv.id });
    }
    broadcastServerMembers(srv.id);
  }));

  socket.on('server:ban', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !srv.members.has(targetNullId)) {
      return socket.emit('server:error', { message: 'Membre introuvable dans ce serveur.' });
    }
    if (!canModerateServer(srv, nullId)) {
      return socket.emit('server:error', { message: 'Action non autorisée.' });
    }
    if (targetNullId === srv.ownerNullId) {
      return socket.emit('server:error', { message: 'Impossible de bannir le propriétaire du serveur.' });
    }
    if (!isServerOwnerOf(srv, nullId) && srv.admins.has(targetNullId)) {
      return socket.emit('server:error', { message: 'Un admin ne peut pas bannir un autre admin.' });
    }

    srv.members.delete(targetNullId);
    srv.admins.delete(targetNullId);
    srv.bannedNullIds.add(targetNullId);

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.sockets.sockets.get(targetSocketId)?.leave(serverRoom(srv.id));
      io.to(targetSocketId).emit('server:banned', { serverId: srv.id, reason: data.reason || null });
    }
    broadcastServerMembers(srv.id);
  }));

  socket.on('server:unban', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    if (!canModerateServer(srv, nullId)) {
      return socket.emit('server:error', { message: 'Action non autorisée.' });
    }
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId)) return;
    srv.bannedNullIds.delete(targetNullId);
    broadcastServerMembers(srv.id);
  }));

  // ==========================================
  // MODÉRATION GLOBALE DE L'APP (owner de l'app uniquement)
  // ==========================================
  // ⚠️ Revalidation indépendante obligatoire : le client n'affiche ces
  // boutons que si son NULLID figure dans une constante locale, ça ne PROUVE
  // rien — n'importe qui pourrait forger ces événements depuis la console.
  // On ne fait donc jamais confiance qu'au nullId issu du socket authentifié
  // et à OWNER_NULLIDS défini côté serveur (variable d'environnement).
  socket.on('app:ban_user', safeHandler(socket, (data = {}) => {
    if (!isAppOwner(nullId)) {
      return socket.emit('friend:error', { message: 'Action non autorisée.' });
    }
    const targetNullId = data.nullId;
    if (!isValidNullId(targetNullId)) return;
    if (isAppOwner(targetNullId)) {
      return socket.emit('friend:error', { message: 'Impossible de bannir un autre owner de l’app.' });
    }

    const targetUsername = nullIdToUser.get(targetNullId) || null;
    appBannedUsers.set(targetNullId, {
      nullId: targetNullId,
      username: targetUsername,
      reason: typeof data.reason === 'string' ? data.reason.slice(0, 300) : null,
      bannedAt: Date.now()
    });

    // Déconnecte TOUTES les sockets actives de ce nullId (pas seulement la
    // dernière connue via userSockets, au cas où plusieurs onglets/sessions
    // seraient ouverts) et révoque tous ses tokens actifs.
    for (const [sockId, info] of connectedSockets.entries()) {
      if (info.nullId !== targetNullId) continue;
      const targetSocket = io.sockets.sockets.get(sockId);
      if (!targetSocket) continue;
      targetSocket.emit('app:user_banned', { reason: data.reason || null });
      targetSocket.disconnect(true);
    }
    if (targetUsername) {
      const tokens = usernameToTokens.get(targetUsername.toLowerCase());
      if (tokens) for (const t of [...tokens]) revokeToken(t);
    }

    log('Compte banni de l’app par', nullId, ':', targetNullId);
  }));

  socket.on('app:unban_user', safeHandler(socket, (data = {}) => {
    if (!isAppOwner(nullId)) {
      return socket.emit('friend:error', { message: 'Action non autorisée.' });
    }
    const targetNullId = data.nullId;
    if (!isValidNullId(targetNullId)) return;
    appBannedUsers.delete(targetNullId);
    log('Compte débanni de l’app par', nullId, ':', targetNullId);
  }));

  socket.on('app:list_banned', safeHandler(socket, () => {
    if (!isAppOwner(nullId)) {
      return socket.emit('friend:error', { message: 'Action non autorisée.' });
    }
    socket.emit('app:banned_users', { users: [...appBannedUsers.values()] });
  }));

  socket.on('disconnect', () => {
    connectedSockets.delete(socket.id);
    if (nullId && userSockets.get(nullId) === socket.id) {
      userSockets.delete(nullId);
      notifyFriendsStatus(nullId, false);
      notifyServersMemberStatus(nullId, false);
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