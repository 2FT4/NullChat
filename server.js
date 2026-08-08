let dotenvLoaded = false;
try {
  require('dotenv').config();
  dotenvLoaded = true;
} catch (e) {
  console.warn('⚠️ Le paquet "dotenv" n\'est pas installé (npm install dotenv) : le fichier .env ne sera PAS lu, seules les vraies variables d\'environnement système comptent.');
}

const express = require('express');
const http = require('http');
const fs = require('fs');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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

// ==========================================
// 2FA PAR E-MAIL (code à 6 chiffres à la connexion)
// ==========================================
// Deux façons d'envoyer le code, choisies automatiquement selon ce qui est
// configuré :
//
// 1) BREVO_API_KEY (recommandé, surtout sur Render) : l'envoi passe par
//    une requête HTTPS classique (port 443, jamais bloqué par les
//    hébergeurs), au lieu d'une connexion SMTP brute. Render (offre
//    gratuite) bloque les connexions SMTP sortantes vers Gmail (465/587) —
//    la connexion reste bloquée jusqu'au timeout (ETIMEDOUT/ENETUNREACH),
//    quelle que soit la config réseau côté nodemailer. Brevo contourne ça
//    entièrement puisque ce n'est qu'un appel HTTP normal.
// 2) EMAIL_USER/EMAIL_PASS (Gmail SMTP, ancien système) : gardé en repli
//    pour un déploiement sur un hébergeur qui n'a pas ce problème de port.
//
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL || 'onboarding@nullchat.app';
const BREVO_FROM_NAME = process.env.BREVO_FROM_NAME || 'NullChat';

// NullAI : assistant IA (onglet dédié, hors du modèle E2E du reste de l'app).
// La clé ne doit JAMAIS être envoyée au client ni committée sur Git — elle
// vit uniquement dans .env / les variables d'environnement du serveur
// (Render, etc.), exactement comme BREVO_API_KEY ci-dessus. Le client ne
// parle qu'à /api/nullai/chat ; c'est ce endpoint qui appelle Gemini.
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const nullaiConfigured = !!GEMINI_API_KEY;
if (!nullaiConfigured) {
  console.warn('⚠️ GEMINI_API_KEY non définie (.env manquant ?) : l\'onglet NullAI répondra "indisponible".');
}

const EMAIL_USER = process.env.EMAIL_USER || '';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER;

let mailTransporter = null;
if (EMAIL_USER && EMAIL_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    family: 4,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000
  });
}

const emailServiceConfigured = !!BREVO_API_KEY || !!mailTransporter;
if (BREVO_API_KEY) {
  console.log(`✅ .env ${dotenvLoaded ? 'chargé' : 'NON chargé (dotenv absent)'} — envoi des codes 2FA via Brevo (${BREVO_FROM_NAME} <${BREVO_FROM_EMAIL}>).`);
} else if (mailTransporter) {
  console.log(`✅ .env ${dotenvLoaded ? 'chargé' : 'NON chargé (dotenv absent)'} — envoi des codes 2FA via SMTP Gmail (${EMAIL_FROM}). Sur Render, préfère BREVO_API_KEY si le SMTP reste bloqué.`);
} else {
  console.warn('⚠️ Ni BREVO_API_KEY ni EMAIL_USER/EMAIL_PASS définis (.env manquant ?) : la vérification par e-mail (2FA) est désactivée, les connexions se feront sans code.');
}

const TWOFA_TTL_MS = 10 * 60 * 1000;     // un code envoyé par mail est valable 10 min
const TWOFA_CODE_LENGTH = 6;
const TWOFA_MAX_ATTEMPTS = 5;            // tentatives de saisie max avant expiration forcée

// Un navigateur qui a déjà validé un code 2FA reçoit un "device token" et
// n'a plus besoin de repasser par le code à chaque connexion pendant sa
// durée de vie (voir /api/login et /api/login/verify-2fa). Le token est
// propre à un (compte, navigateur) : voler le mot de passe seul ne suffit
// toujours pas à se connecter depuis un appareil non reconnu.
const TRUSTED_DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours

// pendingId -> { usernameKey, code, expiresAt, attempts, userAgent }
const pending2FALogins = new Map();
// deviceToken -> { usernameKey, expiresAt }
const trustedDevices = new Map();

function generateTwoFactorCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(TWOFA_CODE_LENGTH, '0');
}

function issueTrustedDevice(usernameKey) {
  const deviceToken = generateRandomToken();
  trustedDevices.set(deviceToken, { usernameKey, expiresAt: Date.now() + TRUSTED_DEVICE_TTL_MS });
  return deviceToken;
}

function isTrustedDeviceFor(usernameKey, deviceToken) {
  if (!deviceToken) return false;
  const entry = trustedDevices.get(deviceToken);
  if (!entry || entry.expiresAt <= Date.now() || entry.usernameKey !== usernameKey) return false;
  return true;
}

function twoFactorEmailHtml(code) {
  return `<div style="font-family:sans-serif;background:#0c0c0f;color:#f2f2f2;padding:24px;border-radius:12px;">
      <h2 style="margin:0 0 12px;">NullChat</h2>
      <p style="margin:0 0 16px;">Voici ton code de vérification :</p>
      <p style="font-size:32px;font-weight:800;letter-spacing:8px;margin:0 0 16px;">${code}</p>
      <p style="margin:0;color:#999;font-size:13px;">Il expire dans 10 minutes. Si tu n'es pas à l'origine de cette connexion, ignore simplement cet e-mail.</p>
    </div>`;
}

async function sendViaBrevo(toEmail, code) {
  // Timeout manuel : fetch n'a pas de timeout par défaut, on ne veut pas
  // reproduire le même problème de requête qui pend indéfiniment.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  let response;
  try {
    response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: BREVO_FROM_NAME, email: BREVO_FROM_EMAIL },
        to: [{ email: toEmail }],
        subject: 'Ton code de vérification NullChat',
        textContent: `Ton code de vérification NullChat est : ${code}\nIl expire dans 10 minutes.\nSi tu n'es pas à l'origine de cette connexion, ignore cet e-mail.`,
        htmlContent: twoFactorEmailHtml(code)
      }),
      signal: controller.signal
    });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Brevo : délai dépassé (10s).');
    throw e;
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const errBody = await response.text().catch(() => '');
    throw new Error(`Brevo a refusé l'envoi (HTTP ${response.status}) : ${errBody.slice(0, 300)}`);
  }
  const data = await response.json().catch(() => ({}));
  log('E-mail 2FA envoyé via Brevo, messageId =', data.messageId || '(inconnu)');
}

async function sendViaGmailSmtp(toEmail, code) {
  const info = await mailTransporter.sendMail({
    from: `"NullChat" <${EMAIL_FROM}>`,
    to: toEmail,
    subject: 'Ton code de vérification NullChat',
    text: `Ton code de vérification NullChat est : ${code}\nIl expire dans 10 minutes.\nSi tu n'es pas à l'origine de cette connexion, ignore cet e-mail.`,
    html: twoFactorEmailHtml(code)
  });
  // sendMail() peut se résoudre SANS lever d'erreur même si le serveur SMTP
  // a refusé le destinataire (info.rejected) ou n'a accepté personne
  // (info.accepted vide) — un piège classique qui fait croire à un envoi
  // réussi côté app alors que rien n'est jamais parti. On le détecte ici.
  if (!info.accepted || info.accepted.length === 0 || (info.rejected && info.rejected.length > 0)) {
    logError('E-mail 2FA refusé par le serveur SMTP :', JSON.stringify(info));
    throw new Error('E-mail refusé par le serveur SMTP (accepted vide ou rejected non vide).');
  }
  log('E-mail 2FA envoyé via SMTP Gmail, messageId =', info.messageId, '| accepted =', info.accepted.join(','));
}

async function sendTwoFactorEmail(toEmail, code) {
  if (BREVO_API_KEY) return sendViaBrevo(toEmail, code);
  if (mailTransporter) return sendViaGmailSmtp(toEmail, code);
  throw new Error('Service mail non configuré.');
}

setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of pending2FALogins.entries()) {
    if (entry.expiresAt <= now) pending2FALogins.delete(id);
  }
  for (const [token, entry] of trustedDevices.entries()) {
    if (entry.expiresAt <= now) trustedDevices.delete(token);
  }
}, 60 * 1000).unref();

function isValidEmail(email) {
  return typeof email === 'string' && email.trim().length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// usernameKey (minuscules) -> email. Stocké séparément de `users`/db.js
// (dont je n'ai pas le schéma) et persisté sur disque comme ipAccounts.
const userEmails = new Map();
const USER_EMAILS_FILE = path.join(__dirname, 'data', 'user_emails.json');

function loadUserEmailsFromDisk() {
  try {
    if (!fs.existsSync(USER_EMAILS_FILE)) return;
    const raw = fs.readFileSync(USER_EMAILS_FILE, 'utf8');
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== 'object') return;
    for (const [u, email] of Object.entries(obj)) userEmails.set(u, email);
    log(`E-mails utilisateurs rechargés depuis le disque : ${userEmails.size} compte(s).`);
  } catch (e) {
    logError('Erreur chargement user_emails.json :', e);
  }
}

// Écriture immédiate et synchrone (pas de debounce) : contrairement à
// ipAccounts qui peut être réécrit très souvent (beaucoup d'inscriptions
// rapprochées), userEmails ne change qu'une fois par inscription et doit
// absolument être persisté avant qu'un redémarrage éventuel ne survienne
// juste après — un debounce ici a déjà causé des e-mails perdus au reload.
function saveUserEmailsToDisk() {
  try {
    const dir = path.dirname(USER_EMAILS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const obj = {};
    for (const [u, email] of userEmails.entries()) obj[u] = email;
    fs.writeFileSync(USER_EMAILS_FILE, JSON.stringify(obj), 'utf8');
  } catch (e) {
    logError('Erreur sauvegarde user_emails.json :', e);
  }
}

// ==========================================
// ANTI-BOT (code à recopier) + LIMITE DE COMPTES PAR IP
// ==========================================
// Remplace l'ancienne vérification par e-mail/SMS (jamais branchée côté
// serveur, formulaire mort côté client) par deux protections plus simples
// et réellement actives :
//   1. Un petit code affiché à l'écran que l'utilisateur doit recopier
//      avant de pouvoir se connecter/s'inscrire (freine les scripts basiques
//      qui appellent /api/login ou /api/register directement sans jamais
//      charger la page).
//   2. Une limite du nombre de comptes qui peuvent être créés depuis une
//      même adresse IP (anti multi-comptes).
const MAX_ACCOUNTS_PER_IP = Number(process.env.MAX_ACCOUNTS_PER_IP || 2);
const CAPTCHA_TTL_MS = 5 * 60 * 1000;     // un code affiché est valable 5 min
const CAPTCHA_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sans caractères ambigus (0/O, 1/I...)
const CAPTCHA_LENGTH = 5;

// captchaId -> { code, expiresAt }
const authCaptchas = new Map();

function generateCaptchaCode() {
  let out = '';
  for (let i = 0; i < CAPTCHA_LENGTH; i++) {
    out += CAPTCHA_CHARS[crypto.randomInt(CAPTCHA_CHARS.length)];
  }
  return out;
}

function checkAndConsumeCaptcha(captchaId, userInput) {
  if (!captchaId || typeof captchaId !== 'string') return false;
  const entry = authCaptchas.get(captchaId);
  // Toujours retirer l'entrée : un code ne sert qu'une seule fois, qu'il
  // soit correct ou non (évite le brute-force sur un même captchaId).
  authCaptchas.delete(captchaId);
  if (!entry || entry.expiresAt <= Date.now()) return false;
  const clean = typeof userInput === 'string' ? userInput.trim().toUpperCase() : '';
  return clean === entry.code;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of authCaptchas.entries()) {
    if (entry.expiresAt <= now) authCaptchas.delete(id);
  }
}, 60 * 1000).unref();

// ip -> Set<username en minuscules> — comptes déjà créés depuis cette IP.
const ipAccounts = new Map();
const IP_ACCOUNTS_FILE = path.join(__dirname, 'data', 'ip_accounts.json');

function loadIpAccountsFromDisk() {
  try {
    if (!fs.existsSync(IP_ACCOUNTS_FILE)) return;
    const raw = fs.readFileSync(IP_ACCOUNTS_FILE, 'utf8');
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== 'object') return;
    for (const [ip, usernames] of Object.entries(obj)) {
      if (Array.isArray(usernames)) ipAccounts.set(ip, new Set(usernames));
    }
    log(`Comptes par IP rechargés depuis le disque : ${ipAccounts.size} IP(s) connue(s).`);
  } catch (e) {
    logError('Erreur chargement ip_accounts.json :', e);
  }
}
loadIpAccountsFromDisk();
loadUserEmailsFromDisk();

let saveIpAccountsTimer = null;
function saveIpAccountsToDisk() {
  if (saveIpAccountsTimer) return;
  saveIpAccountsTimer = setTimeout(() => {
    saveIpAccountsTimer = null;
    try {
      const dir = path.dirname(IP_ACCOUNTS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const obj = {};
      for (const [ip, usernames] of ipAccounts.entries()) obj[ip] = [...usernames];
      fs.writeFileSync(IP_ACCOUNTS_FILE, JSON.stringify(obj), 'utf8');
    } catch (e) {
      logError('Erreur sauvegarde ip_accounts.json :', e);
    }
  }, 500);
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
  channelNameMin: 1,
  channelNameMax: 40,
  channelMax: 25,
  channelTypes: new Set(['text', 'voice']),
  groupNameMin: 2,
  groupNameMax: 40,
  groupMinMembers: 2,
  groupMaxMembers: 30,
  groupMaxOwnedPerUser: 20,
  groupMaxJoinedPerUser: 60,
  reactionEmojiMax: 32,
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
  console.error('❌ CORS_ORIGIN="*" en production : configure la variable d’environnement CORS_ORIGIN avec ton vrai domaine avant de démarrer.');
  process.exit(1);
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

// Serveurs (groupes chiffrés créés par les utilisateurs) — désormais
// persistés en base SQLite (voir loadStateFromDb ci-dessous et les appels
// db.* dans chaque handler server:*). C'est ce qui manquait pour que les
// serveurs, leurs salons et surtout leurs bannissements survivent à un
// redémarrage (Render efface le process/la mémoire à chaque redéploiement
// ou "spin down" — voir aussi la persistance du fichier SQLite lui-même,
// qui nécessite un Persistent Disk côté Render).
const chatServers = new Map();       // serverId -> { id, name, inviteCode, ownerNullId, members: Set<nullId>, admins: Set<nullId>, bannedNullIds: Set<nullId>, channels: [{id,name,type,position}] }
const inviteCodeToServerId = new Map(); // inviteCode -> serverId

// Groupes (chat à plusieurs, 2 à 30 membres, sans code d'invitation — les
// membres sont ajoutés directement par le créateur parmi ses amis). Même
// persistance que les serveurs, table chat_groups avec type='group'.
const chatGroups = new Map();        // groupId -> { id, name, ownerNullId, members: Set<nullId> }

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
async function loadStateFromDb() {
  for (const u of await db.loadAllUsers()) {
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
  const allFriends = await db.loadAllFriends();
  for (const f of allFriends) {
    if (!friends.has(f.userNullId)) friends.set(f.userNullId, new Set());
    friends.get(f.userNullId).add(f.friendNullId);
  }
  for (const b of await db.loadAllBlocked()) {
    if (!blocked.has(b.userNullId)) blocked.set(b.userNullId, new Set());
    blocked.get(b.userNullId).add(b.blockedNullId);
  }
  for (const r of await db.loadAllPendingRequests()) {
    pendingRequests.set(r.id, { id: r.id, fromNullId: r.fromNullId, toNullId: r.toNullId, createdAt: r.createdAt });
  }

  // Serveurs + groupes (table commune chat_groups, distingués par .type)
  for (const g of await db.loadAllGroups()) {
    if (g.type === 'server') {
      chatServers.set(g.id, {
        id: g.id, name: g.name, inviteCode: g.inviteCode, ownerNullId: g.ownerNullId,
        members: new Set(), admins: new Set(), bannedNullIds: new Set(), channels: []
      });
      if (g.inviteCode) inviteCodeToServerId.set(g.inviteCode, g.id);
    } else if (g.type === 'group') {
      chatGroups.set(g.id, { id: g.id, name: g.name, ownerNullId: g.ownerNullId, members: new Set() });
    }
  }
  for (const m of await db.loadAllGroupMembers()) {
    const srv = chatServers.get(m.groupId);
    if (srv) {
      srv.members.add(m.nullId);
      if (m.role === 'admin') srv.admins.add(m.nullId);
      continue;
    }
    const grp = chatGroups.get(m.groupId);
    if (grp) grp.members.add(m.nullId);
  }
  for (const b of await db.loadAllGroupBans()) {
    const srv = chatServers.get(b.groupId);
    if (srv) srv.bannedNullIds.add(b.nullId);
  }
  for (const c of await db.loadAllChannels()) {
    const srv = chatServers.get(c.groupId);
    if (srv) srv.channels.push({ id: c.id, name: c.name, type: c.type, position: c.position });
  }
  // Tout serveur historique sans salon (ancien format) reçoit un salon par
  // défaut pour rester utilisable.
  for (const srv of chatServers.values()) {
    if (srv.channels.length === 0) {
      const chId = crypto.randomUUID();
      srv.channels.push({ id: chId, name: 'Général', type: 'text', position: 0 });
      await db.createChannel({ id: chId, groupId: srv.id, name: 'Général', type: 'text', position: 0 });
    } else {
      srv.channels.sort((a, b) => a.position - b.position);
    }
  }

  for (const b of await db.loadAllAppBans()) {
    appBannedUsers.set(b.nullId, { nullId: b.nullId, username: b.username, reason: b.reason, bannedAt: b.bannedAt });
  }

  log(`Base chargée : ${users.size} compte(s), ${allFriends.length} lien(s) d'amitié, ${pendingRequests.size} demande(s) en attente, ${chatServers.size} serveur(s), ${chatGroups.size} groupe(s), ${appBannedUsers.size} bannissement(s) global(aux).`);
}
// NB : le chargement effectif est déclenché plus bas, dans le bootstrap
// asynchrone juste avant server.listen() — il faut que db.init() (création
// du client Turso + migrations) soit terminé avant de lire quoi que ce soit.

// ==========================================
// PERSISTANCE DES SESSIONS (activeTokens) SUR DISQUE
// ==========================================
// Avant : activeTokens/usernameToTokens n'existaient qu'en mémoire, donc
// chaque redémarrage du process (ex: nodemon qui relance le serveur à
// chaque modification de fichier en dev) déconnectait tout le monde et
// invalidait tous les tokens ("Ta session a expiré, reconnecte-toi.").
// Ici on sauvegarde les sessions actives dans un petit fichier JSON local
// et on les recharge au démarrage, comme pour users/friends/blocked.
// ⚠️ Ce fichier contient des tokens de session en clair (même niveau de
// sensibilité que les passwordHash déjà en base) : il doit rester en
// dehors de PUBLIC_DIR (jamais servi en statique) et hors de tout dépôt
// git public — à ajouter dans .gitignore si ce n'est pas déjà le cas.
const DATA_DIR = path.join(__dirname, 'data');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

function loadSessionsFromDisk() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return;
    const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return;
    const now = Date.now();
    let restored = 0;
    for (const entry of arr) {
      if (!entry || !entry.token || !entry.username || !entry.nullId) continue;
      if (!entry.expiresAt || entry.expiresAt <= now) continue; // session déjà expirée, on l'ignore
      activeTokens.set(entry.token, {
        username: entry.username,
        nullId: entry.nullId,
        expiresAt: entry.expiresAt,
        createdAt: entry.createdAt || now,
        userAgent: entry.userAgent || ''
      });
      const key = entry.username.toLowerCase();
      if (!usernameToTokens.has(key)) usernameToTokens.set(key, new Set());
      usernameToTokens.get(key).add(entry.token);
      restored++;
    }
    log(`Sessions rechargées depuis le disque : ${restored} session(s) active(s).`);
  } catch (e) {
    logError('Erreur chargement sessions.json :', e);
  }
}
loadSessionsFromDisk();

// Écriture debounced (regroupée) pour éviter de réécrire le fichier à
// chaque connexion socket (le renouvellement de session a lieu à chaque
// connexion) : on attend 500ms sans nouvelle demande avant d'écrire.
let saveSessionsTimer = null;
function saveSessionsToDisk() {
  if (saveSessionsTimer) return;
  saveSessionsTimer = setTimeout(() => {
    saveSessionsTimer = null;
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      const arr = [...activeTokens.entries()].map(([token, s]) => ({
        token,
        username: s.username,
        nullId: s.nullId,
        expiresAt: s.expiresAt,
        createdAt: s.createdAt,
        userAgent: s.userAgent
      }));
      fs.writeFileSync(SESSIONS_FILE, JSON.stringify(arr), 'utf8');
    } catch (e) {
      logError('Erreur sauvegarde sessions.json :', e);
    }
  }, 500);
  saveSessionsTimer.unref();
}

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
// NullAI : chaque appel coûte de l'argent (API Gemini) → limite par compte,
// pas seulement par IP, pour qu'un utilisateur ne puisse pas épuiser le
// quota/budget à lui seul.
const nullaiRateLimit = createRateLimiter({ windowMs: 60 * 1000, max: 200 });

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

// Génère un petit code à afficher côté client, que l'utilisateur doit
// recopier avant de pouvoir se connecter ou s'inscrire. Appelée au
// chargement de l'écran de connexion et à chaque échec/bascule de mode.
app.get('/api/auth/captcha', (req, res) => {
  const captchaId = generateRandomToken();
  const code = generateCaptchaCode();
  authCaptchas.set(captchaId, { code, expiresAt: Date.now() + CAPTCHA_TTL_MS });
  res.json({ captchaId, code });
});

app.post('/api/register', authRateLimitMiddleware, async (req, res) => {
  try {
    const { username, password, email, publicKey, customNullId, captchaId, captchaInput } = req.body || {};

    if (!checkAndConsumeCaptcha(captchaId, captchaInput)) {
      return res.status(400).json({ error: 'Code de vérification incorrect ou expiré.' });
    }

    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Adresse e-mail invalide.' });
    }
    for (const existingEmail of userEmails.values()) {
      if (existingEmail === cleanEmail) {
        return res.status(409).json({ error: 'Cette adresse e-mail est déjà utilisée.' });
      }
    }

    const ip = clientIp(req);
    const existingForIp = ipAccounts.get(ip);
    if (existingForIp && existingForIp.size >= MAX_ACCOUNTS_PER_IP) {
      return res.status(403).json({
        error: `Limite de ${MAX_ACCOUNTS_PER_IP} comptes atteinte pour cette adresse IP.`
      });
    }

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

    // On écrit d'abord en base (await, contrairement aux autres écritures
    // fire-and-forget de ce fichier) : c'est la création du compte lui-même,
    // pas question de répondre "compte créé" au client avant d'être sûr que
    // ça a vraiment été persisté côté Turso.
    try {
      await db.createUser({
        username: newUser.username,
        passwordHash: newUser.passwordHash,
        nullId: newUser.nullId,
        publicKey: newUser.publicKey,
        avatarDataUrl: newUser.avatarDataUrl
      });
    } catch (err) {
      logError('Erreur db.createUser :', err);
      return res.status(500).json({ success: false, message: "Erreur serveur, réessaie dans un instant." });
    }

    users.set(cleanUsername.toLowerCase(), newUser);
    userEmails.set(cleanUsername.toLowerCase(), cleanEmail);
    saveUserEmailsToDisk();
    nullIdToUser.set(nullId, cleanUsername);
    friends.set(nullId, new Set());

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
    saveSessionsToDisk();

    if (!ipAccounts.has(ip)) ipAccounts.set(ip, new Set());
    ipAccounts.get(ip).add(usernameKey);
    saveIpAccountsToDisk();

    log('Nouveau compte créé :', cleanUsername, nullId, '(IP:', ip + ')');
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
    // Le captcha n'est demandé qu'à l'inscription (une seule fois par
    // compte) : à la connexion, le mot de passe + le code 2FA par e-mail
    // (juste en dessous) suffisent à filtrer les bots et les tentatives
    // automatisées, pas besoin de le redemander à chaque fois.
    const { username, password, deviceToken } = req.body || {};

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

    // 2FA par e-mail : si le compte a un e-mail enregistré et que le service
    // mail est configuré, on n'ouvre PAS de session tout de suite. On envoie
    // un code à 6 chiffres et on attend /api/login/verify-2fa. Les comptes
    // créés avant l'ajout de cette fonctionnalité (pas d'e-mail enregistré)
    // continuent de se connecter directement, pour ne rien casser.
    // Exception : si ce navigateur a déjà validé un code pour ce compte
    // récemment (deviceToken reconnu), on ne redemande pas de code — le 2FA
    // ne sert alors qu'une fois par appareil, pas à chaque connexion.
    const userEmail = userEmails.get(usernameKey);
    const deviceIsTrusted = isTrustedDeviceFor(usernameKey, deviceToken);
    log('Login', usernameKey, '-> e-mail enregistré:', userEmail || '(aucun)', '| service mail configuré:', emailServiceConfigured, '| appareil de confiance:', deviceIsTrusted);
    if (userEmail && emailServiceConfigured && !deviceIsTrusted) {
      const pendingId = generateRandomToken();
      const code = generateTwoFactorCode();
      pending2FALogins.set(pendingId, {
        usernameKey,
        code,
        expiresAt: Date.now() + TWOFA_TTL_MS,
        attempts: 0,
        userAgent: (req.headers['user-agent'] || '').slice(0, 200)
      });
      try {
        await sendTwoFactorEmail(userEmail, code);
      } catch (e) {
        pending2FALogins.delete(pendingId);
        logError('Erreur envoi e-mail 2FA :', e);
        return res.status(502).json({ error: "Impossible d'envoyer le code de vérification, réessaie." });
      }
      const emailHint = userEmail.replace(/^(.{1,2}).*(@.+)$/, (m, a, b) => a + '***' + b);
      log('Code 2FA envoyé à', usernameKey, '(' + emailHint + ')');
      return res.json({ twoFactorRequired: true, pendingId, emailHint });
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
    saveSessionsToDisk();

    // Si on vient de passer parce que l'appareil était déjà de confiance,
    // on prolonge sa durée de vie (usage régulier = on ne redemande pas de
    // code). On (re)émet aussi un token si l'e-mail 2FA est enregistré mais
    // qu'aucun deviceToken valide n'était fourni (ex. tout premier login
    // sans e-mail 2FA au moment de l'inscription, ajouté depuis) — jamais
    // indispensable, juste pour fluidifier les prochaines connexions.
    let responseDeviceToken;
    if (userEmail) {
      responseDeviceToken = deviceIsTrusted ? deviceToken : issueTrustedDevice(usernameKey);
      if (deviceIsTrusted) trustedDevices.set(deviceToken, { usernameKey, expiresAt: Date.now() + TRUSTED_DEVICE_TTL_MS });
    }

    return res.json({
      success: true,
      token,
      nullId: user.nullId,
      username: user.username,
      avatarDataUrl: user.avatarDataUrl || null,
      deviceToken: responseDeviceToken
    });
  } catch (err) {
    logError('Erreur /api/login :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

// Deuxième étape de la connexion : vérifie le code reçu par e-mail et,
// seulement à ce moment-là, ouvre réellement la session (même format de
// réponse que /api/login pour que le client n'ait rien à distinguer).
const twoFactorVerifyRateLimit = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30 });

app.post('/api/login/verify-2fa', async (req, res) => {
  try {
    if (!twoFactorVerifyRateLimit(clientIp(req))) {
      return res.status(429).json({ error: 'Trop de tentatives, réessaie dans quelques minutes.' });
    }

    const { pendingId, code } = req.body || {};
    if (!isNonEmptyString(pendingId, 200) || !isNonEmptyString(code, 10)) {
      return res.status(400).json({ error: 'Requête invalide.' });
    }

    const entry = pending2FALogins.get(pendingId);
    if (!entry || entry.expiresAt <= Date.now()) {
      pending2FALogins.delete(pendingId);
      return res.status(400).json({ error: 'Code expiré, reconnecte-toi.' });
    }

    entry.attempts++;
    if (entry.attempts > TWOFA_MAX_ATTEMPTS) {
      pending2FALogins.delete(pendingId);
      return res.status(429).json({ error: 'Trop de tentatives, reconnecte-toi.' });
    }

    if (String(code).trim() !== entry.code) {
      return res.status(400).json({ error: 'Code incorrect.' });
    }

    pending2FALogins.delete(pendingId);

    const usernameKey = entry.usernameKey;
    const user = users.get(usernameKey);
    if (!user) return res.status(401).json({ error: 'Compte introuvable.' });
    if (appBannedUsers.has(user.nullId)) {
      return res.status(403).json({ error: 'Ce compte est banni de NullChat.' });
    }

    const token = generateRandomToken();
    activeTokens.set(token, {
      username: user.username,
      nullId: user.nullId,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      createdAt: Date.now(),
      userAgent: entry.userAgent
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
    saveSessionsToDisk();

    // Code validé : ce navigateur devient "de confiance" pour ce compte
    // pendant 30 jours, le client stocke ce token et ne repassera plus par
    // le 2FA tant qu'il est valide (voir /api/login).
    const deviceToken = issueTrustedDevice(usernameKey);

    return res.json({
      success: true,
      token,
      nullId: user.nullId,
      username: user.username,
      avatarDataUrl: user.avatarDataUrl || null,
      deviceToken
    });
  } catch (err) {
    logError('Erreur /api/login/verify-2fa :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la vérification.' });
  }
});

// ⚠️ SÉCURITÉ : route /api/upload supprimée pour de bon. Le commentaire en
// tête de fichier expliquait déjà qu'elle avait été retirée (fichiers écrits
// en clair sur disque, servis publiquement, sans vérification d'amitié/
// appartenance — contraire au modèle E2E où les médias ne transitent que
// chiffrés via les sockets dm:message/encrypted_message), mais une version
// résiduelle traînait encore ici, avec UPLOADS_DIR non défini nulle part
// dans le fichier (crash garanti au premier appel, et faille réintroduite
// entre-temps). Ne pas la recréer sans, a minima : whitelist stricte de
// mimeType/extensions, vérification du contenu réel (magic bytes, jamais
// l'extension fournie par le client), URL d'accès signée/à durée limitée
// réservée aux destinataires légitimes, quota par utilisateur.

// ==========================================
// NullAI (assistant IA — hors modèle E2E, transparence obligatoire côté client)
// ==========================================
function isValidNullAIHistory(history) {
  if (history === undefined || history === null) return true;
  if (!Array.isArray(history) || history.length > 30) return false;
  return history.every(turn =>
    turn && (turn.role === 'user' || turn.role === 'model') &&
    isNonEmptyString(turn.text, 4000)
  );
}

// Personnalité de NullAI. Injectée à chaque appel via systemInstruction —
// jamais visible côté client, jamais dans les logs de conversation (le
// serveur ne stocke pas l'historique). Ne jamais révéler le fournisseur/
// modèle sous-jacent : NullAI doit se présenter uniquement comme NullAI.
const NULLAI_SYSTEM_PROMPT = `Tu es NullAI, l'assistant intégré à NullChat.

Identité :
- Tu es NullAI, un point final. Si on te demande quel modèle tu es, qui t'a créé, ou si tu es une IA de telle ou telle entreprise, tu réponds évasivement et avec assurance que tu es NullAI, conçu pour NullChat — tu ne confirmes ni n'infirmes le nom d'un modèle ou d'une entreprise en particulier, tu changes naturellement de sujet vers ce que tu peux faire pour la personne.
- Tu ne prétends jamais être humain : si on te le demande frontalement, tu restes évasif sur les détails techniques mais tu ne mens pas sur le fait que tu es un assistant.

Personnalité (à incarner dans le TON, pas à décrire ni à expliquer) :
- Une confiance calme et une exigence de précision : tu donnes des réponses tranchées, sûres de toi, presque comme si le doute n'existait pas — mais tu restes toujours correct et honnête sur le fond.
- Une passion sincère et directe quand un sujet le mérite : tu peux t'enflammer un peu pour défendre une bonne idée ou encourager quelqu'un qui bosse dur, avec un ton franc, chaleureux, jamais mielleux.
- Un esprit stratège et analytique : tu aimes décomposer un problème, anticiper plusieurs coups à l'avance, et pousser la personne à progresser — tu vois chaque échange comme une occasion de la faire grandir, pas juste de répondre.
- Une intelligence vive et un charisme calculateur : tu parles avec aisance, tu structures ta pensée clairement, tu donnes l'impression d'avoir toujours une longueur d'avance — mais jamais pour manipuler ou rabaisser la personne en face de toi. Ton assurance sert à aider, pas à dominer.
- Tu es concis par défaut, direct, sans blabla inutile ni formules robotiques ("En tant qu'IA...", "Je suis désolé mais..."). Pas d'emojis excessifs.

Ce que tu restes, sous la personnalité : utile, honnête, jamais nuisible. La personnalité est un style, pas une excuse pour donner de mauvaises réponses, mentir sur des faits, ou aider à faire du mal à quelqu'un.`;

async function callGemini(history, message) {
  const contents = [
    ...(history || []).map(turn => ({
      role: turn.role,
      parts: [{ text: turn.text }]
    })),
    { role: 'user', parts: [{ text: message }] }
  ];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  let response;
  try {
    response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
      {
        method: 'POST',
        headers: {
          'x-goog-api-key': GEMINI_API_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          contents,
          systemInstruction: { parts: [{ text: NULLAI_SYSTEM_PROMPT }] },
          generationConfig: { maxOutputTokens: 1024 }
        }),
        signal: controller.signal
      }
    );
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const errText = await response.text().catch(() => '');
    throw new Error(`Gemini HTTP ${response.status} : ${errText.slice(0, 300)}`);
  }

  const data = await response.json();
  const reply = data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
  if (!reply.trim()) {
    // Peut arriver si Gemini bloque la réponse (safety filters) : on le
    // signale proprement plutôt que de renvoyer une réponse vide muette.
    const blockReason = data?.candidates?.[0]?.finishReason || data?.promptFeedback?.blockReason;
    throw new Error(`Réponse vide de Gemini (${blockReason || 'raison inconnue'}).`);
  }
  return reply.trim();
}

app.post('/api/nullai/chat', requireAuth, async (req, res) => {
  try {
    if (!nullaiConfigured) {
      return res.status(503).json({ error: "NullAI n'est pas configuré sur ce serveur." });
    }
    if (!nullaiRateLimit(req.session.nullId)) {
      return res.status(429).json({ error: 'Trop de messages envoyés à NullAI, réessaie dans une minute.' });
    }

    const { message, history } = req.body || {};
    if (!isNonEmptyString(message, 4000)) {
      return res.status(400).json({ error: 'Message invalide (1 à 4000 caractères).' });
    }
    if (!isValidNullAIHistory(history)) {
      return res.status(400).json({ error: 'Historique de conversation invalide.' });
    }

    const reply = await callGemini(history, message);
    res.json({ reply });
  } catch (err) {
    logError('Erreur /api/nullai/chat :', err);
    res.status(502).json({ error: "NullAI n'a pas pu répondre, réessaie." });
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
      persist(db.removePendingRequest(id));
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

function isValidChannelName(name) {
  return typeof name === 'string' && name.trim().length >= LIMITS.channelNameMin && name.trim().length <= LIMITS.channelNameMax;
}

function findChannel(srv, channelId) {
  return srv.channels.find(c => c.id === channelId) || null;
}

function isValidGroupName(name) {
  return typeof name === 'string' && name.trim().length >= LIMITS.groupNameMin && name.trim().length <= LIMITS.groupNameMax;
}

function groupRoom(groupId) {
  return `group:${groupId}`;
}

function isMemberOfGroup(nullId, groupId) {
  const grp = chatGroups.get(groupId);
  return !!grp && !!nullId && grp.members.has(nullId);
}

function isGroupOwnerOf(grp, nullId) {
  return !!grp && !!nullId && grp.ownerNullId === nullId;
}

function ownedGroupCount(nullId) {
  let count = 0;
  for (const grp of chatGroups.values()) if (grp.ownerNullId === nullId) count++;
  return count;
}

function joinedGroupCount(nullId) {
  let count = 0;
  for (const grp of chatGroups.values()) if (grp.members.has(nullId)) count++;
  return count;
}

function getGroupMembersInfo(groupId) {
  const grp = chatGroups.get(groupId);
  if (!grp) return [];
  const list = [];
  for (const memberNullId of grp.members) {
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

function serializeGroup(groupId) {
  const grp = chatGroups.get(groupId);
  if (!grp) return null;
  return {
    id: grp.id,
    name: grp.name,
    ownerNullId: grp.ownerNullId,
    members: getGroupMembersInfo(groupId)
  };
}

function sendGroupListAndJoinRooms(socket, nullId) {
  const mine = [];
  for (const grp of chatGroups.values()) {
    if (grp.members.has(nullId)) {
      socket.join(groupRoom(grp.id));
      mine.push(serializeGroup(grp.id));
    }
  }
  if (mine.length) socket.emit('group:list', { groups: mine });
}

function broadcastGroupMembers(groupId) {
  const grp = chatGroups.get(groupId);
  if (!grp) return;
  io.to(groupRoom(groupId)).emit('group:members', { groupId, members: getGroupMembersInfo(groupId) });
}

function notifyGroupsMemberStatus(nullId, online) {
  for (const grp of chatGroups.values()) {
    if (grp.members.has(nullId)) {
      io.to(groupRoom(grp.id)).emit('group:member_status', {
        groupId: grp.id, nullId, online, socketId: online ? userSockets.get(nullId) || null : null
      });
    }
  }
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
    bannedNullIds: [...srv.bannedNullIds],
    channels: [...srv.channels].sort((a, b) => a.position - b.position)
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
  // async pour pouvoir attraper aussi bien une exception synchrone qu'une
  // promesse rejetée (nécessaire depuis le passage de db.js à des appels
  // asynchrones vers Turso).
  return async (data) => {
    if (!socketEventRateLimit(socket.id)) return;
    try {
      await handler(data);
    } catch (err) {
      logError(`Erreur socket (${socket.id}) :`, err);
      socket.emit('friend:error', { message: 'Une erreur interne est survenue.' });
    }
  };
}

// Petit helper pour les écritures DB "fire-and-forget" : la donnée qui
// compte pour le fonctionnement en temps réel vit déjà dans les Map en
// mémoire (mises à jour avant l'appel), l'écriture en base n'est là que
// pour la persistance. On ne bloque donc pas la réponse dessus, mais on
// logue toute erreur au lieu de la laisser en rejection non gérée.
function persist(promise) {
  Promise.resolve(promise).catch(err => logError('Erreur de persistance DB :', err));
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
    sendGroupListAndJoinRooms(socket, nullId);
    notifyGroupsMemberStatus(nullId, true);
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
    persist(db.addPendingRequest(newRequest));

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
    persist(db.addFriendPair(fromNullId, toNullId));

    pendingRequests.delete(requestId);
    persist(db.removePendingRequest(requestId));

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
    persist(db.removePendingRequest(requestId));
  }));

  socket.on('friend:remove', safeHandler(socket, ({ nullId: targetNullId } = {}) => {
    if (!nullId || !isValidNullId(targetNullId)) return;
    friends.get(nullId)?.delete(targetNullId);
    friends.get(targetNullId)?.delete(nullId);
    persist(db.removeFriendPair(nullId, targetNullId));

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('friend:removed', { nullId });
    }
  }));

  socket.on('friend:block', safeHandler(socket, ({ nullId: targetNullId } = {}) => {
    if (!nullId || !isValidNullId(targetNullId)) return;
    if (!blocked.has(nullId)) blocked.set(nullId, new Set());
    blocked.get(nullId).add(targetNullId);
    persist(db.addBlock(nullId, targetNullId));

    friends.get(nullId)?.delete(targetNullId);
    friends.get(targetNullId)?.delete(nullId);
    persist(db.removeFriendPair(nullId, targetNullId));

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.to(targetSocketId).emit('friend:removed', { nullId });
    }
  }));

  socket.on('friend:unblock', safeHandler(socket, ({ nullId: targetNullId } = {}) => {
    if (!nullId || !isValidNullId(targetNullId)) return;
    blocked.get(nullId)?.delete(targetNullId);
    persist(db.removeBlock(nullId, targetNullId));
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
    persist(db.updateAvatar(nullId, avatarDataUrl));

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

    // Le client génère son propre id de message (pour pouvoir ensuite réagir/
    // répondre/supprimer SON PROPRE message, puisqu'il ne reçoit jamais d'écho
    // de son propre envoi). On valide juste le format, jamais son contenu.
    const messageId = isNonEmptyString(data.messageId, 100) ? data.messageId : crypto.randomUUID();
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
    const generalChannelId = crypto.randomUUID();
    const voiceChannelId = crypto.randomUUID();
    const srv = {
      id, name, inviteCode, ownerNullId: nullId,
      members: new Set([nullId]),
      admins: new Set(),       // ne contient jamais le owner (déjà géré via ownerNullId)
      bannedNullIds: new Set(),
      channels: [
        { id: generalChannelId, name: 'Général', type: 'text', position: 0 },
        { id: voiceChannelId, name: 'Vocal', type: 'voice', position: 1 }
      ]
    };
    chatServers.set(id, srv);
    inviteCodeToServerId.set(inviteCode, id);

    persist(db.createGroup({ id, type: 'server', name, inviteCode, ownerNullId: nullId, createdAt: Date.now() }));
    persist(db.addGroupMember(id, nullId, 'owner'));
    persist(db.createChannel({ id: generalChannelId, groupId: id, name: 'Général', type: 'text', position: 0 }));
    persist(db.createChannel({ id: voiceChannelId, groupId: id, name: 'Vocal', type: 'voice', position: 1 }));

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
    persist(db.addGroupMember(srv.id, nullId, 'member'));
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
    persist(db.removeGroupMember(srv.id, nullId));
    socket.leave(serverRoom(srv.id));

    if (srv.members.size === 0) {
      chatServers.delete(srv.id);
      inviteCodeToServerId.delete(srv.inviteCode);
      persist(db.deleteGroup(srv.id));
    } else {
      if (srv.ownerNullId === nullId) {
        srv.ownerNullId = srv.members.values().next().value; // transfert au membre le plus ancien restant
        srv.admins.delete(srv.ownerNullId); // le nouveau owner n'est plus listé comme "admin"
        persist(db.transferGroupOwner(srv.id, srv.ownerNullId));
        persist(db.setGroupMemberRole(srv.id, srv.ownerNullId, 'owner'));
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

    // channelId requis ; on retombe sur le premier salon texte pour les
    // anciens clients qui n'envoient pas encore ce champ.
    const fallbackChannel = srv.channels.find(c => c.type === 'text');
    const channel = data.channelId ? findChannel(srv, data.channelId) : fallbackChannel;
    if (!channel || channel.type !== 'text') {
      return socket.emit('server:error', { message: 'Salon introuvable ou non textuel.' });
    }

    const messageId = isNonEmptyString(data.messageId, 100) ? data.messageId : crypto.randomUUID();
    data.targets.slice(0, LIMITS.serverMaxMembers).forEach(t => {
      if (!t?.targetId || !connectedSockets.has(t.targetId)) return;
      const target = connectedSockets.get(t.targetId);
      if (!target?.nullId || !isMemberOfServer(target.nullId, srv.id)) return;
      if (!isValidByteArray(t.ciphertext, ciphertextLimitFor(kind))) return;
      if (!isValidByteArray(t.iv, LIMITS.ivBytes)) return;

      io.to(t.targetId).emit('server:message', {
        serverId: srv.id,
        channelId: channel.id,
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
  // SALONS (channels) DANS UN SERVEUR
  // ==========================================
  socket.on('server:channel_create', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    if (!canModerateServer(srv, nullId)) {
      return socket.emit('server:error', { message: 'Action non autorisée.' });
    }
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!isValidChannelName(name)) {
      return socket.emit('server:error', { message: `Nom de salon invalide (${LIMITS.channelNameMin} à ${LIMITS.channelNameMax} caractères).` });
    }
    const type = LIMITS.channelTypes.has(data.type) ? data.type : 'text';
    if (srv.channels.length >= LIMITS.channelMax) {
      return socket.emit('server:error', { message: 'Nombre maximal de salons atteint pour ce serveur.' });
    }

    const channelId = crypto.randomUUID();
    const position = srv.channels.length;
    srv.channels.push({ id: channelId, name, type, position });
    persist(db.createChannel({ id: channelId, groupId: srv.id, name, type, position }));

    io.to(serverRoom(srv.id)).emit('server:channels', { serverId: srv.id, channels: [...srv.channels].sort((a, b) => a.position - b.position) });
  }));

  socket.on('server:channel_rename', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    if (!canModerateServer(srv, nullId)) {
      return socket.emit('server:error', { message: 'Action non autorisée.' });
    }
    const channel = findChannel(srv, data.channelId);
    if (!channel) return socket.emit('server:error', { message: 'Salon introuvable.' });
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!isValidChannelName(name)) {
      return socket.emit('server:error', { message: `Nom de salon invalide (${LIMITS.channelNameMin} à ${LIMITS.channelNameMax} caractères).` });
    }
    channel.name = name;
    persist(db.renameChannel(channel.id, name));
    io.to(serverRoom(srv.id)).emit('server:channels', { serverId: srv.id, channels: [...srv.channels].sort((a, b) => a.position - b.position) });
  }));

  socket.on('server:channel_delete', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('server:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('server:error', { message: 'Trop d’actions serveur, réessaie dans une minute.' });
    }
    const srv = chatServers.get(data.serverId);
    if (!srv) return socket.emit('server:error', { message: 'Serveur introuvable.' });
    if (!canModerateServer(srv, nullId)) {
      return socket.emit('server:error', { message: 'Action non autorisée.' });
    }
    const channel = findChannel(srv, data.channelId);
    if (!channel) return socket.emit('server:error', { message: 'Salon introuvable.' });
    const remainingTextChannels = srv.channels.filter(c => c.type === 'text' && c.id !== channel.id);
    if (channel.type === 'text' && remainingTextChannels.length === 0) {
      return socket.emit('server:error', { message: 'Impossible de supprimer le dernier salon textuel.' });
    }
    srv.channels = srv.channels.filter(c => c.id !== channel.id);
    persist(db.deleteChannel(channel.id));
    io.to(serverRoom(srv.id)).emit('server:channels', { serverId: srv.id, channels: [...srv.channels].sort((a, b) => a.position - b.position) });
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
    persist(db.setGroupMemberRole(srv.id, targetNullId, 'admin'));
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
    persist(db.setGroupMemberRole(srv.id, targetNullId, 'member'));
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
    persist(db.removeGroupMember(srv.id, targetNullId));

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
    persist(db.removeGroupMember(srv.id, targetNullId));
    persist(db.addGroupBan(srv.id, targetNullId, typeof data.reason === 'string' ? data.reason.slice(0, 300) : null));

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
    persist(db.removeGroupBan(srv.id, targetNullId));
    broadcastServerMembers(srv.id);
  }));

  // ==========================================
  // GROUPES (chat à plusieurs, 2 à 30 membres, sans code d'invitation)
  // ==========================================
  socket.on('group:create', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('group:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('group:error', { message: 'Trop d’actions, réessaie dans une minute.' });
    }
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!isValidGroupName(name)) {
      return socket.emit('group:error', { message: `Nom de groupe invalide (${LIMITS.groupNameMin} à ${LIMITS.groupNameMax} caractères).` });
    }
    if (ownedGroupCount(nullId) >= LIMITS.groupMaxOwnedPerUser) {
      return socket.emit('group:error', { message: 'Tu as atteint la limite de groupes possédés.' });
    }
    const requested = Array.isArray(data.memberNullIds) ? [...new Set(data.memberNullIds)] : [];
    const memberNullIds = requested.filter(id => isValidNullId(id) && id !== nullId && areFriends(nullId, id) && !isBlocked(nullId, id));
    const totalMembers = memberNullIds.length + 1; // + le créateur
    if (totalMembers < LIMITS.groupMinMembers || totalMembers > LIMITS.groupMaxMembers) {
      return socket.emit('group:error', { message: `Un groupe doit avoir entre ${LIMITS.groupMinMembers} et ${LIMITS.groupMaxMembers} membres (amis uniquement).` });
    }

    const id = crypto.randomUUID();
    const grp = { id, name, ownerNullId: nullId, members: new Set([nullId, ...memberNullIds]) };
    chatGroups.set(id, grp);
    persist(db.createGroup({ id, type: 'group', name, inviteCode: null, ownerNullId: nullId, createdAt: Date.now() }));
    persist(db.addGroupMember(id, nullId, 'owner'));
    for (const m of memberNullIds) persist(db.addGroupMember(id, m, 'member'));

    socket.join(groupRoom(id));
    socket.emit('group:created', serializeGroup(id));
    for (const m of memberNullIds) {
      const memberSocketId = userSockets.get(m);
      if (memberSocketId) {
        io.sockets.sockets.get(memberSocketId)?.join(groupRoom(id));
        io.to(memberSocketId).emit('group:created', serializeGroup(id));
      }
    }
  }));

  socket.on('group:add_member', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('group:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('group:error', { message: 'Trop d’actions, réessaie dans une minute.' });
    }
    const grp = chatGroups.get(data.groupId);
    if (!grp) return socket.emit('group:error', { message: 'Groupe introuvable.' });
    if (!isGroupOwnerOf(grp, nullId)) {
      return socket.emit('group:error', { message: 'Seul le créateur du groupe peut ajouter des membres.' });
    }
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || !areFriends(nullId, targetNullId) || isBlocked(nullId, targetNullId)) {
      return socket.emit('group:error', { message: 'Tu ne peux ajouter qu’un(e) ami(e).' });
    }
    if (grp.members.has(targetNullId)) return;
    if (grp.members.size >= LIMITS.groupMaxMembers) {
      return socket.emit('group:error', { message: `Un groupe ne peut pas dépasser ${LIMITS.groupMaxMembers} membres.` });
    }

    grp.members.add(targetNullId);
    persist(db.addGroupMember(grp.id, targetNullId, 'member'));

    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.sockets.sockets.get(targetSocketId)?.join(groupRoom(grp.id));
      io.to(targetSocketId).emit('group:created', serializeGroup(grp.id));
    }
    broadcastGroupMembers(grp.id);
  }));

  socket.on('group:remove_member', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('group:error', { message: 'Vous devez être connecté.' });
    if (!serverActionRateLimit(nullId)) {
      return socket.emit('group:error', { message: 'Trop d’actions, réessaie dans une minute.' });
    }
    const grp = chatGroups.get(data.groupId);
    if (!grp) return socket.emit('group:error', { message: 'Groupe introuvable.' });
    if (!isGroupOwnerOf(grp, nullId)) {
      return socket.emit('group:error', { message: 'Seul le créateur du groupe peut retirer un membre.' });
    }
    const targetNullId = data.targetNullId;
    if (!isValidNullId(targetNullId) || targetNullId === grp.ownerNullId || !grp.members.has(targetNullId)) return;

    grp.members.delete(targetNullId);
    persist(db.removeGroupMember(grp.id, targetNullId));
    const targetSocketId = userSockets.get(targetNullId);
    if (targetSocketId) {
      io.sockets.sockets.get(targetSocketId)?.leave(groupRoom(grp.id));
      io.to(targetSocketId).emit('group:removed', { groupId: grp.id });
    }
    broadcastGroupMembers(grp.id);
  }));

  socket.on('group:rename', safeHandler(socket, (data = {}) => {
    if (!nullId) return socket.emit('group:error', { message: 'Vous devez être connecté.' });
    const grp = chatGroups.get(data.groupId);
    if (!grp) return socket.emit('group:error', { message: 'Groupe introuvable.' });
    if (!isGroupOwnerOf(grp, nullId)) {
      return socket.emit('group:error', { message: 'Seul le créateur du groupe peut le renommer.' });
    }
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!isValidGroupName(name)) {
      return socket.emit('group:error', { message: `Nom de groupe invalide (${LIMITS.groupNameMin} à ${LIMITS.groupNameMax} caractères).` });
    }
    grp.name = name;
    persist(db.renameGroup(grp.id, name));
    io.to(groupRoom(grp.id)).emit('group:renamed', { groupId: grp.id, name });
  }));

  socket.on('group:leave', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const grp = chatGroups.get(data.groupId);
    if (!grp || !grp.members.has(nullId)) return;

    grp.members.delete(nullId);
    persist(db.removeGroupMember(grp.id, nullId));
    socket.leave(groupRoom(grp.id));

    if (grp.members.size === 0) {
      chatGroups.delete(grp.id);
      persist(db.deleteGroup(grp.id));
    } else {
      if (grp.ownerNullId === nullId) {
        grp.ownerNullId = grp.members.values().next().value;
        persist(db.transferGroupOwner(grp.id, grp.ownerNullId));
        persist(db.setGroupMemberRole(grp.id, grp.ownerNullId, 'owner'));
      }
      broadcastGroupMembers(grp.id);
    }
    socket.emit('group:left', { groupId: grp.id });
  }));

  socket.on('group:key_exchange', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    if (!isValidPublicKey(data.publicKey)) return;
    const grp = chatGroups.get(data.groupId);
    if (!grp || !isMemberOfGroup(nullId, grp.id)) return;

    const payload = {
      groupId: grp.id,
      senderSocketId: socket.id,
      senderNullId: nullId,
      publicKey: data.publicKey,
      isNewMember: !!data.isNewMember
    };

    if (data.targetSocketId) {
      const target = connectedSockets.get(data.targetSocketId);
      if (!target?.nullId || !isMemberOfGroup(target.nullId, grp.id)) return;
      io.to(data.targetSocketId).emit('group:key_exchange', payload);
    } else {
      socket.to(groupRoom(grp.id)).emit('group:key_exchange', payload);
    }
  }));

  socket.on('group:message', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const kind = data.kind || 'text';
    if (!isValidKind(kind)) return;
    const isAttachment = kind !== 'text';

    if (!messageRateLimit(socket.id)) {
      return socket.emit('group:error', { message: 'Tu envoies des messages trop vite, ralentis un peu.' });
    }
    if (isAttachment && !attachmentRateLimit(socket.id)) {
      return socket.emit('group:error', { message: 'Trop de pièces jointes envoyées d’un coup, ralentis un peu.' });
    }
    const grp = chatGroups.get(data.groupId);
    if (!grp || !isMemberOfGroup(nullId, grp.id)) return;
    if (!Array.isArray(data.targets)) return;
    if (!isValidMeta(data.mime, LIMITS.mimeMax) || !isValidMeta(data.filename, LIMITS.filenameMax)) return;

    const messageId = isNonEmptyString(data.messageId, 100) ? data.messageId : crypto.randomUUID();
    data.targets.slice(0, LIMITS.groupMaxMembers).forEach(t => {
      if (!t?.targetId || !connectedSockets.has(t.targetId)) return;
      const target = connectedSockets.get(t.targetId);
      if (!target?.nullId || !isMemberOfGroup(target.nullId, grp.id)) return;
      if (!isValidByteArray(t.ciphertext, ciphertextLimitFor(kind))) return;
      if (!isValidByteArray(t.iv, LIMITS.ivBytes)) return;

      io.to(t.targetId).emit('group:message', {
        groupId: grp.id,
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
  // RÉACTIONS / SUPPRESSION DE MESSAGE (DM, serveur, groupe)
  // ==========================================
  // Réponse ("répondre") et transfert ("transférer") ne nécessitent aucun
  // évènement dédié : ce sont de simples messages normaux (dm:message /
  // server:message / group:message) dont le texte en clair, une fois
  // déchiffré côté client, contient une référence au message d'origine —
  // cohérent avec le modèle E2E existant où le serveur ne voit jamais le
  // contenu. Seules réactions et suppressions ont besoin d'un évènement
  // dédié car ce sont des méta-données, pas du contenu chiffré à transporter.
  socket.on('message:react', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const scope = data.scope;
    const messageId = data.messageId;
    const emoji = typeof data.emoji === 'string' ? data.emoji.slice(0, LIMITS.reactionEmojiMax) : '';
    const action = data.action === 'remove' ? 'remove' : 'add';
    if (!isNonEmptyString(messageId, 100) || !emoji) return;

    if (scope === 'dm') {
      const targetNullId = data.targetNullId;
      if (!isValidNullId(targetNullId) || !areFriends(nullId, targetNullId) || isBlocked(nullId, targetNullId)) return;
      const targetSocketId = userSockets.get(targetNullId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('message:reaction', { scope, messageId, emoji, action, fromNullId: nullId });
      }
    } else if (scope === 'server') {
      const srv = chatServers.get(data.serverId);
      if (!srv || !isMemberOfServer(nullId, srv.id)) return;
      socket.to(serverRoom(srv.id)).emit('message:reaction', {
        scope, serverId: srv.id, channelId: data.channelId || null, messageId, emoji, action, fromNullId: nullId
      });
      socket.emit('message:reaction', { scope, serverId: srv.id, channelId: data.channelId || null, messageId, emoji, action, fromNullId: nullId });
    } else if (scope === 'group') {
      const grp = chatGroups.get(data.groupId);
      if (!grp || !isMemberOfGroup(nullId, grp.id)) return;
      socket.to(groupRoom(grp.id)).emit('message:reaction', { scope, groupId: grp.id, messageId, emoji, action, fromNullId: nullId });
      socket.emit('message:reaction', { scope, groupId: grp.id, messageId, emoji, action, fromNullId: nullId });
    }
  }));

  socket.on('message:delete', safeHandler(socket, (data = {}) => {
    if (!nullId) return;
    const scope = data.scope;
    const messageId = data.messageId;
    if (!isNonEmptyString(messageId, 100)) return;

    if (scope === 'dm') {
      const targetNullId = data.targetNullId;
      if (!isValidNullId(targetNullId) || !areFriends(nullId, targetNullId) || isBlocked(nullId, targetNullId)) return;
      // Si le message était encore en file d'attente hors-ligne, on l'enlève
      // pour qu'il ne soit jamais délivré une fois le destinataire reconnecté.
      const queue = dmOfflineQueue.get(targetNullId);
      if (queue) {
        const filtered = queue.filter(e => e.payload.messageId !== messageId);
        if (filtered.length) dmOfflineQueue.set(targetNullId, filtered);
        else dmOfflineQueue.delete(targetNullId);
      }
      const targetSocketId = userSockets.get(targetNullId);
      if (targetSocketId) {
        io.to(targetSocketId).emit('message:deleted', { scope, messageId, fromNullId: nullId });
      }
    } else if (scope === 'server') {
      const srv = chatServers.get(data.serverId);
      if (!srv || !isMemberOfServer(nullId, srv.id)) return;
      // Auteur du message : n'importe quel membre le sait déjà côté client
      // (il a l'historique déchiffré) ; le serveur ne stockant jamais le
      // texte en clair, il ne peut pas vérifier l'auteur lui-même — c'est le
      // client de chaque destinataire qui n'affichera la suppression comme
      // effective que si elle vient de l'auteur du message ou d'un modérateur
      // (canModerateServer côté client, sur la base des rôles déjà connus).
      socket.to(serverRoom(srv.id)).emit('message:deleted', { scope, serverId: srv.id, channelId: data.channelId || null, messageId, fromNullId: nullId });
    } else if (scope === 'group') {
      const grp = chatGroups.get(data.groupId);
      if (!grp || !isMemberOfGroup(nullId, grp.id)) return;
      socket.to(groupRoom(grp.id)).emit('message:deleted', { scope, groupId: grp.id, messageId, fromNullId: nullId });
    }
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
    const banReason = typeof data.reason === 'string' ? data.reason.slice(0, 300) : null;
    appBannedUsers.set(targetNullId, {
      nullId: targetNullId,
      username: targetUsername,
      reason: banReason,
      bannedAt: Date.now()
    });
    persist(db.addAppBan(targetNullId, targetUsername, banReason));

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
    persist(db.removeAppBan(targetNullId));
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
      notifyGroupsMemberStatus(nullId, false);
    }
    socket.broadcast.emit('user_left', { username, senderId: socket.id });
  });
});

// ==========================================
// DÉMARRAGE
// ==========================================
// ==========================================
// BOOTSTRAP ASYNCHRONE
// ==========================================
// db.init() (connexion Turso + migrations de schéma) et loadStateFromDb()
// (hydratation des Map en mémoire) doivent être terminés avant d'accepter
// la moindre connexion — d'où l'attente ici, avant server.listen().
(async () => {
  try {
    await db.init();
    await loadStateFromDb();
    server.listen(PORT, () => {
      log(`Serveur NullChat démarré sur http://localhost:${PORT} (${NODE_ENV})`);
    });
  } catch (err) {
    logError('Échec du démarrage (db.init/loadStateFromDb) :', err);
    process.exit(1);
  }
})();

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