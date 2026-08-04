// ==========================================
// db.js — Persistance SQLite pour NullChat
// ==========================================
// Remplace les Map() en mémoire pour users / friends / blocked / pending_requests.
// La base nullchat.db fournie contenait déjà une table `users` (schéma d'un
// prototype antérieur, sans null_id, avec des lignes de test dont
// encrypted_private_key='[1,2,3]' — clairement des valeurs de dev, pas de
// vraies clés). On la fait évoluer plutôt que la recréer, et on backfill un
// null_id pour toute ligne existante qui n'en a pas.

const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'nullchat.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ---- Schéma ----
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS friends (
    user_null_id TEXT NOT NULL,
    friend_null_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_null_id, friend_null_id)
  );

  CREATE TABLE IF NOT EXISTS blocked (
    user_null_id TEXT NOT NULL,
    blocked_null_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_null_id, blocked_null_id)
  );

  CREATE TABLE IF NOT EXISTS pending_requests (
    id TEXT PRIMARY KEY,
    from_null_id TEXT NOT NULL,
    to_null_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

// Migration douce : la table `users` fournie n'a pas forcément les colonnes
// dont l'app actuelle a besoin (null_id, avatar_data_url). On les ajoute si
// absentes, sans toucher aux colonnes existantes (encrypted_private_key
// reste en base mais n'est plus utilisée : l'app actuelle est E2E pure,
// la clé privée ne quitte jamais le navigateur).
const existingCols = new Set(db.prepare(`PRAGMA table_info(users)`).all().map(c => c.name));
if (!existingCols.has('null_id')) {
  db.exec(`ALTER TABLE users ADD COLUMN null_id TEXT`);
}
if (!existingCols.has('avatar_data_url')) {
  db.exec(`ALTER TABLE users ADD COLUMN avatar_data_url TEXT`);
}
// Index unique sur null_id (posé après coup car SQLite ne permet pas
// d'ajouter une contrainte UNIQUE via ALTER TABLE directement).
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_null_id ON users(null_id)`);

// Backfill : toute ligne historique sans null_id (ex. comptes de test
// laissés par un prototype précédent) reçoit un identifiant généré, pour
// rester utilisable par le reste de l'app qui indexe tout par null_id.
function backfillNullIds() {
  const rows = db.prepare(`SELECT id FROM users WHERE null_id IS NULL OR null_id = ''`).all();
  if (!rows.length) return;
  const taken = new Set(db.prepare(`SELECT null_id FROM users WHERE null_id IS NOT NULL`).all().map(r => r.null_id));
  const update = db.prepare(`UPDATE users SET null_id = ? WHERE id = ?`);
  for (const row of rows) {
    let nullId;
    do {
      const p1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      nullId = `${p1}-${p2}`;
    } while (taken.has(nullId));
    taken.add(nullId);
    update.run(nullId, row.id);
  }
}
backfillNullIds();

// La base fournie a une vieille colonne encrypted_private_key TEXT NOT NULL
// (sans défaut) héritée d'un prototype précédent. L'app actuelle ne l'utilise
// plus (E2E pur, la clé privée ne quitte jamais le navigateur) mais si elle
// existe, l'INSERT doit la satisfaire — sinon SQLite lève une erreur de
// contrainte NOT NULL. Sur une base toute neuve, cette colonne n'existe pas
// du tout (elle n'est pas dans le CREATE TABLE plus haut), donc on l'omet.
const hasLegacyKeyColumn = new Set(db.prepare(`PRAGMA table_info(users)`).all().map(c => c.name)).has('encrypted_private_key');
const insertUserSql = hasLegacyKeyColumn
  ? `INSERT INTO users (username, password_hash, null_id, public_key, avatar_data_url, encrypted_private_key)
     VALUES (@username, @passwordHash, @nullId, @publicKey, @avatarDataUrl, '')`
  : `INSERT INTO users (username, password_hash, null_id, public_key, avatar_data_url)
     VALUES (@username, @passwordHash, @nullId, @publicKey, @avatarDataUrl)`;

// ---- Requêtes préparées ----
const stmts = {
  insertUser: db.prepare(insertUserSql),
  updateAvatar: db.prepare(`UPDATE users SET avatar_data_url = ? WHERE null_id = ?`),
  allUsers: db.prepare(`SELECT username, password_hash AS passwordHash, null_id AS nullId, public_key AS publicKey, avatar_data_url AS avatarDataUrl FROM users`),
  addFriend: db.prepare(`INSERT OR IGNORE INTO friends (user_null_id, friend_null_id) VALUES (?, ?)`),
  removeFriend: db.prepare(`DELETE FROM friends WHERE user_null_id = ? AND friend_null_id = ?`),
  allFriends: db.prepare(`SELECT user_null_id AS userNullId, friend_null_id AS friendNullId FROM friends`),
  addBlocked: db.prepare(`INSERT OR IGNORE INTO blocked (user_null_id, blocked_null_id) VALUES (?, ?)`),
  removeBlocked: db.prepare(`DELETE FROM blocked WHERE user_null_id = ? AND blocked_null_id = ?`),
  allBlocked: db.prepare(`SELECT user_null_id AS userNullId, blocked_null_id AS blockedNullId FROM blocked`),
  addPendingRequest: db.prepare(`INSERT INTO pending_requests (id, from_null_id, to_null_id, created_at) VALUES (?, ?, ?, ?)`),
  removePendingRequest: db.prepare(`DELETE FROM pending_requests WHERE id = ?`),
  allPendingRequests: db.prepare(`SELECT id, from_null_id AS fromNullId, to_null_id AS toNullId, created_at AS createdAt FROM pending_requests`),
};

module.exports = {
  raw: db,

  createUser({ username, passwordHash, nullId, publicKey, avatarDataUrl }) {
    stmts.insertUser.run({
      username,
      passwordHash,
      nullId,
      publicKey: publicKey ? JSON.stringify(publicKey) : null,
      avatarDataUrl: avatarDataUrl || null
    });
  },

  updateAvatar(nullId, avatarDataUrl) {
    stmts.updateAvatar.run(avatarDataUrl || null, nullId);
  },

  loadAllUsers() {
    // publicKey est stocké en JSON (tableau d'octets) ; on le reparse.
    return stmts.allUsers.all().map(u => ({
      ...u,
      publicKey: u.publicKey ? JSON.parse(u.publicKey) : null
    }));
  },

  addFriendPair(a, b) {
    const tx = db.transaction((a, b) => {
      stmts.addFriend.run(a, b);
      stmts.addFriend.run(b, a);
    });
    tx(a, b);
  },

  removeFriendPair(a, b) {
    const tx = db.transaction((a, b) => {
      stmts.removeFriend.run(a, b);
      stmts.removeFriend.run(b, a);
    });
    tx(a, b);
  },

  loadAllFriends() {
    return stmts.allFriends.all();
  },

  addBlock(userNullId, blockedNullId) {
    stmts.addBlocked.run(userNullId, blockedNullId);
  },

  removeBlock(userNullId, blockedNullId) {
    stmts.removeBlocked.run(userNullId, blockedNullId);
  },

  loadAllBlocked() {
    return stmts.allBlocked.all();
  },

  addPendingRequest(req) {
    stmts.addPendingRequest.run(req.id, req.fromNullId, req.toNullId, req.createdAt);
  },

  removePendingRequest(id) {
    stmts.removePendingRequest.run(id);
  },

  loadAllPendingRequests() {
    return stmts.allPendingRequests.all();
  }
};
