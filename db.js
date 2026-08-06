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

  -- "chat_groups" stocke à la fois les serveurs (type='server', avec code
  -- d'invitation + salons + admins) et les groupes (type='group', chat à
  -- plusieurs sans code d'invitation, membres ajoutés directement).
  CREATE TABLE IF NOT EXISTS chat_groups (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    invite_code TEXT UNIQUE,
    owner_null_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS chat_group_members (
    group_id TEXT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
    null_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, null_id)
  );

  CREATE TABLE IF NOT EXISTS chat_group_bans (
    group_id TEXT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
    null_id TEXT NOT NULL,
    reason TEXT,
    banned_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, null_id)
  );

  CREATE TABLE IF NOT EXISTS chat_channels (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'text',
    position INTEGER NOT NULL DEFAULT 0
  );

  -- Bannissements globaux de l'app (owner/co-owner). Auparavant en mémoire
  -- uniquement : disparaissaient au moindre redémarrage, comme les bans de
  -- serveur avant ce correctif.
  CREATE TABLE IF NOT EXISTS app_bans (
    null_id TEXT PRIMARY KEY,
    username TEXT,
    reason TEXT,
    banned_at INTEGER NOT NULL
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

  insertGroup: db.prepare(`INSERT INTO chat_groups (id, type, name, invite_code, owner_null_id, created_at) VALUES (@id, @type, @name, @inviteCode, @ownerNullId, @createdAt)`),
  deleteGroup: db.prepare(`DELETE FROM chat_groups WHERE id = ?`),
  renameGroup: db.prepare(`UPDATE chat_groups SET name = ? WHERE id = ?`),
  transferGroupOwner: db.prepare(`UPDATE chat_groups SET owner_null_id = ? WHERE id = ?`),
  allGroups: db.prepare(`SELECT id, type, name, invite_code AS inviteCode, owner_null_id AS ownerNullId, created_at AS createdAt FROM chat_groups`),

  addGroupMember: db.prepare(`INSERT OR REPLACE INTO chat_group_members (group_id, null_id, role, joined_at) VALUES (?, ?, ?, ?)`),
  removeGroupMember: db.prepare(`DELETE FROM chat_group_members WHERE group_id = ? AND null_id = ?`),
  setGroupMemberRole: db.prepare(`UPDATE chat_group_members SET role = ? WHERE group_id = ? AND null_id = ?`),
  allGroupMembers: db.prepare(`SELECT group_id AS groupId, null_id AS nullId, role FROM chat_group_members`),

  addGroupBan: db.prepare(`INSERT OR REPLACE INTO chat_group_bans (group_id, null_id, reason, banned_at) VALUES (?, ?, ?, ?)`),
  removeGroupBan: db.prepare(`DELETE FROM chat_group_bans WHERE group_id = ? AND null_id = ?`),
  allGroupBans: db.prepare(`SELECT group_id AS groupId, null_id AS nullId, reason, banned_at AS bannedAt FROM chat_group_bans`),

  insertChannel: db.prepare(`INSERT INTO chat_channels (id, group_id, name, type, position) VALUES (@id, @groupId, @name, @type, @position)`),
  deleteChannel: db.prepare(`DELETE FROM chat_channels WHERE id = ?`),
  renameChannel: db.prepare(`UPDATE chat_channels SET name = ? WHERE id = ?`),
  allChannels: db.prepare(`SELECT id, group_id AS groupId, name, type, position FROM chat_channels ORDER BY position ASC`),

  addAppBan: db.prepare(`INSERT OR REPLACE INTO app_bans (null_id, username, reason, banned_at) VALUES (?, ?, ?, ?)`),
  removeAppBan: db.prepare(`DELETE FROM app_bans WHERE null_id = ?`),
  allAppBans: db.prepare(`SELECT null_id AS nullId, username, reason, banned_at AS bannedAt FROM app_bans`),
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
  },

  // ---- Serveurs & groupes (chat_groups sert les deux : type 'server'|'group') ----
  createGroup({ id, type, name, inviteCode, ownerNullId, createdAt }) {
    stmts.insertGroup.run({ id, type, name, inviteCode: inviteCode || null, ownerNullId, createdAt });
  },
  deleteGroup(id) {
    stmts.deleteGroup.run(id);
  },
  renameGroup(id, name) {
    stmts.renameGroup.run(name, id);
  },
  transferGroupOwner(id, newOwnerNullId) {
    stmts.transferGroupOwner.run(newOwnerNullId, id);
  },
  loadAllGroups() {
    return stmts.allGroups.all();
  },

  addGroupMember(groupId, nullId, role, joinedAt) {
    stmts.addGroupMember.run(groupId, nullId, role || 'member', joinedAt || Date.now());
  },
  removeGroupMember(groupId, nullId) {
    stmts.removeGroupMember.run(groupId, nullId);
  },
  setGroupMemberRole(groupId, nullId, role) {
    stmts.setGroupMemberRole.run(role, groupId, nullId);
  },
  loadAllGroupMembers() {
    return stmts.allGroupMembers.all();
  },

  addGroupBan(groupId, nullId, reason) {
    stmts.addGroupBan.run(groupId, nullId, reason || null, Date.now());
  },
  removeGroupBan(groupId, nullId) {
    stmts.removeGroupBan.run(groupId, nullId);
  },
  loadAllGroupBans() {
    return stmts.allGroupBans.all();
  },

  createChannel({ id, groupId, name, type, position }) {
    stmts.insertChannel.run({ id, groupId, name, type: type || 'text', position: position || 0 });
  },
  deleteChannel(id) {
    stmts.deleteChannel.run(id);
  },
  renameChannel(id, name) {
    stmts.renameChannel.run(name, id);
  },
  loadAllChannels() {
    return stmts.allChannels.all();
  },

  addAppBan(nullId, username, reason) {
    stmts.addAppBan.run(nullId, username || null, reason || null, Date.now());
  },
  removeAppBan(nullId) {
    stmts.removeAppBan.run(nullId);
  },
  loadAllAppBans() {
    return stmts.allAppBans.all();
  }
};