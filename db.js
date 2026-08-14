// ==========================================
// db.js — Persistance SQLite/Turso pour NullChat
// ==========================================
// Remplace better-sqlite3 (fichier local, perdu à chaque redéploiement sur
// un hébergeur à disque éphémère comme Render free tier) par @libsql/client,
// qui parle au même dialecte SQL que SQLite mais peut pointer vers une base
// Turso distante et persistante (ou, en dev, vers un fichier local — il
// suffit de ne pas définir TURSO_DATABASE_URL).
//
// Différence majeure avec l'ancienne version : toutes les fonctions sont
// maintenant asynchrones (le driver Turso est basé sur des requêtes réseau
// même en local). Voir server.js pour la façon dont ces appels sont utilisés
// (await au démarrage / lecture, fire-and-forget avec .catch() pour les
// écritures qui n'ont pas besoin de bloquer la réponse).

const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const path = require('path');

// Deux modes :
// 1) Turso (recommandé en prod) : TURSO_DATABASE_URL=libsql://xxx.turso.io
//    + TURSO_AUTH_TOKEN=xxxxx (générés via `turso db create` / `turso db tokens create`).
// 2) Fichier local (dev, ou si tu as un disque persistant) : ne définis rien,
//    ça retombe sur un fichier nullchat.db à côté de ce script (ou DB_PATH).
const TURSO_URL = process.env.TURSO_DATABASE_URL || '';
const TURSO_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN || '';
const LOCAL_DB_PATH = process.env.DB_PATH || path.join(__dirname, 'nullchat.db');

const client = TURSO_URL
  ? createClient({ url: TURSO_URL, authToken: TURSO_AUTH_TOKEN || undefined })
  : createClient({ url: `file:${LOCAL_DB_PATH}` });

if (TURSO_URL) {
  console.log(`✅ db.js : connexion Turso (${TURSO_URL})`);
} else {
  console.warn(`⚠️ db.js : TURSO_DATABASE_URL non défini — fallback sur un fichier local (${LOCAL_DB_PATH}). Sur un hébergeur à disque éphémère (ex: Render free), ce fichier sera réinitialisé à chaque redéploiement.`);
}

const SCHEMA_SQL = `
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

  CREATE TABLE IF NOT EXISTS server_identities (
    group_id TEXT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
    null_id TEXT NOT NULL,
    pseudo TEXT NOT NULL,
    avatar_data_url TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, null_id)
  );

  CREATE TABLE IF NOT EXISTS app_bans (
    null_id TEXT PRIMARY KEY,
    username TEXT,
    reason TEXT,
    banned_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    reporter_null_id TEXT NOT NULL,
    reporter_username TEXT,
    target_null_id TEXT NOT NULL,
    target_username TEXT,
    description TEXT,
    proof_data_url TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    ai_verdict TEXT,
    resolved_by TEXT,
    created_at INTEGER NOT NULL,
    resolved_at INTEGER
  );
`;

let insertUserSql = null; // déterminé dans init(), dépend de la présence de l'ancienne colonne encrypted_private_key
let ready = null;

async function tableColumns(table) {
  const res = await client.execute(`PRAGMA table_info(${table})`);
  return new Set(res.rows.map(r => r.name));
}

async function backfillNullIds() {
  const rows = (await client.execute(`SELECT id FROM users WHERE null_id IS NULL OR null_id = ''`)).rows;
  if (!rows.length) return;
  const takenRows = (await client.execute(`SELECT null_id FROM users WHERE null_id IS NOT NULL`)).rows;
  const taken = new Set(takenRows.map(r => r.null_id));
  for (const row of rows) {
    let nullId;
    do {
      const p1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      nullId = `${p1}-${p2}`;
    } while (taken.has(nullId));
    taken.add(nullId);
    await client.execute({ sql: `UPDATE users SET null_id = ? WHERE id = ?`, args: [nullId, row.id] });
  }
}

// Doit être appelée une fois au démarrage de server.js, avant tout autre
// appel à ce module : `await db.init();`
async function init() {
  if (ready) return ready;
  ready = (async () => {
    await client.executeMultiple(SCHEMA_SQL);

    const existingCols = await tableColumns('users');
    if (!existingCols.has('null_id')) {
      await client.execute(`ALTER TABLE users ADD COLUMN null_id TEXT`);
    }
    if (!existingCols.has('avatar_data_url')) {
      await client.execute(`ALTER TABLE users ADD COLUMN avatar_data_url TEXT`);
    }
    if (!existingCols.has('email')) {
      await client.execute(`ALTER TABLE users ADD COLUMN email TEXT`);
    }
    if (!existingCols.has('phone')) {
      await client.execute(`ALTER TABLE users ADD COLUMN phone TEXT`);
    }
    // Style du pseudo + thème de profil (bannière/fond) : avant, ces
    // préférences n'existaient qu'en mémoire (Map côté server.js) et
    // repartaient donc à zéro à chaque redémarrage/redéploiement, comme le
    // reste avant la migration Turso.
    if (!existingCols.has('name_font')) {
      await client.execute(`ALTER TABLE users ADD COLUMN name_font TEXT`);
    }
    if (!existingCols.has('name_effect')) {
      await client.execute(`ALTER TABLE users ADD COLUMN name_effect TEXT`);
    }
    if (!existingCols.has('name_colors')) {
      await client.execute(`ALTER TABLE users ADD COLUMN name_colors TEXT`); // JSON (tableau de couleurs hex)
    }
    if (!existingCols.has('banner_type')) {
      await client.execute(`ALTER TABLE users ADD COLUMN banner_type TEXT`);
    }
    if (!existingCols.has('banner_value')) {
      await client.execute(`ALTER TABLE users ADD COLUMN banner_value TEXT`);
    }
    if (!existingCols.has('bg_type')) {
      await client.execute(`ALTER TABLE users ADD COLUMN bg_type TEXT`);
    }
    if (!existingCols.has('bg_value')) {
      await client.execute(`ALTER TABLE users ADD COLUMN bg_value TEXT`);
    }
    // Mode Low-Bandwidth / SFW : préférence par compte (0/1), avant purement
    // en mémoire (Map lowBandwidthPrefs côté server.js) et donc perdue à
    // chaque redémarrage.
    if (!existingCols.has('low_bandwidth')) {
      await client.execute(`ALTER TABLE users ADD COLUMN low_bandwidth INTEGER DEFAULT 0`);
    }
    await client.execute(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_null_id ON users(null_id)`);
    await client.execute(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await client.execute(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)`);

    // Salons éphémères : minuteur (en ms) de suppression forcée des messages
    // d'un salon, nul par défaut (pas d'expiration).
    const channelCols = await tableColumns('chat_channels');
    if (!channelCols.has('ephemeral_ttl_ms')) {
      await client.execute(`ALTER TABLE chat_channels ADD COLUMN ephemeral_ttl_ms INTEGER`);
    }

    await backfillNullIds();

    const hasLegacyKeyColumn = (await tableColumns('users')).has('encrypted_private_key');
    insertUserSql = hasLegacyKeyColumn
      ? `INSERT INTO users (username, password_hash, null_id, email, phone, public_key, avatar_data_url, encrypted_private_key)
         VALUES (?, ?, ?, ?, ?, ?, ?, '')`
      : `INSERT INTO users (username, password_hash, null_id, email, phone, public_key, avatar_data_url)
         VALUES (?, ?, ?, ?, ?, ?, ?)`;

    console.log('✅ db.js : schéma prêt.');
  })();
  return ready;
}

module.exports = {
  raw: client,
  init,

  async createUser({ username, passwordHash, nullId, email, phone, publicKey, avatarDataUrl }) {
    await client.execute({
      sql: insertUserSql,
      args: [
        username,
        passwordHash,
        nullId,
        email || null,
        phone || null,
        publicKey ? JSON.stringify(publicKey) : null,
        avatarDataUrl || null
      ]
    });
  },

  async updateAvatar(nullId, avatarDataUrl) {
    await client.execute({ sql: `UPDATE users SET avatar_data_url = ? WHERE null_id = ?`, args: [avatarDataUrl || null, nullId] });
  },

  async updateEmail(nullId, email) {
    await client.execute({ sql: `UPDATE users SET email = ? WHERE null_id = ?`, args: [email || null, nullId] });
  },

  async updatePhone(nullId, phone) {
    await client.execute({ sql: `UPDATE users SET phone = ? WHERE null_id = ?`, args: [phone || null, nullId] });
  },

  async loadAllUsers() {
    const res = await client.execute(
      `SELECT username, password_hash AS passwordHash, null_id AS nullId, email, phone, public_key AS publicKey, avatar_data_url AS avatarDataUrl,
              name_font AS nameFont, name_effect AS nameEffect, name_colors AS nameColors,
              banner_type AS bannerType, banner_value AS bannerValue, bg_type AS bgType, bg_value AS bgValue,
              low_bandwidth AS lowBandwidth
       FROM users`
    );
    return res.rows.map(u => ({
      ...u,
      publicKey: u.publicKey ? JSON.parse(u.publicKey) : null,
      nameColors: u.nameColors ? JSON.parse(u.nameColors) : [],
      lowBandwidth: !!u.lowBandwidth
    }));
  },

  async updateNameStyle(nullId, { nameFont, nameEffect, nameColors }) {
    await client.execute({
      sql: `UPDATE users SET name_font = ?, name_effect = ?, name_colors = ? WHERE null_id = ?`,
      args: [nameFont || 'none', nameEffect || 'none', JSON.stringify(nameColors || []), nullId]
    });
  },

  async updateProfileTheme(nullId, { bannerType, bannerValue, bgType, bgValue }) {
    await client.execute({
      sql: `UPDATE users SET banner_type = ?, banner_value = ?, bg_type = ?, bg_value = ? WHERE null_id = ?`,
      args: [bannerType || 'none', bannerValue || null, bgType || 'none', bgValue || null, nullId]
    });
  },

  async setLowBandwidthPref(nullId, enabled) {
    await client.execute({ sql: `UPDATE users SET low_bandwidth = ? WHERE null_id = ?`, args: [enabled ? 1 : 0, nullId] });
  },

  async addFriendPair(a, b) {
    await client.batch([
      { sql: `INSERT OR IGNORE INTO friends (user_null_id, friend_null_id) VALUES (?, ?)`, args: [a, b] },
      { sql: `INSERT OR IGNORE INTO friends (user_null_id, friend_null_id) VALUES (?, ?)`, args: [b, a] }
    ]);
  },

  async removeFriendPair(a, b) {
    await client.batch([
      { sql: `DELETE FROM friends WHERE user_null_id = ? AND friend_null_id = ?`, args: [a, b] },
      { sql: `DELETE FROM friends WHERE user_null_id = ? AND friend_null_id = ?`, args: [b, a] }
    ]);
  },

  async loadAllFriends() {
    const res = await client.execute(`SELECT user_null_id AS userNullId, friend_null_id AS friendNullId FROM friends`);
    return res.rows;
  },

  async addBlock(userNullId, blockedNullId) {
    await client.execute({ sql: `INSERT OR IGNORE INTO blocked (user_null_id, blocked_null_id) VALUES (?, ?)`, args: [userNullId, blockedNullId] });
  },

  async removeBlock(userNullId, blockedNullId) {
    await client.execute({ sql: `DELETE FROM blocked WHERE user_null_id = ? AND blocked_null_id = ?`, args: [userNullId, blockedNullId] });
  },

  async loadAllBlocked() {
    const res = await client.execute(`SELECT user_null_id AS userNullId, blocked_null_id AS blockedNullId FROM blocked`);
    return res.rows;
  },

  async addPendingRequest(req) {
    await client.execute({
      sql: `INSERT INTO pending_requests (id, from_null_id, to_null_id, created_at) VALUES (?, ?, ?, ?)`,
      args: [req.id, req.fromNullId, req.toNullId, req.createdAt]
    });
  },

  async removePendingRequest(id) {
    await client.execute({ sql: `DELETE FROM pending_requests WHERE id = ?`, args: [id] });
  },

  async loadAllPendingRequests() {
    const res = await client.execute(`SELECT id, from_null_id AS fromNullId, to_null_id AS toNullId, created_at AS createdAt FROM pending_requests`);
    return res.rows;
  },

  async createGroup({ id, type, name, inviteCode, ownerNullId, createdAt }) {
    await client.execute({
      sql: `INSERT INTO chat_groups (id, type, name, invite_code, owner_null_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [id, type, name, inviteCode || null, ownerNullId, createdAt]
    });
  },
  async deleteGroup(id) {
    await client.execute({ sql: `DELETE FROM chat_groups WHERE id = ?`, args: [id] });
  },
  async renameGroup(id, name) {
    await client.execute({ sql: `UPDATE chat_groups SET name = ? WHERE id = ?`, args: [name, id] });
  },
  async transferGroupOwner(id, newOwnerNullId) {
    await client.execute({ sql: `UPDATE chat_groups SET owner_null_id = ? WHERE id = ?`, args: [newOwnerNullId, id] });
  },
  async loadAllGroups() {
    const res = await client.execute(`SELECT id, type, name, invite_code AS inviteCode, owner_null_id AS ownerNullId, created_at AS createdAt FROM chat_groups`);
    return res.rows;
  },

  async addGroupMember(groupId, nullId, role, joinedAt) {
    await client.execute({
      sql: `INSERT OR REPLACE INTO chat_group_members (group_id, null_id, role, joined_at) VALUES (?, ?, ?, ?)`,
      args: [groupId, nullId, role || 'member', joinedAt || Date.now()]
    });
  },
  async removeGroupMember(groupId, nullId) {
    await client.execute({ sql: `DELETE FROM chat_group_members WHERE group_id = ? AND null_id = ?`, args: [groupId, nullId] });
  },
  async setGroupMemberRole(groupId, nullId, role) {
    await client.execute({ sql: `UPDATE chat_group_members SET role = ? WHERE group_id = ? AND null_id = ?`, args: [role, groupId, nullId] });
  },
  async loadAllGroupMembers() {
    const res = await client.execute(`SELECT group_id AS groupId, null_id AS nullId, role FROM chat_group_members`);
    return res.rows;
  },

  async addGroupBan(groupId, nullId, reason) {
    await client.execute({
      sql: `INSERT OR REPLACE INTO chat_group_bans (group_id, null_id, reason, banned_at) VALUES (?, ?, ?, ?)`,
      args: [groupId, nullId, reason || null, Date.now()]
    });
  },
  async removeGroupBan(groupId, nullId) {
    await client.execute({ sql: `DELETE FROM chat_group_bans WHERE group_id = ? AND null_id = ?`, args: [groupId, nullId] });
  },
  async loadAllGroupBans() {
    const res = await client.execute(`SELECT group_id AS groupId, null_id AS nullId, reason, banned_at AS bannedAt FROM chat_group_bans`);
    return res.rows;
  },

  async createChannel({ id, groupId, name, type, position, ephemeralTtlMs }) {
    await client.execute({
      sql: `INSERT INTO chat_channels (id, group_id, name, type, position, ephemeral_ttl_ms) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [id, groupId, name, type || 'text', position || 0, ephemeralTtlMs ?? null]
    });
  },
  async deleteChannel(id) {
    await client.execute({ sql: `DELETE FROM chat_channels WHERE id = ?`, args: [id] });
  },
  async renameChannel(id, name) {
    await client.execute({ sql: `UPDATE chat_channels SET name = ? WHERE id = ?`, args: [name, id] });
  },
  async setChannelEphemeral(id, ephemeralTtlMs) {
    await client.execute({ sql: `UPDATE chat_channels SET ephemeral_ttl_ms = ? WHERE id = ?`, args: [ephemeralTtlMs ?? null, id] });
  },
  async loadAllChannels() {
    const res = await client.execute(`SELECT id, group_id AS groupId, name, type, position, ephemeral_ttl_ms AS ephemeralTtlMs FROM chat_channels ORDER BY position ASC`);
    return res.rows;
  },

  async setServerIdentity(groupId, nullId, pseudo, avatarDataUrl) {
    await client.execute({
      sql: `INSERT OR REPLACE INTO server_identities (group_id, null_id, pseudo, avatar_data_url, updated_at) VALUES (?, ?, ?, ?, ?)`,
      args: [groupId, nullId, pseudo, avatarDataUrl || null, Date.now()]
    });
  },
  async clearServerIdentity(groupId, nullId) {
    await client.execute({ sql: `DELETE FROM server_identities WHERE group_id = ? AND null_id = ?`, args: [groupId, nullId] });
  },
  async loadAllServerIdentities() {
    const res = await client.execute(`SELECT group_id AS groupId, null_id AS nullId, pseudo, avatar_data_url AS avatarDataUrl FROM server_identities`);
    return res.rows;
  },

  async addAppBan(nullId, username, reason) {
    await client.execute({
      sql: `INSERT OR REPLACE INTO app_bans (null_id, username, reason, banned_at) VALUES (?, ?, ?, ?)`,
      args: [nullId, username || null, reason || null, Date.now()]
    });
  },
  async removeAppBan(nullId) {
    await client.execute({ sql: `DELETE FROM app_bans WHERE null_id = ?`, args: [nullId] });
  },
  async loadAllAppBans() {
    const res = await client.execute(`SELECT null_id AS nullId, username, reason, banned_at AS bannedAt FROM app_bans`);
    return res.rows;
  },

  // -----------------------------
  // Signalements (utilisateur / dox)
  // -----------------------------
  async addReport(r) {
    await client.execute({
      sql: `INSERT INTO reports (id, type, reporter_null_id, reporter_username, target_null_id, target_username, description, proof_data_url, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
      args: [r.id, r.type, r.reporterNullId, r.reporterUsername || null, r.targetNullId, r.targetUsername || null, r.description || null, r.proofDataUrl || null, r.createdAt]
    });
  },
  async resolveReport(id, { status, aiVerdict, resolvedBy }) {
    await client.execute({
      sql: `UPDATE reports SET status = ?, ai_verdict = ?, resolved_by = ?, resolved_at = ? WHERE id = ?`,
      args: [status, aiVerdict || null, resolvedBy || null, Date.now(), id]
    });
  },
  async loadAllReports() {
    const res = await client.execute(
      `SELECT id, type, reporter_null_id AS reporterNullId, reporter_username AS reporterUsername,
              target_null_id AS targetNullId, target_username AS targetUsername, description,
              proof_data_url AS proofDataUrl, status, ai_verdict AS aiVerdict, resolved_by AS resolvedBy,
              created_at AS createdAt, resolved_at AS resolvedAt
       FROM reports ORDER BY created_at DESC`
    );
    return res.rows;
  }
};