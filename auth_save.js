'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const EMAIL_CODE_TTL_MINUTES = 15;
const SESSION_TTL_DAYS = 30;
const MAX_SAVE_BYTES = 1024 * 1024;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX = 8;
const attempts = new Map();

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function makeMailer() {
  const port = Number(process.env.SMTP_PORT || 587);
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS || !process.env.SMTP_FROM) {
    throw new Error('Faltan SMTP_HOST, SMTP_USER, SMTP_PASS o SMTP_FROM en Render.');
  }
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

function rateLimit(player, action) {
  const address = player.ws && player.ws._socket
    ? player.ws._socket.remoteAddress || 'unknown'
    : 'unknown';
  const key = `${address}:${action}`;
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now - entry.start > RATE_WINDOW_MS) {
    attempts.set(key, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_MAX;
}

function reply(player, payload) {
  if (player.ws && player.ws.readyState === 1) {
    player.ws.send(JSON.stringify(payload));
  }
}

function cleanText(value, max) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function installAuthSave({ db, originalHandler }) {
  if (!db || typeof db.query !== 'function') throw new Error('Se necesita el Pool de PostgreSQL.');
  if (typeof originalHandler !== 'function') throw new Error('No se encontró handleMessage original.');

  let schemaReady = false;
  let schemaPromise = null;

  async function ensureSchema() {
    if (schemaReady) return;
    if (schemaPromise) return schemaPromise;
    schemaPromise = (async () => {
      await db.query(`CREATE TABLE IF NOT EXISTS accounts (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(32) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )`);
      await db.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email VARCHAR(254)`);
      await db.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE`);
      await db.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS verification_code_hash TEXT`);
      await db.query(`ALTER TABLE accounts ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ`);
      await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS accounts_email_unique ON accounts (LOWER(email)) WHERE email IS NOT NULL`);
      await db.query(`CREATE TABLE IF NOT EXISTS account_sessions (
        id BIGSERIAL PRIMARY KEY,
        account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        token_hash CHAR(64) NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
      await db.query(`CREATE INDEX IF NOT EXISTS account_sessions_account_id_idx ON account_sessions(account_id)`);
      await db.query(`CREATE TABLE IF NOT EXISTS saved_games (
        id BIGSERIAL PRIMARY KEY,
        account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        save_slot VARCHAR(64) NOT NULL DEFAULT 'main',
        save_data JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(account_id, save_slot)
      )`);
      schemaReady = true;
    })().catch((error) => {
      schemaPromise = null;
      throw error;
    });
    return schemaPromise;
  }

  async function sendVerification(email, code) {
    const transporter = makeMailer();
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: 'Verifica tu cuenta',
      text: `Tu código de verificación es: ${code}\nCaduca en ${EMAIL_CODE_TTL_MINUTES} minutos.`,
      html: `<p>Tu código de verificación es:</p><h2>${code}</h2><p>Caduca en ${EMAIL_CODE_TTL_MINUTES} minutos.</p>`
    });
  }

  async function createSession(accountId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 86400000);
    await db.query(
      'INSERT INTO account_sessions (account_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [accountId, sha256(token), expiresAt]
    );
    return { token, expiresAt: expiresAt.toISOString() };
  }

  async function accountForToken(token) {
    if (typeof token !== 'string' || token.length < 40 || token.length > 200) return null;
    const result = await db.query(
      `SELECT a.id, a.username FROM account_sessions s
       JOIN accounts a ON a.id = s.account_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW() AND a.email_verified = TRUE`,
      [sha256(token)]
    );
    return result.rows[0] || null;
  }

  async function handleAuth(player, msg) {
    await ensureSchema();

    if (msg.type === 'account_register') {
      if (rateLimit(player, 'register')) return reply(player, { type: 'account_error', code: 'RATE_LIMIT', message: 'Demasiados intentos. Espera unos minutos.' });
      const username = cleanText(msg.username, 32);
      const email = cleanText(msg.email, 254).toLowerCase();
      const password = typeof msg.password === 'string' ? msg.password : '';
      if (!/^[\p{L}\p{N}_-]{3,32}$/u.test(username)) return reply(player, { type: 'account_error', code: 'INVALID_USERNAME', message: 'El usuario debe tener entre 3 y 32 caracteres.' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply(player, { type: 'account_error', code: 'INVALID_EMAIL', message: 'Correo electrónico no válido.' });
      if (password.length < 8 || password.length > 128) return reply(player, { type: 'account_error', code: 'INVALID_PASSWORD', message: 'La contraseña debe tener entre 8 y 128 caracteres.' });
      const existing = await db.query('SELECT id FROM accounts WHERE username = $1 OR LOWER(email) = $2 LIMIT 1', [username, email]);
      if (existing.rowCount) return reply(player, { type: 'account_error', code: 'ACCOUNT_EXISTS', message: 'Ese usuario o correo ya está registrado.' });
      const passwordHash = await bcrypt.hash(password, 12);
      const code = String(crypto.randomInt(100000, 1000000));
      const codeHash = sha256(code);
      const expiresAt = new Date(Date.now() + EMAIL_CODE_TTL_MINUTES * 60000);
      const inserted = await db.query(
        `INSERT INTO accounts (username, email, password_hash, email_verified, verification_code_hash, verification_expires_at)
         VALUES ($1, $2, $3, FALSE, $4, $5) RETURNING id`,
        [username, email, passwordHash, codeHash, expiresAt]
      );
      try {
        await sendVerification(email, code);
      } catch (mailError) {
        await db.query('DELETE FROM accounts WHERE id = $1', [inserted.rows[0].id]);
        throw mailError;
      }
      return reply(player, { type: 'verification_required', email, message: 'Te enviamos un código de 6 dígitos al correo.' });
    }

    if (msg.type === 'account_verify') {
      if (rateLimit(player, 'verify')) return reply(player, { type: 'account_error', code: 'RATE_LIMIT', message: 'Demasiados intentos. Espera unos minutos.' });
      const email = cleanText(msg.email, 254).toLowerCase();
      const code = cleanText(msg.code, 6);
      const result = await db.query(
        `UPDATE accounts SET email_verified = TRUE, verification_code_hash = NULL, verification_expires_at = NULL
         WHERE LOWER(email) = $1 AND email_verified = FALSE AND verification_code_hash = $2
         AND verification_expires_at > NOW() RETURNING id, username`,
        [email, sha256(code)]
      );
      if (!result.rowCount) return reply(player, { type: 'account_error', code: 'INVALID_CODE', message: 'Código incorrecto o caducado.' });
      return reply(player, { type: 'account_verified', username: result.rows[0].username, message: 'Correo verificado. Ya puedes iniciar sesión.' });
    }

    if (msg.type === 'account_login') {
      if (rateLimit(player, 'login')) return reply(player, { type: 'account_error', code: 'RATE_LIMIT', message: 'Demasiados intentos. Espera unos minutos.' });
      const email = cleanText(msg.email, 254).toLowerCase();
      const password = typeof msg.password === 'string' ? msg.password : '';
      const result = await db.query('SELECT id, username, password_hash, email_verified FROM accounts WHERE LOWER(email) = $1 LIMIT 1', [email]);
      const account = result.rows[0];
      if (!account || !(await bcrypt.compare(password, account.password_hash))) return reply(player, { type: 'account_error', code: 'LOGIN_FAILED', message: 'Correo o contraseña incorrectos.' });
      if (!account.email_verified) return reply(player, { type: 'account_error', code: 'EMAIL_NOT_VERIFIED', message: 'Primero debes verificar tu correo.' });
      const session = await createSession(account.id);
      player.accountId = String(account.id);
      player.accountName = account.username;
      return reply(player, { type: 'account_login_success', accountId: String(account.id), username: account.username, token: session.token, expiresAt: session.expiresAt });
    }

    if (msg.type === 'session_auth') {
      const account = await accountForToken(msg.token);
      if (!account) return reply(player, { type: 'session_invalid', message: 'La sesión caducó o no es válida.' });
      player.accountId = String(account.id);
      player.accountName = account.username;
      return reply(player, { type: 'session_auth_success', accountId: String(account.id), username: account.username });
    }

    if (msg.type === 'account_logout') {
      if (typeof msg.token === 'string' && msg.token.length <= 200) {
        await db.query('DELETE FROM account_sessions WHERE token_hash = $1', [sha256(msg.token)]);
      }
      player.accountId = null;
      player.accountName = null;
      return reply(player, { type: 'account_logout_success' });
    }

    if (msg.type === 'game_save' || msg.type === 'game_load') {
      const account = await accountForToken(msg.token);
      if (!account) return reply(player, { type: 'session_invalid', message: 'Inicia sesión antes de guardar o cargar.' });
      player.accountId = String(account.id);
      const slot = cleanText(msg.slot || 'main', 64);
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(slot)) return reply(player, { type: 'game_save_error', message: 'Nombre de espacio no válido.' });
      if (msg.type === 'game_save') {
        let serialized;
        try { serialized = JSON.stringify(msg.data); } catch { return reply(player, { type: 'game_save_error', message: 'Los datos no son JSON válido.' }); }
        if (!serialized || Buffer.byteLength(serialized, 'utf8') > MAX_SAVE_BYTES) return reply(player, { type: 'game_save_error', message: 'La partida supera el límite de 1 MB.' });
        await db.query(
          `INSERT INTO saved_games (account_id, save_slot, save_data, updated_at)
           VALUES ($1, $2, $3::jsonb, NOW())
           ON CONFLICT (account_id, save_slot) DO UPDATE SET save_data = EXCLUDED.save_data, updated_at = NOW()`,
          [account.id, slot, serialized]
        );
        return reply(player, { type: 'game_save_success', slot, savedAt: new Date().toISOString() });
      }
      const loaded = await db.query('SELECT save_data, updated_at FROM saved_games WHERE account_id = $1 AND save_slot = $2', [account.id, slot]);
      if (!loaded.rowCount) return reply(player, { type: 'game_load_empty', slot });
      return reply(player, { type: 'game_load_success', slot, data: loaded.rows[0].save_data, updatedAt: loaded.rows[0].updated_at });
    }

    return false;
  }

  return function handleMessageWithAccounts(player, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return originalHandler(player, raw); }
    const authTypes = new Set(['account_register', 'account_verify', 'account_login', 'session_auth', 'account_logout', 'game_save', 'game_load']);
    if (!authTypes.has(msg.type)) return originalHandler(player, raw);
    handleAuth(player, msg).catch((error) => {
      console.error('AUTH/SAVE ERROR:', error.message);
      reply(player, { type: 'account_error', code: 'SERVER_ERROR', message: 'No se pudo completar la operación. Inténtalo más tarde.' });
    });
  };
}

module.exports = { installAuthSave };
