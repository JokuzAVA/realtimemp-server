
/**
 * RealTimeMP Server
 * GDevelop + WebSocket + Neon PostgreSQL
 *
 * Multijugador en memoria.
 * Cuentas y partidas en Neon.
 */

const WebSocket = require("ws");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// ============================================================
// CONFIGURACION
// ============================================================

const PORT = parseInt(process.env.PORT) || 8080;
const MAX_ROOMS = parseInt(process.env.MAX_ROOMS) || 100;
const MAX_PLAYERS = parseInt(process.env.MAX_PLAYERS) || 16;

const SESSION_DAYS = 30;
const MAX_SAVE_BYTES = 256 * 1024;
const MAX_WS_BYTES = 512 * 1024;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

db.on("error", (error) => {
  console.error("NEON POOL ERROR:", error.message);
});

// ============================================================
// BASE DE DATOS
// ============================================================

async function initDatabase() {
  try {
    await db.query("SELECT NOW()");

    await db.query(`
      CREATE TABLE IF NOT EXISTS accounts (
        id BIGSERIAL PRIMARY KEY,
        username VARCHAR(32) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS saved_games (
        id BIGSERIAL PRIMARY KEY,
        account_id BIGINT NOT NULL
          REFERENCES accounts(id) ON DELETE CASCADE,
        save_slot VARCHAR(64) NOT NULL DEFAULT 'main',
        save_data JSONB NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(account_id, save_slot)
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS account_sessions (
        token_hash CHAR(64) PRIMARY KEY,
        account_id BIGINT NOT NULL
          REFERENCES accounts(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      );
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS
      idx_sessions_account
      ON account_sessions(account_id);
    `);

    await db.query(`
      CREATE INDEX IF NOT EXISTS
      idx_saved_games_account
      ON saved_games(account_id);
    `);

    console.log("NEON: Connected successfully");
    console.log("NEON: All database tables ready");

    return true;

  } catch (error) {
    console.error("NEON INIT ERROR:", error.message);
    return false;
  }
}

// ============================================================
// AUTHENTICATION
// ============================================================

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function createSession(accountId) {
  const token = createToken();
  const tokenHash = hashToken(token);

  const expiresAt = new Date(
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  );

  await db.query(`
    INSERT INTO account_sessions
      (token_hash, account_id, expires_at)
    VALUES ($1, $2, $3)
  `, [tokenHash, accountId, expiresAt]);

  return token;
}

async function verifySession(token) {
  if (
    typeof token !== "string" ||
    token.length !== 64 ||
    !/^[a-f0-9]+$/i.test(token)
  ) {
    return null;
  }

  const result = await db.query(`
    SELECT a.id, a.username
    FROM account_sessions s
    JOIN accounts a ON a.id = s.account_id
    WHERE s.token_hash = $1
      AND s.expires_at > NOW()
  `, [hashToken(token)]);

  if (result.rows.length === 0) return null;

  return result.rows[0];
}

// ============================================================
// RATE LIMITING
// ============================================================

const authAttempts = new Map();

function allowAuthAttempt(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxAttempts = 8;

  let record = authAttempts.get(ip);

  if (!record || now - record.start > windowMs) {
    record = { start: now, count: 0 };
  }

  record.count++;
  authAttempts.set(ip, record);

  return record.count <= maxAttempts;
}

setInterval(() => {
  const now = Date.now();

  for (const [ip, record] of authAttempts) {
    if (now - record.start > 15 * 60 * 1000) {
      authAttempts.delete(ip);
    }
  }
}, 15 * 60 * 1000).unref();

// ============================================================
// ACCOUNT RESPONSE
// ============================================================

function sendAccountResponse(player, name, data) {
  sendTo(player.id, {
    type: "custom_event",
    name,
    data: JSON.stringify(data),
    senderId: "server"
  });
}

function parseEventData(data) {
  if (typeof data === "string") {
    return JSON.parse(data);
  }

  if (data && typeof data === "object") {
    return data;
  }

  return {};
}

// ============================================================
// ACCOUNT REQUEST HANDLER
// ============================================================

async function handleAccountRequest(player, msg) {
  let data;

  try {
    data = parseEventData(msg.data);
  } catch {
    sendAccountResponse(player, "auth_error", {
      ok: false,
      error: "Invalid request data"
    });
    return;
  }

  try {

    // --------------------------------------------------------
    // REGISTER
    // --------------------------------------------------------

    if (msg.name === "auth_register") {

      if (!allowAuthAttempt(player.ip)) {
        sendAccountResponse(player, "auth_result", {
          ok: false,
          action: "register",
          error: "Too many attempts"
        });
        return;
      }

      const username = String(data.username || "")
        .trim()
        .toLowerCase();

      const password = String(data.password || "");

      if (!/^[a-z0-9_]{3,24}$/.test(username)) {
        sendAccountResponse(player, "auth_result", {
          ok: false,
          action: "register",
          error: "Username must contain 3-24 letters, numbers or underscores"
        });
        return;
      }

      if (
        password.length < 10 ||
        Buffer.byteLength(password, "utf8") > 72
      ) {
        sendAccountResponse(player, "auth_result", {
          ok: false,
          action: "register",
          error: "Password must be at least 10 characters"
        });
        return;
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await db.query(`
        INSERT INTO accounts (username, password_hash)
        VALUES ($1, $2)
        RETURNING id, username
      `, [username, passwordHash]);

      const account = result.rows[0];
      const token = await createSession(account.id);

      player.accountId = account.id;

      sendAccountResponse(player, "auth_result", {
        ok: true,
        action: "register",
        accountId: String(account.id),
        username: account.username,
        token
      });

      return;
    }

    // --------------------------------------------------------
    // LOGIN
    // --------------------------------------------------------

    if (msg.name === "auth_login") {

      if (!allowAuthAttempt(player.ip)) {
        sendAccountResponse(player, "auth_result", {
          ok: false,
          action: "login",
          error: "Too many attempts"
        });
        return;
      }

      const username = String(data.username || "")
        .trim()
        .toLowerCase();

      const password = String(data.password || "");

      const result = await db.query(`
        SELECT id, username, password_hash
        FROM accounts
        WHERE username = $1
      `, [username]);

      if (result.rows.length === 0) {
        sendAccountResponse(player, "auth_result", {
          ok: false,
          action: "login",
          error: "Incorrect username or password"
        });
        return;
      }

      const account = result.rows[0];

      const valid = await bcrypt.compare(
        password,
        account.password_hash
      );

      if (!valid) {
        sendAccountResponse(player, "auth_result", {
          ok: false,
          action: "login",
          error: "Incorrect username or password"
        });
        return;
      }

      const token = await createSession(account.id);

      player.accountId = account.id;

      sendAccountResponse(player, "auth_result", {
        ok: true,
        action: "login",
        accountId: String(account.id),
        username: account.username,
        token
      });

      return;
    }

    // --------------------------------------------------------
    // RESUME SESSION
    // --------------------------------------------------------

    if (msg.name === "auth_resume") {

      const account = await verifySession(data.token);

      if (!account) {
        sendAccountResponse(player, "auth_resume_result", {
          ok: false,
          error: "Session expired or invalid"
        });
        return;
      }

      player.accountId = account.id;

      sendAccountResponse(player, "auth_resume_result", {
        ok: true,
        accountId: String(account.id),
        username: account.username
      });

      return;
    }

    // --------------------------------------------------------
    // LOGOUT
    // --------------------------------------------------------

    if (msg.name === "auth_logout") {

      const token = String(data.token || "");

      if (token.length === 64) {
        await db.query(`
          DELETE FROM account_sessions
          WHERE token_hash = $1
        `, [hashToken(token)]);
      }

      player.accountId = null;

      sendAccountResponse(player, "auth_logout_result", {
        ok: true
      });

      return;
    }

    // --------------------------------------------------------
    // SAVE GAME
    // --------------------------------------------------------

    if (msg.name === "game_save") {

      const account = await verifySession(data.token);

      if (!account) {
        sendAccountResponse(player, "game_save_result", {
          ok: false,
          error: "Invalid session"
        });
        return;
      }

      const slot = String(data.slot || "main");

      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(slot)) {
        sendAccountResponse(player, "game_save_result", {
          ok: false,
          error: "Invalid save slot"
        });
        return;
      }

      const save = data.save;

      if (
        !save ||
        typeof save !== "object" ||
        Array.isArray(save)
      ) {
        sendAccountResponse(player, "game_save_result", {
          ok: false,
          error: "Invalid save data"
        });
        return;
      }

      const json = JSON.stringify(save);

      if (
        Buffer.byteLength(json, "utf8") > MAX_SAVE_BYTES
      ) {
        sendAccountResponse(player, "game_save_result", {
          ok: false,
          error: "Save is too large"
        });
        return;
      }

      await db.query(`
        INSERT INTO saved_games
          (account_id, save_slot, save_data, updated_at)
        VALUES ($1, $2, $3::jsonb, NOW())
        ON CONFLICT (account_id, save_slot)
        DO UPDATE SET
          save_data = EXCLUDED.save_data,
          updated_at = NOW()
      `, [account.id, slot, json]);

      player.accountId = account.id;

      sendAccountResponse(player, "game_save_result", {
        ok: true,
        slot,
        message: "Game saved successfully"
      });

      return;
    }

    // --------------------------------------------------------
    // LOAD GAME
    // --------------------------------------------------------

    if (msg.name === "game_load") {

      const account = await verifySession(data.token);

      if (!account) {
        sendAccountResponse(player, "game_load_result", {
          ok: false,
          error: "Invalid session"
        });
        return;
      }

      const slot = String(data.slot || "main");

      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(slot)) {
        sendAccountResponse(player, "game_load_result", {
          ok: false,
          error: "Invalid save slot"
        });
        return;
      }

      const result = await db.query(`
        SELECT save_data, updated_at
        FROM saved_games
        WHERE account_id = $1
          AND save_slot = $2
      `, [account.id, slot]);

      player.accountId = account.id;

      if (result.rows.length === 0) {
        sendAccountResponse(player, "game_load_result", {
          ok: true,
          found: false,
          slot
        });
        return;
      }

      sendAccountResponse(player, "game_load_result", {
        ok: true,
        found: true,
        slot,
        save: result.rows[0].save_data,
        updatedAt: result.rows[0].updated_at
      });

      return;
    }

  } catch (error) {

    if (error.code === "23505") {
      sendAccountResponse(player, "auth_result", {
        ok: false,
        action: "register",
        error: "Username already exists"
      });
      return;
    }

    console.error("ACCOUNT ERROR:", error.message);

    const responseName =
      msg.name === "game_save" ? "game_save_result" :
      msg.name === "game_load" ? "game_load_result" :
      msg.name === "auth_resume" ? "auth_resume_result" :
      msg.name === "auth_logout" ? "auth_logout_result" :
      "auth_result";

    sendAccountResponse(player, responseName, {
      ok: false,
      error: "Server error. Try again later."
    });
  }
}

// ============================================================
// MULTIPLAYER STATE
// ============================================================

const players = new Map();
const rooms = new Map();

let playerIdCounter = 0;
let roomIdCounter = 0;

function uid(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
}

function sendTo(playerId, msg) {
  const p = players.get(playerId);

  if (p && p.ws.readyState === WebSocket.OPEN) {
    p.ws.send(JSON.stringify(msg));
  }
}

function broadcast(roomId, msg, excludeId = null) {
  const room = rooms.get(roomId);
  if (!room) return;

  const str = JSON.stringify(msg);

  for (const pid of room.players) {
    if (pid === excludeId) continue;

    const p = players.get(pid);

    if (p && p.ws.readyState === WebSocket.OPEN) {
      p.ws.send(str);
    }
  }
}

function broadcastAll(roomId, msg) {
  broadcast(roomId, msg, null);
}

function getRoomSnapshot(room) {
  const playerData = {};

  for (const pid of room.players) {
    const p = players.get(pid);

    if (p) {
      playerData[pid] = { name: p.name };
    }
  }

  return playerData;
}

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function removePlayerFromRoom(player) {
  if (!player.room) return;

  const roomId = player.room;
  const room = rooms.get(roomId);

  player.room = null;

  if (!room) return;

  room.players.delete(player.id);

  broadcast(roomId, {
    type: "player_left",
    playerId: player.id
  });

  if (room.players.size === 0) {
    rooms.delete(roomId);
    return;
  }

  if (room.host === player.id) {
    room.host = [...room.players][0];

    broadcastAll(roomId, {
      type: "host_changed",
      newHostId: room.host
    });
  }
}

// ============================================================
// MESSAGE HANDLER
// ============================================================

function handleMessage(player, raw) {

  let msg;

  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }

  const t = msg.type;

  if (t === "identify") {
    player.name = String(msg.name || "Player").slice(0, 32);
  }

  else if (t === "ping") {
    sendTo(player.id, {
      type: "pong",
      t: msg.t
    });
  }

  // ----------------------------------------------------------
  // ROOM CREATION
  // ----------------------------------------------------------

  else if (t === "create_room") {

    if (rooms.size >= MAX_ROOMS) {
      sendTo(player.id, {
        type: "error",
        message: "Server is full"
      });
      return;
    }

    if (player.room) removePlayerFromRoom(player);

    const roomId = uid("room");
    const roomName = String(msg.roomName || `Room_${roomIdCounter++}`).slice(0, 64);

    const room = {
      id: roomId,
      name: roomName,
      host: player.id,
      players: new Set([player.id]),
      variables: {},
      password: String(msg.password || "").slice(0, 32),
      maxPlayers: Math.min(parseInt(msg.maxPlayers) || MAX_PLAYERS, MAX_PLAYERS),
      isPrivate: !!msg.isPrivate,
      createdAt: Date.now()
    };

    rooms.set(roomId, room);
    player.room = roomId;

    sendTo(player.id, {
      type: "room_joined",
      roomId,
      isHost: true,
      players: getRoomSnapshot(room),
      variables: room.variables
    });
  }

  // ----------------------------------------------------------
  // JOIN ROOM
  // ----------------------------------------------------------

  else if (t === "join_room") {

    const room = rooms.get(msg.roomId);

    if (!room) {
      sendTo(player.id, {
        type: "error",
        message: "Room not found"
      });
      return;
    }

    if (room.password && room.password !== (msg.password || "")) {
      sendTo(player.id, {
        type: "error",
        message: "Wrong password"
      });
      return;
    }

    if (room.players.size >= room.maxPlayers) {
      sendTo(player.id, {
        type: "error",
        message: "Room full"
      });
      return;
    }

    if (player.room) removePlayerFromRoom(player);

    room.players.add(player.id);
    player.room = room.id;

    sendTo(player.id, {
      type: "room_joined",
      roomId: room.id,
      isHost: player.id === room.host,
      players: getRoomSnapshot(room),
      variables: room.variables
    });

    broadcast(room.id, {
      type: "player_joined",
      playerId: player.id,
      playerName: player.name,
      playerData: { name: player.name }
    }, player.id);
  }

  else if (t === "leave_room") {
    if (!player.room) return;

    removePlayerFromRoom(player);

    sendTo(player.id, {
      type: "room_left"
    });
  }

  // ----------------------------------------------------------
  // PLAYER STATE
  // ----------------------------------------------------------

  else if (t === "player_state") {
    if (player.room) {
      broadcast(player.room, {
        type: "player_state",
        playerId: player.id,
        state: msg.state || {}
      }, player.id);
    }
  }

  // ----------------------------------------------------------
  // CUSTOM EVENTS
  // ----------------------------------------------------------

  else if (t === "custom_event") {

    const name = String(msg.name || "");

    const accountEvents = [
      "auth_register",
      "auth_login",
      "auth_resume",
      "auth_logout",
      "game_save",
      "game_load"
    ];

    // Account requests are processed privately by the server.
    // They are NEVER broadcast to other players.

    if (accountEvents.includes(name)) {
      void handleAccountRequest(player, msg);
      return;
    }

    const payload = {
      type: "custom_event",
      name,
      data: msg.data || "",
      senderId: player.id
    };

    if (msg.target && msg.target !== "") {
      sendTo(msg.target, payload);
    } else if (player.room) {
      broadcast(player.room, payload, player.id);
    }
  }

  // ----------------------------------------------------------
  // RPC
  // ----------------------------------------------------------

  else if (t === "rpc") {

    const payload = {
      type: "rpc",
      name: msg.name || "",
      args: msg.args || [],
      senderId: player.id
    };

    if (msg.target && msg.target !== "") {
      sendTo(msg.target, payload);
    } else if (player.room) {
      broadcast(player.room, payload, player.id);
    }
  }

  // ----------------------------------------------------------
  // CHAT
  // ----------------------------------------------------------

  else if (t === "chat") {
    if (player.room) {
      broadcastAll(player.room, {
        type: "chat",
        senderId: player.id,
        senderName: player.name,
        text: String(msg.text || "").slice(0, 512)
      });
    }
  }

  // ----------------------------------------------------------
  // ROOM VARIABLES
  // ----------------------------------------------------------

  else if (t === "room_variable") {

    if (!player.room) return;

    const room = rooms.get(player.room);
    if (!room) return;

    const key = String(msg.key || "").slice(0, 64);
    const value = msg.value !== undefined ? msg.value : "";

    room.variables[key] = value;

    broadcastAll(player.room, {
      type: "room_variable",
      key,
      value
    });
  }

  // ----------------------------------------------------------
  // OBJECT SYNC
  // ----------------------------------------------------------

  else if (t === "object_sync") {
    if (player.room) {
      broadcast(player.room, {
        type: "object_sync",
        objects: msg.objects || {}
      }, player.id);
    }
  }

  //
  // BULLETS
  // ----------------------------------------------------------

  else if (t === "bullet_spawn") {
    if (player.room) {
      broadcast(player.room, {
        type: "bullet_spawn",
        objectName: msg.objectName || "",
        x: msg.x || 0,
        y: msg.y || 0,
        angle: msg.angle || 0,
        animation: msg.animation || "",
        senderId: player.id,
        timestamp: msg.timestamp || Date.now()
      }, player.id);
    }
  }

  // ----------------------------------------------------------
  ----------------------------------------------------------
  // LOBBY
  // ----------------------------------------------------------

  else if (t === "get_lobby") {

    const list = [];

    for (const room of rooms.values()) {
      if (!room.isPrivate) {
        list.push({
          id: room.id,
          name: room.name,
          playerCount: room.players.size,
          maxPlayers: room.maxPlayers,
          locked: room.password !== ""
        });
      }
    }

    sendTo(player.id, {
      type: "lobby_list",
      rooms: list
    });
  }

  // ----------------------------------------------------------
  // KICK
  // ----------------------------------------------------------

  else if (t === "kick") {

    if (!player.room) return;

    const room = rooms.get(player.room);

    if (!room || room.host !== player.id) return;

    const target = players.get(msg.targetId);

    if (!target) return;

    sendTo(target.id, {
      type: "kicked",
      reason: String(msg.reason || "").slice(0, 128)
    });

    removePlayerFromRoom(target);

    if (target.ws.readyState === WebSocket.OPEN) {
      target.ws.close(1000, "Kicked");
    }
  }
}

// =============================
// WEBSOCKET SERVER
// ============================================================

async function startServer() {

  await initDatabase();

  const wss = new WebSocket.Server({
    port: PORT,
    maxPayload: MAX_WS_BYTES
  });

  wss.on("connection", (ws, request) => {

    const playerId = `p${++playerIdCounter}`;

    const player = {
      id: playerId,
      name: "Player",
      room: null,
      ws,
      ip: request.socket.remoteAddress || "unknown",
      accountId: null
    };

    players.set(playerId, player);

    ws.send(JSON.stringify({
      type: "welcome",
      playerId
    }));

    log(`Player connected: ${playerId}`);

    ws.on("message", (raw) => {
      handleMessage(player, raw.toString());
    });

    ws.on("close", () => {
      removePlayerFromRoom(player);
      players.delete(playerId);
      
      log(`Player disconnected: ${playerId}`);
    });

    ws.on("error", (error) => {
      log(`Player error ${playerId}: ${error.message}`);
    });
  });

  log(`RealTimeMP running on port ${PORT}`);
}

startServer().catch((error) => {
  console.error("SERVER START ERROR:", error);
  process.exit(1);
});

// ============================================================
  // PERIODIC CLEANUP
// ============================================================

setInterval(async () => {

  const now = Date.now();

  for (const [id, room] of rooms) {
    if (
      room.players.size === 0 &&
      now - room.createdAt > 60 * 60 * 1000
    ) {
      rooms.delete(id);
    }
  }

  try {
    await db.query(`
      DELETE FROM account_sessions
      WHERE expires_at < NOW()
    `);
  } catch (error) {
    console.error("SESSION CLEANUP ERROR:", error.message);
  }

}, 5 * 60 * 1000);
