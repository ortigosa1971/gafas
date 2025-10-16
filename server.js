// server.js
"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

// ===== Config =====
const NODE_ENV = process.env.NODE_ENV || "production";
const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";
const ALLOW_USERNAME_ONLY =
  String(process.env.ALLOW_USERNAME_ONLY || "").toLowerCase() === "true";

const PUBLIC_DIR = path.join(__dirname, "public");
const DB_DIR = path.join(__dirname, "db");
const DB_FILE = path.join(DB_DIR, "usuarios.db");

function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }
function getDB() { ensureDir(DB_DIR); return new sqlite3.Database(DB_FILE); }

// ===== Column discovery (lee tu esquema existente) =====
let USER_COL = "username";   // se ajustará a tu BD
let PASS_COL = "password";   // se ajustará a tu BD

function quoteIdent(name) {
  // Protege identificadores con backticks (SQLite los admite)
  return "`" + String(name).replace(/`/g, "``") + "`";
}

function detectUserColumns(cb) {
  const db = getDB();
  db.all("PRAGMA table_info(usuarios);", (err, rows) => {
    if (err) {
      console.error("PRAGMA table_info error:", err);
      db.close(); return cb && cb(err);
    }
    // Si no hay tabla, créala con esquema en inglés por defecto
    if (!Array.isArray(rows) || rows.length === 0) {
      db.run(
        `CREATE TABLE IF NOT EXISTS usuarios (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL
        )`,
        (cerr) => {
          if (cerr) { console.error("crear tabla usuarios error:", cerr); db.close(); return cb && cb(cerr); }
          USER_COL = "username"; PASS_COL = "password";
          db.close(); return cb && cb(null);
        }
      );
      return;
    }

    const names = rows.map(r => (r && r.name ? String(r.name).trim() : "")).filter(Boolean);
    const lower = names.map(n => n.toLowerCase());

    // Posibles alias de columnas que solemos ver
    const userCandidates = ["username", "nombre de usuario", "nombre_usuario", "usuario"];
    const passCandidates = ["password", "contraseña", "contrasena", "clave"];

    // Elegir la primera coincidencia que exista en la tabla
    function pick(cands) {
      for (const c of cands) {
        const idx = lower.indexOf(c.toLowerCase());
        if (idx >= 0) return names[idx];
      }
      return null;
    }

    const foundUser = pick(userCandidates);
    const foundPass = pick(passCandidates);

    if (!foundUser || !foundPass) {
      console.warn("No se encontraron columnas de usuario/contraseña reconocibles. Usando esquema por defecto username/password.");
      USER_COL = "username"; PASS_COL = "password";
    } else {
      USER_COL = foundUser;
      PASS_COL = foundPass;
    }

    console.log(`Esquema detectado: USER_COL="${USER_COL}"  PASS_COL="${PASS_COL}"`);
    db.close(); return cb && cb(null);
  });
}

// ===== App =====
const app = express();

// app.set("trust proxy", 1); // descomenta si sirves detrás de proxy HTTPS

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: !!process.env.SESSION_SECURE, // ponlo a true si hay HTTPS tras proxy
      maxAge: 1000 * 60 * 60 * 8, // 8h
    },
  })
);

// Páginas privadas
const paginasPrivadas = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  try {
    if (req.method === "GET" && paginasPrivadas.has(req.path)) {
      if (req.session && req.session.userId) return next();
      return res.redirect(302, "/login.html");
    }
    next();
  } catch (e) {
    console.error("middleware privado error:", e);
    res.status(500).type("text").send("Error de servidor.");
  }
});

// Estáticos
app.use(express.static(PUBLIC_DIR, { fallthrough: true }));

// ===== API: Login (soporta solo-usuario si ALLOW_USERNAME_ONLY=true) =====
app.post("/login", (req, res) => {
  try {
    const b = req.body || {};
    const username = (b.username ?? b.usuario ?? b.user ?? "").toString().trim();
    const password = (b.password ?? b.pass ?? b.contrasena ?? b["contraseña"] ?? "").toString();

    if (!username) {
      return res.status(400).json({ error: "campos_faltantes", detalle: "username requerido" });
    }
    if (!ALLOW_USERNAME_ONLY && !password) {
      return res.status(400).json({ error: "campos_faltantes", detalle: "password requerido" });
    }

    const db = getDB();
    const u = quoteIdent(USER_COL);
    const p = quoteIdent(PASS_COL);

    // Leemos siempre devolviendo alias estándar (username/password) al JS
    const sql = `SELECT id, ${u} AS username, ${p} AS password FROM usuarios WHERE ${u} = ?`;

    db.get(sql, [username], (err2, row) => {
      if (err2) {
        console.error("select usuario error:", err2);
        db.close();
        return res.status(500).json({ error: "error_servidor" });
        }
      if (!row) {
        db.close();
        return res.status(401).json({ error: "usuario_no_encontrado" });
      }

      const stored = String(row.password ?? "");

      // Si ALLOW_USERNAME_ONLY=true y NO se envió password -> pasa.
      // En caso contrario, compara password.
      if (!(ALLOW_USERNAME_ONLY && !password)) {
        if (stored !== String(password)) {
          db.close();
          return res.status(401).json({ error: "credenciales_invalidas" });
        }
      }

      req.session.userId = row.id;
      req.session.username = row.username;
      db.close();

      return res.redirect("/inicio.html");
    });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "error_servidor" });
  }
});

// ===== API: Logout / WhoAmI =====
app.post("/logout", (req, res) => {
  try {
    if (req.session) {
      req.session.destroy(() => res.json({ ok: true }));
    } else {
      res.json({ ok: true });
    }
  } catch (err) {
    console.error("logout error:", err);
    res.status(500).json({ error: "error_servidor" });
  }
});

app.get("/whoami", (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({
      authenticated: true,
      id: req.session.userId,
      username: req.session.username,
    });
  }
  res.json({ authenticated: false });
});

// ===== Healthchecks =====
app.get("/salud", (_req, res) => res.status(200).type("text").send("ok"));
app.get("/health", (_req, res) => res.status(200).type("text").send("ok"));

// ===== Rutas de conveniencia =====
app.get("/", (req, res) => {
  if (req.session && req.session.userId) return res.redirect("/inicio.html");
  return res.redirect("/login.html");
});
app.get("/inicio", (_req, res) => res.redirect(302, "/inicio.html"));
app.get("/historial", (_req, res) => res.redirect(302, "/historial.html"));

// ===== 404 =====
app.use((_, res) => res.status(404).type("text").send("Recurso no encontrado."));

// ===== Arranque =====
detectUserColumns((err) => {
  if (err) process.exit(1);
  app.listen(PORT, HOST, () => {
    console.log(
      `Servidor en http://${HOST}:${PORT} (env:${NODE_ENV}) username-only=${ALLOW_USERNAME_ONLY} | USER_COL=${USER_COL} PASS_COL=${PASS_COL}`
    );
  });
});
