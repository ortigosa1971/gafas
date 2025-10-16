// server.js
"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

// ===== Configuración =====
const NODE_ENV = process.env.NODE_ENV || "desarrollo";
const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";
const ALLOW_USERNAME_ONLY = String(process.env.ALLOW_USERNAME_ONLY || "").toLowerCase() === "true";

const PUBLIC_DIR = path.join(__dirname, "public");
const DB_DIR = path.join(__dirname, "db");
const DB_FILE = path.join(DB_DIR, "usuarios.db");

function ensureDbDir() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
}
function getDB() {
  ensureDbDir();
  return new sqlite3.Database(DB_FILE);
}

const app = express();

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
      secure: !!process.env.SESSION_SECURE,
      maxAge: 1000 * 60 * 60 * 8,
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

app.use(express.static(PUBLIC_DIR, { fallthrough: true }));

// ===== Login con modo "solo usuario" opcional =====
app.post("/login", (req, res) => {
  try {
    const b = req.body || {};
    const username = (b.username ?? b.usuario ?? b.user ?? "").toString().trim();
    const password = (b.password ?? b.pass ?? b.contrasena ?? b["contraseña"] ?? "").toString();

    // Si NO hay username, error siempre
    if (!username) {
      return res.status(400).json({ error: "campos_faltantes", detalle: "username requerido" });
    }
    // Si el modo "solo usuario" NO está permitido y no hay password -> error
    if (!ALLOW_USERNAME_ONLY && !password) {
      return res.status(400).json({ error: "campos_faltantes", detalle: "password requerido" });
    }

    const db = getDB();

    db.run(
      `CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )`,
      (err) => {
        if (err) {
          console.error("crear tabla error:", err);
          db.close();
          return res.status(500).json({ error: "error_servidor" });
        }

        db.get(
          "SELECT id, username, password FROM usuarios WHERE username = ?",
          [username],
          (err2, row) => {
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

            // Lógica de autenticación:
            // - Si ALLOW_USERNAME_ONLY=true y no enviaron password -> pasa (solo por usuario).
            // - Si ALLOW_USERNAME_ONLY=true y enviaron password -> compara como siempre.
            // - Si ALLOW_USERNAME_ONLY=false -> siempre compara password.
            if (!(ALLOW_USERNAME_ONLY && !password)) {
              if (stored !== String(password)) {
                db.close();
                return res.status(401).json({ error: "credenciales_invalidas" });
              }
            }

            // Sesión OK
            req.session.userId = row.id;
            req.session.username = row.username;
            db.close();

            return res.redirect("/inicio.html");
          }
        );
      }
    );
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "error_servidor" });
  }
});

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
    return res.json({ authenticated: true, id: req.session.userId, username: req.session.username });
  }
  res.json({ authenticated: false });
});

// Healthcheck
app.get("/salud", (_req, res) => res.status(200).type("text").send("ok"));
app.get("/health", (_req, res) => res.status(200).type("text").send("ok"));

// Rutas de conveniencia
app.get("/", (req, res) => {
  if (req.session && req.session.userId) return res.redirect("/inicio.html");
  return res.redirect("/login.html");
});
app.get("/inicio", (_req, res) => res.redirect(302, "/inicio.html"));
app.get("/historial", (_req, res) => res.redirect(302, "/historial.html"));

// 404
app.use((req, res) => {
  res.status(404).type("text").send("Recurso no encontrado.");
});

app.listen(PORT, HOST, () => {
  console.log(`Servidor en http://${HOST}:${PORT} (env:${NODE_ENV})  username-only=${ALLOW_USERNAME_ONLY}`);
});

