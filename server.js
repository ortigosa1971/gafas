// server.js
// Servidor Express con sesiones y control de acceso a páginas privadas.
// Incluye healthcheck (/salud), alias de rutas y redirección tras login.

"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

// ===== Configuración básica =====
const NODE_ENV = process.env.NODE_ENV || "desarrollo";
const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";

// Carpeta pública
const PUBLIC_DIR = path.join(__dirname, "public");

// DB: archivo y helper
const DB_DIR = path.join(__dirname, "db");
const DB_FILE = path.join(DB_DIR, "usuarios.db");

function ensureDbDir() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
}

function getDB() {
  ensureDbDir();
  return new sqlite3.Database(DB_FILE);
}

// ===== App =====
const app = express();

// Body parsers
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Sesiones (MemoryStore para dev; en prod usar store persistente)
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: !!process.env.SESSION_SECURE, // ponlo a true si vas a servir sobre HTTPS con proxy que reescriba secure
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// ===== Utilidades =====

// Conjunto de páginas privadas que requieren sesión (sirves estáticos, pero con control)
const paginasPrivadas = new Set(["/inicio.html", "/historial.html"]);

// Middleware: protege las páginas privadas servidas como archivos estáticos
app.use((req, res, next) => {
  try {
    // Solo aplica a GET a rutas exactas de páginas privadas
    if (req.method === "GET" && paginasPrivadas.has(req.path)) {
      if (req.session && req.session.userId) {
        return next();
      }
      // Sin sesión → a login
      return res.redirect(302, "/login.html");
    }
    return next();
  } catch (err) {
    console.error("middleware privado error:", err);
    return res.status(500).type("text").send("Error de servidor.");
  }
});

// Sirve estáticos
app.use(express.static(PUBLIC_DIR, { fallthrough: true }));

// ===== Rutas API =====

// Login: acepta username/usuario/user y password/pass/contraseña/contrasena
app.post("/login", (req, res) => {
  try {
    const b = req.body || {};
    const username =
      (b.username ?? b.usuario ?? b.user ?? "").toString().trim();
    const password =
      (b.password ?? b.pass ?? b.contrasena ?? b["contraseña"] ?? "")
        .toString();

    if (!username || !password) {
      return res.status(400).json({ error: "campos_faltantes" });
    }

    const db = getDB();

    // Nos aseguramos de que exista la tabla (por si el entorno arranca "limpio")
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

        // Busca usuario
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

            // Comparación simple (texto plano). En producción, usa hash (bcrypt).
            if (String(row.password) !== String(password)) {
              db.close();
              return res.status(401).json({ error: "credenciales_invalidas" });
            }

            // OK → sesión y redirige a inicio
            req.session.userId = row.id;
            req.session.username = row.username;
            db.close();

            // Importante: redirigimos para que no se quede en /login (evita 404 posteriores)
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
    return res.status(500).json({ error: "error_servidor" });
  }
});

// Quién soy (útil para front)
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

// ===== Healthcheck (para plataforma) =====
app.get("/salud", (_req, res) => {
  res.status(200).type("text").send("ok");
});
app.get("/health", (_req, res) => {
  res.status(200).type("text").send("ok");
});

// ===== Rutas de conveniencia (después de APIs, antes del 404) =====
app.get("/", (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect("/inicio.html");
  }
  return res.redirect("/login.html");
});

// Alias sin extensión
app.get("/inicio", (_req, res) => res.redirect(302, "/inicio.html"));
app.get("/historial", (_req, res) => res.redirect(302, "/historial.html"));

// ===== 404 genérico (debe ir al final) =====
app.use((req, res) => {
  res.status(404).type("text").send("Recurso no encontrado.");
});

// ===== Arranque =====
app.listen(PORT, HOST, () => {
  console.log(`Servidor en http://${HOST}:${PORT} (env:${NODE_ENV})`);
});

