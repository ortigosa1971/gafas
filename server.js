// server.js
"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

// ===== Config =====
const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = process.env.PORT || 8080;
const HOST = "0.0.0.0";
const ALLOW_USERNAME_ONLY =
  String(process.env.ALLOW_USERNAME_ONLY || "").toLowerCase() === "true";

const PUBLIC_DIR = path.join(__dirname, "public");
const DB_DIR = path.join(__dirname, "db");
const DB_FILE = path.join(DB_DIR, "usuarios.db");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}
function getDB() {
  ensureDir(DB_DIR);
  return new sqlite3.Database(DB_FILE);
}

// ===== Init DB (tabla + migración si columnas están en español) =====
function initDB(cb) {
  const db = getDB();

  db.all(`PRAGMA table_info(usuarios);`, (infoErr, rows) => {
    const noTable = infoErr && /no such table/i.test(String(infoErr));
    const cols = Array.isArray(rows) ? rows.map((r) => r.name) : [];

    const hasUsername = cols.includes("username");
    const hasPassword = cols.includes("password");
    const hasNombreUsuario =
      cols.includes("nombre de usuario") || cols.includes("nombre_usuario");
    const hasContrasena =
      cols.includes("contraseña") || cols.includes("contrasena");

    const createCorrect = () => {
      db.run(
        `CREATE TABLE IF NOT EXISTS usuarios (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL
        )`,
        (err) => {
          if (err) {
            console.error("DB: error creando tabla usuarios:", err);
            db.close();
            return cb && cb(err);
          }
          // seed admin (password vacía; útil si ALLOW_USERNAME_ONLY=true)
          db.run(
            "INSERT OR IGNORE INTO usuarios (username, password) VALUES (?, ?)",
            ["admin", ""],
            (seedErr) => {
              if (seedErr) console.error("DB: seed admin error:", seedErr);
              db.close();
              return cb && cb(null);
            }
          );
        }
      );
    };

    // Sin tabla o ya correcta → crear/sembrar y salir
    if (noTable || (hasUsername && hasPassword && !hasNombreUsuario && !hasContrasena)) {
      return createCorrect();
    }

    // Detectado esquema en español → migrar
    if ((hasNombreUsuario || hasContrasena) && !(hasUsername && hasPassword)) {
      console.warn("DB: detectado esquema en español; migrando a username/password…");

      db.serialize(() => {
        db.run(
          `CREATE TABLE IF NOT EXISTS usuarios_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
          )`
        );

        const userCol = hasNombreUsuario
          ? (cols.includes("nombre_usuario") ? "nombre_usuario" : "`nombre de usuario`")
          : "username";
        const passCol = hasContrasena
          ? (cols.includes("contrasena") ? "contrasena" : "contraseña")
          : "password";

        db.run(
          `INSERT OR IGNORE INTO usuarios_new (id, username, password)
           SELECT id, ${userCol}, ${passCol} FROM usuarios`,
          (copyErr) => {
            if (copyErr) {
              console.error("DB: error copiando datos a usuarios_new:", copyErr);
              return db.run(`ALTER TABLE usuarios RENAME TO usuarios_obsoleta;`, () => {
                createCorrect();
              });
            }

            db.run(`DROP TABLE usuarios;`, (dropErr) => {
              if (dropErr) console.error("DB: error drop usuarios:", dropErr);
              db.run(
                `ALTER TABLE usuarios_new RENAME TO usuarios;`,
                (renErr) => {
                  if (renErr) {
                    console.error("DB: error rename usuarios_new -> usuarios:", renErr);
                    db.close();
                    return cb && cb(renErr);
                  }
                  console.log("DB: migración completada a username/password.");
                  db.run(
                    "INSERT OR IGNORE INTO usuarios (username, password) VALUES (?, ?)",
                    ["admin", ""],
                    (seedErr) => {
                      if (seedErr) console.error("DB: seed admin error:", seedErr);
                      db.close();
                      return cb && cb(null);
                    }
                  );
                }
              );
            });
          }
        );
      });
      return;
    }

    // Cualquier otro caso raro → garantizar estructura correcta
    createCorrect();
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

// Páginas privadas que requieren sesión
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

// ===== API: Login (usuario solo si ALLOW_USERNAME_ONLY=true) =====
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
      }
    );
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
app.use((req, res) => {
  res.status(404).type("text").send("Recurso no encontrado.");
});

// ===== Start =====
initDB((err) => {
  if (err) process.exit(1);
  app.listen(PORT, HOST, () => {
    console.log(
      `Servidor en http://${HOST}:${PORT} (env:${NODE_ENV}) username-only=${ALLOW_USERNAME_ONLY}`
    );
  });
});
