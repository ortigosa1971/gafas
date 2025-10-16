"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

// ==== CONFIGURACIÓN ====
const PUERTO = process.env.PORT || 8080;
const HOST = "0.0.0.0";
const SOLO_USUARIO = String(process.env.ALLOW_USERNAME_ONLY || "").toLowerCase() === "true";
const DB_DIR = path.join(__dirname, "db");
const DB_FILE = path.join(DB_DIR, "usuarios.db");

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

// ==== APP EXPRESS ====
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "clave-super-secreta",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000 * 60 * 60 * 8 },
  })
);

app.use(express.static(path.join(__dirname, "public")));

// ==== FUNCIONES DE BD ====
function abrirDB() {
  return new sqlite3.Database(DB_FILE);
}

// Intenta detectar nombres de columnas válidos
function detectarColumnas(db, cb) {
  db.all("PRAGMA table_info(usuarios);", (err, rows) => {
    if (err) return cb(err);
    const columnas = rows.map((r) => r.name);
    const tiene = (n) => columnas.includes(n);

    let userCol = "nombre_usuario";
    let passCol = "contrasena";

    if (tiene("nombre de usuario")) userCol = "`nombre de usuario`";
    else if (tiene("usuario")) userCol = "usuario";

    if (tiene("contraseña")) passCol = "`contraseña`";
    else if (tiene("clave")) passCol = "clave";

    cb(null, { userCol, passCol });
  });
}

// ==== RUTAS ====
app.get("/salud", (_, res) => res.status(200).send("ok"));

app.post("/login", (req, res) => {
  const { usuario, username, password, contrasena } = req.body;
  const nombre = (usuario || username || "").trim();
  const clave = (contrasena || password || "").trim();

  if (!nombre)
    return res.status(400).json({ error: "faltan_campos", detalle: "usuario requerido" });

  const db = abrirDB();
  detectarColumnas(db, (err, cols) => {
    if (err) {
      console.error("Error detectando columnas:", err);
      return res.status(500).json({ error: "error_db" });
    }

    const sql = `SELECT id, ${cols.userCol} AS usuario, ${cols.passCol} AS contrasena FROM usuarios WHERE ${cols.userCol} = ?`;
    db.get(sql, [nombre], (e2, fila) => {
      if (e2) {
        console.error("Error SELECT:", e2);
        return res.status(500).json({ error: "error_db" });
      }
      if (!fila) return res.status(401).json({ error: "usuario_no_encontrado" });

      if (!SOLO_USUARIO && fila.contrasena !== clave)
        return res.status(401).json({ error: "credenciales_invalidas" });

      req.session.usuarioId = fila.id;
      req.session.nombreUsuario = fila.usuario;
      res.redirect("/inicio.html");
    });
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/", (req, res) => {
  if (req.session.usuarioId) return res.redirect("/inicio.html");
  res.redirect("/login.html");
});

// ==== ARRANQUE ====
app.listen(PUERTO, HOST, () =>
  console.log(`✅ Servidor activo en http://${HOST}:${PUERTO} (solo-usuario=${SOLO_USUARIO})`)
);
