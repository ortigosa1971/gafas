"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

const ENTORNO = process.env.NODE_ENV || "producción";
const PUERTO = process.env.PORT || 8080;
const HOST = "0.0.0.0";
const SOLO_USUARIO =
  String(process.env.ALLOW_USERNAME_ONLY || "").toLowerCase() === "true";

const CARPETA_PUBLICA = path.join(__dirname, "public");
const CARPETA_DB = path.join(__dirname, "db");
const ARCHIVO_DB = path.join(CARPETA_DB, "usuarios.db");

function obtenerDB() {
  if (!fs.existsSync(CARPETA_DB)) fs.mkdirSync(CARPETA_DB, { recursive: true });
  return new sqlite3.Database(ARCHIVO_DB);
}

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "clave",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(express.static(CARPETA_PUBLICA));

app.post("/login", (req, res) => {
  const b = req.body || {};
  const nombreUsuario = (b.usuario || b.username || "").trim();
  const contrasena = (b.contrasena || b.password || b["contraseña"] || "").trim();

  if (!nombreUsuario)
    return res.status(400).json({ error: "nombre_usuario_requerido" });
  if (!SOLO_USUARIO && !contrasena)
    return res.status(400).json({ error: "contrasena_requerida" });

  const db = obtenerDB();
  db.get(
    'SELECT id, nombre_usuario, contrasena FROM usuarios WHERE nombre_usuario = ?',
    [nombreUsuario],
    (err, fila) => {
      if (err) {
        console.error("Error DB:", err);
        return res.status(500).json({ error: "error_db" });
      }
      if (!fila)
        return res.status(401).json({ error: "usuario_no_encontrado" });

      if (!SOLO_USUARIO && fila.contrasena !== contrasena)
        return res.status(401).json({ error: "credenciales_invalidas" });

      req.session.idUsuario = fila.id;
      req.session.nombreUsuario = fila.nombre_usuario;
      return res.redirect("/inicio.html");
    }
  );
});

app.get("/salud", (_, res) => res.send("ok"));
app.get("/", (req, res) =>
  req.session?.idUsuario
    ? res.redirect("/inicio.html")
    : res.redirect("/login.html")
);

app.listen(PUERTO, HOST, () => {
  console.log(
    `Servidor en http://${HOST}:${PUERTO} (solo-usuario=${SOLO_USUARIO})`
  );
});
