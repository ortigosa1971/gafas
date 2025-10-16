"use strict";

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();

// ===== Configuración =====
const ENTORNO = process.env.NODE_ENV || "producción";
const PUERTO = process.env.PORT || 8080;
const HOST = "0.0.0.0";
const SOLO_USUARIO =
  String(process.env.ALLOW_USERNAME_ONLY || "").toLowerCase() === "true";

const CARPETA_PUBLICA = path.join(__dirname, "public");
const CARPETA_DB = path.join(__dirname, "db");
const ARCHIVO_DB = path.join(CARPETA_DB, "usuarios.db");

function asegurarDirectorio(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}
function obtenerDB() {
  asegurarDirectorio(CARPETA_DB);
  return new sqlite3.Database(ARCHIVO_DB);
}

// ===== Aplicación =====
const app = express();

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "sesion",
    secret: process.env.SESSION_SECRET || "secreto-desarrollo",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// Páginas protegidas
const paginasPrivadas = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  try {
    if (req.method === "GET" && paginasPrivadas.has(req.path)) {
      if (req.session && req.session.idUsuario) return next();
      return res.redirect(302, "/login.html");
    }
    next();
  } catch (e) {
    console.error("Error en middleware privado:", e);
    res.status(500).type("text").send("Error interno del servidor.");
  }
});

// Servir archivos estáticos
app.use(express.static(CARPETA_PUBLICA, { fallthrough: true }));

// ===== Ruta: Inicio de sesión =====
app.post("/login", (req, res) => {
  try {
    const b = req.body || {};
    const nombreUsuario = (b.username ?? b.usuario ?? b["nombre de usuario"] ?? "").toString().trim();
    const contrasena = (b.password ?? b.pass ?? b["contraseña"] ?? b.contrasena ?? "").toString();

    if (!nombreUsuario) {
      return res.status(400).json({ error: "campos_faltantes", detalle: "nombre de usuario requerido" });
    }
    if (!SOLO_USUARIO && !contrasena) {
      return res.status(400).json({ error: "campos_faltantes", detalle: "contraseña requerida" });
    }

    const db = obtenerDB();
    const sql = "SELECT id, `nombre de usuario` AS nombreUsuario, `contraseña` AS contrasena FROM usuarios WHERE `nombre de usuario` = ?";

    db.get(sql, [nombreUsuario], (err, fila) => {
      if (err) {
        console.error("Error al seleccionar usuario:", err);
        db.close();
        return res.status(500).json({ error: "error_servidor" });
      }
      if (!fila) {
        db.close();
        return res.status(401).json({ error: "usuario_no_encontrado" });
      }

      const guardada = String(fila.contrasena ?? "");

      // Si solo usuario activado, no se requiere contraseña
      if (!(SOLO_USUARIO && !contrasena)) {
        if (guardada !== String(contrasena)) {
          db.close();
          return res.status(401).json({ error: "credenciales_invalidas" });
        }
      }

      req.session.idUsuario = fila.id;
      req.session.nombreUsuario = fila.nombreUsuario;
      db.close();

      return res.redirect("/inicio.html");
    });
  } catch (err) {
    console.error("Error en login:", err);
    return res.status(500).json({ error: "error_servidor" });
  }
});

// ===== Cierre de sesión =====
app.post("/logout", (req, res) => {
  try {
    if (req.session) {
      req.session.destroy(() => res.json({ ok: true }));
    } else {
      res.json({ ok: true });
    }
  } catch (err) {
    console.error("Error en logout:", err);
    res.status(500).json({ error: "error_servidor" });
  }
});

// ===== Comprobar sesión =====
app.get("/quiensoy", (req, res) => {
  if (req.session && req.session.idUsuario) {
    return res.json({
      autenticado: true,
      id: req.session.idUsuario,
      nombreUsuario: req.session.nombreUsuario,
    });
  }
  res.json({ autenticado: false });
});

// ===== Healthcheck =====
app.get("/salud", (_req, res) => res.status(200).type("text").send("ok"));
app.get("/health", (_req, res) => res.status(200).type("text").send("ok"));

// ===== Rutas de conveniencia =====
app.get("/", (req, res) => {
  if (req.session && req.session.idUsuario) return res.redirect("/inicio.html");
  return res.redirect("/login.html");
});
app.get("/inicio", (_req, res) => res.redirect(302, "/inicio.html"));
app.get("/historial", (_req, res) => res.redirect(302, "/historial.html"));

// ===== 404 =====
app.use((_, res) => res.status(404).type("text").send("Recurso no encontrado."));

// ===== Arranque =====
app.listen(PUERTO, HOST, () => {
  console.log(
    `Servidor en http://${HOST}:${PUERTO} (entorno:${ENTORNO}) solo-usuario=${SOLO_USUARIO}`
  );
});
