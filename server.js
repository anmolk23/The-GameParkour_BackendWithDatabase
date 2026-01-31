// -------------------- IMPORTS --------------------
const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const multer = require("multer");

// -------------------- APP SETUP --------------------
const app = express();
const PORT = process.env.PORT || 3000; // ✅ DECLARED ONLY ONCE
const SALT_ROUNDS = 10;

// -------------------- PERSISTENT DB PATH --------------------
const defaultDir = process.env.DB_DIR || "/tmp";
const defaultDb = path.join(defaultDir, "gamerverse.db");
const DB_PATH = process.env.DB_PATH || defaultDb;

// Ensure DB directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// -------------------- SESSION STORE --------------------
const SESSIONS_DB = path.join(dbDir, "sessions.sqlite");
const SQLiteStore = SQLiteStoreFactory(session);

// -------------------- UPLOADS --------------------
const uploadsDir = path.join(dbDir, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

app.use("/uploads", express.static(uploadsDir));

// -------------------- DATABASE --------------------
const db = new sqlite3.Database(
  DB_PATH,
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error("Failed to open DB:", err);
      process.exit(1);
    }
    console.log("SQLite DB opened at", DB_PATH);
  }
);

// Run init-db.sql if exists
const INIT_SQL = path.join(__dirname, "init-db.sql");
if (fs.existsSync(INIT_SQL)) {
  const sql = fs.readFileSync(INIT_SQL, "utf8");
  db.exec(sql, (err) => {
    if (err) console.error("init-db.sql error:", err);
    else console.log("init-db.sql executed");
  });
}

// -------------------- MIDDLEWARE --------------------
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    store: new SQLiteStore({
      db: path.basename(SESSIONS_DB),
      dir: path.dirname(SESSIONS_DB)
    }),
    secret: process.env.SESSION_SECRET || "replace-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
  })
);

// Serve frontend files
app.use(express.static(path.join(__dirname)));

// -------------------- AUTH MIDDLEWARE --------------------
function requireLogin(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// -------------------- AUTH ROUTES --------------------
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);

  db.run(
    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
    [name, email, hash],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE"))
          return res.status(409).json({ error: "Email exists" });
        return res.status(500).json({ error: "DB error" });
      }
      req.session.userId = this.lastID;
      res.json({ ok: true });
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, user) => {
      if (!user) return res.status(401).json({ error: "Invalid login" });

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return res.status(401).json({ error: "Invalid login" });

      req.session.userId = user.id;
      res.json({ ok: true });
    }
  );
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// -------------------- PROFILE --------------------
app.get("/api/profile", requireLogin, (req, res) => {
  db.get(
    "SELECT id, name, email, bio, photo FROM users WHERE id = ?",
    [req.session.userId],
    (err, row) => {
      res.json({ ok: true, profile: row });
    }
  );
});

app.post(
  "/api/profile/update",
  requireLogin,
  upload.single("photo"),
  (req, res) => {
    const { name, bio } = req.body;
    const photo = req.file ? `/uploads/${req.file.filename}` : null;

    db.run(
      "UPDATE users SET name=?, bio=?, photo=COALESCE(?,photo) WHERE id=?",
      [name, bio, photo, req.session.userId],
      () => res.json({ ok: true })
    );
  }
);

// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`Server running → http://localhost:${PORT}`);
  console.log(`Using DB → ${DB_PATH}`);
});

