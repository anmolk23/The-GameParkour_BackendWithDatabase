const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// -------------------- PERSISTENT DB PATH --------------------

const defaultDir = process.env.DB_DIR || "/var/data";
const defaultDb = path.join(defaultDir, "gamerverse.db");
const DB_PATH = process.env.DB_PATH || defaultDb;

// Ensure directory exists for DB and sessions
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Sessions DB path (store sessions in same persistent dir)
const SESSIONS_DB = path.join(dbDir, "sessions.sqlite");

// -------------------- UPLOADS --------------------
const uploadsDir = path.join(dbDir, "uploads"); // store uploads in persistent dir too
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// Serve uploaded images (use absolute path)
app.use("/uploads", express.static(uploadsDir));

// -------------------- DATABASE --------------------
let db;
try {
  db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
      console.error("Failed to open DB:", err);
      process.exit(1);
    } else {
      console.log("Opened SQLite DB at", DB_PATH);
    }
  });
} catch (e) {
  console.error("DB open error:", e);
  process.exit(1);
}

// Run init-db.sql if present (safe)
const INIT_SQL = path.join(__dirname, "init-db.sql");
if (fs.existsSync(INIT_SQL)) {
  try {
    const sql = fs.readFileSync(INIT_SQL, "utf8");
    db.exec(sql, (err) => {
      if (err) console.error("Error running init-db.sql:", err);
      else console.log("init-db.sql executed (if it contained CREATE TABLE statements).");
    });
  } catch (e) {
    console.error("Failed to read/exec init-db.sql:", e);
  }
}

// handle DB-level errors reported by node-sqlite3
db.on("error", (err) => {
  console.error("SQLite error event:", err);
});

// -------------------- MIDDLEWARE --------------------
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SQLiteStore = SQLiteStoreFactory(session);

app.use(
  session({
    store: new SQLiteStore({ db: path.basename(SESSIONS_DB), dir: path.dirname(SESSIONS_DB) }),
    secret: process.env.SESSION_SECRET || "replace-with-a-strong-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
  })
);

// Serve static frontend files from repo root (ensure your HTML/CSS at repo root)
app.use(express.static(path.join(__dirname)));

// -------------------- AUTH HELPERS --------------------
function requireLogin(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// -------------------- AUTH ROUTES --------------------
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "Missing fields" });

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, hash],
      function (err) {
        if (err) {
          if (err.message && err.message.includes("UNIQUE")) return res.status(409).json({ error: "Email already exists" });
          console.error("Signup DB error:", err);
          return res.status(500).json({ error: "DB error" });
        }
        req.session.userId = this.lastID;
        res.json({ ok: true, userId: this.lastID });
      }
    );
  } catch (e) {
    console.error("Signup error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  db.get("SELECT id, password_hash, name, email FROM users WHERE email = ?", [email], async (err, row) => {
    if (err) {
      console.error("Login DB error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    if (!row) return res.status(401).json({ error: "Invalid credentials" });

    try {
      const match = await bcrypt.compare(password, row.password_hash);
      if (!match) return res.status(401).json({ error: "Invalid credentials" });
      req.session.userId = row.id;
      res.json({ ok: true, userId: row.id, name: row.name, email: row.email });
    } catch (e) {
      console.error("Login compare error:", e);
      res.status(500).json({ error: "Server error" });
    }
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// -------------------- PROFILE --------------------
app.get("/api/profile", requireLogin, (req, res) => {
  db.get(
    "SELECT id, name, email, favorite_genre, hours_played, wins, losses, level, photo, bio FROM users WHERE id = ?",
    [req.session.userId],
    (err, row) => {
      if (err) {
        console.error("Profile GET error:", err);
        return res.status(500).json({ error: "DB error" });
      }
      res.json({ ok: true, profile: row || {} });
    }
  );
});

app.post("/api/profile/update", requireLogin, upload.single("photo"), (req, res) => {
  const { name, email, bio } = req.body;
  const photoPath = req.file ? `/uploads/${path.basename(req.file.path)}` : null;

  db.run(
    `UPDATE users SET name = ?, email = ?, bio = ?, photo = COALESCE(?, photo) WHERE id = ?`,
    [name, email, bio, photoPath, req.session.userId],
    function (err) {
      if (err) {
        console.error("Profile UPDATE error:", err);
        return res.status(500).json({ error: "DB error" });
      }
      res.json({ ok: true });
    }
  );
});

// -------------------- COLLECTION --------------------
app.post("/api/collection", requireLogin, (req, res) => {
  let { title, genre, hours, img_url } = req.body;
  hours = Number(hours) || 0;
  title = title || "Untitled";

  db.run(
    "INSERT INTO games (user_id, title, genre, hours, owned, img_url) VALUES (?, ?, ?, ?, 1, ?)",
    [req.session.userId, title, genre || "", hours, img_url || ""],
    function (err) {
      if (err) {
        console.error("Collection INSERT error:", err);
        return res.status(500).json({ error: "DB error" });
      }
      res.json({ ok: true, id: this.lastID });
    }
  );
});

app.get("/api/collection", requireLogin, (req, res) => {
  db.all("SELECT * FROM games WHERE user_id = ? AND owned = 1 ORDER BY id DESC", [req.session.userId], (err, rows) => {
    if (err) {
      console.error("Collection SELECT error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    res.json({ ok: true, games: rows || [] });
  });
});

app.delete("/api/collection/:id", requireLogin, (req, res) => {
  db.run("DELETE FROM games WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], function (err) {
    if (err) {
      console.error("Collection DELETE error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    res.json({ ok: true, deleted: this.changes });
  });
});

// -------------------- WISHLIST --------------------
app.post("/api/wishlist", requireLogin, (req, res) => {
  const { title, genre, expected_release } = req.body;
  db.run("INSERT INTO wishlist (user_id, title, genre, expected_release) VALUES (?, ?, ?, ?)",
    [req.session.userId, title || "Untitled", genre || "", expected_release || ""],
    function (err) {
      if (err) {
        console.error("Wishlist INSERT error:", err);
        return res.status(500).json({ error: "DB error" });
      }
      res.json({ ok: true, id: this.lastID });
    });
});

app.get("/api/wishlist", requireLogin, (req, res) => {
  db.all("SELECT * FROM wishlist WHERE user_id = ? ORDER BY id DESC", [req.session.userId], (err, rows) => {
    if (err) {
      console.error("Wishlist SELECT error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    // frontend expects { wishlist: [...] } in some of your versions — keep that shape
    return res.json({ ok: true, wishlist: rows || [], list: rows || [] });
  });
});

app.delete("/api/wishlist/:id", requireLogin, (req, res) => {
  db.run("DELETE FROM wishlist WHERE id = ? AND user_id = ?", [req.params.id, req.session.userId], function (err) {
    if (err) {
      console.error("Wishlist DELETE error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    res.json({ ok: true, deleted: this.changes });
  });
});

// -------------------- STATS --------------------
app.get("/api/stats", requireLogin, (req, res) => {
  const userId = req.session.userId;
  db.get("SELECT COUNT(*) AS totalGames, COALESCE(SUM(hours),0) AS totalHours FROM games WHERE user_id = ? AND owned = 1", [userId], (err, gameRow) => {
    if (err) {
      console.error("Stats games query error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    db.get("SELECT level, wins, losses FROM users WHERE id = ?", [userId], (err2, userRow) => {
      if (err2) {
        console.error("Stats user query error:", err2);
        return res.status(500).json({ error: "DB error" });
      }
      const wins = (userRow && userRow.wins) || 0;
      const losses = (userRow && userRow.losses) || 0;
      const winRatio = wins + losses === 0 ? 0 : Math.round((wins / (wins + losses)) * 100);
      const level = (userRow && userRow.level) || 1;
      const levelProgress = Math.min(Math.round((level / 100) * 100), 100);

      res.json({
        ok: true,
        stats: {
          totalGames: (gameRow && gameRow.totalGames) || 0,
          totalHours: (gameRow && gameRow.totalHours) || 0,
          level,
          levelProgress,
          winRatio
        }
      });
    });
  });
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`Server running → http://localhost:${PORT}`);
  console.log(`Using DB at ${DB_PATH}`);
});
