// -------------------- BASIC SETUP --------------------
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

// Create uploads folder if missing
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// Create express app
const app = express();

// -------------------- MULTER (FILE UPLOADS) --------------------
const multer = require("multer");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});

const upload = multer({ storage });

// Serve uploaded images
app.use("/uploads", express.static("uploads"));

// -------------------- DB SETUP --------------------
const DB_FILE = path.join(__dirname, "gamerverse.db");
const PORT = 3000;
const SALT_ROUNDS = 10;

const db = new sqlite3.Database(DB_FILE, err => {
  if (err) console.error("DB connect error:", err);
});

// ❌ REMOVED INIT-DB AUTO EXECUTION
// Run init-db.sql ONLY manually

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Sessions
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: "." }),
    secret: "super-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
  })
);

// Serve frontend
app.use(express.static(__dirname));

// -------------------- LOGIN CHECK --------------------
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// -------------------- AUTH ROUTES --------------------
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Missing fields" });

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    db.run(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, hash],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE"))
            return res.status(409).json({ error: "Email already exists" });
          return res.status(500).json({ error: "DB error" });
        }
        req.session.userId = this.lastID;
        res.json({ ok: true });
      }
    );
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!row) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    req.session.userId = row.id;
    res.json({ ok: true });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// -------------------- PROFILE ROUTES --------------------
app.get("/api/profile", requireLogin, (req, res) => {
  db.get(
    `SELECT id, name, email, favorite_genre, hours_played, wins, losses, level, photo, bio 
     FROM users WHERE id = ?`,
    [req.session.userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ ok: true, profile: row });
    }
  );
});

app.post(
  "/api/profile/update",
  requireLogin,
  upload.single("photo"),
  (req, res) => {
    const { name, email, bio } = req.body;
    const photoPath = req.file ? "/uploads/" + req.file.filename : null;

    const sql = `
      UPDATE users 
      SET name = ?, email = ?, bio = ?, photo = COALESCE(?, photo)
      WHERE id = ?
    `;

    db.run(sql, [name, email, bio, photoPath, req.session.userId], err => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ ok: true });
    });
  }
);

// -------------------- COLLECTION ROUTES --------------------
app.post("/api/collection", requireLogin, (req, res) => {
  const { title, genre, hours, img_url } = req.body;

  db.run(
    `INSERT INTO games (user_id, title, genre, hours, owned, img_url) 
     VALUES (?, ?, ?, ?, 1, ?)`,
    [req.session.userId, title, genre, hours, img_url],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ ok: true, id: this.lastID });
    }
  );
});

app.get("/api/collection", requireLogin, (req, res) => {
  db.all(
    "SELECT * FROM games WHERE user_id = ? AND owned = 1 ORDER BY id DESC",
    [req.session.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json({ ok: true, games: rows });
    }
  );
});

app.delete("/api/collection/:id", requireLogin, (req, res) => {
  db.run(
    "DELETE FROM games WHERE id = ? AND user_id = ?",
    [req.params.id, req.session.userId],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json({ ok: true });
    }
  );
});

// -------------------- WISHLIST ROUTES --------------------
app.post("/api/wishlist", requireLogin, (req, res) => {
  const { title, genre, expected_release } = req.body;

  db.run(
    `INSERT INTO wishlist (user_id, title, genre, expected_release)
     VALUES (?, ?, ?, ?)`,
    [req.session.userId, title, genre, expected_release],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json({ ok: true, id: this.lastID });
    }
  );
});

app.get("/api/wishlist", requireLogin, (req, res) => {
  db.all(
    "SELECT * FROM wishlist WHERE user_id = ? ORDER BY id DESC",
    [req.session.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json({ ok: true, wishlist: rows }); // correct key
    }
  );
});

app.delete("/api/wishlist/:id", requireLogin, (req, res) => {
  db.run(
    "DELETE FROM wishlist WHERE id = ? AND user_id = ?",
    [req.params.id, req.session.userId],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json({ ok: true });
    }
  );
});

// -------------------- STATS --------------------
app.get("/api/stats", requireLogin, (req, res) => {
  const userId = req.session.userId;

  db.get(
    `SELECT COUNT(*) AS totalGames, SUM(hours) AS totalHours 
     FROM games WHERE user_id = ? AND owned = 1`,
    [userId],
    (err, gameRow) => {
      if (err) return res.status(500).json({ error: "DB error" });

      db.get(
        "SELECT level, wins, losses FROM users WHERE id = ?",
        [userId],
        (err2, userRow) => {
          if (err2) return res.status(500).json({ error: "DB error" });

          const wins = userRow.wins || 0;
          const losses = userRow.losses || 0;

          const winRatio =
            wins + losses === 0 ? 0 : Math.round((wins / (wins + losses)) * 100);

          res.json({
            ok: true,
            stats: {
              totalGames: gameRow.totalGames || 0,
              totalHours: gameRow.totalHours || 0,
              level: userRow.level,
              levelProgress: Math.round((userRow.level / 100) * 100),
              winRatio
            }
          });
        }
      );
    }
  );
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => {
  console.log(`Server running → http://localhost:${PORT}`);
});
