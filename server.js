const express = require("express");
const session = require("express-session");
const pgSessionFactory = require("connect-pg-simple");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const trustProxy = process.env.TRUST_PROXY === "true";

if (!process.env.DATABASE_URL) {
  throw new Error("Missing DATABASE_URL secret.");
}

if (!process.env.SESSION_SECRET) {
  throw new Error("Missing SESSION_SECRET secret.");
}

if (trustProxy) {
  app.set("trust proxy", 1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PgSession = pgSessionFactory(session);

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false,
    frameguard: false,
    referrerPolicy: { policy: "no-referrer" }
  })
);

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "200kb" }));

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true
    }),
    name: "love_poem_sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: trustProxy,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login or setup attempts. Please try again later." }
});

const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many write requests. Please slow down." }
});

function cleanName(value) {
  return String(value || "").trim().slice(0, 40);
}

function cleanText(value, max = 8000) {
  return String(value || "").trim().slice(0, max);
}

function cleanEmail(value) {
  return String(value || "").trim().slice(0, 254);
}

function isValidEmail(email) {
  return /^[^s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
  const sessionToken = req.session.csrfToken;
  const sentToken = req.get("x-csrf-token") || req.body.csrfToken || "";

  if (!sessionToken || !sentToken) {
    return res.status(403).json({ error: "Missing CSRF token." });
  }

  const a = Buffer.from(sessionToken, "utf8");
  const b = Buffer.from(String(sentToken), "utf8");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "Invalid CSRF token." });
  }

  next();
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      email TEXT UNIQUE,
      profile_quote TEXT,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email TEXT UNIQUE;
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS profile_quote TEXT;
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS user_name_lower_unique
    ON users (LOWER(name));
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS user_email_lower_unique
    ON users (LOWER(email));
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS poems (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid varchar NOT NULL PRIMARY KEY,
      sess json NOT NULL,
      expire timestamp(6) NOT NULL
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_session_expire
    ON session(expire);
  `);
}

app.use(express.static(path.join(__dirname)));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"))
});

app.get("/api/state", async (req, res) => {
  try {
    const countResult = await pool.query("SELECT COUNT(*)::int AS count FROM users");
    const configured = countResult.rows[0].count >= 2;

    let users = [];
    if (configured) {
      const usersResult = await pool.query("SELECT id, name, email, profile_quote FROM users ORDER BY id ASC");
      users = usersResult.rows;
    }

    let poems = [];
    if (req.session.user) {
      const poemsResult = await pool.query(`
        SELECT poems.id, poems.title, poems.content, poems.created_at,
               users.name AS author
        FROM poems
        JOIN users ON poems.author_id = users.id
        ORDER BY poems.created_at DESC, poems.id DESC
      `);
      poems = poemsResult.rows;
    }

    let needsProfileSetup = false;

    if (req.session.user) {
      const meResult = await pool.query(
        "SELECT email, profile_quote FROM users WHERE id = $1",
        [req.session.user.id]
      );

      if (meResult.rows.length) {
        const me = meResult.rows[0];
        needsProfileSetup = !me.email;
      }
    }

    ensureCsrfToken(req);

    res.json({
      configured,
      users,
      currentUser: req.session.user || null,
      poems,
      csrfToken: req.session.csrfToken, 
      needsProfileSetup
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load state." });
  }
});

app.post("/api/setup", authLimiter, requireCsrf, async (req, res) => {
  const client = await pool.connect();

  try {
    const countResult = await client.query("SELECT COUNT(*)::int AS count FROM users");
    if (countResult.rows[0].count > 0) {
      return res.status(400).json({ error: "Setup is already complete." });
    }

    const name1 = cleanName(req.body.name1);
    const pass1 = String(req.body.pass1 || "");
    const name2 = cleanName(req.body.name2);
    const pass2 = String(req.body.pass2 || "");

    if (!name1 || !name2 || !pass1 || !pass2) {
      return res.status(400).json({ error: "Fill in all setup fields." });
    }

    if (name1.toLowerCase() === name2.toLowerCase()) {
      return res.status(400).json({ error: "The two names must be different." });
    }

    if (pass1.length < 10 || pass2.length < 10) {
      return res.status(400).json({ error: "Passwords must be at least 10 characters." });
    }

    const hash1 = await bcrypt.hash(pass1, 12);
    const hash2 = await bcrypt.hash(pass2, 12);

    await client.query("BEGIN");

    const user1 = await client.query(
      "INSERT INTO users (name, password_hash) VALUES ($1, $2) RETURNING id, name",
      [name1, hash1]
    );

    const user2 = await client.query(
      "INSERT INTO users (name, password_hash) VALUES ($1, $2) RETURNING id, name",
      [name2, hash2]
    );

    await client.query(
      "INSERT INTO poems (title, content, author_id) VALUES ($1, $2, $3)",
      [
        "For You",
        "I'm sorry for the moments that hurt you.\nI love you more deeply than my clumsy words sometimes know how to say.\nIf your heart is tired, let mine be your rest.\nIf your night is heavy, let my love stay awake beside you.",
        user1.rows[0].id
      ]
    );

    await client.query("COMMIT");

    req.session.user = {
      id: user1.rows[0].id,
      name: user1.rows[0].name
    };
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    res.json({
      message: "Your private poem garden is ready.",
      csrfToken: req.session.csrfToken
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(error);
    res.status(500).json({ error: "Setup failed." });
  } finally {
    client.release();
  }
});

app.post("/api/login", authLimiter, requireCsrf, async (req, res) => {
  try {
    const name = cleanName(req.body.name);
    const password = String(req.body.password || "");

    if (!name || !password) {
      return res.status(400).json({ error: "Enter your name and password." });
    }

    const result = await pool.query(
      "SELECT id, name, password_hash FROM users WHERE name = $1",
      [name]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: "Wrong name or password." });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Wrong name or password." });
    }

    req.session.user = {
      id: user.id,
      name: user.name
    };
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    res.json({
      message: "Login successful.",
      csrfToken: req.session.csrfToken
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/profile-setup", requireAuth, requireCsrf, authLimiter, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const profileQuote = cleanText(req.body.profileQuote, 180);

    if (!email) {
      return res.status(400).json({ error: "Email is required." });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    const takenResult = await pool.query(
      "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id <> $2",
      [email, req.session.user.id]
    );

    if (takenResult.rows.length) {
      return res.status(400).json({ error: "That email is already in use." });
    }

    await pool.query(
      "UPDATE users SET email = $1, profile_quote = $2 WHERE id = $3",
      [email, profileQuote || null, req.session.user.id]
    );

    req.session.csrfToken = crypto.randomBytes(32).toString("hex");

    res.json({
      message: "Profile completed.",
      csrfToken: req.session.csrfToken
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not save profile." });
  }
});

app.post("/api/poems", requireAuth, requireCsrf, writeLimiter, async (req, res) => {
  try {
    const title = cleanText(req.body.title, 120);
    const content = cleanText(req.body.content, 8000);

    if (!title || !content) {
      return res.status(400).json({ error: "Add both a title and poem." });
    }

    await pool.query(
      "INSERT INTO poems (title, content, author_id) VALUES ($1, $2, $3)",
      [title, content, req.session.user.id]
    );

    res.json({ message: "Poem saved." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not save poem." });
  }
});

app.delete("/api/poems/:id", requireAuth, requireCsrf, writeLimiter, async (req, res) => {
  try {
    const poemId = Number(req.params.id);
    if (!Number.isInteger(poemId)) {
      return res.status(400).json({ error: "Invalid poem id." });
    }

    const result = await pool.query(
      "SELECT poems.id, poems.author_id FROM poems WHERE poems.id = $1",
      [poemId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Poem not found." });
    }

    if (result.rows[0].author_id !== req.session.user.id) {
      return res.status(403).json({ error: "You can only delete your own poems." });
    }

    await pool.query("DELETE FROM poems WHERE id = $1", [poemId]);

    res.json({ message: "Poem deleted." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not delete poem." });
  }
});

initDB()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("Server running on port " + PORT);
    });
  })
  .catch((error) => {
    console.error("Database init failed:", error);
    process.exit(1);
  });
