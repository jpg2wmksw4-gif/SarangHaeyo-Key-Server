
const express = require("express");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet());
app.use(express.json({ limit: "20kb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60
});

app.use("/api", limiter);

function hashKey(key) {
  return crypto
    .createHash("sha256")
    .update(key.trim().toUpperCase())
    .digest("hex");
}

function adminAuth(req, res, next) {
  const token = req.headers.authorization || "";
  const expected = `Bearer ${process.env.ADMIN_TOKEN || ""}`;

  const a = Buffer.from(token);
  const b = Buffer.from(expected);

  if (
    !process.env.ADMIN_TOKEN ||
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized"
    });
  }

  next();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      key_prefix TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'blocked')),
      expires_at TIMESTAMPTZ,
      max_devices INTEGER NOT NULL DEFAULT 1
        CHECK (max_devices > 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_devices (
      id BIGSERIAL PRIMARY KEY,
      license_id BIGINT NOT NULL
        REFERENCES licenses(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (license_id, device_id)
    )
  `);
}

app.get("/", (req, res) => {
  res.json({
    name: "SarangHaeyo Key Server",
    status: "online"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch {
    res.status(503).json({
      status: "error",
      database: "disconnected"
    });
  }
});

// ACTIVATE / VALIDATE LICENSE
app.post("/api/activate", async (req, res) => {
  const { key, deviceId } = req.body || {};

  if (
    typeof key !== "string" ||
    key.length > 100 ||
    typeof deviceId !== "string" ||
    deviceId.length < 1 ||
    deviceId.length > 200
  ) {
    return res.status(400).json({
      success: false,
      message: "Invalid input"
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT * FROM licenses
       WHERE key_hash = $1 FOR UPDATE`,
      [hashKey(key)]
    );

    if (!result.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        success: false,
        message: "License not found"
      });
    }

    const license = result.rows[0];

    if (license.status !== "active") {
      await client.query("ROLLBACK");
      return res.status(403).json({
        success: false,
        message: "License blocked"
      });
    }

    if (
      license.expires_at &&
      new Date(license.expires_at) <= new Date()
    ) {
      await client.query("ROLLBACK");
      return res.status(403).json({
        success: false,
        message: "License expired"
      });
    }

    const existing = await client.query(
      `SELECT id FROM license_devices
       WHERE license_id = $1 AND device_id = $2`,
      [license.id, deviceId]
    );

    if (existing.rows.length) {
      await client.query(
        `UPDATE license_devices
         SET last_seen = NOW()
         WHERE license_id = $1 AND device_id = $2`,
        [license.id, deviceId]
      );
    } else {
      const count = await client.query(
        `SELECT COUNT(*)::int AS total
         FROM license_devices WHERE license_id = $1`,
        [license.id]
      );

      if (count.rows[0].total >= license.max_devices) {
        await client.query("ROLLBACK");
        return res.status(403).json({
          success: false,
          message: "Device limit reached"
        });
      }

      await client.query(
        `INSERT INTO license_devices
         (license_id, device_id)
         VALUES ($1, $2)`,
        [license.id, deviceId]
      );
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "License valid",
      expiresAt: license.expires_at,
      maxDevices: license.max_devices
    });

  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  } finally {
    client.release();
  }
});

// CREATE LICENSE (ADMIN)
app.post("/api/admin/keys", adminAuth, async (req, res) => {
  const { expiresInDays = null, maxDevices = 1 } = req.body || {};

  if (
    !Number.isInteger(maxDevices) ||
    maxDevices < 1 ||
    maxDevices > 1000 ||
    !(
      expiresInDays === null ||
      (Number.isInteger(expiresInDays) &&
       expiresInDays >= 1 &&
       expiresInDays <= 36500)
    )
  ) {
    return res.status(400).json({
      success: false,
      message: "Invalid expiration or device limit"
    });
  }

  try {
    const raw = crypto.randomBytes(16).toString("hex").toUpperCase();
    const key = "SHK-" + raw.match(/.{1,8}/g).join("-");

    const expiresAt = expiresInDays === null
      ? null
      : new Date(Date.now() + expiresInDays * 86400000);

    const result = await pool.query(
      `INSERT INTO licenses
       (key_hash, key_prefix, expires_at, max_devices)
       VALUES ($1, $2, $3, $4)
       RETURNING id, status, expires_at, max_devices`,
      [hashKey(key), key.slice(0, 12), expiresAt, maxDevices]
    );

    res.status(201).json({
      success: true,
      key,
      license: result.rows[0],
      message: "Save this key securely. It cannot be retrieved again."
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// LIST LICENSES (ADMIN)
app.get("/api/admin/keys", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        l.id,
        l.key_prefix,
        l.status,
        l.expires_at,
        l.max_devices,
        l.created_at,
        COUNT(d.id)::int AS used_devices
      FROM licenses l
      LEFT JOIN license_devices d ON d.license_id = l.id
      GROUP BY l.id
      ORDER BY l.created_at DESC
    `);

    res.json({
      success: true,
      licenses: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false });
  }
});

// BLOCK OR UNBLOCK LICENSE (ADMIN)
app.patch("/api/admin/keys/:id", adminAuth, async (req, res) => {
  const { status, maxDevices } = req.body || {};

  if (
    !/^\d+$/.test(req.params.id) ||
    !Number.isSafeInteger(Number(req.params.id)) ||
    Number(req.params.id) < 1
  ) {
    return res.status(400).json({ success: false, message: "Invalid ID" });
  }

  if (
    !["active", "blocked"].includes(status) &&
    !(Number.isInteger(maxDevices) && maxDevices >= 1 && maxDevices <= 1000)
  ) {
    return res.status(400).json({
      success: false,
      message: "Invalid update"
    });
  }

  try {
    const result = await pool.query(
      `UPDATE licenses
       SET status = COALESCE($1, status),
           max_devices = COALESCE($2, max_devices)
       WHERE id = $3
       RETURNING id, status, max_devices, expires_at`,
      [
        ["active", "blocked"].includes(status) ? status : null,
        Number.isInteger(maxDevices) ? maxDevices : null,
        req.params.id
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: "License not found"
      });
    }

    res.json({ success: true, license: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false });
  }
});

// DELETE LICENSE (ADMIN)
app.delete("/api/admin/keys/:id", adminAuth, async (req, res) => {
  if (
    !/^\d+$/.test(req.params.id) ||
    Number(req.params.id) < 1
  ) {
    return res.status(400).json({ success: false });
  }

  try {
    const result = await pool.query(
      "DELETE FROM licenses WHERE id = $1 RETURNING id",
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: "License not found"
      });
    }

    res.json({ success: true, message: "License deleted" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false });
  }
});

async function start() {
  if (!process.env.DATABASE_URL || !process.env.ADMIN_TOKEN) {
    throw new Error("DATABASE_URL and ADMIN_TOKEN are required");
  }

  await initDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SarangHaeyo server running on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("Startup failed:", error);
  process.exit(1);
});
