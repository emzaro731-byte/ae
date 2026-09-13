import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();
const port = Number(process.env.PORT ?? 8080);
const jwtSecret = process.env.JWT_SECRET ?? '';

if (!jwtSecret && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET is required in production');
}

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined })
  : null;

app.use(cors());
app.use(express.json({ limit: '2mb' }));

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../web');
app.use(express.static(webDir));

app.get('/health', async (_req, res) => {
  let database = 'not_configured';
  if (pool) {
    try {
      await pool.query('select 1');
      database = 'ok';
    } catch {
      database = 'error';
    }
  }
  res.json({ ok: database !== 'error', service: 'veylora-backend', database });
});

app.get('/api', (_req, res) => {
  res.json({
    service: 'veylora-backend',
    version: '1.0.0',
    endpoints: {
      health: 'GET /health',
      signup: 'POST /v1/auth/signup',
      login: 'POST /v1/auth/login'
    }
  });
});

function signToken(userId: string) {
  return jwt.sign({ sub: userId }, jwtSecret || 'development-only-secret', { expiresIn: '30d' });
}

function requireDb(res: express.Response): Pool | null {
  if (!pool) {
    res.status(503).json({ error: 'Database is not configured' });
    return null;
  }
  return pool;
}

app.post('/v1/auth/signup', async (req, res) => {
  const db = requireDb(res);
  if (!db) return;
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');
  if (!email || password.length < 8) {
    return res.status(400).json({ error: 'Valid email and password of at least 8 characters are required' });
  }
  try {
    const existing = await db.query('select id from users where email=$1', [email]);
    if (existing.rowCount) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 12);
    const result = await db.query('insert into users(email,password_hash) values($1,$2) returning id,email,created_at', [email, hash]);
    const user = result.rows[0];
    return res.status(201).json({ user, access_token: signToken(user.id) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Unable to create account' });
  }
});

app.post('/v1/auth/login', async (req, res) => {
  const db = requireDb(res);
  if (!db) return;
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const password = String(req.body?.password ?? '');
  try {
    const result = await db.query('select id,email,password_hash,created_at from users where email=$1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    return res.json({ user: { id: user.id, email: user.email, created_at: user.created_at }, access_token: signToken(user.id) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Unable to sign in' });
  }
});

app.get('*', (_req, res) => res.sendFile(path.join(webDir, 'index.html')));

app.listen(port, () => console.log(`Veylora backend listening on ${port}`));
