import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

dotenv.config();

const {
  KVSERVER_PORT = '8793',
  CORS_ORIGIN = '*',
  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  KV_DATA_DIR = 'app/kvdata',
  KV_TIER = 'free'
} = process.env;

if (!APPWRITE_ENDPOINT || !APPWRITE_PROJECT_ID) {
  throw new Error('Missing env var: APPWRITE_ENDPOINT / APPWRITE_PROJECT_ID');
}

const app = express();

const corsAllowedOrigins = CORS_ORIGIN === '*' ? '*' : CORS_ORIGIN.split(',').map((s) => s.trim()).filter(Boolean);
const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (corsAllowedOrigins === '*') return cb(null, true);
    return cb(null, corsAllowedOrigins.includes(origin));
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204,
  maxAge: 86400
};

app.options('*', cors(corsOptions));
app.use(cors(corsOptions));
app.use(express.json({ limit: '2mb' }));

app.use(rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false
}));

function normalizeBaseUrl(url) {
  return String(url || '').trim().replace(/\/+$/, '');
}

function toSafeSegment(value) {
  return String(value || '').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
}

function keyToFilename(key) {
  const hash = crypto.createHash('sha256').update(String(key)).digest('hex');
  return `${hash}.json`;
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function readJson(filePath, fallback = null) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    if (e && (e.code === 'ENOENT' || e.code === 'ENOTDIR')) return fallback;
    throw e;
  }
}

async function writeJsonAtomic(filePath, data) {
  const tmp = `${filePath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(data), 'utf8');
  await fs.rename(tmp, filePath);
}

async function authenticateAppwrite(req, res, next) {
  try {
    const authHeader = String(req.headers.authorization || '');
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'Missing Bearer token' });

    const r = await fetch(`${normalizeBaseUrl(APPWRITE_ENDPOINT)}/account`, {
      method: 'GET',
      headers: {
        'X-Appwrite-Project': APPWRITE_PROJECT_ID,
        'X-Appwrite-JWT': token
      }
    });

    if (!r.ok) {
      const text = await r.text().catch(() => '');
      return res.status(401).json({ error: 'Invalid token', details: text });
    }

    const user = await r.json();
    req.user = { id: user.$id, email: user.email };
    return next();
  } catch (err) {
    return res.status(500).json({ error: 'Auth error', details: String(err?.message || err) });
  }
}

function namespacesIndexPath() {
  return path.join(KV_DATA_DIR, 'namespaces.json');
}

async function loadNamespacesIndex() {
  await ensureDir(KV_DATA_DIR);
  return (await readJson(namespacesIndexPath(), { entries: [] })) || { entries: [] };
}

async function saveNamespacesIndex(index) {
  await ensureDir(KV_DATA_DIR);
  await writeJsonAtomic(namespacesIndexPath(), index);
}

function getOrCreateNamespaceId({ projectId, userId }) {
  return `ns_${toSafeSegment(projectId)}_${toSafeSegment(userId)}`;
}

function namespaceDir(namespaceId) {
  return path.join(KV_DATA_DIR, 'namespaces', toSafeSegment(namespaceId));
}

function kvDir(namespaceId) {
  return path.join(namespaceDir(namespaceId), 'kv');
}

function kvMetaPath(namespaceId) {
  return path.join(namespaceDir(namespaceId), 'meta.json');
}

async function ensureNamespaceOnDisk(namespaceId, meta) {
  await ensureDir(kvDir(namespaceId));
  const existing = await readJson(kvMetaPath(namespaceId), null);
  if (!existing) {
    await writeJsonAtomic(kvMetaPath(namespaceId), meta);
  }
}

function clampTtlSeconds(ttlSeconds) {
  const ttl = Number(ttlSeconds);
  if (!Number.isFinite(ttl)) return null;
  if (ttl < 60) return 60;
  if (ttl > 3600) return 3600;
  return Math.floor(ttl);
}

async function resolveNamespaceForUserProject({ userId, projectId }) {
  const index = await loadNamespacesIndex();
  const entry = index.entries.find((e) => e.userId === userId && e.projectId === projectId);
  if (!entry) return { namespaceId: null, index };
  return { namespaceId: entry.namespaceId, index };
}

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'kvserver', time: new Date().toISOString() });
});

app.post('/v1/namespace', authenticateAppwrite, async (req, res) => {
  const userId = req.user.id;
  const projectId = String(req.body?.projectId || '').trim();
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });

  const { namespaceId: existingNs, index } = await resolveNamespaceForUserProject({ userId, projectId });
  if (existingNs) {
    return res.json({ ok: true, namespaceId: existingNs, alreadyExisted: true });
  }

  if (String(KV_TIER).toLowerCase() === 'free') {
    const perProjectCount = index.entries.filter((e) => e.userId === userId && e.projectId === projectId).length;
    if (perProjectCount >= 1) {
      return res.status(403).json({ error: 'Free tier limit: one namespace per user per project' });
    }
  }

  const namespaceId = getOrCreateNamespaceId({ projectId, userId });
  const createdAt = new Date().toISOString();

  index.entries.push({ userId, projectId, namespaceId, createdAt, tier: KV_TIER });
  await saveNamespacesIndex(index);

  await ensureNamespaceOnDisk(namespaceId, { namespaceId, userId, projectId, createdAt, tier: KV_TIER });

  return res.json({ ok: true, namespaceId, alreadyExisted: false });
});

app.get('/v1/namespace', authenticateAppwrite, async (req, res) => {
  const userId = req.user.id;
  const projectId = String(req.query?.projectId || '').trim();
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });

  const { namespaceId } = await resolveNamespaceForUserProject({ userId, projectId });
  return res.json({ ok: true, namespaceId: namespaceId || null });
});

app.put('/v1/kv/:namespaceId/:key(*)', authenticateAppwrite, async (req, res) => {
  const namespaceId = String(req.params.namespaceId || '').trim();
  const key = String(req.params.key || '').trim();
  const ttlSeconds = clampTtlSeconds(req.body?.ttlSeconds);
  const value = req.body?.value;

  if (!namespaceId) return res.status(400).json({ error: 'Missing namespaceId' });
  if (!key) return res.status(400).json({ error: 'Missing key' });
  if (ttlSeconds == null) return res.status(400).json({ error: 'Missing/invalid ttlSeconds' });

  const meta = await readJson(kvMetaPath(namespaceId), null);
  if (!meta || meta.userId !== req.user.id) {
    return res.status(404).json({ error: 'Namespace not found' });
  }

  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;

  const record = {
    key,
    value,
    ttlSeconds,
    createdAt: new Date(now).toISOString(),
    expiresAt,
    expiresAtIso: new Date(expiresAt).toISOString()
  };

  const filePath = path.join(kvDir(namespaceId), keyToFilename(key));
  await writeJsonAtomic(filePath, record);

  return res.json({ ok: true, key, ttlSeconds, expiresAt });
});

app.get('/v1/kv/:namespaceId/:key(*)', authenticateAppwrite, async (req, res) => {
  const namespaceId = String(req.params.namespaceId || '').trim();
  const key = String(req.params.key || '').trim();

  if (!namespaceId) return res.status(400).json({ error: 'Missing namespaceId' });
  if (!key) return res.status(400).json({ error: 'Missing key' });

  const meta = await readJson(kvMetaPath(namespaceId), null);
  if (!meta || meta.userId !== req.user.id) {
    return res.status(404).json({ error: 'Namespace not found' });
  }

  const filePath = path.join(kvDir(namespaceId), keyToFilename(key));
  const record = await readJson(filePath, null);
  if (!record) return res.status(404).json({ error: 'Not found' });

  if (record.expiresAt && Date.now() > Number(record.expiresAt)) {
    await fs.unlink(filePath).catch(() => {});
    return res.status(404).json({ error: 'Not found' });
  }

  return res.json({ ok: true, key, value: record.value, expiresAt: record.expiresAt, ttlSeconds: record.ttlSeconds });
});

app.delete('/v1/kv/:namespaceId/:key(*)', authenticateAppwrite, async (req, res) => {
  const namespaceId = String(req.params.namespaceId || '').trim();
  const key = String(req.params.key || '').trim();

  if (!namespaceId) return res.status(400).json({ error: 'Missing namespaceId' });
  if (!key) return res.status(400).json({ error: 'Missing key' });

  const meta = await readJson(kvMetaPath(namespaceId), null);
  if (!meta || meta.userId !== req.user.id) {
    return res.status(404).json({ error: 'Namespace not found' });
  }

  const filePath = path.join(kvDir(namespaceId), keyToFilename(key));
  await fs.unlink(filePath).catch((e) => {
    if (e && e.code === 'ENOENT') return;
    throw e;
  });

  return res.json({ ok: true, key });
});

app.listen(Number(KVSERVER_PORT), () => {
  console.log(`kvserver listening on :${KVSERVER_PORT}`);
});
