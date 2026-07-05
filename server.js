const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { Server } = require('socket.io');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

const publicDir = path.join(__dirname, 'public');
const uploadDir = path.join(publicDir, 'uploads');
const dataDir = path.join(__dirname, 'data');
const savePath = path.join(dataDir, 'maps.json');
fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });

function makeFog(rows, cols, value = 1) {
  return Array.from({ length: rows }, () => Array(cols).fill(value));
}

function makeBlankMap() {
  return {
    id: 'default',
    name: 'Untitled map',
    mapUrl: null,
    gridSize: 50,
    cols: 20,
    rows: 12,
    fog: makeFog(12, 20, 1),
    updatedAt: null,
    groups: []
  };
}

function validFog(rows, cols, fog) {
  return Array.isArray(fog) && fog.length === rows && fog.every(row => Array.isArray(row) && row.length === cols);
}

function cleanMap(map) {
  const cleaned = { ...makeBlankMap(), ...map };
  cleaned.gridSize = Math.max(10, Math.min(250, Number(cleaned.gridSize) || 50));
  cleaned.cols = Math.max(1, Math.min(200, Number(cleaned.cols) || 20));
  cleaned.rows = Math.max(1, Math.min(200, Number(cleaned.rows) || 12));
  if (!validFog(cleaned.rows, cleaned.cols, cleaned.fog)) cleaned.fog = makeFog(cleaned.rows, cleaned.cols, 1);
  cleaned.groups = Array.isArray(cleaned.groups) ? cleaned.groups.map(g => ({
    id: String(g.id || ('group-' + Date.now())),
    name: String(g.name || 'Unnamed group'),
    cells: Array.isArray(g.cells) ? g.cells.filter(cell => cell && Number.isInteger(cell.row) && Number.isInteger(cell.col)) : []
  })) : [];
  return cleaned;
}

function loadStore() {
  try {
    if (fs.existsSync(savePath)) {
      const store = JSON.parse(fs.readFileSync(savePath, 'utf8'));
      const maps = Array.isArray(store.maps) && store.maps.length ? store.maps.map(cleanMap) : [makeBlankMap()];
      const currentMapId = maps.some(m => m.id === store.currentMapId) ? store.currentMapId : maps[0].id;
      return { currentMapId, maps };
    }
  } catch (err) {
    console.error('Could not load maps:', err.message);
  }
  const blank = makeBlankMap();
  return { currentMapId: blank.id, maps: [blank] };
}

let store = loadStore();

function currentMap() {
  return store.maps.find(m => m.id === store.currentMapId) || store.maps[0];
}

let saveTimer = null;
function writeStore() { fs.writeFileSync(savePath, JSON.stringify(store, null, 2)); }
function saveStore(immediate = false) {
  currentMap().updatedAt = new Date().toISOString();
  if (immediate) { clearTimeout(saveTimer); saveTimer = null; writeStore(); return; }
  if (!saveTimer) saveTimer = setTimeout(() => { saveTimer = null; writeStore(); }, 1000);
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { if (saveTimer) writeStore(); process.exit(0); });

function publicState() {
  return { ...currentMap(), maps: store.maps.map(({ id, name, updatedAt, mapUrl }) => ({ id, name, updatedAt, mapUrl })), currentMapId: store.currentMapId };
}

function broadcastState() { io.emit('state', publicState()); }

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-z0-9._-]/gi, '_').toLowerCase();
    cb(null, `${Date.now()}-${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('image/'))
});

app.use(express.json());

// ---- DM auth ----
const configPath = path.join(dataDir, 'config.json');
let config = fs.existsSync(configPath) ? JSON.parse(fs.readFileSync(configPath, 'utf8')) : {};
function saveConfig() { fs.writeFileSync(configPath, JSON.stringify(config, null, 2)); }
function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 32).toString('hex'); }
function isDM(req) {
  return !!config.token && (req.headers.cookie || '').includes('dmtoken=' + config.token);
}
function setDMCookie(res) {
  res.setHeader('Set-Cookie', `dmtoken=${config.token}; HttpOnly; Path=/; Max-Age=31536000; SameSite=Lax`);
}

app.get('/auth/status', (req, res) => res.json({ setup: !!config.hash, dm: isDM(req) }));

app.post('/auth/setup', (req, res) => {
  if (config.hash) return res.status(400).json({ error: 'Password already set.' });
  const pw = String(req.body.password || '');
  if (pw.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  config.salt = crypto.randomBytes(16).toString('hex');
  config.hash = hashPw(pw, config.salt);
  config.token = crypto.randomBytes(24).toString('hex');
  saveConfig();
  setDMCookie(res);
  res.json({ ok: true });
});

app.post('/auth/login', (req, res) => {
  if (!config.hash) return res.status(400).json({ error: 'No password set yet.' });
  const attempt = hashPw(req.body.password || '', config.salt);
  if (crypto.timingSafeEqual(Buffer.from(attempt), Buffer.from(config.hash))) {
    setDMCookie(res);
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Wrong password.' });
});

// dm.html requires auth
app.get('/dm.html', (req, res, next) => (isDM(req) ? next() : res.redirect('/')));

// all mutating routes below require auth
app.use((req, res, next) => {
  if (req.method === 'POST' && !req.path.startsWith('/auth')) {
    if (!isDM(req)) return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

app.use(express.static(publicDir));

app.post('/upload', upload.single('map'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const nameFromBody = (req.body.name || '').trim();
  const name = nameFromBody || req.file.originalname.replace(/\.[^.]+$/, '');
  const map = {
    ...makeBlankMap(),
    id: 'map-' + Date.now(),
    name,
    mapUrl: `/uploads/${req.file.filename}`,
    updatedAt: new Date().toISOString()
  };
  store.maps.push(map);
  store.currentMapId = map.id;
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/select-map', (req, res) => {
  const id = req.body.id;
  if (!store.maps.some(m => m.id === id)) return res.status(404).json({ error: 'Map not found.' });
  store.currentMapId = id;
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/rename-map', (req, res) => {
  const map = currentMap();
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Name required.' });
  map.name = name;
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/delete-map', (req, res) => {
  if (store.maps.length <= 1) return res.status(400).json({ error: 'Cannot delete the only map.' });
  const id = req.body.id || store.currentMapId;
  const index = store.maps.findIndex(m => m.id === id);
  if (index === -1) return res.status(404).json({ error: 'Map not found.' });
  store.maps.splice(index, 1);
  if (store.currentMapId === id) store.currentMapId = store.maps[0].id;
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/settings', (req, res) => {
  const map = currentMap();
  map.gridSize = Math.max(10, Math.min(250, Number(req.body.gridSize) || map.gridSize));
  map.cols = Math.max(1, Math.min(200, Number(req.body.cols) || map.cols));
  map.rows = Math.max(1, Math.min(200, Number(req.body.rows) || map.rows));
  map.fog = makeFog(map.rows, map.cols, 1);
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/save', (req, res) => {
  saveStore(true);
  res.json({ ok: true, state: publicState() });
});

app.post('/groups', (req, res) => {
  const map = currentMap();
  const name = (req.body.name || 'Fog group').trim();
  const cells = Array.isArray(req.body.cells) ? req.body.cells : [];
  const cleanCells = [];
  const seen = new Set();
  for (const cell of cells) {
    const row = Number(cell.row);
    const col = Number(cell.col);
    if (!Number.isInteger(row) || !Number.isInteger(col)) continue;
    if (row < 0 || col < 0 || row >= map.rows || col >= map.cols) continue;
    const key = row + ',' + col;
    if (seen.has(key)) continue;
    seen.add(key);
    cleanCells.push({ row, col });
  }
  if (!cleanCells.length) return res.status(400).json({ error: 'No cells selected.' });
  map.groups.push({ id: 'group-' + Date.now(), name, cells: cleanCells });
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/delete-group', (req, res) => {
  const map = currentMap();
  const id = req.body.id;
  map.groups = map.groups.filter(g => g.id !== id);
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

app.post('/paint-group', (req, res) => {
  const map = currentMap();
  const group = map.groups.find(g => g.id === req.body.id);
  if (!group) return res.status(404).json({ error: 'Group not found.' });
  const v = req.body.value ? 1 : 0;
  for (const { row, col } of group.cells) {
    if (row >= 0 && col >= 0 && row < map.rows && col < map.cols) map.fog[row][col] = v;
  }
  saveStore();
  broadcastState();
  res.json({ ok: true, state: publicState() });
});

io.on('connection', (socket) => {
  socket.emit('state', publicState());
  const dm = isDM(socket.request);

  socket.on('paintTile', ({ row, col, value }) => {
    if (!dm) return;
    const map = currentMap();
    if (row < 0 || col < 0 || row >= map.rows || col >= map.cols) return;
    const v = value ? 1 : 0;
    if (map.fog[row][col] === v) return;
    map.fog[row][col] = v;
    saveStore();
    io.emit('tile', { row, col, value: v, updatedAt: map.updatedAt });
  });

  socket.on('revealAll', () => {
    if (!dm) return;
    const map = currentMap();
    map.fog = makeFog(map.rows, map.cols, 0);
    saveStore();
    broadcastState();
  });

  socket.on('hideAll', () => {
    if (!dm) return;
    const map = currentMap();
    map.fog = makeFog(map.rows, map.cols, 1);
    saveStore();
    broadcastState();
  });
});

server.listen(PORT, () => console.log(`DND Fog running at http://localhost:${PORT}`));
