const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();

// ============================================================
// BUG #1: CORS misconfiguration — credentials: true requires
//         a specific origin, not wildcard '*'
// ============================================================
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// BUG #2: Hardcoded weak secret + stored in plain source code
const JWT_SECRET = 'secret123';

// In-memory user store (simulated DB)
const users = [];

// ============================================================
// BUG #3: Token expiration set to '1s' — tokens expire almost
//         immediately, causing constant 401 errors
// ============================================================
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '1s' }  // should be '1h' or similar
  );
}

// ============================================================
// Auth middleware
// BUG #4: Reads token from 'x-token' header but frontend sends
//         'Authorization: Bearer <token>'  — header name mismatch
// ============================================================
function authMiddleware(req, res, next) {
  const token = req.headers['x-token'];  // should be req.headers['authorization']

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // BUG #5: jwt.verify should use JWT_SECRET but uses a
    //         different string — verification always fails
    const decoded = jwt.verify(token, 'different-secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---- Routes ----

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const existing = users.find(u => u.email === email);
  if (existing) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, email, name, password: hashedPassword };
  users.push(user);

  const token = generateToken(user);

  // BUG #6: Response includes plain-text password hash — security leak
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, password: user.password }
  });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // BUG #7: Compares plain password with plain password instead of
  //         using bcrypt.compare — always fails after hashing at register
  const isValid = (password === user.password);  // should be: await bcrypt.compare(password, user.password)

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = generateToken(user);
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

// GET /api/auth/me  — fetch current user profile
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user: { id: user.id, email: user.email, name: user.name } });
});

// GET /api/protected/dashboard
app.get('/api/protected/dashboard', authMiddleware, (req, res) => {
  res.json({ message: `Welcome ${req.user.email}`, data: [1, 2, 3] });
});

// POST /api/auth/refresh
// BUG #8: Refresh endpoint accepts any token — does not verify the
//         old token's validity before issuing a fresh one
app.post('/api/auth/refresh', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }

  try {
    // Decodes WITHOUT verification — anyone can forge a payload
    const decoded = jwt.decode(token);
    const newToken = generateToken({ id: decoded.id, email: decoded.email });
    res.json({ token: newToken });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// POST /api/auth/logout
// BUG #9: Logout is a no-op — no token blacklist, no session
//         invalidation; the token remains usable until it expires
app.post('/api/auth/logout', (req, res) => {
  // Does nothing — token still valid
  res.json({ message: 'Logged out' });
});

const PORT = 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
