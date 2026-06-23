const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const router = express.Router();

// VULNERABILITY: Hardcoded secret
const JWT_SECRET = 'hardcoded-jwt-secret-auth';
const ADMIN_PASSWORD = 'admin123';

// VULNERABILITY: No rate limiting, weak auth
router.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: false, secure: false, sameSite: 'none' });
    res.send('Logged in as admin');
  } else {
    res.send('Invalid');
  }
});

// VULNERABILITY: Weak password hashing (MD5)
router.post('/auth/register', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.send(hash);
});

// VULNERABILITY: JWT secret verification but hardcoded
router.get('/auth/verify', (req, res) => {
  const token = req.cookies.token;
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send('Invalid');
    res.json(decoded);
  });
});

// VULNERABILITY: Authentication bypass
router.get('/auth/bypass', (req, res) => {
  if (req.query.bypass === 'true') {
    return res.send('Authenticated');
  }
  res.send('Not authenticated');
});

module.exports = router;
