const express = require('express');
const mysql = require('mysql');
const child_process = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const serialize = require('node-serialize');
const yaml = require('js-yaml');

const router = express.Router();

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'db-password-123',
  database: 'vulndb'
});

// VULNERABILITY: SQL Injection
router.get('/api/users', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
router.post('/api/delete', (req, res) => {
  const id = req.body.id;
  const query = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err) => {
    if (err) return res.status(500).send(err.message);
    res.send('Deleted');
  });
});

// VULNERABILITY: Command Injection
router.get('/api/dns', (req, res) => {
  const host = req.query.host;
  const output = child_process.execSync('nslookup ' + host);
  res.send(output);
});

// VULNERABILITY: Path Traversal
router.get('/api/read', (req, res) => {
  const file = req.query.file;
  res.send(fs.readFileSync('/var/app/data/' + file));
});

// VULNERABILITY: SSRF
router.get('/api/proxy', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  }).on('error', err => res.status(500).send(err.message));
});

// VULNERABILITY: Reflected XSS
router.get('/api/greet', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// VULNERABILITY: Stored XSS
router.get('/api/comments', (req, res) => {
  connection.query("SELECT text FROM comments", (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.send(results.map(r => r.text).join('<br>'));
  });
});

// VULNERABILITY: Open redirect
router.get('/api/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// VULNERABILITY: Insecure deserialization
router.post('/api/load', (req, res) => {
  const data = Buffer.from(req.body.data, 'base64').toString();
  res.json(serialize.unserialize(data));
});

// VULNERABILITY: Unsafe YAML load
router.post('/api/yaml', (req, res) => {
  res.json(yaml.load(req.body.yaml));
});

// VULNERABILITY: Weak hashing
router.post('/api/hash', (req, res) => {
  res.send(crypto.createHash('md5').update(req.body.data).digest('hex'));
});

// VULNERABILITY: Hardcoded admin key
router.get('/api/admin', (req, res) => {
  if (req.headers['x-admin-key'] === 'hardcodedadminkey') {
    res.json({ secret: 'top secret' });
  } else {
    res.status(403).send('Forbidden');
  }
});

module.exports = router;
