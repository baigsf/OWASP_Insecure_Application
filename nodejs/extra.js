const express = require('express');
const mysql = require('mysql');
const child_process = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const yaml = require('js-yaml');

const router = express.Router();

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'rootpassword',
  database: 'vulndb'
});

// VULNERABILITY: SQL Injection
router.get('/extra/users', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
router.post('/extra/delete', (req, res) => {
  const id = req.body.id;
  const query = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err) => {
    if (err) return res.status(500).send(err.message);
    res.send('Deleted');
  });
});

// VULNERABILITY: Command Injection
router.get('/extra/ping', (req, res) => {
  const host = req.query.host;
  child_process.exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// VULNERABILITY: Path Traversal
router.get('/extra/read', (req, res) => {
  const file = req.query.file;
  res.send(fs.readFileSync('/var/app/data/' + file));
});

// VULNERABILITY: SSRF
router.get('/extra/fetch', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  }).on('error', err => res.status(500).send(err.message));
});

// VULNERABILITY: Reflected XSS
router.get('/extra/greet', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// VULNERABILITY: Open redirect
router.get('/extra/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// VULNERABILITY: Unsafe YAML load
router.post('/extra/yaml', (req, res) => {
  res.json(yaml.load(req.body.yaml));
});

// VULNERABILITY: Weak hashing
router.post('/extra/hash', (req, res) => {
  res.send(crypto.createHash('md5').update(req.body.data).digest('hex'));
});

// VULNERABILITY: Eval
router.post('/extra/eval', (req, res) => {
  res.send(String(eval(req.body.code)));
});

// VULNERABILITY: Hardcoded admin key
router.get('/extra/admin', (req, res) => {
  if (req.headers['x-admin-key'] === 'hardcodedadminkey') {
    res.json({ secret: 'classified' });
  } else {
    res.status(403).send('Forbidden');
  }
});

module.exports = router;
