const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mysql = require('mysql');
const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const vm = require('vm');
const jwt = require('jsonwebtoken');
const yaml = require('js-yaml');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// VULNERABILITY: Disabled security headers
app.disable('x-powered-by');

// VULNERABILITY: Hardcoded secrets
const JWT_SECRET = 'hardcoded-jwt-secret-nodejs';
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'db-password-123';

// VULNERABILITY: Database connection with hardcoded credentials
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: DB_PASSWORD,
  database: 'vulndb'
});

// VULNERABILITY: SQL Injection
app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
app.get('/users/search', (req, res) => {
  const term = req.query.term;
  const query = "SELECT * FROM users WHERE name LIKE '%" + term + "%'";
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    if (results.length > 0) {
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
      res.cookie('token', token, { httpOnly: false, secure: false });
      res.send('Logged in');
    } else {
      res.send('Invalid');
    }
  });
});

// VULNERABILITY: SQL Injection
app.get('/users/order', (req, res) => {
  const column = req.query.column;
  const query = "SELECT * FROM users ORDER BY " + column;
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: Command Injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  child_process.exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// VULNERABILITY: Command Injection
app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  const output = child_process.execSync(cmd);
  res.send(output);
});

// VULNERABILITY: Path Traversal
app.get('/read', (req, res) => {
  const filename = req.query.file;
  const data = fs.readFileSync('/var/app/data/' + filename);
  res.send(data);
});

// VULNERABILITY: Path Traversal
app.get('/download', (req, res) => {
  const filename = req.query.file;
  res.sendFile('/var/app/uploads/' + filename);
});

// VULNERABILITY: SSRF
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  }).on('error', err => res.status(500).send(err.message));
});

// VULNERABILITY: Reflected XSS
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

// VULNERABILITY: Reflected XSS
app.get('/welcome', (req, res) => {
  const name = req.query.name;
  res.send("<script>alert('Welcome " + name + "');</script>");
});

// VULNERABILITY: Stored XSS
app.post('/comment', (req, res) => {
  const text = req.body.text;
  const query = "INSERT INTO comments (text) VALUES ('" + text + "')";
  connection.query(query, (err) => {
    if (err) return res.status(500).send(err.message);
    res.send('Comment saved');
  });
});

// VULNERABILITY: Stored XSS
app.get('/comments', (req, res) => {
  connection.query("SELECT text FROM comments", (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.send(results.map(r => r.text).join('<br>'));
  });
});

// VULNERABILITY: Open redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// VULNERABILITY: Insecure deserialization (node-serialize)
const serialize = require('node-serialize');
app.post('/deserialize', (req, res) => {
  const data = Buffer.from(req.body.data, 'base64').toString();
  const obj = serialize.unserialize(data);
  res.json(obj);
});

// VULNERABILITY: Unsafe eval
app.post('/eval', (req, res) => {
  const code = req.body.code;
  const result = eval(code);
  res.send(String(result));
});

// VULNERABILITY: Unsafe Function constructor
app.post('/exec', (req, res) => {
  const code = req.body.code;
  const fn = new Function(code);
  res.send(String(fn()));
});

// VULNERABILITY: Unsafe YAML load
app.post('/yaml', (req, res) => {
  const obj = yaml.load(req.body.yaml);
  res.json(obj);
});

// VULNERABILITY: Weak hashing (MD5)
const crypto = require('crypto');
app.post('/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.data).digest('hex');
  res.send(hash);
});

// VULNERABILITY: Weak hashing (SHA1)
app.post('/hash/sha1', (req, res) => {
  const hash = crypto.createHash('sha1').update(req.body.data).digest('hex');
  res.send(hash);
});

// VULNERABILITY: Insecure random
app.get('/token', (req, res) => {
  res.send(String(Math.random()));
});

// VULNERABILITY: Hardcoded admin token
app.get('/admin', (req, res) => {
  if (req.headers['x-admin-token'] === 'hardcodedadmintoken') {
    res.send('Admin panel');
  } else {
    res.status(403).send('Forbidden');
  }
});

// VULNERABILITY: Missing authorization
app.get('/admin/users', (req, res) => {
  connection.query("SELECT * FROM users", (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: Insecure direct object reference
app.get('/account/:id', (req, res) => {
  const id = req.params.id;
  const query = "SELECT * FROM accounts WHERE id = " + id;
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: Verbose error / information disclosure
app.get('/error', (req, res) => {
  throw new Error('Stack trace: ' + JSON.stringify(process.env));
});

// VULNERABILITY: Unrestricted file upload
app.post('/upload', (req, res) => {
  const file = req.files.file;
  file.mv('/var/app/uploads/' + file.name);
  res.send('Uploaded');
});

// VULNERABILITY: CORS misconfiguration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// VULNERABILITY: No CSRF protection, state-changing GET
app.get('/delete', (req, res) => {
  const id = req.query.id;
  const query = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err) => {
    if (err) return res.status(500).send(err.message);
    res.send('Deleted');
  });
});

// VULNERABILITY: Trust boundary / mass assignment
app.post('/register', (req, res) => {
  const { username, password, admin } = req.body;
  const query = "INSERT INTO users (username, password, admin) VALUES ('" + username + "', '" + password + "', '" + admin + "')";
  connection.query(query, (err) => {
    if (err) return res.status(500).send(err.message);
    res.send('Registered');
  });
});

app.listen(3000, () => {
  console.log('Vulnerable Node.js app listening on port 3000');
});
