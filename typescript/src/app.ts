import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import mysql from 'mysql';
import child_process from 'child_process';
import fs from 'fs';
import http from 'http';
import jwt from 'jsonwebtoken';
import yaml from 'js-yaml';
import crypto from 'crypto';

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// VULNERABILITY: Hardcoded secret
const JWT_SECRET: string = 'hardcoded-jwt-secret-typescript';
const API_KEY: string = 'sk-1234567890abcdef';

// VULNERABILITY: Database credentials in source
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'rootpassword',
  database: 'vulndb'
});

// VULNERABILITY: SQL Injection
app.get('/user', (req: Request, res: Response) => {
  const username: string = req.query.username as string;
  const query: string = "SELECT * FROM users WHERE username = '" + username + "'";
  connection.query(query, (err: any, results: any) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
app.get('/users/search', (req: Request, res: Response) => {
  const term: string = req.query.term as string;
  const query: string = "SELECT * FROM users WHERE name LIKE '%" + term + "%'";
  connection.query(query, (err: any, results: any) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
app.post('/login', (req: Request, res: Response) => {
  const username: string = req.body.username;
  const password: string = req.body.password;
  const query: string = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  connection.query(query, (err: any, results: any) => {
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

// VULNERABILITY: Command Injection
app.get('/ping', (req: Request, res: Response) => {
  const host: string = req.query.host as string;
  child_process.exec('ping -c 1 ' + host, (err: any, stdout: string) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// VULNERABILITY: Command Injection
app.get('/run', (req: Request, res: Response) => {
  const cmd: string = req.query.cmd as string;
  const output = child_process.execSync(cmd);
  res.send(output);
});

// VULNERABILITY: Path Traversal
app.get('/read', (req: Request, res: Response) => {
  const filename: string = req.query.file as string;
  const data = fs.readFileSync('/var/app/data/' + filename);
  res.send(data);
});

// VULNERABILITY: SSRF
app.get('/fetch', (req: Request, res: Response) => {
  const url: string = req.query.url as string;
  http.get(url, (response: any) => {
    let data = '';
    response.on('data', (chunk: string) => data += chunk);
    response.on('end', () => res.send(data));
  }).on('error', (err: any) => res.status(500).send(err.message));
});

// VULNERABILITY: Reflected XSS
app.get('/greet', (req: Request, res: Response) => {
  const name: string = req.query.name as string;
  res.send('<h1>Hello ' + name + '</h1>');
});

// VULNERABILITY: Reflected XSS
app.get('/welcome', (req: Request, res: Response) => {
  const name: string = req.query.name as string;
  res.send("<script>alert('Welcome " + name + "');</script>");
});

// VULNERABILITY: Stored XSS
app.post('/comment', (req: Request, res: Response) => {
  const text: string = req.body.text;
  const query: string = "INSERT INTO comments (text) VALUES ('" + text + "')";
  connection.query(query, (err: any) => {
    if (err) return res.status(500).send(err.message);
    res.send('Comment saved');
  });
});

// VULNERABILITY: Stored XSS
app.get('/comments', (req: Request, res: Response) => {
  connection.query("SELECT text FROM comments", (err: any, results: any) => {
    if (err) return res.status(500).send(err.message);
    res.send(results.map((r: any) => r.text).join('<br>'));
  });
});

// VULNERABILITY: Open redirect
app.get('/redirect', (req: Request, res: Response) => {
  res.redirect(req.query.url as string);
});

// VULNERABILITY: Unsafe eval
app.post('/eval', (req: Request, res: Response) => {
  const code: string = req.body.code;
  const result = eval(code);
  res.send(String(result));
});

// VULNERABILITY: Unsafe Function constructor
app.post('/exec', (req: Request, res: Response) => {
  const code: string = req.body.code;
  const fn = new Function(code);
  res.send(String(fn()));
});

// VULNERABILITY: Unsafe YAML load
app.post('/yaml', (req: Request, res: Response) => {
  const obj = yaml.load(req.body.yaml);
  res.json(obj);
});

// VULNERABILITY: Weak hashing (MD5)
app.post('/hash', (req: Request, res: Response) => {
  const hash = crypto.createHash('md5').update(req.body.data).digest('hex');
  res.send(hash);
});

// VULNERABILITY: Weak hashing (SHA1)
app.post('/hash/sha1', (req: Request, res: Response) => {
  const hash = crypto.createHash('sha1').update(req.body.data).digest('hex');
  res.send(hash);
});

// VULNERABILITY: Insecure random
app.get('/token', (req: Request, res: Response) => {
  res.send(String(Math.random()));
});

// VULNERABILITY: Hardcoded admin token
app.get('/admin', (req: Request, res: Response) => {
  if (req.headers['x-admin-token'] === 'hardcodedadmintoken') {
    res.send('Admin panel');
  } else {
    res.status(403).send('Forbidden');
  }
});

// VULNERABILITY: Missing authorization
app.get('/admin/users', (req: Request, res: Response) => {
  connection.query("SELECT * FROM users", (err: any, results: any) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: Insecure direct object reference
app.get('/account/:id', (req: Request, res: Response) => {
  const id: string = req.params.id;
  const query: string = "SELECT * FROM accounts WHERE id = " + id;
  connection.query(query, (err: any, results: any) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: CORS misconfiguration
app.use((req: Request, res: Response, next: any) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// VULNERABILITY: No CSRF protection
app.get('/delete', (req: Request, res: Response) => {
  const id: string = req.query.id as string;
  const query: string = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err: any) => {
    if (err) return res.status(500).send(err.message);
    res.send('Deleted');
  });
});

app.listen(4000, () => {
  console.log('Vulnerable TypeScript app listening on port 4000');
});
