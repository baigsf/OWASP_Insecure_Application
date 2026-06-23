import { Router, Request, Response } from 'express';
import mysql from 'mysql';
import child_process from 'child_process';
import fs from 'fs';
import http from 'http';
import crypto from 'crypto';
import yaml from 'js-yaml';

const router = Router();

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'rootpassword',
  database: 'vulndb'
});

// VULNERABILITY: SQL Injection
router.get('/extra/users', (req: Request, res: Response) => {
  const name: string = req.query.name as string;
  const query: string = "SELECT * FROM users WHERE name = '" + name + "'";
  connection.query(query, (err: any, results: any) => {
    if (err) return res.status(500).send(err.message);
    res.json(results);
  });
});

// VULNERABILITY: SQL Injection
router.post('/extra/delete', (req: Request, res: Response) => {
  const id: string = req.body.id;
  const query: string = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err: any) => {
    if (err) return res.status(500).send(err.message);
    res.send('Deleted');
  });
});

// VULNERABILITY: Command Injection
router.get('/extra/ping', (req: Request, res: Response) => {
  const host: string = req.query.host as string;
  child_process.exec('ping -c 1 ' + host, (err: any, stdout: string) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// VULNERABILITY: Path Traversal
router.get('/extra/read', (req: Request, res: Response) => {
  const file: string = req.query.file as string;
  res.send(fs.readFileSync('/var/app/data/' + file));
});

// VULNERABILITY: SSRF
router.get('/extra/fetch', (req: Request, res: Response) => {
  const url: string = req.query.url as string;
  http.get(url, (response: any) => {
    let data = '';
    response.on('data', (chunk: string) => data += chunk);
    response.on('end', () => res.send(data));
  }).on('error', (err: any) => res.status(500).send(err.message));
});

// VULNERABILITY: Reflected XSS
router.get('/extra/greet', (req: Request, res: Response) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// VULNERABILITY: Open redirect
router.get('/extra/redirect', (req: Request, res: Response) => {
  res.redirect(req.query.url as string);
});

// VULNERABILITY: Unsafe YAML load
router.post('/extra/yaml', (req: Request, res: Response) => {
  res.json(yaml.load(req.body.yaml));
});

// VULNERABILITY: Weak hashing
router.post('/extra/hash', (req: Request, res: Response) => {
  res.send(crypto.createHash('md5').update(req.body.data).digest('hex'));
});

// VULNERABILITY: Eval
router.post('/extra/eval', (req: Request, res: Response) => {
  res.send(String(eval(req.body.code)));
});

// VULNERABILITY: Hardcoded admin key
router.get('/extra/admin', (req: Request, res: Response) => {
  if (req.headers['x-admin-key'] === 'hardcodedadminkey') {
    res.json({ secret: 'classified' });
  } else {
    res.status(403).send('Forbidden');
  }
});

export default router;
