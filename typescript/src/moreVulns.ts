import mysql from 'mysql';
import child_process from 'child_process';
import fs from 'fs';
import http from 'http';
import crypto from 'crypto';
import yaml from 'js-yaml';

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'rootpassword',
  database: 'vulndb'
});

// VULNERABILITY: Hardcoded secret
export const JWT_SECRET: string = 'hardcoded-jwt-secret-more';

export function findUser(name: string): void {
  // VULNERABILITY: SQL Injection
  const query: string = "SELECT * FROM users WHERE name = '" + name + "'";
  connection.query(query, (err: any, results: any) => console.log(results));
}

export function removeUser(id: string): void {
  // VULNERABILITY: SQL Injection
  const query: string = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err: any) => console.log(err));
}

export function runPing(host: string): void {
  // VULNERABILITY: Command Injection
  child_process.exec('ping -c 1 ' + host, (err: any, stdout: string) => console.log(stdout));
}

export function readLog(filename: string): Buffer {
  // VULNERABILITY: Path Traversal
  return fs.readFileSync('/var/log/' + filename);
}

export function proxyRequest(url: string): void {
  // VULNERABILITY: SSRF
  http.get(url, (response: any) => {
    let data = '';
    response.on('data', (chunk: string) => data += chunk);
    response.on('end', () => console.log(data));
  });
}

export function greet(name: string): string {
  // VULNERABILITY: Reflected XSS
  return '<h1>Hello ' + name + '</h1>';
}

export function doRedirect(url: string): string {
  // VULNERABILITY: Open redirect
  return url;
}

export function parseYaml(data: string): any {
  // VULNERABILITY: Unsafe YAML load
  return yaml.load(data);
}

export function hashData(data: string): string {
  // VULNERABILITY: Weak hashing
  return crypto.createHash('md5').update(data).digest('hex');
}

export function runCode(code: string): any {
  // VULNERABILITY: Eval
  return eval(code);
}
