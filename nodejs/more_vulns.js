const mysql = require('mysql');
const child_process = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const yaml = require('js-yaml');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'rootpassword',
  database: 'vulndb'
});

// VULNERABILITY: Hardcoded secret
const JWT_SECRET = 'hardcoded-jwt-secret-more';

function findUser(name) {
  // VULNERABILITY: SQL Injection
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  connection.query(query, (err, results) => console.log(results));
}

function removeUser(id) {
  // VULNERABILITY: SQL Injection
  const query = "DELETE FROM users WHERE id = " + id;
  connection.query(query, (err) => console.log(err));
}

function runPing(host) {
  // VULNERABILITY: Command Injection
  child_process.exec('ping -c 1 ' + host, (err, stdout) => console.log(stdout));
}

function readLog(filename) {
  // VULNERABILITY: Path Traversal
  return fs.readFileSync('/var/log/' + filename);
}

function proxyRequest(url) {
  // VULNERABILITY: SSRF
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => console.log(data));
  });
}

function greet(name) {
  // VULNERABILITY: Reflected XSS
  return '<h1>Hello ' + name + '</h1>';
}

function doRedirect(url) {
  // VULNERABILITY: Open redirect
  return url;
}

function parseYaml(data) {
  // VULNERABILITY: Unsafe YAML load
  return yaml.load(data);
}

function hashData(data) {
  // VULNERABILITY: Weak hashing
  return crypto.createHash('md5').update(data).digest('hex');
}

function runCode(code) {
  // VULNERABILITY: Eval
  return eval(code);
}

module.exports = { findUser, removeUser, runPing, readLog, proxyRequest, greet, doRedirect, parseYaml, hashData, runCode, JWT_SECRET };
