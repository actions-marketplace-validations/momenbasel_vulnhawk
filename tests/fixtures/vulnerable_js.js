/**
 * Intentionally vulnerable JavaScript/Express code for testing VulnHawk.
 */

const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
const JWT_SECRET = "hardcoded-jwt-secret-12345";
const ADMIN_PASSWORD = "admin123";

// --- SQL Injection ---

app.get('/users/search', (req, res) => {
  const query = req.query.q;
  const sql = `SELECT * FROM users WHERE name LIKE '%${query}%'`;
  db.query(sql, (err, results) => {
    res.json(results);
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  db.query(sql, (err, results) => {
    if (results.length > 0) {
      const token = jwt.sign({ userId: results[0].id }, JWT_SECRET);
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// --- IDOR / Missing Auth ---

app.get('/api/users/:id', (req, res) => {
  // No authentication or authorization check
  const userId = req.params.id;
  db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
    // Returns sensitive data including password hash
    res.json(results[0]);
  });
});

app.delete('/api/users/:id', (req, res) => {
  // No auth check - anyone can delete any user
  db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
    res.json({ deleted: true });
  });
});

// --- Command Injection ---

app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.post('/api/convert', (req, res) => {
  const { filename, format } = req.body;
  exec(`convert uploads/${filename} output.${format}`, (err, stdout) => {
    res.json({ result: stdout });
  });
});

// --- Path Traversal ---

app.get('/files/:name', (req, res) => {
  const filePath = `./uploads/${req.params.name}`;
  res.sendFile(filePath);
});

app.get('/api/download', (req, res) => {
  const file = req.query.file;
  const data = fs.readFileSync(`/data/${file}`);
  res.send(data);
});

// --- XSS ---

app.get('/search', (req, res) => {
  const query = req.query.q;
  // Reflected XSS - user input directly in HTML
  res.send(`<h1>Search results for: ${query}</h1>`);
});

// --- JWT Misconfiguration ---

app.post('/api/verify-token', (req, res) => {
  const token = req.headers.authorization;
  // algorithms not specified - vulnerable to none algorithm attack
  const decoded = jwt.verify(token, JWT_SECRET);
  res.json({ user: decoded });
});

// --- SSRF ---

app.post('/api/fetch', (req, res) => {
  const { url } = req.body;
  // No URL validation - can access internal services
  fetch(url)
    .then(r => r.text())
    .then(data => res.send(data));
});

// --- Insecure Cookie ---

app.post('/api/session', (req, res) => {
  res.cookie('session', req.body.token, {
    // Missing: secure, httpOnly, sameSite
    maxAge: 86400000,
  });
  res.json({ ok: true });
});
