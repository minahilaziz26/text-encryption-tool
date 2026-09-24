'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { processRequest, InputError } = require('./crypto');

const PUBLIC_DIR = path.join(__dirname, 'public');
const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'application/javascript; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml']
};

function send(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(payload));
}

function createAppServer() {
  return http.createServer((req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");

    // The application does not store text or passwords on disk or in a database.
    if (req.url === '/api/process') {
      if (req.method !== 'POST') return send(res, 405, { error: 'Use POST for this endpoint.' });
      if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) {
        return send(res, 415, { error: 'Content-Type must be application/json.' });
      }
      // Reject excessively large request bodies to avoid uncontrolled memory use.
      let body = '';
      let tooLarge = false;
      req.setEncoding('utf8');
      req.on('data', chunk => {
        if (tooLarge) return;
        body += chunk;
        if (Buffer.byteLength(body, 'utf8') > 75000) {
          tooLarge = true;
          body = ''; // Discard incoming data while allowing the 413 response to complete.
          send(res, 413, { error: 'Request exceeds the 75 KB limit.' });
        }
      });
      req.on('end', () => {
        if (tooLarge || res.writableEnded) return;
        let data;
        try {
          data = JSON.parse(body);
        } catch {
          return send(res, 400, { error: 'Invalid JSON request.' });
        }
        try {
          return send(res, 200, processRequest(data));
        } catch (err) {
          if (err instanceof InputError) return send(res, 400, { error: err.message });
          console.error('Unexpected processing error:', err.message);
          return send(res, 500, { error: 'Unexpected server error.' });
        }
      });
      req.on('error', () => {
        if (!res.writableEnded && !res.destroyed) send(res, 400, { error: 'Could not read request.' });
      });
      return;
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(res, 405, { error: 'Method not allowed.' });
    }
    const asset = FILES[req.url];
    if (!asset) return send(res, 404, { error: 'Page not found.' });
    const [filename, contentType] = asset;
    fs.readFile(path.join(PUBLIC_DIR, filename), (err, bytes) => {
      if (err) return send(res, 500, { error: 'Could not load the page.' });
      res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : bytes);
    });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const host = process.env.HOST || '127.0.0.1';
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    console.error('Invalid PORT value.');
    process.exit(1);
  }
  createAppServer().listen(port, host, () => {
    console.log(`Text Encryption Tool running at http://${host}:${port}`);
  });
}

module.exports = { createAppServer };
