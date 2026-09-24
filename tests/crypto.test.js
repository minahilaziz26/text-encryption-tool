'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { caesar, vigenere, aesEncrypt, aesDecrypt, processRequest, InputError } = require('../crypto');
const { createAppServer } = require('../server');

const PASSPHRASE = 'long test passphrase 2026';

test('Caesar example preserves case, punctuation and Unicode', () => {
  assert.equal(caesar('Hello, World! 🍀', 3), 'Khoor, Zruog! 🍀');
  assert.equal(caesar('Khoor, Zruog! 🍀', 3, true), 'Hello, World! 🍀');
  assert.equal(caesar('Zz', 1), 'Aa');
});

test('Vigenere standard example and reversible mixed-case text', () => {
  assert.equal(vigenere('ATTACKATDAWN', 'LEMON'), 'LXFOPVEFRNHR');
  assert.equal(vigenere('LXFOPVEFRNHR', 'LEMON', true), 'ATTACKATDAWN');
  const original = 'Attack at dawn! 🌎 123';
  assert.equal(vigenere(vigenere(original, 'Lemon'), 'Lemon', true), original);
});

test('AES round trip supports UTF-8 and random outputs', () => {
  const input = 'Top secret: پاکستان 🌾\nLine two.';
  const cipher1 = aesEncrypt(input, PASSPHRASE);
  const cipher2 = aesEncrypt(input, PASSPHRASE);
  assert.match(cipher1, /^AES256GCM\.v1\./);
  assert.notEqual(cipher1, cipher2, 'random salt and IV should change the ciphertext');
  assert.equal(aesDecrypt(cipher1, PASSPHRASE), input);
  assert.equal(aesDecrypt(cipher2, PASSPHRASE), input);
});

test('AES rejects wrong passphrase and changed authentication tag', () => {
  const cipher = aesEncrypt('Authenticated message', PASSPHRASE);
  assert.throws(() => aesDecrypt(cipher, 'incorrect password'), InputError);
  const parts = cipher.split('.');
  parts[4] = Buffer.alloc(16, 7).toString('base64url');
  assert.throws(() => aesDecrypt(parts.join('.'), PASSPHRASE), InputError);
  assert.throws(() => aesDecrypt('bad input', PASSPHRASE), InputError);
});

test('SHA-256 matches known vector and reports irreversible status', () => {
  const response = processRequest({ mode: 'hash', text: 'abc' });
  assert.equal(response.result, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(response.irreversible, true);
});

test('validation refuses empty text, missing method and invalid keys', () => {
  const base = { mode: 'encrypt', method: 'caesar', text: 'Hello', key: '3' };
  const bad = [
    { ...base, text: '  ' }, { ...base, method: '' },
    { ...base, key: '0' }, { ...base, key: '26' },
    { ...base, key: '3.2' }, { ...base, method: 'vigenere', key: 'KEY4' },
    { ...base, method: 'aes', key: 'short' },
    { ...base, mode: 'unknown' }, { ...base, text: 'x'.repeat(10001) },
    { mode: 'hash', text: 'x'.repeat(10001) },
    { ...base, key: null }
  ];
  for (const value of bad) assert.throws(() => processRequest(value), InputError);
});

test('API accepts valid input and returns errors for invalid requests', async () => {
  const server = createAppServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseURL = `http://127.0.0.1:${server.address().port}`;
  try {
    const page = await fetch(baseURL);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /CipherLab/);
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');

    const good = await fetch(`${baseURL}/api/process`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'encrypt', method: 'caesar', text: 'HELLO', key: '3' })
    });
    assert.equal(good.status, 200);
    assert.equal((await good.json()).result, 'KHOOR');

    const empty = await fetch(`${baseURL}/api/process`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'encrypt', method: '', text: '', key: '' })
    });
    assert.equal(empty.status, 400);
    assert.match((await empty.json()).error, /text/);

    const wrongMethod = await fetch(`${baseURL}/api/process`);
    assert.equal(wrongMethod.status, 405);

    const wrongContentType = await fetch(`${baseURL}/api/process`, { method: 'POST', body: 'x' });
    assert.equal(wrongContentType.status, 415);

    const oversized = await fetch(`${baseURL}/api/process`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'hash', text: 'x'.repeat(80000) })
    });
    assert.equal(oversized.status, 413);

    const aesPayload = { mode: 'encrypt', method: 'aes', text: 'Private message', key: PASSPHRASE };
    const aesResponse = await fetch(`${baseURL}/api/process`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(aesPayload)
    });
    assert.equal(aesResponse.status, 200);
    const encrypted = (await aesResponse.json()).result;
    const aesDecrypted = await fetch(`${baseURL}/api/process`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...aesPayload, mode: 'decrypt', text: encrypted })
    });
    assert.equal((await aesDecrypted.json()).result, 'Private message');

    const missing = await fetch(`${baseURL}/unknown`);
    assert.equal(missing.status, 404);

    const invalidJSON = await fetch(`${baseURL}/api/process`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{bad'
    });
    assert.equal(invalidJSON.status, 400);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
