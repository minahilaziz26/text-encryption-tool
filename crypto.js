'use strict';

const crypto = require('node:crypto');

// Caesar and Vigenere are teaching ciphers, NOT suitable for real secrets.
const METHODS = new Set(['caesar', 'vigenere', 'aes']);
const MODES = new Set(['encrypt', 'decrypt', 'hash']);

class InputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InputError';
  }
}

function rotateAsciiLetter(letter, shift) {
  const code = letter.charCodeAt(0);
  const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
  if (base === null) return letter;
  return String.fromCharCode(base + (((code - base + shift) % 26) + 26) % 26);
}

function caesar(text, shift, decrypt = false) {
  const effectiveShift = decrypt ? -shift : shift;
  return Array.from(text, char => rotateAsciiLetter(char, effectiveShift)).join('');
}

function vigenere(text, keyword, decrypt = false) {
  const key = keyword.toUpperCase();
  let keyPosition = 0;
  return Array.from(text, char => {
    if (!/^[A-Za-z]$/.test(char)) return char;
    const shift = key.charCodeAt(keyPosition % key.length) - 65;
    keyPosition += 1;
    return rotateAsciiLetter(char, decrypt ? -shift : shift);
  }).join('');
}

function aesEncrypt(text, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  // scrypt converts a passphrase to an AES-256 key with a per-message salt.
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Versioned envelope: prefix.salt.iv.authTag.ciphertext (base64url fields).
  return ['AES256GCM', 'v1', salt, iv, tag, encrypted]
    .map((part) => Buffer.isBuffer(part) ? part.toString('base64url') : part)
    .join('.');
}

function decodeField(encoded, expectedSize, name) {
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new InputError('Invalid AES ciphertext format.');
  }
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.toString('base64url') !== encoded || (expectedSize !== null && bytes.length !== expectedSize)) {
    throw new InputError(`Invalid AES ${name} field.`);
  }
  return bytes;
}

function aesDecrypt(payload, passphrase) {
  const parts = payload.split('.');
  if (parts.length !== 6 || parts[0] !== 'AES256GCM' || parts[1] !== 'v1') {
    throw new InputError('Invalid AES ciphertext. Paste an AES-256-GCM result from this tool.');
  }
  const salt = decodeField(parts[2], 16, 'salt');
  const iv = decodeField(parts[3], 12, 'IV');
  const tag = decodeField(parts[4], 16, 'authentication tag');
  const encrypted = decodeField(parts[5], null, 'ciphertext');
  const key = crypto.scryptSync(passphrase, salt, 32);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    // Buffer.toString silently substitutes malformed UTF-8; reject it explicitly.
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } catch {
    throw new InputError('Decryption failed. Check the passphrase and ciphertext.');
  }
}

function processRequest(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new InputError('Send a valid JSON object.');
  }
  const { mode, method, text, key } = data;
  if (!MODES.has(mode)) throw new InputError('Select a valid operation.');
  if (typeof text !== 'string' || !text.trim()) throw new InputError('Please enter some text.');
  if (text.length > 30000) throw new InputError('Text is too long (maximum: 30,000 characters).');

  if (mode === 'hash') {
    if (text.length > 10000) throw new InputError('Text is too long (maximum: 10,000 characters).');
    return { result: crypto.createHash('sha256').update(text, 'utf8').digest('hex'), irreversible: true };
  }

  if (!METHODS.has(method)) throw new InputError('Please select an encryption algorithm.');
  if (typeof key !== 'string') throw new InputError('Please enter a valid key.');
  if (mode === 'encrypt' && text.length > 10000) {
    throw new InputError('Text is too long (maximum: 10,000 characters).');
  }

  if (method === 'caesar') {
    if (!/^(?:[1-9]|1\d|2[0-5])$/.test(key)) {
      throw new InputError('Caesar shift must be a whole number from 1 to 25.');
    }
    return { result: caesar(text, Number(key), mode === 'decrypt'), irreversible: false };
  }
  if (method === 'vigenere') {
    if (!/^[A-Za-z]{1,100}$/.test(key)) {
      throw new InputError('Vigenère keyword must contain 1–100 English letters only.');
    }
    return { result: vigenere(text, key, mode === 'decrypt'), irreversible: false };
  }
  if (key.length < 8 || key.length > 256) {
    throw new InputError('AES passphrase must be between 8 and 256 characters.');
  }
  return {
    result: mode === 'decrypt' ? aesDecrypt(text, key) : aesEncrypt(text, key),
    irreversible: false
  };
}

module.exports = { caesar, vigenere, aesEncrypt, aesDecrypt, processRequest, InputError };
