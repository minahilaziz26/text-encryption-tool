'use strict';

const state = { mode: 'encrypt', lastResult: '' };
const $ = (id) => document.getElementById(id);
const form = $('crypto-form');
const source = $('plaintext');
const algorithm = $('algorithm');
const key = $('key');
const result = $('result');
const alertBox = $('alert');

function clearError() {
  alertBox.textContent = '';
  alertBox.hidden = true;
}

function showError(message) {
  alertBox.textContent = message;
  alertBox.hidden = false;
}

function updateCharacterCount() {
  $('character-count').textContent = `${source.value.length.toLocaleString()} / ${state.mode === 'decrypt' ? '30,000' : '10,000'}`;
}

function resetResult() {
  state.lastResult = '';
  result.value = '';
  $('copy-button').disabled = true;
  $('copy-label').textContent = 'Copy result';
  $('result-tag').textContent = 'AWAITING INPUT';
  $('output-details').textContent = 'The result appears after processing.';
  clearError();
}

function updateKeyField() {
  const method = algorithm.value;
  key.disabled = state.mode === 'hash' || !method;
  key.value = '';
  key.type = method === 'caesar' ? 'number' : method === 'aes' ? 'password' : 'text';
  key.removeAttribute('min');
  key.removeAttribute('max');
  key.removeAttribute('minlength');
  key.removeAttribute('maxlength');
  if (method === 'caesar') {
    $('key-label').innerHTML = 'SHIFT VALUE <span class="required">*</span>';
    key.placeholder = 'Enter a number (1–25)';
    key.min = '1';
    key.max = '25';
    $('key-hint').textContent = 'Use a whole-number shift between 1 and 25.';
  } else if (method === 'vigenere') {
    $('key-label').innerHTML = 'SECRET KEYWORD <span class="required">*</span>';
    key.placeholder = 'Example: LEMON';
    key.maxLength = 100;
    $('key-hint').textContent = 'English letters only; the same keyword decrypts the text.';
  } else if (method === 'aes') {
    $('key-label').innerHTML = 'SECRET PASSPHRASE <span class="required">*</span>';
    key.placeholder = 'Enter a passphrase (minimum 8 characters)';
    key.minLength = 8;
    key.maxLength = 256;
    $('key-hint').textContent = 'Use a long, unique passphrase. Keep it to decrypt later.';
  } else {
    $('key-label').innerHTML = 'SHIFT / KEY <span class="required">*</span>';
    key.placeholder = 'Select an algorithm first';
    $('key-hint').textContent = 'Select a method to see its key requirements.';
  }
  resetResult();
}

function switchMode(nextMode) {
  state.mode = nextMode;
  document.querySelectorAll('[data-mode]').forEach(button => {
    const active = button.dataset.mode === nextMode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  $('algorithm-field').hidden = nextMode === 'hash';
  $('key-field').hidden = nextMode === 'hash';
  algorithm.required = nextMode !== 'hash';
  key.required = nextMode !== 'hash';
  $('text-label').innerHTML = `${nextMode === 'decrypt' ? 'CIPHERTEXT' : 'PLAINTEXT'} <span class="required">*</span>`;
  source.placeholder = nextMode === 'decrypt'
    ? 'Paste your encrypted text here...'
    : nextMode === 'hash' ? 'Type text to generate its SHA-256 fingerprint...' : 'Type or paste the message you want to encrypt...';
  source.maxLength = nextMode === 'decrypt' ? 30000 : 10000;
  $('submit-label').textContent = nextMode === 'hash' ? 'Generate hash' : nextMode === 'decrypt' ? 'Decrypt text' : 'Encrypt text';
  $('submit-icon').textContent = nextMode === 'hash' ? '#' : nextMode === 'decrypt' ? '↙' : '↗';
  $('result-heading').textContent = nextMode === 'hash' ? 'SHA-256 HASH OUTPUT' : nextMode === 'decrypt' ? 'DECRYPTED OUTPUT' : 'ENCRYPTED OUTPUT';
  result.placeholder = nextMode === 'hash' ? 'Your SHA-256 digest will appear here...' : nextMode === 'decrypt' ? 'Your original text will appear here...' : 'Your encrypted result will appear here...';
  source.value = '';
  updateCharacterCount();
  resetResult();
}

function validate() {
  if (!source.value.trim()) return 'Please enter some text.';
  if (state.mode === 'hash') return '';
  if (!algorithm.value) return 'Please select an encryption algorithm.';
  if (!key.value.trim()) return 'Please enter the shift, keyword, or passphrase.';
  if (algorithm.value === 'caesar' && !/^(?:[1-9]|1\d|2[0-5])$/.test(key.value)) {
    return 'Caesar shift must be a whole number from 1 to 25.';
  }
  if (algorithm.value === 'vigenere' && !/^[A-Za-z]{1,100}$/.test(key.value)) {
    return 'Vigenère keyword must contain English letters only (maximum 100).';
  }
  if (algorithm.value === 'aes' && (key.value.length < 8 || key.value.length > 256)) {
    return 'AES passphrase must be between 8 and 256 characters.';
  }
  return '';
}

document.querySelectorAll('[data-mode]').forEach(button => {
  button.addEventListener('click', () => switchMode(button.dataset.mode));
});
algorithm.addEventListener('change', updateKeyField);
source.addEventListener('input', updateCharacterCount);
$('clear-button').addEventListener('click', () => {
  form.reset();
  algorithm.value = '';
  updateKeyField();
  source.value = '';
  updateCharacterCount();
  source.focus();
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  resetResult();
  const validationError = validate();
  if (validationError) return showError(validationError);
  const submit = $('submit-button');
  submit.disabled = true;
  $('submit-label').textContent = 'Processing...';
  try {
    const response = await fetch('/api/process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: state.mode, method: algorithm.value, text: source.value, key: key.value })
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || 'Processing failed.');
    result.value = body.result;
    state.lastResult = body.result;
    $('result-tag').textContent = 'SUCCESS';
    $('output-details').textContent = body.irreversible
      ? '64 hexadecimal characters · SHA-256 cannot be reversed.'
      : `${body.result.length.toLocaleString()} characters · ${state.mode === 'encrypt' ? 'Encrypted' : 'Decrypted'} successfully.`;
    $('copy-button').disabled = false;
  } catch (error) {
    showError(error instanceof TypeError ? 'Cannot reach the server. Start it with npm start.' : error.message);
  } finally {
    submit.disabled = false;
    $('submit-label').textContent = state.mode === 'hash' ? 'Generate hash' : state.mode === 'decrypt' ? 'Decrypt text' : 'Encrypt text';
  }
});

$('copy-button').addEventListener('click', async () => {
  if (!state.lastResult) return;
  try {
    await navigator.clipboard.writeText(state.lastResult);
    $('copy-label').textContent = 'Copied!';
  } catch {
    result.focus();
    result.select();
    showError('Automatic copy is unavailable in this browser. Select the result and press Ctrl+C.');
  }
});

updateCharacterCount();
updateKeyField();
