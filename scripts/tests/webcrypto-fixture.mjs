// Synthetic, nonsecret test password; matches test_crypto_vault.py.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { join } from 'node:path';
const root = process.argv[2];
const header = JSON.parse(await readFile(join(root, 'vault.json'), 'utf8'));
const utf8 = new TextEncoder();
const b64 = value => Uint8Array.from(Buffer.from(value, 'base64'));
const password = 'rivie\u0300re-lumie\u0300re-papillon-citron-42'.normalize('NFC');
const material = await webcrypto.subtle.importKey('raw', utf8.encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await webcrypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt: b64(header.kdf.salt) }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
async function decrypt(descriptor, aad) {
  const raw = await readFile(join(root, descriptor.path));
  return new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(descriptor.iv), additionalData: utf8.encode(aad), tagLength: 128 }, key, raw));
}
const manifest = JSON.parse(new TextDecoder().decode(await decrypt(header.manifest, 'relais-cm1:v1:manifest')));
let count = 0;
for (const descriptor of Object.values(manifest.assets)) {
  const plain = await decrypt(descriptor, `relais-cm1:v1:asset:${descriptor.id}`);
  assert.equal(plain.byteLength, descriptor.sizeBytes);
  const sha = Buffer.from(await webcrypto.subtle.digest('SHA-256', plain)).toString('hex');
  assert.equal(sha, descriptor.sha256);
  count++;
}
assert.equal(manifest.latestDate, '2026-11-19');
console.log(`${count} assets verified through WebCrypto`);
