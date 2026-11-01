// Internal bounded Ed25519 helper. No network, shell, key generation or file I/O.
import { createPrivateKey, createPublicKey, createHash, sign, verify } from 'node:crypto';

try {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 32768) throw new Error('BOUND');
    chunks.push(chunk);
  }
  // Only the Python wrapper constructs this internal request, with fixed fields.
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const fields = value?.operation === 'sign' ? ['operation', 'message', 'key'] : ['operation', 'message', 'key', 'signature'];
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).sort().join() !== fields.sort().join() ||
      !['sign', 'verify'].includes(value.operation) ||
      typeof value.message !== 'string' || !/^[0-9a-f]{2,16384}$/.test(value.message) || value.message.length % 2 ||
      typeof value.key !== 'string' || value.key.length > 8192) throw new Error('INPUT');
  const privateOperation = value.operation === 'sign';
  const label = privateOperation ? 'PRIVATE' : 'PUBLIC';
  const pem = new RegExp(`^-----BEGIN ${label} KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END ${label} KEY-----\\r?\\n?$`);
  if (!pem.test(value.key)) throw new Error('KEY');
  const key = privateOperation ? createPrivateKey(value.key) : createPublicKey(value.key);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('ALGORITHM');
  const publicKey = privateOperation ? createPublicKey(key) : key;
  const fingerprint = createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('hex');
  const message = Buffer.from(value.message, 'hex');
  if (privateOperation) {
    console.log(JSON.stringify({ fingerprint, signature: sign(null, message, key).toString('hex') }));
  } else {
    if (typeof value.signature !== 'string' || !/^[0-9a-f]{128}$/.test(value.signature)) throw new Error('SIGNATURE');
    console.log(JSON.stringify({ fingerprint, valid: verify(null, message, key, Buffer.from(value.signature, 'hex')) }));
  }
} catch {
  console.log(JSON.stringify({ error: 'CRYPTO_INPUT_OR_OPERATION_REJECTED' }));
  process.exitCode = 2;
}
