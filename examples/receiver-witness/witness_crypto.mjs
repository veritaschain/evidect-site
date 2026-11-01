/** Experiment-only Ed25519 witness signing. No network, file IO or key generation. */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
const DOMAIN = Buffer.from('EVIDECT-STATE-WITNESS\0v1\0', 'ascii');
const reject = () => { throw new Error('CRYPTO_INPUT_INVALID'); };
try {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16384) reject();
    chunks.push(chunk);
  }
  const req = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!req || !['sign', 'verify'].includes(req.operation) ||
      typeof req.digest !== 'string' || !/^[0-9a-f]{64}$/.test(req.digest) ||
      typeof req.key !== 'string' || req.key.length > 8192) reject();
  const privateMode = req.operation === 'sign';
  const expected = ['operation', 'digest', 'key', ...(privateMode ? [] : ['signature'])].sort();
  if (JSON.stringify(Object.keys(req).sort()) !== JSON.stringify(expected)) reject();
  const type = privateMode ? 'PRIVATE' : 'PUBLIC';
  const pem = new RegExp('^-----BEGIN ' + type + ' KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END ' + type + ' KEY-----\\r?\\n?$');
  if (!pem.test(req.key)) reject();
  const key = privateMode ? createPrivateKey(req.key) : createPublicKey(req.key);
  if (key.asymmetricKeyType !== 'ed25519') reject();
  const pub = privateMode ? createPublicKey(key) : key;
  const fingerprint = createHash('sha256').update(pub.export({ format: 'der', type: 'spki' })).digest('hex');
  const message = Buffer.concat([DOMAIN, Buffer.from(req.digest, 'hex')]);
  if (privateMode) {
    process.stdout.write(JSON.stringify({ fingerprint, signature: sign(null, message, key).toString('hex') }));
  } else {
    if (typeof req.signature !== 'string' || !/^[0-9a-f]{128}$/.test(req.signature)) reject();
    process.stdout.write(JSON.stringify({ fingerprint, valid: verify(null, message, pub, Buffer.from(req.signature, 'hex')) }));
  }
} catch {
  process.stdout.write(JSON.stringify({ error: 'WITNESS_CRYPTO_REJECTED' }));
  process.exitCode = 2;
}
