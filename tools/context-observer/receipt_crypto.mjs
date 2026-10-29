/** Narrow crypto subprocess for authenticated.py. No key generation or file/network I/O. */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
const DOMAIN = Buffer.from('EVIDECT-CONTEXT-RECEIPT\0v1\0', 'ascii');
const DEMO = '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const reject = code => { throw Object.assign(new Error(), { code }); };
try {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16384) reject('CRYPTO_INPUT_LIMIT');
    chunks.push(chunk);
  }
  // Python constructs this private IPC message after strict receipt parsing.
  const req = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!req || !['sign', 'verify'].includes(req.operation) ||
      typeof req.digest !== 'string' || !/^[0-9a-f]{64}$/.test(req.digest) ||
      typeof req.key !== 'string' || req.key.length > 8192) reject('CRYPTO_INPUT_INVALID');
  const privateMode = req.operation === 'sign';
  const type = privateMode ? 'PRIVATE' : 'PUBLIC';
  const pem = new RegExp('^-----BEGIN ' + type + ' KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END ' + type + ' KEY-----\\r?\\n?$');
  if (!pem.test(req.key)) reject('KEY_FORMAT_UNSUPPORTED');
  const key = privateMode ? createPrivateKey(req.key) : createPublicKey(req.key);
  if (key.asymmetricKeyType !== 'ed25519') reject('KEY_ALGORITHM_UNSUPPORTED');
  const pub = privateMode ? createPublicKey(key) : key;
  const der = pub.export({ format: 'der', type: 'spki' });
  if (der.toString('hex') === DEMO) reject('PUBLIC_DEMO_KEY_REJECTED');
  const fingerprint = createHash('sha256').update(der).digest('hex');
  const message = Buffer.concat([DOMAIN, Buffer.from(req.digest, 'hex')]);
  if (privateMode) {
    process.stdout.write(JSON.stringify({ fingerprint, signature: sign(null, message, key).toString('hex') }));
  } else {
    if (typeof req.signature !== 'string' || !/^[0-9a-f]{128}$/.test(req.signature)) reject('SIGNATURE_FORMAT_INVALID');
    process.stdout.write(JSON.stringify({ fingerprint, valid: verify(null, message, pub, Buffer.from(req.signature, 'hex')) }));
  }
} catch (error) {
  const codes = ['CRYPTO_INPUT_LIMIT', 'CRYPTO_INPUT_INVALID', 'KEY_FORMAT_UNSUPPORTED',
    'KEY_ALGORITHM_UNSUPPORTED', 'PUBLIC_DEMO_KEY_REJECTED', 'SIGNATURE_FORMAT_INVALID'];
  process.stdout.write(JSON.stringify({ error: codes.includes(error.code) ? error.code : 'CRYPTO_OPERATION_REJECTED' }));
  process.exitCode = 2;
}
