/** Fixed-journal, same-user/host observation fixture. Not an arbitrary file service. */
import { randomBytes } from 'node:crypto';
import { fork } from 'node:child_process';
import { constants, openSync, closeSync, fstatSync, lstatSync, readSync, realpathSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SELF = fileURLToPath(import.meta.url);
const FORMAT = 'evidect-runtime-observation/1';
const MAX_FILE = 64 * 1024, MAX_MESSAGE = 128 * 1024, MAX_ROWS = 128;
export const JOURNAL_NAMES = Object.freeze({ 'slot-a': 'slot-a.jsonl', 'slot-b': 'slot-b.jsonl' });
const hex32 = value => typeof value === 'string' && value.length === 32 && !/[^0-9a-f]/.test(value);
const identifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);
const markerValue = value => typeof value === 'string' && value.length >= 1 && value.length <= 64 && !/[^a-zA-Z0-9_-]/.test(value);

export function ordinaryRecord(value, fields) {
  if (value === null || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === fields.length && fields.every(key => keys.includes(key)) && keys.every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor.enumerable && Object.hasOwn(descriptor, 'value');
  });
}

export function validJournalRow(row, runId) {
  return ordinaryRecord(row, ['runId', 'operationId', 'marker', 'origin']) && row.runId === runId && hex32(row.runId) &&
    identifier(row.operationId) && markerValue(row.marker) && ['authorized_wrapper', 'controller_fault_injection'].includes(row.origin);
}

function denseRows(rows) {
  if (!Array.isArray(rows) || Object.getPrototypeOf(rows) !== Array.prototype || rows.length > MAX_ROWS ||
    Reflect.ownKeys(rows).length !== rows.length + 1) return false;
  for (let index = 0; index < rows.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(rows, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}

export function validReceipt(receipt) {
  if (!ordinaryRecord(receipt, ['format', 'runId', 'instanceId', 'challenge', 'phase', 'sequence', 'status', 'reason', 'journals']) ||
    receipt.format !== FORMAT || !hex32(receipt.runId) || !hex32(receipt.instanceId) || !hex32(receipt.challenge) ||
    !['before', 'after'].includes(receipt.phase) || !Number.isSafeInteger(receipt.sequence) || receipt.sequence < 1 || receipt.sequence > 2) return false;
  if (receipt.status === 'UNAVAILABLE') return receipt.reason === 'JOURNAL_UNAVAILABLE' && receipt.journals === null;
  if (receipt.status !== 'AVAILABLE' || receipt.reason !== 'READ_OK' || !ordinaryRecord(receipt.journals, ['slot-a', 'slot-b'])) return false;
  return Object.values(receipt.journals).every(rows => denseRows(rows) &&
    rows.every(row => validJournalRow(row, receipt.runId)));
}

function safeRoot(root) {
  if (typeof root !== 'string' || !isAbsolute(root) || root.length > 4096 || root.includes('\0') ||
    typeof process.getuid !== 'function' || !Number.isInteger(constants.O_NOFOLLOW)) throw Error('JOURNAL_UNAVAILABLE');
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) throw Error('JOURNAL_UNAVAILABLE');
  return realpathSync(root);
}

function fileIdentity(stat) {
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs, stat.nlink].join(':');
}

function readJournal(root, name, runId) {
  const fd = openSync(join(root, name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(process.getuid()) ||
      (before.mode & 0o777n) !== 0o600n || before.size > BigInt(MAX_FILE)) throw Error('JOURNAL_UNAVAILABLE');
    const buffer = Buffer.alloc(MAX_FILE + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    if (length > MAX_FILE || BigInt(length) !== after.size || fileIdentity(before) !== fileIdentity(after)) throw Error('JOURNAL_UNAVAILABLE');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length));
    if (text && !text.endsWith('\n')) throw Error('JOURNAL_UNAVAILABLE');
    const lines = text ? text.slice(0, -1).split('\n') : [];
    if (lines.length > MAX_ROWS) throw Error('JOURNAL_UNAVAILABLE');
    const rows = lines.map(line => {
      const row = JSON.parse(line);
      // Canonical JSON lines reject duplicate keys, alternate shapes and a
      // partially written row without relying on JSON.parse's last-key behavior.
      if (!validJournalRow(row, runId) || JSON.stringify({ runId: row.runId, operationId: row.operationId,
        marker: row.marker, origin: row.origin }) !== line) throw Error('JOURNAL_UNAVAILABLE');
      return row;
    });
    return { rows, identity: fileIdentity(after) };
  } finally { closeSync(fd); }
}

function readJournals(root, runId) {
  root = safeRoot(root);
  const readSet = () => Object.fromEntries(Object.entries(JOURNAL_NAMES).map(([slot, name]) => [slot, readJournal(root, name, runId)]));
  const first = readSet(), second = readSet();
  if (JSON.stringify(first) !== JSON.stringify(second)) throw Error('JOURNAL_UNAVAILABLE');
  return Object.fromEntries(Object.keys(JOURNAL_NAMES).map(slot => [slot, second[slot].rows]));
}

/** A single case owns one client/child. No host environment is passed through. */
export class ObserverClient {
  #root; #runId; #timeout; #child = null; #pid = null; #instanceId = null;
  #pending = null; #exited = false; #exitPromise = null; #resolveExit;
  #stopped = false; #broken = false; #sequence = 0;
  constructor({ root, runId, timeoutMs = 2000 }) {
    if (typeof root !== 'string' || !isAbsolute(root) || root.length > 4096 || root.includes('\0') ||
      !hex32(runId) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw Error('INVALID_OBSERVER_CONFIGURATION');
    this.#root = root; this.#runId = runId; this.#timeout = timeoutMs;
  }
  get instanceId() { return this.#instanceId; }
  get pid() { return this.#pid; }
  get stopped() { return this.#exited || (this.#stopped && this.#child === null); }
  get available() { return !!this.#instanceId && !this.#stopped && !this.#broken && !this.#exited; }

  #fail(code) {
    this.#broken = true;
    if (this.#pending) {
      const pending = this.#pending; this.#pending = null;
      clearTimeout(pending.timer); pending.reject(Error(code));
    }
    if (this.#child && !this.#exited) this.#child.kill('SIGKILL');
  }

  #receive(message) {
    const pending = this.#pending;
    try {
      if (!pending || Buffer.byteLength(JSON.stringify(message)) > MAX_MESSAGE) throw Error();
      if (pending.kind === 'ready') {
        if (!ordinaryRecord(message, ['type', 'runId', 'instanceId', 'challenge', 'sequence']) ||
          message.type !== 'ready' || message.runId !== this.#runId || !hex32(message.instanceId) ||
          message.challenge !== pending.challenge || message.sequence !== 0) throw Error();
        this.#instanceId = message.instanceId;
      } else {
        if (!ordinaryRecord(message, ['type', 'receipt']) || message.type !== 'observation' || !validReceipt(message.receipt)) throw Error();
        const receipt = message.receipt;
        if (receipt.runId !== this.#runId || receipt.instanceId !== this.#instanceId ||
          receipt.challenge !== pending.challenge || receipt.sequence !== pending.sequence || receipt.phase !== pending.phase) throw Error();
      }
      this.#pending = null; clearTimeout(pending.timer);
      pending.resolve(pending.kind === 'ready' ? this.#instanceId : message.receipt);
    } catch { this.#fail('OBSERVER_PROTOCOL_INVALID'); }
  }

  #exchange(message, expected) {
    if (this.#pending || this.#exited || this.#broken || this.#stopped) return Promise.reject(Error('OBSERVER_UNAVAILABLE'));
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => this.#fail('OBSERVER_UNAVAILABLE'), this.#timeout);
      this.#pending = { ...expected, challenge: message.challenge, resolve: resolvePromise, reject, timer };
      this.#child.send(message, error => { if (error) this.#fail('OBSERVER_UNAVAILABLE'); });
    });
  }

  async start() {
    if (this.#child || this.#stopped) throw Error('OBSERVER_ALREADY_STARTED');
    this.#exitPromise = new Promise(resolvePromise => { this.#resolveExit = resolvePromise; });
    this.#child = fork(SELF, ['--fixture-observer'], {
      execArgv: [], env: {}, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], serialization: 'json',
    });
    this.#pid = this.#child.pid ?? null;
    this.#child.on('message', message => this.#receive(message));
    this.#child.on('error', () => {
      this.#fail('OBSERVER_UNAVAILABLE');
      if (this.#pid === null) { this.#exited = true; this.#resolveExit(); }
    });
    this.#child.on('exit', () => {
      this.#exited = true; this.#fail('OBSERVER_UNAVAILABLE'); this.#resolveExit();
    });
    try {
      return await this.#exchange({ type: 'initialize', root: this.#root, runId: this.#runId,
        challenge: randomBytes(16).toString('hex') }, { kind: 'ready' });
    } catch (error) { await this.stop(); throw error; }
  }

  async snapshot(phase) {
    if (!this.available) throw Error('OBSERVER_UNAVAILABLE');
    if (!['before', 'after'].includes(phase) || this.#pending ||
      (phase === 'before' ? this.#sequence !== 0 : this.#sequence !== 1)) throw Error('OBSERVER_PHASE_INVALID');
    const sequence = ++this.#sequence;
    return this.#exchange({ type: 'observe', runId: this.#runId, instanceId: this.#instanceId,
      challenge: randomBytes(16).toString('hex'), phase, sequence }, { kind: 'observation', phase, sequence });
  }

  async stop() {
    this.#stopped = true;
    if (!this.#child || this.#exited) return;
    this.#fail('OBSERVER_UNAVAILABLE'); // SIGKILL targets only this owned child.
    let timer;
    try {
      await Promise.race([this.#exitPromise, new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error('OBSERVER_STOP_FAILED')), 2000);
      })]);
    } finally { clearTimeout(timer); }
  }
}

function worker() {
  let root, runId, instanceId, sequence = 0, initialized = false;
  process.on('message', message => {
    try {
      if (Buffer.byteLength(JSON.stringify(message)) > 8192) throw Error();
      if (!initialized) {
        if (!ordinaryRecord(message, ['type', 'root', 'runId', 'challenge']) || message.type !== 'initialize' ||
          !hex32(message.runId) || !hex32(message.challenge)) throw Error();
        root = safeRoot(message.root); runId = message.runId; instanceId = randomBytes(16).toString('hex'); initialized = true;
        process.send({ type: 'ready', runId, instanceId, challenge: message.challenge, sequence: 0 });
        return;
      }
      if (!ordinaryRecord(message, ['type', 'runId', 'instanceId', 'challenge', 'phase', 'sequence']) ||
        message.type !== 'observe' || message.runId !== runId || message.instanceId !== instanceId ||
        !hex32(message.challenge) || message.sequence !== sequence + 1 || sequence >= 2 ||
        message.phase !== (sequence === 0 ? 'before' : 'after')) throw Error();
      sequence++;
      let status = 'AVAILABLE', reason = 'READ_OK', journals;
      try { journals = readJournals(root, runId); }
      catch { status = 'UNAVAILABLE'; reason = 'JOURNAL_UNAVAILABLE'; journals = null; }
      const receipt = { format: FORMAT, runId, instanceId, challenge: message.challenge,
        phase: message.phase, sequence, status, reason, journals };
      if (Buffer.byteLength(JSON.stringify(receipt)) > MAX_MESSAGE) throw Error();
      process.send({ type: 'observation', receipt });
    } catch { process.exit(2); }
  });
  process.on('disconnect', () => process.exit(0));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length === 3 && process.argv[2] === '--fixture-observer' && typeof process.send === 'function') worker();
  else { process.stderr.write('Internal synthetic observer only; no input arguments accepted.\n'); process.exitCode = 2; }
}
