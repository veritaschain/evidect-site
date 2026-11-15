/** Bounded JSON input for the experimental offline reader. No repair or duplicate-key selection. */
import { constants, openSync, fstatSync, readSync, closeSync } from 'node:fs';
import { TextDecoder } from 'node:util';

export const MAX_JSON_BYTES = 2 * 1024 * 1024;
const fail = () => { throw new TypeError('INVALID_OR_OVERSIZED_JSON'); };

export function parseBoundedJSON(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_JSON_BYTES) fail();
  let cursor = 0, nodes = 0;
  const space = () => { while (cursor < text.length && /[ \t\r\n]/.test(text[cursor])) cursor++; };
  function string() {
    const start = cursor++;
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === '"') {
        const value = JSON.parse(text.slice(start, cursor));
        if (value.length > 8192 || !value.isWellFormed()) fail();
        return value;
      }
      if (character.charCodeAt(0) < 0x20) fail();
      if (character === '\\') {
        const escape = text[cursor++];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(cursor, cursor + 4))) fail();
          cursor += 4;
        } else if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escape)) fail();
      }
    }
    return fail();
  }
  function value(depth) {
    if (depth > 24 || ++nodes > 100000) fail();
    space();
    const character = text[cursor];
    if (character === '"') return string();
    if (character === '{') {
      cursor++; space();
      const result = Object.create(null), keys = new Set();
      if (text[cursor] === '}') { cursor++; return result; }
      for (;;) {
        space();
        if (text[cursor] !== '"') fail();
        const key = string();
        if (keys.has(key) || keys.size >= 64 || key.length > 80) fail();
        keys.add(key); space();
        if (text[cursor++] !== ':') fail();
        result[key] = value(depth + 1); space();
        const separator = text[cursor++];
        if (separator === '}') return result;
        if (separator !== ',') fail();
      }
    }
    if (character === '[') {
      cursor++; space();
      const result = [];
      if (text[cursor] === ']') { cursor++; return result; }
      for (;;) {
        if (result.length >= 256) fail();
        result.push(value(depth + 1)); space();
        const separator = text[cursor++];
        if (separator === ']') return result;
        if (separator !== ',') fail();
      }
    }
    for (const [word, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(word, cursor)) { cursor += word.length; return result; }
    }
    // Only integer lexemes are accepted: converting a decimal/exponent token
    // first could round a non-integer into an apparently safe integer.
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(cursor));
    if (!match) fail();
    cursor += match[0].length;
    const number = Number(match[0]);
    // These fixed evidence contracts contain integer counters/times only.
    if (!Number.isSafeInteger(number) || Object.is(number, -0)) fail();
    return number;
  }
  const result = value(0);
  space();
  if (cursor !== text.length) fail();
  return result;
}

export function readBoundedJSON(filename) {
  if (typeof filename !== 'string' || filename.length === 0 || filename.includes('\0')) fail();
  // Do not block while opening a FIFO before its descriptor can be rejected.
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > MAX_JSON_BYTES) fail();
    const bytes = Buffer.alloc(MAX_JSON_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length > MAX_JSON_BYTES) fail();
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
    return parseBoundedJSON(text);
  } finally { closeSync(descriptor); }
}
