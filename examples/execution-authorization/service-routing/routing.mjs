/** Same-controller synthetic service policy around the unchanged in-memory gate. */
import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { createGate } from '../gate.mjs';

const ROUTE_DOMAIN = 'EVIDECT-EXPERIMENTAL-SERVICE-ROUTE/1\0';
const invalid = () => { throw new TypeError('INVALID_SERVICE_ROUTING_DATA'); };
const need = condition => { if (!condition) invalid(); };
const integer = value => Number.isSafeInteger(value) && value >= 0;
const identifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);

function record(value, fields) {
  need(value !== null && typeof value === 'object' && !isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const keys = Reflect.ownKeys(value);
  need(keys.length === fields.length && fields.every(key => keys.includes(key)));
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    need(descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
  }
}

// Reject proxies before reflection can invoke a trap or reenter execution.
// Snapshot data descriptors, never getters. Bounds apply to both task data and
// the trusted controller's mutable policy snapshots; this is not a JSON API.
function dataSnapshot(value, depth = 0, seen = new Set(), budget = { remaining: 20000 }) {
  need(depth <= 12 && --budget.remaining >= 0);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') { need(value.length <= 4096); return value; }
  if (typeof value === 'number') { need(Number.isFinite(value)); return value; }
  need(value !== null && typeof value === 'object' && !isProxy(value) && !seen.has(value));
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    need(Object.getPrototypeOf(value) === Array.prototype && value.length <= 128);
    need(Reflect.ownKeys(value).length === value.length + 1);
    result = [];
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      need(descriptor && descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
      result.push(dataSnapshot(descriptor.value, depth + 1, seen, budget));
    }
  } else {
    need([Object.prototype, null].includes(Object.getPrototypeOf(value)));
    const keys = Reflect.ownKeys(value);
    need(keys.length <= 32);
    result = {};
    for (const key of keys) {
      need(typeof key === 'string' && key.length <= 80);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      need(descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
      Object.defineProperty(result, key, {
        value: dataSnapshot(descriptor.value, depth + 1, seen, budget),
        enumerable: true, writable: true, configurable: true,
      });
    }
  }
  seen.delete(value);
  return result;
}

function routeSnapshot(route) {
  record(route, ['provider', 'model', 'destination', 'channel']);
  need(['fixture-a', 'fixture-b', 'local'].includes(route.provider));
  need(['refusal-model', 'answer-model', 'none'].includes(route.model));
  need(['slot-a', 'slot-b'].includes(route.destination));
  need(['model', 'non-ai'].includes(route.channel));
  need(route.channel === 'model'
    ? ['fixture-a', 'fixture-b'].includes(route.provider) && ['refusal-model', 'answer-model'].includes(route.model)
    : route.provider === 'local' && route.model === 'none');
  return { provider: route.provider, model: route.model, destination: route.destination, channel: route.channel };
}

export function routeResource(route) {
  const value = routeSnapshot(route);
  return 'route:' + createHash('sha256').update(ROUTE_DOMAIN + JSON.stringify([
    value.provider, value.model, value.destination, value.channel,
  ])).digest('hex');
}

const permissionResult = (status, reason, state = null) => ({
  status, reason, policy_revision: state?.policyRevision ?? null, checked_at: state?.now ?? null,
});

function servicePermission(source, request) {
  let state;
  try {
    state = dataSnapshot(source);
    record(state, ['available', 'now', 'policyRevision', 'audience', 'permissions']);
    need(typeof state.available === 'boolean' && integer(state.now));
    need(identifier(state.policyRevision) && identifier(state.audience));
    need(Array.isArray(state.permissions) && state.permissions.length <= 64);
    const tuples = new Set();
    for (const permission of state.permissions) {
      record(permission, ['issuer', 'agent', 'tenant', 'resource', 'action', 'notBefore', 'expiresAt', 'revoked']);
      need(['issuer', 'agent', 'tenant', 'resource', 'action'].every(key => identifier(permission[key])));
      need(permission.action === 'append_marker' && typeof permission.revoked === 'boolean');
      need(integer(permission.notBefore) && integer(permission.expiresAt) && permission.expiresAt > permission.notBefore);
      const tuple = JSON.stringify(['issuer', 'agent', 'tenant', 'resource', 'action'].map(key => permission[key]));
      need(!tuples.has(tuple));
      tuples.add(tuple);
    }
  } catch { return permissionResult('INDETERMINATE', 'SERVICE_STATE_INVALID'); }
  if (!state.available) return permissionResult('INDETERMINATE', 'SERVICE_STATE_UNAVAILABLE');
  if (state.audience !== request.audience)
    return permissionResult('DENY', 'SERVICE_AUDIENCE_MISMATCH', state);
  const permission = state.permissions.find(candidate =>
    ['issuer', 'agent', 'tenant', 'resource', 'action'].every(key => candidate[key] === request[key]));
  if (!permission) return permissionResult('DENY', 'SERVICE_PERMISSION_MISSING', state);
  if (permission.revoked) return permissionResult('DENY', 'SERVICE_PERMISSION_REVOKED', state);
  if (state.now < permission.notBefore || state.now >= permission.expiresAt)
    return permissionResult('DENY', 'SERVICE_PERMISSION_OUTSIDE_VALIDITY', state);
  return permissionResult('ALLOW', 'SERVICE_PERMISSION_ALLOWED', state);
}

export function createServiceRoutingGate(configuration) {
  record(configuration, ['issuerKeys', 'approverKeys', 'delegationState', 'serviceState']);
  const { issuerKeys, approverKeys, delegationState, serviceState } = configuration;
  need(!isProxy(issuerKeys) && !isProxy(approverKeys));
  // The original gate may clone its state using structuredClone. Give it only
  // owned data, refreshed from the controller without executing accessors.
  const gateState = Object.create(null);
  const gate = createGate({ issuerKeys, approverKeys, state: gateState });
  const history = [];

  function refreshDelegation() {
    let current;
    try {
      current = dataSnapshot(delegationState);
      need(current !== null && typeof current === 'object' && !Array.isArray(current));
    } catch { current = { available: false }; }
    for (const key of Object.keys(gateState)) delete gateState[key];
    Object.assign(gateState, current);
  }

  function assess(input, execute) {
    const result = {
      mode: execute ? 'EXECUTE' : 'PREVIEW', attempt_index: execute ? history.length + 1 : null,
      route: null, resource: null, authorization: 'DENY', reason: 'INVALID_ROUTING_INPUT',
      delegation_preview: null,
      service_permission: permissionResult('NOT_CHECKED', 'INPUT_NOT_VALIDATED'),
      gate_execution_recheck: null, dispatch_delta: { calls: 0, marker_count: 0 },
      synthetic_result: 'NOT_CALLED',
    };
    let captured;
    try {
      record(input, ['request', 'approval', 'session', 'route']);
      captured = dataSnapshot(input);
      result.route = routeSnapshot(captured.route);
      result.resource = routeResource(result.route);
    } catch { return result; }
    refreshDelegation();
    result.delegation_preview = gate.preview(captured.request, captured.approval, captured.session);
    const preview = result.delegation_preview;
    if (preview.request_signature !== 'VALID') {
      result.reason = preview.reason;
      result.service_permission = permissionResult('NOT_CHECKED', 'REQUEST_NOT_VERIFIED');
      return result;
    }
    if (captured.request.payload.resource !== result.resource) {
      result.reason = 'ROUTE_RESOURCE_MISMATCH';
      result.service_permission = permissionResult('NOT_CHECKED', 'ROUTE_NOT_BOUND');
      return result;
    }
    result.service_permission = servicePermission(serviceState, captured.request.payload);
    if (preview.authorization !== 'ALLOW') { result.reason = preview.reason; return result; }
    if (result.service_permission.status !== 'ALLOW') {
      result.reason = result.service_permission.reason;
      return result;
    }
    if (!execute) {
      result.authorization = 'ALLOW';
      result.reason = 'AUTHORIZED_FOR_PREVIEW';
      return result;
    }
    // No await or caller-supplied callback: refresh user state and let the
    // unchanged gate recheck and reserve its nonce before its only toy tool.
    refreshDelegation();
    result.gate_execution_recheck = gate.execute(captured.request, captured.approval, captured.session);
    result.authorization = result.gate_execution_recheck.authorization;
    result.reason = result.gate_execution_recheck.reason;
    if (result.gate_execution_recheck.execution === 'COMPLETED')
      result.synthetic_result = result.route.model === 'refusal-model' ? 'REFUSED' : 'COMPLETED';
    return result;
  }

  return Object.freeze({
    preview(input) { return assess(input, false); },
    execute(input) {
      const before = gate.inspectTool();
      const result = assess(input, true);
      const after = gate.inspectTool();
      result.dispatch_delta = {
        calls: after.calls - before.calls,
        marker_count: after.markers.length - before.markers.length,
      };
      history.push(dataSnapshot(result));
      return dataSnapshot(result);
    },
    inspectTool() { return gate.inspectTool(); },
    inspectHistory() { return history.map(entry => dataSnapshot(entry)); },
  });
}
