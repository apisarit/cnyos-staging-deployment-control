import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { POLICY, POLICY_SHA256, sha256 } from '../scripts/policy.mjs';
import {
  brokerTrustRoot, callSignedBrokerOperation, verifySignedBrokerEnvelope
} from '../scripts/reconcile-netlify-release-state.mjs';

assert.notEqual(process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE, 'true');
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error('OFFLINE_CONTRACT_NETWORK_FORBIDDEN'); };

// These ephemeral keys and injected transports exercise the real shared client.
// No policy file, approval packet, service receipt, or activation pin is written.
// Family-specific contracts separately validate operation results/state transitions.
const families = [
  ['reconciliation', POLICY.externalReconciliationBroker.operationDomain, POLICY.externalReconciliationBroker],
  ['draft', POLICY.draftLifecycleBroker.operationDomain, POLICY.draftLifecycleBroker],
  ['membership', POLICY.rollbackPrincipalMembershipBroker.operationDomain, POLICY.rollbackPrincipalMembershipBroker],
  ['authority', POLICY.netlifyAuthorityBoundary.operationDomain, POLICY.netlifyAuthorityBoundary],
  ['runtime', POLICY.runtimeEvidenceBroker.operationDomain, POLICY.runtimeEvidenceBroker],
  ['rollback', 'cnyos_staging_rollback_attestation', POLICY.rollbackAttestationBroker]
];
const observedAt = new Date('2032-01-01T00:05:00.000Z');
const token = 'offline_ephemeral_oidc_credential_canary';
const operation = 'offline_shared_client_contract';
const resumer = { controllerRepository: 'fixture/controller', controllerRunId: '71',
  controllerRef: 'refs/heads/offline-contract' };
const target = { netlifySiteId: 'offline-site', dispatchNonce: 'offline-nonce', barrierGeneration: 'offline-generation' };
const evidence = { sourceCommit: 'a'.repeat(40), artifactSha256: sha256('offline-artifact'),
  inputSha256: sha256('offline-input'), productionAuthorization: false };
const responseError = /CNYOS_RECONCILIATION_BROKER_RESPONSE_INVALID/;
const signatureError = /CNYOS_RECONCILIATION_BROKER_SIGNATURE_INVALID/;
const staleError = /CNYOS_RECONCILIATION_BROKER_RESPONSE_STALE/;
const reflectionError = /CNYOS_RECONCILIATION_OIDC_TOKEN_REFLECTION_INVALID/;

function fixture(kind, operationDomain) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const origin = `https://${kind}.example.invalid`;
  const trust = Object.freeze({ kind, origin, operationPath: '/v1/offline-contract',
    endpoint: `${origin}/v1/offline-contract`, operationDomain,
    policyId: `offline-${kind}-policy`, policySha256: sha256(kind),
    signingKeyId: `offline-${kind}-key`, publicKey: pair.publicKey,
    signingKeySpkiSha256: sha256(pair.publicKey.export({ type: 'spki', format: 'der' })),
    oidcAudience: `${origin}/oidc`, maximumAgeMs: 600_000, maximumResponseBytes: 4096 });
  return { pair, trust };
}

function signEnvelope(statement, { pair, trust }) {
  const signature = crypto.sign(null, Buffer.from(JSON.stringify(statement)), pair.privateKey);
  return { schemaVersion: 1, evidenceType: 'cnyos_staging_reconciliation_broker_envelope', statement,
    brokerSignature: { algorithm: 'Ed25519', keyId: trust.signingKeyId,
      statementSha256: sha256(JSON.stringify(statement)), signatureSha256: sha256(signature),
      signatureBase64: signature.toString('base64') } };
}

function envelope(body, item, changes = {}) {
  return signEnvelope({ schemaVersion: 1, operationDomain: item.trust.operationDomain,
    operation, policyId: item.trust.policyId, policySha256: item.trust.policySha256,
    requestSha256: sha256(body), issuedAt: '2032-01-01T00:04:00.000Z',
    expiresAt: '2032-01-01T00:10:00.000Z', result: { status: 'offline-contract-only' }, ...changes }, item);
}

function response(raw, endpoint, { status = 200, redirected = false, headers = {} } = {}) {
  const result = new Response(raw, { status, headers: { 'content-type': 'application/json', ...headers } });
  Object.defineProperties(result, { url: { value: endpoint }, redirected: { value: redirected } });
  return result;
}

try {
  for (const [kind, , policy] of families) {
    if (Object.values(policy).some(value => typeof value === 'string' && value.startsWith('__'))) {
      assert.throws(() => brokerTrustRoot(kind),
        new RegExp(`^Error: CNYOS_RECONCILIATION_${kind.toUpperCase()}_BROKER_POLICY_INVALID$`),
        `${kind}: checked-in unreviewed pins must remain unusable`);
    } else {
      // Future reviewed pins must pass the real parser, without any network call.
      assert.equal(brokerTrustRoot(kind).kind, kind);
    }
  }
  assert.throws(() => brokerTrustRoot('unknown'), /CNYOS_RECONCILIATION_UNKNOWN_BROKER_POLICY_INVALID/);

  const fixtures = families.map(([kind, domain]) => fixture(kind, domain));
  for (const item of fixtures) {
    const { trust } = item;
    let tokenCalls = 0;
    let networkCalls = 0;
    let requestBody;
    const options = { env: {}, trust, configuredUrl: trust.endpoint, operation,
      resumer, target, evidence, now: () => new Date(observedAt),
      oidcTokenProvider: async ({ env, audience }) => {
        tokenCalls++;
        assert.deepEqual(env, {});
        assert.equal(audience, trust.oidcAudience);
        return token;
      } };
    const fetchImpl = async (url, init) => {
      networkCalls++;
      assert.equal(String(url), trust.endpoint);
      assert.equal(init.method, 'POST');
      assert.equal(init.redirect, 'error');
      assert.equal(init.credentials, 'omit');
      assert.equal(init.referrerPolicy, 'no-referrer');
      assert.equal(init.cache, 'no-store');
      assert.ok(init.signal instanceof AbortSignal);
      assert.deepEqual(init.headers, { Accept: 'application/json', 'Content-Type': 'application/json',
        Authorization: `Bearer ${token}` });
      requestBody = init.body;
      assert.equal(requestBody.includes(token), false);
      assert.deepEqual(JSON.parse(requestBody), { schemaVersion: 1,
        evidenceType: 'cnyos_staging_reconciliation_broker_request', operationDomain: trust.operationDomain,
        operation, policyId: trust.policyId, policySha256: trust.policySha256,
        controllerPolicySha256: POLICY_SHA256, resumer, target, evidence });
      return response(JSON.stringify(envelope(requestBody, item)), trust.endpoint);
    };
    const valid = await callSignedBrokerOperation({ ...options, fetchImpl });
    assert.equal(tokenCalls, 1);
    assert.equal(networkCalls, 1);
    assert.deepEqual(valid.result, { status: 'offline-contract-only' });
    assert.equal(valid.requestSha256, sha256(requestBody));
    assert.equal(JSON.stringify(valid).includes(token), false);
    const verify = (value, overrides = {}) => verifySignedBrokerEnvelope(JSON.stringify(value), {
      trust, operation, requestSha256: sha256(requestBody), observedAt, ...overrides });
    const validEnvelope = envelope(requestBody, item);
    assert.deepEqual(verify(validEnvelope).statement, validEnvelope.statement);

    // Each independently authenticated binding is required even with a valid signature.
    for (const changes of [
      { operationDomain: 'different-domain' }, { operation: 'different-operation' },
      { policyId: 'different-policy' }, { policySha256: sha256('different-policy') },
      { requestSha256: sha256('different-request') }, { result: [] }, { extra: true }
    ]) assert.throws(() => verify(envelope(requestBody, item, changes)), responseError);
    for (const other of fixtures.filter(value => value !== item)) {
      assert.throws(() => verify(envelope(requestBody, other)), responseError,
        `${trust.kind} must reject the ${other.trust.kind} statement domain`);
      // Identical fields/key label cannot turn a different broker's key into this trust root.
      const wrongKey = signEnvelope(validEnvelope.statement, { pair: other.pair, trust });
      assert.throws(() => verify(wrongKey), signatureError);
    }
    for (const [field, name, replacement] of [
      ['resumer', 'controllerRunId', '72'], ['resumer', 'controllerRef', 'refs/heads/different'],
      ['target', 'netlifySiteId', 'different-site'], ['target', 'dispatchNonce', 'different-nonce'],
      ['target', 'barrierGeneration', 'different-generation'],
      ['evidence', 'sourceCommit', 'b'.repeat(40)], ['evidence', 'artifactSha256', sha256('different-artifact')]
    ]) {
      let replayCalls = 0;
      await assert.rejects(callSignedBrokerOperation({ ...options,
        [field]: { ...options[field], [name]: replacement }, fetchImpl: async (url, init) => {
          replayCalls++;
          assert.equal(JSON.parse(init.body)[field][name], replacement);
          assert.notEqual(sha256(init.body), validEnvelope.statement.requestSha256);
          return response(JSON.stringify(validEnvelope), String(url));
        }
      }), responseError, `${field}.${name}: an earlier signed response cannot satisfy the new request`);
      assert.equal(replayCalls, 1);
    }
    for (const change of [
      value => { value.statement.result.status = 'modified-after-signing'; },
      value => { value.brokerSignature.keyId = 'different-key'; },
      value => { value.brokerSignature.algorithm = 'different-algorithm'; },
      value => { value.brokerSignature.statementSha256 = sha256('wrong-statement'); },
      value => { value.brokerSignature.signatureSha256 = sha256('wrong-signature'); },
      value => { value.brokerSignature.signatureBase64 = Buffer.alloc(64).toString('base64'); }
    ]) {
      const changed = structuredClone(validEnvelope); change(changed);
      assert.throws(() => verify(changed), signatureError);
    }
    for (const changes of [
      { issuedAt: '2032-01-01T00:05:00.001Z' },
      { issuedAt: '2031-12-31T23:54:59.999Z', expiresAt: '2032-01-01T00:04:59.999Z' },
      { expiresAt: observedAt.toISOString() },
      { expiresAt: '2032-01-01T00:04:00.000Z' },
      { expiresAt: '2032-01-01T00:14:00.001Z' }
    ]) assert.throws(() => verify(envelope(requestBody, item, changes)), staleError);
    assert.throws(() => verifySignedBrokerEnvelope(`${JSON.stringify(validEnvelope)}\n`, {
      trust, operation, requestSha256: sha256(requestBody), observedAt
    }), /CNYOS_RECONCILIATION_BROKER_RESPONSE_NONCANONICAL/);

    // Reject endpoint changes before asking for an OIDC credential or calling transport.
    for (const configuredUrl of [
      `${trust.endpoint}?unexpected=1`, `${trust.endpoint}#fragment`, `${trust.origin}/different-path`,
      `https://different.example.invalid${trust.operationPath}`, trust.endpoint.replace('https:', 'http:')
    ]) {
      const before = [tokenCalls, networkCalls];
      await assert.rejects(callSignedBrokerOperation({ ...options, configuredUrl, fetchImpl }),
        /CNYOS_RECONCILIATION_BROKER_URL_INVALID/);
      assert.deepEqual([tokenCalls, networkCalls], before);
    }
    for (const invalidToken of ['', 'short', ` ${token}`, `${token}\n`, `${token} with-space`]) {
      await assert.rejects(callSignedBrokerOperation({ ...options, fetchImpl,
        oidcTokenProvider: async () => invalidToken }), /CNYOS_RECONCILIATION_OIDC_TOKEN_INVALID/);
      assert.equal(networkCalls, 1);
    }
    await assert.rejects(callSignedBrokerOperation({ ...options, fetchImpl, evidence: { token } }),
      /CNYOS_RECONCILIATION_CREDENTIAL_SERIALIZATION_INVALID/);
    assert.equal(networkCalls, 1);

    const rejectResponse = async (makeResponse, error) => assert.rejects(callSignedBrokerOperation({
      ...options, fetchImpl: async (url, init) => makeResponse(init.body, String(url))
    }), error);
    for (const transport of [
      { status: 401 }, { redirected: true }, { headers: { 'content-type': 'text/plain' } },
      { headers: { 'content-length': String(trust.maximumResponseBytes + 1) } },
      { headers: { 'content-length': 'invalid' } }
    ]) await rejectResponse((body, url) => response(JSON.stringify(envelope(body, item)), url, transport), responseError);
    await rejectResponse(body => response(JSON.stringify(envelope(body, item)), 'https://other.example.invalid/'), responseError);
    await rejectResponse((body, url) => response(JSON.stringify(envelope(body, item)), url,
      { headers: { 'x-offline-reflection': token } }), reflectionError);
    await rejectResponse((body, url) => response(JSON.stringify(envelope(body, item,
      { result: { reflected: token } })), url), reflectionError);
    await rejectResponse((_body, url) => response('x'.repeat(trust.maximumResponseBytes + 1), url), responseError);
    let cancelled = false;
    let chunks = 0;
    const oversizedStream = new ReadableStream({
      pull(controller) { chunks++; controller.enqueue(new Uint8Array(1024)); },
      cancel() { cancelled = true; }
    }, { highWaterMark: 0 });
    await rejectResponse((_body, url) => response(oversizedStream, url), responseError);
    assert.equal(cancelled, true, 'an oversized streamed response must cancel further reads');
    assert.equal(chunks, 5, 'enforce accumulated bytes even without Content-Length');
    await assert.rejects(callSignedBrokerOperation({ ...options,
      fetchImpl: async () => { throw new Error(`untrusted transport error ${token}`); }
    }), error => error.message === 'CNYOS_RECONCILIATION_BROKER_REQUEST_FAILED');
  }
} finally {
  globalThis.fetch = originalFetch;
}

process.stdout.write('CNYOS activation contract external-broker-trust-boundaries: passed\n');
