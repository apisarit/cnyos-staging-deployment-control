import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { POLICY, POLICY_SHA256, assertControllerRuntime, deploymentMarker, sha256 } from '../scripts/policy.mjs';
import { recordDraftIntent } from '../scripts/create-netlify-draft-with-durable-intent.mjs';
import { assertDraftOnlyRecoveryPlan, draftCleanupFetchGuard } from '../scripts/cleanup-netlify-draft.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'cnyos-draft-contract-'));
const now = new Date('2030-01-01T00:01:00.000Z');
const createdAt = new Date(now.getTime() - 1000).toISOString();
const expiresAt = new Date(now.getTime() + 240_000).toISOString();
const previous = '1'.repeat(24); const deployed = '2'.repeat(24);
const token = 'synthetic-publisher-token-000000000000';
const oidcToken = 'synthetic-oidc-token-000000000000';
const hash = char => char.repeat(64);
const runtimeEnv = {
  GITHUB_REPOSITORY: POLICY.controller.repository, CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
  GITHUB_REF: POLICY.controller.protectedRef, CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
  GITHUB_REF_PROTECTED: 'true', GITHUB_SHA: 'a'.repeat(40), GITHUB_RUN_ID: '111', GITHUB_RUN_ATTEMPT: '1',
  GITHUB_ACTOR: 'fixture-reviewer', GITHUB_TRIGGERING_ACTOR: 'fixture-reviewer',
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
  GITHUB_WORKFLOW_REF: `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
  CNYOS_DISPATCH_NONCE: Buffer.alloc(32, 7).toString('base64url')
};
const response = (url, value, { status = 200, type = 'application/json', raw } = {}) => {
  const r = new Response(raw ?? JSON.stringify(value), { status, headers: { 'Content-Type': type } });
  Object.defineProperty(r, 'url', { value: String(url) }); return r;
};
async function absent(filename) {
  try { await fs.lstat(filename); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; }
}
try {
  let calls = 0;
  await assert.rejects(recordDraftIntent({ env: runtimeEnv, fetchImpl: () => { calls++; },
    oidcTokenProvider: () => { calls++; } }), /BROKER_POLICY_INVALID/);
  assert.equal(calls, 0, 'placeholder policy must stop before OIDC or mutation');
  const controller = path.join(tmp, 'controller');
  await fs.mkdir(controller);
  await fs.cp(path.join(root, 'scripts'), path.join(controller, 'scripts'), { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const policy = JSON.parse(JSON.stringify(POLICY));
  const trustPolicy = policy.draftLifecycleBroker;
  Object.assign(trustPolicy, { origin: 'https://draft-broker.example.invalid', operationPath: '/reviewed-fixture-operation',
    policyId: 'fixture-draft-policy', policySha256: hash('b'), signingKeyId: 'fixture-draft-key',
    signingPublicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    signingKeySpkiSha256: sha256(publicKey.export({ format: 'der', type: 'spki' })),
    oidcAudience: 'https://draft-broker.example.invalid/oidc', maximumEvidenceAgeMinutes: 10,
    maximumResponseBytes: 65536 });
  policy.privateDraftAccessBoundary = { origin: 'https://draft-reader.example.invalid',
    policyId: 'fixture-private-policy', policySha256: hash('c') };
  policy.publishing.netlifyCliVersion = '99.0.0';
  await fs.writeFile(path.join(controller, 'controller-policy.json'), JSON.stringify(policy));
  const mod = await import(pathToFileURL(path.join(controller, 'scripts/create-netlify-draft-with-durable-intent.mjs')));
  const broker = await import(pathToFileURL(path.join(controller, 'scripts/reconcile-netlify-release-state.mjs')));
  const isolatedPolicy = await import(pathToFileURL(path.join(controller, 'scripts/policy.mjs')));
  const bundleDirectory = path.join(tmp, 'bundle');
  await fs.mkdir(path.join(bundleDirectory, 'payload/dist'), { recursive: true });
  await fs.mkdir(path.join(bundleDirectory, 'payload/netlify/functions'), { recursive: true });
  await fs.writeFile(path.join(bundleDirectory, 'payload/dist/index.html'), 'synthetic inert bytes');
  const runtime = assertControllerRuntime(runtimeEnv);
  const source = { repository: POLICY.sourceRepository, commit: 'd'.repeat(40), tree: 'e'.repeat(40), functionSourceTree: 'f'.repeat(40) };
  const artifact = { artifactSha256: hash('d') };
  const preflight = { sha256: hash('e'), value: { schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_preflight', productionAuthorization: false,
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerRunId: runtime.runId, target: POLICY.target,
    targetSiteAndPublisherExclusion: { productionNetlifySiteId: POLICY.productionDenylist.netlifySiteId,
      productionNetlifyOrigin: POLICY.productionDenylist.netlifyOrigin },
    preReleaseReconciliationEvidenceSha256: hash('f'),
    liveGitHubPrecredentialBoundaryEvidenceSha256: hash('1'),
    runtimeProofEnvelopeSha256: hash('6'),
    authorizationExpiresAt: expiresAt, principalProofExpiresAt: expiresAt,
    liveNetlifyAuthorityBoundaryExpiresAt: expiresAt, deploymentControlBoundaryExpiresAt: expiresAt,
    dispatchNonce: runtimeEnv.CNYOS_DISPATCH_NONCE, source, artifact,
    previousPublishedDeploy: { id: previous }, principalProof: { subject: 'fixture-publisher' } } };
  const deployMessage = deploymentMarker(runtime.runId, runtimeEnv.CNYOS_DISPATCH_NONCE, source.commit);
  const context = { runtime, observedAt: now, preflight, readiness: { sha256: hash('2') },
    gate: { sha256: hash('3'), value: { deployMessage, checkedAt: new Date(now.getTime() - 2000).toISOString() } },
    bundle: { bundleDirectory, manifestSha256: hash('4'), manifest: { dispatchNonce: runtimeEnv.CNYOS_DISPATCH_NONCE,
      candidateCommit: source.commit, candidateTree: source.tree, artifactSha256: artifact.artifactSha256 } } };
  // Exercise real prerequisite loaders/validators (only the already-tested closed
  // producer verifier is substituted); receipt hashes are recomputed from files.
  const prerequisiteDirectory = path.join(tmp, 'prerequisites'); await fs.mkdir(prerequisiteDirectory);
  const prerequisiteEnv = { ...runtimeEnv };
  const prerequisitePreflight = structuredClone(preflight.value);
  prerequisitePreflight.rollbackNetlifyPrincipalBoundary = { subject: 'fixture-rollback',
    membershipRole: 'Publisher', membershipEvidenceSha256: hash('a') };
  async function prerequisite(name, value) {
    const filename = path.join(prerequisiteDirectory, `${name}.json`);
    const bytes = Buffer.from(JSON.stringify(value)); await fs.writeFile(filename, bytes);
    prerequisiteEnv[`CNYOS_CONTROLLER_${name}_EVIDENCE_PATH`] = filename;
    prerequisiteEnv[`CNYOS_EXPECTED_${name}_EVIDENCE_SHA256`] = sha256(bytes);
    return sha256(bytes);
  }
  const actualPreflightSha = await prerequisite('PREFLIGHT', prerequisitePreflight);
  const readinessValue = { schemaVersion: 1, evidenceType: 'cnyos_staging_controller_rollback_readiness',
    status: 'passed', scope: 'cnyos_staging_only', productionAuthorization: false,
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerRunId: runtime.runId, preflightEvidenceSha256: actualPreflightSha, target: POLICY.target,
    principalSubject: 'fixture-rollback', membershipRole: 'Publisher', membershipEvidenceSha256: hash('a'),
    teamOwner: false, teamAdministrator: false, siteAccessScope: 'single_site', liveTokenVerified: true,
    inventoryComplete: true, accessibleSiteCount: 1, allowedSiteIds: [POLICY.target.netlifySiteId],
    restoreCapabilityVerified: true, productionAccess: false, secretValuesSerialized: false,
    verifiedAt: createdAt, expiresAt };
  const actualReadinessSha = await prerequisite('ROLLBACK_READINESS', readinessValue);
  const gateValue = { schemaVersion: 1, evidenceType: 'cnyos_staging_controller_draft_gate',
    authorization: false, promotionAuthorization: false, productionAuthorization: false, scope: 'cnyos_staging_only',
    controllerRepository: runtime.repository, controllerRef: runtime.ref, controllerCommit: runtime.commit,
    controllerRunId: runtime.runId, dispatchNonce: runtimeEnv.CNYOS_DISPATCH_NONCE,
    source, artifact, previousDeployId: previous, target: POLICY.target,
    preflightEvidenceSha256: actualPreflightSha, rollbackReadinessEvidenceSha256: actualReadinessSha,
    checkedAt: createdAt, deployMessage };
  await prerequisite('DRAFT_GATE', gateValue);
  const loaded = await mod.loadDraftMutationContext({ env: prerequisiteEnv, now: () => now,
    bundleVerifier: async () => context.bundle });
  assert.equal(loaded.preflight.sha256, actualPreflightSha);
  assert.equal(loaded.readiness.sha256, actualReadinessSha);
  await assert.rejects(mod.loadDraftMutationContext({ env: { ...prerequisiteEnv,
    CNYOS_DISPATCH_NONCE: Buffer.alloc(32, 8).toString('base64url') }, now: () => now,
    bundleVerifier: async () => context.bundle }), /SOURCE_BINDING_INVALID/);
  await prerequisite('DRAFT_GATE', { ...gateValue, deployMessage: 'unowned' });
  await assert.rejects(mod.loadDraftMutationContext({ env: prerequisiteEnv, now: () => now,
    bundleVerifier: async () => context.bundle }), /DRAFT_GATE_EVIDENCE_INVALID/);
  await prerequisite('DRAFT_GATE', gateValue);
  await prerequisite('ROLLBACK_READINESS', { ...readinessValue, restoreCapabilityVerified: false });
  await assert.rejects(mod.loadDraftMutationContext({ env: prerequisiteEnv, now: () => now,
    bundleVerifier: async () => context.bundle }), /ROLLBACK_READINESS_EVIDENCE_INVALID/);
  await prerequisite('ROLLBACK_READINESS', readinessValue);
  let index = 0;
  async function fixture() {
    const dir = path.join(tmp, `run-${++index}`); await fs.mkdir(dir);
    return { ...runtimeEnv, CNYOS_DRAFT_LIFECYCLE_BROKER_URL: `${trustPolicy.origin}${trustPolicy.operationPath}`,
      CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH: path.join(dir, 'draft-intent.json'),
      CNYOS_NETLIFY_CLI_RECEIPT_PATH: path.join(dir, 'cli-receipt.json'),
      CNYOS_NETLIFY_CLI_PATH: path.join(controller, 'node_modules/.bin/netlify'),
      CNYOS_NETLIFY_CLI_VERSION: '99.0.0' };
  }
  function envelope(request, mutate = () => {}) {
    const e = request.evidence;
    const result = { status: 'recorded', target: request.target, intentId: 'intent-fixture-1',
      intentGeneration: 'intent-generation-1', source: e.source, artifact: e.artifact,
      previousDeployId: e.previousDeployId, principalSubject: e.principalSubject, ownershipMarker: e.ownershipMarker,
      producerManifestSha256: e.producerManifestSha256, preflightEvidenceSha256: e.preflightEvidenceSha256,
      draftGateEvidenceSha256: e.draftGateEvidenceSha256, rollbackReadinessEvidenceSha256: e.rollbackReadinessEvidenceSha256,
      durable: true, discoverableByRunAndNonce: true, ownershipMarkerLookupRequired: true,
      automaticReplayPermitted: false, cleanupOnPrePromotionFailureArmed: true,
      privateDraftBoundary: e.privateDraftBoundary, anonymousAccessDeniedBeforeCreation: true,
      anonymousFunctionAccessDeniedBeforeCreation: true, createdAt, expiresAt };
    mutate(result);
    const statement = { schemaVersion: 1, operationDomain: trustPolicy.operationDomain,
      operation: mod.DRAFT_INTENT_OPERATION, policyId: trustPolicy.policyId, policySha256: trustPolicy.policySha256,
      requestSha256: sha256(JSON.stringify(request)), issuedAt: createdAt, expiresAt, result };
    const signature = crypto.sign(null, Buffer.from(JSON.stringify(statement)), privateKey);
    return { schemaVersion: 1, evidenceType: 'cnyos_staging_reconciliation_broker_envelope', statement,
      brokerSignature: { algorithm: 'Ed25519', keyId: trustPolicy.signingKeyId,
        statementSha256: sha256(JSON.stringify(statement)), signatureBase64: signature.toString('base64'), signatureSha256: sha256(signature) } };
  }
  let brokerCalls = 0;
  function brokerFetch(mutate, responseMutate) {
    return async (url, init) => {
      brokerCalls++;
      assert.equal(String(url), `${trustPolicy.origin}${trustPolicy.operationPath}`);
      assert.equal(init.method, 'POST'); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
      assert.equal(init.headers.Authorization, `Bearer ${oidcToken}`);
      assert.equal(init.body.includes(oidcToken), false);
      const value = envelope(JSON.parse(init.body), mutate);
      const r = response(url, value); return responseMutate ? responseMutate(r, value) : r;
    };
  }
  async function record(env, mutate, responseMutate) {
    return mod.recordDraftIntent({ env, now: () => now, contextLoader: async () => context,
      oidcTokenProvider: async () => oidcToken, fetchImpl: brokerFetch(mutate, responseMutate) });
  }
  const env = await fixture();
  const recorded = await record(env);
  env.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256 = sha256(await fs.readFile(recorded.evidencePath));
  assert.equal(recorded.evidence.intentGeneration, 'intent-generation-1');
  assert.equal(recorded.evidence.brokerEnvelope.statement.result.target.barrierGeneration, null);
  assert.equal(JSON.stringify(recorded.evidence).includes(oidcToken), false);
  await mod.validateStoredDraftIntent({ env, context, now: () => now });
  for (const mutate of [
    r => { r.target = { ...r.target, controllerRunId: '222' }; },
    r => { r.target = { ...r.target, netlifySiteId: POLICY.productionDenylist.netlifySiteId }; },
    r => { r.target = { ...r.target, dispatchNonce: Buffer.alloc(32, 1).toString('base64url') }; },
    r => { r.target = { ...r.target, barrierGeneration: 'wrong-generation' }; },
    r => { r.principalSubject = 'other-publisher'; }, r => { r.intentGeneration = ''; },
    r => { r.source = { ...r.source, commit: '0'.repeat(40) }; }, r => { r.durable = false; },
    r => { r.automaticReplayPermitted = true; }, r => { r.anonymousFunctionAccessDeniedBeforeCreation = false; },
    r => { r.createdAt = '2029-01-01T00:00:00.000Z'; }, r => { r.expiresAt = now.toISOString(); },
    r => { r.extra = 'not in signed protocol'; }
  ]) {
    const bad = await fixture(); await assert.rejects(record(bad, mutate), /CNYOS_/);
    assert.equal(await absent(bad.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH), true);
  }
  for (const mutateResponse of [
    (_r, v) => response(`${trustPolicy.origin}/wrong`, v),
    (r) => { Object.defineProperty(r, 'redirected', { value: true }); return r; },
    (_r, v) => response(env.CNYOS_DRAFT_LIFECYCLE_BROKER_URL, v, { type: 'text/html' }),
    (_r, v) => { v.brokerSignature.signatureBase64 = Buffer.alloc(64).toString('base64');
      return response(env.CNYOS_DRAFT_LIFECYCLE_BROKER_URL, v); },
    (_r, v) => response(env.CNYOS_DRAFT_LIFECYCLE_BROKER_URL, null, { raw: JSON.stringify(v) + ' ' }),
    () => response(env.CNYOS_DRAFT_LIFECYCLE_BROKER_URL, null, { raw: 'x'.repeat(65537) })
  ]) await assert.rejects(record(await fixture(), undefined, mutateResponse), /CNYOS_/);
  const wrongUrl = await fixture(); wrongUrl.CNYOS_DRAFT_LIFECYCLE_BROKER_URL = 'https://other.example.invalid/';
  const beforeUrl = brokerCalls; await assert.rejects(record(wrongUrl), /BROKER_URL_INVALID/); assert.equal(brokerCalls, beforeUrl);
  for (const key of [...broker.OIDC_FORBIDDEN_ENVIRONMENT_NAMES, 'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) {
    await assert.rejects(record({ ...await fixture(), [key]: '' }), /CREDENTIAL_ISOLATION_INVALID/);
  }
  const publisherEnv = { ...env, CNYOS_STAGING_NETLIFY_AUTH_TOKEN: token, NETLIFY_AUTH_TOKEN: token };
  delete publisherEnv.CNYOS_DRAFT_LIFECYCLE_BROKER_URL;
  const apiCalls = [];
  const providerFetch = async (url, init) => {
    assert.equal(init.headers.Authorization, `Bearer ${token}`); apiCalls.push(String(url));
    if (String(url).endsWith('/user')) return response(url, { id: 'fixture-publisher' });
    const site = { id: POLICY.target.netlifySiteId, name: POLICY.target.netlifySiteName,
      ssl_url: POLICY.target.netlifyOrigin, published_deploy: { id: previous } };
    return response(url, String(url).includes('/sites?') ? [site] : site);
  };
  let cliCalls = 0;
  const execute = async (configuration, impl) => mod.deployFromIntent({ env: configuration,
    contextLoader: async () => context, now: () => now, fetchImpl: providerFetch,
    cliProvenanceVerifier: async () => ({ cliRealPath: '/synthetic/controller-cli.mjs' }),
    execFileImpl: (node, args, options) => {
      const beforeMutation = JSON.parse(readFileSync(`${configuration.CNYOS_NETLIFY_CLI_RECEIPT_PATH}.attempt.json`));
      assert.equal(beforeMutation.intentEvidenceSha256, configuration.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256);
      assert.equal(beforeMutation.status, 'outcome_unknown');
      assert.equal(beforeMutation.automaticReplayPermitted, false);
      cliCalls++;
      assert.equal(node, process.execPath); assert.equal(args.includes('--no-build'), true);
      assert.equal(args.includes('--prod'), false); assert.equal(args.includes('--skip-functions-cache'), true);
      assert.equal(args.includes('--auth'), false); assert.equal(args.includes(token), false);
      assert.equal(options.env.NETLIFY_AUTH_TOKEN, token); assert.equal(options.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
      assert.equal(options.cwd.startsWith(awaitFreeTempPrefix), true);
      return impl?.(args, options) ?? JSON.stringify({ deploy_id: deployed, site_id: POLICY.target.netlifySiteId,
        deploy_ssl_url: `https://${deployed}--cnyos.netlify.app` });
    } });
  const awaitFreeTempPrefix = path.join(await fs.realpath('/tmp'), 'cnyos-draft-cli-');
  const deployedResult = await execute(publisherEnv);
  assert.equal(deployedResult.deployId, deployed);
  const journal = JSON.parse(await fs.readFile(`${publisherEnv.CNYOS_NETLIFY_CLI_RECEIPT_PATH}.attempt.json`));
  assert.equal(journal.intentEvidenceSha256, publisherEnv.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256);
  assert.equal(journal.status, 'outcome_unknown'); assert.equal(journal.automaticReplayPermitted, false);
  const beforeReplay = cliCalls; await assert.rejects(execute(publisherEnv), /OUTPUT_ALREADY_EXISTS/); assert.equal(cliCalls, beforeReplay);
  for (const behavior of [() => { throw new Error('potentially accepted'); }, () => 'bad JSON',
    () => JSON.stringify({ deploy_id: previous, deploy_ssl_url: `https://${previous}--cnyos.netlify.app` })]) {
    const bad = await fixture(); await record(bad);
    bad.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256 = sha256(await fs.readFile(bad.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH));
    delete bad.CNYOS_DRAFT_LIFECYCLE_BROKER_URL; bad.CNYOS_STAGING_NETLIFY_AUTH_TOKEN = token;
    await assert.rejects(execute(bad, behavior), /CNYOS_DRAFT_/);
    assert.equal(await absent(bad.CNYOS_NETLIFY_CLI_RECEIPT_PATH), true);
    assert.equal(await absent(`${bad.CNYOS_NETLIFY_CLI_RECEIPT_PATH}.attempt.json`), false);
    const count = cliCalls; await assert.rejects(execute(bad), /OUTPUT_ALREADY_EXISTS/); assert.equal(cliCalls, count);
  }
  // Exercise lifecycle orchestration with real signed-intent verification and
  // provider binding. Content-chain validators have their own contract fixtures;
  // substitute only that composite here to isolate provider/probe bracketing.
  const lifecycle = await import(pathToFileURL(path.join(controller, 'scripts/verify-private-draft-lifecycle.mjs')));
  const lifecycleContext = { ...context, bundle: { ...context.bundle,
    manifest: { ...context.bundle.manifest, files: [{ path: 'payload/dist/index.html' }] } } };
  async function lifecycleFixture() {
    const configuration = await fixture(); await record(configuration);
    configuration.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256 = sha256(await fs.readFile(configuration.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH));
    delete configuration.CNYOS_DRAFT_LIFECYCLE_BROKER_URL;
    configuration.CNYOS_STAGING_NETLIFY_AUTH_TOKEN = token;
    configuration.CNYOS_PRIVATE_DRAFT_ACCESS_BOUNDARY_URL = policy.privateDraftAccessBoundary.origin;
    const dir = path.dirname(configuration.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH);
    configuration.CNYOS_CONTROLLER_PRIVATE_DRAFT_EVIDENCE_PATH = path.join(dir, 'private-lifecycle.json');
    const signedIntent = JSON.parse(await fs.readFile(configuration.CNYOS_CONTROLLER_DRAFT_INTENT_EVIDENCE_PATH));
    for (const kind of ['DRAFT_RECEIPT', 'DRAFT_ACCESS_BOUNDARY', 'DRAFT_VERIFICATION', 'DRAFT_METADATA', 'CONTROL_BEHAVIOR']) {
      const filename = path.join(dir, `${kind}.json`);
      const bytes = Buffer.from(JSON.stringify({ fixtureOnly: kind, ...(kind === 'DRAFT_RECEIPT' ? {
        draftIntentEvidenceSha256: configuration.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256,
        draftIntentId: signedIntent.intentId, draftIntentGeneration: signedIntent.intentGeneration,
        intentBindingScope: 'signed_intent_and_provider_ownership_marker'
      } : {}) }));
      await fs.writeFile(filename, bytes);
      configuration[`CNYOS_CONTROLLER_${kind}_EVIDENCE_PATH`] = filename;
      configuration[`CNYOS_EXPECTED_${kind}_EVIDENCE_SHA256`] = sha256(bytes);
    }
    return configuration;
  }
  async function runLifecycle(configuration, mutation = {}) {
    const events = []; let providerChecks = 0; let chainChecks = 0;
    if (mutation.wrongIntentGeneration) {
      const file = configuration.CNYOS_CONTROLLER_DRAFT_RECEIPT_EVIDENCE_PATH;
      const receipt = JSON.parse(await fs.readFile(file));
      receipt.draftIntentGeneration = 'wrong-generation';
      const bytes = Buffer.from(JSON.stringify(receipt));
      await fs.writeFile(file, bytes);
      configuration.CNYOS_EXPECTED_DRAFT_RECEIPT_EVIDENCE_SHA256 = sha256(bytes);
    }
    const evidencePromise = lifecycle.verifyPrivateDraftLifecycle({ env: configuration,
      now: () => now, contextLoader: async () => lifecycleContext,
      chainValidator: inputs => {
        chainChecks++; assert.equal(inputs.context, lifecycleContext);
        assert.equal(inputs.receipt.value.fixtureOnly, 'DRAFT_RECEIPT');
        return { deployId: deployed, previousDeployId: previous, origin: `https://${deployed}--cnyos.netlify.app` };
      }, fetchImpl: async (url, init) => {
        url = new URL(url);
        if (url.origin !== 'https://api.netlify.com') {
          events.push('anonymous'); assert.equal(init.headers.Authorization, undefined);
          assert.equal(init.headers.Cookie, undefined); assert.equal(init.credentials, 'omit');
          return response(url, null, { status: mutation.anonymousStatus || 403, type: 'text/html', raw: '<html>Private deployment</html>' });
        }
        assert.equal(init.headers.Authorization, `Bearer ${token}`);
        if (url.pathname.endsWith('/user')) return response(url, { id: mutation.principal || 'fixture-publisher' });
        if (url.pathname.endsWith(`/deploys/${deployed}`)) {
          events.push('deploy');
          return response(url, { id: deployed, site_id: POLICY.target.netlifySiteId, context: 'production',
            state: 'ready', draft: true, title: mutation.marker || deployMessage,
            deploy_ssl_url: `https://${deployed}--cnyos.netlify.app`,
            created_at: mutation.createdAt || now.toISOString() });
        }
        const isInventory = url.search !== '';
        if (!isInventory) { providerChecks++; events.push('site'); }
        const site = { id: POLICY.target.netlifySiteId, name: POLICY.target.netlifySiteName,
          ssl_url: POLICY.target.netlifyOrigin,
          published_deploy: { id: mutation.changedAfterProbes && providerChecks > 1 ? deployed : previous } };
        return response(url, isInventory ? [site] : site);
      } });
    if (Object.keys(mutation).length) {
      await assert.rejects(evidencePromise, /CNYOS_/);
      assert.equal(await absent(configuration.CNYOS_CONTROLLER_PRIVATE_DRAFT_EVIDENCE_PATH), true);
      return;
    }
    const result = await evidencePromise;
    assert.equal(chainChecks, 2); assert.equal(providerChecks, 2);
    assert.deepEqual(events.slice(0, 2), ['site', 'deploy']);
    assert.deepEqual(events.slice(-2), ['site', 'deploy']);
    assert.equal(result.evidence.anonymousProbeCount, events.filter(item => item === 'anonymous').length);
    assert.equal(result.evidence.draftIntentEvidenceSha256, configuration.CNYOS_EXPECTED_DRAFT_INTENT_EVIDENCE_SHA256);
    assert.equal(result.evidence.intentBindingScope, 'signed_intent_and_provider_ownership_marker');
    assert.equal(result.evidence.productionAuthorization, false);
    assert.equal(JSON.stringify(result.evidence).includes(token), false);
  }
  await runLifecycle(await lifecycleFixture());
  for (const mutation of [{ changedAfterProbes: true }, { principal: 'wrong-publisher' },
    { marker: 'unowned-draft' }, { createdAt: '2029-12-31T23:59:00.000Z' }, { anonymousStatus: 202 },
    { wrongIntentGeneration: true }]) {
    await runLifecycle(await lifecycleFixture(), mutation);
  }
  const cleanupPlan = { statement: { result: { recoveryDisposition: 'recovery_required', planCore: {
    target: { netlifySiteId: POLICY.target.netlifySiteId }, previousDeployId: previous, currentDeployId: previous,
    draftIntents: [{ intentId: 'intent-fixture-1', deployId: deployed, status: 'deploy_created', ownershipMarker: deployMessage }],
    orderedActions: [{ sequence: 1, kind: 'delete_run_owned_draft', siteId: POLICY.target.netlifySiteId,
      deployId: deployed, intentId: 'intent-fixture-1', requiredOwnershipMarker: deployMessage }] } } } };
  const cleanup = assertDraftOnlyRecoveryPlan(cleanupPlan);
  for (const mutate of [p => { p.currentDeployId = deployed; }, p => { p.orderedActions[0].kind = 'restore_previous_deploy'; },
    p => { p.orderedActions[0].deployId = previous; }, p => { p.draftIntents[0].ownershipMarker = 'unowned'; },
    p => { p.orderedActions[0].siteId = POLICY.productionDenylist.netlifySiteId; }]) {
    const bad = structuredClone(cleanupPlan); mutate(bad.statement.result.planCore);
    assert.throws(() => assertDraftOnlyRecoveryPlan(bad), /CNYOS_/);
  }
  let deletes = 0;
  const init = { method: 'DELETE', redirect: 'error', credentials: 'omit', headers: { Authorization: `Bearer ${token}` } };
  const deleteUrl = `https://api.netlify.com/api/v1/deploys/${deployed}`;
  const guard = draftCleanupFetchGuard(async (url, options) => {
    if (options.method === 'DELETE') { deletes++; return new Response(null, { status: 204 }); }
    return response(url, { id: POLICY.target.netlifySiteId, published_deploy: { id: previous } });
  }, cleanup);
  await guard(deleteUrl, init); assert.equal(deletes, 1);
  await assert.rejects(guard(deleteUrl, init), /TARGET_INVALID/); assert.equal(deletes, 1);
  const conflict = draftCleanupFetchGuard(async url => response(url, { id: POLICY.target.netlifySiteId,
    published_deploy: { id: deployed } }), cleanup);
  await assert.rejects(conflict(deleteUrl, init), /CURRENT_CONFLICT/);
  await assert.rejects(guard(deleteUrl, { ...init, method: 'POST' }), /REQUEST_BOUNDARY_INVALID/);
  await assert.rejects(guard('https://other.example.invalid/api/v1/deploys/' + deployed, init), /REQUEST_BOUNDARY_INVALID/);
  assert.equal(POLICY_SHA256, sha256(await fs.readFile(path.join(root, 'controller-policy.json'))));
  assert.notEqual(isolatedPolicy.POLICY_SHA256, POLICY_SHA256);
  process.stdout.write('CNYOS activation contract draft-mutation-recovery: passed\n');
} finally { await fs.rm(tmp, { recursive: true, force: true }); }
