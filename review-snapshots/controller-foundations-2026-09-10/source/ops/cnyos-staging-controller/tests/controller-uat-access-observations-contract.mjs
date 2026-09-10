import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {
  UAT_ACCESS_ROLES as roles, UAT_DATABASE_CAPABILITIES as capabilities,
  UAT_EXPECTED_CAPABILITIES as grants, assertUatAccessContext,
  assertUatCapabilityObservation, evaluateUatAccessObservations
} from '../scripts/controller-uat-access-observations.mjs';

const target = { clinicId: '11111111-1111-4111-8111-111111111111', clinicCode: 'synthetic-only' };
const sentinel = 'PRIVATE_SENTINEL_TOKEN_EMAIL';
const clone = value => structuredClone(value);
function context(role) {
  return {
    clinic_id: target.clinicId, clinic_code: target.clinicCode,
    clinic_role: ['admin', 'super_admin'].includes(role) ? 'viewer' : role,
    system_role: role === 'super_admin' ? 'super_admin' : role === 'admin' ? 'admin' : 'staff',
    effective_role: role, ready: true
  };
}
function matrix() {
  return roles.map(role => ({ role, context: [context(role)],
    capabilities: Object.fromEntries(capabilities.map(cap => [cap, grants[role].includes(cap)])) }));
}
function rejects(change, code) {
  const observations = matrix();
  change(observations);
  const before = JSON.stringify(observations);
  assert.throws(() => evaluateUatAccessObservations(observations, target), error => {
    assert.equal(error.message, `CNYOS_UAT_ACCESS_${code}`);
    assert.ok(!error.message.includes(sentinel));
    return true;
  });
  assert.equal(JSON.stringify(observations), before);
}

// Read only the existing declarative policy, never load credentials or call a provider.
const support = fs.readFileSync(new URL('../../../scripts/staging-support.mjs', import.meta.url), 'utf8');
const policyStart = support.indexOf('export const STAGING_ROLES =');
const policyEnd = support.indexOf('export const WORKSPACE_ROUTES =');
assert.ok(policyStart > 0 && policyEnd > policyStart);
const policy = vm.runInNewContext(`${support.slice(policyStart, policyEnd).replaceAll('export const ', 'const ')}
  JSON.stringify({ STAGING_ROLES, DATABASE_CAPABILITIES, EXPECTED_DATABASE_CAPABILITIES })`);
assert.deepEqual(JSON.parse(policy), { STAGING_ROLES: roles, DATABASE_CAPABILITIES: capabilities,
  EXPECTED_DATABASE_CAPABILITIES: grants });

const observations = matrix();
const before = JSON.stringify(observations);
const summary = evaluateUatAccessObservations(observations, target);
assert.deepEqual(summary, {
  comparison: 'matches_expected_access_matrix', contextCount: 11, capabilityCount: 132,
  authorization: false, authenticatedIdentityVerified: false,
  crossTenantDenialsVerified: false, uatComplete: false
});
assert.ok(Object.isFrozen(summary));
assert.equal(JSON.stringify(observations), before);
assert.deepEqual(evaluateUatAccessObservations([...observations].reverse(), target), summary);
for (const value of [null, {}, [], matrix().slice(1), [...matrix(), matrix()[0]]]) {
  assert.throws(() => evaluateUatAccessObservations(value, target), /CNYOS_UAT_ACCESS_MATRIX_CARDINALITY/);
}
for (const invalid of [null, {}, { ...target, clinicId: 'invalid' }, { ...target, clinicCode: '' }]) {
  assert.throws(() => evaluateUatAccessObservations(matrix(), invalid), /CNYOS_UAT_ACCESS_EXPECTED_TARGET_INVALID/);
}
rejects(rows => { rows[1] = clone(rows[0]); }, 'DUPLICATE_ROLE');
rejects(rows => { rows[0].role = sentinel; }, 'ROLE_INVALID');
rejects(rows => { rows[0].extra = sentinel; }, 'OBSERVATION_SHAPE');
for (const invalid of [null, {}, [], [null], [context('practitioner'), context('practitioner')]]) {
  rejects(rows => { rows[0].context = invalid; }, 'CONTEXT_CARDINALITY');
}
for (const field of ['clinic_id', 'clinic_code']) {
  rejects(rows => { rows[0].context[0][field] = sentinel; }, 'CONTEXT_TARGET');
}
for (const field of ['clinic_role', 'system_role', 'effective_role', 'ready']) {
  rejects(rows => { rows[0].context[0][field] = sentinel; }, 'CONTEXT_ROLE_OR_READINESS');
}
rejects(rows => { rows[8].context[0].clinic_role = 'admin'; }, 'CONTEXT_ROLE_OR_READINESS');
rejects(rows => { rows[9].context[0].system_role = 'staff'; }, 'CONTEXT_ROLE_OR_READINESS');
rejects(rows => { delete rows[0].capabilities.governance; }, 'CAPABILITY_SET');
rejects(rows => { rows[0].capabilities.extra = false; }, 'CAPABILITY_SET');
for (const invalid of [null, 'false', 'true', 0, 1, [], {}]) {
  rejects(rows => { rows[0].capabilities.governance = invalid; }, 'CAPABILITY_TYPE');
}
rejects(rows => { rows[0].capabilities.clinical = false; }, 'CAPABILITY_MISMATCH');
rejects(rows => { rows[10].capabilities.clinical = true; }, 'CAPABILITY_MISMATCH');
assert.equal(assertUatCapabilityObservation('viewer', 'clinical', false), false);
assert.throws(() => assertUatCapabilityObservation('viewer', sentinel, false), /CNYOS_UAT_ACCESS_CAPABILITY_INVALID/);
const rawContext = { ...context('admin'), email: sentinel, user_id: sentinel, token: sentinel };
assert.deepEqual(assertUatAccessContext('admin', [rawContext], target), context('admin'));

// Execute the ACTUAL candidate read-phase source with injected in-memory transports.
// Exclude the health/mutation/browser phase entirely; no live verifier invocation.
const candidate = fs.readFileSync(new URL('../../../scripts/verify-authenticated-staging.mjs', import.meta.url), 'utf8');
const boundary = "const superSession = sessions.get('super_admin');";
assert.equal(candidate.split(boundary).length, 2);
let importCount = 0;
const readPhase = candidate.slice(0, candidate.indexOf(boundary)).replace(
  /^import[\s\S]*?from '[^']+';\n/gm, () => { importCount++; return ''; });
assert.equal(importCount, 5);
assert.ok(!/\bimport\b|fetch\(|requestJson\(|writeEvidence\(/.test(readPhase));
const script = new vm.Script(`(async () => { ${readPhase}
  return { roleResults, accessObservations }; })()`);
async function runReadPhase(alter = () => {}) {
  const calls = [];
  let comparisons = 0;
  const bindings = {
    STAGING_ROLES: roles, DATABASE_CAPABILITIES: capabilities,
    loadStagingTarget: () => ({ config: { tenant: {
      expectedClinicId: target.clinicId, expectedClinicCode: target.clinicCode
    } } }),
    loadStagingCredentials: () => Object.freeze({}),
    signInStagingRole: async (_target, role) => {
      calls.push(['signIn', role]);
      return { session: { access_token: role, user: { id: sentinel } }, identity: { email: sentinel } };
    },
    rpc: async (_target, role, name, args) => {
      calls.push(['rpc', role, name, args]);
      let value;
      if (name === 'current_access_context') value = [{ ...context(role), extra: sentinel }];
      else {
        assert.equal(name, 'department_can');
        assert.deepEqual(Object.keys(args), ['p_capability']);
        value = grants[role].includes(args.p_capability);
      }
      const changed = { value };
      alter(changed, role, name, args);
      return changed.value;
    },
    assertUatAccessContext, assertUatCapabilityObservation,
    evaluateUatAccessObservations: (rows, expected) => {
      comparisons++;
      return evaluateUatAccessObservations(rows, expected);
    }
  };
  try {
    const result = await script.runInContext(vm.createContext(bindings, {
      codeGeneration: { strings: false, wasm: false }
    }), { timeout: 1000 });
    return { result, calls, comparisons };
  } catch (error) { return { error, calls, comparisons }; }
}
const positive = await runReadPhase();
assert.equal(positive.error, undefined);
assert.equal(positive.comparisons, 1);
assert.equal(positive.result.roleResults.length, 11);
assert.deepEqual(JSON.parse(JSON.stringify(positive.result.accessObservations)), matrix());
const expectedCalls = roles.flatMap(role => [
  ['signIn', role], ['rpc', role, 'current_access_context', undefined],
  ...capabilities.map(cap => ['rpc', role, 'department_can', { p_capability: cap }])
]);
assert.deepEqual(JSON.parse(JSON.stringify(positive.calls)), JSON.parse(JSON.stringify(expectedCalls)));
assert.equal(positive.calls.filter(call => call[0] === 'rpc').length, 143);
assert.ok(!JSON.stringify(positive.result.accessObservations).includes(sentinel));
for (const contextValue of [[], [context('practitioner'), context('practitioner')]]) {
  const failed = await runReadPhase(value => { value.value = contextValue; });
  assert.equal(failed.error?.message, 'CNYOS_UAT_ACCESS_CONTEXT_CARDINALITY');
  assert.equal(failed.calls.length, 2);
  assert.equal(failed.comparisons, 0);
}
for (const observed of [null, 'false', 0]) {
  const failed = await runReadPhase((value, _role, name) => {
    if (name === 'department_can') value.value = observed;
  });
  assert.equal(failed.error?.message, 'CNYOS_UAT_ACCESS_CAPABILITY_TYPE');
  assert.equal(failed.calls.length, 3);
  assert.equal(failed.comparisons, 0);
}
console.log('CNYOS UAT access observation comparison contract: passed');
