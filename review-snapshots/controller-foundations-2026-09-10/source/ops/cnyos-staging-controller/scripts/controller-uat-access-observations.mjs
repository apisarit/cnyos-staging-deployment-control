// Pure comparison of supplied observations. No authentication, transport,
// mutation, evidence publication or controller activation occurs here.
export const UAT_ACCESS_ROLES = Object.freeze([
  'practitioner', 'doctor', 'reception', 'pharmacy', 'production', 'inventory',
  'quality', 'billing', 'admin', 'super_admin', 'viewer'
]);
export const UAT_DATABASE_CAPABILITIES = Object.freeze([
  'governance', 'patient_read', 'patient_registry', 'clinical', 'pharmacy',
  'product_read', 'product_write', 'inventory', 'production_read', 'production',
  'quality', 'billing'
]);
const grants = (...values) => Object.freeze(values);
export const UAT_EXPECTED_CAPABILITIES = Object.freeze({
  practitioner: grants('patient_read', 'patient_registry', 'clinical', 'product_read'),
  doctor: grants('patient_read', 'patient_registry', 'clinical', 'product_read'),
  reception: grants('patient_read', 'patient_registry'),
  pharmacy: grants('patient_read', 'pharmacy', 'product_read', 'product_write', 'inventory'),
  production: grants('product_read', 'product_write', 'inventory', 'production_read', 'production'),
  inventory: grants('product_read', 'product_write', 'inventory', 'production_read', 'production'),
  quality: grants('product_read', 'production_read', 'quality'),
  billing: grants('patient_read', 'billing'),
  admin: grants('governance'),
  super_admin: grants(...UAT_DATABASE_CAPABILITIES),
  viewer: grants()
});
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fail = code => { throw new Error(`CNYOS_UAT_ACCESS_${code}`); };
function roleKnown(role) {
  if (!UAT_ACCESS_ROLES.includes(role)) fail('ROLE_INVALID');
}
function targetKnown(target) {
  if (!record(target) || typeof target.clinicId !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(target.clinicId) ||
    typeof target.clinicCode !== 'string' || !target.clinicCode.length || target.clinicCode.length > 100) {
    fail('EXPECTED_TARGET_INVALID');
  }
}
export function assertUatAccessContext(role, response, target) {
  roleKnown(role);
  targetKnown(target);
  // current_access_context is a table-returning RPC. Never silently take row 0.
  if (!Array.isArray(response) || response.length !== 1 || !record(response[0])) fail('CONTEXT_CARDINALITY');
  const context = response[0];
  const clinicRole = ['admin', 'super_admin'].includes(role) ? 'viewer' : role;
  const systemRole = role === 'super_admin' ? 'super_admin' : role === 'admin' ? 'admin' : 'staff';
  if (context.clinic_id !== target.clinicId || context.clinic_code !== target.clinicCode) fail('CONTEXT_TARGET');
  if (context.clinic_role !== clinicRole || context.system_role !== systemRole ||
    context.effective_role !== role || context.ready !== true) fail('CONTEXT_ROLE_OR_READINESS');
  return Object.freeze({
    clinic_id: context.clinic_id, clinic_code: context.clinic_code,
    clinic_role: context.clinic_role, system_role: context.system_role,
    effective_role: context.effective_role, ready: context.ready
  });
}
export function assertUatCapabilityObservation(role, capability, observed) {
  roleKnown(role);
  if (!UAT_DATABASE_CAPABILITIES.includes(capability)) fail('CAPABILITY_INVALID');
  if (typeof observed !== 'boolean') fail('CAPABILITY_TYPE');
  if (observed !== UAT_EXPECTED_CAPABILITIES[role].includes(capability)) fail('CAPABILITY_MISMATCH');
  return observed;
}
export function evaluateUatAccessObservations(observations, target) {
  targetKnown(target);
  if (!Array.isArray(observations) || observations.length !== UAT_ACCESS_ROLES.length) fail('MATRIX_CARDINALITY');
  const seen = new Set();
  let contextCount = 0;
  let capabilityCount = 0;
  for (const observation of observations) {
    if (!record(observation) || Object.keys(observation).sort().join(',') !== 'capabilities,context,role') fail('OBSERVATION_SHAPE');
    const { role, context, capabilities } = observation;
    roleKnown(role);
    if (seen.has(role)) fail('DUPLICATE_ROLE');
    seen.add(role);
    assertUatAccessContext(role, context, target);
    contextCount++;
    if (!record(capabilities) || Object.keys(capabilities).sort().join(',') !== [...UAT_DATABASE_CAPABILITIES].sort().join(',')) fail('CAPABILITY_SET');
    for (const capability of UAT_DATABASE_CAPABILITIES) {
      assertUatCapabilityObservation(role, capability, capabilities[capability]);
      capabilityCount++;
    }
  }
  return Object.freeze({
    comparison: 'matches_expected_access_matrix', contextCount, capabilityCount,
    authorization: false, authenticatedIdentityVerified: false,
    crossTenantDenialsVerified: false, uatComplete: false
  });
}
