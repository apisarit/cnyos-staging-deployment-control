import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  EXACT_STAGING_PRODUCTION_DENYLIST,
  EXACT_STAGING_TARGET,
  loadExactStagingConfig,
  sha256,
  verifyExactStagingArtifact,
  writeFresh0600
} from './exact-staging-release.mjs';

const EXPECTED_DATABASE_HOST = `db.${EXACT_STAGING_TARGET.supabaseProjectRef}.supabase.co`;
const EXPECTED_SESSION_POOLER_HOST = 'aws-0-ap-southeast-1.pooler.supabase.com';
const EXPECTED_SYSTEM_IDENTIFIER = '7666007964130682852';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FORWARD_WRAPPER = '20261013230000_staging_forward_reconciliation_ce4cee52.psql';
const FORWARD_VERIFIER = '20261013230000_staging_forward_reconciliation_verify.sql';
const AUDIT_MIGRATION = '20261017005000_audit_logs_governance_admin_read.sql';
const CLEANUP_SQL = 'cnyos-staging-partial-backup-replay-cleanup.sql';
const CLEANUP_SHA256 = 'd9c89e85d740b8d5fc0d7542d033688dca090f07083f8dd41d1c84c6821e7d15';
const CLEANUP_PATH = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'sql',
  CLEANUP_SQL);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

export function parseExactStagingDatabaseUrl(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.length > 8192 || EXACT_STAGING_PRODUCTION_DENYLIST.supabaseProjectRefs
    .some(ref => raw.toLowerCase().includes(ref))) {
    fail('CNYOS_EXACT_STAGING_DATABASE_URL_INVALID');
  }
  let parsed;
  try { parsed = new URL(raw); } catch { fail('CNYOS_EXACT_STAGING_DATABASE_URL_INVALID'); }
  const query = [...parsed.searchParams.entries()];
  const username = decodeURIComponent(parsed.username);
  const direct = parsed.hostname === EXPECTED_DATABASE_HOST && username === 'postgres';
  const sessionPooler = parsed.hostname === EXPECTED_SESSION_POOLER_HOST &&
    username === `postgres.${EXACT_STAGING_TARGET.supabaseProjectRef}`;
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol) ||
    (!direct && !sessionPooler) || parsed.port !== '5432' ||
    parsed.pathname !== '/postgres' || !parsed.password || parsed.hash ||
    query.length !== 1 || query[0][0] !== 'sslmode' || query[0][1] !== 'require') {
    fail('CNYOS_EXACT_STAGING_DATABASE_URL_INVALID');
  }
  return Object.freeze({
    PGHOST: parsed.hostname,
    PGPORT: '5432',
    PGDATABASE: 'postgres',
    PGUSER: username,
    PGPASSWORD: decodeURIComponent(parsed.password),
    PGSSLMODE: 'require'
  });
}

function commandEvidence(result) {
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
  return Object.freeze({
    exitCode: Number.isInteger(result.status) ? result.status : null,
    signal: typeof result.signal === 'string' ? result.signal : null,
    stdoutBytes: stdout.length,
    stdoutSha256: stdout.length ? sha256(stdout) : null,
    stderrBytes: stderr.length,
    stderrSha256: stderr.length ? sha256(stderr) : null
  });
}

function runPsql(args, { databaseDirectory, pgEnvironment, input, spawnImpl }) {
  const result = spawnImpl('psql', ['-X', '--no-password', '--set=ON_ERROR_STOP=1', ...args], {
    cwd: databaseDirectory,
    env: {
      PATH: String(process.env.PATH || ''),
      ...pgEnvironment
    },
    encoding: null,
    input,
    maxBuffer: 2 * 1024 * 1024,
    timeout: 120_000,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  return { result, evidence: commandEvidence(result) };
}

function auditPolicyChecks() {
  return String.raw`
  if current_database() <> 'postgres'
     or current_setting('server_version_num')::integer / 10000 <> 17
     or (select system_identifier::text from pg_control_system()) <> '${EXPECTED_SYSTEM_IDENTIFIER}' then
    raise exception 'CNYOS_AUDIT_VERIFY_DATABASE_IDENTITY_MISMATCH';
  end if;
  if exists (select 1 from pg_policies where schemaname='public' and tablename='audit_logs'
    and policyname in ('audit_read_admin','audit_insert_authenticated')) then
    raise exception 'CNYOS_AUDIT_VERIFY_OBSOLETE_POLICY_PRESENT';
  end if;
  if (select count(*) from pg_policy where polrelid='public.audit_logs'::regclass) <> 3
     or (select count(*) from pg_policy where polrelid='public.audit_logs'::regclass
          and polname=any(array['audit_logs_tenant_boundary',
            'cnyos_active_subscription_boundary','audit_read_governance_admin'])) <> 3
     or (select count(*) from pg_policy where polrelid='public.audit_logs'::regclass
          and polname='audit_logs_tenant_boundary' and polcmd='*' and not polpermissive
          and polroles=array[(select oid from pg_roles where rolname='authenticated')]
          and pg_get_expr(polqual,polrelid) =
            $tenant$((clinic_id IS NOT NULL) AND is_clinic_member(clinic_id))$tenant$
          and pg_get_expr(polwithcheck,polrelid) =
            $tenant$((clinic_id IS NOT NULL) AND is_clinic_member(clinic_id))$tenant$) <> 1
     or (select count(*) from pg_policy where polrelid='public.audit_logs'::regclass
          and polname='cnyos_active_subscription_boundary' and polcmd='*'
          and not polpermissive
          and polroles=array[(select oid from pg_roles where rolname='authenticated')]
          and pg_get_expr(polqual,polrelid) =
            $subscription$(current_clinic_id() IS NOT NULL)$subscription$
          and pg_get_expr(polwithcheck,polrelid) =
            $subscription$(current_clinic_id() IS NOT NULL)$subscription$) <> 1 then
    raise exception 'CNYOS_AUDIT_VERIFY_POLICY_INVENTORY_INVALID';
  end if;
  select pg_get_expr(polqual, polrelid) into v_qual from pg_policy
    where polrelid='public.audit_logs'::regclass and polname='audit_read_governance_admin';
  if v_qual is distinct from
    $governance$((( SELECT current_user_role() AS current_user_role) = ANY (ARRAY['governance_admin'::text, 'super_admin'::text])) AND (clinic_id = ( SELECT current_clinic_id() AS current_clinic_id)) AND ( SELECT is_clinic_member(current_clinic_id()) AS is_clinic_member))$governance$ then
    raise exception 'CNYOS_AUDIT_VERIFY_POLICY_INVALID';
  end if;
  if (select count(*) from pg_policy where polrelid='public.audit_logs'::regclass
          and polname='audit_read_governance_admin' and polcmd='r' and polpermissive
          and polroles=array[(select oid from pg_roles where rolname='authenticated')]
          and polwithcheck is null) <> 1 then
    raise exception 'CNYOS_AUDIT_VERIFY_POLICY_SHAPE_INVALID';
  end if;
  if not (select relrowsecurity from pg_class where oid='public.audit_logs'::regclass)
     or (select relforcerowsecurity from pg_class where oid='public.audit_logs'::regclass)
     or not has_table_privilege('authenticated','public.audit_logs','SELECT')
     or has_table_privilege('authenticated','public.audit_logs','INSERT')
     or has_table_privilege('authenticated','public.audit_logs','UPDATE')
     or has_table_privilege('authenticated','public.audit_logs','DELETE')
     or has_table_privilege('authenticated','public.audit_logs','TRUNCATE')
     or has_table_privilege('authenticated','public.audit_logs','REFERENCES')
     or has_table_privilege('authenticated','public.audit_logs','TRIGGER') then
    raise exception 'CNYOS_AUDIT_VERIFY_WRITE_BOUNDARY_INVALID';
  end if;`;
}

// Bind an audit receipt to the exact post-migration authorization surface that
// it attests.  pg_get_expr output is stable because the database identity gate
// above fixes PostgreSQL major 17, and every input line is sorted before the
// digest is calculated.  Include both the stored ACL and effective privileges
// for authenticated so an inherited or direct write grant cannot hide behind
// an otherwise identical policy inventory.
function auditSurfaceFingerprintInto(variableName) {
  return String.raw`
  select encode(digest(convert_to(string_agg(line,E'\n' order by line),'UTF8'),
    'sha256'),'hex')
    into ${variableName}
  from (
    select concat_ws('|','REL','public','audit_logs',c.relrowsecurity::text,
      c.relforcerowsecurity::text,pg_get_userbyid(c.relowner),
      coalesce((select string_agg(acl::text,',' order by acl::text)
        from unnest(c.relacl) acl),'<NULL>')) as line
    from pg_class c where c.oid='public.audit_logs'::regclass
    union all
    select concat_ws('|','POL','public','audit_logs',p.polname,
      p.polpermissive::text,p.polcmd,
      coalesce((select string_agg(r.rolname,',' order by r.rolname)
        from unnest(p.polroles) role_oid
        join pg_roles r on r.oid=role_oid),'<NONE>'),
      coalesce(pg_get_expr(p.polqual,p.polrelid),'<NULL>'),
      coalesce(pg_get_expr(p.polwithcheck,p.polrelid),'<NULL>')) as line
    from pg_policy p where p.polrelid='public.audit_logs'::regclass
    union all
    select concat_ws('|','ACL_EFFECTIVE','public','audit_logs','authenticated',
      has_table_privilege('authenticated','public.audit_logs','SELECT')::text,
      has_table_privilege('authenticated','public.audit_logs','INSERT')::text,
      has_table_privilege('authenticated','public.audit_logs','UPDATE')::text,
      has_table_privilege('authenticated','public.audit_logs','DELETE')::text,
      has_table_privilege('authenticated','public.audit_logs','TRUNCATE')::text,
      has_table_privilege('authenticated','public.audit_logs','REFERENCES')::text,
      has_table_privilege('authenticated','public.audit_logs','TRIGGER')::text) as line
  ) audit_surface;
  if ${variableName} is null or ${variableName} !~ '^[0-9a-f]{64}$' then
    raise exception 'CNYOS_AUDIT_VERIFY_SURFACE_FINGERPRINT_INVALID';
  end if;`;
}

function auditReceiptSql(config, forwardAttemptId, auditAttemptId, migrationSha256) {
  return String.raw`
begin;
do $cnyos$
declare
  v_qual text;
  v_audit_surface_fingerprint text;
begin
${auditPolicyChecks()}
${auditSurfaceFingerprintInto('v_audit_surface_fingerprint')}
  if (select count(*) from cnyos_internal.staging_reconciliation_receipts
      where attempt_id='${forwardAttemptId}'::uuid
        and project_ref='${EXACT_STAGING_TARGET.supabaseProjectRef}'
        and system_identifier='${EXPECTED_SYSTEM_IDENTIFIER}'
        and app_commit='${config.appCommit}' and app_tree='${config.appTree}') <> 1 then
    raise exception 'CNYOS_AUDIT_VERIFY_FORWARD_RECEIPT_MISSING';
  end if;
  insert into cnyos_internal.staging_reconciliation_receipts
    (attempt_id,project_ref,system_identifier,source_tree,app_commit,app_tree,
     artifact_sha256,catalog_fingerprint,schema_version,applied_by,session_role,
     applied_transaction_id)
  select '${auditAttemptId}'::uuid,project_ref,system_identifier,source_tree,app_commit,app_tree,
    '${migrationSha256}',v_audit_surface_fingerprint,schema_version,session_user,current_role,
    txid_current()
  from cnyos_internal.staging_reconciliation_receipts
  where attempt_id='${forwardAttemptId}'::uuid and app_commit='${config.appCommit}'
    and app_tree='${config.appTree}'
  on conflict (attempt_id) do nothing;
end
$cnyos$;
commit;`;
}

function databaseIdentitySql(selectSql) {
  return String.raw`do $cnyos$
begin
  if current_database() <> 'postgres'
     or current_setting('server_version_num')::integer / 10000 <> 17
     or (select system_identifier::text from pg_control_system()) <> '${EXPECTED_SYSTEM_IDENTIFIER}' then
    raise exception 'CNYOS_DATABASE_IDENTITY_MISMATCH';
  end if;
end
$cnyos$;
${selectSql}`;
}

function cleanupMarkerProbeSql() {
  return databaseIdentitySql(String.raw`
select (
  (select count(*) from unnest(array[
    'spa_services','spa_service_prices','spa_appointment_bindings',
    'spa_service_sessions','spa_session_events','clinical_consult_requests',
    'clinical_consult_events','inpatient_admissions','inpatient_clinical_entries',
    'inpatient_admission_events','inpatient_admission_replays'
  ]::text[]) target(name) where to_regclass('public.' || target.name) is not null)
  +
  (select count(*) from (values
    ('export_clinic_backup_domain_v20260901(uuid,text)'),
    ('verify_clinic_restore_trace_v20260901(uuid)')
  ) target(signature) where to_regprocedure('public.' || target.signature) is not null)
  +
  (select count(*) from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.proname=any(array[
        'append_ipd_clinical_entry','assert_assigned_clinical_encounter',
        'book_spa_appointment','complete_spa_session',
        'create_clinical_consult_request','create_ipd_admission_request',
        'create_spa_service','enforce_spa_service_price_non_overlap',
        'export_clinic_backup_domain_v20260901',
        'get_clinical_consult_request','get_ipd_admission',
        'guard_spa_appointment_completion','guard_spa_invoice_source',
        'issue_atomic_spa_invoice','list_clinical_consult_queue',
        'list_clinical_consult_receivers','list_ipd_admission_queue',
        'list_ipd_attending_candidates','list_spa_billing_routes',
        'list_spa_services','list_spa_work_queue','quote_spa_session',
        'read_spa_invoice_evidence','reject_clinical_consult_event_mutation',
        'reject_inpatient_append_only_mutation',
        'reject_prescription_after_active_invoice',
        'reject_spa_session_event_mutation','save_spa_session_draft',
        'set_invoice_clinic_id','set_invoice_item_clinic_id',
        'set_spa_service_price','spa_actor_allowed',
        'sync_spa_session_cancellation','sync_spa_session_encounter',
        'transition_clinical_consult_request','transition_ipd_admission',
        'export_clinic_backup_domain_v20260901',
        'verify_clinic_restore_trace_v20260901'
      ]::text[]))
  +
  (select count(*) from (values
    ('invoices','clinic_id'),('invoices','spa_session_id'),
    ('invoices','spa_hourly_rate_snapshot'),('invoices','spa_actual_minutes'),
    ('invoices','spa_request_fingerprint'),('invoice_items','clinic_id'),
    ('invoice_items','spa_session_id'),('invoice_items','spa_service_id'),
    ('invoice_items','spa_hourly_rate_snapshot'),('invoice_items','spa_actual_minutes')
  ) target(table_name,column_name) where exists (
    select 1 from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid=a.attrelid
    join pg_catalog.pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relname=target.table_name
      and a.attname=target.column_name and a.attnum>0 and not a.attisdropped
  ))
  + (select count(*) from pg_catalog.pg_namespace where nspname='cnyos_internal')
  + (select count(*) from supabase_migrations.schema_migrations
      where version::text=any(array[
        '20261012165506','20261013100000','20261013130000',
        '20261013210000','20261013220000','20261013230000'
      ]::text[]))
)::text;`);
}

function auditVerifierSql(config, auditAttemptId, migrationSha256) {
  return String.raw`
do $cnyos$
declare
  v_qual text;
  v_audit_surface_fingerprint text;
begin
${auditPolicyChecks()}
${auditSurfaceFingerprintInto('v_audit_surface_fingerprint')}
  if (select count(*) from cnyos_internal.staging_reconciliation_receipts
      where attempt_id='${auditAttemptId}'::uuid
        and project_ref='${EXACT_STAGING_TARGET.supabaseProjectRef}'
        and system_identifier='${EXPECTED_SYSTEM_IDENTIFIER}'
        and app_commit='${config.appCommit}' and app_tree='${config.appTree}'
        and artifact_sha256='${migrationSha256}'
        and catalog_fingerprint=v_audit_surface_fingerprint) <> 1 then
    raise exception 'CNYOS_AUDIT_VERIFY_DURABLE_RECEIPT_MISSING';
  end if;
end
$cnyos$;
select json_build_object('status','PASS','project_ref','${EXACT_STAGING_TARGET.supabaseProjectRef}',
  'system_identifier','${EXPECTED_SYSTEM_IDENTIFIER}',
  'attempt_id','${auditAttemptId}',
  'catalog_fingerprint',(select catalog_fingerprint
    from cnyos_internal.staging_reconciliation_receipts
    where attempt_id='${auditAttemptId}'::uuid),
  'policy','audit_read_governance_admin')::text;
`;
}

export async function reconcileExactStagingDatabase(config, databaseUrl, {
  spawnImpl = spawnSync,
  now = () => new Date().toISOString(),
  attemptId = crypto.randomUUID(),
  auditAttemptId = crypto.randomUUID()
} = {}) {
  if (!UUID.test(attemptId) || !UUID.test(auditAttemptId) || attemptId === auditAttemptId) {
    fail('CNYOS_EXACT_STAGING_DATABASE_ATTEMPT_ID_INVALID');
  }
  const startedAt = now();
  const pgEnvironment = parseExactStagingDatabaseUrl(databaseUrl);
  const verified = await verifyExactStagingArtifact(config);
  const artifactHash = verified.reconciliationManifest.artifactSha256;
  const auditMigrationSha256 = verified.databaseManifest.files.find(
    item => item.path === AUDIT_MIGRATION).sha256;
  const phases = {};
  let forwardAttemptId = attemptId;
  let resolvedAuditAttemptId = auditAttemptId;
  let terminalStatus = 'FAIL';
  let terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_RECONCILIATION_INCOMPLETE';
  try {
    const cleanupBytes = await fs.readFile(CLEANUP_PATH).catch(() => null);
    if (!cleanupBytes || sha256(cleanupBytes) !== CLEANUP_SHA256) {
      terminalCode = 'CNYOS_EXACT_STAGING_CLEANUP_ARTIFACT_INVALID';
      fail(terminalCode);
    }
    const receiptProbe = runPsql(['-At', '-c', databaseIdentitySql(
      `select case when to_regclass('cnyos_internal.staging_reconciliation_receipts') ` +
      `is not null then 'true' else 'false' end;`)], {
      databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
    });
    phases.receiptProbe = receiptProbe.evidence;
    if (receiptProbe.result.status !== 0) {
      terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_IDENTITY_PROBE_FAILED';
      fail(terminalCode);
    }
    const forwardTablePresent = Buffer.from(receiptProbe.result.stdout || '')
      .toString('utf8').trim();
    if (!['true', 'false'].includes(forwardTablePresent)) {
      terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_RECEIPT_PROBE_INVALID';
      fail(terminalCode);
    }

    let forwardAlreadyApplied = false;
    if (forwardTablePresent === 'false') {
      const cleanupProbe = runPsql(['-At', '-c', cleanupMarkerProbeSql()], {
        databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
      });
      phases.cleanupProbe = cleanupProbe.evidence;
      if (cleanupProbe.result.status !== 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_CLEANUP_PROBE_FAILED';
        fail(terminalCode);
      }
      const markerCount = Buffer.from(cleanupProbe.result.stdout || '')
        .toString('utf8').trim();
      if (markerCount === '4') {
        const cleanupEnvironment = {
          ...pgEnvironment,
          PGOPTIONS: `-c cnyos.staging_cleanup_project_ref=${EXACT_STAGING_TARGET.supabaseProjectRef}`
        };
        const escapedCleanupPath = CLEANUP_PATH.replaceAll("'", "''");
        const cleanupPreflight = runPsql(['-f', '-'], {
          databaseDirectory: config.databaseDirectory,
          pgEnvironment: cleanupEnvironment,
          input: `begin;\n\\ir '${escapedCleanupPath}'\nrollback;\n`,
          spawnImpl
        });
        phases.cleanupPreflight = cleanupPreflight.evidence;
        if (cleanupPreflight.result.status !== 0) {
          terminalCode = 'CNYOS_EXACT_STAGING_CLEANUP_PREFLIGHT_FAILED';
          fail(terminalCode);
        }
        const cleanupApply = runPsql(['-f', CLEANUP_PATH], {
          databaseDirectory: config.databaseDirectory,
          pgEnvironment: cleanupEnvironment,
          spawnImpl
        });
        phases.cleanupApply = cleanupApply.evidence;
        if (cleanupApply.result.status !== 0) {
          terminalCode = 'CNYOS_EXACT_STAGING_CLEANUP_APPLY_FAILED';
          fail(terminalCode);
        }
      } else if (markerCount !== '0') {
        terminalCode = 'CNYOS_EXACT_STAGING_CLEANUP_UNKNOWN_DRIFT';
        fail(terminalCode);
      }
    }
    if (forwardTablePresent === 'true') {
      const priorForward = runPsql(['-At', '-c', databaseIdentitySql(
        `select coalesce(string_agg(attempt_id::text,',' order by attempt_id::text),'') ` +
        `from cnyos_internal.staging_reconciliation_receipts ` +
        `where project_ref='${EXACT_STAGING_TARGET.supabaseProjectRef}' ` +
        `and system_identifier='${EXPECTED_SYSTEM_IDENTIFIER}' ` +
        `and app_commit='${config.appCommit}' and app_tree='${config.appTree}' ` +
        `and artifact_sha256='${artifactHash}';`)], {
        databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
      });
      phases.priorForwardReceipt = priorForward.evidence;
      if (priorForward.result.status !== 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_PRIOR_RECEIPT_VERIFY_FAILED';
        fail(terminalCode);
      }
      const ids = Buffer.from(priorForward.result.stdout || '').toString('utf8').trim()
        .split(',').filter(Boolean);
      if (ids.length === 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_FOREIGN_RECEIPT_STATE';
        fail(terminalCode);
      }
      if (ids.length !== 1 || !UUID.test(ids[0])) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_PRIOR_RECEIPT_INVALID';
        fail(terminalCode);
      }
      forwardAttemptId = ids[0];
      forwardAlreadyApplied = true;

      const priorForwardVerifyInput = `\\set ON_ERROR_STOP on\n\\o /dev/null\n` +
        `select pg_catalog.set_config('cnyos.staging_reconciliation_project_ref',` +
        `'${EXACT_STAGING_TARGET.supabaseProjectRef}',false);\n` +
        `select pg_catalog.set_config('cnyos.staging_reconciliation_attempt_id',` +
        `'${forwardAttemptId}',false);\n` +
        `select pg_catalog.set_config('cnyos.staging_reconciliation_app_commit',` +
        `'${config.appCommit}',false);\n` +
        `select pg_catalog.set_config('cnyos.staging_reconciliation_app_tree',` +
        `'${config.appTree}',false);\n` +
        `select pg_catalog.set_config('cnyos.staging_reconciliation_artifact_sha256',` +
        `'${artifactHash}',false);\n\\o\n\\ir ${FORWARD_VERIFIER}\n`;
      const priorForwardVerify = runPsql(['-f', '-'], {
        databaseDirectory: config.databaseDirectory, pgEnvironment,
        input: priorForwardVerifyInput, spawnImpl
      });
      phases.priorForwardVerify = priorForwardVerify.evidence;
      if (priorForwardVerify.result.status !== 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_PRIOR_FORWARD_VERIFY_FAILED';
        fail(terminalCode);
      }

      const priorAuditReceipt = runPsql(['-At', '-c', databaseIdentitySql(
        `select coalesce(string_agg(attempt_id::text,',' order by attempt_id::text),'') ` +
        `from cnyos_internal.staging_reconciliation_receipts ` +
        `where project_ref='${EXACT_STAGING_TARGET.supabaseProjectRef}' ` +
        `and system_identifier='${EXPECTED_SYSTEM_IDENTIFIER}' ` +
        `and app_commit='${config.appCommit}' and app_tree='${config.appTree}' ` +
        `and artifact_sha256='${auditMigrationSha256}';`)], {
        databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
      });
      phases.priorAuditReceipt = priorAuditReceipt.evidence;
      if (priorAuditReceipt.result.status !== 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_PRIOR_AUDIT_RECEIPT_VERIFY_FAILED';
        fail(terminalCode);
      }
      const priorAuditIds = Buffer.from(priorAuditReceipt.result.stdout || '')
        .toString('utf8').trim().split(',').filter(Boolean);
      if (priorAuditIds.length > 1 || (priorAuditIds.length === 1 &&
        !UUID.test(priorAuditIds[0]))) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_PRIOR_AUDIT_RECEIPT_INVALID';
        fail(terminalCode);
      }
      if (priorAuditIds.length === 1) {
        resolvedAuditAttemptId = priorAuditIds[0];
        const priorAuditVerify = runPsql(['-c', auditVerifierSql(config,
          resolvedAuditAttemptId, auditMigrationSha256)], {
          databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
        });
        phases.priorAuditVerify = priorAuditVerify.evidence;
        if (priorAuditVerify.result.status !== 0) {
          terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_PRIOR_AUDIT_VERIFY_FAILED';
          fail(terminalCode);
        }
        terminalStatus = 'PASS';
        terminalCode = 'PRIOR_APPLIED_VERIFIED';
      }
    }

    if (terminalStatus !== 'PASS' && !forwardAlreadyApplied) {
      const forwardApply = runPsql([
      '-v', `cnyos_attempt_id=${attemptId}`,
      '-v', `cnyos_app_commit=${config.appCommit}`,
      '-v', `cnyos_app_tree=${config.appTree}`,
      '-f', FORWARD_WRAPPER
    ], { databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl });
    phases.forwardApply = forwardApply.evidence;
    if (forwardApply.result.status !== 0) {
      terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_FORWARD_APPLY_FAILED';
      fail(terminalCode);
    }

      const forwardVerifyInput = `\\set ON_ERROR_STOP on\n\\o /dev/null\n` +
      `select pg_catalog.set_config('cnyos.staging_reconciliation_project_ref',` +
      `'${EXACT_STAGING_TARGET.supabaseProjectRef}',false);\n` +
      `select pg_catalog.set_config('cnyos.staging_reconciliation_attempt_id',` +
      `'${attemptId}',false);\n` +
      `select pg_catalog.set_config('cnyos.staging_reconciliation_app_commit',` +
      `'${config.appCommit}',false);\n` +
      `select pg_catalog.set_config('cnyos.staging_reconciliation_app_tree',` +
      `'${config.appTree}',false);\n` +
      `select pg_catalog.set_config('cnyos.staging_reconciliation_artifact_sha256',` +
      `'${artifactHash}',false);\n\\o\n\\ir ${FORWARD_VERIFIER}\n`;
      const forwardVerify = runPsql(['-f', '-'], {
      databaseDirectory: config.databaseDirectory, pgEnvironment,
      input: forwardVerifyInput, spawnImpl
    });
      phases.forwardVerify = forwardVerify.evidence;
      if (forwardVerify.result.status !== 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_FORWARD_VERIFY_FAILED';
        fail(terminalCode);
      }
    }

    if (terminalStatus !== 'PASS') {
      const auditApply = runPsql(['-f', AUDIT_MIGRATION], {
      databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
    });
    phases.auditApply = auditApply.evidence;
    if (auditApply.result.status !== 0) {
      terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_AUDIT_APPLY_FAILED';
      fail(terminalCode);
    }
      const auditReceipt = runPsql(['-c', auditReceiptSql(config, forwardAttemptId,
      resolvedAuditAttemptId, auditMigrationSha256)], {
      databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
    });
    phases.auditReceipt = auditReceipt.evidence;
    if (auditReceipt.result.status !== 0) {
      terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_AUDIT_RECEIPT_FAILED';
      fail(terminalCode);
    }
      const auditVerify = runPsql(['-c', auditVerifierSql(config,
      resolvedAuditAttemptId, auditMigrationSha256)], {
      databaseDirectory: config.databaseDirectory, pgEnvironment, spawnImpl
    });
      phases.auditVerify = auditVerify.evidence;
      if (auditVerify.result.status !== 0) {
        terminalCode = 'CNYOS_EXACT_STAGING_DATABASE_AUDIT_VERIFY_FAILED';
        fail(terminalCode);
      }
      terminalStatus = 'PASS';
      terminalCode = forwardAlreadyApplied ? 'RESUMED_AUDIT_APPLIED_VERIFIED' :
        'APPLIED_VERIFIED';
    }
  } catch (error) {
    if (error?.code && String(error.code).startsWith('CNYOS_')) terminalCode = error.code;
  }

  const evidence = {
    schemaVersion: 1,
    kind: 'cnyos_exact_staging_database_reconciliation',
    status: terminalStatus,
    result: terminalCode,
    stagingOnly: true,
    productionAuthorized: false,
    resetAttempted: false,
    historicalLedgerReplayed: false,
    realPatientDataRead: false,
    automaticRollbackAttempted: false,
    forwardRemediationRequiredOnFailure: true,
    nonAtomicPhaseBoundary: true,
    controller: { commit: config.controllerCommit },
    source: { commit: config.appCommit, tree: config.appTree },
    target: {
      projectRef: EXACT_STAGING_TARGET.supabaseProjectRef,
      systemIdentifier: EXPECTED_SYSTEM_IDENTIFIER,
      database: 'postgres'
    },
    artifact: {
      databaseManifestSha256: verified.artifact.databaseManifestSha256,
      databaseTreeSha256: verified.artifact.databaseTreeSha256,
      reconciliationArtifactSha256: artifactHash,
      auditMigrationSha256: verified.databaseManifest.files.find(
        item => item.path === AUDIT_MIGRATION).sha256,
      cleanupArtifactSha256: CLEANUP_SHA256
    },
    attemptId: forwardAttemptId,
    forwardAttemptId,
    auditAttemptId: resolvedAuditAttemptId,
    phases,
    startedAt,
    completedAt: now()
  };
  await writeFresh0600(path.join(config.uploadDirectory, 'database-reconciliation.json'),
    evidence, [databaseUrl, pgEnvironment.PGPASSWORD]);
  if (terminalStatus !== 'PASS') fail(terminalCode);
  return Object.freeze(evidence);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const config = loadExactStagingConfig();
  const databaseUrl = String(process.env.CNYOS_STAGING_DATABASE_URL || '').trim();
  await reconcileExactStagingDatabase(config, databaseUrl);
  process.stdout.write('CNYOS exact staging database reconciliation: APPLIED_VERIFIED\n');
}
