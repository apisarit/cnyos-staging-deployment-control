-- One-time, staging-only rollback of the exact known ledgerless partial replay
-- of 20261013220000_clinical_workflow_backup_restore.sql.
--
-- This file is intentionally ONE server statement. Every guard, mutation and
-- postflight check runs inside one DO statement, so any exception rolls back
-- the entire cleanup. It must not be used against production.

do $cnyos_staging_partial_cleanup$
declare
  v_expected_database constant text := 'postgres';
  v_expected_project_ref constant text := 'hsmnjwxurlmsizndjlun';
  v_production_project_ref constant text := 'qptxnrldzzinlcabudjv';
  v_expected_system_identifier constant text := '7666007964130682852';
  v_observed_search_path text := current_setting('search_path');
  v_observed_schemas text := pg_catalog.array_to_string(
    pg_catalog.current_schemas(false), ','
  );
  v_runtime_project_ref text := current_setting(
    'cnyos.staging_cleanup_project_ref', true
  );
  v_system_identifier text;
  v_pgcrypto_digest_trusted boolean;
  v_prerequisite_contract_fingerprint text;
  v_function_count integer;
  v_dependency_count integer;
  v_target_state_count integer;
  v_signature text;
  v_acl_role text;
  v_acl_lines text[];
  v_target_tables constant text[] := array[
    'spa_services','spa_service_prices','spa_appointment_bindings',
    'spa_service_sessions','spa_session_events','clinical_consult_requests',
    'clinical_consult_events','inpatient_admissions',
    'inpatient_clinical_entries','inpatient_admission_events',
    'inpatient_admission_replays'
  ]::text[];
  v_target_routines constant text[] := array[
    'append_ipd_clinical_entry(uuid,text,text,bigint,uuid,bigint,bigint)',
    'assert_assigned_clinical_encounter(uuid)',
    'book_spa_appointment(uuid,uuid,uuid,uuid,text,text)',
    'complete_spa_session(uuid,bigint,uuid,integer,text,text)',
    'create_clinical_consult_request(uuid,uuid,text,text,text,text,uuid)',
    'create_ipd_admission_request(uuid,uuid,uuid,text)',
    'create_spa_service(text,text,text,text,integer,text,uuid)',
    'enforce_spa_service_price_non_overlap()',
    'export_clinic_backup_domain_v20260901(uuid,text)',
    'get_clinical_consult_request(uuid)','get_ipd_admission(uuid)',
    'guard_spa_appointment_completion()','guard_spa_invoice_source()',
    'issue_atomic_spa_invoice(uuid,uuid)',
    'list_clinical_consult_queue(text,text,integer)',
    'list_clinical_consult_receivers()',
    'list_ipd_admission_queue(text,text,integer)',
    'list_ipd_attending_candidates()','list_spa_billing_routes()',
    'list_spa_services()',
    'list_spa_work_queue(timestamptz,timestamptz)',
    'quote_spa_session(uuid)','read_spa_invoice_evidence(uuid)',
    'reject_clinical_consult_event_mutation()',
    'reject_inpatient_append_only_mutation()',
    'reject_prescription_after_active_invoice()',
    'reject_spa_session_event_mutation()',
    'save_spa_session_draft(uuid,bigint,uuid,text,text,text)',
    'set_invoice_clinic_id()','set_invoice_item_clinic_id()',
    'set_spa_service_price(uuid,numeric,timestamptz,timestamptz,text,uuid)',
    'spa_actor_allowed(uuid,text[])','sync_spa_session_cancellation()',
    'sync_spa_session_encounter()',
    'transition_clinical_consult_request(uuid,text,bigint,uuid,text,text)',
    'transition_ipd_admission(uuid,text,bigint,uuid,text,text,text)',
    'verify_clinic_restore_trace_v20260901(uuid)'
  ]::text[];
  v_target_routine_names constant text[] := array[
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
    'verify_clinic_restore_trace_v20260901'
  ]::text[];
  v_target_sequences constant text[] := array[
    'clinical_consult_events_id_seq','inpatient_clinical_entries_id_seq',
    'inpatient_admission_events_id_seq'
  ]::text[];
  v_target_indexes constant text[] := array[
    'clinical_consult_events_timeline_idx',
    'clinical_consult_requests_inbound_idx',
    'clinical_consult_requests_sender_idx',
    'clinical_consult_requests_source_idx',
    'inpatient_admission_events_timeline_idx',
    'inpatient_admission_replays_actor_key_idx',
    'inpatient_admissions_active_bed_uidx',
    'inpatient_admissions_active_patient_uidx',
    'inpatient_admissions_attending_queue_idx',
    'inpatient_admissions_source_queue_idx',
    'inpatient_admissions_source_uidx',
    'inpatient_clinical_entries_current_type_idx',
    'inpatient_clinical_entries_one_discontinuation_uidx',
    'inpatient_clinical_entries_one_successor_uidx',
    'inpatient_clinical_entries_timeline_idx',
    'invoice_items_id_clinic_uidx','invoices_id_clinic_uidx',
    'invoices_one_active_per_spa_session_uidx',
    'spa_appointment_bindings_queue_idx','spa_service_prices_lookup_idx',
    'spa_service_prices_one_current_uidx',
    'spa_service_prices_request_key_uidx',
    'spa_service_sessions_queue_idx','spa_services_clinic_active_idx',
    'spa_services_request_key_uidx','spa_session_events_lookup_idx'
  ]::text[];
  v_target_constraints constant text[] := array[
    'clinical_consult_events_replay_key',
    'clinical_consult_events_request_fkey',
    'clinical_consult_requests_assignment_check',
    'clinical_consult_requests_create_replay_key',
    'clinical_consult_requests_id_clinic_key',
    'clinical_consult_requests_receiver_separation_check',
    'clinical_consult_requests_source_encounter_fkey',
    'clinical_consult_requests_terminal_shape_check',
    'inpatient_admission_events_admission_fkey',
    'inpatient_admission_events_cancel_shape_check',
    'inpatient_admission_events_entry_fkey',
    'inpatient_admission_replays_actor_operation_key',
    'inpatient_admission_replays_admission_fkey',
    'inpatient_admission_replays_admission_key',
    'inpatient_admissions_bed_code_check',
    'inpatient_admissions_distinct_attending_check',
    'inpatient_admissions_id_clinic_key',
    'inpatient_admissions_placement_shape_check',
    'inpatient_admissions_source_encounter_fkey',
    'inpatient_admissions_ward_code_check',
    'inpatient_clinical_entries_admission_fkey',
    'inpatient_clinical_entries_id_admission_clinic_key',
    'inpatient_clinical_entries_no_self_reference_check',
    'inpatient_clinical_entries_reference_shape_check',
    'inpatient_clinical_entries_related_fkey',
    'inpatient_clinical_entries_supersedes_fkey',
    'invoice_items_invoice_clinic_fkey',
    'invoice_items_spa_service_clinic_fkey',
    'invoice_items_spa_session_clinic_fkey','invoices_clinic_id_fkey',
    'invoices_spa_session_clinic_fkey',
    'spa_appointment_binding_appointment_clinic_fkey',
    'spa_appointment_binding_patient_clinic_fkey',
    'spa_appointment_binding_schedule_clinic_fkey',
    'spa_appointment_binding_service_clinic_fkey',
    'spa_appointment_binding_window_check',
    'spa_service_prices_service_clinic_fkey',
    'spa_service_prices_window_check','spa_services_category_length_check',
    'spa_services_default_room_length_check',
    'spa_session_appointment_clinic_fkey',
    'spa_session_binding_clinic_fkey',
    'spa_session_completed_fields_check',
    'spa_session_encounter_clinic_patient_fkey',
    'spa_session_events_session_clinic_fkey',
    'spa_session_patient_clinic_fkey','spa_session_service_clinic_fkey'
  ]::text[];
  v_target_columns constant text[] := array[
    'invoices|clinic_id','invoices|spa_session_id',
    'invoices|spa_hourly_rate_snapshot','invoices|spa_actual_minutes',
    'invoices|spa_request_fingerprint','invoice_items|clinic_id',
    'invoice_items|spa_session_id','invoice_items|spa_service_id',
    'invoice_items|spa_hourly_rate_snapshot',
    'invoice_items|spa_actual_minutes'
  ]::text[];
  v_target_triggers constant text[] := array[
    'clinic_appointments|clinic_appointments_guard_spa_completion',
    'clinic_appointments|clinic_appointments_sync_spa_cancellation',
    'clinic_appointments|clinic_appointments_sync_spa_session_encounter',
    'clinical_consult_events|trg_clinical_consult_events_append_only_rows',
    'clinical_consult_events|trg_clinical_consult_events_append_only_truncate',
    'clinical_consult_events|trg_cnyos_authenticated_subscription_statement_write',
    'clinical_consult_requests|trg_cnyos_authenticated_subscription_statement_write',
    'inpatient_admission_events|trg_cnyos_authenticated_subscription_statement_write',
    'inpatient_admission_events|trg_inpatient_admission_events_append_only_rows',
    'inpatient_admission_events|trg_inpatient_admission_events_append_only_truncate',
    'inpatient_admission_replays|trg_cnyos_authenticated_subscription_statement_write',
    'inpatient_admission_replays|trg_inpatient_admission_replays_append_only_rows',
    'inpatient_admission_replays|trg_inpatient_admission_replays_append_only_truncate',
    'inpatient_admissions|trg_cnyos_authenticated_subscription_statement_write',
    'inpatient_clinical_entries|trg_cnyos_authenticated_subscription_statement_write',
    'inpatient_clinical_entries|trg_inpatient_clinical_entries_append_only_rows',
    'inpatient_clinical_entries|trg_inpatient_clinical_entries_append_only_truncate',
    'invoice_items|invoice_items_set_clinic_id',
    'invoices|invoices_guard_spa_source','invoices|invoices_set_clinic_id',
    'prescriptions|prescriptions_reject_after_active_invoice',
    'spa_appointment_bindings|trg_cnyos_authenticated_subscription_statement_write',
    'spa_service_prices|spa_service_prices_no_overlap',
    'spa_service_prices|trg_cnyos_authenticated_subscription_statement_write',
    'spa_service_sessions|trg_cnyos_authenticated_subscription_statement_write',
    'spa_services|trg_cnyos_authenticated_subscription_statement_write',
    'spa_session_events|spa_session_events_append_only_truncate',
    'spa_session_events|spa_session_events_append_only_update_delete',
    'spa_session_events|trg_cnyos_authenticated_subscription_statement_write'
  ]::text[];
begin
  perform pg_catalog.set_config('lock_timeout', '5s', true);
  perform pg_catalog.set_config('statement_timeout', '30s', true);
  perform pg_catalog.set_config(
    'search_path', 'pg_catalog, public, pg_temp', true
  );
  if not pg_catalog.pg_try_advisory_xact_lock(20261013230000::bigint) then
    raise exception 'CNYOS_STAGING_CLEANUP_LOCK_BUSY';
  end if;

  -- The project ref is an immutable artifact binding; the exact database
  -- system identifier below is the independent runtime binding.
  if v_expected_project_ref = v_production_project_ref
     or v_runtime_project_ref = v_production_project_ref then
    raise exception 'CNYOS_STAGING_CLEANUP_PRODUCTION_PROJECT_FORBIDDEN';
  end if;
  if v_runtime_project_ref is not null
     and v_runtime_project_ref is distinct from v_expected_project_ref then
    raise exception 'CNYOS_STAGING_CLEANUP_PROJECT_REF_MISMATCH: %',
      v_runtime_project_ref;
  end if;
  if current_database() is distinct from v_expected_database then
    raise exception 'CNYOS_STAGING_CLEANUP_DATABASE_MISMATCH: %',
      current_database();
  end if;
  if session_user is distinct from 'postgres'
     or current_user is distinct from 'postgres'
     or current_role is distinct from 'postgres' then
    raise exception 'CNYOS_STAGING_CLEANUP_EXECUTOR_MISMATCH: session=%, current=%, role=%',
      session_user, current_user, current_role;
  end if;
  if v_observed_search_path is distinct from '"$user", public, extensions'
     or v_observed_schemas is distinct from 'public,extensions' then
    raise exception 'CNYOS_STAGING_CLEANUP_SESSION_PATH_MISMATCH: raw=%, schemas=%',
      v_observed_search_path, v_observed_schemas;
  end if;
  if current_setting('server_version_num')::integer / 10000 <> 17 then
    raise exception 'CNYOS_STAGING_CLEANUP_POSTGRES_17_REQUIRED: %',
      current_setting('server_version');
  end if;

  select system_identifier::text
  into v_system_identifier
  from pg_catalog.pg_control_system();
  if v_system_identifier is distinct from v_expected_system_identifier then
    raise exception 'CNYOS_STAGING_CLEANUP_SYSTEM_IDENTIFIER_MISMATCH: %',
      v_system_identifier;
  end if;

  if to_regclass('supabase_migrations.schema_migrations') is null then
    raise exception 'CNYOS_STAGING_CLEANUP_MIGRATION_LEDGER_REQUIRED';
  end if;
  if not exists (
    select 1
    from supabase_migrations.schema_migrations
    where version::text = '20261007160805'
  ) then
    raise exception 'CNYOS_STAGING_CLEANUP_LEDGER_ANCHOR_MISSING: 20261007160805';
  end if;
  if exists (
    select 1
    from supabase_migrations.schema_migrations
    where version::text = any(array[
      '20261012165506','20261013100000','20261013130000',
      '20261013210000','20261013220000','20261013230000'
    ]::text[])
  ) then
    raise exception 'CNYOS_STAGING_CLEANUP_FORWARD_LEDGER_PRESENT';
  end if;

  if to_regprocedure('extensions.digest(bytea,text)') is null then
    raise exception 'CNYOS_STAGING_CLEANUP_PGCRYPTO_DIGEST_REQUIRED';
  end if;
  select exists (
    select 1
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    join pg_catalog.pg_depend d
      on d.classid = 'pg_catalog.pg_proc'::regclass
     and d.objid = p.oid and d.deptype = 'e'
    join pg_catalog.pg_extension e
      on d.refclassid = 'pg_catalog.pg_extension'::regclass
     and d.refobjid = e.oid
    where p.oid = to_regprocedure('extensions.digest(bytea,text)')
      and n.nspname = 'extensions' and e.extname = 'pgcrypto'
      and p.proowner = e.extowner
      and pg_catalog.pg_get_userbyid(e.extowner)
          in ('postgres','supabase_admin')
      and pg_catalog.pg_get_userbyid(n.nspowner)
          in ('postgres','supabase_admin')
      and not has_schema_privilege('public','extensions','CREATE')
      and not has_schema_privilege('anon','extensions','CREATE')
      and not has_schema_privilege('authenticated','extensions','CREATE')
      and not has_schema_privilege('service_role','extensions','CREATE')
  ) into v_pgcrypto_digest_trusted;
  if not v_pgcrypto_digest_trusted then
    raise exception 'CNYOS_STAGING_CLEANUP_PGCRYPTO_PROVENANCE_MISMATCH';
  end if;

  if (select count(*) from pg_catalog.pg_roles
      where rolname = any(array['anon','authenticated','service_role']::text[])) <>
       3
     or exists (
       select 1 from pg_catalog.pg_roles
       where rolname = any(array['anon','authenticated','service_role']::text[])
         and (rolsuper or not rolinherit or rolcreaterole or rolcreatedb
           or rolcanlogin or rolreplication
           or (rolname in ('anon','authenticated') and rolbypassrls)
           or (rolname = 'service_role' and not rolbypassrls))
     ) then
    raise exception 'CNYOS_STAGING_CLEANUP_CRITICAL_ROLE_SAFETY_MISMATCH';
  end if;
  select pg_catalog.encode(extensions.digest(pg_catalog.convert_to((with critical_role_names(name) as (
  select name from unnest(array['anon','authenticated','service_role']::text[]) target(name)
), helper_names(schema_name,routine_name) as (
  select split_part(pair,'|',1),split_part(pair,'|',2)
  from unnest(array['auth|role','auth|uid','public|assert_clinic_subscription_active','public|book_clinic_appointment','public|create_atomic_prescription_handoff','public|current_clinic_id','public|current_user_role','public|department_can','public|enforce_authenticated_subscription_statement_write','public|is_clinic_member','public|is_super_admin','public|next_clinic_counter','public|transition_atomic_prescription_dispensing']::text[]) target(pair)
), catalog_lines(line) as (
  select concat_ws('|','NSP',n.nspname,pg_catalog.pg_get_userbyid(n.nspowner),
    coalesce((select string_agg(acl::text,',' order by acl::text)
      from unnest(n.nspacl) acl),'<NULL>'))
  from pg_catalog.pg_namespace n where n.nspname='public'
  union all
  select concat_ws('|','ROL',r.rolname,r.rolsuper::text,r.rolinherit::text,
    r.rolcreaterole::text,r.rolcreatedb::text,r.rolcanlogin::text,
    r.rolreplication::text,r.rolbypassrls::text,r.rolconnlimit::text,
    coalesce(r.rolvaliduntil::text,'<NULL>'))
  from pg_catalog.pg_roles r
  join critical_role_names target on target.name=r.rolname
  union all
  select concat_ws('|','MEMBER',parent.rolname,member.rolname,
    m.admin_option::text,m.inherit_option::text,m.set_option::text,
    pg_catalog.pg_get_userbyid(m.grantor))
  from pg_catalog.pg_auth_members m
  join pg_catalog.pg_roles parent on parent.oid=m.roleid
  join pg_catalog.pg_roles member on member.oid=m.member
  where parent.rolname in (select name from critical_role_names)
     or member.rolname in (select name from critical_role_names)
  union all
  select concat_ws('|','FUN',n.nspname,p.proname,p.prokind::text,
    pg_catalog.pg_get_function_identity_arguments(p.oid),
    pg_catalog.pg_get_function_arguments(p.oid),
    pg_catalog.pg_get_function_result(p.oid),l.lanname,
    pg_catalog.pg_get_userbyid(p.proowner),p.prosecdef::text,
    p.provolatile::text,p.proparallel::text,p.proisstrict::text,
    p.proleakproof::text,p.procost::text,p.prorows::text,
    coalesce((select string_agg(acl::text,',' order by acl::text)
      from unnest(p.proacl) acl),'<NULL>'),
    coalesce(p.probin,'<NULL>'),p.prosrc)
  from pg_catalog.pg_proc p
  join pg_catalog.pg_namespace n on n.oid=p.pronamespace
  join pg_catalog.pg_language l on l.oid=p.prolang
  join helper_names h on h.schema_name=n.nspname and h.routine_name=p.proname
)
select pg_catalog.string_agg(line,E'\n' order by line) from catalog_lines),'UTF8'),'sha256'),'hex')
  into v_prerequisite_contract_fingerprint;
  if v_prerequisite_contract_fingerprint is distinct from
     '1194b017be087c09e0b1b8a2c67013f3dddd5aa033454a2ffa65a7f15d4be067' then
    raise exception 'CNYOS_STAGING_CLEANUP_PREREQUISITE_CONTRACT_MISMATCH: expected=%, actual=%',
      '1194b017be087c09e0b1b8a2c67013f3dddd5aa033454a2ffa65a7f15d4be067',
      v_prerequisite_contract_fingerprint;
  end if;

  if to_regnamespace('cnyos_internal') is not null then
    raise exception 'CNYOS_STAGING_CLEANUP_INTERNAL_SCHEMA_MUST_BE_ABSENT';
  end if;

  -- This is the exact target-marker surface used by the reviewed forward
  -- reconciliation artifact. The known partial replay has exactly four:
  -- each archived routine is counted once by signature and once by name.
  select coalesce(sum(marker_count), 0)::integer
  into v_target_state_count
  from (
    select count(*) marker_count
    from unnest(v_target_tables) target(name)
    where to_regclass('public.' || target.name) is not null
    union all
    select count(*) from unnest(v_target_routines) target(signature)
    where to_regprocedure('public.' || target.signature) is not null
    union all
    select count(*) from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = any(v_target_routine_names)
    union all
    select count(*) from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'S'
      and c.relname = any(v_target_sequences)
    union all
    select count(*) from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'i'
      and c.relname = any(v_target_indexes)
    union all
    select count(*) from pg_catalog.pg_constraint c
    where c.conname = any(v_target_constraints)
    union all
    select count(*) from unnest(v_target_columns) target(pair)
    where exists (
      select 1 from pg_catalog.pg_attribute a
      join pg_catalog.pg_class c on c.oid = a.attrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
        and c.relname = split_part(target.pair, '|', 1)
        and a.attname = split_part(target.pair, '|', 2)
        and a.attnum > 0 and not a.attisdropped
    )
    union all
    select count(*) from unnest(v_target_triggers) target(pair)
    where exists (
      select 1 from pg_catalog.pg_trigger t
      join pg_catalog.pg_class c on c.oid = t.tgrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where not t.tgisinternal and n.nspname = 'public'
        and c.relname = split_part(target.pair, '|', 1)
        and t.tgname = split_part(target.pair, '|', 2)
    )
    union all
    select count(*) from pg_catalog.pg_namespace n
    where n.nspname = 'cnyos_internal'
  ) state_markers;
  if v_target_state_count <> 4 then
    raise exception 'CNYOS_STAGING_CLEANUP_TARGET_MARKER_COUNT_MISMATCH: expected=4 actual=%',
      v_target_state_count;
  end if;

  select count(*)::integer
  into v_function_count
  from pg_catalog.pg_proc p
  join pg_catalog.pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname = any(array[
      'backup_restore_contract_healthcheck',
      'export_clinic_backup_domain',
      'export_clinic_backup_domain_v20260901',
      'verify_clinic_restore_trace',
      'verify_clinic_restore_trace_v20260901'
    ]::text[]);
  if v_function_count <> 5
     or to_regprocedure('public.backup_restore_contract_healthcheck()') is null
     or to_regprocedure('public.export_clinic_backup_domain(uuid,text)') is null
     or to_regprocedure('public.export_clinic_backup_domain_v20260901(uuid,text)') is null
     or to_regprocedure('public.verify_clinic_restore_trace(uuid)') is null
     or to_regprocedure('public.verify_clinic_restore_trace_v20260901(uuid)') is null then
    raise exception 'CNYOS_STAGING_CLEANUP_EXPECTED_EXACT_FIVE_FUNCTIONS: %',
      v_function_count;
  end if;

  if pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.backup_restore_contract_healthcheck()'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from 'aaae13d5c539d7329229ded1bfd0a0ce7a90e840e437e2499cbbc009122c0b9e'
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.export_clinic_backup_domain(uuid,text)'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from 'afe797a96515d756c84ab8ad922a92ba176aeb5f6f8ba7c94bacd59c39bf9563'
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.export_clinic_backup_domain_v20260901(uuid,text)'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from 'cc9c5f8a6da7122739c20c5711bc598026d4ea9a1a3b818079a3fc59b4297980'
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.verify_clinic_restore_trace(uuid)'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from '7acbb31960b311b049592afed9d9af28c545ff83425e952ed759487420e036c5'
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.verify_clinic_restore_trace_v20260901(uuid)'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from '2d36f5f1d409a7723fa4cb5c3f938c55110dc85a9fd06f3285499d1f64475661'
  then
    raise exception 'CNYOS_STAGING_CLEANUP_FUNCTION_DEFINITION_MISMATCH';
  end if;

  -- Bind ownership and direct grants before mutation. Function-definition
  -- hashes intentionally do not include either property.
  foreach v_signature in array array[
    'public.backup_restore_contract_healthcheck()',
    'public.export_clinic_backup_domain(uuid,text)',
    'public.export_clinic_backup_domain_v20260901(uuid,text)',
    'public.verify_clinic_restore_trace(uuid)',
    'public.verify_clinic_restore_trace_v20260901(uuid)'
  ]::text[] loop
    if (select pg_catalog.pg_get_userbyid(p.proowner)
        from pg_catalog.pg_proc p
        where p.oid = to_regprocedure(v_signature)) is distinct from 'postgres' then
      raise exception 'CNYOS_STAGING_CLEANUP_PREFLIGHT_OWNER_MISMATCH: %',
        v_signature;
    end if;

    select pg_catalog.array_agg(
      concat_ws('|',
        case when acl.grantee = 0 then 'PUBLIC' else r.rolname end,
        acl.privilege_type,
        acl.is_grantable::text
      ) order by
        case when acl.grantee = 0 then 'PUBLIC' else r.rolname end,
        acl.privilege_type,
        acl.is_grantable
    )
    into v_acl_lines
    from pg_catalog.pg_proc p
    cross join lateral pg_catalog.aclexplode(p.proacl) acl
    left join pg_catalog.pg_roles r on r.oid = acl.grantee
    where p.oid = to_regprocedure(v_signature)
      and acl.grantee <> p.proowner;

    if v_signature = 'public.backup_restore_contract_healthcheck()' then
      if v_acl_lines is distinct from array[
        'authenticated|EXECUTE|false',
        'service_role|EXECUTE|false'
      ]::text[] then
        raise exception 'CNYOS_STAGING_CLEANUP_PREFLIGHT_HEALTHCHECK_ACL_MISMATCH: %',
          v_acl_lines;
      end if;
    elsif v_acl_lines is distinct from
          array['service_role|EXECUTE|false']::text[] then
      raise exception 'CNYOS_STAGING_CLEANUP_PREFLIGHT_SERVICE_ACL_MISMATCH: signature=% acl=%',
        v_signature, v_acl_lines;
    end if;
  end loop;

  select count(*)::integer
  into v_dependency_count
  from pg_catalog.pg_depend d
  where d.refclassid = 'pg_catalog.pg_proc'::regclass
    and d.refobjid = any(array[
      to_regprocedure('public.backup_restore_contract_healthcheck()'),
      to_regprocedure('public.export_clinic_backup_domain(uuid,text)'),
      to_regprocedure('public.export_clinic_backup_domain_v20260901(uuid,text)'),
      to_regprocedure('public.verify_clinic_restore_trace(uuid)'),
      to_regprocedure('public.verify_clinic_restore_trace_v20260901(uuid)')
    ]::oid[])
    and d.deptype in ('n','a','i');
  if v_dependency_count <> 0 then
    raise exception 'CNYOS_STAGING_CLEANUP_DEPENDENCY_REFUSAL: %',
      v_dependency_count;
  end if;

  execute $healthcheck$
    create or replace function public.backup_restore_contract_healthcheck()
    returns table (
      ready boolean,
      schema_version text,
      domain_count integer,
      patient_table_count integer,
      product_table_count integer,
      pharmacy_table_count integer,
      transaction_table_count integer,
      managed_database_restore_required boolean
    )
    language sql
    stable
    security definer
    set search_path = pg_catalog, public
    as $function$
      select true, '2026-09-01.1', 4, 31, 16, 7, 12, true
      where auth.role() = 'service_role' or public.is_super_admin();
    $function$
  $healthcheck$;

  execute 'drop function public.export_clinic_backup_domain(uuid, text)';
  execute 'drop function public.verify_clinic_restore_trace(uuid)';
  execute 'alter function public.export_clinic_backup_domain_v20260901(uuid, text) rename to export_clinic_backup_domain';
  execute 'alter function public.verify_clinic_restore_trace_v20260901(uuid) rename to verify_clinic_restore_trace';

  foreach v_signature in array array[
    'public.backup_restore_contract_healthcheck()',
    'public.export_clinic_backup_domain(uuid,text)',
    'public.verify_clinic_restore_trace(uuid)'
  ]::text[] loop
    execute format('alter function %s owner to postgres', v_signature);
    execute format(
      'alter function %s set search_path = pg_catalog, public', v_signature
    );
    execute format(
      'revoke all privileges on function %s from public', v_signature
    );
    for v_acl_role in
      select distinct r.rolname
      from pg_catalog.pg_proc p
      cross join lateral pg_catalog.aclexplode(
        coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))
      ) acl
      join pg_catalog.pg_roles r on r.oid = acl.grantee
      where p.oid = to_regprocedure(v_signature)
        and acl.grantee <> p.proowner
    loop
      execute format(
        'revoke all privileges on function %s from %I',
        v_signature, v_acl_role
      );
    end loop;
  end loop;

  execute 'grant execute on function public.backup_restore_contract_healthcheck() to authenticated, service_role';
  execute 'grant execute on function public.export_clinic_backup_domain(uuid,text) to service_role';
  execute 'grant execute on function public.verify_clinic_restore_trace(uuid) to service_role';

  if pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.backup_restore_contract_healthcheck()'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from '417424b7065ae3a00724abaa3f6d40d527e6a03dc418b3b5ba264680b5dcc80e'
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.export_clinic_backup_domain(uuid,text)'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from 'f18f213e2fc5a821815e31f08e1f1afc478d18d9f07bfbc65bc31651c83fb342'
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
       pg_catalog.pg_get_functiondef(to_regprocedure(
         'public.verify_clinic_restore_trace(uuid)'
       )), 'UTF8'), 'sha256'), 'hex')
       is distinct from '6616dbcb8a2d4bcb12d0ca11f48734bfd1a776d9dc11307d49421e00b61c157e'
  then
    raise exception 'CNYOS_STAGING_CLEANUP_RESTORED_DEFINITION_MISMATCH';
  end if;

  if to_regprocedure(
       'public.export_clinic_backup_domain_v20260901(uuid,text)'
     ) is not null
     or to_regprocedure(
       'public.verify_clinic_restore_trace_v20260901(uuid)'
     ) is not null then
    raise exception 'CNYOS_STAGING_CLEANUP_ARCHIVED_NAME_STILL_PRESENT';
  end if;

  foreach v_signature in array array[
    'public.backup_restore_contract_healthcheck()',
    'public.export_clinic_backup_domain(uuid,text)',
    'public.verify_clinic_restore_trace(uuid)'
  ]::text[] loop
    if (select pg_catalog.pg_get_userbyid(p.proowner)
        from pg_catalog.pg_proc p
        where p.oid = to_regprocedure(v_signature)) is distinct from 'postgres'
       or (select p.proconfig from pg_catalog.pg_proc p
           where p.oid = to_regprocedure(v_signature)) is distinct from
          array['search_path=pg_catalog, public']::text[]
       or (select p.proacl from pg_catalog.pg_proc p
           where p.oid = to_regprocedure(v_signature)) is null then
      raise exception 'CNYOS_STAGING_CLEANUP_OWNER_CONFIG_ACL_MISMATCH: %',
        v_signature;
    end if;

    select pg_catalog.array_agg(
      concat_ws('|',
        case when acl.grantee = 0 then 'PUBLIC' else r.rolname end,
        acl.privilege_type,
        acl.is_grantable::text
      ) order by
        case when acl.grantee = 0 then 'PUBLIC' else r.rolname end,
        acl.privilege_type,
        acl.is_grantable
    )
    into v_acl_lines
    from pg_catalog.pg_proc p
    cross join lateral pg_catalog.aclexplode(p.proacl) acl
    left join pg_catalog.pg_roles r on r.oid = acl.grantee
    where p.oid = to_regprocedure(v_signature)
      and acl.grantee <> p.proowner;

    if v_signature = 'public.backup_restore_contract_healthcheck()' then
      if v_acl_lines is distinct from array[
        'authenticated|EXECUTE|false',
        'service_role|EXECUTE|false'
      ]::text[] then
        raise exception 'CNYOS_STAGING_CLEANUP_HEALTHCHECK_ACL_MISMATCH: %',
          v_acl_lines;
      end if;
    elsif v_acl_lines is distinct from
          array['service_role|EXECUTE|false']::text[] then
      raise exception 'CNYOS_STAGING_CLEANUP_SERVICE_ONLY_ACL_MISMATCH: signature=% acl=%',
        v_signature, v_acl_lines;
    end if;
  end loop;

  if has_function_privilege(
       'anon', to_regprocedure('public.backup_restore_contract_healthcheck()'),
       'EXECUTE'
     )
     or has_function_privilege(
       'anon', to_regprocedure('public.export_clinic_backup_domain(uuid,text)'),
       'EXECUTE'
     )
     or has_function_privilege(
       'anon', to_regprocedure('public.verify_clinic_restore_trace(uuid)'),
       'EXECUTE'
     )
     or not has_function_privilege(
       'authenticated',
       to_regprocedure('public.backup_restore_contract_healthcheck()'),
       'EXECUTE'
     )
     or has_function_privilege(
       'authenticated',
       to_regprocedure('public.export_clinic_backup_domain(uuid,text)'),
       'EXECUTE'
     )
     or has_function_privilege(
       'authenticated',
       to_regprocedure('public.verify_clinic_restore_trace(uuid)'),
       'EXECUTE'
     )
     or not has_function_privilege(
       'service_role',
       to_regprocedure('public.backup_restore_contract_healthcheck()'),
       'EXECUTE'
     )
     or not has_function_privilege(
       'service_role',
       to_regprocedure('public.export_clinic_backup_domain(uuid,text)'),
       'EXECUTE'
     )
     or not has_function_privilege(
       'service_role',
       to_regprocedure('public.verify_clinic_restore_trace(uuid)'),
       'EXECUTE'
     ) then
    raise exception 'CNYOS_STAGING_CLEANUP_EFFECTIVE_EXECUTE_MISMATCH';
  end if;

  select coalesce(sum(marker_count), 0)::integer
  into v_target_state_count
  from (
    select count(*) marker_count
    from unnest(v_target_tables) target(name)
    where to_regclass('public.' || target.name) is not null
    union all
    select count(*) from unnest(v_target_routines) target(signature)
    where to_regprocedure('public.' || target.signature) is not null
    union all
    select count(*) from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = any(v_target_routine_names)
    union all
    select count(*) from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'S'
      and c.relname = any(v_target_sequences)
    union all
    select count(*) from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'i'
      and c.relname = any(v_target_indexes)
    union all
    select count(*) from pg_catalog.pg_constraint c
    where c.conname = any(v_target_constraints)
    union all
    select count(*) from unnest(v_target_columns) target(pair)
    where exists (
      select 1 from pg_catalog.pg_attribute a
      join pg_catalog.pg_class c on c.oid = a.attrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public'
        and c.relname = split_part(target.pair, '|', 1)
        and a.attname = split_part(target.pair, '|', 2)
        and a.attnum > 0 and not a.attisdropped
    )
    union all
    select count(*) from unnest(v_target_triggers) target(pair)
    where exists (
      select 1 from pg_catalog.pg_trigger t
      join pg_catalog.pg_class c on c.oid = t.tgrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where not t.tgisinternal and n.nspname = 'public'
        and c.relname = split_part(target.pair, '|', 1)
        and t.tgname = split_part(target.pair, '|', 2)
    )
    union all
    select count(*) from pg_catalog.pg_namespace n
    where n.nspname = 'cnyos_internal'
  ) state_markers;

  if v_target_state_count <> 0
     or to_regnamespace('cnyos_internal') is not null then
    raise exception 'CNYOS_STAGING_CLEANUP_POSTFLIGHT_TARGET_MISMATCH: markers=% internal_schema=%',
      v_target_state_count,
      to_regnamespace('cnyos_internal') is not null;
  end if;

  raise notice 'CNYOS_STAGING_PARTIAL_REPLAY_CLEANUP_VERIFIED';
end
$cnyos_staging_partial_cleanup$;
