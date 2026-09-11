(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const num = value => value === '' || value == null ? null : Number(value);
  const csv = value => String(value || '').split(',').map(item => item.trim()).filter(Boolean);

  let db;
  let session;
  let profile;
  let currentEncounter = null;
  let patients = [];
  let products = [];
  let encounters = [];
  let prescriptionCart = [];
  let hybridIdentityReady = false;
  let atomicHandoffsReady = false;

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2200);
  }

  function fail(error) {
    console.error(error);
    alert(error?.message || String(error));
  }

  function patientName(id) {
    const patient = patients.find(item => item.id === id);
    return patient ? `${patient.prefix || patient.title || ''}${patient.first_name || ''} ${patient.last_name || ''}`.trim() : '-';
  }

  function optionRows(rows, label) {
    return '<option value="">เลือก</option>' + rows.map(item => `<option value="${item.id}">${esc(label(item))}</option>`).join('');
  }

  function syncPrescriptionUnit() {
    const product = products.find(item => item.id === $('#rx-product').value);
    $('#rx-unit').value = product?.dispense_unit || '';
  }

  function requireAtomicHandoffs() {
    if (!atomicHandoffsReady) {
      throw new Error('ฐานข้อมูลยังไม่เปิดใช้ Atomic Clinical/Financial Handoffs จึงหยุดการบันทึกเพื่อป้องกันข้อมูลครึ่งชุด');
    }
  }

  function setStep(step) {
    const target = $(`[data-stage="${CSS.escape(step)}"]`);
    if (!target) return;
    $$('.clinical-stage').forEach(stage => stage.classList.toggle('active', stage === target));
    $$('[data-clinical-step]').forEach(button => button.classList.toggle('active', button.dataset.clinicalStep === step));
    const url = new URL(location.href);
    url.searchParams.set('step', step);
    history.replaceState({}, '', url);
    if (matchMedia('(max-width: 900px)').matches) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function markStep(step, ready) {
    document.querySelector(`[data-step-state="${step}"]`)?.classList.toggle('ready', Boolean(ready));
  }

  async function loadReferences(preferredEncounter) {
    const [patientResult, productResult, encounterResult] = await Promise.all([
      db.from('patients').select('*').order('created_at', { ascending: false }).limit(500),
      db.from('products').select('*').eq('active', true).order('name_th'),
      db.from('encounters').select('id,encounter_no,patient_id,chief_complaint,thai_diagnosis,started_at,status').order('started_at', { ascending: false }).limit(250)
    ]);
    [patientResult, productResult, encounterResult].forEach(result => { if (result.error) throw result.error; });
    patients = patientResult.data || [];
    products = productResult.data || [];
    encounters = encounterResult.data || [];

    $('#enc-patient').innerHTML = optionRows(patients, item => `${item.hn || '-'} — ${patientName(item.id)}`);
    $('#encounter').innerHTML = '<option value="">เลือก Encounter</option>' + encounters.map(item => `<option value="${item.id}">${esc(item.encounter_no || '-')} — ${esc(patientName(item.patient_id))} — ${esc(item.chief_complaint || '-')}</option>`).join('');
    $('#rx-encounter').innerHTML = optionRows(encounters, item => `${item.encounter_no || '-'} — ${patientName(item.patient_id)}`);
    $('#rx-product').innerHTML = optionRows(products, item => `${item.sku || '-'} — ${item.name_th}`);
    syncPrescriptionUnit();

    if (preferredEncounter && encounters.some(item => item.id === preferredEncounter)) {
      $('#encounter').value = preferredEncounter;
      $('#rx-encounter').value = preferredEncounter;
      await selectEncounter(preferredEncounter);
    }
    window.dispatchEvent(new CustomEvent('chananya:clinical-references-rendered'));
  }

  async function selectEncounter(encounterId) {
    currentEncounter = encounterId || null;
    $('#rx-encounter').value = currentEncounter || '';
    if (!currentEncounter) {
      $('#encounter-info').textContent = 'เลือก Encounter หรือเปิด Visit ใหม่';
      resetEncounterViews();
      markStep('intake', false);
      window.dispatchEvent(new CustomEvent('chananya:encounter-changed', { detail: { encounterId: null } }));
      return;
    }
    const encounter = encounters.find(item => item.id === currentEncounter);
    $('#encounter-info').textContent = `${encounter?.encounter_no || currentEncounter} • ${patientName(encounter?.patient_id)}`;
    markStep('intake', true);
    await loadEncounter();
    window.dispatchEvent(new CustomEvent('chananya:encounter-changed', { detail: { encounterId: currentEncounter } }));
  }

  function resetEncounterViews() {
    renderExam([]); renderDiagnosis(null); renderPlan(null);
    ['history', 'exam', 'diagnosis', 'treatment', 'prescription', 'signoff'].forEach(step => markStep(step, false));
  }

  async function loadEncounter() {
    const [examResult, diagnosisResult, planResult, painResult, historyResult, sessionResult, prescriptionResult, signoffResult] = await Promise.all([
      db.from('clinical_examination_findings').select('*').eq('encounter_id', currentEncounter).order('sequence_no'),
      db.from('ttm_structured_diagnoses').select('*').eq('encounter_id', currentEncounter).maybeSingle(),
      db.from('clinical_treatment_plans').select('*').eq('encounter_id', currentEncounter).order('created_at', { ascending: false }).limit(1).maybeSingle(),
      db.from('body_pain_points').select('*').eq('encounter_id', currentEncounter).order('recorded_at', { ascending: false }),
      db.from('ttm_opd_histories').select('id').eq('encounter_id', currentEncounter).maybeSingle(),
      db.from('clinical_treatment_sessions').select('id').eq('encounter_id', currentEncounter),
      db.from('prescriptions').select('id').eq('encounter_id', currentEncounter),
      db.from('clinical_record_signoffs').select('id,lock_record').eq('encounter_id', currentEncounter).eq('record_section', 'complete_record').maybeSingle()
    ]);
    [examResult, diagnosisResult, planResult, painResult].forEach(result => { if (result.error) throw result.error; });
    renderExam(examResult.data || []);
    renderDiagnosis(diagnosisResult.data);
    renderPlan(planResult.data);
    markStep('history', Boolean(historyResult.data));
    markStep('exam', (examResult.data || []).length > 0 || (painResult.data || []).length > 0);
    markStep('diagnosis', Boolean(diagnosisResult.data));
    markStep('treatment', Boolean(planResult.data) || (sessionResult.data || []).length > 0);
    markStep('prescription', (prescriptionResult.data || []).length > 0);
    markStep('signoff', Boolean(signoffResult.data?.lock_record));
  }

  function renderExam(rows) {
    $('#exam-list').innerHTML = rows.map((row, index) => `<tr><td>${index + 1}</td><td>${esc(row.body_region)}</td><td>${esc(row.side)}</td><td>${[row.tenderness ? 'กดเจ็บ' : '', row.swelling ? 'บวม' : '', row.warmth ? 'ร้อน' : '', row.redness ? 'แดง' : '', row.numbness ? 'ชา' : '', row.muscle_tightness ? 'ตึง' : ''].filter(Boolean).join(', ') || '-'}</td><td>${esc(row.range_of_motion || '-')}</td><td>${esc(row.identified_problem || '-')}</td><td><button class="btn ghost" data-delete-exam="${row.id}">ลบ</button></td></tr>`).join('') || '<tr><td colspan="7">ยังไม่มีผลตรวจ</td></tr>';
    $$('[data-delete-exam]').forEach(button => { button.onclick = () => removeRow('clinical_examination_findings', button.dataset.deleteExam).catch(fail); });
  }

  function renderDiagnosis(row) {
    $('#diagnosis-status').innerHTML = row ? `<b>${esc(row.thai_diagnosis)}</b><br>${esc(row.analysis_summary)}<br><small>${esc([row.dhatu_samutthan, row.utu_samutthan, row.ayu_samutthan, row.kala_samutthan, row.pradesa_samutthan].filter(Boolean).join(' • '))}</small>` : 'ยังไม่มีข้อมูล';
  }

  function renderPlan(row) {
    $('#plan-status').innerHTML = row ? `<b>${esc(row.goal_1)}</b><br>ความถี่ ${esc(row.frequency_per_week || '-')} ครั้ง/สัปดาห์ • ${esc(row.planned_sessions || '-')} ครั้ง<br><small>${esc((row.treatment_modalities || []).join(', '))}</small>` : 'ยังไม่มีแผนการรักษา';
  }

  async function removeRow(table, id) {
    if (!confirm('ยืนยันลบรายการนี้?')) return;
    const result = await db.from(table).delete().eq('id', id);
    if (result.error) throw result.error;
    await loadEncounter();
    toast('ลบแล้ว');
  }

  function bloodPressure() {
    const [systolic, diastolic] = ($('#enc-bp').value || '').split('/').map(Number);
    return { systolic_bp: systolic || null, diastolic_bp: diastolic || null };
  }

  function syncVerificationNoteRequirement() {
    const guardian = $('#enc-verification-method').value === 'guardian_attestation';
    $('#enc-verification-note').required = guardian;
  }

  async function saveEncounter(event) {
    event.preventDefault();
    if (!hybridIdentityReady) {
      throw new Error('ฐานข้อมูลยังไม่เปิดใช้ Hybrid Patient Identity จึงหยุดการเปิด Encounter เพื่อป้องกันข้อมูลคัดกรองครึ่งชุด');
    }
    if (!$('#enc-identity-confirmed').checked) throw new Error('กรุณาตรวจสอบตัวตนกับผู้รับบริการก่อนเปิด Encounter');
    const bp = bloodPressure();
    const intake = {
      chief_complaint: $('#enc-chief').value,
      present_illness: $('#enc-history').value || null,
      past_history: $('#enc-past').value || null,
      current_medications: $('#enc-meds').value || null,
      red_flags: $('#enc-redflags').value || null,
      general_examination: $('#enc-exam').value || null,
      temperature: num($('#enc-temp').value),
      pulse: num($('#enc-pulse').value),
      respiration: num($('#enc-rr').value),
      spo2: num($('#enc-spo2').value),
      systolic_bp: bp.systolic_bp,
      diastolic_bp: bp.diastolic_bp,
      pain_before: num($('#enc-before').value)
    };
    const result = await db.rpc('start_manual_patient_encounter', {
      p_patient_id: $('#enc-patient').value,
      p_verification_method: $('#enc-verification-method').value,
      p_patient_present_confirmed: true,
      p_verification_note: $('#enc-verification-note').value.trim() || null,
      p_chief_complaint: $('#enc-chief').value,
      p_intake: intake
    });
    if (result.error) throw result.error;
    const encounter = Array.isArray(result.data) ? result.data[0] : result.data;
    const encounterId = encounter?.encounter_id;
    if (!encounterId) throw new Error('ไม่สามารถเปิด Encounter ได้');
    event.target.reset();
    syncVerificationNoteRequirement();
    await loadReferences(encounterId);
    setStep('history');
    toast('เปิด Encounter แล้ว');
  }

  async function saveExam(event) {
    event.preventDefault();
    if (!currentEncounter) throw new Error('กรุณาเลือก Encounter');
    const countResult = await db.from('clinical_examination_findings').select('id', { count: 'exact', head: true }).eq('encounter_id', currentEncounter);
    if (countResult.error) throw countResult.error;
    const result = await db.from('clinical_examination_findings').insert({
      encounter_id: currentEncounter, sequence_no: (countResult.count || 0) + 1,
      body_region: $('#exam-region').value, side: $('#exam-side').value,
      tenderness: $('#exam-tenderness').checked, swelling: $('#exam-swelling').checked,
      warmth: $('#exam-warmth').checked, redness: $('#exam-redness').checked,
      numbness: $('#exam-numbness').checked, muscle_tightness: $('#exam-tightness').checked,
      range_of_motion: $('#exam-rom').value, severity: num($('#exam-severity').value),
      movement_notes: $('#exam-movement').value || null, abnormal_finding: $('#exam-abnormal').value || null,
      identified_problem: $('#exam-problem').value, created_by: session.user.id
    });
    if (result.error) throw result.error;
    event.target.reset();
    await loadEncounter();
    toast('เพิ่มผลตรวจแล้ว');
  }

  async function savePlan(event) {
    event.preventDefault();
    if (!currentEncounter) throw new Error('กรุณาเลือก Encounter');
    const result = await db.from('clinical_treatment_plans').insert({
      encounter_id: currentEncounter, plan_number: `TP-${Date.now()}`,
      goal_1: $('#plan-goal1').value, goal_2: $('#plan-goal2').value || null, goal_3: $('#plan-goal3').value || null,
      frequency_per_week: num($('#plan-frequency').value), planned_duration_weeks: num($('#plan-weeks').value),
      planned_sessions: num($('#plan-sessions').value), treatment_modalities: csv($('#plan-modalities').value),
      target_areas: csv($('#plan-areas').value), precautions: $('#plan-precautions').value || null,
      herbal_plan: $('#plan-herbal').value || null, home_program: $('#plan-home').value || null,
      planned_by: session.user.id, status: 'active'
    });
    if (result.error) throw result.error;
    await loadEncounter();
    toast('บันทึก Treatment Plan แล้ว');
  }

  function renderPrescriptionCart() {
    $('#rx-cart').innerHTML = prescriptionCart.map((item, index) => `<article class="item"><div><b>${esc(item.product_name)}</b><small>${item.quantity_prescribed} ${esc(item.unit)} • ${esc(item.dose || '-')} • ${esc(item.frequency || '-')} • ${esc(item.duration || '-')}</small></div><button class="btn ghost" data-remove-rx="${index}">ลบ</button></article>`).join('') || '<p class="muted">ยังไม่มีรายการยา</p>';
    $$('[data-remove-rx]').forEach(button => { button.onclick = () => { prescriptionCart.splice(Number(button.dataset.removeRx), 1); renderPrescriptionCart(); }; });
  }

  function addPrescriptionItem(event) {
    event.preventDefault();
    const product = products.find(item => item.id === $('#rx-product').value);
    if (!product) throw new Error('กรุณาเลือกยา/ผลิตภัณฑ์');
    prescriptionCart.push({
      product_id: product.id, product_name: product.name_th,
      quantity_prescribed: Number($('#rx-qty').value), unit: product.dispense_unit,
      dose: $('#rx-dose').value || null, frequency: $('#rx-frequency').value || null,
      duration: $('#rx-duration').value || null, route: $('#rx-route').value || null,
      instructions: $('#rx-instructions').value || null, status: 'ordered'
    });
    event.target.reset();
    $('#rx-route').value = 'oral';
    syncPrescriptionUnit();
    renderPrescriptionCart();
  }

  async function sendPrescription(event) {
    event.preventDefault();
    requireAtomicHandoffs();
    const encounterId = $('#rx-encounter').value;
    const encounter = encounters.find(item => item.id === encounterId);
    if (!encounter) throw new Error('กรุณาเลือก Encounter');
    if (!prescriptionCart.length) throw new Error('กรุณาเพิ่มรายการยาอย่างน้อย 1 รายการ');
    const requestKey = event.currentTarget.dataset.requestKey || crypto.randomUUID();
    event.currentTarget.dataset.requestKey = requestKey;
    const result = await db.rpc('create_atomic_prescription_handoff', {
      p_request_key: requestKey,
      p_encounter_id: encounter.id,
      p_clinical_notes: $('#rx-clinical-notes').value.trim() || null,
      p_items: prescriptionCart.map(({ product_name, status, ...item }) => item)
    });
    if (result.error) throw result.error;
    delete event.currentTarget.dataset.requestKey;
    prescriptionCart = [];
    event.target.reset();
    $('#rx-encounter').value = currentEncounter || '';
    renderPrescriptionCart();
    await loadEncounter();
    toast('ส่งใบสั่งยาไป Pharmacy แล้ว');
  }

  async function init() {
    try {
      const runtime = window.ChananyaRuntime;
      if (!runtime) throw new Error('ChananyaRuntime ไม่พร้อมใช้งาน');
      db = runtime.getDb();
      session = await runtime.getSession();
      if (!session) { location.replace('/login.html'); return; }
      profile = await runtime.getProfile(session.user.id);
      if (!profile) throw new Error('ไม่พบ Profile');
      if (!runtime.can(profile, 'clinical_write')) throw new Error('บัญชีนี้ไม่มีสิทธิ์บันทึกเวชระเบียน');
      window.ChananyaShell?.mount({ profile, session, active: 'clinical' });
      const identityHealth = await db.rpc('hybrid_patient_identity_healthcheck');
      hybridIdentityReady = !identityHealth.error && Boolean((Array.isArray(identityHealth.data) ? identityHealth.data[0] : identityHealth.data)?.ready);
      const handoffHealth = await db.rpc('clinical_financial_handoffs_healthcheck');
      atomicHandoffsReady = !handoffHealth.error && Boolean((Array.isArray(handoffHealth.data) ? handoffHealth.data[0] : handoffHealth.data)?.ready);
      $('#encounter-form button').disabled = !hybridIdentityReady;
      $('#prescription-form button').disabled = !atomicHandoffsReady;
      const requested = new URL(location.href).searchParams.get('encounter');
      await loadReferences(requested);
      const requestedStep = new URL(location.href).searchParams.get('step');
      if (requestedStep) setStep(requestedStep);
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = error.message;
    }
  }

  $$('[data-clinical-step]').forEach(button => button.addEventListener('click', () => setStep(button.dataset.clinicalStep)));
  $('#encounter').addEventListener('change', event => selectEncounter(event.target.value).catch(fail));
  $('#rx-product').addEventListener('change', syncPrescriptionUnit);
  $('#enc-verification-method').addEventListener('change', syncVerificationNoteRequirement);
  $('#encounter-form').addEventListener('submit', event => saveEncounter(event).catch(fail));
  $('#exam-form').addEventListener('submit', event => saveExam(event).catch(fail));
  $('#plan-form').addEventListener('submit', event => savePlan(event).catch(fail));
  $('#prescription-item-form').addEventListener('submit', event => { try { addPrescriptionItem(event); } catch (error) { fail(error); } });
  $('#prescription-form').addEventListener('submit', event => sendPrescription(event).catch(fail));
  $('#logout').addEventListener('click', async () => { await db.auth.signOut(); location.replace('/login.html'); });
  window.addEventListener('chananya:diagnosis-saved', () => { if (currentEncounter) loadEncounter().catch(fail); });
  window.addEventListener('chananya:clinical-data-changed', event => {
    if (currentEncounter && (!event.detail?.encounterId || event.detail.encounterId === currentEncounter)) loadEncounter().catch(fail);
  });
  window.addEventListener('chananya:signoff-changed', event => { markStep('signoff', Boolean(event.detail?.locked)); });
  renderPrescriptionCart();
  init();
})();
