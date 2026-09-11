(() => {
  'use strict';

  const runtime = window.ChananyaRuntime;
  if (!runtime) { console.error('ChananyaRuntime is required before OPD workflow'); return; }

  const $ = selector => document.querySelector(selector);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const valueOf = selector => $(selector)?.value || null;
  const numberOf = selector => {
    const value = $(selector)?.value;
    return value === '' || value == null ? null : Number(value);
  };
  const setValue = (selector, value) => { const element = $(selector); if (element) element.value = value ?? ''; };

  let db;
  let user;
  let currentEncounter = null;
  let disposed = false;
  let selectionGeneration = 0;
  const editGeneration = { history: 0, session: 0 };
  const readState = { history: 'idle', session: 'idle' };
  const inFlight = { history: false, session: false };
  const uncertainGuard = {
    history: { key: 'chananya.opd.v1.history.uncertain', blocked: false, token: null },
    session: { key: 'chananya.opd.v1.session.uncertain', blocked: false, token: null }
  };

  function guardStatus(kind) {
    return uncertainGuard[kind].blocked ? ' · บันทึกถูกระงับ: ผลการบันทึกก่อนหน้าไม่แน่ชัด กรุณาตรวจสอบรายการ' : '';
  }
  function setStatus(kind, message) {
    const element = kind === 'history' ? $('#opd-history-status') : $('#opd-session-status');
    if (element) element.textContent = `${message}${guardStatus(kind)}`;
  }
  function markGuardBlocked(kind) {
    uncertainGuard[kind].blocked = true;
    if (disposed) return;
    const element = kind === 'history' ? $('#opd-history-status') : $('#opd-session-status');
    if (element && !element.textContent.includes('บันทึกถูกระงับ')) element.textContent += guardStatus(kind);
  }
  function readGuard(kind) {
    const guard = uncertainGuard[kind];
    try {
      const storage = window.sessionStorage;
      if (!storage || typeof storage.getItem !== 'function') throw new Error('UNCERTAIN_GUARD_STORAGE_UNAVAILABLE');
      const marker = storage.getItem(guard.key);
      if (marker === null) return true;
      if (!/^[-0-9a-f]{36}$/i.test(marker)) { markGuardBlocked(kind); return false; }
      markGuardBlocked(kind);
      return false;
    } catch (error) { markGuardBlocked(kind); return false; }
  }
  function installGuard(kind) {
    const guard = uncertainGuard[kind];
    if (guard.blocked || !readGuard(kind)) return false;
    try {
      const token = window.crypto?.randomUUID?.();
      if (!token) throw new Error('UNCERTAIN_GUARD_TOKEN_UNAVAILABLE');
      const storage = window.sessionStorage;
      if (!storage || typeof storage.setItem !== 'function' || typeof storage.getItem !== 'function') throw new Error('UNCERTAIN_GUARD_STORAGE_UNAVAILABLE');
      storage.setItem(guard.key, token);
      if (storage.getItem(guard.key) !== token) throw new Error('UNCERTAIN_GUARD_READBACK_FAILED');
      guard.token = token;
      return true;
    } catch (error) { markGuardBlocked(kind); return false; }
  }
  function clearGuard(kind) {
    const guard = uncertainGuard[kind];
    if (!guard.token || disposed) return false;
    try {
      const storage = window.sessionStorage;
      if (!storage || typeof storage.getItem !== 'function' || typeof storage.removeItem !== 'function') throw new Error('UNCERTAIN_GUARD_STORAGE_UNAVAILABLE');
      if (storage.getItem(guard.key) !== guard.token) { markGuardBlocked(kind); return false; }
      storage.removeItem(guard.key);
      if (storage.getItem(guard.key) !== null) throw new Error('UNCERTAIN_GUARD_REMOVE_FAILED');
      guard.token = null; guard.blocked = false;
      return true;
    } catch (error) { markGuardBlocked(kind); return false; }
  }

  const context = () => ({ id: currentEncounter, generation: selectionGeneration });
  const isCurrent = captured => !disposed && captured.id === currentEncounter && captured.generation === selectionGeneration;
  const formFor = kind => kind === 'history' ? $('#opd-history-form') : $('#opd-session-form');
  function setBusy(kind, busy) {
    const form = formFor(kind);
    if (disposed || !form) return;
    // The workflow lock is inFlight; controls may also be disabled by signoff/access code.
    // Never mutate disabled state, so completion cannot re-enable an external lock.
    form.setAttribute?.('aria-busy', busy ? 'true' : 'false');
  }

  function emitChanged(source, encounterId) {
    if (disposed || !encounterId) return;
    window.dispatchEvent(new CustomEvent('chananya:clinical-data-changed', { detail: { encounterId, source } }));
  }

  async function loadHistory(captured = context()) {
    const form = $('#opd-history-form');
    if (disposed || !captured.id) { readState.history = 'idle'; return; }
    const capturedEdit = editGeneration.history;
    readState.history = 'pending';
    let result;
    try { result = await db.from('ttm_opd_histories').select('*').eq('encounter_id', captured.id).maybeSingle(); }
    catch (error) { if (isCurrent(captured)) { readState.history = 'failed'; setStatus('history', 'อ่าน OPD History ไม่ได้หรือไม่มีสิทธิ์'); } return; }
    if (!isCurrent(captured)) return;
    if (result.error) { readState.history = 'failed'; setStatus('history', 'อ่าน OPD History ไม่ได้หรือไม่มีสิทธิ์'); return; }
    readState.history = 'ready';
    if (capturedEdit !== editGeneration.history) {
      readState.history = 'conflict';
      setStatus('history', 'มีการแก้ไขข้อมูลระหว่างโหลด กรุณาตรวจสอบก่อนบันทึก');
      return;
    }
    const data = result.data || {};
    setValue('#opd-accident', data.accident_history);
    setValue('#opd-surgery', data.surgery_history);
    setValue('#opd-chronic', data.chronic_diseases);
    setValue('#opd-family', data.family_history);
    setValue('#opd-personal', data.personal_history);
    setValue('#opd-food', data.food_pattern);
    setValue('#opd-water', data.water_glasses_per_day);
    setValue('#opd-coffee', data.tea_coffee_glasses_per_day);
    setValue('#opd-smoking', data.smoking_detail);
    setValue('#opd-alcohol', data.alcohol_detail);
    setValue('#opd-urination', data.urination_per_day);
    setValue('#opd-bowel', data.bowel_movement_per_day);
    setValue('#opd-sleep', data.sleep_detail);
    setValue('#opd-posture', data.posture_detail);
    setValue('#opd-emotion', data.emotional_state);
    setValue('#opd-allergy', data.allergy_food_drug);
    setValue('#opd-menstruation', data.menstruation_detail);
    setValue('#opd-meds', data.current_medicines_supplements);
    setValue('#opd-physical', data.physical_exam_narrative);
    setStatus('history', result.data ? 'โหลด OPD History แล้ว' : 'ยังไม่มี OPD History ใน Encounter นี้');
  }

  async function saveHistory(event) {
    event.preventDefault();
    if (disposed) return;
    const captured = context();
    if (disposed || inFlight.history || !captured.id || readState.history !== 'ready' || uncertainGuard.history.blocked) { setStatus('history', disposed || !captured.id ? 'เลือก Encounter ก่อน' : inFlight.history ? 'กำลังบันทึก OPD History กรุณารอสักครู่' : uncertainGuard.history.blocked ? 'ยังบันทึกไม่ได้ เนื่องจากผลการบันทึกก่อนหน้าไม่แน่ชัด' : readState.history === 'pending' ? 'กำลังโหลด OPD History กรุณารอสักครู่' : readState.history === 'conflict' ? 'มีฉบับร่างระหว่างโหลด กรุณาตรวจสอบและโหลดใหม่ก่อนบันทึก' : 'ยังบันทึกไม่ได้ เนื่องจากอ่าน OPD History ไม่สำเร็จ'); return; }
    inFlight.history = true; setBusy('history', true);
    const capturedEdit = editGeneration.history;
    const payload = {
      encounter_id: captured.id,
      accident_history: valueOf('#opd-accident'),
      surgery_history: valueOf('#opd-surgery'),
      chronic_diseases: valueOf('#opd-chronic'),
      family_history: valueOf('#opd-family'),
      personal_history: valueOf('#opd-personal'),
      food_pattern: valueOf('#opd-food'),
      water_glasses_per_day: numberOf('#opd-water'),
      tea_coffee_glasses_per_day: numberOf('#opd-coffee'),
      smoking_detail: valueOf('#opd-smoking'),
      alcohol_detail: valueOf('#opd-alcohol'),
      urination_per_day: numberOf('#opd-urination'),
      bowel_movement_per_day: numberOf('#opd-bowel'),
      sleep_detail: valueOf('#opd-sleep'),
      posture_detail: valueOf('#opd-posture'),
      emotional_state: valueOf('#opd-emotion'),
      allergy_food_drug: valueOf('#opd-allergy'),
      menstruation_detail: valueOf('#opd-menstruation'),
      current_medicines_supplements: valueOf('#opd-meds'),
      physical_exam_narrative: valueOf('#opd-physical'),
      updated_by: user.id,
      updated_at: new Date().toISOString()
    };
    try {
      const existing = await db.from('ttm_opd_histories').select('id').eq('encounter_id', captured.id).maybeSingle();
      if (existing.error) throw existing.error;
      if (!isCurrent(captured) || capturedEdit !== editGeneration.history) return;
      if (!installGuard('history')) { setStatus('history', 'ยังบันทึกไม่ได้ เนื่องจากผลการบันทึกก่อนหน้าไม่แน่ชัด'); return; }
      if (!existing.data) payload.created_by = user.id;
      const result = await db.from('ttm_opd_histories').upsert(payload, { onConflict: 'encounter_id' });
      if (result.error) throw result.error;
      clearGuard('history');
      if (isCurrent(captured)) { setStatus('history', capturedEdit === editGeneration.history ? 'บันทึก OPD History แล้ว' : 'บันทึกฉบับก่อนหน้าแล้ว แต่มีฉบับร่างใหม่ที่ยังไม่ได้บันทึก'); emitChanged('opd-history', captured.id); }
    } catch (error) { if (uncertainGuard.history.token || uncertainGuard.history.blocked) markGuardBlocked('history'); if (isCurrent(captured)) setStatus('history', uncertainGuard.history.token || uncertainGuard.history.blocked ? 'ผลการบันทึก OPD History ไม่แน่ชัด กรุณาตรวจสอบรายการก่อนลองใหม่' : 'บันทึก OPD History ไม่สำเร็จ กรุณาลองใหม่'); }
    finally { inFlight.history = false; setBusy('history', false); }
  }

  async function loadSessions(captured = context()) {
    const box = $('#opd-session-list');
    if (!box) return false;
    if (disposed || !captured.id) { readState.session = 'idle'; return false; }
    readState.session = 'pending';
    let result;
    try { result = await db.from('clinical_treatment_sessions').select('*').eq('encounter_id', captured.id).order('session_no'); }
    catch (error) { if (isCurrent(captured)) { readState.session = 'failed'; box.innerHTML = '<div class="status danger">อ่าน Treatment Session ไม่ได้หรือไม่มีสิทธิ์</div>'; setStatus('session', 'อ่าน Treatment Session ไม่ได้หรือไม่มีสิทธิ์'); } return false; }
    if (!isCurrent(captured)) return false;
    if (result.error) { readState.session = 'failed'; box.innerHTML = '<div class="status danger">อ่าน Treatment Session ไม่ได้หรือไม่มีสิทธิ์</div>'; setStatus('session', 'อ่าน Treatment Session ไม่ได้หรือไม่มีสิทธิ์'); return false; }
    readState.session = 'ready';
    const rows = result.data || [];
    box.innerHTML = rows.map(treatment => `<article class="opd-session"><strong>Session ${treatment.session_no}</strong> · ${esc(new Date(treatment.treated_at).toLocaleString('th-TH'))}<br>${esc((treatment.treatment_modalities || []).join(', '))}<br>${esc(treatment.treatment_detail)}<br><b>Pain:</b> ${esc(treatment.pain_before ?? '-')} → ${esc(treatment.pain_after ?? '-')}<br><b>Outcome:</b> ${esc(treatment.outcome_summary || '-')}</article>`).join('') || '<div class="status">ยังไม่มี Treatment Session</div>';
    setStatus('session', rows.length ? 'โหลด Treatment Session แล้ว' : 'ยังไม่มี Treatment Session');
    return true;
  }

  async function saveSession(event) {
    event.preventDefault();
    if (disposed) return;
    const captured = context();
    if (disposed || inFlight.session || !captured.id || readState.session !== 'ready' || uncertainGuard.session.blocked) { setStatus('session', disposed || !captured.id ? 'เลือก Encounter ก่อน' : inFlight.session ? 'กำลังบันทึก Treatment Session กรุณารอสักครู่' : uncertainGuard.session.blocked ? 'ยังบันทึกไม่ได้ เนื่องจากผลการบันทึกก่อนหน้าไม่แน่ชัด' : readState.session === 'pending' ? 'กำลังโหลด Treatment Session กรุณารอสักครู่' : 'ยังบันทึกไม่ได้ เนื่องจากอ่าน Treatment Session ไม่สำเร็จ'); return; }
    inFlight.session = true; setBusy('session', true);
    const capturedEdit = editGeneration.session;
    const modalities = [...document.querySelectorAll('input[name="opd-modality"]:checked')].map(input => input.value);
    const sessionPayload = {
      p_encounter_id: captured.id,
      p_treatment_modalities: modalities,
      p_treatment_detail: valueOf('#opd-treatment-detail'),
      p_procedure_referral: $('#opd-procedure-referral').checked,
      p_procedure_referral_detail: valueOf('#opd-procedure-detail'),
      p_precautions: valueOf('#opd-precautions'),
      p_pain_before: numberOf('#opd-pain-before'),
      p_pain_after: numberOf('#opd-pain-after'),
      p_outcome_summary: valueOf('#opd-outcome'),
      p_advice: valueOf('#opd-advice')
    };
    let mutationSucceeded = false;
    try {
    if (!installGuard('session')) { setStatus('session', 'ยังบันทึกไม่ได้ เนื่องจากผลการบันทึกก่อนหน้าไม่แน่ชัด'); return; }
    const result = await db.rpc('create_clinical_treatment_session', sessionPayload);
    if (result.error) throw result.error;
    mutationSucceeded = true;
    clearGuard('session');
    if (isCurrent(captured)) {
      const newerDraft = capturedEdit !== editGeneration.session;
      if (!newerDraft) event.target.reset();
      setStatus('session', newerDraft ? 'บันทึกฉบับก่อนหน้าแล้ว แต่มีฉบับร่างใหม่ที่ยังไม่ได้บันทึก' : 'บันทึก Treatment Session แล้ว');
      emitChanged('treatment-session', captured.id);
      if (!newerDraft) {
        const refreshed = await loadSessions(captured);
        if (isCurrent(captured)) {
          const draftSuffix = editGeneration.session === capturedEdit ? '' : ' แต่มีฉบับร่างใหม่ที่ยังไม่ได้บันทึก';
          setStatus('session', refreshed ? `บันทึก Treatment Session แล้ว${draftSuffix}` : `บันทึก Treatment Session แล้ว แต่โหลดรายการซ้ำไม่สำเร็จ${draftSuffix}`);
        }
      }
    }
    } catch (error) { if (!mutationSucceeded) markGuardBlocked('session'); if (isCurrent(captured)) setStatus('session', mutationSucceeded ? 'บันทึก Treatment Session แล้ว แต่โหลดรายการซ้ำไม่สำเร็จ' : 'ผลการบันทึก Treatment Session ไม่แน่ชัด กรุณาตรวจสอบรายการก่อนลองใหม่'); }
    finally { inFlight.session = false; setBusy('session', false); }
  }

  function fail(error) {
    console.error(error);
    alert(error?.message || String(error));
  }

  // No callback from an in-flight read/write may apply after the page is being left.
  window.addEventListener('pagehide', () => { disposed = true; selectionGeneration += 1; currentEncounter = null; });
  window.addEventListener('pageshow', event => {
    if (event.persisted && disposed) {
      setStatus('history', 'หน้านี้กลับจากแคช กรุณาโหลดหน้าใหม่ก่อนทำงานต่อ');
      setStatus('session', 'หน้านี้กลับจากแคช กรุณาโหลดหน้าใหม่ก่อนทำงานต่อ');
    }
  });

  async function init() {
    db = runtime.getDb();
    const runtimeSession = await runtime.getSession();
    if (disposed || !runtimeSession) return;
    user = runtimeSession.user;
    readGuard('history'); readGuard('session');
    const historyForm = $('#opd-history-form');
    const sessionForm = $('#opd-session-form');
    const encounter = $('#encounter');
    if (!historyForm || !sessionForm || !encounter) return;
    historyForm.addEventListener('input', () => { editGeneration.history += 1; });
    historyForm.addEventListener('change', () => { editGeneration.history += 1; });
    sessionForm.addEventListener('input', () => { editGeneration.session += 1; });
    sessionForm.addEventListener('change', () => { editGeneration.session += 1; });
    historyForm.addEventListener('submit', event => saveHistory(event).catch(fail));
    sessionForm.addEventListener('submit', event => saveSession(event).catch(fail));
    encounter.addEventListener('change', async () => {
      if (disposed) return;
      selectionGeneration += 1;
      currentEncounter = encounter.value || null;
      editGeneration.history += 1;
      editGeneration.session += 1;
      readState.history = currentEncounter ? 'pending' : 'idle';
      readState.session = currentEncounter ? 'pending' : 'idle';
      historyForm.reset();
      sessionForm.reset();
      $('#opd-session-list').innerHTML = currentEncounter ? '<div class="status">กำลังโหลด Treatment Session…</div>' : '<div class="status">เลือก Encounter ก่อน</div>';
      setStatus('history', currentEncounter ? 'กำลังโหลด OPD History…' : 'เลือก Encounter ก่อน');
      setStatus('session', currentEncounter ? 'กำลังโหลด Treatment Session…' : 'เลือก Encounter ก่อน');
      const captured = context();
      await Promise.all([loadHistory(captured), loadSessions(captured)]);
    });
    selectionGeneration += 1;
    currentEncounter = encounter.value || null;
    readState.history = currentEncounter ? 'pending' : 'idle';
    readState.session = currentEncounter ? 'pending' : 'idle';
    historyForm.reset();
    sessionForm.reset();
    $('#opd-session-list').innerHTML = currentEncounter ? '<div class="status">กำลังโหลด Treatment Session…</div>' : '<div class="status">เลือก Encounter ก่อน</div>';
    setStatus('history', currentEncounter ? 'กำลังโหลด OPD History…' : 'เลือก Encounter ก่อน');
    setStatus('session', currentEncounter ? 'กำลังโหลด Treatment Session…' : 'เลือก Encounter ก่อน');
    if (disposed) return;
    const initialContext = context();
    await Promise.all([loadHistory(initialContext), loadSessions(initialContext)]);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => init().catch(fail), { once: true });
  else init().catch(fail);
})();
