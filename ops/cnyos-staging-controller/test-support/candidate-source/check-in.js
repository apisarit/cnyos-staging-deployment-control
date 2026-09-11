(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  let db;
  let session;
  let profile;
  let backendReady = false;
  let videoStream = null;
  let detector = null;
  let scanFrame = null;
  let lastDetectionAt = 0;
  let selected = null;
  const qrIssuer = String(window.CLINICAL_OS_CONFIG?.identity?.qrIssuer || 'CHANANYA').trim().toUpperCase();
  const qrPrefix = `${qrIssuer}:PT1:`;

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2200);
  }

  function fail(error) {
    console.error(error);
    const map = {
      QR_INVALID_EXPIRED_OR_USED: 'QR หรือรหัสหมดอายุ ถูกใช้แล้ว หรือไม่ตรงกับคลินิกนี้',
      PATIENT_CONFIRMATION_REQUIRED: 'กรุณาตรวจสอบและยืนยันตัวตนกับผู้รับบริการก่อน',
      GUARDIAN_NOTE_REQUIRED: 'กรุณาระบุชื่อและความสัมพันธ์ของผู้ดูแล',
      SEARCH_QUERY_LENGTH_INVALID: 'กรุณากรอกคำค้น 2–80 ตัวอักษร'
    };
    alert(map[error?.message] || error?.message || String(error));
  }

  function setBackendStatus(message, kind = '') {
    const element = $('#identity-backend-status');
    element.textContent = message;
    element.classList.toggle('danger', kind === 'danger');
  }

  function setBusy(busy) {
    $('#confirm-encounter').disabled = Boolean(busy);
    $('#scanner-start').disabled = Boolean(busy) || !backendReady || !detector;
  }

  function clearConfirmation() {
    selected = null;
    $('#identity-confirmation').classList.add('hidden');
    $('#confirmation-form').reset();
    $('#confirm-allergies').replaceChildren();
    $('#confirm-allergy-box').classList.add('hidden');
  }

  function showConfirmation(record, source) {
    selected = { ...record, source };
    $('#confirm-hn').textContent = record.hn || '—';
    $('#confirm-name').textContent = record.display_name || '—';
    $('#confirm-dob').textContent = record.date_of_birth
      ? new Date(`${record.date_of_birth}T00:00:00`).toLocaleDateString('th-TH')
      : 'ไม่ระบุ';
    $('#confirm-phone').textContent = record.phone_last4 ? `••••••${record.phone_last4}` : 'ไม่ระบุ';

    const allergies = Array.isArray(record.active_allergies) ? record.active_allergies : [];
    $('#confirm-allergies').replaceChildren();
    for (const allergy of allergies) {
      const item = document.createElement('li');
      item.textContent = [allergy.name, allergy.reaction, allergy.severity].filter(Boolean).join(' • ');
      $('#confirm-allergies').append(item);
    }
    $('#confirm-allergy-box').classList.toggle('hidden', allergies.length === 0);
    $('#verification-method-label').classList.toggle('hidden', source === 'qr');
    $('#verification-note-label').classList.toggle('hidden', source === 'qr');
    $('#identity-confirmation').classList.remove('hidden');
    $('#identity-confirmation').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function credentialArguments(value) {
    const trimmed = String(value || '').trim();
    const digits = trimmed.replace(/\D/g, '');
    if (digits.length === 6 && !trimmed.startsWith(qrPrefix)) {
      return { p_token: null, p_display_code: digits };
    }
    if (trimmed.startsWith(qrPrefix) && /^[A-Za-z0-9_-]{43}$/.test(trimmed.slice(qrPrefix.length))) {
      return { p_token: trimmed.slice(qrPrefix.length), p_display_code: null };
    }
    throw new Error('กรุณาสแกน QR ของคลินิกนี้ หรือกรอกรหัส 6 หลัก');
  }

  async function resolveCredential(value) {
    if (!backendReady) throw new Error('Identity backend ยังไม่เปิดใช้งาน');
    setBusy(true);
    try {
      const result = await db.rpc('resolve_patient_qr', credentialArguments(value));
      if (result.error) throw result.error;
      const record = Array.isArray(result.data) ? result.data[0] : result.data;
      if (!record) throw new Error('ไม่พบผู้รับบริการจาก QR นี้');
      stopScanner();
      $('#credential-form').reset();
      showConfirmation(record, 'qr');
      toast('พบผู้รับบริการแล้ว กรุณาตรวจสอบชื่อร่วมกัน');
    } finally {
      setBusy(false);
    }
  }

  async function searchPatients(event) {
    event.preventDefault();
    if (!backendReady) throw new Error('Identity backend ยังไม่เปิดใช้งาน');
    const result = await db.rpc('search_patients_for_checkin', { p_query: $('#manual-search').value.trim() });
    if (result.error) throw result.error;
    const rows = result.data || [];
    const host = $('#manual-results');
    host.replaceChildren();
    if (!rows.length) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'ไม่พบผู้รับบริการ กรุณาตรวจคำค้นหรือกลับไปลงทะเบียนผู้รับบริการ';
      host.append(empty);
      return;
    }
    for (const row of rows) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'item identity-result';
      const main = document.createElement('span');
      const name = document.createElement('b');
      name.textContent = `${row.hn} • ${row.display_name}`;
      const detail = document.createElement('small');
      detail.textContent = `${row.date_of_birth || 'ไม่ระบุวันเกิด'}${row.phone_last4 ? ` • โทรศัพท์ท้าย ${row.phone_last4}` : ''}`;
      main.append(name, detail);
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = 'เลือก';
      button.append(main, badge);
      button.addEventListener('click', () => showConfirmation(row, 'manual'));
      host.append(button);
    }
  }

  async function confirmEncounter(event) {
    event.preventDefault();
    if (!selected) throw new Error('กรุณาเลือกผู้รับบริการ');
    if (!$('#patient-present').checked) throw new Error('PATIENT_CONFIRMATION_REQUIRED');
    setBusy(true);
    try {
      const request = selected.source === 'qr'
        ? db.rpc('confirm_patient_qr', {
          p_qr_session_id: selected.qr_session_id,
          p_patient_present_confirmed: true,
          p_chief_complaint: $('#checkin-chief').value.trim() || null,
          p_intake: {}
        })
        : db.rpc('start_manual_patient_encounter', {
          p_patient_id: selected.patient_id,
          p_verification_method: $('#verification-method').value,
          p_patient_present_confirmed: true,
          p_verification_note: $('#verification-note').value.trim() || null,
          p_chief_complaint: $('#checkin-chief').value.trim() || null,
          p_intake: {}
        });
      const result = await request;
      if (result.error) throw result.error;
      const encounter = Array.isArray(result.data) ? result.data[0] : result.data;
      if (!encounter?.encounter_id) throw new Error('ไม่สามารถเปิด Encounter ได้');
      location.assign(`/clinical-v3.html?encounter=${encodeURIComponent(encounter.encounter_id)}&step=history`);
    } finally {
      setBusy(false);
    }
  }

  async function scanLoop(timestamp) {
    if (!videoStream || !detector) return;
    if (timestamp - lastDetectionAt > 250 && $('#scanner-video').readyState >= 2) {
      lastDetectionAt = timestamp;
      try {
        const codes = await detector.detect($('#scanner-video'));
        const value = codes.find(code => String(code.rawValue || '').startsWith(qrPrefix))?.rawValue;
        if (value) {
          await resolveCredential(value);
          return;
        }
      } catch (error) {
        console.warn('QR detection frame failed', error);
      }
    }
    scanFrame = requestAnimationFrame(scanLoop);
  }

  async function startScanner() {
    if (!detector || !navigator.mediaDevices?.getUserMedia) throw new Error('อุปกรณ์นี้ไม่รองรับกล้องสแกน กรุณาใช้รหัส 6 หลัก');
    stopScanner();
    videoStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } },
      audio: false
    });
    $('#scanner-video').srcObject = videoStream;
    await $('#scanner-video').play();
    $('#scanner-frame').classList.remove('hidden');
    $('#scanner-start').classList.add('hidden');
    $('#scanner-stop').classList.remove('hidden');
    scanFrame = requestAnimationFrame(scanLoop);
  }

  function stopScanner() {
    if (scanFrame) cancelAnimationFrame(scanFrame);
    scanFrame = null;
    if (videoStream) videoStream.getTracks().forEach(track => track.stop());
    videoStream = null;
    $('#scanner-video').srcObject = null;
    $('#scanner-frame').classList.add('hidden');
    $('#scanner-start').classList.remove('hidden');
    $('#scanner-stop').classList.add('hidden');
  }

  async function prepareScanner() {
    if (!('BarcodeDetector' in window) || !navigator.mediaDevices?.getUserMedia) {
      $('#scanner-support').textContent = 'เบราว์เซอร์นี้ไม่รองรับการอ่าน QR โดยตรง ใช้รหัส 6 หลักได้โดยไม่กระทบการรักษา';
      return;
    }
    const formats = await window.BarcodeDetector.getSupportedFormats().catch(() => []);
    if (!formats.includes('qr_code')) {
      $('#scanner-support').textContent = 'กล้องนี้ไม่รองรับ QR ใช้รหัส 6 หลักแทนได้';
      return;
    }
    detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    $('#scanner-support').textContent = 'พร้อมใช้กล้องหลังของโทรศัพท์สแกน QR';
    $('#scanner-start').disabled = !backendReady;
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
      if (!runtime.can(profile, 'patient_checkin')) throw new Error('บัญชีนี้ไม่มีสิทธิ์ยืนยันผู้รับบริการ');
      window.ChananyaShell?.mount({ profile, session, active: 'checkin' });

      const health = await db.rpc('hybrid_patient_identity_healthcheck');
      if (health.error) {
        backendReady = false;
        setBackendStatus('Identity migration ยังไม่ถูกเปิดในฐานข้อมูลนี้ ระบบเดิมยังใช้งานได้จากทะเบียนผู้รับบริการ', 'danger');
      } else {
        backendReady = Boolean((Array.isArray(health.data) ? health.data[0] : health.data)?.ready);
        setBackendStatus(backendReady
          ? 'Identity service พร้อม • HN ออกจากฐานข้อมูล • QR 90 วินาที • มี HN fallback'
          : 'ยังไม่พบ clinic context สำหรับบัญชีนี้', backendReady ? '' : 'danger');
      }

      await prepareScanner();
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = error.message;
    }
  }

  $('#scanner-start').addEventListener('click', () => startScanner().catch(fail));
  $('#scanner-stop').addEventListener('click', stopScanner);
  $('#credential-form').addEventListener('submit', event => {
    event.preventDefault();
    resolveCredential($('#credential-input').value).catch(fail);
  });
  $('#manual-search-form').addEventListener('submit', event => searchPatients(event).catch(fail));
  $('#confirmation-form').addEventListener('submit', event => confirmEncounter(event).catch(fail));
  $('#cancel-confirmation').addEventListener('click', clearConfirmation);
  $('#verification-method').addEventListener('change', event => {
    $('#verification-note-label').classList.toggle('hidden', event.target.value !== 'guardian_attestation');
  });
  $('#logout').addEventListener('click', async () => { stopScanner(); await db.auth.signOut(); location.replace('/login.html'); });
  window.addEventListener('pagehide', stopScanner);
  init();
})();
