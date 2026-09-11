(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const dateTime = value => new Date(value).toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' });

  let db;
  let session;
  let profile;
  let canOperate = false;
  let allPatients = [];

  const patientName = patient => [patient.title || patient.prefix, patient.first_name, patient.last_name].filter(Boolean).join(' ') || patient.full_name || patient.name || 'ไม่ระบุชื่อ';
  const patientLabel = patient => `${patient.hn || patient.patient_no || '-'} — ${patientName(patient)}${patient.phone ? ` • ${patient.phone}` : ''}`;

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2200);
  }

  function fail(error) { console.error(error); alert(error?.message || String(error)); }

  function renderPatients(rows) {
    $('#patient').innerHTML = '<option value="">เลือกผู้รับบริการ</option>' + rows.map(patient => `<option value="${patient.id}">${esc(patientLabel(patient))}</option>`).join('');
    window.dispatchEvent(new CustomEvent('chananya:appointments-rendered'));
  }

  async function loadPatients() {
    const result = await db.from('patients').select('*').order('created_at', { ascending: false }).limit(500);
    if (result.error) throw result.error;
    allPatients = result.data || [];
    renderPatients(allPatients);
  }

  async function loadSchedules() {
    $('#schedule-status').textContent = 'กำลังค้นหาช่วงเวลาว่าง…';
    let request = db.from('available_practitioner_schedules').select('*').gt('available_capacity', 0).order('starts_at');
    const from = $('#date-from').value;
    const to = $('#date-to').value;
    if (from) request = request.gte('starts_at', new Date(`${from}T00:00:00`).toISOString());
    if (to) request = request.lte('starts_at', new Date(`${to}T23:59:59`).toISOString());
    const result = await request;
    if (result.error) throw result.error;
    const term = $('#search').value.trim().toLowerCase();
    const rows = (result.data || []).filter(item => !term || [item.practitioner_name, item.specialty_name_th, item.specialty_name_en, item.title, item.room_code, item.branch_code].some(value => String(value || '').toLowerCase().includes(term)));
    $('#schedule-status').textContent = `พบ ${rows.length} ช่วงเวลาที่ว่าง`;
    $('#schedule-list').innerHTML = rows.map(item => `<article class="schedule-card"><h3>${esc(item.title)}</h3><div class="meta"><span>${esc(item.practitioner_name || '-')}</span><span>${esc(item.specialty_name_th || item.specialty_name_en || '-')}</span><span>${esc(dateTime(item.starts_at))} – ${esc(new Date(item.ends_at).toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' }))}</span><span>สาขา ${esc(item.branch_code || '-')} • ห้อง ${esc(item.room_code || '-')}</span></div><p><span class="capacity">ว่าง ${item.available_capacity}/${item.max_patients}</span></p>${canOperate ? `<button class="btn primary" data-book="${item.id}" data-label="${esc(item.title)} • ${esc(dateTime(item.starts_at))} • ${esc(item.practitioner_name || '-')}">เลือกช่วงเวลานี้</button>` : ''}</article>`).join('') || '<p class="muted">ไม่พบช่วงเวลาว่างตามเงื่อนไข</p>';
    document.querySelectorAll('[data-book]').forEach(button => {
      button.onclick = () => {
        $('#selected-schedule').value = button.dataset.book;
        $('#selected-schedule-label').value = button.dataset.label;
        $('#booking-status').textContent = 'เลือกช่วงเวลาแล้ว กรุณาเลือกผู้รับบริการ';
        $('#booking-section').scrollIntoView({ behavior: 'smooth' });
      };
    });
  }

  async function bookAppointment(event) {
    event.preventDefault();
    if (!canOperate) throw new Error('บัญชีนี้มีสิทธิ์ดูเท่านั้น');
    const scheduleId = $('#selected-schedule').value;
    const patientId = $('#patient').value;
    if (!scheduleId) throw new Error('กรุณาเลือกช่วงเวลาว่าง');
    if (!patientId) throw new Error('กรุณาเลือกผู้รับบริการ');
    $('#booking-status').classList.remove('danger');
    $('#booking-status').textContent = 'กำลังยืนยันการจอง…';
    const result = await db.rpc('book_clinic_appointment', { p_patient_id: patientId, p_schedule_id: scheduleId, p_chief_complaint: $('#chief-complaint').value || null, p_notes: $('#notes').value || null, p_booking_source: 'staff' });
    if (result.error) throw result.error;
    $('#booking-status').textContent = `จองสำเร็จ ${result.data.appointment_no} • คิว ${result.data.queue_number}`;
    event.target.reset();
    $('#selected-schedule-label').value = '';
    $('#selected-schedule').value = '';
    toast('จองนัดหมายสำเร็จ');
    await Promise.all([loadSchedules(), loadAppointments()]);
  }

  async function loadAppointments() {
    $('#appointment-list').innerHTML = '<p class="muted">กำลังโหลด…</p>';
    const day = $('#appointments-date').value;
    const status = $('#status-filter').value;
    let request = db.from('clinic_appointments').select('*').order('scheduled_start');
    if (day) request = request.gte('scheduled_start', new Date(`${day}T00:00:00`).toISOString()).lte('scheduled_start', new Date(`${day}T23:59:59`).toISOString());
    if (status) request = request.eq('status', status);
    const result = await request;
    if (result.error) throw result.error;
    const patientMap = Object.fromEntries(allPatients.map(patient => [patient.id, patient]));
    $('#appointment-list').innerHTML = (result.data || []).map(item => {
      const patient = patientMap[item.patient_id] || {};
      const actions = canOperate ? `${item.status === 'booked' ? `<button class="btn ghost" data-status="confirmed" data-id="${item.id}">ยืนยัน</button>` : ''}${['booked', 'confirmed'].includes(item.status) ? `<button class="btn ghost" data-status="checked_in" data-id="${item.id}">Check-in</button>` : ''}${item.status === 'checked_in' ? `<button class="btn ghost" data-status="in_service" data-id="${item.id}">เริ่มบริการ</button>` : ''}${item.status === 'in_service' ? `<button class="btn ghost" data-status="completed" data-id="${item.id}">เสร็จสิ้น</button>` : ''}${['booked', 'confirmed'].includes(item.status) ? `<button class="btn danger" data-cancel="${item.id}">ยกเลิก</button>` : ''}` : '';
      return `<article class="appt-row"><div><b>${esc(item.appointment_no)} • คิว ${item.queue_number}</b><small>${esc(patientLabel(patient))}</small><small>${esc(dateTime(item.scheduled_start))} • ${esc(item.status)}</small><small>${esc(item.chief_complaint || '')}</small></div><div class="actions">${actions}</div></article>`;
    }).join('') || '<p class="muted">ไม่มีรายการนัดหมาย</p>';
    document.querySelectorAll('[data-status]').forEach(button => { button.onclick = () => setStatus(button.dataset.id, button.dataset.status).catch(fail); });
    document.querySelectorAll('[data-cancel]').forEach(button => { button.onclick = () => cancelAppointment(button.dataset.cancel).catch(fail); });
  }

  async function setStatus(id, status) {
    if (!canOperate) throw new Error('บัญชีนี้มีสิทธิ์ดูเท่านั้น');
    const result = await db.rpc('set_clinic_appointment_status', { p_appointment_id: id, p_new_status: status, p_note: null });
    if (result.error) throw result.error;
    toast('อัปเดตสถานะแล้ว');
    await loadAppointments();
  }

  async function cancelAppointment(id) {
    if (!canOperate) throw new Error('บัญชีนี้มีสิทธิ์ดูเท่านั้น');
    const reason = prompt('เหตุผลที่ยกเลิก');
    if (reason === null) return;
    const result = await db.rpc('cancel_clinic_appointment', { p_appointment_id: id, p_reason: reason });
    if (result.error) throw result.error;
    toast('ยกเลิกนัดแล้ว');
    await Promise.all([loadSchedules(), loadAppointments()]);
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
      if (!runtime.can(profile, 'appointments_view')) throw new Error('บัญชีนี้ไม่มีสิทธิ์ดูระบบนัดหมาย');
      canOperate = runtime.can(profile, 'appointments_operate');
      window.ChananyaShell?.mount({ profile, session, active: 'appointments' });
      $('#view-only-notice').classList.toggle('hidden', canOperate);
      $('#booking-section').classList.toggle('hidden', !canOperate);
      const today = new Date();
      const in14 = new Date(today); in14.setDate(in14.getDate() + 14);
      $('#date-from').value = today.toISOString().slice(0, 10);
      $('#date-to').value = in14.toISOString().slice(0, 10);
      $('#appointments-date').value = today.toISOString().slice(0, 10);
      await loadPatients();
      await Promise.all([loadSchedules(), loadAppointments()]);
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = error.message;
    }
  }

  $('#patient-search').addEventListener('input', event => {
    const term = event.target.value.trim().toLowerCase();
    renderPatients(term ? allPatients.filter(patient => patientLabel(patient).toLowerCase().includes(term)).slice(0, 100) : allPatients);
  });
  $('#search-btn').addEventListener('click', () => loadSchedules().catch(fail));
  $('#booking-form').addEventListener('submit', event => bookAppointment(event).catch(error => { $('#booking-status').textContent = error.message; $('#booking-status').classList.add('danger'); fail(error); }));
  $('#refresh-appts').addEventListener('click', () => loadAppointments().catch(fail));
  $('#logout').addEventListener('click', async () => { await db.auth.signOut(); location.replace('/login.html'); });
  init();
})();
