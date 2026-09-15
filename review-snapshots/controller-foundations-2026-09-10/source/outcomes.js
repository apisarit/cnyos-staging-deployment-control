(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));

  let db;
  let session;
  let profile;

  const dateLabel = value => value
    ? new Date(value).toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' })
    : '-';
  const score = value => value === null || value === undefined ? '-' : String(value);

  function isoDay(date) {
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
    return local.toISOString().slice(0, 10);
  }

  function setDefaultRange() {
    const today = new Date();
    const from = new Date(today);
    from.setDate(from.getDate() - 89);
    $('#outcomes-from').value = isoDay(from);
    $('#outcomes-to').value = isoDay(today);
    $('#outcomes-query').value = '';
  }

  function rangeArgs() {
    const from = $('#outcomes-from').value;
    const to = $('#outcomes-to').value;
    if (!from || !to) throw new Error('กรุณาระบุช่วงวันที่ให้ครบ');
    const fromDate = new Date(`${from}T00:00:00`);
    const toExclusive = new Date(`${to}T00:00:00`);
    toExclusive.setDate(toExclusive.getDate() + 1);
    if (toExclusive <= fromDate) throw new Error('ช่วงวันที่ไม่ถูกต้อง');
    return { p_from: fromDate.toISOString(), p_to: toExclusive.toISOString() };
  }

  function summaryRow(data) {
    return Array.isArray(data) ? (data[0] || {}) : (data || {});
  }

  function renderSummary(row) {
    $('#outcomes-total').textContent = Number(row.total_sessions || 0).toLocaleString('th-TH');
    $('#outcomes-measured').textContent = Number(row.measured_sessions || 0).toLocaleString('th-TH');
    $('#outcomes-before').textContent = Number(row.average_pain_before || 0).toLocaleString('th-TH', { maximumFractionDigits: 2 });
    $('#outcomes-after').textContent = Number(row.average_pain_after || 0).toLocaleString('th-TH', { maximumFractionDigits: 2 });
    $('#outcomes-rate').textContent = `${Number(row.improvement_rate || 0).toLocaleString('th-TH', { maximumFractionDigits: 1 })}%`;
    $('#outcomes-followup').textContent = Number(row.followup_encounters || 0).toLocaleString('th-TH');
  }

  function renderRows(rows) {
    $('#outcomes-meta').textContent = `พบ ${rows.length.toLocaleString('th-TH')} treatment sessions ตามสิทธิ์และช่วงเวลาที่เลือก`;
    $('#outcomes-list').innerHTML = rows.map(row => {
      const change = row.pain_change;
      const changeClass = change > 0 ? 'improved' : change < 0 ? 'worse' : 'neutral';
      const changeLabel = change === null || change === undefined
        ? 'ยังไม่มีคะแนนครบ'
        : change > 0 ? `ดีขึ้น ${change}` : change < 0 ? `เพิ่มขึ้น ${Math.abs(change)}` : 'คงเดิม';
      const modalities = (row.treatment_modalities || []).map(item => `<span>${esc(item)}</span>`);
      const lots = (row.herbal_lots || []).map(item => `<span>Lot ${esc(item)}</span>`);
      const followup = row.next_followup_at
        ? `<p class="outcome-followup"><b>นัดติดตาม:</b> ${esc(dateLabel(row.next_followup_at))}${row.followup_status ? ` • ${esc(row.followup_status)}` : ''}</p>`
        : row.latest_followup_date
          ? `<p class="outcome-followup"><b>ติดตามล่าสุด:</b> ${esc(new Date(`${row.latest_followup_date}T00:00:00`).toLocaleDateString('th-TH'))}${row.followup_status ? ` • ${esc(row.followup_status)}` : ''}</p>`
          : '';
      return `<article class="outcome-card"><div class="outcome-main"><span class="page-kicker">${esc(row.encounter_no || 'Encounter')}</span><h3>${esc(row.hn || '-')} • ${esc(row.patient_name || 'ไม่ระบุชื่อ')}</h3><p>${esc(row.thai_diagnosis || 'ยังไม่ระบุการวินิจฉัยแพทย์แผนไทย')}</p><small>${esc(dateLabel(row.treated_at))} • ${esc(row.practitioner_name || 'ไม่ระบุผู้รักษา')}</small><div class="identity-proof-row">${[...modalities, ...lots].join('') || '<span>ไม่ระบุวิธีรักษา</span>'}</div>${row.outcome_summary ? `<p class="outcome-note"><b>Outcome:</b> ${esc(row.outcome_summary)}</p>` : ''}${row.advice ? `<p class="outcome-note"><b>Advice:</b> ${esc(row.advice)}</p>` : ''}${followup}</div><div class="outcome-score ${changeClass}"><small>Pain</small><strong>${esc(score(row.pain_before))} → ${esc(score(row.pain_after))}</strong><span>${esc(changeLabel)}</span></div></article>`;
    }).join('') || '<div class="status">ไม่พบผลลัพธ์ตามเงื่อนไขนี้</div>';
  }

  async function loadOutcomes() {
    const range = rangeArgs();
    const query = $('#outcomes-query').value.trim();
    $('#outcomes-meta').textContent = 'กำลังอ่านข้อมูลผลลัพธ์…';
    const [summaryResult, searchResult] = await Promise.all([
      db.rpc('clinical_outcomes_summary', range),
      db.rpc('search_clinical_outcomes', {
        ...range,
        p_query: query || null,
        p_limit: 100,
        p_offset: 0
      })
    ]);
    if (summaryResult.error) throw summaryResult.error;
    if (searchResult.error) throw searchResult.error;
    renderSummary(summaryRow(summaryResult.data));
    renderRows(searchResult.data || []);
  }

  function fail(error) {
    console.error(error);
    $('#outcomes-meta').textContent = error?.message || String(error);
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
      if (!runtime.can(profile, 'clinical_read')) {
        throw new Error('บัญชีนี้ไม่มีสิทธิ์อ่านผลลัพธ์ทางคลินิก — ข้อมูลผู้รับบริการเปิดเฉพาะผู้รักษาและ Super Admin');
      }
      window.ChananyaShell?.mount({ profile, session, active: 'outcomes' });
      setDefaultRange();
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
      await loadOutcomes();
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = error?.message || String(error);
    }
  }

  $('#outcomes-filter').addEventListener('submit', event => {
    event.preventDefault();
    loadOutcomes().catch(fail);
  });
  $('#outcomes-reset').addEventListener('click', () => {
    setDefaultRange();
    loadOutcomes().catch(fail);
  });
  $('#logout').addEventListener('click', async () => {
    if (db) await db.auth.signOut();
    location.replace('/login.html');
  });
  init();
})();
