(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const num = value => Number(value || 0);
  const optionalNumber = value => value === '' || value === null ? null : Number(value);

  let db;
  let session;
  let profile;
  let activeOrderId = null;
  let data = { products: [], formulas: [], orders: [], qc: [] };

  const errors = {
    QUALITY_DEPARTMENT_REQUIRED: 'บัญชีนี้ไม่มีสิทธิ์ Quality',
    QC_INDEPENDENCE_REQUIRED: 'บัญชีผู้ผลิต Batch นี้ห้ามเป็นผู้อนุมัติ Quality',
    PRODUCTION_OPERATOR_EVIDENCE_REQUIRED: 'Batch นี้ไม่มีหลักฐานผู้ผลิต จึงยังปล่อยผ่านไม่ได้',
    PRODUCTION_ORDER_NOT_AWAITING_QC: 'Batch นี้ไม่อยู่ในสถานะรอ Quality',
    QC_RESULT_SUMMARY_REQUIRED: 'กรุณาระบุผลตรวจอย่างน้อย 3 ตัวอักษร',
    QC_REJECTION_REASON_REQUIRED: 'กรุณาระบุเหตุผล Reject อย่างน้อย 5 ตัวอักษร'
  };

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2400);
  }

  function messageFor(error) {
    const raw = String(error?.message || error || 'เกิดข้อผิดพลาด');
    const code = Object.keys(errors).find(key => raw.includes(key));
    return code ? errors[code] : raw;
  }

  function fail(error) {
    console.error(error);
    alert(messageFor(error));
  }

  async function query(table, order) {
    let request = db.from(table).select('*');
    if (order) request = request.order(order, { ascending: false });
    const result = await request;
    if (result.error) throw result.error;
    return result.data || [];
  }

  async function rpc(name, args) {
    const result = await db.rpc(name, args);
    if (result.error) throw result.error;
    return Array.isArray(result.data) && result.data.length === 1 ? result.data[0] : result.data;
  }

  const product = id => data.products.find(item => item.id === id);
  const formula = id => data.formulas.find(item => item.id === id);
  const order = id => data.orders.find(item => item.id === id);
  const qcFor = id => data.qc.find(item => item.production_order_id === id);
  const isToday = value => value && new Date(value).toDateString() === new Date().toDateString();

  function orderLabel(item) {
    return `${item.production_order_no} • Batch ${item.batch_number}`;
  }

  function render() {
    const awaiting = data.orders.filter(item => item.status === 'awaiting_qc');
    const history = data.orders.filter(item => ['released', 'rejected'].includes(item.status));
    const blocked = awaiting.filter(item => !item.produced_by || num(item.actual_quantity) <= 0);
    $('#stat-awaiting').textContent = awaiting.length;
    $('#stat-passed').textContent = data.qc.filter(item => item.status === 'passed' && isToday(item.approved_at)).length;
    $('#stat-rejected').textContent = data.qc.filter(item => item.status === 'rejected' && isToday(item.tested_at)).length;
    $('#stat-blocked').textContent = blocked.length;

    $('#quality-queue').innerHTML = awaiting.map(item => {
      const finished = product(item.finished_product_id);
      const linkedFormula = formula(item.formula_id);
      const evidenceReady = Boolean(item.produced_by && num(item.actual_quantity) > 0);
      return `<article class="item column"><div class="row"><div><b>${esc(orderLabel(item))}</b><small>${esc(finished?.name_th || '-')} • Actual ${num(item.actual_quantity)} ${esc(item.planned_unit)} • Yield ${num(item.yield_percent)}%</small><small>Formula ${esc(linkedFormula?.formula_code || '-')} Rev.${esc(linkedFormula?.revision || '-')} • Producer evidence ${evidenceReady ? 'พร้อม' : 'ไม่ครบ'}</small></div><span class="badge">${evidenceReady ? 'awaiting_qc' : 'blocked'}</span></div><div class="right"><button class="btn primary" data-quality-act="release" data-id="${esc(item.id)}"${evidenceReady ? '' : ' disabled'}>QC Pass &amp; Release</button><button class="btn danger" data-quality-act="reject" data-id="${esc(item.id)}"${evidenceReady ? '' : ' disabled'}>QC Reject</button></div></article>`;
    }).join('') || '<p class="muted">ไม่มี Batch รอ Quality</p>';

    $('#quality-history').innerHTML = history.map(item => {
      const qc = qcFor(item.id);
      return `<article class="item"><div><b>${esc(orderLabel(item))} • ${esc(item.status)}</b><small>${esc(product(item.finished_product_id)?.name_th || '-')} • ${esc(qc?.result_summary || 'ไม่มีผลสรุป')}</small><small>${qc?.tested_at ? new Date(qc.tested_at).toLocaleString('th-TH') : '-'} • Quality evidence ${qc?.tested_by ? 'recorded' : 'missing'}</small></div><span class="badge">${esc(qc?.status || item.status)}</span></article>`;
    }).join('') || '<p class="muted">ยังไม่มีประวัติ Quality</p>';
  }

  async function load() {
    const [products, formulas, orders, qc] = await Promise.all([
      query('products', 'created_at'),
      query('formulas', 'created_at'),
      query('production_orders', 'created_at'),
      query('production_qc', 'created_at')
    ]);
    data = { products, formulas, orders, qc };
    render();
  }

  function openDialog(action, id) {
    const selected = order(id);
    if (!selected) return;
    activeOrderId = id;
    if (action === 'release') {
      $('#release-form').reset();
      $('#release-order-label').textContent = `${orderLabel(selected)} • Actual ${num(selected.actual_quantity)} ${selected.planned_unit}`;
      $('#release-dialog').showModal();
    } else {
      $('#reject-form').reset();
      $('#reject-summary').value = 'ไม่ผ่านข้อกำหนด';
      $('#reject-order-label').textContent = `${orderLabel(selected)} • Actual ${num(selected.actual_quantity)} ${selected.planned_unit}`;
      $('#reject-dialog').showModal();
    }
  }

  async function release(event) {
    event.preventDefault();
    await rpc('quality_release_production_order', {
      p_production_order_id: activeOrderId,
      p_result_summary: $('#qc-summary').value.trim(),
      p_sample_reference: $('#qc-sample').value.trim() || null,
      p_appearance_result: $('#qc-appearance').value.trim() || null,
      p_moisture_result: optionalNumber($('#qc-moisture').value),
      p_water_activity_result: optionalNumber($('#qc-water-activity').value),
      p_weight_result: optionalNumber($('#qc-weight').value)
    });
    $('#release-dialog').close();
    await load();
    toast('Quality Release, Finished Goods receipt และ Audit สำเร็จใน transaction เดียว');
  }

  async function reject(event) {
    event.preventDefault();
    await rpc('quality_reject_production_order', {
      p_production_order_id: activeOrderId,
      p_rejection_reason: $('#reject-reason').value.trim(),
      p_result_summary: $('#reject-summary').value.trim()
    });
    $('#reject-dialog').close();
    await load();
    toast('บันทึก Quality Reject และ Audit แล้ว');
  }

  async function detectQualityBoundary() {
    const result = await db.rpc('quality_release_healthcheck');
    const row = Array.isArray(result.data) ? result.data[0] : result.data;
    if (result.error || row?.ready !== true) {
      throw new Error('ฐานข้อมูล Independent Quality migration ยังไม่พร้อม ระบบหยุดการอนุมัติ');
    }
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
      if (!runtime.can(profile, 'quality_operate')) {
        throw new Error('บัญชีนี้ไม่มีสิทธิ์ Quality Workstation — แต่ละบัญชีเข้าได้เฉพาะแผนกของตน');
      }
      await detectQualityBoundary();
      window.ChananyaShell?.mount({ profile, session, active: 'quality' });
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
      await load();
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = messageFor(error);
    }
  }

  $('#quality-queue').addEventListener('click', event => {
    const button = event.target.closest('[data-quality-act]');
    if (button && !button.disabled) openDialog(button.dataset.qualityAct, button.dataset.id);
  });
  $$('[data-close-dialog]').forEach(button => button.addEventListener('click', () => button.closest('dialog')?.close()));
  $$('dialog').forEach(dialog => dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); }));
  $('#release-form').addEventListener('submit', event => release(event).catch(fail));
  $('#reject-form').addEventListener('submit', event => reject(event).catch(fail));
  $('#logout').addEventListener('click', async () => { if (db) await db.auth.signOut(); location.replace('/login.html'); });
  init();
})();
