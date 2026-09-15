(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const collator = new Intl.Collator(['th', 'en'], { sensitivity: 'base', numeric: true });
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const num = value => Number(value || 0);
  const optionalNumber = value => value === '' || value === null ? null : Number(value);

  let db;
  let session;
  let profile;
  let persistenceReady = false;
  let activeOrderId = null;
  let preview = { batchId: null, type: null, rows: [], valid: [] };

  const data = {
    products: [], lots: [], formulas: [], components: [], requests: [],
    orders: [], issues: [], qc: [], receipts: []
  };

  const errorLabels = {
    PRODUCTION_DEPARTMENT_REQUIRED: 'บัญชีนี้ไม่มีสิทธิ์ Production',
    PRODUCTION_REQUEST_NOT_FOUND: 'ไม่พบคำขอผลิตในคลินิกนี้',
    PRODUCTION_REQUEST_NOT_OPEN: 'คำขอผลิตนี้ไม่อยู่ในสถานะเปิด',
    APPROVED_FORMULA_NOT_FOUND: 'ไม่พบสูตรที่อนุมัติสำหรับสินค้านี้',
    FORMULA_COMPONENT_REQUIRED: 'สูตรยังไม่มีรายการวัตถุดิบ',
    PRODUCTION_MATERIAL_INSUFFICIENT: 'วัตถุดิบที่ยังไม่หมดอายุมีไม่เพียงพอ ระบบยกเลิกการเบิกทั้งหมดแล้ว',
    PRODUCTION_UNIT_CONVERSION_REQUIRED: 'หน่วยวัตถุดิบไม่ตรงกับ Product Master ต้องกำหนด conversion ก่อน',
    PRODUCTION_LOT_UNIT_MISMATCH: 'หน่วยของ Lot ไม่ตรงกับสูตร ระบบไม่ได้ตัด Stock',
    IMPORT_BATCH_NOT_VALIDATED: 'ชุด Import นี้ยังไม่ผ่านการตรวจสอบ',
    IMPORT_VALID_ROW_REQUIRED: 'ไม่มีแถวที่ถูกต้องสำหรับ Import'
  };

  function messageFor(error) {
    const raw = error?.message || String(error);
    const key = Object.keys(errorLabels).find(item => raw.includes(item));
    return key ? errorLabels[key] : raw;
  }

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('show');
    window.setTimeout(() => element.classList.remove('show'), 2600);
  }

  function fail(error) {
    console.error(error);
    alert(messageFor(error));
  }

  function product(id) { return data.products.find(item => item.id === id); }
  function formula(id) { return data.formulas.find(item => item.id === id); }
  function order(id) { return data.orders.find(item => item.id === id); }

  async function waitRuntime() {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (window.ChananyaRuntime) return window.ChananyaRuntime;
      await new Promise(resolve => window.setTimeout(resolve, 100));
    }
    throw new Error('ChananyaRuntime ไม่พร้อมใช้งาน');
  }

  async function query(table, orderBy) {
    let request = db.from(table).select('*');
    if (orderBy) request = request.order(orderBy, { ascending: false });
    const result = await request;
    if (result.error) throw result.error;
    return result.data || [];
  }

  async function rpc(name, parameters) {
    if (!persistenceReady) {
      throw new Error('ฐานข้อมูล Production ยังไม่พร้อม ระบบหยุดการเขียนเพื่อป้องกันข้อมูลครึ่งชุด');
    }
    const result = await db.rpc(name, parameters);
    if (result.error) throw result.error;
    return Array.isArray(result.data) && result.data.length === 1 ? result.data[0] : result.data;
  }

  async function load() {
    const rows = await Promise.all([
      query('products', 'updated_at'),
      query('inventory_lots', 'created_at'),
      query('formulas', 'updated_at'),
      query('formula_components'),
      query('production_requests', 'requested_at'),
      query('production_orders', 'created_at'),
      query('production_material_issues', 'issued_at'),
      query('production_qc', 'created_at'),
      query('finished_goods_receipts', 'received_at')
    ]);
    [
      'products', 'lots', 'formulas', 'components', 'requests',
      'orders', 'issues', 'qc', 'receipts'
    ].forEach((key, index) => { data[key] = rows[index]; });
    render();
  }

  function options(rows, label, selected = '') {
    const sorted = [...rows].sort((left, right) => collator.compare(label(left), label(right)));
    return '<option value="">เลือก</option>' + sorted.map(item => (
      `<option value="${esc(item.id)}"${item.id === selected ? ' selected' : ''}>${esc(label(item))}</option>`
    )).join('');
  }

  function syncFormulaUnit() {
    const selected = product($('#f-product')?.value);
    if ($('#f-unit')) $('#f-unit').value = selected?.stock_unit || '';
  }

  function syncComponentUnit() {
    const selected = product($('#c-material')?.value);
    if ($('#c-unit')) $('#c-unit').value = selected?.stock_unit || '';
  }

  function render() {
    const selectedFinishedProduct = $('#f-product')?.value || '';
    const selectedFormula = $('#c-formula')?.value || '';
    const selectedMaterial = $('#c-material')?.value || '';
    const runtimeRoles = window.ChananyaRuntime?.rolesOf(profile);
    $('#role').textContent = runtimeRoles?.effectiveRole || 'production';

    $('#f-product').innerHTML = options(
      data.products.filter(item => item.active !== false),
      item => `${item.sku} — ${item.name_th}`,
      selectedFinishedProduct
    );
    $('#c-formula').innerHTML = options(
      data.formulas.filter(item => item.status !== 'inactive'),
      item => `${item.formula_code} Rev.${item.revision} — ${item.name_th}`,
      selectedFormula
    );
    $('#c-material').innerHTML = options(
      data.products.filter(item => item.active !== false && [
        'raw_material', 'material', 'herb', 'packaging'
      ].includes(String(item.category || '').toLowerCase())),
      item => `${item.sku} — ${item.name_th}`,
      selectedMaterial
    );

    syncFormulaUnit();
    syncComponentUnit();
    $('#stat-requests').textContent = data.requests.filter(item => ![
      'fulfilled', 'cancelled', 'rejected'
    ].includes(item.status)).length;
    $('#stat-orders').textContent = data.orders.filter(item => ![
      'released', 'rejected', 'cancelled'
    ].includes(item.status)).length;
    $('#stat-qc').textContent = data.orders.filter(item => item.status === 'awaiting_qc').length;
    $('#stat-released').textContent = data.orders.filter(item => item.status === 'released').length;
    $('#stat-low').textContent = data.products.filter(item => {
      const quantity = data.lots
        .filter(lot => lot.product_id === item.id && lot.status === 'active')
        .reduce((total, lot) => total + num(lot.current_quantity), 0);
      return quantity <= num(item.reorder_level);
    }).length;

    renderRequests();
    renderOrders();
    renderFormulas();
    renderMaterials();
    bindActions();
    window.dispatchEvent(new CustomEvent('chananya:production-rendered'));
  }

  function renderRequests() {
    const rows = data.requests.map(request => {
      const requestedProduct = product(request.requested_product_id);
      const linkedOrder = data.orders.find(item => item.production_request_id === request.id);
      const requiredBy = request.required_by
        ? new Date(request.required_by).toLocaleString('th-TH')
        : 'ไม่กำหนด';
      const button = !linkedOrder && request.status === 'requested'
        ? `<button class="btn primary" data-act="open-order" data-id="${esc(request.id)}">เปิด Production Order</button>`
        : '';
      return `<div class="item column"><div class="row"><div><b>${esc(request.request_no)} • ${esc(requestedProduct?.name_th || '-')}</b><small>${num(request.requested_quantity)} ${esc(request.unit)} • ${esc(request.priority)} • ต้องการ ${esc(requiredBy)}</small><small>เหตุผล: ${esc(request.reason || 'out_of_stock')}</small></div><span class="badge">${esc(request.status)}</span></div>${button ? `<div class="right">${button}</div>` : ''}</div>`;
    }).join('');
    $('#request-list').innerHTML = rows || '<p class="muted">ยังไม่มีคำขอผลิตจาก Pharmacy</p>';
  }

  function renderOrders() {
    const rows = data.orders.map(item => {
      const finished = product(item.finished_product_id);
      const linkedFormula = formula(item.formula_id);
      const issueLines = data.issues.filter(issue => issue.production_order_id === item.id).length;
      const buttons = [];
      if (item.status === 'planned') {
        buttons.push(`<button class="btn primary" data-act="issue" data-id="${esc(item.id)}">เบิกวัตถุดิบ FEFO</button>`);
      }
      if (['materials_issued', 'in_process'].includes(item.status)) {
        buttons.push(`<button class="btn primary" data-act="complete" data-id="${esc(item.id)}">บันทึกผลผลิต</button>`);
      }
      if (item.status === 'awaiting_qc') {
        buttons.push('<span class="notice">ส่งให้ Independent Quality แล้ว • ผู้ผลิตไม่สามารถอนุมัติ Batch ของตนเอง</span>');
      }
      return `<div class="item column"><div class="row"><div><b>${esc(item.production_order_no)} • Batch ${esc(item.batch_number)}</b><small>${esc(finished?.name_th || '-')} • Plan ${num(item.planned_quantity)} ${esc(item.planned_unit)} • Formula ${esc(linkedFormula?.formula_code || '-')} Rev.${esc(linkedFormula?.revision || '-')}</small><small>Issued ${issueLines} lot line(s) • Actual ${num(item.actual_quantity)} • Yield ${num(item.yield_percent)}%</small></div><span class="badge">${esc(item.status)}</span></div>${buttons.length ? `<div class="right">${buttons.join('')}</div>` : ''}</div>`;
    }).join('');
    $('#order-list').innerHTML = rows || '<p class="muted">ยังไม่มี Production Order</p>';
  }

  function renderFormulas() {
    const formulas = data.formulas.map(item => (
      `<div class="item"><div><b>${esc(item.formula_code)} Rev.${esc(item.revision)} • ${esc(item.name_th)}</b><small>${esc(product(item.finished_product_id)?.name_th || '-')} • Batch ${num(item.standard_batch_size)} ${esc(item.batch_unit)} • ${esc(item.status)}</small></div><span class="badge">${esc(item.status)}</span></div>`
    )).join('');
    $('#formula-list').innerHTML = formulas || '<p class="muted">ยังไม่มี Formula</p>';

    const components = data.components.map(item => {
      const linkedFormula = formula(item.formula_id);
      return `<div class="item"><div><b>${esc(linkedFormula?.formula_code || '-')} Rev.${esc(linkedFormula?.revision || '-')} • ${esc(product(item.material_product_id)?.name_th || '-')}</b><small>${num(item.quantity_per_batch)} ${esc(item.unit)} • Sequence ${num(item.sequence_no)} • ${esc(item.process_stage || 'ไม่ระบุขั้นตอน')}</small></div></div>`;
    }).join('');
    $('#component-list').innerHTML = components || '<p class="muted">ยังไม่มี BOM Component</p>';
  }

  function renderMaterials() {
    const rows = [...data.lots]
      .sort((left, right) => (left.expiry_date || '9999').localeCompare(right.expiry_date || '9999'))
      .map(lot => `<div class="item"><div><b>${esc(product(lot.product_id)?.name_th || '-')} • Lot ${esc(lot.lot_number)}</b><small>EXP ${esc(lot.expiry_date || '-')} • ${esc(lot.storage_location || '-')} • ${esc(lot.status)}</small></div><span class="badge">${num(lot.current_quantity)} ${esc(lot.unit)}</span></div>`)
      .join('');
    $('#material-list').innerHTML = rows || '<p class="muted">ยังไม่มี Lot</p>';
  }

  function bindActions() {
    $$('[data-act]').forEach(button => {
      button.onclick = () => action(button.dataset.act, button.dataset.id, button).catch(fail);
    });
  }

  async function action(actionName, id, button) {
    if (button) button.disabled = true;
    try {
      if (actionName === 'open-order') {
        await rpc('open_production_order', {
          p_request_id: id, p_formula_id: null, p_planned_quantity: null
        });
        await load();
        toast('เปิด Production Order และบันทึก Audit แล้ว');
      } else if (actionName === 'issue') {
        if (!confirm('ยืนยันเบิกวัตถุดิบตาม FEFO? หากวัตถุดิบไม่พอ ระบบจะไม่ตัด Stock แม้แต่รายการเดียว')) return;
        await rpc('issue_production_materials_fefo', { p_production_order_id: id });
        await load();
        toast('เบิกวัตถุดิบ FEFO แบบ transaction เดียวแล้ว');
      } else if (actionName === 'complete') {
        openCompleteDialog(id);
      }
    } finally {
      if (button?.isConnected) button.disabled = false;
    }
  }

  function openCompleteDialog(id) {
    const selected = order(id);
    if (!selected) return;
    activeOrderId = id;
    $('#complete-form').reset();
    $('#complete-order-label').textContent = `${selected.production_order_no} • Plan ${num(selected.planned_quantity)} ${selected.planned_unit}`;
    $('#complete-actual').value = selected.actual_quantity || selected.planned_quantity;
    $('#complete-loss').value = selected.loss_quantity || 0;
    $('#complete-waste').value = selected.waste_quantity || 0;
    $('#complete-dialog').showModal();
  }

  async function saveCompletedOrder(event) {
    event.preventDefault();
    await rpc('complete_production_order', {
      p_production_order_id: activeOrderId,
      p_actual_quantity: num($('#complete-actual').value),
      p_loss_quantity: num($('#complete-loss').value),
      p_waste_quantity: num($('#complete-waste').value)
    });
    $('#complete-dialog').close();
    await load();
    toast('บันทึกผลผลิตและส่ง QC พร้อม Audit แล้ว');
  }

  async function saveFormula(event) {
    event.preventDefault();
    await rpc('upsert_production_formula', {
      p_formula_id: null,
      p_formula_code: $('#f-code').value.trim(),
      p_revision: $('#f-rev').value.trim(),
      p_name_th: $('#f-name').value.trim(),
      p_finished_product_id: $('#f-product').value,
      p_standard_batch_size: num($('#f-batch').value),
      p_batch_unit: $('#f-unit').value.trim(),
      p_expected_yield_percent: num($('#f-yield').value) || 100,
      p_shelf_life_days: optionalNumber($('#f-shelf').value),
      p_manufacturing_instructions: $('#f-instructions').value.trim() || null,
      p_status: $('#f-status').value
    });
    event.target.reset();
    $('#f-rev').value = '00';
    $('#f-yield').value = '100';
    await load();
    toast('บันทึก Formula และ Audit แล้ว');
  }

  async function saveComponent(event) {
    event.preventDefault();
    await rpc('upsert_production_formula_component', {
      p_component_id: null,
      p_formula_id: $('#c-formula').value,
      p_material_product_id: $('#c-material').value,
      p_sequence_no: num($('#c-seq').value) || 1,
      p_quantity_per_batch: num($('#c-qty').value),
      p_unit: $('#c-unit').value,
      p_process_stage: $('#c-stage').value.trim() || null,
      p_notes: null
    });
    event.target.reset();
    $('#c-seq').value = '1';
    await load();
    toast('เพิ่ม BOM Component และ Audit แล้ว');
  }

  const aliases = {
    sku: ['sku', 'product_code', 'รหัสสินค้า', 'รหัสวัตถุดิบ'],
    name_th: ['name_th', 'name', 'ชื่อ', 'ชื่อสินค้า', 'ชื่อวัตถุดิบ'],
    category: ['category', 'ประเภท'],
    stock_unit: ['stock_unit', 'unit', 'หน่วย'],
    dispense_unit: ['dispense_unit', 'หน่วยจ่าย'],
    supplier_code: ['supplier_code', 'รหัสผู้ขาย'],
    supplier_name: ['supplier_name', 'supplier', 'ชื่อผู้ขาย'],
    formula_code: ['formula_code', 'รหัสสูตร'],
    revision: ['revision', 'rev'],
    finished_sku: ['finished_sku', 'finished_product_sku', 'sku_finished'],
    batch_size: ['batch_size', 'standard_batch_size'],
    batch_unit: ['batch_unit', 'หน่วยผลิต'],
    material_sku: ['material_sku', 'raw_material_sku'],
    quantity: ['quantity', 'qty', 'จำนวน', 'quantity_per_batch'],
    sequence_no: ['sequence_no', 'sequence', 'ลำดับ'],
    unit: ['unit', 'หน่วย'],
    lot_number: ['lot_number', 'lot', 'ล็อต'],
    expiry_date: ['expiry_date', 'expiry', 'วันหมดอายุ'],
    current_quantity: ['current_quantity', 'opening_qty', 'quantity', 'จำนวนคงเหลือ'],
    location: ['location', 'storage_location', 'ตำแหน่ง']
  };

  function normalize(row) {
    const normalized = {};
    for (const [key, names] of Object.entries(aliases)) {
      const source = Object.keys(row).find(rawKey => {
        const candidate = String(rawKey).trim();
        return names.includes(candidate.toLowerCase()) || names.includes(candidate);
      });
      if (source !== undefined && row[source] !== undefined && row[source] !== null && row[source] !== '') {
        normalized[key] = row[source];
      }
    }
    return normalized;
  }

  async function previewFile(event) {
    event.preventDefault();
    const file = $('#import-file').files[0];
    const type = $('#import-type').value;
    if (!file) throw new Error('กรุณาเลือกไฟล์');
    const buffer = await file.arrayBuffer();
    const workbook = XLSX.read(buffer, { type: 'array' });
    const sheetName = workbook.SheetNames[0];
    const rawRows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { defval: '' });
    if (!rawRows.length) throw new Error('ไฟล์ไม่มีข้อมูล');
    const rows = rawRows.map((raw, index) => ({
      row_number: index + 2,
      raw_data: raw,
      normalized_data: normalize(raw)
    }));
    const batch = await rpc('stage_production_import', {
      p_import_type: type,
      p_source_file_name: file.name,
      p_source_sheet_name: sheetName,
      p_rows: rows
    });
    const staged = await db.from('import_rows').select('*')
      .eq('import_batch_id', batch.id).order('row_number');
    if (staged.error) throw staged.error;
    preview = {
      batchId: batch.id,
      type,
      rows: staged.data || [],
      valid: (staged.data || []).filter(row => row.validation_status === 'valid')
    };
    renderPreview();
    toast(`ตรวจสอบบน Server แล้ว: ผ่าน ${batch.valid_rows} / ${batch.total_rows} rows`);
  }

  function renderPreview() {
    const rows = preview.rows;
    const keys = [...new Set(rows.flatMap(row => Object.keys(row.normalized_data || {})))];
    $('#import-summary').innerHTML = `<p><b>${rows.length}</b> rows • Valid <b>${preview.valid.length}</b> • Invalid <b>${rows.length - preview.valid.length}</b></p>`;
    $('#preview-table').innerHTML = `<thead><tr><th>Row</th><th>Status</th>${keys.map(key => `<th>${esc(key)}</th>`).join('')}</tr></thead><tbody>${rows.slice(0, 100).map(row => `<tr><td>${row.row_number}</td><td>${row.validation_status === 'valid' ? 'OK' : `<span class="error">${esc((row.validation_errors || []).join(', '))}</span>`}</td>${keys.map(key => `<td>${esc(row.normalized_data?.[key] ?? '')}</td>`).join('')}</tr>`).join('')}</tbody>`;
    $('#confirm-import').classList.toggle('hidden', !preview.valid.length);
  }

  async function confirmImport() {
    if (!preview.batchId) throw new Error('ยังไม่มี Import batch ที่ผ่านการตรวจสอบ');
    const result = await rpc('commit_production_import', { p_import_batch_id: preview.batchId });
    $('#confirm-import').classList.add('hidden');
    await load();
    toast(`Import แบบ transaction เดียวสำเร็จ ${result.imported_rows} rows`);
  }

  async function detectPersistence() {
    const result = await db.rpc('production_execution_healthcheck');
    const row = Array.isArray(result.data) ? result.data[0] : result.data;
    persistenceReady = !result.error && row?.ready === true;
    if (!persistenceReady) {
      throw new Error('ฐานข้อมูล Atomic Production migration ยังไม่พร้อม ระบบหยุดการเขียนเพื่อป้องกันข้อมูลครึ่งชุด');
    }
  }

  async function init() {
    try {
      const runtime = await waitRuntime();
      db = runtime.getDb();
      session = await runtime.getSession();
      if (!session) { location.replace('/login.html'); return; }
      profile = await runtime.getProfile(session.user.id);
      if (!profile) throw new Error('ไม่พบ Profile');
      if (!runtime.can(profile, 'production_operate')) {
        throw new Error('บัญชีนี้ไม่มีสิทธิ์ Production Workstation — แต่ละบัญชีเข้าได้เฉพาะแผนกของตน');
      }
      await detectPersistence();
      window.ChananyaShell?.mount({ profile, session, active: 'production' });
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
      await load();
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = messageFor(error);
    }
  }

  $$('.nav button').forEach(button => {
    button.onclick = () => {
      $$('.nav button').forEach(item => item.classList.toggle('active', item === button));
      $$('.view').forEach(view => view.classList.toggle('active', view.id === button.dataset.view));
    };
  });
  $$('[data-close-dialog]').forEach(button => {
    button.addEventListener('click', () => button.closest('dialog')?.close());
  });
  $$('dialog').forEach(dialog => {
    dialog.addEventListener('click', event => {
      if (event.target === dialog) dialog.close();
    });
  });
  $('#formula-form').addEventListener('submit', event => saveFormula(event).catch(fail));
  $('#component-form').addEventListener('submit', event => saveComponent(event).catch(fail));
  $('#import-form').addEventListener('submit', event => previewFile(event).catch(fail));
  $('#complete-form').addEventListener('submit', event => saveCompletedOrder(event).catch(fail));
  $('#confirm-import').addEventListener('click', () => confirmImport().catch(fail));
  $('#f-product').addEventListener('change', syncFormulaUnit);
  $('#c-material').addEventListener('change', syncComponentUnit);
  $('#logout').onclick = async () => {
    if (db) await db.auth.signOut();
    location.replace('/login.html');
  };
  init();
})();
