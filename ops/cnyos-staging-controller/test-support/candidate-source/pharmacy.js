(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const collator = new Intl.Collator(['th', 'en'], { sensitivity: 'base', numeric: true });
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const num = value => Number(value || 0);
  const money = value => num(value).toLocaleString('th-TH', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });

  let db;
  let session;
  let profile;
  let persistenceReady = false;
  let productionRequestKey = null;
  let productionRequestAttempted = false;
  const data = {
    products: [], sales: [], items: [], patients: [], prescriptions: [], dispensing: [],
    prescriptionItems: [], dispensingItems: [], productionRequests: []
  };

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

  async function waitRuntime() {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (window.ChananyaRuntime) return window.ChananyaRuntime;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('ChananyaRuntime ไม่พร้อมใช้งาน');
  }

  async function query(table, select = '*', order) {
    let request = db.from(table).select(select);
    if (order) request = request.order(order, { ascending: false });
    const result = await request;
    if (result.error) throw result.error;
    return result.data || [];
  }

  async function detectPersistence() {
    const [departmentResult, prescriptionResult] = await Promise.all([
      db.rpc('department_persistence_healthcheck'),
      db.rpc('prescription_dispensing_healthcheck')
    ]);
    const department = Array.isArray(departmentResult.data)
      ? departmentResult.data[0]
      : departmentResult.data;
    const prescription = Array.isArray(prescriptionResult.data)
      ? prescriptionResult.data[0]
      : prescriptionResult.data;
    persistenceReady = !departmentResult.error
      && !prescriptionResult.error
      && department?.ready === true
      && prescription?.ready === true;
    if (!persistenceReady) {
      throw new Error('ฐานข้อมูล Department/Prescription Pharmacy migration ยังไม่พร้อม ระบบหยุดการเขียนเพื่อป้องกันข้อมูลข้ามแผนกหรือข้อมูลครึ่งชุด');
    }
  }

  function requirePersistence() {
    if (!persistenceReady) {
      throw new Error('ฐานข้อมูล Pharmacy ยังไม่พร้อมสำหรับการบันทึกแบบตรวจสอบย้อนหลัง');
    }
  }

  async function load() {
    const [
      products, sales, items, patients, prescriptions, dispensing,
      prescriptionItems, dispensingItems, productionRequests
    ] = await Promise.all([
      query('products', '*', 'updated_at'),
      query('pharmacy_counter_sales', '*', 'created_at'),
      query('pharmacy_counter_sale_items'),
      query('patients'),
      query('prescriptions', '*', 'prescribed_at'),
      query('dispensing_orders', '*', 'created_at'),
      query('prescription_items'),
      query('dispensing_items'),
      query('production_requests', '*', 'requested_at')
    ]);
    Object.assign(data, {
      products, sales, items, patients, prescriptions, dispensing,
      prescriptionItems, dispensingItems, productionRequests
    });
    render();
  }

  function product(id) { return data.products.find(item => item.id === id); }
  function patient(id) { return data.patients.find(item => item.id === id); }
  function patientName(item) {
    return item ? `${item.prefix || ''}${item.first_name || ''} ${item.last_name || ''}`.trim() : '';
  }

  function options(rows, label, selected = '') {
    const sorted = [...rows].sort((left, right) => collator.compare(label(left), label(right)));
    return '<option value="">เลือก</option>' + sorted.map(item => (
      `<option value="${esc(item.id)}"${item.id === selected ? ' selected' : ''}>${esc(label(item))}</option>`
    )).join('');
  }

  function activeProducts() { return data.products.filter(item => item.active !== false); }

  function syncItemProduct() {
    const selected = product($('#item-product')?.value);
    if ($('#item-unit')) $('#item-unit').value = selected?.dispense_unit || '';
  }

  function render() {
    const selectedSale = $('#item-sale')?.value || '';
    const selectedProduct = $('#item-product')?.value || '';
    const selectedPatient = $('#sale-patient')?.value || '';
    const draftSales = data.sales.filter(sale => sale.status === 'draft');

    $('#item-sale').innerHTML = options(
      draftSales,
      sale => `${sale.sale_no} — ${sale.customer_name || patientName(patient(sale.patient_id)) || 'Walk-in'}`,
      selectedSale
    );
    $('#item-product').innerHTML = options(
      activeProducts(),
      item => `${item.sku} — ${item.name_th}`,
      selectedProduct
    );
    $('#sale-patient').innerHTML = options(
      data.patients,
      item => `${item.hn || '-'} — ${patientName(item)}${item.phone ? ` • ${item.phone}` : ''}`,
      selectedPatient
    );

    syncItemProduct();
    renderPrescriptionQueue();
    renderProductionRequests();
    renderWalkin();
    renderProducts();
    renderHistory();
    window.dispatchEvent(new CustomEvent('chananya:pharmacy-rendered'));
  }

  function renderPrescriptionQueue() {
    const rows = data.dispensing.map(order => {
      const prescription = data.prescriptions.find(item => item.id === order.prescription_id);
      const linkedPatient = patient(prescription?.patient_id);
      const label = linkedPatient
        ? `${linkedPatient.hn || '-'} ${patientName(linkedPatient)}`
        : '-';
      const prescribed = data.prescriptionItems.filter(item => item.prescription_id === prescription?.id);
      const allocations = data.dispensingItems.filter(item => item.dispensing_order_id === order.id);
      const itemRows = prescribed.map(item => {
        const linkedProduct = product(item.product_id);
        const dispensed = allocations
          .filter(allocation => allocation.prescription_item_id === item.id)
          .reduce((total, allocation) => total + num(allocation.quantity_dispensed), 0);
        const price = allocations.find(allocation => allocation.prescription_item_id === item.id)?.unit_price;
        const priceControl = order.status === 'reviewed'
          ? `<label class="rx-price">ราคาขายต่อ ${esc(item.unit)}<input data-rx-price="${esc(item.id)}" type="number" min="0" max="1000000" step="0.01" required></label>`
          : `<small>จ่าย ${dispensed || 0}/${num(item.quantity_prescribed)} ${esc(item.unit)}${price == null ? '' : ` • ฿${money(price)}/${esc(item.unit)}`}</small>`;
        return `<div class="drug"><b>${esc(linkedProduct?.sku || '-')} • ${esc(linkedProduct?.name_th || '-')}</b><small>สั่ง ${num(item.quantity_prescribed)} ${esc(item.unit)} • ${esc(item.dose || '')} ${esc(item.frequency || '')} ${esc(item.duration || '')}</small>${priceControl}</div>`;
      }).join('');
      const buttons = [];
      if (['waiting', 'pending'].includes(order.status)) {
        buttons.push(`<button class="btn primary" data-act="rx-review" data-id="${esc(order.id)}">เภสัชกร Review</button>`);
      }
      if (order.status === 'reviewed') {
        buttons.push(`<button class="btn primary" data-act="rx-dispense" data-id="${esc(order.id)}">จ่ายยา FEFO</button>`);
      }
      if (order.status === 'dispensed') {
        buttons.push(`<button class="btn primary" data-act="rx-billing" data-id="${esc(order.id)}">ส่ง Checkout / Billing</button>`);
      }
      return `<article class="item column" data-dispensing-order-id="${esc(order.id)}"><div class="row"><div><b>${esc(order.queue_number || '-')} • ${esc(label)}</b><small>${esc(prescription?.prescription_no || '-')}</small></div><span class="badge">${esc(order.status)}</span></div>${itemRows}<div class="right">${buttons.join('')}</div></article>`;
    }).join('');
    $('#rx-list').innerHTML = rows || '<p class="muted">ไม่มีคิวใบสั่งยาจากผู้รักษา</p>';
  }

  function prescription(id) {
    return data.prescriptions.find(item => item.id === id);
  }

  function dispensingOrder(id) {
    return data.dispensing.find(item => item.id === id);
  }

  function productionItem(id) {
    return data.prescriptionItems.find(item => item.id === id);
  }

  function renderProductionRequests() {
    const selectedOrder = $('#production-dispensing')?.value || '';
    const eligibleOrders = data.dispensing.filter(order => ![
      'submitted_to_billing', 'billed', 'cancelled', 'rejected'
    ].includes(order.status));
    $('#production-dispensing').innerHTML = options(
      eligibleOrders,
      order => {
        const rx = prescription(order.prescription_id);
        const linkedPatient = patient(rx?.patient_id);
        return `${order.queue_number || '-'} — ${linkedPatient?.hn || '-'} ${patientName(linkedPatient)}`;
      },
      selectedOrder
    );
    syncProductionRequestItems();

    const rows = data.productionRequests.map(request => {
      const requestedProduct = product(request.requested_product_id);
      const requiredBy = request.required_by
        ? new Date(request.required_by).toLocaleString('th-TH')
        : 'ไม่กำหนด';
      return `<div class="item"><div><b>${esc(request.request_no)} • ${esc(requestedProduct?.name_th || '-')}</b><small>${num(request.requested_quantity)} ${esc(request.unit)} • ${esc(request.priority)} • ต้องการ ${esc(requiredBy)}</small></div><span class="badge">${esc(request.status)}</span></div>`;
    }).join('');
    $('#production-request-list').innerHTML = rows || '<p class="muted">ยังไม่มีคำขอผลิต</p>';
  }

  function syncProductionRequestItems() {
    const selectedOrder = dispensingOrder($('#production-dispensing')?.value);
    const rx = prescription(selectedOrder?.prescription_id);
    const selectedItem = $('#production-item')?.value || '';
    const items = data.prescriptionItems.filter(item => item.prescription_id === rx?.id);
    $('#production-item').innerHTML = options(
      items,
      item => {
        const linkedProduct = product(item.product_id);
        const hasActiveRequest = data.productionRequests.some(request => (
          request.prescription_item_id === item.id
          && !['fulfilled', 'cancelled', 'rejected'].includes(request.status)
        ));
        return `${linkedProduct?.sku || '-'} — ${linkedProduct?.name_th || '-'} • ${num(item.quantity_prescribed)} ${item.unit}${hasActiveRequest ? ' • มีคำขอแล้ว' : ''}`;
      },
      selectedItem
    );
    syncProductionRequestProduct();
    window.dispatchEvent(new CustomEvent('chananya:pharmacy-rendered'));
  }

  function syncProductionRequestProduct() {
    const item = productionItem($('#production-item')?.value);
    const linkedProduct = product(item?.product_id);
    $('#production-unit').value = linkedProduct?.stock_unit || '';
    if (item && linkedProduct) {
      const sameUnit = String(item.unit || '').trim().toLocaleLowerCase('th-TH')
        === String(linkedProduct.stock_unit || '').trim().toLocaleLowerCase('th-TH');
      if (sameUnit && !$('#production-qty').value) {
        $('#production-qty').value = item.quantity_prescribed;
      }
      $('#production-unit-note').textContent = sameUnit
        ? `ใบสั่งยา ${num(item.quantity_prescribed)} ${item.unit}; ใช้หน่วย Stock เดียวกัน`
        : `ใบสั่งยา ${num(item.quantity_prescribed)} ${item.unit}; กรุณาระบุจำนวนผลิตเป็น ${linkedProduct.stock_unit} ตาม Product Master`;
    } else {
      $('#production-unit-note').textContent = 'เลือก Product เพื่อดูหน่วยจาก Product Master';
    }
  }

  function newRequestKey() {
    if (!window.crypto?.randomUUID) {
      throw new Error('เบราว์เซอร์นี้ไม่รองรับ secure request key กรุณาอัปเดตเบราว์เซอร์');
    }
    return window.crypto.randomUUID();
  }

  async function saveProductionRequest(event) {
    event.preventDefault();
    requirePersistence();
    const item = productionItem($('#production-item').value);
    const linkedProduct = product(item?.product_id);
    if (!item || !linkedProduct) throw new Error('กรุณาเลือกรายการจากใบสั่งยา');
    productionRequestKey ||= newRequestKey();
    productionRequestAttempted = true;
    const result = await db.rpc('create_production_request', {
      p_request_key: productionRequestKey,
      p_dispensing_order_id: $('#production-dispensing').value,
      p_prescription_item_id: item.id,
      p_requested_quantity: num($('#production-qty').value),
      p_unit: linkedProduct.stock_unit,
      p_required_by: $('#production-required').value
        ? new Date($('#production-required').value).toISOString()
        : null,
      p_priority: $('#production-priority').value,
      p_reason: $('#production-reason').value.trim() || 'out_of_stock'
    });
    if (result.error) throw result.error;
    productionRequestKey = null;
    productionRequestAttempted = false;
    event.target.reset();
    await load();
    toast('ส่งคำขอผลิตแบบ idempotent และบันทึก Audit แล้ว');
  }

  function itemRows(sale) {
    return data.items.filter(item => item.sale_id === sale.id).map(item => {
      const removeButton = sale.status === 'draft'
        ? `<button class="btn ghost" data-act="remove-item" data-id="${esc(item.id)}">ลบรายการ</button>`
        : '';
      return `<div class="drug"><b>${esc(product(item.product_id)?.name_th || '-')}</b> ${num(item.quantity_requested)} ${esc(item.unit)} × ฿${money(item.unit_price)}<br><small>${esc(item.dose || '')} ${esc(item.frequency || '')} ${esc(item.duration || '')}</small>${removeButton ? `<div class="right">${removeButton}</div>` : ''}</div>`;
    }).join('');
  }

  function renderWalkin() {
    const rows = data.sales.filter(sale => !['paid', 'cancelled'].includes(sale.status)).map(sale => {
      const buttons = [];
      if (sale.status === 'draft') buttons.push(`<button class="btn primary" data-act="review" data-id="${esc(sale.id)}">เภสัชกร Review</button>`);
      if (sale.status === 'reviewed') buttons.push(`<button class="btn primary" data-act="dispense" data-id="${esc(sale.id)}">จ่ายยา FEFO</button>`);
      if (sale.status === 'dispensed') buttons.push(`<button class="btn primary" data-act="billing" data-id="${esc(sale.id)}">ส่งการเงิน</button>`);
      const linkedPatient = patient(sale.patient_id);
      const customer = linkedPatient
        ? `${linkedPatient.hn || '-'} • ${patientName(linkedPatient)}`
        : sale.customer_name || 'Walk-in';
      return `<div class="item column" data-sale-id="${esc(sale.id)}"><div class="row"><b>${esc(sale.sale_no)} • ${esc(customer)}</b><span class="badge">${esc(sale.status)}</span></div><small>อาการ: ${esc(sale.presenting_symptoms || '-')} • แพ้ยา: ${esc(sale.allergy_notes || '-')}</small>${itemRows(sale)}<div class="right">${buttons.join('')}</div></div>`;
    }).join('');
    $('#walkin-list').innerHTML = rows || '<p class="muted">ยังไม่มีรายการ Walk-in</p>';
    bindActions();
  }

  function renderProducts() {
    const box = $('#product-list');
    if (!box) return;
    const term = ($('#product-master-search')?.value || '').trim().toLocaleLowerCase('th-TH');
    const showInactive = $('#show-inactive-products')?.checked;
    const rows = data.products.filter(item => (
      (showInactive || item.active !== false)
      && (!term || [item.sku, item.name_th, item.name_en, item.category, item.dosage_form]
        .some(value => String(value || '').toLocaleLowerCase('th-TH').includes(term)))
    )).map(item => `<div class="item column"><div class="row"><div><b>${esc(item.sku)} • ${esc(item.name_th)}</b><small>${esc(item.category)} • Stock ${esc(item.stock_unit)} • Dispense ${esc(item.dispense_unit)}</small></div><span class="badge">${item.active === false ? 'inactive' : 'active'}</span></div><div class="right"><button class="btn ghost" data-act="edit-product" data-id="${esc(item.id)}">แก้ไข</button><button class="btn ${item.active === false ? 'primary' : 'danger'}" data-act="toggle-product" data-id="${esc(item.id)}">${item.active === false ? 'เปิดใช้งาน' : 'ปิดใช้งาน'}</button></div></div>`).join('');
    box.innerHTML = rows || '<p class="muted">ไม่พบผลิตภัณฑ์</p>';
    bindActions();
  }

  function renderHistory() {
    const rows = data.sales.map(sale => `<div class="item" data-sale-id="${esc(sale.id)}"><div><b>${esc(sale.sale_no)} • ${esc(sale.customer_name || patientName(patient(sale.patient_id)) || 'Walk-in')}</b><small>ยอด ฿${money(sale.grand_total)} • ${new Date(sale.created_at).toLocaleString('th-TH')}</small></div><span class="badge">${esc(sale.status)}</span></div>`).join('');
    $('#history-list').innerHTML = rows || '<p class="muted">ยังไม่มีประวัติ</p>';
  }

  function bindActions() {
    $$('[data-act]').forEach(button => {
      button.onclick = () => act(button.dataset.act, button.dataset.id).catch(fail);
    });
  }

  async function act(action, id) {
    requirePersistence();
    let result;
    let successMessage = '';
    if (action === 'rx-review') {
      result = await db.rpc('transition_atomic_prescription_dispensing', {
        p_dispensing_order_id: id,
        p_action: 'review',
        p_item_prices: [],
        p_reason: null
      });
      successMessage = 'Review ใบสั่งยาและบันทึก Audit แล้ว';
    } else if (action === 'rx-dispense') {
      const order = dispensingOrder(id);
      const rx = prescription(order?.prescription_id);
      const prices = data.prescriptionItems
        .filter(item => item.prescription_id === rx?.id)
        .map(item => {
          const input = document.querySelector(`[data-rx-price="${item.id}"]`);
          const unitPrice = num(input?.value);
          if (!input || input.value === '' || unitPrice < 0) {
            throw new Error('กรุณาระบุราคาขายของยาทุกรายการ');
          }
          return { prescription_item_id: item.id, unit_price: unitPrice };
        });
      result = await db.rpc('transition_atomic_prescription_dispensing', {
        p_dispensing_order_id: id,
        p_action: 'dispense',
        p_item_prices: prices,
        p_reason: 'Dispensed from Pharmacy workstation'
      });
      successMessage = 'จ่ายยา FEFO ตัด Stock และบันทึก Audit แล้ว';
    } else if (action === 'rx-billing') {
      result = await db.rpc('transition_atomic_prescription_dispensing', {
        p_dispensing_order_id: id,
        p_action: 'submit_billing',
        p_item_prices: [],
        p_reason: null
      });
      successMessage = 'ส่ง Checkout / Billing และบันทึก Audit แล้ว';
    } else if (action === 'review') {
      result = await db.rpc('transition_pharmacy_counter_sale', {
        p_sale_id: id, p_action: 'review', p_reason: null
      });
      successMessage = 'Review และบันทึก Audit แล้ว';
    } else if (action === 'dispense') {
      result = await db.rpc('dispense_pharmacy_counter_sale', { p_sale_id: id });
      successMessage = 'จ่ายยาและตัด Stock แบบ FEFO แล้ว';
    } else if (action === 'billing') {
      result = await db.rpc('transition_pharmacy_counter_sale', {
        p_sale_id: id, p_action: 'submit_billing', p_reason: null
      });
      successMessage = 'ส่งการเงินและบันทึก Audit แล้ว';
    } else if (action === 'remove-item') {
      if (!confirm('ลบรายการยานี้หรือไม่?')) return;
      result = await db.rpc('remove_pharmacy_counter_sale_item', { p_sale_item_id: id });
      successMessage = 'ลบรายการยาและบันทึก Audit แล้ว';
    } else if (action === 'edit-product') {
      fillProductForm(id);
      return;
    } else if (action === 'toggle-product') {
      const item = product(id);
      if (!item) return;
      const active = item.active === false;
      result = await db.rpc('set_product_master_active', {
        p_product_id: id,
        p_active: active,
        p_reason: active ? 'เปิดใช้งานจาก Product Master' : 'ปิดใช้งานจาก Product Master'
      });
      successMessage = active ? 'เปิดใช้งานผลิตภัณฑ์แล้ว' : 'ปิดใช้งานโดยรักษาประวัติเดิมไว้แล้ว';
    } else {
      return;
    }
    if (result.error) throw result.error;
    if (successMessage) toast(successMessage);
    await load();
  }

  function syncSalePatient() {
    const linked = patient($('#sale-patient')?.value);
    if (!linked) return;
    $('#customer-name').value = patientName(linked);
    $('#customer-phone').value = linked.phone || '';
  }

  async function saveSale(event) {
    event.preventDefault();
    requirePersistence();
    const result = await db.rpc('create_pharmacy_counter_sale', {
      p_patient_id: $('#sale-patient').value || null,
      p_customer_name: $('#customer-name').value.trim() || null,
      p_customer_phone: $('#customer-phone').value.trim() || null,
      p_presenting_symptoms: $('#symptoms').value.trim(),
      p_allergy_notes: $('#allergies').value.trim() || null,
      p_current_medicines: $('#current-meds').value.trim() || null,
      p_contraindication_notes: $('#contra').value.trim() || null,
      p_pharmacist_assessment: $('#assessment').value.trim(),
      p_advice: $('#advice').value.trim() || null
    });
    if (result.error) throw result.error;
    event.target.reset();
    await load();
    toast('สร้างรายการ Walk-in และบันทึก Audit แล้ว');
  }

  async function saveItem(event) {
    event.preventDefault();
    requirePersistence();
    const saleId = $('#item-sale').value;
    const productId = $('#item-product').value;
    if (!saleId) throw new Error('กรุณาเลือกรายการขายสถานะ Draft');
    if (!productId) throw new Error('กรุณาเลือกยา/ผลิตภัณฑ์');
    const result = await db.rpc('upsert_pharmacy_counter_sale_item', {
      p_sale_item_id: null,
      p_sale_id: saleId,
      p_product_id: productId,
      p_quantity_requested: num($('#item-qty').value),
      p_unit_price: num($('#item-price').value),
      p_dose: $('#item-dose').value.trim() || null,
      p_frequency: $('#item-frequency').value.trim() || null,
      p_duration: $('#item-duration').value.trim() || null,
      p_instructions: $('#item-instructions').value.trim() || null
    });
    if (result.error) throw result.error;
    event.target.reset();
    await load();
    toast('เพิ่มยาและบันทึก Audit แล้ว');
  }

  function resetProductForm() {
    $('#product-form')?.reset();
    $('#product-id').value = '';
    $('#product-conversion').value = '1';
    $('#product-cost').value = '0';
    $('#product-min-stock').value = '0';
    $('#product-reorder').value = '0';
  }

  function fillProductForm(id) {
    const item = product(id);
    if (!item) return;
    $('#product-id').value = item.id;
    $('#product-sku').value = item.sku || '';
    $('#product-name-th').value = item.name_th || '';
    $('#product-name-en').value = item.name_en || '';
    $('#product-category').value = item.category || '';
    $('#product-dosage-form').value = item.dosage_form || '';
    $('#product-purchase-unit').value = item.purchase_unit || '';
    $('#product-stock-unit').value = item.stock_unit || '';
    $('#product-dispense-unit').value = item.dispense_unit || '';
    $('#product-conversion').value = item.conversion_factor ?? 1;
    $('#product-cost').value = item.standard_cost ?? 0;
    $('#product-min-stock').value = item.min_stock ?? 0;
    $('#product-reorder').value = item.reorder_level ?? 0;
    $('#product-sku').focus();
  }

  async function saveProduct(event) {
    event.preventDefault();
    requirePersistence();
    const id = $('#product-id').value || null;
    const result = await db.rpc('upsert_product_master', {
      p_product_id: id,
      p_sku: $('#product-sku').value.trim(),
      p_name_th: $('#product-name-th').value.trim(),
      p_name_en: $('#product-name-en').value.trim() || null,
      p_category: $('#product-category').value.trim(),
      p_dosage_form: $('#product-dosage-form').value.trim() || null,
      p_purchase_unit: $('#product-purchase-unit').value.trim() || null,
      p_stock_unit: $('#product-stock-unit').value.trim(),
      p_dispense_unit: $('#product-dispense-unit').value.trim(),
      p_conversion_factor: num($('#product-conversion').value) || 1,
      p_standard_cost: num($('#product-cost').value),
      p_min_stock: num($('#product-min-stock').value),
      p_reorder_level: num($('#product-reorder').value)
    });
    if (result.error) throw result.error;
    resetProductForm();
    await load();
    toast(id ? 'แก้ไขผลิตภัณฑ์และบันทึก Audit แล้ว' : 'เพิ่มผลิตภัณฑ์และบันทึก Audit แล้ว');
  }

  async function init() {
    try {
      const runtime = await waitRuntime();
      db = runtime.getDb();
      session = await runtime.getSession();
      if (!session) { location.replace('/login.html'); return; }
      profile = await runtime.getProfile(session.user.id);
      if (!profile) throw new Error('ไม่พบ Profile');
      if (!runtime.can(profile, 'pharmacy_operate')) {
        throw new Error('บัญชีนี้ไม่มีสิทธิ์ Pharmacy — แต่ละบัญชีเข้าได้เฉพาะแผนกของตน');
      }
      await detectPersistence();
      window.ChananyaShell?.mount({ profile, session, active: 'pharmacy' });
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
      await load();
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = error.message;
    }
  }

  $$('.nav button').forEach(button => {
    button.onclick = () => {
      $$('.nav button').forEach(item => item.classList.toggle('active', item === button));
      $$('.view').forEach(view => view.classList.toggle('active', view.id === button.dataset.view));
    };
  });
  $('#sale-form').addEventListener('submit', event => saveSale(event).catch(fail));
  $('#item-form').addEventListener('submit', event => saveItem(event).catch(fail));
  $('#production-request-form')?.addEventListener('submit', event => saveProductionRequest(event).catch(fail));
  $('#production-request-form')?.addEventListener('input', () => {
    if (!productionRequestAttempted) return;
    productionRequestKey = null;
    productionRequestAttempted = false;
  });
  $('#product-form')?.addEventListener('submit', event => saveProduct(event).catch(fail));
  $('#product-cancel')?.addEventListener('click', resetProductForm);
  $('#sale-patient')?.addEventListener('change', syncSalePatient);
  $('#item-product')?.addEventListener('change', syncItemProduct);
  $('#production-dispensing')?.addEventListener('change', () => {
    $('#production-qty').value = '';
    syncProductionRequestItems();
  });
  $('#production-item')?.addEventListener('change', () => {
    $('#production-qty').value = '';
    syncProductionRequestProduct();
  });
  $('#product-master-search')?.addEventListener('input', renderProducts);
  $('#show-inactive-products')?.addEventListener('change', renderProducts);
  $('#logout').onclick = async () => {
    if (db) await db.auth.signOut();
    location.replace('/login.html');
  };
  init();
})();
