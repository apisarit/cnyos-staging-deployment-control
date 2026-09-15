(() => {
  'use strict';

  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));

  const TYPE_LABELS = Object.freeze({
    cosmology: 'โลกและแบบจำลองมนุษย์', constitution: 'ธาตุเจ้าเรือน', constitution_rule: 'กฎธาตุเจ้าเรือน',
    element: 'ธาตุ', dhatu_state: 'สถานะธาตุ', samutthan: 'สมุฏฐาน', context_rule: 'กฎบริบท',
    coordinate: 'พิกัด', organ: 'อวัยวะ/รูปธาตุ', body_group: 'ทะเบียนฐานกาย', disease: 'โรคแผนไทย',
    symptom: 'อาการ', specialty: 'องค์ความรู้เฉพาะ', canon: 'คัมภีร์', guidance_rule: 'กฎแนวทาง',
    therapeutic_principle: 'หลักการรักษา', formula: 'ตำรับยา', herb: 'สมุนไพร', taste: 'รสยา',
    procedure: 'หัตถการ', sen_line: 'เส้น', knowledge_rule: 'กฎความรู้', category: 'หมวดรากวิชา'
  });
  const DOMAIN_LABELS = Object.freeze({
    constitution: 'นิยามธาตุเจ้าเรือน', conception_month: 'เดือนปฏิสนธิ', birth_weekday: 'วันเกิด',
    coordinate: 'พิกัดสมุฏฐาน', age_samutthan: 'อายุสมุฏฐาน', kala_samutthan: 'กาลสมุฏฐานหลัก',
    kala_ekadot: 'กาลเอกโทษ', kala_duvandot: 'กาลทวิโทษ', kala_tridot: 'กาลตรีโทษ',
    season_4: 'ฤดู 4', season_6: 'ฤดู 6', season_pitsadan: 'ฤดูพิสดาร',
    zodiac_samutthan: 'ราศีสมุฏฐาน', pradesa_samutthan: 'ประเทศสมุฏฐาน', food_taste: 'รสอาหาร'
  });
  const LENS_LABELS = Object.freeze({ constitution: 'ธาตุเจ้าเรือน', age: 'อายุสมุฏฐาน', time: 'กาลสมุฏฐาน' });
  const AXIS_LABELS = Object.freeze({ pitta: 'ปิตตะ', vata: 'วาตะ', semha: 'เสมหะ' });
  const BODY_GROUPS = Object.freeze([
    { code: 'body_registry.pitta4', label: 'ปิตตะ', target: 4, className: 'pitta' },
    { code: 'body_registry.vata6', label: 'วาตะ', target: 6, className: 'vata' },
    { code: 'body_registry.semha12', label: 'เสมหะ', target: 12, className: 'semha' },
    { code: 'body_registry.pathavi20', label: 'ปถวี', target: 20, className: 'pathavi' }
  ]);
  const LEGACY_DOMAIN = Object.freeze({
    constitution: ['constitution_rule', 1], conception_month: ['constitution_rule', 1], birth_weekday: ['constitution_rule', 1],
    age_samutthan: ['context_rule', 2], kala_samutthan: ['context_rule', 2], kala_ekadot: ['context_rule', 2],
    kala_duvandot: ['context_rule', 2], kala_tridot: ['context_rule', 2], coordinate: ['coordinate', 2],
    food_taste: ['guidance_rule', 4]
  });

  let db;
  let session;
  let profile;
  let selectedLayer = 'all';
  let lastReasoning = null;
  let state = { mode: 'loading', concepts: [], sources: [], relations: [], rules: [] };

  function toast(message) {
    const element = $('#toast');
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2200);
  }

  function sourceOf(concept) {
    return state.sources.find(source => source.id === concept.source_id || source.source_code === concept.source_code) || null;
  }

  function conceptById(id) {
    return state.concepts.find(concept => String(concept.id) === String(id)) || null;
  }

  function layerOf(concept) {
    const explicit = Number(concept.foundation_layer);
    if (explicit >= 1 && explicit <= 5) return explicit;
    if (['cosmology', 'constitution', 'constitution_rule', 'element'].includes(concept.concept_type)) return 1;
    if (['dhatu_state', 'samutthan', 'context_rule', 'coordinate', 'organ', 'body_group'].includes(concept.concept_type)) return 2;
    if (['disease', 'symptom', 'specialty', 'canon'].includes(concept.concept_type)) return 3;
    if (['therapeutic_principle', 'guidance_rule', 'formula', 'herb', 'taste'].includes(concept.concept_type)) return 4;
    if (['procedure', 'sen_line'].includes(concept.concept_type)) return 5;
    return 2;
  }

  function setMode(text, warning = false) {
    const mode = $('#foundation-mode');
    mode.textContent = text;
    mode.classList.toggle('warning-badge', warning);
  }

  async function fetchAll(table, columns, configure = query => query) {
    const output = [];
    const pageSize = 1000;
    for (let from = 0; ; from += pageSize) {
      const query = configure(db.from(table).select(columns)).range(from, from + pageSize - 1);
      const result = await query;
      if (result.error) throw result.error;
      const page = result.data || [];
      output.push(...page);
      if (page.length < pageSize) break;
    }
    return output;
  }

  async function loadOntology() {
    const [concepts, sources, relations, rules] = await Promise.all([
      fetchAll('ttm_concepts', 'id,concept_code,concept_type,preferred_term_th,preferred_term_en,foundation_layer,definition,source_id,review_status,version,active,metadata', query => query.eq('active', true).order('foundation_layer').order('preferred_term_th')),
      fetchAll('ttm_sources', 'id,source_code,title_th,title_en,source_type,citation,provenance,review_status,version,active,metadata', query => query.eq('active', true).order('title_th')),
      fetchAll('ttm_concept_relations', 'id,subject_concept_id,predicate,object_concept_id,source_id,evidence_note,qualifiers,review_status,version,active', query => query.eq('active', true)),
      fetchAll('ttm_diagnostic_knowledge', '*', query => query.eq('active', true).order('domain').order('rule_key'))
    ]);
    state = { mode: 'ontology', concepts, sources, relations, rules };
    const completeDkr = rules.filter(rule => rule.version === 'TTM-DKR-v1').length >= 113;
    const pikad = sources.some(source => source.source_code === 'OWNER-PIKAD-YA-20260830');
    setMode(`${completeDkr ? 'DKR 113 rules' : `DKR ${rules.length} rules`} • ${pikad ? 'พิกัดยาเชื่อมแล้ว' : 'ยังไม่พบพิกัดยา'} • review guard on`, !completeDkr);
  }

  async function loadLegacy() {
    const [rules, lines] = await Promise.all([
      fetchAll('ttm_diagnostic_knowledge', '*', query => query.eq('active', true).order('domain').order('rule_key')),
      fetchAll('sen_line_master', 'code,name_th,name_en,description,clinical_notes,is_active', query => query.eq('is_active', true).order('code')).catch(() => [])
    ]);
    const sourceMap = new Map();
    const concepts = rules.map(rule => {
      const [conceptType, foundationLayer] = LEGACY_DOMAIN[rule.domain] || ['knowledge_rule', 2];
      const sourceCode = rule.source_ref ? `legacy:${rule.source_ref}` : 'legacy:unspecified';
      if (!sourceMap.has(sourceCode)) sourceMap.set(sourceCode, {
        id: sourceCode, source_code: sourceCode, title_th: rule.source_ref || 'ยังไม่ระบุแหล่งอ้างอิง',
        source_type: 'legacy_reference', citation: rule.source_ref || null,
        review_status: rule.review_status || 'review_required', version: rule.version || 'TTM-DKR-v1'
      });
      return {
        id: rule.id, concept_code: `legacy.${rule.domain}.${rule.id}`, concept_type: conceptType,
        preferred_term_th: rule.input_key || rule.rule_key, preferred_term_en: null, foundation_layer: foundationLayer,
        definition: [rule.output_value, rule.description].filter(Boolean).join(' — '),
        review_status: rule.review_status || 'review_required', version: rule.version || 'TTM-DKR-v1',
        source_code: sourceCode, metadata: { domain: rule.domain, rule_key: rule.rule_key, element: rule.element }
      };
    });
    for (const line of lines) concepts.push({
      id: `sen:${line.code}`, concept_code: `sen.${line.code}`, concept_type: 'sen_line', preferred_term_th: line.name_th,
      preferred_term_en: line.name_en, foundation_layer: 5, definition: line.description || line.clinical_notes,
      review_status: line.name_th?.startsWith('แนวเส้น S.') ? 'review_required' : 'approved', version: 'legacy-sen-line',
      source_code: 'legacy:sen-line-master', metadata: { code: line.code }
    });
    state = { mode: 'legacy', concepts, sources: [...sourceMap.values()], relations: [], rules };
    setMode('Legacy bridge • graph schema ยังไม่พร้อม', true);
  }

  function clinicalRules() {
    return state.rules.filter(rule => rule.review_status === 'approved'
      && rule.metadata?.clinical_inference_allowed === true
      && rule.metadata?.rule_role === 'finding_to_hypothesis');
  }

  function updateStats() {
    const approved = state.concepts.filter(concept => concept.review_status === 'approved').length;
    const review = state.concepts.filter(concept => concept.review_status !== 'approved' && concept.review_status !== 'rejected').length;
    $('#foundation-rule-count').textContent = state.rules.length;
    $('#foundation-clinical-rule-count').textContent = clinicalRules().length;
    $('#foundation-relation-count').textContent = state.relations.length;
    $('#foundation-therapy-count').textContent = state.relations.filter(relation => relation.predicate === 'has_traditional_claim_for').length;
    $('#foundation-approved-count').textContent = approved;
    $('#foundation-review-count').textContent = review;
    $('#layer-count-all').textContent = state.concepts.length;
    for (let layer = 1; layer <= 5; layer += 1) {
      $(`#layer-count-${layer}`).textContent = state.concepts.filter(concept => layerOf(concept) === layer).length;
    }
  }

  function switchTab(tab) {
    $$('[data-foundation-tab]').forEach(button => {
      const active = button.dataset.foundationTab === tab;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', String(active));
    });
    $$('[data-foundation-panel]').forEach(panel => {
      const active = panel.dataset.foundationPanel === tab;
      panel.hidden = !active;
      panel.classList.toggle('active', active);
    });
  }

  function bindTabs() {
    $$('[data-foundation-tab]').forEach(button => button.addEventListener('click', () => switchTab(button.dataset.foundationTab)));
  }

  function renderTypeOptions() {
    const types = [...new Set(state.concepts.map(concept => concept.concept_type).filter(Boolean))].sort();
    $('#foundation-type').innerHTML = '<option value="">ทุกชนิด</option>' + types.map(type => `<option value="${esc(type)}">${esc(TYPE_LABELS[type] || type)}</option>`).join('');
  }

  function visibleConcepts() {
    const search = $('#foundation-search').value.trim().toLocaleLowerCase('th');
    const type = $('#foundation-type').value;
    return state.concepts.filter(concept => {
      if (selectedLayer !== 'all' && layerOf(concept) !== Number(selectedLayer)) return false;
      if (type && concept.concept_type !== type) return false;
      if (!search) return true;
      const source = sourceOf(concept);
      const haystack = [concept.preferred_term_th, concept.preferred_term_en, concept.definition, concept.concept_code,
        source?.title_th, source?.citation, concept.metadata ? JSON.stringify(concept.metadata) : ''].filter(Boolean).join(' ').toLocaleLowerCase('th');
      return haystack.includes(search);
    });
  }

  function renderConcepts() {
    const concepts = visibleConcepts();
    const shown = concepts.slice(0, 160);
    const layerLabel = selectedLayer === 'all' ? 'ทุกชั้น' : `ชั้น ${selectedLayer}`;
    $('#foundation-result-meta').textContent = `${layerLabel} • พบ ${concepts.length} จาก ${state.concepts.length} node${concepts.length > shown.length ? ` • แสดง ${shown.length} รายการแรก โปรดค้นให้แคบลง` : ''}`;
    $('#foundation-results').innerHTML = shown.map(concept => {
      const source = sourceOf(concept);
      const approved = concept.review_status === 'approved';
      return `<button type="button" class="foundation-concept" data-foundation-concept="${esc(concept.id)}"><span class="foundation-concept-main"><small>ชั้น ${layerOf(concept)} • ${esc(TYPE_LABELS[concept.concept_type] || concept.concept_type)}</small><b>${esc(concept.preferred_term_th)}</b><span>${esc(concept.definition || 'ยังไม่มีคำอธิบายที่รับรอง')}</span></span><span class="foundation-concept-side"><em class="${approved ? 'approved' : 'review'}">${approved ? 'รับรองแล้ว' : 'รอทบทวน'}</em><small>${esc(source?.title_th || concept.version || 'ไม่ระบุ source')}</small></span></button>`;
    }).join('') || '<div class="status">ไม่พบ node ตามตัวกรองนี้</div>';
    $$('[data-foundation-concept]').forEach(button => button.addEventListener('click', () => showDetail(button.dataset.foundationConcept)));
  }

  function syncLayerButtons() {
    $$('[data-foundation-layer]').forEach(button => {
      const active = button.dataset.foundationLayer === selectedLayer;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
      const action = button.querySelector('[data-layer-action]');
      if (action) action.textContent = active ? 'กำลังแสดง ✓' : 'แตะเพื่อดู ↓';
    });
  }

  function selectLayer(layer, moveToResults = true) {
    selectedLayer = layer;
    switchTab('knowledge');
    syncLayerButtons();
    renderConcepts();
    if (!moveToResults) return;
    toast(`เลือก${selectedLayer === 'all' ? 'ทุกชั้น' : `ชั้น ${selectedLayer}`}แล้ว • ${visibleConcepts().length} node`);
    const target = $('#foundation-browser');
    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
    target.classList.remove('filter-arrived');
    window.requestAnimationFrame(() => target.classList.add('filter-arrived'));
  }

  function showDetail(conceptId) {
    const concept = conceptById(conceptId);
    if (!concept) return;
    const source = sourceOf(concept);
    const relationRows = state.relations.flatMap(relation => {
      if (String(relation.subject_concept_id) === String(concept.id)) return [{ relation, direction: 'out' }];
      if (String(relation.object_concept_id) === String(concept.id)) return [{ relation, direction: 'in' }];
      return [];
    }).slice(0, 80);
    const relationMarkup = relationRows.map(({ relation, direction }) => {
      const peerId = direction === 'out' ? relation.object_concept_id : relation.subject_concept_id;
      const peer = conceptById(peerId);
      return `<li><span>${direction === 'out' ? '→' : '←'} ${esc(relation.predicate)}</span><b>${esc(peer?.preferred_term_th || peerId)}</b><small>${esc(relation.evidence_note || relation.review_status || '')}</small></li>`;
    }).join('') || '<li><span>ยังไม่มี typed relation</span><small>node นี้ยังไม่เชื่อมกับ graph</small></li>';
    $('#foundation-detail-content').className = 'foundation-detail-content';
    $('#foundation-detail-content').innerHTML = `<span class="badge">ชั้น ${layerOf(concept)} • ${esc(TYPE_LABELS[concept.concept_type] || concept.concept_type)}</span><h3>${esc(concept.preferred_term_th)}</h3><p>${esc(concept.definition || 'ยังไม่มีคำอธิบายที่รับรอง')}</p><dl><dt>Concept code</dt><dd>${esc(concept.concept_code)}</dd><dt>สถานะ</dt><dd>${esc(concept.review_status || 'review_required')}</dd><dt>Version</dt><dd>${esc(concept.version || '-')}</dd><dt>แหล่งอ้างอิง</dt><dd>${esc(source?.title_th || 'ยังไม่ผูก source')}</dd><dt>Citation</dt><dd>${esc(source?.citation || 'ยังไม่มี citation ระดับหน้า/ข้อความ')}</dd></dl><h4>ความสัมพันธ์ (${relationRows.length})</h4><ul>${relationMarkup}</ul>`;
  }

  function bindKnowledgeFilters() {
    $('#foundation-search').addEventListener('input', renderConcepts);
    $('#foundation-type').addEventListener('change', renderConcepts);
    $('#foundation-reset').addEventListener('click', () => {
      $('#foundation-search').value = '';
      $('#foundation-type').value = '';
      selectLayer('all', false);
      toast('ล้างตัวกรองแล้ว');
    });
    $$('[data-foundation-layer]').forEach(button => button.addEventListener('click', () => selectLayer(button.dataset.foundationLayer)));
  }

  function caseInput() {
    return {
      caseName: $('#ttm-case-name').value.trim(),
      birthDate: $('#ttm-birth-date').value,
      conceptionMonth: $('#ttm-conception-month').value,
      symptomTime: $('#ttm-symptom-time').value,
      kalaMode: $('#ttm-kala-mode').value,
      observationText: $('#ttm-observation-text').value.trim(),
      hypothesisAxis: $('#ttm-hypothesis-axis').value,
      hypothesisState: $('#ttm-hypothesis-state').value
    };
  }

  function statusBadge(status) {
    return status === 'approved' ? '<span class="coverage-state ready">approved</span>' : '<span class="coverage-state review">review_required</span>';
  }

  function evidenceText(items) {
    if (!items.length) return '<span class="foundation-lens-empty">ยังไม่พบกฎที่ตรง</span>';
    return items.map(item => `<span>${esc(item.output || item.description || item.label)} ${statusBadge(item.reviewStatus)}</span>`).join('');
  }

  function renderLenses(result) {
    const constitutionEvidence = result.constitution.evidence || [];
    const ageEvidence = result.evidence.filter(item => item.lens === 'age');
    const timeEvidence = result.evidence.filter(item => item.lens === 'time');
    const observation = result.input.observationText;
    const selectedAxis = result.hypothesis.axis ? AXIS_LABELS[result.hypothesis.axis] : null;
    const cards = [
      { title: 'ธาตุเจ้าเรือนเกิด', meta: [result.constitution.weekday ? `เกิดวัน${result.constitution.weekday}` : null, result.constitution.birthElement, result.constitution.conceptionElement ? `ปฏิสนธิ: ${result.constitution.conceptionElement}` : null].filter(Boolean).join(' • '), items: constitutionEvidence },
      { title: 'อายุสมุฏฐาน', meta: result.constitution.age === null ? 'ยังไม่ทราบอายุ' : `อายุ ${result.constitution.age} ปี`, items: ageEvidence },
      { title: 'กาลสมุฏฐาน', meta: result.input.symptomTime ? `${result.input.symptomTime} • ${result.input.kalaMode}` : 'ยังไม่ระบุเวลา', items: timeEvidence },
      { title: 'ข้อค้นพบปัจจุบัน', meta: observation || 'ยังไม่บันทึกอาการ', note: observation ? 'เก็บเป็นข้อความอ่านประกอบ • ไม่สร้างคะแนน' : null, items: [] },
      { title: 'สมมติฐานผู้ประกอบวิชาชีพ', meta: selectedAxis ? `${selectedAxis}${result.hypothesis.state ? ` • ${result.hypothesis.state}` : ''}` : 'ยังไม่เลือก', note: selectedAxis ? 'แยกจากผลระบบ • ยังไม่ยืนยัน' : null, items: [] }
    ];
    $('#ttm-lenses').innerHTML = cards.map(card => `<article class="foundation-lens-card"><small>${esc(card.title)}</small><b>${esc(card.meta || 'ไม่มีข้อมูล')}</b>${card.note ? `<p>${esc(card.note)}</p>` : ''}${card.items.length ? `<div>${evidenceText(card.items)}</div>` : ''}</article>`).join('');
  }

  function renderAxisCards(result) {
    $('#ttm-context-axis-cards').innerHTML = Object.entries(AXIS_LABELS).map(([axis, label]) => {
      const percent = Number(result.context.percent[axis] || 0);
      const top = result.context.topAxis === axis;
      return `<article class="foundation-axis-card ${axis}${top ? ' top' : ''}"><span><b>${label}</b><strong>${percent.toFixed(1)}%</strong></span><div class="foundation-axis-track" role="meter" aria-label="น้ำหนักบริบท ${label}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}"><i style="width:${percent}%"></i></div><small>${top ? 'น้ำหนักบริบทสูงสุด' : 'น้ำหนักจากกฎบริบท'} • ไม่ใช่โอกาสเป็นโรค</small></article>`;
    }).join('');
  }

  function renderMessages(target, messages, emptyText, kind) {
    $(target).innerHTML = messages.length
      ? messages.map(message => `<div class="foundation-message ${kind}">${esc(message)}</div>`).join('')
      : `<div class="foundation-message clear">${esc(emptyText)}</div>`;
  }

  function renderPath(result) {
    const hasPerson = Boolean(result.input.birthDate || result.input.caseName);
    const hasContext = result.evidence.length + result.constitution.evidence.length > 0;
    const hasFinding = Boolean(result.input.observationText);
    const clinicalCandidate = result.clinical.status === 'candidate_only';
    const hasHypothesis = Boolean(result.hypothesis.axis);
    const stages = [
      { index: '01', title: 'บุคคล', state: hasPerson ? 'ready' : 'pending', detail: hasPerson ? (result.input.caseName || 'มีข้อมูลวันเกิด') : 'รอข้อมูล' },
      { index: '02', title: 'บริบทหลายเลนส์', state: hasContext ? 'ready' : 'pending', detail: `${result.evidence.length + result.constitution.evidence.length} evidence` },
      { index: '03', title: 'อาการ / สิ่งตรวจพบ', state: hasFinding ? 'review' : 'pending', detail: hasFinding ? 'บันทึกแล้ว แต่ยังไม่ structured' : 'รอข้อมูล' },
      { index: '04', title: 'สมมติฐานจากกฎ', state: clinicalCandidate ? 'review' : 'locked', detail: clinicalCandidate ? 'candidate เท่านั้น' : 'หลักฐานไม่พอ • หยุดที่นี่' },
      { index: '05', title: 'ผู้ประกอบวิชาชีพยืนยัน', state: hasHypothesis ? 'review' : 'locked', detail: hasHypothesis ? 'เลือกเพื่อพิจารณา • ยังไม่ยืนยัน' : 'ต้องยืนยันในเวชระเบียน' },
      { index: '06', title: 'หลักรักษา / ตำรับ', state: hasHypothesis ? 'review' : 'locked', detail: hasHypothesis ? 'เปิดเฉพาะ claim เพื่อทบทวน' : 'ยังไม่เปิดตัวเลือก' }
    ];
    $('#ttm-reasoning-path').innerHTML = stages.map(stage => `<article class="foundation-path-stage ${stage.state}"><span>${stage.index}</span><div><b>${esc(stage.title)}</b><small>${esc(stage.detail)}</small></div><em>${stage.state === 'ready' ? 'พร้อม' : stage.state === 'review' ? 'ต้องทบทวน' : stage.state === 'locked' ? 'ล็อก' : 'รอข้อมูล'}</em></article>`).join('');
  }

  function renderAudit(result) {
    const evidence = [...result.constitution.evidence, ...result.evidence, ...(result.clinical.evidence || [])];
    if (!evidence.length) {
      $('#ttm-evidence-audit').innerHTML = '<div class="status">ยังไม่มีกฎที่จับคู่กับข้อมูลนี้</div>';
      return;
    }
    $('#ttm-evidence-audit').innerHTML = `<div class="foundation-audit-head"><b>เลนส์ / กฎ</b><b>ผล</b><b>สถานะ / ที่มา</b></div>${evidence.map(item => `<div class="foundation-audit-row"><span><small>${esc(LENS_LABELS[item.lens] || item.lens)}</small><b>${esc(item.ruleKey || item.label)}</b><em>${esc(item.input || item.label)}</em></span><span>${esc(item.output || item.description || '-')}</span><span>${statusBadge(item.reviewStatus)}<small>${esc(item.sourceRef)}</small><em>${esc(item.sourceClass)}</em></span></div>`).join('')}`;
  }

  function therapyCandidates(axis) {
    const targetCode = `dosha.${axis}`;
    const target = state.concepts.find(concept => concept.concept_code === targetCode);
    if (!target) return [];
    return state.relations
      .filter(relation => relation.predicate === 'has_traditional_claim_for' && String(relation.object_concept_id) === String(target.id))
      .map(relation => ({ relation, concept: conceptById(relation.subject_concept_id) }))
      .filter(item => item.concept)
      .sort((a, b) => a.concept.preferred_term_th.localeCompare(b.concept.preferred_term_th, 'th'));
  }

  function renderTherapy(result) {
    const axis = result.hypothesis.axis;
    if (!axis) {
      $('#ttm-therapy-candidates').innerHTML = '<div class="status">เลือกสมมติฐานของผู้ประกอบวิชาชีพก่อน จึงจะเห็น claim ที่เชื่อมไว้</div>';
      return;
    }
    const all = therapyCandidates(axis);
    const shown = all.slice(0, 12);
    const candidateMarkup = shown.map(({ relation, concept }) => {
      const occurrence = relation.qualifiers?.occurrences?.[0] || {};
      return `<article class="foundation-therapy-item"><span><small>${esc(concept.metadata?.coordinate_family || 'พิกัดยา')}</small><b>${esc(concept.preferred_term_th)}</b><p>${esc(relation.evidence_note || occurrence.claim_text || 'claim จากต้นทาง')}</p></span><span>${statusBadge(relation.review_status)}<small>${esc(occurrence.source_ref || concept.metadata?.source_refs?.[0] || 'ยังไม่ระบุเซลล์ต้นทาง')}</small><button type="button" data-foundation-open-concept="${esc(concept.id)}">ดู node</button></span></article>`;
    }).join('') || '<div class="status">ยังไม่มี relation จากพิกัดยาที่เชื่อมกับแกนนี้</div>';
    $('#ttm-therapy-candidates').innerHTML = `<div class="foundation-therapy-warning"><b>พบ ${all.length} claim สำหรับแกน ${esc(AXIS_LABELS[axis])}</b><span>แสดง ${shown.length} รายการแรก • ทั้งหมดเป็น review_required และไม่ใช่ขนาดยา/ใบสั่งยา</span></div>${candidateMarkup}`;
    $$('[data-foundation-open-concept]').forEach(button => button.addEventListener('click', () => {
      switchTab('knowledge');
      showDetail(button.dataset.foundationOpenConcept);
      $('#foundation-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }));
  }

  function renderReasoning(result) {
    const matched = result.evidence.length + result.constitution.evidence.length;
    const ageText = result.constitution.age === null ? 'ไม่ทราบอายุ' : `อายุ ${result.constitution.age} ปี`;
    const dayText = result.constitution.weekday ? `เกิดวัน${result.constitution.weekday}` : 'ยังไม่ระบุวันเกิด';
    $('#ttm-case-status').innerHTML = `<b>${esc(result.input.caseName || 'เคสไม่ระบุชื่อ')}</b><span>${esc(ageText)} • ${esc(dayText)} • จับคู่ ${matched} evidence • approved ${result.counts.approvedEvidence} / review ${result.counts.reviewRequiredEvidence}</span>`;
    const gate = $('#ttm-clinical-gate');
    const open = result.clinical.status === 'candidate_only';
    gate.className = `foundation-clinical-gate ${open ? 'review' : 'blocked'}`;
    gate.innerHTML = open
      ? `<b>Clinical inference: candidate only</b><span>มีกฎที่อนุมัติ ${result.clinical.approvedRuleCount} กฎ และจับคู่ ${result.clinical.evidenceCount} evidence • ต้องยืนยันโดยผู้ประกอบวิชาชีพ</span>`
      : `<b>Clinical inference: หยุดเพราะหลักฐานไม่พอ</b><span>กฎ finding → hypothesis ที่อนุมัติ ${result.clinical.approvedRuleCount} กฎ • น้ำหนักบริบทห้ามถูกใช้แทน diagnosis</span>`;
    renderLenses(result);
    renderAxisCards(result);
    renderMessages('#ttm-conflicts', result.conflicts, 'ยังไม่พบ conflict จากข้อมูลที่กรอก', 'conflict');
    renderMessages('#ttm-gaps', result.gaps, 'ไม่มี knowledge gap ที่ตรวจพบในขั้นนี้', 'gap');
    renderPath(result);
    renderAudit(result);
    renderTherapy(result);
  }

  function analyzeCase() {
    const engine = window.ChananyaTtmReasoning;
    if (!engine) throw new Error('TTM reasoning engine ไม่พร้อมใช้งาน');
    const input = caseInput();
    if (![input.birthDate, input.symptomTime, input.observationText, input.hypothesisAxis].some(Boolean)) {
      toast('กรอกข้อมูลอย่างน้อย 1 เลนส์ก่อนวิเคราะห์');
      return;
    }
    lastReasoning = engine.buildContextReasoning(input, state.rules, new Date());
    renderReasoning(lastReasoning);
  }

  function sampleBirthDate() {
    const now = new Date();
    const sample = new Date(Date.UTC(now.getUTCFullYear() - 16, now.getUTCMonth(), now.getUTCDate()));
    return sample.toISOString().slice(0, 10);
  }

  function loadSample() {
    $('#ttm-case-name').value = 'เคสสาธิต • boundary audit';
    $('#ttm-birth-date').value = sampleBirthDate();
    $('#ttm-conception-month').value = '6';
    $('#ttm-symptom-time').value = '23:30';
    $('#ttm-kala-mode').value = 'main';
    $('#ttm-observation-text').value = 'ตัวร้อน แน่นท้อง และนอนไม่สบาย — ข้อความนี้ยังไม่ใช่ finding แบบ structured';
    $('#ttm-hypothesis-axis').value = 'pitta';
    $('#ttm-hypothesis-state').value = 'กำเริบ';
    analyzeCase();
    toast('โหลดเคสสาธิตแล้ว • ตั้งใจให้เห็น boundary conflict');
  }

  function clearCase() {
    $('#ttm-case-form').reset();
    lastReasoning = null;
    $('#ttm-case-status').textContent = 'กรอกข้อมูลหรือโหลดเคสตัวอย่างเพื่อเริ่ม';
    $('#ttm-clinical-gate').className = 'foundation-clinical-gate blocked';
    $('#ttm-clinical-gate').innerHTML = '<b>Clinical inference: ยังไม่เปิด</b><span>ต้องมีกฎสิ่งตรวจพบ → สมมติฐานที่ผ่านอนุมัติก่อน</span>';
    $('#ttm-lenses').innerHTML = '<div class="status">ยังไม่มีข้อมูล</div>';
    $('#ttm-context-axis-cards').innerHTML = '<div class="status">ยังไม่มีข้อมูล</div>';
    $('#ttm-conflicts').innerHTML = '';
    $('#ttm-gaps').innerHTML = '';
    $('#ttm-evidence-audit').innerHTML = '<div class="status">ยังไม่มีการวิเคราะห์</div>';
    $('#ttm-therapy-candidates').innerHTML = '<div class="status">เลือกสมมติฐานก่อนเพื่อดูความเชื่อมโยง</div>';
    renderEmptyPath();
  }

  function renderEmptyPath() {
    const stages = ['บุคคล', 'บริบทหลายเลนส์', 'อาการ / สิ่งตรวจพบ', 'สมมติฐานจากกฎ', 'ผู้ประกอบวิชาชีพยืนยัน', 'หลักรักษา / ตำรับ'];
    $('#ttm-reasoning-path').innerHTML = stages.map((title, index) => `<article class="foundation-path-stage ${index > 2 ? 'locked' : 'pending'}"><span>0${index + 1}</span><div><b>${title}</b><small>${index > 2 ? 'ยังล็อก' : 'รอข้อมูล'}</small></div><em>${index > 2 ? 'ล็อก' : 'รอข้อมูล'}</em></article>`).join('');
  }

  function bindWorkbench() {
    $('#ttm-case-form').addEventListener('submit', event => { event.preventDefault(); analyzeCase(); });
    $('#ttm-load-sample').addEventListener('click', loadSample);
    $('#ttm-clear-case').addEventListener('click', clearCase);
    $('#ttm-hypothesis-axis').addEventListener('change', () => { if (lastReasoning) analyzeCase(); });
    $('#ttm-hypothesis-state').addEventListener('change', () => { if (lastReasoning) analyzeCase(); });
  }

  function renderBodyRegistry() {
    $('#ttm-body-registry').innerHTML = BODY_GROUPS.map(group => {
      const concept = state.concepts.find(item => item.concept_code === group.code);
      const approvedMembers = Number(concept?.metadata?.member_count_approved || 0);
      const percent = Math.min(100, (approvedMembers / group.target) * 100);
      return `<article class="foundation-body-card ${group.className}"><span><small>เป้าหมายทะเบียน</small><strong>${group.target}</strong></span><div><h3>${group.label}</h3><p>${concept ? 'สร้าง registry node แล้ว' : 'ยังไม่พบ registry node ในฐาน staging'} • รายชื่อสมาชิกต้องมี source ไม่อนุมานให้ครบเอง</p><div class="foundation-body-track"><i style="width:${percent}%"></i></div><small>สมาชิกที่รับรอง ${approvedMembers}/${group.target}</small></div>${concept ? statusBadge(concept.review_status) : '<span class="coverage-state missing">missing</span>'}</article>`;
    }).join('');
  }

  function renderRuleCoverage() {
    const coverage = window.ChananyaTtmReasoning?.coverageByDomain(state.rules) || [];
    const rows = coverage.map(item => `<div class="foundation-coverage-row"><span><b>${esc(DOMAIN_LABELS[item.domain] || item.domain)}</b><small>${esc(item.domain)}</small></span><strong>${item.total}</strong><span class="coverage-number ready">${item.approved} approved</span><span class="coverage-number review">${item.reviewRequired} review</span></div>`).join('');
    $('#ttm-rule-coverage').innerHTML = `<div class="foundation-coverage-head"><b>Domain</b><b>ทั้งหมด</b><b>อนุมัติ</b><b>รอทบทวน</b></div>${rows || '<div class="status">ยังไม่พบกฎ</div>'}<div class="foundation-coverage-summary"><b>Clinical finding → hypothesis</b><strong>${clinicalRules().length} approved</strong><span>${clinicalRules().length ? 'เปิดได้เฉพาะ candidate' : 'ยังไม่พร้อมใช้ระบุภาวะจากอาการ'}</span></div>`;
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
      if (!runtime.can(profile, 'knowledge_read')) throw new Error('บัญชีนี้ไม่มีสิทธิ์อ่านรากวิชา');
      window.ChananyaShell?.mount({ profile, session, active: 'foundation' });
      try {
        await loadOntology();
      } catch (ontologyError) {
        console.warn('Foundation graph is not installed; using legacy bridge', ontologyError);
        await loadLegacy();
      }
      updateStats();
      renderTypeOptions();
      bindTabs();
      bindKnowledgeFilters();
      bindWorkbench();
      renderConcepts();
      renderBodyRegistry();
      renderRuleCoverage();
      renderEmptyPath();
      $('#app').classList.remove('hidden');
      $('#boot').classList.add('hidden');
      window.dispatchEvent(new CustomEvent('chananya:foundation-rendered'));
    } catch (error) {
      console.error(error);
      $('#boot-error').textContent = error.message;
    }
  }

  $('#logout').addEventListener('click', async () => { await db.auth.signOut(); location.replace('/login.html'); });
  init();
})();
