// Shared, browser-safe package specification. Contains no credentials or tenant registry.
export const PLATFORM_FEATURES = Object.freeze([
  { id: 'core', name: 'ระบบหลัก', detail: 'บัญชีผู้ใช้ สิทธิ์ ศูนย์ปฏิบัติการ และ Audit', requires: [], required: true, pages: [] },
  { id: 'appointments', name: 'นัดหมาย', detail: 'ตารางแพทย์และคิวผู้รับบริการ', requires: ['core'], pages: ['appointments'] },
  { id: 'knowledge', name: 'ฐานความรู้แผนไทย', detail: 'รากวิชาและสมุฏฐานวินิจฉัย', requires: ['core'], pages: ['foundation', 'evidence'] },
  { id: 'u-synthesise', name: 'U Synthesise', detail: 'Luopan · Wuxing–BaZi · โหรไทย · สมุฏฐาน', requires: ['core'], pages: ['luopan', 'luopan-wheel'] },
  { id: 'clinical', name: 'เวชระเบียน', detail: 'ตรวจ วินิจฉัย และแผนการรักษา', requires: ['knowledge'], pages: ['clinical-v3'] },
  { id: 'outcomes', name: 'ติดตามผล', detail: 'ผลการรักษาและการติดตามผู้รับบริการ', requires: ['clinical'], pages: ['outcomes'] },
  { id: 'pharmacy', name: 'ห้องยา', detail: 'ใบสั่งยา การจ่ายยา และผลิตภัณฑ์', requires: ['clinical'], pages: ['pharmacy'] },
  { id: 'production', name: 'ผลิตและคลัง', detail: 'สูตรการผลิต Batch และวัตถุดิบ', requires: ['pharmacy'], pages: ['production'] },
  { id: 'quality', name: 'ควบคุมคุณภาพ', detail: 'ตรวจ QC และอนุมัติปล่อยผ่าน', requires: ['production'], pages: ['quality'] }
].map(item => Object.freeze({ ...item, requires: Object.freeze(item.requires), pages: Object.freeze(item.pages) })));

export function platformError(code, field = '') {
  return Object.assign(new Error(code), { field });
}

export function resolvePlatformFeatures(value) {
  if (!Array.isArray(value) || value.length > PLATFORM_FEATURES.length
    || value.some(id => !PLATFORM_FEATURES.some(feature => feature.id === id))) {
    throw platformError('PLATFORM_FEATURES_INVALID', 'features');
  }
  const chosen = new Set(['core', ...value]);
  function add(id) {
    for (const dependency of PLATFORM_FEATURES.find(feature => feature.id === id).requires) {
      chosen.add(dependency); add(dependency);
    }
  }
  [...chosen].forEach(add);
  return PLATFORM_FEATURES.filter(feature => chosen.has(feature.id)).map(feature => feature.id);
}

function cleanText(value, field, max, optional = false) {
  if (typeof value !== 'string') throw platformError('PLATFORM_INPUT_INVALID', field);
  const result = value.trim();
  if ((!optional && result.length < 2) || result.length > max || /[\u0000-\u001f\u007f]/.test(result)) {
    throw platformError('PLATFORM_INPUT_INVALID', field);
  }
  return result;
}

function urlInput(value, field) {
  let url;
  try { url = new URL(value); } catch { throw platformError('PLATFORM_LINK_INVALID', field); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port) {
    throw platformError('PLATFORM_LINK_INVALID', field);
  }
  return url;
}

// Normalize identifiers only. A pasted link never authorizes an outbound request.
export function normalizePlatformLink(kind, value) {
  const input = cleanText(value || '', kind, 500, true);
  if (!input) return null;
  if (kind === 'nas') {
    if (input.startsWith('smb://')) {
      let smb;
      try { smb = new URL(input); } catch { throw platformError('PLATFORM_NAS_LINK_INVALID', kind); }
      if (smb.protocol !== 'smb:' || smb.hash || smb.username || smb.password || smb.port || smb.search
        || !/^[a-z0-9.-]+$/i.test(smb.hostname)) {
        throw platformError('PLATFORM_NAS_LINK_INVALID', kind);
      }
      const normalized = `${smb.protocol}//${smb.host}${smb.pathname}`.replace(/\/$/, '');
      if (!normalized) throw platformError('PLATFORM_NAS_LINK_INVALID', kind);
      return { kind, url: normalized, requiresAgent: true };
    }
    if (input.startsWith('http://') || input.startsWith('https://')) {
      const url = urlInput(input, kind);
      if (url.search) throw platformError('PLATFORM_LINK_SECRET_DENIED', kind);
      if (!/^[a-z0-9.-]+$/i.test(url.hostname)) throw platformError('PLATFORM_NAS_LINK_INVALID', kind);
      return { kind, url: url.toString().replace(/\/$/, ''), requiresAgent: true };
    }
    const startsAsPath = input.startsWith('\\\\') || /^[A-Za-z]:\\/.test(input) || input.startsWith('/');
    const hasForbiddenChars = /[<>:"|?*\u0000-\u001f]/.test(input)
      || (input.includes(':') && !/^[A-Za-z]:/.test(input));
    if (!startsAsPath || hasForbiddenChars) throw platformError('PLATFORM_NAS_LINK_INVALID', kind);
    return { kind, url: input.replace(/[\\/]$/, ''), requiresAgent: true };
  }
  if (kind === 'drive') {
    let id = input;
    if (input.includes('://')) {
      const url = urlInput(input, kind);
      if (url.hostname !== 'drive.google.com' || [...url.searchParams.keys()].some(key => !['usp', 'id'].includes(key))) {
        throw platformError('PLATFORM_DRIVE_LINK_INVALID', kind);
      }
      id = url.pathname.match(/^\/drive\/(?:u\/\d+\/)?folders\/([A-Za-z0-9_-]+)\/?$/)?.[1]
        || (url.pathname === '/open' ? url.searchParams.get('id') : '');
    }
    if (!/^[A-Za-z0-9_-]{10,200}$/.test(id)) throw platformError('PLATFORM_DRIVE_LINK_INVALID', kind);
    return { kind, id, url: `https://drive.google.com/drive/folders/${id}` };
  }
  if (kind === 'database') {
    const url = urlInput(input, kind);
    if (url.search) throw platformError('PLATFORM_LINK_SECRET_DENIED', kind);
    const ref = (url.hostname === 'supabase.com'
      ? url.pathname.match(/^\/dashboard\/project\/([a-z]{20})(?:\/[a-zA-Z0-9/_-]*)?$/)?.[1]
      : url.pathname === '/' ? url.hostname.match(/^([a-z]{20})\.supabase\.co$/)?.[1] : '');
    if (!ref) throw platformError('PLATFORM_DATABASE_LINK_INVALID', kind);
    return { kind, projectRef: ref, url: `https://${ref}.supabase.co` };
  }
  const url = urlInput(input, kind);
  if (url.search) throw platformError('PLATFORM_LINK_SECRET_DENIED', kind);
  if (kind === 'site') {
    if (url.pathname !== '/' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(url.hostname)) {
      throw platformError('PLATFORM_SITE_LINK_INVALID', kind);
    }
    return { kind, url: url.origin };
  }
  throw platformError('PLATFORM_LINK_KIND_INVALID', kind);
}

export function normalizePlatformPlan(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw platformError('PLATFORM_INPUT_INVALID');
  const keys = ['name', 'slug', 'targetKey', 'site', 'database', 'drive', 'nas', 'features'];
  if (Object.keys(input).some(key => !keys.includes(key))) throw platformError('PLATFORM_UNKNOWN_FIELD_DENIED');
  const name = cleanText(input.name, 'name', 80);
  const slug = cleanText(input.slug, 'slug', 48);
  if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(slug)) throw platformError('PLATFORM_SLUG_INVALID', 'slug');
  const targetKey = cleanText(input.targetKey || '', 'targetKey', 60, true);
  if (targetKey && !/^[a-z][a-z0-9-]{1,59}$/.test(targetKey)) throw platformError('PLATFORM_TARGET_INVALID', 'targetKey');
  const links = Object.fromEntries(['site', 'database', 'drive', 'nas'].map(kind => [kind, normalizePlatformLink(kind, input[kind] || '')]));
  return { schemaVersion: 1, name, slug, targetKey, links, features: resolvePlatformFeatures(input.features) };
}

export function platformPlanInput(plan) {
  return { name: plan.name, slug: plan.slug, targetKey: plan.targetKey,
    ...Object.fromEntries(['site', 'database', 'drive', 'nas'].map(kind => [kind, plan.links[kind]?.url || ''])),
    features: plan.features };
}

export function platformPreflight(plan, targets, { dispatcherReady = false } = {}) {
  const target = targets.find(item => item.key === plan.targetKey);
  const checks = [];
  const check = (id, status, message) => checks.push({ id, status, message });
  check('package', 'ready', `จัดชุด ${plan.features.length} ฟีเจอร์ รวมส่วนที่จำเป็นแล้ว`);
  check('target', target ? 'ready' : 'blocked', target ? `ปลายทางที่ลงทะเบียน: ${target.label}` : 'ต้องลงทะเบียนเว็บไซต์ปลายทางก่อน Deploy');
  const matches = target && plan.links.site?.url === target.siteOrigin
    && plan.links.database?.projectRef === target.projectRef
    && (!plan.links.drive || plan.links.drive.id === target.driveRootId);
  check('isolation', matches ? 'ready' : 'blocked', matches ? 'ชื่อเว็บไซต์และฐานข้อมูลตรงกับลูกค้าที่ลงทะเบียน' : 'ลิงก์เว็บไซต์ ฐานข้อมูล หรือ Drive ยังไม่ตรงกับลูกค้าที่เลือก');
  check('dispatcher', dispatcherReady ? 'ready' : 'blocked', dispatcherReady ? 'เชื่อมบริการส่งงาน Deploy แล้ว' : 'ยังต้องเชื่อมสิทธิ์ GitHub สำหรับส่งงาน Deploy');
  if (plan.links.drive) check('drive', 'pending', 'จำลิงก์ Drive แล้ว ต้องเชื่อมบัญชีและทดสอบสำรอง/กู้คืนก่อนใช้งานจริง');
  if (plan.links.nas) check('nas', 'pending', 'จำลิงก์ NAS แล้ว ต้องติดตั้งตัวเชื่อมต่อและทดสอบสิทธิ์เขียน');
  check('live', 'pending', 'Deploy ทดสอบจะล็อกฐานข้อมูลไว้; เปิดใช้จริงผ่านขั้นตอนอนุมัติ Production เดิม');
  return { checks, canDeployPreview: checks.every(item => item.status !== 'blocked'), canDeployProduction: false };
}
