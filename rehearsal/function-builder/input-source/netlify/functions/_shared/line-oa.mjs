import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const LINE_REPLY_URL = 'https://api.line.me/v2/bot/message/reply';
const ACTIONS = new Set([
  'card',
  'status',
  'appointments',
  'privacy',
  'revoke',
  'help',
  'unknown',
  'none'
]);

export function sha256Hex(value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex');
}

export function verifyLineWebhookSignature(rawBody, signature, channelSecret) {
  if (typeof rawBody !== 'string' || !signature || !channelSecret || channelSecret.length < 16) {
    return false;
  }

  let supplied;
  try {
    supplied = Buffer.from(String(signature), 'base64');
  } catch {
    return false;
  }
  const expected = createHmac('sha256', channelSecret).update(rawBody, 'utf8').digest();
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export async function readLineWebhookBody(request, maxBytes = 1_048_576) {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > maxBytes) throw new Error('LINE_WEBHOOK_REQUEST_TOO_LARGE');
  const rawBody = await request.text();
  if (Buffer.byteLength(rawBody, 'utf8') > maxBytes) {
    throw new Error('LINE_WEBHOOK_REQUEST_TOO_LARGE');
  }
  return rawBody;
}

export function parseLineWebhook(rawBody) {
  let payload;
  try {
    payload = JSON.parse(rawBody || '{}');
  } catch {
    throw new Error('LINE_WEBHOOK_JSON_INVALID');
  }
  if (!payload || typeof payload !== 'object' || !Array.isArray(payload.events)) {
    throw new Error('LINE_WEBHOOK_PAYLOAD_INVALID');
  }
  if (payload.events.length > 50) throw new Error('LINE_WEBHOOK_EVENT_LIMIT_EXCEEDED');
  return payload.events;
}

function normalizedText(value) {
  return String(value || '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\s._-]+/g, '');
}

function postbackAction(data) {
  if (typeof data !== 'string' || data.length > 512) return 'unknown';
  const params = new URLSearchParams(data);
  const action = normalizedText(params.get('action'));
  return ACTIONS.has(action) ? action : 'unknown';
}

export function classifyLineAction(event) {
  if (!event || typeof event !== 'object') return 'unknown';
  if (event.type === 'follow' || event.type === 'unfollow') return 'none';
  if (event.type === 'postback') return postbackAction(event.postback?.data);
  if (event.type !== 'message' || event.message?.type !== 'text') return 'unknown';

  const value = normalizedText(event.message.text);
  if (!value) return 'unknown';
  if (/(ถอนความยินยอม|ยกเลิกการเชื่อม|ลบบัญชี|unlink|revoke)/u.test(value)) return 'revoke';
  if (/(ความเป็นส่วนตัว|ข้อมูลส่วนบุคคล|นโยบายข้อมูล|pdpa|privacy)/u.test(value)) return 'privacy';
  if (/(นัดหมาย|การนัด|นัด|appointment|booking)/u.test(value)) return 'appointments';
  if (/(บัตรผู้รับบริการ|บัตรผู้ป่วย|คิวอาร์|qr|เอชเอ็น|hn)/u.test(value)) return 'card';
  if (/(สถานะ|เชื่อมบัญชี|status|linked)/u.test(value)) return 'status';
  if (/(ช่วยเหลือ|เมนู|วิธีใช้|help|menu)/u.test(value)) return 'help';
  return 'unknown';
}

export function lineEventHashes(event) {
  const serialized = JSON.stringify(event || {});
  const stableId = String(event?.webhookEventId || serialized);
  return Object.freeze({
    eventIdHash: sha256Hex(stableId),
    payloadHash: sha256Hex(serialized)
  });
}

export function lineEventTimestamp(event, now = Date.now()) {
  const milliseconds = Number(event?.timestamp);
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return new Date(now).toISOString();
  const timestamp = new Date(milliseconds);
  return Number.isNaN(timestamp.getTime()) ? new Date(now).toISOString() : timestamp.toISOString();
}

export function safePatientCardUrl(value) {
  try {
    const url = new URL(String(value || ''));
    if (url.protocol !== 'https:') return '';
    if (url.username || url.password) return '';
    return url.toString();
  } catch {
    return '';
  }
}

function quickReply(cardUrl) {
  const items = [];
  if (cardUrl) {
    items.push({
      type: 'action',
      action: { type: 'uri', label: 'เปิดบัตรผู้รับบริการ', uri: cardUrl }
    });
  }
  items.push(
    { type: 'action', action: { type: 'message', label: 'ดูเมนู', text: 'เมนู' } },
    { type: 'action', action: { type: 'message', label: 'ความเป็นส่วนตัว', text: 'ความเป็นส่วนตัว' } }
  );
  return { items };
}

export function buildLineReplyMessages(action, options = {}) {
  const cardUrl = safePatientCardUrl(options.patientCardUrl);
  const brandName = String(options.brandName || 'ชนัญญา').trim().slice(0, 40) || 'ชนัญญา';
  const menu = quickReply(cardUrl);
  const messages = {
    follow: `ยินดีต้อนรับสู่ ${brandName}\n\nใช้ LINE เพื่อเปิดบัตรผู้รับบริการและสร้าง QR แบบใช้ครั้งเดียวได้ โดยข้อมูลชื่อ HN การวินิจฉัย ยา และข้อมูลสุขภาพจะไม่ถูกส่งในห้องแชตนี้`,
    card: cardUrl
      ? 'เปิดบัตรผู้รับบริการผ่านปุ่มด้านล่างเพื่อสร้าง QR ที่หมดอายุภายใน 90 วินาที หากไม่มีมือถือสามารถแจ้ง HN กับเจ้าหน้าที่ได้ตามปกติ'
      : 'บริการบัตรผู้รับบริการดิจิทัลยังไม่เปิดใช้งาน กรุณาแจ้ง HN หรือติดต่อเจ้าหน้าที่',
    status: cardUrl
      ? 'เพื่อความเป็นส่วนตัว ระบบจะไม่แสดงชื่อ HN หรือสถานะการรักษาในแชต กรุณาตรวจสอบผ่านบัตรผู้รับบริการที่ยืนยันด้วย LINE'
      : 'กรุณาติดต่อเจ้าหน้าที่เพื่อตรวจสอบสถานะการเชื่อมบัญชี',
    appointments: 'ระบบจะไม่ส่งรายละเอียดนัดหรือข้อมูลสุขภาพในแชต กรุณาติดต่อเจ้าหน้าที่ของคลินิกเพื่อยืนยันนัดหมาย',
    privacy: 'ระบบไม่เก็บข้อความสนทนาไว้ในเวชระเบียน และไม่ส่งชื่อ HN การวินิจฉัย ยา หรือข้อมูลสุขภาพในแชต คุณสามารถขอเข้าถึง แก้ไข หรือยกเลิกการเชื่อมบัญชีผ่านเจ้าหน้าที่',
    revoke: 'หากต้องการถอนความยินยอมหรือยกเลิกการเชื่อม LINE กรุณาแจ้งเจ้าหน้าที่ ระบบจะเพิกถอนลิงก์และทำให้ QR ที่ยังไม่ใช้หมดอายุทันที โดยไม่ลบประวัติการตรวจสอบย้อนหลัง',
    help: 'เมนู LINE ของคลินิก\n• พิมพ์ “บัตรผู้รับบริการ” เพื่อเปิด QR\n• พิมพ์ “นัดหมาย” เพื่อติดต่อเรื่องนัด\n• พิมพ์ “ความเป็นส่วนตัว” เพื่อดูหลักการคุ้มครองข้อมูล',
    unknown: 'เพื่อความปลอดภัย LINE นี้ไม่รับอาการ การวินิจฉัย หรือรายการยาอัตโนมัติ กรุณาเลือกเมนูด้านล่างหรือติดต่อเจ้าหน้าที่'
  };
  const key = action === 'none' ? 'help' : action;
  return [{ type: 'text', text: messages[key] || messages.unknown, quickReply: menu }];
}

export async function replyLineMessage({ replyToken, messages, channelAccessToken, fetchImpl = fetch }) {
  if (!replyToken || typeof replyToken !== 'string' || replyToken.length > 256) {
    throw new Error('LINE_REPLY_TOKEN_INVALID');
  }
  if (!channelAccessToken || channelAccessToken.length < 20) {
    throw new Error('LINE_CHANNEL_ACCESS_TOKEN_INVALID');
  }
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > 5) {
    throw new Error('LINE_REPLY_MESSAGES_INVALID');
  }

  const response = await fetchImpl(LINE_REPLY_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${channelAccessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ replyToken, messages }),
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error('LINE_REPLY_FAILED');
  return true;
}

export function publicLineWebhookError(error) {
  const known = new Set([
    'LINE_WEBHOOK_REQUEST_TOO_LARGE',
    'LINE_WEBHOOK_JSON_INVALID',
    'LINE_WEBHOOK_PAYLOAD_INVALID',
    'LINE_WEBHOOK_EVENT_LIMIT_EXCEEDED',
    'LINE_WEBHOOK_SIGNATURE_INVALID',
    'LINE_WEBHOOK_NOT_CONFIGURED'
  ]);
  const code = known.has(error?.message) ? error.message : 'LINE_WEBHOOK_PROCESSING_FAILED';
  const status = code === 'LINE_WEBHOOK_SIGNATURE_INVALID' ? 401
    : code === 'LINE_WEBHOOK_NOT_CONFIGURED' ? 503
      : code.includes('INVALID') || code.includes('LIMIT') || code.includes('LARGE') ? 400
        : 500;
  return Object.freeze({ code, status });
}
