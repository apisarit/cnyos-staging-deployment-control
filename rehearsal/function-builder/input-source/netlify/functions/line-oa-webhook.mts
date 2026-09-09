import {
  buildLineReplyMessages,
  classifyLineAction,
  lineEventHashes,
  lineEventTimestamp,
  parseLineWebhook,
  publicLineWebhookError,
  readLineWebhookBody,
  replyLineMessage,
  safePatientCardUrl,
  sha256Hex,
  verifyLineWebhookSignature
} from './_shared/line-oa.mjs';
import { hmacSha256, normalizeClinicId, supabaseRpc } from './_shared/patient-identity.mjs';

function noStoreHeaders() {
  return {
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Content-Type': 'application/json; charset=utf-8',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff'
  };
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: noStoreHeaders() });
}

function env(name) {
  return Netlify.env.get(name) || '';
}

function configuration() {
  const liffId = env('LINE_LIFF_ID');
  const configuredPatientUrl = env('LINE_OA_PATIENT_CARD_URL');
  const patientCardUrl = safePatientCardUrl(
    configuredPatientUrl || (liffId ? `https://liff.line.me/${liffId}` : '')
  );
  let expectedClinicId = '';
  try {
    expectedClinicId = normalizeClinicId(env('CNYOS_RUNTIME_EXPECTED_CLINIC_ID'));
  } catch {
    expectedClinicId = '';
  }
  const config = {
    messagingChannelId: env('LINE_MESSAGING_CHANNEL_ID'),
    channelSecret: env('LINE_MESSAGING_CHANNEL_SECRET'),
    channelAccessToken: env('LINE_MESSAGING_CHANNEL_ACCESS_TOKEN'),
    identitySecret: env('PATIENT_IDENTITY_HMAC_SECRET'),
    supabaseUrl: env('SUPABASE_URL'),
    serviceRoleKey: env('SUPABASE_SERVICE_ROLE_KEY'),
    expectedClinicId,
    patientCardUrl,
    brandName: env('LINE_OA_BRAND_NAME') || 'ชนัญญา'
  };
  const enabled = Boolean(
    config.messagingChannelId
    && config.channelSecret.length >= 16
    && config.channelAccessToken.length >= 20
    && config.identitySecret.length >= 32
    && config.supabaseUrl
    && config.serviceRoleKey
    && config.expectedClinicId
  );
  return Object.freeze({ ...config, enabled });
}

async function rpc(config, name, body) {
  return supabaseRpc({
    url: config.supabaseUrl,
    serviceRoleKey: config.serviceRoleKey,
    name,
    body
  });
}

function firstRow(payload) {
  return Array.isArray(payload) ? payload[0] || null : payload || null;
}

function eventSubject(event) {
  if (event?.source?.type !== 'user') return '';
  const userId = String(event.source.userId || '');
  return /^U[a-fA-F0-9]{20,64}$/.test(userId) ? userId : '';
}

function eventType(event) {
  const type = String(event?.type || 'unknown');
  return /^[A-Za-z][A-Za-z0-9]{1,40}$/.test(type) ? type : 'unknown';
}

function safeInternalCode(error) {
  const value = String(error?.message || 'UNKNOWN');
  return /^[A-Z][A-Z0-9_]{2,80}$/.test(value) ? value : 'UNKNOWN';
}

async function finalize(config, channelHash, eventIdHash, processingStatus, replyStatus, errorCode = null) {
  const finalized = await rpc(config, 'finalize_line_oa_webhook_event', {
    p_provider_channel_hash: channelHash,
    p_event_id_hash: eventIdHash,
    p_processing_status: processingStatus,
    p_reply_status: replyStatus,
    p_error_code: errorCode
  });
  if (finalized !== true) throw new Error('LINE_OA_FINALIZATION_FAILED');
}

async function finalizeBestEffort(config, channelHash, eventIdHash, processingStatus, replyStatus, errorCode) {
  try {
    await finalize(config, channelHash, eventIdHash, processingStatus, replyStatus, errorCode);
  } catch (error) {
    console.error('LINE OA webhook finalization failed', { code: safeInternalCode(error) });
  }
}

async function processEvent(event, config, context) {
  const { eventIdHash, payloadHash } = lineEventHashes(event);
  const channelHash = sha256Hex(config.messagingChannelId);
  const subject = eventSubject(event);
  const subjectHash = subject ? hmacSha256(subject, config.identitySecret) : null;
  const action = classifyLineAction(event);
  const type = eventType(event);

  const claim = firstRow(await rpc(config, 'register_line_oa_webhook_event_for_clinic', {
    p_clinic_id: config.expectedClinicId,
    p_provider_channel_hash: channelHash,
    p_event_id_hash: eventIdHash,
    p_subject_hash: subjectHash,
    p_event_type: type,
    p_action_code: action,
    p_event_timestamp: lineEventTimestamp(event),
    p_is_redelivery: event?.deliveryContext?.isRedelivery === true,
    p_payload_hash: hmacSha256(payloadHash, config.identitySecret)
  }));
  if (!claim?.accepted) return { duplicate: true };

  try {
    if (event?.source?.type !== 'user') {
      await finalize(config, channelHash, eventIdHash, 'ignored', 'not_applicable');
      return { ignored: true };
    }
    if (type === 'unfollow') {
      await finalize(config, channelHash, eventIdHash, 'processed', 'not_applicable');
      return { processed: true };
    }

    const replyable = type === 'follow'
      || type === 'postback'
      || (type === 'message' && event?.message?.type === 'text');
    if (!replyable || !event.replyToken) {
      await finalize(config, channelHash, eventIdHash, 'ignored', 'not_applicable');
      return { ignored: true };
    }

    const replyAction = type === 'follow' ? 'follow' : action;
    const messages = buildLineReplyMessages(replyAction, {
      patientCardUrl: config.patientCardUrl,
      brandName: config.brandName
    });
    // Re-check immediately before the external LINE send. Registration and
    // database mutations are already guarded; this closes the practical race
    // between accepting the event and consuming its one-time reply token.
    await rpc(config, 'assert_clinic_subscription_active', {
      p_clinic_id: config.expectedClinicId
    });
    await replyLineMessage({
      replyToken: String(event.replyToken),
      messages,
      channelAccessToken: config.channelAccessToken
    });
    await finalize(config, channelHash, eventIdHash, 'processed', 'sent');
    return { processed: true };
  } catch (error) {
    const code = safeInternalCode(error);
    await finalizeBestEffort(config, channelHash, eventIdHash, 'failed', 'failed', code);
    console.error('LINE OA event processing failed', {
      requestId: context.requestId,
      eventId: eventIdHash.slice(0, 12),
      code
    });
    throw error;
  }
}

export default async (request, context) => {
  const config = configuration();
  let signatureVerified = false;
  let received = 0;

  if (request.method === 'GET') {
    return json({
      enabled: config.enabled,
      callbackPath: '/api/line-oa-webhook',
      patientCardConfigured: Boolean(config.patientCardUrl),
      chatContainsClinicalData: false
    });
  }
  if (request.method !== 'POST') {
    return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);
  }
  if (!config.enabled) {
    return json({ ok: false, code: 'LINE_WEBHOOK_NOT_CONFIGURED' }, 503);
  }

  try {
    const rawBody = await readLineWebhookBody(request);
    const signature = request.headers.get('x-line-signature') || '';
    if (!verifyLineWebhookSignature(rawBody, signature, config.channelSecret)) {
      throw new Error('LINE_WEBHOOK_SIGNATURE_INVALID');
    }
    signatureVerified = true;
    const events = parseLineWebhook(rawBody);
    received = events.length;
    await rpc(config, 'assert_clinic_subscription_active', {
      p_clinic_id: config.expectedClinicId
    });
    const results = [];
    for (const event of events) {
      results.push(await processEvent(event, config, context));
    }
    return json({ ok: true, received: events.length, processed: results.filter(item => item.processed).length });
  } catch (error) {
    if (signatureVerified && error?.message === 'CNYOS_SUBSCRIPTION_SUSPENDED') {
      // A valid delivery to a suspended clinic is acknowledged without
      // registering tenant state or sending a LINE reply. Gateway finalization
      // remains a narrow non-tenant evidence exception for a concurrent OFF.
      return json({ ok: true, suspended: true, received, processed: 0 });
    }
    const safe = publicLineWebhookError(error);
    console.error('LINE OA webhook request failed', {
      requestId: context.requestId,
      code: safe.code,
      internalCode: safeInternalCode(error)
    });
    return json({ ok: false, code: safe.code }, safe.status);
  }
};

export const config = {
  path: '/api/line-oa-webhook',
  method: ['GET', 'POST']
};
