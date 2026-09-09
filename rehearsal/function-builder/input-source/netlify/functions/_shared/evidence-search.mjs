import { assertOwnerRuntime } from './owner-control.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SOURCES = new Set(['pubmed', 'clinicaltrials', 'dailymed']);
const KNOWLEDGE_ROLES = new Set(['super_admin', 'practitioner', 'doctor', 'pharmacy', 'production', 'inventory']);
const RESPONSE_LIMIT = 524_288;
const MAX_RESULTS = 5;
const HEADERS = Object.freeze({
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'private, no-store, max-age=0',
  'Netlify-CDN-Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff'
});

function failure(code, status) {
  return Object.assign(new Error(code), { publicCode: code, status });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: HEADERS });
}

function tokenClaims(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3 || !parts.every(part => /^[A-Za-z0-9_-]+$/.test(part))) throw new Error();
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new Error();
    return claims;
  } catch { throw failure('EVIDENCE_SESSION_REQUIRED', 401); }
}

export function evidenceConfiguration(getEnv) {
  if (getEnv('CNYOS_EVIDENCE_ENABLED') !== 'true') throw failure('EVIDENCE_DISABLED', 503);
  const expectedProjectRef = getEnv('CNYOS_OWNER_EXPECTED_PROJECT_REF');
  const expectedClinicId = getEnv('CNYOS_RUNTIME_EXPECTED_CLINIC_ID');
  const supabaseUrl = getEnv('SUPABASE_URL');
  const publicKey = getEnv('SUPABASE_PUBLISHABLE_KEY') || getEnv('SUPABASE_ANON_KEY');
  if (!/^[a-z]{20}$/.test(expectedProjectRef)
    || !UUID.test(expectedClinicId)
    || ![ `https://${expectedProjectRef}.supabase.co`, `https://${expectedProjectRef}.supabase.co/` ].includes(supabaseUrl)) {
    throw failure('EVIDENCE_NOT_CONFIGURED', 503);
  }
  // Public API keys only. An accidentally supplied elevated key must fail closed.
  if (!/^sb_publishable_[A-Za-z0-9_-]{20,200}$/.test(publicKey)) {
    try {
      const claims = tokenClaims(publicKey);
      if (claims.role !== 'anon' || claims.ref !== expectedProjectRef) throw new Error();
    } catch { throw failure('EVIDENCE_NOT_CONFIGURED', 503); }
  }
  return Object.freeze({
    supabaseUrl: supabaseUrl.replace(/\/$/, ''), publicKey,
    pubmedEnabled: getEnv('CNYOS_EVIDENCE_PUBMED_ENABLED') === 'true',
    expectedClinicId: expectedClinicId.toLowerCase(),
    expectedSiteId: getEnv('CNYOS_OWNER_EXPECTED_NETLIFY_SITE_ID'),
    expectedSiteOrigin: getEnv('CNYOS_OWNER_EXPECTED_SITE_ORIGIN')
  });
}

export function normalizeEvidenceQuery(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some(key => !['source', 'query'].includes(key))
    || !SOURCES.has(body.source) || typeof body.query !== 'string') {
    throw failure('EVIDENCE_INPUT_INVALID', 400);
  }
  const query = body.query.trim().replace(/\s+/g, ' ');
  if (body.query.length > 200 || query.length < 2 || query.length > 160
    || /[\u0000-\u001f\u007f<>\\{}]/.test(body.query)
    || /(?:[a-z][a-z0-9+.-]*:\/\/|www\.|@)/i.test(query)) {
    throw failure('EVIDENCE_QUERY_INVALID', 400);
  }
  return Object.freeze({ source: body.source, query });
}

async function readBoundedJson(message, maxBytes, code, status) {
  const statedLength = Number(message.headers.get('content-length') || 0);
  if (statedLength > maxBytes || !message.body) throw failure(code, status);
  const reader = message.body.getReader();
  const chunks = [];
  let count = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      count += value.byteLength;
      if (count > maxBytes) {
        await reader.cancel();
        throw failure(code, status);
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw failure(code, status); }
}

async function databaseRequest(config, token, resource, fetchImpl, signal) {
  const isAuth = resource === '/auth/v1/user';
  if (!isAuth && resource !== '/rest/v1/rpc/current_access_context') {
    throw failure('EVIDENCE_ACCESS_UNAVAILABLE', 503);
  }
  let response;
  try {
    response = await fetchImpl(`${config.supabaseUrl}${resource}`, {
      method: isAuth ? 'GET' : 'POST',
      headers: {
        apikey: config.publicKey,
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        ...(!isAuth ? { 'Content-Type': 'application/json' } : {})
      },
      ...(!isAuth ? { body: '{}' } : {}),
      redirect: 'error', signal
    });
  } catch { throw failure('EVIDENCE_ACCESS_UNAVAILABLE', 503); }
  if (response.status === 401) throw failure('EVIDENCE_SESSION_REQUIRED', 401);
  if (response.status === 403) throw failure('EVIDENCE_ACCESS_DENIED', 403);
  if (!response.ok) throw failure('EVIDENCE_ACCESS_UNAVAILABLE', 503);
  return readBoundedJson(response, 65_536, 'EVIDENCE_ACCESS_UNAVAILABLE', 503);
}

function validateAccess(rows, config) {
  // This existing RPC joins the current auth.uid() to active membership and
  // active clinic subscription on every request. Never trust browser roles.
  if (!Array.isArray(rows) || rows.length !== 1 || rows[0]?.ready !== true
    || String(rows[0]?.clinic_id || '').toLowerCase() !== config.expectedClinicId) {
    throw failure('EVIDENCE_ACCESS_DENIED', 403);
  }
  if (!KNOWLEDGE_ROLES.has(rows[0].effective_role)) throw failure('EVIDENCE_CAPABILITY_DENIED', 403);
}

function text(value, limit = 500) {
  return typeof value === 'string'
    ? value.replace(/<[^>]*>/g, '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, limit)
    : '';
}

function result(id, title, url, date, detail) {
  return { id, title: text(title), url, date: text(date, 60) || null, detail: text(detail, 350) };
}

function total(value) {
  const count = Number(value);
  return Number.isSafeInteger(count) && count >= 0 ? count : undefined;
}

async function providerJson(url, fetchImpl, signal) {
  // Called only with internally constructed URLs. No client-controlled URL,
  // headers, pagination links, identifiers or redirect destination is fetched.
  let response;
  try {
    response = await fetchImpl(url.toString(), {
      headers: { Accept: 'application/json' }, redirect: 'error', signal
    });
  } catch { throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502); }
  if (response.status === 429) throw failure('EVIDENCE_SOURCE_BUSY', 429);
  if (!response.ok) throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502);
  const type = response.headers.get('content-type') || '';
  if (!/application\/(?:[a-z0-9.+-]+\+)?json\b/i.test(type)) throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502);
  return readBoundedJson(response, RESPONSE_LIMIT, 'EVIDENCE_SOURCE_UNAVAILABLE', 502);
}

export async function searchEvidence(input, { fetchImpl = fetch, signal = AbortSignal.timeout(8000) } = {}) {
  const { source, query } = normalizeEvidenceQuery(input);
  if (source === 'pubmed') {
    const searchUrl = new URL('https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi');
    searchUrl.search = new URLSearchParams({ db: 'pubmed', retmode: 'json', retmax: String(MAX_RESULTS), term: query }).toString();
    const search = await providerJson(searchUrl, fetchImpl, signal);
    if (!Array.isArray(search?.esearchresult?.idlist)) throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502);
    const ids = [...new Set(search.esearchresult.idlist)].filter(id => typeof id === 'string' && /^[1-9][0-9]{0,9}$/.test(id)).slice(0, MAX_RESULTS);
    if (!ids.length) return { results: [], total: total(search.esearchresult.count) };
    const summaryUrl = new URL('https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi');
    summaryUrl.search = new URLSearchParams({ db: 'pubmed', retmode: 'json', id: ids.join(',') }).toString();
    const summary = await providerJson(summaryUrl, fetchImpl, signal);
    if (!summary?.result || typeof summary.result !== 'object') throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502);
    const results = ids.flatMap(id => {
      const item = summary.result[id];
      if (item?.uid !== id || !text(item.title)) return [];
      return [result(id, item.title, `https://pubmed.ncbi.nlm.nih.gov/${id}/`, item.pubdate,
        [text(item.fulljournalname, 200), text(item.source, 80)].filter(Boolean).join(' · '))];
    });
    return { results, total: total(search.esearchresult.count) };
  }
  if (source === 'clinicaltrials') {
    const url = new URL('https://clinicaltrials.gov/api/v2/studies');
    url.search = new URLSearchParams({ 'query.term': query, pageSize: String(MAX_RESULTS), format: 'json',
      fields: 'NCTId,BriefTitle,OverallStatus,LastUpdatePostDate', countTotal: 'true' }).toString();
    const payload = await providerJson(url, fetchImpl, signal);
    if (!Array.isArray(payload?.studies)) throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502);
    const results = payload.studies.slice(0, MAX_RESULTS).flatMap(study => {
      const identification = study?.protocolSection?.identificationModule;
      const status = study?.protocolSection?.statusModule;
      const id = identification?.nctId;
      if (typeof id !== 'string' || !/^NCT[0-9]{8}$/.test(id) || !text(identification?.briefTitle)) return [];
      return [result(id, identification.briefTitle, `https://clinicaltrials.gov/study/${id}`,
        status?.lastUpdatePostDateStruct?.date, text(status?.overallStatus, 80).replaceAll('_', ' '))];
    });
    return { results, total: total(payload.totalCount) };
  }
  const url = new URL('https://dailymed.nlm.nih.gov/dailymed/services/v2/spls.json');
  url.search = new URLSearchParams({ drug_name: query, pagesize: String(MAX_RESULTS), page: '1' }).toString();
  const payload = await providerJson(url, fetchImpl, signal);
  if (!Array.isArray(payload?.data)) throw failure('EVIDENCE_SOURCE_UNAVAILABLE', 502);
  const results = payload.data.slice(0, MAX_RESULTS).flatMap(item => {
    const id = typeof item?.setid === 'string' ? item.setid.toLowerCase() : '';
    if (!UUID.test(id) || !text(item.title)) return [];
    return [result(id, item.title, `https://dailymed.nlm.nih.gov/dailymed/drugInfo.cfm?setid=${id}`,
      item.published_date, 'U.S. submitted drug labeling; check the full label and local authorization.')];
  });
  return { results, total: total(payload.metadata?.total_elements) };
}

export async function handleEvidenceSearch(request, context, { getEnv, fetchImpl = fetch } = {}) {
  if (request.method !== 'POST') return json({ ok: false, code: 'METHOD_NOT_ALLOWED' }, 405);
  if (request.headers.get('origin') !== new URL(request.url).origin) {
    return json({ ok: false, code: 'EVIDENCE_ORIGIN_DENIED' }, 403);
  }
  try {
    const config = evidenceConfiguration(getEnv);
    try { assertOwnerRuntime(request, context, config.expectedSiteId, config.expectedSiteOrigin); }
    catch { throw failure('EVIDENCE_RUNTIME_DENIED', 503); }
    const authorization = request.headers.get('authorization') || '';
    const token = /^Bearer ([A-Za-z0-9_.-]{32,8192})$/i.exec(authorization)?.[1];
    if (!token) throw failure('EVIDENCE_SESSION_REQUIRED', 401);
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type') || '')) {
      throw failure('EVIDENCE_CONTENT_TYPE_REQUIRED', 415);
    }
    const input = normalizeEvidenceQuery(await readBoundedJson(request, 2048, 'EVIDENCE_INPUT_INVALID', 400));
    const claims = tokenClaims(token);
    if (claims.role !== 'authenticated' || !UUID.test(claims.sub)
      || claims.iss !== `${config.supabaseUrl}/auth/v1`
      || !Number.isFinite(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) {
      throw failure('EVIDENCE_SESSION_REQUIRED', 401);
    }
    const signal = AbortSignal.timeout(15_000);
    const user = await databaseRequest(config, token, '/auth/v1/user', fetchImpl, signal);
    if (!UUID.test(user?.id) || user.id !== claims.sub) throw failure('EVIDENCE_SESSION_REQUIRED', 401);
    validateAccess(await databaseRequest(config, token, '/rest/v1/rpc/current_access_context', fetchImpl, signal), config);
    if (input.source === 'pubmed' && !config.pubmedEnabled) throw failure('EVIDENCE_PUBMED_DISABLED', 503);
    const evidence = await searchEvidence(input, { fetchImpl, signal });
    // Recheck after the external request so an OFF or role revocation while
    // the provider is responding does not release results under stale access.
    validateAccess(await databaseRequest(config, token, '/rest/v1/rpc/current_access_context', fetchImpl, signal), config);
    return json({ ok: true, source: input.source, retrievedAt: new Date().toISOString(), ...evidence });
  } catch (error) {
    // Never emit tokens, input queries, raw upstream bodies or patient data to logs.
    return json({ ok: false, code: error.publicCode || 'EVIDENCE_REQUEST_FAILED' }, error.status || 500);
  }
}
