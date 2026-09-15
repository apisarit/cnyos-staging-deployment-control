import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  GITHUB_LOGIN,
  POLICY,
  POLICY_SHA256,
  assertControllerRuntime,
  assertExactKeys,
  assertPolicyTarget,
  canonicalIsoTimestamp,
  exactSha256,
  fail,
  isPlainObject,
  parseJsonObject,
  readFileBounded,
  required,
  sha256,
  writeJsonExclusive
} from './policy.mjs';

export const LIVE_GITHUB_RELEASE_PHASES = Object.freeze([
  'before_netlify_credential',
  'before_promotion'
]);

export const LIVE_GITHUB_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON',
  'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64',
  'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN',
  'CNYOS_STAGING_DATABASE_PASSWORD',
  'CNYOS_STAGING_DATABASE_URL',
  'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD',
  'CNYOS_SUPABASE_ACCESS_TOKEN',
  'DATABASE_URL',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'NETLIFY_AUTH_TOKEN',
  'PGPASSWORD',
  'POSTGRES_PASSWORD',
  'SUPABASE_ACCESS_TOKEN',
  'SUPABASE_SERVICE_ROLE_KEY'
]);

const AUTHORIZATION_BOUNDARY_KEYS = Object.freeze([
  'repository', 'pr36', 'promotion', 'independentReviewerGitHubLogin'
]);
const AUTHORIZATION_SOURCE_KEYS = Object.freeze([
  'repository', 'commit', 'tree', 'functionSourceTree'
]);
const AUTHORIZATION_ARTIFACT_KEYS = Object.freeze([
  'producerManifestSha256', 'artifactSha256', 'fileCount',
  'candidateBuildArtifactDigest', 'staticReproducibilityEvidenceSha256',
  'staticArtifactSha256', 'candidateDependencyLockSha256', 'stagingConfigSha256',
  'productionDenylistConfigSha256', 'functionBundleManifestSha256',
  'functionBundleDependencyLockSha256', 'functionSourcesSha256', 'producerRunId',
  'githubArtifactDigest'
]);
const AUTHORIZATION_PR_KEYS = Object.freeze([
  'number', 'url', 'headRef', 'headCommit', 'baseRef', 'baseCommit', 'requiredState'
]);
const AUTHORIZATION_PROMOTION_KEYS = Object.freeze([
  ...AUTHORIZATION_PR_KEYS,
  'headTree',
  'orderedMigrationEvidenceSha256'
].sort());
const OBSERVED_PR_KEYS = Object.freeze([
  'repository', 'number', 'url', 'state', 'draft', 'merged', 'headRef', 'headCommit',
  'baseRef', 'baseCommit', 'authorGitHubLogin', 'reviewInventoryComplete',
  'reviewCount', 'reviewsSha256', 'pullRequestSha256', 'currentHeadApprovalCount'
]);
const OBSERVED_PROMOTION_KEYS = Object.freeze([
  ...OBSERVED_PR_KEYS,
  'headTree',
  'independentReviewerGitHubLogin',
  'independentApprovalReviewId',
  'independentApprovalSubmittedAt',
  'orderedMigrationEvidenceSha256'
].sort());
const EVIDENCE_KEYS = Object.freeze([
  'schemaVersion', 'evidenceType', 'status', 'authorization', 'scope',
  'productionAuthorization', 'realPatientDataAuthorized', 'checkedAt', 'phase',
  'controllerRepository', 'controllerRef', 'controllerCommit', 'controllerWorkflowPath',
  'controllerRunId', 'controllerRunAttempt', 'dispatchNonce', 'policySha256', 'source',
  'artifact', 'target', 'authorizationEvidenceSha256', 'priorBoundaryEvidenceSha256',
  'githubApiOrigin', 'githubHttpMethods', 'githubMutationAttempted',
  'githubReadCredentialSerialized', 'forbiddenCredentialEnvironmentAbsent',
  'redirectsFollowed', 'paginationComplete', 'githubRequestCount', 'pr36', 'promotion'
]);

function sameLogin(left, right) {
  return typeof left === 'string' && typeof right === 'string' &&
    GITHUB_LOGIN.test(left) && GITHUB_LOGIN.test(right) &&
    left.toLowerCase() === right.toLowerCase();
}

function releasePolicy() {
  const value = POLICY.githubReleaseBoundary;
  if (!isPlainObject(value) || value.apiOrigin !== 'https://api.github.com' ||
    value.webOrigin !== 'https://github.com' || value.sourceRepository !== POLICY.sourceRepository ||
    value.pr36Number !== 36 || !Number.isSafeInteger(value.maximumEvidenceAgeMinutes) ||
    value.maximumEvidenceAgeMinutes < 1 || value.maximumEvidenceAgeMinutes > 10 ||
    !Number.isSafeInteger(value.maximumResponseBytes) || value.maximumResponseBytes < 1024 ||
    value.maximumResponseBytes > 4 * 1024 * 1024 ||
    !Number.isSafeInteger(value.reviewsPerPage) || value.reviewsPerPage !== 100 ||
    !Number.isSafeInteger(value.maximumReviewPages) || value.maximumReviewPages < 1 ||
    value.maximumReviewPages > 20) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_POLICY_INVALID');
  }
  return value;
}

function assertCredentialIsolation(env) {
  for (const name of LIVE_GITHUB_FORBIDDEN_ENVIRONMENT_NAMES) {
    if (Object.hasOwn(env, name)) fail('CNYOS_CONTROLLER_GITHUB_RELEASE_CREDENTIAL_ISOLATION_INVALID');
  }
}

function strictGitHubToken(value) {
  const token = required(value, 'CNYOS_CONTROLLER_GITHUB_READ_TOKEN_REQUIRED', 4096);
  if (value !== token || token.length < 20 || /[\s\0]/.test(token)) {
    fail('CNYOS_CONTROLLER_GITHUB_READ_TOKEN_INVALID');
  }
  return token;
}

function exactBranch(value, code) {
  const branch = required(value, code, 200);
  if (value !== branch || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(branch) ||
    branch.endsWith('/') || branch.includes('..') || branch.includes('//') ||
    branch.includes('@{') || branch.split('/').some(part => !part || part === '.' ||
      part.endsWith('.lock'))) fail(code);
  return branch;
}

function exactSha40(value, code) {
  const sha = required(value, code, 40).toLowerCase();
  if (value !== sha || !/^[0-9a-f]{40}$/.test(sha)) fail(code);
  return sha;
}

async function loadAuthorization(env, runtime, now) {
  const bytes = await readFileBounded(
    required(env.CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_PATH_REQUIRED', 4096),
    4 * 1024 * 1024,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID'
  );
  const digest = sha256(bytes);
  if (digest !== exactSha256(env.CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_DIGEST_REQUIRED')) {
    fail('CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_DIGEST_MISMATCH');
  }
  const value = parseJsonObject(bytes.toString('utf8'),
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  const boundary = value.githubReleaseBoundary;
  assertExactKeys(boundary, AUTHORIZATION_BOUNDARY_KEYS,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  assertExactKeys(boundary?.pr36, AUTHORIZATION_PR_KEYS,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  assertExactKeys(boundary?.promotion, AUTHORIZATION_PROMOTION_KEYS,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  assertExactKeys(value.source, AUTHORIZATION_SOURCE_KEYS,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  assertExactKeys(value.artifact, AUTHORIZATION_ARTIFACT_KEYS,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  assertExactKeys(value.target, Object.keys(POLICY.target),
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  assertPolicyTarget(value.target, 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  const policy = releasePolicy();
  const expectedPr36Url = `${policy.webOrigin}/${policy.sourceRepository}/pull/${policy.pr36Number}`;
  const expectedPromotionUrl = `${policy.webOrigin}/${policy.sourceRepository}/pull/${boundary.promotion.number}`;
  const expiresAt = canonicalIsoTimestamp(value.authorizationExpiresAt,
    'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  if (value.evidenceType !== 'cnyos_staging_controller_authorization_validation' ||
    value.status !== 'authorized' || value.scope !== 'cnyos_staging_only' ||
    value.productionAuthorization !== false || value.realPatientDataAuthorized !== false ||
    value.controllerRepository !== runtime.repository || value.controllerRef !== runtime.ref ||
    value.controllerCommit !== runtime.commit || value.controllerWorkflowPath !== runtime.workflowPath ||
    value.controllerRunId !== runtime.runId || value.controllerRunAttempt !== 1 ||
    value.policySha256 !== POLICY_SHA256 || expiresAt <= now ||
    value.source?.repository !== POLICY.sourceRepository ||
    !/^[0-9a-f]{40}$/.test(String(value.source?.commit || '')) ||
    !/^[0-9a-f]{40}$/.test(String(value.source?.tree || '')) ||
    !/^[0-9a-f]{64}$/.test(String(value.artifact?.artifactSha256 || '')) ||
    boundary.repository !== policy.sourceRepository || boundary.pr36.number !== policy.pr36Number ||
    boundary.pr36.url !== expectedPr36Url || boundary.pr36.requiredState !== 'open_draft_unapproved' ||
    boundary.promotion.number === policy.pr36Number ||
    !Number.isSafeInteger(boundary.promotion.number) || boundary.promotion.number < 1 ||
    boundary.promotion.url !== expectedPromotionUrl ||
    boundary.promotion.requiredState !== 'open_ready_for_independent_review' ||
    boundary.promotion.headCommit !== value.source.commit ||
    boundary.promotion.headTree !== value.source.tree ||
    !/^[0-9a-f]{64}$/.test(String(boundary.promotion.orderedMigrationEvidenceSha256 || '')) ||
    !GITHUB_LOGIN.test(String(boundary.independentReviewerGitHubLogin || '')) ||
    sameLogin(boundary.independentReviewerGitHubLogin, runtime.actor)) {
    fail('CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  }
  for (const item of [boundary.pr36, boundary.promotion]) {
    exactBranch(item.headRef, 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
    exactBranch(item.baseRef, 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
    exactSha40(item.headCommit, 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
    exactSha40(item.baseCommit, 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  }
  if (boundary.pr36.headRef === 'main' || boundary.promotion.headRef === 'main') {
    fail('CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID');
  }
  return Object.freeze({ value, sha256: digest, boundary });
}

function header(response, name) {
  try { return String(response?.headers?.get?.(name) || '').trim(); }
  catch { fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID'); }
}

async function boundedResponseBytes(response, maximumBytes) {
  const reader = response?.body?.getReader?.();
  if (!reader) fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (!isPlainObject(item) || typeof item.done !== 'boolean' ||
        (!item.done && !(item.value instanceof Uint8Array))) {
        fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
      }
      if (item.done) break;
      length += item.value.byteLength;
      if (length > maximumBytes) {
        try { await reader.cancel(); } catch {}
        fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
      }
      chunks.push(Buffer.from(item.value));
    }
  } catch (error) {
    if (String(error?.message || '').startsWith('CNYOS_CONTROLLER_')) throw error;
    fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
  }
  if (length < 2) fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
  return Buffer.concat(chunks, length);
}

async function githubJson(fetchImpl, token, pathname, { list = false } = {}) {
  const policy = releasePolicy();
  const url = new URL(pathname, `${policy.apiOrigin}/`);
  if (url.origin !== policy.apiOrigin || url.username || url.password || url.port || url.hash) {
    fail('CNYOS_CONTROLLER_GITHUB_REQUEST_TARGET_INVALID');
  }
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'cnyos-staging-protected-controller',
        'X-GitHub-Api-Version': '2022-11-28'
      },
      signal: AbortSignal.timeout(20_000)
    });
  } catch {
    fail('CNYOS_CONTROLLER_GITHUB_REQUEST_FAILED');
  }
  const responseUrl = String(response?.url || '');
  const remaining = header(response, 'x-ratelimit-remaining');
  const retryAfter = header(response, 'retry-after');
  const contentType = header(response, 'content-type').toLowerCase();
  const contentLength = header(response, 'content-length');
  if (response?.status !== 200 || response?.redirected === true ||
    (responseUrl && responseUrl !== url.href) || retryAfter ||
    !/^\d+$/.test(remaining) || Number(remaining) < 1 ||
    !/^application\/(?:json|vnd\.github\+json)(?:\s*;|$)/.test(contentType) ||
    (contentLength && (!/^\d+$/.test(contentLength) ||
      Number(contentLength) > policy.maximumResponseBytes))) {
    fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
  }
  const bytes = await boundedResponseBytes(response, policy.maximumResponseBytes);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID'); }
  if ((list && (!Array.isArray(value) || value.length > policy.reviewsPerPage)) ||
    (!list && !isPlainObject(value))) fail('CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID');
  return Object.freeze({
    value,
    sha256: sha256(bytes),
    link: header(response, 'link'),
    nextPage: header(response, 'x-next-page'),
    pageCount: header(response, 'x-page-count') || header(response, 'x-total-pages')
  });
}

function linkPagination(link, expectedUrl, currentPage) {
  if (!link) return Object.freeze({ next: null, last: null });
  let next = null;
  let last = null;
  const seenRelations = new Set();
  for (const rawPart of link.split(',')) {
    const match = rawPart.trim().match(/^<([^<>]+)>\s*;\s*rel="([A-Za-z ]+)"$/);
    if (!match) fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
    let linked;
    try { linked = new URL(match[1]); }
    catch { fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS'); }
    if (linked.origin !== expectedUrl.origin || linked.username || linked.password || linked.port ||
      linked.hash || linked.pathname !== expectedUrl.pathname ||
      linked.searchParams.get('per_page') !== String(releasePolicy().reviewsPerPage) ||
      [...linked.searchParams.keys()].some(key => !['per_page', 'page'].includes(key)) ||
      !/^\d+$/.test(linked.searchParams.get('page') || '')) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
    }
    const relations = match[2].split(/\s+/);
    const page = Number(linked.searchParams.get('page'));
    for (const relation of relations) {
      if (!['first', 'prev', 'next', 'last'].includes(relation) ||
        seenRelations.has(relation)) {
        fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
      }
      seenRelations.add(relation);
      if ((relation === 'first' && page !== 1) ||
        (relation === 'prev' && (currentPage <= 1 || page !== currentPage - 1)) ||
        (relation === 'next' && page !== currentPage + 1) ||
        (relation === 'last' && page < currentPage)) {
        fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
      }
      if (relation === 'next') next = page;
      if (relation === 'last') last = page;
    }
  }
  if ((last !== null && last > currentPage && next === null) ||
    (last !== null && next !== null && last < next) ||
    (next !== null && last === null)) {
    fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
  }
  return Object.freeze({ next, last });
}

async function githubReviewInventory(fetchImpl, token, repositoryPath, number) {
  const policy = releasePolicy();
  const reviews = [];
  const responseDigests = [];
  const seenIds = new Set();
  let page = 1;
  let requestCount = 0;
  let expectedTerminalPage = null;
  while (true) {
    if (page > policy.maximumReviewPages) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_INCOMPLETE');
    }
    const pathname = `/repos/${repositoryPath}/pulls/${number}/reviews?per_page=${policy.reviewsPerPage}&page=${page}`;
    const expectedUrl = new URL(pathname, `${policy.apiOrigin}/`);
    const response = await githubJson(fetchImpl, token, pathname, { list: true });
    requestCount += 1;
    responseDigests.push(response.sha256);
    const linkPaginationState = linkPagination(response.link, expectedUrl, page);
    const nextFromLink = linkPaginationState.next;
    if (response.nextPage && (!/^\d+$/.test(response.nextPage) ||
      Number(response.nextPage) !== (nextFromLink || 0))) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
    }
    const declaredPageCount = response.pageCount && /^\d+$/.test(response.pageCount)
      ? Number(response.pageCount)
      : null;
    if (response.pageCount && (declaredPageCount === null ||
      declaredPageCount < page || declaredPageCount > policy.maximumReviewPages ||
      (nextFromLink !== null && nextFromLink > declaredPageCount))) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
    }
    const declaredTerminalPages = [linkPaginationState.last, declaredPageCount]
      .filter(value => value !== null);
    if (new Set(declaredTerminalPages).size > 1 ||
      (expectedTerminalPage !== null && declaredTerminalPages.some(value =>
        value !== expectedTerminalPage))) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
    }
    if (expectedTerminalPage === null && declaredTerminalPages.length > 0) {
      expectedTerminalPage = declaredTerminalPages[0];
    }
    if (expectedTerminalPage !== null &&
      ((page < expectedTerminalPage && nextFromLink !== page + 1) ||
        (page === expectedTerminalPage && nextFromLink !== null) ||
        page > expectedTerminalPage)) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
    }
    for (const review of response.value) {
      if (!isPlainObject(review) || !Number.isSafeInteger(review.id) || seenIds.has(review.id)) {
        fail('CNYOS_CONTROLLER_GITHUB_REVIEWS_INVALID');
      }
      seenIds.add(review.id);
      reviews.push(review);
    }
    if (reviews.length > policy.reviewsPerPage * policy.maximumReviewPages) {
      fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_INCOMPLETE');
    }
    const fullPage = response.value.length === policy.reviewsPerPage;
    if (nextFromLink === null && !fullPage && expectedTerminalPage === null) break;
    if (expectedTerminalPage === page) {
      if (fullPage) fail('CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS');
      break;
    }
    page += 1;
  }
  return Object.freeze({
    reviews: Object.freeze(reviews),
    sha256: sha256(JSON.stringify(responseDigests)),
    requestCount
  });
}

function pullRequestView(value, expected, { promotion = false } = {}) {
  const code = 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID';
  if (!isPlainObject(value) || value.number !== expected.number || value.html_url !== expected.url ||
    value.state !== 'open' || value.merged !== false || value.merged_at !== null ||
    value.closed_at !== null ||
    value.draft !== !promotion || !isPlainObject(value.head) || !isPlainObject(value.base) ||
    !isPlainObject(value.head.repo) || !isPlainObject(value.base.repo) ||
    value.head.repo.full_name !== POLICY.sourceRepository ||
    value.base.repo.full_name !== POLICY.sourceRepository ||
    value.head.ref !== expected.headRef || value.head.sha !== expected.headCommit ||
    value.base.ref !== expected.baseRef || value.base.sha !== expected.baseCommit ||
    !isPlainObject(value.user) || !GITHUB_LOGIN.test(String(value.user.login || ''))) fail(code);
  return Object.freeze({
    repository: POLICY.sourceRepository,
    number: value.number,
    url: value.html_url,
    state: value.state,
    draft: value.draft,
    merged: value.merged,
    headRef: value.head.ref,
    headCommit: value.head.sha,
    baseRef: value.base.ref,
    baseCommit: value.base.sha,
    authorGitHubLogin: value.user.login
  });
}

function reviewsView(value, headCommit) {
  const reviews = [];
  for (const item of value) {
    if (!isPlainObject(item) || !Number.isSafeInteger(item.id) || item.id < 1 ||
      !['APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED', 'PENDING'].includes(item.state) ||
      !isPlainObject(item.user) || !GITHUB_LOGIN.test(String(item.user.login || '')) ||
      (item.commit_id !== null && !/^[0-9a-f]{40}$/.test(String(item.commit_id || ''))) ||
      ((item.state === 'PENDING' && item.submitted_at !== null) ||
        (item.state !== 'PENDING' && (typeof item.submitted_at !== 'string' ||
          Number.isNaN(Date.parse(item.submitted_at))))) ) {
      fail('CNYOS_CONTROLLER_GITHUB_REVIEWS_INVALID');
    }
    reviews.push(Object.freeze({
      id: item.id,
      state: item.state,
      githubLogin: item.user.login,
      commit: item.commit_id,
      submittedAt: item.submitted_at === null ? null : new Date(item.submitted_at).toISOString()
    }));
  }
  const latestDecisive = new Map();
  for (const review of reviews) {
    if (!['APPROVED', 'CHANGES_REQUESTED'].includes(review.state)) continue;
    const key = review.githubLogin.toLowerCase();
    const previous = latestDecisive.get(key);
    if (!previous || review.submittedAt > previous.submittedAt ||
      (review.submittedAt === previous.submittedAt && review.id > previous.id)) {
      latestDecisive.set(key, review);
    }
  }
  const active = [...latestDecisive.values()];
  return Object.freeze({
    reviews: Object.freeze(reviews),
    activeDecisive: Object.freeze(active),
    currentApprovals: Object.freeze(active.filter(item =>
      item.state === 'APPROVED' && item.commit === headCommit)),
    currentChangeRequests: Object.freeze(active.filter(item =>
      item.state === 'CHANGES_REQUESTED'))
  });
}

function validateObservedPr(value, expected, { promotion = false } = {}) {
  assertExactKeys(value, promotion ? OBSERVED_PROMOTION_KEYS : OBSERVED_PR_KEYS,
    'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  const commonInvalid = value.repository !== POLICY.sourceRepository || value.number !== expected.number ||
    value.url !== expected.url || value.state !== 'open' || value.draft !== !promotion ||
    value.merged !== false || value.headRef !== expected.headRef ||
    value.headCommit !== expected.headCommit || value.baseRef !== expected.baseRef ||
    value.baseCommit !== expected.baseCommit || !GITHUB_LOGIN.test(String(value.authorGitHubLogin || '')) ||
    value.reviewInventoryComplete !== true || !Number.isSafeInteger(value.currentHeadApprovalCount) ||
    value.currentHeadApprovalCount < 0 || !Number.isSafeInteger(value.reviewCount) ||
    value.reviewCount < 0 || !/^[0-9a-f]{64}$/.test(String(value.reviewsSha256 || '')) ||
    !/^[0-9a-f]{64}$/.test(String(value.pullRequestSha256 || ''));
  if (commonInvalid) fail('CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  if (!promotion && value.currentHeadApprovalCount !== 0) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  }
}

export function validateLiveGitHubReleaseBoundaryEvidence(value, {
  runtime,
  authorization,
  authorizationSha256,
  expectedPhase,
  priorBoundarySha256 = null,
  now,
  allowHistorical = false
}) {
  assertExactKeys(value, EVIDENCE_KEYS, 'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  if (!(now instanceof Date) || Number.isNaN(now.getTime()) ||
    !LIVE_GITHUB_RELEASE_PHASES.includes(expectedPhase)) fail('CNYOS_CONTROLLER_TIME_INVALID');
  const checkedAt = canonicalIsoTimestamp(value.checkedAt,
    'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  const maximumAge = releasePolicy().maximumEvidenceAgeMinutes * 60 * 1000;
  if (checkedAt > now || (!allowHistorical &&
      now.getTime() - checkedAt.getTime() > maximumAge) ||
    value.schemaVersion !== 1 ||
    value.evidenceType !== 'cnyos_staging_controller_live_github_release_boundary' ||
    value.status !== 'passed' || value.authorization !== false ||
    value.scope !== 'cnyos_staging_only' || value.productionAuthorization !== false ||
    value.realPatientDataAuthorized !== false || value.phase !== expectedPhase ||
    value.controllerRepository !== runtime.repository || value.controllerRef !== runtime.ref ||
    value.controllerCommit !== runtime.commit || value.controllerWorkflowPath !== runtime.workflowPath ||
    value.controllerRunId !== runtime.runId || value.controllerRunAttempt !== 1 ||
    value.dispatchNonce !== authorization.value.dispatchNonce || value.policySha256 !== POLICY_SHA256 ||
    value.source?.repository !== authorization.value.source?.repository ||
    value.source?.commit !== authorization.value.source?.commit ||
    value.source?.tree !== authorization.value.source?.tree ||
    value.artifact?.artifactSha256 !== authorization.value.artifact?.artifactSha256 ||
    value.target?.netlifySiteId !== POLICY.target.netlifySiteId ||
    value.authorizationEvidenceSha256 !== authorizationSha256 ||
    value.priorBoundaryEvidenceSha256 !== priorBoundarySha256 ||
    value.githubApiOrigin !== releasePolicy().apiOrigin ||
    JSON.stringify(value.githubHttpMethods) !== '["GET"]' ||
    value.githubMutationAttempted !== false || value.githubReadCredentialSerialized !== false ||
    value.forbiddenCredentialEnvironmentAbsent !== true || value.redirectsFollowed !== false ||
    value.paginationComplete !== true || !Number.isSafeInteger(value.githubRequestCount) ||
    value.githubRequestCount < 7 ||
    value.githubRequestCount > 5 + 2 * releasePolicy().maximumReviewPages) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  }
  validateObservedPr(value.pr36, authorization.boundary.pr36);
  validateObservedPr(value.promotion, authorization.boundary.promotion, { promotion: true });
  if (value.promotion.headTree !== authorization.boundary.promotion.headTree ||
    !sameLogin(value.promotion.independentReviewerGitHubLogin,
      authorization.boundary.independentReviewerGitHubLogin) ||
    !Number.isSafeInteger(value.promotion.independentApprovalReviewId) ||
    value.promotion.independentApprovalReviewId < 1 ||
    Number.isNaN(Date.parse(value.promotion.independentApprovalSubmittedAt)) ||
    value.promotion.orderedMigrationEvidenceSha256 !==
      authorization.boundary.promotion.orderedMigrationEvidenceSha256 ||
    value.promotion.currentHeadApprovalCount < 1) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  }
  return Object.freeze({ checkedAt });
}

async function loadPriorBoundary(env, runtime, authorization, now) {
  const bytes = await readFileBounded(
    required(env.CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_PATH_REQUIRED', 4096),
    4 * 1024 * 1024,
    'CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_INVALID'
  );
  const digest = sha256(bytes);
  if (digest !== exactSha256(env.CNYOS_EXPECTED_PRIOR_GITHUB_RELEASE_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_DIGEST_REQUIRED')) {
    fail('CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_DIGEST_MISMATCH');
  }
  const value = parseJsonObject(bytes.toString('utf8'),
    'CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_INVALID');
  validateLiveGitHubReleaseBoundaryEvidence(value, {
    runtime,
    authorization,
    authorizationSha256: authorization.sha256,
    expectedPhase: 'before_netlify_credential',
    priorBoundarySha256: null,
    now,
    allowHistorical: true
  });
  return Object.freeze({
    value,
    sha256: digest,
    checkedAt: canonicalIsoTimestamp(
      value.checkedAt,
      'CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_INVALID'
    )
  });
}

async function validateStoredLiveGitHubReleaseBoundaryMode({
  env = process.env,
  runtime = assertControllerRuntime(env),
  now = () => new Date(),
  allowHistorical
} = {}) {
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_TIME_INVALID');
  }
  if (typeof allowHistorical !== 'boolean') {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  }
  const authorization = await loadAuthorization(env, runtime, observedAt);
  const phase = required(env.CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE,
    'CNYOS_CONTROLLER_GITHUB_RELEASE_PHASE_REQUIRED', 50);
  if (!LIVE_GITHUB_RELEASE_PHASES.includes(phase)) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_PHASE_INVALID');
  }
  if (allowHistorical && phase !== 'before_netlify_credential') {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_PHASE_INVALID');
  }
  const prior = phase === 'before_promotion'
    ? await loadPriorBoundary(env, runtime, authorization, observedAt)
    : null;
  if (prior && prior.checkedAt >= observedAt) {
    fail('CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_INVALID');
  }
  const bytes = await readFileBounded(
    required(env.CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH_REQUIRED', 4096),
    4 * 1024 * 1024,
    'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID'
  );
  const digest = sha256(bytes);
  if (digest !== exactSha256(env.CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256,
    'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_DIGEST_REQUIRED')) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_DIGEST_MISMATCH');
  }
  const value = parseJsonObject(bytes.toString('utf8'),
    'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID');
  validateLiveGitHubReleaseBoundaryEvidence(value, {
    runtime,
    authorization,
    authorizationSha256: authorization.sha256,
    expectedPhase: phase,
    priorBoundarySha256: prior?.sha256 || null,
    now: observedAt,
    allowHistorical
  });
  return Object.freeze({ evidence: value, evidencePath:
    path.resolve(env.CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH), sha256: digest });
}

export async function validateStoredLiveGitHubReleaseBoundary(options = {}) {
  return validateStoredLiveGitHubReleaseBoundaryMode({
    ...options,
    allowHistorical: false
  });
}

export async function validateStoredHistoricalPrecredentialGitHubReleaseBoundary(options = {}) {
  return validateStoredLiveGitHubReleaseBoundaryMode({
    ...options,
    allowHistorical: true
  });
}

export async function verifyLiveGitHubReleaseBoundary({
  env = process.env,
  fetchImpl = fetch,
  now = () => new Date()
} = {}) {
  const runtime = assertControllerRuntime(env);
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) {
    fail('CNYOS_CONTROLLER_TIME_INVALID');
  }
  if (typeof fetchImpl !== 'function') fail('CNYOS_CONTROLLER_GITHUB_FETCH_INVALID');
  assertCredentialIsolation(env);
  const authorization = await loadAuthorization(env, runtime, observedAt);
  const phase = required(env.CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE,
    'CNYOS_CONTROLLER_GITHUB_RELEASE_PHASE_REQUIRED', 50);
  if (!LIVE_GITHUB_RELEASE_PHASES.includes(phase)) {
    fail('CNYOS_CONTROLLER_GITHUB_RELEASE_PHASE_INVALID');
  }
  const prior = phase === 'before_promotion'
    ? await loadPriorBoundary(env, runtime, authorization, observedAt)
    : null;
  if (prior && prior.checkedAt >= observedAt) {
    fail('CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_INVALID');
  }
  const token = strictGitHubToken(env.CNYOS_GITHUB_ACTIONS_READ_TOKEN);
  const repositoryPath = authorization.boundary.repository.split('/').map(encodeURIComponent).join('/');
  const pr36Number = authorization.boundary.pr36.number;
  const promotionNumber = authorization.boundary.promotion.number;
  const pr36FirstRaw = await githubJson(
    fetchImpl, token, `/repos/${repositoryPath}/pulls/${pr36Number}`);
  pullRequestView(pr36FirstRaw.value, authorization.boundary.pr36);
  const pr36Inventory = await githubReviewInventory(
    fetchImpl, token, repositoryPath, pr36Number);
  const pr36FinalRaw = await githubJson(
    fetchImpl, token, `/repos/${repositoryPath}/pulls/${pr36Number}`);
  const pr36 = pullRequestView(pr36FinalRaw.value, authorization.boundary.pr36);

  const promotionFirstRaw = await githubJson(
    fetchImpl, token, `/repos/${repositoryPath}/pulls/${promotionNumber}`);
  pullRequestView(promotionFirstRaw.value, authorization.boundary.promotion,
    { promotion: true });
  const promotionInventory = await githubReviewInventory(
    fetchImpl, token, repositoryPath, promotionNumber);
  const promotionFinalRaw = await githubJson(
    fetchImpl, token, `/repos/${repositoryPath}/pulls/${promotionNumber}`);
  const promotion = pullRequestView(promotionFinalRaw.value, authorization.boundary.promotion,
    { promotion: true });
  const promotionCommitRaw = await githubJson(fetchImpl, token,
    `/repos/${repositoryPath}/git/commits/${authorization.boundary.promotion.headCommit}`);

  const pr36Reviews = reviewsView(pr36Inventory.reviews, pr36.headCommit);
  const promotionReviews = reviewsView(promotionInventory.reviews, promotion.headCommit);
  if (pr36Reviews.activeDecisive.some(item => item.state === 'APPROVED')) {
    fail('CNYOS_CONTROLLER_PR36_CURRENT_APPROVAL_PRESENT');
  }
  if (!isPlainObject(promotionCommitRaw.value) ||
    promotionCommitRaw.value.sha !== promotion.headCommit ||
    !isPlainObject(promotionCommitRaw.value.tree) ||
    promotionCommitRaw.value.tree.sha !== authorization.boundary.promotion.headTree) {
    fail('CNYOS_CONTROLLER_PROMOTION_HEAD_TREE_MISMATCH');
  }
  const independentApprovals = promotionReviews.currentApprovals.filter(item =>
    sameLogin(item.githubLogin, authorization.boundary.independentReviewerGitHubLogin));
  if (independentApprovals.length < 1 || promotionReviews.currentChangeRequests.length !== 0 ||
    sameLogin(promotion.authorGitHubLogin, authorization.boundary.independentReviewerGitHubLogin)) {
    fail('CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID');
  }
  const approval = independentApprovals.toSorted((left, right) =>
    right.submittedAt.localeCompare(left.submittedAt) || right.id - left.id)[0];
  const githubRequestCount = 5 + pr36Inventory.requestCount + promotionInventory.requestCount;
  const evidence = Object.freeze({
    schemaVersion: 1,
    evidenceType: 'cnyos_staging_controller_live_github_release_boundary',
    status: 'passed',
    authorization: false,
    scope: 'cnyos_staging_only',
    productionAuthorization: false,
    realPatientDataAuthorized: false,
    checkedAt: observedAt.toISOString(),
    phase,
    controllerRepository: runtime.repository,
    controllerRef: runtime.ref,
    controllerCommit: runtime.commit,
    controllerWorkflowPath: runtime.workflowPath,
    controllerRunId: runtime.runId,
    controllerRunAttempt: 1,
    dispatchNonce: authorization.value.dispatchNonce,
    policySha256: POLICY_SHA256,
    source: authorization.value.source,
    artifact: authorization.value.artifact,
    target: POLICY.target,
    authorizationEvidenceSha256: authorization.sha256,
    priorBoundaryEvidenceSha256: prior?.sha256 || null,
    githubApiOrigin: releasePolicy().apiOrigin,
    githubHttpMethods: Object.freeze(['GET']),
    githubMutationAttempted: false,
    githubReadCredentialSerialized: false,
    forbiddenCredentialEnvironmentAbsent: true,
    redirectsFollowed: false,
    paginationComplete: true,
    githubRequestCount,
    pr36: Object.freeze({
      ...pr36,
      reviewInventoryComplete: true,
      reviewCount: pr36Reviews.reviews.length,
      reviewsSha256: pr36Inventory.sha256,
      pullRequestSha256: sha256(JSON.stringify([
        pr36FirstRaw.sha256, pr36FinalRaw.sha256
      ])),
      currentHeadApprovalCount: 0
    }),
    promotion: Object.freeze({
      ...promotion,
      reviewInventoryComplete: true,
      reviewCount: promotionReviews.reviews.length,
      reviewsSha256: promotionInventory.sha256,
      pullRequestSha256: sha256(JSON.stringify([
        promotionFirstRaw.sha256, promotionFinalRaw.sha256
      ])),
      currentHeadApprovalCount: promotionReviews.currentApprovals.length,
      headTree: promotionCommitRaw.value.tree.sha,
      independentReviewerGitHubLogin: authorization.boundary.independentReviewerGitHubLogin,
      independentApprovalReviewId: approval.id,
      independentApprovalSubmittedAt: approval.submittedAt,
      orderedMigrationEvidenceSha256:
        authorization.boundary.promotion.orderedMigrationEvidenceSha256
    })
  });
  const serialized = JSON.stringify(evidence);
  if (serialized.includes(token)) fail('CNYOS_CONTROLLER_GITHUB_READ_TOKEN_SERIALIZED');
  const evidencePath = await writeJsonExclusive(
    required(env.CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH,
      'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH_REQUIRED', 4096),
    evidence
  );
  return Object.freeze({ evidence, evidencePath });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const command = process.argv[2] || 'query';
  const action = command === 'query'
    ? verifyLiveGitHubReleaseBoundary
    : command === 'validate-evidence'
      ? validateStoredLiveGitHubReleaseBoundary
      : command === 'validate-historical-precredential-evidence'
        ? validateStoredHistoricalPrecredentialGitHubReleaseBoundary
      : null;
  if (!action) {
    process.stderr.write('Usage: node verify-live-github-release-boundary.mjs <query|validate-evidence|validate-historical-precredential-evidence>\n');
    process.exitCode = 1;
  } else {
    action().then(async result => {
      process.stdout.write(`${JSON.stringify({
        evidencePath: result.evidencePath,
        evidenceSha256: result.sha256 || sha256(await fs.readFile(result.evidencePath)),
        phase: result.evidence.phase
      })}\n`);
    }).catch(error => {
      process.stderr.write(`${String(error?.message || 'CNYOS_CONTROLLER_GITHUB_RELEASE_BOUNDARY_FAILED')}\n`);
      process.exitCode = 1;
    });
  }
}
