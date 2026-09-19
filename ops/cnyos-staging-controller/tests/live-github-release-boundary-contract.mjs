import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  POLICY,
  POLICY_SHA256,
  sha256
} from '../scripts/policy.mjs';
import {
  LIVE_GITHUB_FORBIDDEN_ENVIRONMENT_NAMES,
  validateStoredHistoricalPrecredentialGitHubReleaseBoundary,
  validateStoredLiveGitHubReleaseBoundary,
  verifyLiveGitHubReleaseBoundary
} from '../scripts/verify-live-github-release-boundary.mjs';

assert.notEqual(
  process.env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE,
  'true',
  'live GitHub release-boundary contract must remain credential-free'
);

const checkedAt = new Date('2030-01-01T00:00:00.000Z');
const promotionCheckedAt = new Date('2030-01-01T00:01:00.000Z');
const controllerCommit = '9'.repeat(40);
const sourceCommit = 'a'.repeat(40);
const sourceTree = 'b'.repeat(40);
const artifactSha256 = 'c'.repeat(64);
const pr36HeadCommit = 'd'.repeat(40);
const pr36BaseCommit = 'e'.repeat(40);
const promotionBaseCommit = 'f'.repeat(40);
const orderedMigrationEvidenceSha256 = '1'.repeat(64);
const staleReviewCommit = '2'.repeat(40);
const token = 'github_pat_offline_contract_token_never_networked';
const actor = 'apisarit';
const reviewer = 'Jaoball';
const promotionNumber = 99;
const repositoryPath = POLICY.sourceRepository.split('/').map(encodeURIComponent).join('/');
const pr36Path = `/repos/${repositoryPath}/pulls/36`;
const pr36ReviewsPath = `${pr36Path}/reviews?per_page=100&page=1`;
const promotionPath = `/repos/${repositoryPath}/pulls/${promotionNumber}`;
const promotionReviewsPath = `${promotionPath}/reviews?per_page=100&page=1`;
const promotionCommitPath = `/repos/${repositoryPath}/git/commits/${sourceCommit}`;

const runtimeEnvironment = Object.freeze({
  GITHUB_REPOSITORY: POLICY.controller.repository,
  CNYOS_CONTROLLER_EXPECTED_REPOSITORY: POLICY.controller.repository,
  GITHUB_RUN_ID: '730001',
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_REF_PROTECTED: 'true',
  CNYOS_CONTROLLER_PROTECTED_REF: POLICY.controller.protectedRef,
  GITHUB_REF: POLICY.controller.protectedRef,
  GITHUB_SHA: controllerCommit,
  CNYOS_CONTROLLER_WORKFLOW_PATH: POLICY.controller.releaseWorkflowPath,
  GITHUB_WORKFLOW_REF:
    `${POLICY.controller.repository}/${POLICY.controller.releaseWorkflowPath}@${POLICY.controller.protectedRef}`,
  GITHUB_ACTOR: actor,
  GITHUB_TRIGGERING_ACTOR: actor
});

const authorizationEvidence = Object.freeze({
  schemaVersion: 1,
  evidenceType: 'cnyos_staging_controller_authorization_validation',
  status: 'authorized',
  authorization: true,
  scope: 'cnyos_staging_only',
  productionAuthorization: false,
  realPatientDataAuthorized: false,
  authorizationExpiresAt: '2030-01-02T00:00:00.000Z',
  controllerRepository: POLICY.controller.repository,
  controllerRef: POLICY.controller.protectedRef,
  controllerCommit,
  controllerWorkflowPath: POLICY.controller.releaseWorkflowPath,
  controllerRunId: runtimeEnvironment.GITHUB_RUN_ID,
  controllerRunAttempt: 1,
  dispatchNonce: Buffer.alloc(32, 0x3a).toString('base64url'),
  policySha256: POLICY_SHA256,
  source: Object.freeze({
    repository: POLICY.sourceRepository,
    commit: sourceCommit,
    tree: sourceTree,
    functionSourceTree: '8'.repeat(40)
  }),
  artifact: Object.freeze({
    producerManifestSha256: '3'.repeat(64),
    artifactSha256,
    fileCount: 12,
    candidateBuildArtifactDigest: '4'.repeat(64),
    staticReproducibilityEvidenceSha256: '5'.repeat(64),
    staticArtifactSha256: '6'.repeat(64),
    candidateDependencyLockSha256: '7'.repeat(64),
    stagingConfigSha256: '8'.repeat(64),
    productionDenylistConfigSha256: '9'.repeat(64),
    functionBundleManifestSha256: 'a'.repeat(64),
    functionBundleDependencyLockSha256: 'b'.repeat(64),
    functionSourcesSha256: 'c'.repeat(64),
    producerRunId: runtimeEnvironment.GITHUB_RUN_ID,
    githubArtifactDigest: 'd'.repeat(64)
  }),
  target: Object.freeze(structuredClone(POLICY.target)),
  githubReleaseBoundary: Object.freeze({
    repository: POLICY.sourceRepository,
    pr36: Object.freeze({
      number: 36,
      url: `https://github.com/${POLICY.sourceRepository}/pull/36`,
      headRef: 'agent/p0-security-trigger-acl',
      headCommit: pr36HeadCommit,
      baseRef: 'main',
      baseCommit: pr36BaseCommit,
      requiredState: 'open_draft_unapproved'
    }),
    promotion: Object.freeze({
      number: promotionNumber,
      url: `https://github.com/${POLICY.sourceRepository}/pull/${promotionNumber}`,
      headRef: 'agent/ordered-migration-promotion',
      headCommit: sourceCommit,
      headTree: sourceTree,
      baseRef: 'main',
      baseCommit: promotionBaseCommit,
      requiredState: 'open_ready_for_independent_review',
      orderedMigrationEvidenceSha256
    }),
    independentReviewerGitHubLogin: reviewer
  })
});

const temporaryRoot = await fs.mkdtemp(
  path.join(os.tmpdir(), 'cnyos-live-github-release-boundary-contract-')
);
const authorizationPath = path.join(temporaryRoot, 'authorization.json');
let activeAuthorizationEvidence = authorizationEvidence;
let authorizationBytes = Buffer.from(JSON.stringify(activeAuthorizationEvidence));
await fs.writeFile(authorizationPath, authorizationBytes, { flag: 'wx', mode: 0o600 });
let authorizationSha256 = sha256(authorizationBytes);
let caseSequence = 0;
let globalFetchCalls = 0;
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => {
  globalFetchCalls += 1;
  throw new Error('CNYOS_TEST_FORBIDS_GLOBAL_NETWORK');
};

function pullRequestFixture(expected, { promotion = false } = {}) {
  return {
    number: expected.number,
    html_url: expected.url,
    state: 'open',
    merged: false,
    merged_at: null,
    closed_at: null,
    draft: !promotion,
    head: {
      repo: { full_name: POLICY.sourceRepository },
      ref: expected.headRef,
      sha: expected.headCommit
    },
    base: {
      repo: { full_name: POLICY.sourceRepository },
      ref: expected.baseRef,
      sha: expected.baseCommit
    },
    user: { login: actor }
  };
}

function responseFixtures() {
  const boundary = activeAuthorizationEvidence.githubReleaseBoundary;
  return new Map([
    [pr36Path, {
      body: pullRequestFixture(boundary.pr36)
    }],
    [pr36ReviewsPath, {
      body: []
    }],
    [promotionPath, {
      body: pullRequestFixture(boundary.promotion, { promotion: true })
    }],
    [promotionReviewsPath, {
      body: [{
        id: 7001,
        state: 'APPROVED',
        user: { login: reviewer },
        commit_id: sourceCommit,
        submitted_at: '2029-12-31T23:50:00.000Z'
      }]
    }],
    [promotionCommitPath, {
      body: {
        sha: sourceCommit,
        tree: { sha: sourceTree }
      }
    }]
  ]);
}

function responseFrom(specification) {
  const raw = Object.hasOwn(specification, 'raw')
    ? String(specification.raw)
    : JSON.stringify(specification.body);
  const bytes = Buffer.from(raw);
  const headers = new Map(Object.entries({
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(bytes.byteLength),
    'x-ratelimit-remaining': '4999',
    ...(specification.headers || {})
  }).map(([name, value]) => [name.toLowerCase(), String(value)]));
  return {
    status: specification.status ?? 200,
    redirected: specification.redirected ?? false,
    url: specification.url || '',
    headers: {
      get(name) {
        return headers.get(String(name).toLowerCase()) ?? null;
      }
    },
    body: {
      getReader() {
        let delivered = false;
        return {
          async read() {
            if (delivered) return { done: true, value: undefined };
            delivered = true;
            return { done: false, value: Uint8Array.from(bytes) };
          },
          async cancel() {}
        };
      }
    }
  };
}

function githubFetchFixture(responses) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    assert.ok(url instanceof URL);
    assert.equal(url.origin, POLICY.githubReleaseBoundary.apiOrigin);
    assert.equal(url.username, '');
    assert.equal(url.password, '');
    assert.equal(url.hash, '');
    assert.equal(options?.method, 'GET');
    assert.equal(options?.redirect, 'error');
    assert.equal(options?.headers?.Accept, 'application/vnd.github+json');
    assert.equal(options?.headers?.Authorization, `Bearer ${token}`);
    assert.equal(options?.headers?.['User-Agent'], 'cnyos-staging-protected-controller');
    assert.equal(options?.headers?.['X-GitHub-Api-Version'], '2022-11-28');
    assert.ok(options?.signal, 'each GitHub request must have a timeout signal');
    assert.equal(url.href.includes(token), false, 'GitHub token must not enter the request URL');
    const requestPath = `${url.pathname}${url.search}`;
    calls.push(Object.freeze({ method: options.method, requestPath }));
    const specification = responses.get(requestPath);
    if (!specification) throw new Error(`UNEXPECTED_OFFLINE_GITHUB_REQUEST:${requestPath}`);
    if (specification.throw) throw specification.throw;
    return responseFrom(specification);
  };
  return Object.freeze({ calls, fetchImpl });
}

function nextEvidencePath(label) {
  caseSequence += 1;
  return path.join(temporaryRoot, `${String(caseSequence).padStart(3, '0')}-${label}.json`);
}

function queryEnvironment(outputPath, phase = 'before_netlify_credential', prior = null) {
  return {
    ...runtimeEnvironment,
    CNYOS_CONTROLLER_AUTHORIZATION_EVIDENCE_PATH: authorizationPath,
    CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256: authorizationSha256,
    CNYOS_GITHUB_RELEASE_BOUNDARY_PHASE: phase,
    CNYOS_GITHUB_ACTIONS_READ_TOKEN: token,
    CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_PATH: outputPath,
    ...(prior ? {
      CNYOS_CONTROLLER_PRIOR_GITHUB_RELEASE_EVIDENCE_PATH: prior.path,
      CNYOS_EXPECTED_PRIOR_GITHUB_RELEASE_EVIDENCE_SHA256: prior.sha256
    } : {})
  };
}

async function assertFileAbsent(filename) {
  await assert.rejects(fs.lstat(filename), error => error?.code === 'ENOENT');
}

async function verifySuccess({
  phase,
  now,
  prior = null,
  mutateResponses = () => {},
  expectedPr36ApprovalCount = 0,
  expectedAdditionalPaths = []
}) {
  const outputPath = nextEvidencePath(`success-${phase}`);
  const responses = responseFixtures();
  mutateResponses(responses);
  const github = githubFetchFixture(responses);
  const env = queryEnvironment(outputPath, phase, prior);
  const result = await verifyLiveGitHubReleaseBoundary({
    env,
    fetchImpl: github.fetchImpl,
    now: () => new Date(now)
  });
  assert.equal(result.evidencePath, path.resolve(outputPath));
  assert.equal(result.evidence.phase, phase);
  assert.equal(result.evidence.pr36.state, 'open');
  assert.equal(result.evidence.pr36.draft, true);
  assert.equal(result.evidence.pr36.merged, false);
  assert.equal(result.evidence.pr36.currentHeadApprovalCount, expectedPr36ApprovalCount);
  assert.equal(result.evidence.promotion.state, 'open');
  assert.equal(result.evidence.promotion.draft, false);
  assert.equal(result.evidence.promotion.merged, false);
  assert.equal(result.evidence.promotion.headTree, sourceTree);
  assert.equal(result.evidence.promotion.independentReviewerGitHubLogin, reviewer);
  assert.equal(result.evidence.promotion.independentApprovalReviewId, 7001);
  assert.equal(result.evidence.priorBoundaryEvidenceSha256, prior?.sha256 || null);
  assert.equal(result.evidence.githubMutationAttempted, false);
  assert.deepEqual(result.evidence.githubHttpMethods, ['GET']);
  assert.equal(github.calls.length, 7 + expectedAdditionalPaths.length);
  assert.deepEqual(
    [...github.calls].map(call => call.requestPath).sort(),
    [
      pr36Path,
      pr36Path,
      pr36ReviewsPath,
      promotionPath,
      promotionPath,
      promotionReviewsPath,
      promotionCommitPath,
      ...expectedAdditionalPaths
    ].sort()
  );
  assert.ok(github.calls.every(call => call.method === 'GET'));

  const evidenceBytes = await fs.readFile(outputPath);
  assert.equal(evidenceBytes.includes(Buffer.from(token)), false);
  const evidenceSha256 = sha256(evidenceBytes);
  const stored = await validateStoredLiveGitHubReleaseBoundary({
    env: {
      ...env,
      CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256: evidenceSha256
    },
    now: () => new Date(now)
  });
  assert.equal(stored.sha256, evidenceSha256);
  assert.deepEqual(stored.evidence, result.evidence);
  return Object.freeze({ path: outputPath, sha256: evidenceSha256, evidence: result.evidence });
}

async function setPr36ReviewOnlyMode() {
  const next = structuredClone(authorizationEvidence);
  next.githubReleaseBoundary.pr36.requiredState = 'open_draft_review_only';
  delete next.migrationPromotion;
  activeAuthorizationEvidence = next;
  authorizationBytes = Buffer.from(JSON.stringify(activeAuthorizationEvidence));
  authorizationSha256 = sha256(authorizationBytes);
  await fs.writeFile(authorizationPath, authorizationBytes);
}

async function expectQueryFailure(label, {
  expected,
  mutateResponses = () => {},
  mutateEnvironment = () => {},
  phase = 'before_netlify_credential',
  prior = null,
  now = checkedAt
}) {
  const outputPath = nextEvidencePath(label);
  const responses = responseFixtures();
  mutateResponses(responses);
  const github = githubFetchFixture(responses);
  const env = queryEnvironment(outputPath, phase, prior);
  mutateEnvironment(env);
  await assert.rejects(
    verifyLiveGitHubReleaseBoundary({
      env,
      fetchImpl: github.fetchImpl,
      now: () => new Date(now)
    }),
    error => {
      assert.equal(error?.message, expected, `${label} must fail with the expected closed code`);
      return true;
    }
  );
  await assertFileAbsent(outputPath);
  return github;
}

let completed = false;
try {
  const initialBoundary = await verifySuccess({
    phase: 'before_netlify_credential',
    now: checkedAt
  });
  const delayedStoredAt = new Date(checkedAt.getTime() +
    (POLICY.githubReleaseBoundary.maximumEvidenceAgeMinutes * 60 * 1000) + 1);
  const delayedStoredEnvironment = {
    ...queryEnvironment(initialBoundary.path),
    CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256: initialBoundary.sha256
  };
  await assert.rejects(validateStoredLiveGitHubReleaseBoundary({
    env: delayedStoredEnvironment,
    now: () => delayedStoredAt
  }), /CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID/,
  'the first credential consumer must not accept stale live GitHub evidence');
  const historicalStoredBoundary = await validateStoredHistoricalPrecredentialGitHubReleaseBoundary({
    env: delayedStoredEnvironment,
    now: () => delayedStoredAt
  });
  assert.equal(historicalStoredBoundary.sha256, initialBoundary.sha256,
    'downstream hash-chain consumers may revalidate the exact first-credential proof historically');
  const promotionBoundary = await verifySuccess({
    phase: 'before_promotion',
    now: promotionCheckedAt,
    prior: initialBoundary
  });
  assert.equal(promotionBoundary.evidence.priorBoundaryEvidenceSha256, initialBoundary.sha256);
  await assert.rejects(validateStoredHistoricalPrecredentialGitHubReleaseBoundary({
    env: {
      ...queryEnvironment(promotionBoundary.path, 'before_promotion', initialBoundary),
      CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256: promotionBoundary.sha256
    },
    now: () => new Date(promotionCheckedAt.getTime() + 1)
  }), /CNYOS_CONTROLLER_GITHUB_RELEASE_PHASE_INVALID/,
  'historical mode must never accept a prepromotion mutation-gate record');
  const delayedPromotionBoundary = await verifySuccess({
    phase: 'before_promotion',
    now: new Date(checkedAt.getTime() +
      (POLICY.githubReleaseBoundary.maximumEvidenceAgeMinutes * 60 * 1000) + 1),
    prior: initialBoundary
  });
  assert.equal(
    delayedPromotionBoundary.evidence.priorBoundaryEvidenceSha256,
    initialBoundary.sha256,
    'historical precredential evidence remains valid through its hash-bound release chain'
  );
  const supersededApprovalBoundary = await verifySuccess({
    phase: 'before_netlify_credential',
    now: checkedAt,
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = [{
        id: 6001,
        state: 'APPROVED',
        user: { login: 'PriorReviewer' },
        commit_id: staleReviewCommit,
        submitted_at: '2029-12-31T23:40:00.000Z'
      }, {
        id: 6002,
        state: 'CHANGES_REQUESTED',
        user: { login: 'PriorReviewer' },
        commit_id: pr36HeadCommit,
        submitted_at: '2029-12-31T23:50:00.000Z'
      }];
    }
  });
  assert.equal(supersededApprovalBoundary.evidence.pr36.currentHeadApprovalCount, 0);

  await expectQueryFailure('closed-pr36', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      responses.get(pr36Path).body.state = 'closed';
    }
  });
  await expectQueryFailure('pr36-not-draft', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      responses.get(pr36Path).body.draft = false;
    }
  });
  await expectQueryFailure('promotion-is-draft', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      responses.get(promotionPath).body.draft = true;
    }
  });
  await expectQueryFailure('merged-pr36', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      responses.get(pr36Path).body.merged = true;
      responses.get(pr36Path).body.merged_at = '2030-01-01T00:00:00.000Z';
    }
  });
  await expectQueryFailure('promotion-head-mismatch', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      responses.get(promotionPath).body.head.sha = staleReviewCommit;
    }
  });
  await expectQueryFailure('promotion-base-mismatch', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      responses.get(promotionPath).body.base.ref = 'unexpected-base';
    }
  });
  await expectQueryFailure('promotion-tree-mismatch', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_HEAD_TREE_MISMATCH',
    mutateResponses(responses) {
      responses.get(promotionCommitPath).body.tree.sha = '3'.repeat(40);
    }
  });
  await expectQueryFailure('promotion-review-stale-head', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID',
    mutateResponses(responses) {
      responses.get(promotionReviewsPath).body[0].commit_id = staleReviewCommit;
    }
  });
  await expectQueryFailure('pr36-current-head-approval', {
    expected: 'CNYOS_CONTROLLER_PR36_CURRENT_APPROVAL_PRESENT',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body.push({
        id: 7002,
        state: 'APPROVED',
        user: { login: 'IndependentTwo' },
        commit_id: pr36HeadCommit,
        submitted_at: '2029-12-31T23:51:00.000Z'
      });
    }
  });
  await expectQueryFailure('pr36-active-old-head-approval', {
    expected: 'CNYOS_CONTROLLER_PR36_CURRENT_APPROVAL_PRESENT',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body.push({
        id: 7003,
        state: 'APPROVED',
        user: { login: 'OldHeadApprover' },
        commit_id: staleReviewCommit,
        submitted_at: '2029-12-31T23:51:00.000Z'
      });
    }
  });
  await expectQueryFailure('wrong-independent-reviewer', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID',
    mutateResponses(responses) {
      responses.get(promotionReviewsPath).body[0].user.login = 'SomeoneElse';
    }
  });
  await expectQueryFailure('reviewer-is-pr-author', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID',
    mutateResponses(responses) {
      responses.get(promotionPath).body.user.login = reviewer;
    }
  });
  await expectQueryFailure('reviews-pagination-incomplete', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS',
    mutateResponses(responses) {
      responses.get(promotionReviewsPath).headers = {
        'x-next-page': '2'
      };
    }
  });
  await expectQueryFailure('reviews-pagination-last-without-next', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).headers = {
        link: '<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=2>; rel="last"'
      };
    }
  });
  const pr36ReviewsPageTwoPath = `${pr36Path}/reviews?per_page=100&page=2`;
  const pr36ReviewsPageThreePath = `${pr36Path}/reviews?per_page=100&page=3`;
  const fullCommentPage = () => Array.from({ length: 100 }, (_, index) => ({
    id: 8000 + index,
    state: 'COMMENTED',
    user: { login: `Reviewer${index + 1}` },
    commit_id: pr36HeadCommit,
    submitted_at: '2029-12-31T23:40:00.000Z'
  }));
  const fullSecondCommentPage = () => Array.from({ length: 100 }, (_, index) => ({
    id: 9300 + index,
    state: 'COMMENTED',
    user: { login: `TerminalReviewer${index + 1}` },
    commit_id: pr36HeadCommit,
    submitted_at: '2029-12-31T23:41:00.000Z'
  }));
  const hiddenApproval = await expectQueryFailure('approval-hidden-on-page-two', {
    expected: 'CNYOS_CONTROLLER_PR36_CURRENT_APPROVAL_PRESENT',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = Array.from({ length: 100 }, (_, index) => ({
        id: 8100 + index, state: 'COMMENTED', user: { login: `LaterPageReviewer${index + 1}` },
        commit_id: pr36HeadCommit, submitted_at: '2029-12-31T23:40:00.000Z'
      }));
      responses.set(pr36ReviewsPageTwoPath, {
        body: [{
          id: 9001,
          state: 'APPROVED',
          user: { login: 'PageTwoApprover' },
          commit_id: pr36HeadCommit,
          submitted_at: '2029-12-31T23:55:00.000Z'
        }]
      });
    }
  });
  assert.ok(hiddenApproval.calls.some(call => call.requestPath === pr36ReviewsPageTwoPath),
    'a full first page must cause a locally generated second-page request');
  await expectQueryFailure('duplicate-review-id-across-pages', {
    expected: 'CNYOS_CONTROLLER_GITHUB_REVIEWS_INVALID',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = fullCommentPage();
      responses.set(pr36ReviewsPageTwoPath, {
        body: [{
          ...fullCommentPage()[0]
        }]
      });
    }
  });
  await expectQueryFailure('reviews-pagination-declared-last-disappears', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = fullCommentPage();
      responses.get(pr36ReviewsPath).headers = {
        link: `<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=2>; rel="next", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=3>; rel="last"`
      };
      responses.set(pr36ReviewsPageTwoPath, {
        body: [{
          id: 9101,
          state: 'COMMENTED',
          user: { login: 'PageTwoReviewer' },
          commit_id: pr36HeadCommit,
          submitted_at: '2029-12-31T23:54:00.000Z'
        }]
      });
      responses.set(pr36ReviewsPageThreePath, {
        body: [{
          id: 9102,
          state: 'APPROVED',
          user: { login: 'HiddenPageThreeApprover' },
          commit_id: pr36HeadCommit,
          submitted_at: '2029-12-31T23:55:00.000Z'
        }]
      });
    }
  });
  await expectQueryFailure('reviews-pagination-declared-terminal-page-is-full', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = fullCommentPage();
      responses.get(pr36ReviewsPath).headers = {
        link: `<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=2>; rel="next last"`
      };
      responses.set(pr36ReviewsPageTwoPath, {
        body: fullSecondCommentPage(),
        headers: {
          link: `<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=1>; rel="first prev", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=2>; rel="last"`
        }
      });
    }
  });
  const hiddenPageThreeApproval = await expectQueryFailure('approval-on-declared-page-three', {
    expected: 'CNYOS_CONTROLLER_PR36_CURRENT_APPROVAL_PRESENT',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = fullCommentPage();
      responses.get(pr36ReviewsPath).headers = {
        link: `<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=2>; rel="next", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=3>; rel="last"`
      };
      responses.set(pr36ReviewsPageTwoPath, {
        body: [{
          id: 9201,
          state: 'COMMENTED',
          user: { login: 'PageTwoReviewer' },
          commit_id: pr36HeadCommit,
          submitted_at: '2029-12-31T23:54:00.000Z'
        }],
        headers: {
          link: `<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=1>; rel="first", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=1>; rel="prev", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=3>; rel="next last"`
        }
      });
      responses.set(pr36ReviewsPageThreePath, {
        body: [{
          id: 9202,
          state: 'APPROVED',
          user: { login: 'PageThreeApprover' },
          commit_id: pr36HeadCommit,
          submitted_at: '2029-12-31T23:55:00.000Z'
        }],
        headers: {
          link: `<https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=1>; rel="first", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=2>; rel="prev", <https://api.github.com/repos/apisarit/chananya-clinical-wellness-os/pulls/36/reviews?per_page=100&page=3>; rel="last"`
        }
      });
    }
  });
  assert.ok(hiddenPageThreeApproval.calls.some(call =>
    call.requestPath === pr36ReviewsPageThreePath),
  'a carried terminal-page declaration must force the page-three request');
  await expectQueryFailure('malicious-pagination-host', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PAGINATION_AMBIGUOUS',
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).headers = {
        link: '<https://evil.example/reviews?per_page=100&page=2>; rel="next"'
      };
    }
  });
  await expectQueryFailure('rate-limit-exhausted', {
    expected: 'CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID',
    mutateResponses(responses) {
      responses.get(pr36Path).headers = { 'x-ratelimit-remaining': '0' };
    }
  });
  await expectQueryFailure('redirect-response', {
    expected: 'CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID',
    mutateResponses(responses) {
      responses.get(pr36Path).redirected = true;
      responses.get(pr36Path).url = 'https://api.github.com/repositories/redirected';
    }
  });
  await expectQueryFailure('malformed-json-response', {
    expected: 'CNYOS_CONTROLLER_GITHUB_RESPONSE_INVALID',
    mutateResponses(responses) {
      delete responses.get(promotionCommitPath).body;
      responses.get(promotionCommitPath).raw = '{malformed';
    }
  });
  await expectQueryFailure('partial-api-failure', {
    expected: 'CNYOS_CONTROLLER_GITHUB_REQUEST_FAILED',
    mutateResponses(responses) {
      responses.get(promotionReviewsPath).throw = new Error('OFFLINE_PARTIAL_API_FAILURE');
    }
  });
  await expectQueryFailure('partial-pull-json', {
    expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
    mutateResponses(responses) {
      delete responses.get(promotionPath).body.head.repo;
    }
  });

  let futureTokenReads = 0;
  const futureBoundary = await expectQueryFailure('future-prior-boundary', {
    phase: 'before_promotion',
    prior: initialBoundary,
    now: new Date(checkedAt.getTime() - 1),
    expected: 'CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID',
    mutateEnvironment(env) {
      delete env.CNYOS_GITHUB_ACTIONS_READ_TOKEN;
      Object.defineProperty(env, 'CNYOS_GITHUB_ACTIONS_READ_TOKEN', {
        enumerable: true,
        get() {
          futureTokenReads += 1;
          return token;
        }
      });
    }
  });
  assert.equal(futureTokenReads, 0,
    'future prior evidence must fail before reading the GitHub token');
  assert.equal(futureBoundary.calls.length, 0,
    'future prior evidence must fail before GitHub requests');

  for (const forbiddenName of LIVE_GITHUB_FORBIDDEN_ENVIRONMENT_NAMES) {
    let isolatedTokenReads = 0;
    const isolated = await expectQueryFailure(`token-isolation-${forbiddenName.toLowerCase()}`, {
      expected: 'CNYOS_CONTROLLER_GITHUB_RELEASE_CREDENTIAL_ISOLATION_INVALID',
      mutateEnvironment(env) {
        env[forbiddenName] = 'forbidden-offline-value';
        delete env.CNYOS_GITHUB_ACTIONS_READ_TOKEN;
        Object.defineProperty(env, 'CNYOS_GITHUB_ACTIONS_READ_TOKEN', {
          enumerable: true,
          get() {
            isolatedTokenReads += 1;
            return token;
          }
        });
      }
    });
    assert.equal(isolatedTokenReads, 0,
      `${forbiddenName} must fail before reading the GitHub token`);
    assert.equal(isolated.calls.length, 0,
      `${forbiddenName} must fail before any GitHub request`);
  }

  const invalidToken = await expectQueryFailure('invalid-read-token', {
    expected: 'CNYOS_CONTROLLER_GITHUB_READ_TOKEN_INVALID',
    mutateEnvironment(env) {
      env.CNYOS_GITHUB_ACTIONS_READ_TOKEN = 'short';
    }
  });
  assert.equal(invalidToken.calls.length, 0, 'invalid token must fail before GitHub requests');

  await setPr36ReviewOnlyMode();
  const reviewOnlyBoundary = await verifySuccess({
    phase: 'before_netlify_credential',
    now: checkedAt,
    expectedPr36ApprovalCount: 1,
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body.push({
        id: 7010,
        state: 'APPROVED',
        user: { login: 'ReviewOnlyApprover' },
        commit_id: pr36HeadCommit,
        submitted_at: '2029-12-31T23:55:00.000Z'
      });
    }
  });
  assert.equal(reviewOnlyBoundary.evidence.pr36.reviewCount, 1,
    'review-only evidence must retain the observed PR #36 review count');
  for (const [label, mutate] of [
    ['closed', responses => { responses.get(pr36Path).body.state = 'closed'; }],
    ['merged', responses => {
      responses.get(pr36Path).body.merged = true;
      responses.get(pr36Path).body.merged_at = '2030-01-01T00:00:00.000Z';
    }],
    ['not-draft', responses => { responses.get(pr36Path).body.draft = false; }],
    ['head-drift', responses => { responses.get(pr36Path).body.head.sha = staleReviewCommit; }],
    ['head-ref-drift', responses => { responses.get(pr36Path).body.head.ref = 'unexpected-pr36-head'; }],
    ['base-drift', responses => { responses.get(pr36Path).body.base.ref = 'unexpected-base'; }],
    ['base-sha-drift', responses => { responses.get(pr36Path).body.base.sha = '4'.repeat(40); }]
  ]) {
    await expectQueryFailure(`review-only-pr36-${label}`, {
      expected: 'CNYOS_CONTROLLER_GITHUB_PULL_REQUEST_INVALID',
      mutateResponses: mutate
    });
  }
  const pr36ReviewsPageTwoPathReviewOnly = `${pr36Path}/reviews?per_page=100&page=2`;
  await verifySuccess({
    phase: 'before_netlify_credential',
    now: checkedAt,
    expectedPr36ApprovalCount: 1,
    expectedAdditionalPaths: [pr36ReviewsPageTwoPathReviewOnly],
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = Array.from({ length: 100 }, (_, index) => ({
        id: 8100 + index, state: 'COMMENTED', user: { login: `LaterPageReviewer${index + 1}` },
        commit_id: pr36HeadCommit, submitted_at: '2029-12-31T23:40:00.000Z'
      }));
      responses.set(pr36ReviewsPageTwoPathReviewOnly, { body: [{
        id: 7011, state: 'APPROVED', user: { login: 'LaterPageApprover' },
        commit_id: pr36HeadCommit, submitted_at: '2029-12-31T23:56:00.000Z'
      }] });
    }
  });
  const historicalReviewOnly = await verifySuccess({
    phase: 'before_netlify_credential',
    now: checkedAt,
    expectedPr36ApprovalCount: 0,
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body = [{
        id: 7012, state: 'APPROVED', user: { login: 'HistoricalReviewer' },
        commit_id: staleReviewCommit, submitted_at: '2029-12-31T23:30:00.000Z'
      }];
    }
  });
  assert.equal(historicalReviewOnly.evidence.pr36.reviewCount, 1,
    'review-only historical approval must be retained in the review count');
  const reviewOnlyPromotionBoundary = await verifySuccess({
    phase: 'before_promotion',
    now: promotionCheckedAt,
    prior: reviewOnlyBoundary,
    expectedPr36ApprovalCount: 1,
    mutateResponses(responses) {
      responses.get(pr36ReviewsPath).body.push({
        id: 7013, state: 'APPROVED', user: { login: 'PromotionPhaseApprover' },
        commit_id: pr36HeadCommit, submitted_at: '2029-12-31T23:56:00.000Z'
      });
    }
  });
  assert.equal(reviewOnlyPromotionBoundary.evidence.priorBoundaryEvidenceSha256,
    reviewOnlyBoundary.sha256,
    'review-only promotion phase must bind the prior boundary hash');
  const reviewOnlyAuthorizationEvidence = activeAuthorizationEvidence;
  const tamperedReviewOnlyAuthorization = structuredClone(reviewOnlyAuthorizationEvidence);
  tamperedReviewOnlyAuthorization.policySha256 = 'f'.repeat(64);
  activeAuthorizationEvidence = tamperedReviewOnlyAuthorization;
  authorizationBytes = Buffer.from(JSON.stringify(activeAuthorizationEvidence));
  authorizationSha256 = sha256(authorizationBytes);
  await fs.writeFile(authorizationPath, authorizationBytes);
  let stalePolicyTokenReads = 0;
  const stalePolicyHash = await expectQueryFailure('review-only-stale-policy-hash', {
    expected: 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_INVALID',
    mutateEnvironment(env) {
      delete env.CNYOS_GITHUB_ACTIONS_READ_TOKEN;
      Object.defineProperty(env, 'CNYOS_GITHUB_ACTIONS_READ_TOKEN', {
        enumerable: true,
        get() {
          stalePolicyTokenReads += 1;
          return token;
        }
      });
    }
  });
  assert.equal(stalePolicyTokenReads, 0,
    'stale review-only policy hash must fail before reading the GitHub token');
  assert.equal(stalePolicyHash.calls.length, 0,
    'stale review-only policy hash must fail before GitHub requests');
  activeAuthorizationEvidence = reviewOnlyAuthorizationEvidence;
  authorizationBytes = Buffer.from(JSON.stringify(activeAuthorizationEvidence));
  authorizationSha256 = sha256(authorizationBytes);
  await fs.writeFile(authorizationPath, authorizationBytes);
  const historicalEvidence = JSON.parse(await fs.readFile(historicalReviewOnly.path, 'utf8'));
  for (const [label, value] of [
    ['negative', -1], ['string', '0'], ['fraction', 0.5], ['too-large', 2]
  ]) {
    historicalEvidence.pr36.currentHeadApprovalCount = value;
    const tamperedPath = nextEvidencePath(`review-only-count-${label}`);
    await fs.writeFile(tamperedPath, JSON.stringify(historicalEvidence));
    await assert.rejects(validateStoredLiveGitHubReleaseBoundary({
      env: { ...queryEnvironment(tamperedPath),
        CNYOS_EXPECTED_GITHUB_RELEASE_EVIDENCE_SHA256: sha256(await fs.readFile(tamperedPath)) },
      now: () => checkedAt
    }), /CNYOS_CONTROLLER_GITHUB_RELEASE_EVIDENCE_INVALID/);
  }
  await expectQueryFailure('review-only-missing-promotion-approval', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID',
    mutateResponses(responses) {
      responses.get(promotionReviewsPath).body = [];
    }
  });
  await expectQueryFailure('review-only-stale-promotion-approval', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID',
    mutateResponses(responses) {
      responses.get(promotionReviewsPath).body[0].commit_id = staleReviewCommit;
    }
  });
  await expectQueryFailure('review-only-promotion-author-approval', {
    expected: 'CNYOS_CONTROLLER_PROMOTION_CURRENT_APPROVAL_INVALID',
    mutateResponses(responses) {
      responses.get(promotionPath).body.user.login = reviewer;
    }
  });

  let digestFailureTokenReads = 0;
  const digestFailure = await expectQueryFailure('authorization-digest-mismatch', {
    expected: 'CNYOS_CONTROLLER_GITHUB_AUTHORIZATION_EVIDENCE_DIGEST_MISMATCH',
    mutateEnvironment(env) {
      env.CNYOS_EXPECTED_AUTHORIZATION_EVIDENCE_SHA256 = '7'.repeat(64);
      delete env.CNYOS_GITHUB_ACTIONS_READ_TOKEN;
      Object.defineProperty(env, 'CNYOS_GITHUB_ACTIONS_READ_TOKEN', {
        enumerable: true,
        get() {
          digestFailureTokenReads += 1;
          return token;
        }
      });
    }
  });
  assert.equal(digestFailureTokenReads, 0,
    'invalid authorization digest must fail before reading the GitHub token');
  assert.equal(digestFailure.calls.length, 0,
    'invalid authorization digest must fail before GitHub requests');

  assert.equal(globalFetchCalls, 0, 'contract must not make a live network request');
  completed = true;
} finally {
  globalThis.fetch = originalFetch;
  await fs.rm(temporaryRoot, { recursive: true, force: true });
}

if (completed) {
  process.stdout.write('CNYOS activation contract live-github-release-boundary: passed\n');
}
