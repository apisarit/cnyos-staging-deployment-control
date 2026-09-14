import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflowPath = path.join(root, '.github', 'workflows', 'admit-vps-staging-release.yml');
const workflow = fs.readFileSync(workflowPath, 'utf8');
const service = fs.readFileSync(path.join(root, 'systemd', 'cnyos-staging-broker.service'), 'utf8');
const executableLines = workflow
  .split('\n')
  .map(line => line.replace(/\s+#.*$/, ''))
  .join('\n');

assert.match(workflow, /^name: Admit VPS staging release/m);
assert.match(workflow, /^  workflow_dispatch:\s*$/m);
assert.doesNotMatch(workflow, /^\s+(push|pull_request|schedule):/m,
  'admission must be an explicit operator-triggered request');
assert.match(workflow, /environment:\n\s+name: staging/);
assert.match(workflow, /runs-on: \[self-hosted, linux, x64, cnyos-staging-deployer\]/);
assert.match(workflow, /cancel-in-progress: false/);
assert.match(workflow, /contents: read/);
assert.match(workflow, /id-token: write/);

for (const input of [
  'source_commit',
  'candidate_run_id',
  'candidate_artifact_id',
  'candidate_archive_sha256',
  'release_request_sha256',
]) {
  assert.match(workflow, new RegExp(`^      ${input}:`, 'm'), `missing required input: ${input}`);
}

assert.match(workflow, /\^\[0-9a-f\]\{40\}\$/);
assert.match(workflow, /\^\[0-9a-f\]\{64\}\$/);
assert.match(workflow, /audience=cnyos-vps-staging-broker/);
assert.match(workflow, /https:\/\/127\.0\.0\.1:9443\/v1\/staging\/releases/);
assert.match(workflow, /--cacert \/etc\/cnyos-broker\/ca\.pem/);
assert.match(workflow, /Authorization: Bearer \$\{oidc_token\}/);
assert.match(workflow, /X-CNYOS-Request-ID/);
assert.match(workflow, /--data-binary "@\$\{payload_file\}"/);
assert.match(workflow, /schema_version/);
assert.match(workflow, /"controller":/);
assert.match(workflow, /apisarit\/cnyos-staging-deployment-control/);
assert.match(workflow, /github\.repository_id/);
assert.match(workflow, /CONTROLLER_REPOSITORY_ID" == "1362863285"/);
assert.match(workflow, /github\.ref_protected/);
assert.match(workflow, /github\.workflow_ref/);
assert.match(workflow, /github\.workflow_sha/);
assert.match(workflow, /admit-vps-staging-release\.yml@refs\/heads\/main/);
assert.match(workflow, /controller main ref is not protected/);
assert.match(workflow, /github\.actor_id/);
assert.match(workflow, /github\.triggering_actor/);
assert.match(workflow, /CONTROLLER_ACTOR" == "apisarit" && "\$CONTROLLER_ACTOR_ID" == "216305243"/);
assert.match(workflow, /apisarit\/chananya-clinical-wellness-os/);
assert.match(workflow, /"workflow_file": "deploy-vps-staging\.yml"/);
assert.match(workflow, /producer_run_id/);
assert.match(workflow, /archive_sha256/);
assert.match(workflow, /release_request_sha256/);
assert.match(workflow, /"status": "accepted"/);
assert.match(workflow, /broker response did not exactly confirm this request/);

assert.doesNotMatch(executableLines, /(^|\s)(docker|sudo)(\s|$)/m,
  'the controller runner must not execute Docker or privileged shell commands');
assert.doesNotMatch(executableLines, /actions\/(checkout|download-artifact)@/,
  'the admission job must not checkout or download candidate code');
assert.doesNotMatch(executableLines, /\b(?:GITHUB_TOKEN|secrets\.)/,
  'the broker admission must not use a repository token or secret');
assert.doesNotMatch(executableLines, /(?:--insecure|\s-k(?:\s|$))/,
  'TLS verification must never be disabled');
assert.doesNotMatch(executableLines, /echo\s+.*(?:oidc_response|oidc_token|ACTIONS_ID_TOKEN_REQUEST_TOKEN)/i,
  'OIDC material must never be printed');
assert.match(workflow, /only component allowed to download, verify, and invoke the VPS deployer/);
assert.match(service, /CNYOS_BROKER_CANDIDATE_VERIFIER=\/opt\/cnyos-staging-controller\/broker\/adapters\/candidate-verifier\.mjs/);
assert.match(service, /CNYOS_BROKER_ARTIFACT_FETCHER=\/opt\/cnyos-staging-controller\/broker\/adapters\/artifact-fetcher\.mjs/);
assert.match(service, /CNYOS_BROKER_DEPLOYER=\/opt\/cnyos-staging-controller\/broker\/adapters\/deployer\.mjs/);

process.stdout.write('CNYOS VPS staging admission workflow contract: passed\n');
