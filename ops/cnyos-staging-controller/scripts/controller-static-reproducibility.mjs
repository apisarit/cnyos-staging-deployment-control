import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import {
  POLICY, POLICY_SHA256, MAX_FILE_BYTES, assertControllerRuntime,
  readRegularFileStable, portableRelativePath, sha1, sha256
} from './policy.mjs';
import { parseFunctionBundleGitInventory } from './controller-function-bundle.mjs';
import {
  parseImmutableGitBlobBatchCheck, parseImmutableGitBlobBatch,
  assertImmutableGitBlobLimits
} from './create-producer-bundle.mjs';

const SOURCE_LIMIT = 256 * 1024 * 1024;
const FILE_LIMIT = 4096;
const METADATA_LIMIT = 4 * 1024 * 1024;
const WIRE_LIMIT = Math.ceil(SOURCE_LIMIT * 4 / 3) + METADATA_LIMIT;
const DOCKER_TIMEOUT = 5 * 60 * 1000;
const CHILD_ENV = Object.freeze({ PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' });
const RECIPE = 'node scripts/generate-tenant-config.mjs && node scripts/build-u-synthesise.mjs && node scripts/build-netlify-publish.mjs';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIGEST = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const IMAGE = /^sha256:[0-9a-f]{64}$/;
const fail = suffix => { throw new Error(`CNYOS_STATIC_REPRODUCIBILITY_${suffix}`); };

export const STATIC_REPRODUCIBILITY_FORBIDDEN_ENVIRONMENT_NAMES = Object.freeze([
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
  'CNYOS_CONTROLLER_AUTHORIZATION_JSON', 'CNYOS_CONTROLLER_RISK_OWNER_SIGNATURE_BASE64',
  'CNYOS_CONTROLLER_SECURITY_SIGNATURE_BASE64', 'CNYOS_CREDENTIAL_SEPARATION_HMAC_KEY',
  'CNYOS_GITHUB_ACTIONS_READ_TOKEN',
  'CNYOS_STAGING_DRAFT_ACCESS_BOUNDARY_TOKEN', 'CNYOS_STAGING_NETLIFY_AUTH_TOKEN',
  'CNYOS_STAGING_NETLIFY_ROLLBACK_TOKEN', 'CNYOS_STAGING_SUPABASE_SERVICE_ROLE_KEY',
  'CNYOS_STAGING_TEST_PASSWORD', 'GH_TOKEN', 'GITHUB_TOKEN', 'NETLIFY_AUTH_TOKEN',
  'PGPASSWORD', 'SUPABASE_DB_PASSWORD', 'SUPABASE_SERVICE_ROLE_KEY'
].sort());

function credentialFree(env) {
  if (!env || typeof env !== 'object') fail('ENVIRONMENT_INVALID');
  for (const key of Object.keys(env)) {
    if (STATIC_REPRODUCIBILITY_FORBIDDEN_ENVIRONMENT_NAMES.includes(key) ||
      /^(?:DOCKER_|CONTAINER_|SSH_|NODE_OPTIONS$|LD_|DYLD_)/.test(key)) {
      fail('AMBIENT_AUTHORITY_REJECTED');
    }
  }
  if (Object.hasOwn(env, 'CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE') &&
    env.CNYOS_CONTROLLER_CREDENTIALS_AVAILABLE !== 'false') fail('AMBIENT_AUTHORITY_REJECTED');
}

function policyPins() {
  const policy = POLICY.staticArtifactReproducibility;
  if (policy?.contractRequired !== true || policy?.networkDisabledDuringBuild !== true ||
    !IMAGE.test(policy?.hermeticBuilderImageDigest || '') ||
    !DIGEST.test(policy?.stagingConfigSha256 || '') ||
    !DIGEST.test(policy?.productionDenylistConfigSha256 || '')) fail('POLICY_NOT_REVIEWED');
  return policy;
}

async function directory(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value ||
    value === path.parse(value).root || /[,\u0000-\u001f\u007f]/.test(value)) fail('PATH_INVALID');
  const status = await fs.lstat(value);
  if (!status.isDirectory() || status.isSymbolicLink() || await fs.realpath(value) !== value) {
    fail('PATH_INVALID');
  }
  return value;
}

async function freshPath(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value ||
    /[,\u0000-\u001f\u007f]/.test(value)) fail('PATH_INVALID');
  await directory(path.dirname(value));
  try { await fs.lstat(value); } catch (error) {
    if (error.code === 'ENOENT') return value;
    throw error;
  }
  fail('OUTPUT_ALREADY_EXISTS');
}

function overlap(left, right) {
  return left === right || left.startsWith(`${right}${path.sep}`) || right.startsWith(`${left}${path.sep}`);
}

function git(cwd, args, input, limit = METADATA_LIMIT) {
  try {
    return execFileSync('/usr/bin/git', [
      '--no-replace-objects', '--literal-pathspecs',
      '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
      '-c', 'protocol.allow=never', ...args
    ], {
      cwd, env: { ...CHILD_ENV, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_NO_REPLACE_OBJECTS: '1', GIT_NO_LAZY_FETCH: '1', GIT_OPTIONAL_LOCKS: '0',
        GIT_TERMINAL_PROMPT: '0', GIT_ATTR_NOSYSTEM: '1' },
      input, encoding: 'buffer', maxBuffer: limit, timeout: 30_000,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch { fail('GIT_READ_FAILED'); }
}

function objectId(type, bytes) {
  return sha1(Buffer.concat([Buffer.from(`${type} ${bytes.length}\0`), bytes]));
}

export function readStaticImmutableSource(cwd, commit) {
  if (!COMMIT.test(commit || '')) fail('CANDIDATE_INVALID');
  const head = () => git(cwd, ['rev-parse', '--verify', 'HEAD^{commit}']).toString().trim();
  if (head() !== commit) fail('HEAD_CHANGED');
  if (git(cwd, ['rev-parse', '--show-object-format']).toString().trim() !== 'sha1') {
    fail('OBJECT_FORMAT_INVALID');
  }
  const commitBytes = git(cwd, ['cat-file', 'commit', commit]);
  if (objectId('commit', commitBytes) !== commit) fail('COMMIT_BYTES_INVALID');
  const tree = /^tree ([0-9a-f]{40})\n/.exec(commitBytes.toString('utf8'))?.[1];
  if (!tree) fail('COMMIT_BYTES_INVALID');
  const timestamp = git(cwd, ['show', '-s', '--format=%cI', commit]).toString().trim();
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) fail('COMMIT_TIME_INVALID');
  // This full-source parser permits tracked dotfiles, but never a .git path,
  // symlink, submodule, portable-name collision or non-regular Git mode.
  const inventory = parseFunctionBundleGitInventory(git(cwd, ['ls-tree', '-r', '-z', '--full-tree', commit]));
  const objects = [...new Set(inventory.map(item => item.gitObject))].sort();
  const input = Buffer.from(`${objects.join('\n')}\n`);
  const sizes = parseImmutableGitBlobBatchCheck(git(cwd,
    ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], input), objects);
  assertImmutableGitBlobLimits(inventory.map(item => ({ object: item.gitObject })), sizes,
    { maximumFiles: FILE_LIMIT, maximumAggregateBytes: SOURCE_LIMIT });
  const bytes = parseImmutableGitBlobBatch(git(cwd, ['cat-file', '--batch'], input,
    SOURCE_LIMIT + METADATA_LIMIT), objects, sizes);
  const blobs = inventory.map(item => ({ ...item, bytes: bytes.get(item.gitObject) }));
  const lock = blobs.find(item => item.path === 'package-lock.json');
  const pkg = blobs.find(item => item.path === 'package.json');
  let manifest;
  try { manifest = JSON.parse(pkg?.bytes.toString('utf8')); } catch { fail('BUILD_RECIPE_INVALID'); }
  if (!lock || manifest?.scripts?.['build:staging-artifact'] !== RECIPE ||
    Object.hasOwn(manifest.scripts, 'prebuild:staging-artifact') ||
    Object.hasOwn(manifest.scripts, 'postbuild:staging-artifact')) fail('BUILD_RECIPE_INVALID');
  if (head() !== commit) fail('HEAD_CHANGED');
  return { commit, tree, commitBytes, timestamp: date.toISOString(), blobs,
    candidateDependencyLockSha256: sha256(lock.bytes) };
}

async function writeExclusive(filename, bytes, mode = 0o600) {
  await fs.mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  await fs.writeFile(filename, bytes, { flag: 'wx', mode });
}

async function materialize(snapshot, root) {
  const source = path.join(root, 'source');
  const gitRoot = path.join(root, 'git');
  await fs.mkdir(source, { mode: 0o700 });
  await fs.mkdir(gitRoot, { mode: 0o700 });
  const stored = new Set();
  async function store(type, bytes) {
    const id = objectId(type, bytes);
    if (!stored.has(id)) {
      await writeExclusive(path.join(gitRoot, 'objects', id.slice(0, 2), id.slice(2)),
        zlib.deflateSync(Buffer.concat([Buffer.from(`${type} ${bytes.length}\0`), bytes])));
      stored.add(id);
    }
    return id;
  }
  const rootTree = new Map();
  for (const blob of snapshot.blobs) {
    const parts = blob.path.split('/');
    let node = rootTree;
    for (const part of parts.slice(0, -1)) {
      if (!node.has(part)) node.set(part, new Map());
      if (!(node.get(part) instanceof Map)) fail('SOURCE_PATH_CONFLICT');
      node = node.get(part);
    }
    if (node.has(parts.at(-1))) fail('SOURCE_PATH_CONFLICT');
    node.set(parts.at(-1), blob);
    await writeExclusive(path.join(source, blob.path), blob.bytes, blob.mode === '100755' ? 0o700 : 0o600);
    if (await store('blob', blob.bytes) !== blob.gitObject) fail('SOURCE_CHANGED');
  }
  async function treeObject(entries) {
    const records = [];
    for (const [name, item] of entries) {
      const isTree = item instanceof Map;
      records.push({ name, isTree, mode: isTree ? '40000' : item.mode,
        id: isTree ? await treeObject(item) : item.gitObject });
    }
    records.sort((a, b) => Buffer.compare(Buffer.from(a.name + (a.isTree ? '/' : '')),
      Buffer.from(b.name + (b.isTree ? '/' : ''))));
    return store('tree', Buffer.concat(records.map(item => Buffer.concat([
      Buffer.from(`${item.mode} ${item.name}\0`), Buffer.from(item.id, 'hex')
    ]))));
  }
  if (await treeObject(rootTree) !== snapshot.tree ||
    await store('commit', snapshot.commitBytes) !== snapshot.commit) fail('SOURCE_TREE_MISMATCH');
  await writeExclusive(path.join(gitRoot, 'HEAD'), Buffer.from(`${snapshot.commit}\n`));
  await writeExclusive(path.join(gitRoot, 'config'), Buffer.from('[core]\nrepositoryformatversion = 0\nbare = true\n'));
  await writeExclusive(path.join(gitRoot, 'shallow'), Buffer.from(`${snapshot.commit}\n`));
  await fs.mkdir(path.join(gitRoot, 'refs'), { mode: 0o700 });
  return { source, gitRoot };
}

async function protectedConfig(filename, expectedHash, target, kind) {
  const expected = path.join(ROOT, 'config', kind === 'staging' ?
    'cnyos-public-staging.json' : 'cnyos-production-denylist.json');
  if (filename !== expected) fail('CONFIG_NOT_CONTROLLER_OWNED');
  await directory(path.dirname(filename));
  const bytes = await readRegularFileStable(filename, MAX_FILE_BYTES, 'CNYOS_STATIC_REPRODUCIBILITY_CONFIG_INVALID', 1);
  if (sha256(bytes) !== expectedHash) fail('CONFIG_DIGEST_MISMATCH');
  let config;
  try { config = JSON.parse(bytes.toString('utf8')); } catch { fail('CONFIG_INVALID'); }
  const staging = kind === 'staging';
  if (config?.schemaVersion !== 1 || config.database?.provider !== 'supabase' ||
    config.database?.url !== target.supabaseOrigin ||
    config.tenant?.expectedClinicId !== target.clinicId ||
    config.tenant?.expectedClinicCode !== target.clinicCode ||
    config.identity?.qrIssuer !== target.qrIssuer ||
    config.auth?.redirectOrigin !== (staging ? target.authRedirectOrigin : target.netlifyOrigin) ||
    (staging && (config.deploymentId !== target.deploymentId || config.auth?.provider !== 'google')) ||
    !/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(config.database?.publishableKey || '') ||
    /(?:placeholder|example|replace|change[-_]?me|test(?:_|-)?only)/i.test(config.database.publishableKey)) {
    fail('CONFIG_TARGET_INVALID');
  }
  return bytes;
}

// This launcher is controller-owned. The candidate is interpreted only inside
// the inspected, credential-free container. No npm lifecycle or install runs.
const LAUNCHER = `import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
if (process.versions.node !== '24.20.0') process.exit(31);
fs.cpSync('/input/source', '/work/source', {recursive:true, force:false, errorOnExist:true});
for (const script of ['generate-tenant-config','build-u-synthesise','build-netlify-publish']) {
 const r = spawnSync('/usr/local/bin/node', ['scripts/'+script+'.mjs'], {
  cwd:'/work/source',env:process.env,stdio:'ignore',timeout:120000});
 if (r.error || r.status !== 0 || r.signal) process.exit(32);
}
const files=[]; let total=0;
function visit(current,prefix='') {
 for (const entry of fs.readdirSync(current,{withFileTypes:true})) {
  const name=prefix?prefix+'/'+entry.name:entry.name;
  const filename=current+'/'+entry.name;
  const before=fs.lstatSync(filename);
  if (before.isSymbolicLink()) process.exit(33);
  if (before.isDirectory()) {visit(filename,name);continue;}
  if (!before.isFile() || before.nlink!==1 || before.size>33554432 || files.length>=4096) process.exit(33);
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  const opened=fs.fstatSync(fd); const bytes=fs.readFileSync(fd); const after=fs.fstatSync(fd);fs.closeSync(fd);
  if (opened.ino!==before.ino || opened.dev!==before.dev || after.ino!==before.ino ||
   after.size!==before.size || after.mtimeMs!==before.mtimeMs || after.ctimeMs!==before.ctimeMs ||
   bytes.length!==before.size || after.nlink!==1) process.exit(33);
  total+=bytes.length; if(total>268435456)process.exit(33);
  files.push({path:name,size:bytes.length,base64:bytes.toString('base64')});
 }
}
const distRoot=fs.lstatSync('/work/source/dist');
if (!distRoot.isDirectory() || distRoot.isSymbolicLink()) process.exit(33);
visit('/work/source/dist');
process.stdout.write(JSON.stringify({schemaVersion:1,nodeVersion:process.versions.node,files}));
`;

export function staticDockerCreateArguments(plan) {
  const mounts = [
    [plan.source, '/input/source'], [plan.gitRoot, '/input/git'],
    [plan.configRoot, '/config'], [plan.launcher, '/controller/launch.mjs']
  ];
  const buildEnv = [
    'PATH=/usr/local/bin:/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', 'TZ=UTC',
    'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null', 'GIT_NO_REPLACE_OBJECTS=1',
    'GIT_NO_LAZY_FETCH=1', 'GIT_OPTIONAL_LOCKS=0', 'GIT_TERMINAL_PROMPT=0',
    'GIT_DIR=/input/git', 'GIT_WORK_TREE=/work/source',
    'CONTEXT=production', `URL=${POLICY.target.netlifyOrigin}`,
    'CLINICAL_OS_STAGING_DEPLOYMENT=true', 'CLINICAL_OS_ALLOW_STAGING_DATABASE=true',
    'CLINICAL_OS_STAGING_DATABASE_ACK=STAGING_ONLY', 'CLINICAL_OS_REQUIRE_SOURCE_COMMIT=true',
    'CLINICAL_OS_TENANT_CONFIG_PATH=/config/staging.json',
    'CLINICAL_OS_PRODUCTION_CONFIG_PATH=/config/production.json',
    `CLINICAL_OS_SOURCE_COMMIT=${plan.snapshot.commit}`,
    `CLINICAL_OS_SOURCE_TREE=${plan.snapshot.tree}`,
    `CLINICAL_OS_BUILD_TIMESTAMP=${plan.snapshot.timestamp}`
  ];
  return ['container', 'create', '--name', plan.name, '--pull=never', '--platform=linux/amd64',
    '--network=none', '--read-only', '--user', `${plan.uid}:${plan.gid}`, '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true', '--pids-limit=64', '--memory=536870912',
    '--memory-swap=536870912', '--cpus=1', '--restart=no', '--no-healthcheck',
    '--log-driver=none', '--ipc=none', '--cgroupns=private', '--stop-timeout=1',
    '--tmpfs', '/work:rw,nosuid,nodev,noexec,size=536870912,nr_inodes=16384,mode=1777',
    ...mounts.flatMap(([source, target]) => ['--mount',
      `type=bind,source=${source},target=${target},readonly,bind-propagation=rprivate`]),
    '--entrypoint=/usr/bin/env', plan.image, '-i', ...buildEnv,
    '/usr/local/bin/node', '/controller/launch.mjs'];
}

export function assertStaticContainerInspection(info, plan, exited = false) {
  const h = info?.HostConfig;
  const c = info?.Config;
  const expectedArgs = staticDockerCreateArguments(plan);
  const imageIndex = expectedArgs.indexOf(plan.image);
  if (!/^[0-9a-f]{64}$/.test(info?.Id || '') || info.Image !== plan.image ||
    info.Name !== `/${plan.name}` || h?.NetworkMode !== 'none' || h.ReadonlyRootfs !== true ||
    h.Privileged !== false || h.PublishAllPorts !== false ||
    h.PidMode || h.IpcMode !== 'none' || h.CgroupnsMode !== 'private' ||
    h.PidsLimit !== 64 || h.Memory !== 536870912 || h.MemorySwap !== 536870912 ||
    h.NanoCpus !== 1_000_000_000 || h.RestartPolicy?.Name !== 'no' ||
    JSON.stringify(h.CapDrop) !== '["ALL"]' || (h.CapAdd?.length || 0) !== 0 ||
    JSON.stringify(h.SecurityOpt) !== '["no-new-privileges=true"]' ||
    Object.keys(h.PortBindings || {}).length || (h.Devices?.length || 0) ||
    (h.DeviceRequests?.length || 0) || (h.VolumesFrom?.length || 0) ||
    h.LogConfig?.Type !== 'none' || c?.User !== `${plan.uid}:${plan.gid}` ||
    JSON.stringify(c.Entrypoint) !== '["/usr/bin/env"]' ||
    JSON.stringify(c.Cmd) !== JSON.stringify(expectedArgs.slice(imageIndex + 1)) ||
    JSON.stringify(c.Healthcheck?.Test) !== '["NONE"]' ||
    JSON.stringify(h.Tmpfs) !== JSON.stringify({ '/work': 'rw,nosuid,nodev,noexec,size=536870912,nr_inodes=16384,mode=1777' })) {
    fail('CONTAINER_ISOLATION_INVALID');
  }
  const expected = new Map([
    ['/input/source', [plan.source, false]], ['/input/git', [plan.gitRoot, false]],
    ['/config', [plan.configRoot, false]], ['/controller/launch.mjs', [plan.launcher, false]]
  ]);
  if (!Array.isArray(info.Mounts) || info.Mounts.length !== expected.size) fail('CONTAINER_MOUNTS_INVALID');
  for (const mount of info.Mounts) {
    const wanted = expected.get(mount.Destination);
    if (!wanted || mount.Type !== 'bind' || mount.Source !== wanted[0] || mount.RW !== wanted[1] ||
      mount.Propagation !== 'rprivate') fail('CONTAINER_MOUNTS_INVALID');
    expected.delete(mount.Destination);
  }
  if (expected.size || Object.keys(info.NetworkSettings?.Networks || {}).some(key => key !== 'none')) {
    fail('CONTAINER_ISOLATION_INVALID');
  }
  if (exited ? (info.State?.Status !== 'exited' || info.State.Running !== false ||
    info.State.ExitCode !== 0 || info.State.OOMKilled !== false || info.State.Error !== '') :
    (info.State?.Status !== 'created' || info.State.Running !== false)) fail('CONTAINER_EXECUTION_FAILED');
}

async function trustedDocker(plan) {
  if (process.platform !== 'linux' || !Number.isSafeInteger(plan.uid) || plan.uid <= 0) {
    fail('LINUX_UNPRIVILEGED_RUNNER_REQUIRED');
  }
  const binary = '/usr/bin/docker';
  for (const ancestor of ['/usr', '/usr/bin', '/run']) {
    const parent = await fs.lstat(ancestor);
    if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== 0 || (parent.mode & 0o022)) {
      fail('DOCKER_HOST_PATH_UNTRUSTED');
    }
  }
  const stat = await fs.lstat(binary);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022)) {
    fail('DOCKER_BINARY_UNTRUSTED');
  }
  const socket = await fs.realpath('/var/run/docker.sock');
  if (socket !== '/run/docker.sock' && socket !== '/var/run/docker.sock') fail('DOCKER_SOCKET_UNTRUSTED');
  const socketStat = await fs.lstat(socket);
  if (!socketStat.isSocket() || socketStat.uid !== 0 || (socketStat.mode & 0o002)) fail('DOCKER_SOCKET_UNTRUSTED');
  const config = path.join(plan.scratch, 'docker-config');
  await fs.mkdir(config, { mode: 0o700 });
  await writeExclusive(path.join(config, 'config.json'), Buffer.from('{}\n'));
  return (args, timeout = 30_000) => {
    try {
      return execFileSync(binary, ['--host', `unix://${socket}`, '--config', config, ...args], {
        env: CHILD_ENV, encoding: 'utf8', timeout,
        maxBuffer: args[0] === 'container' && args[1] === 'start' ? WIRE_LIMIT : METADATA_LIMIT,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch { fail('DOCKER_COMMAND_FAILED'); }
  };
}

function singleJson(raw) {
  let value;
  try { value = JSON.parse(raw); } catch { fail('DOCKER_RESPONSE_INVALID'); }
  if (!Array.isArray(value) || value.length !== 1 || !value[0] || typeof value[0] !== 'object') {
    fail('DOCKER_RESPONSE_INVALID');
  }
  return value[0];
}

async function executeDocker(plan, dockerFactory) {
  const docker = await dockerFactory(plan);
  const image = singleJson(await docker(['image', 'inspect', plan.image]));
  if (image.Id !== plan.image || image.Os !== 'linux' || image.Architecture !== 'amd64' ||
    Object.keys(image.Config?.Volumes || {}).length) fail('IMAGE_IDENTITY_INVALID');
  let id;
  let owned = false;
  let output;
  try {
    // A failed/ambiguous create never licenses deletion by name: another container
    // could already own that name. Leave an uncertain inactive resource untouched.
    id = String(await docker(staticDockerCreateArguments(plan))).trim();
    if (!/^[0-9a-f]{64}$/.test(id)) fail('CONTAINER_ID_INVALID');
    const before = singleJson(await docker(['container', 'inspect', id]));
    if (before.Id !== id) fail('CONTAINER_ID_INVALID');
    assertStaticContainerInspection(before, plan);
    owned = true;
    output = await docker(['container', 'start', '--attach', id], DOCKER_TIMEOUT);
    const after = singleJson(await docker(['container', 'inspect', id]));
    if (after.Id !== id) fail('CONTAINER_ID_INVALID');
    assertStaticContainerInspection(after, plan, true);
  } finally {
    if (owned) await docker(['container', 'rm', '--force', id]);
  }
  return parseStaticBuildOutput(output);
}

export function parseStaticBuildOutput(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > WIRE_LIMIT) fail('BUILD_OUTPUT_INVALID');
  let value;
  try { value = JSON.parse(raw); } catch { fail('BUILD_OUTPUT_INVALID'); }
  if (!value || Object.keys(value).sort().join(',') !== 'files,nodeVersion,schemaVersion' ||
    value.schemaVersion !== 1 || value.nodeVersion !== '24.20.0' || !Array.isArray(value.files) ||
    !value.files.length || value.files.length > FILE_LIMIT) fail('BUILD_OUTPUT_INVALID');
  const names = new Set();
  let total = 0;
  const files = value.files.map(item => {
    if (!item || Object.keys(item).sort().join(',') !== 'base64,path,size' ||
      typeof item.base64 !== 'string' || !Number.isSafeInteger(item.size) || item.size < 0 ||
      item.size > MAX_FILE_BYTES) fail('BUILD_OUTPUT_INVALID');
    portableRelativePath(item.path, 'CNYOS_STATIC_REPRODUCIBILITY_BUILD_PATH_INVALID');
    if (names.has(item.path.toLowerCase())) fail('BUILD_OUTPUT_INVALID');
    names.add(item.path.toLowerCase());
    const bytes = Buffer.from(item.base64, 'base64');
    if (bytes.length !== item.size || bytes.toString('base64') !== item.base64) fail('BUILD_OUTPUT_INVALID');
    total += bytes.length;
    if (total > SOURCE_LIMIT) fail('BUILD_OUTPUT_INVALID');
    return { path: item.path, size: item.size, sha256: sha256(bytes), bytes };
  });
  for (const name of names) {
    const parts = name.split('/');
    for (let i = 1; i < parts.length; i += 1) if (names.has(parts.slice(0, i).join('/'))) fail('BUILD_OUTPUT_INVALID');
  }
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

async function snapshotOutput(root) {
  await directory(root);
  const entries = [];
  const names = new Set();
  let total = 0;
  async function visit(current, prefix) {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      portableRelativePath(relative, 'CNYOS_STATIC_REPRODUCIBILITY_ARTIFACT_PATH_INVALID');
      const folded = relative.toLowerCase();
      if (names.has(folded) || names.size >= FILE_LIMIT) fail('ARTIFACT_INVENTORY_INVALID');
      names.add(folded);
      const filename = path.join(current, entry.name);
      const status = await fs.lstat(filename);
      if (status.isSymbolicLink()) fail('ARTIFACT_LINK_REJECTED');
      if (status.isDirectory()) { await visit(filename, relative); continue; }
      if (!status.isFile() || status.nlink !== 1) fail('ARTIFACT_LINK_REJECTED');
      const bytes = await readRegularFileStable(filename, MAX_FILE_BYTES,
        'CNYOS_STATIC_REPRODUCIBILITY_ARTIFACT_CHANGED', 1);
      total += bytes.length;
      if (total > SOURCE_LIMIT) fail('ARTIFACT_TOO_LARGE');
      entries.push({ path: relative, size: bytes.length, sha256: sha256(bytes), bytes });
    }
  }
  await visit(root, '');
  if (!entries.length) fail('ARTIFACT_EMPTY');
  return entries.sort((a, b) => a.path.localeCompare(b.path));
}

function sameEntries(left, right) {
  return left.length === right.length && left.every((item, index) =>
    item.path === right[index].path && item.bytes.equals(right[index].bytes));
}

export async function runControllerStaticReproducibility({ env = process.env, dockerFactory = trustedDocker } = {}) {
  env = Object.freeze({ ...env });
  credentialFree(env);
  const runtime = assertControllerRuntime(env);
  const pins = policyPins(); // Never run a container or create output under placeholder policy.
  if (typeof dockerFactory !== 'function') fail('DOCKER_ADAPTER_INVALID');
  const candidate = await directory(env.CNYOS_CANDIDATE_DIRECTORY);
  const reference = await directory(env.CNYOS_UNTRUSTED_STATIC_DIRECTORY);
  const output = await freshPath(env.CNYOS_REPRODUCED_STATIC_DIRECTORY);
  const evidence = await freshPath(env.CNYOS_STATIC_REPRODUCIBILITY_EVIDENCE_PATH);
  const paths = [candidate, reference, output, evidence];
  if (paths.some((a, i) => paths.some((b, j) => i !== j && overlap(a, b))) ||
    overlap(output, ROOT) || overlap(evidence, ROOT)) fail('PATHS_NOT_ISOLATED');
  const artifactDigest = env.CNYOS_EXPECTED_CANDIDATE_BUILD_ARTIFACT_DIGEST;
  if (!DIGEST.test(artifactDigest || '')) fail('REFERENCE_DIGEST_INVALID');
  const snapshot = readStaticImmutableSource(candidate, env.CNYOS_CANDIDATE_SHA);
  const staging = await protectedConfig(env.CNYOS_PUBLIC_STAGING_CONFIG_PATH,
    pins.stagingConfigSha256, POLICY.target, 'staging');
  const production = await protectedConfig(env.CNYOS_PRODUCTION_DENYLIST_CONFIG_PATH,
    pins.productionDenylistConfigSha256, POLICY.productionDenylist, 'production');
  const untrusted = await snapshotOutput(reference);
  const scratch = await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'cnyos-static-build-'));
  let removedScratch = false;
  try {
    const materialized = await materialize(snapshot, scratch);
    const configRoot = path.join(scratch, 'config');
    await writeExclusive(path.join(configRoot, 'staging.json'), staging);
    await writeExclusive(path.join(configRoot, 'production.json'), production);
    const launcher = path.join(scratch, 'launch.mjs');
    await writeExclusive(launcher, Buffer.from(LAUNCHER));
    const reproduced = await executeDocker({ ...materialized, scratch, configRoot, launcher,
      snapshot, image: pins.hermeticBuilderImageDigest,
      name: `cnyos-static-${path.basename(scratch).slice('cnyos-static-build-'.length).toLowerCase()}`,
      uid: process.getuid(), gid: process.getgid() }, dockerFactory);
    if (!sameEntries(reproduced, untrusted) || !sameEntries(untrusted, await snapshotOutput(reference))) {
      fail('BYTE_COMPARISON_FAILED');
    }
    const finalSource = readStaticImmutableSource(candidate, snapshot.commit);
    if (finalSource.tree !== snapshot.tree || finalSource.candidateDependencyLockSha256 !== snapshot.candidateDependencyLockSha256) {
      fail('SOURCE_CHANGED');
    }
    // Re-read protected bytes before publication; never trust candidate-produced receipts.
    if (!(await protectedConfig(env.CNYOS_PUBLIC_STAGING_CONFIG_PATH, pins.stagingConfigSha256,
      POLICY.target, 'staging')).equals(staging) ||
      !(await protectedConfig(env.CNYOS_PRODUCTION_DENYLIST_CONFIG_PATH, pins.productionDenylistConfigSha256,
        POLICY.productionDenylist, 'production')).equals(production)) fail('CONFIG_CHANGED');
    const files = reproduced.map(({ path: name, size, sha256: digest }) => ({ path: name, size, sha256: digest }));
    const receipt = {
      schemaVersion: 1, evidenceType: 'cnyos_staging_controller_static_reproducibility',
      status: 'passed', authorization: false, credentialsAvailable: false,
      controllerRepository: runtime.repository, controllerRef: runtime.ref,
      controllerCommit: runtime.commit, controllerRunId: runtime.runId, controllerRunAttempt: 1,
      policySha256: POLICY_SHA256, sourceRepository: POLICY.sourceRepository,
      candidateCommit: snapshot.commit, candidateTree: snapshot.tree,
      untrustedReferenceArtifactDigest: artifactDigest,
      candidateDependencyLockSha256: snapshot.candidateDependencyLockSha256,
      configInputs: { stagingConfigSha256: pins.stagingConfigSha256,
        productionDenylistConfigSha256: pins.productionDenylistConfigSha256 },
      buildEnvironment: { containerImageDigest: pins.hermeticBuilderImageDigest, nodeVersion: '24.20.0',
        networkDisabled: true, lifecycleScriptsDisabled: true, sourceMountedReadOnly: true, isolatedOutput: true },
      staticArtifactSha256: sha256(JSON.stringify(files)), byteForByteMatchWithUntrustedReference: true,
      fileCount: files.length, files, verifiedAt: new Date().toISOString()
    };
    // Successful evidence must never precede container/input cleanup.
    await fs.rm(scratch, { recursive: true, force: true });
    removedScratch = true;
    await fs.mkdir(output, { mode: 0o700 });
    for (const entry of reproduced) await writeExclusive(path.join(output, entry.path), entry.bytes);
    if (!sameEntries(reproduced, await snapshotOutput(output))) fail('OUTPUT_CHANGED');
    const bytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`);
    if (bytes.length > METADATA_LIMIT) fail('RECEIPT_TOO_LARGE');
    // Link a complete same-filesystem temporary file into place: atomic, no replacement.
    const staged = await fs.mkdtemp(path.join(path.dirname(evidence), '.cnyos-static-receipt-'));
    try {
      const filename = path.join(staged, 'receipt.json');
      await writeExclusive(filename, bytes);
      await fs.link(filename, evidence);
    } finally { await fs.rm(staged, { recursive: true, force: true }); }
    return Object.freeze(receipt);
  } finally {
    if (!removedScratch) await fs.rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runControllerStaticReproducibility().then(() => {
    process.stdout.write('CNYOS static reproducibility: passed\n');
  }).catch(error => {
    const code = /^CNYOS_[A-Z0-9_]+$/.test(error?.message || '') ? error.message :
      'CNYOS_STATIC_REPRODUCIBILITY_FAILED';
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
