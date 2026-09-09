import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// Candidate rehearsal, NOT the protected controller or a deployment authorization.
// Host runs only this reviewed orchestrator. Application inputs execute solely inside
// inspected, credential-free, network-disabled containers. Docker socket is never mounted.
const root = path.dirname(fileURLToPath(import.meta.url));
const names = ['account-access', 'database-backup', 'database-backup-background',
  'database-backup-recovery', 'evidence-search', 'line-oa-webhook', 'owner-drive',
  'owner-subscription', 'patient-identity', 'platform-console', 'restore-source'].sort();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw Error(`CNYOS_BUILD_REHEARSAL_${code}`); };
const childEnv = { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC' };
let scratch;
const ownedContainers = new Set();
let dockerConfig;
function docker(args, timeout = 30_000) {
  try {
    return execFileSync('/usr/bin/docker', ['--host', 'unix:///var/run/docker.sock',
      '--config', dockerConfig, ...args], { env: childEnv, encoding: 'utf8', timeout,
      maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    // JSON-escaped single line prevents candidate output becoming Actions commands.
    // No credentials enter these children, but defensively redact token-like text.
    process.stderr.write(JSON.stringify({ diagnostic: 'isolated-docker-operation',
      operation: args.slice(0, 2).join(' '), exitStatus: error.status ?? null,
      detail: sanitizeDiagnostic(`${error.stderr || ''}\n${error.stdout || ''}`) }) + '\n');
    fail('DOCKER_OPERATION_FAILED');
  }
}
export function sanitizeDiagnostic(text) {
  return String(text).slice(0, 8192).replace(/\u001b\[[0-9;]*[A-Za-z]/g, '')
    .replace(/https?:\/\/[^\s"']+/gi, '[redacted-url]')
    .replace(/\bBearer\s+\S+/gi, 'Bearer [redacted]')
    .replace(/\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)[A-Z0-9_]*)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .replace(/[A-Za-z0-9_+/=-]{48,}/g, '[redacted-long-value]').slice(0, 2048);
}
async function regular(filename, max = 16 * 1024 * 1024) {
  const s = await fs.lstat(filename);
  if (await fs.realpath(filename) !== filename || !s.isFile() || s.isSymbolicLink() ||
    s.nlink !== 1 || s.size < 1 || s.size > max) fail('FILE_INVALID');
  return fs.readFile(filename);
}
async function inventory(directory) {
  const result = []; let total = 0;
  async function walk(current, relative = '') {
    if (await fs.realpath(current) !== current || !(await fs.lstat(current)).isDirectory()) {
      fail('OUTPUT_DIRECTORY_INVALID');
    }
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const item of entries.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      if (!/^[A-Za-z0-9_@.+-]+$/.test(item.name)) fail('OUTPUT_PATH_INVALID');
      const p = path.join(current, item.name); const rel = relative + item.name;
      if (item.isDirectory()) await walk(p, rel + '/');
      else if (item.isFile() && !item.isSymbolicLink()) {
        const bytes = await regular(p);
        total += bytes.length;
        if (total > 64 * 1024 * 1024 || result.length >= 4096) fail('OUTPUT_LIMIT');
        result.push({ path: rel, size: bytes.length, sha256: hash(bytes) });
      } else fail('OUTPUT_TYPE_INVALID');
    }
  }
  if (!(await fs.lstat(directory)).isDirectory()) fail('OUTPUT_DIRECTORY_INVALID');
  await walk(directory);
  if (JSON.stringify([...new Set(result.map(x => x.path.split('/')[0]))].sort()) !==
    JSON.stringify(names)) fail('FUNCTION_SET_INVALID');
  return result.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
async function main() {
  if (process.platform !== 'linux' || process.arch !== 'x64' || process.getuid() <= 0) {
    fail('LINUX_NONROOT_HOST_REQUIRED');
  }
  const uid = process.getuid(); const gid = process.getgid();
  const binary = await fs.lstat('/usr/bin/docker');
  const socket = await fs.stat('/var/run/docker.sock');
  if (!binary.isFile() || binary.isSymbolicLink() || binary.uid !== 0 ||
    (binary.mode & 0o022) || !socket.isSocket() || socket.uid !== 0 || (socket.mode & 0o002)) {
    fail('DOCKER_BOUNDARY_INVALID');
  }
  scratch = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'cnyos-build-rehearsal-'));
  dockerConfig = path.join(scratch, 'docker-config');
  await fs.mkdir(dockerConfig, { mode: 0o700 });
  await fs.writeFile(path.join(dockerConfig, 'config.json'), '{}\n', { flag: 'wx', mode: 0o600 });

  // Closed minimal image-build context: never send application inputs or checkout .git.
  const context = path.join(scratch, 'toolchain');
  await fs.mkdir(context, { mode: 0o700 });
  for (const name of ['Dockerfile', '.dockerignore', 'package.json', 'package-lock.json', 'build-functions.mjs']) {
    await fs.writeFile(path.join(context, name), await regular(path.join(root, name)),
      { flag: 'wx', mode: 0o444 });
  }
  const manifestBytes = await regular(path.join(root, 'input-manifest.json'), 64 * 1024);
  if (hash(manifestBytes) !== '03d815265f93d4dc25d73d7614e931bcbb3b91054f882d8aa43d9f5b34981e1f') {
    fail('INPUT_MANIFEST_DIGEST_MISMATCH');
  }
  const manifest = JSON.parse(manifestBytes);
  if (manifest.schema !== 'cnyos-function-source-input/v1' ||
    manifest.declaredGitCommit !== 'dc6c8c776909ed8a3280765d7232ed8eacba955c' ||
    !Array.isArray(manifest.files) || manifest.files.length !== 21) fail('INPUT_MANIFEST_INVALID');
  const input = path.join(scratch, 'input');
  await fs.mkdir(path.join(input, 'source'), { recursive: true, mode: 0o700 });
  let previous = '';
  for (const item of manifest.files) {
    if (typeof item.path !== 'string' || item.path <= previous ||
      !/^(netlify\/functions\/[a-z-]+\.mts|netlify\/functions\/_shared\/[a-z-]+\.mjs|platform-config\.js)$/.test(item.path) ||
      !/^[0-9a-f]{64}$/.test(item.sha256)) fail('INPUT_MANIFEST_INVALID');
    previous = item.path;
    const bytes = await regular(path.join(root, 'input-source', item.path));
    if (hash(bytes) !== item.sha256) fail('INPUT_DIGEST_MISMATCH');
    const dest = path.join(input, 'source', item.path);
    await fs.mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
    await fs.writeFile(dest, bytes, { flag: 'wx', mode: 0o444 });
  }
  await fs.writeFile(path.join(input, 'input-manifest.json'), manifestBytes, { flag: 'wx', mode: 0o444 });
  // Network is permitted ONLY to acquire pinned public toolchain dependencies here;
  // no app input or credential is part of this build context or Docker client env.
  const image = docker(['build', '--quiet', '--pull=false', '--no-cache', '--platform=linux/amd64', context], 600_000);
  if (!/^sha256:[0-9a-f]{64}$/.test(image)) fail('IMAGE_ID_INVALID');
  const [imageInfo] = JSON.parse(docker(['image', 'inspect', image]));
  if (imageInfo.Id !== image || imageInfo.Os !== 'linux' || imageInfo.Architecture !== 'amd64') fail('IMAGE_INVALID');
  const outputs = [];
  for (let run = 0; run < 2; run++) {
    const output = path.join(scratch, `output-${run}`);
    await fs.mkdir(output, { mode: 0o700 });
    const containerName = `cnyos-function-rehearsal-${randomBytes(12).toString('hex')}`;
    const args = ['container', 'create', '--name', containerName, '--pull=never', '--platform=linux/amd64',
      '--network=none', '--read-only', '--user', `${uid}:${gid}`, '--cap-drop=ALL',
      '--security-opt=no-new-privileges=true', '--pids-limit=128', '--memory=2147483648',
      '--memory-swap=2147483648', '--cpus=2', '--restart=no', '--no-healthcheck',
      '--log-driver=none', '--ipc=none', '--cgroupns=private', '--stop-timeout=1',
      '--tmpfs', '/work:rw,nosuid,nodev,noexec,size=1073741824,mode=1777',
      '--mount', `type=bind,source=${input},target=/input,readonly,bind-propagation=rprivate`,
      '--mount', `type=bind,source=${output},target=/output,bind-propagation=rprivate`,
      '--entrypoint=/usr/bin/env', image, '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
      'LANG=C', 'LC_ALL=C', 'TZ=UTC', 'HOME=/work', 'TMPDIR=/work',
      '/usr/local/bin/node', '/toolchain/build-functions.mjs', '--source', '/input/source',
      '--input-manifest', '/input/input-manifest.json', '--output', '/output/result'];
    const id = docker(args);
    if (!/^[0-9a-f]{64}$/.test(id)) fail('CONTAINER_ID_INVALID');
    ownedContainers.add(id);
    const [info] = JSON.parse(docker(['container', 'inspect', id]));
    const h = info.HostConfig; const c = info.Config;
    if (info.Image !== image || info.State.Status !== 'created' || h.NetworkMode !== 'none' ||
      h.ReadonlyRootfs !== true || h.Privileged !== false || c.User !== `${uid}:${gid}` ||
      JSON.stringify(h.CapDrop) !== '["ALL"]' || h.CapAdd?.length ||
      JSON.stringify(h.SecurityOpt) !== '["no-new-privileges=true"]' ||
      h.Memory !== 2147483648 || h.MemorySwap !== 2147483648 || h.NanoCpus !== 2_000_000_000 ||
      h.PidsLimit !== 128 || h.IpcMode !== 'none' || h.PidMode || h.CgroupnsMode !== 'private' ||
      h.PublishAllPorts !== false || Object.keys(h.PortBindings || {}).length ||
      h.Devices?.length || h.DeviceRequests?.length || h.VolumesFrom?.length ||
      h.RestartPolicy.Name !== 'no' || h.LogConfig.Type !== 'none' ||
      JSON.stringify(h.Tmpfs) !== JSON.stringify({ '/work': 'rw,nosuid,nodev,noexec,size=1073741824,mode=1777' }) ||
      JSON.stringify(c.Entrypoint) !== '["/usr/bin/env"]' ||
      JSON.stringify(c.Cmd) !== JSON.stringify(args.slice(args.indexOf(image) + 1)) ||
      info.Mounts.filter(m => m.Type === 'bind').length !== 2 ||
      info.Mounts.length > 3 || info.Mounts.some(m => m.Type === 'tmpfs' ?
        (m.Destination !== '/work' || m.RW !== true || m.Source) :
        (m.Type !== 'bind' || m.Propagation !== 'rprivate' ||
        !((m.Source === input && m.Destination === '/input' && m.RW === false) ||
        (m.Source === output && m.Destination === '/output' && m.RW === true))))) fail('ISOLATION_INVALID');
    docker(['container', 'start', '--attach', id], 300_000); // Capture, never forward candidate logs.
    const [after] = JSON.parse(docker(['container', 'inspect', id]));
    if (after.State.Status !== 'exited' || after.State.ExitCode !== 0 || after.State.OOMKilled ||
      after.State.Error) fail('BUILD_FAILED');
    outputs.push(await inventory(path.join(output, 'result', 'functions')));
    docker(['container', 'rm', id]);
    ownedContainers.delete(id);
  }
  if (JSON.stringify(outputs[0]) !== JSON.stringify(outputs[1])) {
    const left = new Map(outputs[0].map(file => [file.path, file]));
    const right = new Map(outputs[1].map(file => [file.path, file]));
    const differing = [...new Set([...left.keys(), ...right.keys()])].sort()
      .filter(name => JSON.stringify(left.get(name)) !== JSON.stringify(right.get(name)));
    process.stderr.write(JSON.stringify({ diagnostic: 'build-bytes-differ',
      differingFileCount: differing.length,
      firstDifferences: differing.slice(0, 10).map(name => ({ path: name,
        first: left.get(name) ?? null, second: right.get(name) ?? null })) }) + '\n');
    fail('BUILD_BYTES_DIFFER');
  }
  return { kind: 'candidate-function-build-rehearsal',
    authorization: false, productionAuthorization: false, controllerActivation: false,
    independentReview: false, runtimeExecutionTested: false, comparison: 'equal',
    outputDiskQuotaEnforced: false,
    imageId: image, inputManifestSha256: hash(manifestBytes), declaredSourceCommit: manifest.declaredGitCommit,
    functionCount: names.length, fileCount: outputs[0].length,
    outputInventorySha256: hash(JSON.stringify(outputs[0])) };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
let summary;
try { summary = await main(); }
catch (error) {
  const code = /^CNYOS_BUILD_REHEARSAL_[A-Z_]+$/.test(error.message) ? error.message : 'CNYOS_BUILD_REHEARSAL_FAILED';
  process.stderr.write(code + '\n'); process.exitCode = 1;
} finally {
  for (const id of ownedContainers) {
    try { docker(['container', 'rm', '--force', id]); }
    catch { process.stderr.write('CNYOS_BUILD_REHEARSAL_CLEANUP_FAILED\n'); process.exitCode = 1; }
  }
  try { if (scratch) await fs.rm(scratch, { recursive: true, force: true }); }
  catch { process.stderr.write('CNYOS_BUILD_REHEARSAL_SCRATCH_CLEANUP_FAILED\n'); process.exitCode = 1; }
}
if (summary && process.exitCode !== 1) process.stdout.write(JSON.stringify(summary) + '\n');
}
