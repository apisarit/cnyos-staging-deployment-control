# Official Docker Hub library/node Linux amd64 manifest, verified 2026-09-10.
# Toolchain acquisition only: no application source is in this build context.
FROM node:24.20.0-bookworm-slim@sha256:6642ef280aebc09c4541bee0b15c9f89f0f3f3c247ddee79ae1d37eddfdcbbaa
WORKDIR /toolchain
COPY package.json package-lock.json ./
RUN test "$(node --version)" = "v24.20.0" \
 && test "$(npm --version)" = "11.19.0" \
 && node --input-type=module -e "import fs from 'node:fs'; import crypto from 'node:crypto'; if (crypto.createHash('sha256').update(fs.readFileSync('package-lock.json')).digest('hex') !== 'f9d030d772c2c1518a1bdc4ceb5124ed8c3d23753d041b964cf1ee783410c286') process.exit(1)" \
 && env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/npm-home \
    NPM_CONFIG_USERCONFIG=/tmp/empty-user.npmrc NPM_CONFIG_GLOBALCONFIG=/tmp/empty-global.npmrc \
    npm ci --ignore-scripts --include=optional --no-audit --no-fund --registry=https://registry.npmjs.org \
 && node --input-type=module -e "import fs from 'node:fs'; const p=JSON.parse(fs.readFileSync('node_modules/@esbuild/linux-x64/package.json')); if(p.version!=='0.28.1'||!fs.statSync('node_modules/@esbuild/linux-x64/bin/esbuild').isFile())process.exit(1)"
COPY build-functions.mjs ./
RUN chmod -R a-w /toolchain
# The runner supplies nonroot UID, empty environment, exact command, isolated
# scratch/output and --network=none. This image alone does not prove isolation.
