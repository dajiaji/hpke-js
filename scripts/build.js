#!/usr/bin/env node

const { buildSync } = require('esbuild');
const { join } = require('path');

const { dependencies, peerDependencies } = require('../package.json');

const opts = {
  entryPoints: ['src/mod.ts'],
  absWorkingDir: join(__dirname, '..'),
  bundle: true,
  sourcemap: true,
};

const external = Object.keys({ ...dependencies, ...peerDependencies });

try {
  // esm
  buildSync({
    ...opts,
    platform: 'neutral',
    outfile: 'dist/esm/hpke.js',
    external,
  });
  // node
  buildSync({
    ...opts,
    platform: 'node',
    outfile: 'dist/cjs/hpke.js',
    external,
  });
  // browser
  buildSync({
    ...opts,
    platform: 'browser',
    outfile: 'dist/hpke.js',
    globalName: 'hpke',
  });
  // browser-min
  buildSync({
    ...opts,
    platform: 'browser',
    outfile: 'dist/hpke.min.js',
    globalName: 'hpke',
    minify: true,
  });
} catch (err) {
  // esbuild handles error reporting
  process.exitCode = 1;
}
