/**
 * esbuild Configuration for Lambda Bundling
 *
 * Bundles TypeScript + @oauth-server/shared into a single JS file.
 * AWS SDK is excluded (provided by Lambda runtime).
 *
 * @see https://esbuild.github.io/api/
 */

import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: ['src/index.ts'],
    outfile: 'dist/index.js',
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    minify: true,
    sourcemap: true,
    external: ['@aws-sdk/*'],
    logLevel: 'info',
});
