/**
 * esbuild Configuration for Client Registry Lambda
 * 
 * Bundles RFC 7591/7592 Dynamic Client Registration endpoint.
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
