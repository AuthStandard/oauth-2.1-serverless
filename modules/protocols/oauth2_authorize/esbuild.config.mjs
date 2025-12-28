/**
 * esbuild Configuration for Lambda Bundling
 *
 * Bundles TypeScript to JavaScript for AWS Lambda deployment.
 * Terraform triggers this via null_resource when source files change.
 *
 * Key settings:
 * - external: @aws-sdk/* (provided by Lambda runtime)
 * - target: node20 (matches Lambda runtime)
 * - format: cjs (Lambda requirement)
 * - minify: true (smaller bundles, faster cold starts)
 * - sourcemap: true (debugging support)
 */

import * as esbuild from 'esbuild';

const commonOptions = {
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    minify: true,
    sourcemap: true,
    external: ['@aws-sdk/*'],
    logLevel: 'info',
};

await Promise.all([
    esbuild.build({
        ...commonOptions,
        entryPoints: ['src/index.ts'],
        outfile: 'dist/index.js',
    }),
    esbuild.build({
        ...commonOptions,
        entryPoints: ['src/callback.ts'],
        outfile: 'dist/callback.js',
    }),
]);
