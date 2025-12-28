/**
 * esbuild Configuration for OIDC Logout Lambda Function
 *
 * Bundles TypeScript source into a single JavaScript file for AWS Lambda deployment.
 * AWS SDK is excluded as it's provided by the Lambda runtime.
 *
 * @see https://esbuild.github.io/api/
 * @see https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
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
