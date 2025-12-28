/**
 * SCIM v2 User Provisioning - esbuild Configuration
 *
 * Bundles TypeScript source into a single JavaScript file for Lambda deployment.
 * Includes @oauth-server/shared module in the bundle (no Lambda Layers needed).
 */

import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: ['src/index.ts'],
    bundle: true,
    platform: 'node',
    target: 'node20',
    outfile: 'dist/index.js',
    format: 'cjs',
    sourcemap: true,
    minify: false,
    // Externalize AWS SDK (provided by Lambda runtime)
    external: [
        '@aws-sdk/client-dynamodb',
        '@aws-sdk/lib-dynamodb',
    ],
});

console.log('Build complete: dist/index.js');
