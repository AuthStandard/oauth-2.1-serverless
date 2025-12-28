/**
 * esbuild Configuration for TOTP MFA Strategy Lambda Functions
 *
 * Bundles TypeScript handlers with dependencies for AWS Lambda deployment.
 * Uses otplib for TOTP generation/verification and qrcode for QR code generation.
 *
 * @see https://esbuild.github.io/api/
 */

import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: [
        'src/setup.ts',
        'src/verify.ts',
        'src/validate.ts',
        'src/disable.ts',
    ],

    outdir: 'dist',
    bundle: true,

    platform: 'node',
    target: 'node20',
    format: 'cjs',

    minify: true,
    sourcemap: true,

    // Exclude AWS SDK (provided by Lambda runtime)
    external: ['@aws-sdk/*'],

    logLevel: 'info',
});
