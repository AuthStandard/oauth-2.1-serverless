/**
 * esbuild Configuration for SAML Strategy Lambda Functions
 *
 * ============================================================================
 * ARCHITECTURE DECISION: Why esbuild?
 * ============================================================================
 *
 * 1. SHARED CODE SUPPORT
 *    - Bundles @oauth-server/shared into the Lambda package
 *    - No Lambda Layers needed - simpler deployment
 *
 * 2. TREE SHAKING
 *    - Only includes code that's actually used
 *    - Smaller bundles = faster cold starts
 *
 * 3. PERFORMANCE
 *    - 10-100x faster than webpack
 *    - Sub-second builds
 *
 * ============================================================================
 * MULTIPLE ENTRY POINTS
 * ============================================================================
 *
 * This strategy has two Lambda handlers:
 *   - metadata.ts → GET  /auth/saml/metadata
 *   - callback.ts → POST /auth/saml/callback
 *
 * Each is bundled separately to keep Lambda packages minimal.
 *
 * @see https://esbuild.github.io/api/
 */

import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: [
        'src/metadata.ts',
        'src/callback.ts',
    ],

    // Output configuration - each entry point gets its own file
    outdir: 'dist',
    bundle: true,

    // Node.js Lambda runtime settings
    platform: 'node',
    target: 'node20',
    format: 'cjs',

    // Optimization
    minify: true,
    sourcemap: true,

    // CRITICAL: Exclude AWS SDK - provided by Lambda runtime
    external: ['@aws-sdk/*'],

    // Better error messages
    logLevel: 'info',
});
