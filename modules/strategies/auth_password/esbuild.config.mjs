/**
 * esbuild Configuration for Password Strategy Lambda Functions
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
 *   - login-handler.ts  → GET  /auth/password/login
 *   - verify-handler.ts → POST /auth/password/verify
 *
 * Each is bundled separately to keep Lambda packages minimal.
 *
 * ============================================================================
 * ARGON2 IMPLEMENTATION
 * ============================================================================
 *
 * Uses hash-wasm which is a pure WebAssembly implementation.
 * No native binaries - works on any platform without compilation.
 * The WASM binary is embedded in the bundle.
 *
 * @see https://esbuild.github.io/api/
 */

import * as esbuild from 'esbuild';

await esbuild.build({
    entryPoints: [
        'src/login-handler.ts',
        'src/verify-handler.ts',
        'src/forgot-handler.ts',
        'src/reset-handler.ts',
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
    // hash-wasm is bundled (pure WebAssembly, no native binaries)
    external: ['@aws-sdk/*'],

    // Better error messages
    logLevel: 'info',
});
