/**
 * esbuild Configuration for Lambda Function Bundling
 * 
 * ============================================================================
 * ARCHITECTURE DECISION: Why esbuild?
 * ============================================================================
 * 
 * This project uses esbuild to bundle Lambda functions for several reasons:
 * 
 * 1. SHARED CODE SUPPORT
 *    - Allows importing from @oauth-server/shared without deployment complexity
 *    - All shared utilities are bundled into a single file
 *    - No need to deploy shared module separately or use Lambda Layers
 * 
 * 2. TREE SHAKING
 *    - Only includes code that's actually used
 *    - Reduces bundle size significantly (typically 50-80% smaller)
 *    - Faster cold starts for Lambda functions
 * 
 * 3. PERFORMANCE
 *    - 10-100x faster than webpack or rollup
 *    - Sub-second builds even for large projects
 *    - Enables fast iteration during development
 * 
 * 4. INDUSTRY STANDARD
 *    - Used by AWS SAM, SST, Serverless Framework, AWS CDK
 *    - Well-maintained and battle-tested
 *    - Excellent TypeScript support out of the box
 * 
 * ============================================================================
 * IMPORTANT: DO NOT CHANGE WITHOUT UNDERSTANDING
 * ============================================================================
 * 
 * The configuration below is carefully tuned for AWS Lambda:
 * 
 * - external: @aws-sdk/* 
 *   AWS SDK v3 is provided by Lambda runtime. Excluding it:
 *   - Reduces bundle size by ~2MB
 *   - Ensures compatibility with Lambda's SDK version
 *   - Avoids version conflicts
 * 
 * - platform: node
 *   Targets Node.js runtime (not browser)
 * 
 * - target: node20
 *   Matches Lambda runtime version. Update when changing Lambda runtime.
 * 
 * - format: cjs
 *   CommonJS format required for Lambda (ESM support is limited)
 * 
 * - bundle: true
 *   Bundles all dependencies into single file
 * 
 * - minify: true (production)
 *   Reduces bundle size. Disable for debugging if needed.
 * 
 * - sourcemap: true
 *   Enables stack traces to point to original TypeScript code
 * 
 * ============================================================================
 * MODULE-SPECIFIC: Multiple Entry Points
 * ============================================================================
 * 
 * This module has TWO Lambda handlers:
 *   - index.ts -> GET /.well-known/openid-configuration (provider metadata)
 *   - jwks.ts  -> GET /keys (JSON Web Key Set)
 * 
 * Both are bundled separately but share common code (logger, etc.)
 * which is tree-shaken independently for each bundle.
 * 
 * ============================================================================
 * USAGE
 * ============================================================================
 * 
 * Build:     npm run build
 * Typecheck: npm run typecheck
 * Clean:     npm run clean
 * 
 * Terraform automatically runs `npm install && npm run build` when source
 * files change. See main.tf null_resource.build for details.
 * 
 * @see https://esbuild.github.io/api/
 * @see https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
 */

import * as esbuild from 'esbuild';

// Common build options for all Lambda handlers
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

// Build both Lambda handlers
await Promise.all([
    // GET /.well-known/openid-configuration - Discovery document
    esbuild.build({
        ...commonOptions,
        entryPoints: ['src/index.ts'],
        outfile: 'dist/index.js',
    }),
    
    // GET /keys - JWKS endpoint
    esbuild.build({
        ...commonOptions,
        entryPoints: ['src/jwks.ts'],
        outfile: 'dist/jwks.js',
    }),
]);
