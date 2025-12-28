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

await esbuild.build({
    // Entry point - the Lambda handler
    entryPoints: ['src/index.ts'],
    
    // Output configuration
    outfile: 'dist/index.js',
    bundle: true,
    
    // Node.js Lambda runtime settings
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    
    // Optimization
    minify: true,
    sourcemap: true,
    
    // CRITICAL: Exclude AWS SDK - it's provided by Lambda runtime
    // This reduces bundle size by ~2MB and avoids version conflicts
    external: ['@aws-sdk/*'],
    
    // Better error messages
    logLevel: 'info',
});
