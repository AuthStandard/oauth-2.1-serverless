#!/usr/bin/env node
/**
 * Handlebars Template Compiler
 *
 * Precompiles HTML templates into TypeScript modules with type-safe render functions.
 * Templates are compiled at build time for zero runtime overhead.
 *
 * Usage:
 *   compile-templates --out <dir> --templates <name1> [name2] ...
 *
 * Example:
 *   compile-templates --out src/templates --templates login error
 *
 * Output:
 *   Creates TypeScript files with precompiled Handlebars templates.
 *   Each file exports a typed `render(data)` function.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import Handlebars from 'handlebars';

// =============================================================================
// Configuration
// =============================================================================

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_ROOT = resolve(__dirname, '..');

/**
 * Template metadata: defines the TypeScript interface for each template.
 * Add new templates here when creating them.
 */
const TEMPLATE_SCHEMAS = {
    login: {
        interface: `{
    /** OAuth session identifier */
    sessionId: string;
    /** CSRF protection token */
    csrfToken: string;
    /** Form submission URL */
    verifyUrl: string;
    /** Brand name displayed in UI */
    brandName: string;
    /** Error message to display (optional) */
    error?: string;
}`,
        description: 'Login form template',
    },
    error: {
        interface: `{
    /** Error page title */
    title: string;
    /** User-friendly error message */
    message: string;
    /** Brand name displayed in UI */
    brandName: string;
    /** Technical error code (optional) */
    errorCode?: string;
    /** URL to retry the action (optional) */
    returnUrl?: string;
}`,
        description: 'Error page template',
    },
    'form-post': {
        interface: `{
    /** Client redirect URI */
    redirectUri: string;
    /** Pre-rendered hidden input fields HTML */
    hiddenFields: string;
}`,
        description: 'OAuth form_post response template',
    },
};

// =============================================================================
// CLI Argument Parsing
// =============================================================================

function parseCliArgs() {
    const { values } = parseArgs({
        options: {
            out: { type: 'string', short: 'o' },
            templates: { type: 'string', multiple: true, short: 't' },
            help: { type: 'boolean', short: 'h' },
        },
        allowPositionals: false,
    });

    if (values.help) {
        printUsage();
        process.exit(0);
    }

    if (!values.out) {
        console.error('Error: --out <directory> is required');
        printUsage();
        process.exit(1);
    }

    if (!values.templates || values.templates.length === 0) {
        console.error('Error: --templates <name> is required');
        printUsage();
        process.exit(1);
    }

    return {
        outputDir: values.out,
        templateNames: values.templates,
    };
}

function printUsage() {
    console.log(`
Usage: compile-templates --out <dir> --templates <name1> [--templates name2] ...

Options:
  -o, --out <dir>        Output directory for compiled templates
  -t, --templates <name> Template name(s) to compile (can be repeated)
  -h, --help             Show this help message

Available templates: ${Object.keys(TEMPLATE_SCHEMAS).join(', ')}

Example:
  compile-templates --out src/templates --templates login --templates error
`);
}

// =============================================================================
// Template Compilation
// =============================================================================

function compileTemplate(name) {
    const schema = TEMPLATE_SCHEMAS[name];
    if (!schema) {
        throw new Error(`Unknown template: ${name}. Available: ${Object.keys(TEMPLATE_SCHEMAS).join(', ')}`);
    }

    const htmlPath = join(TEMPLATES_ROOT, name, 'index.html');
    if (!existsSync(htmlPath)) {
        throw new Error(`Template file not found: ${htmlPath}`);
    }

    let html = readFileSync(htmlPath, 'utf8');

    // Inline external CSS if styles.css exists
    const cssPath = join(TEMPLATES_ROOT, name, 'styles.css');
    if (existsSync(cssPath)) {
        const css = readFileSync(cssPath, 'utf8').trim();
        // Inject before </head> or at end of <head>
        if (html.includes('</head>')) {
            html = html.replace('</head>', `  <style>\n${css}\n  </style>\n</head>`);
        }
        console.log(`    + Inlined styles.css`);
    }

    // Validate required Handlebars syntax
    validateTemplate(name, html);

    // Precompile to JavaScript
    const precompiled = Handlebars.precompile(html, {
        strict: true,
        assumeObjects: true,
    });

    // Generate TypeScript interface name
    const interfaceName = name
        .split('-')
        .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
        .join('') + 'Data';

    return {
        name,
        interfaceName,
        interface: schema.interface,
        description: schema.description,
        precompiled,
    };
}

function validateTemplate(name, html) {
    // Check for DOCTYPE
    if (!html.includes('<!DOCTYPE html>')) {
        console.warn(`Warning [${name}]: Missing <!DOCTYPE html>`);
    }

    // Check for lang attribute
    if (!/<html[^>]*lang=/.test(html)) {
        console.warn(`Warning [${name}]: Missing lang attribute on <html>`);
    }
}

function generateTypeScript(compiled) {
    return `// @ts-nocheck
/**
 * Precompiled Handlebars Template: ${compiled.name}
 * ${compiled.description}
 *
 * Source: templates/${compiled.name}/index.html
 * Generated by @oauth-server/templates
 *
 * DO NOT EDIT THIS FILE DIRECTLY
 */

import Handlebars from 'handlebars';

/** Template data for ${compiled.name} */
export type ${compiled.interfaceName} = ${compiled.interface};

const templateSpec = ${compiled.precompiled};
const template = Handlebars.template(templateSpec);

/**
 * Render the ${compiled.name} template.
 * All string values are automatically HTML-escaped by Handlebars.
 */
export function render(data: ${compiled.interfaceName}): string {
    return template(data);
}
`;
}

// =============================================================================
// Main
// =============================================================================

function main() {
    const { outputDir, templateNames } = parseCliArgs();

    console.log(`Compiling templates to ${outputDir}/`);

    // Create output directory
    mkdirSync(outputDir, { recursive: true });

    let hasErrors = false;

    for (const name of templateNames) {
        try {
            const compiled = compileTemplate(name);
            const tsCode = generateTypeScript(compiled);
            const outputPath = join(outputDir, `${name}.ts`);

            writeFileSync(outputPath, tsCode, 'utf8');
            console.log(`  ✓ ${name} -> ${outputPath}`);
        } catch (err) {
            console.error(`  ✗ ${name}: ${err.message}`);
            hasErrors = true;
        }
    }

    if (hasErrors) {
        process.exit(1);
    }

    console.log('Done');
}

main();
