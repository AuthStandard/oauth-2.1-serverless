# Templates

Customizable HTML templates for OAuth Server authentication pages.

## Structure

```
templates/
├── package.json          # Template compiler package
├── bin/
│   └── compile.mjs       # Handlebars precompiler CLI
├── login/
│   ├── index.html        # Login form (Handlebars syntax)
│   └── REQUIRED.md       # Required placeholders
├── error/
│   ├── index.html        # Error page
│   └── REQUIRED.md
└── form-post/
    ├── index.html        # OAuth form_post response
    └── REQUIRED.md
```

## How It Works

1. Templates use [Handlebars](https://handlebarsjs.com/) syntax
2. At build time, templates are precompiled to JavaScript
3. Zero runtime compilation overhead
4. All values are automatically HTML-escaped (XSS protection)

## Customization

Edit the HTML files directly. Use standard Handlebars syntax:

```html
<!-- Simple variable -->
<h1>Welcome, {{brandName}}</h1>

<!-- Conditional -->
{{#if error}}
<div class="error">{{error}}</div>
{{/if}}
```

### Using Your Own Framework

You can use any framework that outputs static HTML:
- Tailwind CSS (inline the built CSS)
- React/Next.js (export as static HTML)
- Vue/Nuxt (export as static HTML)

Just ensure the final `index.html` uses Handlebars placeholders.

## Adding to a Module

1. Add dependency in `package.json`:
```json
"dependencies": {
    "@oauth-server/templates": "file:../../../templates",
    "handlebars": "^4.7.8"
}
```

2. Add prebuild script:
```json
"scripts": {
    "prebuild": "compile-templates --out src/templates --templates login --templates error"
}
```

3. Import in your code:
```typescript
import { render, type LoginData } from './templates/login';

const html = render({
    sessionId: '...',
    csrfToken: '...',
    verifyUrl: '/auth/verify',
    brandName: 'My App',
});
```

## Adding New Templates

1. Create folder: `templates/<name>/`
2. Create `index.html` with Handlebars syntax
3. Create `REQUIRED.md` documenting placeholders
4. Add schema to `bin/compile.mjs` in `TEMPLATE_SCHEMAS`

## CLI Usage

```bash
compile-templates --out <dir> --templates <name1> [--templates name2] ...

# Example
compile-templates --out src/templates --templates login --templates error
```
