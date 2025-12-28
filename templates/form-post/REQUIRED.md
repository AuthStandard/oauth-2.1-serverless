# Form Post Template Requirements

This template is used for OAuth 2.0 Form Post Response Mode.
It auto-submits a form to send authorization response parameters.

**Most users don't need to customize this** - it's only visible for a split second.

## Required Placeholders

| Placeholder | Description |
|-------------|-------------|
| `{{REDIRECT_URI}}` | Client's redirect URI (form action) |
| `{{HIDDEN_FIELDS}}` | Pre-rendered hidden input fields |

## Required Structure

```html
<body onload="document.forms[0].submit()">
  <form method="POST" action="{{REDIRECT_URI}}">
    {{HIDDEN_FIELDS}}
    <noscript>
      <button type="submit">Continue</button>
    </noscript>
  </form>
</body>
```

## Security Requirements

1. Form must use `method="POST"`
2. Form action must be `{{REDIRECT_URI}}`
3. Must include `{{HIDDEN_FIELDS}}` inside the form
4. Must auto-submit via `onload="document.forms[0].submit()"`
5. Must have noscript fallback button

## Why Auto-Submit?

Per OAuth 2.0 Form Post Response Mode specification, the page should
automatically submit the form via JavaScript. The button is only shown
if JavaScript is disabled.

Users should never see this page - it flashes for milliseconds during redirect.
