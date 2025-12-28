# Login Template Requirements

Your `index.html` must include these elements for the OAuth flow to work.

## Required Placeholders

| Placeholder | Type | Description |
|-------------|------|-------------|
| `{{sessionId}}` | string | OAuth session identifier |
| `{{csrfToken}}` | string | CSRF protection token |
| `{{verifyUrl}}` | string | Form submission endpoint |
| `{{brandName}}` | string | Configured brand name |
| `{{error}}` | string? | Error message (optional) |

## Required Form Structure

```html
<form method="POST" action="{{verifyUrl}}">
  <input type="hidden" name="session_id" value="{{sessionId}}">
  <input type="hidden" name="csrf_token" value="{{csrfToken}}">
  <input type="email" name="email" required>
  <input type="password" name="password" required>
  <button type="submit">Sign In</button>
</form>
```

## Error Display

```html
{{#if error}}
<div class="error" role="alert">{{error}}</div>
{{/if}}
```

## Security Requirements

1. Form must use `method="POST"`
2. Form action must be `{{verifyUrl}}`
3. Hidden fields `session_id` and `csrf_token` are mandatory
4. Input names must be exactly `email` and `password`
