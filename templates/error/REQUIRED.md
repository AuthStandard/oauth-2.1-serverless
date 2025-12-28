# Error Template Requirements

Your `index.html` must include these placeholders for error display.

## Required Placeholders

| Placeholder | Description | Example Value |
|-------------|-------------|---------------|
| `{{TITLE}}` | Error page title | `Something went wrong` |
| `{{MESSAGE}}` | User-friendly error message | `Your session has expired.` |
| `{{ERROR_CODE}}` | Technical error code (optional) | `session_expired` |
| `{{BRAND_NAME}}` | Configured brand name | `My Company` |

## Optional Elements

### Return Link

If you want to show a "Try Again" link:

```html
{{#RETURN_URL}}
<a href="{{RETURN_URL}}">Try Again</a>
{{/RETURN_URL}}
```

### Error Code Display

Show technical error code for debugging:

```html
{{#ERROR_CODE}}
<p class="error-code">Error: {{ERROR_CODE}}</p>
{{/ERROR_CODE}}
```

## Example Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <title>{{TITLE}} - {{BRAND_NAME}}</title>
</head>
<body>
  <h1>{{TITLE}}</h1>
  <p>{{MESSAGE}}</p>
  
  {{#ERROR_CODE}}
  <p><code>{{ERROR_CODE}}</code></p>
  {{/ERROR_CODE}}
  
  {{#RETURN_URL}}
  <a href="{{RETURN_URL}}">Try Again</a>
  {{/RETURN_URL}}
</body>
</html>
```

## Example

See the default `index.html` in this folder for a complete working example.
