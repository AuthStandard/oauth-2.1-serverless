/**
 * OAuth 2.1 Test App - Client-side JavaScript
 * 
 * Implements all OAuth 2.1 flows for manual testing.
 */

// =============================================================================
// Configuration
// =============================================================================

let config = {
    apiBaseUrl: '',
    clientId: '',
    clientSecret: '',
    // Detect redirect URI based on current path
    redirectUri: window.location.origin + window.location.pathname.replace(/index\.html$/, '').replace(/\/$/, '') + '/callback.html',
    scopes: 'openid profile email offline_access',
};

// Token storage
let tokens = {
    accessToken: null,
    refreshToken: null,
    idToken: null,
    expiresAt: null,
};

// Results log
const results = [];

// =============================================================================
// PKCE Helpers
// =============================================================================

function generateRandomString(length = 64) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('').slice(0, length);
}

function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// API Helpers
// =============================================================================

async function apiRequest(endpoint, options = {}) {
    const url = config.apiBaseUrl + endpoint;
    const startTime = Date.now();

    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
            },
        });

        const contentType = response.headers.get('content-type');
        let data;
        if (contentType?.includes('application/json')) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        const result = {
            success: response.ok,
            status: response.status,
            data,
            duration: Date.now() - startTime,
            timestamp: new Date().toISOString(),
            endpoint,
        };

        logResult(result);
        return result;
    } catch (error) {
        const result = {
            success: false,
            error: error.message,
            duration: Date.now() - startTime,
            timestamp: new Date().toISOString(),
            endpoint,
        };
        logResult(result);
        return result;
    }
}

function logResult(result) {
    results.unshift(result);
    if (results.length > 20) results.pop();
    renderResults();
}

// Loading state helper
async function runFlow(button, flowFn) {
    const originalContent = button.innerHTML;
    button.innerHTML = '<span class="spinner"></span> Loading...';
    button.classList.add('loading');

    try {
        await flowFn();
    } finally {
        button.innerHTML = originalContent;
        button.classList.remove('loading');
    }
}

// =============================================================================
// OAuth Flows
// =============================================================================

async function startAuthorizationFlow(options = {}) {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const state = generateRandomString(32);
    const nonce = generateRandomString(32);

    // Store in sessionStorage for callback
    sessionStorage.setItem('oauth_verifier', verifier);
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_nonce', nonce);
    sessionStorage.setItem('oauth_redirect_uri', config.redirectUri);

    const params = new URLSearchParams({
        response_type: 'code',
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        scope: config.scopes,
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256',
    });

    if (options.prompt) params.set('prompt', options.prompt);
    if (options.maxAge !== undefined) params.set('max_age', options.maxAge);
    if (options.loginHint) params.set('login_hint', options.loginHint);

    const authUrl = config.apiBaseUrl + '/authorize?' + params.toString();
    window.location.href = authUrl;
}

async function exchangeCodeForTokens(code) {
    const verifier = sessionStorage.getItem('oauth_verifier');

    const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.redirectUri,
        client_id: config.clientId,
        code_verifier: verifier,
    });

    // Add client secret for confidential clients
    if (config.clientSecret) {
        body.set('client_secret', config.clientSecret);
    }

    const result = await apiRequest('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });

    if (result.success && result.data) {
        tokens.accessToken = result.data.access_token;
        tokens.refreshToken = result.data.refresh_token;
        tokens.idToken = result.data.id_token;
        tokens.expiresAt = Date.now() + (result.data.expires_in * 1000);
        saveTokens();
        renderTokens();
    }

    // Clean up
    sessionStorage.removeItem('oauth_verifier');
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_nonce');

    return result;
}

async function refreshAccessToken() {
    if (!tokens.refreshToken) {
        logResult({ success: false, error: 'No refresh token available', endpoint: '/token' });
        return;
    }

    const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refreshToken,
        client_id: config.clientId,
    });

    if (config.clientSecret) {
        body.set('client_secret', config.clientSecret);
    }

    const result = await apiRequest('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });

    if (result.success && result.data) {
        tokens.accessToken = result.data.access_token;
        if (result.data.refresh_token) {
            tokens.refreshToken = result.data.refresh_token;
        }
        tokens.expiresAt = Date.now() + (result.data.expires_in * 1000);
        saveTokens();
        renderTokens();
    }

    return result;
}

async function clientCredentialsFlow() {
    if (!config.clientSecret) {
        logResult({ success: false, error: 'Client secret required for this flow', endpoint: '/token' });
        return;
    }

    const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: 'openid',
    });

    const result = await apiRequest('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });

    if (result.success && result.data) {
        tokens.accessToken = result.data.access_token;
        tokens.expiresAt = Date.now() + (result.data.expires_in * 1000);
        saveTokens();
        renderTokens();
    }

    return result;
}

async function getUserInfo() {
    if (!tokens.accessToken) {
        logResult({ success: false, error: 'No access token available', endpoint: '/userinfo' });
        return;
    }

    return await apiRequest('/userinfo', {
        headers: { 'Authorization': `Bearer ${tokens.accessToken}` },
    });
}

async function introspectToken(token) {
    if (!config.clientSecret) {
        logResult({ success: false, error: 'Client secret required for introspection', endpoint: '/introspect' });
        return;
    }

    const body = new URLSearchParams({
        token: token || tokens.accessToken,
        client_id: config.clientId,
        client_secret: config.clientSecret,
    });

    return await apiRequest('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });
}

async function revokeToken(tokenType = 'access') {
    const token = tokenType === 'refresh' ? tokens.refreshToken : tokens.accessToken;

    if (!token) {
        logResult({ success: false, error: `No ${tokenType} token available`, endpoint: '/revoke' });
        return;
    }

    const body = new URLSearchParams({
        token,
        token_type_hint: tokenType === 'refresh' ? 'refresh_token' : 'access_token',
        client_id: config.clientId,
    });

    if (config.clientSecret) {
        body.set('client_secret', config.clientSecret);
    }

    const result = await apiRequest('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });

    if (result.success) {
        if (tokenType === 'refresh') {
            tokens.refreshToken = null;
        } else {
            tokens.accessToken = null;
        }
        saveTokens();
        renderTokens();
    }

    return result;
}

async function logout() {
    const params = new URLSearchParams();
    if (tokens.idToken) {
        params.set('id_token_hint', tokens.idToken);
    }
    params.set('post_logout_redirect_uri', window.location.origin + '/tests/webapp/');

    // Clear tokens
    tokens = { accessToken: null, refreshToken: null, idToken: null, expiresAt: null };
    saveTokens();

    window.location.href = config.apiBaseUrl + '/connect/logout?' + params.toString();
}

async function fetchDiscovery() {
    return await apiRequest('/.well-known/openid-configuration');
}

async function fetchJwks() {
    return await apiRequest('/keys');
}

// =============================================================================
// Storage
// =============================================================================

function saveConfig() {
    localStorage.setItem('oauth_test_config', JSON.stringify(config));
}

function loadConfig() {
    const saved = localStorage.getItem('oauth_test_config');
    if (saved) {
        const parsed = JSON.parse(saved);
        // Don't restore redirectUri - always calculate from current path
        config.apiBaseUrl = parsed.apiBaseUrl || '';
        config.clientId = parsed.clientId || '';
        config.clientSecret = parsed.clientSecret || '';
        config.scopes = parsed.scopes || 'openid profile email';
    }
    // Always set redirectUri based on current location
    config.redirectUri = window.location.origin + window.location.pathname.replace(/index\.html$/, '').replace(/\/$/, '') + '/callback.html';
}

function saveTokens() {
    localStorage.setItem('oauth_test_tokens', JSON.stringify(tokens));
}

function loadTokens() {
    const saved = localStorage.getItem('oauth_test_tokens');
    if (saved) {
        tokens = JSON.parse(saved);
    }
}

function clearAll() {
    tokens = { accessToken: null, refreshToken: null, idToken: null, expiresAt: null };
    localStorage.removeItem('oauth_test_tokens');
    renderTokens();
    logResult({ success: true, data: 'Tokens cleared', endpoint: 'local' });
}

// =============================================================================
// UI Rendering
// =============================================================================

function renderConfig() {
    document.getElementById('apiBaseUrl').value = config.apiBaseUrl;
    document.getElementById('clientId').value = config.clientId;
    document.getElementById('clientSecret').value = config.clientSecret;
    document.getElementById('scopes').value = config.scopes;
}

function renderTokens() {
    const container = document.getElementById('tokenDisplay');

    if (!tokens.accessToken && !tokens.refreshToken && !tokens.idToken) {
        container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <p>No tokens yet. Start an authorization flow to get tokens.</p>
      </div>
    `;
        return;
    }

    container.innerHTML = `
    <div class="token-display">
      <h3>Current Tokens</h3>
      ${tokens.accessToken ? `
        <div class="token-item">
          <label>Access Token:</label>
          <code>${tokens.accessToken.substring(0, 50)}...</code>
        </div>
      ` : ''}
      ${tokens.refreshToken ? `
        <div class="token-item">
          <label>Refresh Token:</label>
          <code>${tokens.refreshToken.substring(0, 30)}...</code>
        </div>
      ` : ''}
      ${tokens.idToken ? `
        <div class="token-item">
          <label>ID Token:</label>
          <code>${tokens.idToken.substring(0, 50)}...</code>
        </div>
      ` : ''}
      ${tokens.expiresAt ? `
        <div class="token-item">
          <label>Expires:</label>
          <code>${new Date(tokens.expiresAt).toLocaleTimeString()}</code>
        </div>
      ` : ''}
      <button onclick="clearAll()" style="margin-top: 0.75rem; padding: 0.5rem 1rem; background: #b91c1c; color: white; border: none; border-radius: 4px; font-size: 0.75rem; cursor: pointer;">Clear Tokens</button>
    </div>
  `;
}

function renderResults() {
    const container = document.getElementById('resultsContainer');

    if (results.length === 0) {
        container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
          <line x1="16" y1="13" x2="8" y2="13"/>
          <line x1="16" y1="17" x2="8" y2="17"/>
          <polyline points="10 9 9 9 8 9"/>
        </svg>
        <p>No results yet. Run a flow to see the response.</p>
      </div>
    `;
        return;
    }

    container.innerHTML = results.map(r => `
    <div class="result-card">
      <div class="result-header">
        <div>
          <span class="status ${r.success ? 'success' : 'error'}">${r.success ? 'SUCCESS' : 'ERROR'}</span>
          <span style="margin-left: 0.5rem; font-size: 0.8125rem;">${r.endpoint}</span>
          ${r.status ? `<span style="margin-left: 0.5rem; font-size: 0.75rem; color: var(--text-muted);">(${r.status})</span>` : ''}
        </div>
        <span class="timestamp">${new Date(r.timestamp).toLocaleTimeString()} · ${r.duration}ms</span>
      </div>
      <div class="result-body">
        <pre>${JSON.stringify(r.data || r.error, null, 2)}</pre>
      </div>
    </div>
  `).join('');
}

// =============================================================================
// Event Handlers
// =============================================================================

function updateConfig() {
    config.apiBaseUrl = document.getElementById('apiBaseUrl').value.replace(/\/$/, '');
    config.clientId = document.getElementById('clientId').value;
    config.clientSecret = document.getElementById('clientSecret').value;
    config.scopes = document.getElementById('scopes').value;
    saveConfig();

    // Show visual feedback
    const btn = document.querySelector('.config-section button');
    const originalText = btn.textContent;
    btn.textContent = '✓ Saved!';
    btn.style.background = '#059669';
    setTimeout(() => {
        btn.textContent = originalText;
        btn.style.background = '';
    }, 2000);

    logResult({ success: true, data: { apiBaseUrl: config.apiBaseUrl, clientId: config.clientId, scopes: config.scopes, redirectUri: config.redirectUri }, endpoint: 'config' });
}

// =============================================================================
// Initialization
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    loadConfig();
    loadTokens();
    renderConfig();
    renderTokens();
    renderResults();
});

// Export for use in callback
window.exchangeCodeForTokens = exchangeCodeForTokens;
