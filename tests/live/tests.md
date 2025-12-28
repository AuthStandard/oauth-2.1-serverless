# AuthServer Test Suite

## Category 1: Infrastructure & Discovery
*Ensures the server speaks the correct language and protects itself.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **INF-01** | **OIDC Discovery Integrity** | GET `/.well-known/openid-configuration` | 200 OK. JSON `issuer` must match the API Domain exactly (no trailing slash mismatches). | Prevents Issuer Mismatch attacks. |
| **INF-02** | **JWKS Caching Headers** | GET `/keys` | 200 OK. Headers: `Cache-Control: public, max-age=...`. | Prevents KMS throttling/DoS. |
| **INF-03** | **JWKS Key ID Rotation** | GET `/keys` | Response must contain `kid` (Key ID). | Essential for key rotation support. |
| **INF-04** | **HTTP Method Check** | POST `/.well-known/openid-configuration` | 405 Method Not Allowed. | RFC strictness. |
| **INF-05** | **Large Payload DoS** | POST `/token` with 10MB JSON body. | 413 Payload Too Large (API Gateway should block this). | Prevents Lambda cost explosion. |
| **INF-06** | **CORS Wildcard Block** | OPTIONS `/token` with `Origin: https://evil.com` | Access-Control-Allow-Origin != `*`. | Prevents browser-based attacks. |
| **INF-07** | **Security Headers (HSTS)** | GET `/authorize` | Header `Strict-Transport-Security` present. | Prevents downgrade attacks. |
| **INF-08** | **Security Headers (Frame)**| GET `/authorize` | Header `X-Frame-Options: DENY` (or SAMEORIGIN). | Prevents Clickjacking/UI Redress. |
| **INF-09** | **AWS Trace ID** | Any Request | Logs must contain `x-amzn-trace-id`. | Required for debugging distributed traces. |
| **INF-10** | **Rate Limit Burst** | Send 5001 requests in 1s. | 429 Too Many Requests (after 5000). | Validates Throttling config. |

## Category 2: Dynamic Client Registration (RFC 7591)
*Ensures apps can be onboarded securely.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **DCR-01** | **Valid Registration** | POST `/register` (Valid JSON). | 201 Created. Returns `client_id`, `client_secret`. | Happy Path. |
| **DCR-02** | **Secret Hash Storage** | Admin checks DB after DCR-01. | DB `SK=CONFIG` must contain `secret_hash`, NOT `secret`. | Database leak protection. |
| **DCR-03** | **Bad Redirect URI (HTTP)**| POST `/register` with `http://app.com`. | 400 Bad Request (`invalid_redirect_uri`). | Enforces HTTPS. |
| **DCR-04** | **Bad Redirect URI (Local)**| POST `/register` with `http://localhost` (Public Client). | 201 Created (Allowed for Native Apps only). | RFC 8252 Compliance. |
| **DCR-05** | **Malicious Name (XSS)** | POST with `client_name: <script>alert(1)</script>`. | 400 Bad Request or Sanitize on Output. | Stored XSS prevention. |
| **DCR-06** | **Duplicate Client** | N/A (Client IDs are UUIDs). | Ensure UUID collision prob is handled (virtually 0). | System integrity. |
| **DCR-07** | **Read Client (Auth)** | GET `/register/{id}` without token. | 401 Unauthorized. | Access Control. |
| **DCR-08** | **Read Client (Wrong)** | GET `/register/{id_A}` with Token B. | 403 Forbidden. | Tenant Isolation. |
| **DCR-09** | **Rotate Secret** | PUT `/register/{id}` (Update Secret). | 200 OK. New secret returned. Old secret invalid immediately. | Credential Lifecycle. |
| **DCR-10** | **Delete Client** | DELETE `/register/{id}`. | 204 No Content. Subsequent token requests fail. | De-provisioning check. |

## Category 3: Authorization Request (GET /authorize)
*Tests the OAuth 2.1 Protocol Inputs.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **AUT-01** | **Missing Client ID** | GET `?response_type=code`. | 400 Bad Request (Show Error Page, DO NOT REDIRECT). | RFC 6749. |
| **AUT-02** | **Unknown Client ID** | GET `?client_id=bad`. | 400 Bad Request (Error Page). | Anti-Phishing. |
| **AUT-03** | **Missing Redirect URI**| GET `?client_id=good`. | 400 Bad Request (If multiple URIs registered). | RFC 6749. |
| **AUT-04** | **Mismatch Redirect URI**| Registered: `https://a.com`. Request: `https://b.com`. | 400 Bad Request (Error Page). | Prevents Token Leakage. |
| **AUT-05** | **Open Redirect** | GET `?redirect_uri=https://evil.com`. | 400 Bad Request. | Prevents Open Redirect Vulnerability. |
| **AUT-06** | **Fuzzy URI Match** | Registered: `.../cb`. Request: `.../cb?foo=bar`. | 400 Bad Request. | RFC Strict Matching. |
| **AUT-07** | **Missing Response Type**| GET `?client_id=...`. | 400 Bad Request. | Protocol Compliance. |
| **AUT-08** | **Implicit Flow** | GET `?response_type=token`. | 400 Bad Request (`unsupported_response_type`). | OAuth 2.1 Compliance. |
| **AUT-09** | **Missing PKCE** | GET `?response_type=code` (No challenge). | 400 Bad Request. | OAuth 2.1 Compliance. |
| **AUT-10** | **Weak PKCE** | GET `?code_challenge_method=plain`. | 400 Bad Request (Only S256 allowed). | Security Best Practice. |
| **AUT-11** | **Short PKCE** | `code_challenge` < 43 chars. | 400 Bad Request. | RFC 7636. |
| **AUT-12** | **Long PKCE** | `code_challenge` > 128 chars. | 400 Bad Request. | RFC 7636 / Buffer Overflow. |
| **AUT-13** | **Invalid Scope** | `scope=openid unknown`. | 303 Redirect. Code issued. Token response ignores `unknown_scope`. | RFC 6749. |
| **AUT-14** | **State Injection** | `state=<script>...`. | 303 Redirect. State returned exactly as is (Output Encoded). | Reflected XSS. |
| **AUT-15** | **Response Mode Query** | `response_mode=query`. | 303 Redirect `uri?code=...`. | Standard Flow. |
| **AUT-16** | **Response Mode Fragment**| `response_mode=fragment`. | 303 Redirect `uri#code=...`. | Frontend App Support. |
| **AUT-17** | **Prompt None (Logged Out)**| `prompt=none` (User not logged in). | 303 Redirect `error=login_required`. | Silent Auth. |
| **AUT-18** | **Prompt None (Logged In)**| `prompt=none` (User logged in). | 303 Redirect `code=...`. | Silent Auth. |
| **AUT-19** | **Prompt Login** | `prompt=login` (User logged in). | Show Login UI (Ignore session). | Force Re-auth. |
| **AUT-20** | **Max Age** | `max_age=60` (Login was 2 mins ago). | Show Login UI. | Session Freshness. |

## Category 4: Token Exchange (POST /token)
*Tests the "Grand Exchange" logic.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **TOK-01** | **Happy Path (Auth Code)**| Valid `code` + `verifier`. | 200 OK. Access + ID + Refresh Token. | Core Logic. |
| **TOK-02** | **Missing Grant Type** | POST without `grant_type`. | 400 Bad Request (`invalid_request`). | RFC 6749. |
| **TOK-03** | **Bad Grant Type** | `grant_type=password`. | 400 Bad Request (`unsupported_grant_type`). | OAuth 2.1. |
| **TOK-04** | **Wrong PKCE Verifier** | `code_verifier` != `challenge`. | 400 Bad Request (`invalid_grant`). | RFC 7636. |
| **TOK-05** | **Missing Verifier** | Request without `code_verifier`. | 400 Bad Request. | RFC 7636. |
| **TOK-06** | **Code Replay (The Kill)**| Use Code A twice. | Request 2: 400. **Side Effect:** Revoke Token A. | RFC 6749 Sec 4.1.2. |
| **TOK-07** | **Expired Code** | Wait >10 mins, use Code. | 400 Bad Request. | Security TTL. |
| **TOK-08** | **Client Mismatch** | Client B tries to swap Client A's code. | 400 Bad Request. | Binding Check. |
| **TOK-09** | **Redirect URI Mismatch**| Token req URI != Auth req URI. | 400 Bad Request. | Code Injection Protection. |
| **TOK-10** | **Confidential No Auth** | Confidential Client, no Secret. | 401 Unauthorized (`invalid_client`). | Auth check. |
| **TOK-11** | **Confidential Bad Auth**| Confidential Client, wrong Secret. | 401 Unauthorized. | Auth check. |
| **TOK-12** | **Public Client Secret** | Public Client sends a secret. | 200 OK (Ignore secret) OR 400 (Strict). | RFC 8252. |
| **TOK-13** | **Refresh Token Happy** | Valid Refresh Token. | 200 OK. New Access + New Refresh. | Rotation. |
| **TOK-14** | **Refresh Token Replay** | Use Refresh Token A twice. | Request 2: 400. **Side Effect:** Kill Family A. | RFC 6749 / Security BCP. |
| **TOK-15** | **Refresh Scope Escalation**| Refresh with `scope=admin`. | 400 Bad Request (Original scope was `user`). | Privilege Escalation. |
| **TOK-16** | **Client Creds Happy** | Valid ID/Secret. | 200 OK. Access Token (No Refresh). | M2M Flow. |
| **TOK-17** | **Client Creds Scope** | Request `scope=user` (not allowed). | 400 Bad Request or Downscope. | Scope Governance. |
| **TOK-18** | **DPoP Header Missing** | Client has DPoP enabled, sends none. | 400 Bad Request. | RFC 9449. |
| **TOK-19** | **DPoP Invalid Proof** | Bad Signature on DPoP JWT. | 401 Unauthorized. | RFC 9449. |
| **TOK-20** | **DPoP Replay** | Use DPoP Proof JWT twice. | 401 Unauthorized (`jti` check). | RFC 9449. |

## Category 5: Session & Login UI
*Tests the HTML/Form interaction.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **SES-01** | **Load Login Page** | GET `/auth/login`. | 200 OK. HTML Content. | UI Check. |
| **SES-02** | **CSRF Login Form** | POST `/verify` without `csrf_token`. | 403 Forbidden. | CSRF Protection. |
| **SES-03** | **Bad Password** | Valid Email, Bad Pass. | 200 OK (HTML). Audit Log: FAILURE. | Brute force check. |
| **SES-04** | **User Enumeration** | POST unknown email. | 200 OK (HTML "Invalid Creds"). Time taken = same as valid. | Timing Attack Protection. |
| **SES-05** | **SQL Injection** | Email: `' OR 1=1 --`. | 200 OK (HTML "Invalid"). No DB Error. | Sanitization. |
| **SES-06** | **Session Fixation** | Login. Get Cookie. | Cookie `HttpOnly; Secure; SameSite=Lax`. | Cookie Security. |
| **SES-07** | **Expired Session** | Wait 30 mins (TTL). | Redirect to Login. | Session Timeout. |
| **SES-08** | **MFA Setup** | User enables MFA. | DB updated. Next login requires OTP. | MFA Logic. |
| **SES-09** | **MFA Bypass** | Login Password. Skip OTP. Call `/authorize`. | Redirect back to MFA Page. | MFA Enforcement. |
| **SES-10** | **MFA Rate Limit** | Guess OTP 10 times. | Account/Session Lockout. | Brute Force Protection. |

## Category 6: User Management (SCIM & RBAC)
*Tests the Enterprise features.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **USR-01** | **Create User** | POST `/scim/Users` (Valid). | 201 Created. | Provisioning. |
| **USR-02** | **Duplicate Email** | POST `/scim/Users` (Existing). | 409 Conflict. | Data Integrity. |
| **USR-03** | **Bad Email Format** | Email: `bob`. | 400 Bad Request. | Validation. |
| **USR-04** | **Patch Active False** | PATCH `active: false`. | 200 OK. **Side Effect:** Refresh Tokens Deleted. | Kill Switch. |
| **USR-05** | **Get Me** | GET `/scim/Me` with Token. | 200 OK. Returns own profile. | Self Service. |
| **USR-06** | **Hack Me (ID)** | GET `/scim/Me` (Token A) try ID B. | 200 OK (Returns A). Ignore ID param. | Broken Access Control. |
| **USR-07** | **Patch Me (Groups)** | PATCH `/scim/Me` (`groups`). | 403 Forbidden. | Privilege Escalation. |
| **USR-08** | **Create Group** | POST `/scim/Groups`. | 201 Created. | RBAC. |
| **USR-09** | **Add Member** | PATCH Group (Add User). | 204 No Content. | RBAC. |
| **USR-10** | **Token Claims (Group)**| Get Token for User in Group. | JWT contains `groups: ["..."]`. | RBAC. |

## Category 7: Token Management (Revoke/Introspect)
*Tests API security.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **MGT-01** | **Introspect Valid** | POST `/introspect` (Active Token). | 200 OK. `active: true`. | RFC 7662. |
| **MGT-02** | **Introspect Expired**| POST `/introspect` (Dead Token). | 200 OK. `active: false`. | RFC 7662. |
| **MGT-03** | **Introspect Garbage**| POST `/introspect` (Random string). | 200 OK. `active: false`. | Error Handling. |
| **MGT-04** | **Revoke Refresh** | POST `/revoke` (Refresh Token). | 200 OK. Token deleted. | RFC 7009. |
| **MGT-05** | **Revoke Garbage** | POST `/revoke` (Random string). | 200 OK. (Do not error). | Privacy / Enumeration. |

## Category 8: OIDC Logout (RP-Initiated)
*Tests session termination.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **LOG-01** | **Logout Happy** | GET `/logout?id_token_hint=...`. | 303 Redirect. Cookie Cleared. | OIDC Logout. |
| **LOG-02** | **Logout No Hint** | GET `/logout`. | Show Confirmation Page (Don't auto logout). | OIDC Logout. |
| **LOG-03** | **Bad Hint** | GET `/logout?id_token_hint=bad`. | 400 Bad Request. | Security. |
| **LOG-04** | **Post Logout URI** | `post_logout_redirect_uri` (Whitelisted). | Redirect to URI after logout. | UX. |
| **LOG-05** | **Malicious URI** | `post_logout_redirect_uri` (Evil). | Logout, but stop at default page. | Open Redirect. |

## Category 9: SAML Integration
*Tests the Enterprise bridge.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **SAM-01** | **Metadata Gen** | GET `/saml/metadata`. | 200 OK. Valid XML. | Setup. |
| **SAM-02** | **SAML Consume** | POST `/saml/callback` (Valid Signed XML). | 303 Redirect to Authorize. Session Created. | Happy Path. |
| **SAM-03** | **SAML Bad Sig** | POST `/saml/callback` (Modified XML). | 400 Bad Request. Audit Log: FAIL. | Integrity. |
| **SAM-04** | **SAML Replay** | POST same SAML Assertion twice. | 400 Bad Request (`NotOnOrAfter` check). | Replay Attack. |
| **SAM-05** | **JIT Provision** | SAML Login (New User). | User created in DB with `SAML` link. | JIT. |

## Category 10: JWT Structure & Crypto
*Tests the artifacts.*

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **JWT-01** | **Algorithm** | Inspect Header. | `alg: RS256` (or ES256). NOT HS256/None. | Crypto Standards. |
| **JWT-02** | **Audience** | Inspect Payload. | `aud` includes Client ID. | Token Scope. |
| **JWT-03** | **Issuer** | Inspect Payload. | `iss` matches Discovery URL. | Token Validation. |
| **JWT-04** | **Expiry** | Inspect Payload. | `exp` is in future (~1 hour). | Lifetime. |
| **JWT-05** | **Sub Type** | Public Client Token. | `sub` is UUID (Pairwise if configured). | Privacy. |

## Category 11: Core Happy Path Flows

| ID | Test Name | Input / Action | Expected Result | Rationale |
|:---|:---|:---|:---|:---|
| **HPF-01** | **Password Login** | POST `/verify` (Valid email/pass/CSRF). | 200 OK. Session cookie set. Redirect to callback. | Core Auth. |
| **HPF-02** | **Authorization Code (Public)** | Full flow: Login → Authorize → Code → Token (with PKCE, no secret). | 200 OK. Access + ID token. | Public Client. |
| **HPF-03** | **Authorization Code (Confidential)** | Full flow: Login → Authorize → Code → Token (with secret). | 200 OK. Access + ID + Refresh token. | Confidential Client. |
| **HPF-04** | **UserInfo Retrieval** | GET `/userinfo` with valid access token. | 200 OK. JSON with `sub`, `email`, etc. | OIDC Core. |
| **HPF-05** | **MFA Login** | Login → OTP prompt → Valid OTP → Success. | 200 OK. Session created. | MFA Happy Path. |
| **HPF-06** | **Scope Restriction** | Request `scope=openid profile` → Token. | Token contains only `openid profile` claims. | Scope Control. |
| **HPF-07** | **Refresh Token Downgrade** | Refresh with reduced scope. | 200 OK. New token with reduced scope. | Scope Flexibility. |