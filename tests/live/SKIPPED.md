# Skipped Tests Documentation

This document lists tests that are skipped in the API test suite (`specs/`) and their status.

**API Tests**: 143 passing, 17 skipped
**Browser Tests**: 59 passing, 1 failed



## Pending Browser Implementation

These tests require browser automation and should be migrated to `browser/`.

| Test ID | Test Name | Complexity |
|---------|-----------|------------|
| AUT-20 | Max Age (Session Check) | Medium - implementation in progress |

## Requires Special Setup

| Test ID | Test Name | Blocker |
|---------|-----------|---------|
| TOK-07 | Expired Code | Requires wait time or short TTL config |
| TOK-18 | DPoP Required Client | Requires DPoP-required client in seed data |
| SES-02 | CSRF Login Form | Requires form structure analysis |
| SES-04 | User Enumeration | Requires timing analysis |
| SES-06 | Session Fixation | Requires cookie inspection |
| USR-04 | Patch Active False | Requires user with active tokens |
| USR-07 | Patch Me (Groups) | Requires user token + group setup |
| USR-09 | Add Member | Requires group + user setup |
| USR-10 | Token Claims (Group) | Requires user in group |
| HPF-06 | Scope Restriction | Requires scope validation |
| HPF-07 | Refresh Token Downgrade | Requires scope downgrade test |

## Time-Dependent Tests

| Test ID | Test Name | Blocker |
|---------|-----------|---------|
| MGT-02 | Introspect Expired | Requires 1+ hour wait |
| SES-07 | Expired Session | Requires 30+ minute wait |

## Infrastructure Tests

| Test ID | Test Name | Blocker |
|---------|-----------|---------|
| INF-05 | Large Payload DoS | 10MB payload times out |
| INF-10 | Rate Limit Burst | Requires 5001 requests |

## MFA Tests (Module Not Deployed)

| Test ID | Test Name | Blocker |
|---------|-----------|---------|
| SES-08 | MFA Setup | Enable `enable_mfa_totp_strategy = true` |
| SES-09 | MFA Bypass | Requires MFA-enabled user |
| SES-10 | MFA Rate Limit | Requires MFA-enabled user |
| HPF-05 | MFA Login | Requires MFA-enabled user |

## Running Browser Tests

```bash
# Run all browser tests
npm run test:browser

# Run with visible browser
npm run test:browser:headed

# Run specific test
npm run test:browser -- --grep "TOK-01"
```
