# OAuth Proxy README

> Public URL: `https://oauth-proxy.eng.sdc.nycu.club/`

---

## Project Description

This service provides a shared Google OAuth Proxy for project teams.

Google OAuth requires redirect URIs to be registered in the Google Cloud Console. For short-term snapshots or frequently changing test environments, we cannot add every temporary domain / callback URI to Google’s whitelist, nor do we want to frequently register numerous callback URIs. The purpose of this proxy is:

1. Provide a stable callback URL already registered in the Google whitelist (`https://oauth-proxy.eng.sdc.nycu.club/api/auth/google/callback`).
2. When Google sends a callback to the proxy, the proxy uses the `state` (JWT) to determine the request and securely forward the result to your final service (`redirect_url`).
3. Reduce the effort for each project to register and maintain redirect URIs, making development simpler and faster.

**Note**: If your service’s domain (dev/stage/prod) is already whitelisted in Google’s redirect URIs, you do not need to use this proxy.

---

## Usage

1. When performing Google OAuth, your backend should generate a `state` (JWT) and use this proxy’s callback URL (`https://oauth-proxy.eng.sdc.nycu.club/api/auth/google/callback`) as the `redirect_uri` in the Google authorization URL.
2. The user is directed to Google and completes authentication. Google will return a `code` (or `error`) and the `state` to this service.
3. Once the proxy receives the callback:

   * It verifies the signature and validity of the `state`.
   * Depending on the outcome, it redirects the user to the `callback_url`, with query string parameters appended:

     * Success: `https://your.callback.url/path?code=...&state=...`
     * Failure: `https://your.callback.url/path?error=...`

---

## `state` (JWT) Format

* **Signing Method**: HS256 (HMAC-SHA256), secret key (`STATE_SECRET`) provided by the administrator.
* **Recommended payload fields (JSON)**:

```json
{
  "service": "core system",
  "environment": "snapshot",
  "callback_url": "https://app.dev.example.org/auth/google/callback",
  "redirect_url": "https://app.dev.example.org/",
  "iss": "sdc-oauth-proxy-client",
  "sub": "<user-or-session-id>",
  "exp": 1700000000,
  "nbf": 1699999700,
  "iat": 1699999700,
  "jti": "uuid-xxxx-..."
}
```

* `callback_url`: The final internal service URL where the user should be redirected.
* `iss/sub/exp/nbf/iat/jti`: Fill in according to JWT standards.
