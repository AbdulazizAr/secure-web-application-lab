# Security notes

This lab keeps the controls visible and easy to review.

| Risk | Control used |
| --- | --- |
| Password disclosure | Python's `scrypt` implementation stores a salted password hash rather than the original password. |
| SQL injection | Every query uses placeholders and separate parameters. |
| Cross-site request forgery | Each form requires a random token stored in the user's session. |
| Stored cross-site scripting | Jinja escapes titles and details before displaying them. |
| Broken object-level authorization | Delete queries include both the record ID and the signed-in owner's ID. |
| Credential guessing | Login attempts are limited per client address. |
| Browser-based attacks | CSP, frame protection, MIME sniffing protection, and restrictive browser policies are returned. |

## Deliberate limits

Sessions and rate limits are stored in process memory. Multiple application workers would require shared storage such as Redis. The local server does not provide HTTPS, so the `Secure` cookie attribute is enabled through `COOKIE_SECURE=1` when HTTPS is available. Production deployments should also use a mature framework, centralized logging, secret management, database backups, and dependency monitoring.
