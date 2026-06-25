# Changelog

## [0.1.0] - 2026-06-25
### Added
- User registration with bcrypt password hashing.
- Login with JWT access and refresh tokens.
- TOTP-based 2FA/MFA (setup, enable, verify, disable).
- WebAuthn/Passkey registration and authentication (full crypto when py_webauthn installed; transparent mock fallback for local dev).
- SETI@Home-style contribution stats per user (tasks submitted/completed/failed, compute time, tokens generated).
- Rank system: Bronze → Silver → Gold → Platinum → Diamond.
- Global leaderboard endpoint.
- Internal contribution recording endpoint for node → auth integration.
- SQLite-backed async user store.
