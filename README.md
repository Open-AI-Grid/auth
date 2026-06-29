# Open AI Grid Auth Service

Authentication and identity service for Open AI Grid.

This service provides:
- user registration and login
- JWT access/refresh tokens
- TOTP MFA (2FA)
- passkey (WebAuthn) endpoints
- contribution tracking (SETI@Home/Folding@Home style)
- leaderboard API

## Quick Start

### 1. Install

```bash
cd open-ai-grid-auth
pip install -r requirements.txt
pip install -e .
```

### 2. Configure

Edit `config/default_config.yaml`:

```yaml
auth:
  port: 8800
  jwt_secret: ""
  db_path: "data/users.db"
  rp_id: "localhost"
  rp_name: "Open AI Grid"
  origin: "http://localhost:8800"
  internal_api_key: ""
```

Recommended for production:
- set `JWT_SECRET` environment variable
- set a strong `internal_api_key`
- run behind TLS and a reverse proxy

### 3. Run

```bash
aig-auth start --port 8800
```

or

```bash
python cli/main.py start --port 8800
```

## Main Endpoints

### Auth
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `GET /auth/me`

### MFA
- `POST /auth/mfa/setup`
- `POST /auth/mfa/enable`
- `POST /auth/mfa/verify`
- `POST /auth/mfa/disable`

### Passkeys
- `POST /auth/passkey/register/begin`
- `POST /auth/passkey/register/complete`
- `POST /auth/passkey/login/begin`
- `POST /auth/passkey/login/complete`

### Contributions
- `GET /auth/contributions`
- `POST /auth/contributions/record` (node/internal use)
- `GET /auth/leaderboard`

### Health
- `GET /health`

## Contribution Stats Model

Per user:
- tasks submitted/completed/failed
- total compute time in ms
- total tokens generated
- first/last contribution timestamps
- rank (Bronze/Silver/Gold/Platinum/Diamond)

## Notes

- Passkey cryptographic verification is enabled when `webauthn` is installed.
- If unavailable, a mock fallback keeps local development functional.

## Versioning

- Version source of truth: `VERSION`
- Changelog: `CHANGELOG.md`
