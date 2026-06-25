"""WebAuthn / Passkey registration and authentication.

Full cryptographic verification is performed when py_webauthn is installed.
A transparent mock fallback is used when it is not, so the service starts
without errors and the endpoints remain functional for local development.
"""

import base64
import logging
import os
from typing import Optional, Tuple

from ..models.user import User

logger = logging.getLogger(__name__)


class PasskeyHandler:
    def __init__(self, rp_id: str, rp_name: str, origin: str):
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        try:
            import webauthn  # noqa: F401

            self._available = True
            logger.info("WebAuthn (py_webauthn) available – full passkey support enabled.")
        except ImportError:
            self._available = False
            logger.warning(
                "py_webauthn not installed – passkey endpoints use mock mode. "
                "Install with: pip install webauthn"
            )

    # ── Registration ─────────────────────────────────────────────────────────

    def generate_registration_options(self, user: User) -> Tuple[dict, str]:
        if not self._available:
            return self._mock_reg_options(user)

        from webauthn import generate_registration_options, options_to_json
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )
        import json

        opts = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user.user_id.encode(),
            user_name=user.username,
            user_display_name=user.username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        challenge = base64.b64encode(opts.challenge).decode()
        return json.loads(options_to_json(opts)), challenge

    def verify_registration(self, credential: dict, challenge: str) -> Optional[dict]:
        if not self._available:
            return self._mock_verify_reg(credential)

        try:
            from webauthn import verify_registration_response

            v = verify_registration_response(
                credential=credential,
                expected_challenge=base64.b64decode(challenge),
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
            )
            return {
                "credential_id": base64.b64encode(v.credential_id).decode(),
                "public_key": base64.b64encode(v.credential_public_key).decode(),
                "sign_count": v.sign_count,
            }
        except Exception as exc:
            logger.error("Passkey registration failed: %s", exc)
            return None

    # ── Authentication ────────────────────────────────────────────────────────

    def generate_authentication_options(self, user: User) -> Tuple[dict, str]:
        if not self._available:
            return self._mock_auth_options(user)

        import json
        from webauthn import generate_authentication_options, options_to_json
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        allow = [
            PublicKeyCredentialDescriptor(id=base64.b64decode(pk["credential_id"]))
            for pk in user.passkeys
        ]
        opts = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        challenge = base64.b64encode(opts.challenge).decode()
        return json.loads(options_to_json(opts)), challenge

    def verify_authentication(
        self, credential: dict, challenge: str, user: User
    ) -> Tuple[bool, int]:
        if not self._available:
            return True, 1

        cred_id = credential.get("id", "")
        passkey = next((p for p in user.passkeys if p["credential_id"] == cred_id), None)
        if not passkey:
            return False, 0

        try:
            from webauthn import verify_authentication_response

            v = verify_authentication_response(
                credential=credential,
                expected_challenge=base64.b64decode(challenge),
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=base64.b64decode(passkey["public_key"]),
                credential_current_sign_count=passkey["sign_count"],
            )
            return True, v.new_sign_count
        except Exception as exc:
            logger.error("Passkey authentication failed: %s", exc)
            return False, 0

    # ── Mock helpers ──────────────────────────────────────────────────────────

    def _mock_reg_options(self, user: User) -> Tuple[dict, str]:
        import secrets as sec

        challenge = base64.b64encode(sec.token_bytes(32)).decode()
        return {
            "rp": {"id": self.rp_id, "name": self.rp_name},
            "user": {"id": user.user_id, "name": user.username, "displayName": user.username},
            "challenge": challenge,
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "_mock": True,
        }, challenge

    def _mock_verify_reg(self, _credential: dict) -> dict:
        import secrets as sec

        return {
            "credential_id": base64.b64encode(sec.token_bytes(32)).decode(),
            "public_key": base64.b64encode(sec.token_bytes(64)).decode(),
            "sign_count": 0,
        }

    def _mock_auth_options(self, user: User) -> Tuple[dict, str]:
        import secrets as sec

        challenge = base64.b64encode(sec.token_bytes(32)).decode()
        return {
            "rpId": self.rp_id,
            "challenge": challenge,
            "allowCredentials": [
                {"type": "public-key", "id": pk["credential_id"]} for pk in user.passkeys
            ],
            "userVerification": "required",
            "_mock": True,
        }, challenge
