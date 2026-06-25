"""TOTP / MFA support using pyotp."""

import pyotp

ISSUER = "Open AI Grid"


class TOTPHandler:
    def generate_secret(self) -> str:
        return pyotp.random_base32()

    def get_provisioning_uri(self, secret: str, username: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)

    def verify(self, secret: str, code: str, valid_window: int = 1) -> bool:
        try:
            return pyotp.TOTP(secret).verify(code, valid_window=valid_window)
        except Exception:
            return False

    def current_code(self, secret: str) -> str:
        return pyotp.TOTP(secret).now()
