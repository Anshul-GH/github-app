import time
import jwt


def make_jwt(app_id: str, private_key: str) -> str:
    """
    Create a short-lived JWT for the GitHub App.

    GitHub requires:
    - 'iss' = app ID
    - 'iat' = issued at (<= 60s in the past)
    - 'exp' = expiration (<= 10 minutes in the future)
    """
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": app_id,
    }
    encoded = jwt.encode(payload, private_key, algorithm="RS256")
    # PyJWT may return bytes or str depending on version; normalize to str
    if isinstance(encoded, bytes):
        encoded = encoded.decode("utf-8")
    return encoded
