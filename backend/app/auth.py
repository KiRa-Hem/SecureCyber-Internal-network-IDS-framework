from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.config import settings


def _jwt_secret() -> Optional[str]:
    return getattr(settings, "JWT_SECRET", None) or None


def _jwt_algo() -> str:
    return getattr(settings, "JWT_ALGORITHM", "HS256")


def create_jwt(subject: str, role: str, ttl_seconds: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    issuer = getattr(settings, "JWT_ISSUER", None)
    audience = getattr(settings, "JWT_AUDIENCE", None)
    if issuer:
        payload["iss"] = issuer
    if audience:
        payload["aud"] = audience
    secret = _jwt_secret()
    if not secret:
        raise ValueError("JWT_SECRET is not configured.")
    return jwt.encode(payload, secret, algorithm=_jwt_algo())


def get_role_from_token(token: str) -> Optional[str]:
    secret = _jwt_secret()
    if not secret:
        return None
    try:
        options = {"verify_aud": bool(getattr(settings, "JWT_AUDIENCE", None))}
        payload = jwt.decode(
            token,
            secret,
            algorithms=[_jwt_algo()],
            audience=getattr(settings, "JWT_AUDIENCE", None),
            issuer=getattr(settings, "JWT_ISSUER", None),
            options=options,
        )
    except JWTError:
        return None
    role = payload.get("role")
    if isinstance(role, str):
        return role
    roles = payload.get("roles")
    if isinstance(roles, list) and roles:
        return str(roles[0])
    return None
