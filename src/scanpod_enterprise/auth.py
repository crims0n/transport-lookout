import hmac
from collections.abc import Callable
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .config import settings
from .db import get_session
from .models import Role, User


def current_user(request: Request, session: Session = Depends(get_session)) -> User:
    """Resolve a locally bootstrapped user or validate a production OIDC JWT."""
    authorization = request.headers.get("Authorization", "")
    if settings.bootstrap_enabled and settings.bootstrap_token and authorization.startswith("Bearer "):
        if hmac.compare_digest(authorization.removeprefix("Bearer "), settings.bootstrap_token):
            user = session.query(User).filter_by(subject="bootstrap-admin").one_or_none()
            if user is None:
                user = User(subject="bootstrap-admin", role=Role.platform_admin)
                session.add(user)
                session.commit()
            return user
    if settings.oidc_issuer and settings.oidc_audience and authorization.startswith("Bearer "):
        try:
            claims = validate_oidc_token(authorization.removeprefix("Bearer "))
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid access token") from exc
        subject = claims.get("sub")
        if not subject:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="access token missing subject")
        user = session.query(User).filter_by(subject=subject).one_or_none()
        if user:
            return user
        # Authentication does not grant authorization. Administrators provision
        # roles before a user can access scanning data.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user is not provisioned")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")


@lru_cache(maxsize=1)
def _jwks_client() -> jwt.PyJWKClient:
    url = settings.oidc_jwks_url or f"{settings.oidc_issuer.rstrip('/')}/.well-known/jwks.json"
    return jwt.PyJWKClient(url, cache_keys=True)


def validate_oidc_token(token: str) -> dict:
    signing_key = _jwks_client().get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        signing_key,
        algorithms=["RS256", "ES256"],
        audience=settings.oidc_audience,
        issuer=settings.oidc_issuer,
        options={"require": ["exp", "iat", "sub"]},
    )


def require_roles(*roles: Role) -> Callable:
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return user

    return dependency
