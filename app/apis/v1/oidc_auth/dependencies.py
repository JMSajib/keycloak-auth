from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from app.core.config import Config

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verify JWT token from Authorization header
    """
    try:
        token = credentials.credentials
        # Verify token with Keycloak public key (you'll need to implement this)
        # For now, this is a placeholder
        payload = jwt.decode(
            token,
            algorithms=["RS256"],
            options={"verify_signature": False}  # Remove this in production
        )
        return payload
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )