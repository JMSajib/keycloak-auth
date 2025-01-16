from fastapi import APIRouter, Depends
from sqlmodel.ext.asyncio.session import AsyncSession
from app.db.session import get_session

from app.apis.v1.oidc_auth.crud import (
    login_request,
    callback_function,
    me, 
    initiate_refresh_token, 
    logout_user
)

from app.apis.v1.utils import token_required, get_refresh_token

from app.apis.v1.oidc_auth.schemas import TokenResponse, TokenRequest


auth_router = APIRouter(
    tags=["oidc-auth"]
)


@auth_router.get("/social-login/{provider}")
async def login(provider: str, invitation_token: str = None):
    return await login_request(provider, invitation_token)

@auth_router.post("/token", response_model=TokenResponse)
async def callback(request: TokenRequest, session: AsyncSession = Depends(get_session)):
    return await callback_function(request, session)

@auth_router.post("/refresh")
async def refresh_token(refresh_token_data: dict = Depends(get_refresh_token), session: AsyncSession = Depends(get_session)):    
    return await initiate_refresh_token(refresh_token_data, session)


@auth_router.get("/me")
async def user_info(current_user: dict = Depends(token_required), session: AsyncSession = Depends(get_session)):
    return await me(current_user, session)


@auth_router.get('/logout')  # Changed to POST to match frontend expectations
async def logout(current_user: dict = Depends(token_required), session: AsyncSession = Depends(get_session)):
    return await logout_user(current_user, session)
    

@auth_router.get("/alive")
async def alive():
    return {"message": "Auth API is running"}