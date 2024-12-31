from fastapi import Request, Depends, APIRouter
from app.db.session import get_session
from sqlmodel.ext.asyncio.session import AsyncSession

from app.apis.v1.saml_auth.crud import (
    get_current_user, 
    initiate_saml_login,
    assertion_consumer_service,
    initiate_tokens,
    initiate_refresh_token,
    me,
    logout_user,
    single_logout
)

auth_saml = APIRouter(
    tags=["saml-auth"]
)

@auth_saml.get("/saml-login")
async def initiate_saml(request: Request, provider: str, invitation_token: str = None):
    return await initiate_saml_login(request, provider, invitation_token)
    
    
@auth_saml.post("/acs")
async def acs(request: Request, session: AsyncSession = Depends(get_session)):
    return await assertion_consumer_service(request, session)
    
    
@auth_saml.get("/token")
async def get_tokens(
    code: str,
    session_index: str
):
    return await initiate_tokens(code, session_index)
    

@auth_saml.get("/refresh")
async def refresh_token(current_user: dict = Depends(get_current_user)):
    return await initiate_refresh_token(current_user)


@auth_saml.get("/me")
async def get_user_info(current_user: dict = Depends(get_current_user)):
    return await me(current_user)
    

@auth_saml.get("/logout")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    return await logout_user(request, current_user)


@auth_saml.get("/slo")
async def slo(request: Request):
    return await single_logout(request)