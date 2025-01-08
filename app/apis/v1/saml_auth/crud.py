import random, secrets,uuid
from app.apis.v1.saml_auth.models import UserMapper, Role, Project, UserRoleProject, BlackListedToken
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from fastapi import HTTPException, Depends, Request, status, Header
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, JSONResponse
from app.core.redis_client import redis_client
from app.core.config import Config
import jwt
import json
from app.core.security import security
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from datetime import datetime, timedelta, UTC
from typing import Optional
from app.db.session import get_session
from httpx import AsyncClient
from app.apis.v1.utils import (
    get_groups_or_create_groups, 
    add_user_to_group, 
    get_roles, 
    assign_realm_role_to_user,
    get_keycloak_admin,
    get_composite_roles
)


FRONTEND_BASE_URL = Config.FRONTEND_BASE_URL
FRONTEND_REDIRECT_URL = Config.FRONTEND_REDIRECT_URL
BACKEND_BASE_URL = Config.BACKEND_BASE_URL

REDIS_HOST = Config.REDIS_HOST
REDIS_PORT = Config.REDIS_PORT
REDIS_DB = Config.REDIS_DB

SP_ACS_URL = Config.SP_ACS_URL
SP_SLO_URL = Config.SP_SLO_URL
SP_CERT = Config.SP_CERT
SP_KEY = Config.SP_KEY

IDP_ENTITY_ID = Config.IDP_ENTITY_ID
IDP_SSO_URL = Config.IDP_SSO_URL
IDP_SLO_URL = Config.IDP_SLO_URL
IDP_CERT = Config.IDP_CERT

SECRET_KEY = Config.SECRET_KEY

REDIRECT_URL = FRONTEND_REDIRECT_URL

# SAML settings and Configurations
saml_settings = {
    "strict": True,  # Set to True for production
    "debug": True,
    "security": {
        "nameIdEncrypted": False,
        "authnRequestsSigned": True,  # Enable request signing
        "logoutRequestSigned": True,
        "logoutResponseSigned": True,
        "signMetadata": True,
        "wantMessagesSigned": True,
        "wantAssertionsSigned": True,  # Require signed assertions
        "wantNameIdEncrypted": False,
        "allowRepeatAttributeName": True,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
    },
    "sp": {
        "entityId": "saml-client",
        "assertionConsumerService": {
            "url": SP_ACS_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": SP_SLO_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "x509cert": SP_CERT,
        "privateKey": SP_KEY
    },
    "idp": {
        "entityId": IDP_ENTITY_ID,
        "singleSignOnService": {
            "url": IDP_SSO_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": IDP_SLO_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": IDP_CERT
    }
    
}


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    return auth

def create_token(sub:str, session_index: str, token_type: str = "access"):
    payload = {
        "sub": sub,
        "session_index": session_index,
        "sso_user": True
,       "exp": datetime.now(UTC) + timedelta(hours=1) if token_type == "access" else datetime.now(UTC) + timedelta(days=30)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")


async def get_refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        if not token:
            raise HTTPException(
                status_code=401,
                detail="No token found"
            )
        # Verify JWT token
        payload = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=["HS256"]
        )
        # Validate required claims
        if not payload.get("sub"):
            raise HTTPException(
                status_code=401,
                detail="Invalid token: missing subject claim"
            )
        return {
            "token": token,
            "sub": payload.get("sub"),
            "session_index": payload.get("session_index")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Refresh token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

async def add_to_blacklist(token: str, session: AsyncSession) -> None:
    """Add a token to the blacklist"""
    try:
        blacklisted_token = BlackListedToken(token=token)
        session.add(blacklisted_token)
        await session.commit()
    except Exception as e:
        await session.rollback()
        print(f"Error blacklisting token: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to blacklist token: {e}"
        )

async def is_token_blacklisted(token: str, session: AsyncSession) -> bool:
    """Check if a token is blacklisted"""
    try:
        statement = select(BlackListedToken).where(BlackListedToken.token == token)
        result = await session.exec(statement)
        return bool(result.first())
    except Exception as e:
        print(f"Error checking blacklist: {e}")
        return False

async def create_user_mapper(user_keycloak_uid, email, role_keycloak_uid, group_keycloak_uid, group_name, session: AsyncSession, first_name:str=None, last_name:str=None, invitation_token:str=None):
    """Handle user mapping for both new and invited users"""
    try:
        # Convert strings to UUID
        user_uid = uuid.UUID(user_keycloak_uid)
        project_uid = uuid.UUID(group_keycloak_uid)
        role_uid = uuid.UUID(role_keycloak_uid)
        
        # 1. Get or create user
        user_stmt = select(UserMapper).where(UserMapper.user_keycloak_uid == user_uid)
        result = await session.exec(user_stmt)
        user = result.first()
        
        if not user:
            user = UserMapper(
                user_core_id=random.randint(1, 1000000),
                user_keycloak_uid=user_uid,
                username=email,
                email=email,
                first_name=first_name,
                last_name=last_name
            )
            session.add(user)
            await session.flush()  # Just flush to get the ID
            
        # 2. Get or create project
        project_stmt = select(Project).where(Project.project_keycloak_uid == project_uid)
        result = await session.exec(project_stmt)
        project = result.first()
        
        if not project:
            project = Project(
                project_keycloak_uid=project_uid,
                project_name=group_name
            )
            session.add(project)
            await session.flush()  # Just flush to get the ID
            
        # 3. Get role
        role_stmt = select(Role).where(Role.role_keycloak_uid == role_uid)
        result = await session.exec(role_stmt)
        role = result.first()
        
        if not role:
            raise HTTPException(
                status_code=404,
                detail=f"Role with keycloak_uid {role_keycloak_uid} not found"
            )
            
        # 4. Check if user-role-project mapping exists
        mapping_stmt = select(UserRoleProject).where(
            UserRoleProject.user_id == user.id,
            UserRoleProject.project_id == project.id
        )
        result = await session.exec(mapping_stmt)
        existing_mapping = result.first()
        
        if existing_mapping:
            # User already has a role in this project
            return {
                "status": "exists",
                "message": f"User already has role {existing_mapping.role_id} in project {project.project_name}"
            }
        
        # 5. Create new user-role-project mapping
        new_mapping = UserRoleProject(
            user_id=user.id,
            role_id=role.id,
            project_id=project.id
        )
        session.add(new_mapping)
        
        # Only commit once at the end
        await session.commit()
        
        return {
            "status": "success",
            "message": "User role mapping created successfully",
            "data": {
                "user_id": user.id,
                "project_id": project.id,
                "role_id": role.id
            }
        }
            
    except Exception as e:
        await session.rollback()
        print(f"Error in create_user_mapper: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process user: {str(e)}"
        )


    
async def token_required(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Validate JWT token and return current user data from Redis session
    """
    try:
        token = credentials.credentials
        if not token:
            raise HTTPException(
                status_code=401,
                detail="No token found"
            )
        # Verify JWT token
        payload = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=["HS256"]
        )
        # Validate required claims
        if not payload.get("sub"):
            raise HTTPException(
                status_code=401,
                detail="Invalid token: missing subject claim"
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )
    except Exception as e:
        print(f"******* Exception IN TOKEN VALIDATION: {e} *******")
        raise HTTPException(
            status_code=401,
            detail=str(e)
        )
    
    
async def get_cached_admin_token() -> Optional[str]:
    """Get admin token from cache or fetch new one if expired"""
    try:
        # Try to get cached token and its expiration
        cached_data = redis_client.get("keycloak_admin_token")
        
        if cached_data:
            cached_data = json.loads(cached_data)
            expiration = datetime.fromisoformat(cached_data['expiration'])
            
            # If token is still valid (with 30s buffer), return it
            if datetime.now(UTC) < (expiration - timedelta(seconds=30)):
                return cached_data['token']
        
        # If no valid cached token, get new one
        admin_token = await get_keycloak_admin()
        
        # Cache the new token with expiration (typical Keycloak token expires in 60s)
        token_data = {
            'token': admin_token,
            'expiration': (datetime.now(UTC) + timedelta(seconds=60)).isoformat()
        }
        redis_client.setex(
            "keycloak_admin_token",
            55,  # Store for 55 seconds (slightly less than actual expiration)
            json.dumps(token_data)
        )
        
        return admin_token
        
    except Exception as e:
        print(f"Error getting cached admin token: {e}")
        # Fallback to direct token fetch if caching fails
        return await get_keycloak_admin()
    
    
async def initiate_saml_login(request: Request, provider: str, invitation_token: str = None):
    try:
        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': {},
            'base_url': BACKEND_BASE_URL 
        }

        # Generate state and relay state
        state = secrets.token_urlsafe(64)
        
        # Store state in Redis
        redis_client.setex(
            f"saml_state:{state}",
            300,  # 5 minutes
            "true"
        )
        
        # Initialize SAML auth
        auth = init_saml_auth(req)
        
        # Set RelayState to include frontend callback URL and state
        if invitation_token:
            relay_state = f"{REDIRECT_URL}?state={state}&invitation_token={invitation_token}"
        else:
            relay_state = f"{REDIRECT_URL}?state={state}"
        
        sso_built_url = auth.login(
            return_to=relay_state,
        )
        
        sso_built_url += f"&kc_idp_hint={provider}&prompt=select_account"
        
        return {
            "saml_request": sso_built_url,
            "state": state
        }
    except Exception as e:
        print(f"Error initiating SAML login: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
async def assertion_consumer_service(request: Request, session: AsyncSession = Depends(get_session)):
    try:
        form_data = await request.form()
        saml_response = form_data.get('SAMLResponse')
        relay_state = form_data.get('RelayState')
        # Extract state and invitation_token from relay_state
        state = None
        invitation_token = None
        
        if relay_state:
            # Split the URL parameters
            params = dict(param.split('=') for param in relay_state.split('?')[1].split('&'))
            state = params.get('state')
            invitation_token = params.get('invitation_token')
        
        # Verify state
        stored_state = redis_client.get(f"saml_state:{state}")
        if not stored_state:
            frontend_url = f"{REDIRECT_URL}?error=invalid_state"
            return RedirectResponse(url=frontend_url)
            
        # Delete used state
        redis_client.delete(f"saml_state:{state}")
        
        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': form_data,
            'base_url': BACKEND_BASE_URL
        }

        modified_settings = saml_settings.copy() 
        
        auth = OneLogin_Saml2_Auth(req, modified_settings)
        
        # Process the response
        auth.process_response()
        errors = auth.get_errors()
        
        if len(errors) > 0:
            raise HTTPException(status_code=401, detail=f"SAML Error: {', '.join(errors)}")
            
        if not auth.is_authenticated():
            raise HTTPException(status_code=401, detail="Authentication failed")

        # Get SAML data
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()
        
        user_id = attributes['user_id'][0]
        
        # or session_data["attributes"]["urn:oid:1.2.840.113549.1.9.1"][0]
        first_name = attributes["urn:oid:2.5.4.42"][0]  # givenName
        last_name = attributes["urn:oid:2.5.4.4"][0]    # surname
        
        if invitation_token:
            # Get project and role details from invitation token
            # project_details = await validate_invitation_token(invitation_token)
            # if invitation_token is not valid, raise an error and redirect to the frontend
            role_id = "c378f016-62d1-42a9-8eaf-c53750f29ef9"
            group_id = "ca45e5cb-92c3-4537-850b-a586e7f0e816"
            group_name = "jahidul.momin.sajib-group"
        else:
            # First time user setup with owner role
            keycloak_admin_token = await get_cached_admin_token()
            group_name = f"{name_id.split('@')[0]}-group"
            group_id = await get_groups_or_create_groups(keycloak_admin_token, group_name)
            # Add user to group
            await add_user_to_group(keycloak_admin_token, user_id, group_id)
            
            # (It will be owner Role)
            roles = await get_roles(keycloak_admin_token, 'owner')
            if not roles:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Owner role not found in realm"
                )
            role_id = roles.get('id')
            
            await assign_realm_role_to_user(keycloak_admin_token, user_id, role_id, 'owner')
        
        # Create or verify user mapping
        user_result = await create_user_mapper(
            user_keycloak_uid=user_id,
            email=name_id,
            role_keycloak_uid=role_id,
            group_keycloak_uid=group_id,
            group_name=group_name,
            session=session,
            first_name=first_name,
            last_name=last_name,
            invitation_token=invitation_token
        )

        # Generate temporary code
        temp_code = secrets.token_urlsafe(64)
        
        # Store SAML session data
        session_data = {
            "name_id": name_id,
            "session_index": session_index,
            "attributes": attributes,
            "created_at": datetime.now(UTC).isoformat()
        }
        
        redis_client.setex(
            f"saml_code:{temp_code}",
            300,
            json.dumps(session_data)
        )

        # Redirect to frontend with code and session_index
        frontend_url = f"{REDIRECT_URL}?code={temp_code}&session_index={session_index}&state={state}"
        return RedirectResponse(url=frontend_url, status_code=303)
        
    except Exception as e:
        print(f"******* Exception: {e} *******")
        # raise HTTPException(status_code=500, detail=str(e))
        return RedirectResponse(url=f"{FRONTEND_BASE_URL}?error={e}", status_code=303)
    
async def initiate_tokens(code: str, session_index: str):
    try:
        # Get and validate temporary code
        session_data = redis_client.get(f"saml_code:{code}")
        if not session_data:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_code",
                    "error_description": "Invalid or expired code",
                    "status": "error"
                }
            )
            
        session_data = json.loads(session_data)
        
        # Verify session_index
        if session_data['session_index'] != session_index:
            raise HTTPException(status_code=400, detail="Invalid session")
            
        # Delete used code
        redis_client.delete(f"saml_code:{code}")
        
        # Extract user information
        email = session_data["name_id"]
        
        # Create tokens
        access_token = create_token(email, session_index, "access")
        refresh_token = create_token(email, session_index, "refresh")
        
        return JSONResponse({
            "access_token": access_token,
            "refresh_token": refresh_token,
        })
        
    except Exception as e:
        print(f"******* Exception: {e} *******")
        raise HTTPException(status_code=500, detail=str(e))
    
async def initiate_refresh_token(refresh_token_data: dict, session: AsyncSession):
    try:
        session_index = refresh_token_data.get("session_index")
        refresh_token = refresh_token_data.get("token")
        email = refresh_token_data.get("sub")
        
        user_statement = select(UserMapper).where(UserMapper.email == email)
        result = await session.exec(user_statement)
        user = result.first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if refresh token is blacklisted
        if await is_token_blacklisted(refresh_token, session):
            raise HTTPException(
                status_code=401,
                detail="Refresh token has been invalidated"
            )
        
        # Generate new access token
        new_access_token = create_token(email, session_index, "access")
        # Generate new refresh token
        new_refresh_token = create_token(email, session_index, "refresh")
        
        # Blacklist the old refresh token
        await add_to_blacklist(refresh_token, session)
                
        return JSONResponse({
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        })
    except Exception as e:
        print(f"Refresh token error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

        
async def me(current_user: dict, session: AsyncSession):
    try:
        email = current_user.get("sub")
        session_index = current_user.get("session_index")
        
        user_statement = select(UserMapper).where(UserMapper.email == email)
        result = await session.exec(user_statement)
        user = result.first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        session_data_str = redis_client.get(f"saml_session_for_user:{session_index}")
        if session_data_str:
            print(f"******* Session Data: {json.loads(session_data_str)} *******")
            print(f"Return from Redis Cache")
            return JSONResponse({
                "status": "success",
                "data": json.loads(session_data_str)
            })
        
        user_project_statement = select(
            UserMapper.id,
            UserMapper.email,
            UserMapper.first_name,
            UserMapper.last_name,
            Role.id.label('role_id'),
            Role.role_keycloak_uid.label('role_uid'),
            Role.role_name,
            Project.id.label('project_id'),
            Project.project_keycloak_uid.label('project_uid'),
            Project.project_name
        ).join(
            UserRoleProject, UserMapper.id == UserRoleProject.user_id
        ).join(
            Role, UserRoleProject.role_id == Role.id
        ).join(
            Project, UserRoleProject.project_id == Project.id
        ).where(
            UserMapper.email == email
        )
        
        result = await session.exec(user_project_statement)
        user_projects = result.all()
        
        if not user_projects:
            raise HTTPException(status_code=404, detail="User projects not found")
        
        # Get Keycloak admin token
        admin_token = await get_cached_admin_token()
        
        
        projects_info = []
        for row in user_projects:
            # Try to get cached permissions for this role
            cached_permissions = redis_client.get(f"role_permissions:{row.role_name}")
            
            if cached_permissions:
                print(f"Cache hit: Using cached permissions for role {row.role_name}")
                role_permissions = json.loads(cached_permissions)
            else:
                print(f"Cache miss: Fetching permissions for role {row.role_name}")
                # Get permissions from Keycloak
                role_permissions = await get_composite_roles(admin_token, row.role_name)
                # Cache the permissions for this role (1 hour expiry)
                redis_client.set(
                    f"role_permissions:{row.role_name}",
                    json.dumps(role_permissions)
                )

            projects_info.append({
                "project_id": row.project_id,
                "project_uid": str(row.project_uid),
                "project_name": row.project_name,
                "role_id": row.role_id,
                "role_uid": str(row.role_uid),
                "role_name": row.role_name,
                "permissions": role_permissions
            })

        # Create new session data
        session_data = {
            "user_id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "name_id": user.email,
            "email": user.email,
            "projects": projects_info
        }

        # Store back in Redis for future requests
        redis_client.setex(
            f"saml_session_for_user:{session_index}",
            60 * 60 * 24 * 30,  # 30 days
            json.dumps(session_data)
        )

        print(f"******* Session Data From DB: {session_data} *******")  
        return JSONResponse({
            "status": "success",
            "data": session_data
        })
    except Exception as e:
        print(f"******* Exception IN GET USER INFO API: {e} *******")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": str(e),
                "status": "error"
            }
        )
        
async def logout_user(request: Request, refresh_token_data: dict, session: AsyncSession):
    try:
        print(f"******* JUST LOGOUT CALLED *******")
        session_index = refresh_token_data.get("session_index")
        email = refresh_token_data.get("sub")
        refresh_token = refresh_token_data.get("token")
        
        user_statement = select(UserMapper).where(UserMapper.email == email)
        result = await session.exec(user_statement)
        user = result.first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        await add_to_blacklist(refresh_token, session)

        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': {},
            'base_url': BACKEND_BASE_URL
        }
        
        auth = init_saml_auth(req)

        slo_url = auth.logout(
            name_id=email,
            session_index=session_index,
            return_to=FRONTEND_BASE_URL
        )
        redis_client.delete(f"saml_session:{session_index}")
        async with AsyncClient() as client:
            await client.get(slo_url, follow_redirects=True)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Logout successful",
            }
        )
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "logout_error",
                "error_description": str(e),
                "status": "error"
            }
        )
        
async def single_logout(request: Request):
    print(f"*********************** SLO CALLED ********************")
    try:
        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': await request.form() if request.method == "POST" else {},
            'base_url': BACKEND_BASE_URL
        }
        
        auth = init_saml_auth(req)
        
        def delete_session_callback():
            if hasattr(request, 'session'):
                request.session.clear()

        url = auth.process_slo(
            delete_session_cb=delete_session_callback,
            keep_local_session=False,
        )
        
        return RedirectResponse(
            url=FRONTEND_BASE_URL,
            status_code=303
        )
            
    except Exception as e:
        print(f"SLO error: {str(e)}")
        return RedirectResponse(
            url=FRONTEND_BASE_URL,
            status_code=303
        )