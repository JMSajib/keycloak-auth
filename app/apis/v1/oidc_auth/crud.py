import random, uuid, json, secrets
import requests
from urllib.parse import quote

from fastapi import status
from fastapi.responses import JSONResponse
from fastapi import HTTPException

from app.core.config import Config
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select

from app.core.redis_client import redis_client

from app.apis.v1.saml_auth.models import (
    Role, 
    Project, 
    UserRoleProject, 
    BlackListedToken, 
    UserMapper
)

from app.apis.v1.utils import (
    get_groups_or_create_groups, 
    get_roles, 
    assign_realm_role_to_user,
    get_cached_admin_token,
    add_user_to_group,
    get_user_info,
    get_composite_roles,
    create_token
)

import jwt


from app.apis.v1.oidc_auth.schemas import TokenRequest


TOKEN_URL = f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/token"
AUTH_URL = f"{Config.KEYCLOAK_EXTERNAL_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/auth"
REDIRECT_URI = f"{Config.FRONTEND_BASE_URL}/auth/callback"


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
    

        
async def login_request(provider: str, invitation_token: str = None):
    """
    Handle social login initialization for different providers
    """
    if provider not in ["google", "oidc"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported provider"
        )
    state = secrets.token_urlsafe(64)
    if invitation_token:
        print(f"******* Invitation Token: {invitation_token} *******")
        # Store state in Redis
        redis_client.setex(
            f"invitation_code:{state}",
            300,  # 5 minutes
            invitation_token
        )
    # Construct authorization URL for the social provider
    auth_params = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": REDIRECT_URI,
        "kc_idp_hint": provider,
        "state": state
    }    
    auth_url = f"{AUTH_URL}?{'&'.join(f'{k}={quote(v)}' for k, v in auth_params.items())}"
    return {"auth_url": auth_url}


        
async def callback_function(request: TokenRequest, session: AsyncSession):
    print(f"************** CALLBACK CALLED ***************")
    print(f"code: {request.code}, session_state: {request.session_state}, invitation_token: {request.state}")
    if not request.code or not request.session_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code and session state are required"
        )
    if request.state:
        invitation_token = redis_client.get(f"invitation_code:{request.state}")
        redis_client.delete(f"invitation_code:{request.state}")
    
    code = request.code
    session_state = request.session_state

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "session_state": session_state
    }
    
    print(f"******* TOKEN URL: {TOKEN_URL} *******")
    
    try:
        token_response = requests.post(TOKEN_URL, data=token_data)
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token exchange failed"
            )

        tokens = token_response.json()
        decoded_data = jwt.decode(tokens["access_token"], options={"verify_signature": False})
        print(f"******* DECODED DATA: {decoded_data} *******")
        user_info = get_user_info(tokens["access_token"])
        print(f"******* USER INFO: {user_info} *******")
        email = user_info.get('email')
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email not provided by authentication provider"
            )
        
        # if invitation_token:
        #     pass
        # else:
        #     pass
        
        # Initialize Keycloak admin
        keycloak_admin_token = await get_cached_admin_token()

        group_name = f"{email.split('@')[0]}-project"  # Use part before @ as group name
        group_id = await get_groups_or_create_groups(keycloak_admin_token, group_name)
        
        # Add user to group
        await add_user_to_group(keycloak_admin_token, user_info['sub'], group_id)
        
        # Get Admin role
        roles = await get_roles(keycloak_admin_token, 'Admin')
        if not roles:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"'{'Admin'}' role not found in realm"
            )
        role_id = roles.get('id')
        await assign_realm_role_to_user(keycloak_admin_token, user_info['sub'], role_id, 'Admin')
        # create user mapper
        # user_id, email, dev_role_id, group_id, group_name, session: AsyncSession, first_name:str=None, last_name:str=None,
        await create_user_mapper(user_info['sub'], email, role_id, group_id, group_name, session, user_info.get('given_name'), user_info.get('family_name'))
        
        # Create tokens
        access_token = create_token(email, "access")
        refresh_token = create_token(email, "refresh")
        
        token_data = {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token")
        }
        redis_client.set(
            f"keycloak_tokens:{email}",
            json.dumps(token_data)
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except HTTPException as he:
        print(f"HTTPException Onboarding: {he}")
        raise he
    except Exception as e:
        print(f"Exception During Authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )
        
        
async def me(current_user: dict, session: AsyncSession):
    try:
        email = current_user.get("sub")
        
        user_statement = select(UserMapper).where(UserMapper.email == email)
        result = await session.exec(user_statement)
        user = result.first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        session_data_str = redis_client.get(f"oidc_for_user:{email}")
        if session_data_str:
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
            f"oidc_for_user:{email}",
            60 * 60 * 24 * 30,  # 30 days
            json.dumps(session_data)
        )

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


async def logout_user(current_user: dict, session: AsyncSession):
    try:
        email = current_user.get("sub")
        token_data = redis_client.get(f"keycloak_tokens:{email}")
        refresh_token = None
        access_token = None
        if token_data:
            token_data = json.loads(token_data)
            refresh_token = token_data.get("refresh_token")
            access_token = token_data.get("access_token")
        else:
            pass
        
        # Construct logout URL with all necessary parameters
        logout_params = {
            'client_id': Config.KEYCLOAK_CLIENT_ID,
            'client_secret': Config.KEYCLOAK_CLIENT_SECRET,
            'refresh_token': refresh_token  # Using access token here
        }
        
        # End Keycloak session using the logout endpoint
        response = requests.post(
            f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/logout",
            data=logout_params
        )
        
        if response.status_code not in [200, 204]:
            print(f"Keycloak logout failed with status {response.status_code}: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to logout from authentication server"
            )
        redis_client.delete(f"keycloak_tokens:{email}")
        redis_client.delete(f"oidc_for_user:{email}")

        return {
            "message": "Logged out successfully",
            "status": "success"
        }

    except Exception as e:
        print(f"Error during logout process: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during logout: {str(e)}"
        )

        
async def initiate_refresh_token(refresh_token_data: dict, session: AsyncSession):
    try:
        refresh_token = refresh_token_data.get("token")
        email = refresh_token_data.get("sub")
        
        user_statement = select(UserMapper).where(UserMapper.email == email)
        result = await session.exec(user_statement)
        user = result.first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if refresh token is blacklisted
        if await is_token_blacklisted(refresh_token, session):
            return JSONResponse({
                "status": "error",
                "error": "invalid_token",
                "error_description": "Refresh token has been invalidated"
            }, status_code=401)
        
        # Generate new access token
        new_access_token = create_token(email, "access")
        # Generate new refresh token
        new_refresh_token = create_token(email, "refresh")
        
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