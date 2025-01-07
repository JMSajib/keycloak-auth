from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional
import requests
from urllib.parse import quote
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.db.session import get_session
from app.core.config import Config
from app.apis.v1.saml_auth.crud import create_user_mapper

auth_router = APIRouter()

security = HTTPBearer()

# Keycloak endpoints
TOKEN_URL = f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/token"
AUTH_URL = f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/auth"
REDIRECT_URI = f"{Config.BASE_URL}/auth/callback"

ADMIN_TOKEN_URL = f"{Config.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
DEV_ROLE_NAME = "owner"



class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    login_type: str = "credentials"
    code: Optional[str] = None


async def get_keycloak_admin():
    """Helper function to get KeycloakAdmin instance"""
    try:
        # Get admin token
        admin_token_data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": Config.KEYCLOAK_ADMIN_USERNAME,
            "password": Config.KEYCLOAK_ADMIN_PASSWORD
        }
        response = requests.post(ADMIN_TOKEN_URL, data=admin_token_data)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get('access_token')
        if not access_token:
            raise ValueError("No access token in response")        
        return access_token
    except Exception as e:
        print(f"Keycloak admin initialization error: {str(e)}")
        print(f"Response content: {response.content}")  # Debug print
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize Keycloak admin: {str(e)}"
        )

async def get_groups_or_create_groups(access_token: str, group_name: str):
    """Helper function to get groups from Keycloak"""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    group_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/groups"
    
    response = requests.get(group_url, headers=headers)
    response.raise_for_status()
    groups = response.json()
    
    existing_group = next((group for group in groups if group['name'] == group_name), None)
    if existing_group:
        return existing_group.get('id')
    else:
        response = requests.post(group_url, headers=headers, json={"name": group_name})
        response.raise_for_status()
        # Get group ID from the Location header
        if 'Location' in response.headers:
            # Location header format: '.../groups/group-id'
            group_id = response.headers['Location'].split('/')[-1]
            print(f"Created new group with ID: {group_id}")
            return group_id
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create group: no location header in response"
        )

# async def add_user_to_group(access_token: str, user_id: str, group_id: str):
#     headers = {"Authorization": f"Bearer {access_token}"}
#     group_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/users/{user_id}/groups/{group_id}"
#     response = requests.put(group_url, headers=headers)
#     response.raise_for_status()


async def add_user_to_group(access_token: str, user_id: str, group_id: str):
    """Helper function to add user to group if not already a member"""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # First, check user's current groups
    user_groups_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/users/{user_id}/groups"
    response = requests.get(user_groups_url, headers=headers)
    response.raise_for_status()
    current_groups = response.json()
    
    # Check if user is already in the group
    if any(group['id'] == group_id for group in current_groups):
        print(f"User {user_id} is already in group {group_id}, skipping...")
        return
    
    # If not in group, add them
    group_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/users/{user_id}/groups/{group_id}"
    response = requests.put(group_url, headers=headers)
    response.raise_for_status()
    
    
async def get_roles(access_token, role_name="owner"):
    headers = {"Authorization": f"Bearer {access_token}"}
    roles_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/roles"
    response = requests.get(roles_url, headers=headers)
    response.raise_for_status()
    roles = response.json()
    role = next((r for r in roles if r['name'] == role_name), None)
    return role

async def assign_realm_role_to_user(access_token, user_id, role_id, role_name):
    headers = {"Authorization": f"Bearer {access_token}"}
    assign_role_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm"
    response = requests.post(assign_role_url, headers=headers, json=[{"id": role_id, "name": role_name}])
    response.raise_for_status()
    
    
async def get_composite_roles(access_token, role_name):
    headers = {"Authorization": f"Bearer {access_token}"}
    composite_roles_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/roles/{role_name}/composites"
    response = requests.get(composite_roles_url, headers=headers)
    roles = response.json()
    
    role_names = [role['name'] for role in roles]
    return role_names

@auth_router.post("/login")
async def login(request: LoginRequest):
    """
    Unified login endpoint that handles both credentials and social login
    """
    try:
        if request.login_type == "credentials":
            if not request.username or not request.password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username and password are required for credentials login"
                )
            
            # Handle direct login through Keycloak
            token_data = {
                "grant_type": "password",
                "client_id": Config.KEYCLOAK_CLIENT_ID,
                "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
                "username": request.username,
                "password": request.password
            }
            
            return await exchange_token(token_data)
            
        elif request.login_type in ["google", "facebook", "github"]:
            # Return authorization URL for social login
            auth_params = {
                "client_id": Config.KEYCLOAK_CLIENT_ID,
                "response_type": "code",
                "scope": "openid email profile",
                "redirect_uri": REDIRECT_URI,
                "kc_idp_hint": request.login_type
            }
            
            auth_url = f"{AUTH_URL}?{'&'.join(f'{k}={quote(v)}' for k, v in auth_params.items())}"
            return {"auth_url": auth_url}
            
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid login type"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@auth_router.post("/social-login/{provider}")
async def social_login(provider: str):
    """
    Handle social login initialization for different providers
    """
    if provider not in ["google", "facebook", "github"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported provider"
        )
    
    # Construct authorization URL for the social provider
    auth_params = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": REDIRECT_URI,
        "kc_idp_hint": provider
    }
    
    auth_url = f"{AUTH_URL}?{'&'.join(f'{k}={quote(v)}' for k, v in auth_params.items())}"
    return {"auth_url": auth_url}

@auth_router.get("/callback")
async def social_callback(code: str, session_state: str, session: AsyncSession = Depends(get_session)):
    """
    Handle callback from social login providers
    """
    if not code or not session_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code and session state is required"
        )

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "session_state": session_state
    }
    
    try:
        token_response = requests.post(TOKEN_URL, data=token_data)
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token exchange failed"
            )

        tokens = token_response.json()
        user_info = get_user_info(tokens["access_token"])
        
        
        # Initialize Keycloak admin
        keycloak_admin_token = await get_keycloak_admin()
        
        # Get or create group based on email
        email = user_info.get('email')
        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email not provided by authentication provider"
            )
        
        group_name = f"{email.split('@')[0]}-group"  # Use part before @ as group name
        group_id = await get_groups_or_create_groups(keycloak_admin_token, group_name)
        
        # Add user to group
        await add_user_to_group(keycloak_admin_token, user_info['sub'], group_id)
        
        # # Get dev role
        roles = await get_roles(keycloak_admin_token, DEV_ROLE_NAME)
        if not roles:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"'{DEV_ROLE_NAME}' role not found in realm"
            )
        role_id = roles.get('id')
        await assign_realm_role_to_user(keycloak_admin_token, user_info['sub'], role_id, DEV_ROLE_NAME)
        # create user mapper
        await create_user_mapper(user_info, role_id, group_id, group_name, session)
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "expires_in": tokens["expires_in"],
            "token_type": tokens["token_type"],
            "user": user_info,
            "permissions": await get_composite_roles(keycloak_admin_token, DEV_ROLE_NAME)
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

@auth_router.post("/refresh")
async def refresh_token(refresh_token: str):
    """
    Refresh access token using refresh token
    """
    token_data = {
        "grant_type": "refresh_token",
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    
    return await exchange_token(token_data)

async def exchange_token(token_data: dict):
    """
    Helper function to exchange tokens with Keycloak
    """
    try:
        token_response = requests.post(TOKEN_URL, data=token_data)
        if token_response.status_code == 200:
            tokens = token_response.json()
            user_info = get_user_info(tokens["access_token"])
            
            return {
                "success": True,
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "user": user_info
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token exchange failed"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

def get_user_info(access_token: str) -> dict:
    """
    Get user info from Keycloak using access token specifically for logout
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_url = f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
        
        response = requests.get(userinfo_url, headers=headers)
        response.raise_for_status()  # This will raise an exception for 401 and other error status codes
        
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error getting user info: {e.response.status_code} - {e.response.text}")
        return None
    except Exception as e:
        print(f"Error getting user info: {e}")
        return None


@auth_router.get('/logout')  # Changed to POST to match frontend expectations
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Logout endpoint that matches the Flask implementation
    Requires Bearer token in Authorization header
    """
    try:
        refresh_token = credentials.credentials
        
        # 1. Revoke the access token
        try:
            response = requests.post(
                f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/revoke",
                data={
                    'client_id': Config.KEYCLOAK_CLIENT_ID,
                    'client_secret': Config.KEYCLOAK_CLIENT_SECRET,
                    'token': refresh_token,
                    'token_type_hint': 'refresh_token'
                }
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Error revoking access token: {e}")

        # 2. End Keycloak session
        try:
            response = requests.post(
                f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/logout",
                headers={'Authorization': f'Bearer {refresh_token}'},
                data={
                    'client_id': Config.KEYCLOAK_CLIENT_ID,
                    'client_secret': Config.KEYCLOAK_CLIENT_SECRET,
                    'token': refresh_token
                }
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Error ending Keycloak session: {e}")


        return {
            "message": "Logged out successfully"
        }

    except Exception as e:
        print(f"Error during logout process: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during logout: {str(e)}"
        )


@auth_router.get("/alive")
async def alive():
    return {"message": "Hello, World!"}
