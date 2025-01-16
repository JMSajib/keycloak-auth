import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from app.core.security import security
from app.core.config import Config
from httpx import AsyncClient
from datetime import datetime, timedelta, UTC
import json
from typing import Optional

import requests

from app.core.redis_client import redis_client


def create_token(sub:str, token_type: str = "access"):
    payload = {
        "sub": sub,
        "sso_user": True,
        "exp": datetime.now(UTC) + timedelta(hours=1) if token_type == "access" else datetime.now(UTC) + timedelta(days=30)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")

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

async def get_keycloak_admin() -> str:
    """Get a new admin token from Keycloak"""
    try:
        async with AsyncClient() as client:
            response = await client.post(
                f"{Config.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": Config.KEYCLOAK_ADMIN_USERNAME,
                    "password": Config.KEYCLOAK_ADMIN_PASSWORD
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to get admin token"
                )
                
            return response.json()["access_token"]
            
    except Exception as e:
        print(f"Error getting admin token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
    

async def get_roles(access_token, role_name="Admin"):
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


def get_user_info(access_token: str) -> dict:
    """
    Get user info from Keycloak using access token specifically for logout
    """
    try:
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }        
        print(f"******* USERINFO URL: {Config.USERINFO_URL} *******")
        response = requests.get(Config.USERINFO_URL, headers=headers, verify=False)
        response.raise_for_status()  # This will raise an exception for 401 and other error status codes
        
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error getting user info: {e.response.status_code} - {e.response.text}")
        return None
    except Exception as e:
        print(f"Error getting user info: {e}")
        return None