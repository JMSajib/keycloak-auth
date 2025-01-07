import requests
from fastapi import HTTPException, status
from app.core.config import Config
from httpx import AsyncClient


TOKEN_URL = f"{Config.KEYCLOAK_URL}/realms/{Config.KEYCLOAK_REALM}/protocol/openid-connect/token"
REDIRECT_URI = f"{Config.BASE_URL}/auth/callback"

ADMIN_TOKEN_URL = f"{Config.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
DEV_ROLE_NAME = "owner"

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
    print(f"******* User ID: {user_id} *******")
    print(f"******* Group ID: {group_id} *******")
    """Helper function to add user to group if not already a member"""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # First, check user's current groups
    user_groups_url = f"{Config.KEYCLOAK_URL}/admin/realms/{Config.KEYCLOAK_REALM}/users/{user_id}/groups"
    response = requests.get(user_groups_url, headers=headers)
    response.raise_for_status()
    current_groups = response.json()
    
    print(f"Current groups: {current_groups}")
    
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