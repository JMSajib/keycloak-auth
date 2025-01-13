from datetime import datetime, timedelta, UTC
import jwt
from app.core.config import Config
from app.apis.v1.saml_auth.models import UserMapper
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials
from app.core.security import security
from app.core.redis_client import redis_client
from fastapi.responses import JSONResponse
import json

from app.apis.v1.saml_auth.models import Role, Project, UserRoleProject
from app.apis.v1.utils import get_cached_admin_token, get_composite_roles

def create_token(sub:str, token_type: str = "access"):
    payload = {
        "sub": sub,
        "sso_user": True,
        "exp": datetime.now(UTC) + timedelta(hours=1) if token_type == "access" else datetime.now(UTC) + timedelta(days=30)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")


async def create_user_mapper(user_id, email, dev_role_id, group_id, group_name, session: AsyncSession, first_name:str=None, last_name:str=None,):
    """Create a new user mapping"""
    try:
        statement = select(UserMapper).where(
            UserMapper.user_uid == user_id,
            UserMapper.group_id == group_id
        )
        result = await session.exec(statement)
        existing_user = result.first()
        
        if existing_user:
            print(f"User already exists in project {group_name} with role {existing_user.role_id}")
            raise Exception(f"User already exists in project {group_name} with role {existing_user.role_id}")
        user_mapper = UserMapper(
            user_uid=user_id,
            role_id=dev_role_id,
            group_id=group_id,
            project_name=group_name,
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        session.add(user_mapper)
        await session.commit()
        return user_mapper
    except Exception as e:
        session.rollback()
        raise Exception(f"Failed to create user: {str(e)}")
    
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
            f"oidc_for_user:{email}",
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