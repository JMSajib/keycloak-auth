from app.apis.v1.oidc_auth.models import UserMapper
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select



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