from datetime import datetime
import uuid
import sqlalchemy
import sqlalchemy.dialects.postgresql as pg
from sqlmodel import Column, Field, SQLModel


class UserMapper(SQLModel, table=True):
    __tablename__ = "users_mapper"

    id: int = Field(
        sa_column=Column(pg.INTEGER, nullable=False, primary_key=True)
    )
    user_core_id: int = Field(
        sa_column=Column(pg.INTEGER, nullable=False)
    )
    user_keycloak_uid: uuid.UUID = Field(
        sa_column=Column(pg.UUID, nullable=False, unique=True)
    )
    username: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=False)
    )
    email: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=False)
    )
    first_name: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=True)
    )
    last_name: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=True)
    )
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))

    def __repr__(self):
        return f"<User {self.username}>"


class Role(SQLModel, table=True):
    __tablename__ = "roles"

    id: int = Field(sa_column=Column(pg.INTEGER, nullable=False, primary_key=True))
    role_keycloak_uid: uuid.UUID = Field(sa_column=Column(pg.UUID, nullable=False, unique=True))
    role_name: str = Field(sa_column=Column(pg.VARCHAR, nullable=False, unique=True))
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))


class Project(SQLModel, table=True):
    __tablename__ = "projects"

    id: int = Field(sa_column=Column(pg.INTEGER, nullable=False, primary_key=True))
    project_keycloak_uid: uuid.UUID = Field(sa_column=Column(pg.UUID, nullable=False, unique=True))
    project_name: str = Field(sa_column=Column(pg.VARCHAR, nullable=False, unique=True))
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))


class UserRoleProject(SQLModel, table=True):
    __tablename__ = "user_role_project"

    id: int = Field(sa_column=Column(pg.INTEGER, nullable=False, primary_key=True))
    user_id: int = Field(default=False, foreign_key="users_mapper.id")
    role_id: int = Field(nullable=False, foreign_key="roles.id")
    project_id: int = Field(nullable=False, foreign_key="projects.id")
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))

    __table_args__ = (
        # Ensure user can only have one role per project
        sqlalchemy.UniqueConstraint('user_id', 'project_id', name='unique_user_project'),
    )
    
    
class BlackListedToken(SQLModel, table=True):
    __tablename__ = "blacklisted_tokens"
    
    id: int = Field(sa_column=Column(pg.INTEGER, nullable=False, primary_key=True))
    token: str = Field(sa_column=Column(pg.VARCHAR, nullable=False))
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))