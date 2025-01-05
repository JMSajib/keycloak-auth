from datetime import datetime

import sqlalchemy
import sqlalchemy.dialects.postgresql as pg
from sqlmodel import Column, Field, SQLModel


class Role(SQLModel, table=True):
    __tablename__ = "roles"

    id: int = Field(sa_column=Column(pg.INTEGER, nullable=False, primary_key=True))
    role_name: str = Field(sa_column=Column(pg.VARCHAR, nullable=False, unique=True))
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))

class Project(SQLModel, table=True):
    __tablename__ = "projects"

    id: int = Field(sa_column=Column(pg.INTEGER, nullable=False, primary_key=True))
    project_name: str = Field(sa_column=Column(pg.VARCHAR, nullable=False))
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