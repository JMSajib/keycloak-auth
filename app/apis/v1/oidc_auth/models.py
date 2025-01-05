from datetime import datetime

import sqlalchemy
import sqlalchemy.dialects.postgresql as pg
from sqlmodel import Column, Field, SQLModel


class UserMapper(SQLModel, table=True):
    __tablename__ = "users_mapper"

    id: int = Field(
        sa_column=Column(pg.INTEGER, nullable=False, primary_key=True)
    )
    user_uid: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=False)
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
    role_id: str = Field(
        sa_column=Column(pg.UUID, nullable=False)
    )
    group_id: str = Field(
        sa_column=Column(pg.UUID, nullable=False)
    )
    project_name: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=False)
    )
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))

    def __repr__(self):
        return f"<User {self.username}>"