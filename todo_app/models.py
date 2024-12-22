from sqlalchemy import Column, Integer, String, Boolean
from database import Base


class TodoItem(Base):
    __tablename__ = "todo_items"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, nullable=True)
    user_id = Column(Integer)
    completed = Column(Boolean, default=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    password = Column(String)
