from typing import List, Optional, Annotated
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import TodoItem as TodoItemModel
from models import User
from passlib.context import CryptContext
import security

Base.metadata.create_all(bind=engine)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app = FastAPI()


class UserModel(BaseModel):
    username: str
    password: str


class TodoCreate(BaseModel):
    title: str
    description: Optional[str] = None
    completed: bool = False


class TodoItem(BaseModel):
    id: int
    title: str
    user_id: int
    description: Optional[str] = None
    completed: bool = False

    class Config:
        orm_mode = True


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_hashed_password(password):
    return pwd_context.hash(password)


def verify_user(user: UserModel, db: Session):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Item not found")
    elif not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Wrong password, try again")
    return db_user


def get_current_user(token: str, db: Session):
    payload = security.decode_jwt(token)
    user_id: int = payload.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=403, detail="Wrong token")
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=403, detail="User from token does not exist")
    return db_user


@app.post("/users/signup")
async def create_user(user: UserModel, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="User already exists")
    new_user = User(
        username=user.username,
        password=get_hashed_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Sign up is successful"}


@app.post("/users/login")
async def user_login(user: UserModel, db: Session = Depends(get_db)):
    db_user = verify_user(user, db)
    return security.sign_jwt(db_user.id)


@app.get("/items", response_model=List[TodoItem])
def get_items(token: Annotated[str, Depends(security.JWTBearer())], db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    items = db.query(TodoItemModel).filter(TodoItemModel.user_id == user.id).all()
    return items


@app.get("/items/{item_id}", response_model=TodoItem)
def get_item(item_id: int, token: Annotated[str, Depends(security.JWTBearer())],  db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    item = db.query(TodoItemModel).filter(TodoItemModel.id == item_id and TodoItemModel.user_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.post("/items", response_model=TodoItem)
def create_item(item: TodoCreate, token: Annotated[str, Depends(security.JWTBearer())], db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    new_item = TodoItemModel(
        title=item.title,
        description=item.description,
        user_id=user.id,
        completed=item.completed
    )
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item


@app.put("/items/{item_id}", response_model=TodoItem)
def update_item(item_id: int, item: TodoCreate, token: Annotated[str, Depends(security.JWTBearer())], db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    db_item = db.query(TodoItemModel).filter(TodoItemModel.id == item_id and TodoItemModel.user_id == user.id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    db_item.title = item.title
    db_item.description = item.description
    db_item.completed = item.completed
    db.commit()
    db.refresh(db_item)
    return db_item


@app.delete("/items/{item_id}")
def delete_item(item_id: int, token: Annotated[str, Depends(security.JWTBearer())], db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    db_item = db.query(TodoItemModel).filter(TodoItemModel.id == item_id and TodoItemModel.user_id == user.id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(db_item)
    db.commit()
    return {"message": "Item deleted"}

