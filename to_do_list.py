import uvicorn
from fastapi import FastAPI
from fastapi import Query, HTTPException, Depends,status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
import os
from datetime import datetime, timedelta
from typing import Union, Any
from jose import jwt
import _ssl

app = FastAPI()


# Connect python with MongoDB
cl = MongoClient("mongodb+srv://akki712:4410@awsinstances.2sixhn0.mongodb.net/test")
db = cl["to_do"]
collection  = db["collection"]


ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minute                  as
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = 'kdsnvjcsnvjnvcdvgdfsjfhcfinifdghdfbvcdifjgbhc' # should be kept secret
JWT_REFRESH_SECRET_KEY = 'pasakopewejoerngchnkxnnerbtryrewiunfjcmbwhkbkhmrhddcmx'  # should be kept secret

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    name: str = Query(None, min_length=1)
    email: str = Query(None, regex='^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$')
    password: str = Query(None, min_length=0, max_length=20)


@app.post('/signup')
async def sign_up(user: User):
    db_collection = db['user']

    # try:
    #     db_collection = db['user']
    #     if db_collection:
    #         count = db.db_collection.count({"email": user.email},{"_id":0})
    #     else:
    #         count = 0
    # except:
    #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server Error")
    #
    # if count > 0:
    #     raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exist")

    user_dict = user.dict()
    password = user_dict['password']
    user_dict['password'] = get_hashed_password(password)
    res = db_collection.insert_one(user_dict)
    return {}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db.get(form_data.username, None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )

    hashed_pass = user['password']
    if not verify_password(form_data.password, hashed_pass):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )

    return {
        "access_token": create_access_token(user['email']),
        "refresh_token": create_refresh_token(user['email']),
    }


@app.get("/items/")
async def read_items(token: str = Depends(oauth2_scheme)):
    return {"token": token}


## CRUD Operations

""""  
C in CRUD - Create 
this route posts data to  the Database
"""
@app.post('/to_do_list/{Task}/{Done}')
def add_to_list(Task:str,Done:str):
    task ={"Task":Task,"Done":Done}
    db.collection.insert_one(task)
    return "posted"


""" 
R in CRUD - Read
this route gets the data from the Database
"""
@app.get('/to_do_list')
def get_list():
    return list(db.collection.find({},{"_id":0}))



""" 
U in CRUD - Update
this route updates the data already present in the Database
"""
@app.put('/to_do_list/{Task}/{Done}')
def update_list(Task:str,Done:str):
    db.collection.update_one({"Task":Task},{"$set":{"Done":Done}})
    return "updated"


"""
D in CRUD - Delete
this route deletes the data from the Database
"""
@app.delete('/to_do_list/{Task}')
def delete_from_list(Task:str):
    db.collection.remove({"Task":Task})
    return "Deleted"


if __name__ == '__main__':
    uvicorn.run("to_do_list:app", host="127.0.0.1", port=8080, reload=True)

