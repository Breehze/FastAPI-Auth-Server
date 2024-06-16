from fastapi import FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from os import getenv
from dotenv import load_dotenv

import motor.motor_asyncio
from pymongo import ReturnDocument

load_dotenv()

API_KEY =  getenv("API_KEY")

load_dotenv()

def get_api_key(api_key_header: str = Security(APIKeyHeader(name="X-API-Key"))) -> str:
    if api_key_header == API_KEY :
        return api_key_header
    raise HTTPException(status_code= 401 ,detail="Unauthorized")

def get_db():
    client = motor.motor_asyncio.AsyncIOMotorClient(getenv("MONGO_CON_STR"))
    db = client["AuthUsers"]
    collection = db['Users']
    try:
        yield collection
    finally:
        client.close()
