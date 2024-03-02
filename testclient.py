from fastapi import Depends, FastAPI
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import uvicorn
import requests
from jwt import decode
from typing import Annotated
import base64

app = FastAPI()

oauth_scheme = OAuth2AuthorizationCodeBearer(authorizationUrl= "http://127.0.0.1:8000/v0/auth?client_id=testclient&redirect_uri=http://127.0.0.1:9000/redeem" , tokenUrl="http://127.0.0.1:8000/v0/token_form")

giv_key_pls = requests.get("http://127.0.0.1:8000/v0/client_pub_key",headers={"x-api-key":"test_key"})
pub_key = base64.b64decode(giv_key_pls.json())


async def get_user(token : Annotated[str, Depends(oauth_scheme)]):
    subbie = jwt.decode(token,pub_key,algorithms=["RS256"],audience="http://127.0.0.1:9000")['sub']
    return subbie



@app.get("/test")
async def test(user = Depends(get_user)): 
    return user

if __name__ == "__main__":
    uvicorn.run("main:app",host="0.0.0.0",port=9000)
