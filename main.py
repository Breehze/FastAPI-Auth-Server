import fastapi
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from urllib.parse import urlencode 
from cryptostuff import CodeManager, JWTmanager , KeyManager , PasswordManager
from endpoint_dependencies import get_api_key
from contextlib import asynccontextmanager
import  asyncio
from pydantic import BaseModel 

TOKEN_ISSUER = "https://breehze-auth.com"


codes = {}

code_manager = CodeManager(codes)

jwt_manager = JWTmanager()

key_manager = KeyManager()

pw_manager = PasswordManager()

@asynccontextmanager
async def lifespan(app : fastapi.FastAPI):
    c_m = asyncio.create_task(code_manager.manage())
    k_m = asyncio.create_task(key_manager.key_rotate())
    asyncio.gather(c_m)
    yield

app = fastapi.FastAPI(lifespan=lifespan)

app.mount("/static",StaticFiles(directory = "static"), name = "static")

templates = Jinja2Templates(directory="templates")


test_clients = {"someclient" : "https://example.com/callback"}

test_users = {"boris" : {"password" : b'$2b$12$vjPmHb3HEuMjmWsr4PuJAO5C2.gVhcJ3hDbpVnkegVC3P9KuYy862'},"fiitsucksdick" : {"password" : "jolanda"}}

class AuthGrantBody(BaseModel):
    grant_type : str
    code : str
    redirect_uri : str
    client_id : str 
    client_secret : str | None = None

class RegisterBody(BaseModel):
    user_mail : str
    user_password : str
    user_password_repeat : str

@app.get("/v0/auth")
async def authentification_page(request : fastapi.Request,response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None):
    q_str = urlencode(dict(request.query_params))
    login_p_endp = "/v0/login?"+q_str
    return templates.TemplateResponse("login.html",{"request": request,"url" : login_p_endp})

@app.get("/v0/client_pub_key")
async def retrieve_public_key(api_key : str = fastapi.Security(get_api_key)):
    return key_manager.pub_base64

@app.post("/v0/token")
async def exchange_token(auth_grant_body : AuthGrantBody):
    if auth_grant_body.grant_type != "authorization_code":
        raise fastapi.HTTPException(status_code=400, detail= "Authorization flow not supported")
    if code_manager.validate_code(auth_grant_body.code) is False:
        raise fastapi.HTTPException(status_code=400, detail= "Invalid or Expired token")
    if code_manager.validate_url(auth_grant_body.code,auth_grant_body.redirect_uri) is False:
        raise fastapi.HTTPException(status_code=400, detail= "Invalid redirect url")
    if auth_grant_body.client_id not in test_clients:
        raise fastapi.HTTPException(status_code=400, detail= "Client does not exist")
    
    print(auth_grant_body.redirect_uri)
    token = jwt_manager.jwt_get(issuer= TOKEN_ISSUER ,sub= codes[auth_grant_body.code]['associated_user']  , aud = auth_grant_body.redirect_uri)
    print(jwt_manager.jwt_decode(token,aud=auth_grant_body.redirect_uri))
    codes.pop(auth_grant_body.code)
    
    return {"access_token" : token, "token_type" : "bearer"}

@app.post("/v0/register")
async def register_user(register : RegisterBody): 
    if register.user_mail in test_users:
        raise fastapi.HTTPException(status_code=409, detail="This user already exists")
    if register.user_password != register.user_password_repeat:
        raise fastapi.HTTPException(status_code=400, detail="Passwords do not match")
    test_users.update({register.user_mail : {"password" : pw_manager.hash_pw(register.user_password) }})
    return {"Created_user" : register.user_mail}

@app.post("/v0/login")
async def login_user(form_data : OAuth2PasswordRequestForm = fastapi.Depends(),response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None):
    if form_data.username not in test_users or pw_manager.check_pw(form_data.password,test_users[form_data.username]["password"]) != True:
        raise fastapi.HTTPException(status_code=401, detail= "Incorect password or username")
    if client_id not in test_clients or client_id is None:
        raise fastapi.HTTPException(status_code=400, detail= "Client does not exist")
    if redirect_uri != test_clients["someclient"] or redirect_uri is None:
        raise fastapi.HTTPException(status_code=400, detail= "Redirect URI not valid")

    authorization_code = code_manager.url_code()

    uri_tempered = f"{redirect_uri}?code={authorization_code}"

    if state is not None:
        uri_tempered += f"&state={state}"

    codes.update({authorization_code : {"issue_time" : code_manager.issuance_time(), "associated_url" : redirect_uri,"associated_user" : form_data.username}})

    return fastapi.responses.RedirectResponse(uri_tempered,status_code=303)

