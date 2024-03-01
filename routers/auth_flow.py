from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from utils.cryptostuff import CodeManager, JWTmanager, PasswordManager
from utils.models import AuthGrantBody
from urllib.parse import urlencode
from utils.endpoint_dependencies import get_db
from fastapi.templating import Jinja2Templates
from state_handler import code_manager

jwt_manager = JWTmanager()

pw_manager = PasswordManager()

TOKEN_ISSUER = "https://breehze-auth.com"

templates = Jinja2Templates(directory="templates")

test_clients = {"someclient" : "https://example.com/callback",
                "testclient" : "http://127.0.0.1:9000"}


router = APIRouter()

@router.get("/v0/auth")
async def authentification_page(request : Request,response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None):
    q_str = urlencode(dict(request.query_params))
    login_p_endp = "/v0/login?"+q_str
    return templates.TemplateResponse("login.html",{"request": request,"url" : login_p_endp})

@router.post("/v0/token")
async def exchange_auth_code_JSON_body(request: Request, auth_grant_body : AuthGrantBody):
    if auth_grant_body.grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail= "Authorization flow not supported")
    if code_manager.validate_code(auth_grant_body.code) is False:
        raise HTTPException(status_code=400, detail= "Invalid or Expired token")
    if code_manager.validate_url(auth_grant_body.code,auth_grant_body.redirect_uri) is False:
        raise HTTPException(status_code=400, detail= "Invalid redirect url")
    if auth_grant_body.client_id not in test_clients:
        raise HTTPException(status_code=400, detail= "Client does not exist")
    
    print(test_clients[auth_grant_body.client_id])
    token = jwt_manager.jwt_get(issuer= TOKEN_ISSUER ,sub= code_manager.managee[auth_grant_body.code]['associated_user']  , aud = test_clients[auth_grant_body.client_id])
    print(jwt_manager.jwt_decode(token,aud=test_clients[auth_grant_body.client_id]))
    code_manager.managee.pop(auth_grant_body.code)
    
    return {"access_token" : token, "token_type" : "bearer"}


@router.post("/v0/token_form")
async def exchange_auth_code_form_body(grant_type : str = Form(), code : str = Form(),redirect_uri : str = Form(),client_id : str = Form(), client_secret : str = Form(None)):
    auth_grant_body = AuthGrantBody(grant_type=grant_type,code=code,redirect_uri=redirect_uri,client_id=client_id,client_secret=client_secret)
    if auth_grant_body.grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail= "Authorization flow not supported")
    if code_manager.validate_code(auth_grant_body.code) is False:
        raise HTTPException(status_code=400, detail= "Invalid or Expired token")
    if code_manager.validate_url(auth_grant_body.code,auth_grant_body.redirect_uri) is False:
        raise HTTPException(status_code=400, detail= "Invalid redirect url")
    if auth_grant_body.client_id not in test_clients:
        raise HTTPException(status_code=400, detail= "Client does not exist")
    
    print(test_clients[client_id])
    token = jwt_manager.jwt_get(issuer= TOKEN_ISSUER ,sub= code_manager.managee[auth_grant_body.code]['associated_user']  , aud = test_clients[auth_grant_body.client_id])
    print(jwt_manager.jwt_decode(token,aud=test_clients[auth_grant_body.client_id]))
    code_manager.managee.pop(auth_grant_body.code)
    
    return {"access_token" : token, "token_type" : "bearer"}

@router.post("/v0/login")
async def login_user(form_data : OAuth2PasswordRequestForm = Depends(),response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None, db = Depends(get_db)):
    user = await db.find_one({"_id": form_data.username })
    
    if not user or pw_manager.check_pw(form_data.password,user["password"]) != True:
        raise HTTPException(status_code=401, detail= "Incorect password or username")
    if client_id not in test_clients or client_id is None:
        raise HTTPException(status_code=400, detail= "Client does not exist")
    if not redirect_uri.startswith(test_clients[client_id]) or redirect_uri is None:
        raise HTTPException(status_code=400, detail= "Redirect URI not valid")

    authorization_code = code_manager.url_code()

    uri_tempered = f"{redirect_uri}?code={authorization_code}"

    if state is not None:
        uri_tempered += f"&state={state}"

    code_manager.managee.update({authorization_code : {"issue_time" : code_manager.issuance_time(), "associated_url" : redirect_uri,"associated_user" : form_data.username}})

    return RedirectResponse(uri_tempered,status_code=303)
