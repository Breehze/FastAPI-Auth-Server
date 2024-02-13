import fastapi
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates 
import cryptostuff
import  asyncio
from pydantic import BaseModel 


test_codes = {}

app = fastapi.FastAPI()

code_manager = cryptostuff.CodeManager(test_codes)

app.mount("/static",StaticFiles(directory = "static"), name = "static")

templates = Jinja2Templates(directory="templates")


test_clients = {"someclient" : "http://example.com/callback"}

test_users = {"boris" : {"password" : "hello"}}

class AuthGrantBody(BaseModel):
    grant_type : str
    code : str
    redirect_uri : str
    client_id : str 
    client_secret : str | None = None




@app.on_event("startup")
async def startup_events():
    c_m = asyncio.create_task(code_manager.manage())
    print("Startup complete")
    asyncio.gather(c_m)



@app.post("/token")
async def exchange_token(auth_grant_body : AuthGrantBody):
    if auth_grant_body.grant_type != "authorization_code":
        return {"Error" : "I do not support this flow"}
    if code_manager.validate_code(auth_grant_body.code) is False:
        return {"Error" : "Invalid/Expired token"}
    if code_manager.validate_url(auth_grant_body.code,auth_grant_body.redirect_uri) is False:
        return {"Error" : "Invalid redirect url"}
    if auth_grant_body.client_id not in test_clients:
        return {"Error" : "This client app does not exist"}

    
    return {"Hello" : auth_grant_body.grant_type}

@app.get("/login")
async def login_proc(request : fastapi.Request,response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None):
    return templates.TemplateResponse("login.html",{"request": request})

@app.post("/login")
async def login(form_data : OAuth2PasswordRequestForm = fastapi.Depends(),response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None):
    if form_data.username not in test_users or form_data.password != test_users[form_data.username]["password"] :
        return fastapi.HTTPException(status_code=401, detail= "Incorect password or username")
    if client_id not in test_clients or client_id is None:
        return fastapi.HTTPException(status_code=400, detail= "Client does not exist")
    if redirect_uri != test_clients["someclient"] or redirect_uri is None:
        return fastapi.HTTPException(status_code=400, detail= "Redirect URI not valid")

    authorization_code = cryptostuff.url_code()

    uri_tempered = f"{redirect_uri}?code={authorization_code}"

    if state is not None:
        uri_tempered += f"&state={state}"

    test_codes.update({authorization_code : {"issue_time" : cryptostuff.issuance_time(), "associated_url" : redirect_uri} })

    return fastapi.responses.RedirectResponse(uri_tempered,status_code=303)


@app.get("/auth")
async def authorization(response_type : str = "code", client_id : str = None, redirect_uri : str = None, state : str = None):
    if client_id not in test_clients or client_id is None:
        return {"Error" : "Client does not exist"}
    if redirect_uri != test_clients["someclient"] or redirect_uri is None:
        return {"Error": "Invalid uri"}

    authorization_code = cryptostuff.url_code()

    uri_tempered = f"{redirect_uri}?code={authorization_code}"

    if state is not None:
        uri_tempered += f"&state={state}"

    test_codes.update({authorization_code : {"issue_time" : cryptostuff.issuance_time(), "associated_url" : redirect_uri} })

    return fastapi.responses.RedirectResponse(uri_tempered)


