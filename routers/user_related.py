from contextlib import asynccontextmanager
from fastapi import APIRouter, HTTPException, Depends , Request
from utils.models import RegisterBody,ReqResetPasswordBody,ResetPasswordBody
from utils.endpoint_dependencies import get_db
from utils.cryptostuff import PasswordManager 
from contextlib import asynccontextmanager
from  fastapi.templating import Jinja2Templates
from pymongo.errors import DuplicateKeyError
from utils.mailstuff import send_pw_reset
from state_handler import pw_reset_manager
from dotenv import load_dotenv
from os import getenv
from time import time


pw_manager = PasswordManager()

router = APIRouter()

templates = Jinja2Templates(directory="templates")

anti_spam = {}
expiration_time = 3600  

@router.get("/v0/register")
async def register_page(request:Request):
    return templates.TemplateResponse("register.html",{"request": request})

@router.get("/v0/reset_password")
async def password_reset_submit_mail(request:Request):
    return templates.TemplateResponse("pw_reset_mail.html",{"request": request})

@router.post("/v0/register")
async def register_user(register : RegisterBody, db = Depends(get_db)): 
    if register.user_password != register.user_password_repeat:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    try:
        await db.insert_one({"_id" : register.user_mail, "password" : pw_manager.hash_pw(register.user_password) })
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="This user already exists")

    return {"Created_user" : register.user_mail}

@router.post("/v0/req_pw_reset")
async def request_reset_password(request : Request,reset: ReqResetPasswordBody,db = Depends(get_db)):
    if reset.user_mail in anti_spam:
        if   time() - anti_spam[reset.user_mail] >= expiration_time :
            anti_spam.pop(reset.user_mail)
        else:
            raise HTTPException(status_code=400,detail="User requested reset")
    user = await db.find_one({"_id": reset.user_mail })
    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")
    reset_token = pw_reset_manager.url_code()
    pw_reset_manager.managee.update({reset_token : {"issue_time" : pw_reset_manager.issuance_time(),"associated_user" : reset.user_mail}})
    anti_spam.update({reset.user_mail : time()})
    send_pw_reset(reset.user_mail,templates.TemplateResponse("pw_reset_template.html",{"request": request,"reset_url" : f"{getenv('DOMAIN')}/v0/pw_reset?token={reset_token}" }).body)
    return "Mail sent"

@router.get("/v0/pw_reset")
async def password_reset_page( request : Request, token : str = None):
    if token is not None and token not in pw_reset_manager.managee:
        pass
    reset_url = f"http://127.0.0.1:8000/v0/pw_reset/{token}"
    return templates.TemplateResponse("pw_reset_page.html",{"request" : request, "reset_url" : reset_url})

@router.patch("/v0/pw_reset/{token}")
async def password_reset(body: ResetPasswordBody, token : str = None, db = Depends(get_db) ):
    if token not in pw_reset_manager.managee or token is None:
        raise HTTPException(status_code=400,detail="Invalid token")
    if body.new_password != body.new_password_repeat:
        raise HTTPException(status_code=400, detail= "New passwords do not match")
    result = await db.update_one({"_id": pw_reset_manager.managee[token]['associated_user']}, {"$set": {"password" : pw_manager.hash_pw(body.new_password)}})
    pw_reset_manager.managee.pop(token)
    return "Password reset"
    
