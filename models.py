from pydantic import BaseModel, EmailStr

class AuthGrantBody(BaseModel):
    grant_type : str
    code : str
    redirect_uri : str
    client_id : str 
    client_secret : str | None = None

class RegisterBody(BaseModel):
    user_mail : EmailStr
    user_password : str
    user_password_repeat : str
