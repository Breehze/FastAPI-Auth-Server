import uuid
import time
import asyncio
import copy 
import os
import jwt
from dotenv import load_dotenv


class JWTmanager:
    def __init__(self):
        with open("private_key.pem", 'r') as key_file:
            self.private_key = key_file.read()
        with open("public_key.pem", 'r') as key_file:
            self.public_key = key_file.read()
    def jwt_get(self,sub : any , aud : str ,payload_append : dict = None):
        issued_time = time.time()
        payload = {"iss" : "",
                   "sub" : sub,
                   "aud" : aud,
                   "exp" : issued_time + 3600,
                   "iat" : issued_time}
        if payload_append != None:
            payload.update(payload_append)
        print(payload["aud"])
        return jwt.encode(payload,self.private_key,algorithm = "RS256")
    def jwt_decode(self,token,aud = None):
        return jwt.decode(token,self.public_key,algorithms = ["RS256"],audience = aud)

class CodeManager:
    def __init__(self,managee: dict):
        self.managee = managee    
    
    def url_code(self):
        return str(uuid.uuid4())
    
    def issuance_time(self):
        return time.time()
    
    def validate_code(self,code):
        if code not in self.managee:
            return False
        return True
    
    def validate_url(self,code,new_url):
        if self.managee[code]["associated_url"] != new_url:
            return False
        return True
    
    async def manage(self):
        while True: 
            for token,metadata in copy.copy(self.managee).items():
                if time.time() - metadata["issue_time"] >= 120 :
                    self.managee.pop(token)
            await asyncio.sleep(2)

