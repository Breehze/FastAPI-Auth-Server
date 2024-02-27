import uuid
import time
import asyncio
import copy 
import os
import jwt
import base64
import bcrypt
from dotenv import load_dotenv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class KeyManager:
    def __init__(self):
        self.pub_base64 = ''
    async def key_rotate(self):
        while True:
            private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
            public_key = private_key.public_key()
            with open("private_key.pem", "wb") as f:
                f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()))
            with open("public_key.pem", "wb") as f:
                f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
            self.pub_base64 = self.get_base64("private_key.pem")
            await asyncio.sleep(120)
    
    def get_base64(self,path):
        with open(path,"rb") as rd:
            pem_data = rd.read()
            base64_enc = base64.b64encode(pem_data).decode("utf-8")
            data = '\n'.join([base64_enc[i:i+64] for i in range(0, len(base64_enc), 64)])
        return data
class JWTmanager:
    def jwt_get(self,issuer : str ,sub : any , aud : str ,payload_append : dict = None):
        with open("private_key.pem", 'r') as key_file:
            private_key = key_file.read()
        issued_time = time.time()
        payload = {"iss" : issuer,
                   "sub" : sub,
                   "aud" : aud,
                   "exp" : issued_time + 3600,
                   "iat" : issued_time}
        if payload_append != None:
            payload.update(payload_append)
        print(payload["aud"])
        return jwt.encode(payload,private_key,algorithm = "RS256")
    def jwt_decode(self,token,aud = None):
        with open("public_key.pem", 'r') as key_file:
            public_key = key_file.read()
        return jwt.decode(token,public_key,algorithms = ["RS256"],audience = aud)

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
    
    def validate_url(self,code : str,new_url : str):
        if self.managee[code]["associated_url"] != new_url:
            return False
        return True
    
    async def manage(self,expiration_time = 120):
        while True: 
            for token,metadata in copy.copy(self.managee).items():
                if time.time() - metadata["issue_time"] >= expiration_time :
                    self.managee.pop(token)
            await asyncio.sleep(5)

class PasswordManager:
    def hash_pw(self,password ):
        return bcrypt.hashpw(password.encode("utf-8"),bcrypt.gensalt())
    def check_pw(self,pw_to_check,pw_saved):
        if bcrypt.checkpw(pw_to_check.encode("utf-8"),pw_saved):
            return True
        return False