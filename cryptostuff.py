import uuid
import time
import asyncio
import copy 


def url_code():
    return str(uuid.uuid4())

def issuance_time():
    return time.time()

class CodeManager:
    def __init__(self,managee: dict):
        self.managee = managee    
    
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
            print(self.managee)
            await asyncio.sleep(2)
        
