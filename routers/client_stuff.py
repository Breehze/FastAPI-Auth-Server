from fastapi import APIRouter
from fastapi import Security
from utils.cryptostuff import KeyManager 
from utils.endpoint_dependencies import get_api_key
from state_handler import key_manager 


router = APIRouter()


@router.get("/v0/client_pub_key")
async def retrieve_public_key(api_key : str = Security(get_api_key)):
    return key_manager.pub_base64
