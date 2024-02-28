from asyncio.tasks import create_task
from fastapi import FastAPI 
from fastapi.staticfiles import StaticFiles
from routers import auth_flow, user_related
from contextlib import asynccontextmanager
import asyncio
from routers.client_stuff import router
from state_handler import key_manager, code_manager,pw_reset_manager
from dotenv import load_dotenv
from os import getenv

TOKEN_ISSUER = getenv("DOMAIN") 

@asynccontextmanager
async def lifespan(app : FastAPI):
    c_m = asyncio.create_task(code_manager.manage())
    k_m = asyncio.create_task(key_manager.key_rotate())
    pr_m = asyncio.create_task(pw_reset_manager.manage())
    asyncio.gather(k_m,c_m,pr_m)
    yield



app = FastAPI(lifespan = lifespan)

app.mount("/static",StaticFiles(directory = "static"), name = "static")


app.include_router(auth_flow.router)
app.include_router(user_related.router)
app.include_router(router)
