from fastapi.testclient import TestClient
import pytest
from main import app, TOKEN_ISSUER 
from utils.cryptostuff import JWTmanager
from state_handler import code_manager
from utils.endpoint_dependencies import get_db
from routers.auth_flow import test_clients

import motor.motor_asyncio
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from pymongo import MongoClient

from dotenv import load_dotenv
from os import getenv

CON_STRING = getenv("MONGO_CON_STR")

def override_get_db():
    client = motor.motor_asyncio.AsyncIOMotorClient(CON_STRING) 
    db = client["AuthUsers"]
    collection = db['testUsers']
    try:
        yield collection
    finally:
        
        client.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture(autouse = True)
def setup_teardown():
    client = MongoClient(CON_STRING)
    db = client["AuthUsers"]
    collection = db['testUsers']
    code_manager.managee.clear()
    yield
    collection.delete_many({})


def test_register_password_missmatch():
    req_body = {
        "user_mail" : "something@something.com",
        "user_password" : "hello",
        "user_password_repeat" : "gotohell"
    }
    response = client.post('/v0/register',json=req_body)
    assert response.status_code == 400


def test_register_new_user():
    req_body = {
        "user_mail" : "something@something.com",
        "user_password" : "hello",
        "user_password_repeat" : "hello"
    }
    response = client.post('/v0/register',json=req_body)
    assert response.status_code == 200
    assert response.json() == {"Created_user" : req_body['user_mail']}

def test_register_registered_user():
    req_body = {
        "user_mail" : "something@something.com",
        "user_password" : "hello",
        "user_password_repeat" : "hello"
    }
    client.post('/v0/register',json=req_body)
    response = client.post('/v0/register',json=req_body)
    assert response.status_code == 409

def test_login_sucssesful_login():
    req_body = {
        "username" : "something@something.com",
        "password" : "hello"
    }
    client.post('/v0/register', json= {"user_mail" : "something@something.com" , "user_password" : "hello", "user_password_repeat" : "hello"})
    response = client.post('/v0/login?redirect_uri=https://example.com/callback&client_id=someclient', data=req_body, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['Location'] == 'https://example.com/callback?code='+ list(code_manager.managee.keys())[0]


def test_login_wrong_passwords():
    req_body = {
        "username" : "test",
        "password" : "wrong_password"
    }
    client.post('/v0/register', json= {"user_mail" : "test" , "user_password" : "test", "user_password_repeat" : "test"})
    response = client.post('/v0/login?redirect_uri=https://example.com/callback&client_id=someclient', data=req_body, follow_redirects=False)
    assert response.status_code == 401

def test_login_non_existing_user():
    req_body = {
        "username" : "test",
        "password" : "test"
    }
    response = client.post('/v0/login?redirect_uri=https://example.com/callback&client_id=someclient', data=req_body, follow_redirects=False)
    assert response.status_code == 401

def test_login_invalid_clientId():
    req_body = {
        "username" : "something@something.com",
        "password" : "hello"
    }
    client.post('/v0/register', json= {"user_mail" : "something@something.com" , "user_password" : "hello", "user_password_repeat" : "hello"})
    response = client.post('/v0/login?redirect_uri=https://example.com/callback&client_id=otherclient', data=req_body, follow_redirects=False)
    assert response.status_code == 400

def test_login_invalid_redirectURI():
    req_body = {
        "username" : "something@something.com",
        "password" : "hello"
    }
    client.post('/v0/register', json= {"user_mail" : "something@something.com" , "user_password" : "hello", "user_password_repeat" : "hello"})
    response = client.post('/v0/login?redirect_uri=https://other.hello&client_id=someclient', data=req_body, follow_redirects=False)
    assert response.status_code == 400

def test_token_valid_token():
    client.post('/v0/register', json= {"user_mail" : "something@something.com" , "user_password" : "hello", "user_password_repeat" : "hello"})
    client.post('/v0/login?redirect_uri=https://example.com/callback&client_id=someclient', data= {"username" : "something@something.com","password" : "hello"}, follow_redirects=False)
    req_body = {
        "grant_type" : "authorization_code",
        "code" : list(code_manager.managee.keys())[0] ,  
        "redirect_uri" : "https://example.com/callback",
        "client_id" : "someclient"
    }
    response = client.post('/v0/token', json= req_body)
    assert response.status_code == 200
    assert len(code_manager.managee) == 0

def test_token_invalid_flow():
    req_body = {
        "grant_type" : "another_flow",
        "code" : "somecode" ,  
        "redirect_uri" : "https://example.com/callback",
        "client_id" : "someclient"
    }
    response = client.post('/v0/token', json= req_body)
    assert response.status_code == 400

def test_token_invalid_code():
    req_body = {
        "grant_type" : "authorization_code",
        "code" : "somecode" ,  
        "redirect_uri" : "https://example.com/callback",
        "client_id" : "someclient"
    }
    response = client.post('/v0/token', json= req_body)
    assert response.status_code == 400
    assert req_body["code"] not in code_manager.managee

def test_token_invalid_redirect():
    req_body = {
        "grant_type" : "authorization_code",
        "code" : "somecode" ,  
        "redirect_uri" : "https://hello.world",
        "client_id" : "someclient"
    }
    response = client.post('/v0/token', json= req_body)
    assert response.status_code == 400

def test_token_invalid_client():
    req_body = {
        "grant_type" : "authorization_code",
        "code" : "somecode" ,  
        "redirect_uri" : "https://hello.world",
        "client_id" : "anotherclient"
    }
    response = client.post('/v0/token', json= req_body)
    assert response.status_code == 400
    assert req_body["redirect_uri"] not in test_clients 

