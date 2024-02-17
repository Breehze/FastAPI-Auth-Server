# FastAPI auth server

This project implements an authentication server using FastAPI, focusing on the authorization code flow, which is widely recognized for its robustness. This implementation is currently a prototype and not recommended for production environments.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

* Python 3.11< 
* Basic authorization code flow knowledge

### Installation

Create virtual enviroment

```
python -m venv '.'
```

Activate virtual enviroment (Dunno how to do on Linux so here is Windows)
```
Scripts\Activate.bat
```
Install dependencies
```
pip install -r requirements.txt
```

Run tests
```
pytest
```


Run uvicorn 
```
uvicorn main:app
```

## Usage

Here is a basic flow that client app should follow.

Endpoints:
```
GET - /v0/auth?client_id=someclient&response_type=code&redirect_uri=https://example.com/callback
```
**redirect_uri** - This is where you will recieve your authorization code 

**client_id** - must be included, as the name sugests client app id

**response_type** - always set to code, don't worry about it

```
POST - /v0/token
```
This is where you exchange your auth code for JWT

Request body is self explanatory.

```
{
    "grant_type" : "authorization_code",
    "code" : "ef7b9c90-8b5d-443b-854f-590c4f9feada",
    "redirect_uri" : "https://example.com/callback",
    "client_id" : "someclient"
}
```

```
/v0/client_pub_key
```

This is where resource server would retrieve public key for decode.

Hidden behind API_KEY of course.

There are some other endpoints like Register or Login but those are pretty self explanatory.

## Future upgrades

* Use actual DB
* PKCE
* Unique RSA keys for every client
* Unique API_KEY for every resource server
* More secure way to store keys
* Dockerize
* Production ready

