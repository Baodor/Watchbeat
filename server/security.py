"""OIDC discovery, state, ID token signature and local session handling."""
import os, secrets, time
from urllib.parse import urlencode
import httpx
import jwt
from fastapi import HTTPException, Request

SECRET = os.getenv('SESSION_SECRET', '')
OIDC_ISSUER = os.getenv('OIDC_ISSUER', '').rstrip('/')
CLIENT_ID = os.getenv('OIDC_CLIENT_ID', '')
CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET', '')
PUBLIC_URL = os.getenv('PUBLIC_URL', 'http://localhost:8080').rstrip('/')
SECURE_COOKIE = PUBLIC_URL.startswith('https://')

def issue(payload: dict, ttl: int = 86400) -> str:
    if len(SECRET) < 32:
        raise RuntimeError('SESSION_SECRET must be at least 32 characters')
    return jwt.encode({**payload, 'exp': int(time.time()) + ttl, 'iat': int(time.time())}, SECRET, algorithm='HS256')

def decode(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=['HS256'])
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(401, 'Invalid or expired session')

def actor(request: Request):
    auth = request.headers.get('Authorization', '')
    token = auth[7:] if auth.startswith('Bearer ') else request.cookies.get('wb_session', '')
    if not token:
        raise HTTPException(401, 'Sign in or join a room')
    return decode(token)

def host(request: Request):
    who = actor(request)
    if who.get('type') != 'user':
        raise HTTPException(403, 'Account required')
    return who

def require_origin(request: Request):
    # Browser cookie authentication needs CSRF protection. Bearer tokens aren't ambient.
    if request.method not in ('GET','HEAD','OPTIONS') and not request.headers.get('Authorization','').startswith('Bearer '):
        origin = request.headers.get('origin')
        if origin and origin.rstrip('/') != PUBLIC_URL:
            raise HTTPException(403, 'Origin mismatch')

async def discovery():
    if not OIDC_ISSUER:
        raise HTTPException(503, 'Pocket ID is not configured')
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(OIDC_ISSUER + '/.well-known/openid-configuration')
        r.raise_for_status()
        return r.json()

async def exchange(code: str, verifier: str):
    d = await discovery()
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(d['token_endpoint'], data={
            'grant_type':'authorization_code', 'code':code, 'redirect_uri':PUBLIC_URL+'/auth/callback',
            'client_id':CLIENT_ID, 'client_secret':CLIENT_SECRET, 'code_verifier':verifier})
        r.raise_for_status()
        token = r.json()
        keys = (await client.get(d['jwks_uri'])).json()
        header = jwt.get_unverified_header(token['id_token'])
        key = next((k for k in keys['keys'] if k.get('kid') == header.get('kid')), None)
        if not key:
            raise HTTPException(401, 'OIDC key not found')
        info = jwt.decode(token['id_token'], jwt.PyJWK.from_dict(key).key,
                          algorithms=[header['alg']], audience=CLIENT_ID, issuer=d['issuer'],
                          options={'require':['exp','iss','sub','aud']})
        return info
