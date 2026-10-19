"""Watchbeat: self-hosted collaborative music & video rooms.

Security boundaries: OIDC host sessions; room-scoped guests; server-side votes,
limits, moderation, and playback state. Protected music is never proxied.
"""
import asyncio, base64, hashlib, os, re, secrets, uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import urlparse, parse_qs, urlencode

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import security as sec
from .db import Base, engine, SessionLocal, now, User, Room, Participant, QueueItem, Vote, SkipVote, Message, Friendship, Invitation, RoomExclusion

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'web'))
clients: dict[str, set[WebSocket]] = defaultdict(set)
client_participants: dict[WebSocket, str] = {}

async def expire_loop():
    while True:
        try:
            with SessionLocal() as db:
                limit = now() - timedelta(hours=24)
                stale = db.scalars(select(Room).where(Room.updated_at < limit)).all()
                for room in stale:
                    remove_room(db, room.id)
                db.commit()
        except Exception as exc:
            print('cleanup error:', exc, flush=True)
        await asyncio.sleep(600)

@asynccontextmanager
async def lifespan(_app):
    Base.metadata.create_all(engine)  # New installs. Use migrations before changing an existing schema.
    task = asyncio.create_task(expire_loop())
    yield
    task.cancel()
    try: await task
    except asyncio.CancelledError: pass

app = FastAPI(title='Watchbeat API', version='0.1.0', lifespan=lifespan)
app.mount('/assets', StaticFiles(directory=os.path.join(ROOT, 'assets')), name='assets')

@app.middleware('http')
async def secure_requests(request: Request, call_next):
    if request.url.path.startswith('/api/'):
        try: sec.require_origin(request)
        except HTTPException as exc: return JSONResponse({'detail':str(exc.detail)},status_code=exc.status_code)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

@app.get('/')
def index(): return FileResponse(os.path.join(ROOT, 'index.html'))

@app.get('/app.js')
def client_js(): return FileResponse(os.path.join(ROOT, 'app.js'), media_type='text/javascript')

@app.get('/app.css')
def client_css(): return FileResponse(os.path.join(ROOT, 'app.css'), media_type='text/css')

@app.get('/site.webmanifest')
def manifest(): return FileResponse(os.path.join(ROOT, 'site.webmanifest'))

@app.get('/sw.js')
def sw(): return FileResponse(os.path.join(ROOT, 'sw.js'), media_type='text/javascript')

@app.get('/api/health')
def health(): return {'ok': True, 'name': 'Watchbeat'}

# ---------- OpenID Connect (invites are managed in Pocket ID) ----------
@app.get('/auth/login')
async def login():
    if not sec.CLIENT_ID or not sec.CLIENT_SECRET:
        raise HTTPException(503, 'Configure Pocket ID first')
    discovery = await sec.discovery()
    state, nonce, verifier = secrets.token_urlsafe(25), secrets.token_urlsafe(25), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    query = urlencode({'client_id':sec.CLIENT_ID, 'redirect_uri':sec.PUBLIC_URL+'/auth/callback',
                       'response_type':'code', 'scope':'openid profile email', 'state':state,
                       'nonce':nonce, 'code_challenge_method':'S256', 'code_challenge':challenge})
    response = RedirectResponse(discovery['authorization_endpoint']+'?'+query)
    response.set_cookie('wb_oidc', sec.issue({'state':state, 'nonce':nonce, 'verifier':verifier}, ttl=600),
                        httponly=True, secure=sec.SECURE_COOKIE, samesite='lax', max_age=600)
    return response

@app.get('/auth/callback')
async def callback(request: Request, code: str = '', state: str = ''):
    flow = sec.decode(request.cookies.get('wb_oidc', ''))
    if not state or not secrets.compare_digest(flow.get('state',''), state) or not code:
        raise HTTPException(401, 'Invalid OIDC state')
    try:
        info = await sec.exchange(code, flow['verifier'])
    except Exception:
        raise HTTPException(401, 'Pocket ID authentication failed')
    if info.get('nonce') != flow['nonce']:
        raise HTTPException(401, 'OIDC nonce mismatch')
    with SessionLocal.begin() as db:
        uid = info['sub']
        user = db.get(User, uid)
        username = re.sub(r'[^a-zA-Z0-9_.-]', '-', info.get('preferred_username') or uid[:16]).strip('-')[:60] or uid[:12]
        if not user:
            candidate = username
            if db.scalar(select(User).where(User.username==candidate)):
                candidate += '-' + secrets.token_hex(3)
            user = User(id=uid, username=candidate)
            db.add(user)
        user.display_name = str(info.get('name') or user.username)[:160]
        user.picture = str(info.get('picture') or '')[:2000]
        user.email = str(info.get('email') or '')[:320]
    response = RedirectResponse('/')
    response.delete_cookie('wb_oidc')
    response.set_cookie('wb_session', sec.issue({'type':'user','sub':uid}, ttl=7*86400),
                        httponly=True, secure=sec.SECURE_COOKIE, samesite='lax', max_age=7*86400)
    return response

@app.post('/api/logout')
async def logout():
    response = RedirectResponse('/', status_code=303)
    response.delete_cookie('wb_session')
    return response

@app.post('/api/dev-login')
def dev_login(request: Request):
    # Tests and a deliberately opt-in LAN-only demo; never turn on on a public deployment.
    if os.getenv('DEV_LOGIN_ENABLED') != 'true' or sec.PUBLIC_URL.startswith('https://'):
        raise HTTPException(404)
    with SessionLocal.begin() as db:
        user = db.get(User, 'local-demo')
        if not user:
            user=User(id='local-demo', username='demo', display_name='Demo Host');db.add(user)
    from fastapi.responses import JSONResponse
    response=JSONResponse({'ok':True})
    response.set_cookie('wb_session',sec.issue({'type':'user','sub':'local-demo'}),httponly=True,samesite='lax')
    return response

@app.get('/api/me')
def me(request: Request):
    try: who=sec.host(request)
    except HTTPException: return {'authenticated':False, 'oidc_configured':bool(sec.CLIENT_ID), 'dev_login':os.getenv('DEV_LOGIN_ENABLED')=='true'}
    with SessionLocal() as db:
        user=db.get(User, who['sub'])
        if not user: return {'authenticated':False}
        return {'authenticated':True,'id':user.id,'username':user.username,'name':user.display_name,'picture':user.picture, 'email':user.email}

# ---------- Validation / helpers ----------
class RoomIn(BaseModel):
    name: str = Field(default='Watchbeat Room', min_length=1, max_length=100)
    mode: str = 'music'
    multiple_players: bool = False

class JoinIn(BaseModel):
    secret: str | None = None
    name: str = Field(default='Guest', max_length=80)

class SettingsIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    mode: str | None = None
    music_limit: int | None = Field(default=None, ge=0, le=100)
    video_limit: int | None = Field(default=None, ge=0, le=100)
    require_approval: bool | None = None
    join_enabled: bool | None = None
    multiple_players: bool | None = None

class ItemIn(BaseModel):
    media_kind: str
    source: str
    source_id: str = Field(min_length=1, max_length=2048)
    title: str = Field(min_length=1,max_length=200)
    artist: str = Field(default='', max_length=200)
    artwork: str = Field(default='',max_length=2048)

class PlaybackIn(BaseModel):
    action: str
    position: float | None = Field(default=None, ge=0, le=86400)

class ChatIn(BaseModel):
    message: str = Field(min_length=1,max_length=1000)

class UsernameIn(BaseModel):
    username: str = Field(min_length=1,max_length=80)

class InviteIn(BaseModel):
    user_id: str

class MemberModerationIn(BaseModel):
    action: str = Field(pattern=r'^(kick|ban)$')

class SyncIn(BaseModel):
    device: str = Field(max_length=100)
    offset_ms: int = Field(ge=-5000, le=5000)


def remove_room(db: Session, room_id: str):
    itemids=select(QueueItem.id).where(QueueItem.room_id==room_id)
    db.execute(delete(Vote).where(Vote.item_id.in_(itemids)))
    db.execute(delete(SkipVote).where(SkipVote.room_id==room_id))
    db.execute(delete(Message).where(Message.room_id==room_id))
    db.execute(delete(Invitation).where(Invitation.room_id==room_id))
    db.execute(delete(RoomExclusion).where(RoomExclusion.room_id==room_id))
    db.execute(delete(QueueItem).where(QueueItem.room_id==room_id))
    db.execute(delete(Participant).where(Participant.room_id==room_id))
    db.execute(delete(Room).where(Room.id==room_id))


def room_or_404(db, room_id):
    room=db.get(Room,room_id)
    if not room:raise HTTPException(404,'Room not found')
    return room


def participant(db, room, who):
    if who.get('type')=='guest':
        p=db.get(Participant,who.get('sub'))
        if not p or p.room_id!=room.id:raise HTTPException(403,'Not a room member')
    elif who.get('type')=='user':
        p=db.scalar(select(Participant).where(Participant.room_id==room.id,Participant.user_id==who['sub']))
        if not p and room.owner_id==who['sub']:
            user=db.get(User,who['sub'])
            p=Participant(id=str(uuid.uuid4()),room_id=room.id,user_id=user.id,name=user.display_name or user.username,role='host')
            db.add(p);db.flush()
        if not p:raise HTTPException(403,'Join this room first')
    else:raise HTTPException(401)
    rules=[RoomExclusion.room_id==room.id]
    if who.get('type')=='user':
        rules.append(or_(RoomExclusion.participant_id==p.id,
                         and_(RoomExclusion.user_id==who['sub'], RoomExclusion.action=='ban')))
    else:
        rules.append(RoomExclusion.participant_id==p.id)
    if db.scalar(select(RoomExclusion).where(*rules)):
        raise HTTPException(403,'You have been removed from this room')
    p.last_seen=now()
    room.updated_at=now()
    return p


def owner(room,p):
    if p.role!='host':raise HTTPException(403,'Host only')


def item_data(db, item):
    up=db.scalar(select(func.count(Vote.id)).where(Vote.item_id==item.id, Vote.value==1)) or 0
    down=db.scalar(select(func.count(Vote.id)).where(Vote.item_id==item.id, Vote.value==-1)) or 0
    return {'id':item.id,'source':item.source,'source_id':item.source_id,'media_kind':item.media_kind,
            'title':item.title,'artist':item.artist,'artwork':item.artwork,'status':item.status,
            'participant_id':item.participant_id,'up':up,'down':down,'score':up-down,'created_at':item.created_at.isoformat()}


def snapshot(db,room,who=None):
    items=db.scalars(select(QueueItem).where(QueueItem.room_id==room.id)).all()
    entries=[item_data(db,i) for i in items]
    queued=sorted((x for x in entries if x['status']=='queued' and x['media_kind']==room.mode),key=lambda x:(-x['score'],x['created_at'],x['id']))
    pending=[x for x in entries if x['status']=='pending' and x['media_kind']==room.mode]
    current=next((x for x in entries if x['id']==room.current_id),None)
    excluded={x.participant_id for x in db.scalars(select(RoomExclusion).where(RoomExclusion.room_id==room.id))}
    people=[p for p in db.scalars(select(Participant).where(Participant.room_id==room.id)) if p.id not in excluded]
    active=[p for p in people if p.last_seen and (now()-as_utc(p.last_seen)).total_seconds()<60]
    skips=db.scalar(select(func.count(SkipVote.id)).where(SkipVote.room_id==room.id,SkipVote.item_id==room.current_id)) if room.current_id else 0
    position=room.position
    if room.playing and room.started_at:
        position+=max(0,(now()-as_utc(room.started_at)).total_seconds())
    return {'id':room.id,'name':room.name,'mode':room.mode,'multiple_players':room.multiple_players,
            'join_enabled':room.join_enabled,'require_approval':room.require_approval,
            'music_limit':room.music_limit,'video_limit':room.video_limit,'current':current,'playing':room.playing,
            'position':round(position,2),'queued':queued,'pending':pending,'items':entries,
            'skip_votes':skips or 0,'skip_required':len(active)//2+1,
            'participants':[{'id':p.id,'name':p.name,'role':p.role,'active':p in active} for p in people],
            'join_secret':room.join_secret if who and who.get('type')=='user' and who['sub']==room.owner_id else None,
            'owner_id':room.owner_id,'server_time':now().isoformat()}


def as_utc(x):
    from datetime import timezone
    return x.replace(tzinfo=timezone.utc) if x.tzinfo is None else x.astimezone(timezone.utc)

async def disconnect_participant(room_id: str, participant_id: str, reason: str):
    for ws in list(clients[room_id]):
        if client_participants.get(ws)!=participant_id: continue
        try:
            await ws.send_json({'event':'removed','action':reason})
            await ws.close(code=1008)
        except Exception:
            pass
        clients[room_id].discard(ws)
        client_participants.pop(ws,None)

async def broadcast(room_id: str):
    with SessionLocal() as db:
        room=db.get(Room,room_id)
        if room is None:return
        state=snapshot(db,room)
    for ws in list(clients[room_id]):
        try:await ws.send_json({'event':'state','room':state})
        except Exception:clients[room_id].discard(ws)


def begin_next(db,room):
    entries=db.scalars(select(QueueItem).where(QueueItem.room_id==room.id,QueueItem.status=='queued',QueueItem.media_kind==room.mode)).all()
    if room.current_id:
        existing=db.get(QueueItem,room.current_id)
        if existing:existing.status='played'
    if not entries:
        room.current_id=None;room.playing=False;room.position=0;room.started_at=None
        return
    # Sort by score then enqueue timestamp. Database owns all voting.
    scores={i.id:(db.scalar(select(func.coalesce(func.sum(Vote.value),0)).where(Vote.item_id==i.id)) or 0) for i in entries}
    best=min(entries,key=lambda i:(-scores[i.id],i.created_at,i.id))
    best.status='playing';room.current_id=best.id;room.playing=True;room.position=0;room.started_at=now()

# ---------- Rooms ----------
@app.get('/api/rooms')
def my_rooms(request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        rooms=db.scalars(select(Room).where(Room.owner_id==who['sub']).order_by(Room.updated_at.desc())).all()
        return [{'id':r.id,'name':r.name,'mode':r.mode,'updated_at':r.updated_at.isoformat()} for r in rooms]

@app.post('/api/rooms')
async def new_room(request:Request, data:RoomIn):
    who=sec.host(request)
    if data.mode not in ('music','video'):raise HTTPException(422,'Invalid media type')
    with SessionLocal.begin() as db:
        r=Room(id=str(uuid.uuid4()),name=data.name.strip(),owner_id=who['sub'],mode=data.mode,
               multiple_players=data.multiple_players,join_secret=secrets.token_urlsafe(24))
        db.add(r)
        user=db.get(User,who['sub'])
        db.add(Participant(id=str(uuid.uuid4()), room_id=r.id, user_id=who['sub'],role='host',name=user.display_name or user.username))
        rid=r.id
    return {'id':rid}

@app.post('/api/rooms/{room_id}/join')
async def join(room_id:str, data:JoinIn, request:Request):
    who=None
    try:who=sec.actor(request)
    except HTTPException:pass
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        invited=False
        if who and who.get('type')=='user':
            invited=room.owner_id==who['sub'] or bool(db.scalar(select(Invitation).where(Invitation.room_id==room_id,Invitation.recipient_id==who['sub'])))
        if not invited and (not room.join_enabled or not secrets.compare_digest(data.secret or '',room.join_secret)):
            raise HTTPException(403,'Room invitation invalid or disabled')
        if who and who.get('type')=='user':
            user=db.get(User,who['sub'])
            if not user:raise HTTPException(403,'Account not found')
            if db.scalar(select(RoomExclusion).where(RoomExclusion.room_id==room.id,RoomExclusion.user_id==user.id,RoomExclusion.action=='ban')):
                raise HTTPException(403,'You are banned from this room')
            p=db.scalar(select(Participant).where(Participant.room_id==room.id,Participant.user_id==user.id))
            if not p:
                p=Participant(id=str(uuid.uuid4()),room_id=room.id,user_id=user.id,name=user.display_name or user.username,role='host' if user.id==room.owner_id else 'guest')
                db.add(p)
            else:
                old_kick=db.scalar(select(RoomExclusion).where(RoomExclusion.room_id==room.id,RoomExclusion.participant_id==p.id))
                if old_kick and old_kick.action=='kick':db.delete(old_kick)
            token=None
        else:
            if who and who.get('type')=='guest' and db.scalar(select(RoomExclusion).where(
                RoomExclusion.room_id==room.id,RoomExclusion.participant_id==who.get('sub')
            )):
                raise HTTPException(403,'Your guest session has been removed')
            name=data.name.strip()[:80]
            if not name:raise HTTPException(422,'Name required')
            p=Participant(id=str(uuid.uuid4()),room_id=room.id,name=name,role='guest')
            db.add(p)
            token=sec.issue({'type':'guest','sub':p.id,'room':room_id},ttl=24*3600)
        room.updated_at=now()
        pid=p.id
    await broadcast(room_id)
    return {'participant_id':pid, 'guest_token':token}

@app.get('/api/rooms/{room_id}')
def get_room(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        result=snapshot(db,room,who)
        result['me']={'participant_id':p.id,'role':p.role,'name':p.name}
        return result

@app.patch('/api/rooms/{room_id}')
async def patch_room(room_id:str,request:Request,data:SettingsIn):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        changes=data.model_dump(exclude_unset=True,exclude_none=True)
        for key,value in changes.items():
            if key=='mode' and value not in ('music','video'):raise HTTPException(422,'Invalid mode')
            setattr(room,key,value)
        if 'mode' in changes and room.current_id:
            current=db.get(QueueItem,room.current_id)
            if current:current.status='queued'
            room.current_id=None;room.position=0;room.playing=False;room.started_at=None
    await broadcast(room_id)
    return {'ok':True}

@app.delete('/api/rooms/{room_id}')
async def delete_room(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        remove_room(db,room_id)
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/rotate-invite')
async def rotate_invite(room_id:str,request:Request):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        if room.owner_id!=who['sub']:raise HTTPException(403,'Host only')
        room.join_secret=secrets.token_urlsafe(32)
        room.updated_at=now()
    await broadcast(room_id)
    return {'ok':True}

@app.get('/api/rooms/{room_id}/moderation')
def blocked_participants(room_id:str,request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        room=room_or_404(db,room_id)
        if room.owner_id!=who['sub']:raise HTTPException(403,'Host only')
        entries=db.scalars(select(RoomExclusion).where(RoomExclusion.room_id==room_id).order_by(RoomExclusion.created_at.desc())).all()
        return [{'participant_id':x.participant_id,
                 'name':(db.get(Participant,x.participant_id).name if db.get(Participant,x.participant_id) else 'Unknown'),
                 'action':x.action,'account':bool(x.user_id)} for x in entries]

@app.post('/api/rooms/{room_id}/participants/{participant_id}/moderate')
async def moderate_participant(room_id:str,participant_id:str,data:MemberModerationIn,request:Request):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        if room.owner_id!=who['sub']:raise HTTPException(403,'Host only')
        person=db.get(Participant,participant_id)
        if not person or person.room_id!=room.id:raise HTTPException(404,'Participant not found')
        if person.role=='host' or person.user_id==room.owner_id:raise HTTPException(403,'Cannot remove host')
        exclusion=db.scalar(select(RoomExclusion).where(RoomExclusion.room_id==room_id,RoomExclusion.participant_id==person.id))
        if exclusion:
            exclusion.action=data.action
            exclusion.user_id=person.user_id if data.action=='ban' else None
        else:
            db.add(RoomExclusion(id=str(uuid.uuid4()),room_id=room_id,
                participant_id=person.id,user_id=person.user_id if data.action=='ban' else None,action=data.action))
        for item in db.scalars(select(QueueItem).where(
            QueueItem.room_id==room_id,QueueItem.participant_id==person.id,QueueItem.status.in_(['queued','pending'])
        )):
            item.status='removed'
        db.execute(delete(Vote).where(Vote.participant_id==person.id))
        db.execute(delete(SkipVote).where(SkipVote.participant_id==person.id))
        room.updated_at=now()
    await disconnect_participant(room_id,participant_id,data.action)
    await broadcast(room_id)
    return {'ok':True,'action':data.action}

@app.delete('/api/rooms/{room_id}/moderation/{participant_id}')
async def unblock_participant(room_id:str,participant_id:str,request:Request):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        if room.owner_id!=who['sub']:raise HTTPException(403,'Host only')
        exclusion=db.scalar(select(RoomExclusion).where(RoomExclusion.room_id==room_id,RoomExclusion.participant_id==participant_id))
        if not exclusion:raise HTTPException(404,'Exclusion not found')
        db.delete(exclusion);room.updated_at=now()
    await broadcast(room_id)
    return {'ok':True}

# ---------- Queue & voting ----------
@app.post('/api/rooms/{room_id}/queue')
async def queue_item(room_id:str,request:Request,data:ItemIn):
    who=sec.actor(request)
    if data.media_kind not in ('music','video'):raise HTTPException(422,'Invalid media kind')
    if data.source not in ('apple','youtube','direct'):raise HTTPException(422,'Invalid source')
    if data.source=='apple' and data.media_kind!='music':raise HTTPException(422,'Apple Music items must be music')
    if data.source=='youtube' and data.media_kind!='video':raise HTTPException(422,'YouTube items must be video')
    if data.source=='youtube':
        if not re.fullmatch(r'[A-Za-z0-9_-]{11}',data.source_id):raise HTTPException(422,'Invalid YouTube ID')
    if data.source=='direct':
        if data.media_kind=='music' and not re.search(r'\.(mp3|m4a|aac|ogg|wav|flac)(?:\?|$)',data.source_id,re.I):
            raise HTTPException(422,'Unsupported direct audio format')
        parsed=urlparse(data.source_id)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
            raise HTTPException(422,'Direct media URLs must use HTTPS')
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        if data.media_kind !=room.mode:raise HTTPException(409,'Switch room mode first')
        # Avoid duplicate pending/queued songs in the same room.
        duplicate=db.scalar(select(QueueItem).where(QueueItem.room_id==room_id,QueueItem.source==data.source,QueueItem.source_id==data.source_id,QueueItem.status.in_(['queued','pending','playing'])))
        if duplicate:raise HTTPException(409,'Already in the room queue')
        if p.role!='host':
            limit=room.music_limit if data.media_kind=='music' else room.video_limit
            used=db.scalar(select(func.count()).select_from(QueueItem).where(QueueItem.room_id==room_id,QueueItem.participant_id==p.id,QueueItem.media_kind==data.media_kind,QueueItem.status.in_(['queued','pending'])))
            if used>=limit:raise HTTPException(409,f'Guest queue limit reached ({used}/{limit})')
        item=QueueItem(id=str(uuid.uuid4()),room_id=room_id,participant_id=p.id,media_kind=data.media_kind,
                       source=data.source,source_id=data.source_id,title=data.title,artist=data.artist,artwork=data.artwork,
                       status='pending' if room.require_approval and p.role!='host' else 'queued')
        db.add(item);item_id=item.id
    await broadcast(room_id)
    return {'id':item_id}

@app.post('/api/rooms/{room_id}/queue/{item_id}/vote')
async def vote(room_id:str,item_id:str,request:Request,data:dict):
    who=sec.actor(request);value=data.get('value')
    if type(value) is not int or value not in (-1,0,1):raise HTTPException(422,'Vote must be -1, 0, or 1')
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        item=db.get(QueueItem,item_id)
        if not item or item.room_id!=room_id or item.status not in ('queued','pending'):
            raise HTTPException(409,'Item cannot be voted on')
        existing=db.scalar(select(Vote).where(Vote.item_id==item_id,Vote.participant_id==p.id))
        if value==0:
            if existing:db.delete(existing)
        elif existing:existing.value=value
        else:db.add(Vote(item_id=item_id,participant_id=p.id,value=value))
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/queue/{item_id}/moderate')
async def moderate(room_id:str,item_id:str,request:Request,data:dict):
    who=sec.actor(request)
    if data.get('action') not in ('approve','remove'):raise HTTPException(422,'Bad action')
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        item=db.get(QueueItem,item_id)
        if not item or item.room_id!=room_id:raise HTTPException(404)
        if data['action']=='approve' and item.status=='pending':item.status='queued'
        elif data['action']=='remove' and item.status in ('pending','queued'):item.status='removed'
        else:raise HTTPException(409,'Cannot moderate this item')
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/playback')
async def playback(room_id:str,request:Request,data:PlaybackIn):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        if data.action in ('next','start'):
            begin_next(db,room)
        elif data.action=='pause':
            if room.playing and room.started_at:room.position+=max(0,(now()-as_utc(room.started_at)).total_seconds())
            room.playing=False;room.started_at=None
        elif data.action=='play':
            if not room.current_id:begin_next(db,room)
            else:room.playing=True;room.started_at=now()
        elif data.action=='seek':
            if data.position is None:raise HTTPException(422,'Position required')
            room.position=data.position;room.started_at=now() if room.playing else None
        else:raise HTTPException(422,'Unknown playback command')
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/skip')
async def skip(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        if not room.current_id:raise HTTPException(409,'Nothing playing')
        prior=db.scalar(select(SkipVote).where(SkipVote.room_id==room_id,SkipVote.item_id==room.current_id,SkipVote.participant_id==p.id))
        if not prior:db.add(SkipVote(room_id=room_id,item_id=room.current_id,participant_id=p.id));db.flush()
        eligible=db.scalar(select(func.count()).select_from(Participant).where(Participant.room_id==room_id,Participant.last_seen>now()-timedelta(seconds=60))) or 1
        votes=db.scalar(select(func.count()).select_from(SkipVote).where(SkipVote.room_id==room_id,SkipVote.item_id==room.current_id)) or 0
        skipped=votes>eligible/2
        if skipped:begin_next(db,room)
    await broadcast(room_id)
    return {'skipped':skipped, 'votes':votes,'required':eligible//2+1}

# ---------- Chat, friends, invites ----------
@app.get('/api/rooms/{room_id}/chat')
def chat(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);participant(db,room,who)
        messages=db.scalars(select(Message).where(Message.room_id==room_id).order_by(Message.id.desc()).limit(100)).all()
        return [{'id':m.id,'name':m.name,'message':m.body,'participant_id':m.participant_id,'created_at':m.created_at.isoformat()} for m in reversed(messages)]

@app.post('/api/rooms/{room_id}/chat')
async def chat_send(room_id:str,request:Request,data:ChatIn):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        db.add(Message(room_id=room_id,participant_id=p.id,name=p.name,body=data.message.strip()))
    await broadcast_event(room_id,{'event':'chat'})
    return {'ok':True}

async def broadcast_event(room_id,payload):
    for ws in list(clients[room_id]):
        try:await ws.send_json(payload)
        except Exception:clients[room_id].discard(ws)

@app.get('/api/friends')
def friends(request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        relations=db.scalars(select(Friendship).where(or_(Friendship.requester_id==who['sub'],Friendship.recipient_id==who['sub']))).all()
        return [{'id':r.id,'user_id':r.recipient_id if r.requester_id==who['sub'] else r.requester_id,
                 'username': (db.get(User,r.recipient_id if r.requester_id==who['sub'] else r.requester_id)).username,
                 'status':r.status,'incoming':r.recipient_id==who['sub']} for r in relations]

@app.get('/api/users')
def find_users(request:Request,q:str=''):
    who=sec.host(request)
    if len(q.strip())<2:return []
    with SessionLocal() as db:
        users=db.scalars(select(User).where(User.username.ilike('%'+q[:40].replace('%','').replace('_','')+'%'),User.id!=who['sub']).limit(15)).all()
        return [{'id':u.id,'username':u.username,'name':u.display_name} for u in users]

@app.post('/api/friends/request')
def request_friend(request:Request,data:InviteIn):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        if data.user_id==who['sub'] or not db.get(User,data.user_id):raise HTTPException(404)
        edge=db.scalar(select(Friendship).where(or_(
            (Friendship.requester_id==who['sub']) & (Friendship.recipient_id==data.user_id),
            (Friendship.requester_id==data.user_id) & (Friendship.recipient_id==who['sub']))))
        if edge:raise HTTPException(409,'Friend request already exists')
        db.add(Friendship(requester_id=who['sub'],recipient_id=data.user_id))
    return {'ok':True}

@app.post('/api/friends/{friendship_id}/accept')
def accept_friend(friendship_id:int,request:Request):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        relation=db.get(Friendship,friendship_id)
        if not relation or relation.recipient_id!=who['sub']:raise HTTPException(403)
        relation.status='accepted'
    return {'ok':True}

@app.post('/api/rooms/{room_id}/invite')
def invite(room_id:str,request:Request,data:InviteIn):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        if room.owner_id!=who['sub']:raise HTTPException(403)
        relation=db.scalar(select(Friendship).where(Friendship.status=='accepted',or_(
            (Friendship.requester_id==who['sub']) & (Friendship.recipient_id==data.user_id),
            (Friendship.requester_id==data.user_id) & (Friendship.recipient_id==who['sub']))))
        if not relation:raise HTTPException(403,'Only friends can be directly invited')
        if not db.scalar(select(Invitation).where(Invitation.room_id==room_id,Invitation.recipient_id==data.user_id)):
            db.add(Invitation(id=str(uuid.uuid4()),room_id=room_id,recipient_id=data.user_id))
    return {'ok':True}

@app.get('/api/invitations')
def invitations(request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        invites=db.scalars(select(Invitation).where(Invitation.recipient_id==who['sub'])).all()
        return [{'id':i.id,'room_id':i.room_id,'name':db.get(Room,i.room_id).name} for i in invites if db.get(Room,i.room_id)]

@app.get('/api/rooms/{room_id}/qr.png')
def room_qr(room_id:str,request:Request):
    """Generate an invitation QR locally: never leak the join secret to third-party QR services."""
    import io, qrcode
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        invitation=f"{sec.PUBLIC_URL}/?room={room.id}&invite={room.join_secret}"
    image=qrcode.make(invitation)
    buffer=io.BytesIO();image.save(buffer,format='PNG')
    return Response(buffer.getvalue(),media_type='image/png',headers={'Cache-Control':'no-store'})

@app.get('/api/rooms/{room_id}/apple/config')
def apple_config(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);participant(db,room,who)
    # Developer token is intended for browser SDK; personal music user tokens are never stored by Watchbeat.
    tok=os.getenv('APPLE_MUSIC_DEVELOPER_TOKEN','')
    return {'available':bool(tok),'developer_token':tok if tok else None,'storefront':os.getenv('APPLE_MUSIC_STOREFRONT','de')}

# ---------- Room realtime ----------
@app.websocket('/ws/{room_id}')
async def ws_room(ws:WebSocket,room_id:str):
    origin=ws.headers.get('origin','')
    if origin and origin.rstrip('/')!=sec.PUBLIC_URL:
        await ws.close(code=1008);return
    token=ws.query_params.get('token') or ws.cookies.get('wb_session','')
    try:
        who=sec.decode(token)
        with SessionLocal.begin() as db:
            room=room_or_404(db,room_id)
            p=participant(db,room,who)
            pid=p.id
    except HTTPException:
        await ws.close(code=1008);return
    await ws.accept()
    clients[room_id].add(ws)
    client_participants[ws]=pid
    try:
        await broadcast(room_id)
        while True:
            message=await ws.receive_json()
            if message.get('event')=='ping':
                with SessionLocal.begin() as db:
                    p=db.get(Participant,pid);r=db.get(Room,room_id)
                    if p and r:
                        if db.scalar(select(RoomExclusion).where(RoomExclusion.room_id==room_id,RoomExclusion.participant_id==pid)):
                            await ws.close(code=1008);return
                        p.last_seen=now();r.updated_at=now()
                await ws.send_json({'event':'pong'})
            elif message.get('event')=='reaction' and str(message.get('emoji')) in ('❤️','🔥','😂','👏','🎉','👍'):
                await broadcast_event(room_id,{'event':'reaction','emoji':message['emoji'],'from':pid})
    except (WebSocketDisconnect,ValueError,RuntimeError):
        pass
    finally:
        client_participants.pop(ws,None)
        clients[room_id].discard(ws)
        if not clients[room_id]:clients.pop(room_id,None))

class SyncIn(BaseModel):
    device: str = Field(max_length=100)
    offset_ms: int = Field(ge=-5000, le=5000)


def remove_room(db: Session, room_id: str):
    itemids=select(QueueItem.id).where(QueueItem.room_id==room_id)
    db.execute(delete(Vote).where(Vote.item_id.in_(itemids)))
    db.execute(delete(SkipVote).where(SkipVote.room_id==room_id))
    db.execute(delete(Message).where(Message.room_id==room_id))
    db.execute(delete(Invitation).where(Invitation.room_id==room_id))
    db.execute(delete(QueueItem).where(QueueItem.room_id==room_id))
    db.execute(delete(Participant).where(Participant.room_id==room_id))
    db.execute(delete(Room).where(Room.id==room_id))


def room_or_404(db, room_id):
    room=db.get(Room,room_id)
    if not room:raise HTTPException(404,'Room not found')
    return room


def participant(db, room, who):
    if who.get('type')=='guest':
        p=db.get(Participant,who.get('sub'))
        if not p or p.room_id!=room.id:raise HTTPException(403,'Not a room member')
    elif who.get('type')=='user':
        p=db.scalar(select(Participant).where(Participant.room_id==room.id,Participant.user_id==who['sub']))
        if not p and room.owner_id==who['sub']:
            user=db.get(User,who['sub'])
            p=Participant(id=str(uuid.uuid4()),room_id=room.id,user_id=user.id,name=user.display_name or user.username,role='host')
            db.add(p);db.flush()
        if not p:raise HTTPException(403,'Join this room first')
    else:raise HTTPException(401)
    p.last_seen=now()
    room.updated_at=now()
    return p


def owner(room,p):
    if p.role!='host':raise HTTPException(403,'Host only')


def item_data(db, item):
    up=db.scalar(select(func.count(Vote.id)).where(Vote.item_id==item.id, Vote.value==1)) or 0
    down=db.scalar(select(func.count(Vote.id)).where(Vote.item_id==item.id, Vote.value==-1)) or 0
    return {'id':item.id,'source':item.source,'source_id':item.source_id,'media_kind':item.media_kind,
            'title':item.title,'artist':item.artist,'artwork':item.artwork,'status':item.status,
            'participant_id':item.participant_id,'up':up,'down':down,'score':up-down,'created_at':item.created_at.isoformat()}


def snapshot(db,room,who=None):
    items=db.scalars(select(QueueItem).where(QueueItem.room_id==room.id)).all()
    entries=[item_data(db,i) for i in items]
    queued=sorted((x for x in entries if x['status']=='queued' and x['media_kind']==room.mode),key=lambda x:(-x['score'],x['created_at'],x['id']))
    pending=[x for x in entries if x['status']=='pending' and x['media_kind']==room.mode]
    current=next((x for x in entries if x['id']==room.current_id),None)
    people=db.scalars(select(Participant).where(Participant.room_id==room.id)).all()
    active=[p for p in people if p.last_seen and (now()-as_utc(p.last_seen)).total_seconds()<60]
    skips=db.scalar(select(func.count(SkipVote.id)).where(SkipVote.room_id==room.id,SkipVote.item_id==room.current_id)) if room.current_id else 0
    position=room.position
    if room.playing and room.started_at:
        position+=max(0,(now()-as_utc(room.started_at)).total_seconds())
    return {'id':room.id,'name':room.name,'mode':room.mode,'multiple_players':room.multiple_players,
            'join_enabled':room.join_enabled,'require_approval':room.require_approval,
            'music_limit':room.music_limit,'video_limit':room.video_limit,'current':current,'playing':room.playing,
            'position':round(position,2),'queued':queued,'pending':pending,'items':entries,
            'skip_votes':skips or 0,'skip_required':len(active)//2+1,
            'participants':[{'id':p.id,'name':p.name,'role':p.role,'active':p in active} for p in people],
            'join_secret':room.join_secret if who and who.get('type')=='user' and who['sub']==room.owner_id else None,
            'owner_id':room.owner_id,'server_time':now().isoformat()}


def as_utc(x):
    from datetime import timezone
    return x.replace(tzinfo=timezone.utc) if x.tzinfo is None else x.astimezone(timezone.utc)

async def broadcast(room_id: str):
    with SessionLocal() as db:
        room=db.get(Room,room_id)
        if room is None:return
        state=snapshot(db,room)
    for ws in list(clients[room_id]):
        try:await ws.send_json({'event':'state','room':state})
        except Exception:clients[room_id].discard(ws)


def begin_next(db,room):
    entries=db.scalars(select(QueueItem).where(QueueItem.room_id==room.id,QueueItem.status=='queued',QueueItem.media_kind==room.mode)).all()
    if room.current_id:
        existing=db.get(QueueItem,room.current_id)
        if existing:existing.status='played'
    if not entries:
        room.current_id=None;room.playing=False;room.position=0;room.started_at=None
        return
    # Sort by score then enqueue timestamp. Database owns all voting.
    scores={i.id:(db.scalar(select(func.coalesce(func.sum(Vote.value),0)).where(Vote.item_id==i.id)) or 0) for i in entries}
    best=min(entries,key=lambda i:(-scores[i.id],i.created_at,i.id))
    best.status='playing';room.current_id=best.id;room.playing=True;room.position=0;room.started_at=now()

# ---------- Rooms ----------
@app.get('/api/rooms')
def my_rooms(request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        rooms=db.scalars(select(Room).where(Room.owner_id==who['sub']).order_by(Room.updated_at.desc())).all()
        return [{'id':r.id,'name':r.name,'mode':r.mode,'updated_at':r.updated_at.isoformat()} for r in rooms]

@app.post('/api/rooms')
async def new_room(request:Request, data:RoomIn):
    who=sec.host(request)
    if data.mode not in ('music','video'):raise HTTPException(422,'Invalid media type')
    with SessionLocal.begin() as db:
        r=Room(id=str(uuid.uuid4()),name=data.name.strip(),owner_id=who['sub'],mode=data.mode,
               multiple_players=data.multiple_players,join_secret=secrets.token_urlsafe(24))
        db.add(r)
        user=db.get(User,who['sub'])
        db.add(Participant(id=str(uuid.uuid4()), room_id=r.id, user_id=who['sub'],role='host',name=user.display_name or user.username))
        rid=r.id
    return {'id':rid}

@app.post('/api/rooms/{room_id}/join')
async def join(room_id:str, data:JoinIn, request:Request):
    who=None
    try:who=sec.actor(request)
    except HTTPException:pass
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        invited=False
        if who and who.get('type')=='user':
            invited=room.owner_id==who['sub'] or bool(db.scalar(select(Invitation).where(Invitation.room_id==room_id,Invitation.recipient_id==who['sub'])))
        if not invited and (not room.join_enabled or not secrets.compare_digest(data.secret or '',room.join_secret)):
            raise HTTPException(403,'Room invitation invalid or disabled')
        if who and who.get('type')=='user':
            user=db.get(User,who['sub'])
            p=db.scalar(select(Participant).where(Participant.room_id==room.id,Participant.user_id==user.id))
            if not p:
                p=Participant(id=str(uuid.uuid4()),room_id=room.id,user_id=user.id,name=user.display_name or user.username,role='host' if user.id==room.owner_id else 'guest')
                db.add(p)
            token=None
        else:
            name=data.name.strip()[:80]
            if not name:raise HTTPException(422,'Name required')
            p=Participant(id=str(uuid.uuid4()),room_id=room.id,name=name,role='guest')
            db.add(p)
            token=sec.issue({'type':'guest','sub':p.id,'room':room_id},ttl=24*3600)
        room.updated_at=now()
        pid=p.id
    await broadcast(room_id)
    return {'participant_id':pid, 'guest_token':token}

@app.get('/api/rooms/{room_id}')
def get_room(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        result=snapshot(db,room,who)
        result['me']={'participant_id':p.id,'role':p.role,'name':p.name}
        return result

@app.patch('/api/rooms/{room_id}')
async def patch_room(room_id:str,request:Request,data:SettingsIn):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        changes=data.model_dump(exclude_unset=True,exclude_none=True)
        for key,value in changes.items():
            if key=='mode' and value not in ('music','video'):raise HTTPException(422,'Invalid mode')
            setattr(room,key,value)
        if 'mode' in changes and room.current_id:
            current=db.get(QueueItem,room.current_id)
            if current:current.status='queued'
            room.current_id=None;room.position=0;room.playing=False;room.started_at=None
    await broadcast(room_id)
    return {'ok':True}

@app.delete('/api/rooms/{room_id}')
async def delete_room(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        remove_room(db,room_id)
    await broadcast(room_id)
    return {'ok':True}

# ---------- Queue & voting ----------
@app.post('/api/rooms/{room_id}/queue')
async def queue_item(room_id:str,request:Request,data:ItemIn):
    who=sec.actor(request)
    if data.media_kind not in ('music','video'):raise HTTPException(422,'Invalid media kind')
    if data.source not in ('apple','youtube','direct'):raise HTTPException(422,'Invalid source')
    if data.source=='apple' and data.media_kind!='music':raise HTTPException(422,'Apple Music items must be music')
    if data.source=='youtube' and data.media_kind!='video':raise HTTPException(422,'YouTube items must be video')
    if data.source=='youtube':
        if not re.fullmatch(r'[A-Za-z0-9_-]{11}',data.source_id):raise HTTPException(422,'Invalid YouTube ID')
    if data.source=='direct':
        if data.media_kind=='music' and not re.search(r'\.(mp3|m4a|aac|ogg|wav|flac)(?:\?|$)',data.source_id,re.I):
            raise HTTPException(422,'Unsupported direct audio format')
        parsed=urlparse(data.source_id)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
            raise HTTPException(422,'Direct media URLs must use HTTPS')
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        if data.media_kind !=room.mode:raise HTTPException(409,'Switch room mode first')
        # Avoid duplicate pending/queued songs in the same room.
        duplicate=db.scalar(select(QueueItem).where(QueueItem.room_id==room_id,QueueItem.source==data.source,QueueItem.source_id==data.source_id,QueueItem.status.in_(['queued','pending','playing'])))
        if duplicate:raise HTTPException(409,'Already in the room queue')
        if p.role!='host':
            limit=room.music_limit if data.media_kind=='music' else room.video_limit
            used=db.scalar(select(func.count()).select_from(QueueItem).where(QueueItem.room_id==room_id,QueueItem.participant_id==p.id,QueueItem.media_kind==data.media_kind,QueueItem.status.in_(['queued','pending'])))
            if used>=limit:raise HTTPException(409,f'Guest queue limit reached ({used}/{limit})')
        item=QueueItem(id=str(uuid.uuid4()),room_id=room_id,participant_id=p.id,media_kind=data.media_kind,
                       source=data.source,source_id=data.source_id,title=data.title,artist=data.artist,artwork=data.artwork,
                       status='pending' if room.require_approval and p.role!='host' else 'queued')
        db.add(item);item_id=item.id
    await broadcast(room_id)
    return {'id':item_id}

@app.post('/api/rooms/{room_id}/queue/{item_id}/vote')
async def vote(room_id:str,item_id:str,request:Request,data:dict):
    who=sec.actor(request);value=data.get('value')
    if type(value) is not int or value not in (-1,0,1):raise HTTPException(422,'Vote must be -1, 0, or 1')
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        item=db.get(QueueItem,item_id)
        if not item or item.room_id!=room_id or item.status not in ('queued','pending'):
            raise HTTPException(409,'Item cannot be voted on')
        existing=db.scalar(select(Vote).where(Vote.item_id==item_id,Vote.participant_id==p.id))
        if value==0:
            if existing:db.delete(existing)
        elif existing:existing.value=value
        else:db.add(Vote(item_id=item_id,participant_id=p.id,value=value))
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/queue/{item_id}/moderate')
async def moderate(room_id:str,item_id:str,request:Request,data:dict):
    who=sec.actor(request)
    if data.get('action') not in ('approve','remove'):raise HTTPException(422,'Bad action')
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        item=db.get(QueueItem,item_id)
        if not item or item.room_id!=room_id:raise HTTPException(404)
        if data['action']=='approve' and item.status=='pending':item.status='queued'
        elif data['action']=='remove' and item.status in ('pending','queued'):item.status='removed'
        else:raise HTTPException(409,'Cannot moderate this item')
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/playback')
async def playback(room_id:str,request:Request,data:PlaybackIn):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        if data.action in ('next','start'):
            begin_next(db,room)
        elif data.action=='pause':
            if room.playing and room.started_at:room.position+=max(0,(now()-as_utc(room.started_at)).total_seconds())
            room.playing=False;room.started_at=None
        elif data.action=='play':
            if not room.current_id:begin_next(db,room)
            else:room.playing=True;room.started_at=now()
        elif data.action=='seek':
            if data.position is None:raise HTTPException(422,'Position required')
            room.position=data.position;room.started_at=now() if room.playing else None
        else:raise HTTPException(422,'Unknown playback command')
    await broadcast(room_id)
    return {'ok':True}

@app.post('/api/rooms/{room_id}/skip')
async def skip(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        if not room.current_id:raise HTTPException(409,'Nothing playing')
        prior=db.scalar(select(SkipVote).where(SkipVote.room_id==room_id,SkipVote.item_id==room.current_id,SkipVote.participant_id==p.id))
        if not prior:db.add(SkipVote(room_id=room_id,item_id=room.current_id,participant_id=p.id));db.flush()
        eligible=db.scalar(select(func.count()).select_from(Participant).where(Participant.room_id==room_id,Participant.last_seen>now()-timedelta(seconds=60))) or 1
        votes=db.scalar(select(func.count()).select_from(SkipVote).where(SkipVote.room_id==room_id,SkipVote.item_id==room.current_id)) or 0
        skipped=votes>eligible/2
        if skipped:begin_next(db,room)
    await broadcast(room_id)
    return {'skipped':skipped, 'votes':votes,'required':eligible//2+1}

# ---------- Chat, friends, invites ----------
@app.get('/api/rooms/{room_id}/chat')
def chat(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);participant(db,room,who)
        messages=db.scalars(select(Message).where(Message.room_id==room_id).order_by(Message.id.desc()).limit(100)).all()
        return [{'id':m.id,'name':m.name,'message':m.body,'participant_id':m.participant_id,'created_at':m.created_at.isoformat()} for m in reversed(messages)]

@app.post('/api/rooms/{room_id}/chat')
async def chat_send(room_id:str,request:Request,data:ChatIn):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);p=participant(db,room,who)
        db.add(Message(room_id=room_id,participant_id=p.id,name=p.name,body=data.message.strip()))
    await broadcast_event(room_id,{'event':'chat'})
    return {'ok':True}

async def broadcast_event(room_id,payload):
    for ws in list(clients[room_id]):
        try:await ws.send_json(payload)
        except Exception:clients[room_id].discard(ws)

@app.get('/api/friends')
def friends(request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        relations=db.scalars(select(Friendship).where(or_(Friendship.requester_id==who['sub'],Friendship.recipient_id==who['sub']))).all()
        return [{'id':r.id,'user_id':r.recipient_id if r.requester_id==who['sub'] else r.requester_id,
                 'username': (db.get(User,r.recipient_id if r.requester_id==who['sub'] else r.requester_id)).username,
                 'status':r.status,'incoming':r.recipient_id==who['sub']} for r in relations]

@app.get('/api/users')
def find_users(request:Request,q:str=''):
    who=sec.host(request)
    if len(q.strip())<2:return []
    with SessionLocal() as db:
        users=db.scalars(select(User).where(User.username.ilike('%'+q[:40].replace('%','').replace('_','')+'%'),User.id!=who['sub']).limit(15)).all()
        return [{'id':u.id,'username':u.username,'name':u.display_name} for u in users]

@app.post('/api/friends/request')
def request_friend(request:Request,data:InviteIn):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        if data.user_id==who['sub'] or not db.get(User,data.user_id):raise HTTPException(404)
        edge=db.scalar(select(Friendship).where(or_(
            (Friendship.requester_id==who['sub']) & (Friendship.recipient_id==data.user_id),
            (Friendship.requester_id==data.user_id) & (Friendship.recipient_id==who['sub']))))
        if edge:raise HTTPException(409,'Friend request already exists')
        db.add(Friendship(requester_id=who['sub'],recipient_id=data.user_id))
    return {'ok':True}

@app.post('/api/friends/{friendship_id}/accept')
def accept_friend(friendship_id:int,request:Request):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        relation=db.get(Friendship,friendship_id)
        if not relation or relation.recipient_id!=who['sub']:raise HTTPException(403)
        relation.status='accepted'
    return {'ok':True}

@app.post('/api/rooms/{room_id}/invite')
def invite(room_id:str,request:Request,data:InviteIn):
    who=sec.host(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id)
        if room.owner_id!=who['sub']:raise HTTPException(403)
        relation=db.scalar(select(Friendship).where(Friendship.status=='accepted',or_(
            (Friendship.requester_id==who['sub']) & (Friendship.recipient_id==data.user_id),
            (Friendship.requester_id==data.user_id) & (Friendship.recipient_id==who['sub']))))
        if not relation:raise HTTPException(403,'Only friends can be directly invited')
        if not db.scalar(select(Invitation).where(Invitation.room_id==room_id,Invitation.recipient_id==data.user_id)):
            db.add(Invitation(id=str(uuid.uuid4()),room_id=room_id,recipient_id=data.user_id))
    return {'ok':True}

@app.get('/api/invitations')
def invitations(request:Request):
    who=sec.host(request)
    with SessionLocal() as db:
        invites=db.scalars(select(Invitation).where(Invitation.recipient_id==who['sub'])).all()
        return [{'id':i.id,'room_id':i.room_id,'name':db.get(Room,i.room_id).name} for i in invites if db.get(Room,i.room_id)]

@app.get('/api/rooms/{room_id}/qr.png')
def room_qr(room_id:str,request:Request):
    """Generate an invitation QR locally: never leak the join secret to third-party QR services."""
    import io, qrcode
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);owner(room,participant(db,room,who))
        invitation=f"{sec.PUBLIC_URL}/?room={room.id}&invite={room.join_secret}"
    image=qrcode.make(invitation)
    buffer=io.BytesIO();image.save(buffer,format='PNG')
    return Response(buffer.getvalue(),media_type='image/png',headers={'Cache-Control':'no-store'})

@app.get('/api/rooms/{room_id}/apple/config')
def apple_config(room_id:str,request:Request):
    who=sec.actor(request)
    with SessionLocal.begin() as db:
        room=room_or_404(db,room_id);participant(db,room,who)
    # Developer token is intended for browser SDK; personal music user tokens are never stored by Watchbeat.
    tok=os.getenv('APPLE_MUSIC_DEVELOPER_TOKEN','')
    return {'available':bool(tok),'developer_token':tok if tok else None,'storefront':os.getenv('APPLE_MUSIC_STOREFRONT','de')}

# ---------- Room realtime ----------
@app.websocket('/ws/{room_id}')
async def ws_room(ws:WebSocket,room_id:str):
    origin=ws.headers.get('origin','')
    if origin and origin.rstrip('/')!=sec.PUBLIC_URL:
        await ws.close(code=1008);return
    token=ws.query_params.get('token') or ws.cookies.get('wb_session','')
    try:
        who=sec.decode(token)
        with SessionLocal.begin() as db:
            room=room_or_404(db,room_id)
            p=participant(db,room,who)
            pid=p.id
    except HTTPException:
        await ws.close(code=1008);return
    await ws.accept()
    clients[room_id].add(ws)
    try:
        await broadcast(room_id)
        while True:
            message=await ws.receive_json()
            if message.get('event')=='ping':
                with SessionLocal.begin() as db:
                    p=db.get(Participant,pid);r=db.get(Room,room_id)
                    if p and r:p.last_seen=now();r.updated_at=now()
                await ws.send_json({'event':'pong'})
            elif message.get('event')=='reaction' and str(message.get('emoji')) in ('❤️','🔥','😂','👏','🎉','👍'):
                await broadcast_event(room_id,{'event':'reaction','emoji':message['emoji'],'from':pid})
    except (WebSocketDisconnect,ValueError):
        pass
    finally:
        clients[room_id].discard(ws)
        if not clients[room_id]:clients.pop(room_id,None)