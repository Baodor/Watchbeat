"""API integration smoke/regression tests using the deliberately opt-in local demo login."""
import os, tempfile, importlib
os.environ['SESSION_SECRET']='test-session-secret-long-enough-32-bytes-123456'
os.environ['PUBLIC_URL']='http://localhost:8080'
os.environ['DEV_LOGIN_ENABLED']='true'
os.environ['DATABASE_URL']='sqlite:///'+os.path.join(tempfile.mkdtemp(),'test.db')
from fastapi.testclient import TestClient
from server.main import app


def test_full_room_flow():
    with TestClient(app,base_url='http://localhost:8080') as host:
        assert host.get('/api/health').json()['ok']
        assert host.get('/app.js').status_code==200
        assert host.get('/app.css').status_code==200
        assert host.get('/site.webmanifest').status_code==200
        assert host.get('/assets/icons/watchbeat-180.png').status_code==200
        assert host.post('/api/dev-login').status_code==200
        assert host.get('/api/me').json()['authenticated']
        created=host.post('/api/rooms',json={'name':'Party','mode':'video','multiple_players':True})
        assert created.status_code==200,created.text
        rid=created.json()['id']
        data=host.get('/api/rooms/'+rid).json()
        secret=data['join_secret']
        with TestClient(app,base_url='http://localhost:8080') as guest:
            joined=guest.post(f'/api/rooms/{rid}/join',json={'secret':secret,'name':'Jo'});assert joined.status_code==200,joined.text
            token=joined.json()['guest_token'];guest.headers['Authorization']='Bearer '+token
            assert guest.get(f'/api/rooms/{rid}').json()['me']['role']=='guest'
            first=guest.post(f'/api/rooms/{rid}/queue',json={'media_kind':'video','source':'youtube','source_id':'M7lc1UVf-VE','title':'Demo'})
            assert first.status_code==200,first.text
            item=first.json()['id']
            assert guest.post(f'/api/rooms/{rid}/queue/{item}/vote',json={'value':1}).status_code==200
            assert guest.post(f'/api/rooms/{rid}/queue/{item}/vote',json={'value':-1}).status_code==200
            room=guest.get(f'/api/rooms/{rid}').json()
            assert room['queued'][0]['score']==-1
            assert guest.post(f'/api/rooms/{rid}/playback',json={'action':'start'}).status_code==403
            assert host.post(f'/api/rooms/{rid}/playback',json={'action':'start'}).status_code==200
            assert host.get(f'/api/rooms/{rid}').json()['current']['id']==item
            assert guest.post(f'/api/rooms/{rid}/skip').status_code==200
            assert host.post(f'/api/rooms/{rid}/skip').json()['skipped']
            assert guest.post(f'/api/rooms/{rid}/chat',json={'message':'Hello'}).status_code==200
            assert guest.get(f'/api/rooms/{rid}/chat').json()[-1]['message']=='Hello'
        assert host.patch(f'/api/rooms/{rid}',json={'mode':'music','music_limit':2}).status_code==200
        assert host.delete(f'/api/rooms/{rid}').status_code==200
        assert host.get(f'/api/rooms/{rid}').status_code==404


def test_invalid_origin_rejected():
    with TestClient(app,base_url='http://localhost:8080') as client:
        assert client.post('/api/dev-login',headers={'Origin':'https://attacker.example'}).status_code==403


def test_guest_join_rejects_wrong_invitation():
    with TestClient(app,base_url='http://localhost:8080') as client:
        client.post('/api/dev-login')
        rid=client.post('/api/rooms',json={'name':'Private'}).json()['id']
        client.cookies.clear()
        assert client.post(f'/api/rooms/{rid}/join',json={'secret':'wrong','name':'intruder'}).status_code==403

def test_limits_direct_audio_and_approval():
    with TestClient(app,base_url='http://localhost:8080') as host:
        host.post('/api/dev-login')
        rid=host.post('/api/rooms',json={'name':'Audio','mode':'music'}).json()['id']
        assert host.patch(f'/api/rooms/{rid}',json={'music_limit':1,'require_approval':True}).status_code==200
        secret=host.get(f'/api/rooms/{rid}').json()['join_secret']
        with TestClient(app,base_url='http://localhost:8080') as guest:
            tok=guest.post(f'/api/rooms/{rid}/join',json={'secret':secret,'name':'Friend'}).json()['guest_token']
            guest.headers['Authorization']='Bearer '+tok
            add=lambda name:guest.post(f'/api/rooms/{rid}/queue',json={'media_kind':'music','source':'direct','source_id':f'https://example.org/{name}.mp3','title':name})
            a=add('one');assert a.status_code==200,a.text
            assert guest.get(f'/api/rooms/{rid}').json()['pending'][0]['title']=='one'
            assert add('two').status_code==409
            assert guest.post(f'/api/rooms/{rid}/queue/{a.json()["id"]}/vote',json={'value':1}).status_code==200
            assert guest.post(f'/api/rooms/{rid}/queue/{a.json()["id"]}/vote',json={'value':1}).status_code==200
        assert host.post(f'/api/rooms/{rid}/queue/{a.json()["id"]}/moderate',json={'action':'approve'}).status_code==200
        assert host.get(f'/api/rooms/{rid}').json()['queued'][0]['score']==1
        qr=host.get(f'/api/rooms/{rid}/qr.png')
        assert qr.status_code==200 and qr.headers['content-type']=='image/png' and qr.content[:8]==b'\x89PNG\r\n\x1a\n'
def test_invite_rotation_and_guest_moderation():
    with TestClient(app,base_url='http://localhost:8080') as host:
        host.post('/api/dev-login')
        rid=host.post('/api/rooms',json={'name':'Moderated'}).json()['id']
        secret=host.get(f'/api/rooms/{rid}').json()['join_secret']
        with TestClient(app,base_url='http://localhost:8080') as guest:
            joined=guest.post(f'/api/rooms/{rid}/join',json={'secret':secret,'name':'Visitor'})
            assert joined.status_code==200,joined.text
            pid=joined.json()['participant_id']
            guest.headers['Authorization']='Bearer '+joined.json()['guest_token']
            assert guest.post(f'/api/rooms/{rid}/rotate-invite').status_code==403
            assert guest.post(f'/api/rooms/{rid}/participants/{pid}/moderate',json={'action':'ban'}).status_code==403
            assert host.post(f'/api/rooms/{rid}/participants/{pid}/moderate',json={'action':'kick'}).status_code==200
            assert guest.get(f'/api/rooms/{rid}').status_code==403
            assert pid not in [x['id'] for x in host.get(f'/api/rooms/{rid}').json()['participants']]
        assert host.get(f'/api/rooms/{rid}/moderation').json()[0]['participant_id']==pid
        assert host.post(f'/api/rooms/{rid}/rotate-invite').status_code==200
        newer=host.get(f'/api/rooms/{rid}').json()['join_secret']
        assert newer!=secret
        with TestClient(app,base_url='http://localhost:8080') as newcomer:
            assert newcomer.post(f'/api/rooms/{rid}/join',json={'secret':secret,'name':'Late'}).status_code==403
            assert newcomer.post(f'/api/rooms/{rid}/join',json={'secret':newer,'name':'Late'}).status_code==200
        assert host.delete(f'/api/rooms/{rid}/moderation/{pid}').status_code==200
        assert host.get(f'/api/rooms/{rid}/moderation').json()==[]


def test_registered_room_ban():
    from server.db import SessionLocal, User
    from server.security import issue
    with TestClient(app,base_url='http://localhost:8080') as host:
        host.post('/api/dev-login')
        rid=host.post('/api/rooms',json={'name':'Accounts'}).json()['id']
        secret=host.get(f'/api/rooms/{rid}').json()['join_secret']
        with SessionLocal.begin() as db:
            db.add(User(id='second-test-user',username='second-test-user',display_name='Other User'))
        with TestClient(app,base_url='http://localhost:8080') as user:
            user.headers['Authorization']='Bearer '+issue({'type':'user','sub':'second-test-user'})
            joined=user.post(f'/api/rooms/{rid}/join',json={'secret':secret})
            assert joined.status_code==200,joined.text
            pid=joined.json()['participant_id']
            assert host.post(f'/api/rooms/{rid}/participants/{pid}/moderate',json={'action':'ban'}).status_code==200
            assert user.get(f'/api/rooms/{rid}').status_code==403
            assert user.post(f'/api/rooms/{rid}/join',json={'secret':secret}).status_code==403
            assert host.delete(f'/api/rooms/{rid}/moderation/{pid}').status_code==200
            assert user.post(f'/api/rooms/{rid}/join',json={'secret':secret}).status_code==200
