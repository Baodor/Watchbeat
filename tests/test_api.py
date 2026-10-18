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
