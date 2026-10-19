# Watchbeat

<p align="center"><img src="web/assets/icons/watchbeat-512.png" alt="Watchbeat icon" width="128"></p>

<p align="center"><strong>Watch together. Listen together. Control the vibe together.</strong></p>

Watchbeat is a **self-hosted collaborative watch-party and music-room application**. Create temporary rooms, invite guests using a private QR code, control playback across devices, vote on a shared queue and chat in real time. Its responsive web app is designed for desktop, mobile and in-car browsers, with Apple-inspired translucent UI surfaces.

> **Status: functional early-access build, not a fully finished production release.** Core room, voting, chat, session and video APIs are implemented and covered by automated tests. Apple Music requires your own MusicKit credentials; browser/provider compatibility must be tested. Multi-device acoustic synchronization remains experimental. Do not deploy as an unattended public service without further review, backups and hardening.

## What currently works

- Docker Compose application with FastAPI, PostgreSQL, real-time WebSockets and a responsive installable PWA.
- **Pocket ID / OIDC login** (authorization-code flow with PKCE, verified ID token and secure HTTP-only application session). **Invitation-only account registration is configured in Pocket ID**, not by a second Watchbeat password database.
- Rooms created by authenticated hosts; anonymous guests join via locally generated QR code and choose a display name. Rooms expire after **24 hours of inactivity**.
- Switch a room between music and video without losing participants or queued items. Enable one-screen or multi-viewer behavior.
- Shared queue with **one upvote, downvote, or neutral vote per queue item and participant**; highest net score plays first. Hosts configure separate guest limits for music and video and can require approval of suggestions.
- Active-participant majority voting to skip the current item, with playback controls reserved to the host.
- YouTube IFrame API playback and HTML5 direct HTTPS media playback on eligible browsers, with server-coordinated play/pause/seek state and periodic drift correction.
- Live participant presence, room chat and emoji reactions.
- Local friend search, requests/acceptance and direct room invitations (same Watchbeat instance).
- MusicKit on the Web integration: developer-token configuration, Apple Music catalog search, host authorization and personal playlist browser; host-only protected music playback in an explicitly enabled viewer. Direct HTTPS audio files can also be queued and played on multiple viewers (when you have the rights).
- Manual video/audio output timing offset and a **beta** microphone test-tone measurement (not a production-grade multi-device calibration system).

## Known limits

- Apple Music is **not redistributable**. Guest search and voting are possible without an Apple Music subscription, but an **authorized player** needs the appropriate subscription. One host subscription is **not permission to restream music** to other devices. This app never proxies protected music or bypasses DRM. MusicKit player APIs and Tesla browser compatibility require real-device testing.
- The microphone experiment estimates local acoustic capture delay; direct audio playback uses approximate server time plus manual output offsets. It **does not automatically synchronize multiple Bluetooth speakers**, nor does it measure a protected MusicKit stream. Multi-device video playback is best effort because browser autoplay, codec and YouTube policies differ.
- Web Push, provider-neutral audio synchronization, moderator kick/ban, encrypted at-rest provider token storage, automatic database migrations and full accessibility audits are not complete.
- WebSockets currently use an **in-memory connection registry**. Run **one backend replica** unless a Redis pub/sub backplane is added.
- Direct media currently supports HTTPS MP4/WebM and browser-supported files. HLS depends on the browser (no HLS.js adapter included). No backend-side URL fetching or transcoding is performed.
- Docker/Traefik images are configured but this repository is **not tested against your specific home-server deployment or credentials**.

## Requirements

- Docker Engine and Docker Compose plugin
- An existing `proxy` Docker network and Traefik v3 with a `cloudflare` TLS certificate resolver (or adapt `compose.yaml` for your reverse proxy)
- A public HTTPS domain for secure passkey login, microphone access, PWA installation and Apple Music
- A Pocket ID confidential OIDC client with redirect URL: `https://watchbeat.example.com/auth/callback`
- Optional: Apple Developer/MusicKit integration credentials and an ES256 developer JWT

## Install with Docker Compose

```bash
git clone https://github.com/Baodor/Watchbeat.git
cd Watchbeat
cp .env.example .env
# Set all mandatory variables in .env; never commit it.
openssl rand -hex 48  # put output in SESSION_SECRET
openssl rand -hex 32  # put output in POSTGRES_PASSWORD

docker network create proxy 2>/dev/null || true  # skip if your Traefik network exists
docker compose up -d --build
docker compose ps
docker compose logs -f watchbeat
```

Configure your `.env`:

| Name | Purpose |
| --- | --- |
| `WATCHBEAT_HOST` | Hostname used by the Traefik router, e.g. `watchbeat.example.com` |
| `PUBLIC_URL` | Exact public origin, e.g. `https://watchbeat.example.com` (no trailing slash) |
| `OIDC_ISSUER` | Pocket ID issuer URL shown by its discovery metadata |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Confidential OIDC client credentials |
| `SESSION_SECRET` | At least 32 random characters, persistent across restarts |
| `POSTGRES_PASSWORD` | Strong database password |
| `APPLE_MUSIC_DEVELOPER_TOKEN` | Optional MusicKit developer token, generated separately |
| `APPLE_MUSIC_STOREFRONT` | Country storefront for catalog search, default `de` |

For Pocket ID, restrict self-registration to invite links, create a **confidential** OIDC client, set the callback URL to the one above, then grant the intended user groups access to that client. Watchbeat relies on Pocket ID for passkey enrollment and identity lifecycle.

The service listens inside Docker on port `8080` but **does not publish a host port**. Traefik routes `websecure` HTTPS traffic to the container over the existing external `proxy` network; this avoids host-port collisions on shared Docker servers. Change the network/labels for your own infrastructure. The PostgreSQL data is persisted in the `postgres_data` volume.

Health endpoint: `/api/health`. API documentation: `/docs` (avoid exposing developer docs publicly without additional controls).

### Permission-denied errors during Docker startup

If the container repeatedly restarts with a `PermissionError` when importing Uvicorn from `site-packages`, upgrade to the current Dockerfile and **rebuild** with `docker compose up -d --build`. The current Dockerfile installs dependencies as root, explicitly makes installed Python libraries readable by the unprivileged UID 10001, then verifies imports as that user during the build. On servers with unstable Docker-build DNS, this layout can reuse the previously cached successful `pip install` layer. Run `docker compose up -d --build` to apply the Dockerfile change. If the build still reports `Temporary failure in name resolution` for PyPI, fix the builder's DNS/connectivity first; a `No matching distribution found` error after DNS failures is misleading.

### Missing Python package `server` on startup

If the backend exits with `ModuleNotFoundError: No module named 'server'`, pull the latest Dockerfile and rebuild the image. The source is copied into `/app/server`, `PYTHONPATH=/app` and `uvicorn --app-dir /app` make the package location explicit, and the image build now tests `from server.main import app` as UID 10001. A simple container restart does **not** rebuild the image.

### Local API smoke tests (without Pocket ID)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest
PYTHONPATH=. pytest -q tests/
```

A developer-only demo login exists for local HTTP testing if `DEV_LOGIN_ENABLED=true` and `PUBLIC_URL` uses HTTP. **Do not enable it on a deployed instance**. It is not present in the production Docker Compose environment.

## How it works

1. Sign in through Pocket ID with your passkey.
2. Create a room and choose music/video and device mode.
3. Open **Join QR**; friends scan it, choose a display name and join without a Watchbeat account.
4. Add Apple Music songs (MusicKit integration required), directly hosted HTTPS audio, or a YouTube/direct video URL. Participants vote; the room orders queued media by score.
5. Start playback from a host session. On another device, switch to **Viewer**; the controller can be a different signed-in device of the same host.
6. Use chat, reactions, skip votes and the room configuration. Rooms automatically disappear 24 hours after the last activity.

## Architecture

```text
Browser / installable PWA / Tesla browser (where supported)
      |  HTTPS + WebSocket
      v
Traefik (TLS termination / Cloudflare DNS-01)
      |
      v
FastAPI (OIDC, API, room authorization, queue/votes, chat, playback coordinator)
      |                           |
      v                           v
PostgreSQL                  In-memory WS fanout
      |
      +-- Room / participant / vote / message / friend state

Playback is client-side: YouTube IFrame, native HTML5 video or authorized MusicKit.
No Apple Music audio is intercepted or relayed by Watchbeat.
```

The code intentionally separates `server/db.py` models, `server/security.py` OIDC/session logic, `server/main.py` API + coordinator and `web/` frontend. API authorization and vote uniqueness are enforced on the server, not merely hidden in the UI.

## Security notes

- Protect your `.env` and database backups. Never commit OIDC secrets, session keys, or private MusicKit signing keys.
- QR room links contain revocable bearer secrets. **Room QR images are generated on your server**, not by a third-party QR service.
- Cookies are HTTP-only and Secure on an HTTPS deployment, with origin validation on state-changing API calls.
- Room guest tokens have a maximum lifetime and are scoped to a single room. Anonymous guests can still create another identity with another browser session; per-real-human identity cannot be guaranteed.
- Direct URLs are validated, but browser compatibility and third-party hosting policies remain the operator's responsibility. Avoid treating remote URLs as safe executable content.
- Back up Postgres before upgrading. There is no formal migration framework in this early release.

## Development and next milestones

- [x] Core Docker/DB/backend, room sessions and expiration
- [x] Guest invitations, server-side voting, limits, moderation and chat
- [x] Shared video player coordination, MusicKit connector scaffolding, Liquid Glass-inspired PWA
- [ ] Real Pocket ID / MusicKit / Tesla device acceptance tests
- [ ] Web Push subscription persistence and notifications
- [ ] Secure persistent provider connection settings and playback-device ownership
- [ ] Robust multi-device clock calibration and permitted acoustic sync
- [ ] Database migrations, rate limiting, user account cleanup, kick/ban controls, end-to-end tests
- [ ] Accessibility and responsive design audit

## Disclaimer

Watchbeat is independent and not affiliated with Apple, Google/YouTube, Pocket ID or Tesla. Apple Music availability and use are governed by Apple's developer terms and applicable content licenses. The custom glass design is a browser recreation, not an Apple-owned native Liquid Glass engine.

No license has been selected yet; source availability does not automatically grant an open-source license.
