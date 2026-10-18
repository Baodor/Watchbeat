"""Persistent SQLAlchemy models. PostgreSQL in Docker; SQLite supported for tests."""
import os
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./watchbeat.db')
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)

def now():
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(160), default='')
    picture: Mapped[str] = mapped_column(Text, default='')
    email: Mapped[str] = mapped_column(String(320), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Room(Base):
    __tablename__ = 'rooms'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    name: Mapped[str] = mapped_column(String(100))
    join_secret: Mapped[str] = mapped_column(String(100), unique=True)
    mode: Mapped[str] = mapped_column(String(12), default='music')
    multiple_players: Mapped[bool] = mapped_column(Boolean, default=False)
    join_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    music_limit: Mapped[int] = mapped_column(Integer, default=3)
    video_limit: Mapped[int] = mapped_column(Integer, default=2)
    current_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    playing: Mapped[bool] = mapped_column(Boolean, default=False)
    position: Mapped[float] = mapped_column(default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Participant(Base):
    __tablename__ = 'participants'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    room_id: Mapped[str] = mapped_column(ForeignKey('rooms.id', ondelete='CASCADE'), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    name: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(16), default='guest')
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class QueueItem(Base):
    __tablename__ = 'queue_items'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    room_id: Mapped[str] = mapped_column(ForeignKey('rooms.id', ondelete='CASCADE'), index=True)
    participant_id: Mapped[str] = mapped_column(ForeignKey('participants.id'), index=True)
    media_kind: Mapped[str] = mapped_column(String(10))
    source: Mapped[str] = mapped_column(String(20))
    source_id: Mapped[str] = mapped_column(String(2048))
    title: Mapped[str] = mapped_column(String(200))
    artist: Mapped[str] = mapped_column(String(200), default='')
    artwork: Mapped[str] = mapped_column(Text, default='')
    status: Mapped[str] = mapped_column(String(20), default='queued')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Vote(Base):
    __tablename__ = 'votes'
    __table_args__ = (UniqueConstraint('item_id', 'participant_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    item_id: Mapped[str] = mapped_column(ForeignKey('queue_items.id', ondelete='CASCADE'), index=True)
    participant_id: Mapped[str] = mapped_column(ForeignKey('participants.id'))
    value: Mapped[int] = mapped_column(Integer)

class SkipVote(Base):
    __tablename__ = 'skip_votes'
    __table_args__ = (UniqueConstraint('room_id', 'item_id', 'participant_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    room_id: Mapped[str] = mapped_column(ForeignKey('rooms.id', ondelete='CASCADE'))
    item_id: Mapped[str] = mapped_column(String(36))
    participant_id: Mapped[str] = mapped_column(ForeignKey('participants.id'))

class Message(Base):
    __tablename__ = 'messages'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    room_id: Mapped[str] = mapped_column(ForeignKey('rooms.id', ondelete='CASCADE'), index=True)
    participant_id: Mapped[str] = mapped_column(ForeignKey('participants.id'))
    name: Mapped[str] = mapped_column(String(80))
    body: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Friendship(Base):
    __tablename__ = 'friendships'
    __table_args__ = (UniqueConstraint('requester_id', 'recipient_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    requester_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    recipient_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(16), default='pending')

class Invitation(Base):
    __tablename__ = 'invitations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    room_id: Mapped[str] = mapped_column(ForeignKey('rooms.id', ondelete='CASCADE'))
    recipient_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
