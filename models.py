"""
CryptoVote SQLAlchemy Models
Defines the database schema and object-relational mapping for candidates, voters,
used tokens, the cryptographic vote hash-chain ledger, and audit logs.
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def utc_now_str():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def utc_now():
    return datetime.now(timezone.utc)

class Candidate(db.Model):
    __tablename__ = 'candidates'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    votes = db.relationship('Vote', backref='candidate', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'party': self.party,
            'bio': self.bio
        }


class Voter(db.Model):
    __tablename__ = 'voters'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    voter_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    has_requested_ballot = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utc_now)

    def to_dict(self):
        return {
            'voter_id': self.voter_id,
            'has_requested_ballot': self.has_requested_ballot,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class UsedToken(db.Model):
    __tablename__ = 'used_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    used_at = db.Column(db.DateTime, default=utc_now)


class Vote(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id'), nullable=False)
    token = db.Column(db.String(128), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    timestamp = db.Column(db.String(32), default=utc_now_str, nullable=False)

    @property
    def block_index(self):
        return self.id

    def to_dict(self):
        return {
            'block_index': self.id,
            'candidate_id': self.candidate_id,
            'token': self.token,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash,
            'timestamp': str(self.timestamp)
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'description': self.description,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
