"""
Database Initialization Script for CryptoVote
Creates all tables defined in models.py and seeds initial candidate data.
Works identically on local SQLite and production Amazon RDS MySQL.
"""
import os
import sys
from flask import Flask

# Add project root to sys.path so imports work seamlessly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models import db, Candidate, Voter, UsedToken, Vote, AuditLog

def init_database(database_uri=None):
    app = Flask(__name__)
    
    # Use provided database_uri, or environment variable, or default local SQLite
    db_uri = database_uri or os.environ.get('DATABASE_URL', 'sqlite:///cryptovote.db')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        print(f"[*] Connecting to database: {db_uri.split('@')[-1] if '@' in db_uri else db_uri}")
        print("[*] Creating all database tables: voters, candidates, used_tokens, votes, audit_log...")
        db.create_all()
        print("[+] All tables successfully created/verified!")

        # Check if candidates exist, seed them if table is empty
        if Candidate.query.count() == 0:
            print("[*] Seeding default candidates...")
            candidates = [
                Candidate(
                    name="Alice Green",
                    party="Cyber Security Party",
                    bio="Advocate for digital privacy, transparent systems, and open-source infrastructure."
                ),
                Candidate(
                    name="Bob Stone",
                    party="Cloud Computing Alliance",
                    bio="Focused on high availability, scalable services, and resilient architecture."
                ),
                Candidate(
                    name="Charlie Vance",
                    party="Innovation Coalition",
                    bio="Championing cryptographic integrity, machine learning, and student welfare."
                )
            ]
            db.session.bulk_save_objects(candidates)
            
            # Log initial audit entry
            init_audit = AuditLog(
                event_type="SYSTEM_INIT",
                description="Database initialized and candidates seeded.",
                ip_address="127.0.0.1"
            )
            db.session.add(init_audit)
            db.session.commit()
            print("[+] Seeded 3 election candidates and system audit log successfully!")
        else:
            print(f"[i] Candidates already seeded (Count: {Candidate.query.count()}). Skipping seeding.")

        print("\n--- Current Election Candidates in Database ---")
        for c in Candidate.query.all():
            print(f"  [Candidate #{c.id}] {c.name} ({c.party})")
        print("------------------------------------------------\n")

if __name__ == '__main__':
    init_database()
