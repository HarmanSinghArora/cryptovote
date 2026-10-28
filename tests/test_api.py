"""
Integration Test Suite for CryptoVote Flask API
Tests all 9 endpoints using Flask test client:
1. Candidate listing
2. Voter registration & salted PBKDF2 password authentication
3. Session token issuance
4. Cryptographic ballot blinding and blind signature issuance
5. Unblinded anonymous voting
6. Double-vote rejection
7. Receipt verification
8. Full hash chain verification
9. Administrative election closure
"""

import os
import sys
import json
import secrets
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import Config
from app import create_app
from models import db, Candidate
from crypto.blind_rsa import hash_to_int, blind_message, unblind_signature

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'  # Pure in-memory SQLite database
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class TestCryptoVoteAPI(unittest.TestCase):

    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            if Candidate.query.count() == 0:
                c1 = Candidate(name="Alice Green", party="Cyber Security Party")
                c2 = Candidate(name="Bob Stone", party="Cloud Computing Alliance")
                db.session.add_all([c1, c2])
                db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_01_health_and_candidates(self):
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['status'], 'HEALTHY')

        res = self.client.get('/candidates')
        self.assertEqual(res.status_code, 200)
        candidates = res.json['candidates']
        self.assertGreaterEqual(len(candidates), 2)
        print("  [PASS] Endpoint: GET / and GET /candidates")

    def test_02_registration_and_authentication(self):
        voter_id = f"voter_{secrets.token_hex(4)}"
        password = "SecurePassword2026!"

        # 1. Register voter
        res_reg = self.client.post('/register', json={'voter_id': voter_id, 'password': password})
        self.assertEqual(res_reg.status_code, 201)
        self.assertEqual(res_reg.json['voter_id'], voter_id)

        # 2. Reject duplicate voter_id
        res_dup = self.client.post('/register', json={'voter_id': voter_id, 'password': password})
        self.assertEqual(res_dup.status_code, 409)

        # 3. Reject wrong password login
        res_bad = self.client.post('/login', json={'voter_id': voter_id, 'password': 'WrongPassword!'})
        self.assertEqual(res_bad.status_code, 401)

        # 4. Successful login
        res_login = self.client.post('/login', json={'voter_id': voter_id, 'password': password})
        self.assertEqual(res_login.status_code, 200)
        self.assertIn('token', res_login.json)
        print("  [PASS] Endpoint: POST /register and POST /login (Auth verified)")

    def test_03_complete_voting_cycle_and_ledger(self):
        voter_id = f"voter_{secrets.token_hex(4)}"
        password = "SecurePassword2026!"

        # Register & Login
        self.client.post('/register', json={'voter_id': voter_id, 'password': password})
        res_login = self.client.post('/login', json={'voter_id': voter_id, 'password': password})
        token = res_login.json['token']

        # Get authority public key
        res_key = self.client.get('/crypto/public-key')
        self.assertEqual(res_key.status_code, 200)
        e = int(res_key.json['e'])
        n = int(res_key.json['n'])

        # Prepare anonymous ballot for candidate 1
        candidate_id = 1
        ballot_token = secrets.token_hex(16)
        ballot_raw = f"candidate:{candidate_id};token:{ballot_token}".encode('utf-8')
        m = hash_to_int(ballot_raw, n)

        # Client blinds ballot
        m_prime, r = blind_message(m, e, n)

        # Request blind signature
        headers = {'Authorization': f'Bearer {token}'}
        res_blind = self.client.post('/blind-sign', json={'blinded_message': str(m_prime)}, headers=headers)
        self.assertEqual(res_blind.status_code, 200)
        s_prime = int(res_blind.json['blind_signature'])

        # Voter cannot request a second ballot
        res_blind_dup = self.client.post('/blind-sign', json={'blinded_message': str(m_prime)}, headers=headers)
        self.assertEqual(res_blind_dup.status_code, 400)

        # Voter unblinds signature locally
        s = unblind_signature(s_prime, r, n)

        # Cast vote anonymously (NO session token or voter ID attached!)
        vote_payload = {
            'candidate_id': candidate_id,
            'token': ballot_token,
            'signature': str(s)
        }
        res_vote = self.client.post('/vote', json=vote_payload)
        self.assertEqual(res_vote.status_code, 200)
        receipt_hash = res_vote.json['receipt_hash']
        print(f"  [PASS] Endpoint: POST /blind-sign and POST /vote (Receipt: {receipt_hash[:16]}...)")

        # Double-voting rejection test
        res_dup_vote = self.client.post('/vote', json=vote_payload)
        self.assertEqual(res_dup_vote.status_code, 409)
        print("  [PASS] Double-voting blocked: Ballot token reuse rejected with 409 Conflict")

        # Verify receipt lookup
        res_receipt = self.client.get(f'/receipt/{receipt_hash}')
        self.assertEqual(res_receipt.status_code, 200)
        self.assertTrue(res_receipt.json['verified'])
        print(f"  [PASS] Endpoint: GET /receipt/{receipt_hash[:16]}...")

        # Verify hash chain
        res_chain = self.client.get('/admin/verify-chain')
        self.assertEqual(res_chain.status_code, 200)
        self.assertTrue(res_chain.json['is_valid'])
        self.assertEqual(res_chain.json['total_blocks'], 1)
        print("  [PASS] Endpoint: GET /admin/verify-chain (Cryptographic ledger integrity confirmed)")

        # Verify results
        res_results = self.client.get('/results')
        self.assertEqual(res_results.status_code, 200)
        self.assertEqual(res_results.json['total_votes'], 1)
        print("  [PASS] Endpoint: GET /results")

    def test_04_admin_election_closure(self):
        admin_secret = self.app.config['ADMIN_SECRET_KEY']

        # Close election with correct secret
        res_close = self.client.post('/admin/close', json={'admin_secret': admin_secret})
        self.assertEqual(res_close.status_code, 200)
        self.assertEqual(res_close.json['results_summary']['election_status'], 'CLOSED')

        # After closure, no more votes can be cast
        res_blocked = self.client.post('/vote', json={'candidate_id': 1, 'token': 'abc', 'signature': '123'})
        self.assertEqual(res_blocked.status_code, 403)
        print("  [PASS] Endpoint: POST /admin/close (Election closed & voting locked)")

    def test_05_forged_token_rejection(self):
        # Professor's Test: Vote with forged token -> Rejected; INVALID_TOKEN appears in logs
        forged_payload = {
            'candidate_id': 1,
            'token': f"forged_token_{secrets.token_hex(16)}",
            'signature': '99999999999999999999999999'  # Forged fake signature
        }
        res_forged = self.client.post('/vote', json=forged_payload)
        self.assertEqual(res_forged.status_code, 400)
        self.assertEqual(res_forged.json.get('code'), 'INVALID_TOKEN')
        print("  [PASS] Forged token rejected with 400 Bad Request & code=INVALID_TOKEN")

if __name__ == '__main__':
    unittest.main()
