"""
CryptoVote Backend Application
Main Flask entry point implementing all 9 REST API endpoints for the secure voting system.
"""

import os
import json
import secrets
import hashlib
import hmac
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template

from config import Config
from models import db, Candidate, Voter, UsedToken, Vote, AuditLog
from crypto.blind_rsa import (
    generate_keypair,
    hash_to_int,
    sign_blinded,
    verify_signature
)
from crypto.hashchain import HashChainLedger, GENESIS_PREV_HASH
from crypto.password import hash_password, verify_password

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    with app.app_context():
        db.create_all()
        if Candidate.query.count() == 0:
            c1 = Candidate(name="Alice Green", party="Cyber Security Party", bio="Advocate for digital privacy.")
            c2 = Candidate(name="Bob Stone", party="Cloud Computing Alliance", bio="Focused on high availability.")
            c3 = Candidate(name="Charlie Vance", party="Innovation Coalition", bio="Championing cryptographic integrity.")
            db.session.add_all([c1, c2, c3])
            db.session.commit()
            print("[+] Initialized database tables and default election candidates.")

    # Persistent Authority Keypair Management
    keys_dir = os.path.join(os.path.dirname(__file__), 'keys')
    os.makedirs(keys_dir, exist_ok=True)
    key_file = os.path.join(keys_dir, 'authority_keypair.json')

    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            key_data = json.load(f)
            pub_key = key_data['public_key']
            priv_key = key_data['private_key']
            print("[+] Loaded existing 2048-bit Election Authority Keypair.")
    else:
        print("[*] Generating new 2048-bit Election Authority Keypair...")
        pub_key, priv_key = generate_keypair(key_size=2048)
        with open(key_file, 'w') as f:
            json.dump({'public_key': pub_key, 'private_key': priv_key}, f)
        print("[+] Generated and persisted Election Authority Keypair in keys/authority_keypair.json")

    # In-memory session store: token -> voter_id
    active_sessions = {}
    
    # State flag: is election open
    election_state = {'is_open': True}

    def log_audit(event_type, description):
        """Helper to record audit events."""
        try:
            ip = request.remote_addr if request else '127.0.0.1'
            audit = AuditLog(event_type=event_type, description=description, ip_address=ip)
            db.session.add(audit)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"[!] Audit log error: {e}")

    def publish_sns_alert(subject, message):
        """Publishes critical alerts to Amazon SNS topic if configured."""
        topic_arn = os.environ.get('SNS_TOPIC_ARN') or app.config.get('SNS_TOPIC_ARN')
        if not topic_arn:
            try:
                import boto3
                ssm = boto3.client('ssm', region_name=app.config.get('AWS_REGION', 'ap-south-1'))
                param = ssm.get_parameter(Name='/cryptovote/sns_topic_arn')
                topic_arn = param['Parameter']['Value']
            except Exception:
                topic_arn = None

        if topic_arn:
            try:
                import boto3
                sns = boto3.client('sns', region_name=app.config.get('AWS_REGION', 'ap-south-1'))
                sns.publish(
                    TopicArn=topic_arn,
                    Subject=subject[:100],
                    Message=message
                )
                print(f"[+] Successfully published SNS alert to {topic_arn}!")
                log_audit('SNS_ALERT_SENT', f"SNS alert sent: {subject}")
            except Exception as e:
                print(f"[!] Failed to publish SNS alert: {e}")
        else:
            print(f"[i] SNS_TOPIC_ARN not configured. Simulated SNS Alert: {subject}")

    # =========================================================================
    # 0. SYSTEM & CRYPTO METADATA ENDPOINTS
    # =========================================================================

    @app.route('/', methods=['GET'])
    def health_check():
        accept = request.headers.get('Accept', '')
        # If requested from a browser accepting HTML, render modern responsive frontend
        if 'text/html' in accept and 'application/json' not in accept:
            return render_template('index.html')

        return jsonify({
            'service': 'CryptoVote REST API',
            'status': 'HEALTHY',
            'version': '1.0.0',
            'election_status': 'OPEN' if election_state['is_open'] else 'CLOSED',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200

    @app.route('/portal', methods=['GET'])
    @app.route('/index.html', methods=['GET'])
    def portal_view():
        return render_template('index.html')

    @app.route('/crypto/public-key', methods=['GET'])
    def get_public_key():
        """Returns the Election Authority's public key (e, n) for client blinding & verification."""
        return jsonify({
            'e': str(pub_key['e']),
            'n': str(pub_key['n']),
            'algorithm': 'RSA-2048-Blind-Signature',
            'hash_algorithm': 'SHA-256'
        }), 200

    # =========================================================================
    # 1. CANDIDATES ENDPOINT
    # =========================================================================

    @app.route('/candidates', methods=['GET'])
    def get_candidates():
        candidates = Candidate.query.order_by(Candidate.id.asc()).all()
        return jsonify({
            'candidates': [c.to_dict() for c in candidates]
        }), 200

    # =========================================================================
    # 2. VOTER REGISTRATION & AUTHENTICATION
    # =========================================================================

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json(silent=True) or {}
        voter_id = data.get('voter_id', '').strip()
        password = data.get('password', '').strip()

        if not voter_id or not password:
            return jsonify({'error': 'voter_id and password are required'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400

        existing = Voter.query.filter_by(voter_id=voter_id).first()
        if existing:
            return jsonify({'error': f'Voter ID {voter_id} is already registered'}), 409

        # PBKDF2-HMAC-SHA256 password hashing with salt
        pwd_hash, salt = hash_password(password)

        new_voter = Voter(
            voter_id=voter_id,
            password_hash=pwd_hash,
            salt=salt,
            has_requested_ballot=False
        )

        db.session.add(new_voter)
        db.session.commit()

        log_audit('VOTER_REGISTER', f"Voter {voter_id} registered successfully.")

        return jsonify({
            'message': 'Voter registered successfully',
            'voter_id': voter_id
        }), 201

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json(silent=True) or {}
        voter_id = data.get('voter_id', '').strip()
        password = data.get('password', '').strip()

        if not voter_id or not password:
            return jsonify({'error': 'voter_id and password are required'}), 400

        voter = Voter.query.filter_by(voter_id=voter_id).first()
        if not voter:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Constant-time PBKDF2 verification
        if not verify_password(voter.password_hash, voter.salt, password):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Generate secure random session token
        # Generate cryptographically signed stateless session token
        ts = str(int(datetime.now(timezone.utc).timestamp()))
        sig = hmac.new(app.config['SECRET_KEY'].encode('utf-8'), f"{voter_id}:{ts}".encode('utf-8'), hashlib.sha256).hexdigest()
        session_token = f"{voter_id}.{ts}.{sig}"
        active_sessions[session_token] = voter_id

        log_audit('VOTER_LOGIN', f"Voter {voter_id} logged in.")

        return jsonify({
            'message': 'Login successful',
            'token': session_token,
            'voter_id': voter.voter_id,
            'has_requested_ballot': voter.has_requested_ballot
        }), 200

    # =========================================================================
    # 3. BLIND SIGNATURE ISSUANCE (Voter Identity Known, Ballot Choice HIDDEN)
    # =========================================================================

    @app.route('/blind-sign', methods=['POST'])
    def blind_sign():
        if not election_state['is_open']:
            return jsonify({'error': 'Election is closed. Ballots are no longer issued.'}), 403

        # Authenticate via Bearer Token
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '').strip()

        voter_id = active_sessions.get(token)
        if not voter_id and '.' in token:
            parts = token.split('.')
            if len(parts) == 3:
                vid, ts, sig = parts
                expected_sig = hmac.new(app.config['SECRET_KEY'].encode('utf-8'), f"{vid}:{ts}".encode('utf-8'), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, expected_sig):
                    voter_id = vid
        if not voter_id:
            return jsonify({'error': 'Unauthorized: Valid session token required'}), 401
        voter = Voter.query.filter_by(voter_id=voter_id).first()

        if not voter:
            return jsonify({'error': 'Voter not found'}), 404

        if voter.has_requested_ballot:
            return jsonify({
                'error': 'Duplicate ballot request rejected. Voter has already received a blind signature.'
            }), 400

        data = request.get_json(silent=True) or {}
        blinded_message = data.get('blinded_message')

        if not blinded_message:
            return jsonify({'error': 'blinded_message integer is required'}), 400

        try:
            m_prime = int(blinded_message)
        except ValueError:
            return jsonify({'error': 'blinded_message must be a valid integer'}), 400

        # Sign the blinded message: s' = (m')^d mod n
        # Notice: Server signs m_prime without ever knowing what candidate was chosen!
        s_prime = sign_blinded(m_prime, priv_key['d'], priv_key['n'])

        # Mark voter as having received their one authorized ballot
        voter.has_requested_ballot = True
        db.session.commit()

        log_audit('BLIND_SIGN', f"Blind signature issued for voter {voter_id}.")

        return jsonify({
            'blind_signature': str(s_prime)
        }), 200

    # =========================================================================
    # 4. ANONYMOUS VOTE SUBMISSION (Ballot Verified, Identity UNKNOWN)
    # =========================================================================

    @app.route('/vote', methods=['POST'])
    def submit_vote():
        if not election_state['is_open']:
            return jsonify({'error': 'Election is closed. No new votes accepted.'}), 403

        data = request.get_json(silent=True) or {}
        candidate_id = data.get('candidate_id')
        token = data.get('token')
        signature = data.get('signature')

        if candidate_id is None or not token or not signature:
            return jsonify({'error': 'candidate_id, token, and signature are required'}), 400

        try:
            candidate_id = int(candidate_id)
            sig_int = int(signature)
        except ValueError:
            return jsonify({'error': 'candidate_id and signature must be integers'}), 400

        # Verify candidate exists
        candidate = db.session.get(Candidate, candidate_id)
        if not candidate:
            return jsonify({'error': f'Candidate with ID {candidate_id} not found'}), 404

        # 1. Cryptographic Verification of the Unblinded RSA Signature
        # Reconstruct message m = SHA256("candidate:{id};token:{token}") mod n
        ballot_raw = f"candidate:{candidate_id};token:{token}".encode('utf-8')
        m = hash_to_int(ballot_raw, pub_key['n'])

        if not verify_signature(m, sig_int, pub_key['e'], pub_key['n']):
            print(f"[!] INVALID_TOKEN: Forged or invalid cryptographic signature for candidate {candidate_id}")
            log_audit('INVALID_TOKEN', f"INVALID_TOKEN: Forged ballot signature detected for candidate {candidate_id}")
            return jsonify({'error': 'Invalid cryptographic signature. Vote rejected.', 'code': 'INVALID_TOKEN'}), 400

        # 2. Prevent Double Voting via Used Token Table
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        existing_token = UsedToken.query.filter_by(token_hash=token_hash).first()
        if existing_token:
            log_audit('VOTE_REJECTED', "Duplicate token reuse detected and rejected.")
            return jsonify({'error': 'Double voting rejected: Ballot token has already been used.'}), 409

        # Record token as spent
        db.session.add(UsedToken(token_hash=token_hash))

        # 3. Append to Hash Chain Ledger
        last_vote = Vote.query.order_by(Vote.id.desc()).first()
        prev_hash = last_vote.entry_hash if last_vote else GENESIS_PREV_HASH

        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        next_block_index = (last_vote.id + 1) if last_vote else 1

        entry_hash = HashChainLedger.compute_vote_hash(
            block_index=next_block_index,
            candidate_id=candidate_id,
            token=token,
            signature=signature,
            previous_hash=prev_hash,
            timestamp_str=now_str
        )

        new_vote = Vote(
            candidate_id=candidate_id,
            token=token,
            signature=str(signature),
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            timestamp=now_str
        )

        db.session.add(new_vote)
        db.session.commit()

        log_audit('VOTE_CAST', f"Anonymous vote appended to ledger at block #{new_vote.id}.")

        return jsonify({
            'message': 'Vote recorded successfully',
            'receipt_hash': entry_hash,
            'block_index': new_vote.id,
            'timestamp': now_str
        }), 200

    # =========================================================================
    # 5. RECEIPT LOOKUP & RESULTS
    # =========================================================================

    @app.route('/receipt/<hash_val>', methods=['GET'])
    def get_receipt(hash_val):
        vote = Vote.query.filter_by(entry_hash=hash_val).first()
        if not vote:
            return jsonify({'verified': False, 'error': 'Receipt hash not found in blockchain ledger'}), 404

        return jsonify({
            'verified': True,
            'block_index': vote.id,
            'candidate_id': vote.candidate_id,
            'receipt_hash': vote.entry_hash,
            'previous_hash': vote.previous_hash,
            'timestamp': str(vote.timestamp) if vote.timestamp else None
        }), 200

    @app.route('/results', methods=['GET'])
    def get_results():
        candidates = Candidate.query.all()
        total_votes = Vote.query.count()

        results = []
        for c in candidates:
            c_votes = Vote.query.filter_by(candidate_id=c.id).count()
            results.append({
                'candidate_id': c.id,
                'name': c.name,
                'party': c.party,
                'votes': c_votes
            })

        return jsonify({
            'election_status': 'OPEN' if election_state['is_open'] else 'CLOSED',
            'total_votes': total_votes,
            'results': results
        }), 200

    # =========================================================================
    # 6. ADMIN CHAIN VERIFICATION & ELECTION CLOSURE
    # =========================================================================

    @app.route('/admin/verify-chain', methods=['GET'])
    def admin_verify_chain():
        votes = Vote.query.order_by(Vote.id.asc()).all()
        is_valid, details = HashChainLedger.verify_chain(votes)

        if not is_valid:
            alert_msg = (
                f"CRITICAL: CryptoVote Hash-Chain Integrity Verification FAILED!\n\n"
                f"Error: {details.get('error')}\n"
                f"Block Index: {details.get('block_index')}\n"
                f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n\n"
                f"Immediate administrative intervention required. Please inspect the audit log."
            )
            publish_sns_alert("CRITICAL ALERT: CryptoVote Hash Chain Tampering Detected!", alert_msg)
            log_audit('CHAIN_TAMPER_DETECTED', f"Tamper detected: {details.get('error')}")

        return jsonify({
            'is_valid': is_valid,
            'total_blocks': len(votes),
            'details': details
        }), 200

    @app.route('/admin/close', methods=['POST'])
    def admin_close():
        data = request.get_json(silent=True) or {}
        admin_secret = request.headers.get('X-Admin-Secret') or data.get('admin_secret')

        if admin_secret != app.config['ADMIN_SECRET_KEY']:
            return jsonify({'error': 'Unauthorized: Invalid admin secret'}), 403

        election_state['is_open'] = False

        # Gather final tally & complete hash chain
        votes = Vote.query.order_by(Vote.id.asc()).all()
        is_valid, chain_details = HashChainLedger.verify_chain(votes)

        candidates = Candidate.query.all()
        tally = [
            {'candidate_id': c.id, 'name': c.name, 'party': c.party, 'votes': Vote.query.filter_by(candidate_id=c.id).count()}
            for c in candidates
        ]

        results_data = {
            'election_status': 'CLOSED',
            'closed_at': datetime.now(timezone.utc).isoformat(),
            'total_votes': len(votes),
            'results': tally,
            'chain_verified': is_valid
        }

        chain_data = [v.to_dict() for v in votes]

        # Save artifacts locally
        exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
        os.makedirs(exports_dir, exist_ok=True)
        results_path = os.path.join(exports_dir, 'results.json')
        chain_path = os.path.join(exports_dir, 'chain.json')

        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        with open(chain_path, 'w') as f:
            json.dump(chain_data, f, indent=2)

        s3_status = 'Local export complete (AWS S3 upload ready for production)'

        # Production S3 upload if AWS is available
        if app.config.get('USE_PARAMETER_STORE') or os.environ.get('AWS_ACCESS_KEY_ID') or os.path.exists(os.path.expanduser('~/.aws/credentials')):
            try:
                import boto3
                s3 = boto3.client('s3', region_name=app.config.get('AWS_REGION', 'ap-south-1'))
                bucket = app.config.get('S3_BUCKET_NAME')
                s3.upload_file(results_path, bucket, 'results.json')
                s3.upload_file(chain_path, bucket, 'chain.json')
                s3_status = f"Successfully uploaded results.json and chain.json to s3://{bucket}"
            except Exception as e:
                s3_status = f"S3 upload error: {str(e)}"

        log_audit('ELECTION_CLOSED', "Election closed by administrator.")

        return jsonify({
            'message': 'Election closed successfully',
            'results_summary': results_data,
            's3_status': s3_status
        }), 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
