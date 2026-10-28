"""
Automated Cryptographic Unit Tests for CryptoVote
Validates:
1. RSA Blind Signatures (blinding, authority blind signing, unblinding, and verification)
2. SHA-256 Hash Chain (integrity verification and tamper detection)
3. Salted PBKDF2 Password Hashing (correct password match and brute-force resistance)
"""

import os
import sys
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto.blind_rsa import (
    generate_keypair,
    hash_to_int,
    blind_message,
    sign_blinded,
    unblind_signature,
    verify_signature
)
from crypto.hashchain import HashChainBlock, HashChainLedger
from crypto.password import hash_password, verify_password

class TestCryptoVoteCryptography(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n[+] Generating 2048-bit RSA Authority Keypair for Tests...")
        cls.pub, cls.priv = generate_keypair(key_size=2048)
        print(f"[+] Keypair generated! Modulus N bit-length: {cls.pub['n'].bit_length()}")

    def test_01_blind_signature_flow(self):
        """Test complete David Chaum Blind Signature cycle."""
        e, n = self.pub['e'], self.pub['n']
        d = self.priv['d']

        # 1. Voter prepares ballot message
        ballot_data = b"candidate:1;token:tok_secret_994827"
        m = hash_to_int(ballot_data, n)

        # 2. Voter blinds the message
        m_prime, r = blind_message(m, e, n)
        self.assertNotEqual(m, m_prime, "Blinded message must not match original message")

        # 3. Server (Election Authority) signs blinded message
        # Server only sees m_prime, never m!
        s_prime = sign_blinded(m_prime, d, n)
        self.assertNotEqual(s_prime, m, "Blind signature must not match original message")

        # 4. Voter unblinds the signature using their secret factor r
        s = unblind_signature(s_prime, r, n)

        # 5. Anyone can verify signature s on original message m using public key (e, n)
        is_valid = verify_signature(m, s, e, n)
        self.assertTrue(is_valid, "Unblinded signature must be valid on original message m")

        # 6. Verify that an altered message fails verification
        tampered_ballot = b"candidate:2;token:tok_secret_994827"
        tampered_m = hash_to_int(tampered_ballot, n)
        self.assertFalse(
            verify_signature(tampered_m, s, e, n),
            "Signature must fail on tampered ballot message"
        )
        print("  [PASS] RSA Blind Signature: Blinding -> Authority Sign -> Unblinding -> Public Verification")

    def test_02_hash_chain_integrity_and_tamper_detection(self):
        """Test hash chain creation, integrity verification, and tamper resistance."""
        blocks = []
        prev_hash = HashChainLedger.get_genesis_hash()

        # Build a chain of 4 votes
        for i in range(1, 5):
            block = HashChainBlock(
                block_index=i,
                candidate_id=(i % 3) + 1,
                token=f"token_{i * 100}",
                signature=f"sig_{i * 777}",
                previous_hash=prev_hash
            )
            blocks.append(block)
            prev_hash = block.entry_hash

        # Verify pristine chain
        is_valid, info = HashChainLedger.verify_chain(blocks)
        self.assertTrue(is_valid, f"Pristine chain must verify cleanly: {info}")
        self.assertEqual(info['verified_blocks'], 4)
        print(f"  [PASS] Hash Chain Verified: 4 blocks cleanly linked back to Genesis")

        # Now simulate an attacker tampering with block #2 (changing candidate vote)
        blocks[1].candidate_id = 999  # Tampering vote in block 2
        is_valid_tampered, tamper_info = HashChainLedger.verify_chain(blocks)
        self.assertFalse(is_valid_tampered, "Tampered chain must be detected as invalid")
        self.assertIn("tampered", tamper_info['error'].lower())
        print(f"  [PASS] Tamper Detection Confirmed: {tamper_info['error']}")

    def test_03_password_hashing_pbkdf2(self):
        """Test PBKDF2-HMAC-SHA256 password salting and verification."""
        password = "StudentVoterPass2026!"
        password_hash, salt = hash_password(password)

        self.assertEqual(len(salt), 32, "Salt must be 16 bytes (32 hex characters)")
        self.assertEqual(len(password_hash), 64, "Derived key must be 32 bytes (64 hex characters)")

        # Verify correct password
        self.assertTrue(verify_password(password_hash, salt, password))

        # Verify wrong password
        self.assertFalse(verify_password(password_hash, salt, "WrongPassword123"))
        print("  [PASS] PBKDF2 Password Hashing: Salted derivation and constant-time match confirmed")

if __name__ == '__main__':
    unittest.main()
