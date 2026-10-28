"""
Hash Chain Implementation for CryptoVote
Provides a blockchain-inspired immutable ledger where every vote block
contains the cryptographic SHA-256 hash of the previous vote block.
"""

import hashlib
import json
from datetime import datetime, timezone

GENESIS_PREV_HASH = "0" * 64

class HashChainBlock:
    def __init__(self, block_index, candidate_id, token, signature, previous_hash, timestamp=None, entry_hash=None):
        self.block_index = block_index
        self.candidate_id = candidate_id
        self.token = token
        self.signature = str(signature)
        self.previous_hash = previous_hash
        self.timestamp = timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.entry_hash = entry_hash or self.calculate_hash()

    def calculate_hash(self):
        """
        Calculates SHA-256 using the unified compute_vote_hash method.
        """
        return HashChainLedger.compute_vote_hash(
            self.block_index,
            self.candidate_id,
            self.token,
            self.signature,
            self.previous_hash,
            self.timestamp
        )

    def to_dict(self):
        return {
            'block_index': self.block_index,
            'timestamp': self.timestamp,
            'candidate_id': self.candidate_id,
            'token': self.token,
            'signature': self.signature,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash
        }


class HashChainLedger:
    @staticmethod
    def get_genesis_hash():
        return GENESIS_PREV_HASH

    @staticmethod
    def compute_vote_hash(block_index, candidate_id, token, signature, previous_hash, timestamp_str):
        """Utility function to calculate a vote's entry hash with consistent timestamp serialization."""
        if hasattr(timestamp_str, 'strftime'):
            ts_clean = timestamp_str.strftime('%Y-%m-%dT%H:%M:%SZ')
        elif isinstance(timestamp_str, str):
            ts_clean = timestamp_str.replace('+00:00', 'Z')
        else:
            ts_clean = str(timestamp_str)
        payload = f"{block_index}|{ts_clean}|{candidate_id}|{token}|{str(signature)}|{previous_hash}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_chain(blocks):
        """
        Verifies the integrity of the entire hash chain.
        Ensures:
        1. Each block's entry_hash matches its recalculation.
        2. Each block's previous_hash matches the previous block's entry_hash.
        Returns: (is_valid: bool, details: dict)
        """
        if not blocks:
            return True, {"message": "Chain is empty.", "verified_blocks": 0}

        for i, block in enumerate(blocks):
            block_idx = getattr(block, 'block_index', getattr(block, 'id', i + 1))
            # Verify linkage to previous block
            if i == 0:
                # First block must point to genesis previous hash
                if block.previous_hash != GENESIS_PREV_HASH:
                    return False, {
                        "error": "Genesis block previous_hash is invalid.",
                        "block_index": block_idx,
                        "expected": GENESIS_PREV_HASH,
                        "found": block.previous_hash
                    }
            else:
                prev_block = blocks[i - 1]
                prev_idx = getattr(prev_block, 'block_index', getattr(prev_block, 'id', i))
                if block.previous_hash != prev_block.entry_hash:
                    return False, {
                        "error": f"Chain broken between block {prev_idx} and block {block_idx}.",
                        "block_index": block_idx,
                        "expected_prev_hash": prev_block.entry_hash,
                        "found_prev_hash": block.previous_hash
                    }

            # Verify block self-integrity
            recalculated_hash = HashChainLedger.compute_vote_hash(
                block_idx,
                block.candidate_id,
                block.token,
                block.signature,
                block.previous_hash,
                block.timestamp if isinstance(block.timestamp, str) else block.timestamp.isoformat()
            )

            if block.entry_hash != recalculated_hash:
                return False, {
                    "error": f"Block {block_idx} data has been tampered with!",
                    "block_index": block_idx,
                    "expected_entry_hash": recalculated_hash,
                    "found_entry_hash": block.entry_hash
                }

        return True, {
            "message": "Complete hash chain successfully verified. All cryptographic links are intact.",
            "verified_blocks": len(blocks)
        }
