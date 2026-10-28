-- =====================================================================
-- CryptoVote: Secure Online Voting System
-- Database Schema for Amazon RDS MySQL (and compatible with SQLite)
-- Author: Person B (Backend & Database Engineer)
-- =====================================================================

-- 1. CANDIDATES TABLE
-- Stores election candidate profiles.
CREATE TABLE IF NOT EXISTS candidates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    party VARCHAR(100) NOT NULL,
    bio TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. VOTERS TABLE
-- Tracks voter identity, authentication credentials, and ballot eligibility.
-- IMPORTANT: This table NEVER records how someone voted.
CREATE TABLE IF NOT EXISTS voters (
    id INT AUTO_INCREMENT PRIMARY KEY,
    voter_id VARCHAR(64) UNIQUE NOT NULL,       -- Unique student/voter registration ID
    password_hash VARCHAR(256) NOT NULL,        -- Salted PBKDF2-HMAC-SHA256 hash
    salt VARCHAR(64) NOT NULL,                  -- Unique 16-byte cryptographically secure random salt (hex)
    has_requested_ballot BOOLEAN DEFAULT FALSE, -- Flag: Set to TRUE once blind signature is issued
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. USED TOKENS TABLE
-- Enforces the "one-person-one-vote" rule without violating voter anonymity.
-- When a vote is cast anonymously, the SHA-256 hash of its token is stored here.
-- The UNIQUE constraint on token_hash causes MySQL to immediately reject duplicate attempts.
CREATE TABLE IF NOT EXISTS used_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token_hash VARCHAR(64) UNIQUE NOT NULL,     -- SHA-256 of the ballot token
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. VOTES TABLE (The Cryptographic Ledger / Blockchain-like Hash Chain)
-- Stores each cast vote, linked cryptographically to the previous vote.
-- Notice: There is NO voter_id foreign key! Anonymity is mathematically preserved.
CREATE TABLE IF NOT EXISTS votes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    candidate_id INT NOT NULL,                  -- Candidate receiving the vote
    token VARCHAR(128) NOT NULL,                -- Unique anonymous token generated during blinding
    signature TEXT NOT NULL,                    -- Unblinded RSA signature proving authority authorization
    previous_hash VARCHAR(64) NOT NULL,         -- SHA-256 hash of the immediately preceding vote row
    entry_hash VARCHAR(64) UNIQUE NOT NULL,     -- SHA-256 hash of this complete vote entry (Block Hash)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
);

-- 5. AUDIT LOG TABLE
-- Records system-level events for administrative auditing and CloudWatch log correlation.
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,            -- e.g., 'VOTER_REGISTER', 'BLIND_SIGN', 'VOTE_CAST', 'CHAIN_VERIFY', 'CLOSE_ELECTION'
    description TEXT NOT NULL,                  -- Human-readable details
    ip_address VARCHAR(45),                     -- IPv4 or IPv6 of the client
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================================
-- INITIAL SAMPLE DATA SEEDING
-- =====================================================================
INSERT INTO candidates (name, party, bio) VALUES
('Alice Green', 'Cyber Security Party', 'Advocate for digital privacy, transparent systems, and open-source infrastructure.'),
('Bob Stone', 'Cloud Computing Alliance', 'Focused on high availability, scalable services, and resilient architecture.'),
('Charlie Vance', 'Innovation Coalition', 'Championing cryptographic integrity, machine learning, and student welfare.');
