# CryptoVote: Cryptography Specification & Security Report
**Project:** CryptoVote – Secure Online Voting System  
**Author:** Person B (Application Backend, Database & Cryptography Lead)  
**Academic Course:** Cloud Computing Lab Mini Project  
**Date:** October 2026  

---

## 1. Executive Summary

Online voting systems face an apparent paradox: **the system must authenticate voters to prevent duplicate or unauthorized voting, yet must remain cryptographically blind to the voter's choice to preserve voter privacy.** Furthermore, the system must guarantee that results cannot be modified by any party—including rogue database administrators or privileged cloud users.

CryptoVote resolves this trilemma through a triad of cryptographic primitives:
1. **David Chaum's RSA Blind Signatures (1982)** to decouple voter identity from ballot content.
2. **Cryptographic SHA-256 Hash Chaining (Blockchain Ledger)** to provide tamper-evident append-only ballot storage.
3. **PBKDF2-HMAC-SHA256 Password Derivation** with per-user 128-bit salts to secure voter authentication against credential-stuffing and GPU attacks.

---

## 2. David Chaum RSA Blind Signature Scheme

### 2.1 The Privacy Paradox in Digital Elections
In standard digital signature schemes (e.g., standard RSA or ECDSA), the signer views the cleartext message before computing the signature. If applied directly to voting, the server would observe:
$$\text{Server Record} = (\text{Voter ID}, \text{Candidate Choice})$$
This violates voter privacy and enables coercion and vote selling.

David Chaum introduced **Blind Signatures** in 1982, drawing an analogy to placing a ballot and carbon paper inside a sealed envelope. The election authority signs the outside of the envelope, transferring the signature onto the ballot through the carbon paper. When the voter opens the envelope, they possess an authentic signature from the authority, but the authority never saw the ballot choice.

---

### 2.2 Mathematical Formulation & Protocol Flow

Let $(e, N)$ be the Election Authority's public key, and $(d, N)$ be the private signing key, where:
$$N = p \cdot q \quad (p, q \text{ are large 1024-bit primes, } |N| = 2048 \text{ bits})$$
$$e \cdot d \equiv 1 \pmod{\phi(N)}$$
$$\gcd(e, \phi(N)) = 1, \quad e = 65537$$

```
   Voter Client                                              Election Authority (Flask Server)
  ==============                                            ===================================
        |                                                                    |
 1. Generate Ballot:                                                         |
    choice = 1                                                               |
    nonce  = random_256_bit()                                                |
    token  = random_256_bit()                                                |
    m = int(SHA256(choice || nonce || token))                                |
        |                                                                    |
 2. Blinding Step:                                                           |
    Select random r in [2, N-1], gcd(r, N) == 1                              |
    m' = (m * r^e) mod N                                                     |
        |                                                                    |
        | ----- POST /blind-sign {blinded_message: m'} (Bearer Token) -----> |
        |                                                                    |
        |                                                       3. Verify Voter Authenticity:
        |                                                          - Voter has logged in? (PBKDF2)
        |                                                          - has_requested_ballot == False?
        |                                                          - Mark has_requested_ballot = True
        |                                                                    |
        |                                                       4. Sign Blinded Message:
        |                                                          s' = (m')^d mod N
        |                                                          (Server signs without viewing m!)
        |                                                                    |
        | <------------- Response {blind_signature: s'} -------------------- |
        |                                                                    |
 5. Unblinding Step:                                                         |
    Compute r_inv = r^(-1) mod N via Extended Euclidean                     |
    s = (s' * r_inv) mod N                                                   |
        |                                                                    |
 6. Anonymous Ballot Casting:                                                |
    (Zero voter identity headers, no session tokens)                         |
        |                                                                    |
        | ----- POST /vote {candidate_id, nonce, token, signature: s} -----> |
        |                                                                    |
        |                                                       7. Independent Verification:
        |                                                          - Check token not in used_tokens
        |                                                          - Recompute m = SHA256(...)
        |                                                          - Verify: s^e mod N == m
        |                                                          - Insert token into used_tokens
        |                                                          - Append vote to Hash Chain
```

---

### 2.3 Mathematical Proof of Correctness

We must prove that the unblinded signature $s$ satisfies the standard RSA signature verification equation:
$$s^e \equiv m \pmod N$$

**Proof:**
1. The server computes the blind signature:
   $$s' \equiv (m')^d \pmod N$$
2. Substitute the blinding equation $m' \equiv m \cdot r^e \pmod N$:
   $$s' \equiv (m \cdot r^e)^d \equiv m^d \cdot (r^e)^d \pmod N$$
3. By Euler's Totient Theorem, $(r^e)^d \equiv r^{ed} \equiv r^1 \equiv r \pmod N$:
   $$s' \equiv m^d \cdot r \pmod N$$
4. The client unblinds by multiplying with the modular inverse $r^{-1} \pmod N$:
   $$s \equiv s' \cdot r^{-1} \equiv (m^d \cdot r) \cdot r^{-1} \equiv m^d \cdot (r \cdot r^{-1}) \equiv m^d \cdot 1 \equiv m^d \pmod N$$
5. During vote casting, any validator verifies the ballot using public key $(e, N)$:
   $$s^e \equiv (m^d)^e \equiv m^{ed} \equiv m \pmod N$$

$\blacksquare$ **Q.E.D.**  
The resulting signature $s = m^d \pmod N$ is a perfectly valid RSA digital signature over message $m$, identical to what the server would have produced had it seen $m$ directly. However, the server only ever observed $m'$, from which computing $m$ is computationally intractable without knowing the secret blinding factor $r$.

---

### 2.4 Prevention of Double Voting (Anonymous Token Commitments)

If voter identity is scrubbed from the cast ballot, what stops a voter from submitting $s$ multiple times?

1. Each ballot message includes a high-entropy anonymous token $T \in \{0, 1\}^{256}$.
2. When `POST /vote` is called, the database performs an atomic lookup and insertion into the `used_tokens` table:
   ```sql
   INSERT INTO used_tokens (token_hash) VALUES (SHA256(token));
   ```
3. The `token_hash` column is defined with a `UNIQUE` constraint. If a voter attempts to cast the ballot a second time, the database raises an integrity violation (`IntegrityError`), and the server immediately aborts with:
   $$\text{HTTP } 409 \text{ Conflict: Ballot token has already been spent.}$$

---

## 3. SHA-256 Hash Chain Ledger (Tamper-Evident Storage)

### 3.1 Design Principles
Traditional relational databases allow arbitrary `UPDATE` and `DELETE` operations. An adversary with database root access or an insider could alter vote tallies unnoticed. CryptoVote implements an append-only **Hash Chain Ledger** where each vote block is mathematically bound to its predecessor.

### 3.2 Block Structure & Serialization Format
Each block $B_i$ in the `votes` table contains:
- $i$: Monotonically increasing Block Index ($1, 2, 3, \dots$).
- $C_i$: Candidate ID voted for.
- $t_i$: ISO-8601 UTC timestamp ($\text{YYYY-MM-DDTHH:MM:SSZ}$).
- $H_{i-1}$: Previous Block Hash (32-byte hex string).
- $H_i$: Current Entry Hash (32-byte hex string).

$$\text{For the Genesis Block } (i = 1): \quad H_0 = 0^{64} = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$

$$\text{For all subsequent blocks } (i \ge 1): \quad H_i = \text{SHA-256}(i \parallel C_i \parallel t_i \parallel H_{i-1})$$

The payload is strictly normalized before hashing to guarantee cross-platform deterministic serialization:
```python
payload = f"{block_index}:{candidate_id}:{timestamp_str}:{previous_hash}"
entry_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
```

### 3.3 Tamper Detection Proof
Suppose an attacker attempts to alter candidate choice $C_k$ in block $k$ to $C'_k$ ($C'_k \ne C_k$):
1. The recalculated hash for block $k$ becomes:
   $$H'_k = \text{SHA-256}(k \parallel C'_k \parallel t_k \parallel H_{k-1})$$
2. Due to the **avalanche effect** and **pre-image resistance** of SHA-256:
   $$H'_k \ne H_k \quad \text{with probability } 1 - 2^{-256} \approx 1$$
3. When `GET /admin/verify-chain` executes, it computes $H'_k$ and compares it to stored $H_k$:
   $$\text{Stored } H_k \ne \text{Computed } H'_k \implies \text{Tamper Detected in Block } k!$$
4. Even if the attacker attempts to update stored $H_k \leftarrow H'_k$, the subsequent block $k+1$ contains $H_k$ as its $H_{prev}$:
   $$H_{k+1} = \text{SHA-256}(k+1 \parallel C_{k+1} \parallel t_{k+1} \parallel H_k) \ne \text{SHA-256}(k+1 \parallel C_{k+1} \parallel t_{k+1} \parallel H'_k)$$
   The chain breaks at block $k+1$.
5. To successfully forge a single vote, an attacker would have to recompute the entire chain up to the latest block $N$, an impossible feat if hashes are audited or anchored to external storage (such as Amazon S3 audit logs).

---

## 4. Password Security: PBKDF2-HMAC-SHA256

Voter credentials must be protected against database breaches and offline dictionary attacks.

### 4.1 Specification
- **Algorithm:** Password-Based Key Derivation Function 2 (PBKDF2) defined in RFC 8018 / PKCS #5 v2.1.
- **Pseudorandom Function (PRF):** HMAC-SHA256.
- **Iteration Count ($c$):** $100,000$ iterations.
- **Salt ($S$):** $16$ bytes ($128$ bits) of cryptographically secure pseudorandomness generated via Python's `secrets.token_bytes(16)`.
- **Derived Key Length ($dkLen$):** $32$ bytes ($256$ bits).

$$\text{Derived Key} = \text{PBKDF2}(\text{HMAC-SHA256}, \text{Password}, \text{Salt}, 100000, 32)$$

### 4.2 Security Properties
1. **Rainbow Table Invalidation:** Because every voter is assigned a unique 128-bit salt, precomputed lookup tables (rainbow tables) are rendered completely useless.
2. **GPU / ASIC Attack Throttling:** 100,000 rounds of HMAC-SHA256 introduce a computational delay of $\approx 80\text{ ms}$ per verification on modern CPUs. This negligible delay is imperceptible to legitimate users during login, but multiplies brute-force search time by $100,000 \times$, rendering dictionary attacks computationally infeasible.
3. **Timing-Attack Resistance:** Password verification is executed using `hmac.compare_digest()`, guaranteeing constant-time comparison regardless of how many initial characters match.

---

## 5. Security Threat Matrix & Countermeasures

| Threat / Attack Vector | Severity | Vulnerability in Standard Voting | CryptoVote Countermeasure |
|---|---|---|---|
| **Voter Coercion / Vote Selling** | Critical | Server knows who voted for whom. | **RSA Blind Signatures:** Choice $m$ is blinded by $r^e$ before server signs. Server never learns candidate choice. |
| **Double Voting** | Critical | Voter submits ballot multiple times. | **Used Tokens Table:** Anonymous token $T$ has a database `UNIQUE` constraint; second submission triggers HTTP 409. |
| **Ballot Forgery / Stuffing** | Critical | Attacker invents votes without credentials. | **Signature Verification:** Ballots without a valid RSA signature matching public key $(e, N)$ are rejected (HTTP 400). |
| **Database Tampering** | High | Rogue DB admin modifies stored votes. | **SHA-256 Hash Chain:** Every block links to predecessor. Tampering breaks the chain and triggers Amazon SNS alerts. |
| **Credential Stuffing** | High | Leaked passwords reused across accounts. | **PBKDF2-HMAC-SHA256:** 100,000 iterations + 16-byte random salt prevents dictionary attacks. |
| **Timing Attacks** | Medium | Comparing password hashes byte-by-byte leaks length. | **Constant-Time Comparison:** Evaluated using `hmac.compare_digest()`. |
| **Privileged Insider Misuse** | High | Cloud admin accesses raw secrets. | **AWS SSM Parameter Store:** DB passwords and secrets stored as encrypted `SecureString` types with IAM least-privilege policies. |
| **Election Audit Tampering** | Medium | Tampering with local tally files post-election. | **Amazon S3 Immutability:** Final election tally (`results.json`) and chain (`chain.json`) are uploaded directly to S3 upon closure. |

---

## 6. Conclusion
CryptoVote demonstrates that strong voter privacy, rigorous fraud prevention, and complete auditability can coexist in an online voting system through the disciplined application of established cryptographic protocols. By pairing David Chaum's blind RSA scheme with cryptographic hash chaining and AWS cloud security, the system satisfies all major academic and practical standards for digital democratic voting.
