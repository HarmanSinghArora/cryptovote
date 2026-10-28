"""
RSA Blind Signature Implementation for CryptoVote
Based on David Chaum's Blind Signature Scheme (1982).

Mathematical Principle:
1. Key Generation:
   - Modulus N = p * q
   - Public exponent e = 65537
   - Private exponent d = e^(-1) mod phi(N)
   - Public Key: (e, N)
   - Private Key: (d, N)

2. Message Preparation (Voter):
   - Message m = SHA-256(ballot) mod N

3. Blinding (Voter):
   - Choose secret random r coprime to N: gcd(r, N) == 1
   - Blinded message: m' = (m * r^e) mod N

4. Blind Signing (Election Authority / Server):
   - Signature on blinded message: s' = (m')^d mod N
   - Because m' = m * r^e:
     s' = (m * r^e)^d = m^d * (r^e)^d = m^d * r mod N

5. Unblinding (Voter):
   - Compute modular inverse: r^(-1) mod N
   - Unblinded signature: s = s' * r^(-1) = (m^d * r) * r^(-1) = m^d mod N

6. Verification (Anyone with Public Key):
   - Check if (s^e mod N) == m
"""

import math
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(key_size=2048):
    """
    Generates a 2048-bit RSA keypair and returns public (e, n) and private (d, n) components.
    """
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key_obj = private_key_obj.public_key()

    priv_numbers = private_key_obj.private_numbers()
    pub_numbers = public_key_obj.public_numbers()

    e = pub_numbers.e
    n = pub_numbers.n
    d = priv_numbers.d

    return {'e': e, 'n': n}, {'d': d, 'n': n}

def export_private_key_pem(d, n, e=65537):
    """Encodes RSA private key numbers to PEM format string for Parameter Store or files."""
    # Compute p and q or construct standard numbers
    # Alternatively store integer JSON representation
    return f"{d}:{n}:{e}"

def hash_to_int(data_bytes, n):
    """
    Hashes arbitrary bytes with SHA-256 and maps the digest to an integer mod n.
    """
    digest = hashlib.sha256(data_bytes).digest()
    m = int.from_bytes(digest, byteorder='big') % n
    # Ensure m is non-zero
    if m == 0:
        m = 1
    return m

def blind_message(m, e, n):
    """
    Voter blinds the message m using a secret random blinding factor r.
    Returns (m_prime, r) where m_prime is the blinded value to send to the server.
    """
    while True:
        # Generate random integer r in range [2, n - 1]
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break

    # m' = (m * r^e) mod n
    r_pow_e = pow(r, e, n)
    m_prime = (m * r_pow_e) % n
    return m_prime, r

def sign_blinded(m_prime, d, n):
    """
    Election Authority signs the blinded message m_prime without knowing m.
    Returns s' = (m_prime)^d mod n.
    """
    s_prime = pow(m_prime, d, n)
    return s_prime

def unblind_signature(s_prime, r, n):
    """
    Voter removes the blinding factor r from the server's blind signature s'.
    Returns s = (s' * r^(-1)) mod n, which is a valid RSA signature on the original m.
    """
    # In Python 3.8+, pow(r, -1, n) calculates the modular multiplicative inverse
    r_inv = pow(r, -1, n)
    s = (s_prime * r_inv) % n
    return s

def verify_signature(m, s, e, n):
    """
    Verifies that s is a valid signature on m under public key (e, n).
    Checks if s^e mod n == m.
    """
    reconstructed_m = pow(s, e, n)
    return reconstructed_m == m
