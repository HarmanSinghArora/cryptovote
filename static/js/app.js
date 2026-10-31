/**
 * CrypticVote Frontend Logic & Client-Side Cryptography
 * Cyber Brutalism Implementation with native BigInt David Chaum Blind Signatures.
 */

// Application State
const state = {
    voterId: localStorage.getItem('voter_id') || null,
    sessionToken: localStorage.getItem('session_token') || null,
    hasRequestedBallot: localStorage.getItem('has_ballot') === 'true',
    authorityKey: null, // { e: BigInt, n: BigInt }
    candidates: [],
    lastReceiptHash: localStorage.getItem('last_receipt') || null
};

// Dynamic API Resolver: automatically forwards to live EC2 when loaded via file://
function apiUrl(path) {
    if (typeof window !== 'undefined' && (window.location.protocol === 'file:' || !window.location.host)) {
        return `http://15.206.173.159${path}`;
    }
    return path;
}

// ============================================================================
// 1. LIVE SYSTEM TIME CLOCK
// ============================================================================

function startSystemClock() {
    const timeEl = document.getElementById('live-sys-time');
    if (!timeEl) return;
    function update() {
        const now = new Date();
        const hours = String(now.getUTCHours()).padStart(2, '0');
        const minutes = String(now.getUTCMinutes()).padStart(2, '0');
        const seconds = String(now.getUTCSeconds()).padStart(2, '0');
        timeEl.textContent = `${hours}:${minutes}:${seconds}`;
    }
    update();
    setInterval(update, 1000);
}

// ============================================================================
// ============================================================================
// 2. CRYPTOGRAPHIC UTILITIES (UNIVERSAL CLIENT SHA-256 & DAVID CHAUM RSA)
// ============================================================================

function sha256_pure_js(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length';
    var i, j;
    var result = '';
    var words = [];
    var asciiBitLength = ascii[lengthProperty] * 8;
    
    var hash = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    var k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    ascii += '\x80';
    while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
    words[words[lengthProperty]] = (asciiBitLength | 0);

    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16);
        var oldHash = hash;
        hash = hash.slice(0, 8);

        for (i = 0; i < 64; i++) {
            var i2 = i + j;
            var w15 = w[i - 15], w2 = w[i - 2];

            var a = hash[0], e = hash[4];
            var temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                + ((e & hash[5]) ^ ((~e) & hash[6]))
                + k[i]
                + (w[i] = (i < 16) ? w[i] : (
                        w[i - 16]
                        + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
                        + w[i - 7]
                        + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                    ) | 0
                );
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));

            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
        }

        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            var b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
}

function getRandomBytes(length) {
    const arr = new Uint8Array(length);
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
        try {
            window.crypto.getRandomValues(arr);
            return arr;
        } catch (e) {
            // fallback below
        }
    }
    for (let i = 0; i < length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
}

function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
}

function extendedGcd(a, b) {
    if (a === 0n) return [b, 0n, 1n];
    const [gcd, x1, y1] = extendedGcd(b % a, a);
    const x = y1 - (b / a) * x1;
    const y = x1;
    return [gcd, x, y];
}

function modInverse(a, m) {
    const [gcd, x] = extendedGcd(a, m);
    if (gcd !== 1n) throw new Error("Modular inverse does not exist");
    return ((x % m) + m) % m;
}

async function sha256ToInt(str, modN) {
    let hex;
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(str);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) {
            hex = sha256_pure_js(str);
        }
    } else {
        hex = sha256_pure_js(str);
    }
    return BigInt('0x' + hex) % modN;
}

function getRandomBigInt(bytes = 32) {
    const arr = getRandomBytes(bytes);
    let hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    return BigInt('0x' + hex);
}

// 3. UI NAVIGATION & NOTIFICATION HELPERS
// ============================================================================

function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));

    const targetSec = document.getElementById(sectionId);
    if (targetSec) targetSec.classList.add('active');

    const targetNav = document.getElementById(`nav-${sectionId}`);
    if (targetNav) targetNav.classList.add('active');

    if (sectionId === 'candidates' || sectionId === 'voting') loadCandidates();
    if (sectionId === 'results') loadResults();

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showAlert(elementId, message, type = 'danger') {
    const alertBox = document.getElementById(elementId);
    if (!alertBox) return;
    alertBox.className = `alert alert-${type}`;
    alertBox.innerHTML = `<strong>[ ${type.toUpperCase()} ]</strong> ${message}`;
    alertBox.style.display = 'block';
    setTimeout(() => {
        alertBox.style.display = 'none';
    }, 7000);
}

function updateSessionUI() {
    const sessionDiv = document.getElementById('user-session');
    if (!sessionDiv) return;

    if (state.voterId && state.sessionToken) {
        sessionDiv.innerHTML = `
            <span style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 800; color: var(--purple-main);">VOTER: ${state.voterId}</span>
            <button onclick="logout()" class="btn btn-black btn-sm">LOGOUT</button>
        `;
    } else {
        sessionDiv.innerHTML = `
            <button onclick="showSection('login')" class="btn btn-black btn-sm">AUTHENTICATE ↗</button>
        `;
    }
}

function logout() {
    state.voterId = null;
    state.sessionToken = null;
    state.hasRequestedBallot = false;
    localStorage.removeItem('voter_id');
    localStorage.removeItem('session_token');
    localStorage.removeItem('has_ballot');
    updateSessionUI();
    showSection('landing');
}

// ============================================================================
// 4. API CLIENT CALLS
// ============================================================================

async function fetchAuthorityPublicKey() {
    if (state.authorityKey) return state.authorityKey;
    try {
        const res = await fetch(apiUrl('/crypto/public-key'));
        const data = await res.json();
        state.authorityKey = {
            e: BigInt(data.e),
            n: BigInt(data.n)
        };
        return state.authorityKey;
    } catch (err) {
        console.error("Failed to load authority public key:", err);
        return null;
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const voterId = document.getElementById('reg-voter-id').value.trim();
    const password = document.getElementById('reg-password').value.trim();

    try {
        const res = await fetch(apiUrl('/register'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voter_id: voterId, password: password })
        });
        const data = await res.json();

        if (res.ok) {
            showAlert('reg-alert', `Voter account enrolled: ${voterId}. Please authenticate now.`, 'success');
            setTimeout(() => showSection('login'), 1200);
        } else {
            showAlert('reg-alert', data.error || 'Registration failed');
        }
    } catch (err) {
        showAlert('reg-alert', `Network error: ${err.message || 'Cannot connect to API server'}`); console.error('Register failed:', err);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const voterId = document.getElementById('login-voter-id').value.trim();
    const password = document.getElementById('login-password').value.trim();

    try {
        const res = await fetch(apiUrl('/login'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voter_id: voterId, password: password })
        });
        const data = await res.json();

        if (res.ok) {
            state.voterId = data.voter_id;
            state.sessionToken = data.token;
            state.hasRequestedBallot = data.has_requested_ballot;

            localStorage.setItem('voter_id', data.voter_id);
            localStorage.setItem('session_token', data.token);
            localStorage.setItem('has_ballot', data.has_requested_ballot);

            updateSessionUI();
            showAlert('login-alert', 'Authentication verified via PBKDF2! Redirecting to ballot console...', 'success');
            setTimeout(() => showSection('voting'), 1000);
        } else {
            showAlert('login-alert', data.error || 'Invalid credentials');
        }
    } catch (err) {
        showAlert('login-alert', `Network error: ${err.message || 'Cannot connect to API server'}`); console.error('Login failed:', err);
    }
}

async function loadCandidates() {
    try {
        const res = await fetch(apiUrl('/candidates'));
        const data = await res.json();
        state.candidates = data.candidates || [];

        // Render Candidates Display Page
        const listDiv = document.getElementById('candidates-list');
        if (listDiv) {
            listDiv.innerHTML = state.candidates.map(c => `
                <div class="candidate-brutalist-card">
                    <div class="candidate-media-box">
                        <span class="candidate-num-tag">[ CANDIDATE 0${c.id} ]</span>
                        <div class="candidate-avatar">
                        <svg width="52" height="52" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <rect x="12" y="12" width="40" height="40" stroke="#7c3aed" stroke-width="2"/>
                            <circle cx="32" cy="27" r="8" stroke="#ccff00" stroke-width="2"/>
                            <path d="M20 48C20 41 25 39 32 39C39 39 44 41 44 48" stroke="#ffffff" stroke-width="2" stroke-linecap="square"/>
                            <line x1="6" y1="32" x2="12" y2="32" stroke="#7c3aed" stroke-width="2"/>
                            <line x1="52" y1="32" x2="58" y2="32" stroke="#7c3aed" stroke-width="2"/>
                            <line x1="32" y1="6" x2="32" y2="12" stroke="#7c3aed" stroke-width="2"/>
                            <line x1="32" y1="52" x2="32" y2="58" stroke="#7c3aed" stroke-width="2"/>
                        </svg>
                    </div>
                    </div>
                    <div class="candidate-info-box">
                        <div>
                            <div class="candidate-name">${c.name}</div>
                            <div class="candidate-party">PARTY // ${c.party}</div>
                            <p class="candidate-bio">${c.bio || 'Official vetted candidate standing for the 2026 CrypticVote general election.'}</p>
                        </div>
                        <button onclick="selectAndVote(${c.id})" class="btn btn-purple" style="width: 100%;">
                            Vote for ${c.name} ↗
                        </button>
                    </div>
                </div>
            `).join('');
        }

        // Render Voting Radio Options
        const voteOptions = document.getElementById('vote-candidate-options');
        if (voteOptions) {
            voteOptions.innerHTML = state.candidates.map(c => `
                <div class="candidate-radio-item" onclick="document.getElementById('cand-${c.id}').checked = true">
                    <input type="radio" name="candidate_choice" id="cand-${c.id}" value="${c.id}">
                    <label for="cand-${c.id}">
                        ${c.name} <span style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--purple-main); font-weight: 800;">[ ${c.party} ]</span>
                    </label>
                </div>
            `).join('');
        }
    } catch (err) {
        console.error("Failed to load candidates:", err);
    }
}

function selectAndVote(candidateId) {
    showSection('voting');
    const radio = document.getElementById(`cand-${candidateId}`);
    if (radio) radio.checked = true;
}

// ============================================================================
// 5. CLIENT-SIDE DAVID CHAUM BLIND VOTING PIPELINE
// ============================================================================

async function executeAnonymousVote(e) {
    e.preventDefault();
    const alertId = 'vote-alert';

    if (!state.sessionToken) {
        showAlert(alertId, 'Authentication required! Please log in to request a ballot.');
        setTimeout(() => showSection('login'), 1200);
        return;
    }

    const selectedRadio = document.querySelector('input[name="candidate_choice"]:checked');
    if (!selectedRadio) {
        showAlert(alertId, 'Please select a candidate before submitting!');
        return;
    }

    const candidateId = parseInt(selectedRadio.value);
    const voteBtn = document.getElementById('btn-submit-vote');
    voteBtn.disabled = true;
    voteBtn.textContent = '>> [1/3] BLINDING BALLOT & PROOF GEN...';

    try {
        // Step 1: Fetch Authority RSA Public Key
        const pubKey = await fetchAuthorityPublicKey();
        if (!pubKey) throw new Error("Could not fetch election authority public key");

        // Step 2: Generate random anonymous token T and secret blinding factor r
        const tokenArr = getRandomBytes(16);
        const token = Array.from(tokenArr).map(b => b.toString(16).padStart(2, '0')).join('');

        const rawMessage = `candidate:${candidateId};token:${token}`;
        const m = await sha256ToInt(rawMessage, pubKey.n);

        // Blinding factor r coprime to N
        let r = getRandomBigInt(32) % pubKey.n;
        if (r < 2n) r = 2n;

        // m' = (m * r^e) mod N
        const r_pow_e = modPow(r, pubKey.e, pubKey.n);
        const m_prime = (m * r_pow_e) % pubKey.n;

        // Step 3: Call POST /blind-sign with m' (Identity Known, Ballot Choice HIDDEN)
        voteBtn.textContent = '>> [2/3] AUTHORITY BLIND SIGNATURE...';
        const signRes = await fetch(apiUrl('/blind-sign'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.sessionToken}`
            },
            body: JSON.stringify({ blinded_message: m_prime.toString() })
        });
        const signData = await signRes.json();

        if (!signRes.ok) {
            throw new Error(signData.error || "Failed to obtain blind signature");
        }

        const s_prime = BigInt(signData.blind_signature);

        // Step 4: Unblind signature locally: s = (s' * r^-1) mod N
        voteBtn.textContent = '>> [3/3] UNBLINDING & CASTING ON-CHAIN...';
        const r_inv = modInverse(r, pubKey.n);
        const s = (s_prime * r_inv) % pubKey.n;

        // Step 5: Cast vote anonymously (No session headers!)
        const voteRes = await fetch(apiUrl('/vote'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                candidate_id: candidateId,
                token: token,
                signature: s.toString()
            })
        });
        const voteData = await voteRes.json();

        if (!voteRes.ok) {
            throw new Error(voteData.error || "Vote rejected by blockchain ledger");
        }

        // Success!
        state.lastReceiptHash = voteData.receipt_hash;
        localStorage.setItem('last_receipt', voteData.receipt_hash);
        localStorage.setItem('has_ballot', 'true');
        state.hasRequestedBallot = true;

        showAlert(alertId, `Vote successfully anchored in ledger block #${voteData.block_index}!`, 'success');
        
        // Populate receipt section
        document.getElementById('receipt-hash-input').value = voteData.receipt_hash;
        setTimeout(() => {
            showSection('receipt');
            lookupReceipt(voteData.receipt_hash);
        }, 1500);

    } catch (err) {
        showAlert(alertId, err.message);
    } finally {
        voteBtn.disabled = false;
        voteBtn.textContent = 'Submit Cryptographic Ballot ↗';
    }
}

// ============================================================================
// 6. RECEIPT LOOKUP & VERIFICATION
// ============================================================================

async function handleReceiptLookup(e) {
    if (e) e.preventDefault();
    const hash = document.getElementById('receipt-hash-input').value.trim();
    if (!hash) return;
    lookupReceipt(hash);
}

async function lookupReceipt(hash) {
    const resultDiv = document.getElementById('receipt-result');
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<p style="font-family: var(--font-mono); font-weight: 700;">Querying SHA-256 blockchain ledger...</p>';

    try {
        const res = await fetch(apiUrl(`/receipt/${hash}`));
        const data = await res.json();

        if (res.ok && data.verified) {
            resultDiv.innerHTML = `
                <div class="cyber-panel" style="border-color: var(--success); background: #ffffff;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
                        <span class="btn btn-lime btn-sm" style="pointer-events: none;">VERIFIED ON-CHAIN</span>
                        <span style="font-family: var(--font-mono); font-weight: 800; color: var(--purple-main);">BLOCK #${data.block_index}</span>
                    </div>
                    <p style="font-family: var(--font-mono); font-size: 0.88rem;"><strong>CANDIDATE ID:</strong> Candidate #${data.candidate_id}</p>
                    <p style="font-family: var(--font-mono); font-size: 0.88rem;"><strong>UTC TIMESTAMP:</strong> ${data.timestamp}</p>
                    <p style="font-family: var(--font-mono); font-size: 0.8rem; margin-top: 0.5rem; color: var(--text-muted);"><strong>ENTRY RECEIPT HASH (SHA-256):</strong></p>
                    <div class="code-box">${data.receipt_hash}</div>
                    <p style="font-family: var(--font-mono); font-size: 0.8rem; margin-top: 0.5rem; color: var(--text-muted);"><strong>PREVIOUS BLOCK HASH:</strong></p>
                    <div class="code-box">${data.previous_hash}</div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="cyber-panel" style="border-color: var(--danger); background: var(--danger-light);">
                    <div style="font-family: var(--font-mono); font-weight: 800; color: var(--danger);">[ 404 NOT FOUND ] RECEIPT UNVERIFIED</div>
                    <p style="margin-top: 0.5rem; font-family: var(--font-mono); font-size: 0.85rem; color: #7f1d1d;">The receipt hash provided does not match any block in the SHA-256 blockchain ledger.</p>
                </div>
            `;
        }
    } catch (err) {
        resultDiv.innerHTML = `<p style="color: var(--danger); font-family: var(--font-mono);">Error querying receipt: ${err.message}</p>`;
    }
}

// ============================================================================
// 7. LIVE RESULTS & ELECTION STATUS
// ============================================================================

async function loadResults() {
    try {
        const res = await fetch(apiUrl('/results'));
        const data = await res.json();

        const badge = document.getElementById('results-status-badge');
        if (badge) {
            badge.className = `btn btn-sm ${data.election_status === 'OPEN' ? 'btn-lime' : 'btn-danger'}`;
            badge.textContent = `ELECTION ${data.election_status}`;
        }

        document.getElementById('results-total-votes').textContent = `${data.total_votes} Total Votes Cast`;

        const container = document.getElementById('results-bars');
        const total = data.total_votes || 0;

        container.innerHTML = data.results.map(c => {
            const pct = total > 0 ? ((c.votes / total) * 100).toFixed(1) : 0;
            return `
                <div style="margin-bottom: 1.5rem;">
                    <div style="display: flex; justify-content: space-between; font-family: var(--font-mono); font-weight: 800; font-size: 0.88rem; margin-bottom: 0.4rem;">
                        <span>${c.name} <span style="color: var(--purple-main);">[ ${c.party} ]</span></span>
                        <span>${c.votes} VOTES (${pct}%)</span>
                    </div>
                    <div style="height: 16px; background: #e2e1ec; border: 2px solid var(--border-color); position: relative;">
                        <div style="height: 100%; width: ${pct}%; background: var(--purple-main); transition: width 0.6s ease;"></div>
                    </div>
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error("Failed to load results:", err);
    }
}

// ============================================================================
// 8. ADMIN CONTROLS: CHAIN AUDIT & CLOSURE
// ============================================================================

async function adminVerifyChain() {
    const out = document.getElementById('admin-chain-output');
    out.style.display = 'block';
    out.innerHTML = '<p style="font-family: var(--font-mono); font-weight: 700;">Recalculating SHA-256 hashes from Genesis block (0^64)...</p>';

    try {
        const res = await fetch(apiUrl('/admin/verify-chain'));
        const data = await res.json();

        if (data.is_valid) {
            out.innerHTML = `
                <div class="cyber-panel" style="border-color: var(--success); background: #ffffff;">
                    <div style="color: var(--success); font-family: var(--font-mono); font-weight: 800; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="square"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>SHA-256 HASH CHAIN INTEGRITY CONFIRMED // ALL BLOCKS LINKED</span>
                    </div>
                    <p style="font-family: var(--font-mono); font-size: 0.88rem;">All ${data.total_blocks} vote blocks are cryptographically verified back to Genesis.</p>
                    <p style="color: var(--text-muted); font-family: var(--font-mono); font-size: 0.82rem; margin-top: 0.5rem;">${data.details.message}</p>
                </div>
            `;
        } else {
            out.innerHTML = `
                <div class="cyber-panel" style="border-color: var(--danger); background: var(--danger-light);">
                    <div style="color: var(--danger); font-family: var(--font-mono); font-weight: 800; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="square"><polygon points="12 2 22 20 2 20 12 2"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        <span>TAMPER DETECTED: CRYPTOGRAPHIC LINK BROKEN!</span>
                    </div>
                    <p style="font-family: var(--font-mono); font-size: 0.88rem;">Discrepancy identified at ledger block index #${data.details.block_index}.</p>
                    <p style="color: var(--danger); font-family: var(--font-mono); font-weight: 700;">${data.details.error}</p>
                    <div class="code-box">Expected Hash: ${data.details.expected_entry_hash}\nStored Hash:   ${data.details.found_entry_hash}</div>
                    <p style="color: var(--purple-main); font-family: var(--font-mono); font-size: 0.82rem; font-weight: 800;">Automated alert published to Amazon SNS!</p>
                </div>
            `;
        }
    } catch (err) {
        out.innerHTML = `<p style="color: var(--danger); font-family: var(--font-mono);">Verification error: ${err.message}</p>`;
    }
}

async function adminCloseElection() {
    const secret = document.getElementById('admin-secret-input').value.trim();
    if (!secret) {
        showAlert('admin-alert', 'Please enter the administrative secret key!');
        return;
    }

    if (!confirm("Are you sure you want to CLOSE the election? This locks all voting and uploads audit archives to S3.")) {
        return;
    }

    try {
        const res = await fetch(apiUrl('/admin/close'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-Secret': secret
            },
            body: JSON.stringify({ admin_secret: secret })
        });
        const data = await res.json();

        if (res.ok) {
            showAlert('admin-alert', `Election officially CLOSED! ${data.s3_status}`, 'success');
            loadResults();
        } else {
            showAlert('admin-alert', data.error || 'Failed to close election');
        }
    } catch (err) {
        showAlert('admin-alert', `Network error: ${err.message}`);
    }
}

// Initial Boot
document.addEventListener('DOMContentLoaded', () => {
    startSystemClock();
    updateSessionUI();
    fetchAuthorityPublicKey();
    if (state.lastReceiptHash) {
        const input = document.getElementById('receipt-hash-input');
        if (input) input.value = state.lastReceiptHash;
    }
});

