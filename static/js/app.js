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
// 2. BIGINT CRYPTOGRAPHIC UTILITIES (DAVID CHAUM RSA BLIND SIGNATURES)
// ============================================================================

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
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    let hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return BigInt('0x' + hex) % modN;
}

function getRandomBigInt(bytes = 32) {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    let hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    return BigInt('0x' + hex);
}

// ============================================================================
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
        const res = await fetch('/crypto/public-key');
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
        const res = await fetch('/register', {
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
        showAlert('reg-alert', 'Network error connecting to API server');
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const voterId = document.getElementById('login-voter-id').value.trim();
    const password = document.getElementById('login-password').value.trim();

    try {
        const res = await fetch('/login', {
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
        showAlert('login-alert', 'Network error connecting to API server');
    }
}

async function loadCandidates() {
    try {
        const res = await fetch('/candidates');
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
        const tokenArr = new Uint8Array(16);
        crypto.getRandomValues(tokenArr);
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
        const signRes = await fetch('/blind-sign', {
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
        const voteRes = await fetch('/vote', {
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
        const res = await fetch(`/receipt/${hash}`);
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
        const res = await fetch('/results');
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
        const res = await fetch('/admin/verify-chain');
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
        const res = await fetch('/admin/close', {
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

