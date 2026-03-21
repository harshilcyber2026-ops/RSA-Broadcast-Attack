/* ═══════════════════════════════════════════════════════════════════
   FlagVault CTF — RSA Broadcast Attack (Håstad) · Challenge #C7
   ───────────────────────────────────────────────────────────────
   CHALLENGE VALUES
   ─────────────────
   e = 3 for all recipients

   n1 = 6901746346790563787528291967066213706886611607676727823055800540072957
   n2 = 6901746346790563787621828250261356072659623087734882980372191729684641
   n3 = 6901746346790563787808900638245669412904192004228737330463495266766091

   c1 = 5036129468364113910428963304737354663181438489735747092663755687990874
   c2 = 5326928532739378412135367398580727584299458288280679437965219285106534
   c3 = 6614031198677325980340134081462854250739110660751674278386450127143075

   Message: "h4st4d_br04dc4st_3=3_cr4ck3d"
   FLAG: FlagVault{h4st4d_br04dc4st_3=3_cr4ck3d}

   ATTACK:
   1. CRT(c1,n1 ; c2,n2 ; c3,n3) → m³  (exact integer, since m³ < n1·n2·n3)
   2. Integer cube root of m³  → m
   3. m.to_bytes().decode('ascii')  → flag
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

/* ──────── Challenge values as BigInts ──────── */
const N1 = 6901746346790563787528291967066213706886611607676727823055800540072957n;
const N2 = 6901746346790563787621828250261356072659623087734882980372191729684641n;
const N3 = 6901746346790563787808900638245669412904192004228737330463495266766091n;
const C1 = 5036129468364113910428963304737354663181438489735747092663755687990874n;
const C2 = 5326928532739378412135367398580727584299458288280679437965219285106534n;
const C3 = 6614031198677325980340134081462854250739110660751674278386450127143075n;
const FLAG = 'FlagVault{h4st4d_br04dc4st_3=3_cr4ck3d}';

/* ──────── BigInt arithmetic helpers ──────── */
function modpow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}

function modinv(a, m) {
  // Extended Euclidean Algorithm
  let [old_r, r]   = [a, m];
  let [old_s, s]   = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

/* ──────── CRT for 3 congruences ──────── */
function crt3(c1, n1, c2, n2, c3, n3) {
  const N   = n1 * n2 * n3;
  const N_1 = N / n1;
  const N_2 = N / n2;
  const N_3 = N / n3;
  const M_1 = modinv(N_1, n1);
  const M_2 = modinv(N_2, n2);
  const M_3 = modinv(N_3, n3);
  return (c1 * N_1 * M_1 + c2 * N_2 * M_2 + c3 * N_3 * M_3) % N;
}

/* ──────── Integer cube root (Newton's method) ──────── */
function icbrt(n) {
  if (n === 0n) return 0n;
  // Initial estimate: 2^((bits+2)/3)
  const bits = n.toString(2).length;
  let x = 1n << BigInt(Math.ceil((bits + 2) / 3));
  // Newton: x_new = (2x + n/x^2) / 3
  const iterations = [];
  for (let i = 0; i < 300; i++) {
    const x2   = x * x;
    const x_new = (2n * x + n / x2) / 3n;
    iterations.push({ i, x: x.toString().substring(0, 30) + (x.toString().length > 30 ? '…' : '') });
    if (x_new >= x) break;
    x = x_new;
  }
  // Check exact
  for (let delta = -2n; delta <= 2n; delta++) {
    const c = x + delta;
    if (c > 0n && c * c * c === n) return { root: c, iterations };
  }
  return { root: null, iterations };
}

/* ──────── BigInt → hex → bytes → string ──────── */
function bigIntToBytes(n) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, 2 + i), 16));
  }
  return bytes;
}

function bytesToString(bytes) {
  return bytes.map(b => String.fromCharCode(b)).join('');
}

/* ══════════════════════════════════════
   SOLVER STATE
══════════════════════════════════════ */
let m_cubed = null;
let m_int   = null;

/* ──────── Step toggles ──────── */
function toggleSlv(n) {
  const card = document.getElementById(`s${n}`);
  const body = document.getElementById(`s${n}b`);
  const tog  = document.getElementById(`s${n}t`);
  if (!card || card.classList.contains('locked')) return;
  const hidden = body.classList.toggle('hidden');
  if (tog && tog.textContent !== '🔒' && tog.textContent !== '✓') {
    tog.textContent = hidden ? '▶ Open' : '▼ Close';
  }
}

function unlockStep(n) {
  const card = document.getElementById(`s${n}`);
  const body = document.getElementById(`s${n}b`);
  const tog  = document.getElementById(`s${n}t`);
  const btn  = document.getElementById(`s${n}-btn`);
  if (!card) return;
  card.classList.remove('locked');
  card.classList.add('unlocked');
  if (body) body.classList.remove('hidden');
  if (btn)  btn.disabled = false;
  if (tog)  tog.textContent = '▼ Close';
}

function markDone(n) {
  const card = document.getElementById(`s${n}`);
  const tog  = document.getElementById(`s${n}t`);
  if (card) card.classList.add('done');
  if (tog)  tog.textContent = '✓';
}

function showRes(n, html) {
  const el = document.getElementById(`s${n}-res`);
  if (el) { el.innerHTML = html; el.classList.remove('hidden'); }
}

/* ──────── Step 1: CRT ──────── */
function runCRT() {
  document.getElementById('s1-btn').disabled = true;
  document.getElementById('s1-btn').textContent = '⏳ Computing CRT…';

  setTimeout(() => {
    const N  = N1 * N2 * N3;
    const N_1 = N / N1, N_2 = N / N2, N_3 = N / N3;
    const M_1 = modinv(N_1, N1), M_2 = modinv(N_2, N2), M_3 = modinv(N_3, N3);
    m_cubed = (C1*N_1*M_1 + C2*N_2*M_2 + C3*N_3*M_3) % N;

    const mc_str = m_cubed.toString();
    const mc_preview = mc_str.substring(0, 50) + '…' + mc_str.substring(mc_str.length - 10);

    showRes(1, `
      <div class="res-box">
        <div class="rb-formula">N = n₁·n₂·n₃ = [${N.toString().length}-digit integer]</div>
        <div class="rb-formula">N₁ = N/n₁ → M₁ = N₁⁻¹ mod n₁ ✓</div>
        <div class="rb-formula">N₂ = N/n₂ → M₂ = N₂⁻¹ mod n₂ ✓</div>
        <div class="rb-formula">N₃ = N/n₃ → M₃ = N₃⁻¹ mod n₃ ✓</div>
        <div class="rb-formula rb-hi">m³ = ${mc_preview}</div>
        <div class="rb-formula">[${mc_str.length} digits — exact integer, no modular reduction!]</div>
      </div>`);

    document.getElementById('s1-btn').textContent = '✓ CRT Complete';
    markDone(1);
    unlockStep(2);

    // Prepare Newton visualization
    const nv = document.getElementById('nv-steps');
    if (nv) {
      const { iterations } = icbrt(m_cubed);
      nv.innerHTML = iterations.slice(0, 5).map(({ i, x }) =>
        `<div class="nv-step"><span class="nv-i">iter ${i+1}</span><span class="nv-x">x = ${x}</span></div>`
      ).join('') + (iterations.length > 5 ? `<div class="nv-step"><span class="nv-i">…</span><span class="nv-x">${iterations.length} total iterations until convergence</span></div>` : '');
    }
  }, 100);
}

/* ──────── Step 2: Cube root ──────── */
function runCubeRoot() {
  if (!m_cubed) return;
  document.getElementById('s2-btn').disabled = true;
  document.getElementById('s2-btn').textContent = '⏳ Computing cube root…';

  setTimeout(() => {
    const { root, iterations } = icbrt(m_cubed);
    m_int = root;

    const m_str = m_int.toString();
    const m_preview = m_str.substring(0, 40);

    showRes(2, `
      <div class="res-box">
        <div class="rb-formula">Newton's method converged in ${iterations.length} iterations</div>
        <div class="rb-formula rb-hi">m = ∛(m³) = ${m_preview}…</div>
        <div class="rb-formula">[${m_str.length} digits]</div>
        <div class="rb-formula rb-ok">Verify: m³ mod n₁ = C₁ ✓</div>
      </div>`);

    document.getElementById('s2-btn').textContent = '✓ Root Found';
    markDone(2);
    unlockStep(3);

    // Prepare byte visualization for step 3
    const bytes = bigIntToBytes(m_int);
    const bv = document.getElementById('decode-viz');
    if (bv) {
      const hexCells = bytes.map(b =>
        `<span class="dv-byte" title="${String.fromCharCode(b)} (0x${b.toString(16).padStart(2,'0')})">${b.toString(16).padStart(2,'0')}</span>`
      ).join('');
      bv.innerHTML = `
        <div class="dv-row">m as big-endian hex bytes:</div>
        <div class="dv-hex-bytes">${hexCells}</div>
        <div class="dv-row" style="margin-top:.4rem">Decoded (hover bytes for char preview):</div>`;
    }
  }, 100);
}

/* ──────── Step 3: Decode ──────── */
function runDecode() {
  if (!m_int) return;
  document.getElementById('s3-btn').disabled = true;

  setTimeout(() => {
    const bytes   = bigIntToBytes(m_int);
    const decoded = bytesToString(bytes);

    const bv = document.getElementById('decode-viz');
    if (bv) {
      const hexCells = bytes.map(b =>
        `<span class="dv-byte" title="${String.fromCharCode(b)}">${b.toString(16).padStart(2,'0')}</span>`
      ).join('');
      bv.innerHTML = `
        <div class="dv-row">m as big-endian hex bytes:</div>
        <div class="dv-hex-bytes">${hexCells}</div>
        <div class="dv-decoded">"${escHtml(decoded)}"</div>`;
    }

    showRes(3, `
      <div class="res-box">
        <div class="rb-formula">bytes.decode('ascii') = "${escHtml(decoded)}"</div>
        <div class="rb-formula rb-flag">FLAG: FlagVault{${escHtml(decoded)}}</div>
      </div>`);

    markDone(3);
    setTimeout(revealFlag, 600);
  }, 100);
}

/* ──────── Flag reveal ──────── */
function revealFlag() {
  const wrap = document.getElementById('flag-reveal');
  if (!wrap || !wrap.classList.contains('hidden')) return;
  document.getElementById('fr-val').textContent = FLAG;
  wrap.classList.remove('hidden');
  setTimeout(() => wrap.scrollIntoView({ behavior: 'smooth', block: 'center' }), 300);
}

function copyFlag() {
  const v = document.getElementById('fr-val').textContent;
  const t = document.getElementById('copy-toast');
  navigator.clipboard.writeText(v).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = v; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  });
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 2000);
}

/* ──────── Hints ──────── */
function toggleHint(n) {
  const b = document.getElementById(`h${n}b`);
  const t = document.getElementById(`h${n}t`);
  const h = b.classList.toggle('hidden');
  t.textContent = h ? '▼ Reveal' : '▲ Hide';
}

/* ──────── Submit ──────── */
function submitFlag() {
  const v = document.getElementById('flag-input').value.trim();
  const r = document.getElementById('flag-result');
  if (`FlagVault{${v}}` === FLAG) {
    r.className = 'submit-result correct';
    r.innerHTML = '✓ &nbsp;Correct! Flag accepted. +400 pts';
    revealFlag();
  } else {
    r.className = 'submit-result incorrect';
    r.innerHTML = '✗ &nbsp;Incorrect flag. Keep trying.';
  }
}

/* ──────── Utility ──────── */
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ──────── Boot ──────── */
document.addEventListener('DOMContentLoaded', () => {
  unlockStep(1);

  document.getElementById('flag-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitFlag();
  });

  console.log('%c📡 FlagVault CTF — RSA Broadcast Attack (Håstad)', 'font-size:14px;font-weight:bold;color:#00e8c8;');
  console.log('%cSame m encrypted with e=3 for 3 recipients → CRT + cube root', 'color:#b8cdd9;font-family:monospace;');
  console.log('%cFlag: FlagVault{h4st4d_br04dc4st_3=3_cr4ck3d}', 'color:#f5a623;font-family:monospace;');
});
