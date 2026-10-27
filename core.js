// Secret word translator: core logic (runs in the browser and in Node for testing).
// A passphrase deterministically shuffles the English word list, so every
// English word maps to exactly one other English word (and back again).
const SecretWords = (function () {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  // Pure-JS SHA-256 so the page works from file:// and plain http too.
  function sha256(msg) {
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const l = msg.length;
    const padLen = ((l + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 4, (l * 8) >>> 0);
    dv.setUint32(padLen - 8, Math.floor((l * 8) / 4294967296));
    const w = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i] >>> 0);
    return out;
  }

  // Passphrase -> 128-bit seed. Repeated hashing makes guessing passphrases slower.
  function deriveSeed(pass) {
    let h = sha256(new TextEncoder().encode("secret-words-v1:" + pass));
    for (let i = 0; i < 5000; i++) h = sha256(h);
    const dv = new DataView(h.buffer, h.byteOffset);
    return [dv.getUint32(0), dv.getUint32(4), dv.getUint32(8), dv.getUint32(12)];
  }

  function sfc32(a, b, c, d) {
    const next = function () {
      a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
      let t = (a + b) | 0;
      a = b ^ (b >>> 9);
      b = (c + (c << 3)) | 0;
      c = (c << 21) | (c >>> 11);
      d = (d + 1) | 0;
      t = (t + d) | 0;
      c = (c + t) | 0;
      return (t >>> 0) / 4294967296;
    };
    for (let i = 0; i < 15; i++) next();
    return next;
  }

  // Build the two lookup tables for a passphrase.
  function buildMaps(words, pass) {
    const rand = sfc32.apply(null, deriveSeed(pass));
    const shuf = words.slice();
    for (let i = shuf.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      const tmp = shuf[i]; shuf[i] = shuf[j]; shuf[j] = tmp;
    }
    const enc = new Map();
    const dec = new Map();
    for (let i = 0; i < words.length; i++) {
      enc.set(words[i], shuf[i]);
      dec.set(shuf[i], words[i]);
    }
    return { enc: enc, dec: dec };
  }

  function applyCase(src, out) {
    if (src.length > 1 && src === src.toUpperCase()) return out.toUpperCase();
    if (src[0] === src[0].toUpperCase()) return out.charAt(0).toUpperCase() + out.slice(1);
    return out;
  }

  // Swap every dictionary word using the map; everything else is left alone.
  function translate(text, map) {
    return text.replace(/[A-Za-z]+/g, function (tok) {
      const hit = map.get(tok.toLowerCase());
      return hit === undefined ? tok : applyCase(tok, hit);
    });
  }

  // One-way fingerprint of a passkey, used to check it without storing it in the page.
  function verifier(pass) {
    let h = sha256(new TextEncoder().encode("gate-v1:" + pass));
    for (let i = 0; i < 5000; i++) h = sha256(h);
    return Array.from(h, function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  return { sha256: sha256, buildMaps: buildMaps, translate: translate, verifier: verifier };
})();

if (typeof module !== "undefined") module.exports = SecretWords;
