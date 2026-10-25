const express = require('express');
const dns = require('node:dns').promises;
const net = require('node:net');
const path = require('node:path');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: '8kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  return p[0] === 0 || p[0] === 10 || p[0] === 127 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    p[0] >= 224;
}
function isPrivateIPv6(ip) {
  const s = ip.toLowerCase().split('%')[0];
  return s === '::' || s === '::1' || s.startsWith('fc') || s.startsWith('fd') ||
    /^fe[89ab]/.test(s) || s.startsWith('::ffff:127.') || s.startsWith('::ffff:10.') ||
    s.startsWith('::ffff:192.168.') || s.startsWith('::ffff:169.254.');
}
async function assertPublicHttpUrl(value) {
  let u;
  try { u = new URL(value); } catch { throw new Error('URL tidak valid.'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Hanya URL HTTP/HTTPS yang didukung.');
  if (u.username || u.password) throw new Error('URL dengan kredensial tidak diizinkan.');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) throw new Error('Host lokal tidak diizinkan.');
  if (net.isIP(host)) {
    if ((net.isIPv4(host) && isPrivateIPv4(host)) || (net.isIPv6(host) && isPrivateIPv6(host))) throw new Error('Alamat IP privat tidak diizinkan.');
  } else {
    let records;
    try { records = await dns.lookup(host, { all: true, verbatim: true }); }
    catch { throw new Error('Domain tidak dapat ditemukan.'); }
    if (!records.length || records.some(r => (net.isIPv4(r.address) && isPrivateIPv4(r.address)) || (net.isIPv6(r.address) && isPrivateIPv6(r.address)))) {
      throw new Error('Domain mengarah ke alamat jaringan privat dan ditolak.');
    }
  }
  return u;
}

app.post('/api/bypass', async (req, res) => {
  try {
    const raw = String(req.body?.url || '').trim();
    if (!raw || raw.length > 2048) return res.status(400).json({ error: 'Masukkan URL yang valid (maksimal 2048 karakter).' });
    let current = raw;
    const maxRedirects = 10;
    const timeoutMs = 8000;
    for (let i = 0; i <= maxRedirects; i++) {
      const u = await assertPublicHttpUrl(current);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response;
      try {
        response = await fetch(u, {
          method: 'GET', redirect: 'manual', signal: controller.signal,
          headers: { 'user-agent': 'KS-Bypass/1.0 (+ordinary redirect resolver)', 'accept': 'text/html,application/xhtml+xml,*/*;q=0.8' }
        });
      } catch (e) {
        if (e.name === 'AbortError') throw new Error('Waktu permintaan habis. Coba lagi.');
        throw new Error('Link tidak dapat diakses atau koneksi ditolak.');
      } finally { clearTimeout(timer); }
      const location = response.headers.get('location');
      if ([301, 302, 303, 307, 308].includes(response.status) && location) {
        if (i === maxRedirects) throw new Error('Terlalu banyak pengalihan URL.');
        current = new URL(location, u).toString();
        continue;
      }
      // We intentionally resolve ordinary HTTP redirects only; we do not execute scripts or defeat access controls.
      return res.json({ success: true, finalUrl: u.toString(), status: response.status,
        message: response.status >= 400 ? `Tujuan ditemukan, tetapi server merespons HTTP ${response.status}.` : 'Tujuan akhir berhasil ditemukan.' });
    }
    throw new Error('Pengalihan URL tidak dapat diselesaikan.');
  } catch (e) {
    res.status(400).json({ error: e.message || 'Terjadi kesalahan saat memproses URL.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, app: 'KS-Bypass' }));
app.listen(PORT, () => console.log(`KS-Bypass running on http://localhost:${PORT}`));
