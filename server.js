// Server Tugas + Supabase (PDF, Word, Excel).  Jalankan: npm install && node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

// ---- Muat file .env (tanpa dependensi tambahan) ----
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Za-z_]\w*)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (_) { /* .env tidak wajib jika memakai environment variable hosting */ }

const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // rahasia: hanya di server!
const BUCKET = 'dokumen-tugas';
const MAX_BYTES = 25 * 1024 * 1024;

if (!ADMIN_PASSWORD || !SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: isi ADMIN_PASSWORD, SUPABASE_URL, dan SUPABASE_SERVICE_ROLE_KEY di file .env');
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

const PUB = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
};
const DOC_MIME = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
};

// ---- Sesi admin (kadaluarsa 12 jam) & pembatas percobaan login ----
const SESSION_MS = 12 * 3600 * 1000;
const sessions = new Map();
const fails = new Map(); // ip -> {n, until}
setInterval(() => { const now = Date.now(); for (const [t, ts] of sessions) if (now - ts > SESSION_MS) sessions.delete(t); }, 600000).unref();

const authed = req => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const ts = sessions.get(t);
  if (!ts) return false;
  if (Date.now() - ts > SESSION_MS) { sessions.delete(t); return false; }
  return true;
};
const clientIp = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();

// ---- Helper ----
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };
const readBody = (req, limit) => new Promise((ok, no) => {
  const chunks = []; let n = 0, over = false;
  req.on('data', d => { n += d.length; if (over) return; if (n > limit) { over = true; chunks.length = 0; no(new Error('too big')); } else chunks.push(d); });
  req.on('end', () => { if (!over) ok(Buffer.concat(chunks)); });
  req.on('error', no);
});
const clean = m => ({ title: String(m.title || '').trim().slice(0, 120), description: String(m.desc || m.description || '').trim().slice(0, 400) });
const safeParse = (s, fallback = {}) => { try { return JSON.parse(s); } catch (_) { return fallback; } };
const header = (req, k, d) => { try { return decodeURIComponent(req.headers[k] || d); } catch (_) { return d; } };

// Validasi tipe file lewat ekstensi + "magic bytes"
const OLE = [0xD0, 0xCF, 0x11, 0xE0]; // format lama .doc / .xls
const checkDoc = (buf, filename) => {
  const ext = path.extname(filename).toLowerCase();
  if (!DOC_MIME[ext] || buf.length < 8) return null;
  if (ext === '.pdf') return buf.slice(0, 5).toString() === '%PDF-' ? ext : null;
  if (ext === '.docx' || ext === '.xlsx') return buf[0] === 0x50 && buf[1] === 0x4B ? ext : null; // ZIP "PK"
  return OLE.every((b, i) => buf[i] === b) ? ext : null; // .doc / .xls
};
const toDto = r => ({ id: r.id, title: r.title, desc: r.description, createdAt: r.created_at, fileName: r.file_name, fileType: r.file_type, fileSize: r.file_size });

http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x'), p = u.pathname;

    // ---------- Publik: daftar tugas ----------
    if (p === '/api/tugas' && req.method === 'GET') {
      const { data, error } = await supabase.from('tugas')
        .select('id,title,description,created_at,file_name,file_type,file_size')
        .order('created_at', { ascending: false });
      if (error) throw new Error(error.message);
      return json(res, 200, data.map(toDto));
    }

    // ---------- Login ----------
    if (p === '/api/login' && req.method === 'POST') {
      const ip = clientIp(req), f = fails.get(ip);
      if (f && f.n >= 5 && Date.now() < f.until) return json(res, 429, { error: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' });
      const { password } = safeParse((await readBody(req, 4096)).toString() || '{}');
      const a = crypto.createHash('sha256').update(String(password || '')).digest();
      const b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
      if (!crypto.timingSafeEqual(a, b)) {
        const n = (f && Date.now() < f.until ? f.n : 0) + 1;
        fails.set(ip, { n, until: Date.now() + 15 * 60000 });
        return json(res, 401, { error: 'Password salah' });
      }
      fails.delete(ip);
      const t = crypto.randomBytes(24).toString('hex'); sessions.set(t, Date.now());
      return json(res, 200, { token: t });
    }

    if (p === '/api/me') return json(res, 200, { admin: authed(req) });

    let m;
    // ---------- Publik: buka / unduh file (diteruskan lewat server, bucket tetap private) ----------
    if ((m = p.match(/^\/api\/file\/([\w-]+)$/)) && req.method === 'GET') {
      const { data: row } = await supabase.from('tugas').select('file_path,file_name,file_type').eq('id', m[1]).maybeSingle();
      if (!row) return json(res, 404, { error: 'Tidak ditemukan' });
      const { data: blob, error } = await supabase.storage.from(BUCKET).download(row.file_path);
      if (error || !blob) return json(res, 404, { error: 'File tidak ada di penyimpanan' });
      const buf = Buffer.from(await blob.arrayBuffer());
      const isPdf = row.file_type === 'pdf';
      res.writeHead(200, {
        'Content-Type': DOC_MIME['.' + row.file_type] || 'application/octet-stream',
        'Content-Length': buf.length,
        'Content-Disposition': `${isPdf ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(row.file_name)}`,
        'X-Content-Type-Options': 'nosniff'
      });
      return res.end(buf);
    }

    // ---------- Khusus admin ----------
    if (p.startsWith('/api/')) {
      if (!authed(req)) return json(res, 401, { error: 'Harus login' });
      const meta = () => clean(safeParse(header(req, 'x-meta', '%7B%7D')));
      const fname = () => header(req, 'x-filename', 'dokumen.pdf');

      // Upload baru
      if (p === '/api/tugas' && req.method === 'POST') {
        const mt = meta(), original = fname();
        const buf = await readBody(req, MAX_BYTES);
        if (!mt.title) return json(res, 400, { error: 'Judul wajib diisi' });
        const ext = checkDoc(buf, original);
        if (!ext) return json(res, 400, { error: 'Format file tidak didukung (gunakan PDF, Word, atau Excel yang valid)' });

        const id = 't' + Date.now() + crypto.randomBytes(2).toString('hex');
        const filePath = `${id}${ext}`;
        const up = await supabase.storage.from(BUCKET).upload(filePath, buf, { contentType: DOC_MIME[ext], upsert: false });
        if (up.error) throw new Error('Storage: ' + up.error.message);

        const ins = await supabase.from('tugas').insert({
          id, title: mt.title, description: mt.description,
          file_path: filePath, file_name: path.basename(original), file_type: ext.slice(1), file_size: buf.length
        });
        if (ins.error) {
          await supabase.storage.from(BUCKET).remove([filePath]); // rollback agar tidak ada file yatim
          throw new Error('Database: ' + ins.error.message);
        }
        return json(res, 201, { id });
      }

      if ((m = p.match(/^\/api\/tugas\/([\w-]+)$/))) {
        const id = m[1];
        const { data: existing } = await supabase.from('tugas').select('*').eq('id', id).maybeSingle();
        if (!existing) return json(res, 404, { error: 'Tidak ditemukan' });

        // Hapus
        if (req.method === 'DELETE') {
          const del = await supabase.from('tugas').delete().eq('id', id);
          if (del.error) throw new Error(del.error.message);
          await supabase.storage.from(BUCKET).remove([existing.file_path]);
          return json(res, 200, { ok: true });
        }

        // Edit (judul/deskripsi, dan opsional ganti file)
        if (req.method === 'PUT') {
          if ((req.headers['content-type'] || '').includes('json')) {
            const mt = clean(safeParse((await readBody(req, 8192)).toString()));
            if (!mt.title) return json(res, 400, { error: 'Judul wajib diisi' });
            const up = await supabase.from('tugas').update({ title: mt.title, description: mt.description }).eq('id', id);
            if (up.error) throw new Error(up.error.message);
            return json(res, 200, { ok: true });
          }
          const mt = meta(), original = fname();
          const buf = await readBody(req, MAX_BYTES);
          if (!mt.title) return json(res, 400, { error: 'Judul wajib diisi' });
          const ext = checkDoc(buf, original);
          if (!ext) return json(res, 400, { error: 'Format file tidak didukung' });

          // Unggah file baru DULU, baru hapus yang lama (supaya data lama tidak hilang jika gagal)
          const newPath = `${id}-${Date.now()}${ext}`;
          const up = await supabase.storage.from(BUCKET).upload(newPath, buf, { contentType: DOC_MIME[ext], upsert: false });
          if (up.error) throw new Error('Storage: ' + up.error.message);
          const upd = await supabase.from('tugas').update({
            title: mt.title, description: mt.description, file_path: newPath,
            file_name: path.basename(original), file_type: ext.slice(1), file_size: buf.length
          }).eq('id', id);
          if (upd.error) { await supabase.storage.from(BUCKET).remove([newPath]); throw new Error(upd.error.message); }
          await supabase.storage.from(BUCKET).remove([existing.file_path]);
          return json(res, 200, { ok: true });
        }
      }
      return json(res, 404, { error: 'Not found' });
    }

    // ---------- File statis ----------
    const rel = p === '/' ? '/index.html' : decodeURIComponent(p);
    const f = path.normalize(path.join(PUB, rel));
    if (!f.startsWith(PUB + path.sep) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end('404'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream' });
    fs.createReadStream(f).pipe(res);
  } catch (e) {
    const big = e.message === 'too big';
    if (!big) console.error(e);
    if (!res.headersSent) json(res, big ? 413 : 500, { error: big ? 'File terlalu besar (maks 25 MB)' : (e.message || 'Kesalahan server') });
  }
}).listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));
