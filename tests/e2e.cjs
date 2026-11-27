// End-to-end browser test with a mocked ntfy relay (needs: npm i playwright).
// Usage: node tests/e2e.cjs
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');
const os = require('os');

const FILE = 'file://' + path.join(__dirname, '..', 'vathur.html');
let pass = 0, fail = 0;
const ok = (c, n) => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + n); };

(async () => {
  const b = await chromium.launch();
  const errs = [];
  const log = [];                       // [topicPath, eventJson]
  const files = new Map();              // id -> Buffer
  const evilHits = [];
  const state = { tamper: false, putDelay: 5000 };
  const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': '*' };

  const relay = async route => {
    const req = route.request(); const url = new URL(req.url());
    if (url.hostname === 'evil.example') { evilHits.push(req.url()); return route.fulfill({ status: 200, body: 'x', headers: CORS }); }
    if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: CORS });
    if (url.pathname.startsWith('/file/')) {
      let buf = files.get(url.pathname.slice(6).split('.')[0]);
      if (!buf) return route.fulfill({ status: 404, body: 'gone', headers: CORS });
      if (state.tamper) { buf = Buffer.from(buf); buf[buf.length - 3] ^= 1; }
      return route.fulfill({ status: 200, body: buf, headers: { ...CORS, 'content-type': 'application/octet-stream' } });
    }
    const topic = url.pathname.replace(/\/sse$/, '');
    if (req.method() === 'POST') {
      log.push([topic, JSON.stringify({ event: 'message', message: req.postData() })]);
      return route.fulfill({ status: 200, body: '{}', headers: CORS });
    }
    if (req.method() === 'PUT') {
      const buf = req.postDataBuffer();
      await new Promise(r => setTimeout(r, state.putDelay));          // slow upload
      const id = Math.random().toString(36).slice(2, 14);
      files.set(id, buf);
      const attachment = { name: 'v.bin', type: 'application/octet-stream', size: buf.length, expires: Math.floor(Date.now() / 1000) + 3 * 3600, url: 'https://ntfy.sh/file/' + id + '.bin' };
      log.push([topic, JSON.stringify({ event: 'message', message: 'You received a file: v.bin', attachment })]);
      return route.fulfill({ status: 200, body: JSON.stringify({ event: 'message', attachment }), headers: CORS });
    }
    const body = log.filter(l => l[0] === topic).map(l => 'data: ' + l[1] + '\n\n').join('');
    route.fulfill({ status: 200, body, headers: { ...CORS, 'content-type': 'text/event-stream' } });
  };
  const newCtx = async () => { const c = await b.newContext({ acceptDownloads: true }); await c.route(/^https:\/\/(ntfy\.sh|evil\.example)\//, relay); return c; };
  const newPage = async (ctx, name) => {
    const p = await ctx.newPage();
    p.on('pageerror', e => errs.push(name + ': ' + e.message));
    p.on('console', m => m.type() === 'error' && !/Failed to load resource/.test(m.text()) && errs.push(name + ' console: ' + m.text()));
    await p.goto(FILE); return p;
  };
  const signup = async (p, name, pw) => {
    await p.fill('input[placeholder^="callsign"]', name);
    await p.fill('input[placeholder="passphrase"]', pw);
    await p.fill('input[placeholder="repeat passphrase"]', pw);
    await p.click('text=Create vault'); await p.waitForSelector('#app');
  };
  const join = async (p, code) => {
    await p.click('footer >> text=Join'); await p.fill('input[placeholder^="room name"]', 'r');
    await p.fill('input[placeholder^="invite"]', code); await p.click('button.primary:has-text("Join")');
    await p.waitForSelector('#title:has-text("r")');
  };
  const text = (p, sel) => p.locator(sel).first().textContent();

  const A = await newPage(await newCtx(), 'A'); await signup(A, 'ghost', 'correct horse battery');
  await A.click('text=New room'); await A.fill('input[placeholder^="room name"]', 'r'); await A.click('button:has-text("Create")');
  await A.waitForSelector('.fp'); const code = await text(A, '.fp');
  await A.evaluate(() => document.querySelectorAll('.ov').forEach(o => o.remove()));
  const B = await newPage(await newCtx(), 'B'); await signup(B, 'wraith', 'another long passphrase'); await join(B, code);

  // a big noisy test image
  const dataUrl = await A.evaluate(() => {
    const c = document.createElement('canvas'); c.width = 2400; c.height = 1800; const g = c.getContext('2d');
    for (let i = 0; i < 4000; i++) { g.fillStyle = `hsl(${Math.random() * 360},70%,50%)`; g.fillRect(Math.random() * 2400, Math.random() * 1800, 60, 60); }
    return c.toDataURL('image/png');
  });
  const png = path.join(os.tmpdir(), 'vathur-e2e.png');
  fs.writeFileSync(png, Buffer.from(dataUrl.split(',')[1], 'base64'));

  // ---- send ----
  await A.setInputFiles('#file', png);
  await B.waitForSelector('.m .note:has-text("is sending an image")', { timeout: 20000 });
  ok(true, 'receiver sees a "sending an image… please wait" notice while upload is in progress');
  ok(/KB|MB/.test(await text(B, '.m .note')), 'notice shows the announced size');
  ok(await B.locator('.m .bar').count() === 1, 'receiver sees a progress indicator');
  await B.waitForSelector('.m img.pic', { timeout: 30000 });
  ok(true, 'image arrives and renders for receiver');
  const warn = await text(B, '.m .warnbox');
  ok(/deleted within 3 hours/.test(warn) && /Download/.test(warn), 'warning: deleted after 3 hours or less, download to keep');
  ok(/\d+h \d+m|\d+ min/.test(await text(B, '.m [data-exp]')), 'live countdown shown');
  const [dl] = await Promise.all([B.waitForEvent('download'), B.click('.m button.mini:has-text("Download")')]);
  const saved = fs.readFileSync(await dl.path());
  ok(saved[0] === 0xFF && saved[1] === 0xD8 && saved[2] === 0xFF, 'downloaded file is a real JPEG');
  ok(saved.length < 2 * 1024 * 1024 && saved.length > 5000, 'image was compressed (' + Math.round(saved.length / 1024) + ' KB from ' + Math.round(fs.statSync(png).size / 1024) + ' KB PNG)');
  ok(/\.jpg$/.test(dl.suggestedFilename()), 'download has a sensible filename: ' + dl.suggestedFilename());
  const stored = [...files.values()][0];
  ok(!(stored[12] === 0xFF && stored[13] === 0xD8) && stored.length === saved.length + 28, 'relay only ever held ciphertext');
  ok(!log.some(l => /ghost|FFD8|JFIF/.test(l[1])), 'relay log leaks no username or image markers');
  await A.waitForSelector('.m img.pic', { timeout: 30000 });
  ok(await A.locator('.m .warnbox').count() === 1, 'sender also sees the warning');

  // ---- malicious / broken control messages from a room member ----
  const inject = (p, x) => p.evaluate(async x => { await post(cur, await seal(cur, '', V.ident, Date.now(), x)); }, x);
  const KEY = 'A'.repeat(43);
  await inject(A, { k: 'img', id: 'EVILEVILEVIL', sz: 100, url: 'https://evil.example/file/x.bin', key: KEY, exp: Date.now() + 1e6 });
  await B.waitForSelector('.m .note.bad:has-text("Image not available")', { timeout: 15000 });
  ok(evilHits.length === 0, 'image URL on a foreign host is never fetched');
  await inject(A, { k: 'img', id: 'OLDOLDOLDOLD', sz: 100, url: 'https://ntfy.sh/file/zzz.bin', key: KEY, exp: Date.now() - 1000 });
  await B.waitForSelector('.m .note.bad:has-text("expired")', { timeout: 15000 });
  ok(true, 'already-expired image shows an "expired" notice without fetching');
  await inject(A, { k: 'img0', id: 'CANCELCANCEL', sz: 5000 });
  await B.waitForSelector('.m .note:has-text("is sending an image")', { timeout: 15000 });
  await inject(A, { k: 'imgx', id: 'CANCELCANCEL' });
  await B.waitForSelector('.m .note.bad:has-text("cancelled")', { timeout: 15000 });
  ok(true, 'cancelled upload resolves from "sending" to a clear failure');
  await inject(A, { k: 'bogus', id: 'BOGUSBOGUSBO' });
  await inject(A, { k: 'img', id: 'short' });
  await B.waitForTimeout(4000);
  const nMsgs = await B.locator('.m').count();
  ok(nMsgs === 4, 'invalid control messages are dropped silently (4 image entries, got ' + nMsgs + ')');

  // ---- tampered file ----
  state.tamper = true;
  const C = await newPage(await newCtx(), 'C'); await signup(C, 'cipher', 'yet another passphrase'); await join(C, code);
  await C.waitForSelector('.m .note.bad:has-text("could not be verified")', { timeout: 20000 });
  ok(true, 'a modified file from the relay fails verification and is never displayed');
  ok(await C.locator('.m img.pic').count() === 0, 'tampered image is not rendered');
  state.tamper = false;

  // ---- relay expiry (404) ----
  files.clear();
  const D = await newPage(await newCtx(), 'D'); await signup(D, 'echo', 'a fourth long passphrase'); await join(D, code);
  await D.waitForSelector('.m .note.bad:has-text("expired")', { timeout: 20000 });
  ok(true, 'relay 404 (deleted after 3h) shows "expired"');

  ok(!errs.length, 'no page errors' + (errs.length ? ': ' + JSON.stringify(errs) : ''));
  await B.screenshot({ path: path.join(os.tmpdir(), 'vathur-e2e-B.png') });
  console.log(`\n${pass} passed, ${fail} failed`);
  await b.close(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
