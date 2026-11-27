import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, '..', 'vathur.html'), 'utf8');
const code = html.split('// <CRYPTO>')[1].split('// </CRYPTO>')[0];
const api = new Function('crypto','TextEncoder','TextDecoder','btoa','atob', code + `
return {newIdentity,loadSigner,fingerprint,vaultCreate,vaultOpen,makeRoom,seal,open,parseInvite,newSecret,ed25519Supported,b64,unb64,EPOCH,sealFile,openFile,sniffImage,parseImgCtl,fileUrlOk,MAX_IMG_BYTES};`)
  (globalThis.crypto, TextEncoder, TextDecoder, btoa, atob);
const {newIdentity,loadSigner,vaultCreate,vaultOpen,makeRoom,seal,open,parseInvite,newSecret,ed25519Supported,b64,unb64,EPOCH,sealFile,openFile,sniffImage,parseImgCtl,fileUrlOk,MAX_IMG_BYTES}=api;

let pass=0, fail=0;
const ok=(c,n)=>{ c?pass++:fail++; console.log((c?'PASS ':'FAIL ')+n); };
const rejects=async(f,n)=>{ try{await f(); ok(false,n);}catch{ok(true,n);} };
const mk=async name=>{const id=await newIdentity();return{name,pub:id.pub,signer:await loadSigner(id)}};

ok(await ed25519Supported(),'Ed25519 available');
const secret=newSecret(); const room=await makeRoom(secret); const room2=await makeRoom(secret);
const alice=await mk('alice'), mallory=await mk('mallory');
const now=Date.now();

// roundtrip
const w=await seal(room,'hello wörld ✓',alice,now);
const r=await open(room2,w,now);
ok(r.text==='hello wörld ✓'&&r.user==='alice','roundtrip across independent room instances');
// no plaintext / no username in wire format
ok(!w.includes('alice')&&!w.includes('hello'),'wire format leaks no plaintext or username');
// nonces unique
const w2=await seal(room,'hello wörld ✓',alice,now);
ok(JSON.parse(w).n!==JSON.parse(w2).n&&JSON.parse(w).c!==JSON.parse(w2).c,'fresh nonce each message');
// length padding
const a=JSON.parse(await seal(room,'a',alice,now)).c, b=JSON.parse(await seal(room,'bbbbbbbbbb',alice,now)).c;
ok(a.length===b.length,'short messages padded to same length');
// wrong room
const other=await makeRoom(newSecret());
await rejects(()=>open(other,w,now),'wrong room secret rejected');
ok(other.topic!==room.topic,'different secret -> different topic');
// cross-room replay: same secret can't be the issue, but topic is in AAD/signature
// tamper each field
for (const f of ['c','n','e','p','s']) {
  const m=JSON.parse(w);
  if(f==='e')m.e+=1; else if(f==='p')m.p=mallory.pub; else { const u=unb64(m[f]); u[0]^=1; m[f]=b64(u); }
  await rejects(()=>open(room,JSON.stringify(m),now),`tampered field "${f}" rejected`);
}
// impersonation: mallory swaps in her key but keeps alice's sig/ct
{ const m=JSON.parse(w); m.p=mallory.pub; await rejects(()=>open(room,JSON.stringify(m),now),'key-swap impersonation rejected'); }
// mallory signs validly but can't forge ciphertext without room key
{ const wr=await makeRoom(newSecret()); const f=await seal(wr,'fake',mallory,now); await rejects(()=>open(room,f,now),'valid signature but wrong room key rejected'); }
// stale / future
await rejects(()=>open(room,w,now+EPOCH*500),'stale message rejected');
await rejects(()=>open(room,w,now-EPOCH*500),'far-future epoch rejected');
{ const fut=await seal(room,'x',alice,now+10*60000); await rejects(()=>open(room,fut,now),'message from the future rejected'); }
// rotation: different epochs use different keys, both decrypt
const old=await seal(room,'old',alice,now-EPOCH*3);
ok((await open(room,old,now)).text==='old','message from earlier epoch still opens within window');
ok(JSON.parse(old).e!==JSON.parse(w).e,'epoch rotates');
// oversize
await rejects(()=>seal(room,'x'.repeat(2000),alice,now),'oversize message refused');
// garbage
for (const g of ['','null','{}','[]','{"v":1}','not json']) await rejects(()=>open(room,g,now),'garbage rejected: '+JSON.stringify(g));
// invite parsing
ok(parseInvite('VATHUR1:'+secret)===secret,'invite parse (code)');
ok(parseInvite('https://x.io/vathur.html#join='+secret)===secret,'invite parse (link)');
ok(parseInvite('nope')===null,'invite parse rejects junk');
await rejects(()=>makeRoom('AAAA'),'short room secret rejected');
// vault
const id=await newIdentity(); const vault={name:'a',id,rooms:[{name:'r',secret}]};
const {ctx,blob}=await vaultCreate(vault,'correct horse battery');
ok(!JSON.stringify(blob).includes(id.priv.d),'vault blob does not contain private key');
const o=await vaultOpen(JSON.parse(JSON.stringify(blob)),'correct horse battery');
ok(o.vault.rooms[0].secret===secret&&o.vault.id.pub===id.pub,'vault roundtrip');
await rejects(()=>vaultOpen(blob,'wrong passphrase!!'),'wrong passphrase rejected');
{ const t={...blob}; const u=unb64(t.c); u[5]^=1; t.c=b64(u); await rejects(()=>vaultOpen(t,'correct horse battery'),'tampered vault rejected'); }
await rejects(()=>vaultOpen({...blob,i:1},'correct horse battery'),'weak iteration count in blob rejected');

// ---- images ----
{
  const jpeg = new Uint8Array(3000).map((_, i) => i % 251); jpeg.set([0xFF,0xD8,0xFF,0xE0],0);
  const id = 'AAAAAAAAAAAA';
  const { blob, key } = await sealFile(room, jpeg, id);
  ok(blob.length === jpeg.length + 28, 'file blob = nonce + ciphertext + tag');
  const back = await openFile(room2, blob, key, id, jpeg.length);
  ok(back.length === jpeg.length && back.every((b, i) => b === jpeg[i]), 'file roundtrip (independent room instance)');
  ok(!blob.slice(12).every((b, i) => b === jpeg[i]), 'file ciphertext differs from plaintext');
  await rejects(() => openFile(room, blob, key, 'BBBBBBBBBBBB', jpeg.length), 'file bound to its id (swap rejected)');
  await rejects(() => openFile(other, blob, key, id, jpeg.length), 'file bound to its room');
  { const t = blob.slice(); t[40] ^= 1; await rejects(() => openFile(room, t, key, id, jpeg.length), 'tampered file rejected'); }
  await rejects(() => openFile(room, blob, key, id, jpeg.length - 1), 'announced size must match exactly');
  await rejects(() => openFile(room, blob, b64(new Uint8Array(32)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''), id, jpeg.length), 'wrong file key rejected');
  ok(sniffImage(jpeg) === 'image/jpeg', 'sniff jpeg');
  ok(sniffImage(new Uint8Array([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0,0,0,0,0,0])) === 'image/png', 'sniff png');
  ok(sniffImage(new TextEncoder().encode('RIFF....WEBPVP8 ')) === 'image/webp', 'sniff webp');
  ok(sniffImage(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>')) === null, 'SVG/HTML never accepted as image');
  ok(sniffImage(new Uint8Array(5)) === null, 'tiny/garbage not an image');
  const good = { k: 'img', id, sz: 3000, url: 'https://ntfy.sh/file/abc123.bin', key, exp: Date.now() };
  ok(parseImgCtl(good) !== null, 'valid img control accepted');
  ok(parseImgCtl({ ...good, id: 'short' }) === null, 'bad id rejected');
  ok(parseImgCtl({ ...good, sz: MAX_IMG_BYTES + 1 }) === null, 'oversized claim rejected');
  ok(parseImgCtl({ ...good, key: 'x' }) === null, 'bad key length rejected');
  ok(parseImgCtl({ ...good, k: 'evil' }) === null, 'unknown control kind rejected');
  ok(parseImgCtl({ k: 'img0', id, sz: 10 }) !== null && parseImgCtl({ k: 'imgx', id }) !== null, 'img0/imgx accepted');
  ok(fileUrlOk('https://ntfy.sh/file/abc123.bin', 'https://ntfy.sh'), 'file url on own relay ok');
  ok(!fileUrlOk('https://evil.example/file/abc.bin', 'https://ntfy.sh'), 'foreign host rejected');
  ok(!fileUrlOk('https://ntfy.sh/file/../../x', 'https://ntfy.sh'), 'path tricks rejected');
  ok(!fileUrlOk('https://ntfy.sh.evil.com/file/a.bin', 'https://ntfy.sh'), 'lookalike host rejected');
  ok(!fileUrlOk('https://ntfy.sh/file/a.bin?x=1', 'https://ntfy.sh'), 'query string rejected');
  // control messages ride inside normal sealed messages
  const alice2 = await mk('alice');
  const w3 = await seal(room, '', alice2, now, { k: 'img0', id, sz: 3000 });
  const o3 = await open(room2, w3, now);
  ok(o3.x && o3.x.k === 'img0' && o3.x.sz === 3000 && !w3.includes('img0'), 'control message roundtrips and is not visible on the wire');
  ok((await open(room2, w, now)).x === null, 'plain text messages carry no control data');
}
console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail?1:0);
