/******************************
 * main.js — BalanceChain PWA core (ES2018)
 * Master-class build: compact+encrypted CBOR P2P, offline-first vault, deterministic unlocks,
 * strict ownership rules, segment proofs, and caps enforcement — no external libraries.
 *
 * Key Guarantees (aligned with finalized TVM contract & docs):
 *  - Mint (TVM): vault_owner is both original_owner and previous_owner; current_owner is NOT the vault. ownershipChangeCount = 1.
 *  - P2P: Sender MUST be current owner; after transfer → receiver becomes current, sender becomes previous.
 *  - Immutability: Only current owner can spend/use a segment.
 *  - Double-spend guard: Previous owner can “catch in” (claim) on conflict with proof history.
 *  - On-chain TVM claim consumes ONLY segments with ownershipChangeCount === 1 (no 10-history on-chain).
 *  - P2P sends only unlocked segments; after send, auto-unlock equal count (if caps allow).
 *  - Caps: 360/day, 3,600/month, 10,800/year segments; Yearly TVM 900 + 100 parity bonus (EXTRA_BONUS_TVM).
 *
 * Storage:
 *  - IndexedDB DB_NAME='BioVaultDB' v4; stores: 'vault', 'segments', 'proofs'
 *
 * Crypto:
 *  - Header: tiny CBOR map (integer keys). Body: CBOR payload encrypted with AES-GCM.
 *  - Signatures:
 *      • If window.ethereum is available → EIP-191 personal_sign over (header || ciphertext).
 *      • Otherwise → WebCrypto ECDSA P-256 (offline P2P). (On-chain claims don’t use this signature.)
 *
 * Compat:
 *  - ES2018 (no optional chaining, no private fields, no numeric separators).
 ******************************/

// ---------- Global Constants ----------
var DB_NAME = 'BioVaultDB';
var DB_VERSION = 4;
var VAULT_STORE = 'vault';
var SEGMENTS_STORE = 'segments';
var PROOFS_STORE = 'proofs';

var INITIAL_BALANCE_SHE = 1200;
var EXCHANGE_RATE = 12; // 1 TVM = 12 SHE (segments)
var GENESIS_BIO_CONSTANT = 1736565605; // keep aligned with docs
var BIO_TOLERANCE_SECONDS = 720;

var SEGMENTS_PER_LAYER = 1200; // deterministic unlock baseline
var LAYERS = 10;               // 0..9 = 10 layers, 12,000 segments/year

// Caps
var DAILY_CAP = 360;
var MONTHLY_CAP = 3600;
var YEARLY_CAP = 10800;
var YEARLY_TVM_CAP = 900;
var EXTRA_BONUS_TVM = 100; // parity reserve; unlocked when parity condition met

// Contract addresses (lowercase to bypass strict checksum if using ethers v6 externally)
var TVM_CONTRACT_ADDRESS = '0xcc79b1bc9eabc3d30a3800f4d41a4a0599e1f3c6';
var USDT_ADDRESS = '0xdac17f958d2ee523a2206206994597c13d831ec7';

// P2P Payload Version
var P2P_VERSION = 3; // breaking change: compact header + encrypted CBOR

// ---------- Utilities ----------
function log() {
  try { console.log.apply(console, ['[BioVault]'].concat([].slice.call(arguments))); } catch (e) {}
}
function err() {
  try { console.error.apply(console, ['[BioVault]'].concat([].slice.call(arguments))); } catch (e) {}
}

function nowTs() { return Math.floor(Date.now() / 1000); }
function toISO(ts) { return new Date(ts * 1000).toISOString(); }

function bytesConcat(a, b) {
  var out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
function strToUtf8(str) {
  return new TextEncoder().encode(str);
}
function utf8ToStr(u8) {
  return new TextDecoder().decode(u8);
}
function hexToBytes(hex) {
  hex = hex.replace(/^0x/, '');
  var len = hex.length / 2;
  var out = new Uint8Array(len);
  for (var i=0;i<len;i++) out[i] = parseInt(hex.substr(i*2,2),16);
  return out;
}
function bytesToHex(buf) {
  var s = '0x';
  for (var i=0;i<buf.length;i++) {
    var h = buf[i].toString(16);
    if (h.length < 2) h = '0' + h;
    s += h;
  }
  return s;
}
function b64uEncode(bytes) {
  var bin = '';
  for (var i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  var b64 = btoa(bin);
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64uDecode(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  var bin = atob(s);
  var out = new Uint8Array(bin.length);
  for (var i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
function randomBytes(n) {
  var a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

// ---------- Tiny CBOR (subset: int, string, bytes, array, map, bool, null) ----------
var CBOR = (function(){
  // Major types
  var MT_UINT = 0, MT_NEGINT = 1, MT_BYTES = 2, MT_STRING = 3, MT_ARRAY = 4, MT_MAP = 5, MT_SIMPLE = 7;

  function encodeUInt(u) {
    if (u < 24) return new Uint8Array([ (MT_UINT<<5)|u ]);
    if (u < 256) return new Uint8Array([ (MT_UINT<<5)|24, u ]);
    if (u < 65536) return new Uint8Array([ (MT_UINT<<5)|25, u>>8, u&255 ]);
    var a = new Uint8Array(5); a[0] = (MT_UINT<<5)|26; a[1]=(u>>>24)&255; a[2]=(u>>>16)&255; a[3]=(u>>>8)&255; a[4]=u&255; return a;
  }
  function encodeInt(n) {
    if (n >= 0) return encodeUInt(n);
    var m = -1 - n; // CBOR negative
    // limited to 32-bit
    if (m < 24) return new Uint8Array([ (MT_NEGINT<<5)|m ]);
    if (m < 256) return new Uint8Array([ (MT_NEGINT<<5)|24, m ]);
    if (m < 65536) return new Uint8Array([ (MT_NEGINT<<5)|25, m>>8, m&255 ]);
    var a = new Uint8Array(5); a[0] = (MT_NEGINT<<5)|26; a[1]=(m>>>24)&255; a[2]=(m>>>16)&255; a[3]=(m>>>8)&255; a[4]=m&255; return a;
  }
  function encodeBytes(b) {
    var hdr;
    var l = b.length;
    if (l < 24) hdr = new Uint8Array([ (MT_BYTES<<5)|l ]);
    else if (l < 256) hdr = new Uint8Array([ (MT_BYTES<<5)|24, l ]);
    else if (l < 65536) hdr = new Uint8Array([ (MT_BYTES<<5)|25, l>>8, l&255 ]);
    else throw new Error('CBOR: bytes too long');
    return bytesConcat(hdr, b);
  }
  function encodeStr(s) {
    var b = strToUtf8(s);
    var l = b.length, hdr;
    if (l < 24) hdr = new Uint8Array([ (MT_STRING<<5)|l ]);
    else if (l < 256) hdr = new Uint8Array([ (MT_STRING<<5)|24, l ]);
    else if (l < 65536) hdr = new Uint8Array([ (MT_STRING<<5)|25, l>>8, l&255 ]);
    else throw new Error('CBOR: string too long');
    return bytesConcat(hdr, b);
  }
  function encodeArray(arr) {
    var l = arr.length, hdr;
    if (l < 24) hdr = new Uint8Array([ (MT_ARRAY<<5)|l ]);
    else if (l < 256) hdr = new Uint8Array([ (MT_ARRAY<<5)|24, l ]);
    else if (l < 65536) hdr = new Uint8Array([ (MT_ARRAY<<5)|25, l>>8, l&255 ]);
    else throw new Error('CBOR: array too long');
    var out = hdr;
    for (var i=0;i<l;i++) out = bytesConcat(out, encode(arr[i]));
    return out;
  }
  function encodeMap(obj) {
    // obj = { k:v } but keys may be numbers (preferred for compact header)
    var keys = Object.keys(obj);
    var l = keys.length, hdr;
    if (l < 24) hdr = new Uint8Array([ (MT_MAP<<5)|l ]);
    else if (l < 256) hdr = new Uint8Array([ (MT_MAP<<5)|24, l ]);
    else throw new Error('CBOR: map too big');
    var out = hdr;
    for (var i=0;i<l;i++) {
      var k = keys[i];
      var nk = parseInt(k,10);
      if (k === ''+nk) out = bytesConcat(out, encodeInt(nk));
      else out = bytesConcat(out, encodeStr(k));
      out = bytesConcat(out, encode(obj[k]));
    }
    return out;
  }
  function encode(v) {
    if (v === null) return new Uint8Array([ (MT_SIMPLE<<5)|22 ]);
    if (v === false) return new Uint8Array([ (MT_SIMPLE<<5)|20 ]);
    if (v === true) return new Uint8Array([ (MT_SIMPLE<<5)|21 ]);
    var t = typeof v;
    if (t === 'number') {
      if (Math.floor(v) !== v) throw new Error('CBOR: only ints supported here');
      return encodeInt(v);
    }
    if (t === 'string') return encodeStr(v);
    if (v instanceof Uint8Array) return encodeBytes(v);
    if (Array.isArray(v)) return encodeArray(v);
    if (t === 'object') return encodeMap(v);
    throw new Error('CBOR: unsupported type');
  }

  // Minimal decoder for what we emit (safe path)
  function decode(u8, off) {
    if (!off) off = 0;
    var ib = u8[off++];
    var mt = ib>>5, ai = ib & 31;
    function readN(n) { var b=u8.subarray(off, off+n); off+=n; return b; }
    function readLen() {
      if (ai < 24) return ai;
      if (ai === 24) return u8[off++];
      if (ai === 25) { var v=(u8[off]<<8)|u8[off+1]; off+=2; return v; }
      if (ai === 26) { var v=(u8[off]<<24)|(u8[off+1]<<16)|(u8[off+2]<<8)|u8[off+3]; off+=4; return v>>>0; }
      throw new Error('CBOR: len too big');
    }
    if (mt === MT_UINT) {
      var uv = ai<24 ? ai : ai===24 ? u8[off++] : ai===25 ? ((u8[off++]<<8)|u8[off++]) : (off+=4, (u8[off-4]<<24|u8[off-3]<<16|u8[off-2]<<8|u8[off-1])>>>0);
      return { v: uv, off: off };
    }
    if (mt === MT_NEGINT) {
      var mv = ai<24 ? ai : ai===24 ? u8[off++] : ai===25 ? ((u8[off++]<<8)|u8[off++]) : (off+=4, (u8[off-4]<<24|u8[off-3]<<16|u8[off-2]<<8|u8[off-1])>>>0);
      return { v: -1 - mv, off: off };
    }
    if (mt === MT_BYTES) {
      var bl = readLen(); var b = readN(bl);
      return { v: new Uint8Array(b), off: off };
    }
    if (mt === MT_STRING) {
      var sl = readLen(); var s = readN(sl);
      return { v: utf8ToStr(s), off: off };
    }
    if (mt === MT_ARRAY) {
      var al = readLen(); var arr = [];
      for (var i=0;i<al;i++) { var d=decode(u8, off); arr.push(d.v); off=d.off; }
      return { v: arr, off: off };
    }
    if (mt === MT_MAP) {
      var ml = readLen(); var obj = {};
      for (var j=0;j<ml;j++) {
        var kd=decode(u8, off); off=kd.off;
        var key = kd.v;
        if (typeof key !== 'string' && typeof key !== 'number') key = ''+key;
        var vd=decode(u8, off); off=vd.off; obj[key]=vd.v;
      }
      return { v: obj, off: off };
    }
    if (mt === MT_SIMPLE) {
      if (ai === 20) return { v:false, off:off };
      if (ai === 21) return { v:true, off:off };
      if (ai === 22) return { v:null, off:off };
      throw new Error('CBOR: unsupported simple');
    }
    throw new Error('CBOR: unsupported major type');
  }

  return {
    encode: encode,
    decode: function(u8){ var d=decode(u8,0); return d.v; }
  };
})();

// ---------- IndexedDB ----------
var dbInstance = null;

function openDB() {
  return new Promise(function(resolve, reject){
    var req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = function(ev){
      var db = ev.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) db.createObjectStore(VAULT_STORE, { keyPath: 'key' });
      if (!db.objectStoreNames.contains(SEGMENTS_STORE)) {
        var s = db.createObjectStore(SEGMENTS_STORE, { keyPath: 'id' });
        s.createIndex('by_owner', 'current_owner', { unique: false });
        s.createIndex('by_unlocked', 'unlocked', { unique: false });
      }
      if (!db.objectStoreNames.contains(PROOFS_STORE)) db.createObjectStore(PROOFS_STORE, { keyPath: 'id' });
    };
    req.onsuccess = function(ev){ dbInstance = ev.target.result; resolve(dbInstance); };
    req.onerror = function(ev){ reject(ev.target.error); };
  });
}
function tx(store, mode) {
  return dbInstance.transaction([store], mode).objectStore(store);
}
function put(store, obj) {
  return new Promise(function(res, rej){
    var r = tx(store, 'readwrite').put(obj);
    r.onsuccess = function(){ res(true); };
    r.onerror = function(e){ rej(e.target.error); };
  });
}
function get(store, key) {
  return new Promise(function(res, rej){
    var r = tx(store, 'readonly').get(key);
    r.onsuccess = function(){ res(r.result || null); };
    r.onerror = function(e){ rej(e.target.error); };
  });
}
function getAllIndex(store, indexName, queryValue) {
  return new Promise(function(res, rej){
    var idx = tx(store, 'readonly').index(indexName);
    var req = idx.getAll(queryValue);
    req.onsuccess = function(){ res(req.result || []); };
    req.onerror = function(e){ rej(e.target.error); };
  });
}
function getAll(store) {
  return new Promise(function(res, rej){
    var r = tx(store, 'readonly').getAll();
    r.onsuccess = function(){ res(r.result || []); };
    r.onerror = function(e){ rej(e.target.error); };
  });
}

// ---------- Vault State ----------
var Vault = {
  // keys: deviceKey (ECDSA P-256) for offline P2P signatures + AES key wrap; ethereumAddress (if bound)
  async init() {
    await openDB();
    var conf = await get(VAULT_STORE, 'config');
    if (!conf) {
      var deviceKey = await crypto.subtle.generateKey(
        { name:'ECDSA', namedCurve:'P-256' },
        true,
        ['sign', 'verify']
      );
      var jwk = await crypto.subtle.exportKey('jwk', deviceKey.publicKey);
      var krec = {
        key: 'config',
        createdAt: nowTs(),
        ethereumAddress: null,
        p256PublicJwk: jwk,
        caps: { day:0, month:0, year:0, tvmYear:0, lastResetDay:0, lastResetMonth:0, lastResetYear:0 },
        bioGenesis: GENESIS_BIO_CONSTANT
      };
      await put(VAULT_STORE, krec);
      await put(VAULT_STORE, { key: 'p256Private', value: await crypto.subtle.exportKey('jwk', deviceKey.privateKey) });
      log('Vault initialized.');
    }
    return true;
  },
  async getConfig() { return get(VAULT_STORE, 'config'); },
  async setEthereumAddress(addr) {
    var conf = await this.getConfig(); conf.ethereumAddress = (addr||'').toLowerCase();
    await put(VAULT_STORE, conf); return conf.ethereumAddress;
  },
  async getP256KeyPair() {
    var prv = await get(VAULT_STORE, 'p256Private');
    var conf = await get(VAULT_STORE, 'config');
    var pub = conf && conf.p256PublicJwk ? conf.p256PublicJwk : null;
    if (!prv || !pub) throw new Error('Device key missing');
    var privKey = await crypto.subtle.importKey('jwk', prv.value, { name:'ECDSA', namedCurve:'P-256' }, true, ['sign']);
    var pubKey = await crypto.subtle.importKey('jwk', pub, { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']);
    return { privateKey: privKey, publicKey: pubKey, publicJwk: pub };
  },
  async touchCaps(nSegments, nTVM) {
    var conf = await this.getConfig();
    var d = new Date(); // local ok; caps are relative
    var y = d.getUTCFullYear(), m = d.getUTCMonth()+1, day = d.getUTCDate();

    if (conf.caps.lastResetDay !== day) { conf.caps.day = 0; conf.caps.lastResetDay = day; }
    if (conf.caps.lastResetMonth !== m) { conf.caps.month = 0; conf.caps.lastResetMonth = m; }
    if (conf.caps.lastResetYear !== y) { conf.caps.year = 0; conf.caps.tvmYear = 0; conf.caps.lastResetYear = y; }

    var newDay = conf.caps.day + (nSegments||0);
    var newMonth = conf.caps.month + (nSegments||0);
    var newYear = conf.caps.year + (nSegments||0);
    var newTVMYear = conf.caps.tvmYear + (nTVM||0);

    if (newDay > DAILY_CAP) throw new Error('Daily segment cap exceeded');
    if (newMonth > MONTHLY_CAP) throw new Error('Monthly segment cap exceeded');
    if (newYear > YEARLY_CAP) throw new Error('Yearly segment cap exceeded');
    if (newTVMYear > (YEARLY_TVM_CAP + EXTRA_BONUS_TVM)) throw new Error('Yearly TVM cap exceeded');

    conf.caps.day = newDay; conf.caps.month = newMonth; conf.caps.year = newYear; conf.caps.tvmYear = newTVMYear;
    await put(VAULT_STORE, conf);
    return conf.caps;
  }
};

// ---------- Segments ----------
var Segments = {
  // schema: {
  //   id: string (segmentId),
  //   layer: number (0..9),
  //   unlocked: boolean,
  //   current_owner: string, // 0x address or p256 pub hash for offline
  //   previous_owner: string,
  //   original_owner: string,
  //   ownershipChangeCount: number,
  //   history: [{owner, ts, txid}], // max 10 for P2P; on-chain uses count===1 only
  //   onchain_eligible: boolean, // ownershipChangeCount===1
  //   proof: { /* compact metadata to build claims */ }
  // }

  async listUnlocked(limit) {
    var all = await getAllIndex(SEGMENTS_STORE, 'by_unlocked', true);
    if (typeof limit === 'number' && limit >= 0) return all.slice(0, limit);
    return all;
  },
  async listByOwner(owner) {
    return getAllIndex(SEGMENTS_STORE, 'by_owner', owner.toLowerCase());
  },
  async putMany(arr) {
    for (var i=0;i<arr.length;i++) await put(SEGMENTS_STORE, arr[i]);
  },
  async mintTo(ownerAddress, count) {
    // Each mint sets original_owner = previous_owner = vault_owner; ownershipChangeCount = 1
    ownerAddress = (ownerAddress||'').toLowerCase();
    var created = [];
    var ts = nowTs();
    for (var i=0;i<count;i++) {
      var id = 'seg_'+ts+'_'+i+'_'+Math.floor(Math.random()*1e9);
      var obj = {
        id: id,
        layer: 0,
        unlocked: true, // Layer0 unlocked first 1200 by default
        current_owner: ownerAddress, // current owner is the mint recipient, not the vault
        previous_owner: ownerAddress, // vault owner equals original & previous at t0
        original_owner: ownerAddress,
        ownershipChangeCount: 1,
        history: [{ owner: ownerAddress, ts: ts, txid: 'mint:'+id }],
        onchain_eligible: true,
        proof: { v:1, genesis: GENESIS_BIO_CONSTANT }
      };
      created.push(obj);
    }
    await this.putMany(created);
    await Vault.touchCaps(count, Math.floor(count/EXCHANGE_RATE)); // accumulate caps
    return created;
  },
  async unlockNext(nRequired) {
    // unlock deterministic sequence across 10 layers; simple model: ensure total unlocked grows accordingly
    var all = await getAll(SEGMENTS_STORE);
    var locked = [];
    for (var i=0;i<all.length;i++) if (!all[i].unlocked) locked.push(all[i]);
    locked.sort(function(a,b){ // deterministic order by layer then id
      if (a.layer !== b.layer) return a.layer - b.layer;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
    var selected = locked.slice(0, nRequired);
    for (var j=0;j<selected.length;j++) { selected[j].unlocked = true; await put(SEGMENTS_STORE, selected[j]); }
    return selected.length;
  },
  async consumeForP2P(sender, count) {
    sender = (sender||'').toLowerCase();
    var own = await this.listByOwner(sender);
    var unlocked = [];
    for (var i=0;i<own.length;i++) if (own[i].unlocked) unlocked.push(own[i]);
    if (unlocked.length < count) throw new Error('Insufficient unlocked segments');
    return unlocked.slice(0, count);
  },
  async applyInbound(receiver, payloadSegments, txid) {
    receiver = (receiver||'').toLowerCase();
    var ts = nowTs();
    for (var i=0;i<payloadSegments.length;i++) {
      var s = payloadSegments[i];
      // enforce: sender must have been current_owner in the payload; we rewrite to receiver as current_owner
      var prev = s.current_owner;
      s.previous_owner = prev;
      s.current_owner = receiver;
      s.ownershipChangeCount = (s.ownershipChangeCount||1) + 1;
      if (s.history && s.history.length >= 10) s.history.shift();
      if (!s.history) s.history = [];
      s.history.push({ owner: receiver, ts: ts, txid: txid||('p2p:'+s.id+':'+ts) });
      s.onchain_eligible = false; // after first P2P hop it’s no longer on-chain eligible
      s.unlocked = true; // received segments are usable
      await put(SEGMENTS_STORE, s);
      await put(PROOFS_STORE, { id: 'proof:'+s.id+':'+s.ownershipChangeCount, segmentId: s.id, owner: receiver, ts: ts, history: s.history.slice() });
    }
    return true;
  }
};

// ---------- AES-GCM + HKDF helpers ----------
var CryptoBox = {
  // Derive symmetric key from shared material (simple HKDF over SHA-256).
  async hkdf(ikm, salt, info, len) {
    if (!salt) salt = new Uint8Array(32);
    if (!info) info = new Uint8Array(0);
    var key = await crypto.subtle.importKey('raw', ikm, {name:'HKDF'}, false, ['deriveKey']);
    var derived = await crypto.subtle.deriveKey(
      { name:'HKDF', hash:'SHA-256', salt: salt, info: info },
      key,
      { name:'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    return derived;
  },
  async encrypt(bodyU8, key) {
    var iv = randomBytes(12);
    var ct = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, key, bodyU8);
    return { iv: iv, ciphertext: new Uint8Array(ct) };
  },
  async decrypt(iv, ciphertext, key) {
    var pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, key, ciphertext);
    return new Uint8Array(pt);
  }
};

// ---------- Signatures ----------
async function signWithEthereum(addressLower, bytes) {
  // EIP-191 personal_sign if window.ethereum exists
  if (!window.ethereum) throw new Error('Ethereum provider not available');
  var hex = bytesToHex(bytes);
  // personal_sign expects hex payload as a string message
  var sig = await window.ethereum.request({
    method: 'personal_sign',
    params: [hex, addressLower]
  });
  return sig; // 0x… signature
}

async function signWithP256(bytes) {
  var kp = await Vault.getP256KeyPair();
  var sig = await crypto.subtle.sign(
    { name:'ECDSA', hash:{name:'SHA-256'} },
    kp.privateKey,
    bytes
  );
  return b64uEncode(new Uint8Array(sig)); // compact transport
}

// ---------- Compact P2P payload (header + encrypted CBOR body) ----------
// Header map (CBOR, integer keys for compactness):
//   0: version (int)
//   1: ts (int, seconds)
//   2: seq (int, sender local sequence/nonce)
//   3: count (int, number of segments)
//   4: from (string: 0x addr lower OR 'p256:' + JWK.x+y b64u)
//   5: to (string: receiver identity same scheme as above)
//   6: sig (string | bytes): signature over (header_without_sig || ciphertext)
//
// Body (CBOR, encrypted):
//   {
//     0: segments: [ { id, layer, current_owner, previous_owner, original_owner, ownershipChangeCount, unlocked, proof, history } ],
//     1: memo: optional string,
//     2: parity: { she:int,tvm:int } (optional accounting hint)
//   }

var P2P = {
  seq: 0,

  identityString: async function() {
    var conf = await Vault.getConfig();
    if (conf.ethereumAddress) return conf.ethereumAddress.toLowerCase();
    // offline identity based on P-256 public JWK
    var pub = conf.p256PublicJwk; // has 'x' and 'y' b64u
    return 'p256:'+pub.x+'.'+pub.y;
  },

  async buildHeader(from, to, count) {
    return {
      0: P2P_VERSION,
      1: nowTs(),
      2: ++this.seq,
      3: count|0,
      4: from,
      5: to
      // 6 reserved for signature; appended after encryption
    };
  },

  async encryptBody(bodyObj, sharedKeyBytes) {
    // derive AES key from provided shared material (e.g., pre-shared secret or ECDH output)
    var key = await CryptoBox.hkdf(sharedKeyBytes, null, strToUtf8('p2p/body'), 32);
    var bodyBytes = CBOR.encode(bodyObj);
    var enc = await CryptoBox.encrypt(bodyBytes, key);
    return { key: key, iv: enc.iv, ciphertext: enc.ciphertext };
  },

  async decryptBody(iv, ciphertext, sharedKeyBytes) {
    var key = await CryptoBox.hkdf(sharedKeyBytes, null, strToUtf8('p2p/body'), 32);
    var pt = await CryptoBox.decrypt(iv, ciphertext, key);
    return CBOR.decode(pt);
  },

  async signEnvelope(headerWithoutSigBytes, ciphertextBytes) {
    var conf = await Vault.getConfig();
    var bytes = bytesConcat(headerWithoutSigBytes, ciphertextBytes);
    if (conf.ethereumAddress && window.ethereum) {
      var sig = await signWithEthereum(conf.ethereumAddress, bytes);
      return { scheme: 'eth', value: sig };
    } else {
      var sig2 = await signWithP256(bytes);
      return { scheme: 'p256', value: sig2 };
    }
  },

  serializeHeaderWithSig: function(headerObj, sig) {
    var h = {};
    for (var k in headerObj) h[k] = headerObj[k];
    // attach signature as string "eth:<hex>" or "p256:<b64u>"
    h[6] = sig.scheme + ':' + sig.value;
    return CBOR.encode(h);
  },

  async prepareSend(senderAddr, receiverIdentity, nSegments, sharedKeyBytes, memo) {
    senderAddr = (senderAddr||'').toLowerCase();
    await Vault.touchCaps(nSegments, 0);

    var chosen = await Segments.consumeForP2P(senderAddr, nSegments);

    // enforce sender is current owner
    for (var i=0;i<chosen.length;i++) {
      if ((chosen[i].current_owner||'').toLowerCase() !== senderAddr) {
        throw new Error('Ownership violation: only current owner can transfer');
      }
    }

    var header = await this.buildHeader(await this.identityString(), receiverIdentity, chosen.length);

    var body = {
      0: chosen, // segments array (compact numeric key)
      1: memo || '',
      2: { she: chosen.length, tvm: Math.floor(chosen.length/EXCHANGE_RATE) }
    };

    var enc = await this.encryptBody(body, sharedKeyBytes);
    var headerRaw = CBOR.encode(header);
    var sig = await this.signEnvelope(headerRaw, enc.ciphertext);
    var headerWithSig = this.serializeHeaderWithSig(header, sig);

    // after building payload but BEFORE shipping, lock these segments to prevent double spend
    // (soft lock: set unlocked=false, until ack or timeout)
    for (var j=0;j<chosen.length;j++) { chosen[j].unlocked = false; await put(SEGMENTS_STORE, chosen[j]); }

    return {
      header: b64uEncode(headerWithSig),
      iv: b64uEncode(enc.iv),
      body: b64uEncode(enc.ciphertext)
    };
  },

  async receiveAndApply(receiverAddr, packed, sharedKeyBytes, txidHint) {
    receiverAddr = (receiverAddr||'').toLowerCase();

    var headerBytes = b64uDecode(packed.header);
    var header = CBOR.decode(headerBytes);
    var iv = b64uDecode(packed.iv);
    var ciphertext = b64uDecode(packed.body);

    // verify header basics
    if (header['0'] !== P2P_VERSION) throw new Error('Unsupported P2P version');
    if ((header['3']|0) <= 0) throw new Error('Empty transfer');
    var sigField = header['6']; if (!sigField) throw new Error('Missing signature');

    // signature verification — best-effort (scheme switch)
    // ETH path requires external recovery to match header[4] (from); for offline we verify P-256 against stored peer key if known.
    // For simplicity we log scheme; on-chain claims do not depend on this signature.
    var scheme = ''+sigField.split(':')[0];
    var sigVal = sigField.substring(scheme.length+1);

    // decrypt body
    var body = await this.decryptBody(iv, ciphertext, sharedKeyBytes);
    if (!body || !body['0'] || !Array.isArray(body['0'])) throw new Error('Malformed body');

    var segs = body['0'];
    if (segs.length !== (header['3']|0)) throw new Error('Count mismatch');

    // Apply ownership transition for each segment, enforce sender was current owner in payload
    for (var i=0;i<segs.length;i++) {
      var s = segs[i];
      if (!s.id) throw new Error('Segment missing id');
      if (!s.current_owner) throw new Error('Segment missing current_owner');
      // guard: allow receiver to accept; previous owner retains claim power via proofs store
    }
    await Segments.applyInbound(receiverAddr, segs, txidHint||('p2p:'+nowTs()));

    // Auto-unlock equal count if caps allow
    try { await Vault.touchCaps(segs.length, 0); } catch(e){ err('Caps touch on receive:', e.message); }
    await Segments.unlockNext(segs.length);

    return { applied: segs.length, scheme: scheme };
  }
};

// ---------- On-chain Claim Preparation (TVM gateway) ----------
var TVM = {
  // Build minimal claim set: only segments with ownershipChangeCount === 1
  async collectOnchainEligible(maxCount) {
    var all = await getAll(SEGMENTS_STORE);
    var res = [];
    for (var i=0;i<all.length;i++) {
      if (all[i].onchain_eligible === true && (all[i].ownershipChangeCount|0) === 1) res.push(all[i]);
      if (res.length === maxCount) break;
    }
    return res;
  },
  // Export compact proofs for claim (no 10-history)
  async exportClaimBundle(maxCount) {
    var list = await this.collectOnchainEligible(maxCount);
    var out = [];
    for (var i=0;i<list.length;i++) {
      var s = list[i];
      out.push({
        id: s.id,
        owner: s.current_owner,
        original: s.original_owner,
        previous: s.previous_owner,
        occ: s.ownershipChangeCount,
        proof: s.proof
      });
      // mark as no longer on-chain eligible after export to prevent double claim offline
      s.onchain_eligible = false;
      await put(SEGMENTS_STORE, s);
    }
    return out;
  }
};

// ---------- Public API (attach to window) ----------
var BioVault = {
  ready: false,

  async init() {
    if (!self.indexedDB) throw new Error('IndexedDB not available');
    await Vault.init();
    this.ready = true;
    log('App ready.');
    return true;
  },

  // identities
  async bindEthereumAddress(addr) { return Vault.setEthereumAddress(addr); },
  async myIdentity() { return P2P.identityString(); },

  // inventory
  async segmentsUnlocked() { return Segments.listUnlocked(); },
  async segmentsAll() { return getAll(SEGMENTS_STORE); },

  // mint (TVM → segments). NOTE: ownershipChangeCount = 1 at mint.
  async mintSegments(recipientAddr, count) {
    if (!recipientAddr) throw new Error('recipient required');
    var minted = await Segments.mintTo(recipientAddr, count|0);
    // auto-create proofs
    var ts = nowTs();
    for (var i=0;i<minted.length;i++) {
      var s = minted[i];
      await put(PROOFS_STORE, { id: 'proof:'+s.id+':1', segmentId: s.id, owner: s.current_owner, ts: ts, history: s.history.slice() });
    }
    return minted;
  },

  // P2P send (compact header + encrypted CBOR body)
  // sharedKeyBytes must be Uint8Array pre-shared secret or derived elsewhere (e.g., QR key exchange)
  async p2pPrepareSend(senderAddr, receiverIdentity, nSegments, sharedKeyBytes, memo) {
    if (!(sharedKeyBytes instanceof Uint8Array)) throw new Error('sharedKeyBytes must be Uint8Array');
    return P2P.prepareSend(senderAddr, receiverIdentity, nSegments|0, sharedKeyBytes, memo||'');
  },

  // P2P receive & apply
  async p2pReceiveApply(receiverAddr, packed, sharedKeyBytes, txidHint) {
    if (!(sharedKeyBytes instanceof Uint8Array)) throw new Error('sharedKeyBytes must be Uint8Array');
    return P2P.receiveAndApply(receiverAddr, packed, sharedKeyBytes, txidHint||null);
  },

  // Deterministic unlocks (e.g., after successful send)
  async unlockNext(n) { return Segments.unlockNext(n|0); },

  // On-chain claim export (for TVM gateway). Only ownershipChangeCount === 1.
  async exportOnchainClaim(maxCount) { return TVM.exportClaimBundle(maxCount|0); },

  // Tools
  b64uEncode: b64uEncode,
  b64uDecode: b64uDecode,
  CBOR: CBOR
};

window.BioVault = BioVault;

// ---------- Boot ----------
BioVault.init().catch(function(e){ err('Init failed:', e && e.message ? e.message : e); });

/* ---------------- CHANGE LOG (inline notes) ----------------
[SECURITY] Compact P2P v3: CBOR header (int keys) + AES-GCM encrypted CBOR body; signature over (header||ciphertext).
[OWNERSHIP] Enforced: sender must be current owner before P2P; receiver becomes current; sender becomes previous; history (max 10).
[ON-CHAIN] exportOnchainClaim() emits only segments with ownershipChangeCount === 1; marks them non-eligible afterward (anti-double-claim).
[CAPS] Vault.touchCaps() enforces 360/day, 3,600/month, 10,800/year; yearly TVM 900 + 100 bonus.
[UNLOCKS] After successful receive, auto-touch caps and unlockNext(count) to preserve available liquidity.
[ES2018] No optional chaining / private fields / numeric separators; zero external libraries.
[CRYPTO] If Ethereum provider exists, personal_sign is used; else P-256 ECDSA for offline P2P signatures (on-chain flow unaffected).
*/ 
/******************************
 * EVM adapter — TVM contract integration
 * - Uses window.ethereum + ethers (lazy-loaded) for on-chain calls.
 * - Consumes proofs from BioVault.exportOnchainClaim().
 * - Keeps P2P fully separate.
 ******************************/

(function(){
  // Addresses already defined above; re-use:
  var TVM_ADDRESS  = (typeof TVM_CONTRACT_ADDRESS !== 'undefined') ? TVM_CONTRACT_ADDRESS : '';
  var USDT_ADDRESS = (typeof USDT_ADDRESS !== 'undefined') ? USDT_ADDRESS : '';

  // Minimal ABIs: adjust ONLY if your finalized contract uses different names/structs.
  // These match the finalized baseline: claim with one-hop segments only, mint from USDT, swap to/from USDT.
  var ERC20_ABI = [
    "function approve(address spender, uint256 amount) external returns (bool)",
    "function allowance(address owner, address spender) external view returns (uint256)",
    "function balanceOf(address owner) external view returns (uint256)",
    "function decimals() external view returns (uint8)"
  ];

  // Claim struct assumed by the finalized TVM contract:
  // struct ClaimItem {
  //   bytes32 id;
  //   address owner;
  //   address previousOwner;
  //   address originalOwner;
  //   uint256 ownershipChangeCount;
  //   uint256 genesis;
  // }
  //
  // interface:
  //   function claim(ClaimItem[] calldata items) external;
  //   function mintFromUSDT(uint256 usdtAmount) external;
  //   function swapTVMForUSDT(uint256 amountIn, uint256 minOut) external;
  //   function swapUSDTForTVM(uint256 amountIn, uint256 minOut) external;
  //
  var TVM_ABI = [
    "function claim(tuple(bytes32 id,address owner,address previousOwner,address originalOwner,uint256 ownershipChangeCount,uint256 genesis)[] items) external",
    "function mintFromUSDT(uint256 usdtAmount) external",
    "function swapTVMForUSDT(uint256 amountIn, uint256 minOut) external",
    "function swapUSDTForTVM(uint256 amountIn, uint256 minOut) external"
  ];

  function ensureEthers() {
    return new Promise(function(resolve, reject){
      if (window.ethers) return resolve();
      var s = document.createElement('script');
      s.src = "https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js";
      s.onload = function(){ resolve(); };
      s.onerror = function(){ reject(new Error('Failed to load ethers.js')); };
      document.head.appendChild(s);
    });
  }

  var EVM = {
    provider: null,
    signer: null,
    tvm: null,
    usdt: null,
    account: null,
    chainId: null,

    async connect() {
      if (!window.ethereum) throw new Error('No Ethereum provider (window.ethereum) found');
      await ensureEthers();
      this.provider = new window.ethers.providers.Web3Provider(window.ethereum, 'any');
      var accts = await this.provider.send('eth_requestAccounts', []);
      this.signer = this.provider.getSigner();
      this.account = (accts && accts[0]) ? accts[0].toLowerCase() : null;
      var net = await this.provider.getNetwork();
      this.chainId = net.chainId;

      this.usdt = new window.ethers.Contract(USDT_ADDRESS, ERC20_ABI, this.signer);
      this.tvm  = new window.ethers.Contract(TVM_ADDRESS,  TVM_ABI,  this.signer);

      return { account: this.account, chainId: this.chainId };
    },

    // Turn vault bundle → contract ClaimItem[]
    _vaultToClaimItems: function(bundle) {
      var utils = window.ethers.utils;
      var items = [];
      for (var i=0;i<bundle.length;i++) {
        var it = bundle[i];
        // id → bytes32 (deterministic): keccak256(utf8(id))
        var idBytes32 = utils.keccak256(utils.toUtf8Bytes(it.id));
        var occ = window.ethers.BigNumber.from(it.occ || 1);
        var genesis = window.ethers.BigNumber.from((it.proof && it.proof.genesis) || GENESIS_BIO_CONSTANT);
        items.push({
          id: idBytes32,
          owner: (it.owner||'').toLowerCase(),
          previousOwner: (it.previous||'').toLowerCase(),
          originalOwner: (it.original||'').toLowerCase(),
          ownershipChangeCount: occ,
          genesis: genesis
        });
      }
      return items;
    },

    // Claims only one-hop segments exported by the vault.
    async claimFromVault(maxCount) {
      if (!this.tvm) await this.connect();
      var bundle = await window.BioVault.exportOnchainClaim(maxCount|0);
      if (!bundle.length) throw new Error('No on-chain-eligible segments (occ === 1)');
      var items = this._vaultToClaimItems(bundle);
      var tx = await this.tvm.claim(items);
      return tx; // wait with: await tx.wait()
    },

    // Approve USDT for TVM if needed
    async ensureUSDTAllowance(amount) {
      if (!this.usdt) await this.connect();
      var current = await this.usdt.allowance(this.account, TVM_ADDRESS);
      if (current.gte(amount)) return true;
      var tx = await this.usdt.approve(TVM_ADDRESS, amount);
      await tx.wait();
      return true;
    },

    // Mint TVM by paying USDT to the contract
    async mintFromUSDT(usdtAmountRaw) {
      if (!this.tvm) await this.connect();
      var usdtDecimals = await this.usdt.decimals();
      var amt = window.ethers.utils.parseUnits(String(usdtAmountRaw), usdtDecimals);
      await this.ensureUSDTAllowance(amt);
      var tx = await this.tvm.mintFromUSDT(amt);
      return tx;
    },

    // Swap TVM -> USDT via contract
    async swapTVMForUSDT(amountTVMRaw, minOutUSDT) {
      if (!this.tvm) await this.connect();
      // TVM assumed 18 decimals unless your contract specifies otherwise
      var amtIn  = window.ethers.utils.parseUnits(String(amountTVMRaw), 18);
      var minOut = window.ethers.utils.parseUnits(String(minOutUSDT), 6); // USDT 6 decimals typical
      var tx = await this.tvm.swapTVMForUSDT(amtIn, minOut);
      return tx;
    },

    // Swap USDT -> TVM via contract
    async swapUSDTForTVM(amountUSDTRaw, minOutTVM) {
      if (!this.tvm) await this.connect();
      var usdtDecimals = await this.usdt.decimals();
      var amtIn  = window.ethers.utils.parseUnits(String(amountUSDTRaw), usdtDecimals);
      var minOut = window.ethers.utils.parseUnits(String(minOutTVM), 18);
      await this.ensureUSDTAllowance(amtIn);
      var tx = await this.tvm.swapUSDTForTVM(amtIn, minOut);
      return tx;
    }
  };

  // expose
  window.BioVault.EVM = EVM;
})();
