/* ======================================================================
 * main.js — BalanceChain PWA core (ES2018)
 *
 * Clean rewrite: DOM‑agnostic vault API at window.BioVault.
 * Focused on correctness, caps, and wire‑compat with the on‑chain TVM.
 *
 * ✅ Key guarantees (per spec):
 *   - P2P is separate/off‑chain, encrypted end‑to‑end (HPKE‑lite) with gzip.
 *   - On‑chain TVM claim uses ONLY segments with ownershipChangeCount === 1.
 *   - Sends use only UNLOCKED segments; after send, auto‑unlock the same count
 *     if daily/monthly/yearly caps allow.
 *   - Tracks 360/3600/10800 segment caps and 900 TVM/yr (+100 parity bonus).
 *   - Biometric gating enforced before send/receive/claim; ZKP bound in proofs.
 *   - IndexedDB schema is versioned and migrates legacy stores/indexes.
 *   - History ring buffer (10) per segment; deterministic conflict resolver.
 *   - ES2018 compatible (no BigInt literals, optional chaining, etc.).
 * ====================================================================== */

/* ===================== console helpers ===================== */
function _log(){ try{ console.log.apply(console, ['[BioVault]'].concat([].slice.call(arguments))); }catch(e){} }
function _err(){ try{ console.error.apply(console, ['[BioVault]'].concat([].slice.call(arguments))); }catch(e){} }

/* ===================== Global constants ===================== */
var DB_NAME='BioVaultDB';
var DB_VERSION=9; // robust migrations

var VAULT_STORE='vault';
var SEGMENTS_STORE='segments';
var NULLIFIERS_STORE='nullifiers';
var REPLAYS_STORE='replays';
var CONTACTS_STORE='contacts';

// Monetary / protocol constants
var INITIAL_BALANCE_SHE=1200;               // genesis unlocked
var EXCHANGE_RATE=12;                        // 12 SHE = 1 TVM
var GENESIS_BIO_CONSTANT=1736565605;        // 2025‑01‑11 UTC
var BIO_STEP=1;                              // bioConst step per hop
var SEGMENTS_PER_LAYER=1200;
var LAYERS=10;
var DAILY_CAP_TVM=30, MONTHLY_CAP_TVM=300, YEARLY_CAP_TVM=900, EXTRA_BONUS_TVM=100;
var SEGMENTS_PER_TVM=12;
var DAILY_CAP_SEG=DAILY_CAP_TVM*SEGMENTS_PER_TVM;     // 360
var MONTHLY_CAP_SEG=MONTHLY_CAP_TVM*SEGMENTS_PER_TVM; // 3600
var YEARLY_CAP_SEG=YEARLY_CAP_TVM*SEGMENTS_PER_TVM;   // 10800
var MAX_TRANSFER_SEGMENTS=300;              // per‑transfer cap
var SEGMENT_HISTORY_MAX=10;                 // ring buffer cap

// Contract (ABI matches Smart Contract (TVM))
var CONTRACT_ADDRESS='0xcc79b1bc9eabc3d30a3800f4d41a4a0599e1f3c6'; // lowercased
var EXPECTED_CHAIN_ID=1;
var TVM_ABI=[
  {"inputs":[{"components":[
    {"internalType":"uint256","name":"segmentIndex","type":"uint256"},
    {"internalType":"uint256","name":"currentBioConst","type":"uint256"},
    {"internalType":"bytes32","name":"ownershipProof","type":"bytes32"},
    {"internalType":"bytes32","name":"unlockIntegrityProof","type":"bytes32"},
    {"internalType":"bytes32","name":"spentProof","type":"bytes32"},
    {"internalType":"uint256","name":"ownershipChangeCount","type":"uint256"},
    {"internalType":"bytes32","name":"biometricZKP","type":"bytes32"}
  ],"internalType":"struct TVM.SegmentProof[]","name":"proofs","type":"tuple[]"},
  {"internalType":"bytes","name":"signature","type":"bytes"},
  {"internalType":"bytes32","name":"deviceKeyHash","type":"bytes32"},
  {"internalType":"uint256","name":"userBioConstant","type":"uint256"},
  {"internalType":"uint256","name":"nonce","type":"uint256"}],
  "name":"claimTVM","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
];

// Hash domains
var H_SEGMENT='SEG_V2|';
var H_NULLIFIER='NF_V1|';
var H_AAD='P2P_AAD_V3|';

// P2P envelope
var P2P_VERSION=3;
var P2P_SCHEMA='p2p/v3@2025-08-27';

// UI/session guard (API is DOM‑agnostic; this is just a sane default)
var MAX_IDLE_MS=15*60*1000;

/* ===================== utils ===================== */
var Utils=(function(){
  function enc(){return new TextEncoder();}
  function dec(){return new TextDecoder();}
  function toB64(buf){ var a=buf instanceof ArrayBuffer?new Uint8Array(buf):(buf&&buf.buffer)?new Uint8Array(buf.buffer):new Uint8Array(buf||[]); var CH=32768,s=''; for(var i=0;i<a.length;i+=CH){ s+=String.fromCharCode.apply(null,a.subarray(i,i+CH)); } return btoa(s); }
  function fromB64(b64){ return Uint8Array.from(atob(b64),function(c){return c.charCodeAt(0);}).buffer; }
  function sha256Hex(str){ return crypto.subtle.digest('SHA-256', enc().encode(str)).then(function(buf){ return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,'0');}).join(''); }); }
  function randomNonce(){ var u=new Uint32Array(4); crypto.getRandomValues(u); return [u[0],u[1],u[2],u[3]].map(function(x){return x.toString(16)}).join(''); }
  function canonical(obj){ return JSON.stringify(obj, Object.keys(obj).sort()); }
  return {enc:enc(), dec:dec(), toB64:toB64, fromB64:fromB64, sha256Hex:sha256Hex, randomNonce:randomNonce, canonical:canonical};
})();

/* ===================== CBOR (tiny subset) ===================== */
var CBOR=(function(){function c(a,b){var o=new Uint8Array(a.length+b.length);o.set(a,0);o.set(b,a.length);return o;}function eu(n){if(n<24)return new Uint8Array([n]);if(n<256)return new Uint8Array([24,n]);if(n<65536)return new Uint8Array([25,n>>8,n&255]);var a=new Uint8Array(5);a[0]=26;a[1]=(n>>>24)&255;a[2]=(n>>>16)&255;a[3]=(n>>>8)&255;a[4]=n&255;return a;}function eb(b){var l=b.length,h;if(l<24)h=new Uint8Array([(2<<5)|l]);else if(l<256)h=new Uint8Array([(2<<5)|24,l]);else if(l<65536)h=new Uint8Array([(2<<5)|25,l>>8,l&255]);else throw new Error('CBOR bytes too long');return c(h,b);}function es(s){var b=new TextEncoder().encode(s),l=b.length,h;if(l<24)h=new Uint8Array([(3<<5)|l]);else if(l<256)h=new Uint8Array([(3<<5)|24,l]);else if(l<65536)h=new Uint8Array([(3<<5)|25,l>>8,l&255]);else throw new Error('CBOR string too long');return c(h,b);}function ea(arr){var l=arr.length,h;if(l<24)h=new Uint8Array([(4<<5)|l]);else if(l<256)h=new Uint8Array([(4<<5)|24,l]);else if(l<65536)h=new Uint8Array([(4<<5)|25,l>>8,l&255]);else throw new Error('CBOR array too long');var out=h;for(var i=0;i<l;i++) out=c(out,encode(arr[i]));return out;}function em(obj){var ks=Object.keys(obj),l=ks.length,h;if(l<24)h=new Uint8Array([(5<<5)|l]);else if(l<256)h=new Uint8Array([(5<<5)|24,l]);else throw new Error('CBOR map too big');var out=h;for(var i=0;i<l;i++){var k=ks[i],nk=parseInt(k,10);out=c(out,(k===''+nk)?encode(nk):es(k));out=c(out,encode(obj[k]));}return out;}function encode(v){if(v===null)return new Uint8Array([(7<<5)|22]);if(v===false)return new Uint8Array([(7<<5)|20]);if(v===true)return new Uint8Array([(7<<5)|21]);var t=typeof v;if(t==='number'){if(Math.floor(v)!==v) throw new Error('CBOR:int only'); if(v>=0){ if(v<24)return new Uint8Array([(0<<5)|v]); if(v<256)return new Uint8Array([(0<<5)|24,v]); if(v<65536)return new Uint8Array([(0<<5)|25,v>>8,v&255]); var a=new Uint8Array(5); a[0]=(0<<5)|26; a[1]=(v>>>24)&255;a[2]=(v>>>16)&255;a[3]=(v>>>8)&255;a[4]=v&255; return a; } else { var m=-1-v; if(m<24)return new Uint8Array([(1<<5)|m]); if(m<256)return new Uint8Array([(1<<5)|24,m]); if(m<65536)return new Uint8Array([(1<<5)|25,m>>8,m&255]); var a2=new Uint8Array(5); a2[0]=(1<<5)|26; a2[1]=(m>>>24)&255;a2[2]=(m>>>16)&255;a2[3]=(m>>>8)&255;a2[4]=m&255; return a2; } } if(t==='string')return es(v); if(v instanceof Uint8Array)return eb(v); if(Array.isArray(v))return ea(v); if(t==='object')return em(v); throw new Error('CBOR:unsupported'); } function rl(u8,off,ai){if(ai<24)return{l:ai,o:off}; if(ai===24)return{l:u8[off],o:off+1}; if(ai===25)return{l:(u8[off]<<8)|u8[off+1],o:off+2}; if(ai===26){var v=(u8[off]<<24)|(u8[off+1]<<16)|(u8[off+2]<<8)|u8[off+3]; return{l:(v>>>0),o:off+4};} throw new Error('CBOR:len');} function dec(u8,off){if(!off)off=0; var ib=u8[off++],mt=ib>>5,ai=ib&31; if(mt===0){ if(ai<24)return{v:ai,off:off}; if(ai===24)return{v:u8[off],off:off+1}; if(ai===25)return{v:(u8[off]<<8)|u8[off+1],off:off+2}; if(ai===26){var v=(u8[off]<<24)|(u8[off+1]<<16)|(u8[off+2]<<8)|u8[off+3]; return{v:(v>>>0),off:off+4}; } } if(mt===1){ if(ai<24)return{v:-1-ai,off:off}; if(ai===24)return{v:-1-u8[off],off:off+1}; if(ai===25){var m=(u8[off]<<8)|u8[off+1]; return{v:-1-m,off:off+2}; } if(ai===26){var mm=(u8[off]<<24)|(u8[off+1]<<16)|(u8[off+2]<<8)|u8[off+3]; return{v:-1-(mm>>>0),off:off+4}; } } if(mt===2){var r=rl(u8,off,ai); var bytes=u8.subarray(r.o,r.o+r.l); return{v:new Uint8Array(bytes),off:r.o+r.l}; } if(mt===3){var r2=rl(u8,off,ai); var str=new TextDecoder().decode(u8.subarray(r2.o,r2.o+r2.l)); return{v:str,off:r2.o+r2.l}; } if(mt===4){var r3=rl(u8,off,ai),arr=[],o=r3.o; for(var i=0;i<r3.l;i++){var d=dec(u8,o); arr.push(d.v); o=d.off;} return{v:arr,off:o}; } if(mt===5){var r4=rl(u8,off,ai),obj={},o2=r4.o; for(var i2=0;i2<r4.l;i2++){var kd=dec(u8,o2); o2=kd.off; var key=kd.v; if(typeof key!=='string'&&typeof key!=='number') key=''+key; var vd=dec(u8,o2); o2=vd.off; obj[key]=vd.v; } return{v:obj,off:o2}; } if(mt===7){ if(ai===20)return{v:false,off:off}; if(ai===21)return{v:true,off:off}; if(ai===22)return{v:null,off:off}; } throw new Error('CBOR:bad major'); } return {encode:encode, decode:function(u8){return dec(u8,0).v;}};})();

/* ===================== IndexedDB (with migrations) ===================== */
var _db=null;
function openDB(){return new Promise(function(res,rej){var req=indexedDB.open(DB_NAME,DB_VERSION); req.onupgradeneeded=function(ev){var db=ev.target.result; var old=ev.oldVersion|0; var tx=ev.currentTarget.transaction; // capture legacy
    var legacyVault=[], legacySegs=[], legacyNulls=[], legacyReplays=[], legacyContacts=[];
    function grab(name){ try{ var s=tx.objectStore(name); var g=s.getAll(); g.onsuccess=function(){ if(name==='vault') legacyVault=g.result; if(name==='segments') legacySegs=g.result; if(name==='nullifiers') legacyNulls=g.result; if(name==='replays') legacyReplays=g.result; if(name==='contacts') legacyContacts=g.result; }; }catch(e){}
    }
    if(old>0){ ['vault','segments','nullifiers','replays','contacts'].forEach(grab); }
    // drop & recreate stores with canonical definitions
    try{ if(db.objectStoreNames.contains('vault')) db.deleteObjectStore('vault'); }catch(e){}
    var v=db.createObjectStore(VAULT_STORE,{keyPath:'key'});
    try{ if(db.objectStoreNames.contains('segments')) db.deleteObjectStore('segments'); }catch(e){}
    var s=db.createObjectStore(SEGMENTS_STORE,{keyPath:'segmentIndex'}); s.createIndex('by_owner','currentOwner',{unique:false}); s.createIndex('by_unlocked','unlocked',{unique:false});
    try{ if(db.objectStoreNames.contains(NULLIFIERS_STORE)) db.deleteObjectStore(NULLIFIERS_STORE); }catch(e){}
    db.createObjectStore(NULLIFIERS_STORE,{keyPath:'z'});
    try{ if(db.objectStoreNames.contains(REPLAYS_STORE)) db.deleteObjectStore(REPLAYS_STORE); }catch(e){}
    db.createObjectStore(REPLAYS_STORE,{keyPath:'nonce'});
    try{ if(db.objectStoreNames.contains(CONTACTS_STORE)) db.deleteObjectStore(CONTACTS_STORE); }catch(e){}
    db.createObjectStore(CONTACTS_STORE,{keyPath:'id'});
    // reinsert legacy with new semantics
    var vt=tx.objectStore('vault');
    if(legacyVault&&legacyVault.length){ legacyVault.forEach(function(r){ if(r){ if(r.id && !r.key){ r.key=r.id; delete r.id; } vt.put(r); } }); }
    var st=tx.objectStore('segments'); if(legacySegs&&legacySegs.length){ legacySegs.forEach(function(r){ if(r){ st.put(r);} }); }
    var nt=tx.objectStore(NULLIFIERS_STORE); if(legacyNulls&&legacyNulls.length) legacyNulls.forEach(function(r){ nt.put(r); });
    var rt=tx.objectStore(REPLAYS_STORE); if(legacyReplays&&legacyReplays.length) legacyReplays.forEach(function(r){ rt.put(r); });
    var ct=tx.objectStore(CONTACTS_STORE); if(legacyContacts&&legacyContacts.length) legacyContacts.forEach(function(r){ ct.put(r); });
  };
  req.onsuccess=function(e){ _db=e.target.result; res(_db); };
  req.onerror=function(e){ rej(e.target.error); };
});}
function _tx(name,mode){return _db.transaction([name],mode).objectStore(name);} 
function idbPut(store,obj){return new Promise(function(res,rej){var r=_tx(store,'readwrite').put(obj); r.onsuccess=function(){res(true)}; r.onerror=function(e){rej(e.target.error)}});} 
function idbGet(store,key){return new Promise(function(res,rej){var r=_tx(store,'readonly').get(key); r.onsuccess=function(){res(r.result||null)}; r.onerror=function(e){rej(e.target.error)}});} 
function idbGetAll(store){return new Promise(function(res,rej){var r=_tx(store,'readonly').getAll(); r.onsuccess=function(){res(r.result||[])}; r.onerror=function(e){rej(e.target.error)}});} 
function idbIndexAll(store,idx,val){return new Promise(function(res,rej){var i=_tx(store,'readonly').index(idx); var q=i.getAll(val); q.onsuccess=function(){res(q.result||[])}; q.onerror=function(e){rej(e.target.error)}});} 

/* ===================== Vault model (with optional at‑rest encryption) ===================== */
var vaultData={ bioIBAN:null, deviceKeyHash:'', credentialId:null, joinTimestamp:0, balanceSHE:0, caps:{dayKey:'',monthKey:'',yearKey:'',dayUsedSeg:0,monthUsedSeg:0,yearUsedSeg:0,tvmYearlyClaimed:0}, nextSegmentIndex:INITIAL_BALANCE_SHE+1, autoCopy:false, transactions:[] };
var _vaultKey=null; // CryptoKey for AES‑GCM when passphrase set

var VaultCrypto={ SALT_LABEL:'BioVault-v3',
  async deriveKey(passphrase){ var salt=new TextEncoder().encode(this.SALT_LABEL); var base=await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',salt:salt,iterations:310000,hash:'SHA-256'}, base, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']); },
  async encrypt(obj,key){ var iv=crypto.getRandomValues(new Uint8Array(12)); var pt=new TextEncoder().encode(JSON.stringify(obj)); var ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv}, key, pt); return { iv:Utils.toB64(iv), ct:Utils.toB64(new Uint8Array(ct)) }; },
  async decrypt(pack,key){ var iv=new Uint8Array(Utils.fromB64(pack.iv)); var ct=new Uint8Array(Utils.fromB64(pack.ct)); var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv}, key, ct); return JSON.parse(new TextDecoder().decode(new Uint8Array(pt))); }
};

async function loadVaultOnBoot(){ var rec=await idbGet(VAULT_STORE,'vaultDataEnc'); if(rec && rec.value){ // encrypted
    if(!_vaultKey){ return; } // cannot auto‑decrypt without passphrase
    try{ var dec=await VaultCrypto.decrypt(rec.value,_vaultKey); vaultData=dec; }catch(e){ _err('Vault decrypt failed', e); }
  } else { var plain=await idbGet(VAULT_STORE,'vaultData'); if(plain && plain.value){ vaultData=plain.value; } }
}

async function persistVault(){ if(_vaultKey){ var pack=await VaultCrypto.encrypt(vaultData,_vaultKey); await idbPut(VAULT_STORE,{key:'vaultDataEnc', value:pack}); } else { await idbPut(VAULT_STORE,{key:'vaultData', value:vaultData}); } }

/* ===================== Nullifiers & replays ===================== */
var Nullifiers={ async seen(z){var r=await idbGet(NULLIFIERS_STORE,z); return !!r;}, async add(z,meta){ return idbPut(NULLIFIERS_STORE,{z:z, meta:meta||{}, ts:Date.now()}); } };

/* ===================== Segments ===================== */
// segment record: { segmentIndex, currentOwner, previousOwner, originalOwner,
// ownershipChangeCount, unlocked, claimed, history:[{event,timestamp,from,to,bioConst,parent,integrityHash,counted,nonce?,nullifier?}] }
var Segments={ async get(i){return idbGet(SEGMENTS_STORE,i);}, async put(s){ // ring buffer cap
    if(Array.isArray(s.history) && s.history.length>SEGMENT_HISTORY_MAX) s.history=s.history.slice(-SEGMENT_HISTORY_MAX);
    return idbPut(SEGMENTS_STORE,s);
  }, async all(){return idbGetAll(SEGMENTS_STORE);}, async ownedBy(o){return idbIndexAll(SEGMENTS_STORE,'by_owner',o);}, async unlockedOwnedBy(o){var all=await idbIndexAll(SEGMENTS_STORE,'by_owner',o); return all.filter(function(x){return x.unlocked && !x.claimed;});} };

/* ===================== BioGuard (biometric gating) ===================== */
var BioGuard={ MAX_FAILS:3, LOCKOUT_SECONDS:3600,
  async check(){ var c=await idbGet(VAULT_STORE,'config'); var now=(Date.now()/1000)|0; if(c&&c.lockoutUntil&&now<c.lockoutUntil) return {ok:false,reason:'locked'}; return {ok:true}; },
  async fail(){ var c=await idbGet(VAULT_STORE,'config')||{key:'config'}; c.authFails=(c.authFails||0)+1; if(c.authFails>=this.MAX_FAILS){ c.lockoutUntil=((Date.now()/1000)|0)+this.LOCKOUT_SECONDS; c.authFails=0; } await idbPut(VAULT_STORE,c); },
  async pass(){ var c=await idbGet(VAULT_STORE,'config')||{key:'config'}; c.authFails=0; c.lockoutUntil=0; await idbPut(VAULT_STORE,c); }
};

var Biometric={ busy:false, async enroll(){ if(this.busy) return null; this.busy=true; try{ var cred=await navigator.credentials.create({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)), rp:{name:'BioVault',id:location.hostname}, user:{id:crypto.getRandomValues(new Uint8Array(16)), name:'user@biovault', displayName:'User'}, pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}], authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required'}, timeout:60000}}); if(!cred) return null; var b64u=btoa(String.fromCharCode.apply(null,new Uint8Array(cred.rawId))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); var c=await idbGet(VAULT_STORE,'config')||{key:'config'}; c.bioCredentialId=b64u; await idbPut(VAULT_STORE,c); return b64u; }catch(e){ _err('Enroll failed',e); return null; } finally{ this.busy=false; } }, async assert(){ if(this.busy) return false; this.busy=true; try{ var c=await idbGet(VAULT_STORE,'config'); if(!c||!c.bioCredentialId) return false; function b64uToU8(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; var bin=atob(s); var out=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; } var raw=b64uToU8(c.bioCredentialId); var ass=await navigator.credentials.get({ publicKey:{ challenge:crypto.getRandomValues(new Uint8Array(32)), allowCredentials:[{type:'public-key',id:raw}], userVerification:'required', timeout:60000 }}); return !!ass; }catch(e){ _err('Assertion failed',e); return false; } finally{ this.busy=false; } }, async zkp(){ if(this.busy) return null; this.busy=true; try{ var c=await idbGet(VAULT_STORE,'config'); if(!c||!c.bioCredentialId) return null; var raw=(function(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; var bin=atob(s); var out=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; })(c.bioCredentialId); var chal=crypto.getRandomValues(new Uint8Array(32)); var ass=await navigator.credentials.get({ publicKey:{ challenge:chal, allowCredentials:[{type:'public-key', id:raw}], userVerification:'required', timeout:60000 }}); if(!ass||!ass.response||!ass.response.signature) return null; var sigU8=new Uint8Array(ass.response.signature); var digest=await crypto.subtle.digest('SHA-256', sigU8); return '0x'+Array.from(new Uint8Array(digest)).map(function(b){return b.toString(16).padStart(2,'0');}).join(''); }catch(e){ _err('ZKP failed',e); return null; } finally{ this.busy=false; } }
};

/* ===================== Ethers wiring ===================== */
function ethersReady(){ return typeof ethers!=='undefined' && ethers.Contract; }
async function ensureEthers(){ if(ethersReady()) return; await new Promise(function(resolve,reject){ var s=document.createElement('script'); s.src='https://cdn.jsdelivr.net/npm/ethers@6.9.0/dist/ethers.umd.min.js'; s.onload=resolve; s.onerror=function(){reject(new Error('ethers.js failed to load'));}; document.head.appendChild(s); }); }

var EVM={ provider:null, signer:null, account:null, chainId:null, tvm:null,
  async connect(){ if(!window.ethereum) throw new Error('Install MetaMask'); await ensureEthers(); this.provider=new ethers.BrowserProvider(window.ethereum); await this.provider.send('eth_requestAccounts',[]); this.signer=await this.provider.getSigner(); this.account=(await this.signer.getAddress()); var net=await this.provider.getNetwork(); this.chainId=Number(net.chainId); if(this.chainId!==EXPECTED_CHAIN_ID) throw new Error('Wrong network'); this.tvm=new ethers.Contract(CONTRACT_ADDRESS.toLowerCase(), TVM_ABI, this.signer); return this.account; }
};

/* ===================== HPKE‑lite (ECDH P‑256 + HKDF → AES‑GCM) ===================== */
var HPKE={ async importP256PubJwk(jwk){ return crypto.subtle.importKey('jwk', jwk, {name:'ECDH',namedCurve:'P-256'}, true, []); }, async exportP256PubKey(key){ return crypto.subtle.exportKey('jwk', key); }, async generateEphemeral(){ return crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'}, true, ['deriveKey','deriveBits']); }, async deriveShared(priv,pub){ var bits=await crypto.subtle.deriveBits({name:'ECDH',public:pub}, priv, 256); return new Uint8Array(bits); } };
async function hkdfAesKey(shared, infoBytes, saltU8){ var base=await crypto.subtle.importKey('raw', shared, {name:'HKDF'}, false, ['deriveKey']); return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:saltU8,info:infoBytes}, base, {name:'AES-GCM',length:256}, true, ['encrypt','decrypt']); }
async function aesGcmEncrypt(key, iv, ptU8, aadU8){ return new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv,additionalData:aadU8}, key, ptU8)); }
async function aesGcmDecrypt(key, iv, ctU8, aadU8){ return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:iv,additionalData:aadU8}, key, ctU8)); }

// gzip helpers (await write)
async function gzipCompress(u8){ try{ if(typeof CompressionStream==='function'){ var cs=new CompressionStream('gzip'); var writer=cs.writable.getWriter(); await writer.write(u8); await writer.close(); var resp=new Response(cs.readable); var ab=await resp.arrayBuffer(); return new Uint8Array(ab); } }catch(e){} return u8; }
async function gzipDecompress(u8){ try{ if(typeof DecompressionStream==='function'){ var ds=new DecompressionStream('gzip'); var writer=ds.writable.getWriter(); await writer.write(u8); await writer.close(); var resp=new Response(ds.readable); var ab=await resp.arrayBuffer(); return new Uint8Array(ab); } }catch(e){} return u8; }

/* ===================== Helpers ===================== */
function segHash(prevHash,event,timestamp,from,to,bioConst,counted){ return Utils.sha256Hex(H_SEGMENT+prevHash+'|'+event+'|'+timestamp+'|'+from+'|'+to+'|'+bioConst+'|'+(counted?1:0)); }
function mkNullifier(segmentIndex,occAfter,parentHash){ return Utils.sha256Hex(H_NULLIFIER+segmentIndex+'|'+occAfter+'|'+parentHash); }
function utcDayKey(d){ var x=new Date(d); return x.getUTCFullYear()+"-"+String(x.getUTCMonth()+1).padStart(2,'0')+"-"+String(x.getUTCDate()).padStart(2,'0'); }
function utcMonthKey(d){ var x=new Date(d); return x.getUTCFullYear()+"-"+String(x.getUTCMonth()+1).padStart(2,'0'); }
function utcYearKey(d){ return String(new Date(d).getUTCFullYear()); }

function resetCapsIfNeeded(){ var now=Date.now(); var d=utcDayKey(now), m=utcMonthKey(now), y=utcYearKey(now); if(vaultData.caps.dayKey!==d){ vaultData.caps.dayKey=d; vaultData.caps.dayUsedSeg=0; } if(vaultData.caps.monthKey!==m){ vaultData.caps.monthKey=m; vaultData.caps.monthUsedSeg=0; } if(vaultData.caps.yearKey!==y){ vaultData.caps.yearKey=y; vaultData.caps.yearUsedSeg=0; vaultData.caps.tvmYearlyClaimed=0; } }
function canUnlock(n){ resetCapsIfNeeded(); if(vaultData.caps.dayUsedSeg+n>DAILY_CAP_SEG) return false; if(vaultData.caps.monthUsedSeg+n>MONTHLY_CAP_SEG) return false; if(vaultData.caps.yearUsedSeg+n>YEARLY_CAP_SEG) return false; return true; }
function recordUnlock(n){ resetCapsIfNeeded(); vaultData.caps.dayUsedSeg+=n; vaultData.caps.monthUsedSeg+=n; vaultData.caps.yearUsedSeg+=n; }

async function recomputeBalance(){ var all=await Segments.all(); var mine=all.filter(function(s){ return s.currentOwner===vaultData.bioIBAN && !s.claimed; }); vaultData.balanceSHE=mine.length; await persistVault(); }

/* ===================== Boot & genesis ===================== */
async function initGenesisIfNeeded(){ var conf=await idbGet(VAULT_STORE,'config'); if(conf){ await loadVaultOnBoot(); return; }
  // new vault: p256 keypair for P2P
  var kp=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'}, true, ['deriveKey','deriveBits']); var pubJwk=await crypto.subtle.exportKey('jwk',kp.publicKey); var privJwk=await crypto.subtle.exportKey('jwk',kp.privateKey);
  await idbPut(VAULT_STORE,{key:'p256Pub', jwk:pubJwk}); await idbPut(VAULT_STORE,{key:'p256Priv', jwk:privJwk});
  // Bio‑IBAN (0x random)
  var rnd='0x'+await Utils.sha256Hex(Math.random().toString()); vaultData.bioIBAN=rnd; vaultData.joinTimestamp=Date.now(); vaultData.deviceKeyHash='0x'+await Utils.sha256Hex('Balance-Chain-v3-PRD:'+rnd);
  vaultData.balanceSHE=INITIAL_BALANCE_SHE;
  await persistVault();
  await idbPut(VAULT_STORE,{key:'config', createdAt:Date.now(), ethereumAddress:null, bioCredentialId:null, lockoutUntil:0, authFails:0});
  // deterministic mint + unlock for 1..1200
  var now=Date.now();
  for(var i=1;i<=INITIAL_BALANCE_SHE;i++){
    var parent='0x'+await Utils.sha256Hex('genesis|'+i+'|'+vaultData.bioIBAN);
    var mintHash='0x'+await Utils.sha256Hex(H_SEGMENT+parent+'|Mint|'+now+'|'+vaultData.bioIBAN+'|Locked|'+(GENESIS_BIO_CONSTANT+i)+'|1');
    var unlockHash='0x'+await Utils.sha256Hex(H_SEGMENT+mintHash+'|Unlock|'+(now+1)+'|Locked|'+vaultData.bioIBAN+'|'+(GENESIS_BIO_CONSTANT+i+1)+'|0');
    var seg={ segmentIndex:i, currentOwner:vaultData.bioIBAN, previousOwner:vaultData.bioIBAN, originalOwner:vaultData.bioIBAN, ownershipChangeCount:1, unlocked:true, claimed:false, history:[ {event:'Mint',timestamp:now,from:vaultData.bioIBAN,to:'Locked',bioConst:GENESIS_BIO_CONSTANT+i,parent:parent,integrityHash:mintHash,counted:true}, {event:'Unlock',timestamp:now+1,from:'Locked',to:vaultData.bioIBAN,bioConst:GENESIS_BIO_CONSTANT+i+1,parent:mintHash,integrityHash:unlockHash,counted:false} ] };
    await Segments.put(seg);
  }
}

/* ===================== Recipient key resolver ===================== */
async function saveRecipientKey(identity, jwk){ if(!identity||!jwk) throw new Error('Missing identity/JWK'); await idbPut(CONTACTS_STORE,{id:identity, jwk:jwk}); }
async function resolveRecipientKey(identity){ if(!identity) throw new Error('Missing recipient'); var rec=await idbGet(CONTACTS_STORE, identity); if(rec&&rec.jwk) return rec.jwk; if(identity.indexOf('p256:')===0){ var parts=identity.slice(5).split('.'); if(parts.length===2){ return {kty:'EC', crv:'P-256', x:parts[0], y:parts[1], ext:true}; } } throw new Error('Unknown recipient key; add via saveRecipientKey(...)'); }

/* ===================== Range packing ===================== */
function packEntries(segs){ // compact entries for transport
  segs.sort(function(a,b){return a.segmentIndex-b.segmentIndex});
  return segs.map(function(s){ return {i:s.segmentIndex,p:s._parent,o:s._occAfter,h:s._integrityHash,b:s._bioConst,z:s._nullifier}; });
}
function unpackEntries(arr){ return (arr||[]).map(function(e){ return {segmentIndex:e.i,_parent:e.p,_occAfter:e.o,_integrityHash:e.h,_bioConst:e.b,_nullifier:e.z}; }); }

/* ===================== P2P ===================== */
var P2P={
  async prepareSend(recipientIdentity, amountSegments, memo){ amountSegments=(amountSegments|0); if(!(amountSegments>0)) throw new Error('Invalid amount'); if(amountSegments>MAX_TRANSFER_SEGMENTS) throw new Error('Transfer too large');
    // biometric proof gate
    var ok=await Biometric.assert(); if(!ok) throw new Error('Biometric verification required');
    var owner=vaultData.bioIBAN; var mine=await Segments.unlockedOwnedBy(owner); if(mine.length<amountSegments) throw new Error('Insufficient unlocked segments');
    var chosen=mine.slice(0,amountSegments);
    var now=Date.now(); var bodySegs=[]; var zList=[];
    for(var k=0;k<chosen.length;k++){
      var s=chosen[k]; var last=s.history[s.history.length-1]; var occAfter=(s.ownershipChangeCount|0)+1; var parent=last.integrityHash;
      var integ='0x'+await Utils.sha256Hex(H_SEGMENT+parent+'|Transfer|'+now+'|'+s.currentOwner+'|'+recipientIdentity+'|'+(last.bioConst+BIO_STEP)+'|1');
      var z='0x'+await mkNullifier(s.segmentIndex,occAfter,parent);
      // mutate sender state once
      s.previousOwner=s.currentOwner; s.currentOwner=recipientIdentity; s.ownershipChangeCount=occAfter; s.unlocked=true;
      s.history.push({event:'Transfer', timestamp:now, from:s.previousOwner, to:recipientIdentity, bioConst:last.bioConst+BIO_STEP, parent:parent, integrityHash:integ, counted:true, nullifier:z});
      await Segments.put(s); await Nullifiers.add(z,{segmentIndex:s.segmentIndex, from:s.previousOwner, to:recipientIdentity});
      bodySegs.push({ segmentIndex:s.segmentIndex, _parent:parent, _integrityHash:integ, _bioConst:last.bioConst+BIO_STEP, _occAfter:occAfter, _nullifier:z });
      zList.push(z);
    }
    // cascade unlock
    var created=await unlockNextSegments(amountSegments); if(created<amountSegments){ _log('Auto‑unlock partial due to caps'); }
    // encrypt to recipient
    var recipJwk=await resolveRecipientKey(recipientIdentity);
    var recipPub=await HPKE.importP256PubJwk(recipJwk);
    var eph=await HPKE.generateEphemeral(); var eJwk=await HPKE.exportP256PubKey(eph.publicKey);
    var shared=await HPKE.deriveShared(eph.privateKey, recipPub);
    var salt=crypto.getRandomValues(new Uint8Array(32)); var info=new TextEncoder().encode(H_AAD+P2P_SCHEMA);
    var aesKey=await hkdfAesKey(shared, info, salt);
    // header (CBOR) + AAD
    var header={ v:P2P_VERSION, schema:P2P_SCHEMA, from:owner, to:recipientIdentity, t:now, nonce:Utils.randomNonce(), e:eJwk, s:Utils.toB64(salt), count:bodySegs.length, z:zList };
    var headerCbor=CBOR.encode(header);
    var entries=packEntries(bodySegs);
    var bodyCbor=CBOR.encode({ entries:entries, memo:memo||'' });
    var gz=await gzipCompress(bodyCbor);
    var iv=crypto.getRandomValues(new Uint8Array(12)); var ct=await aesGcmEncrypt(aesKey, iv, gz, headerCbor);
    await persistVault(); await recomputeBalance();
    return { header:Utils.toB64(headerCbor), iv:Utils.toB64(iv), body:Utils.toB64(ct) };
  },
  async receiveApply(payload){ var gate=await Biometric.assert(); if(!gate) throw new Error('Biometric verification required');
    var headerU8=new Uint8Array(Utils.fromB64(payload.header)); var header=CBOR.decode(headerU8);
    // replay by nonce
    var seen=await idbGet(REPLAYS_STORE, header.nonce); if(seen) throw new Error('Replay (nonce)'); await idbPut(REPLAYS_STORE,{nonce:header.nonce, ts:Date.now()});
    // derive shared
    var privRec=await idbGet(VAULT_STORE,'p256Priv'); var priv=await crypto.subtle.importKey('jwk', privRec.jwk, {name:'ECDH',namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
    var ePub=await HPKE.importP256PubJwk(header.e); var shared=await crypto.subtle.deriveBits({name:'ECDH',public:ePub}, priv, 256).then(function(bits){return new Uint8Array(bits)});
    var salt=new Uint8Array(Utils.fromB64(header.s)); var info=new TextEncoder().encode(H_AAD+P2P_SCHEMA); var aesKey=await hkdfAesKey(shared,info,salt);
    var iv=new Uint8Array(Utils.fromB64(payload.iv)); var ct=new Uint8Array(Utils.fromB64(payload.body));
    var gz=await aesGcmDecrypt(aesKey, iv, ct, headerU8); var body=CBOR.decode(await gzipDecompress(gz));
    var segs=unpackEntries(body.entries||[]); var applied=0, rejected=0;
    for(var i=0;i<segs.length;i++){
      var ent=segs[i]; if(await Nullifiers.seen(ent._nullifier)){ rejected++; continue; }
      var local=await Segments.get(ent.segmentIndex);
      if(local){ var last=local.history[local.history.length-1]; if(last.integrityHash!==ent._parent){ var keep=P2P.resolveConflict(local, ent, header); if(!keep){ rejected++; continue; } } }
      var integR='0x'+await Utils.sha256Hex(H_SEGMENT+ent._integrityHash+'|Received|'+header.t+'|'+header.from+'|'+header.to+'|'+(ent._bioConst+BIO_STEP)+'|0');
      var seg=local||{ segmentIndex:ent.segmentIndex, originalOwner:header.from, previousOwner:null, currentOwner:null, ownershipChangeCount:ent._occAfter, unlocked:true, claimed:false, history:[] };
      seg.previousOwner=header.from; seg.currentOwner=header.to; seg.ownershipChangeCount=ent._occAfter;
      seg.history.push({event:'Received', timestamp:header.t, from:header.from, to:header.to, bioConst:ent._bioConst+BIO_STEP, parent:ent._integrityHash, integrityHash:integR, counted:false, nonce:header.nonce, nullifier:ent._nullifier});
      await Segments.put(seg); await Nullifiers.add(ent._nullifier,{segmentIndex:seg.segmentIndex, from:header.from, to:header.to}); applied++;
    }
    if(applied>0){ await unlockNextSegments(applied); }
    await persistVault(); await recomputeBalance();
    return { applied:applied, rejected:rejected };
  },
  resolveConflict(localSeg, incomingEnt, header){ var localLast=localSeg.history[localSeg.history.length-1]; var tLocal=localLast.timestamp||0, tIn=header.t||0; if(tIn<tLocal) return true; if(tIn>tLocal) return false; var nLocal=(localLast.nonce||'~'); var nIn=header.nonce||''; if(nIn<nLocal) return true; if(nIn>nLocal) return false; return (incomingEnt._nullifier < (localLast.nullifier||'~')); }
};

/* ===================== Unlock (cascade) ===================== */
async function unlockNextSegments(count){ if(count<=0) return 0; if(!canUnlock(count)) return 0; var created=0; var now=Date.now(); for(var k=0;k<count;k++){ var idx=vaultData.nextSegmentIndex; if(idx> LAYERS*SEGMENTS_PER_LAYER) break; var parent='0x'+await Utils.sha256Hex('genesis|'+idx+'|'+vaultData.bioIBAN); var mintHash='0x'+await Utils.sha256Hex(H_SEGMENT+parent+'|Mint|'+now+'|'+vaultData.bioIBAN+'|Locked|'+(GENESIS_BIO_CONSTANT+idx)+'|1'); var unlockHash='0x'+await Utils.sha256Hex(H_SEGMENT+mintHash+'|Unlock|'+(now+1)+'|Locked|'+vaultData.bioIBAN+'|'+(GENESIS_BIO_CONSTANT+idx+1)+'|0'); var seg={ segmentIndex:idx, currentOwner:vaultData.bioIBAN, previousOwner:vaultData.bioIBAN, originalOwner:vaultData.bioIBAN, ownershipChangeCount:1, unlocked:true, claimed:false, history:[ {event:'Mint',timestamp:now,from:vaultData.bioIBAN,to:'Locked',bioConst:GENESIS_BIO_CONSTANT+idx,parent:parent,integrityHash:mintHash,counted:true}, {event:'Unlock',timestamp:now+1,from:'Locked',to:vaultData.bioIBAN,bioConst:GENESIS_BIO_CONSTANT+idx+1,parent:mintHash,integrityHash:unlockHash,counted:false} ] }; await Segments.put(seg); vaultData.nextSegmentIndex=idx+1; created++; } if(created>0){ recordUnlock(created); await persistVault(); } return created; }

/* ===================== On‑chain claim ===================== */
async function buildMintProofsForOcc1(needSeg){ // choose unlocked, occ==1
  var all=await Segments.all(); var pool=[]; for(var i=0;i<all.length;i++){ var s=all[i]; if(s.claimed) continue; if((s.ownershipChangeCount|0)===1 && s.originalOwner===vaultData.bioIBAN && s.previousOwner===vaultData.bioIBAN){ pool.push(s); if(pool.length===needSeg) break; } }
  if(pool.length<needSeg) throw new Error('Not enough occ==1 segments');
  var proofs=[]; // contract expects flattened chains
  for(var k=0;k<pool.length;k++){ var s=pool[k]; var last=s.history[s.history.length-1]; var segmentIndex=s.segmentIndex; var currentBioConst=last.bioConst; var ownershipProof='0x'+await Utils.sha256Hex(String(currentBioConst)); var unlockIntegrityProof=ownershipProof; var spentProof='0x'+await Utils.sha256Hex(vaultData.deviceKeyHash+'|'+segmentIndex+'|'+Date.now()); var biometricZKP=await Biometric.zkp(); if(!biometricZKP) throw new Error('Missing biometric ZKP'); proofs.push({ segmentIndex:segmentIndex, currentBioConst:currentBioConst, ownershipProof:ownershipProof, unlockIntegrityProof:unlockIntegrityProof, spentProof:spentProof, ownershipChangeCount:1, biometricZKP:biometricZKP }); }
  return { proofs:proofs, used:pool };
}

async function claimTVM_onchain(tvmCount){ tvmCount=(tvmCount|0)||1; resetCapsIfNeeded(); if(vaultData.caps.tvmYearlyClaimed + tvmCount > (YEARLY_CAP_TVM + EXTRA_BONUS_TVM)) throw new Error('Yearly TVM cap reached'); var needSeg=tvmCount*SEGMENTS_PER_TVM; var pack=await buildMintProofsForOcc1(needSeg);
  await ensureEthers(); if(!EVM.tvm) await EVM.connect();
  // Build EIP‑712 claim per contract
  var coder=new ethers.AbiCoder(); var inner=pack.proofs.map(function(p){ return ethers.keccak256(coder.encode(['uint256','uint256','bytes32','bytes32','bytes32','uint256','bytes32'], [p.segmentIndex,p.currentBioConst,p.ownershipProof,p.unlockIntegrityProof,p.spentProof,p.ownershipChangeCount,p.biometricZKP])); }); var proofsHash=ethers.keccak256(coder.encode(['bytes32[]'],[inner]));
  var deviceKeyHash=vaultData.deviceKeyHash; var userBioConstant=pack.proofs[0]?pack.proofs[0].currentBioConst:GENESIS_BIO_CONSTANT; var nonce=(Math.floor(Math.random()*0xFFFFFFFF)>>>0);
  var domain={ name:'TVM', version:'1', chainId:Number(EVM.chainId||EXPECTED_CHAIN_ID), verifyingContract:CONTRACT_ADDRESS.toLowerCase() };
  var types={ Claim:[ {name:'user',type:'address'},{name:'proofsHash',type:'bytes32'},{name:'deviceKeyHash',type:'bytes32'},{name:'userBioConstant',type:'uint256'},{name:'nonce',type:'uint256'} ]};
  var value={ user:EVM.account, proofsHash:proofsHash, deviceKeyHash:deviceKeyHash, userBioConstant:userBioConstant, nonce:nonce };
  var signature=await EVM.signer.signTypedData(domain,types,value);
  // double biometric right before sending
  var ok=await Biometric.assert(); if(!ok) throw new Error('Biometric verification required');
  var tx=await EVM.tvm.claimTVM(pack.proofs, signature, deviceKeyHash, userBioConstant, nonce);
  await tx.wait();
  // mark used segments as claimed
  for(var i=0;i<pack.used.length;i++){ var s=pack.used[i]; var last=s.history[s.history.length-1]; var ts=Date.now(); var integ='0x'+await Utils.sha256Hex(H_SEGMENT+last.integrityHash+'|Claimed|'+ts+'|'+vaultData.bioIBAN+'|OnChain|'+(last.bioConst+1)+'|0'); s.claimed=true; s.history.push({event:'Claimed', timestamp:ts, from:vaultData.bioIBAN, to:'OnChain', bioConst:last.bioConst+1, parent:last.integrityHash, integrityHash:integ, counted:false}); await Segments.put(s); }
  vaultData.caps.tvmYearlyClaimed+=tvmCount; await persistVault(); await recomputeBalance();
  return { tx:tx.hash, tvm:tvmCount, segments:needSeg };
}

/* ===================== Public API ===================== */
var BioVault={
  // lifecycle
  async init(){ await openDB(); await initGenesisIfNeeded(); await loadVaultOnBoot(); return true; },
  async setVaultPassphrase(pass){ _vaultKey=await VaultCrypto.deriveKey(pass); var plain=await idbGet(VAULT_STORE,'vaultData'); if(plain && plain.value){ await idbPut(VAULT_STORE,{key:'vaultData', value:null}); } await persistVault(); return true; },
  // identity + biometrics
  async enrollBiometric(){ return Biometric.enroll(); }, async biometricAssert(){ return Biometric.assert(); }, async biometricZKP(){ return Biometric.zkp(); },
  // contacts / resolver
  async saveRecipientKey(id,jwk){ return saveRecipientKey(id,jwk); },
  // p2p
  async p2pPrepareSend(recipientIdentity,n,memo){ return P2P.prepareSend(recipientIdentity,n|0,memo||''); },
  async p2pReceiveApply(payload){ return P2P.receiveApply(payload); },
  // unlock & claim
  async unlockNext(n){ return unlockNextSegments(n|0); },
  async claimTVM(n){ return claimTVM_onchain(n|0); },
  // misc
  async myIdentity(){ var pub=await idbGet(VAULT_STORE,'p256Pub'); return 'p256:'+pub.jwk.x+'.'+pub.jwk.y; }
};
window.BioVault=BioVault;

/* ===================== Boot ===================== */
BioVault.init().then(function(){ _log('BioVault ready'); }).catch(function(e){ _err('Init failed', e&&e.message?e.message:e); });
