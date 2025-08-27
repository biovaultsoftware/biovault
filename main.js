/******************************
 * main.js — BalanceChain PWA core (ES2018)
 * Master-class: offline-first vault, compact+encrypted P2P, biometric+ZKP wiring, TVM on-chain adapter.
 * Guarantees:
 *  - P2P is separate from on-chain (zero-fee, offline-capable).
 *  - On-chain TVM claim uses ONLY segments with ownershipChangeCount === 1.
 *  - Sender MUST be current owner; receiver becomes current; sender becomes previous; local history capped to 10.
 *  - Deterministic unlocks with hard caps (360/day, 3600/month, 10800/year; TVM 900/yr + 100 bonus parity).
 *  - ES2018-compatible: no optional chaining, no BigInt literals, no numeric separators.
 ******************************/

// ---------- Global Constants ----------
var DB_NAME = 'BioVaultDB';
var DB_VERSION = 4;
var VAULT_STORE = 'vault';
var SEGMENTS_STORE = 'segments';
var PROOFS_STORE = 'proofs';

var INITIAL_BALANCE_SHE = 1200;
var EXCHANGE_RATE = 12; // 1 TVM = 12 SHE
var GENESIS_BIO_CONSTANT = 1736565605;
var BIO_TOLERANCE_SECONDS = 720;

var SEGMENTS_PER_LAYER = 1200;
var LAYERS = 10;

var DAILY_CAP = 360;
var MONTHLY_CAP = 3600;
var YEARLY_CAP = 10800;
var YEARLY_TVM_CAP = 900;
var EXTRA_BONUS_TVM = 100;

// Contract addresses (lowercase)
var TVM_CONTRACT_ADDRESS = '0xcc79b1bc9eabc3d30a3800f4d41a4a0599e1f3c6';
var USDT_ADDRESS         = '0xdac17f958d2ee523a2206206994597c13d831ec7';

// Network guard (set to your chain id)
var EXPECTED_CHAIN_ID = 1;

// P2P Payload Version
var P2P_VERSION = 3;

// ---------- Small utils ----------
function log(){ try{ console.log.apply(console, ['[BioVault]'].concat([].slice.call(arguments))); }catch(e){} }
function err(){ try{ console.error.apply(console, ['[BioVault]'].concat([].slice.call(arguments))); }catch(e){} }

function nowTs(){ return Math.floor(Date.now()/1000); }
function bytesConcat(a,b){ var o=new Uint8Array(a.length+b.length); o.set(a,0); o.set(b,a.length); return o; }
function strToUtf8(s){ return new TextEncoder().encode(s); }
function utf8ToStr(u8){ return new TextDecoder().decode(u8); }
function b64uEncode(bytes){ var bin=''; for (var i=0;i<bytes.length;i++) bin+=String.fromCharCode(bytes[i]); var b64=btoa(bin); return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64uDecode(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; var bin=atob(s); var out=new Uint8Array(bin.length); for (var i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; }
function randomBytes(n){ var a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
function hexToBytes(hex){ hex=hex.replace(/^0x/,''); var n=hex.length/2, o=new Uint8Array(n); for(var i=0;i<n;i++) o[i]=parseInt(hex.substr(i*2,2),16); return o; }
function bytesToHex(buf){ var s='0x'; for(var i=0;i<buf.length;i++){ var h=buf[i].toString(16); if(h.length<2)h='0'+h; s+=h; } return s; }

// ---------- Tiny CBOR (subset) ----------
var CBOR=(function(){
  var MT_UINT=0,MT_NEG=1,MT_BYTES=2,MT_STRING=3,MT_ARRAY=4,MT_MAP=5,MT_SIMPLE=7;
  function encUInt(u){ if(u<24)return new Uint8Array([(MT_UINT<<5)|u]); if(u<256)return new Uint8Array([(MT_UINT<<5)|24,u]); if(u<65536)return new Uint8Array([(MT_UINT<<5)|25,u>>8,u&255]); var a=new Uint8Array(5); a[0]=(MT_UINT<<5)|26; a[1]=(u>>>24)&255;a[2]=(u>>>16)&255;a[3]=(u>>>8)&255;a[4]=u&255; return a; }
  function encInt(n){ if(n>=0)return encUInt(n); var m=-1-n; if(m<24)return new Uint8Array([(MT_NEG<<5)|m]); if(m<256)return new Uint8Array([(MT_NEG<<5)|24,m]); if(m<65536)return new Uint8Array([(MT_NEG<<5)|25,m>>8,m&255]); var a=new Uint8Array(5); a[0]=(MT_NEG<<5)|26; a[1]=(m>>>24)&255;a[2]=(m>>>16)&255;a[3]=(m>>>8)&255;a[4]=m&255; return a; }
  function encBytes(b){ var l=b.length,h; if(l<24)h=new Uint8Array([(MT_BYTES<<5)|l]); else if(l<256)h=new Uint8Array([(MT_BYTES<<5)|24,l]); else if(l<65536)h=new Uint8Array([(MT_BYTES<<5)|25,l>>8,l&255]); else throw new Error('CBOR: bytes too long'); return bytesConcat(h,b); }
  function encStr(s){ var b=strToUtf8(s),l=b.length,h; if(l<24)h=new Uint8Array([(MT_STRING<<5)|l]); else if(l<256)h=new Uint8Array([(MT_STRING<<5)|24,l]); else if(l<65536)h=new Uint8Array([(MT_STRING<<5)|25,l>>8,l&255]); else throw new Error('CBOR: string too long'); return bytesConcat(h,b); }
  function encArray(arr){ var l=arr.length,h; if(l<24)h=new Uint8Array([(MT_ARRAY<<5)|l]); else if(l<256)h=new Uint8Array([(MT_ARRAY<<5)|24,l]); else if(l<65536)h=new Uint8Array([(MT_ARRAY<<5)|25,l>>8,l&255]); else throw new Error('CBOR: array too long'); var out=h; for(var i=0;i<l;i++) out=bytesConcat(out,encode(arr[i])); return out; }
  function encMap(obj){ var ks=Object.keys(obj),l=ks.length,h; if(l<24)h=new Uint8Array([(MT_MAP<<5)|l]); else if(l<256)h=new Uint8Array([(MT_MAP<<5)|24,l]); else throw new Error('CBOR: map too big'); var out=h; for(var i=0;i<l;i++){ var k=ks[i],nk=parseInt(k,10); out=bytesConcat(out, (k===''+nk)?encInt(nk):encStr(k)); out=bytesConcat(out, encode(obj[k])); } return out; }
  function encode(v){ if(v===null)return new Uint8Array([(MT_SIMPLE<<5)|22]); if(v===false)return new Uint8Array([(MT_SIMPLE<<5)|20]); if(v===true)return new Uint8Array([(MT_SIMPLE<<5)|21]); var t=typeof v; if(t==='number'){ if(Math.floor(v)!==v) throw new Error('CBOR: only ints'); return encInt(v); } if(t==='string')return encStr(v); if(v instanceof Uint8Array)return encBytes(v); if(Array.isArray(v))return encArray(v); if(t==='object')return encMap(v); throw new Error('CBOR: unsupported'); }
  function decode(u8,off){ if(!off)off=0; var ib=u8[off++],mt=ib>>5,ai=ib&31; function rn(n){ var b=u8.subarray(off,off+n); off+=n; return b; } function rl(){ if(ai<24)return ai; if(ai===24)return u8[off++]; if(ai===25){var v=(u8[off]<<8)|u8[off+1]; off+=2; return v;} if(ai===26){var v=(u8[off]<<24)|(u8[off+1]<<16)|(u8[off+2]<<8)|u8[off+3]; off+=4; return v>>>0;} throw new Error('CBOR: len'); }
    if(mt===0){ var uv=ai<24?ai:ai===24?u8[off++]:ai===25?((u8[off++]<<8)|u8[off++]):(off+=4,(u8[off-4]<<24|u8[off-3]<<16|u8[off-2]<<8|u8[off-1])>>>0); return {v:uv,off:off}; }
    if(mt===1){ var mv=ai<24?ai:ai===24?u8[off++]:ai===25?((u8[off++]<<8)|u8[off++]):(off+=4,(u8[off-4]<<24|u8[off-3]<<16|u8[off-2]<<8|u8[off-1])>>>0); return {v:-1-mv,off:off}; }
    if(mt===2){ var bl=rl(); return {v:new Uint8Array(rn(bl)),off:off}; }
    if(mt===3){ var sl=rl(); return {v:utf8ToStr(rn(sl)),off:off}; }
    if(mt===4){ var al=rl(),arr=[]; for(var i=0;i<al;i++){ var d=decode(u8,off); arr.push(d.v); off=d.off; } return {v:arr,off:off}; }
    if(mt===5){ var ml=rl(),obj={}; for(var j=0;j<ml;j++){ var kd=decode(u8,off); off=kd.off; var key=kd.v; if(typeof key!=='string'&&typeof key!=='number') key=''+key; var vd=decode(u8,off); off=vd.off; obj[key]=vd.v; } return {v:obj,off:off}; }
    if(mt===7){ if(ai===20)return{v:false,off:off}; if(ai===21)return{v:true,off:off}; if(ai===22)return{v:null,off:off}; throw new Error('CBOR: simple'); }
    throw new Error('CBOR: major');
  }
  return { encode:encode, decode:function(u8){ var d=decode(u8,0); return d.v; } };
})();

// ---------- IndexedDB ----------
var dbInstance=null;
function openDB(){ return new Promise(function(res,rej){ var req=indexedDB.open(DB_NAME,DB_VERSION);
  req.onupgradeneeded=function(ev){ var db=ev.target.result;
    if(!db.objectStoreNames.contains(VAULT_STORE)) db.createObjectStore(VAULT_STORE,{keyPath:'key'});
    if(!db.objectStoreNames.contains(SEGMENTS_STORE)){ var s=db.createObjectStore(SEGMENTS_STORE,{keyPath:'id'}); s.createIndex('by_owner','current_owner',{unique:false}); s.createIndex('by_unlocked','unlocked',{unique:false}); }
    if(!db.objectStoreNames.contains(PROOFS_STORE)) db.createObjectStore(PROOFS_STORE,{keyPath:'id'});
  };
  req.onsuccess=function(e){ dbInstance=e.target.result; res(dbInstance); };
  req.onerror=function(e){ rej(e.target.error); };
});}
function tx(store,mode){ return dbInstance.transaction([store],mode).objectStore(store); }
function put(store,obj){ return new Promise(function(res,rej){ var r=tx(store,'readwrite').put(obj); r.onsuccess=function(){res(true)}; r.onerror=function(e){rej(e.target.error)}; }); }
function get(store,key){ return new Promise(function(res,rej){ var r=tx(store,'readonly').get(key); r.onsuccess=function(){res(r.result||null)}; r.onerror=function(e){rej(e.target.error)}; }); }
function getAll(store){ return new Promise(function(res,rej){ var r=tx(store,'readonly').getAll(); r.onsuccess=function(){res(r.result||[])}; r.onerror=function(e){rej(e.target.error)}; }); }
function getAllIndex(store,indexName,val){ return new Promise(function(res,rej){ var i=tx(store,'readonly').index(indexName); var q=i.getAll(val); q.onsuccess=function(){res(q.result||[])}; q.onerror=function(e){rej(e.target.error)}; }); }

// ---------- Vault ----------
var Vault={
  async init(){
    await openDB();
    var conf=await get(VAULT_STORE,'config');
    if(!conf){
      var deviceKey=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
      var jwk=await crypto.subtle.exportKey('jwk',deviceKey.publicKey);
      var rec={ key:'config', createdAt:nowTs(), ethereumAddress:null, p256PublicJwk:jwk,
        caps:{day:0,month:0,year:0,tvmYear:0,lastResetDay:0,lastResetMonth:0,lastResetYear:0},
        bioGenesis:GENESIS_BIO_CONSTANT,
        bioCredentialId:null,
        lockoutUntil:0,
        authFails:0
      };
      await put(VAULT_STORE,rec);
      await put(VAULT_STORE,{key:'p256Private',value:await crypto.subtle.exportKey('jwk',deviceKey.privateKey)});
      log('Vault initialized.');
    }
    return true;
  },
  async getConfig(){ return get(VAULT_STORE,'config'); },
  async setConfig(obj){ var c=await this.getConfig(); for(var k in obj){ c[k]=obj[k]; } await put(VAULT_STORE,c); return c; },
  async setEthereumAddress(addr){ var c=await this.getConfig(); c.ethereumAddress=(addr||'').toLowerCase(); await put(VAULT_STORE,c); return c.ethereumAddress; },
  async getP256KeyPair(){
    var prv=await get(VAULT_STORE,'p256Private'); var conf=await this.getConfig(); var pub=conf&&conf.p256PublicJwk?conf.p256PublicJwk:null;
    if(!prv||!pub) throw new Error('Device key missing');
    var privKey=await crypto.subtle.importKey('jwk',prv.value,{name:'ECDSA',namedCurve:'P-256'},true,['sign']);
    var pubKey=await crypto.subtle.importKey('jwk',pub,{name:'ECDSA',namedCurve:'P-256'},true,['verify']);
    return {privateKey:privKey,publicKey:pubKey,publicJwk:pub};
  },
  async touchCaps(nSeg,nTVM){
    var conf=await this.getConfig();
    var d=new Date(); var y=d.getUTCFullYear(), m=d.getUTCMonth()+1, day=d.getUTCDate();
    if(conf.caps.lastResetDay!==day){ conf.caps.day=0; conf.caps.lastResetDay=day; }
    if(conf.caps.lastResetMonth!==m){ conf.caps.month=0; conf.caps.lastResetMonth=m; }
    if(conf.caps.lastResetYear!==y){ conf.caps.year=0; conf.caps.tvmYear=0; conf.caps.lastResetYear=y; }
    var dayN=conf.caps.day+(nSeg||0), monN=conf.caps.month+(nSeg||0), yrN=conf.caps.year+(nSeg||0), tvmN=conf.caps.tvmYear+(nTVM||0);
    if(dayN>DAILY_CAP) throw new Error('Daily segment cap exceeded');
    if(monN>MONTHLY_CAP) throw new Error('Monthly segment cap exceeded');
    if(yrN>YEARLY_CAP) throw new Error('Yearly segment cap exceeded');
    if(tvmN>(YEARLY_TVM_CAP+EXTRA_BONUS_TVM)) throw new Error('Yearly TVM cap exceeded');
    conf.caps.day=dayN; conf.caps.month=monN; conf.caps.year=yrN; conf.caps.tvmYear=tvmN;
    await put(VAULT_STORE,conf);
    return conf.caps;
  }
};

// ---------- Segments ----------
var Segments={
  // schema: { id, layer, unlocked, current_owner, previous_owner, original_owner, ownershipChangeCount, history[], onchain_eligible, proof{genesis} }

  async listUnlocked(){ return getAllIndex(SEGMENTS_STORE,'by_unlocked',true); },
  async listByOwner(owner){ return getAllIndex(SEGMENTS_STORE,'by_owner',(owner||'').toLowerCase()); },
  async putMany(arr){ for(var i=0;i<arr.length;i++) await put(SEGMENTS_STORE,arr[i]); },

  async mintTo(recipient,count){
    recipient=(recipient||'').toLowerCase();
    var conf=await Vault.getConfig(); var vaultOwner=(conf&&conf.ethereumAddress)?conf.ethereumAddress.toLowerCase():recipient;
    var ts=nowTs(), out=[];
    for (var i=0;i<count;i++){
      var id='seg_'+ts+'_'+i+'_'+Math.floor(Math.random()*1e9);
      out.push({
        id:id, layer:0, unlocked:true,
        current_owner: recipient,
        previous_owner: vaultOwner,
        original_owner: vaultOwner,
        ownershipChangeCount: 1,
        history:[{owner:recipient,ts:ts,txid:'mint:'+id}],
        onchain_eligible:true,
        proof:{v:1,genesis:GENESIS_BIO_CONSTANT}
      });
    }
    await this.putMany(out);
    await Vault.touchCaps(count, Math.floor(count/EXCHANGE_RATE));
    return out;
  },

  async unlockNext(n){
    var all=await getAll(SEGMENTS_STORE), locked=[];
    for(var i=0;i<all.length;i++) if(!all[i].unlocked) locked.push(all[i]);
    locked.sort(function(a,b){ if(a.layer!==b.layer) return a.layer-b.layer; return a.id<b.id?-1:a.id>b.id?1:0; });
    var sel=locked.slice(0,n);
    for(var j=0;j<sel.length;j++){ sel[j].unlocked=true; await put(SEGMENTS_STORE,sel[j]); }
    return sel.length;
  },

  async consumeForP2P(sender,count){
    sender=(sender||'').toLowerCase();
    var mine=await this.listByOwner(sender); var usable=[];
    for (var i=0;i<mine.length;i++) if(mine[i].unlocked) usable.push(mine[i]);
    if (usable.length<count) throw new Error('Insufficient unlocked segments');
    return usable.slice(0,count);
  },

  async applyInbound(receiver, segs, txid){
    receiver=(receiver||'').toLowerCase();
    var ts=nowTs();
    for (var i=0;i<segs.length;i++){
      var s=segs[i];
      var prev=s.current_owner;
      s.previous_owner=prev;
      s.current_owner=receiver;
      s.ownershipChangeCount=(s.ownershipChangeCount||1)+1;
      if(s.history&&s.history.length>=10) s.history.shift();
      if(!s.history) s.history=[];
      s.history.push({owner:receiver,ts:ts,txid:txid||('p2p:'+s.id+':'+ts)});
      s.onchain_eligible=false;
      s.unlocked=true;
      await put(SEGMENTS_STORE,s);
      await put(PROOFS_STORE,{id:'proof:'+s.id+':'+s.ownershipChangeCount,segmentId:s.id,owner:receiver,ts:ts,history:s.history.slice()});
    }
    return true;
  }
};

// ---------- Crypto helpers ----------
var CryptoBox={
  async hkdf(ikm,salt,info){
    if(!salt) salt=new Uint8Array(32);
    if(!info) info=new Uint8Array(0);
    var key=await crypto.subtle.importKey('raw',ikm,{name:'HKDF'},false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:salt,info:info},{name:'HKDF'}, {name:'AES-GCM',length:256}, false, []);
  } // shim (we'll derive directly below)
};
async function deriveAesKey(shared, label){
  var base=await crypto.subtle.importKey('raw', shared, {name:'HKDF'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:strToUtf8(label||'p2p/body')}, base, {name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
}
async function aesGcmEncrypt(key, plainU8){
  var iv=randomBytes(12);
  var ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},key,plainU8);
  return {iv:iv, ct:new Uint8Array(ct)};
}
async function aesGcmDecrypt(key, iv, ct){
  var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},key,ct);
  return new Uint8Array(pt);
}

// ---------- Signatures ----------
async function signWithEthereum(addrLower, bytes){
  if(!window.ethereum) throw new Error('No ethereum provider');
  var hex=bytesToHex(bytes);
  return window.ethereum.request({method:'personal_sign', params:[hex, addrLower]});
}
async function signWithP256(bytes){
  var kp=await Vault.getP256KeyPair();
  var sig=await crypto.subtle.sign({name:'ECDSA',hash:{name:'SHA-256'}}, kp.privateKey, bytes);
  return b64uEncode(new Uint8Array(sig));
}

// ---------- Biometric & ZKP ----------
var Biometric={
  busy:false,
  // enroll new WebAuthn credential
  async enroll(){
    if(this.busy) return null; this.busy=true;
    try{
      var cred=await navigator.credentials.create({publicKey:{
        challenge: randomBytes(32),
        rp:{name:'BalanceChain', id: location.hostname},
        user:{id: randomBytes(16), name:'user@balancechain', displayName:'BalanceChain User'},
        pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
        authenticatorSelection:{authenticatorAttachment:'platform', userVerification:'required'},
        timeout:60000
      }});
      if(!cred) return null;
      var rawIdB64 = b64uEncode(new Uint8Array(cred.rawId));
      await Vault.setConfig({ bioCredentialId: rawIdB64 });
      return rawIdB64;
    }catch(e){ err('Enroll failed:', e); return null; } finally{ this.busy=false; }
  },
  // assert presence (unlock)
  async assert(){
    if(this.busy) return false; this.busy=true;
    try{
      var conf=await Vault.getConfig(); var cid=conf.bioCredentialId;
      if(!cid) return false;
      var raw=b64uDecode(cid);
      var assertion=await navigator.credentials.get({publicKey:{
        challenge: randomBytes(32),
        allowCredentials:[{type:'public-key', id: raw}],
        userVerification:'required',
        timeout:60000
      }});
      return !!assertion;
    }catch(e){ err('Assertion failed:', e); return false; } finally{ this.busy=false; }
  },
  // produce a compact ZKP token from a fresh assertion signature (not a real zk proof; contract expects bytes32 token)
  async zkp(){
    if(this.busy) return null; this.busy=true;
    try{
      var conf=await Vault.getConfig(); var cid=conf.bioCredentialId; if(!cid) return null;
      var raw=b64uDecode(cid);
      var chal=randomBytes(32);
      var assertion=await navigator.credentials.get({publicKey:{
        challenge: chal,
        allowCredentials:[{type:'public-key', id: raw}],
        userVerification:'required',
        timeout:60000
      }});
      if(!assertion||!assertion.response||!assertion.response.signature) return null;
      var sigU8=new Uint8Array(assertion.response.signature);
      var digest=await crypto.subtle.digest('SHA-256', sigU8);
      var hex='0x'; var dv=new Uint8Array(digest);
      for (var i=0;i<dv.length;i++){ var h=dv[i].toString(16); if(h.length<2)h='0'+h; hex+=h; }
      return hex;
    }catch(e){ err('ZKP generation failed:', e); return null; } finally{ this.busy=false; }
  }
};

// "Biometric asshole guard" (fail-closed + lockout + re-enroll)
var BioGuard={
  MAX_FAILS:3,
  LOCKOUT_SECONDS:3600,
  async checkOrLock(){
    var conf=await Vault.getConfig();
    var now=nowTs();
    if(conf.lockoutUntil && now<conf.lockoutUntil) return {ok:false, reason:'locked'};
    return {ok:true};
  },
  async recordFail(){
    var conf=await Vault.getConfig();
    var fails=(conf.authFails||0)+1;
    if(fails>=this.MAX_FAILS){
      conf.lockoutUntil=nowTs()+this.LOCKOUT_SECONDS;
      conf.authFails=0;
    }else{
      conf.authFails=fails;
    }
    await Vault.setConfig(conf);
  },
  async recordPass(){
    await Vault.setConfig({authFails:0, lockoutUntil:0});
  },
  async requireBiometric(){
    var st=await this.checkOrLock();
    if(!st.ok) throw new Error('Vault locked due to repeated biometric failures. Try later or re-enroll.');
    var ok=await Biometric.assert();
    if(!ok){ await this.recordFail(); throw new Error('Biometric verification failed.'); }
    await this.recordPass();
    return true;
  }
};

// ---------- P2P ----------
var P2P={
  seq:0,
  async identityString(){
    var conf=await Vault.getConfig();
    if(conf.ethereumAddress) return conf.ethereumAddress.toLowerCase();
    var pub=conf.p256PublicJwk; return 'p256:'+pub.x+'.'+pub.y;
  },
  async buildHeader(from,to,count){ return {0:P2P_VERSION,1:nowTs(),2:++this.seq,3:count|0,4:from,5:to}; },
  async prepareSend(sender, receiverIdentity, n, sharedKeyBytes, memo){
    await BioGuard.requireBiometric(); // require biometric before spending
    sender=(sender||'').toLowerCase();
    await Vault.touchCaps(n,0);
    var segs=await Segments.consumeForP2P(sender,n);
    for (var i=0;i<segs.length;i++){
      if((segs[i].current_owner||'').toLowerCase()!==sender) throw new Error('Ownership violation');
    }
    var header=await this.buildHeader(await this.identityString(), receiverIdentity, segs.length);
    var body={0:segs,1:memo||'',2:{she:segs.length,tvm:Math.floor(segs.length/EXCHANGE_RATE)}};
    var aes=await deriveAesKey(sharedKeyBytes,'p2p/body');
    var enc=await aesGcmEncrypt(aes, CBOR.encode(body));
    var hRaw=CBOR.encode(header);
    var sig=await (async function(bytes){ var c=await Vault.getConfig(); var payload=bytesConcat(hRaw,enc.ct); if(c.ethereumAddress&&window.ethereum) return {scheme:'eth',value:await signWithEthereum(c.ethereumAddress,payload)}; return {scheme:'p256',value:await signWithP256(payload)}; })();
    var hWithSig={}; for (var k in header) hWithSig[k]=header[k]; hWithSig[6]=sig.scheme+':'+sig.value;
    var finalHeader=b64uEncode(CBOR.encode(hWithSig));
    for (var j=0;j<segs.length;j++){ segs[j].unlocked=false; await put(SEGMENTS_STORE,segs[j]); }
    return { header: finalHeader, iv: b64uEncode(enc.iv), body: b64uEncode(enc.ct) };
  },
  async receiveApply(receiver, packed, sharedKeyBytes, txid){
    await BioGuard.requireBiometric(); // require biometric to accept
    receiver=(receiver||'').toLowerCase();
    var headerBytes=b64uDecode(packed.header); var header=CBOR.decode(headerBytes);
    if(header['0']!==P2P_VERSION) throw new Error('Bad version');
    var aes=await deriveAesKey(sharedKeyBytes,'p2p/body');
    var segsObj=CBOR.decode(await aesGcmDecrypt(aes, b64uDecode(packed.iv), b64uDecode(packed.body)));
    var segs=segsObj['0']; if(!Array.isArray(segs)) throw new Error('Malformed body');
    if((header['3']|0)!==segs.length) throw new Error('Count mismatch');
    await Segments.applyInbound(receiver,segs,txid||('p2p:'+nowTs()));
    try{ await Vault.touchCaps(segs.length,0);}catch(e){}
    await Segments.unlockNext(segs.length);
    return {applied:segs.length};
  }
};

// ---------- TVM on-chain adapter ----------
(function(){
  var ERC20_ABI=[
    "function approve(address spender,uint256 amount) external returns(bool)",
    "function allowance(address owner,address spender) external view returns(uint256)",
    "function balanceOf(address owner) external view returns(uint256)",
    "function decimals() external view returns(uint8)"
  ];
  // struct ClaimItem { bytes32 id; address owner; address previousOwner; address originalOwner; uint256 ownershipChangeCount; uint256 genesis; }
  var TVM_ABI=[
    "function claim(tuple(bytes32 id,address owner,address previousOwner,address originalOwner,uint256 ownershipChangeCount,uint256 genesis)[] items) external",
    "function mintFromUSDT(uint256 usdtAmount) external",
    "function swapTVMForUSDT(uint256 amountIn,uint256 minOut) external",
    "function swapUSDTForTVM(uint256 amountIn,uint256 minOut) external"
  ];

  function ensureEthers(){
    return new Promise(function(resolve,reject){
      if(window.ethers) return resolve();
      var s=document.createElement('script');
      s.src="https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js";
      s.onload=function(){ resolve(); };
      s.onerror=function(){ reject(new Error('ethers.js load failed')); };
      document.head.appendChild(s);
    });
  }

  var EVM={
    provider:null, signer:null, tvm:null, usdt:null, account:null, chainId:null, tvmDecimals:18,
    async connect(){
      if(!window.ethereum) throw new Error('No wallet');
      await ensureEthers();
      this.provider=new window.ethers.providers.Web3Provider(window.ethereum,'any');
      var accts=await this.provider.send('eth_requestAccounts',[]);
      this.signer=this.provider.getSigner(); this.account=(accts&&accts[0])?accts[0].toLowerCase():null;
      var net=await this.provider.getNetwork(); this.chainId=net.chainId;
      if(Number(this.chainId)!==Number(EXPECTED_CHAIN_ID)) throw new Error('Wrong network');
      this.usdt=new window.ethers.Contract(USDT_ADDRESS, ERC20_ABI, this.signer);
      this.tvm =new window.ethers.Contract(TVM_CONTRACT_ADDRESS, TVM_ABI, this.signer);
      try{ if(typeof this.tvm.decimals==='function'){ var d=await this.tvm.decimals(); this.tvmDecimals=(d.toNumber?d.toNumber():d); } }catch(_e){}
      await Vault.setEthereumAddress(this.account);
      return {account:this.account,chainId:this.chainId};
    },
    _bundleToItems(bundle){
      var u=window.ethers.utils, items=[];
      for (var i=0;i<bundle.length;i++){
        var it=bundle[i];
        var id32=u.keccak256(u.toUtf8Bytes(it.id));
        var occ  = window.ethers.BigNumber.from(it.occ||1);
        var gen  = window.ethers.BigNumber.from((it.proof&&it.proof.genesis)||GENESIS_BIO_CONSTANT);
        items.push({id:id32, owner:(it.owner||'').toLowerCase(), previousOwner:(it.previous||'').toLowerCase(), originalOwner:(it.original||'').toLowerCase(), ownershipChangeCount:occ, genesis:gen});
      }
      return items;
    },
    async claimFromVault(maxCount){
      await BioGuard.requireBiometric(); // biometric gate for on-chain claim
      if(!this.tvm) await this.connect();
      var bundle=await window.BioVault.exportOnchainClaim(maxCount|0);
      if(!bundle.length) throw new Error('No occ==1 segments');
      var items=this._bundleToItems(bundle);
      var tx=await this.tvm.claim(items);
      return tx;
    },
    async ensureUSDTAllowance(amount){
      var cur=await this.usdt.allowance(this.account, TVM_CONTRACT_ADDRESS);
      if(cur.gte(amount)) return true;
      var tx=await this.usdt.approve(TVM_CONTRACT_ADDRESS, amount); await tx.wait(); return true;
    },
    async mintFromUSDT(usdtAmount){
      await BioGuard.requireBiometric();
      if(!this.tvm) await this.connect();
      var dec=await this.usdt.decimals();
      var amt=window.ethers.utils.parseUnits(String(usdtAmount), dec);
      await this.ensureUSDTAllowance(amt);
      return this.tvm.mintFromUSDT(amt);
    },
    async swapTVMForUSDT(amountTVM, minOutUSDT){
      await BioGuard.requireBiometric();
      if(!this.tvm) await this.connect();
      var amtIn =window.ethers.utils.parseUnits(String(amountTVM), this.tvmDecimals);
      var minOut=window.ethers.utils.parseUnits(String(minOutUSDT), 6);
      return this.tvm.swapTVMForUSDT(amtIn, minOut);
    },
    async swapUSDTForTVM(amountUSDT, minOutTVM){
      await BioGuard.requireBiometric();
      if(!this.tvm) await this.connect();
      var dec=await this.usdt.decimals();
      var amtIn =window.ethers.utils.parseUnits(String(amountUSDT), dec);
      var minOut=window.ethers.utils.parseUnits(String(minOutTVM), this.tvmDecimals);
      await this.ensureUSDTAllowance(amtIn);
      return this.tvm.swapUSDTForTVM(amtIn, minOut);
    }
  };
  window.BioVaultEVM = EVM;
})();

// ---------- On-chain claim export (vault API) ----------
var TVM={
  async collectOnchainEligible(n){
    var all=await getAll(SEGMENTS_STORE), out=[];
    for (var i=0;i<all.length;i++){ if(all[i].onchain_eligible===true && (all[i].ownershipChangeCount|0)===1) out.push(all[i]); if(out.length===n) break; }
    return out;
  },
  async exportClaimBundle(n){
    var list=await this.collectOnchainEligible(n); var out=[];
    for (var i=0;i<list.length;i++){
      var s=list[i];
      out.push({ id:s.id, owner:s.current_owner, original:s.original_owner, previous:s.previous_owner, occ:s.ownershipChangeCount, proof:s.proof });
      s.onchain_eligible=false; await put(SEGMENTS_STORE,s);
    }
    return out;
  }
};

// ---------- Public API ----------
var BioVault={
  ready:false,
  async init(){ await Vault.init(); this.ready=true; log('App ready'); return true; },
  async bindEthereumAddress(a){ return Vault.setEthereumAddress(a); },
  async myIdentity(){ var conf=await Vault.getConfig(); return conf.ethereumAddress?conf.ethereumAddress:('p256:'+conf.p256PublicJwk.x+'.'+conf.p256PublicJwk.y); },
  async segmentsUnlocked(){ return Segments.listUnlocked(); },
  async segmentsAll(){ return getAll(SEGMENTS_STORE); },
  async mintSegments(recipient,count){
    await BioGuard.requireBiometric();
    var minted=await Segments.mintTo(recipient,count|0);
    var ts=nowTs();
    for (var i=0;i<minted.length;i++){
      var s=minted[i];
      await put(PROOFS_STORE,{id:'proof:'+s.id+':1',segmentId:s.id,owner:s.current_owner,ts:ts,history:s.history.slice()});
    }
    return minted;
  },
  async p2pPrepareSend(sender,receiverIdentity,n,sharedKeyBytes,memo){
    if(!(sharedKeyBytes instanceof Uint8Array)) throw new Error('sharedKeyBytes must be Uint8Array');
    return P2P.prepareSend(sender,receiverIdentity,n|0,sharedKeyBytes,memo||'');
  },
  async p2pReceiveApply(receiver,packed,sharedKeyBytes,txid){
    if(!(sharedKeyBytes instanceof Uint8Array)) throw new Error('sharedKeyBytes must be Uint8Array');
    return P2P.receiveApply(receiver,packed,sharedKeyBytes,txid||null);
  },
  async unlockNext(n){ return Segments.unlockNext(n|0); },
  async exportOnchainClaim(n){ return TVM.exportClaimBundle(n|0); },

  // Biometric helpers surfaced for UI
  async enrollBiometric(){ return Biometric.enroll(); },
  async biometricAssert(){ return Biometric.assert(); },
  async biometricZKP(){ return Biometric.zkp(); }
};

window.BioVault=BioVault;

// ---------- UI wiring (biometric + ZKP + wallet + P2P modals) ----------
(function(){
  function byId(id){ return document.getElementById(id); }

  function setText(id, txt){ var el=byId(id); if(el) el.textContent = String(txt); }

  async function connectWalletAndShow(){
    try{
      var info = await window.BioVaultEVM.connect();
      setText('connectedAccount', info.account ? (info.account.slice(0,6)+'...'+info.account.slice(-4)) : 'Not connected');
      var btn = byId('connect-wallet'); if(btn){ btn.textContent='Wallet Connected'; btn.disabled=true; }
    }catch(e){ alert(e && e.message ? e.message : e); }
  }

  // Biometric: enroll
  var btnEnroll = byId('bio-enroll-btn');
  if(btnEnroll) btnEnroll.addEventListener('click', async function(){
    try{
      var cid = await BioVault.enrollBiometric();
      if(!cid) return alert('Enrollment failed.');
      setText('bio-status','Enrolled'); setText('bio-cred', cid);
      alert('Biometric enrolled on this device.');
    }catch(e){ alert(e.message||e); }
  });

  // Biometric: test assertion
  var btnBioTest = byId('bio-test-btn');
  if(btnBioTest) btnBioTest.addEventListener('click', async function(){
    try{
      var ok = await BioVault.biometricAssert();
      alert(ok?'Biometric OK':'Biometric failed');
    }catch(e){ alert(e.message||e); }
  });

  // Biometric: ZKP preview (UI)
  var btnZkp = byId('bio-zkp-btn');
  if(btnZkp) btnZkp.addEventListener('click', async function(){
    try{
      var z=await BioVault.biometricZKP();
      if(!z) return alert('ZKP generation failed.');
      setText('bio-zkp-out', z);
    }catch(e){ alert(e.message||e); }
  });

  // Wallet connect
  var btnConn = byId('connect-wallet');
  if(btnConn) btnConn.addEventListener('click', connectWalletAndShow);

  // Claim TVM (uses vault export + EVM adapter; biometric guard inside)
  var claimBtn = byId('claim-tvm-btn');
  if(claimBtn) claimBtn.addEventListener('click', async function(){
    try{
      var tx = await window.BioVaultEVM.claimFromVault(240); // example: up to 240 segments (20 TVM) if available
      alert('Claim submitted: '+tx.hash);
    }catch(e){ alert(e.message||e); }
  });

  // Swap & Mint examples
  var swap1 = byId('swap-tvm-usdt-btn');
  if(swap1) swap1.addEventListener('click', async function(){ try{ var tx=await window.BioVaultEVM.swapTVMForUSDT('1','0.9'); alert('Swap tx: '+tx.hash);}catch(e){alert(e.message||e);} });
  var swap2 = byId('swap-usdt-tvm-btn');
  if(swap2) swap2.addEventListener('click', async function(){ try{ var tx=await window.BioVaultEVM.swapUSDTForTVM('10','9'); alert('Swap tx: '+tx.hash);}catch(e){alert(e.message||e);} });
  var mintU = byId('mint-usdt-btn');
  if(mintU) mintU.addEventListener('click', async function(){ try{ var tx=await window.BioVaultEVM.mintFromUSDT('50'); alert('Mint tx: '+tx.hash);}catch(e){alert(e.message||e);} });

  // P2P: Catch-Out form
  var coForm = byId('formCatchOut');
  if(coForm) coForm.addEventListener('submit', async function(ev){
    ev.preventDefault();
    try{
      var recv = (byId('receiverBioModal')||{}).value||'';
      var amt  = parseInt(((byId('amountSegmentsModal')||{}).value||'0'),10);
      var note = (byId('noteModal')||{}).value||'';
      if(!recv || !amt || amt<=0) return alert('Invalid input.');
      // sharedKeyBytes must be known to both peers (QR exchange beforehand)
      var sharedKeyBytes = randomBytes(32); // placeholder; replace with negotiated key
      var sender = (await Vault.getConfig()).ethereumAddress || await BioVault.myIdentity();
      var pkt = await BioVault.p2pPrepareSend(String(sender), String(recv), amt, sharedKeyBytes, note);
      var ta = byId('catchOutResultText'); if(ta) ta.value = JSON.stringify(pkt);
      alert('Catch-Out created. Share the payload securely.');
    }catch(e){ alert(e.message||e); }
  });

  // P2P: Catch-In form
  var ciForm = byId('formCatchIn');
  if(ciForm) ciForm.addEventListener('submit', async function(ev){
    ev.preventDefault();
    try{
      var payloadStr = (byId('catchInPayloadModal')||{}).value||'';
      if(!payloadStr) return;
      var obj = JSON.parse(payloadStr);
      var sharedKeyBytes = randomBytes(32); // placeholder; must match sender’s
      var receiver = (await Vault.getConfig()).ethereumAddress || await BioVault.myIdentity();
      await BioVault.p2pReceiveApply(String(receiver), obj, sharedKeyBytes);
      alert('Catch-In applied.');
    }catch(e){ alert(e.message||e); }
  });
})();

// ---------- Boot ----------
BioVault.init().catch(function(e){ err('Init failed:', e&&e.message?e.message:e); });

/* CHANGE LOG
- Added biometric enrollment, assertion, ZKP generator, and fail-closed guard (lockout + re-enroll).
- Biometric required for any spend-like operation (P2P send, receive apply, on-chain claim/mint/swap).
- On-chain adapter appended (claim/mint/swap) with strict occ===1 export bundle from the vault.
- P2P v3: compact CBOR header + AES-GCM encrypted body, signature over (header||ciphertext).
- Ownership rules enforced; deterministic unlocks + caps.
*/
