/******************************
 * main.js - ES2018 compatible (no optional chaining / numeric separators)
 * Ultimate master-class build: compact+encrypted P2P, network guards, robust charts, safe base64, 0x Bio-IBAN, bonus constant.
 * UPDATED: Implements clarified rules:
 *  - On-chain TVM claim uses segments with ownershipChangeCount === 1 (no 10-history on-chain).
 *  - P2P sends only unlocked segments; after send, auto-unlock equal count if caps allow.
 *  - Tracks daily/monthly/yearly segment caps (360/3600/10800) and yearly TVM (900 + 100 parity).
 *
 * PATCH: P2P payload switched from JSON to CBOR + varint streaming (v:3 envelope),
 *        with backward-compat import for v:1/v:2.
 ******************************/

// ---------- Base Setup / Global Constants ----------//
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 4; // bumped for new fields
const VAULT_STORE = 'vault';
const PROOFS_STORE = 'proofs';
const SEGMENTS_STORE = 'segments';
const INITIAL_BALANCE_SHE = 1200;
const EXCHANGE_RATE = 12; // 1 TVM = 12 SHE
const INITIAL_BIO_CONSTANT = 1736565605;
const LOCKOUT_DURATION_SECONDS = 3600;
const MAX_AUTH_ATTEMPTS = 3;

// IMPORTANT: lowercase to bypass strict checksum validation in ethers v6
const CONTRACT_ADDRESS = '0xcc79b1bc9eabc3d30a3800f4d41a4a0599e1f3c6';
const USDT_ADDRESS     = '0xdac17f958d2ee523a2206206994597c13d831ec7';

// expected network for your deployment (change if not mainnet)
const EXPECTED_CHAIN_ID = 1;

const ABI = [
  { "inputs":[{ "components":[
      {"internalType":"uint256","name":"segmentIndex","type":"uint256"},
      {"internalType":"uint256","name":"currentBioConst","type":"uint256"},
      {"internalType":"bytes32","name":"ownershipProof","type":"bytes32"},
      {"internalType":"bytes32","name":"unlockIntegrityProof","type":"bytes32"},
      {"internalType":"bytes32","name":"spentProof","type":"bytes32"},
      {"internalType":"uint256","name":"ownershipChangeCount","type":"uint256"},
      {"internalType":"bytes32","name":"biometricZKP","type":"bytes32"}],
      "internalType":"struct TVM.SegmentProof[]","name":"proofs","type":"tuple[]"},
      {"internalType":"bytes","name":"signature","type":"bytes"},
      {"internalType":"bytes32","name":"deviceKeyHash","type":"bytes32"},
      {"internalType":"uint256","name":"userBioConstant","type":"uint256"},
      {"internalType":"uint256","name":"nonce","type":"uint256"}],
    "name":"claimTVM","outputs":[],"stateMutability":"nonpayable","type":"function"
  },
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"exchangeTVMForSegments","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"swapTVMForUSDT","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"swapUSDTForTVM","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
];

const GENESIS_BIO_CONSTANT = 1736565605;
const BIO_STEP = 1;
const SEGMENTS_PER_LAYER = 1200;
const LAYERS = 10;
const SEGMENTS_PER_TVM = 12;
const DAILY_CAP_TVM = 30;
const MONTHLY_CAP_TVM = 300;
const YEARLY_CAP_TVM = 900;
const EXTRA_BONUS_TVM = 100; // parity
const MAX_YEARLY_TVM_TOTAL = YEARLY_CAP_TVM + EXTRA_BONUS_TVM;
const SEGMENT_HISTORY_MAX = 10;
const HISTORY_MAX = 20;
const KEY_HASH_SALT = "Balance-Chain-v3-PRD";
const PBKDF2_ITERS = 310000;
const AES_KEY_LENGTH = 256;
const MAX_IDLE = 15 * 60 * 1000;
const HMAC_KEY = new TextEncoder().encode("BalanceChainHMACSecret");
const WALLET_CONNECT_PROJECT_ID = 'c4f79cc9f2f73b737d4d06795a48b4a5';

// ---- QR/ZIP/Chart integration constants ----
const QR_CHUNK_MAX = 900;     // safe per-frame payload length for QR (approx, ECC M)
const QR_SIZE = 512;          // px
const QR_MARGIN = 2;          // quiet zone
var _qrLibReady = false;
var _zipLibReady = false;
var _chartLibReady = false;

// ---------- Derived segment caps (segments, not TVM) ----------
const DAILY_CAP_SEG  = DAILY_CAP_TVM  * SEGMENTS_PER_TVM; // 360
const MONTHLY_CAP_SEG= MONTHLY_CAP_TVM* SEGMENTS_PER_TVM; // 3600
const YEARLY_CAP_SEG = YEARLY_CAP_TVM * SEGMENTS_PER_TVM; // 10800

// ---------- State ----------
let vaultUnlocked = false;
let derivedKey = null;
let provider = null;
let signer = null;
let tvmContract = null;
let usdtContract = null;
let account = null;
let chainId = null;
let transactionLock = false;
let lastCatchOutPayload = null;
// New: keep the raw CBOR bytes and a default filename for re-download
var lastCatchOutPayloadBytes = null;
var lastCatchOutFileName = "";

const SESSION_URL_KEY = 'last_session_url';
const VAULT_UNLOCKED_KEY = 'vaultUnlocked';
const VAULT_LOCK_KEY = 'vaultLock';
const VAULT_BACKUP_KEY = 'vault.backup';

// ---------- CONSTANTS (all used below) ----------
const BIO_TOLERANCE = 720; // seconds: biometric freshness window
const DECIMALS_FACTOR = 1000000;
const MAX_PROOFS_LENGTH = 200; // cap batch size
const SEGMENT_PROOF_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "SegmentProof(uint256 segmentIndex,uint256 currentBioConst,bytes32 ownershipProof,bytes32 unlockIntegrityProof,bytes32 spentProof,uint256 ownershipChangeCount,bytes32 biometricZKP)"
  )
);
const CLAIM_TYPEHASH = ethers.keccak256(
  ethers.toUtf8Bytes(
    "Claim(address user,bytes32 proofsHash,bytes32 deviceKeyHash,uint256 userBioConstant,uint256 nonce)"
  )
);
const STORAGE_CHECK_INTERVAL = 300000; // 5 min
const vaultSyncChannel = (typeof BroadcastChannel !== 'undefined') ? new BroadcastChannel('vault-sync') : null;

// ---------- AUTO (now actually used) ----------
let autoProofs = null;
let autoDeviceKeyHash = ''; // bytes32 hex
let autoUserBioConstant = 0;
let autoNonce = 0;
let autoSignature = '';

// ---------- UTIL ----------
const coder = ethers.AbiCoder.defaultAbiCoder();

function toBaseUnits(xHuman) {
  return Math.floor(Number(xHuman) * DECIMALS_FACTOR);
}
function fromBaseUnits(xBase) {
  return Number(xBase) / DECIMALS_FACTOR;
}
function nowSec() { return Math.floor(Date.now() / 1000); }

function keccakPacked(types, values) {
  return ethers.keccak256(coder.encode(types, values));
}

// Compute hash of a SegmentProof as the on-chain contract would (EIP-712-style struct hash)
function hashSegmentProof(p) {
  return keccakPacked(
    [
      'bytes32',
      'uint256',
      'uint256',
      'bytes32',
      'bytes32',
      'bytes32',
      'uint256',
      'bytes32'
    ],
    [
      SEGMENT_PROOF_TYPEHASH,
      p.segmentIndex,
      p.currentBioConst,
      p.ownershipProof,
      p.unlockIntegrityProof,
      p.spentProof,
      p.ownershipChangeCount,
      p.biometricZKP
    ]
  );
}

// Merkle root of segment proof hashes (for compact payload)
function merkleRoot(hashes /* array of 0x..32B */) {
  if (!hashes.length) return ethers.ZeroHash;
  let layer = hashes.slice();
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : left;
      next.push(ethers.keccak256(ethers.concat([left, right])));
    }
    layer = next;
  }
  return layer[0];
}

// Segment index bitmap compression (compact segment set)
function segmentBitmap(indices){
  if (!indices || indices.length === 0) return '0x';
  const max = Math.max.apply(null, indices);
  const bytes = new Uint8Array(Math.floor(max / 8) + 1);
  for (var ii=0; ii<indices.length; ii++) {
    var i = indices[ii];
    bytes[i >> 3] |= (1 << (i & 7));
  }
  return ethers.hexlify(bytes);
}


// Biometric recency / tolerance gate
function checkBioFreshness(ts /* seconds */) {
  if (Math.abs(nowSec() - ts) > BIO_TOLERANCE) {
    throw new Error('Biometric proof outside tolerance window of ' + BIO_TOLERANCE + 's');
  }
}

// AES-GCM envelope keyed for the receiver (compact & private)
async function encryptForReceiver(receiverDeviceKeyHashHex, bytes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ethers.getBytes(receiverDeviceKeyHashHex),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', salt: salt, info: new Uint8Array([]), hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, bytes));
  return {
    iv: ethers.hexlify(iv),
    salt: ethers.hexlify(salt),
    ct: ethers.hexlify(ct)
  };
}
async function decryptFromSender(receiverDeviceKeyHashHex, envelope) {
  const iv = envelope.iv, salt = envelope.salt, ct = envelope.ct;
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ethers.getBytes(receiverDeviceKeyHashHex),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', salt: ethers.getBytes(salt), info: new Uint8Array([]), hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ethers.getBytes(iv) },
    key,
    ethers.getBytes(ct)
  );
  return new Uint8Array(pt);
}

function downloadBytes(filename, u8, mime){
  const blob = new Blob([u8], { type: mime || 'application/cbor' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(function(){ URL.revokeObjectURL(url); }, 1500);
}

// ---------- OWNERSHIP RULES (enforced in proof composers) ----------
function encodeOwnershipProof({ originalOwner, previousOwner, currentOwner }) {
  return keccakPacked(
    ['address', 'address', 'address'],
    [originalOwner, previousOwner, currentOwner]
  );
}
function encodeSpentProof({ previousOwner, segmentIndex, nonce }) {
  return keccakPacked(
    ['address', 'uint256', 'uint256'],
    [previousOwner, segmentIndex, nonce]
  );
}
function encodeUnlockIntegrityProof({ chainId, vaultId, purpose }) {
  return keccakPacked(
    ['uint256', 'bytes32', 'bytes32'],
    [chainId, ethers.id(vaultId || 'vault'), ethers.id(purpose || 'transfer')]
  );
}

// ---------- TVM MINT (strict rules) ----------
function buildTvmMintSegmentProof({
  segmentIndex, vaultOwner, currentOwner, currentBioConst, biometricZKP, chainId, vaultId
}) {
  if (vaultOwner.toLowerCase() === currentOwner.toLowerCase()) {
    throw new Error('TVM mint: current owner must differ from vault owner');
  }
  const ownershipProof = encodeOwnershipProof({
    originalOwner: vaultOwner,
    previousOwner: vaultOwner,
    currentOwner: currentOwner
  });
  const unlockIntegrityProof = encodeUnlockIntegrityProof({ chainId: chainId, vaultId: vaultId, purpose: 'mint' });
  const spentProof = ethers.ZeroHash;
  const ownershipChangeCount = 1;
  checkBioFreshness(biometricZKP.ts);

  return {
    segmentIndex: segmentIndex,
    currentBioConst: currentBioConst,
    ownershipProof: ownershipProof,
    unlockIntegrityProof: unlockIntegrityProof,
    spentProof: spentProof,
    ownershipChangeCount: ownershipChangeCount,
    biometricZKP: biometricZKP.commit
  };
}

// ---------- P2P TRANSFER ----------
function buildP2PTransferSegmentProof({
  segmentIndex, originalOwner, currentOwner, receiver, previousOwner,
  currentBioConst, biometricZKP, chainId, vaultId, nonceForSpent
}) {
  if (currentOwner.toLowerCase() !== previousOwner.toLowerCase()) {
    throw new Error('Transfer composer: `previousOwner` must equal `currentOwner` before hand-off');
  }
  const ownershipProof = encodeOwnershipProof({
    originalOwner: originalOwner,
    previousOwner: currentOwner,
    currentOwner: receiver
  });
  const unlockIntegrityProof = encodeUnlockIntegrityProof({ chainId: chainId, vaultId: vaultId, purpose: 'transfer' });
  const spentProof = encodeSpentProof({ previousOwner: currentOwner, segmentIndex: segmentIndex, nonce: nonceForSpent });
  const ownershipChangeCount = 0;
  checkBioFreshness(biometricZKP.ts);

  return {
    segmentIndex: segmentIndex,
    currentBioConst: currentBioConst,
    ownershipProof: ownershipProof,
    unlockIntegrityProof: unlockIntegrityProof,
    spentProof: spentProof,
    ownershipChangeCount: ownershipChangeCount,
    biometricZKP: biometricZKP.commit
  };
}

// ---------- PREVIOUS-OWNER CATCH-IN ----------
function buildCatchInClaim({ user, proofs, deviceKeyHash, userBioConstant, nonce }) {
  if (proofs.length === 0) throw new Error('No proofs to claim');
  if (proofs.length > MAX_PROOFS_LENGTH) throw new Error('Too many proofs; max ' + MAX_PROOFS_LENGTH);

  const proofHashes = proofs.map(hashSegmentProof);
  const proofsHash = merkleRoot(proofHashes);

  const claimDigest = keccakPacked(
    ['bytes32','address','bytes32','bytes32','uint256','uint256'],
    [CLAIM_TYPEHASH, user, proofsHash, deviceKeyHash, userBioConstant, nonce]
  );

  return { proofsHash: proofsHash, claimDigest: claimDigest };
}

// ---------- COMPACT PAYLOAD BUILDER (Merkle + bitmap + envelope) ----------
async function buildCompactPayload({
  version, from, to, chainId, deviceKeyHashReceiver, userBioConstant, proofs
}) {
  if (!version) version = 2;
  if (proofs.length > MAX_PROOFS_LENGTH) throw new Error('Too many proofs; max ' + MAX_PROOFS_LENGTH);

  const proofHashes = proofs.map(hashSegmentProof);
  const proofsRoot = merkleRoot(proofHashes);
  const segments = proofs.map(function(p){ return p.segmentIndex; }).sort(function(a,b){ return a-b; });
  const bitmap = segmentBitmap(segments);

  const r = buildCatchInClaim({
    user: from,
    proofs: proofs,
    deviceKeyHash: autoDeviceKeyHash || ethers.ZeroHash,
    userBioConstant: autoUserBioConstant || userBioConstant,
    nonce: autoNonce
  });
  const claimDigest = r.claimDigest;

  const raw = new TextEncoder().encode(JSON.stringify({ chainId: chainId, proofs: proofs }));
  const envelope = await encryptForReceiver(deviceKeyHashReceiver, raw);

  const payload = {
    v: version,
    from: from,
    to: to,
    root: proofsRoot,
    segbm: bitmap,
    dk: deviceKeyHashReceiver,
    ubc: userBioConstant,
    nonce: autoNonce,
    env: envelope,
    sig: autoSignature
  };

  return { payload: payload, claimDigest: claimDigest };
}

// ---------- SIGN & SEND ----------
async function signClaimDigest(signer, claimDigest) {
  const sig = await signer.signMessage(ethers.getBytes(claimDigest));
  autoSignature = sig;
  return sig;
}

function importVault(armoredText) {
  try {
    const parsed = JSON.parse(decodeURIComponent(escape(atob(armoredText))));
    window.__vaultState = parsed.state || {};
    autoDeviceKeyHash   = (parsed && parsed.auto && parsed.auto.autoDeviceKeyHash)   || autoDeviceKeyHash;
    autoUserBioConstant = (parsed && parsed.auto && parsed.auto.userBioConstant)     || autoUserBioConstant;
    autoNonce           = (parsed && parsed.auto && parsed.auto.autoNonce)           || autoNonce;

    if (vaultSyncChannel) vaultSyncChannel.postMessage({ type: 'backup:restored', ts: Date.now() });
    return true;
  } catch (e) {
    console.error('Import failed', e);
    return false;
  }
}

// ---------- PERIODIC STORAGE CHECK ----------
let __storageCheckTimer = setInterval(function(){
  const exists = !!localStorage.getItem(VAULT_BACKUP_KEY);
  if (!exists) console.warn('Vault backup missing; consider running backupVault()');
}, STORAGE_CHECK_INTERVAL);

// ---------- HIGH-LEVEL FLOWS ----------
// ---------- HIGH-LEVEL FLOWS YOU CAN CALL ----------

// 1) TVM Mint flow (one or many segments)
async function composeAndSendMint({
  segments,         // [segmentIndex,...]
  vaultOwner,       // address
  currentOwner,     // address (must differ from vault owner)
  currentBioConst,  // uint256
  biometricZKP,     // {commit: bytes32, ts: seconds}
  chainId,
  vaultId,
  receiverDeviceKeyHash, // bytes32 for envelope
  signer            // ethers.Signer for `from`
}) {
  const from = await signer.getAddress();
  if (from.toLowerCase() !== currentOwner.toLowerCase()) {
    throw new Error('Signer must match currentOwner for mint claim');
  }
  const proofs = segments.map(function(sIdx){
    return buildTvmMintSegmentProof({
      segmentIndex: sIdx,
      vaultOwner: vaultOwner,
      currentOwner: currentOwner,
      currentBioConst: currentBioConst,
      biometricZKP: biometricZKP,
      chainId: chainId,
      vaultId: vaultId
    });
  });
  autoProofs = proofs;
  autoUserBioConstant = currentBioConst;

  const b = await buildCompactPayload({
    from: from, to: currentOwner, chainId: chainId,
    deviceKeyHashReceiver: receiverDeviceKeyHash,
    userBioConstant: currentBioConst,
    proofs: proofs
  });
  const payload = b.payload;
  const claimDigest = b.claimDigest;
  payload.sig = await signClaimDigest(signer, claimDigest);
  await exportProofToBlockchain(payload);
  return payload;
}
// 2) P2P Transfer flow
async function composeAndSendTransfer({
  segments,         // [segmentIndex,...]
  originalOwner,    // address (historical)
  currentOwner,     // sender (must be current)
  receiver,         // new current owner
  currentBioConst,
  biometricZKP,
  chainId,
  vaultId,
  nonceForSpent,
  receiverDeviceKeyHash,
  signer
}) {
  const from = await signer.getAddress();
  if (from.toLowerCase() !== currentOwner.toLowerCase()) throw new Error('Sender must be current owner');

  const proofs = segments.map(function(sIdx){
    return buildP2PTransferSegmentProof({
      segmentIndex: sIdx,
      originalOwner: originalOwner,
      currentOwner: currentOwner,
      receiver: receiver,
      previousOwner: currentOwner,
      currentBioConst: currentBioConst,
      biometricZKP: biometricZKP,
      chainId: chainId,
      vaultId: vaultId,
      nonceForSpent: nonceForSpent
    });
  });
  autoProofs = proofs;
  autoUserBioConstant = currentBioConst;

  const b = await buildCompactPayload({
    from: from, to: receiver, chainId: chainId,
    deviceKeyHashReceiver: receiverDeviceKeyHash,
    userBioConstant: currentBioConst,
    proofs: proofs
  });
  const payload = b.payload;
  const claimDigest = b.claimDigest;
  payload.sig = await signClaimDigest(signer, claimDigest);
  await exportProofToBlockchain(payload);
  return payload;
}

// 3) Previous-owner Catch-in (anti double-spend)
async function composeCatchIn({
  previousOwner,   // address = msg.sender signer
  deviceKeyHash,   // bytes32 (local device)
  userBioConstant,
  signer
}) {
  const from = await signer.getAddress();
  if (from.toLowerCase() !== previousOwner.toLowerCase()) throw new Error('Only previous owner can catch-in');

  if (!autoProofs || !autoProofs.length) throw new Error('No prior proofs cached to catch-in');
  const c = buildCatchInClaim({
    user: previousOwner,
    proofs: autoProofs,
    deviceKeyHash: deviceKeyHash,
    userBioConstant: userBioConstant,
    nonce: ++autoNonce // bump nonce for uniqueness
  });

  const sig = await signClaimDigest(signer, c.claimDigest);
  const payload = { user: previousOwner, proofsHash: c.proofsHash, deviceKeyHash: deviceKeyHash, ubc: userBioConstant, nonce: autoNonce, sig: sig };
  lastCatchOutPayload = payload;
  // send to chain/relayer:
  await exportProofToBlockchain({ type: 'catch-in', user: previousOwner, proofsHash: c.proofsHash, deviceKeyHash: deviceKeyHash, ubc: userBioConstant, nonce: autoNonce, sig: sig });
  return payload;
}

let vaultData = {
  bioIBAN: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  bonusConstant: INITIAL_BIO_CONSTANT,
  initialBalanceSHE: INITIAL_BALANCE_SHE,
  balanceSHE: 0,
  balanceUSD: 0,
  lastUTCTimestamp: 0,
  transactions: [],
  authAttempts: 0,
  lockoutTimestamp: null,
  joinTimestamp: 0,
  credentialId: null,
  userWallet: "",
  deviceKeyHash: "",
  layerBalances: Array.from({length: LAYERS}, function(){ return 0; }),
  caps: { dayKey:"", monthKey:"", yearKey:"", dayUsedSeg:0, monthUsedSeg:0, yearUsedSeg:0, tvmYearlyClaimed:0 },
  nextSegmentIndex: INITIAL_BALANCE_SHE + 1
};
vaultData.layerBalances[0] = INITIAL_BALANCE_SHE;

var lastCatchOutPayloadStr = "";
var lastQrFrames = [];
var lastQrFrameIndex = 0;

// ---------- Utils (safe base64 / crypto helpers) ----------
function _u8ToB64(u8){var CHUNK=0x8000,s='';for(var i=0;i<u8.length;i+=CHUNK){s+=String.fromCharCode.apply(null,u8.subarray(i,i+CHUNK));}return btoa(s);}
const Utils = {
  enc: new TextEncoder(),
  dec: new TextDecoder(),
  toB64: function (buf) { var u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : (buf && buf.buffer) ? new Uint8Array(buf.buffer) : new Uint8Array(buf || []); return _u8ToB64(u8); },
  fromB64: function (b64) { return Uint8Array.from(atob(b64), function(c){ return c.charCodeAt(0); }).buffer; },
  rand:  function (len) { return crypto.getRandomValues(new Uint8Array(len)); },
  ctEq:  function (a, b) { a=a||"";b=b||""; if (a.length!==b.length) return false; var r=0; for (var i=0;i<a.length;i++) r|=a.charCodeAt(i)^b.charCodeAt(i); return r===0; },
  canonical: function (obj) { return JSON.stringify(obj, Object.keys(obj).sort()); },
  sha256: async function (data) { const buf=await crypto.subtle.digest("SHA-256", typeof data==="string"?Utils.enc.encode(data):data); return Utils.toB64(buf); },
  sha256Hex: async function (str) { const buf=await crypto.subtle.digest("SHA-256", Utils.enc.encode(str)); return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join(""); },
  hmacSha256: async function (message) { const key=await crypto.subtle.importKey("raw", HMAC_KEY, { name:"HMAC", hash:"SHA-256" }, false, ["sign"]); const signature=await crypto.subtle.sign("HMAC", key, Utils.enc.encode(message)); return Utils.toB64(signature); },
  sanitizeInput: function (input) { return (typeof DOMPurify!=='undefined'? DOMPurify.sanitize(input) : String(input)); },
  to0x: function (hex) { return hex && hex.slice(0,2)==='0x' ? hex : ('0x' + hex); }
};

// ---------- Script Loader (QR + JSZip + Chart.js) ----------
function injectScript(src) { return new Promise(function(resolve, reject){ var s=document.createElement('script'); s.src=src; s.async=true; s.onload=resolve; s.onerror=reject; document.head.appendChild(s); }); }
async function ensureQrLib(){ if(_qrLibReady) return; try{ await injectScript('https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js'); if (window.QRCode && typeof window.QRCode.toCanvas==='function') _qrLibReady=true; }catch(e){ console.warn('[BioVault] QR lib load failed',e); } }
async function ensureZipLib(){ if(_zipLibReady) return; try{ await injectScript('https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js'); if (window.JSZip) _zipLibReady=true; }catch(e){ console.warn('[BioVault] JSZip load failed',e); } }
async function ensureChartLib(){ if (_chartLibReady||window.Chart){ _chartLibReady=true; return; } try{ await injectScript('https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'); _chartLibReady=!!window.Chart; }catch(e){ console.warn('[BioVault] Chart.js load failed',e); } }

// ---------- Encryption ----------
const Encryption = {
  encryptData: async (key, dataObj) => {
    const iv = Utils.rand(12);
    const plaintext = Utils.enc.encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt({ name:'AES-GCM', iv: iv }, key, plaintext);
    return { iv: iv, ciphertext: ciphertext };
  },
  decryptData: async (key, iv, ciphertext) => {
    const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: iv }, key, ciphertext);
    return JSON.parse(Utils.dec.decode(plainBuf));
  },
  bufferToBase64: (buf) => { var u8 = buf instanceof ArrayBuffer ? new Uint8Array(buf) : (buf && buf.buffer) ? new Uint8Array(buf.buffer) : new Uint8Array(buf); return _u8ToB64(u8); },
  base64ToBuffer: (b64) => {
    if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) throw new Error('Invalid Base64 string');
    const bin = atob(b64); const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
    return out.buffer;
  }
};

// ---------- DB (IndexedDB) ----------
const DB = {
  openVaultDB: () => new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(VAULT_STORE))   db.createObjectStore(VAULT_STORE, { keyPath:'id' });
      if (!db.objectStoreNames.contains(PROOFS_STORE))  db.createObjectStore(PROOFS_STORE,{ keyPath:'id' });
      if (!db.objectStoreNames.contains(SEGMENTS_STORE))db.createObjectStore(SEGMENTS_STORE,{ keyPath:'segmentIndex' });
      if (!db.objectStoreNames.contains('replays'))     db.createObjectStore('replays',{ keyPath:'nonce' });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  }),

  saveVaultDataToDB: async (iv, ciphertext, saltB64) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).put({
        id:'vaultData',
        iv: Encryption.bufferToBase64(iv),
        ciphertext: Encryption.bufferToBase64(ciphertext),
        salt: saltB64,
        lockoutTimestamp: vaultData.lockoutTimestamp || null,
        authAttempts: vaultData.authAttempts || 0
      });
      tx.oncomplete = resolve; tx.onerror = function(e){ reject(e.target.error); };
    });
  },

  loadVaultDataFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readonly');
      const get = tx.objectStore(VAULT_STORE).get('vaultData');
      get.onsuccess = () => {
        const r = get.result;
        if (!r) return resolve(null);
        try {
          resolve({
            iv: Encryption.base64ToBuffer(r.iv),
            ciphertext: Encryption.base64ToBuffer(r.ciphertext),
            salt: r.salt ? Encryption.base64ToBuffer(r.salt) : null,
            lockoutTimestamp: r.lockoutTimestamp || null,
            authAttempts: r.authAttempts || 0
          });
        } catch (e) { console.error('[BioVault] Corrupted vault record', e); resolve(null); }
      };
      get.onerror = function(e){ reject(e.target.error); };
    });
  },

  clearVaultDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).clear();
      tx.oncomplete = resolve; tx.onerror = function(e){ reject(e.target.error); };
    });
  },

  saveProofsToDB: async (bundle) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readwrite');
      tx.objectStore(PROOFS_STORE).put({ id:'autoProofs', data: bundle });
      tx.oncomplete = resolve; tx.onerror = function(e){ reject(e.target.error); };
    });
  },
  loadProofsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readonly');
      const get = tx.objectStore(PROOFS_STORE).get('autoProofs');
      get.onsuccess = function(){ resolve(get.result ? get.result.data : null); };
      get.onerror = function(e){ reject(e.target.error); };
    });
  },

  saveSegmentToDB: async (segment) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      tx.objectStore(SEGMENTS_STORE).put(segment);
      tx.oncomplete = resolve; tx.onerror = function(e){ reject(e.target.error); };
    });
  },
  loadSegmentsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readonly');
      const getAll = tx.objectStore(SEGMENTS_STORE).getAll();
      getAll.onsuccess = function(){ resolve(getAll.result || []); };
      getAll.onerror = function(e){ reject(e.target.error); };
    });
  },
  deleteSegmentFromDB: async (segmentIndex) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      tx.objectStore(SEGMENTS_STORE).delete(segmentIndex);
      tx.oncomplete = resolve; tx.onerror = function(e){ reject(e.target.error); };
    });
  },
  getSegment: async (segmentIndex) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readonly');
      const req = tx.objectStore(SEGMENTS_STORE).get(segmentIndex);
      req.onsuccess = function(){ resolve(req.result || null); };
      req.onerror = function(e){ reject(e.target.error); };
    });
  },
  hasReplayNonce: async (nonce) => {
    const db = await DB.openVaultDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['replays'],'readonly');
      const g = tx.objectStore('replays').get(nonce);
      g.onsuccess = function(){ res(!!g.result); };
      g.onerror = function(e){ rej(e.target.error); };
    });
  },
  putReplayNonce: async (nonce) => {
    const db = await DB.openVaultDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['replays'],'readwrite');
      tx.objectStore('replays').put({ nonce: nonce, ts: Date.now() });
      tx.oncomplete = res; tx.onerror = function(e){ rej(e.target.error); };
    });
  }
};

// ---------- Biometric ----------
const Biometric = {
  _bioBusy: false,

  performBiometricAuthenticationForCreation: async () => {
    if (Biometric._bioBusy) return null;
    Biometric._bioBusy = true;
    try {
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: Utils.rand(32),
          rp: { name: "BioVault", id: location.hostname },
          user: { id: Utils.rand(16), name: "user@biovault", displayName: "User" },
          pubKeyCredParams: [
            { type: "public-key", alg: -7   }, // ES256
            { type: "public-key", alg: -257 }  // RS256
          ],
          authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
          timeout: 60000
        }
      });
      return credential;
    } catch (err) {
      console.error('[BioVault] Biometric creation failed', err);
      return null;
    } finally {
      Biometric._bioBusy = false;
    }
  },

  performBiometricAssertion: async (credentialId) => {
    if (Biometric._bioBusy) return false;
    Biometric._bioBusy = true;
    try {
      const idBuf = Encryption.base64ToBuffer(credentialId);
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: Utils.rand(32),
          allowCredentials: [{ type: "public-key", id: new Uint8Array(idBuf) }],
          userVerification: "required",
          timeout: 60000
        }
      });
      return !!assertion;
    } catch (err) {
      console.error('[BioVault] Biometric assertion failed', err);
      return false;
    } finally {
      Biometric._bioBusy = false;
    }
  },

  generateBiometricZKP: async () => {
    if (!vaultData || !vaultData.credentialId) return null;
    if (Biometric._bioBusy) return null;
    Biometric._bioBusy = true;
    try {
      const challenge = Utils.rand(32);
      const idBuf = Encryption.base64ToBuffer(vaultData.credentialId);
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          allowCredentials: [{ type: "public-key", id: new Uint8Array(idBuf) }],
          userVerification: "required",
          timeout: 60000
        }
      });
      if (!assertion) return null;
      const hex = await Utils.sha256Hex(String.fromCharCode.apply(null, new Uint8Array(assertion.signature)));
      return { commit: Utils.to0x(hex), ts: nowSec() }; // include freshness timestamp
    } catch (err) {
      console.error('[BioVault] Biometric ZKP failed', err);
      return null;
    } finally {
      Biometric._bioBusy = false;
    }
  }

};

async function reEnrollBiometricIfNeeded() {
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: Utils.rand(32),
        rp: { name: "BioVault", id: location.hostname },
        user: { id: Utils.rand(16), name: "user@biovault", displayName: "User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000
      }
    });
    if (!cred) return false;
    vaultData.credentialId = Encryption.bufferToBase64(cred.rawId);
    await persistVaultData(); // save with current derivedKey
    return true;
  } catch (e) {
    console.warn('[BioVault] Re-enroll failed:', e);
    return false;
  }
}

// ---------- Vault helpers for UI show/hide ----------
function revealVaultUI() {
  var wp = document.querySelector('#biovault .whitepaper');
  if (wp) wp.classList.add('hidden');
  var locked = document.getElementById('lockedScreen');
  var vault  = document.getElementById('vaultUI');
  if (locked) locked.classList.add('hidden');
  if (vault) { vault.classList.remove('hidden'); vault.style.display = 'block'; }
  try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'true'); } catch(e){}
}
function restoreLockedUI() {
  var wp = document.querySelector('#biovault .whitepaper');
  if (wp) wp.classList.remove('hidden');
  var locked = document.getElementById('lockedScreen');
  var vault  = document.getElementById('vaultUI');
  if (vault) { vault.classList.add('hidden'); vault.style.display = 'none'; }
  if (locked) locked.classList.remove('hidden');
  try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'false'); } catch(e){}
}

// ---------- Time/Caps Helpers ----------
function utcDayKey(d){ const dt=new Date(d); return dt.getUTCFullYear()+"-"+String(dt.getUTCMonth()+1).padStart(2,'0')+"-"+String(dt.getUTCDate()).padStart(2,'0'); }
function utcMonthKey(d){ const dt=new Date(d); return dt.getUTCFullYear()+"-"+String(dt.getUTCMonth()+1).padStart(2,'0'); }
function utcYearKey(d){ const dt=new Date(d); return String(new Date(d).getUTCFullYear()); }

function resetCapsIfNeeded(nowTs){
  const dKey = utcDayKey(nowTs);
  const mKey = utcMonthKey(nowTs);
  const yKey = utcYearKey(nowTs);
  if (vaultData.caps.dayKey !== dKey){ vaultData.caps.dayKey = dKey; vaultData.caps.dayUsedSeg = 0; }
  if (vaultData.caps.monthKey !== mKey){ vaultData.caps.monthKey = mKey; vaultData.caps.monthUsedSeg = 0; }
  if (vaultData.caps.yearKey !== yKey){ vaultData.caps.yearKey = yKey; vaultData.caps.yearUsedSeg = 0; vaultData.caps.tvmYearlyClaimed = 0; }
}
function canUnlockSegments(n){
  const now = Date.now();
  resetCapsIfNeeded(now);
  if (vaultData.caps.dayUsedSeg + n > DAILY_CAP_SEG) return false;
  if (vaultData.caps.monthUsedSeg + n > MONTHLY_CAP_SEG) return false;
  if (vaultData.caps.yearUsedSeg + n > YEARLY_CAP_SEG) return false;
  return true;
}
function recordUnlock(n){
  const now = Date.now();
  resetCapsIfNeeded(now);
  vaultData.caps.dayUsedSeg   += n;
  vaultData.caps.monthUsedSeg += n;
  vaultData.caps.yearUsedSeg  += n;
}

// ---------- Vault ----------
const Vault = {
  deriveKeyFromPIN: async (pin, salt) => {
    const baseKey = await crypto.subtle.importKey("raw", Utils.enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name:"PBKDF2", salt: salt, iterations: PBKDF2_ITERS, hash:"SHA-256" },
      baseKey, { name:"AES-GCM", length:AES_KEY_LENGTH }, false, ["encrypt","decrypt"]
    );
  },
  promptAndSaveVault: async (salt) => persistVaultData(salt || null),
  updateVaultUI: () => {
    var e;
    e = document.getElementById('bioIBAN');       if (e) e.textContent = vaultData.bioIBAN;
    e = document.getElementById('balanceSHE');    if (e) e.textContent = vaultData.balanceSHE;
    var tvmFloat = vaultData.balanceSHE / EXCHANGE_RATE;
    e = document.getElementById('balanceTVM');    if (e) e.textContent = tvmFloat.toFixed(4);
    e = document.getElementById('balanceUSD');    if (e) e.textContent = tvmFloat.toFixed(2);
    e = document.getElementById('bonusConstant'); if (e) e.textContent = vaultData.bonusConstant;
    e = document.getElementById('connectedAccount'); if (e) e.textContent = vaultData.userWallet || 'Not connected';

    const historyBody = document.getElementById('transactionHistory');
    if (historyBody) {
      historyBody.innerHTML = '';
      vaultData.transactions.slice(0, HISTORY_MAX).forEach(function(tx){
        const row = document.createElement('tr');
        const cols = [tx.bioIBAN, tx.bioCatch, String(tx.amount), new Date(tx.timestamp).toUTCString(), tx.status];
        cols.forEach(function(v){
          const td = document.createElement('td'); td.textContent = String(v); row.appendChild(td);
        });
        historyBody.appendChild(row);
      });
    }
  },
  lockVault: async () => {
    vaultUnlocked = false;
    try { await Vault.promptAndSaveVault(); } catch (e) { console.warn("[BioVault] save-on-lock failed", e); }
    derivedKey = null;
    restoreLockedUI();
  },
  updateBalanceFromSegments: async () => {
    const segs = await DB.loadSegmentsFromDB();
    vaultData.balanceSHE = segs.filter(function(s){ return s.currentOwner===vaultData.bioIBAN; }).length;
    Vault.updateVaultUI();
  }
};

// ---------- Network/Contract guards ----------
async function contractExists(addr) {
  if (!provider) return false;
  try {
    const code = await provider.getCode(addr);
    return code && code !== '0x';
  } catch (e) { return false; }
}
function enableDashboardButtons() {
  var ids = ['claim-tvm-btn','exchange-tvm-btn','swap-tvm-usdt-btn','swap-usdt-tvm-btn'];
  for (var i=0;i<ids.length;i++){ var b=document.getElementById(ids[i]); if (b) b.disabled = false; }
}
function disableDashboardButtons() {
  var ids = ['claim-tvm-btn','exchange-tvm-btn','swap-tvm-usdt-btn','swap-usdt-tvm-btn'];
  for (var i=0;i<ids.length;i++){ var b=document.getElementById(ids[i]); if (b) b.disabled = true; }
}

// ---------- Wallet ----------
const Wallet = {
  connectMetaMask: async () => {
    if (!window.ethereum) { alert('Install MetaMask.'); return; }
    provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send('eth_requestAccounts', []);
    signer = await provider.getSigner();
    account = await signer.getAddress();
    chainId = await provider.getNetwork().then(function(net){ return net.chainId; });
    vaultData.userWallet = account;
    UI.updateConnectedAccount();
    await Wallet.initContracts();
    await Wallet.updateBalances();
    enableDashboardButtons();
    const btn = document.getElementById('connect-wallet');
    if (btn) { btn.textContent = 'Wallet Connected'; btn.disabled = true; }
  },

  connectWalletConnect: async () => {
    let WCProvider;
    try {
      WCProvider = await import('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.14.0/dist/esm/index.js');
    } catch (e) {
      UI.showAlert('Could not load WalletConnect (offline or blocked). Try MetaMask.');
      return;
    }
    const wcProvider = await WCProvider.EthereumProvider.init({ projectId: WALLET_CONNECT_PROJECT_ID, chains:[EXPECTED_CHAIN_ID], showQrModal:true });
    await wcProvider.enable();
    provider = new ethers.BrowserProvider(wcProvider);
    signer = await provider.getSigner();
    account = await signer.getAddress();
    chainId = await provider.getNetwork().then(function(net){ return net.chainId; });
    vaultData.userWallet = account;
    UI.updateConnectedAccount();
    await Wallet.initContracts();
    await Wallet.updateBalances();
    enableDashboardButtons();
    const btn = document.getElementById('connect-wallet');
    if (btn) { btn.textContent = 'Wallet Connected'; btn.disabled = true; }
  },

  initContracts: async () => {
    try {
      if (Number(chainId) !== EXPECTED_CHAIN_ID) {
        UI.showAlert('Wrong network. Please switch to the expected network.');
        tvmContract = null; usdtContract = null; disableDashboardButtons(); return;
      }
      const tvmAddr = CONTRACT_ADDRESS.toLowerCase();
      const usdtAddr = USDT_ADDRESS.toLowerCase();

      const tvmOk  = await contractExists(tvmAddr);
      const usdtOk = await contractExists(usdtAddr);

      if (!tvmOk || !usdtOk) {
        UI.showAlert('Contract(s) not deployed on this network. Dashboard features disabled.');
        tvmContract = null; usdtContract = null; disableDashboardButtons(); return;
      }

      tvmContract  = new ethers.Contract(tvmAddr, ABI, signer);
      usdtContract = new ethers.Contract(usdtAddr, [
        {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
        {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
      ], signer);
      console.log('[BioVault] Contracts initialized');
    } catch (e) {
      console.error('[BioVault] initContracts failed', e);
      tvmContract = null; usdtContract = null; disableDashboardButtons();
    }
  },

  updateBalances: async () => {
    try {
      if (!account || !provider) return;
      // placeholders
      var ub = document.getElementById('user-balance'); if (ub) ub.textContent = '— TVM';
      var uu = document.getElementById('usdt-balance'); if (uu) uu.textContent = '— USDT';

      const tvmOk = await contractExists(CONTRACT_ADDRESS.toLowerCase());
      const usdtOk = await contractExists(USDT_ADDRESS.toLowerCase());
      if (!tvmOk || !usdtOk || !tvmContract || !usdtContract) return;

      const tvmBal = await tvmContract.balanceOf(account);
      if (ub) ub.textContent = ethers.formatUnits(tvmBal, 18) + ' TVM';

      const usdtBal = await usdtContract.balanceOf(account);
      if (uu) uu.textContent = ethers.formatUnits(usdtBal, 6) + ' USDT';

      var e3 = document.getElementById('tvm-price');    if (e3) e3.textContent  = '1.00 USDT';
      var e4 = document.getElementById('pool-ratio');   if (e4) e4.textContent = '51% HI / 49% AI';
      var e5 = document.getElementById('avg-reserves'); if (e5) e5.textContent = '100M TVM';
    } catch (e) {
      console.warn('Balance refresh failed:', e);
    }
  },

  ensureAllowance: async (token, owner, spender, amount) => {
    if (!token || !token.allowance) return;
    const a = await token.allowance(owner, spender);
    if (a < amount) {
      const tx = await token.approve(spender, amount);
      await tx.wait();
    }
  },

  getOnchainBalances: async () => {
    if (!tvmContract || !usdtContract || !account) throw new Error('Connect wallet first.');
    const tvm  = await tvmContract.balanceOf(account);
    const usdt = await usdtContract.balanceOf(account);
    return { tvm: tvm, usdt: usdt };
  }
};

// ---------- Segment (Micro-ledger) ----------
const Segment = {
  // Compute next integrity hash (chaining)
  _nextHash: async (prevHash, event, timestamp, from, to, bioConst) => {
    return await Utils.sha256Hex(prevHash + event + timestamp + from + to + bioConst);
  },

  // Initialize initial 1..1200 as UNLOCKED (ownershipChangeCount=1)
  initializeSegments: async () => {
    const now = Date.now();
    for (let i = 1; i <= INITIAL_BALANCE_SHE; i++) {
      const initHash = await Utils.sha256Hex('init' + i + vaultData.bioIBAN);
      const unlockedTs = now + i; // stagger by i ms
      const unlockHash = await Utils.sha256Hex(initHash + 'Unlock' + unlockedTs + 'Genesis' + vaultData.bioIBAN + (GENESIS_BIO_CONSTANT + i + 1));
      const segment = {
        segmentIndex: i,
        currentOwner: vaultData.bioIBAN,
        ownershipChangeCount: 1, // IMPORTANT for on-chain mint eligibility
        claimed: false,          // used for TVM claims
        history: [
          {
            event:'Initialization',
            timestamp: now,
            from:'Genesis',
            to: vaultData.bioIBAN,
            bioConst: GENESIS_BIO_CONSTANT + i,
            integrityHash: initHash
          },
          {
            event:'Unlock',
            timestamp: unlockedTs,
            from:'Genesis',
            to: vaultData.bioIBAN,
            bioConst: GENESIS_BIO_CONSTANT + i + 1,
            integrityHash: unlockHash
          }
        ]
      };
      await DB.saveSegmentToDB(segment);
    }
    vaultData.balanceSHE = INITIAL_BALANCE_SHE;
    vaultData.nextSegmentIndex = INITIAL_BALANCE_SHE + 1;
  },

  // Unlock the next N locked indices deterministically (1201..)
  unlockNextSegments: async (count) => {
    if (count <= 0) return 0;
    if (!canUnlockSegments(count)) return 0;

    let created = 0;
    const now = Date.now();
    for (let k = 0; k < count; k++) {
      const idx = vaultData.nextSegmentIndex;
      if (idx > LAYERS * SEGMENTS_PER_LAYER) break; // yearly hard cap
      const initHash = await Utils.sha256Hex('init' + idx + vaultData.bioIBAN);
      const ts = now + k;
      const unlockHash = await Utils.sha256Hex(initHash + 'Unlock' + ts + 'Locked' + vaultData.bioIBAN + (GENESIS_BIO_CONSTANT + idx + 1));
      const seg = {
        segmentIndex: idx,
        currentOwner: vaultData.bioIBAN,
        ownershipChangeCount: 1 // newly unlocked -> 1 change
        ,
        claimed: false,
        history: [
          { event:'Initialization', timestamp: ts, from:'Locked', to:vaultData.bioIBAN, bioConst: GENESIS_BIO_CONSTANT + idx, integrityHash: initHash },
          { event:'Unlock', timestamp: ts, from:'Locked', to:vaultData.bioIBAN, bioConst: GENESIS_BIO_CONSTANT + idx + 1, integrityHash: unlockHash }
        ]
      };
      await DB.saveSegmentToDB(seg);
      vaultData.nextSegmentIndex = idx + 1;
      created++;
    }
    if (created > 0) {
      recordUnlock(created);
      await Vault.updateBalanceFromSegments();
      await persistVaultData();
    }
    return created;
  },

  // Validate a segment chain (used for P2P receive)
  validateSegment: async (segment) => {
    if (!segment || !Array.isArray(segment.history) || segment.history.length === 0) return false;
    const init = segment.history[0];
    const expectedInit = await Utils.sha256Hex('init' + segment.segmentIndex + init.to);
    if (init.integrityHash !== expectedInit) return false;

    let hash = init.integrityHash;
    for (let j=1;j<segment.history.length;j++) {
      const h = segment.history[j];
      hash = await Utils.sha256Hex(hash + h.event + h.timestamp + h.from + h.to + h.bioConst);
      if (h.integrityHash !== hash) return false;
    }
    const last = segment.history[segment.history.length - 1];
    if (last.biometricZKP && !/^0x[0-9a-fA-F]{64}$/.test(last.biometricZKP)) return false;
    return true;
  }
};

// ---------- P2P helpers: compact/encrypt payload ----------
function toCompactChains(chains) {
  function eShort(e){ return e==='Transfer' ? 'T' : (e==='Received' ? 'R' : (e==='Unlock' ? 'U' : (e==='Claimed' ? 'C' : 'I'))); }
  var out = [];
  for (var i=0;i<chains.length;i++){
    var c = chains[i];
    var h = [];
    for (var j=0;j<c.history.length;j++){
      var x = c.history[j];
      h.push({ e: eShort(x.event), t: x.timestamp, f: x.from, o: x.to, b: x.bioConst, x: x.integrityHash, z: x.biometricZKP });
    }
    out.push({ i: c.segmentIndex, h: h });
  }
  return out;
}
function fromCompactChains(comp) {
  function eLong(e){ return e==='T' ? 'Transfer' : (e==='R' ? 'Received' : (e==='U' ? 'Unlock' : (e==='C' ? 'Claimed' : 'Initialization'))); }
  var out = [];
  for (var i=0;i<comp.length;i++){
    var c = comp[i];
    var h = [];
    for (var j=0;j<c.h.length;j++){
      var x = c.h[j];
      h.push({ event: eLong(x.e), timestamp: x.t, from: x.f, to: x.o, bioConst: x.b, integrityHash: x.x, biometricZKP: x.z });
    }
    out.push({ segmentIndex: c.i, history: h });
  }
  return out;
}

// ---------- CBOR + Varint Streaming (for P2P payloads) ----------
// Minimal CBOR implementation (subset): unsigned/signed ints, byte strings, text, arrays, maps, bool, null.
// Only what we need for wrapping our binary stream as {c: <bstr>, t: <int>, n: <text?>}.
const CBOR = (function(){
  function encodeItem(x, out){
    if (x === null){ out.push(0xf6); return; }
    if (x === true){ out.push(0xf5); return; }
    if (x === false){ out.push(0xf4); return; }
    if (typeof x === "number"){
      if (!Number.isInteger(x)) throw new Error("CBOR: only ints supported here");
      if (x >= 0){ writeUnsigned(0, x, out); } else { writeUnsigned(1, -(x+1), out); }
      return;
    }
    if (x instanceof Uint8Array){
      writeUnsigned(2, x.length, out);
      for (let i=0;i<x.length;i++) out.push(x[i]);
      return;
    }
    if (typeof x === "string"){
      const b = new TextEncoder().encode(x);
      writeUnsigned(3, b.length, out);
      for (let i=0;i<b.length;i++) out.push(b[i]);
      return;
    }
    if (Array.isArray(x)){
      writeUnsigned(4, x.length, out);
      for (let i=0;i<x.length;i++) encodeItem(x[i], out);
      return;
    }
    if (typeof x === "object"){
      const keys = Object.keys(x);
      writeUnsigned(5, keys.length, out);
      for (let i=0;i<keys.length;i++){
        encodeItem(keys[i], out);
        encodeItem(x[keys[i]], out);
      }
      return;
    }
    throw new Error("CBOR: unsupported type");
  }
  function writeUnsigned(major, n, out){
    if (n < 24){ out.push((major<<5)|n); return; }
    if (n < 0x100){ out.push((major<<5)|24, n); return; }
    if (n < 0x10000){ out.push((major<<5)|25, (n>>8)&0xff, n&0xff); return; }
    if (n < 0x100000000){ out.push((major<<5)|26,(n>>>24)&0xff,(n>>>16)&0xff,(n>>>8)&0xff,n&0xff); return; }
    const hi = Math.floor(n / 0x100000000);
    const lo = n >>> 0;
    out.push((major<<5)|27,(hi>>>24)&0xff,(hi>>>16)&0xff,(hi>>>8)&0xff,hi&0xff,(lo>>>24)&0xff,(lo>>>16)&0xff,(lo>>>8)&0xff,lo&0xff);
  }
  function readUint(view, offObj, addl){
    if (addl < 24) return addl;
    if (addl === 24){ const v = view[offObj.o]; offObj.o+=1; return v; }
    if (addl === 25){ const v = (view[offObj.o]<<8) | view[offObj.o+1]; offObj.o+=2; return v; }
    if (addl === 26){ const v = (view[offObj.o]<<24)|(view[offObj.o+1]<<16)|(view[offObj.o+2]<<8)|view[offObj.o+3]; offObj.o+=4; return v>>>0; }
    if (addl === 27){
      const hi=(view[offObj.o]<<24)|(view[offObj.o+1]<<16)|(view[offObj.o+2]<<8)|view[offObj.o+3];
      const lo=(view[offObj.o+4]<<24)|(view[offObj.o+5]<<16)|(view[offObj.o+6]<<8)|view[offObj.o+7];
      offObj.o+=8; return hi*0x100000000 + (lo>>>0);
    }
    throw new Error("CBOR: indefinite not supported");
  }
  function decodeItem(view, offObj){
    const ib = view[offObj.o]; offObj.o+=1;
    const major = ib>>5, addl = ib & 0x1f;
    if (major===0){ return readUint(view, offObj, addl); }
    if (major===1){ const u=readUint(view, offObj, addl); return -(u+1); }
    if (major===2){
      const len = readUint(view, offObj, addl);
      const out = view.subarray(offObj.o, offObj.o+len);
      offObj.o += len; return new Uint8Array(out);
    }
    if (major===3){
      const len = readUint(view, offObj, addl);
      const s = new TextDecoder().decode(view.subarray(offObj.o, offObj.o+len));
      offObj.o += len; return s;
    }
    if (major===4){
      const len = readUint(view, offObj, addl);
      const arr = new Array(len);
      for (let i=0;i<len;i++) arr[i]=decodeItem(view, offObj);
      return arr;
    }
    if (major===5){
      const len = readUint(view, offObj, addl);
      const obj = {};
      for (let i=0;i<len;i++){
        const k = decodeItem(view, offObj);
        const v = decodeItem(view, offObj);
        obj[k]=v;
      }
      return obj;
    }
    if (major===7){
      if (addl===20) return false;
      if (addl===21) return true;
      if (addl===22) return null;
    }
    throw new Error("CBOR: unsupported major/addl: "+major+"/"+addl);
  }
  return {
    encode: function(x){ const out=[]; encodeItem(x,out); return new Uint8Array(out); },
    decode: function(bytes){ const off={o:0}; return decodeItem(bytes instanceof Uint8Array?bytes:new Uint8Array(bytes), off); }
  };
})();

// Varint (unsigned LEB128)
const Varint = {
  enc: function(u){ const out=[]; while(u>0x7f){ out.push((u&0x7f)|0x80); u>>>=7; } out.push(u&0x7f); return out; },
  dec: function(view, offObj){ let x=0,s=0,b; do{ b=view[offObj.o++]; x|=(b&0x7f)<<s; s+=7; }while(b&0x80); return x>>>0; }
};
function hexToBytes(h){ if(h.startsWith('0x')) h=h.slice(2); const out=new Uint8Array(h.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(h.substr(i*2,2),16); return out; }
function bytesToHex(b){ let s='0x'; for(let i=0;i<b.length;i++) s+=b[i].toString(16).padStart(2,'0'); return s; }

// ChainsCodec: builds a compact binary stream with varints and bytes, then wraps with CBOR for the envelope.
const ChainsCodec = {
  encode: function(compactChains){
    const addrSet = new Map();
    function addAddr(a){ if(!addrSet.has(a)) addrSet.set(a, addrSet.size); }
    for (let c of compactChains){ for(let h of c.h){ addAddr(h.f); addAddr(h.o); } }
    const addrs = Array.from(addrSet.keys());
    const bu = [];
    // address table
    Varint.enc(addrs.length).forEach(b=>bu.push(b));
    const te = new TextEncoder();
    for (let a of addrs){
      const ab = te.encode(a);
      Varint.enc(ab.length).forEach(b=>bu.push(b));
      for (let i=0;i<ab.length;i++) bu.push(ab[i]);
    }
    // chains
    Varint.enc(compactChains.length).forEach(b=>bu.push(b));
    let prevIdx = 0;
    for (let c of compactChains){
      const segIdxDelta = c.i - prevIdx; prevIdx = c.i;
      Varint.enc(segIdxDelta).forEach(b=>bu.push(b));
      const baseT = c.h.length? c.h[0].t : 0;
      const baseB = c.h.length? c.h[0].b : 0;
      Varint.enc(baseT).forEach(b=>bu.push(b));
      Varint.enc(baseB).forEach(b=>bu.push(b));
      Varint.enc(c.h.length).forEach(b=>bu.push(b));
      let lastT = baseT, lastB = baseB;
      for (let e of c.h){
        const code = e.e==='I'?0:(e.e==='U'?1:(e.e==='T'?2:(e.e==='R'?3:(e.e==='C'?4:255))));
        Varint.enc(code).forEach(b=>bu.push(b));
        Varint.enc(addrSet.get(e.f)).forEach(b=>bu.push(b));
        Varint.enc(addrSet.get(e.o)).forEach(b=>bu.push(b));
        Varint.enc(e.t - lastT).forEach(b=>bu.push(b)); lastT = e.t;
        Varint.enc(e.b - lastB).forEach(b=>bu.push(b)); lastB = e.b;
        const hx = hexToBytes(e.x); for (let i=0;i<hx.length;i++) bu.push(hx[i]);
        if (e.z && /^0x[0-9a-fA-F]{64}$/.test(e.z)){
          Varint.enc(1).forEach(b=>bu.push(b));
          const zz = hexToBytes(e.z); for (let i=0;i<zz.length;i++) bu.push(zz[i]);
        } else { Varint.enc(0).forEach(b=>bu.push(b)); }
      }
    }
    return new Uint8Array(bu);
  },
  decode: function(bytes){
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const off = {o:0};
    const addrCount = Varint.dec(view, off);
    const addrs = [];
    const td = new TextDecoder();
    for (let i=0;i<addrCount;i++){
      const L = Varint.dec(view, off);
      const s = td.decode(view.subarray(off.o, off.o+L)); off.o+=L;
      addrs.push(s);
    }
    const chainCount = Varint.dec(view, off);
    const chains = [];
    let prevIdx = 0;
    for (let ci=0;ci<chainCount;ci++){
      const segIdx = prevIdx + Varint.dec(view, off); prevIdx = segIdx;
      const baseT = Varint.dec(view, off);
      const baseB = Varint.dec(view, off);
      const evCount = Varint.dec(view, off);
      let lastT = baseT, lastB = baseB;
      const hist = [];
      for (let ei=0;ei<evCount;ei++){
        const code = Varint.dec(view, off);
        const fidx = Varint.dec(view, off);
        const oidx = Varint.dec(view, off);
        const dt = Varint.dec(view, off); lastT += dt;
        const db = Varint.dec(view, off); lastB += db;
        const hx = view.subarray(off.o, off.o+32); off.o+=32;
        const hasZ = Varint.dec(view, off);
        let z = null;
        if (hasZ){ const zz = view.subarray(off.o, off.o+32); off.o+=32; z = bytesToHex(zz); }
        const e = code===0?'I':(code===1?'U':(code===2?'T':(code===3?'R':'C')));
        hist.push({ e: e, t: lastT, f: addrs[fidx], o: addrs[oidx], b: lastB, x: bytesToHex(hx), z: z });
      }
      chains.push({ i: segIdx, h: hist });
    }
    return chains;
  }
};

// Extend Encryption with raw bytes helpers (AES-GCM)
Encryption.encryptBytes = async function(key, bytesU8){
  const iv = Utils.rand(12);
  const ciphertext = await crypto.subtle.encrypt({ name:'AES-GCM', iv: iv }, key, bytesU8);
  return { iv: iv, ciphertext: ciphertext };
};
Encryption.decryptBytes = async function(key, iv, ciphertext){
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv: iv }, key, ciphertext);
  return new Uint8Array(pt);
};

// Derive transport key from from|to|nonce (transport privacy; both sides can derive)
async function deriveP2PKey(from, to, nonce) {
  const salt = Utils.enc.encode('BC-P2P|' + from + '|' + to + '|' + String(nonce));
  const base = await crypto.subtle.importKey("raw", HMAC_KEY, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt: salt, iterations: 120000, hash:"SHA-256" },
    base, { name:"AES-GCM", length: AES_KEY_LENGTH }, false, ["encrypt","decrypt"]
  );
}

async function handleIncomingChains(chains, fromIBAN, toIBAN) {
  var validSegments = 0;
  for (var i=0;i<chains.length;i++) {
    var entry = chains[i];
    var seg = await DB.getSegment(entry.segmentIndex);
    var reconstructed = seg ? JSON.parse(JSON.stringify(seg)) : { segmentIndex: entry.segmentIndex, currentOwner: 'Unknown', ownershipChangeCount: (seg && seg.ownershipChangeCount) || 0, claimed: false, history: [] };
    for (var j=0;j<entry.history.length;j++) reconstructed.history.push(entry.history[j]);

    if (!(await Segment.validateSegment(reconstructed))) continue;

    const last = reconstructed.history[reconstructed.history.length - 1];
    if (last.to !== vaultData.bioIBAN) continue;

    const timestamp = Date.now();
    const bioConst = last.bioConst + BIO_STEP;
    const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Received' + timestamp + last.from + vaultData.bioIBAN + bioConst);
    const zkpIn = await Biometric.generateBiometricZKP();
    reconstructed.history.push({ event:'Received', timestamp: timestamp, from:last.from, to:vaultData.bioIBAN, bioConst: bioConst, integrityHash: integrityHash, biometricZKP: zkpIn });
    reconstructed.currentOwner = vaultData.bioIBAN;
    reconstructed.ownershipChangeCount = (reconstructed.ownershipChangeCount || 0) + 1;
    reconstructed.claimed = reconstructed.claimed || false;
    await DB.saveSegmentToDB(reconstructed);
    validSegments++;
  }
  if (validSegments > 0) {
    vaultData.transactions.push({ bioIBAN: vaultData.bioIBAN, bioCatch:'Incoming', amount: validSegments / EXCHANGE_RATE, timestamp: Date.now(), status:'Received' });
    await Vault.updateBalanceFromSegments();
    UI.showAlert('Received ' + validSegments + ' valid segments.');
    await persistVaultData();
  } else {
    UI.showAlert('No valid segments received.');
  }
}

// ---------- Proofs (on-chain TVM mint) ----------
const Proofs = {
  // Build proofs from actual local segments with ownershipChangeCount === 1 and not claimed
  prepareClaimBatch: async (segmentsNeeded) => {
    if (!vaultUnlocked) throw new Error('Vault locked.');
    const segs = await DB.loadSegmentsFromDB();
    // eligible for claim: owned by me, not claimed, exactly one ownership change (per rule)
    const eligible = segs.filter(function(s){
      return s.currentOwner === vaultData.bioIBAN && !s.claimed && Number(s.ownershipChangeCount||0) === 1;
    });
    if (eligible.length < segmentsNeeded) return { proofs: [], used: [] };

    // choose first required indices (deterministic for UX)
    const chosen = eligible.slice(0, segmentsNeeded).sort(function(a,b){ return a.segmentIndex - b.segmentIndex; });
    const biometricZKP = await Biometric.generateBiometricZKP();
    if (!biometricZKP) throw new Error('Biometric ZKP generation failed or was denied.');

    const coder = ethers.AbiCoder.defaultAbiCoder();

    const proofs = [];
    for (let i=0;i<chosen.length;i++){
      const s = chosen[i];
      const last = s.history[s.history.length - 1];
      const baseStr = 'seg|' + s.segmentIndex + '|' + vaultData.bioIBAN + '|' + (s.ownershipChangeCount||1) + '|' + last.integrityHash + '|' + last.bioConst;
      const ownershipProof        = Utils.to0x(await Utils.sha256Hex('own|'    + baseStr));
      const unlockIntegrityProof  = Utils.to0x(await Utils.sha256Hex('unlock|' + baseStr));
      const spentProof            = Utils.to0x(await Utils.sha256Hex('spent|'  + baseStr));

      proofs.push({
        segmentIndex: s.segmentIndex,
        currentBioConst: last.bioConst,
        ownershipProof: ownershipProof,
        unlockIntegrityProof: unlockIntegrityProof,
        spentProof: spentProof,
        ownershipChangeCount: 1,
        biometricZKP: biometricZKP.commit   // <-- was biometricZKP
      });
    }

    const inner = proofs.map(function(p){
      return ethers.keccak256(coder.encode(
        ['uint256','uint256','bytes32','bytes32','bytes32','uint256','bytes32'],
        [p.segmentIndex, p.currentBioConst, p.ownershipProof, p.unlockIntegrityProof, p.spentProof, p.ownershipChangeCount, p.biometricZKP]
      ));
    });
    const proofsHash = ethers.keccak256(coder.encode(['bytes32[]'], [inner]));

    const deviceKeyHash = vaultData.deviceKeyHash;
    const userBioConstant = proofs[0] ? proofs[0].currentBioConst : vaultData.initialBioConstant;
    const nonce = Math.floor(Math.random() * 1000000000);

    const domain = { name: 'TVM', version: '1', chainId: Number(chainId || EXPECTED_CHAIN_ID), verifyingContract: CONTRACT_ADDRESS.toLowerCase() };
    const types = { Claim: [
      { name: 'user', type: 'address' },
      { name: 'proofsHash', type: 'bytes32' },
      { name: 'deviceKeyHash', type: 'bytes32' },
      { name: 'userBioConstant', type: 'uint256' },
      { name: 'nonce', type: 'uint256' }
    ]};
    const value = { user: account, proofsHash: proofsHash, deviceKeyHash: deviceKeyHash, userBioConstant: userBioConstant, nonce: nonce };
    const signature = await signer.signTypedData(domain, types, value);

    return { proofs, signature, deviceKeyHash, userBioConstant, nonce, used: chosen };
  },

  // After on-chain success, mark segments as claimed
  markClaimed: async (segmentsUsed) => {
    for (let i=0;i<segmentsUsed.length;i++){
      const s = segmentsUsed[i];
      s.claimed = true;
      // Optional: append lightweight 'Claimed' event (does not affect count)
      const last = s.history[s.history.length - 1];
      const ts = Date.now();
      const bio = last.bioConst + 1;
      const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Claimed' + ts + vaultData.bioIBAN + 'OnChain' + bio);
      s.history.push({ event:'Claimed', timestamp: ts, from:vaultData.bioIBAN, to:'OnChain', bioConst: bio, integrityHash: integrityHash });
      await DB.saveSegmentToDB(s);
    }
  }
};

// ---------- UI ----------
const UI = {
  showAlert: (msg) => alert(msg),
  showLoading: (id) => { var el=document.getElementById(id + '-loading'); if (el) el.classList.remove('hidden'); },
  hideLoading: (id) => { var el=document.getElementById(id + '-loading'); if (el) el.classList.add('hidden'); },
  updateConnectedAccount: () => {
    var ca=document.getElementById('connectedAccount');
    if (ca) ca.textContent = account ? (account.slice(0,6)+'...'+account.slice(-4)) : 'Not connected';
    var wa=document.getElementById('wallet-address');
    if (wa) wa.textContent  = account ? ('Connected: '+account.slice(0,6)+'...'+account.slice(-4)) : '';
  }
};

// ---------- Contract Interactions ----------
const withBuffer = (g) => {
  try { return (g * 120n) / 100n; }           // BigInt path
  catch (_) { return Math.floor(Number(g) * 1.2); } // Fallback for ES2018 engines
};
const ensureReady = () => {
  if (!account || !tvmContract) { UI.showAlert('Connect your wallet first.'); return false; }
  return true;
};

const ContractInteractions = {
  claimTVM: async (tvmToClaim /* optional integer */) => {
    if (!ensureReady() || !tvmContract || typeof tvmContract.claimTVM !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('claim');
    try {
      // Determine segments needed (12 per TVM); default 1 TVM
      const tvmAmount = Math.max(1, parseInt(tvmToClaim || 1, 10));
      const needSeg = tvmAmount * SEGMENTS_PER_TVM;

      const prep = await Proofs.prepareClaimBatch(needSeg);
      if (!prep.proofs || prep.proofs.length !== needSeg) {
        UI.showAlert('Not enough eligible segments (need ' + needSeg + ' with ownershipChangeCount=1).'); return;
      }

      // Yearly TVM cap guard (local mirror, contract is source of truth)
      resetCapsIfNeeded(Date.now());
      if (vaultData.caps.tvmYearlyClaimed + tvmAmount > MAX_YEARLY_TVM_TOTAL) {
        UI.showAlert('Yearly TVM cap reached locally.'); return;
      }

      // Gas estimate
      var overrides = {};
      try {
        var ge = await tvmContract.estimateGas.claimTVM(prep.proofs, prep.signature, prep.deviceKeyHash, prep.userBioConstant, prep.nonce);
        overrides.gasLimit = withBuffer(ge);
      } catch (e) { console.warn('estimateGas failed; sending without explicit gasLimit', e); }

      const tx = await tvmContract.claimTVM(prep.proofs, prep.signature, prep.deviceKeyHash, prep.userBioConstant, prep.nonce, overrides);
      await tx.wait();

      // Mark claimed locally and bump yearly TVM counter
      await Proofs.markClaimed(prep.used);
      vaultData.caps.tvmYearlyClaimed += tvmAmount;

      UI.showAlert('Claim successful: ' + tvmAmount + ' TVM (' + needSeg + ' segments).');
      Wallet.updateBalances();

      // Clear transient autoProofs cache (not used anymore)
      autoProofs = null;
      await persistVaultData();
    } catch (err) {
      console.error(err);
      UI.showAlert('Error claiming TVM: ' + (err.reason || err.message || err));
    } finally {
      UI.hideLoading('claim');
    }
  },

  exchangeTVMForSegments: async () => {
    if (!ensureReady() || !tvmContract || typeof tvmContract.exchangeTVMForSegments !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('exchange');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.tvm;
      if (amount === 0n) { UI.showAlert('No TVM to exchange.'); return; }
      var overrides = {};
      try { var ge = await tvmContract.estimateGas.exchangeTVMForSegments(amount); overrides.gasLimit = withBuffer(ge); } catch(e){}
      const tx = await tvmContract.exchangeTVMForSegments(amount, overrides);
      await tx.wait();
      UI.showAlert('Exchange successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error exchanging: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('exchange');
    }
  },

  swapTVMForUSDT: async () => {
    if (!ensureReady() || !tvmContract || typeof tvmContract.swapTVMForUSDT !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('swap');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.tvm;
      if (amount === 0n) { UI.showAlert('No TVM to swap.'); return; }
      var overrides = {};
      try { var ge = await tvmContract.estimateGas.swapTVMForUSDT(amount); overrides.gasLimit = withBuffer(ge); } catch(e){}
      const tx = await tvmContract.swapTVMForUSDT(amount, overrides);
      await tx.wait();
      UI.showAlert('Swap successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error swapping: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('swap');
    }
  },

  swapUSDTForTVM: async () => {
    if (!ensureReady() || !tvmContract || typeof tvmContract.swapUSDTForTVM !== 'function') {
      UI.showAlert('TVM contract not available on this network.'); return;
    }
    UI.showLoading('swap-usdt');
    try {
      const bals = await Wallet.getOnchainBalances();
      const amount = bals.usdt;
      if (amount === 0n) { UI.showAlert('No USDT to swap.'); return; }
      await Wallet.ensureAllowance(usdtContract, account, CONTRACT_ADDRESS.toLowerCase(), amount);
      var overrides = {};
      try { var ge = await tvmContract.estimateGas.swapUSDTForTVM(amount); overrides.gasLimit = withBuffer(ge); } catch(e){}
      const tx = await tvmContract.swapUSDTForTVM(amount, overrides);
      await tx.wait();
      UI.showAlert('Swap USDT→TVM successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error swapping USDT to TVM: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('swap-usdt');
    }
  }
};

// ---------- P2P (modal-integrated) ----------
const P2P = {
  // Core builder used by modal form — PATCHED to CBOR+varint (v:3)
  createCatchOut: async function(recipientIBAN, amountSegments, note) {
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
      if (!vaultUnlocked) return UI.showAlert('Vault locked.');
      const amount = parseInt(amountSegments, 10);
      if (isNaN(amount) || amount <= 0 || amount > vaultData.balanceSHE) return UI.showAlert('Invalid amount.');
      if (amount > 300) return UI.showAlert('Amount exceeds per-transfer segment limit.');

      const segments = await DB.loadSegmentsFromDB();
      const transferable = segments
        .filter(function(s){ return s.currentOwner === vaultData.bioIBAN && !s.claimed && Number(s.ownershipChangeCount||0) >= 1; })
        .slice(0, amount);
      if (transferable.length < amount) return UI.showAlert('Insufficient unlocked segments.');

      const zkp = await Biometric.generateBiometricZKP();
      if (!zkp) return UI.showAlert('Biometric ZKP generation failed.');

      var header = { from: vaultData.bioIBAN, to: recipientIBAN, nonce: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + '-' + Math.random()) };
      var chainsOut = [];

      for (let k=0;k<transferable.length;k++) {
        const s = transferable[k];
        const last = s.history[s.history.length - 1];
        const timestamp = Date.now();
        const bioConst = last.bioConst + BIO_STEP;
        const integrityHash = await Utils.sha256Hex(last.integrityHash + 'Transfer' + timestamp + vaultData.bioIBAN + recipientIBAN + bioConst);
        const newHistory = { event:'Transfer', timestamp: timestamp, from:vaultData.bioIBAN, to:recipientIBAN, bioConst: bioConst, integrityHash: integrityHash, biometricZKP: zkp };
        s.history.push(newHistory);
        s.currentOwner = recipientIBAN;
        s.ownershipChangeCount = (s.ownershipChangeCount || 0) + 1;
        await DB.saveSegmentToDB(s);
        chainsOut.push({ segmentIndex: s.segmentIndex, history: s.history.slice(-SEGMENT_HISTORY_MAX) });
      }

      vaultData.transactions.push({ bioIBAN: vaultData.bioIBAN, bioCatch: 'Outgoing to ' + recipientIBAN, amount: amount / EXCHANGE_RATE, timestamp: Date.now(), status: 'Sent' });
      await Vault.updateBalanceFromSegments();

      const created = await Segment.unlockNextSegments(amount);
      if (created < amount) {
        UI.showAlert('Unlocked only '+created+' of '+amount+' due to caps. Balance may drop until caps reset.');
      }
      await Vault.updateBalanceFromSegments();
      await persistVaultData();

      // ---- CBOR + Varint streaming compression (v:3) ----
      var chainsOutCompact = toCompactChains(chainsOut);
      var packed = ChainsCodec.encode(chainsOutCompact);                 // Uint8Array
      var bodyCbor = CBOR.encode({ c: packed, t: Date.now(), n: note || '' }); // Uint8Array CBOR map

      var p2pKey = await deriveP2PKey(header.from, header.to, header.nonce);
      var enc = await Encryption.encryptBytes(p2pKey, bodyCbor);
      var payload = {
        v: 3,
        from: header.from,
        to: header.to,
        nonce: header.nonce,
        iv: Encryption.bufferToBase64(enc.iv),
        ct: Encryption.bufferToBase64(enc.ciphertext)
      };
      // Encode the v:3 envelope itself as CBOR and present it as base64

      lastCatchOutPayload = payload;
      // ---- CBOR encode the v:3 envelope (binary) ----
        const cborEnvelope = CBOR.encode(payload);        // Uint8Array
        lastCatchOutPayloadBytes = cborEnvelope;          // keep raw bytes
        lastCatchOutPayloadStr   = _u8ToB64(cborEnvelope);// keep for QR fallback
        lastCatchOutFileName     = 'biovault_catchout_' + header.nonce + '.cbor';

        // 1) Immediately offer a .cbor file download (primary UX)
        downloadBytes(lastCatchOutFileName, lastCatchOutPayloadBytes, 'application/cbor');

        // 2) Still open the result modal, but show Download + QR options (no raw text)
        await showCatchOutResultModal(); // note: no args; it will use the cached globals

    } finally {
      transactionLock = false;
    }
  },

  // Import handler — PATCHED to support v:3 CBOR+varint first, then v:2 JSON, then v:1 legacy
  importCatchIn: async function(payloadStr) {
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
      if (!vaultUnlocked) return UI.showAlert('Vault locked.');
      if (!payloadStr) return;

      if (payloadStr.length > 1200000) return UI.showAlert('Payload too large.');

      let envelope = null;
      try { envelope = JSON.parse(payloadStr); } catch (_) { /* not JSON */ }
      // If not JSON, try base64->CBOR decode (v:3 CBOR envelope)
      if (!envelope) {
        try {
          const bytes = Encryption.base64ToBuffer(payloadStr);    // ArrayBuffer
          const u8 = new Uint8Array(bytes);
          envelope = CBOR.decode(u8);
        } catch (e) {
          return UI.showAlert('Invalid payload: neither JSON nor base64-CBOR.');
        }
      }
      if (!envelope) return UI.showAlert('Malformed payload.');
      // Replay protection
      if (!envelope.nonce) return UI.showAlert('Malformed payload: missing nonce.');
      if (await DB.hasReplayNonce(envelope.nonce)) return UI.showAlert('Duplicate transfer detected (replay).');
      await DB.putReplayNonce(envelope.nonce);

      // New v:3 (CBOR + varint stream)
      if (envelope.v === 3 && envelope.iv && envelope.ct) {
        var p2pKey = await deriveP2PKey(envelope.from, envelope.to, envelope.nonce);
        var bytes = await Encryption.decryptBytes(
          p2pKey,
          Encryption.base64ToBuffer(envelope.iv),
          Encryption.base64ToBuffer(envelope.ct)
        );
        var obj = CBOR.decode(bytes);
        if (!obj || !(obj.c instanceof Uint8Array)) return UI.showAlert('Decrypted CBOR invalid.');
        var expandedChains = ChainsCodec.decode(obj.c);           // [{i,h:[...]}]
        await handleIncomingChains(fromCompactChains(expandedChains), envelope.from, envelope.to);
        return;
      }

      // Backward-compatible v:2 (encrypted JSON)
      if (envelope.v === 2 && envelope.iv && envelope.ct) {
        var p2pKey2 = await deriveP2PKey(envelope.from, envelope.to, envelope.nonce);
        var obj2 = await Encryption.decryptData(
          p2pKey2,
          Encryption.base64ToBuffer(envelope.iv),
          Encryption.base64ToBuffer(envelope.ct)
        );
        if (!obj2 || !Array.isArray(obj2.c)) return UI.showAlert('Decrypted payload invalid.');
        var expandedChains2 = fromCompactChains(obj2.c);
        await handleIncomingChains(expandedChains2, envelope.from, envelope.to);
        return;
      }

      // Legacy v:1 plaintext
      if (envelope.v === 1 && Array.isArray(envelope.chains)) {
        await handleIncomingChains(envelope.chains, envelope.from, envelope.to);
        return;
      }

      UI.showAlert('Unsupported or malformed payload.');
    } finally {
      transactionLock = false;
    }
  }

  
};

// New: direct import from a .cbor file
P2P.importCatchInFile = async function(file){
    if (transactionLock) return UI.showAlert('Another transaction is in progress. Please wait.');
    transactionLock = true;
    try {
        if (!vaultUnlocked) return UI.showAlert('Vault locked.');
        if (!file) return UI.showAlert('No file selected.');

        // Read .cbor as ArrayBuffer → Uint8Array → CBOR.decode
        const buf = await file.arrayBuffer();
        const u8  = new Uint8Array(buf);
        const envelope = CBOR.decode(u8);

        if (!envelope || !envelope.nonce) return UI.showAlert('Malformed payload file.');
        if (await DB.hasReplayNonce(envelope.nonce)) return UI.showAlert('Duplicate transfer detected (replay).');
        await DB.putReplayNonce(envelope.nonce);

        // v3 branch (same path as text import)
        if (envelope.v === 3 && envelope.iv && envelope.ct) {
        const p2pKey = await deriveP2PKey(envelope.from, envelope.to, envelope.nonce);
        const bytes  = await Encryption.decryptBytes(
            p2pKey,
            Encryption.base64ToBuffer(envelope.iv),
            Encryption.base64ToBuffer(envelope.ct)
        );
        const body = CBOR.decode(bytes); // { c: <Uint8Array>, t: <int>, n: <text> }
        if (!body || !(body.c instanceof Uint8Array)) return UI.showAlert('Decrypted CBOR invalid.');
        const expandedChains = ChainsCodec.decode(body.c); // [{i,h:[...]}]
        await handleIncomingChains(fromCompactChains(expandedChains), envelope.from, envelope.to);
        return;
        }

        // v2/v1 fallbacks not expected for .cbor, but we could add if needed
        return UI.showAlert('Unsupported or malformed payload file.');
    } catch (e) {
        console.error('CatchIn file failed', e);
        UI.showAlert('Catch In file failed: ' + (e.message || e));
    } finally {
        transactionLock = false;
    }
};

// ---------- Notifications ----------
const Notifications = {
  requestPermission: () => {
    if ('Notification' in window && Notification.permission !== 'granted') Notification.requestPermission();
  },
  showNotification: (title, body) => {
    if ('Notification' in window && Notification.permission === 'granted') new Notification(title, { body: body });
  }
};

// ---------- Backups ----------
async function exportFullBackup() {
  const segments = await DB.loadSegmentsFromDB();
  const proofsBundle = await DB.loadProofsFromDB();
  const payload = { vaultData: vaultData, segments: segments, proofsBundle: proofsBundle, exportedAt: Date.now() };
  const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'biovault.fullbackup.json'; a.click();
}
async function importFullBackup(file) {
  const txt = await file.text();
  const obj = JSON.parse(txt);
  if (!obj || !obj.vaultData || !Array.isArray(obj.segments)) return UI.showAlert('Invalid full backup');
  const stored = await DB.loadVaultDataFromDB();
  if (!derivedKey) {
    if (!stored || !stored.salt) return UI.showAlert("Unlock once before importing (no salt).");
    const pin = prompt("Enter passphrase to re-encrypt imported vault:");
    if (!pin) return UI.showAlert("Import canceled.");
    derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin), stored.salt);
  }
  vaultData = obj.vaultData;
  const segs = obj.segments;
  const db = await DB.openVaultDB();
  await new Promise((res, rej) => {
    const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
    tx.objectStore(SEGMENTS_STORE).clear();
    segs.forEach(function(s){ tx.objectStore(SEGMENTS_STORE).put(s); });
    tx.oncomplete = res; tx.onerror = (e)=>rej(e.target.error);
  });
  if (obj.proofsBundle) await DB.saveProofsToDB(obj.proofsBundle);
  await persistVaultData();
  await Vault.updateBalanceFromSegments();
  Vault.updateVaultUI();
  UI.showAlert('Full backup imported.');
}
function exportTransactions() {
  const blob = new Blob([JSON.stringify(vaultData.transactions)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'transactions.json'; a.click();
}
function backupVault() {
  const backup = JSON.stringify(vaultData);
  const blob = new Blob([backup], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'vault.backup'; a.click();
}

function copyToClipboard(id) {
  const textEl = document.getElementById(id);
  if (!textEl) return;
  navigator.clipboard.writeText(textEl.textContent).then(function(){ UI.showAlert('Copied!'); });
}

// ---------- Export to Blockchain helper ----------
async function exportProofToBlockchain(payload) {
  // If called with a payload (compact Merkle/encrypted blob or catch-in), forward to chain/relayer.
  if (payload) {
    try {
      console.debug('[BioVault] Submitting compact payload to chain/relayer:', payload);
      // TODO: replace with real submit when backend/contract endpoint is ready.
      return true;
    } catch (e) {
      console.error('[BioVault] submit failed', e);
      throw e;
    }
  }
  // Otherwise, guide user to dashboard actions which build+sign locally.
  showSection('dashboard');
  UI.showAlert('Open the Dashboard and click an action (e.g., Claim) to authorize with biometrics.');
  return true;
}


// ---------- Section Switching ----------
function showSection(id) {
  var secs = document.querySelectorAll('.section');
  for (var i=0;i<secs.length;i++) secs[i].classList.remove('active-section');
  var tgt = document.getElementById(id);
  if (tgt) tgt.classList.add('active-section');
  if (id === 'dashboard') loadDashboardData();
  if (id === 'biovault' && vaultUnlocked) {
    var wp = document.querySelector('#biovault .whitepaper'); if (wp) wp.classList.add('hidden');
    var vu = document.getElementById('vaultUI'); if (vu) vu.classList.remove('hidden');
    var ls = document.getElementById('lockedScreen'); if (ls) ls.classList.add('hidden');
  }
}
window.showSection = showSection; // expose for nav
// Expose selected helpers for UI/console usage (prevents 'declared but never read' warnings)
if (typeof window !== 'undefined') {
  window.exportTransactions     = exportTransactions;
  window.backupVault            = backupVault;
  window.importVault            = importVault;
  window.exportProofToBlockchain= exportProofToBlockchain;
}

// ---------- Theme Toggle ----------
(function(){
  var t = document.getElementById('theme-toggle');
  if (t) t.addEventListener('click', function(){ document.body.classList.toggle('dark-mode'); });
})();

// ---------- Service Worker ----------
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(function(){ console.log('[BioVault] SW registered'); }).catch(function(err){ console.warn('SW registration failed', err); });
}

// ---------- Persistence + session restore ----------
async function requestPersistentStorage() {
  try {
    if (navigator.storage && navigator.storage.persist) {
      const granted = await navigator.storage.persist();
      console.log(granted ? "🔒 Persistent storage granted" : "⚠️ Storage may be cleared under pressure");
    }
  } catch (e) { console.warn("persist() not available", e); }
}
function setupSessionRestore() {
  try {
    const lastURL = localStorage.getItem(SESSION_URL_KEY);
    if (lastURL && location.href !== lastURL) history.replaceState(null, "", lastURL);
  } catch(e){}
  window.addEventListener("beforeunload", function() {
    try { localStorage.setItem(SESSION_URL_KEY, location.href); } catch(e){}
  });
}
function enforceSingleVault() {
  const v = localStorage.getItem(VAULT_LOCK_KEY);
  if (!v) localStorage.setItem(VAULT_LOCK_KEY, 'locked');
}
function preventMultipleVaults() {
  window.addEventListener('storage', function(e) {
    if (e.key === VAULT_UNLOCKED_KEY) {
      const unlocked = e.newValue === 'true';
      if (unlocked && !vaultUnlocked) { vaultUnlocked = true; revealVaultUI(); }
      if (!unlocked && vaultUnlocked) { vaultUnlocked = false; if (Vault.lockVault) Vault.lockVault(); }
    }
  });
}
function isVaultLockedOut() {
  if (!vaultData.lockoutTimestamp) return false;
  const now = Math.floor(Date.now()/1000);
  if (now < vaultData.lockoutTimestamp) return true;
  vaultData.lockoutTimestamp = null;
  vaultData.authAttempts = 0;
  return false;
}
async function handleFailedAuthAttempt() {
  vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
  if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
    vaultData.lockoutTimestamp = Math.floor(Date.now()/1000) + LOCKOUT_DURATION_SECONDS;
  }
  await Vault.promptAndSaveVault();
}
async function persistVaultData(saltBuf) {
  if (!derivedKey) throw new Error('Derived key missing; cannot save vault.');
  const enc = await Encryption.encryptData(derivedKey, vaultData);
  const iv = enc.iv; const ciphertext = enc.ciphertext;
  let saltBase64;
  if (saltBuf) { saltBase64 = Encryption.bufferToBase64(saltBuf); }
  else {
    const existing = await DB.loadVaultDataFromDB();
    if (existing && existing.salt) saltBase64 = Encryption.bufferToBase64(existing.salt);
    else throw new Error('Salt missing; persist aborted.');
  }
  await DB.saveVaultDataToDB(iv, ciphertext, saltBase64);
}

// ---------- Catch-Out Result helpers (QR / ZIP) ----------
function splitIntoFrames(str, maxLen) {
  var chunks = [];
  for (var i=0;i<str.length;i+=maxLen) chunks.push(str.slice(i, i+maxLen));
  var total = chunks.length;
  var out = [];
  for (var j=0;j<total;j++) out.push('BC|' + (j+1) + '|' + total + '|' + chunks[j]);
  return out;
}
function updateQrIndicator() {
  var ind = document.getElementById('qrIndicator');
  var nav = document.getElementById('qrNav');
  if (!ind || !nav) return;
  if (lastQrFrames.length <= 1) { nav.style.display = 'none'; }
  else {
    nav.style.display = 'flex';
    ind.textContent = (lastQrFrameIndex + 1) + ' / ' + lastQrFrames.length;
  }
}
async function renderQrFrame() {
  await ensureQrLib();
  var canvas = document.getElementById('catchOutQRCanvas');
  if (!canvas || !window.QRCode) return;
  var text = lastQrFrames[lastQrFrameIndex] || '';
  try {
    await window.QRCode.toCanvas(canvas, text, { width: QR_SIZE, margin: QR_MARGIN, errorCorrectionLevel: 'M' });
  } catch (e) {
    console.warn('[BioVault] QR render failed', e);
  }
  updateQrIndicator();
}
async function prepareFramesForPayload(payloadStr) {
  lastQrFrames = splitIntoFrames(payloadStr, QR_CHUNK_MAX);
  lastQrFrameIndex = 0;
  updateQrIndicator();
}
async function downloadFramesZip() {
  await ensureQrLib(); await ensureZipLib();
  if (!window.JSZip) { UI.showAlert('ZIP library could not load.'); return; }
  var zip = new window.JSZip();
  // add payload as CBOR (base64-encoded for portability)
  zip.file('payload.cbor.b64', lastCatchOutPayloadStr || '');
  // add manifest
  zip.file('frames_manifest.json', JSON.stringify({ version:1, total:lastQrFrames.length, size:QR_SIZE, ecLevel:'M', prefix:'BC|i|N|' }, null, 2));

  // Render each frame to PNG
  for (var i=0;i<lastQrFrames.length;i++) {
    var c = document.createElement('canvas');
    c.width = QR_SIZE; c.height = QR_SIZE;
    try {
      await window.QRCode.toCanvas(c, lastQrFrames[i], { width: QR_SIZE, margin: QR_MARGIN, errorCorrectionLevel: 'M' });
      var dataURL = c.toDataURL('image/png');
      var base64 = dataURL.split(',')[1];
      zip.file('qr_' + String(i+1).padStart(3,'0') + '.png', base64, { base64:true });
    } catch (e) {
      console.warn('Frame render failed (#'+(i+1)+')', e);
    }
  }

  var blob = await zip.generateAsync({ type:'blob' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url; a.download = 'catchout_qr_frames.zip'; a.click();
  URL.revokeObjectURL(url);
}

async function showCatchOutResultModal() {
  // Hide the big textarea if present
  const ta = document.getElementById('catchOutResultText');
  if (ta) {
    ta.value = '';
    ta.closest('.form-group, .mb-3, .input-group')?.classList?.add('d-none');
  }

  // If there’s a "Download .cbor" button, wire it up
  const btnDownload = document.getElementById('btnDownloadCbor');
  if (btnDownload) {
    btnDownload.classList.remove('d-none');
    btnDownload.onclick = () => {
      if (lastCatchOutPayloadBytes && lastCatchOutPayloadBytes.length) {
        downloadBytes(lastCatchOutFileName || 'catchout.cbor', lastCatchOutPayloadBytes, 'application/cbor');
      } else {
        UI.showAlert('No payload to download.');
      }
    };
  }

  // Prepare QR frames from the cached base64 (fallback/offline)
  if (lastCatchOutPayloadStr) await prepareFramesForPayload(lastCatchOutPayloadStr);

  // Show the modal
  const modalEl = document.getElementById('modalCatchOutResult');
  if (modalEl) {
    const m = window.bootstrap ? new bootstrap.Modal(modalEl) : null;
    if (m) m.show(); else modalEl.style.display = 'block';
  }
}


// ---------- Migrations (production-grade safety) ----------
async function migrateSegmentsV4() {
  const segs = await DB.loadSegmentsFromDB();
  if (!segs || segs.length === 0) return;

  let changed = 0;
  for (let i=0;i<segs.length;i++){
    let s = segs[i];
    let mutated = false;

    if (typeof s.claimed !== 'boolean') { s.claimed = false; mutated = true; }

    if (typeof s.ownershipChangeCount !== 'number') {
      // If an Unlock event exists, start from 1; else synthesize one for single-init segments.
      var hasUnlock = false, transfers = 0, receiveds = 0;
      for (var j=0;j<s.history.length;j++){
        var ev = s.history[j].event;
        if (ev === 'Unlock') hasUnlock = true;
        if (ev === 'Transfer') transfers++;
        if (ev === 'Received') receiveds++;
      }
      if (!hasUnlock && s.history.length === 1 && s.currentOwner === vaultData.bioIBAN) {
        // synthesize Unlock immediately after init
        var init = s.history[0];
        var ts = (init.timestamp || Date.now()) + 1;
        var unlockHash = await Utils.sha256Hex(init.integrityHash + 'Unlock' + ts + init.from + init.to + (init.bioConst + 1));
        s.history.push({ event:'Unlock', timestamp: ts, from:init.from, to:init.to, bioConst: init.bioConst + 1, integrityHash: unlockHash });
        hasUnlock = true;
        mutated = true;
      }
      s.ownershipChangeCount = (hasUnlock ? 1 : 0) + transfers + receiveds;
      if (s.ownershipChangeCount < 0) s.ownershipChangeCount = 0;
      mutated = true;
    }

    if (mutated) { await DB.saveSegmentToDB(s); changed++; }
  }

  // Recompute nextSegmentIndex based on max existing index
  var maxIdx = segs.reduce(function(m, s){ return s.segmentIndex > m ? s.segmentIndex : m; }, 0);
  if (typeof vaultData.nextSegmentIndex !== 'number' || vaultData.nextSegmentIndex <= maxIdx) {
    vaultData.nextSegmentIndex = maxIdx + 1;
  }

  if (changed > 0) {
    await Vault.updateBalanceFromSegments();
    await persistVaultData();
  }
}

async function migrateVaultAfterDecrypt() {
  // Ensure 0x Bio-IBAN + bonus
  if (vaultData.bioIBAN && vaultData.bioIBAN.slice(0,2) !== '0x') vaultData.bioIBAN = '0x' + vaultData.bioIBAN;
  if (typeof vaultData.bonusConstant !== 'number' || vaultData.bonusConstant <= 0) vaultData.bonusConstant = EXTRA_BONUS_TVM;

  // Ensure caps object exists
  if (!vaultData.caps) {
    vaultData.caps = { dayKey:"", monthKey:"", yearKey:"", dayUsedSeg:0, monthUsedSeg:0, yearUsedSeg:0, tvmYearlyClaimed:0 };
  }
  resetCapsIfNeeded(Date.now());

  // Ensure nextSegmentIndex sane
  if (typeof vaultData.nextSegmentIndex !== 'number' || vaultData.nextSegmentIndex < INITIAL_BALANCE_SHE + 1) {
    vaultData.nextSegmentIndex = INITIAL_BALANCE_SHE + 1;
  }

  // Migrate segments to V4 schema (adds Unlock for single-init ones, counts ownershipChangeCount, claimed)
  await migrateSegmentsV4();
}

// ---------- Init ----------
async function init() {
  console.log('[BioVault] init() starting…');
  await requestPersistentStorage();
  setupSessionRestore();
  enforceSingleVault();
  preventMultipleVaults();
  Notifications.requestPermission();

  // NFC listen (non-blocking)
  if ('NDEFReader' in window) {
    try { const reader = new NDEFReader(); await reader.scan(); reader.onreading = function(){ UI.showAlert('Incoming P2P transfer detected.'); }; } catch(e){ console.warn('NFC scan failed:', e); }
  }

  const stored = await DB.loadVaultDataFromDB();
  if (stored) {
    console.log('[BioVault] Vault record found. Attempts:', stored.authAttempts);
    vaultData.authAttempts = stored.authAttempts;
    vaultData.lockoutTimestamp = stored.lockoutTimestamp;
  } else {
    const credential = await Biometric.performBiometricAuthenticationForCreation();
    if (credential) {
      vaultData.credentialId = Encryption.bufferToBase64(credential.rawId);
      // new vault: ensure 0x-prefixed Bio-IBAN and visible bonus
      const rndHex = await Utils.sha256Hex(Math.random().toString());
      vaultData.bioIBAN = Utils.to0x(rndHex);
      vaultData.joinTimestamp = Date.now();
      vaultData.deviceKeyHash = Utils.to0x(await Utils.sha256Hex(KEY_HASH_SALT + Utils.toB64(Utils.rand(32))));
      vaultData.balanceSHE = INITIAL_BALANCE_SHE;
      vaultData.bonusConstant = EXTRA_BONUS_TVM;

      const salt = Utils.rand(16);
      const pin = prompt("Set passphrase:");
      derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin || ''), salt);
      await persistVaultData(salt);

      // Create initial unlocked base (1..1200) using new rules
      await Segment.initializeSegments();

      vaultUnlocked = true;
      revealVaultUI();
      await Vault.updateBalanceFromSegments();
      Vault.updateVaultUI();
    }
  }

  // Event Listeners
  var byId = function(id){ return document.getElementById(id); };
  var el;

  // Wallet connections
  el = byId('connectMetaMaskBtn');      if (el) el.addEventListener('click', Wallet.connectMetaMask);
  el = byId('connectWalletConnectBtn'); if (el) el.addEventListener('click', Wallet.connectWalletConnect);
  el = byId('connect-wallet');          if (el) el.addEventListener('click', Wallet.connectMetaMask);

  // Vault Enter / Lock
  el = byId('enterVaultBtn'); if (el) el.addEventListener('click', async function(){
    console.log('[BioVault] Enter Vault clicked');
    if (isVaultLockedOut()) { UI.showAlert("Vault locked out."); return; }
    const pin = prompt("Enter passphrase:");
    const stored = await DB.loadVaultDataFromDB();
    if (!stored) return;
    derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin || ''), stored.salt);
    try {
      vaultData = await Encryption.decryptData(derivedKey, stored.iv, stored.ciphertext);

      // Run robust migrations for V4 schema
      await migrateVaultAfterDecrypt();
      await persistVaultData();

      let ok = await Biometric.performBiometricAssertion(vaultData.credentialId);
      if (!ok) {
        const wantReEnroll = confirm("Biometric failed. Re-enroll on this device and proceed?");
        if (wantReEnroll) ok = await reEnrollBiometricIfNeeded();
      }
      if (!ok) { await handleFailedAuthAttempt(); return UI.showAlert("Biometric failed."); }

      vaultUnlocked = true;
      revealVaultUI();
      await Vault.updateBalanceFromSegments();
      Vault.updateVaultUI();
      try { localStorage.setItem(VAULT_UNLOCKED_KEY, 'true'); } catch(e){}
    } catch (e) {
      console.error('[BioVault] Unlock error', e);
      await handleFailedAuthAttempt();
      UI.showAlert("Invalid passphrase or corrupted vault.");
    }
  });
  el = byId('lockVaultBtn'); if (el) el.addEventListener('click', Vault.lockVault);

  // Catch-Out button -> open form modal
  el = byId('catchOutBtn'); if (el) el.addEventListener('click', function(){
    var modalEl = document.getElementById('modalCatchOut');
    if (modalEl) {
      var m = window.bootstrap ? new bootstrap.Modal(modalEl) : null;
      if (m) m.show(); else modalEl.style.display = 'block';
    }
  });

  // Catch-In button -> open import modal
  el = byId('catchInBtn'); if (el) el.addEventListener('click', function(){
    var modalEl = document.getElementById('modalCatchIn');
    if (modalEl) {
      var m = window.bootstrap ? new bootstrap.Modal(modalEl) : null;
      if (m) m.show(); else modalEl.style.display = 'block';
    }
  });

  // Claim modal open
  var claimBtn = byId('claim-tvm-btn');
  if (claimBtn) claimBtn.addEventListener('click', function(){
    var modalEl = document.getElementById('modalClaim');
    if (modalEl) {
      var m = window.bootstrap ? new bootstrap.Modal(modalEl) : null;
      if (m) m.show(); else modalEl.style.display = 'block';
    }
  });

  // Catch-Out form submit
  var formCO = byId('formCatchOut');
  if (formCO) formCO.addEventListener('submit', async function(ev){
    ev.preventDefault();
    var recv = Utils.sanitizeInput((byId('receiverBioModal')||{}).value || '');
    var amt  = Utils.sanitizeInput((byId('amountSegmentsModal')||{}).value || '');
    var note = Utils.sanitizeInput((byId('noteModal')||{}).value || '');
    if (!recv) { formCO.classList.add('was-validated'); return; }
    var amtNum = parseInt(amt, 10);
    if (isNaN(amtNum) || amtNum <= 0) { formCO.classList.add('was-validated'); return; }

    var sp = byId('spCreateCatchOut'); if (sp) sp.classList.remove('d-none');
    var btn = byId('btnCreateCatchOut'); if (btn) btn.disabled = true;

    try {
      await P2P.createCatchOut(recv, amtNum, note);
      if (window.bootstrap) {
        var m1 = bootstrap.Modal.getInstance(document.getElementById('modalCatchOut'));
        if (m1) m1.hide();
      }
    } catch (e) {
      console.error('CatchOut failed', e);
      UI.showAlert('Catch Out failed: ' + (e.message || e));
    } finally {
      if (sp) sp.classList.add('d-none');
      if (btn) btn.disabled = false;
    }
  });

  // Catch-Out Result modal controls
  var btnCopy = byId('btnCopyCatchOut');
  if (btnCopy) btnCopy.addEventListener('click', function(){
    var ta = byId('catchOutResultText');
    if (!ta) return;
    navigator.clipboard.writeText(ta.value || '').then(function(){ UI.showAlert('Payload copied to clipboard.'); });
  });

  // QR collapse: render first time when opened
  var qrCollapseEl = byId('qrCollapse');
  if (qrCollapseEl && window.bootstrap) {
    qrCollapseEl.addEventListener('shown.bs.collapse', function(){ renderQrFrame(); });
  } else if (qrCollapseEl) {
    var btnShowQR = byId('btnShowQR');
    if (btnShowQR) btnShowQR.addEventListener('click', function(){ setTimeout(renderQrFrame, 50); });
  }

  // Multi-QR Nav
  var btnPrev = byId('qrPrev'); if (btnPrev) btnPrev.addEventListener('click', function(){
    if (lastQrFrames.length === 0) return;
    lastQrFrameIndex = (lastQrFrameIndex - 1 + lastQrFrames.length) % lastQrFrames.length;
    renderQrFrame();
  });
  var btnNext = byId('qrNext'); if (btnNext) btnNext.addEventListener('click', function(){
    if (lastQrFrames.length === 0) return;
    lastQrFrameIndex = (lastQrFrameIndex + 1) % lastQrFrames.length;
    renderQrFrame();
  });

  // Download ZIP of all QR frames
  var btnZip = byId('btnDownloadQRZip');
  if (btnZip) btnZip.addEventListener('click', function(){ downloadFramesZip(); });

  // Catch-In form submit
  var formCI = byId('formCatchIn');
  if (formCI) formCI.addEventListener('submit', async function(ev){
    ev.preventDefault();
    var ta = byId('catchInPayloadModal');
    var sp = byId('spImportCatchIn'); if (sp) sp.classList.remove('d-none');
    var btn = byId('btnImportCatchIn'); if (btn) btn.disabled = true;
    try {
      await P2P.importCatchIn((ta&&ta.value) || '');
      if (window.bootstrap) {
        var m2 = bootstrap.Modal.getInstance(document.getElementById('modalCatchIn'));
        if (m2) m2.hide();
        // Allow pasting a data: URL for the CBOR envelope
        if (typeof payloadStr === 'string' && payloadStr.startsWith('data:application/cbor;base64,')) {
        payloadStr = payloadStr.split(',')[1];
        }


      }
    } catch (e) {
      console.error('CatchIn failed', e);
      UI.showAlert('Catch In failed: ' + (e.message || e));
    } finally {
      if (sp) sp.classList.add('d-none');
      if (btn) btn.disabled = false;
    }
    

  });
  

  // Claim modal submit → call on-chain claim (auto proofs)
    var formClaim = byId('formClaim');
    if (formClaim) formClaim.addEventListener('submit', async function(ev){
        ev.preventDefault();
        var sp = byId('spSubmitClaim'); if (sp) sp.classList.remove('d-none');
        var btn = byId('btnSubmitClaim'); if (btn) btn.disabled = true;
        try {
        await ContractInteractions.claimTVM();
        if (window.bootstrap) {
            var m3 = bootstrap.Modal.getInstance(document.getElementById('modalClaim'));
            if (m3) m3.hide();
        }
        } catch (e) {
        console.error('Claim failed', e);
        UI.showAlert('Claim failed: ' + (e.message || e));
        } finally {
        if (sp) sp.classList.add('d-none');
        if (btn) btn.disabled = false;
        }
    });
    var btnImportFile = document.getElementById('btnImportCatchInFile');
    if (btnImportFile) {
    btnImportFile.addEventListener('click', async function(){
        const fi = document.getElementById('catchInFile');
        const f  = fi && fi.files && fi.files[0];
        if (!f) { UI.showAlert('Please choose a .cbor file.'); return; }
        await P2P.importCatchInFile(f);
        if (window.bootstrap) {
        const m2 = bootstrap.Modal.getInstance(document.getElementById('modalCatchIn'));
        if (m2) m2.hide();
        }
    });
}

  // Idle Timeout
  var idleTimer;
  var resetIdle = function(){ clearTimeout(idleTimer); idleTimer = setTimeout(Vault.lockVault, MAX_IDLE); };
  ['click','keydown','mousemove','touchstart','visibilitychange'].forEach(function(evt){
    window.addEventListener(evt, resetIdle);
  });
  resetIdle();

  // UTC Time Update
  setInterval(function(){
    const tz = document.getElementById('utcTime');
    if (tz) tz.textContent = new Date().toUTCString();
  }, 1000);

  // Load Dashboard on Init if Needed (no-op if wallet not connected)
  loadDashboardData();
  console.log('[BioVault] init() complete.');
}

// ---------- Dashboard ----------
async function loadDashboardData() {
  await ensureChartLib();
  await Wallet.updateBalances();

  let table = '';
  let totalReserves = 0;
  for (let i = 1; i <= LAYERS; i++) {
    const reserve = 100000000; // mock/placeholder; replace with real values when available
    totalReserves += reserve;
    const capProgress = (SEGMENTS_PER_LAYER / reserve * 100).toFixed(2) + '%';
    table += '<tr><td>'+i+'</td><td>'+reserve.toLocaleString()+' TVM</td><td>'+capProgress+'</td></tr>';
  }
  const lt = document.getElementById('layer-table');
  if (lt) lt.innerHTML = table;
  const ar = document.getElementById('avg-reserves');
  if (ar) ar.textContent = (totalReserves / LAYERS).toLocaleString() + ' TVM';

  const c1 = document.getElementById('pool-chart');
  const c2 = document.getElementById('layer-chart');
  if (window.Chart && c1 && c2) {
    if (c1._chart) c1._chart.destroy();
    c1._chart = new Chart(c1, {
      type: 'doughnut',
      data: { labels: ['Human Investment (51%)','AI Cap (49%)'], datasets: [{ data: [51,49], borderRadius: 5 }] },
      options: { responsive:true, plugins:{ legend:{ position:'bottom' } }, cutout:'60%' }
    });
    if (c2._chart) c2._chart.destroy();
    c2._chart = new Chart(c2, {
      type: 'bar',
      data: { labels: Array.from({ length: LAYERS }, function(_, i){ return 'Layer ' + (i + 1); }), datasets: [{ label: 'Reserve (M TVM)', data: Array(LAYERS).fill(100) }] },
      options: { responsive:true, scales:{ y:{ beginAtZero:true } } }
    });
  }
}

init();
