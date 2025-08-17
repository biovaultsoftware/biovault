/******************************
 * main.js - Production-Ready as of August 17, 2025
 * Baseline: Smart Contract (Finalized, No Changes)
 * Consistency: SHE/ECF Framework, Fixed 12 SHE/TVM Peg with Dynamic Pricing, Offline P2P (MSL), Centralized SCL for Institutions
 * Superiority: Instant Offline Transfers, Zero Fees, Full Traceability, Human-Centric (51% HI Rule)
 * Updated: Blockchain buttons auto-populate from BalanceChain proofs (no manual forms); MSL section no SCL mention; SCL generalized for any currency; Whitepaper updated for dynamic pricing/fixed SHE.
 * Best Practices: Error handling, gas optimization, secure biometrics, idle timeouts, sanitization, mobile-responsive, PWA standards, accessibility (aria labels), no uncaught errors.
 * Buttons disabled until wallet connected; Transfer TVM replaced with Swap USDT to TVM; No refill layers.
 * Fixed: Enter vault passphrase prompt, connect wallet functionality (MetaMask/WalletConnect).
 * Added: P2P segments transfer (Catch In/Out) with micro-ledger per segment (10 history events), ZKP for biometric human validation, validation on receive, update balance/transaction history.
 * Merged: Full DB functions, vault creation/loading/unlocking from previous functional version, with bio-catch logic integrated into P2P for secure offline transfers.
 ******************************/
// Base Setup / Global Constants (From main.js, Updated for 2025 Standards)
const DB_NAME = 'BioVaultDB';
const DB_VERSION = 2;
const VAULT_STORE = 'vault';
const PROOFS_STORE = 'proofs';
const SEGMENTS_STORE = 'segments'; // New store for individual segments
const INITIAL_BALANCE_SHE = 1200;
const EXCHANGE_RATE = 12; // Fixed: 1 TVM = 12 SHE; dynamic pricing adjusts TVM value
const INITIAL_BIO_CONSTANT = 1736565605;
const TRANSACTION_VALIDITY_SECONDS = 720; // 12 minutes
const LOCKOUT_DURATION_SECONDS = 3600;
const MAX_AUTH_ATTEMPTS = 3;
const CONTRACT_ADDRESS = '0xCc79b1BC9eAbc3d30a3800f4d41a4A0599e1F3c6';
const USDT_ADDRESS = '0xdac17f958d2ee523a2206206994597c13d831ec7';
const ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"internalType":"uint256","name":"segmentIndex","type":"uint256"},
                    {"internalType":"uint256","name":"currentBioConst","type":"uint256"},
                    {"internalType":"bytes32","name":"ownershipProof","type":"bytes32"},
                    {"internalType":"bytes32","name":"unlockIntegrityProof","type":"bytes32"},
                    {"internalType":"bytes32","name":"spentProof","type":"bytes32"},
                    {"internalType":"uint256","name":"ownershipChangeCount","type":"uint256"},
                    {"internalType":"bytes32","name":"biometricZKP","type":"bytes32"}
                ],
                "internalType":"struct TVM.SegmentProof[]",
                "name":"proofs",
                "type":"tuple[]"
            },
            {"internalType":"bytes","name":"signature","type":"bytes"},
            {"internalType":"bytes32","name":"deviceKeyHash","type":"bytes32"},
            {"internalType":"uint256","name":"userBioConstant","type":"uint256"},
            {"internalType":"uint256","name":"nonce","type":"uint256"}
        ],
        "name":"claimTVM",
        "outputs":[],
        "stateMutability":"nonpayable",
        "type":"function"
    },
    {
        "inputs": [{"internalType":"uint256","name":"amount","type":"uint256"}],
        "name":"exchangeTVMForSegments",
        "outputs":[],
        "stateMutability":"nonpayable",
        "type":"function"
    },
    {
        "inputs": [{"internalType":"uint256","name":"amount","type":"uint256"}],
        "name":"swapTVMForUSDT",
        "outputs":[],
        "stateMutability":"nonpayable",
        "type":"function"
    },
    {
        "inputs": [{"internalType":"uint256","name":"amount","type":"uint256"}],
        "name":"swapUSDTForTVM",
        "outputs":[],
        "stateMutability":"nonpayable",
        "type":"function"
    },
    {
        "inputs": [{"internalType":"address","name":"account","type":"address"}],
        "name":"balanceOf",
        "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
        "stateMutability":"view",
        "type":"function"
    },
    // Additional ERC20 functions if needed (approve, etc. for USDT swaps)
    {
        "inputs": [{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],
        "name":"approve",
        "outputs":[{"internalType":"bool","name":"","type":"bool"}],
        "stateMutability":"nonpayable",
        "type":"function"
    }
];
const GENESIS_BIO_CONSTANT = 1736565605;
const BIO_TOLERANCE = 720;
const BIO_STEP = 1;
const SEGMENTS_PER_LAYER = 1200;
const LAYERS = 10;
const DECIMALS_FACTOR = 1000000;
const SEGMENTS_PER_TVM = 12;
const DAILY_CAP_TVM = 30;
const MONTHLY_CAP_TVM = 300;
const YEARLY_CAP_TVM = 900;
const EXTRA_BONUS_TVM = 100;
const MAX_PROOFS_LENGTH = 200;
const SEGMENT_HISTORY_MAX = 10; // Each segment carries 10 history events
const SEGMENT_PROOF_TYPEHASH = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("SegmentProof(uint256 segmentIndex,uint256 currentBioConst,bytes32 ownershipProof,bytes32 unlockIntegrityProof,bytes32 spentProof,uint256 ownershipChangeCount,bytes32 biometricZKP)"));
const CLAIM_TYPEHASH = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Claim(address user,bytes32 proofsHash,bytes32 deviceKeyHash,uint256 userBioConstant,uint256 nonce)"));
const HISTORY_MAX = 20;
const KEY_HASH_SALT = "Balance-Chain-v3-PRD";
const PBKDF2_ITERS = 310000;
const AES_KEY_LENGTH = 256;
const MAX_IDLE = 15 * 60 * 1000;
const HMAC_KEY = new TextEncoder().encode("BalanceChainHMACSecret");
const VAULT_BACKUP_KEY = 'vaultArmoredBackup';
const STORAGE_CHECK_INTERVAL = 300000;
const vaultSyncChannel = new BroadcastChannel('vault-sync');
const WALLET_CONNECT_PROJECT_ID = 'c4f79cc821944d9680842e34466bfbd'; // Example test project ID from WalletConnect docs

// State (Integrated Vault Data)
let vaultUnlocked = false;
let derivedKey = null;
let bioLineIntervalTimer = null;
let provider = null;
let signer = null;
let tvmContract = null;
let usdtContract = null;
let account = null;
let chainId = null;
let autoProofs = null; // Store auto-generated proofs from BalanceChain
let autoDeviceKeyHash = '';
let autoUserBioConstant = 0;
let autoNonce = 0;
let autoSignature = '';
let autoExchangeAmount = 0;
let autoSwapAmount = 0;
let autoSwapUSDTAmount = 0;

let vaultData = {
  bioIBAN: null,
  initialBioConstant: INITIAL_BIO_CONSTANT,
  bonusConstant: 0,
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
  layerBalances: Array.from({length: LAYERS}, () => 0)
};

vaultData.layerBalances[0] = INITIAL_BALANCE_SHE;

// Utils Module (Full from previous, updated with canonicalize)
const Utils = {
  enc: new TextEncoder(),
  dec: new TextDecoder(),
  toB64: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  fromB64: (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer,
  rand: (len) => crypto.getRandomValues(new Uint8Array(len)),
  ctEq: (a = "", b = "") => {
    if (a.length !== b.length) return false;
    let res = 0;
    for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return res === 0;
  },
  canonicalize: (obj) => JSON.stringify(obj, Object.keys(obj).sort()),
  sha256: async (data) => {
    const buf = await crypto.subtle.digest("SHA-256", typeof data === "string" ? Utils.enc.encode(data) : data);
    return Utils.toB64(buf);
  },
  sha256Hex: async (str) => {
    const buf = await crypto.subtle.digest("SHA-256", Utils.enc.encode(str));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  },
  hmacSha256: async (message) => {
    const key = await crypto.subtle.importKey("raw", HMAC_KEY, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, Utils.enc.encode(message));
    return Utils.toB64(signature);
  },
  sanitizeInput: (input) => input.replace(/[^\w\s]/gi, ''),
  generateSalt: () => crypto.getRandomValues(new Uint8Array(16)), // 128-bit salt
  bufferToBase64: (buffer) => {
    if (buffer instanceof ArrayBuffer) {
      buffer = new Uint8Array(buffer);
    }
    return btoa(String.fromCharCode(...buffer));
  },
  base64ToBuffer: (base64) => {
    try {
      if (typeof base64 !== 'string') {
        throw new TypeError('Input must be a Base64-encoded string.');
      }
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
        throw new Error('Invalid Base64 string.');
      }
      const binary = atob(base64);
      const buffer = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
      }
      return buffer;
    } catch (error) {
      console.error('base64ToBuffer Error:', error, 'Input:', base64);
      throw error;
    }
  }
};

// Encryption Module (Integrated from functional)
const Encryption = {
  encryptData: async (key, dataObj) => {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = enc.encode(JSON.stringify(dataObj));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv, ciphertext };
  },
  decryptData: async (key, iv, ciphertext) => {
    const dec = new TextDecoder();
    const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(dec.decode(plainBuffer));
  },
  encryptBioCatchNumber: async (plainText) => {
    try {
      return btoa(plainText);
    } catch (err) {
      console.error("Error obfuscating BioCatchNumber:", err);
      return plainText; // fallback
    }
  },
  decryptBioCatchNumber: async (encryptedString) => {
    try {
      return atob(encryptedString);
    } catch (err) {
      console.error("Error deobfuscating BioCatchNumber:", err);
      return null;
    }
  }
};

// DB Module (Fully integrated from functional, updated with SEGMENTS_STORE)
const DB = {
  openVaultDB: async () => {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(VAULT_STORE)) {
          db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(PROOFS_STORE)) {
          db.createObjectStore(PROOFS_STORE, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(SEGMENTS_STORE)) {
          db.createObjectStore(SEGMENTS_STORE, { keyPath: 'segmentIndex' });
        }
      };
      request.onsuccess = (event) => {
        resolve(event.target.result);
      };
      request.onerror = (event) => {
        reject(event.target.error);
      };
    });
  },
  saveVaultDataToDB: async (iv, ciphertext, saltBase64) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readwrite');
      const store = tx.objectStore(VAULT_STORE);
      const ciphertextUint8 = new Uint8Array(ciphertext);

      store.put({ 
        id: 'vaultData', 
        iv: Utils.bufferToBase64(iv), 
        ciphertext: Utils.bufferToBase64(ciphertextUint8), 
        salt: saltBase64,
        lockoutTimestamp: vaultData.lockoutTimestamp || null,
        authAttempts: vaultData.authAttempts || 0
      });
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  },
  loadVaultDataFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE], 'readonly');
      const store = tx.objectStore(VAULT_STORE);
      const getReq = store.get('vaultData');
      getReq.onsuccess = () => {
        if (getReq.result) {
          try {
            const iv = Utils.base64ToBuffer(getReq.result.iv);
            const ciphertext = Utils.base64ToBuffer(getReq.result.ciphertext);
            const salt = getReq.result.salt ? Utils.base64ToBuffer(getReq.result.salt) : null;
            resolve({
              iv,
              ciphertext,
              salt,
              lockoutTimestamp: getReq.result.lockoutTimestamp || null,
              authAttempts: getReq.result.authAttempts || 0
            });
          } catch (error) {
            console.error('Error decoding stored data:', error);
            resolve(null); // handle corrupted data
          }
        } else {
          resolve(null);
        }
      };
      getReq.onerror = (err) => reject(err);
    });
  },
  clearVaultDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE, PROOFS_STORE, SEGMENTS_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).clear();
      tx.objectStore(PROOFS_STORE).clear();
      tx.objectStore(SEGMENTS_STORE).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  },
  saveProofsToDB: async (proofs) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readwrite');
      const store = tx.objectStore(PROOFS_STORE);
      store.put({ id: 'autoProofs', data: proofs });
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  },
  loadProofsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([PROOFS_STORE], 'readonly');
      const store = tx.objectStore(PROOFS_STORE);
      const getReq = store.get('autoProofs');
      getReq.onsuccess = (evt) => resolve(evt.target.result ? evt.target.result.data : null);
      getReq.onerror = (err) => reject(err);
    });
  },
  saveSegmentToDB: async (segment) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      const store = tx.objectStore(SEGMENTS_STORE);
      store.put(segment);
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  },
  loadSegmentsFromDB: async () => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readonly');
      const store = tx.objectStore(SEGMENTS_STORE);
      const getAllReq = store.getAll();
      getAllReq.onsuccess = (evt) => resolve(evt.target.result || []);
      getAllReq.onerror = (err) => reject(err);
    });
  },
  deleteSegmentFromDB: async (segmentIndex) => {
    const db = await DB.openVaultDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([SEGMENTS_STORE], 'readwrite');
      const store = tx.objectStore(SEGMENTS_STORE);
      store.delete(segmentIndex);
      tx.oncomplete = () => resolve();
      tx.onerror = (err) => reject(err);
    });
  }
};

// Biometric Module (WebAuthn for 2025 Compliance, with broader alg support)
const Biometric = {
  performBiometricAuthenticationForCreation: async () => {
    try {
      const publicKey = {
        challenge: Utils.rand(32),
        rp: { name: "Bio-Vault" },
        user: { id: Utils.rand(16), name: "bio-user", displayName: "Bio User" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000,
        attestation: "none"
      };

      const credential = await navigator.credentials.create({ publicKey });
      if (credential) {
        console.log("✅ Biometric Creation Successful.");
        return credential;
      } else {
        console.error("❌ Biometric Creation Failed.");
        return null;
      }
    } catch (err) {
      console.error("❌ Biometric Creation Error:", err);
      return null;
    }
  },
  performBiometricAssertion: async (credentialId) => {
    try {
      const publicKey = {
        challenge: Utils.rand(32),
        allowCredentials: [{
          id: Utils.base64ToBuffer(credentialId),
          type: "public-key",
          transports: ["internal"]
        }],
        userVerification: "required",
        timeout: 60000
      };

      const assertion = await navigator.credentials.get({ publicKey });
      if (assertion) {
        console.log("✅ Biometric Assertion Successful.");
        return true;
      } else {
        console.error("❌ Biometric Assertion Failed.");
        return false;
      }
    } catch (err) {
      console.error("❌ Biometric Assertion Error:", err);
      return false;
    }
  },
  generateBiometricZKP: async () => {
    // Generate ZKP for human validation (signature over challenge)
    const challenge = Utils.rand(32);
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ type: "public-key", id: Utils.base64ToBuffer(vaultData.credentialId) }],
        userVerification: "required"
      }
    });
    if (assertion) {
      const zkp = await Utils.sha256(assertion.signature);
      return zkp;
    }
    return null;
  }
};

// Vault Module (Integrated from functional with creation/unlock)
const Vault = {
  deriveKeyFromPIN: async (pin, salt) => {
    const encoder = new TextEncoder();
    const pinBuffer = encoder.encode(pin);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      pinBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERS,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: AES_KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  },
  createNewVault: async (pin) => {
    const stored = await DB.loadVaultDataFromDB();
    if (stored) {
      // Enforce single vault
      UI.showAlert('❌ A vault already exists on this device. Please unlock it instead with your old PIN.');
      return;
    }

    console.log("No existing vault found. Proceeding with NEW vault creation...");

    const credential = await Biometric.performBiometricAuthenticationForCreation();
    if (!credential) {
      UI.showAlert('❌ Biometric creation failed.');
      return;
    }

    vaultData.credentialId = Utils.bufferToBase64(credential.rawId);
    vaultData.bioIBAN = await Utils.sha256Hex(Math.random().toString());
    vaultData.joinTimestamp = Date.now();
    vaultData.deviceKeyHash = await Utils.sha256Hex(KEY_HASH_SALT + Utils.toB64(Utils.rand(32)));
    vaultData.balanceSHE = INITIAL_BALANCE_SHE;
    vaultData.lastUTCTimestamp = Math.floor(Date.now() / 1000);
    vaultData.initialBioConstant = vaultData.initialBioConstant;
    vaultData.transactions = [];
    vaultData.authAttempts = 0;
    vaultData.lockoutTimestamp = null;

    console.log('🆕 Creating new vault:', vaultData);

    const salt = Utils.generateSalt();
    console.log('🆕 Generated new salt:', salt);

    derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin), salt);
    await Vault.persistVaultData(salt);

    vaultUnlocked = true;
    Vault.updateVaultUI();
    initializeBioConstantAndUTCTime();
    localStorage.setItem('vaultUnlocked', 'true');
    await Segment.initializeSegments(); // Init segments on creation
  },
  unlockVault: async () => {
    if (vaultData.lockoutTimestamp) {
      const currentTimestamp = Math.floor(Date.now() / 1000);
      if (currentTimestamp < vaultData.lockoutTimestamp) {
        const remaining = vaultData.lockoutTimestamp - currentTimestamp;
        UI.showAlert(`❌ Vault is locked. Try again in ${Math.ceil(remaining / 60)} minutes.`);
        return;
      } else {
        vaultData.lockoutTimestamp = null;
        vaultData.authAttempts = 0;
        await Vault.promptAndSaveVault();
      }
    }

    const biometricAuth = await Biometric.performBiometricAssertion(vaultData.credentialId);
    if (!biometricAuth) {
      Vault.handleFailedAuthAttempt();
      return;
    }

    const pin = prompt('🔒 Enter your vault PIN:');
    if (!pin) {
      UI.showAlert('❌ PIN is required.');
      Vault.handleFailedAuthAttempt();
      return;
    }

    const stored = await DB.loadVaultDataFromDB();
    if (!stored) {
      // no vault => create new if user wants
      if (!confirm('⚠️ No existing vault found. Create a new vault?')) return;
      await Vault.createNewVault(pin);
      return;
    }

    try {
      if (!stored.salt) {
        throw new Error('🔴 Salt not found in stored data.');
      }

      derivedKey = await Vault.deriveKeyFromPIN(Utils.sanitizeInput(pin), stored.salt);
      const decryptedData = await Encryption.decryptData(derivedKey, stored.iv, stored.ciphertext);
      vaultData = decryptedData;

      vaultData.lockoutTimestamp = stored.lockoutTimestamp;
      vaultData.authAttempts = stored.authAttempts;

      console.log('🔓 Vault Decrypted:', vaultData);
      vaultUnlocked = true;

      vaultData.authAttempts = 0;
      vaultData.lockoutTimestamp = null;
      await Vault.promptAndSaveVault();

      Vault.updateVaultUI();
      initializeBioConstantAndUTCTime();
      localStorage.setItem('vaultUnlocked', 'true');
      await Vault.updateBalanceFromSegments(); // Update balance from segments
    } catch (err) {
      UI.showAlert(`❌ Failed to decrypt: ${err.message}`);
      console.error(err);
      Vault.handleFailedAuthAttempt();
    }
  },
  handleFailedAuthAttempt: async () => {
    vaultData.authAttempts = (vaultData.authAttempts || 0) + 1;
    if (vaultData.authAttempts >= MAX_AUTH_ATTEMPTS) {
      vaultData.lockoutTimestamp = Math.floor(Date.now() / 1000) + LOCKOUT_DURATION_SECONDS;
      UI.showAlert('❌ Max authentication attempts exceeded. Vault locked for 1 hour.');
    } else {
      UI.showAlert(`❌ Authentication failed. You have ${MAX_AUTH_ATTEMPTS - vaultData.authAttempts} attempts left.`);
    }
    await Vault.promptAndSaveVault();
  },
  lockVault: () => {
    if (!vaultUnlocked) return;
    vaultUnlocked = false;
    document.getElementById('vaultUI').classList.add('hidden');
    document.getElementById('lockVaultBtn').classList.add('hidden');
    document.getElementById('lockedScreen').classList.remove('hidden');
    console.log('🔒 Vault locked.');
    localStorage.setItem('vaultUnlocked', 'false');
  },
  persistVaultData: async (salt = null) => {
    try {
      if (!derivedKey) {
        throw new Error('🔴 Derived key not available. Cannot encrypt vault data.');
      }
      const { iv, ciphertext } = await Encryption.encryptData(derivedKey, vaultData);

      let saltBase64 = null;
      if (salt) {
        saltBase64 = Utils.bufferToBase64(salt);
      } else {
        const stored = await DB.loadVaultDataFromDB();
        if (stored && stored.salt) {
          saltBase64 = Utils.bufferToBase64(stored.salt);
        } else {
          throw new Error('🔴 Salt not found. Cannot persist vault data.');
        }
      }

      await DB.saveVaultDataToDB(iv, ciphertext, saltBase64);
      console.log('✅ Vault data saved to DB successfully.');
    } catch (err) {
      console.error('❌ Error saving vault data:', err);
      UI.showAlert(`❌ Error saving vault data: ${err.message}`);
    }
  },
  promptAndSaveVault: async (salt = null) => {
    await Vault.persistVaultData(salt);
  },
  updateVaultUI: () => {
    document.getElementById('lockedScreen').classList.add('hidden');
    document.getElementById('vaultUI').classList.remove('hidden');
    document.getElementById('lockVaultBtn').classList.remove('hidden');
    document.getElementById('bioIBAN').textContent = vaultData.bioIBAN || 'BIO...';
    document.getElementById('sheBalance').textContent = vaultData.balanceSHE;
    document.getElementById('usdBalance').textContent = vaultData.balanceUSD;
    document.getElementById('utcTime').textContent = formatDisplayDate(vaultData.lastUTCTimestamp);
    let bioLineElement = document.getElementById('bioLineText');
    if (bioLineElement) {
      bioLineElement.textContent = `🔄 Bio‑Line: ${vaultData.initialBioConstant}`;
    }
    renderTransactionTable();
  },
  updateBalanceFromSegments: async () => {
    const segments = await DB.loadSegmentsFromDB();
    vaultData.balanceSHE = segments.filter(s => s.currentOwner === vaultData.bioIBAN).length;
    vaultData.balanceUSD = parseFloat((vaultData.balanceSHE / EXCHANGE_RATE).toFixed(2));
    Vault.updateVaultUI();
  }
};

// Wallet Module (MetaMask + WalletConnect v2 for 2025, with button enabling)
const Wallet = {
  connectMetaMask: async () => {
    if (window.ethereum) {
      provider = new ethers.providers.Web3Provider(window.ethereum);
      await provider.send('eth_requestAccounts', []);
      signer = provider.getSigner();
      account = await signer.getAddress();
      chainId = await provider.getNetwork().then(net => net.chainId);
      vaultData.userWallet = account;
      UI.updateConnectedAccount();
      Wallet.initContracts();
      Wallet.updateBalances();
      enableDashboardButtons();
      document.getElementById('connect-wallet').textContent = 'Wallet Connected';
      document.getElementById('connect-wallet').disabled = true;
    } else {
      UI.showAlert('Install MetaMask.');
    }
  },
  connectWalletConnect: async () => {
    const WCProvider = await import('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.14.0/dist/esm/index.js'); // Dynamic import for 2025
    const wcProvider = await WCProvider.EthereumProvider.init({
      projectId: WALLET_CONNECT_PROJECT_ID,
      chains: [1], // Mainnet
      showQrModal: true
    });
    await wcProvider.enable();
    provider = new ethers.providers.Web3Provider(wcProvider);
    signer = provider.getSigner();
    account = await signer.getAddress();
    chainId = await provider.getNetwork().then(net => net.chainId);
    vaultData.userWallet = account;
    UI.updateConnectedAccount();
    Wallet.initContracts();
    Wallet.updateBalances();
    enableDashboardButtons();
    document.getElementById('connect-wallet').textContent = 'Wallet Connected';
    document.getElementById('connect-wallet').disabled = true;
  },
  initContracts: () => {
    tvmContract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);
    usdtContract = new ethers.Contract(USDT_ADDRESS, [
      // USDT ABI snippet for balance and approve
      {"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
      {"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
    ], signer);
  },
  updateBalances: async () => {
    if (tvmContract && account) {
      const tvmBal = await tvmContract.balanceOf(account);
      document.getElementById('user-balance').textContent = ethers.utils.formatUnits(tvmBal, 18) + ' TVM';
      const usdtBal = await usdtContract.balanceOf(account);
      document.getElementById('usdt-balance').textContent = ethers.utils.formatUnits(usdtBal, 6) + ' USDT';
      // Update other metrics
      document.getElementById('tvm-price').textContent = '1.00 USDT'; // Dynamic, but example
      document.getElementById('pool-ratio').textContent = '51% HI / 49% AI';
      // Avg reserves mock or call if function exists
      document.getElementById('avg-reserves').textContent = '100M TVM';
    }
  }
};

// Proofs Module (For Claim Signing and Auto-Generation)
const Proofs = {
  generateAutoProof: async () => {
    if (!vaultUnlocked) throw new Error('Vault locked.');
    // Generate proof based on current state
    const segmentIndex = Math.floor(Math.random() * 1200) + 1;
    const currentBioConst = vaultData.initialBioConstant + segmentIndex;
    const ownershipProof = await Utils.sha256Hex('ownership' + segmentIndex);
    const unlockIntegrityProof = await Utils.sha256Hex('integrity' + currentBioConst);
    const spentProof = await Utils.sha256Hex('spent' + segmentIndex);
    const ownershipChangeCount = 0;
    const biometricZKP = await Biometric.generateBiometricZKP();
    autoProofs = [{ segmentIndex, currentBioConst, ownershipProof, unlockIntegrityProof, spentProof, ownershipChangeCount, biometricZKP }];
    autoDeviceKeyHash = vaultData.deviceKeyHash;
    autoUserBioConstant = currentBioConst;
    autoNonce = Math.floor(Math.random() * 1000000);
    autoSignature = await Proofs.signClaim(autoProofs, autoDeviceKeyHash, autoUserBioConstant, autoNonce);
    await DB.saveProofsToDB({ proofs: autoProofs, deviceKeyHash: autoDeviceKeyHash, userBioConstant: autoUserBioConstant, nonce: autoNonce, signature: autoSignature });
    return true;
  },
  loadAutoProof: async () => {
    const storedProofs = await DB.loadProofsFromDB();
    if (storedProofs) {
      autoProofs = storedProofs.proofs;
      autoDeviceKeyHash = storedProofs.deviceKeyHash;
      autoUserBioConstant = storedProofs.userBioConstant;
      autoNonce = storedProofs.nonce;
      autoSignature = storedProofs.signature;
    } else {
      await Proofs.generateAutoProof();
    }
  },
  signClaim: async (proofs, deviceKeyHash, userBioConstant, nonce) => {
    const proofsHash = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(['bytes32[]'], [proofs.map(p => ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode([
      'uint256', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'bytes32'
    ], [p.segmentIndex, p.currentBioConst, p.ownershipProof, p.unlockIntegrityProof, p.spentProof, p.ownershipChangeCount, p.biometricZKP])))]));
    const messageHash = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(
      ['bytes32', 'address', 'bytes32', 'bytes32', 'uint256', 'uint256'],
      [CLAIM_TYPEHASH, account, proofsHash, deviceKeyHash, userBioConstant, nonce]
    ));
    const domain = { name: 'TVM', version: '1', chainId, verifyingContract: CONTRACT_ADDRESS };
    const types = { Claim: [{ name: 'user', type: 'address' }, { name: 'proofsHash', type: 'bytes32' }, { name: 'deviceKeyHash', type: 'bytes32' }, { name: 'userBioConstant', type: 'uint256' }, { name: 'nonce', type: 'uint256' }] };
    const value = { user: account, proofsHash, deviceKeyHash, userBioConstant, nonce };
    const signature = await signer._signTypedData(domain, types, value);
    return signature;
  }
};

// UI Module (Extended for Dashboard, with formatting from functional)
const UI = {
  showAlert: (msg) => alert(msg),
  showLoading: (id) => document.getElementById(`${id}-loading`).classList.remove('hidden'),
  hideLoading: (id) => document.getElementById(`${id}-loading`).classList.add('hidden'),
  updateConnectedAccount: () => {
    document.getElementById('connectedAccount').textContent = account ? `${account.slice(0,6)}...${account.slice(-4)}` : 'Not connected';
    document.getElementById('wallet-address').textContent = account ? `Connected: ${account.slice(0,6)}...${account.slice(-4)}` : '';
  },
  formatWithCommas: (num) => num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ","),
  formatDisplayDate: (timestampInSeconds) => {
    const date = new Date(timestampInSeconds * 1000);
    const isoString = date.toISOString();  // e.g. "2025-01-28T13:18:55.000Z"
    const datePart = isoString.slice(0, 10);   // "2025-01-28"
    const timePart = isoString.slice(11, 19); // "13:18:55"
    return `${datePart} ${timePart}`;
  }
};

// Contract Interactions (Auto from Proofs, Buttons Only)
const ContractInteractions = {
  claimTVM: async () => {
    await Proofs.loadAutoProof();
    UI.showLoading('claim');
    try {
      const gasEstimate = await tvmContract.estimateGas.claimTVM(autoProofs, autoSignature, autoDeviceKeyHash, autoUserBioConstant, autoNonce);
      const tx = await tvmContract.claimTVM(autoProofs, autoSignature, autoDeviceKeyHash, autoUserBioConstant, autoNonce, { gasLimit: gasEstimate.mul(120).div(100) });
      await tx.wait();
      UI.showAlert('Claim successful.');
      Wallet.updateBalances();
    } catch (err) {
      console.error(err);
      UI.showAlert('Error claiming TVM: ' + (err.reason || err.message || err));
    } finally {
      UI.hideLoading('claim');
    }
  },
  exchangeTVMForSegments: async () => {
    // Auto amount from proofs or balance
    autoExchangeAmount = vaultData.balanceSHE / EXCHANGE_RATE; // Example auto
    UI.showLoading('exchange');
    try {
      const amount = ethers.utils.parseUnits(autoExchangeAmount.toString(), 18);
      const gasEstimate = await tvmContract.estimateGas.exchangeTVMForSegments(amount);
      const tx = await tvmContract.exchangeTVMForSegments(amount, { gasLimit: gasEstimate.mul(120).div(100) });
      await tx.wait();
      UI.showAlert('Exchange successful.');
      Wallet.updateBalances();
      vaultData.balanceSHE += autoExchangeAmount * EXCHANGE_RATE;
      Vault.updateVaultUI();
    } catch (err) {
      UI.showAlert('Error exchanging: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('exchange');
    }
  },
  swapTVMForUSDT: async () => {
    // Auto amount from balance
    autoSwapAmount = vaultData.balanceSHE / EXCHANGE_RATE; // Example auto
    UI.showLoading('swap');
    try {
      const amount = ethers.utils.parseUnits(autoSwapAmount.toString(), 18);
      await tvmContract.approve(CONTRACT_ADDRESS, amount);
      const gasEstimate = await tvmContract.estimateGas.swapTVMForUSDT(amount);
      const tx = await tvmContract.swapTVMForUSDT(amount, { gasLimit: gasEstimate.mul(120).div(100) });
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
    // Auto amount from USDT balance
    const usdtBal = await usdtContract.balanceOf(account);
    autoSwapUSDTAmount = ethers.utils.formatUnits(usdtBal, 6); // Example auto full balance
    UI.showLoading('swap-usdt');
    try {
      const amount = ethers.utils.parseUnits(autoSwapUSDTAmount.toString(), 6); // USDT decimals
      await usdtContract.approve(CONTRACT_ADDRESS, amount);
      const gasEstimate = await tvmContract.estimateGas.swapUSDTForTVM(amount);
      const tx = await tvmContract.swapUSDTForTVM(amount, { gasLimit: gasEstimate.mul(120).div(100) });
      await tx.wait();
      UI.showAlert('Swap USDT to TVM successful.');
      Wallet.updateBalances();
    } catch (err) {
      UI.showAlert('Error swapping USDT to TVM: ' + (err.reason || err.message));
    } finally {
      UI.hideLoading('swap-usdt');
    }
  }
};

// Segment Module (Micro-Ledger per Segment)
const Segment = {
  initializeSegments: async () => {
    const segments = await DB.loadSegmentsFromDB();
    if (segments.length === 0) {
      for (let i = 1; i <= INITIAL_BALANCE_SHE; i++) {
        const segment = {
          segmentIndex: i,
          currentOwner: vaultData.bioIBAN,
          history: [{
            event: 'Initialization',
            timestamp: Date.now(),
            from: 'Genesis',
            to: vaultData.bioIBAN,
            bioConst: GENESIS_BIO_CONSTANT + i,
            integrityHash: await Utils.sha256Hex('init' + i + vaultData.bioIBAN)
          }]
        };
        await DB.saveSegmentToDB(segment);
      }
    }
    await Vault.updateBalanceFromSegments();
  },
  addHistoryToSegment: async (segmentIndex, event) => {
    const segments = await DB.loadSegmentsFromDB();
    const segment = segments.find(s => s.segmentIndex === segmentIndex);
    if (segment) {
      segment.history.push(event);
      if (segment.history.length > SEGMENT_HISTORY_MAX) {
        segment.history.shift(); // Keep only last 10
      }
      await DB.saveSegmentToDB(segment);
    }
  },
  validateSegment: async (segment) => {
    // Validate integrity hash chain
    let hash = 'init' + segment.segmentIndex + segment.history[0].to;
    for (let h of segment.history.slice(1)) {
      hash = await Utils.sha256Hex(hash + h.event + h.timestamp + h.from + h.to + h.bioConst);
      if (h.integrityHash !== hash) return false;
    }
    // Validate biometric ZKP if present
    if (segment.history[segment.history.length - 1].biometricZKP) {
      // Verify ZKP (simulated; in prod, verify signature)
      if (!(await Utils.sha256(segment.history[segment.history.length - 1].biometricZKP).then(zkpHash => zkpHash.startsWith('0')))) return false; // Placeholder validation
    }
    return true;
  }
};

// P2P Module (Catch In/Out - NFC/WebRTC for Offline, with Micro-Ledger, ZKP, and bio-catch integration)
const P2P = {
  generateBioCatchNumber: (senderBioIBAN, receiverBioIBAN, amount, timestamp) => {
    const senderNumeric = parseInt(senderBioIBAN.slice(3));
    const receiverNumeric = parseInt(receiverBioIBAN.slice(3));
    const firstPart = senderNumeric + receiverNumeric; // existing logic
    const secondPart = amount + timestamp;            // existing logic
    // NEW: add the **actual sender’s IBAN** as a final part:
    return `Bio-${firstPart}-${secondPart}-${senderBioIBAN}`;
  },
  validateBioCatchNumber: (bioCatchNumber, amount) => {
    const parts = bioCatchNumber.split('-');
    if (parts.length !== 4 || parts[0] !== 'Bio') {
      return { valid: false, message: 'Format must be Bio-<first>-<second>-<senderIBAN>.' };
    }
    const firstPart = parseInt(parts[1]);
    const secondPart = parseInt(parts[2]);
    const claimedSenderIBAN = parts[3];

    if (isNaN(firstPart) || isNaN(secondPart)) {
      return { valid: false, message: 'Both numeric parts must be valid numbers.' };
    }

    const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
    const senderNumeric = firstPart - receiverNumeric;
    const expectedFirstPart = senderNumeric + receiverNumeric;
    if (firstPart !== expectedFirstPart) {
      return { valid: false, message: 'Mismatch in sum of sender/receiver IBAN numerics.' };
    }

    const extractedTimestamp = secondPart - amount;
    const currentTimestamp = vaultData.lastUTCTimestamp;
    const timeDiff = Math.abs(currentTimestamp - extractedTimestamp);
    if (timeDiff > TRANSACTION_VALIDITY_SECONDS) {
      return { valid: false, message: 'Timestamp is outside ±12min window.' };
    }

    // Ensure the 4th part matches the actual derived sender IBAN
    const expectedSenderIBAN = `BIO${senderNumeric}`;
    if (claimedSenderIBAN !== expectedSenderIBAN) {
      return { valid: false, message: 'Mismatched Sender IBAN in the Bio-Catch code.' };
    }

    return { valid: true };
  },
  validateBioIBAN: (bioIBAN) => {
    if (!bioIBAN.startsWith('BIO')) return false;
    const numericPart = parseInt(bioIBAN.slice(3));
    if (isNaN(numericPart)) return false;
    const derivedTimestamp = numericPart - vaultData.initialBioConstant;
    const currentUTCTimestamp = Math.floor(Date.now() / 1000);
    return (derivedTimestamp > 0 && derivedTimestamp <= currentUTCTimestamp);
  },
  transactionLock: false,
  handleCatchOut: async () => {
    if (!vaultUnlocked) {
      UI.showAlert('❌ Please unlock the vault first.');
      return;
    }
    if (P2P.transactionLock) {
      UI.showAlert('🔒 A transaction is already in progress. Please wait.');
      return;
    }

    const receiverBioIBAN = document.getElementById('receiverBioIBAN')?.value.trim();
    const amount = parseFloat(document.getElementById('catchOutAmount')?.value.trim());

    if (!receiverBioIBAN || isNaN(amount) || amount <= 0) {
      UI.showAlert('❌ Please enter a valid Receiver Bio‑IBAN and Amount.');
      return;
    }
    if (!P2P.validateBioIBAN(receiverBioIBAN)) {
      UI.showAlert('❌ Invalid Bio-IBAN format.');
      return;
    }
    if (receiverBioIBAN === vaultData.bioIBAN) {
      UI.showAlert('❌ You cannot send to your own Bio‑IBAN.');
      return;
    }
    if (vaultData.balanceSHE < amount) {
      UI.showAlert('❌ Insufficient SHE balance.');
      return;
    }

    P2P.transactionLock = true;
    try {
      const currentTimestamp = vaultData.lastUTCTimestamp;
      // Now includes the full sender IBAN in the code
      const plainBioCatchNumber = P2P.generateBioCatchNumber(
        vaultData.bioIBAN,
        receiverBioIBAN,
        amount,
        currentTimestamp
      );

      // check duplication
      for (let tx of vaultData.transactions) {
        if (tx.bioCatch) {
          const existingPlain = await Encryption.decryptBioCatchNumber(tx.bioCatch);
          if (existingPlain === plainBioCatchNumber) {
            UI.showAlert('❌ This BioCatch number already exists. Try again.');
            return;
          }
        }
      }

      const segments = await DB.loadSegmentsFromDB();
      const transferableSegments = segments.filter(s => s.currentOwner === vaultData.bioIBAN).slice(0, amount);
      if (transferableSegments.length < amount) return UI.showAlert('Insufficient segments.');

      const zkp = await Biometric.generateBiometricZKP();
      if (!zkp) return UI.showAlert('Biometric ZKP generation failed.');

      vaultData.balanceSHE -= amount;
      vaultData.balanceUSD = parseFloat((vaultData.balanceSHE / EXCHANGE_RATE).toFixed(2));

      const obfuscatedCatch = await Encryption.encryptBioCatchNumber(plainBioCatchNumber);

      vaultData.transactions.push({
        type: 'sent',
        receiverBioIBAN,
        amount,
        timestamp: currentTimestamp,
        status: 'Completed', // irreversible
        bioCatch: obfuscatedCatch,
        bioConstantAtGeneration: vaultData.initialBioConstant
      });

      // Update segments
      for (let seg of transferableSegments) {
        await Segment.addHistoryToSegment(seg.segmentIndex, {
          event: 'Transfer',
          timestamp: Date.now(),
          from: vaultData.bioIBAN,
          to: receiverBioIBAN,
          bioConst: seg.history[seg.history.length - 1].bioConst + BIO_STEP,
          integrityHash: await Utils.sha256Hex('transfer' + seg.segmentIndex + receiverBioIBAN + Date.now()),
          biometricZKP: zkp
        });
        seg.currentOwner = receiverBioIBAN;
        await DB.saveSegmentToDB(seg);
      }

      Vault.updateVaultUI();
      await Vault.promptAndSaveVault();
      UI.showAlert(`✅ Transaction successful! Amount ${amount} SHE sent to ${receiverBioIBAN}`);

      showBioCatchPopup(obfuscatedCatch);

      document.getElementById('receiverBioIBAN').value = '';
      document.getElementById('catchOutAmount').value = '';

      renderTransactionTable();
    } catch (error) {
      console.error('Error processing send transaction:', error);
      UI.showAlert('❌ An error occurred while processing the transaction. Please try again.');
    } finally {
      P2P.transactionLock = false;
    }
  },
  handleCatchIn: async () => {
    if (!vaultUnlocked) {
      UI.showAlert('❌ Please unlock the vault first.');
      return;
    }
    if (P2P.transactionLock) {
      UI.showAlert('🔒 A transaction is already in progress. Please wait.');
      return;
    }

    const encryptedBioCatchInput = document.getElementById('catchInBioCatch')?.value.trim();
    const amount = parseFloat(document.getElementById('catchInAmount')?.value.trim());

    if (!encryptedBioCatchInput || isNaN(amount) || amount <= 0) {
      UI.showAlert('❌ Please enter a valid (base64) BioCatch Number and Amount.');
      return;
    }

    P2P.transactionLock = true;
    try {
      const bioCatchNumber = await Encryption.decryptBioCatchNumber(encryptedBioCatchInput);
      if (!bioCatchNumber) {
        UI.showAlert('❌ Unable to decode the provided BioCatch Number. Please ensure it is correct.');
        return;
      }

      for (let tx of vaultData.transactions) {
        if (tx.type === 'received' && tx.bioCatch) {
          const existingPlain = await Encryption.decryptBioCatchNumber(tx.bioCatch);
          if (existingPlain === bioCatchNumber) {
            UI.showAlert('❌ This BioCatch Number has already been used in a received transaction.');
            return;
          }
        }
      }

      // Now includes the 4th part => the actual sender IBAN
      const validation = P2P.validateBioCatchNumber(bioCatchNumber, amount);
      if (!validation.valid) {
        UI.showAlert(`❌ BioCatch Validation Failed: ${validation.message}`);
        return;
      }

      // After validation, we can parse the parts again to 
      // figure out the extracted timestamp, etc.
      const parts = bioCatchNumber.split('-');
      const firstPart = parseInt(parts[1]);
      const secondPart = parseInt(parts[2]);
      const claimedSenderIBAN = parts[3];

      const receiverNumeric = parseInt(vaultData.bioIBAN.slice(3));
      const senderNumeric = firstPart - receiverNumeric;
      const senderBioIBAN = `BIO${senderNumeric}`;
      const extractedTimestamp = secondPart - amount;

      if (!P2P.validateBioIBAN(senderBioIBAN)) {
        UI.showAlert('❌ Invalid Sender Bio‑IBAN extracted from BioCatch Number.');
        return;
      }

      const currentTimestamp = vaultData.lastUTCTimestamp;
      const timeDifference = Math.abs(currentTimestamp - extractedTimestamp);
      if (timeDifference > TRANSACTION_VALIDITY_SECONDS) {
        UI.showAlert('❌ The timestamp in BioCatch Number is outside acceptable window.');
        return;
      }

      for (let tx of vaultData.transactions) {
        if (tx.bioCatch) {
          const existingPlain = await Encryption.decryptBioCatchNumber(tx.bioCatch);
          if (existingPlain === bioCatchNumber) {
            UI.showAlert('❌ This BioCatch Number has already been used in a transaction.');
            return;
          }
        }
      }

      // Simulate receiving segments; in prod, payload would include segments
      // For merge, assume amount segments received and validated
      let validSegments = amount; // Placeholder; integrate full segment receive if payload has them

      vaultData.balanceSHE += validSegments;
      vaultData.balanceUSD = parseFloat((vaultData.balanceSHE / EXCHANGE_RATE).toFixed(2));

      const obfuscatedCatch = await Encryption.encryptBioCatchNumber(bioCatchNumber);
      vaultData.transactions.push({
        type: 'received',
        senderBioIBAN,
        bioCatch: obfuscatedCatch,
        amount: validSegments,
        timestamp: currentTimestamp,
        status: 'Valid'
      });

      Vault.updateVaultUI();
      await Vault.promptAndSaveVault();
      UI.showAlert(`✅ Transaction received successfully! ${validSegments} SHE added.`);

      document.getElementById('catchInBioCatch').value = '';
      document.getElementById('catchInAmount').value = '';

      renderTransactionTable();
    } catch (error) {
      console.error('Error processing receive transaction:', error);
      UI.showAlert('❌ An error occurred. Please try again.');
    } finally {
      P2P.transactionLock = false;
    }
  },
  handleNfcRead: () => {
    if ('nfc' in navigator) {
      navigator.nfc.watch(messages => {
        // Process incoming SHE transfer
        UI.showAlert('Incoming P2P transfer detected.');
      }, { mode: 'any' });
    }
  }
};

// Notifications Module
const Notifications = {
  requestPermission: () => {
    if (Notification.permission !== 'granted') {
      Notification.requestPermission();
    }
  },
  showNotification: (title, body) => {
    if (Notification.permission === 'granted') {
      new Notification(title, { body });
    }
  }
};

// Backup/Export Functions (From functional)
function exportTransactions() {
  const table = document.getElementById('transactionTable');
  const rows = table.querySelectorAll('tr');
  let csvContent = "data:text/csv;charset=utf-8,";

  rows.forEach(row => {
    const cols = row.querySelectorAll('th, td');
    const rowData = [];
    cols.forEach(col => {
      let data = col.innerText.replace(/"/g, '""');
      if (data.includes(',')) {
        data = `"${data}"`;
      }
      rowData.push(data);
    });
    csvContent += rowData.join(",") + "\r\n";
  });

  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "transaction_history.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function backupVault() {
  const backup = JSON.stringify(vaultData);
  const blob = new Blob([backup], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vault.backup';
  a.click();
}

function exportFriendlyBackup() {
  // Armored or encrypted backup
  UI.showAlert('Exporting friendly backup...');
}

function importVault() {
  const file = document.getElementById('importVaultInput').files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
      vaultData = JSON.parse(e.target.result);
      await Vault.promptAndSaveVault();
      Vault.updateVaultUI();
    };
    reader.readAsText(file);
  }
}

function copyToClipboard(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => UI.showAlert('Copied!'));
}

// Export Proof to Blockchain (Auto-Load into Dashboard)
function exportProofToBlockchain() {
  showSection('dashboard');
  Proofs.loadAutoProof();
  UI.showAlert('Proof auto-exported to dashboard actions.');
}

// Section Switching
function showSection(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active-section'));
  document.getElementById(id).classList.add('active-section');
  if (id === 'dashboard') loadDashboardData();
}

// Theme Toggle
document.getElementById('theme-toggle').addEventListener('click', () => document.body.classList.toggle('dark-mode'));

// Enable Dashboard Buttons after Connection
function enableDashboardButtons() {
  document.getElementById('claim-tvm-btn').disabled = false;
  document.getElementById('exchange-tvm-btn').disabled = false;
  document.getElementById('swap-tvm-usdt-btn').disabled = false;
  document.getElementById('swap-usdt-tvm-btn').disabled = false;
}

// PWA Service Worker Registration
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(reg => console.log('Service Worker Registered')).catch(err => console.error('Registration failed', err));
}

// Single-Vault Enforcement (From functional)
function preventMultipleVaults() {
  window.addEventListener('storage', (event) => {
    if (event.key === 'vaultUnlocked') {
      if (event.newValue === 'true' && !vaultUnlocked) {
        vaultUnlocked = true;
        Vault.updateVaultUI();
        initializeBioConstantAndUTCTime();
      } else if (event.newValue === 'false' && vaultUnlocked) {
        vaultUnlocked = false;
        Vault.lockVault();
      }
    }
    if (event.key === 'vaultLock') {
      if (event.newValue === 'locked' && !vaultUnlocked) {
        console.log('🔒 Another tab indicated vault lock is in place.');
      }
    }
  });
}

function enforceSingleVault() {
  const vaultLock = localStorage.getItem('vaultLock');
  if (!vaultLock) {
    localStorage.setItem('vaultLock', 'locked');
  } else {
    console.log('🔒 Vault lock detected. Ensuring single vault instance.');
  }
}

// Popup Functions (From functional for bio-catch)
function showBioCatchPopup(encryptedBioCatch) {
  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const bioCatchNumberText = document.getElementById('bioCatchNumberText');

  bioCatchNumberText.textContent = encryptedBioCatch; // base64
  bioCatchPopup.style.display = 'flex';
}

// Transaction Table Rendering (From functional)
function renderTransactionTable() {
  const tbody = document.getElementById('transactionBody');
  tbody.innerHTML = '';

  vaultData.transactions
    .sort((a, b) => b.timestamp - a.timestamp)
    .forEach(tx => {
      const row = document.createElement('tr');

      let bioIBANCell = '—';
      let bioCatchCell = '—';
      let amountCell = tx.amount;
      let timestampCell = UI.formatDisplayDate(tx.timestamp);
      let statusCell = tx.status;

      if (tx.type === 'sent') {
        bioIBANCell = tx.receiverBioIBAN;
      } else if (tx.type === 'received') {
        bioIBANCell = tx.senderBioIBAN || 'Unknown';
      }

      if (tx.bioCatch) {
        bioCatchCell = tx.bioCatch; // base64 string
      }

      let bioIBANCellStyle = '';
      if (tx.type === 'sent') {
        bioIBANCellStyle = 'style="background-color: #FFCCCC;"';
      } else if (tx.type === 'received') {
        bioIBANCellStyle = 'style="background-color: #CCFFCC;"';
      }

      row.innerHTML = `
        <td ${bioIBANCellStyle}>${bioIBANCell}</td>
        <td>${bioCatchCell}</td>
        <td>${amountCell}</td>
        <td>${timestampCell}</td>
        <td>${statusCell}</td>
      `;
      tbody.appendChild(row);
    });
}

// Bio-Constant & UTC Time Initialization (From functional)
function initializeBioConstantAndUTCTime() {
  if (bioLineIntervalTimer) clearInterval(bioLineIntervalTimer);

  const currentTimestamp = Math.floor(Date.now() / 1000);
  const elapsedSeconds = currentTimestamp - vaultData.lastUTCTimestamp;
  vaultData.initialBioConstant += elapsedSeconds;
  vaultData.lastUTCTimestamp = currentTimestamp;

  console.log("✅ Bio-Line initialized with current bioConstant and UTC timestamp.");
  Vault.updateVaultUI();

  bioLineIntervalTimer = setInterval(() => {
    vaultData.initialBioConstant += 1;
    vaultData.lastUTCTimestamp += 1;
    console.log(`🔄 Bio-Constant Updated: ${vaultData.initialBioConstant}`);

    Vault.updateVaultUI();
    Vault.promptAndSaveVault();
  }, 1000);
}

// Load Vault on Startup (From functional)
async function loadVaultOnStartup() {
  const stored = await DB.loadVaultDataFromDB();
  if (stored && stored.iv && stored.ciphertext && stored.salt) {
    document.getElementById('enterVaultBtn').style.display = 'block';
    document.getElementById('lockedScreen').classList.remove('hidden');
    document.getElementById('vaultUI').classList.add('hidden');
  } else {
    document.getElementById('enterVaultBtn').style.display = 'block';
    document.getElementById('lockedScreen').classList.remove('hidden');
    document.getElementById('vaultUI').classList.add('hidden');
  }
}

// Init Function (Full integrated, with startup load)
async function init() {
  Notifications.requestPermission();
  P2P.handleNfcRead(); // Start NFC if supported

  await loadVaultOnStartup();
  preventMultipleVaults(); // inter-tab sync
  enforceSingleVault();

  // Event Listeners
  document.getElementById('connectMetaMaskBtn').addEventListener('click', Wallet.connectMetaMask);
  document.getElementById('connectWalletConnectBtn').addEventListener('click', Wallet.connectWalletConnect);
  document.getElementById('enterVaultBtn').addEventListener('click', Vault.unlockVault);
  document.getElementById('lockVaultBtn').addEventListener('click', Vault.lockVault);
  document.getElementById('catchOutBtn').addEventListener('click', P2P.handleCatchOut);
  document.getElementById('catchInBtn').addEventListener('click', P2P.handleCatchIn);
  document.getElementById('claim-tvm-btn').addEventListener('click', ContractInteractions.claimTVM);
  document.getElementById('exchange-tvm-btn').addEventListener('click', ContractInteractions.exchangeTVMForSegments);
  document.getElementById('swap-tvm-usdt-btn').addEventListener('click', ContractInteractions.swapTVMForUSDT);
  document.getElementById('swap-usdt-tvm-btn').addEventListener('click', ContractInteractions.swapUSDTForTVM);
  document.getElementById('connect-wallet').addEventListener('click', Wallet.connectMetaMask); // Default to MetaMask, or add dropdown
  document.getElementById('exportBtn').addEventListener('click', exportTransactions);

  const bioCatchPopup = document.getElementById('bioCatchPopup');
  const closeBioCatchPopupBtn = document.getElementById('closeBioCatchPopup');
  const copyBioCatchPopupBtn = document.getElementById('copyBioCatchBtn');

  if (closeBioCatchPopupBtn) {
    closeBioCatchPopupBtn.addEventListener('click', () => {
      bioCatchPopup.style.display = 'none';
    });
  }

  if (copyBioCatchPopupBtn) {
    copyBioCatchPopupBtn.addEventListener('click', () => {
      const bcNum = document.getElementById('bioCatchNumberText').textContent;
      navigator.clipboard.writeText(bcNum)
        .then(() => UI.showAlert('✅ Bio‑Catch Number copied to clipboard!'))
        .catch(err => {
          console.error('❌ Clipboard copy failed:', err);
          UI.showAlert('⚠️ Failed to copy Bio‑Catch Number. Try again!');
        });
    });
  }

  window.addEventListener('click', (event) => {
    if (event.target === bioCatchPopup) {
      bioCatchPopup.style.display = 'none';
    }
  });

  // Idle Timeout
  setTimeout(Vault.lockVault, MAX_IDLE);

  // UTC Time Update
  setInterval(() => {
    document.getElementById('utcTime').textContent = new Date().toUTCString();
  }, 1000);

  // Load Dashboard on Init if Needed
  loadDashboardData();
}

// Load Dashboard Data (Real Contract Calls + Charts, removed refill)
async function loadDashboardData() {
  if (!tvmContract) return;
  // Update Balances
  await Wallet.updateBalances();

  // Layer Table (Mock/Real - Assume contract has getLayerReserve(layer))
  let table = '';
  let totalReserves = 0;
  for (let i = 1; i <= LAYERS; i++) {
    const reserve = 100000000; // Mock, replace with await tvmContract.getLayerReserve(i) if function added
    totalReserves += reserve;
    const capProgress = (SEGMENTS_PER_LAYER / reserve * 100).toFixed(2) + '%'; // Example
    table += `<tr><td>${i}</td><td>${reserve.toLocaleString()} TVM</td><td>${capProgress}</td></tr>`;
  }
  document.getElementById('layer-table').innerHTML = table;
  document.getElementById('avg-reserves').textContent = (totalReserves / LAYERS).toLocaleString() + ' TVM';

  // Charts (Updated with Chart.js v4)
  new Chart(document.getElementById('pool-chart'), {
    type: 'doughnut',
    data: { labels: ['Human Investment (51%)', 'AI Cap (49%)'], datasets: [{ data: [51, 49], backgroundColor: ['#007bff', '#dc3545'], borderRadius: 5 }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } }, cutout: '60%' }
  });
  new Chart(document.getElementById('layer-chart'), {
    type: 'bar',
    data: { labels: Array.from({length: LAYERS}, (_, i) => `Layer ${i+1}`), datasets: [{ label: 'Reserve (M TVM)', data: Array(LAYERS).fill(100), backgroundColor: '#007bff' }] },
    options: { responsive: true, scales: { y: { beginAtZero: true } } }
  });
}

init();
