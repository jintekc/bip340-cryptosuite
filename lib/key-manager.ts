import { Btc1KeyManager } from '../src/btc1-key-manager.js';
import { Cryptosuite } from '../src/di-bip340/cryptosuite/index.js';
import { DataIntegrityProof } from '../src/di-bip340/data-integrity-proof/index.js';
import { Multikey } from '../src/di-bip340/multikey/index.js';
import { KeyPair } from '../src/utils/keypair.js';

const d = new Uint8Array([
  159,  79, 128, 155, 191, 173,  89, 197,
  77, 153,  66, 245, 104,  93, 212, 152,
  14, 174,   1,  99,  18,  32,  32,  87,
  255, 108, 254,  69, 207, 106, 115,  41
]);
console.log('privateKey', d);
const keys = new KeyPair(d);
console.log('keys', keys);
const controller = 'did:btc1:k1qvddh3hl7n5czluwhz9ry35tunkhtldhgr66zp907ewg4l7p6u786tz863a';
const multikey = new Multikey({ id: '#initialKey', controller, privateKey: d });
const cryptosuite = new Cryptosuite({ cryptosuite: 'bip340-jcs-2025', multikey });
const proof = new DataIntegrityProof(cryptosuite);
const keyManager = new Btc1KeyManager({ multikey, proof });
console.log(keyManager);