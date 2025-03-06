import { KeyPair } from '../src/keys/key-pair.js';
import { Multikey } from '../src/di-bip340/multikey/index.js';
// Crypto Constants
const privateKeyBytes = new Uint8Array([
  115, 253, 220, 18, 252, 147, 66, 187,
  41, 174, 155, 94, 212, 118, 50,  59,
  220, 105,  58, 17, 110,  54, 81,  36,
  85, 174, 232, 48, 254, 138, 37, 162
]);
const keyPair = KeyPair.fromPrivateKey(privateKeyBytes);
const { publicKey, privateKey } = keyPair;
console.log('privateKey', privateKey);
console.log('publicKey', publicKey);
// Multikey Constants
const id = '#initialKey';
const type = 'Multikey';
const controller = 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7e0qglk';
// const fullId = `${controller}${id}`;
const publicKeyMultibase = 'z66PwJnYvwJLhGrVc8vcuUkKs99sKCzYRM2HQ2gDCGTAStHk';
// const verificationMethod = { id, type, controller, publicKeyMultibase };
// const validSignature = new Uint8Array([
//   137, 213,   6, 127,  43, 174, 181, 234,  11, 137,  60,
//   194, 144,  17, 167,   8, 147,  88,  28, 216,  31,  43,
//   126, 169,  50, 116,  82,  19,  10, 241,  43,  59, 100,
//   240, 118, 252, 224, 251,  94,  29, 151,  99, 120,  55,
//   108, 211,  65,  61, 190,   9,  27, 141, 120, 205, 151,
//   4, 188,  26,  32, 221, 190, 248,  87, 105
// ]);
// const invalidSignature =  new Uint8Array([
//   25, 105, 158, 232,  91,   7,  61,   8,   2, 215, 191,
//   122,  47,  51, 195, 195, 207,  95, 213, 226,  72, 224,
//   10, 153,  84,  66, 197, 186, 110, 108,  91, 156, 195,
//   157, 126,  82,  51,  10, 167, 163, 240, 244, 231, 140,
//   202, 250, 220, 245, 132,  34, 102,  64, 202,  24,  97,
//   163,  84,  73, 128,   5, 188, 219,  47, 133
// ]);

const message = 'hello, did:btc1';

const multikey = new Multikey({ id, controller, keyPair });
console.log('multikey', multikey);

const vm = { id, type, controller, publicKeyMultibase };
const fromVM = multikey.fromVerificationMethod(vm);
console.log('fromVM', fromVM);

const signature = multikey.sign(message);
console.log('signature', signature);

// const verify = [validSignature, invalidSignature].map(s => multikey.verify(message, s));
// console.log('verify', verify);

// const encoded = multikey.encode();
// console.log('encoded', encoded);

// let pubkey = multikey.decode(encoded);
// console.log('pubkey1', pubkey);

// const prefix = pubkey.subarray(0, 2);
// console.log('prefix', prefix);

// pubkey = pubkey.subarray(2);
// console.log('pubkey2', pubkey);

// const verificationMethod = multikey.toVerificationMethod();
// console.log('verificationMethod', verificationMethod);

// const multikeyFromVm = multikey.fromVerificationMethod(verificationMethod);
// console.log('multikeyFromVm', multikeyFromVm);