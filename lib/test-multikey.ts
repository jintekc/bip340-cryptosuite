import { KeyPairUtils } from '../src/keys/key-pair.js';
import { Multikey } from '../src/di-bip340/multikey/index.js';
// Crypto Constants
const privateKeyBytes = new Uint8Array([
  115, 253, 220, 18, 252, 147, 66, 187,
  41, 174, 155, 94, 212, 118, 50,  59,
  220, 105,  58, 17, 110,  54, 81,  36,
  85, 174, 232, 48, 254, 138, 37, 162
]);
/*const publicKeyBytes = new Uint8Array([
  2, 154, 213, 246, 168,  93,  39, 238,
  105, 177,  51, 174, 210, 115, 180, 242,
  245, 215,  14, 212, 167,  22, 117,   1,
  156,  26, 118, 240,  76, 102,  53,  38,
  239
]);*/
const keyPair = KeyPairUtils.fromPrivateKey(privateKeyBytes);
// const { publicKey, privateKey } = keyPair;

// Multikey Constants
const id = '#initialKey';
const type = 'Multikey';
const controller = 'did:btc1:k1qvddh3hl7n5czluwhz9ry35tunkhtldhgr66zp907ewg4l7p6u786tz863a';
const controlId = `${controller}${id}`;
const publicKeyMultibase = 'z66PwJnYvwJLhGrVc8vcuUkKs99sKCzYRM2HQ2gDCGTAStHk';
const verificationMethod = { id, type, controller, publicKeyMultibase };
const message = Buffer.from('Hello BTC1!');
const validSignature = new Uint8Array([
  120, 106, 121,  54, 225,  45, 189, 134,  48,  20, 118,
  70, 228,  69,  29,  32,  74, 170,  55, 215, 193, 245,
  54, 220, 220,  20,  69,  11, 192, 138, 137,  85, 121,
  26, 215,  77, 208, 122, 118,  95,  30,  91,   3, 137,
  245,   1,  67, 147,  99,  48,  39,  83, 189, 132, 158,
  65, 114, 110,  48,  39,  91, 142, 117, 138
]);
const invalidSignature =  new Uint8Array([
  25, 105, 158, 232,  91,   7,  61,   8,   2, 215, 191,
  122,  47,  51, 195, 195, 207,  95, 213, 226,  72, 224,
  10, 153,  84,  66, 197, 186, 110, 108,  91, 156, 195,
  157, 126,  82,  51,  10, 167, 163, 240, 244, 231, 140,
  202, 250, 220, 245, 132,  34, 102,  64, 202,  24,  97,
  163,  84,  73, 128,   5, 188, 219,  47, 133
]);
const multikey = new Multikey({ id, controller, keyPair });
console.log('multikey', multikey);

const signature = multikey.sign(message);
console.log('signature', signature);

const verify = [validSignature, invalidSignature].map(s => multikey.verify(s, message));
console.log('verify', verify);

const encoded = multikey.publicKey.multibase;
console.log('encoded', encoded);

let decoded = multikey.publicKey.decodeMultibase();
console.log('decoded', decoded);

const prefix = decoded.subarray(0, 2);
console.log('prefix', prefix);

const publicKeyBytes = decoded.subarray(2);
console.log('publicKeyBytes', publicKeyBytes);

const toVM = multikey.toVerificationMethod();
console.log('toVM', toVM);

const multikeyFromVm = multikey.fromVerificationMethod(verificationMethod);
console.log('multikeyFromVm', multikeyFromVm);

const fullId = multikey.fullId();
console.log('fullId', fullId);
console.log('controlId', controlId);