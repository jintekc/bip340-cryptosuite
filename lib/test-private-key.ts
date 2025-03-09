import { PrivateKey, PrivateKeyUtils } from '../src/keys/private-key.js';

const BYTES = new Uint8Array([
  115, 253, 220, 18, 252, 147, 66, 187,
  41, 174, 155, 94, 212, 118, 50,  59,
  220, 105,  58, 17, 110,  54, 81,  36,
  85, 174, 232, 48, 254, 138, 37, 162
]);
const SECRET = 52464508790539176856770556715241483442035423615466097401201513777400180778402n;
const prvFromSec = PrivateKeyUtils.fromSecret(SECRET);
console.log('prvFromSec', prvFromSec);
const pubFromPk = prvFromSec.computePublicKey();
console.log('pubFromPk', pubFromPk);

const privateKey = new PrivateKey(BYTES);
console.log('new privateKey', privateKey);
const publicKey = privateKey.computePublicKey();
console.log('publicKey', Object.entries(publicKey).map(([k, v]) => ({k, v})));