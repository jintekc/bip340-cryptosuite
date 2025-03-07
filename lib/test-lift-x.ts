import { getPublicKey } from '@noble/secp256k1';
import { PrivateKey } from '../src/keys/private-key';

const SECRET = 52464508790539176856770556715241483442035423615466097401201513777400180778402n;
console.log('SECRET', SECRET);
const privateKey = PrivateKey.fromSecret(SECRET);
console.log('privateKey', privateKey);
const getPubKey = getPublicKey(privateKey.raw, true);
console.log('getPubKey', getPubKey);
const publicKey = privateKey.computePublicKey();
console.log('publicKey', publicKey);
