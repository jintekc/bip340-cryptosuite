import * as tinysecp from 'tiny-secp256k1';
import { PrivateKey } from '../src/keys/private-key';
import { PublicKeyUtils } from '../src/keys/public-key';

const SECRET = 52464508790539176856770556715241483442035423615466097401201513777400180778402n;
console.log('SECRET', SECRET);
const privateKey = PrivateKey.fromSecret(SECRET);
console.log('privateKey', privateKey);
const publicKey = privateKey.computePublicKey();
const publicKey = PublicKeyUtils.liftX(.compressed);
console.log('publicKey', publicKey);

const uncompressed = tinysecp.pointCompress(this.compressed, false) as PublicKeyBytes;