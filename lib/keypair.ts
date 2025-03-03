import { KeyPair } from '../src/crypto/key-pair.js';
import { PrivateKey } from '../src/crypto/private-key.js';
import { PublicKey } from '../src/crypto/public-key.js';
import { Multikey } from '../src/di-bip340/multikey/index.js';

const privateKeyBytes = new Uint8Array([
  139, 106,  49, 176,  63,  12, 121,  46,
  94, 115, 142, 201,  94,  75, 143, 216,
  210,  68, 197, 137, 232,  63,  63, 178,
  30, 220, 161, 210,  96, 218, 198, 158
]);
const publicKeyBytes = new Uint8Array([
  3,  79,  96, 138,  82,   3,  54,  86,
  141, 235,  42, 148,  25,  72,  25,  71,
  0, 240, 255, 250, 153,  12, 162, 243,
  137,  60,  65, 215, 217, 230,  85,   1,
  42
]);
const privateKey = new PrivateKey(privateKeyBytes);
const publicKey = new PublicKey(publicKeyBytes);
const keyPair = new KeyPair(privateKey);
const multikey = new Multikey({
  keyPair,
  publicKey,
  id         : '#initialKey',
  controller : 'did:btc1:k1qvddh3hl7n5czluwhz9ry35tunkhtldhgr66zp907ewg4l7p6u786tz863a',
});
console.log(multikey);
console.log('keyPair.publicKey.equals(publicKey)', keyPair.publicKey.equals(publicKey));