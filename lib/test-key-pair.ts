import { KeyPair } from '../src/keys/key-pair.js';

const privateKeyBytes = new Uint8Array([
  115, 253, 220, 18, 252, 147, 66, 187,
  41, 174, 155, 94, 212, 118, 50,  59,
  220, 105,  58, 17, 110,  54, 81,  36,
  85, 174, 232, 48, 254, 138, 37, 162
]);
const kpFromPrv = KeyPair.fromPrivateKey(privateKeyBytes);
console.log('kpFromPrv.privateKey', kpFromPrv.privateKey);
console.log('kpFromPrv.publicKey', kpFromPrv.publicKey);

const kpGen = KeyPair.generate();
console.log('kpGen.privateKey.raw', kpGen.privateKey.raw);
console.log('kpGen.privateKey.secret', kpGen.privateKey.secret);
console.log('kpGen.privateKey.point', kpGen.privateKey.point);
console.log('kpGen.privateKey.hex', kpGen.privateKey.hex());
console.log('kpGen.publicKey.raw', kpGen.publicKey.compressed);
console.log('kpGen.publicKey.uncompressed', kpGen.publicKey.uncompressed);
console.log('kpGen.publicKey.x', kpGen.publicKey.x);
console.log('kpGen.publicKey.y', kpGen.publicKey.y);