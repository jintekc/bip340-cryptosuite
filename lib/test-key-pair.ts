import { KeyPair } from '../src/keys/key-pair.js';
import { PrivateKeyUtils } from '../src/keys/private-key.js';

const privateKeyBytes = PrivateKeyUtils.random();
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