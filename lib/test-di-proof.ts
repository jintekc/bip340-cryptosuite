import { Cryptosuite } from '../src/di-bip340/cryptosuite/index.js';
import { DataIntegrityProof } from '../src/di-bip340/data-integrity-proof/index.js';
import { Multikey } from '../src/di-bip340/multikey/index.js';
import { KeyPair } from '../src/keys/key-pair.js';
import { PrivateKey } from '../src/keys/private-key.js';
import { ProofOptions } from '../src/types/di-proof.js';

// Unsecured document
const unsecuredDocument = {
  '@context' : [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2',
  ],
  'id'                : 'http://university.example/credentials/58473',
  'type'              : ['VerifiableCredential', 'ExampleAlumniCredential'],
  'validFrom'         : '2020-01-01T00:00:00Z',
  'credentialSubject' : {
    'id'       : 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    'alumniOf' : {
      'id'   : 'did:example:c276e12ec21ebfeb1f712ebc6f1',
      'name' : 'Example University',
    },
  },
  'issuer' : 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65',
};
// Multikey id and controller
const id = '#initialKey';
const controller = 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65';

// // Private key secret
// // Schnorr key
const SECRET = 52464508790539176856770556715241483442035423615466097401201513777400180778402n;
console.log('SECRET', SECRET);
const privateKey = PrivateKey.fromSecret(SECRET);
console.log('privateKey', privateKey);
// const secretHex = (SECRET % CURVE.n).toString(16).padStart(64, '0');
// console.log('secretHex', secretHex);
// const privateKey = new Uint8Array(
//   secretHex.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
// );
// // Private key
// console.log('privateKey', privateKey);
// Get public key
// const publicKey = secp.getPublicKey(privateKey, true);
// console.log('publicKey', publicKey);

// const privateKeyBytes = new Uint8Array([
//   115, 253, 220, 18, 252, 147, 66, 187,
//   41, 174, 155, 94, 212, 118, 50,  59,
//   220, 105,  58, 17, 110,  54, 81,  36,
//   85, 174, 232, 48, 254, 138, 37, 162
// ]);
console.log('privateKey.raw', privateKey.raw);
// const publicKeyBytes = new Uint8Array([
//   3,  79,  96, 138,  82,   3,  54,  86,
//   141, 235,  42, 148,  25,  72,  25,  71,
//   0, 240, 255, 250, 153,  12, 162, 243,
//   137,  60,  65, 215, 217, 230,  85,   1,
//   42
// ]);
const publicKey = privateKey.computePublicKey();
console.log('publicKey.compressed', publicKey.compressed);

const keyPair = new KeyPair({ privateKey });
console.log('keyPair', keyPair);

// Create multikey
const multikey = new Multikey({ id, controller, keyPair });
console.log('multikey', multikey);
console.log('multikey.keyPair.publicKey.multibase', multikey.keyPair.publicKey.multibase);
// Create cryptosuite
const cryptosuite = new Cryptosuite({ cryptosuite: 'bip340-jcs-2025', multikey });
console.log('cryptosuite', cryptosuite);
const message = Buffer.from('Hello BTC1!');
const signature = multikey.sign(message);
console.log('signature', signature);
// Create data integrity proof
const diProof = new DataIntegrityProof(cryptosuite);
// console.log('diProof', diProof);

// Set options
const options: ProofOptions = {
  type               : 'DataIntegrityProof',
  cryptosuite        : 'bip340-jcs-2025',
  verificationMethod : 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65#initialKey',
  proofPurpose       : 'attestationMethod'
};
// Add proof
const securedDocument = await diProof.addProof({ document: unsecuredDocument, options });
console.log('securedDocument', securedDocument);

const expectedPurpose = 'attestationMethod';
const mediaType = 'application/json';
const document = JSON.stringify(securedDocument);
// Verify proof
const verifiedProof = await diProof.verifyProof({ document, expectedPurpose, mediaType });
console.log('verifiedProof', verifiedProof);
