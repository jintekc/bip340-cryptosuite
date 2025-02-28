// import { expect } from 'chai';
// import { Btc1KeyManagerError } from '../src/error.js';
// import Multikey from '../src/multikey.js';
// import ObjectUtils from '../src/utils.js';

/**
 * Multikey Test Cases
 *
 * 1. id, controller only → should throw
 * 2. id, controller, privateKey → should succeed
 * 3. id, controller, publicKey → should succeed
 * 4. id, controller, privateKey, publicKey → should succeed
 *
 */
// describe('Main', () => {
//   const id = '#initialKey';
//   const type = 'Multikey';
//   const controller = 'did:btc1:k1qvddh3hl7n5czluwhz9ry35tunkhtldhgr66zp907ewg4l7p6u786tz863a';
//   const fullId = `${controller}#${id}`;
//   const prefix = new Uint8Array([225,  74]);
//   const publicKeyMultibase = 'z66PrEE8AWgvHuw3Zyd3mFEJjgFmAfswkDGF9TurXoKr5hmb';
//   const verificationMethod = { id, type, controller, publicKeyMultibase };
//   const publicKey = new Uint8Array([
//     79,  96, 138,  82,   3,  54,  86, 141,
//     235,  42, 148,  25,  72,  25,  71,   0,
//     240, 255, 250, 153,  12, 162, 243, 137,
//     60,  65, 215, 217, 230,  85,   1,  42
//   ]);
//   const privateKey = new Uint8Array([
//     139, 106,  49, 176,  63,  12, 121,  46,
//     94, 115, 142, 201,  94,  75, 143, 216,
//     210,  68, 197, 137, 232,  63,  63, 178,
//     30, 220, 161, 210,  96, 218, 198, 158
//   ]);

//   const SECRET = 52464508790539176856770556715241483442035423615466097401201513777400180778402n;
//   const unsecuredDocument = {
//     '@context' : [
//       'https://www.w3.org/ns/credentials/v2',
//       'https://www.w3.org/ns/credentials/examples/v2'],
//     'id'                : 'http://university.example/credentials/58473',
//     'type'              : ['VerifiableCredential', 'ExampleAlumniCredential'],
//     'validFrom'         : '2020-01-01T00:00:00Z',
//     'credentialSubject' : {
//       'id'       : 'did:example:ebfeb1f712ebc6f1c276e12ec21',
//       'alumniOf' : {
//         'id'   : 'did:example:c276e12ec21ebfeb1f712ebc6f1',
//         'name' : 'Example University'
//       }
//     },
//     'issuer' : 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65'
//   };

// });