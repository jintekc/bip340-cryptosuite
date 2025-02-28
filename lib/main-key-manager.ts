import Multikey from '../src/multikey.js';
import JcsCryptosuite from '../src/jcs-cryptosuite.js';
import DataIntegrityProof from '../src/data-integrity-proof.js';
import { ProofOptions } from '../src/types.js';

const id = '#initialKey';
const controller = 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65';
const SECRET = 52464508790539176856770556715241483442035423615466097401201513777400180778402n;
const privateKey = Uint8Array.from(Buffer.from(SECRET.toString(16).padStart(64, '0'), 'hex'));
console.log('privateKey', privateKey);
const multikey = new Multikey({ id, controller, privateKey });
const publicKey = multikey.publicKey;
console.log('publicKey', publicKey);
const cryptosuite = new JcsCryptosuite(multikey);
const diProof = new DataIntegrityProof(cryptosuite);
// DIDUpdatePayload
const unsecuredDocument = {
  '@context' : [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2'
  ],
  'issuer'            : 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65',
  'id'                : 'http://university.example/credentials/58473',
  'type'              : ['VerifiableCredential', 'ExampleAlumniCredential'],
  'validFrom'         : '2020-01-01T00:00:00Z',
  'credentialSubject' : {
    'id'       : 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    'alumniOf' : {
      'id'   : 'did:example:c276e12ec21ebfeb1f712ebc6f1',
      'name' : 'Example University'
    }
  },
};
// Options are the "proof section"
// Proof Options => all but proof value
const proofOptions = {
  type               : 'DataIntegrityProof',
  cryptosuite        : 'schnorr-secp256k1-jcs-2025',
  verificationMethod : 'did:btc1:k1q2ddta4gt5n7u6d3xwhdyua57t6awrk55ut82qvurfm0qnrxx5nw7vnsy65#initialKey',
  proofPurpose       : 'attestationMethod',
  domain             : '',
  challenge          : '',
} as ProofOptions;
const securedDocument = diProof.addProof(unsecuredDocument, proofOptions);
console.log('securedDocument', securedDocument);
const verifiedProof = diProof.verifyProof({
  documentBytes        : Buffer.from(JSON.stringify(securedDocument)),
  expectedProofPurpose : 'attestationMethod',
});
console.log('verifiedProof', verifiedProof);
