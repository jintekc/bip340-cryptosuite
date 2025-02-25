import SchnorrSecp256k1Jcs2025 from './jcs-cryptosuite.js';
import SchnorrSecp256k1Rdfc2025 from './rdfc-cryptosuite.js';
import { ProofDocument, ProofOptions } from './types.js';

type Cryptosuite = SchnorrSecp256k1Jcs2025 | SchnorrSecp256k1Rdfc2025;
type VerifyProof = {
  mediaType?: string;
  documentBytes: Uint8Array;
  expectedProofPurpose: string;
  domain?: string;
  challenge?: string;
};
export default class DataIntegrityProof {
  cryptosuite: Cryptosuite;

  constructor(cryptosuite: Cryptosuite) {
    this.cryptosuite = cryptosuite;
  }

  addProof(inputDocument: ProofDocument, options: ProofOptions): ProofDocument {
    const proof = this.cryptosuite.createProof(inputDocument, options);

    const { type, verificationMethod, proofPurpose } = proof;
    if (!type || !verificationMethod || !proofPurpose) {
      throw new Error('PROOF_GENERATION_ERROR');
    }

    const domain = options.domain;
    const proofDomain = proof.domain;

    if (domain && domain !== proofDomain) {
      throw new Error('PROOF_GENERATION_ERROR');
    }

    const challenge = options.challenge;
    if (challenge && challenge !== proof.challenge) {
      throw new Error('PROOF_GENERATION_ERROR');
    }

    inputDocument.proof = proof;
    return inputDocument;
  }

  verifyProof({
    mediaType,
    documentBytes,
    expectedProofPurpose,
    // domain,
    challenge
  }: VerifyProof) {
    const securedDocument = JSON.parse(new TextDecoder().decode(documentBytes));

    if (typeof securedDocument !== 'object' || typeof securedDocument.proof !== 'object') {
      throw new Error('PARSING_ERROR');
    }

    const proof = securedDocument.proof;
    const type = proof.type;
    const proofPurpose = proof.proofPurpose;
    const proofVm = proof.verificationMethod;
    const proofChallenge = proof.challenge;

    if (!type || !proofVm || !proofPurpose) {
      throw new Error('PROOF_VERIFICATION_ERROR');
    }

    if (expectedProofPurpose && expectedProofPurpose !== proofPurpose) {
      throw new Error('PROOF_VERIFICATION_ERROR');
    }

    if (challenge && challenge !== proofChallenge) {
      throw new Error('INVALID_CHALLENGE_ERROR');
    }

    const cryptosuiteVerificationResult = this.cryptosuite.verifyProof(securedDocument);

    const verificationResult = {
      verified         : cryptosuiteVerificationResult.verified,
      verifiedDocument : cryptosuiteVerificationResult.verifiedDocument,
      mediaType        : mediaType
    };

    return verificationResult;
  }
}


