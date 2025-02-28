import { Bip340Cryptosuite } from '../../types/cryptosuite.js';
import { AddProofParams, SecureDocument, VerificationResult, VerifyProofParams } from '../../types/di-proof.js';
import { IDataIntegrityProof } from './interface.js';

/**
 * Implements section
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#dataintegrityproof | 2.2.1 DataIntegrityProof}
 * of the {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1 | Data Integrity BIP-340 Cryptosuite} spec
 * @export
 * @class DataIntegrityProof
 * @type {DataIntegrityProof}
 * @implements {IDataIntegrityProof}
 */
export class DataIntegrityProof implements IDataIntegrityProof {
  /** @type {Bip340Cryptosuite} The cryptosuite to use for proof generation and verification. */
  public cryptosuite: Bip340Cryptosuite;

  /**
   * Creates an instance of DataIntegrityProof.
   * @constructor
   * @param {Bip340Cryptosuite} cryptosuite The cryptosuite to use for proof generation and verification.
   */
  constructor(cryptosuite: Bip340Cryptosuite) {
    this.cryptosuite = cryptosuite;
  }

  /** @see IDataIntegrityProof.addProof */
  public addProof({ document, options }: AddProofParams): SecureDocument {
    // Generate the proof
    const proof = this.cryptosuite.createProof({ document, options });

    // Deconstruct the proof object
    const { type, verificationMethod, proofPurpose } = proof;
    // Check if the type, verificationMethod, and proofPurpose are defined
    if (!type || !verificationMethod || !proofPurpose) {
      throw new Error('PROOF_GENERATION_ERROR');
    }

    // Deconstruct the proof object
    const { domain } = proof;
    // Check if the domain is defined and if it matches the domain
    if (options.domain && options.domain !== domain) {
      throw new Error('PROOF_GENERATION_ERROR');
    }

    // Deconstruct the proof object
    const { challenge } = proof;
    // Check if the challenge is defined and if it matches the challenge
    if (options.challenge && options.challenge !== challenge) {
      throw new Error('PROOF_GENERATION_ERROR');
    }

    // Return the secure document
    return { ...document, proof } as SecureDocument;
  }

  /** @see IDataIntegrityProof.verifyProof */
  public verifyProof(params: VerifyProofParams): VerificationResult {
    // Deconstruct the params object
    const { mediaType, document, expectedPurpose, expectedDomain, expectedChallenge } = params;
    // Parse the document
    const diproof = JSON.parse(Buffer.from(document).toString());
    // Deconstruct the diproof object
    const { proof } = diproof;
    // Check if the proof object is an object
    if (typeof diproof !== 'object' || typeof proof !== 'object') {
      throw new Error('PARSING_ERROR');
    }
    // Deconstruct the proof object
    const { type, proofPurpose, verificationMethod } = proof;
    // Check if the type, proofPurpose, and verificationMethod are defined
    if (!type || !verificationMethod || !proofPurpose) {
      throw new Error('PROOF_VERIFICATION_ERROR');
    }
    // Check if the expectedPurpose is defined and if it matches the proofPurpose
    if (expectedPurpose && expectedPurpose !== proofPurpose) {
      throw new Error('PROOF_VERIFICATION_ERROR');
    }
    // Check if the expectedChallenge is defined and if it matches the challenge
    if (expectedChallenge && expectedChallenge !== proof.challenge) {
      throw new Error('INVALID_CHALLENGE_ERROR');
    }
    // Check if the expectedDomain is defined and if it matches the domain
    if(expectedDomain && expectedDomain !== proof.domain) {
      throw new Error('INVALID_DOMAIN_ERROR');
    }
    // Verify the proof
    const verificationResult = this.cryptosuite.verifyProof(diproof);
    // Return the verification result
    return { ...verificationResult, mediaType } as VerificationResult;
  }
}