import { AddProofParams, Proof, SecureDocument, VerificationResult, VerifyProofParams } from '../../types/di-proof.js';
import { ProofError } from '../../utils/error.js';
import ObjectUtils from '../../utils/object-utils.js';
import { Cryptosuite } from '../cryptosuite/index.js';
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
  /** @type {Cryptosuite} The cryptosuite to use for proof generation and verification. */
  public cryptosuite: Cryptosuite;

  /**
   * Creates an instance of DataIntegrityProof.
   * @constructor
   * @param {Cryptosuite} cryptosuite The cryptosuite to use for proof generation and verification.
   */
  constructor(cryptosuite: Cryptosuite) {
    this.cryptosuite = cryptosuite;
  }

  /** @see IDataIntegrityProof.addProof */
  public async addProof({ document, options }: AddProofParams): Promise<SecureDocument> {
    // Generate the proof
    const proof = await this.cryptosuite.createProof({ document, options });

    // Deconstruct the proof object
    const { type, verificationMethod, proofPurpose } = proof;

    // Check if the type, verificationMethod, and proofPurpose are defined
    if (!type || !verificationMethod || !proofPurpose) {
      throw new ProofError('Missing properties: type, verificationMethod or proofPurpose', 'PROOF_GENERATION_ERROR');
    }

    // Deconstruct the domain from the proof object and check:
    // if the options domain is defined, ensure it matches the proof domain
    // TODO: Adjust the domain check to match the spec (domain as a list of urls)
    const { domain } = proof;
    if (options.domain && options.domain !== domain) {
      throw new ProofError('Domain mismatch between options and domain passed', 'PROOF_GENERATION_ERROR');
    }

    // Deconstruct the challenge from the proof object and check:
    // if options challenge is defined, ensure it matches the proof challenge
    const { challenge } = proof;
    if (options.challenge && options.challenge !== challenge) {
      throw new ProofError('Challenge mismatch options and challenge passed', 'PROOF_GENERATION_ERROR');
    }

    // Set the proof in the document and return as a SecureDocument
    return { ...document, proof } as SecureDocument;
  }

  /** @see IDataIntegrityProof.verifyProof */
  public async verifyProof({
    mediaType,
    document,
    expectedPurpose,
    expectedDomain,
    expectedChallenge
  }: VerifyProofParams): Promise<VerificationResult> {
    // Parse the document
    const secure = JSON.parse(document) as SecureDocument;

    // Deconstruct the secure object to get the proof
    const { proof }: { proof: Proof } = secure;

    // Check if the proof object is an object
    if (typeof secure !== 'object' || typeof proof !== 'object') {
      throw new Error('PARSING_ERROR');
    }

    // Deconstruct the proof object
    const { type, proofPurpose, verificationMethod, challenge, domain } = proof;
    // Check if the type, proofPurpose, and verificationMethod are defined
    if (!type || !verificationMethod || !proofPurpose) {
      throw new Error('PROOF_VERIFICATION_ERROR');
    }

    // Check if the expectedPurpose is defined and if it matches the proofPurpose
    if (expectedPurpose && expectedPurpose !== proofPurpose) {
      throw new Error('PROOF_VERIFICATION_ERROR');
    }

    // Check if the expectedChallenge is defined and if it matches the challenge
    if (expectedChallenge && expectedChallenge !== challenge) {
      throw new Error('INVALID_CHALLENGE_ERROR');
    }

    // Check if the expectedDomain length matches the proof.domain length
    if(expectedDomain && expectedDomain?.length !== domain?.length) {
      throw new Error('INVALID_DOMAIN_ERROR');
    }

    // If defined, check that each entry in expectedDomain can be found in proof.domain
    if(expectedDomain && !expectedDomain?.every(url => domain?.includes(url))) {
      throw new Error('INVALID_DOMAIN_ERROR');
    }

    // Verify the proof
    const { verified, verifiedDocument, mediaType: mt } = await this.cryptosuite.verifyProof(secure);

    // Add the mediaType to the verification result
    mediaType ??= mt;

    const sansProof = ObjectUtils.delete({
      obj : verifiedDocument as Record<string, any>,
      key : 'proof'
    }) as SecureDocument;

    // Return the verification result
    return {verified, verifiedDocument: verified ? sansProof : undefined, mediaType};
  }
}