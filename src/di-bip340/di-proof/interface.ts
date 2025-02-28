import { Bip340Cryptosuite } from '../../types/cryptosuite.js';
import {
  AddProofParams,
  SecureDocument,
  VerificationResult,
  VerifyProofParams
} from '../../types/di-proof.js';

/**
 * Interface representing a BIP-340 DataIntegrityProof.
 * @export
 * @interface IDataIntegrityProof
 * @type {IDataIntegrityProof}
 */
export interface IDataIntegrityProof {
  /** @type {Bip340Cryptosuite} Bip340CryptosuiteJcs or Bip340CryptosuiteRdfc class object  */
  cryptosuite: Bip340Cryptosuite;

  /**
   * Add a proof to a document.
   * @param {AddProofParams} params Parameters for adding a proof to a document.
   * @param {InsecureDocument} params.document The document to add a proof to.
   * @param {ProofOptions} params.options Options for adding a proof to a document.
   * @returns {SecureDocument} A document with a proof added.
   */
  addProof({ document, options }: AddProofParams): SecureDocument;

  /**
   * Verify a proof.
   * @param {VerifyProofParams} params Parameters for verifying a proof.
   * @param {VerifyProofParams} params.mediaType The media type of the document.
   * @param {VerifyProofParams} params.document The document to verify.
   * @param {VerifyProofParams} params.expectedPurpose The expected purpose of the proof.
   * @param {VerifyProofParams} params.expectedDomain The expected domain of the proof.
   * @param {VerifyProofParams} params.expectedChallenge The expected challenge of the proof.
   * @returns {VerificationResult} The result of verifying the proof.
   */
  verifyProof({ mediaType, document, expectedPurpose, expectedDomain, expectedChallenge }: VerifyProofParams): VerificationResult;
}