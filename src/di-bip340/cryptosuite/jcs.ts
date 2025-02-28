import { sha256 } from '@noble/hashes/sha256';
import * as jcs from '@web5/crypto';
import { base58btc } from 'multiformats/bases/base58';
import {
  GenerateHashParams,
  InsecureDocumentParams,
  ProofOptionsParam,
  SerializeParams,
  TransformParams,
  VerificationParams
} from '../../types/cryptosuite.js';
import {
  CanonicalizedProofConfig,
  DataIntegrityProofType,
  Proof,
  SecureDocument,
  VerificationResult
} from '../../types/di-proof.js';
import { HashHex, SignatureBytes } from '../../types/shared.js';
import { Bip340CryptosuiteError } from '../../utils/error.js';
import { Bip340Multikey } from '../multikey/multikey.js';
import { ICryptosuite } from './interface.js';

/**
 * Implements section
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#schnorr-secp256k1-jcs-2025 | 3.3 bip-340-jcs-2025}
 * of the {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1 | Data Integrity BIP-340 Cryptosuite} spec
 * @export
 * @class Bip340CryptosuiteJcs
 * @type {Bip340CryptosuiteJcs}
 */
export class Bip340CryptosuiteJcs implements ICryptosuite {
  /** @type {DataIntegrityProofType} The type of proof produced by the Cryptosuite */
  public type: DataIntegrityProofType = 'DataIntegrityProof';

  /** @type {string} The name of the cryptosuite */
  public cryptosuite: string = 'bip340-jcs-2025';

  /** @type {Bip340Multikey} The multikey used to sign and verify proofs */
  public multikey: Bip340Multikey;

  /**
   * Creates an instance of Bip340CryptosuiteJcs.
   * @constructor
   * @param {Bip340Multikey} multikey The parameters to create the multikey
   */
  constructor(multikey: Bip340Multikey) {
    this.multikey = multikey;
  }

  /** @see ICryptosuite.createProof */
  public createProof({ document, options }: InsecureDocumentParams): Proof {
    // Make a copy of the options as a Proof
    const proof = options as Proof;
    // Get the context from the document
    const context = document['@context'];
    // If a context exists, add it to the proof
    if (context) proof['@context'] = context;
    // Transform the document into a canonical form
    const canonicalDocument = this.transformDocument({ document, options });
    // Create a canonical form of the proof configuration
    const canonicalProofConfig = this.proofConfiguration({ options: proof });
    // Generate a hash of the canonical proof configuration and canonical document
    const hashData = this.generateHash({ canonicalProofConfig, canonicalDocument });
    // Serialize the proof
    const proofBytes = this.proofSerialization({ hashData, options });
    // Encode the proof bytes to base
    proof.proofValue = base58btc.encode(proofBytes);
    // Return the proof
    return { ...proof, type: this.type, };
  }

  /** @see ICryptosuite.verifyProof */
  public verifyProof(secure: SecureDocument): VerificationResult {
    // Get the proof from the secure document as a Proof to act as the options
    const options = secure.proof as Proof;
    // Make a copy of the options as a Proof
    const proof = secure.proof as Proof;
    // Transform the secure document into a canonical form
    const canonicalDocument = this.transformDocument({ document: secure, options: proof });
    // Create a canonical form of the proof configuration
    const canonicalProofConfig = this.proofConfiguration({ options });
    // Decode the proof value from base
    const proofBytes = base58btc.decode(options.proofValue);
    // Generate a hash of the canonical proof configuration and canonical document
    const hashData = this.generateHash({ canonicalProofConfig, canonicalDocument });
    // Verify the proof
    const verified = this.proofVerification({ hashData, proofBytes, options });
    // Return the verification result
    const verifiedDocument = verified ? secure : undefined;
    // Return the verification result
    return { verified, verifiedDocument };
  }

  /** @see ICryptosuite.transformDocument */
  public transformDocument({ document, options }: TransformParams): string {
    // Error type for the transformDocument method
    const ERROR_TYPE = 'PROOF_TRANSFORMATION_ERROR';
    // Get the type from the options
    const { type } = options;
    // If the type does not match the cryptosuite type, throw an error
    if (type !== this.type) {
      throw new Bip340CryptosuiteError(`Options type ${type} !== cryptosuite type ${this.type}`, ERROR_TYPE);
    }
    // Get the cryptosuite from the options
    const { cryptosuite } = options;
    // If the cryptosuite does not match the cryptosuite name, throw an error
    if (cryptosuite !== this.cryptosuite) {
      throw new Bip340CryptosuiteError('Proof options cryptosuite name does not match cryptosuite name', ERROR_TYPE);
    }
    // Return the JCS canonicalized document
    return jcs.canonicalize(document);
  }

  /** @see ICryptosuite.generateHash */
  public generateHash({ canonicalProofConfig, canonicalDocument }: GenerateHashParams): HashHex {
    // Convert the canonical proof config to buffer
    const configBuffer = Buffer.from(canonicalProofConfig);
    // Convert the canonical document to buffer
    const documentBuffer = Buffer.from(canonicalDocument);
    // Concatenate the buffers and hash the result
    const bytesToHash = Buffer.concat([configBuffer, documentBuffer]);
    // Return the hash as a hex string
    return Buffer.from(sha256(bytesToHash)).toString('hex');
  }

  /** @see ICryptosuite.proofConfiguration */
  public proofConfiguration({ options }: ProofOptionsParam): CanonicalizedProofConfig {
    // Error type for the proofConfiguration method
    const ERROR_TYPE = 'PROOF_CONFIGURATION_ERROR';
    // Get the type from the options
    const { type } = options;
    // If the type does not match the cryptosuite type, throw
    if (type !== this.type) {
      throw new Bip340CryptosuiteError(`Options type ${type} !== ${this.type}`, ERROR_TYPE);
    }
    // Get the cryptosuite from the
    const { cryptosuite } = options;
    // If the cryptosuite does not match the cryptosuite name, throw
    if (cryptosuite !== this.cryptosuite) {
      throw new Bip340CryptosuiteError(`Options cryptosuite ${cryptosuite} !== ${this.cryptosuite}`, ERROR_TYPE);
    }
    // Return the JCS canonicalized proof configuration
    return jcs.canonicalize(options);
  }

  /** @see ICryptosuite.proofSerialization */
  public proofSerialization({ hashData, options }: SerializeParams): SignatureBytes {
    // Error type for the proofSerialization method
    const ERROR_TYPE = 'PROOF_SERIALIZATION_ERROR';
    // Get the verification method from the options
    const vm = options.verificationMethod;
    // Get the multikey fullId
    const fullId = this.multikey.fullId();
    // If the verification method does not match the multikey fullId, throw an error
    if (vm !== fullId) {
      throw new Bip340CryptosuiteError(`Multikey fullId ${fullId} !== options verificationMethod ${vm}`, ERROR_TYPE);
    }
    // Return the signed hashData
    return this.multikey.sign(hashData);
  }

  /** @see ICryptosuite.proofVerification */
  public proofVerification({ hashData, proofBytes, options }: VerificationParams): boolean {
    // Error type for the proofVerification method
    const ERROR_TYPE = 'PROOF_VERIFICATION_ERROR';
    // Get the verification method from the options
    const vm = options.verificationMethod;
    // Get the multikey fullId
    const fullId = this.multikey.fullId();
    // If the verification method does not match the multikey fullId, throw an error
    if (vm !== fullId) {
      throw new Bip340CryptosuiteError(`Multikey fullId ${fullId} !== verificationMethod ${vm}`, ERROR_TYPE);
    }
    // Return the verified hashData and proofBytes
    return this.multikey.verify(hashData, proofBytes);
  }
}