import { sha256 } from '@noble/hashes/sha256';
import { base58btc } from 'multiformats/bases/base58';
import {
  CanonicalizableObject,
  CryptosuiteParams,
  CryptosuiteType,
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
import { HashBytes, SignatureBytes } from '../../types/shared.js';
import { CryptosuiteError } from '../../utils/error.js';
import { Multikey } from '../multikey/index.js';
import { ICryptosuite } from './interface.js';
import { Canonicalize } from './canonicalize.js';

/**
 * TODO: Test RDFC and figure out what the contexts should be
 * Implements
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#schnorr-secp256k1-rdfc-2025 | 3.2 schnorr-secp256k1-rdfc-2025}
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#schnorr-secp256k1-jcs-2025 | 3.3 schnorr-secp256k1-jcs-2025}
 *
 * @export
 * @class Cryptosuite
 * @type {Cryptosuite}
 */
export class Cryptosuite implements ICryptosuite {
  /** @type {DataIntegrityProofType} The type of proof produced by the Cryptosuite */
  public type: DataIntegrityProofType = 'DataIntegrityProof';

  /** @type {string} The name of the cryptosuite */
  public cryptosuite: CryptosuiteType;

  /** @type {Multikey} The multikey used to sign and verify proofs */
  public multikey: Multikey;

  /** @type {string} The algorithm used for canonicalization */
  public algorithm: string;

  /**
   * Creates an instance of Cryptosuite.
   * @constructor
   * @param {Multikey} multikey The parameters to create the multikey
   */
  constructor({ cryptosuite, multikey }: CryptosuiteParams) {
    this.cryptosuite = cryptosuite;
    this.multikey = multikey;
    this.algorithm = cryptosuite.includes('rdfc') ? 'RDFC-1.0' : 'JCS';
  }

  /** @see ICryptosuite.canonicalize */
  public async canonicalize(object: CanonicalizableObject): Promise<string> {
    const algorithm = this.algorithm;
    // If the cryptosuite includes 'rdfc', use RDFC canonicalization else use JCS
    return algorithm === 'RDFC-1.0'
      ? Canonicalize.rdfc(object, algorithm)
      : Canonicalize.jcs(object);
  }

  /** @see ICryptosuite.createProof */
  public async createProof({ document, options }: InsecureDocumentParams): Promise<Proof> {
    // Get the context from the document
    const context = document['@context'];

    // If a context exists, add it to the proof
    const proof = (
      context
        ? { ...options, '@context': context }
        : options
    ) as Proof;

    // Create a canonical form of the proof configuration
    const canonicalConfig = await this.proofConfiguration({ options: proof });

    // Transform the document into a canonical form
    const canonicalDocument = await this.transformDocument({ document, options });

    // Generate a hash of the canonical proof configuration and canonical document
    const hash = this.generateHash({ canonicalConfig, canonicalDocument });

    // Serialize the proof
    const serialized = this.proofSerialization({ hash, options });

    // Encode the proof bytes to base
    proof.proofValue = base58btc.encode(serialized);
    if(this.cryptosuite.includes('rdfc'))
      proof['@type'] = this.type;
    else
      proof.type = this.type;

    // Return the proof
    return proof;
  }

  /** @see ICryptosuite.verifyProof */
  public async verifyProof(secure: SecureDocument): Promise<VerificationResult> {
    // Create an insecure document from the secure document by removing the proof
    const insecure = { ...secure, proof: undefined };

    // Create a copy of the proof options removing the proof value
    const options = { ...secure.proof, proofValue: undefined };

    // Decode the secure document proof value from base58btc to bytes
    const proof = base58btc.decode(secure.proof.proofValue);

    // Transform the newly insecured document to canonical form
    const canonicalDocument = await this.transformDocument({ document: insecure, options });

    // Canonicalize the proof options to create a proof configuration
    const canonicalConfig = await this.proofConfiguration({ options });

    // Generate a hash of the canonical insecured document and the canonical proof configuration`
    const hash = this.generateHash({ canonicalConfig, canonicalDocument });

    // Verify the hashed data against the proof bytes
    const verified = this.proofVerification({ hash, signature: proof, options });

    // Return the verification result
    return { verified, verifiedDocument: verified ? secure : undefined };
  }

  /** @see ICryptosuite.transformDocument */
  public async transformDocument({ document, options }: TransformParams): Promise<string> {
    // Error type for the transformDocument method
    const ERROR_TYPE = 'PROOF_VERIFICATION_ERROR';

    // Get the type from the options and check:
    // If the options type does not match this type, throw error
    const type = options.type ?? options['@type'];
    if (type !== this.type) {
      throw new CryptosuiteError(`Type mismatch between config and this: ${type} !== ${this.type}`, ERROR_TYPE);
    }

    // Get the cryptosuite from the options and check:
    // If the options cryptosuite does not match this cryptosuite, throw error
    const { cryptosuite } = options;
    if (cryptosuite !== this.cryptosuite) {
      const message = `Cryptosuite mismatch between config and this: ${cryptosuite} !== ${this.cryptosuite}`;
      throw new CryptosuiteError(message, ERROR_TYPE);
    }

    // Return the canonicalized document
    return await this.canonicalize(document);
  }

  /** @see ICryptosuite.generateHash */
  public generateHash({ canonicalConfig, canonicalDocument }: GenerateHashParams): HashBytes {
    // Convert the canonical proof config to buffer and sha256 hash it
    const configHash = sha256(Buffer.from(canonicalConfig, 'utf-8'));

    // Convert the canonical document to buffer and sha256 hash it
    const documentHash = sha256(Buffer.from(canonicalDocument, 'utf-8'));

    // Concatenate the hashes
    const combinedHash = Buffer.concat([configHash, documentHash]);

    // sha256 hash the combined hashes and return
    return sha256(combinedHash);
  }

  /** @see ICryptosuite.proofConfiguration */
  public async proofConfiguration({ options }: ProofOptionsParam): Promise<CanonicalizedProofConfig> {
    // Error type for the proofConfiguration method
    const ERROR_TYPE = 'PROOF_GENERATION_ERROR';

    // Get the type from the options
    const type = options.type ?? options['@type'];

    // If the type does not match the cryptosuite type, throw
    if (type !== this.type) {
      throw new CryptosuiteError(`Mismatch "type" between config and this: ${type} !== ${this.type}`, ERROR_TYPE);
    }

    // If the cryptosuite does not match the cryptosuite name, throw
    if (options.cryptosuite !== this.cryptosuite) {
      const message = `Mismatch on "cryptosuite" in config and this: ${options.cryptosuite} !== ${this.cryptosuite}`;
      throw new CryptosuiteError(message, ERROR_TYPE);
    }

    // TODO: check valid XMLSchema DateTime
    if(options.created) {
      console.log('TODO: check valid XMLSchema DateTime');
    }

    // Return the RDFC canonicalized proof configuration
    return await this.canonicalize(options);
  }

  /** @see ICryptosuite.proofSerialization */
  public proofSerialization({ hash, options }: SerializeParams): SignatureBytes {
    // Error type for the proofSerialization method
    const ERROR_TYPE = 'PROOF_SERIALIZATION_ERROR';
    // Get the verification method from the options
    const vm = options.verificationMethod;
    // Get the multikey fullId
    const fullId = this.multikey.fullId();
    // If the verification method does not match the multikey fullId, throw an error
    if (vm !== fullId) {
      throw new CryptosuiteError(`Mismatch on "fullId" in options and multikey: ${fullId} !== ${vm}`, ERROR_TYPE);
    }
    // Return the signed hash
    return this.multikey.sign(hash);
  }

  /** @see ICryptosuite.proofVerification */
  public proofVerification({ hash, signature, options }: VerificationParams): boolean {
    // Error type for the proofVerification method
    const ERROR_TYPE = 'PROOF_VERIFICATION_ERROR';
    // Get the verification method from the options
    const vm = options.verificationMethod;
    // Get the multikey fullId
    const fullId = this.multikey.fullId();
    // If the verification method does not match the multikey fullId, throw an error
    if (vm !== fullId) {
      throw new CryptosuiteError(`Mismatch on "fullId" in options and multikey: ${fullId} !== ${vm}`, ERROR_TYPE);
    }
    // Return the verified hashData and signedProof
    return this.multikey.verify(signature, hash);
  }
}