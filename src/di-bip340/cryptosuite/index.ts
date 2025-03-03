import { sha256 } from '@noble/hashes/sha256';
import { LogLevel, LogMethod, SimpleLogger } from '@sphereon/ssi-types';
import * as jcs from '@web5/crypto';
import { createHash } from 'crypto';
import { base58btc } from 'multiformats/bases/base58';
import rdfc from 'rdf-canonize';
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
import { HashBytes, ProofBytes } from '../../types/shared.js';
import { CryptosuiteError } from '../../utils/error.js';
import { Multikey } from '../multikey/index.js';
import { ICryptosuite } from './interface.js';

// const logger = new SimpleLogger({
//   namespace       : 'Cryptosuite',
//   defaultLogLevel : LogLevel.INFO,
//   methods         : [LogMethod.CONSOLE],
// });

// const roomyInfo = (message: any)  => console.info(message);
/**
 * TODO: Test RDFC and figure out what the contexts should be
 * Implements sections
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#schnorr-secp256k1-rdfc-2025 | 3.2 schnorr-secp256k1-rdfc-2025}
 * and {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#schnorr-secp256k1-jcs-2025 | 3.3 schnorr-secp256k1-jcs-2025}
 * of {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1 | Data Integrity Schnorr secp256k1 Cryptosuite v0.1}
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
      ? await rdfc.canonize([object], { algorithm })
      : jcs.canonicalize(object);
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
    const hashBytes = this.generateHash({ canonicalConfig, canonicalDocument });

    // Serialize the proof
    const proofBytes = this.proofSerialization({ hashBytes, options });

    // Encode the proof bytes to base
    proof.proofValue = base58btc.encode(proofBytes);
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
    const proofBytes = base58btc.decode(secure.proof.proofValue);

    // Transform the newly insecured document to canonical form
    const canonicalDocument = await this.transformDocument({ document: insecure, options });

    // Canonicalize the proof options to create a proof configuration
    const canonicalConfig = await this.proofConfiguration({ options });

    // Generate a hash of the canonical insecured document and the canonical proof configuration`
    const hashBytes = this.generateHash({ canonicalConfig, canonicalDocument });

    // Verify the hashed data against the proof bytes
    const verified = this.proofVerification({ hashBytes, proofBytes, options });

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
    // Convert the canonical proof config to buffer
    const configBuffer = Buffer.from(canonicalConfig, 'utf-8');
    // roomyInfo('\n configBuffer \n' + configBuffer);
    // Convert the canonical document to buffer
    const documentBuffer = Buffer.from(canonicalDocument, 'utf-8');
    // roomyInfo('\n documentBuffer \n' + documentBuffer);
    // Concatenate the buffers and hash the result
    const bytesToHash = Buffer.concat([configBuffer, documentBuffer]);
    // roomyInfo('\n bytesToHash \n' + bytesToHash);
    const hash1 = createHash('sha256').update(bytesToHash).digest('hex');
    // roomyInfo('\n hash1 \n' + hash1);
    const hash2 = sha256(bytesToHash);
    // roomyInfo('\n hash2 \n' + hash2);
    // Return the hash as a hex string
    return hash2;
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
  public proofSerialization({ hashBytes, options }: SerializeParams): ProofBytes {
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
    // Return the signed hashBytes
    return this.multikey.sign(hashBytes);
  }

  /** @see ICryptosuite.proofVerification */
  public proofVerification({ hashBytes, proofBytes, options }: VerificationParams): boolean {
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
    // Return the verified hashData and proofBytes
    return this.multikey.verify(hashBytes, proofBytes);
  }

}