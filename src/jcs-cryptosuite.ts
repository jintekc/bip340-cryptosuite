import { sha256 } from '@noble/hashes/sha256';
import * as jcs from '@web5/crypto';
import { base58btc } from 'multiformats/bases/base58';
import { CryptoSuite } from './cryptosuite.js';
import { Btc1KeyManagerError } from './error.js';
import Multikey from './multikey.js';
import { IDataIntegrityProof, ProofDocument, ProofOptions, SignatureBytes, VerifiedProof } from './types.js';

/**
 * Implements section
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#schnorr-secp256k1-jcs-2025 | 3.3 schnorr-secp256k1-jcs-2025}
 * of the {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1 | Data Integrity Schnorr secp256k1 Cryptosuite} spec
 *
 * @export
 * @class JcsCryptosuite
 * @type {JcsCryptosuite}
 */

export default class JcsCryptosuite implements CryptoSuite {
  type = 'DataIntegrityProof';
  cryptosuite = 'schnorr-secp256k1-jcs-2025';
  multikey: Multikey;

  constructor(multikey: Multikey) {
    this.multikey = multikey;
  }


  createProof(unsecuredDocument: ProofDocument, proofOptions: ProofOptions): IDataIntegrityProof {
    const proof = proofOptions as IDataIntegrityProof;
    const context = unsecuredDocument['@context'];
    if (context) {
      proof['@context'] = context;
    }
    const transformedData = this.transformDocument(unsecuredDocument, proofOptions);
    const proofConfig = this.proofConfiguration(proof);
    const hashData = this.generateHash(proofConfig, transformedData);
    const proofBytes = this.proofSerialization(hashData, proofOptions);
    proof.proofValue = base58btc.encode(proofBytes);
    return proof as IDataIntegrityProof;
  }

  verifyProof(securedDocument: IDataIntegrityProof): VerifiedProof {
    const transformedData = this.transformDocument(securedDocument, securedDocument.proof);
    const proofConfig = this.proofConfiguration(securedDocument.proof);
    const proofBytes = base58btc.decode(securedDocument.proof.proofValue);
    const hashData = this.generateHash(proofConfig, transformedData);
    const verified = this.proofVerification(hashData, proofBytes, securedDocument.proof);
    const verifiedDocument = verified ? securedDocument : undefined;
    return { verified, verifiedDocument };
  }

  transformDocument(unsecuredDocument: ProofDocument, options: ProofOptions): string {
    if (options.type !== this.type || options.cryptosuite !== this.cryptosuite) {
      throw new Error('PROOF VERIFICATION ERROR');
    }
    return jcs.canonicalize(unsecuredDocument);
  }

  generateHash(canonicalProofConfig: string, canonicalDocument: string): string {
    const bytesToHash = Buffer.concat([Buffer.from(canonicalProofConfig), Buffer.from(canonicalDocument)]);
    return Buffer.from(sha256(bytesToHash)).toString('hex');
  }

  proofConfiguration(options: ProofOptions): string {
    const proofConfig = options;
    if (proofConfig.type !== this.type || proofConfig.cryptosuite !== this.cryptosuite) {
      throw new Error('PROOF_GENERATION_ERROR');
    }
    return jcs.canonicalize(proofConfig);
  }

  proofSerialization(hashData: string, options: ProofOptions): SignatureBytes {
    const vm = options.verificationMethod;
    if (vm !== this.multikey.fullId()) {
      throw new Btc1KeyManagerError(`Multikey ${this.multikey.fullId()} does not match verificationMethod ${vm}`, 'JcsCryptoSuiteError');
    }
    return this.multikey.sign(hashData);
  }

  proofVerification(hashData: string, proofBytes: Uint8Array, options: ProofOptions): boolean {
    const proofVm = options['verificationMethod'];
    if (proofVm !== this.multikey.fullId()) {
      throw new Btc1KeyManagerError('Multikey does not match expected verificationMethod: ' + proofVm);
    }
    return this.multikey.verify(hashData, proofBytes);
  }
}