import Multikey from './multikey.js';
import { IDataIntegrityProof, ProofDocument, ProofOptions, SignatureBytes, VerifiedProof } from './types.js';

export interface CryptoSuite {
  type: string; // 'IDataIntegrityProof'
  cryptosuite: string; // 'schnorr-secp256k1-jcs-2025' | 'schnorr-secp256k1-rdfc-2025';
  multikey: Multikey;
  createProof(unsecuredDocument: ProofDocument, proofOptions: ProofOptions): IDataIntegrityProof;
  verifyProof(securedDocument: ProofDocument): VerifiedProof;
  transformDocument(unsecuredDocument: ProofDocument, options: ProofOptions): string;
  generateHash(canonicalProofConfig: string, canonicalDocument: string): string;
  proofConfiguration(options: ProofOptions): string;
  proofSerialization(hashData: string, options: ProofOptions): SignatureBytes;
  proofVerification(hashData: string, proofBytes: Uint8Array, options: ProofOptions): boolean;
}

/*export class CryptoSuite implements ICryptoSuite {
  cryptosuite: SchnorrSecp256k1Jcs2025 | SchnorrSecp256k1Rdfc2025;
  constructor(options: CryptosuiteOptions) {
    this.cryptosuite = options.cryptosuite === 'schnorr-secp256k1-jcs-2025'
      ? new SchnorrSecp256k1Jcs2025(new Multikey(options.multikey))
      : new SchnorrSecp256k1Rdfc2025(new Multikey(options.multikey));
    this.createProof = this.cryptosuite.createProof;
    this.verifyProof = this.cryptosuite.verifyProof;
    return this;
  }
  transformDocument(unsecuredDocument: ProofDocument, options: ProofOptions): string {}
  generateHash(canonicalProofConfig: string, canonicalDocument: string): string {}
  proofConfiguration(options: ProofOptions): string {}
  proofSerialization(hashData: string, options: ProofOptions): SignatureBytes {}
  proofVerification(hashData: string, proofBytes: Uint8Array, options: ProofOptions): boolean {}
  createProof(unsecuredDocument: ProofDocument, proofOptions: ProofOptions): IDataIntegrityProof {}
  verifyProof(securedDocument: ProofDocument): VerifiedProof {}
}*/