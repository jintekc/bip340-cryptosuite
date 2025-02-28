import { Bip340CryptosuiteJcs } from '../di-bip340/cryptosuite/jcs.js';
import { Bip340CryptosuiteRdfc } from '../di-bip340/cryptosuite/rdfc.js';
import { InsecureDocument, ProofOptions, SecureDocument } from './di-proof.js';
import { Bip340MultikeyParams } from './multikey.js';

/** Types */
export type ProofOptionsParam = { options: ProofOptions }
export type InsecureDocumentParams = { document: InsecureDocument } & ProofOptionsParam;
export type SecureDocumentParams = { document: SecureDocument } & ProofOptionsParam;
export type DocumentParams = { document: InsecureDocument | SecureDocument }
export type TransformParams = DocumentParams & ProofOptionsParam;
export type SerializeParams = {
  hashData: string;
  options: ProofOptions;
};
export type VerificationParams = {
  hashData: string;
  proofBytes: Uint8Array;
  options: ProofOptions;
}
export type GenerateHashParams = {
  canonicalProofConfig: string;
  canonicalDocument: string
}
export type Bip340CryptosuiteType = 'bip-340-jcs-2025' | 'bip-340-rdfc-2025';
export type Bip340Cryptosuite = Bip340CryptosuiteJcs | Bip340CryptosuiteRdfc;

/** Interfaces */
export interface CryptosuiteOptions {
  type: 'DataIntegrityProof';
  multikey: Bip340MultikeyParams;
  cryptosuite: Bip340CryptosuiteType;
}
