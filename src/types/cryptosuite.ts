import { Multikey } from '../di-bip340/multikey/index.js';
import { DataIntegrityProofType, InsecureDocument, ProofOptions, SecureDocument } from './di-proof.js';
import { HashBytes, ProofBytes } from './shared.js';

/** Types */
export type ProofOptionsParam = { options: ProofOptions }
export type InsecureDocumentParams = ProofOptionsParam & {
  document: InsecureDocument
}
export type SecureDocumentParams = ProofOptionsParam & {
  document: SecureDocument
};
export type DocumentParams = {
  document:
    | InsecureDocument
    | SecureDocument
}
export type CanonicalizableObject = Record<string, any>;
export type TransformParams = DocumentParams & ProofOptionsParam;
export type SerializeParams = {
  hashBytes: HashBytes;
  options: ProofOptions;
};
export type VerificationParams = {
  hashBytes: HashBytes;
  proofBytes: ProofBytes;
  options: ProofOptions;
}
export type GenerateHashParams = {
  canonicalConfig: string;
  canonicalDocument: string
}
export type CryptosuiteType = 'bip-340-jcs-2025' | 'bip-340-rdfc-2025';

/** Interfaces */
export interface CryptosuiteParams {
  type?: DataIntegrityProofType;
  cryptosuite: CryptosuiteType;
  multikey: Multikey;
}