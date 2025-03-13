import { Multikey } from '../di-bip340/multikey/index.js';
import { DataIntegrityProofType, InsecureDocument, ProofOptions, SecureDocument } from './di-proof.js';
import { HashBytes, SignatureBytes } from './shared.js';

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
  hash: HashBytes;
  options: ProofOptions;
};
export type VerificationParams = {
  hash: HashBytes;
  signature: SignatureBytes;
  options: ProofOptions;
}
export type GenerateHashParams = {
  canonicalConfig: string;
  canonicalDocument: string
}
export type CryptosuiteType = 'bip340-jcs-2025' | 'bip340-rdfc-2025';

/** Interfaces */
export interface CryptosuiteParams {
  type?: DataIntegrityProofType;
  cryptosuite: CryptosuiteType;
  multikey: Multikey;
}