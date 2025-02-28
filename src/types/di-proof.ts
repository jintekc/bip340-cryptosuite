import { Bip340CryptosuiteType } from './cryptosuite.js';
import { Btc1Identifier, Bytes } from './shared.js';

/** Types */
export type DataIntegrityProofType = 'DataIntegrityProof';
export type InsecureDocument = Record<string | number | symbol, any>;
export type SecureDocument = InsecureDocument & { proof: Proof };
export type ContextObject = Record<string | number | symbol, any>;
export type Context = string | string[] | ContextObject | ContextObject[]
export type ProofOptions = Partial<Proof>;
export type AddProofParams = { document: InsecureDocument, options: ProofOptions };
export type CanonicalizedProofConfig = string;

/** Interfaces */
export interface Proof {
  '@context': Context;
  type: DataIntegrityProofType;
  cryptosuite: Bip340CryptosuiteType;
  verificationMethod: `${Btc1Identifier}#initialKey`;
  proofPurpose: string;
  proofValue: string;
  domain: string[];
  challenge: string;
}
export interface VerifyProofParams {
  mediaType?: string;
  document: Bytes;
  expectedPurpose: string;
  expectedDomain?: string[];
  expectedChallenge?: string;
};
export interface VerificationResult {
  verified: boolean;
  verifiedDocument?: SecureDocument;
}
