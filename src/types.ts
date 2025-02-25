import { DidVerificationMethod } from '@web5/dids';
import Multikey from './multikey.js';
import SchnorrSecp256k1Rdfc2025 from './rdfc-cryptosuite.js';

/** Types */
export type Bytes = Uint8Array;
export type Hex = Bytes | string;
export type PrivateKey = Hex;
export type PublicKey = Hex;
export type PrivateKeyBytes = Bytes;
export type PublicKeyBytes = Bytes;
export type MultikeyPrefix = Bytes;
export type SignatureBytes = Bytes;
export type SignatureHex = string;
export type Signature = Hex;
export type Base58BtcPrefix = 'z';
export type PublicKeyMultibase = `${Base58BtcPrefix}66P${string}`;
export type SchnorrKeyPair = {
  privateKey: PrivateKeyBytes;
  publicKey: PublicKeyBytes;
};
export type DID = 'did';
export type MethodName = string;
export type MethodSpecificId = string;
export type DecentralizedIdentifier = `${DID}:${MethodName}:${MethodSpecificId}`;
export type Btc1MethodName = 'btc1';
export type Btc1DeterministicPrefix = 'k';
export type Btc1ExternalPrefix = 'x';
export type Btc1Prefix = `${Btc1DeterministicPrefix | Btc1ExternalPrefix}1`;
export type Bech32Id = string;
export type Btc1Id = `${Btc1Prefix}${Bech32Id}`
export type Btc1Identifier = `${DID}:${Btc1MethodName}:${Btc1Id}`;
export type Controller = Btc1Identifier;
export type Id = 'initialKey';
export type FullId = `${Controller}#${Id}`;
export type TwoDigits = `${number}${number}`;
export type ThreeDigits = `${number}${number}${number}`;
export type Year = `${1 | 2}${ThreeDigits}`;
export type Month = TwoDigits;
export type Day = TwoDigits;
export type Hours = TwoDigits;
export type Minutes = TwoDigits;
export type Seconds = TwoDigits;
export type UtcTimestamp = `${Year}-${Month}-${Day}T${Hours}:${Minutes}:${Seconds}`;
export type TzOffset = `${Hours}:${Minutes}`;
export type DateTimestamp = `${UtcTimestamp}Z` | `${UtcTimestamp}-${TzOffset}`;
export type SchnorrSecp256k1Cryptosuite = 'schnorr-secp256k1-jcs-2025' | 'schnorr-secp256k1-rdfc-2025';
export type VerifiedProof = {
  verified: boolean;
  verifiedDocument?: IDataIntegrityProof;
}
export type ContextObject = Record<string | number | symbol, any>;
/** Interfaces */
export type MultikeyParams  = {
  id: string;
  controller: string;
} & (
  | {
      privateKey: PrivateKeyBytes;
      publicKey?: never;
    }
  | {
      privateKey?: never;
      publicKey: PublicKeyBytes;
    }
  | {
      privateKey: PrivateKeyBytes;
      publicKey: PublicKeyBytes;
    }
    | {
      privateKey?: never;
      publicKey?: never;
    }
);
export interface SchnorrSecp256k1Multikey {
  id: string;
  controller: string;
  privateKey?: PrivateKeyBytes;
  publicKey?: PublicKeyBytes;
  sign(data: string): Signature;
  verify(data: string, signature: Bytes): boolean;
  toVerificationMethod(): DidVerificationMethod;
  fromVerificationMethod(verificationMethod: DidVerificationMethod): Multikey;
}
export interface ProofOptions {
  type: 'DataIntegrityProof';
  cryptosuite: SchnorrSecp256k1Cryptosuite | SchnorrSecp256k1Rdfc2025;
  verificationMethod: `${Btc1Identifier}#initialKey`;
  proofPurpose: string;
  domain: string | string[];
  challenge: string;
}
export interface CryptosuiteOptions {
  type: 'DataIntegrityProof';
  cryptosuite: SchnorrSecp256k1Cryptosuite;
  multikey: MultikeyParams;
}
export type Proof = ProofOptions & {
  '@context'?: Array<string | ContextObject>;
  type: 'DataIntegrityProof';
  cryptosuite: SchnorrSecp256k1Cryptosuite | SchnorrSecp256k1Rdfc2025;
  verificationMethod: `${Btc1Identifier}#initialKey`;
  proofPurpose: string;
  proofValue: string;
}
export type IDataIntegrityProof = Proof & {
  '@context': Array<string | ContextObject>;
  id: string;
  created?: DateTimestamp;
  expires: DateTimestamp;
  previousProof?: string;
  nonce?: string;
  proof: Proof;
}
export type ProofDocument = {
  '@context': Array<string | ContextObject>;
  [key: string]: any;
};