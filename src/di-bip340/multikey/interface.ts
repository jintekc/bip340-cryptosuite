import { DidVerificationMethod } from '@web5/dids';
import { PublicKey } from '../../crypto/public-key.js';
import { HashBytes, PrivateKeyBytes, PublicKeyBytes, SignatureBytes } from '../../types/shared.js';
import { Multikey } from './index.js';
import { PrivateKey } from '../../crypto/private-key.js';
import { KeyPair } from '../../crypto/key-pair.js';
export interface DidParams {
  id: string;
  controller: string;
}

export interface FromPrivateKey extends DidParams {
  privateKey: PrivateKeyBytes;
}
export interface FromPublicKey extends DidParams {
  publicKey: PublicKeyBytes;
}
export interface MultikeyParams extends DidParams {
  keyPair?: KeyPair;
}

/**
 * Interface representing a BIP340 Multikey.
 * @interface IMultikey
 */
export interface IMultikey {
  /** @type {string} @readonly Get the Multikey id. */
  readonly id: string;

  /** @type {string} @readonly Get the Multikey controller. */
  readonly controller: string;

  /** @type {KeyPair} @readonly Get the Multikey KeyPair. */
  readonly keyPair: KeyPair;

  /** @type {PublicKey} @readonly Get the Multikey PublicKey. */
  readonly publicKey: PublicKey;

  /** @type {PrivateKey} @readonly Get the Multikey PrivateKey. */
  readonly privateKey?: PrivateKey;

  /** @type {boolean} @readonly Get signing ability of the Multikey (i.e. is there a valid privateKey). */
  readonly isSigner: boolean;

  /**
   * Produce signed data with a private key.
   * @param {string} data Data to be signed.
   * @returns {SignatureBytes} Signature byte array.
   * @throws {Btc1KeyManagerError} if no private key is provided.
   */
  sign(data: string): SignatureBytes;

  /**
   * Verify a signature.
   * @param {SignatureBytes} signature Signature for verification.
   * @param {string} message Data for verification.
   * @returns {boolean} If the signature is valid against the public key.
   */
  verify(signature: SignatureBytes, message: string): boolean;

  /**
   * Get the full id of the multikey
   * @returns {string} The full id of the multikey
   */
  fullId(): string

  /**
   * Convert the multikey to a verification method.
   * @returns {DidVerificationMethod} The verification method.
   */
  toVerificationMethod(): DidVerificationMethod;

  /**
   * Convert a verification method to a multikey.
   * @param {DidVerificationMethod} verificationMethod The verification method to convert.
   * @returns {Multikey} Multikey instance.
   * @throws {MultikeyError}
   * if the verification method is missing required fields.
   * if the verification method has an invalid type.
   * if the publicKeyMultibase has an invalid prefix.
   */
  fromVerificationMethod(verificationMethod: DidVerificationMethod): Multikey;
}