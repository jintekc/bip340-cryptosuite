import { DidVerificationMethod } from '@web5/dids';
import { PublicKey } from '../../crypto/public-key.js';
import { HashBytes, PrivateKeyBytes, SignatureBytes } from '../../types/shared.js';
import { Multikey } from './index.js';
import { PrivateKey } from '../../crypto/private-key.js';

/**
 * Interface representing a BIP-340 Multikey.
 * @interface IMultikey
 */
export interface IMultikey {
  /**
   * @readonly
   * @type {string} The unique identifier of the multikey
   */
  readonly id: string;

  /**
   * @readonly
   * @type {string} The controller of the multikey
   */
  readonly controller: string;

  /**
   * @readonly
   * @type {PublicKey} Lazily computes the public key bytes and returns a {@link PublicKey} instance
   */
  readonly publicKey?: PublicKey;

  /**
   * @readonly
   * @type {PrivateKey} Getter returns a copy of the private key, ensuring immutability
   */
  readonly privateKey?: PrivateKey;

  /**
   * Produce signed data with a private key
   * @param {HashBytes} data Data to be signed
   * @returns {SignatureBytes} Signature byte array
   * @throws {Btc1KeyManagerError} if no private key is provided
   */
  sign(data: HashBytes): SignatureBytes;

  /**
   * Verify a signature
   * @param {HashBytes} data Data for verification
   * @param {SignatureBytes} signature Signature for verification
   * @returns {boolean} If the signature is valid against the public key
   */
  verify(data: HashBytes, signature: SignatureBytes): boolean;

  /**
   * Encode the PublicKey to Multibase Format
   * @returns {string} The multibase formatted public key
   */
  encode(): string;

  /**
   * Decode the public key from Multibase Format to a PublicKey
   * @returns {PublicKey} A public key instance
   */
  decode(): PublicKey;

  /**
   * Get the full id of the multikey
   * @returns {string} The full id of the multikey
   */
  fullId(): string

  /**
   * Convert the multikey to a verification method
   * @returns {DidVerificationMethod} The verification method
   */
  toVerificationMethod(): DidVerificationMethod;

  /**
   * Convert a verification method to a multikey
   * @param {DidVerificationMethod} verificationMethod The verification method to convert
   * @returns {Multikey} Multikey instance
   * @throws {Btc1KeyManagerError} if the verification method is missing required fields
   * @throws {Btc1KeyManagerError} if the verification method has an invalid type
   * @throws {Btc1KeyManagerError} if the publicKeyMultibase has an invalid prefix
   */
  fromVerificationMethod(verificationMethod: DidVerificationMethod): Multikey;
}