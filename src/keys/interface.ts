import { Hex } from '@noble/secp256k1';
import { PrivateKeyBytes, PublicKeyBytes } from '../types/shared.js';
import { KeyPair } from './key-pair.js';
import { PrivateKey } from './private-key.js';
import { PublicKey } from './public-key.js';

/**
 * Interface for the PrivateKey class.
 * @export
 * @interface IPrivateKey
 * @type {IPrivateKey}
 */
export interface IPrivateKey {
  /** @readonly @type {PrivateKeyBytes} Get the private key bytes */
  raw: PrivateKeyBytes;

  /** @type {BigInt} Get/set the private key secret */
  secret: BigInt;

  /** @readonly @type {BigInt} Get the private key point */
  point: BigInt;

  /**
   * Checks if this private key is equal to another private key
   * @public
   * @returns {boolean} True if the private keys are equal
   */
  equals(other: PrivateKey): boolean;

  /**
   * Uses the private key to compute the corresponding public key.
   * @returns {PublicKey} A new PublicKey object
   */
  computePublicKey(): PublicKey;

  /**
   * Returns the private key as a hex string
   * @public
   * @returns {Hex} The private key as a hex string
   */
  hex(): Hex;
}


/**
 * Interface for the PublicKey class.
 * @export
 * @interface IPublicKey
 * @type {IPublicKey}
 */
export interface IPublicKey {
  /** @type {PublicKeyBytes} Get the 33-byte compressed public key bytes */
  compressed: PublicKeyBytes;

  /** @type {number} Get the prefixed parity byte byte of the public key (must be 0x02) */
  prefix: number;

  /** @type {PublicKeyBytes} Get the 32-byte x-only public key (for schnorr ops) */
  x: PublicKeyBytes;

  /** @type {PublicKeyBytes} Get the 32-byte y-coordinate of the public key */
  y: PublicKeyBytes;

  /** @type {PublicKeyBytes} Get the uncompressed (65-byte) public key: prefix, x-coord, y-coord */
  uncompressed: PublicKeyBytes;

  /** @returns {string} Get the compressed x-only public key in base58btc multibase format */
  multibase: string;

  /**
   * Decode the base58btc multibase string to the compressed public key prefixed with 0x02
   * @returns {PublicKey} A new PublicKey object
   */
  decode(): PublicKey;

  /**
   * Encode the PublicKey as an x-only base58btc multibase public key
   * @returns {string} The public key formatted a base58btc multibase string
   */
  encode(): string;

  /**
   * Returns the public key as a hex string
   * @returns {Hex} The public key as a hex string
   */
  hex(): Hex;

  /**
   * Checks if this public key is equal to another public key
   * @param {PublicKey} other The public key to compare
   * @returns {boolean} True if the public keys are equal
   */
  equals(other: PublicKey): boolean;
}

export interface IPublicKeyUtils {
  generate(): KeyPair;
  decode(publicKeyMultibase: string): PublicKeyBytes;
  encode(xOnlyPublicKeyBytes: PublicKeyBytes): string;
}

/**
 * Interface for class KeyPair
 * @export
 * @interface IKeyPair
 * @type {IKeyPair}
 */
export interface IKeyPair {
  /** @readonly @type {PublicKey} Get/set the public key associated with the key pair (required) */
  readonly publicKey: PublicKey;

  /**
   * @readonly
   * @type {PrivateKey} The private key associated with this key pair (optional)
   * @throws {KeyPairError} If the private key is not available
   */
  readonly privateKey?: PrivateKey;
}