import { Hex, PrefixBytes, PrivateKeyBytes, PrivateKeyPoint, PrivateKeySecret, PublicKeyBytes, PublicKeyMultibaseBytes } from '../types/shared.js';
import { PrivateKey } from './private-key.js';
import { PublicKey } from './public-key.js';

/**
 * Interface for the PrivateKey class.
 * @export
 * @interface IPrivateKey
 * @type {IPrivateKey}
 */
export interface IPrivateKey {
  /**
   * Get the private key bytes
   * @readonly @type {PrivateKeyBytes} The private key bytes.
   */
  bytes: PrivateKeyBytes;

  /**
   * Getter returns the private key bytes in secret form.
   * Setter allows alternative method of using a bigint secret to genereate the private key bytes.
   * @type {BigInt} The private key secret.
   */
  secret: BigInt;

  /**
   * Get the private key point
   * @readonly @type {BigInt} The private key point.
   */
  point: BigInt;

  /**
   * Checks if this private key is equal to another private key
   * @public
   * @returns {boolean} True if the private keys are equal
   */
  equals(other: PrivateKey): boolean;

  /**
   * Uses the private key to compute the corresponding public key.
   * @see PrivateKeyUtils.computePublicKey
   * @public
   * @returns {PublicKey} A new PublicKey object
   */
  computePublicKey(): PublicKey;

  /**
   * Returns the private key as a hex string
   * @public
   * @returns {Hex} The private key as a hex string
   */
  hex(): Hex;

  /**
   * Converts a Uint8Array private key bytes to a bigint secret.
   * @public
   * @param {PrivateKeyBytes} bytes
   * @returns {bigint}
   */
  toSecret(bytes: PrivateKeyBytes): bigint;

  /**
   * Converts a bigint secret to a Uint8Array private key bytes.
   * @public
   * @param {bigint} secret
   * @returns {PrivateKeyBytes}
   */
  toBytes(secret: bigint): PrivateKeyBytes;


  /**
   * Generates new PrivateKey from random bytes.
   * @returns {PrivateKey}
   * @see PrivateKeyUtils.generate
   */
  generate(): PrivateKey

  /**
   * Generates new random private key bytes.
   * @returns {PrivateKeyBytes}
   * @see PrivateKeyUtils.random
   */
  random(): PrivateKeyBytes
}


/**
 * Interface for the PublicKey class.
 * @export
 * @interface IPublicKey
 * @type {IPublicKey}
 */
export interface IPublicKey {
  /**
   * Compressed public key getter
   * @type {PublicKeyBytes} The 33 byte compressed public key [parity, x-coord]
   */
  compressed: PublicKeyBytes;

  /**
   * Uncompressed public key getter
   * @type {PublicKeyBytes} The 65 byte uncompressed public key [0x04, x-coord, y-coord]
   */
  uncompressed: PublicKeyBytes;

  /**
   * Public key parity getter
   * @type {number} The 1 byte parity (0x02 if even, 0x03 if odd)
   */
  parity: number;

  /**
   * Public key multibase prefix getter
   * @type {PrefixBytes} The 2 byte multibase prefix
   */
  prefix: PrefixBytes;

  /**
   * Public key x-coordinate getter
   * @type {PublicKeyBytes} The 32 byte x-coordinate of the public key
   */
  x: PublicKeyBytes;

  /**
   * Public key y-coordinate getter
   * @type {PublicKeyBytes} The 32 byte y-coordinate of the public key
   */
  y: PublicKeyBytes;

  /**
   * Public key multibase getter
   * @returns {string} The public key as a base58btc multibase string
   */
  multibase: string;

  /**
   * Decode the public key from multibase format to the compressed x-coordinate public key.
   * @returns {PublicKeyMultibaseBytes} The decoded public key bytes (34 bytes = 2 bytes header + 32 byte x-coordinate).
   */
  decodeMultibase(): PublicKeyMultibaseBytes;

  /**
   * Encode the PublicKey bytes to bip340 multibase format (34 bytes = 2 bytes header + 32 byte x-coordinate).
   * @returns {string} The public key x-coord bytes prefixed with bip340 header base58btc encoded.
   */
  encodeMultibase(): string;

  /**
   * Public key hex getter.
   * @returns {Hex} The public key as a hex string.
   */
  hex(): Hex;

  /**
   * Public key equality check. Checks if `this` public key is equal to `other` public key.
   * @param {PublicKey} other The public key to compare.
   * @returns {boolean} True if the public keys are equal.
   */
  equals(other: PublicKey): boolean;


  /**
   * Public key json representation.
   * @returns {object} The public key as a json object.
   */
  json(): object;
}

/**
 * Interface for class KeyPair
 * @export
 * @interface IKeyPair
 * @type {IKeyPair}
 */
export interface IKeyPair {
  /**
   * Get/set the public key associated with the key pair (required).
   * @readonly
   * @type {PublicKey} The public key associated with the key pair (required).
   */
  readonly publicKey: PublicKey;

  /**
   * Get the private key associated with this key pair (optional).
   * @readonly
   * @type {PrivateKey} The private key associated with this key pair (optional)
   * @throws {KeyPairError} If the private key is not available
   */
  readonly privateKey?: PrivateKey;


  /**
   * Returns the key pair as a MultibaseKey object.
   * @returns {MultikeyPair} The key pair as a MultibaseKey object.
   */
  multibase(): MultikeyPair;
}


/** Params for the {@link KeyPair} constructor */
export interface KeyPairParams {
  privateKey?: PrivateKey | null;
  publicKey?: PublicKey | null;
}

/**
 * Interface for the MultikeyPair class.
 * @export
 * @interface IMultikeyPair
 * @type {IMultikeyPair}
 */
export interface IMultikeyPair {
  publicKey: PublicKeyObject;
  privateKey: PrivateKeyObject;
}

export type PublicKeyObject = {
  parity    : number,
  x         : PublicKeyBytes,
  y         : PublicKeyBytes,
  multibase : string,
  prefix    : PrefixBytes,
}

export type PrivateKeyObject = {
  bytes: PrivateKeyBytes;
  secret: PrivateKeySecret;
  point: PrivateKeyPoint
  hex: Hex;
}

// TODO: Update the MultikeyPair to include id and controller

/**
 * Object class representatopm of a MultikeyPair.
 * @export
 * @class MultikeyPair
 * @type {MultikeyPair}
 * @implements {IMultikeyPair}
 */
export class MultikeyPair implements IMultikeyPair {
  public publicKey: PublicKeyObject;
  public privateKey: PrivateKeyObject;

  constructor({ publicKey, privateKey }: IMultikeyPair) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }
}