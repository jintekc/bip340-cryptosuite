import { CURVE, Hex, utils } from '@noble/secp256k1';
import { getRandomValues } from 'crypto';
import * as tinysecp from 'tiny-secp256k1';
import { PrivateKeyBytes } from '../types/shared.js';
import { PrivateKeyError } from '../utils/error.js';
import { IPrivateKey } from './interface.js';
import { PublicKey } from './public-key.js';

/**
 * Encapsulates a secp256k1 private key
 * Provides get methods for different formats (raw, secret, point).
 * Provides helpers methods for comparison, serialization and publicKey generation.
 * @export
 * @class PrivateKey
 * @type {PrivateKey}
 * @implements {IPrivateKey}
 */
export class PrivateKey implements IPrivateKey {
  /** @type {PrivateKeyBytes} The Uint8Array private key */
  private _bytes: PrivateKeyBytes;

  /**
   * Creates an instance of PrivateKey.
   * @constructor
   * @param {PrivateKeyBytes} bytes The private key byte array.
   */
  constructor(bytes: PrivateKeyBytes) {
    // If bytes are passed but do not produce a valid private key, throw an error
    if (bytes && !tinysecp.isPrivate(bytes)) {
      throw new PrivateKeyError('Invalid argument: bytes produced invalid private key', 'PRIVATE_KEY_CONSTRUCTOR_ERROR');
    }
    // Set the private key bytes
    this._bytes = bytes;
  }

  /** @see IPrivateKey.raw */
  get raw(): Uint8Array {
    // If no private key bytes, throw an error
    if (!this._bytes) {
      throw new PrivateKeyError('Missing variable: private key not set', 'RAW_PRIVATE_KEY_ERROR');
    }
    // Return a copy of the private key bytes
    return new Uint8Array(this._bytes);
  }

  /** @see IPrivateKey.secret */
  get secret(): BigInt {
    // Convert private key bytes to a bigint
    return this.raw.reduce((acc, byte) => (acc << BigInt(8)) | BigInt(byte), BigInt(0));
  }

  /** @see IPrivateKey.secret */
  set secret(s: bigint) {
    // Convert bigint to bytes and set the private key
    this._bytes = Uint8Array.from({ length: 32 }, (_, i) => Number(s >> BigInt(8 * (31 - i)) & BigInt(0xff)));
  }

  /** @see IPrivateKey.point */
  get point(): BigInt {
    // Multiply the generator point by the private key
    return BigInt(CURVE.Gx * utils.normPrivateKeyToScalar(this.raw));
  }

  /** @see IPrivateKey.hex */
  public hex(): Hex | string {
    // Convert the raw private key bytes to a hex string
    return Buffer.from(this.raw).toString('hex');
  }

  /** @see IPrivateKey.equals */
  public equals(other: PrivateKey): boolean {
    // Compare the hex strings of the private keys
    return this.hex() === other.hex();
  }

  /** @see IPrivateKey.toPublicKey */
  public toPublicKey(): PublicKey {
    // Derive compressed public key bytes from the raw private key
    const publicKeyBytes = tinysecp.pointFromScalar(this.raw, true);
    // If no public key bytes, throw an error
    if (!publicKeyBytes) {
      throw new PrivateKeyError('Invalid response: failed to derive public key', 'PRIVATE_KEY_DERIVE_PUBLIC_KEY_ERROR');
    }
    // Return a new PublicKey object
    return new PublicKey(publicKeyBytes);
  }

  /**
   * Create a new PrivateKey object from a bigint secret.
   * @static
   * @param {BigInt} secret The secret bigint
   * @returns {PrivateKey} A new PrivateKey object
   */
  public static fromSecret(secret: BigInt): PrivateKey {
    // Convert the secret bigint to a hex string
    const secretHex = secret.toString(16).padStart(64, '0');
    // Convert the hex string to a Uint8Array
    const privateKeyBytes = new Uint8Array(secretHex.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
    // Return a new PrivateKey object
    return new PrivateKey(privateKeyBytes);
  }

  /**
   * Static method to generate a new PrivateKey from random bytes.
   * @static
   * @returns {PrivateKey} A new PrivateKey object.
   */
  public static generate(): PrivateKey {
    return new PrivateKey(this.random());
  }

  /**
   * Static method to generate random private key bytes.
   * @static
   * @returns {PrivateKeyBytes} Uint8Array of 32 random bytes.
   */
  public static random(): PrivateKeyBytes {
    return getRandomValues(new Uint8Array(32));
  }
}
