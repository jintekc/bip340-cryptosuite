import { getRandomValues } from 'crypto';
import * as tinysecp from 'tiny-secp256k1';
import { Hex, PrivateKeyBytes } from '../types/shared.js';
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
   * Creates an instance of PrivateKey from private key bytes.
   * @constructor
   * @param {PrivateKeyBytes} bytes The private key bytes.
   */
  constructor(bytes: PrivateKeyBytes) {
    // If no bytes or bytes are not length 32
    if (!bytes || bytes.length !== 32) {
      throw new PrivateKeyError(
        'Invalid argument: must provide a 32-byte private key',
        'PRIVATE_KEY_CONSTRUCTOR_ERROR'
      );
    }
    // If bytes do not produce a valid private key, throw error
    if (!tinysecp.isPrivate(bytes)) {
      throw new PrivateKeyError(
        'Invalid argument: bytes produce an invalid private key',
        'PRIVATE_KEY_CONSTRUCTOR_ERROR'
      );
    }

    // Set the private key bytes
    this._bytes = new Uint8Array(bytes);
  }

  /** @see IPrivateKey.secret */
  set secret(secretn: bigint) {
    // ensure it’s a valid 32-byte value in [1, n-1]
    // Convert bigint to bytes and set the private key
    const bytes = Uint8Array.from(
      { length: 32 },
      (_, i) => Number(secretn >> BigInt(8 * (31 - i)) & BigInt(0xff))
    );

    if (!tinysecp.isPrivate(bytes)) {
      throw new PrivateKeyError(
        'Invalid private key: secret out of valid range',
        'PRIVATE_KEY_SET_ERROR'
      );
    }

    this._bytes = bytes;
  }

  /** @see IPrivateKey.raw */
  get raw(): Uint8Array {
    // If no private key bytes, throw an error
    if (!this._bytes) {
      throw new PrivateKeyError(
        'Missing variable: private key not set',
        'RAW_PRIVATE_KEY_ERROR'
      );
    }
    // Return a copy of the private key bytes
    return new Uint8Array(this._bytes);
  }

  /**
   * Return the raw private key as a bigint secret.
   * @see IPrivateKey.secret
   */
  get secret(): BigInt {
    // Convert private key bytes to a bigint
    return this.raw.reduce(
      (acc, byte) => (acc << BigInt(8)) | BigInt(byte),
      BigInt(0)
    );
  }

  /** @see IPrivateKey.point */
  get point(): BigInt {
    // Multiply the generator point by the private key
    const publicKey = tinysecp.pointFromScalar(this.raw, true);
    // If no public key, throw error
    if (!publicKey) {
      throw new PrivateKeyError('Undefined publicKey: failed to compute public key', 'PRIVATE_KEY_POINT_ERROR');
    }

    // If length is incorrect, throw error
    if (!tinysecp.isPointCompressed(publicKey)) {
      throw new PrivateKeyError('Malformed publicKey: public key not compressed format', 'PRIVATE_KEY_POINT_ERROR');
    }

    // Extract the x-coordinate from the compressed public key (bytes 1-33).
    return BigInt('0x' + Buffer.from(publicKey.slice(1, 33)).toString('hex'));
  }

  /**
   * Returns the raw private key as a hex string.
   * @see IPrivateKey.Hex
   */
  public hex(): Hex | string {
    // Convert the raw private key bytes to a hex string
    return Buffer.from(this.raw).toString('hex');
  }

  /**
   * Checks if this private key is equal to another.
   * @see IPrivateKey.equals
   */
  public equals(other: PrivateKey): boolean {
    // Compare the hex strings of the private keys
    return this.hex() === other.hex();
  }

  /** @see IPrivateKey.computePublicKey */
  public computePublicKey(): PublicKey {
    let publicKeyBytes = tinysecp.pointFromScalar(this.raw, true);

    if (!publicKeyBytes) {
      throw new PrivateKeyError(
        'Invalid response: failed to derive public key',
        'PRIVATE_KEY_DERIVE_PUBLIC_KEY_ERROR'
      );
    }

    // If we already have even parity, great.
    if (publicKeyBytes[0] === 0x02) {
      return new PublicKey(publicKeyBytes);
    }

    // Otherwise, flip this private key to n - secret
    const flipped = CURVE.n - this.secret;
    this.secret = flipped;

    // Derive again
    publicKeyBytes = tinysecp.pointFromScalar(this.raw, true);
    if (!publicKeyBytes || publicKeyBytes[0] !== 0x02) {
      throw new PrivateKeyError(
        'Failed to produce even-parity public key after flipping',
        'PRIVATE_KEY_PARITY_ERROR'
      );
    }

    return new PublicKey(publicKeyBytes);  }

  /**
   * Create a new PrivateKey object from a bigint secret.
   * @static
   * @param {BigInt} secret The secret bigint
   * @returns {PrivateKey} A new PrivateKey object
   */
  public static fromSecret(secret: BigInt): PrivateKey {
    // Convert the secret bigint to a hex string
    const hexsecret = secret.toString(16).padStart(64, '0');
    // Convert the hex string to a Uint8Array
    const privateKeyBytes = new Uint8Array(hexsecret.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
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
