import { getRandomValues } from 'crypto';
import * as tinysecp from 'tiny-secp256k1';
import { Hex, PrivateKeyBytes } from '../types/shared.js';
import { PrivateKeyError } from '../utils/error.js';
import { CURVE } from './constants.js';
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
  /** @type {PrivateKeyUtils} The Uint8Array private key */
  public utils: PrivateKeyUtils = new PrivateKeyUtils();

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
        'SET_PRIVATE_KEY_ERROR'
      );
    }

    // Set the private key bytes
    this._bytes = new Uint8Array(bytes);
  }

  /** @see IPrivateKey.raw */
  get raw(): Uint8Array {
    // If no private key bytes, throw an error
    if (!this._bytes) {
      throw new PrivateKeyError(
        'Missing variable: private key not set',
        'GET_RAW_PRIVATE_KEY_ERROR'
      );
    }
    // Return a copy of the private key bytes
    return new Uint8Array(this._bytes);
  }

  /**
   * Return the raw private key as a bigint secret.
   * @see IPrivateKey.secret
   */
  get secret(): bigint {
    // Convert private key bytes to a bigint
    return this.raw.reduce(
      (acc, byte) => (acc << 8n) | BigInt(byte), 0n
    );
  }

  /** @see IPrivateKey.point */
  get point(): bigint {
    // Multiply the generator point by the private key
    const publicKey = tinysecp.pointFromScalar(this.raw, true);
    // If no public key, throw error
    if (!publicKey) {
      throw new PrivateKeyError(
        'Undefined publicKey: failed to compute public key',
        'PRIVATE_KEY_POINT_ERROR'
      );
    }

    // If length is incorrect, throw error
    if (!tinysecp.isPointCompressed(publicKey)) {
      throw new PrivateKeyError(
        'Malformed publicKey: public key not compressed format',
        'PRIVATE_KEY_POINT_ERROR'
      );
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
    // Derive the public key from the private key
    const publicKeyBytes = tinysecp.pointFromScalar(this.raw, true);

    // If no public key, throw error
    if (!publicKeyBytes) {
      throw new PrivateKeyError(
        'Invalid response: failed to derive public key',
        'COMPUTE_PUBLIC_KEY_ERROR'
      );
    }

    // If public key is not compressed, throw error
    if(publicKeyBytes.length !== 33) {
      throw new PrivateKeyError(
        'Invalid response: public key not compressed format',
        'COMPUTE_PUBLIC_KEY_ERROR'
      );
    }

    const finalPublicKeyBytes = publicKeyBytes[0] === 0x03
      ? this.utils.lift_x(publicKeyBytes.slice(1, 33))
      : publicKeyBytes;

    return new PublicKey(finalPublicKeyBytes);
  }

  /**
   * Create a new PrivateKey object from a bigint secret.
   * @static
   * @param {bigint} secret The secret bigint
   * @returns {PrivateKey} A new PrivateKey object
   */
  public static fromSecret(secret: bigint): PrivateKey {
    // Convert the secret bigint to a hex string
    const hexsecret = secret.toString(16).padStart(64, '0');
    // Convert the hex string to a Uint8Array
    const privateKeyBytes = new Uint8Array(hexsecret.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
    // Return a new PrivateKey object
    return new PrivateKey(privateKeyBytes);
  }
}

/**
 * Static methods for creating and working with PrivateKey objects.
 * @export
 * @class PrivateKeyUtils
 * @type {PrivateKeyUtils}
 * @extends {PrivateKey}
 */
export class PrivateKeyUtils {

  /**
   * Static method to generate a new PrivateKey from random bytes.
   * @static
   * @returns {PrivateKey} A new PrivateKey object.
   */
  public static generate(): PrivateKey {
    // Generate random private key bytes
    const privateKeyBytes = this.random();

    // Return a new PrivateKey object
    return new PrivateKey(privateKeyBytes);
  }

  /**
   * Static method to generate random private key bytes.
   * @static
   * @returns {PrivateKeyBytes} Uint8Array of 32 random bytes.
   */
  public static random(): PrivateKeyBytes {
    // Generate empty 32-byte array
    const byteArray = new Uint8Array(32);
    // Use the getRandomValues function to fill the byteArray with random values
    return getRandomValues(byteArray);
  }


  /**
 * Computes modular exponentiation: (base^exp) % mod.
 * Used for computing modular square roots.
 */
  public static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  };

  /**
 * Computes `sqrt(a) mod p` using Tonelli-Shanks algorithm.
 * This finds `y` such that `y^2 ≡ a mod p`.
 */
  public static sqrtMod(a: bigint, p: bigint): bigint {
    return this.modPow(a, (p + 1n) >> 2n, p);
  };

  /**
 * Lifts a 32-byte x-only coordinate into a full secp256k1 point (x, y).
 * Does **not** enforce even parity.
 *
 * @param xBytes 32-byte x-coordinate
 * @returns 65-byte uncompressed public key (starts with `0x04`)
 */
  public lift_x(xBytes: Uint8Array): Uint8Array {
    if (xBytes.length !== 32) throw new Error('Invalid x-coordinate length');

    // Convert x from Uint8Array → BigInt
    const x = BigInt('0x' + Buffer.from(xBytes).toString('hex'));
    if (x <= 0n || x >= CURVE.p) throw new Error('x out of range');

    // Compute y² = x³ + 7 mod p
    const ySquared = BigInt((x ** 3n + CURVE.b) % CURVE.p);

    // Compute y (do not enforce parity)
    const y = PrivateKeyUtils.sqrtMod(ySquared, CURVE.p);

    // Convert x and y to Uint8Array
    const yBytes = Buffer.from(y.toString(16).padStart(64, '0'), 'hex');

    // Return 65-byte uncompressed public key: `0x04 || x || y`
    return Buffer.concat([Buffer.from([0x04]), Buffer.from(xBytes), yBytes]);
  };
}

