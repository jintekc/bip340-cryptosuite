import { getRandomValues } from 'crypto';
import * as tinysecp from 'tiny-secp256k1';
import { Hex, PrivateKeyBytes, PrivateKeyPoint, PrivateKeySecret } from '../types/shared.js';
import { PrivateKeyError } from '../utils/error.js';
import { IPrivateKey, PrivateKeyObject } from './interface.js';
import { PublicKey } from './public-key.js';
import { CURVE } from './constants.js';

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
  /** @type {PrivateKeyUtils} Static PrivateKeyUtils class instance */
  public utils: PrivateKeyUtils = new PrivateKeyUtils();

  /** @type {PrivateKeyBytes} The Uint8Array private key bytes */
  private _bytes?: PrivateKeyBytes;

  /** @type {PrivateKeySecret} The bigint private key secret */
  private _secret?: PrivateKeySecret;

  /**
   * Instantiates an instance of PrivateKey.
   * @constructor
   * @param {PrivateKeyBytes | bigint} seed bytes or secret
   */
  constructor(seed: PrivateKeyBytes | PrivateKeySecret) {
    // If no bytes or secret, throw error
    if(!seed) {
      throw new PrivateKeyError(
        'Invalid argument: must provide a 32-byte private key or a bigint secret',
        'PRIVATE_KEY_CONSTRUCTOR_ERROR'
      );
    }

    // If bytes and bytes are not length 32
    const isBytes = seed instanceof Uint8Array;
    if (isBytes && seed.length !== 32) {
      throw new PrivateKeyError(
        'Invalid argument: must provide a 32-byte private key',
        'PRIVATE_KEY_CONSTRUCTOR_ERROR'
      );
    }

    // If secret and secret is not a valid bigint, throw error
    const isSecret = typeof seed === 'bigint';
    if (isSecret && (seed < 1n || seed >= CURVE.n)) {
      throw new PrivateKeyError(
        'Invalid argument: secret out of valid range',
        'PRIVATE_KEY_CONSTRUCTOR_ERROR'
      );
    }

    // Set the private key _bytes or _secret
    this._bytes = seed as PrivateKeyBytes ?? this.toBytes(seed as PrivateKeySecret);
    this._secret = seed as PrivateKeySecret ?? this.toSecret(seed as PrivateKeyBytes);
  }

  /**
   * Getter/setter for the private key secret and bytes.
   * @see IPrivateKey.secret
  set secret(secret: bigint) {
    // Set the private key bytes
    this._secret = secret;
    this._bytes = this.toBytes(secret);
  }*/

  /**
   * Get the private key bytes.
   * @see IPrivateKey.bytes
   */
  get bytes(): PrivateKeyBytes {
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
  get secret(): PrivateKeySecret {
    // Convert private key bytes to a bigint
    return this.bytes.reduce(
      (acc, byte) => (acc << 8n) | BigInt(byte), 0n
    );
  }

  /**
   * Get the private key point.
   * @see IPrivateKey.point
   */
  get point(): PrivateKeyPoint {
    // Multiply the generator point by the private key
    const publicKey = tinysecp.pointFromScalar(this.bytes, true);

    // If no public key, throw error
    if (!publicKey) {
      throw new PrivateKeyError(
        'Undefined publicKey: failed to compute public key',
        'PRIVATE_KEY_POINT_ERROR'
      );
    }

    // If not compressed point, throw error
    if (!tinysecp.isPointCompressed(publicKey)) {
      throw new PrivateKeyError(
        'Malformed publicKey: public key not compressed format',
        'PRIVATE_KEY_POINT_ERROR'
      );
    }

    // Extract the x-coordinate from the compressed public key, convert to hex, and return as bigint
    return BigInt('0x' + Buffer.from(publicKey.slice(1, 33)).toString('hex'));
  }

  /**
   * Returns the raw private key as a hex string.
   * @see IPrivateKey.Hex
   */
  public hex(): Hex | string {
    // Convert the raw private key bytes to a hex string
    return Buffer.from(this.bytes).toString('hex');
  }

  /**
   * Checks if this private key is equal to another.
   * @see IPrivateKey.equals
   */
  public equals(other: PrivateKey): boolean {
    // Compare the hex strings of the private keys
    return this.hex() === other.hex();
  }

  /**
   * Uses the private key to compute the corresponding public key.
   * @see IPrivateKey.computePublicKey
   */
  public computePublicKey(): PublicKey {
    return this.utils.computePublicKey(this.bytes);
  }

  /**
   * Converts a Uint8Array private key bytes to a bigint secret.
   * @see IPrivateKey.toSecret
   */
  public toSecret(bytes: PrivateKeyBytes): bigint {
    return bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
  }

  /**
   * Converts a bigint secret to a Uint8Array private key bytes.
   * @see IPrivateKey.toBytes
   */
  public toBytes(secret: bigint): PrivateKeyBytes {
    // Ensure it’s a valid 32-byte value in [1, n-1] and convert bigint to Uint8Array
    const bytes = Uint8Array.from(
      { length: 32 },
      (_, i) => Number(secret >> BigInt(8 * (31 - i)) & BigInt(0xff))
    );

    // If bytes are not a valid secp256k1 private key, throw error
    if (!tinysecp.isPrivate(bytes)) {
      throw new PrivateKeyError(
        'Invalid private key: secret out of valid range',
        'SET_PRIVATE_KEY_ERROR'
      );
    }
    return new Uint8Array(bytes);;
  }

  /**
   * Generates a new PrivateKey from random bytes.
   * @see IPrivateKey.generate
   */
  public generate(): PrivateKey {
    return PrivateKeyUtils.generate();
  }

  /**
   * Generates new random private key bytes.
   * @see IPrivateKey.random
   */
  public random(): PrivateKeyBytes {
    return PrivateKeyUtils.random();
  }


  /**
   * Returns the private key as a JSON object.
   * @see IPrivateKey.json
   */
  public json(): PrivateKeyObject {
    return {
      bytes  : this.bytes,
      secret : this.secret,
      point  : this.point,
      hex    : this.hex(),
    };
  }
}

/**
 * Static methods for creating and working with PrivateKey objects.
 * @export
 * @class PrivateKeyUtils
 * @type {PrivateKeyUtils}
 */
export class PrivateKeyUtils {

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

  /**
   * Computes the public key from a private key.
   * @public
   * @param {PrivateKeyBytes} privateKeyBytes The private key bytes
   * @returns {PublicKey} A new PublicKey object
   */
  public computePublicKey(privateKeyBytes: PrivateKeyBytes): PublicKey {
    // Derive the public key from the private key
    const publicKeyBytes = tinysecp.pointFromScalar(privateKeyBytes, true);

    // If no public key, throw error
    if (!publicKeyBytes) {
      throw new PrivateKeyError(
        'Invalid compute: failed to derive public key',
        'COMPUTE_PUBLIC_KEY_ERROR'
      );
    }

    // If public key is not compressed, throw error
    if(publicKeyBytes.length !== 33) {
      throw new PrivateKeyError(
        'Invalid compute: public key not compressed format',
        'COMPUTE_PUBLIC_KEY_ERROR'
      );
    }

    return new PublicKey(publicKeyBytes);
  }

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
}