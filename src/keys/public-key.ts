import { base58btc } from 'multiformats/bases/base58';
import * as tinysecp from 'tiny-secp256k1';
import { Hex, PrivateKeyBytes, PublicKeyBytes } from '../types/shared.js';
import { PublicKeyError } from '../utils/error.js';
import { IPublicKey } from './interface.js';
import { PrivateKey, PrivateKeyUtils } from './private-key.js';
import { SECP256K1_XONLY_PREFIX } from './constants.js';

/**
 * Encapsulates a secp256k1 public key.
 * Provides get methods for different formats (compressed, x-only, multibase).
 * Provides helpers methods for comparison and serialization.
 * @export
 * @class PublicKey
 * @type {PublicKey}
 * @implements {IPublicKey}
 */
export class PublicKey implements IPublicKey {
  /** @type {PublicKeyBytes} The Uint8Array public key */
  private readonly _bytes: PublicKeyBytes;

  /**
   * Creates an instance of PublicKey.
   * @constructor
   * @param {PublicKeyBytes} bytes The public key byte array.
   * @throws {PublicKeyError} if the bytes are not x-only or compressed with 0x02 prefix
   */
  constructor(bytes: PublicKeyBytes) {
    const bytelength = bytes.length;
    if(bytelength === 33 && bytes[0] === 3) {
      throw new PublicKeyError(
        'Invalid argument: "bytes" must be 32-byte x-only or 33-byte compressed with 0x02 prefix',
        'PUBLIC_KEY_CONSTRUCTOR_ERROR'
      );
    }
    this._bytes = bytelength === 32 ? new Uint8Array([0x02, ...Array.from(bytes)]) : bytes;
  }

  /** @see IPublicKey.compressed */
  get compressed(): Uint8Array {
    return new Uint8Array(this._bytes);
  }

  /** @see IPublicKey.parity */
  get prefix(): number {
    const prefixb = this.compressed[0];
    return prefixb;
  }

  /** @see IPublicKey.x */
  get x(): PublicKeyBytes {
    return this.compressed.slice(1, 33);
  }

  /** @see IPublicKey.y */
  get y(): PublicKeyBytes {
    return this.uncompressed.slice(33, 65);
  }

  /** @see IPublicKey.uncompressed */
  get uncompressed(): PublicKeyBytes {
    return tinysecp.pointCompress(this.compressed, false) as PublicKeyBytes;
  }

  /** @see IPublicKey.multibase */
  get multibase(): string {
    return PublicKeyUtils.encode(this.x);
  }

  /** @see IPublicKey.decode */
  /** @see PublicKeyUtils.decode */
  public encode(): string {
    return PublicKeyUtils.encode(this.x);
  }

  /** @see IPublicKey.decode */
  /** @see PublicKeyUtils.decode */
  public decode(): PublicKeyBytes {
    return PublicKeyUtils.decode(this.multibase);
  }

  /** @see IPublicKey.hex */
  public hex(): Hex {
    return Buffer.from(this.compressed).toString('hex');
  }

  /** @see IPublicKey.equals */
  public equals(other: PublicKey): boolean {
    return this.hex() === other.hex();
  }
}

/**
 * Utility class for Multikey operations/
 *
 * @export
 * @class PublicKeyUtils
 * @type {PublicKeyUtils}
 * @implements {IPublicKey}
 */
export class PublicKeyUtils {
  /**
   * Computes a private key's public key in compressed even-parity-only format.
   * @static
   * @param {PrivateKeyBytes} privateKeyBytes The private key bytes
   * @returns {PublicKey} A new PublicKey object
   */
  public static fromPrivateKey(privateKeyBytes: PrivateKeyBytes): PublicKey {
    const bytelength = privateKeyBytes.length;
    if(bytelength !== 32) {
      throw new PublicKeyError('Invalid arg: must be 32 byte private key', 'FROM_PRIVATE_KEY_ERROR');
    }
    const privateKey = new PrivateKey(privateKeyBytes);
    return privateKey.computePublicKey();
  }

  /**
   * Generates random public key bytes.
   * @warning DOES NOT RETURN PRIVATE KEY! DO NOT USE IN PRODUCTION!
   * @static
   * @returns {PublicKeyBytes} Uint8Array of 32 random bytes.
   */
  public static random(compressed?: boolean): PublicKeyBytes {
    // Generate random private key bytes
    const privateKeyBytes = PrivateKeyUtils.random();
    // Generate public key bytes from private key bytes
    const publicKeyBytes = tinysecp.pointFromScalar(privateKeyBytes, compressed ?? true);
    // If no public key bytes, throw error
    if (!publicKeyBytes) {
      throw new PublicKeyError('Missing public key: failed to generate public key', 'RANDOM_PUBLIC_KEY_FAILED');
    }
    // Return the public key bytes
    return publicKeyBytes;
  }

  /**
   * Generates a new PublicKey from random bytes.
   * @static
   * @returns {PublicKey} A new PublicKey object
   */
  public static generate(): PublicKey {
    // Generate random public key bytes
    const publicKeyBytes = this.random();
    // Return a new PublicKey object
    return new PublicKey(publicKeyBytes);
  }

  /**
   * Adjusts a secp256k1 public key to have even parity (leading byte 0x02).
   * @static
   * @param {Uint8Array} publicKey The compressed public key.
   * @returns {Uint8Array} Adjusted public key with even parity.
   */
  public static ensureEvenParity(publicKey: Uint8Array): Uint8Array {
    // Check if the public key has the correct length, is compressed and has parity byte of 2 or 3
    if (publicKey.length !== 33 || (publicKey[0] !== 0x02 && publicKey[0] !== 0x03)) {
      throw new PublicKeyError('Invalid format: publicKey must 33 byte compressed', 'ENSURE_EVEN_PARITY_ERROR');
    }

    // If the public key starts with 0x03, flip the prefix to 0x02
    if (publicKey[0] === 0x03) {
      const adjustedPublicKey = new Uint8Array(publicKey);
      adjustedPublicKey[0] = 0x02; // Flip to even parity
      return adjustedPublicKey;
    }

    // Already even parity, return as is
    return publicKey;
  }

  /**
   * Decodes a string in compressed secp256k1 base58btc multibase format to its corresponding public key bytes
   * @static
   * @param {PublicKeyMultibase} publicKeyMultibase The multibase formatted public key
   * @returns {PublicKey}
   */
  public static decode(publicKeyMultibase: string): PublicKeyBytes {
    const publicKeyBytes = base58btc.decode(publicKeyMultibase);
    const prefix = publicKeyBytes.subarray(0, 2);
    if (!prefix.every((b, i) => b === SECP256K1_XONLY_PREFIX[i])) {
      throw new PublicKeyError('Invalid prefix: malformed multibase prefix', 'DECODE_PUBLIC_KEY_MULTIBASE_ERROR');
    }
    return publicKeyBytes;
  }

  /**
   * Encodes compressed secp256k1 public key from bytes to BIP340 base58btc multibase format
   * @static
   * @param {PublicKeyBytes} xOnlyPublicKeyBytes
   * @returns {PublicKeyMultibase}
   */
  public static encode(xOnlyPublicKeyBytes: PublicKeyBytes): string {
    if (xOnlyPublicKeyBytes.length !== 32) {
      throw new PublicKeyError('x-only public key must be 32 bytes');
    }
    // Set the prefix and the public key bytes
    const multikeyBytes = new Uint8Array([...Array.from(SECP256K1_XONLY_PREFIX), ...Array.from(xOnlyPublicKeyBytes)]);
    // Encode the public key as a multibase base58btc string
    return base58btc.encode(multikeyBytes);
  }
}