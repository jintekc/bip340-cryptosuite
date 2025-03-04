import { Hex } from '@noble/secp256k1';
import * as tinysecp from 'tiny-secp256k1';
import { MultikeyUtils } from '../di-bip340/multikey/utils.js';
import { PrivateKeyBytes, PublicKeyBytes } from '../types/shared.js';
import { PublicKeyError } from '../utils/error.js';
import { IPublicKey } from './interface.js';
import { PrivateKey } from './private-key.js';

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
    return this.encode();
  }

  /** @see IPublicKey.encode */
  /** @see MultikeyUtils.encode */
  public encode(): string {
    return MultikeyUtils.encode(this.x);
  }

  /** @see IPublicKey.decode */
  /** @see MultikeyUtils.decode */
  public decode(): PublicKey {
    // Decode the multibase to public key bytes
    const publicKeyBytes = MultikeyUtils.decode(this.multibase);
    // Dump the bytes into a new array with the prefix
    const publicKey = new Uint8Array([this.prefix, ...Array.from(publicKeyBytes)]);
    // Return a new PublicKey instance
    return new PublicKey(publicKey);
  }

  /** @see IPublicKey.hex */
  public hex(): Hex {
    return Buffer.from(this.compressed).toString('hex');
  }

  /** @see IPublicKey.equals */
  public equals(other: PublicKey): boolean {
    return this.hex() === other.hex();
  }

  /**
   * Static method generates a new PublicKey from random bytes.
   * @static
   * @returns {PublicKey} A new KeyPair object
   */
  public static generate(): PublicKey {
    return new PublicKey(this.random());
  }

  /**
   * Static method computes the corresponding public key for a given private key.
   * @static
   * @param {PrivateKeyBytes} bytes The private key bytes
   * @returns {PublicKey} A new PublicKey object
   */
  public static fromPrivateKey(bytes: PrivateKeyBytes): PublicKey {
    const privateKey = new PrivateKey(bytes);
    return privateKey.toPublicKey();
  }

  /**
   * Static method to generate random public key bytes.
   * @static
   * @returns {PublicKeyBytes} Uint8Array of 32 random bytes.
   */
  public static random(): PublicKeyBytes {
    const publicKeyBytes = tinysecp.pointFromScalar(PrivateKey.random(), true);
    if (!publicKeyBytes) {
      throw new PublicKeyError('Failed to generate random public key', 'PUBLIC_KEY_GENERATION_FAILED');
    }
    return publicKeyBytes;
  }
}
