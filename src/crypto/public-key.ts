import { getPublicKey, Hex } from '@noble/secp256k1';
import { MultikeyUtils } from '../di-bip340/multikey/utils.js';
import { PublicKeyBytes } from '../types/shared.js';
import { Btc1KeyManagerError } from '../utils/error.js';
// import { sha256 } from '@noble/hashes/sha256';


/**
 * Represents a secp256k1 public key and provides different formats (compressed, x-only, multibase)
 * @export
 * @class PublicKey
 * @type {PublicKey}
 */
export class PublicKey {
  private readonly _bytes: PublicKeyBytes;

  constructor(publicKey: PublicKeyBytes) {
    if (publicKey.length !== 33) {
      throw new Btc1KeyManagerError('Invalid public key: Expected 33-byte compressed secp256k1 key');
    }
    this._bytes = publicKey;
  }

  /**
   * Get the 33-byte compressed public key (prefix + x-coordinate)
   */
  get compressed(): PublicKeyBytes {
    return new Uint8Array(this._bytes);
  }

  /**
   * Get the 32-byte x-only public key (for Schnorr signatures and Taproot)
   */
  get x(): PublicKeyBytes {
    return new Uint8Array(this.compressed.slice(1, 33));
  }

  /**
   * Get the 32-byte y-coordinate of the public key
   */
  get y(): PublicKeyBytes {
    return new Uint8Array(this.uncompressed.slice(33, 65));
  }

  /**
   * Get the full public key (prefix + x + y)
   */
  get uncompressed(): PublicKeyBytes {
    return new Uint8Array(getPublicKey(this.compressed, false));
  }

  /** Converts the public key to a Multibase string */
  public multibase(): string {
    return MultikeyUtils.encode(this.compressed);
  }

  /**
   * Returns the public key as a hex string
   * @public
   * @returns {Hex} The public key as a hex string
   */
  public hex(): Hex {
    return Buffer.from(this.compressed).toString('hex');
  }

  /**
   * Checks if this public key is equal to another public key
   * @public
   * @returns {boolean} True if the public keys are equal
   */
  public equals(other: PublicKey): boolean {
    return this.hex() === other.hex();
  }
}
