import { CURVE, getPublicKey, Hex, utils } from '@noble/secp256k1';
import { PrivateKeyBytes } from '../types/shared.js';
import { KeyPairError } from '../utils/error.js';
import { PublicKey } from './public-key.js';

/**
 * Interface for a private key
 * @export
 * @interface IPrivateKey
 * @type {IPrivateKey}
 */
export interface IPrivateKey {
  /** @type {PublicKey} Converts the private key to its corresponding PublicKey object */
  toPublicKey(): PublicKey;

  /** @type {Hex} Returns the private key as a hex string */
  hex(): Hex;

  /** @type {PrivateKeyBytes} The private key bytes */
  compressed: PrivateKeyBytes;

  /** @type {BigInt} The private key scalar */
  secret: BigInt;

  /** @type {BigInt} The private key point */
  point: BigInt;
}

/**
 * Encapsulates a secp256k1 private key
 * @export
 * @class PrivateKey
 * @type {PrivateKey}
 * @implements {IPrivateKey}
 */
export class PrivateKey implements IPrivateKey {
  private readonly _bytes: PrivateKeyBytes;

  constructor(privateKey?: PrivateKeyBytes) {
    this._bytes = !privateKey ? utils.randomPrivateKey() : privateKey;
    if (!utils.isValidPrivateKey(this._bytes)){
      throw new KeyPairError('Invalid private key');
    }
  }

  /**
   * Returns the private key bytes
   * @readonly
   * @type {PrivateKeyBytes} A copy of the private key bytes
   */
  get compressed(): PrivateKeyBytes {
    return new Uint8Array(this._bytes);
  }

  /**
   * Returns the private key scalar
   * @readonly
   * @type {BigInt} The private key scalar as a BigInt
   */
  get secret(): BigInt {
    return BigInt(utils.normPrivateKeyToScalar(this.compressed));
  }

  /**
   * Returns the private key point
   * @readonly
   * @type {BigInt} The private key point as a BigInt
   */
  get point(): BigInt {
    return BigInt(CURVE.Gx * utils.normPrivateKeyToScalar(this.compressed));
  }

  /**
   * Returns the private key as a hex string
   * @public
   * @returns {Hex} The private key as a hex string
   */
  public hex(): Hex {
    return Buffer.from(this.compressed).toString('hex');
  }

  /**
   * Derives the corresponding public key
   * @returns {PublicKey} The corresponding public key as a PublicKey object
   */
  public toPublicKey(): PublicKey {
    return new PublicKey(getPublicKey(this.compressed, true));
  }
}
