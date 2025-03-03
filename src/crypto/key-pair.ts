import { PrivateKeyBytes } from '../types/shared.js';
import { PrivateKey } from './private-key.js';
import { PublicKey } from './public-key.js';
import { IPrivateKey } from './private-key.js';

/**
 * Interface for a key pair
 * @export
 * @interface IKeyPair
 * @type {IKeyPair}
 */
export interface IKeyPair {
  /** @type {PublicKey} The public key associated with this key pair */
  readonly publicKey: PublicKey;

  /** @type {PrivateKey} The private key associated with this key pair */
  readonly privateKey: PrivateKey;

  /** @type {KeyPair} Creates a KeyPair from an existing private key */
  fromPrivateKey(privateKey: IPrivateKey): KeyPair;
}

/**
 * A compressed secp256k1 public/private key pair
 * @export
 * @class KeyPair
 * @type {KeyPair}
 * @implements {IKeyPair}
 */
export class KeyPair implements IKeyPair {
  private _privateKey: PrivateKey;
  private _publicKey: PublicKey;

  /**
   * Creates an instance of KeyPair
   * @constructor
   * @param {PrivateKey} privateKey The private key bytes to use
   */
  constructor(privateKey?: PrivateKey) {
    // If there is no PrivateKey, generate one
    this._privateKey = privateKey ?? new PrivateKey();
    this._publicKey = this._privateKey.toPublicKey();
  }

  /**
   * Returns the public key
   * @readonly
   * @type {PublicKey} The public key object
   */
  get publicKey(): PublicKey {
    return this._publicKey;
  }

  /**
   * Returns the private key
   * @readonly
   * @type {PrivateKey} The private key object
   */
  get privateKey(): PrivateKey {
    return this._privateKey;
  }

  /**
   * Creates a KeyPair from existing private key bytes
   * @param {PrivateKeyBytes} bytes
   * @returns {KeyPair}
   */
  public fromPrivateKeyBytes(bytes: PrivateKeyBytes): KeyPair {
    return this.fromPrivateKey(new PrivateKey(bytes));
  }

  /**
   * Creates a KeyPair from an existing private key
   * @param privateKey The private key (must be valid)
   * @returns {KeyPair}
   */
  public fromPrivateKey(privateKey: PrivateKey): KeyPair {
    this._privateKey = privateKey;
    return new KeyPair(privateKey);
  }

  /**
   * Creates a KeyPair from an existing private key.
   * @static
   * @param privateKey The private key (must be valid)
   * @returns {KeyPair}
   */
  public static initialize(privateKey: PrivateKey): KeyPair {
    return new KeyPair(privateKey);
  }

  /**
   * Generate a new key pair
   * @static
   * @returns {KeyPair} A new key pair
   */
  public static generate(): KeyPair {
    return new KeyPair();
  }
}