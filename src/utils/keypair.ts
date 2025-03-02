import { Bytes, getPublicKey, utils } from '@noble/secp256k1';
import { PrivateKeyBytes, PublicKeyBytes } from '../types/shared.js';

/**
 * A compressed secp256k1 key pair
 * @export
 * @class KeyPair
 * @type {KeyPair}
 */
export class KeyPair {
  public type: string = 'secp256k1';
  public compressed: boolean = true;
  public prefix: Bytes;
  public x: PublicKeyBytes;
  public y: PublicKeyBytes;
  protected d: PrivateKeyBytes;

  /**
   * Creates an instance of KeyPair
   * @constructor
   * @param {PrivateKeyBytes} privateKey The private key bytes to use
   */
  constructor(privateKey?: PrivateKeyBytes) {
    if(!privateKey) console.info('KeyPair: No privateKey provided, generating new key pair');
    this.d = privateKey ?? this.generatePrivateKey();
    const publicKey = this.generatePublicKey(false);
    this.prefix = publicKey.slice(0, 1);
    this.x = publicKey.slice(1, 33);
    this.y = publicKey.slice(33, publicKey.length);
  }

  /**
   * Get the private key
   * @readonly
   * @returns {PrivateKeyBytes} The private key
   */
  get privateKey(): PrivateKeyBytes {
    if(!this.d) {
      throw new Error('Private key not set');
    }
    return this.d!;
  }

  get publicKey(): PublicKeyBytes {
    return this.generatePublicKey();
  }


  /**
   * Generate a new private key
   * @public
   * @returns {PrivateKeyBytes} A new private key
   */
  public generatePrivateKey(): PrivateKeyBytes {
    const privateKey = utils.randomPrivateKey();
    if(!utils.isValidPrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    return privateKey;
  }


  /**
   * Generates the public key for the corresponding private key
   * @public
   * @returns {PublicKeyBytes} The public key of the key pair
   */
  public generatePublicKey(compressed?: boolean): PublicKeyBytes {
    if(!this.privateKey) {
      throw new Error('Private key not set');
    }
    return getPublicKey(this.privateKey, compressed ?? this.compressed);
  }

  /**
   * Generate a new key pair
   * @static
   * @returns {KeyPair} A new key pair
   * @throws {Error} if the private key is invalid
   */
  public static generate(): KeyPair {
    const privateKey = utils.randomPrivateKey();
    if(!utils.isValidPrivateKey(privateKey)) {
      throw new Error('Invalid private key');
    }
    return new KeyPair(privateKey);
  };
}