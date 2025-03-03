import { schnorr } from '@noble/curves/secp256k1';
import { DidVerificationMethod } from '@web5/dids';
import { randomBytes } from 'crypto';
import { base58btc } from 'multiformats/bases/base58';
import { KeyPair } from '../../crypto/key-pair.js';
import { PrivateKey } from '../../crypto/private-key.js';
import { PublicKey } from '../../crypto/public-key.js';
import { HashBytes, PrivateKeyBytes, PublicKeyBytes, SignatureBytes } from '../../types/shared.js';
import { Btc1KeyManagerError } from '../../utils/error.js';
import { IMultikey } from './interface.js';
import { MultikeyUtils, SECP256K1_XONLY_PREFIX } from './utils.js';

interface DidParams {
  id: string;
  controller: string;
}

interface FromPrivateKey extends DidParams {
  privateKey: PrivateKeyBytes
}
interface FromPublicKey extends DidParams {
  publicKey: PublicKeyBytes
}
export interface MultikeyParams extends DidParams {
  keyPair?: KeyPair;
  publicKey?: PublicKey;
}

/**
 * Implements section
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#multikey | 2.1.1 Multikey} of the
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1 | Data Integrity Bip340 Cryptosuite} spec
 * @export
 * @class Multikey
 * @type {Multikey}
 * @implements {Multikey}
 */
export class Multikey implements IMultikey {
  /** @type {string} The id references which key to use for various operations in the DID Document */
  public readonly id: string;

  /** @type {string} The controller is the DID that controls the keys and information in the DID DOcument */
  public readonly controller: string;

  /** @type {PrivateKeyBytes} The private key bytes for the multikey (optional) */
  // private readonly _privateKey?: PrivateKeyBytes;
  private readonly _keyPair?: KeyPair;

  /** @type {PublicKey} The private key bytes for the multikey */
  private _publicKey?: PublicKey;

  /**
   * Creates an instance of Multikey.
   * @constructor
   * @param {MultikeyParams} params The parameters to create the multikey
   * @param {string} params.id The id of the multikey (required)
   * @param {string} params.controller The controller of the multikey (required)
   * @param {KeyPair} params.keypair The keypair of the multikey (optional, required if no publicKey)
   * @param {PublicKeyBytes} params.keypair.publicKey The public key of the multikey (optional, required if no privateKey)
   * @param {PrivateKeyBytes} params.keypair.privateKey The private key of the multikey (optional)
   * @throws {Btc1KeyManagerError} if neither a publicKey nor a privateKey is provided
   */
  constructor({ id, controller, keyPair, publicKey }: MultikeyParams) {
    // If there is no public or private key, throw an error
    if (!keyPair && !publicKey) {
      throw new Btc1KeyManagerError('Must pass keyPair, publicKey or both');
    }

    // Set the class variables
    this.id = id;
    this.controller = controller;
    this._keyPair = keyPair;

    // Do a gut check on ketPair.publicKey and publicKey if both are passed
    if((keyPair && publicKey) && !keyPair.publicKey.equals(publicKey)) {
      throw new Btc1KeyManagerError('Mismatching keyPair.publicKey and publicKey', 'PUBLIC_KEY_MISMATCH');
    }

    // Set the public key
    this._publicKey = keyPair ? keyPair.publicKey : publicKey;
  }

  /** @see IMultikey.privateKey */
  get privateKey(): PrivateKey {
    if(!this._keyPair) {
      throw new Btc1KeyManagerError('No private key provided', 'PRIVATE_KEY_ERROR');
    }
    return this._keyPair?.privateKey;
  }

  /** @see IMultikey.publicKey */
  get publicKey(): PublicKey {
    if (!this._publicKey && !this.privateKey) {
      throw new Btc1KeyManagerError('No public key provided and no private key available', 'PUBLIC_KEY_ERROR');
    }

    if (!this.privateKey || !this._publicKey) {
      throw new Btc1KeyManagerError('No public key provided and no private key available', 'PUBLIC_KEY_ERROR');
    }
    return this._publicKey ? new PublicKey(this._publicKey.compressed) : this.privateKey.toPublicKey();
  }

  /** @see IMultikey.sign */
  public sign(hashb: HashBytes): SignatureBytes {
    // If there is no private key, throw an error
    if (!this.privateKey) {
      throw new Btc1KeyManagerError('Signing error: Private key is required to sign');
    }
    // Sign the hashb and return it
    return schnorr.sign(hashb, this.privateKey.compressed, randomBytes(32));
  }

  /** @see IMultikey.verify */
  public verify(message: HashBytes, signature: SignatureBytes): boolean {
    // Verify the signature and return the result
    return schnorr.verify(signature, message, this.publicKey.x);
  }

  /** @see IMultikey.encode */
  public encode(): string {
    // Encode the public key and return it
    return this.publicKey.multibase();
  }

  /** @see IMultikey.decode */
  public decode(): PublicKey {
    // Decode the public key and return it
    return MultikeyUtils.decode(this.publicKey.multibase());
  }

  /** @see IMultikey.fullId */
  public fullId(): string {
    // If the id starts with a #, return concat of controller and id no #
    // Else, return the id
    return this.id.startsWith('#') ? `${this.controller}${this.id}` : this.id;
  }

  /** @see IMultikey.toVerificationMethod */
  public toVerificationMethod(): DidVerificationMethod {
    // Return the verification method
    return {
      id                 : this.id,
      type               : 'Multikey',
      controller         : this.controller,
      publicKeyMultibase : this.encode()
    };
  }

  /** @see IMultikey.fromVerificationMethod */
  public fromVerificationMethod(verificationMethod: DidVerificationMethod): Multikey {
    // Destructure the verification method
    const { id, type, controller, publicKeyMultibase } = verificationMethod;

    // Check if the required field id is missing
    if (!id) {
      throw new Btc1KeyManagerError('Verification method missing id');
    }

    // Check if the required field controller is missing
    if (!controller) {
      throw new Btc1KeyManagerError('Verification method missing controller');
    }

    // Check if the required field publicKeyMultibase is missing
    if (!publicKeyMultibase) {
      throw new Btc1KeyManagerError('Verification method missing publicKeyMultibase');
    }

    // Check if the type is not Multikey
    if (type !== 'Multikey') {
      throw new Btc1KeyManagerError('Verification method has an invalid type');
    }

    // Decode the public key multibase
    const publicKeyBytes = base58btc.decode(publicKeyMultibase);

    // Check if the prefix is correct
    const prefix = publicKeyBytes.slice(0, SECP256K1_XONLY_PREFIX.length);
    if (!prefix.every((b, i) => b === SECP256K1_XONLY_PREFIX[i])) {
      throw new Btc1KeyManagerError('Invalid publicKeyMultibase prefix');
    }

    // Get the publicKey by slicing off the prefix and return the multikey
    const publicKey = publicKeyBytes.slice(SECP256K1_XONLY_PREFIX.length);
    return new Multikey({ id, controller, publicKey: new PublicKey(publicKey) });
  }

  /**
   * Returns true if this Multikey has a private key
   * @readonly
   * @type {boolean} True if this Multikey has a private key
   */
  get isSigner(): boolean {
    return !!this._keyPair;
  }

  /**
   * Creates a `Multikey` instance from a private key
   * @public @static
   * @param {FromPublicKey} params The parameters to create the multikey
   * @param {string} params.id The id of the multikey
   * @param {string} params.controller The controller of the multikey
   * @param {PrivateKeyBytes} params.privateKey The private key bytes for the multikey
   * @returns {Multikey} The new multikey instance
   */
  public static fromPrivateKey({ id, controller, privateKey }: FromPrivateKey): Multikey {
    return new Multikey({ id, controller, keyPair: new KeyPair(new PrivateKey(privateKey)) });
  }

  /**
   * Creates a `Multikey` instance from a public key
   * @public @static
   * @param {FromPublicKey} params The parameters to create the multikey
   * @param {string} params.id The id of the multikey
   * @param {string} params.controller The controller of the multikey
   * @param {PublicKeyBytes} params.publicKey The public key bytes for the multikey
   * @returns {Multikey} The new multikey instance
   */
  public static fromPublicKey({ id, controller, publicKey }: FromPublicKey): Multikey {
    return new Multikey({ id, controller, publicKey: new PublicKey(publicKey) });
  }
}