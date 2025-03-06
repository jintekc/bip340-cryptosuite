import { schnorr } from '@noble/curves/secp256k1';
import { DidVerificationMethod } from '@web5/dids';
import { randomBytes } from 'crypto';
import { base58btc } from 'multiformats/bases/base58';
import { KeyPair } from '../../keys/key-pair.js';
import { PrivateKey } from '../../keys/private-key.js';
import { PublicKey } from '../../keys/public-key.js';
import { Hex, SignatureBytes } from '../../types/shared.js';
import { MultikeyError } from '../../utils/error.js';
import { FromPrivateKey, FromPublicKey, IMultikey, MultikeyParams } from './interface.js';
import { SECP256K1_XONLY_PREFIX } from '../../keys/constants.js';

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
  /** @type {string} The verification metod type */
  public static readonly type: string = 'Multikey';

  /** @type {string} The id references which key to use for various operations in the DID Document */
  public readonly id: string;

  /** @type {string} The controller is the DID that controls the keys and information in the DID DOcument */
  public readonly controller: string;

  /** @type {PrivateKeyBytes} The private key bytes for the multikey (optional) */
  // private readonly _privateKey?: PrivateKeyBytes;
  private readonly _keyPair: KeyPair;

  /**
   * Creates an instance of Multikey.
   * @constructor
   * @param {MultikeyParams} params The parameters to create the multikey
   * @param {string} params.id The id of the multikey (required)
   * @param {string} params.controller The controller of the multikey (required)
   * @param {KeyPair} params.keypair The keypair of the multikey (optional, required if no publicKey)
   * @param {PublicKeyBytes} params.keypair.publicKey The public key of the multikey (optional, required if no privateKey)
   * @param {PrivateKeyBytes} params.keypair.privateKey The private key of the multikey (optional)
   * @throws {MultikeyError} if neither a publicKey nor a privateKey is provided
   */
  constructor({ id, controller, keyPair }: MultikeyParams) {
    // If no keypair passed, throw an error
    if (!keyPair) {
      throw new MultikeyError('Argument missing: "keyPair" required', 'MULTIKEY_CONSTRUCTOR_ERROR');
    }

    // If the keypair does not have a public key, throw an error
    if(!keyPair.publicKey) {
      throw new MultikeyError('Argument missing: "keyPair" must contain a "publicKey"', 'MULTIKEY_CONSTRUCTOR_ERROR');
    }

    // Set the class variables
    this.id = id;
    this.controller = controller;
    this._keyPair = keyPair;
  }

  /** @see IMultikey.keyPair */
  get keyPair(): KeyPair {
    // Return a copy of the keypair
    const keyPair = this._keyPair;
    return keyPair;
  }

  /** @see IMultikey.publicKey */
  get publicKey(): PublicKey {
    // Create and return a copy of the keyPair.publicKey
    const publicKey = this.keyPair.publicKey;
    return publicKey;
  }

  /** @see IMultikey.privateKey */
  get privateKey(): PrivateKey {
    // Create and return a copy of the keyPair.privateKey
    const privateKey = this.keyPair.privateKey;
    // If there is no private key, throw an error
    if(!this.isSigner) {
      throw new MultikeyError('Cannot get: no privateKey', 'MULTIKEY_PRIVATE_KEY_ERROR');
    }
    return privateKey;
  }

  /** @see IMultikey.sign */
  public sign(data: Hex): SignatureBytes {
    // If there is no private key, throw an error
    if (!this.isSigner) {
      throw new MultikeyError('Cannot sign: no privateKey', 'MULTIKEY_SIGN_ERROR');
    }
    // Sign the hashb and return it
    return schnorr.sign(data, this.privateKey.raw, randomBytes(32));
  }

  /** @see IMultikey.verify */
  public verify(signature: SignatureBytes, data: Hex): boolean {
    // Verify the signature and return the result
    return schnorr.verify(signature, data, this.publicKey.x);
  }

  /** @see IMultikey.fullId */
  public fullId(): string {
    // If the id starts with "#", return concat(controller, id); else return id
    return this.id.startsWith('#') ? `${this.controller}${this.id}` : this.id;
  }

  /** @see IMultikey.toVerificationMethod */
  public toVerificationMethod(): DidVerificationMethod {
    // Construct and return the verification method
    return {
      id                 : this.id,
      type               : Multikey.type,
      controller         : this.controller,
      publicKeyMultibase : this.publicKey.multibase
    };
  }

  /** @see IMultikey.fromVerificationMethod */
  public fromVerificationMethod(verificationMethod: DidVerificationMethod): Multikey {
    const VM_ERROR = 'MULTIKEY_VERIFICATION_METHOD_ERROR';

    // Destructure the verification method
    const { id, type, controller, publicKeyMultibase } = verificationMethod;

    // Check if the required field id is missing
    if (!id) {
      throw new MultikeyError('Invalid verificationMethod: "id" required', VM_ERROR);
    }

    // Check if the required field controller is missing
    if (!controller) {
      throw new MultikeyError('Invalid verificationMethod: "controller" required', VM_ERROR);
    }

    // Check if the required field publicKeyMultibase is missing
    if (!publicKeyMultibase) {
      throw new MultikeyError('Invalid verificationMethod: "publicKeyMultibase" required', VM_ERROR);
    }

    // Check if the type is not Multikey
    if (type !== 'Multikey') {
      throw new MultikeyError('Invalid verificationMethod: "type" should be "Multikey"', VM_ERROR);
    }

    // Decode the public key multibase
    const publicKeyMultibaseBytes = base58btc.decode(publicKeyMultibase);
    console.log('publicKeyMultibaseBytes', publicKeyMultibaseBytes);
    // Check if the prefix is correct
    const prefix = publicKeyMultibaseBytes.slice(0, SECP256K1_XONLY_PREFIX.length);
    if (!prefix.every((b, i) => b === SECP256K1_XONLY_PREFIX[i])) {
      throw new MultikeyError('Invalid publicKeyMultibase: incorrect prefix', VM_ERROR);
    }

    // Slice off the prefix to get just the 32-byte public key
    const noPrefix = Array.from(publicKeyMultibaseBytes.slice(SECP256K1_XONLY_PREFIX.length));

    // Create a new public key bytes array with the parity byte added
    const publicKeyBytes = new Uint8Array([this.keyPair.publicKey.prefix, ...noPrefix]);

    // Instantiate a new PublicKey
    const publicKey = new PublicKey(publicKeyBytes);

    // Return a new Multikey instance
    return new Multikey({ id, controller, keyPair: new KeyPair({ publicKey }) });
  }


  /** @see IMultikey.isSigner */
  get isSigner(): boolean {
    return !!this.keyPair.privateKey;
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
    const keyPair = KeyPair.fromPrivateKey(privateKey);
    return new Multikey({ id, controller, keyPair });
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
    const keyPair = new KeyPair({ publicKey: new PublicKey(publicKey) });
    return new Multikey({ id, controller, keyPair });
  }
}