import { schnorr } from '@noble/curves/secp256k1';
import { utils } from '@noble/secp256k1';
import { DidVerificationMethod } from '@web5/dids';
import { randomBytes } from 'crypto';
import { base58btc } from 'multiformats/bases/base58';
import { Btc1KeyManagerError } from './error.js';
import {
  Hex,
  MultikeyParams,
  PrivateKeyBytes,
  PublicKeyBytes,
  PublicKeyMultibase,
  SchnorrKeyPair,
  SchnorrSecp256k1Multikey
} from './types.js';
const SECP256K1_XONLY_PREFIX: Uint8Array = new Uint8Array([0xe1, 0x4a]);

/**
 * Implements section
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1/#multikey | 2.1.1 Multikey} of the
 * {@link https://dcdpr.github.io/data-integrity-schnorr-secp256k1 | Data Integrity Schnorr secp256k1 Cryptosuite} spec
 *
 * @export
 * @class Multikey
 * @type {Multikey}
 * @implements {SchnorrSecp256k1Multikey}
 */
export default class Multikey implements SchnorrSecp256k1Multikey {
  id: string;
  controller: string;
  privateKey?: PrivateKeyBytes;
  publicKey: PublicKeyBytes;

  /**
   * Creates an instance of Multikey.
   * @constructor
   * @param {MultikeyParams} params The parameters to create the multikey
   * @param {string} params.id The id of the multikey (required)
   * @param {string} params.controller The controller of the multikey (required)
   * @param {PrivateKeyBytes} params.privateKey The private key of the multikey (optional, required if publicKey is not provided)
   * @param {PublicKeyBytes} params.publicKey The public key of the multikey (optional, required if privateKey is not provided)
   * @throws {Btc1KeyManagerError} if no public or private key is provided
   */
  constructor({ id, controller, privateKey, publicKey }: MultikeyParams) {
    // If there is no public or private key, throw an error
    if (!publicKey && !privateKey) {
      throw new Btc1KeyManagerError('Must pass one of: publicKey, privateKey or both');
    }

    // Set the id and controller
    this.id = id;
    this.controller = controller;
    // If there is a private key, set it
    this.privateKey = privateKey;
    // If there is no public key, generate it. Otherwise, set it
    this.publicKey = privateKey
      ? schnorr.getPublicKey(privateKey)
      : publicKey;
  }

  /**
   * Produce signed data with a private key
   * @param {string} data Data to be signed
   * @returns {SignatureBytes} Signature byte array
   * @throws {Btc1KeyManagerError} if no private key is provided
   */
  sign(data: Hex): Uint8Array {
    // If there is no private key, throw an error
    if (!this.privateKey) {
      throw new Btc1KeyManagerError('No private key');
    }
    // Sign the data and return it
    return schnorr.sign(data, this.privateKey, randomBytes(32));
  }

  /**
   * Verify a signature
   * @param {string} message Data for verification
   * @param {Hex} signature Signature for verification
   * @returns {boolean} If the signature is valid against the public key
   */
  verify(message: Hex, signature: Hex): boolean {
    return schnorr.verify(signature, message, this.publicKey);
  }

  /**
   * Encode the public key in SchnorrSecp256k1 Multikey Format
   * @returns {PublicKeyMultibase} The encoded public key
   */
  encode(): PublicKeyMultibase {
    return MultikeyUtils.encode(this.publicKey);
  }

  /**
   * Decode the public key in SchnorrSecp256k1 Multikey Format
   * @param {PublicKeyMultibase} publicKeyMultibase The encoded public key
   * @returns {PublicKeyBytes} The encoded public key
   */
  decode(publicKeyMultibase: PublicKeyMultibase): PublicKeyBytes {
    return MultikeyUtils.decode(publicKeyMultibase);
  }

  /**
  * Get the full id of the multikey
  * @returns {string} The full id of the multikey
  */
  fullId(): string {
    if (this.id.startsWith('#')) {
      return `${this.controller}${this.id}`;
    }
    return this.id;
  }


  /**
   * Convert the multikey to a verification method
   * @returns {DidVerificationMethod} The verification method
   */
  toVerificationMethod(): DidVerificationMethod {
    return {
      id                 : this.id,
      type               : 'Multikey',
      controller         : this.controller,
      publicKeyMultibase : this.encode()
    };
  }

  /**
   *
   * Convert a verification method to a multikey
   * @param {DidVerificationMethod} verificationMethod The verification method to convert
   * @returns {Multikey} Multikey instance
   * @throws {Btc1KeyManagerError} if the verification method is missing required fields
   * @throws {Btc1KeyManagerError} if the verification method has an invalid type
   * @throws {Btc1KeyManagerError} if the publicKeyMultibase has an invalid prefix
   */
  fromVerificationMethod(verificationMethod: DidVerificationMethod): Multikey {
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
    const publicKeyBytes = base58btc.decode(publicKeyMultibase);
    const prefix = publicKeyBytes.slice(0, SECP256K1_XONLY_PREFIX.length);
    if (!prefix.every((b, i) => b === SECP256K1_XONLY_PREFIX[i])) {
      throw new Btc1KeyManagerError('Invalid publicKeyMultibase prefix');
    }
    const publicKey = publicKeyBytes.slice(SECP256K1_XONLY_PREFIX.length);
    return new Multikey({ id, controller, publicKey });
  }
}

export class MultikeyUtils {
  multikey?: Multikey;

  constructor(params?: MultikeyParams) {
    if(params) {
      this.multikey = new Multikey(params);
    }
  }
  /**
   * @static Helper function to easily generate a new keypair
   * @returns {SchnorrKeyPair} A new keypair
   * @throws {Error} if the private key is invalid
   */
  static generate(): SchnorrKeyPair {
    // Generate a random private key
    const privateKey = schnorr.utils.randomPrivateKey();
    // Ensure the private key is valid, throw an error if not valid
    if (!utils.isValidPrivateKey(privateKey)) {
      throw new Btc1KeyManagerError('Invalid private key generated');
    }
    // Generate public key from private key
    const publicKey = schnorr.getPublicKey(privateKey);
    // Return the keypair
    return { privateKey, publicKey };
  }

  /**
   * @static Helper function to decode a SchnorrSecp256k1 Multikey to public key bytes
   * @param {PublicKeyMultibase} publicKeyMultibase
   * @returns {PublicKeyBytes}
   */
  static decode(publicKeyMultibase: PublicKeyMultibase): PublicKeyBytes {
    const publicKey = base58btc.decode(publicKeyMultibase);
    const prefix = publicKey.subarray(0, 2);
    if (!prefix.every((b, i) => b === SECP256K1_XONLY_PREFIX[i])) {
      throw new Btc1KeyManagerError('Invalid publicKeyMultibase prefix');
    }
    return publicKey;
  }

  /**
   * @static Helper function to encode a secp256k1 key in SchnorrSecp256k1 Multikey Format
   * @param {PublicKeyBytes} xOnlyPublicKeyBytes
   * @returns {PublicKeyMultibase}
   */
  static encode(xOnlyPublicKeyBytes: PublicKeyBytes): any {
    if (xOnlyPublicKeyBytes.length !== 32) {
      throw new Btc1KeyManagerError('x-only public key must be 32 bytes');
    }
    // Encode the public key as a multibase base58btc string
    const multikeyBytes = new Uint8Array(SECP256K1_XONLY_PREFIX.length + 32);
    // Set the prefix
    multikeyBytes.set(SECP256K1_XONLY_PREFIX, 0);
    // Set the public key
    multikeyBytes.set(xOnlyPublicKeyBytes, SECP256K1_XONLY_PREFIX.length);
    // return the encoded public key
    return base58btc.encode(multikeyBytes);
  }
}