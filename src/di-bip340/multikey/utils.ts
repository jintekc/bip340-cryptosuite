import { schnorr } from '@noble/curves/secp256k1';
import { utils } from '@noble/secp256k1';
import { base58btc } from 'multiformats/bases/base58';
import { PublicKeyBytes, SchnorrKeyPair } from '../../types/shared.js';
import { Btc1KeyManagerError } from '../../utils/error.js';

/* Fixed header bytes per the spec for a BIP-340 Multikey */
export const SECP256K1_XONLY_PREFIX: Uint8Array = new Uint8Array([0xe1, 0x4a]);

/**
 * Utility class for Multikey operations/
 *
 * @export
 * @class MultikeyUtils
 * @type {MultikeyUtils}
 */
export class MultikeyUtils {
  /**
     * @static Helper function to easily generate a new keypair
     * @returns {SchnorrKeyPair} A new keypair
     * @throws {Error} if the private key is invalid
     */
  public static generate(): SchnorrKeyPair {
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
     * @returns {PublicKey}
     */
  public static decode(publicKeyMultibase: string): PublicKeyBytes {
    const publicKeyBytes = base58btc.decode(publicKeyMultibase);
    const prefix = publicKeyBytes.subarray(0, 2);
    if (!prefix.every((b, i) => b === SECP256K1_XONLY_PREFIX[i])) {
      throw new Btc1KeyManagerError('Invalid publicKeyMultibase prefix');
    }
    return publicKeyBytes;
  }

  /**
     * @static Helper function to encode a secp256k1 key in SchnorrSecp256k1 Multikey Format
     * @param {PublicKeyBytes} xOnlyPublicKeyBytes
     * @returns {PublicKeyMultibase}
     */
  public static encode(xOnlyPublicKeyBytes: PublicKeyBytes): string {
    if (xOnlyPublicKeyBytes.length !== 32) {
      throw new Btc1KeyManagerError('x-only public key must be 32 bytes');
    }
    // Set the prefix and the public key bytes
    const multikeyBytes = new Uint8Array([...Array.from(SECP256K1_XONLY_PREFIX), ...Array.from(xOnlyPublicKeyBytes)]);
    // Encode the public key as a multibase base58btc string
    return base58btc.encode(multikeyBytes);
  }
}