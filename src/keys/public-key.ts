import { sha256 } from '@noble/hashes/sha256';
import { base58btc } from 'multiformats/bases/base58';
import * as tinysecp from 'tiny-secp256k1';
import { Hex, PrefixBytes, PrivateKeyBytes, PublicKeyBytes, PublicKeyMultibaseBytes } from '../types/shared.js';
import { PublicKeyError } from '../utils/error.js';
import { BIP340_MULTIKEY_PREFIX, BIP340_MULTIKEY_PREFIX_HASH, CURVE } from './constants.js';
import { IPublicKey } from './interface.js';
import { PrivateKey, PrivateKeyUtils } from './private-key.js';

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
  /** @type {PublicKeyUtils} Static PublicKeyUtils class instance */
  public utils: PublicKeyUtils = new PublicKeyUtils();

  /** @type {PublicKeyBytes} The Uint8Array public key */
  private readonly _bytes: PublicKeyBytes;

  /**
   * Creates an instance of PublicKey.
   * @constructor
   * @param {PublicKeyBytes} bytes The public key byte array.
   * @throws {PublicKeyError} if the byte length is not 32 (x-only) or 33 (compressed)
   */
  constructor(bytes: PublicKeyBytes) {
    // If the byte length is not 32 or 33, throw an error
    const bytelength = bytes.length;
    if(![32, 33].includes(bytelength)) {
      throw new PublicKeyError(
        'Invalid argument: byte length must be 32 (x-only) or 33 (compressed)',
        'PUBLIC_KEY_CONSTRUCTOR_ERROR'
      );
    }
    // If the byte length is 32, prepend the parity byte, else set the bytes
    this._bytes = bytelength === 32
      ? new Uint8Array([0x02, ...Array.from(bytes)])
      : bytes;
  }

  /** @see IPublicKey.compressed */
  get compressed(): Uint8Array {
    return new Uint8Array(this._bytes);
  }

  /** @see IPublicKey.uncompressed */
  get uncompressed(): PublicKeyBytes {
    return this.utils.liftX(this.x);
  }

  /** @see IPublicKey.parity */
  get parity(): number {
    const parityb = this.compressed[0];
    return parityb;
  }

  /** @see IPublicKey.x */
  get x(): PublicKeyBytes {
    return this.compressed.slice(1, 33);
  }

  /** @see IPublicKey.y */
  get y(): PublicKeyBytes {
    return this.uncompressed.slice(33, 65);
  }

  /** @see IPublicKey.multibase */
  get multibase(): string {
    return this.encodeMultibase();
  }

  /** @see IPublicKey.prefix */
  get prefix(): PrefixBytes {
    return this.decodeMultibase().subarray(0, 2);
  }

  /**
   * Decodes the multibase string to the 34-byte corresponding public key (2 byte prefix + 32 byte public key).
   * @static
   * @returns {PublicKeyMultibaseBytes} The decoded public key: prefix and public key bytes
   */
  public decodeMultibase(): PublicKeyMultibaseBytes {
    // Decode the public key multibase string
    const multibase = base58btc.decode(this.multibase);

    // If the public key bytes are not 34 bytes, throw an error
    if(multibase.length !== 34) {
      throw new PublicKeyError('Invalid argument: must be 34 byte publicKeyMultibase', 'DECODE_PUBLIC_KEY_ERROR');
    }

    // Grab the prefix bytes
    const prefix = multibase.subarray(0, 2);
    // Compute the prefix hash
    const prefixHash = Buffer.from(sha256(prefix)).toString('hex');

    // If the prefix hash does not equal the BIP340 prefix hash, throw an error
    if (prefixHash !== BIP340_MULTIKEY_PREFIX_HASH) {
      throw new PublicKeyError(`Invalid prefix: malformed multibase prefix ${prefix}`, 'DECODE_PUBLIC_KEY_ERROR');
    }

    // Return the decoded public key bytes
    return multibase;
  }

  /**
   * Encode the PublicKey bytes to bip340 multibase format (34 bytes = 2 bytes header + 32 byte x-coordinate).
   * @static
   * @returns {string} The public key x-coord bytes prefixed with bip340 header base58btc encoded.
   */
  public encodeMultibase(): string {
    // Create a local copy of the public key x-coordinate to avoid mutation
    const xCoordinate = this.x;

    // Ensure the public key is schnorr x-only (32 bytes)
    if (xCoordinate.length !== 32) {
      throw new PublicKeyError('Invalid argument: must be x-only public key (32 bytes)', 'ENCODE_PUBLIC_KEY_ERROR');
    }

    // Convert the prefix and public key bytes to arrays and dump into new Uint8Array
    const multikeyBytes = new Uint8Array([...Array.from(BIP340_MULTIKEY_PREFIX), ...Array.from(xCoordinate)]);

    // Encode as a multibase base58btc string
    return base58btc.encode(multikeyBytes);
  }

  /**
   * Public key hex getter.
   * @returns {Hex} The public key as a hex string.
   */
  public hex(): Hex {
    return Buffer.from(this.compressed).toString('hex');
  }

  /**
   * Public key equality check. Checks if `this` public key is equal to `other` public key.
   * @param {PublicKey} other The public key to compare.
   * @returns {boolean} True if the public keys are equal.
   */
  public equals(other: PublicKey): boolean {
    return this.hex() === other.hex();
  }

  /**
   * Public key JSON representation.
   * @returns {object} The public key as a JSON object.
   */
  public json(): object {
    return {
      parity    : this.parity,
      x         : this.x,
      y         : this.y,
      multibase : this.multibase,
      prefix    : this.prefix,
    };
  }

  /**
   * Generates a new PublicKey from random public key bytes.
   * @see IPublicKey.generate
   */
  public generate(): PublicKey {
    return PublicKeyUtils.generate();
  }

  /**
   * Generates new random public key bytes.
   * @see IPublicKey.random
   */
  public random(): PublicKeyBytes {
    return PublicKeyUtils.random();
  }

}

/**
 * Utility class for Multikey operations/
 * @export
 * @class PublicKeyUtils
 * @type {PublicKeyUtils}
 */
export class PublicKeyUtils {
  /**
   * Computes the deterministic public key for a given private key.
   * @static
   * @param {PrivateKey | PrivateKeyBytes} pk The PrivateKey object or the private key bytes
   * @returns {PublicKey} A new PublicKey object
   */
  public static fromPrivateKey(pk: PrivateKeyBytes): PublicKey {
    // If the private key is a PrivateKey object, get the raw bytes else use the bytes
    const bytes = pk instanceof PrivateKey ? pk.bytes : pk;

    // Throw error if the private key is not 32 bytes
    if(bytes.length !== 32) {
      throw new PublicKeyError('Invalid arg: must be 32 byte private key', 'FROM_PRIVATE_KEY_ERROR');
    }

    // Compute the public key from the private key
    const privateKey = pk instanceof PrivateKey ? pk : new PrivateKey(pk);

    // Return a new PublicKey object
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
   * Computes modular exponentiation: (base^exp) % mod.
   * Used for computing modular square roots.
   * @static
   * @param {bigint} base The base value
   * @param {bigint} exp The exponent value
   * @param {bigint} mod The modulus value
   * @returns {bigint} The result of the modular exponentiation
   */
  public modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  };

  /**
   * Computes `sqrt(a) mod p` using Tonelli-Shanks algorithm.
   * This finds `y` such that `y^2 ≡ a mod p`.
   * @static
   * @param {bigint} a The value to find the square root of
   * @param {bigint} p The prime modulus
   * @returns {bigint} The square root of `a` mod `p`
   */
  public sqrtMod(a: bigint, p: bigint): bigint {
    return this.modPow(a, (p + 1n) >> 2n, p);
  };

  /**
   * Lifts a 32-byte x-only coordinate into a full secp256k1 point (x, y).
   * @param xBytes 32-byte x-coordinate
   * @returns {Uint8Array} 65-byte uncompressed public key (starts with `0x04`)
   */
  public liftX(xBytes: Uint8Array): Uint8Array {
    // Ensure x-coordinate is 32 bytes
    if (xBytes.length !== 32) {
      throw new PublicKeyError('Invalid argument: x-coordinate length must be 32 bytes', 'LIFT_X_ERROR');
    }

    // Convert x from Uint8Array → BigInt
    const x = BigInt('0x' + Buffer.from(xBytes).toString('hex'));
    if (x <= 0n || x >= CURVE.p) {
      throw new PublicKeyError('Invalid conversion: x out of range as BigInt', 'LIFT_X_ERROR');
    }

    // Compute y² = x³ + 7 mod p
    const ySquared = BigInt((x ** 3n + CURVE.b) % CURVE.p);

    // Compute y (do not enforce parity)
    const y = this.sqrtMod(ySquared, CURVE.p);

    // Convert x and y to Uint8Array
    const yBytes = Buffer.from(y.toString(16).padStart(64, '0'), 'hex');

    // Return 65-byte uncompressed public key: `0x04 || x || y`
    return new Uint8Array(Buffer.concat([Buffer.from([0x04]), Buffer.from(xBytes), yBytes]));
  };
}