import * as jcs from '@web5/crypto';

import { Cryptosuite } from './di-bip340/cryptosuite/index.js';
import { DataIntegrityProof } from './di-bip340/data-integrity-proof/index.js';
import { Multikey } from './di-bip340/multikey/index.js';
import { CryptosuiteType } from './types/cryptosuite.js';
import { PrivateKeyBytes } from './types/shared.js';
import { KeyPair } from './utils/keypair.js';
import { sha256 } from '@noble/hashes/sha256';
import { base58btc } from 'multiformats/bases/base58';

interface Btc1KeyManagerParams {
    multikey: Multikey;
    proof: DataIntegrityProof;
}

interface InitializeKeyManager {
    fullId: string;
    privateKey?: PrivateKeyBytes;
    type?: CryptosuiteType;
}
interface IBtc1KeyManager {
    multikey: Multikey;
    proof: DataIntegrityProof;
    // digest(): Promise<Uint8Array>;
    // exportKey(): Promise<KeyPair>;
    // generateKey(): Promise<PrivateKeyBytes>;
    // getKeyUri(): Promise<void>;
    // getPublicKey(): Promise<PublicKeyBytes>;
    // importKey(): Promise<void>;
    // sign(): Promise<void>;
    // verify(): Promise<void>;
}

export class Btc1KeyManager implements IBtc1KeyManager {
  public multikey: Multikey;
  public proof: DataIntegrityProof;

  constructor({ multikey, proof }: Btc1KeyManagerParams) {
    this.multikey = multikey;
    this.proof = proof;
  }

  public async digest(): Promise<Uint8Array> {
    return new Uint8Array();
  }
  //   public async exportKey(): Promise<KeyPair> {}
  //   public async generateKey(): Promise<PrivateKeyBytes> {}
  //   public async getKeyUri(): Promise<void> {}
  //   public async getPublicKey(): Promise<PublicKeyBytes> {}
  //   public async importKey(): Promise<void> {}
  //   public async sign(): Promise<void> {}
  //   public async verify(): Promise<void> {}

  public computeFingerprint(keyPair: KeyPair): string {
    if (!keyPair || !keyPair.publicKey || !keyPair.privateKey) {
      throw new Error('Invalid KeyPair provided');
    }

    // Ensure canonicalization by using the compressed public key
    const canonicalKeyPair = jcs.canonicalize(keyPair);

    // Hash the canonical public key
    const hash = sha256(canonicalKeyPair);

    // Encode the hash using Base58
    return base58btc.encode(hash);
  }

  public static initialize({ fullId, type, privateKey }: InitializeKeyManager): Btc1KeyManager {
    if(!fullId) {
      throw new Error('Must provide a fullId');
    }
    type ??= 'schnorr-secp256k1-jcs-2025';
    privateKey ??= new KeyPair().privateKey;
    const [id, controller] = fullId.split('#');
    const multikey = new Multikey({ id: `#${id}`, controller, privateKey });
    const cryptosuite = new Cryptosuite({ cryptosuite: type, multikey });
    const proof = new DataIntegrityProof(cryptosuite);
    return new Btc1KeyManager({ multikey, proof });
  }
}