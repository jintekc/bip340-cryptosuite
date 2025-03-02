import { PrivateKeyBytes } from '../src/types/shared.js';
import { KeyPair } from '../src/utils/keypair.js';

const genKeyPair = (privateKey?: PrivateKeyBytes) => {
  return new KeyPair(privateKey);
};
console.log(genKeyPair());