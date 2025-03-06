export class Btc1KeyManagerError extends Error {
  name: string = 'Btc1KeyManagerError';
  type: string = 'Btc1KeyManagerError';
  message: string;

  constructor(message: string, type?: string, name?: string) {
    super();
    this.type = type ?? this.type;
    this.name = name ?? this.name;
    this.message = message;
  }
}

export class CryptosuiteError extends Btc1KeyManagerError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'CryptosuiteError', 'CryptosuiteError');
  }
}

export class KeyPairError extends Btc1KeyManagerError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'KeyPairError', 'KeyPairError');
  }
}

export class PrivateKeyError extends Btc1KeyManagerError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'PrivateKeyError', 'PrivateKeyError');
  }
}

export class PublicKeyError extends Btc1KeyManagerError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'PublicKeyError', 'PublicKeyError');
  }
}

export class MultikeyError extends Btc1KeyManagerError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'MultikeyError', 'MultikeyError');
  }
}

export class ProofError extends Btc1KeyManagerError {
  constructor(message: string, type?: string) {
    super(message, type ?? 'ProofError', 'ProofError');
  }
}