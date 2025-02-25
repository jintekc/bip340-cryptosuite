export class Btc1KeyManagerError extends Error {
  name: string;
  type: string;
  message: string;

  constructor(message: string, type: string = 'Btc1KeyManagerError') {
    super();
    this.name = 'Btc1KeyManagerError';
    this.type = type;
    this.message = message;
  }
}