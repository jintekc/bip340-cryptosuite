function decimalToHex(num: number): string {
  return '0x' + num.toString(16);
}

function varintEncode(num: number): Uint8Array {
  const bytes: number[] = [];
  while (true) {
    let tmp = num & 0x7f;   // Take lower 7 bits
    num >>>= 7;            // Shift right 7 bits
    if (num === 0) {
      bytes.push(tmp);
      break;
    } else {
      bytes.push(tmp | 0x80); // Set continuation bit
    }
  }
  return new Uint8Array(bytes);
}

const SECP256K1_XONLY_PREFIX: Uint8Array = new Uint8Array([0xe1, 0x4a]);

// 1) Start with decimal 9569
const decimalValue = 9569;

// 2) Convert to hex (0x2561)
const hexValue = decimalToHex(decimalValue);
console.log('Decimal 9569 => Hex:', hexValue); // 0x2561

// 3) Varint-encode => [0xe1, 0x4a]
const varintBytes = varintEncode(decimalValue);
console.log('varintBytes', varintBytes);
const varintHex = [...varintBytes].map(b => '0x' + b.toString(16));
console.log('varintHex', varintHex);

console.log('SECP256K1_XONLY_PREFIX', SECP256K1_XONLY_PREFIX);
console.log('Varint-encoded bytes:', [...varintBytes].map(b => '' + b.toString(16)));
// [ '0xe1', '0x4a' ]
