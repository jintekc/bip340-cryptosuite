/* Fixed header bytes per the spec for a BIP-340 Multikey */
export const SECP256K1_XONLY_PREFIX: Uint8Array = new Uint8Array([0xe1, 0x4a]);

export const B256 = 2n ** 256n;
// curve's field prime
export const P = B256 - 0x1000003d1n;
// curve (group) order
export const N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
// base point x
export const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
// base point y
export const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

export const CURVE = {
  p : P,
  n : N,
  a : 0n,
  b : 7n,
  Gx,
  Gy
};