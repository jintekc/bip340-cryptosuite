export default class ObjectUtils extends Object {
  /**
   * Recursively checks deep equality of all keys, values, nested objects and arrays of
   * JSON objects using strict equality checks. Handles arrays as objects with numeric keys.
   * @static
   * @param {*} a
   * @param {*} b
   * @returns {boolean}
   */
  static deepEqual(a: any, b: any): boolean {
    // If they're strictly equal, they're immediately the same (handles primitives as well).
    if (a === b) return true;

    // If either is null or their types differ, they can't be equal.
    if (a === null || b === null || typeof a !== typeof b) return false;

    // If both are objects, compare their properties
    if (typeof a === 'object') {
      // Check if they're both arrays
      const isArrayA = Array.isArray(a);
      const isArrayB = Array.isArray(b);
      if (isArrayA !== isArrayB) return false;

      if (isArrayA && isArrayB) {
        // Compare array lengths first
        if (a.length !== b.length) return false;
        // Compare each array element
        for (let i = 0; i < a.length; i++) {
          if (!this.deepEqual(a[i], b[i])) return false;
        }
        return true;
      } else {
        // Compare object keys
        const keysA = Object.keys(a);
        const keysB = Object.keys(b);
        if (keysA.length !== keysB.length) return false;

        // Compare each key's value
        for (const key of keysA) {
          if (!Object.prototype.hasOwnProperty.call(b, key)) {
            return false;
          }
          if (!this.deepEqual(a[key], b[key])) {
            return false;
          }
        }
        return true;
      }
    }

    // Otherwise, they're different primitives (e.g. number vs. string)
    return false;
  }

}