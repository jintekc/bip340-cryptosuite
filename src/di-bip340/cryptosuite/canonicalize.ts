import { CanonicalizableObject } from '../../types/cryptosuite.js';
import rdfc from 'rdf-canonize';

export type JSONObject = { [key: string]: any };

export class Canonicalize {
  /**
   * Canonicalizes a given object according to RFC 8785 (https://tools.ietf.org/html/rfc8785),
   * which describes JSON Canonicalization Scheme (JCS). This function sorts the keys of the
   * object and its nested objects alphabetically and then returns a stringified version of it.
   * This method handles nested objects, array values, and null values appropriately.
   *
   * @param object - The object to canonicalize.
   * @returns The stringified version of the input object with its keys sorted alphabetically
   * per RFC 8785.
   */
  public static jcs(object: CanonicalizableObject): string {
    /**
     * Recursively sorts the keys of an object.
     * @param {CanonicalizableObject} object The object whose keys are to be sorted.
     * @returns {Promise<string>} A new object with sorted keys.
     */
    const sortObjKeys = (object: JSONObject): JSONObject => {
      if (object !== null && typeof object === 'object' && !Array.isArray(object)) {
        const sortedKeys = Object.keys(object).sort();
        const sortedObj: { [key: string]: any } = {};
        for (const key of sortedKeys) {
          // Recursively sort keys of nested objects.
          sortedObj[key] = sortObjKeys(object[key]);
        }
        return sortedObj;
      }
      return object;
    };

    // Stringify and return the final sorted object.
    const sortedObj = sortObjKeys(object);
    return JSON.stringify(sortedObj);
  }


  /**
   * Canonicalizes a given object according to RDF Canonicalization (RDFC) 1.0
   * @public
   * @static
   * @param {CanonicalizableObject} object
   * @returns {Promise<string>}
   */
  public static async rdfc(object: CanonicalizableObject, algorithm: string): Promise<string> {
    return await rdfc.canonize([object], { algorithm });
  }
}