import { markError, markSuccess } from '../providers/types.js';
import { pwnedPasswords } from '../providers/index.js';

/**
 * Proxy a Pwned Passwords range query. Accepts ONLY a 5-hex-char prefix. The
 * plaintext password and full hash stay in the browser.
 */
export async function fetchHashRange(prefix: string): Promise<string> {
  try {
    const body = await pwnedPasswords.fetchRange(prefix);
    markSuccess(pwnedPasswords.id);
    return body;
  } catch (err) {
    markError(pwnedPasswords.id, err);
    throw err;
  }
}
