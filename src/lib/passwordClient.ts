import { buildPasswordResult, parseRangeResponse } from '../../shared/passwordCheck';
import type { PasswordCheckResult } from '../../shared/types';
import { api } from '../api';

/** SHA-1 hex (uppercase) computed locally via Web Crypto. */
export async function sha1Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/**
 * Privacy-preserving password check. Plaintext + full hash never leave the
 * browser — only the 5-char SHA-1 prefix is sent.
 */
export async function checkPassword(password: string): Promise<PasswordCheckResult> {
  const hash = await sha1Hex(password);
  const body = await api.passwordRange(hash.slice(0, 5));
  return buildPasswordResult(parseRangeResponse(body, hash.slice(5)));
}

/**
 * Combo check. The browser hashes the password and sends the email + the
 * 5-char prefix + the 35-char suffix (a hash fragment, not the password) so the
 * server can do the range lookup and the email lookup and combine them.
 */
export async function checkCombo(email: string, password: string) {
  const hash = await sha1Hex(password);
  return api.combo(email, hash.slice(0, 5), hash.slice(5));
}
