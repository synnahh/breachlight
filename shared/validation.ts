// Email validation shared by frontend and backend.
// Pragmatic RFC-5321-ish check: one @, a sane local part, a dotted domain.

const EMAIL_RE =
  /^(?=.{3,254}$)[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

export function isValidEmail(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v.includes('..')) return false;
  return EMAIL_RE.test(v);
}

export function normaliseEmail(value: string): string {
  return value.trim().toLowerCase();
}
