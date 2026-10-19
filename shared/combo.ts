// Pure logic for the Combo Finder ("credential exposure check").
//
// Distinguishes three DIFFERENT facts:
//   - email exposed        (email appeared in a breach)
//   - password exposed     (this password string appears in breach datasets)
//   - credential combination exposed  (we can ONLY infer risk — we never assert
//     that this exact email+password pair was verified against a live site)

import type { ComboResult, Confidence, Severity } from './types.js';

export interface ComboInput {
  email: string;
  emailExposed: boolean;
  emailBreachCount: number;
  emailConfidence: Confidence;
  passwordOccurrences: number; // 0 = not found
}

export function assessCombo(input: ComboInput): ComboResult {
  const passwordExposed = input.passwordOccurrences > 0;
  const { risk, reason } = combinationRisk(input, passwordExposed);

  const notes: string[] = [
    'Email exposed, password exposed and credential-combination exposed are three different facts.',
    'This check never tests the credential against any website and never attempts to log in.',
  ];
  if (passwordExposed && input.emailExposed) {
    notes.push(
      'Both your email and this password appear in breach data. That does not prove this exact pair was used together, but the pair should be treated as compromised.',
    );
  } else if (passwordExposed) {
    notes.push(
      'This password appears in breach datasets even though this email was not found. Do not use this password anywhere.',
    );
  } else if (input.emailExposed) {
    notes.push(
      'Your email was found in breaches but this specific password was not found in the Pwned Passwords dataset. Breach datasets are incomplete — a strong unique password is still recommended.',
    );
  }

  return {
    email: input.email,
    emailExposed: input.emailExposed,
    emailBreachCount: input.emailBreachCount,
    passwordExposed,
    passwordOccurrences: passwordExposed ? input.passwordOccurrences : 0,
    combinationRisk: risk,
    combinationRiskReason: reason,
    recommendedActions: passwordExposed
      ? [
          'Change this password immediately on every account where it is used',
          'Never reuse this password again',
          'Enable multi-factor authentication on the affected accounts',
          'Sign out active sessions on those accounts',
          'Review account recovery email and phone settings',
          'Switch to a unique, password-manager-generated password',
        ]
      : input.emailExposed
        ? [
            'Confirm this password is unique to one account',
            'Enable multi-factor authentication where possible',
            'Review the breach findings for this email and secure the affected services',
          ]
        : [
            'Keep using unique passwords per account',
            'Enable multi-factor authentication where possible',
            'Re-run a scan periodically — breach datasets are incomplete',
          ],
    notes,
    checkedAt: new Date().toISOString(),
  };
}

function combinationRisk(
  input: ComboInput,
  passwordExposed: boolean,
): { risk: Severity; reason: string } {
  if (passwordExposed && input.emailExposed) {
    return {
      risk: 'critical',
      reason:
        'Both the email and the password appear in known breach data. Treat every account using this pair as compromised.',
    };
  }
  if (passwordExposed) {
    return {
      risk: 'high',
      reason:
        'The password appears in known breach datasets and must be considered public, regardless of this email.',
    };
  }
  if (input.emailExposed && input.emailBreachCount >= 3) {
    return {
      risk: 'medium',
      reason:
        'The email appears in several breaches. The password was not found, but exposure history raises phishing and targeting risk.',
    };
  }
  if (input.emailExposed) {
    return {
      risk: 'medium',
      reason: 'The email appears in breach data. The password was not found in the queried dataset.',
    };
  }
  return {
    risk: 'low',
    reason: 'Neither the email nor this password was found in the queried sources. This is not a guarantee of safety.',
  };
}
