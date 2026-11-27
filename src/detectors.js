/* =====================================================================
   PRIVASHIELD — detectors.js (Stage 2). One detector per entity
      type: a candidate pattern plus its validator. prio: lower wins
      during overlap resolution.
   ===================================================================== */

import { validateAadhaar, validateCard, validateEmail, validateIPv4, validateIPv6, validatePAN, validatePhone } from './validators.js';

export const DETECTORS = [
  {
    type: 'CREDIT_CARD',
    label: 'Credit card',
    color: 'var(--c-card)',
    severity: 'CRITICAL',
    prio: 0,
    pattern: /(?:\d{4}[- ]){3}\d{4}|\d{4}[- ]\d{6}[- ]\d{5}|\d{4}[- ]\d{6}[- ]\d{4}|\d{13,19}/g,
    validate: validateCard,
    digitBoundary: true
  },
  {
    type: 'AADHAAR',
    label: 'Aadhaar',
    color: 'var(--c-aadhaar)',
    severity: 'CRITICAL',
    prio: 1,
    pattern: /\d{4}[\s-]\d{4}[\s-]\d{4}|\d{12}/g,
    validate: validateAadhaar,
    digitBoundary: true
  },
  {
    type: 'PAN',
    label: 'PAN',
    color: 'var(--c-pan)',
    severity: 'HIGH',
    prio: 2,
    pattern: /[A-Z]{5}[0-9]{4}[A-Z]/g,
    validate: validatePAN,
    alnumBoundary: true
  },
  {
    type: 'EMAIL',
    label: 'Email',
    color: 'var(--c-email)',
    severity: 'MEDIUM',
    prio: 3,
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g,
    validate: validateEmail
  },
  {
    type: 'IP',
    label: 'IP address',
    color: 'var(--c-ip)',
    severity: 'LOW',
    prio: 4,
    pattern: /[0-9A-Fa-f:.]*::[0-9A-Fa-f:.]*|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3}/g,
    validate: (v) => (v.includes(':') ? validateIPv6(v) : validateIPv4(v)),
    ipBoundary: true
  },
  {
    type: 'PHONE',
    label: 'Phone',
    color: 'var(--c-phone)',
    severity: 'HIGH',
    prio: 5,
    pattern: /(?:\+91|0091)[\s-]?[6-9]\d{4}[\s-]?\d{5}|(?:\+91|0091)[\s-]?[6-9]\d{9}|91[\s-][6-9]\d{4}[\s-]?\d{5}|[6-9]\d{4}[\s-]\d{5}|[6-9]\d{9}|0[6-9]\d{9}|\+\d{1,3}[\s-]?\(\d{2,4}\)[\s-]?\d{3,4}[\s-]?\d{4}|\+\d{1,3}[\s-]\d{2,4}[\s-]\d{3,4}[\s-]\d{4}|\(\d{3}\)\s?\d{3}[- ]\d{4}|0\d{2,4}[- ]\d{3,4}[- ]\d{4}|0\d{2,4}[- ]\d{6,8}/g,
    validate: validatePhone,
    digitBoundary: true
  }
];

export const TYPE_META = Object.fromEntries(DETECTORS.map((d) => [d.type, d]));

export const SEV_WEIGHT = { CRITICAL: 30, HIGH: 18, MEDIUM: 10, LOW: 5 };
