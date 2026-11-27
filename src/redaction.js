/* =====================================================================
   PRIVASHIELD — redaction.js (Stage 4). Three production
      redaction modes behind one interface: FULL, PARTIAL, PSEUDO
      (document-scoped, in-memory alias store — never exported).
   ===================================================================== */

export const PSEUDO_PREFIX = {
  EMAIL: 'EMAIL',
  PHONE: 'PHONE',
  IP: 'IP',
  PAN: 'PAN',
  AADHAAR: 'AADHAAR',
  CREDIT_CARD: 'CARD'
};

/** Create a document-scoped, in-memory pseudonym store keyed by type + normalized value. */
export function createPseudoStore() {
  return {
    map: {},
    counters: {},
    getAlias(det) {
      const key = `${det.type}|${det.normalized}`;
      if (!this.map[key]) {
        const n = (this.counters[det.type] || 0) + 1;
        this.counters[det.type] = n;
        this.map[key] = `${PSEUDO_PREFIX[det.type] || det.type}_${String(n).padStart(3, '0')}`;
      }
      return this.map[key];
    },
    peekAlias(det) {
      return this.map[`${det.type}|${det.normalized}`] || null;
    },
    reset() {
      this.map = {};
      this.counters = {};
    },
    size() {
      return Object.keys(this.map).length;
    },
    aliases() {
      return Object.values(this.map).sort();
    }
  };
}

/* --- Partial-mask policies (one per entity type) --- */
export function maskEmailPartial(value) {
  const at = value.lastIndexOf('@');
  if (at < 1) return '***@***';
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  const labels = domain.split('.');
  const tld = labels[labels.length - 1];
  const localMask = `${local.charAt(0)}***${local.length > 2 ? local.charAt(local.length - 1) : ''}`;
  return `${localMask}@${domain.charAt(0)}***.${tld}`;
}

export function maskPhonePartial(value) {
  const digits = value.replace(/\D/g, '');
  return `***-***-${digits.slice(-4)}`;
}

export function maskAadhaarPartial(value) {
  const digits = value.replace(/\D/g, '');
  return `XXXX XXXX ${digits.slice(-4)}`;
}

export function maskPANPartial(value) {
  return `${value.slice(0, 2)}******${value.slice(-2)}`;
}

export function maskCardPartial(value) {
  const digits = value.replace(/\D/g, '');
  return `**** **** **** ${digits.slice(-4)}`;
}

export function maskIPPartial(value) {
  if (value.includes(':')) { /* IPv6: keep only the first group */
    const first = value.split(':')[0] || '0';
    return `${first}:****:****:****:****`;
  }
  const parts = value.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
  return '***.***.***.***';
}

export function partialMask(det) {
  switch (det.type) {
    case 'EMAIL': return maskEmailPartial(det.value);
    case 'PHONE': return maskPhonePartial(det.value);
    case 'AADHAAR': return maskAadhaarPartial(det.value);
    case 'PAN': return maskPANPartial(det.value);
    case 'CREDIT_CARD': return maskCardPartial(det.value);
    case 'IP': return maskIPPartial(det.value);
    default: return '[REDACTED]';
  }
}

/** Return the replacement string for a single detection under `mode`. */
export function replacementFor(det, mode, store) {
  if (mode === 'PARTIAL') return partialMask(det);
  if (mode === 'PSEUDO') return store.getAlias(det);
  return '[REDACTED]'; /* FULL — and the safe default for anything else */
}

/**
 * Offset-safe application: matches carry offsets into the original text
 * and are consumed left-to-right against a moving cursor.
 */
export function applyRedactions(text, matches, planFor) {
  let out = '';
  let last = 0;
  matches.forEach((m) => {
    const rep = planFor(m);
    out += text.slice(last, m.start) + (rep === null ? m.value : rep);
    last = m.end;
  });
  out += text.slice(last);
  return out;
}
