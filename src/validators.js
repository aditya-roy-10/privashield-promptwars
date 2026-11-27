/* =====================================================================
   PRIVASHIELD — validators.js (Stage 2). Pure validators: Luhn,
      Verhoeff, IPv4/IPv6 parsers, PAN holder codes, email & phone rules.
      Validation is mathematical/structural consistency only — never
      identity verification.
   ===================================================================== */

export var VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];

export var VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];

export function verhoeffValid(num){
  var c = 0, s = String(num);
  for (var i = 0; i < s.length; i++){
    var digit = s.charCodeAt(s.length - 1 - i) - 48;
    if (digit < 0 || digit > 9) return false;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

export function luhnValid(digits){
  if (!/^\d{13,19}$/.test(digits)) return false;
  var sum = 0, dbl = false;
  for (var i = digits.length - 1; i >= 0; i--){
    var d = digits.charCodeAt(i) - 48;
    if (dbl){ d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return sum % 10 === 0;
}

export function ipv4Valid(s){
  var parts = s.split(".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i++){
    if (!/^\d{1,3}$/.test(parts[i])) return false;
    if (parts[i].length > 1 && parts[i][0] === "0") return false; /* leading-zero octets are ambiguous — reject */
    var n = parseInt(parts[i], 10);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

export function ipv4Normalize(s){ return s.split(".").map(function(p){ return String(parseInt(p, 10)); }).join("."); }

export function ipv6Valid(s){
  if (!s || s.indexOf(":") === -1) return false;
  if (s.indexOf(":::") !== -1) return false;
  var halves = s.split("::");
  if (halves.length > 2) return false;
  function parseSide(str){
    if (str === "") return 0;
    var parts = str.split(":"), count = 0;
    for (var i = 0; i < parts.length; i++){
      var p = parts[i];
      if (p.indexOf(".") !== -1){
        if (i !== parts.length - 1) return -1;
        if (!ipv4Valid(p)) return -1;
        count += 2;
      } else {
        if (!/^[0-9A-Fa-f]{1,4}$/.test(p)) return -1;
        count += 1;
      }
    }
    return count;
  }
  if (halves.length === 2){
    var L = parseSide(halves[0]), R = parseSide(halves[1]);
    if (L < 0 || R < 0) return false;
    return (L + R) < 8; /* :: must stand for at least one omitted group */
  }
  return parseSide(s) === 8;
}

export function validateEmail(v){
  var at = v.split("@");
  if (at.length !== 2) return null;
  var local = at[0], domain = at[1];
  if (local.length < 1 || local.length > 64) return null;
  if (local[0] === "." || local[local.length - 1] === ".") return null;
  if (local.indexOf("..") !== -1) return null;
  if (!/^[A-Za-z0-9._%+-]+$/.test(local)) return null;
  var labels = domain.split(".");
  if (labels.length < 2) return null;
  for (var i = 0; i < labels.length; i++){
    var lb = labels[i];
    if (lb.length < 1 || lb.length > 63) return null;
    if (!/^[A-Za-z0-9-]+$/.test(lb)) return null;
    if (lb[0] === "-" || lb[lb.length - 1] === "-") return null;
  }
  if (!/^[A-Za-z]{2,}$/.test(labels[labels.length - 1])) return null;
  if (v.length > 254) return null;
  return { normalized:v.toLowerCase(), status:"FORMAT_VALID", detail:"Address format valid (local@domain, TLD present) — format check only, mailbox existence not verified", confidence:"HIGH", review:"CONFIRMED" };
}

export function validatePhone(v){
  var raw = v.replace(/[\s()-]/g, "");
  var digits = v.replace(/\D/g, "");
  var is0091 = raw.indexOf("0091") === 0;
  var hasPlus = raw.charAt(0) === "+";
  if (is0091){
    var sub = digits.slice(4);
    if (!/^[6-9]\d{9}$/.test(sub)) return null;
    return { normalized:"+91" + sub, status:"FORMAT_VALID", detail:"Indian mobile via 0091 prefix; subscriber starts " + sub[0] + " (valid 6–9 range)", confidence:"HIGH", review:"CONFIRMED" };
  }
  if (hasPlus){
    if (digits.indexOf("91") === 0){
      var sub2 = digits.slice(2);
      if (!/^[6-9]\d{9}$/.test(sub2)) return null;
      return { normalized:"+91" + sub2, status:"FORMAT_VALID", detail:"Indian mobile via +91; subscriber starts " + sub2[0] + " (valid 6–9 range)", confidence:"HIGH", review:"CONFIRMED" };
    }
    if (digits.length < 10 || digits.length > 15) return null;
    return { normalized:"+" + digits, status:"FORMAT_VALID", detail:"International E.164-style number (" + digits.length + " digits incl. country code) — format check only", confidence:"HIGH", review:"CONFIRMED" };
  }
  if (/^[6-9]\d{9}$/.test(digits)) return { normalized:"+91" + digits, status:"FORMAT_VALID", detail:"Indian mobile (10-digit, starts " + digits[0] + ") — country code +91 assumed from format", confidence:"HIGH", review:"CONFIRMED" };
  if (/^91[6-9]\d{9}$/.test(digits)) return { normalized:"+" + digits, status:"FORMAT_VALID", detail:"Indian mobile with 91 prefix (no +)", confidence:"HIGH", review:"CONFIRMED" };
  if (/^0[6-9]\d{9}$/.test(digits)) return { normalized:"+91" + digits.slice(1), status:"FORMAT_VALID", detail:"Indian mobile with trunk 0 prefix", confidence:"HIGH", review:"CONFIRMED" };
  if (/^0\d{8,10}$/.test(digits)) return { normalized:digits, status:"FORMAT_VALID", detail:"Domestic landline format (STD code + number) — format check only", confidence:"MEDIUM", review:"CONFIRMED" };
  if (digits.length >= 10 && digits.length <= 11 && /^\(\d{3}\)/.test(v)) return { normalized:digits, status:"FORMAT_VALID", detail:"Parenthesised area-code format — format check only", confidence:"MEDIUM", review:"CONFIRMED" };
  return null;
}

export var PAN_HOLDERS = { P:"Individual", C:"Company", H:"HUF (Hindu Undivided Family)", F:"Firm / LLP", A:"Association of Persons", T:"Trust", B:"Body of Individuals", L:"Local Authority", J:"Artificial Juridical Person", G:"Government" };

export function validatePAN(v){
  if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(v)) return null;
  var holder = v.charAt(3);
  if (PAN_HOLDERS[holder]) return { normalized:v, status:"STRUCTURE_VALID", detail:"PAN structure valid — 4th character '" + holder + "' = " + PAN_HOLDERS[holder] + ". Structure check only, not a registry lookup", confidence:"HIGH", review:"CONFIRMED" };
  return { normalized:v, status:"FORMAT_CANDIDATE", detail:"Matches AAAAA9999A shape but 4th character '" + holder + "' is not a recognised PAN holder code (P/C/H/F/A/T/B/L/J/G) — flagged as candidate for human review", confidence:"MEDIUM", review:"NEEDS_REVIEW" };
}

export function validateAadhaar(v){
  var d = v.replace(/[\s-]/g, "");
  if (!/^\d{12}$/.test(d)) return null;
  if (!/^[2-9]/.test(d)) return null; /* UIDAI numbers never start with 0 or 1 */
  var grouped = d.slice(0,4) + " " + d.slice(4,8) + " " + d.slice(8,12);
  if (verhoeffValid(d)) return { normalized:grouped, status:"CHECKSUM_VALID", detail:"Verhoeff checksum passed — proves the digits are internally consistent, NOT that the Aadhaar is issued or belongs to anyone", confidence:"HIGH", review:"CONFIRMED" };
  return { normalized:grouped, status:"FORMAT_CANDIDATE", detail:"12-digit format + leading digit OK, but Verhoeff checksum FAILED — kept as a format candidate for human review, not a validated Aadhaar", confidence:"MEDIUM", review:"NEEDS_REVIEW" };
}

export function cardBrand(d){
  if (/^4/.test(d)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(d)) return "Mastercard";
  if (/^3[47]/.test(d)) return "American Express";
  if (/^6(?:011|5)/.test(d)) return "Discover";
  if (/^3(?:0[0-5]|[68])/.test(d)) return "Diners Club";
  if (/^35/.test(d)) return "JCB";
  return "unknown brand";
}

export function validateCard(v){
  if (/[- ]/.test(v) && v.indexOf("-") !== -1 && v.indexOf(" ") !== -1) return null; /* mixed separators */
  var groups = v.split(/[- ]/);
  if (groups.length > 1){
    var lens = groups.map(function(g){ return g.length; });
    var ok = lens.every(function(l){ return l === 4; }) || lens.join(",") === "4,6,5" || lens.join(",") === "4,6,4" ||
             (lens.length === 4 && lens[0] === 4 && lens[1] === 4 && lens[2] === 4 && lens[3] >= 1 && lens[3] <= 4);
    if (!ok) return null;
  }
  var d = v.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(d)) return null;
  if (!luhnValid(d)) return null; /* Luhn is mandatory — failures never become confirmed cards */
  return { normalized:d, status:"CHECKSUM_VALID", detail:"Luhn checksum passed (" + d.length + " digits, " + cardBrand(d) + " pattern) — checksum only, NOT proof of a real or active card", confidence:"HIGH", review:"CONFIRMED" };
}

export function validateIPv4(v){
  if (!ipv4Valid(v)) return null;
  return { normalized:ipv4Normalize(v), status:"FORMAT_VALID", detail:"IPv4 — all four octets within 0–255", confidence:"HIGH", review:"CONFIRMED" };
}

export function validateIPv6(v){
  if (!ipv6Valid(v)) return null;
  return { normalized:v.toLowerCase(), status:"FORMAT_VALID", detail:"IPv6 — group/compression structure valid" + (v.indexOf("::") !== -1 ? " (compressed :: form)" : ""), confidence:"HIGH", review:"CONFIRMED" };
}
