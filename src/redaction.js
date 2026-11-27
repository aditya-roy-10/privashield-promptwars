/* =====================================================================
   PRIVASHIELD — redaction.js (Stage 4). Three production
      redaction modes behind one interface: FULL, PARTIAL, PSEUDO
      (document-scoped, in-memory alias store — never exported).
   ===================================================================== */

export var PSEUDO_PREFIX = { EMAIL:"EMAIL", PHONE:"PHONE", IP:"IP", PAN:"PAN", AADHAAR:"AADHAAR", CREDIT_CARD:"CARD" };

export function createPseudoStore(){
  return {
    map:{}, counters:{},
    getAlias:function(det){
      var key = det.type + "|" + det.normalized;
      if (!this.map[key]){
        var n = (this.counters[det.type] || 0) + 1;
        this.counters[det.type] = n;
        this.map[key] = (PSEUDO_PREFIX[det.type] || det.type) + "_" + String(n).padStart(3, "0");
      }
      return this.map[key];
    },
    peekAlias:function(det){ return this.map[det.type + "|" + det.normalized] || null; },
    reset:function(){ this.map = {}; this.counters = {}; },
    size:function(){ return Object.keys(this.map).length; },
    aliases:function(){
      var out = [];
      for (var k in this.map) out.push(this.map[k]);
      return out.sort();
    }
  };
}

/* --- Partial-mask policies (one per entity type) --- */
export function maskEmailPartial(value){
  var at = value.lastIndexOf("@");
  if (at < 1) return "***@***";
  var local = value.slice(0, at), domain = value.slice(at + 1);
  var labels = domain.split(".");
  var tld = labels[labels.length - 1];
  var localMask = local.charAt(0) + "***" + (local.length > 2 ? local.charAt(local.length - 1) : "");
  return localMask + "@" + domain.charAt(0) + "***." + tld;
}

export function maskPhonePartial(value){
  var digits = value.replace(/\D/g, "");
  var last4 = digits.slice(-4);
  return "***-***-" + last4;
}

export function maskAadhaarPartial(value){
  var digits = value.replace(/\D/g, "");
  return "XXXX XXXX " + digits.slice(-4);
}

export function maskPANPartial(value){
  return value.slice(0, 2) + "******" + value.slice(-2);
}

export function maskCardPartial(value){
  var digits = value.replace(/\D/g, "");
  return "**** **** **** " + digits.slice(-4);
}

export function maskIPPartial(value){
  if (value.indexOf(":") !== -1){ /* IPv6: keep only the first group */
    var first = value.split(":")[0] || "0";
    return first + ":****:****:****:****";
  }
  var parts = value.split(".");
  if (parts.length === 4) return parts[0] + "." + parts[1] + ".*.*";
  return "***.***.***.***";
}

export function partialMask(det){
  switch (det.type){
    case "EMAIL": return maskEmailPartial(det.value);
    case "PHONE": return maskPhonePartial(det.value);
    case "AADHAAR": return maskAadhaarPartial(det.value);
    case "PAN": return maskPANPartial(det.value);
    case "CREDIT_CARD": return maskCardPartial(det.value);
    case "IP": return maskIPPartial(det.value);
    default: return "[REDACTED]";
  }
}

export function replacementFor(det, mode, store){
  if (mode === "PARTIAL") return partialMask(det);
  if (mode === "PSEUDO") return store.getAlias(det);
  return "[REDACTED]"; /* FULL — and the safe default for anything else */
}

/* Offset-safe application: matches carry offsets into the ORIGINAL
   text and are consumed left-to-right against a moving cursor, so a
   replacement (longer or shorter than the match) can never shift the
   position of a later match. planFor(det) returns the replacement
   string, or null to keep the original value visible. */
export function applyRedactions(text, matches, planFor){
  var out = "", last = 0;
  matches.forEach(function(m){
    var rep = planFor(m);
    out += text.slice(last, m.start) + (rep === null ? m.value : rep);
    last = m.end;
  });
  out += text.slice(last);
  return out;
}
