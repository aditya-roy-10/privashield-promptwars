/* =====================================================================
   PRIVASHIELD — worker.js. Web Worker entry for large-input
      scans. Imports the same engine modules as the main thread and
      answers { id, text } with { id, matches, stats }. No DOM here.
   ===================================================================== */

import { detectAll, engineStats } from './engine.js';

self.onmessage = function(e){
  var ms = detectAll(e.data.text);
  self.postMessage({ id: e.data.id, matches: ms, stats: engineStats });
};
