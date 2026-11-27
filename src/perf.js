/* =====================================================================
   PRIVASHIELD — perf.js (Stage 3). Web Worker scan for large
      inputs. Vite bundles src/worker.js as a separate module-worker
      chunk; any worker failure falls back to a synchronous scan.
   ===================================================================== */

export const WORKER_THRESHOLD = 20000;

export function createEngineWorker() {
  try {
    return new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  } catch (err) {
    console.warn('PRIVASHIELD Web Worker initialization failed; falling back to synchronous scan:', err);
    return null;
  }
}
