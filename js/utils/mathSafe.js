/**
 * mathSafe.js
 * `Math.max(1, ...bigArray)` / `Math.min(...)` spread large arrays onto the
 * call stack as individual function arguments — this silently throws
 * "RangeError: Maximum call stack size exceeded" once an array gets large
 * enough (V8's own argument-spread limit, roughly ~65k-125k elements
 * depending on engine/version and current stack depth). This is the exact
 * same bug class that previously caused a real crash in clustering.js
 * (`packetIndices.push(...bigArray)`); this module closes it everywhere
 * else `Math.max`/`Math.min` was applied to a value that scales with
 * capture size (host count, flow count, per-bucket counts, etc.) instead
 * of a small, fixed-size list.
 */
export function maxOf(arr, fallback = -Infinity) {
  let m = fallback;
  for (let i = 0; i < arr.length; i++) if (arr[i] > m) m = arr[i];
  return m;
}

export function minOf(arr, fallback = Infinity) {
  let m = fallback;
  for (let i = 0; i < arr.length; i++) if (arr[i] < m) m = arr[i];
  return m;
}
