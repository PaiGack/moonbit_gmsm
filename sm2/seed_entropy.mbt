///|
/// `seed_from_entropy` call counter, mixed into every seed so that two calls
/// in the same millisecond still differ.
let seed_call_counter : Ref[Int32] = Ref(0)

///|
/// Hash every entropy source the environment exposes into a CSPRNG seed.
///
/// `moonbitlang/core/env` only provides OS entropy on `native`, `js` and
/// `wasm`; on `wasm-gc` `@env.rand` always reports failure. This function
/// probes each source without requiring any of them: whatever is available is
/// mixed in, together with the wall clock and per-call state.
///
/// The result is not a replacement for a real OS CSPRNG. A fully sandboxed
/// host (e.g. a bare `wasm-gc` host that exposes nothing to the guest) leaves
/// only the clock and per-call state, which keeps successive seeds distinct
/// but not unpredictable. Prefer `os_rand()`; use this only where it is the
/// best source available.
pub fn seed_from_entropy() -> Bytes {
  let sb = StringBuilder()
  sb.write_string("gmsm/seed_from_entropy/v1|")
  // Provider entropy, if the host has any.
  if @env.rand(32) is Some(bytes) {
    sb.write_string("rand=")
    for i in 0..<bytes.length() {
      sb.write_string(bytes[i].to_int().to_string())
      sb.write_char(',')
    }
    sb.write_char(';')
  }
  // Wall clock in milliseconds, where the platform provides one. Always
  // written, so the layout does not reveal whether it was available.
  sb.write_string("time=")
  sb.write_string(@env.now().to_string())
  sb.write_char(';')
  // Per-call state: a call counter, so repeated calls never agree.
  seed_call_counter.val = seed_call_counter.val + 1
  sb.write_string("n=")
  sb.write_string(seed_call_counter.val.to_string())
  sb.write_char('|')
  @sm3.sm3_sum(@utf8.encode(sb.to_string()))
}
