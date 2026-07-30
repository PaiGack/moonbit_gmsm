/// SM2 Big Number (256-bit) arithmetic layer.
/// Uses 4 × 64-bit limbs, little-endian (limb 0 = least significant).
/// All arithmetic is modulo the SM2 prime p.

///|
/// SM2 prime p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
fn p_limbs() -> FixedArray[UInt64] {
  FixedArray::from_array([
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL,
  ])
}

///|
/// SM2 curve order n
fn n_limbs() -> FixedArray[UInt64] {
  FixedArray::from_array([
    0x53BBF40939D54123UL, 0x7203DF6B21C6052BUL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFEFFFFFFFFUL,
  ])
}

///|
/// Check if a == 0 (4 limbs)
fn bn_is_zero(a : FixedArray[UInt64]) -> Bool {
  (a[0] | a[1] | a[2] | a[3]) == 0UL
}

///|
/// Set r to zero
fn bn_zero(r : FixedArray[UInt64]) -> Unit {
  r[0] = 0UL
  r[1] = 0UL
  r[2] = 0UL
  r[3] = 0UL
}

///|
/// Copy src to dst (4 limbs)
fn bn_copy(dst : FixedArray[UInt64], src : FixedArray[UInt64]) -> Unit {
  dst[0] = src[0]
  dst[1] = src[1]
  dst[2] = src[2]
  dst[3] = src[3]
}

///|
/// a == b (4 limbs)
fn bn_eq(a : FixedArray[UInt64], b : FixedArray[UInt64]) -> Bool {
  a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

///|
/// a < b (4 limbs, unsigned)
fn bn_lt(a : FixedArray[UInt64], b : FixedArray[UInt64]) -> Bool {
  if a[3] != b[3] {
    return a[3] < b[3]
  }
  if a[2] != b[2] {
    return a[2] < b[2]
  }
  if a[1] != b[1] {
    return a[1] < b[1]
  }
  a[0] < b[0]
}

///|
/// a > b (4 limbs, unsigned)
fn bn_gt(a : FixedArray[UInt64], b : FixedArray[UInt64]) -> Bool {
  if a[3] != b[3] {
    return a[3] > b[3]
  }
  if a[2] != b[2] {
    return a[2] > b[2]
  }
  if a[1] != b[1] {
    return a[1] > b[1]
  }
  a[0] > b[0]
}

///|
/// Multiply two UInt64 values, returning (high 64 bits, low 64 bits)
fn mul_128(a : UInt64, b : UInt64) -> (UInt64, UInt64) {
  let mask32 = 0xFFFFFFFFUL
  let a0 = a & mask32
  let a1 = a >> 32
  let b0 = b & mask32
  let b1 = b >> 32

  let x = a0 * b0
  let y0 = a1 * b0
  let y1 = a0 * b1
  let y = y0 + y1
  let y_overflow : UInt64 = if y < y0 { 1UL } else { 0UL }
  let z = a1 * b1

  let y_lo_shifted = (y & mask32) << 32
  let lo = x + y_lo_shifted
  let lo_carry : UInt64 = if lo < x { 1UL } else { 0UL }

  let hi = z + (y >> 32) + (y_overflow << 32) + lo_carry

  (hi, lo)
}

///|
/// 512-bit accumulator functions (9 limbs)

///|
/// Add a UInt64 value shifted left by `bits` to a 9-limb accumulator
fn acc_add_shifted(
  acc : FixedArray[UInt64],
  value : UInt64,
  bits : Int,
) -> Unit {
  if value == 0UL {
    return
  }
  let limb_idx = bits / 64
  let bit_off = bits % 64
  if bit_off == 0 {
    acc_add_at(acc, limb_idx, value)
  } else {
    let lo_part = value << bit_off
    let hi_part = value >> (64 - bit_off)
    acc_add_at(acc, limb_idx, lo_part)
    if hi_part != 0UL {
      acc_add_at(acc, limb_idx + 1, hi_part)
    }
  }
}

///|
/// Subtract a UInt64 value shifted left by `bits` from a 9-limb accumulator
fn acc_sub_shifted(
  acc : FixedArray[UInt64],
  value : UInt64,
  bits : Int,
) -> Unit {
  if value == 0UL {
    return
  }
  let limb_idx = bits / 64
  let bit_off = bits % 64
  if bit_off == 0 {
    acc_sub_at(acc, limb_idx, value)
  } else {
    let lo_part = value << bit_off
    let hi_part = value >> (64 - bit_off)
    acc_sub_at(acc, limb_idx, lo_part)
    if hi_part != 0UL {
      acc_sub_at(acc, limb_idx + 1, hi_part)
    }
  }
}

///|
/// Add value at limb position with carry propagation (9-limb acc)
fn acc_add_at(acc : FixedArray[UInt64], idx : Int, value : UInt64) -> Unit {
  let mut s = acc[idx] + value
  acc[idx] = s
  let mut i = idx + 1
  let mut v = value
  while s < v && i < 9 {
    v = 1UL
    s = acc[i] + 1UL
    acc[i] = s
    i = i + 1
  }
}

///|
/// Subtract value at limb position with borrow propagation (9-limb acc)
fn acc_sub_at(acc : FixedArray[UInt64], idx : Int, value : UInt64) -> Unit {
  if value == 0UL {
    return
  }
  let diff = acc[idx]
  if diff >= value {
    acc[idx] = diff - value
    return
  }
  acc[idx] = diff + (0xFFFFFFFFFFFFFFFFUL - value) + 1UL
  let mut i = idx + 1
  while i < 9 {
    if acc[i] > 0UL {
      acc[i] = acc[i] - 1UL
      return
    }
    acc[i] = 0xFFFFFFFFFFFFFFFFUL
    i = i + 1
  }
}

///|
/// Recursively reduce a term: coeff * 2^power mod p
fn reduce_term(acc : FixedArray[UInt64], coeff : UInt64, power : Int) -> Unit {
  if coeff == 0UL {
    return
  }
  if power < 256 {
    acc_add_shifted(acc, coeff, power)
  } else {
    let base = power - 256
    reduce_term(acc, coeff, base + 224)
    reduce_term(acc, coeff, base + 96)
    reduce_term_neg(acc, coeff, base + 64)
    reduce_term(acc, coeff, base)
  }
}

///|
fn reduce_term_neg(
  acc : FixedArray[UInt64],
  coeff : UInt64,
  power : Int,
) -> Unit {
  if coeff == 0UL {
    return
  }
  if power < 256 {
    acc_sub_shifted(acc, coeff, power)
  } else {
    let base = power - 256
    reduce_term_neg(acc, coeff, base + 224)
    reduce_term_neg(acc, coeff, base + 96)
    reduce_term_pos(acc, coeff, base + 64)
    reduce_term_neg(acc, coeff, base)
  }
}

///|
fn reduce_term_pos(
  acc : FixedArray[UInt64],
  coeff : UInt64,
  power : Int,
) -> Unit {
  if coeff == 0UL {
    return
  }
  if power < 256 {
    acc_add_shifted(acc, coeff, power)
  } else {
    let base = power - 256
    reduce_term_pos(acc, coeff, base + 224)
    reduce_term_pos(acc, coeff, base + 96)
    reduce_term_neg(acc, coeff, base + 64)
    reduce_term_pos(acc, coeff, base)
  }
}

///|
fn acc_ge_bn(acc : FixedArray[UInt64], b : FixedArray[UInt64]) -> Bool {
  if (acc[4] | acc[5] | acc[6] | acc[7] | acc[8]) != 0UL {
    return true
  }
  if acc[3] != b[3] {
    return acc[3] > b[3]
  }
  if acc[2] != b[2] {
    return acc[2] > b[2]
  }
  if acc[1] != b[1] {
    return acc[1] > b[1]
  }
  acc[0] >= b[0]
}

///|
fn acc_sub_bn(acc : FixedArray[UInt64], b : FixedArray[UInt64]) -> Unit {
  let mut borrow : UInt64 = 0UL
  for i in 0..<9 {
    let bv = if i < 4 { b[i] } else { 0UL }
    let acc_i = acc[i]
    let d1 = acc_i - bv
    let borrow1 : UInt64 = if acc_i < bv { 1UL } else { 0UL }
    let d2 = d1 - borrow
    let borrow2 : UInt64 = if d1 < borrow { 1UL } else { 0UL }
    acc[i] = d2
    borrow = borrow1 + borrow2
  }
}

///|
/// Modular reduction modulo p (P2: Barrett-style with recursive term splitting)
/// The single recursive pass folds the original high limbs of the product, but it
/// can leave spillover terms in limbs >= 4 (e.g. 2^224·coeff spills its top 32 bits
/// into the 2^256 region). Those must be reduced again, so we iterate until no limb
/// at or above 2^256 remains, then do the final conditional subtraction of p.
fn bn_mod_p(r : FixedArray[UInt64], s : FixedArray[UInt64]) -> Unit {
  let acc : FixedArray[UInt64] = FixedArray::makei(9, fn(_) { 0UL })

  for i in 0..<8 {
    acc[i] = s[i]
  }

  // Iteratively reduce every limb at position >= 2^256. Each reduction folds the
  // term into lower limbs, possibly spilling bits back into the >= 2^256 region, so
  // we repeat until no such limb is left. Coefficients are < 2^64, so each pass
  // shifts them down by 32 bits and the loop converges in a few iterations.
  let mut again = true
  while again {
    again = false
    for i in 4..<9 {
      if acc[i] != 0UL {
        let c = acc[i]
        acc[i] = 0UL
        let power = (i - 4) * 64 + 256
        reduce_term(acc, c, power)
        again = true
      }
    }
  }

  let p = p_limbs()
  while acc_ge_bn(acc, p) {
    acc_sub_bn(acc, p)
  }

  for i in 0..<4 {
    r[i] = acc[i]
  }
}

///|
/// Schoolbook multiplication: r (8 limbs) = a (4 limbs) × b (4 limbs)
/// The 128-bit product of each limb pair (hi*2^64 + lo) is placed at limbs
/// (i+j) and (i+j+1). `acc_add_at` propagates carries correctly across all
/// limbs, including the rare case where `hi + carry == 2^64`.
fn bn_mul(
  r : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> Unit {
  for i in 0..<8 {
    r[i] = 0UL
  }

  for i in 0..<4 {
    let ai = a[i]
    if ai == 0UL {
      continue
    }
    for j in 0..<4 {
      let bj = b[j]
      if bj == 0UL {
        continue
      }
      let (hi, lo) = mul_128(ai, bj)
      let idx = i + j
      acc_add_at(r, idx, lo)
      acc_add_at(r, idx + 1, hi)
    }
  }
}

///|
/// Square: r (8 limbs) = a (4 limbs)²
fn bn_sqr(r : FixedArray[UInt64], a : FixedArray[UInt64]) -> Unit {
  bn_mul(r, a, a)
}

///|
/// True if the 256-bit value is odd.
fn bn_is_odd(a : FixedArray[UInt64]) -> Bool {
  (a[0] & 1UL) != 0UL
}

///|
/// Right shift a 256-bit value by one bit (safe in place: processes high→low).
fn bn_shr_1(r : FixedArray[UInt64], a : FixedArray[UInt64]) -> Unit {
  let mut carry : UInt64 = 0UL
  for i = 3; i >= 0; i = i - 1 {
    let v = a[i]
    r[i] = (v >> 1) | (carry << 63)
    carry = v & 1UL
  }
}

///|
/// Low `w` bits of a 256-bit value as an Int (w <= 8).
fn bn_low_bits(a : FixedArray[UInt64], w : Int) -> Int {
  let mask : UInt64 = (1UL << w) - 1UL
  (a[0] & mask).to_int()
}

///|
/// Add a small signed integer `d` (|d| < 2^31) to a 256-bit value.
/// Used by the wNAF digit loop (k = (k - digit) / 2).
fn bn_add_int(r : FixedArray[UInt64], a : FixedArray[UInt64], d : Int) -> Unit {
  // NOTE: carry/borrow must be computed BEFORE writing to r[i], because the
  // wNAF digit loop calls this in-place (r === a). Writing first would clobber
  // the source value and produce wrong carry propagation.
  if d >= 0 {
    let add = d.to_uint64()
    let s0 = a[0] + add
    let c0 : UInt64 = if s0 < a[0] { 1UL } else { 0UL }
    r[0] = s0
    let mut c = c0
    for i in 1..<4 {
      let s = a[i] + c
      let new_c : UInt64 = if s < a[i] { 1UL } else { 0UL }
      r[i] = s
      c = new_c
    }
  } else {
    let sub = (-d).to_uint64()
    let s0 = a[0] - sub
    let borrow0 : UInt64 = if a[0] < sub { 1UL } else { 0UL }
    r[0] = s0
    let mut borrow = borrow0
    for i in 1..<4 {
      let s = a[i] - borrow
      let new_borrow : UInt64 = if a[i] < borrow { 1UL } else { 0UL }
      r[i] = s
      borrow = new_borrow
    }
  }
}

///|
/// Modular multiplication modulo p: r = (a * b) mod p
fn bn_modmul_p(
  r : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> Unit {
  let s : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL })
  bn_mul(s, a, b)
  bn_mod_p(r, s)
}

///|
/// Modular squaring modulo p: r = a² mod p
/// Uses the plain 256-bit square `bn_sqr` followed by reduction, mirroring
/// tjfoc/gmsm's `sm2P256Square` + reduce.
fn bn_modsqr_p(r : FixedArray[UInt64], a : FixedArray[UInt64]) -> Unit {
  let s : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL })
  bn_sqr(s, a)
  bn_mod_p(r, s)
}

///|
/// Addition with carry: r = a + b, returns carry
fn bn_add(
  r : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> UInt {
  let mut carry : UInt64 = 0UL
  for i in 0..<4 {
    let sum = a[i] + b[i] + carry
    let new_carry : UInt64 = if sum < a[i] || (carry != 0UL && sum == a[i]) {
      1UL
    } else {
      0UL
    }
    r[i] = sum
    carry = new_carry
  }
  carry.to_uint()
}

///|
/// Subtraction with borrow: r = a - b, returns borrow
fn bn_sub(
  r : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> UInt {
  let mut borrow : UInt64 = 0UL
  for i in 0..<4 {
    let ai = a[i]
    let bi = b[i]
    // d1 = ai - bi, then d2 = d1 - borrow; track each step's borrow separately
    // to avoid the overflow bug when bi == 2^64-1 and borrow == 1.
    let d1 = ai - bi
    let borrow1 : UInt64 = if ai < bi { 1UL } else { 0UL }
    let d2 = d1 - borrow
    let borrow2 : UInt64 = if d1 < borrow { 1UL } else { 0UL }
    r[i] = d2
    borrow = borrow1 + borrow2
  }
  borrow.to_uint()
}

///|
/// Modular addition modulo p: r = (a + b) mod p
fn bn_addmod_p(
  r : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> Unit {
  let carry = bn_add(r, a, b)
  let p = p_limbs()
  if carry != 0U || !bn_lt(r, p) {
    bn_sub(r, r, p) |> ignore
  }
}

///|
/// Modular subtraction modulo p: r = (a - b) mod p
fn bn_submod_p(
  r : FixedArray[UInt64],
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> Unit {
  let borrow = bn_sub(r, a, b)
  let p = p_limbs()
  if borrow != 0U {
    bn_add(r, r, p) |> ignore
    return
  }
  if !bn_lt(r, p) {
    bn_sub(r, r, p) |> ignore
  }
}

///|
/// Modular inversion modulo p using Fermat: a^(p-2) mod p
fn bn_modinv_p(r : FixedArray[UInt64], a : FixedArray[UInt64]) -> Unit {
  let p = p_limbs()
  let p_minus_2 = FixedArray::makei(4, fn(i) {
    if i == 0 {
      p[0] - 2UL
    } else {
      p[i]
    }
  })
  bn_exp_mod_p(r, a, p_minus_2)
}

///|
/// Modular exponentiation: r = base^exp mod p (square-and-multiply)
fn bn_exp_mod_p(
  r : FixedArray[UInt64],
  base : FixedArray[UInt64],
  exp : FixedArray[UInt64],
) -> Unit {
  r[0] = 1UL
  r[1] = 0UL
  r[2] = 0UL
  r[3] = 0UL

  let tmp : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_copy(tmp, base)

  for limb_idx = 3; limb_idx >= 0; limb_idx = limb_idx - 1 {
    let mut e = exp[limb_idx]
    for _bit in 0..<64 {
      let bit_val = (e >> 63) & 1UL
      e = e << 1

      bn_modsqr_p(r, r)

      if bit_val == 1UL {
        bn_modmul_p(r, r, tmp)
      }
    }
  }
}

///|
/// Modular reduction modulo n (curve order).
/// Since n > 2^255, we have 2^256 = n + t with t = 2^256 mod n (t ≈ 2^224).
/// Write the value as hi*2^256 + lo ≡ hi*t + lo (mod n). Each folding step
/// decreases the value by hi*n > 0, so iterating until the high half is zero
/// terminates (each step shrinks the value by roughly 2^32 bits of headroom).
/// A final conditional subtraction of n yields the canonical result.
fn bn_mod_n(r : FixedArray[UInt64], a : FixedArray[UInt64]) -> Unit {
  let n = n_limbs()

  // t = 2^256 mod n
  let t : FixedArray[UInt64] = FixedArray::from_array([
    0xAC440BF6C62ABEDDUL, 0x8DFC2094DE39FAD4UL, 0x0000000000000000UL, 0x0000000100000000UL,
  ])

  let work : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { a[i] })
  while (work[4] | work[5] | work[6] | work[7]) != 0UL {
    let hi : FixedArray[UInt64] = FixedArray::makei(4, fn(i) { work[i + 4] })
    let lo : FixedArray[UInt64] = FixedArray::makei(4, fn(i) { work[i] })
    bn_mul(work, hi, t)
    add_8(work, lo)
  }

  let rr : FixedArray[UInt64] = FixedArray::makei(4, fn(i) { work[i] })
  while !bn_lt(rr, n) {
    bn_sub(rr, rr, n) |> ignore
  }
  for i in 0..<4 {
    r[i] = rr[i]
  }
}

///|
/// Add the low 4 limbs of `b` into the 8-limb accumulator `a` (with carry).
fn add_8(a : FixedArray[UInt64], b : FixedArray[UInt64]) -> Unit {
  let mut carry : UInt64 = 0UL
  for i in 0..<4 {
    let s1 = a[i] + b[i]
    let c1 : UInt64 = if s1 < a[i] { 1UL } else { 0UL }
    let s2 = s1 + carry
    let c2 : UInt64 = if s2 < s1 { 1UL } else { 0UL }
    a[i] = s2
    carry = c1 + c2
  }
  let mut i = 4
  while carry != 0UL && i < 8 {
    let s = a[i] + carry
    carry = if s < carry { 1UL } else { 0UL }
    a[i] = s
    i = i + 1
  }
}

///|
/// Process-wide fallback generator used when the caller passes `None`.
///
/// `@random.Rand::chacha8()` is seeded with a *fixed* default seed, so
/// creating a fresh instance on every call would hand out the very same `k`
/// every time — fatal for signature nonces and for ephemeral keys. Keeping a
/// single shared stream at least guarantees that successive draws differ.
/// Production code should still pass its own properly seeded `@random.Rand`.
let fallback_rand : @random.Rand = @random.Rand::chacha8()

///|
/// Generate random k: 1 ≤ k ≤ n-1
fn bn_rand_k(random : @random.Rand?) -> FixedArray[UInt64] {
  let n = n_limbs()
  let k : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let r = match random {
    Some(r) => r
    None => fallback_rand
  }
  while true {
    let buf = Bytes::makei(32, fn(_i) { (r.int(limit=256) & 0xFF).to_byte() })
    @byteutil.bn_from_bytes(k, buf, 0)
    if !bn_is_zero(k) && bn_lt(k, n) {
      return k
    }
  }
  k
}
