/// Whitebox tests for `bn.mbt` internal accumulator / comparison branches.

///|
test "bn_lt_partial_branches" {
  // a[3] != b[3] branch
  let a = FixedArray::makei(4, fn(i) { if i == 3 { 1UL } else { 0UL } })
  let b = FixedArray::makei(4, fn(_) { 0UL })
  assert_false(bn_lt(a, b))
  // a[3] == b[3], a[2] != b[2] branch
  let c = FixedArray::makei(4, fn(i) { if i == 2 { 1UL } else { 0UL } })
  let d = FixedArray::makei(4, fn(_) { 0UL })
  assert_false(bn_lt(c, d))
  // a[3] == b[3], a[2] == b[2], a[1] != b[1] branch
  let e = FixedArray::makei(4, fn(i) { if i == 1 { 1UL } else { 0UL } })
  let f = FixedArray::makei(4, fn(_) { 0UL })
  assert_false(bn_lt(e, f))
  // all equal -> a[0] < b[0] (both 0 -> false)
  let g = FixedArray::makei(4, fn(_) { 0UL })
  assert_false(bn_lt(g, g))
}

///|
test "bn_gt_partial_branches" {
  // a[3] != b[3] branch
  let a = FixedArray::makei(4, fn(i) { if i == 3 { 1UL } else { 0UL } })
  let b = FixedArray::makei(4, fn(_) { 0UL })
  assert_true(bn_gt(a, b))
  // a[3] == b[3], a[2] != b[2] branch
  let c = FixedArray::makei(4, fn(i) { if i == 2 { 1UL } else { 0UL } })
  let d = FixedArray::makei(4, fn(_) { 0UL })
  assert_true(bn_gt(c, d))
  // a[3] == b[3], a[2] == b[2], a[1] != b[1] branch
  let e = FixedArray::makei(4, fn(i) { if i == 1 { 1UL } else { 0UL } })
  let f = FixedArray::makei(4, fn(_) { 0UL })
  assert_true(bn_gt(e, f))
}

///|
test "bn_acc_zero_value_early_returns" {
  let acc = FixedArray::makei(9, fn(_) { 0UL })
  // All of these early-return when value/coeff == 0, leaving acc unchanged.
  acc_add_shifted(acc, 0UL, 0)
  acc_sub_shifted(acc, 0UL, 0)
  acc_sub_at(acc, 0, 0UL)
  reduce_term(acc, 0UL, 100)
  reduce_term_neg(acc, 0UL, 100)
  reduce_term_pos(acc, 0UL, 100)
  for i in 0..<9 {
    assert_eq(acc[i], 0UL)
  }
  // Separate: reduce_term_pos with power >= 256 exercises the recursive else
  // branch (base = power - 256) at line 294. This performs real work, so acc
  // is no longer zero afterwards.
  let acc2 = FixedArray::makei(9, fn(_) { 0UL })
  reduce_term_pos(acc2, 1UL, 320)
}

///|
test "acc_ge_bn_branches" {
  let b = new_bn(0UL)
  // High limbs (>= 4) non-zero -> early return true
  let acc_hi = FixedArray::makei(9, fn(i) { if i == 8 { 5UL } else { 0UL } })
  assert_true(acc_ge_bn(acc_hi, b))
  // limb3 == b[3], limb2 differs -> return limb2 comparison (true)
  let acc2 = FixedArray::makei(9, fn(i) { if i == 2 { 1UL } else { 0UL } })
  assert_true(acc_ge_bn(acc2, b))
  // acc == b -> acc[0] >= b[0] is true
  let acc3 = FixedArray::makei(9, fn(_) { 0UL })
  assert_true(acc_ge_bn(acc3, b))
}

///|
test "bn_sqr_called" {
  // Covers the bn_sqr wrapper body (bn_mul(r, a, a)).
  let a = new_bn(3UL)
  let r = FixedArray::makei(8, fn(_) { 0UL })
  bn_sqr(r, a)
  // 3^2 = 9
  assert_eq(r[0], 9UL)
}

///|
test "bn_addmod_p_reduces" {
  // a + b >= p (no carry but result >= p) -> the bn_sub reduction branch.
  let p = p_limbs()
  let r = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(r, p, new_bn(0UL)) // p + 0 = p -> reduce to 0
  assert_true(bn_is_zero(r))
}

///|
fn new_bn(v : UInt64) -> FixedArray[UInt64] {
  FixedArray::makei(4, fn(i) { if i == 0 { v } else { 0UL } })
}
