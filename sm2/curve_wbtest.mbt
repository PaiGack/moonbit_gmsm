/// Whitebox tests for `curve.mbt` internal branches.

///|
test "point_to_affine_infinity" {
  // Covers the early-return branch for the point at infinity.
  let (x, y) = point_to_affine(point_infinity())
  assert_true(bn_is_zero(x))
  assert_true(bn_is_zero(y))
}

///|
test "point_is_on_curve_affine_zero_x" {
  // x = 0 -> three_x = 0 -> bn_zero(ax) branch.
  let zero = FixedArray::makei(4, fn(_) { 0UL })
  let y = FixedArray::makei(4, fn(_) { 0UL })
  assert_false(point_is_on_curve_affine(zero, y))
}

///|
test "point_is_on_curve_affine_generator" {
  let g = g_point()
  let (gx, gy) = point_to_affine(g)
  assert_true(point_is_on_curve_affine(gx, gy))
}

///|
test "point_double_infinity" {
  // Early return when doubling the point at infinity.
  let p = point_infinity()
  point_double(p)
  assert_true(point_is_infinity(p))
}

///|
test "point_add_q_infinity" {
  // p + O = p (q is infinity -> early return).
  let p = g_point()
  let before = point_to_affine(p)
  point_add(p, point_infinity())
  let after = point_to_affine(p)
  assert_true(bn_eq(before.0, after.0))
  assert_true(bn_eq(before.1, after.1))
}

///|
test "point_add_p_infinity" {
  // O + q = q (p is infinity -> point_copy branch).
  let p = point_infinity()
  let q = g_point()
  point_add(p, q)
  assert_true(point_eq(p, q))
}

///|
test "point_add_self_doubles" {
  // p == q -> h == 0 && r == 0 -> point_double branch.
  let p = g_point()
  let q = point_infinity()
  point_copy(q, p)
  point_add(p, q)
  // Result must equal 2*G.
  let doubled = point_infinity()
  point_copy(doubled, g_point())
  point_double(doubled)
  assert_true(point_eq(p, doubled))
}

///|
test "point_add_negated_is_infinity" {
  // p + (-p) -> h == 0 but r != 0 -> point_set_infinity branch.
  let p = g_point()
  let neg = point_infinity()
  point_copy(neg, p)
  point_neg(neg)
  point_add(p, neg)
  assert_true(point_is_infinity(p))
}

///|
test "point_add_affine_p_infinity" {
  // p is infinity -> copies q affine coords.
  let p = point_infinity()
  let g = g_point()
  let (gx, gy) = point_to_affine(g)
  point_add_affine(p, gx, gy)
  assert_true(point_eq(p, g))
}

///|
test "point_add_affine_body" {
  // p (z=1) + q (affine, q != p) exercises the main body (t1 != 0).
  let p = g_point()
  let g2 = point_infinity()
  scalar_base_mult(g2, two_bn())
  let (g2x, g2y) = point_to_affine(g2)
  point_add_affine(p, g2x, g2y)
  // Result should equal G + 2G = 3G.
  let expected = point_infinity()
  point_add(expected, g_point())
  point_add(expected, g2)
  assert_true(point_eq(p, expected))
}

///|
test "point_add_affine_negated_q" {
  // p (z=1) + q = -p (affine) -> t1 == 0 but t2 != 0 -> point_set_infinity.
  let p = g_point()
  let neg = point_infinity()
  point_copy(neg, p)
  point_neg(neg)
  let (nx, ny) = point_to_affine(neg)
  point_add_affine(p, nx, ny)
  assert_true(point_is_infinity(p))
}

///|
test "point_neg_infinity" {
  // Early return when negating the point at infinity.
  let p = point_infinity()
  point_neg(p)
  assert_true(point_is_infinity(p))
}

///|
test "point_eq_variants" {
  let inf = point_infinity()
  assert_true(point_eq(inf, inf))
  let g = g_point()
  assert_true(point_eq(g, g))
  assert_false(point_eq(inf, g))
}

///|
// Helper: the SM2 base point G in affine (z = 1) representation.
fn g_point() -> SM2Point {
  SM2Point::{
    x: FixedArray::makei(4, fn(i) {
      match i {
        0 => 0x715A4589334C74C7UL
        1 => 0x8FE30BBFF2660BE1UL
        2 => 0x5F9904466A39C994UL
        3 => 0x32C4AE2C1F198119UL
        _ => 0UL
      }
    }),
    y: FixedArray::makei(4, fn(i) {
      match i {
        0 => 0x02DF32E52139F0A0UL
        1 => 0xD0A9877CC62A4740UL
        2 => 0x59BDCEE36B692153UL
        3 => 0xBC3736A2F4F6779CUL
        _ => 0UL
      }
    }),
    z: FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } }),
  }
}

///|
fn two_bn() -> FixedArray[UInt64] {
  FixedArray::makei(4, fn(i) { if i == 0 { 2UL } else { 0UL } })
}
