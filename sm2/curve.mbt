/// SM2 Curve and Point Operations
/// Uses Jacobian projective coordinates: (X, Y, Z)

///|
/// SM2 Point in Jacobian coordinates
pub(all) struct SM2Point {
  x : FixedArray[UInt64]  // length 4
  y : FixedArray[UInt64]  // length 4
  z : FixedArray[UInt64]  // length 4
}

///|
/// Create a new point (0, 0, 0) — the point at infinity
pub fn point_infinity() -> SM2Point {
  SM2Point::{
    x: FixedArray::makei(4, fn(_) { 0UL }),
    y: FixedArray::makei(4, fn(_) { 0UL }),
    z: FixedArray::makei(4, fn(_) { 0UL }),
  }
}

///|
/// Check if point is at infinity (z == 0)
pub fn point_is_infinity(p : SM2Point) -> Bool {
  bn_is_zero(p.z)
}

///|
/// Set point to infinity
pub fn point_set_infinity(p : SM2Point) -> Unit {
  bn_zero(p.x)
  bn_zero(p.y)
  bn_zero(p.z)
}

///|
/// Copy src to dst
pub fn point_copy(dst : SM2Point, src : SM2Point) -> Unit {
  bn_copy(dst.x, src.x)
  bn_copy(dst.y, src.y)
  bn_copy(dst.z, src.z)
}

///|
/// Convert Jacobian point to affine coordinates
pub fn point_to_affine(p : SM2Point) -> (FixedArray[UInt64], FixedArray[UInt64]) {
  let x : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let y : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })

  if point_is_infinity(p) {
    return (x, y)
  }

  let z_inv : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modinv_p(z_inv, p.z)

  let z_inv2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(z_inv2, z_inv)

  let z_inv3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(z_inv3, z_inv2, z_inv)

  bn_modmul_p(x, p.x, z_inv2)
  bn_modmul_p(y, p.y, z_inv3)

  (x, y)
}

///|
/// Check if affine point (x, y) is on the curve: y^2 ≡ x^3 + a*x + b (mod p)
pub fn point_is_on_curve_affine(x : FixedArray[UInt64], y : FixedArray[UInt64]) -> Bool {
  let y2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(y2, y)

  let x2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(x2, x)

  let x3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(x3, x2, x)

  // a = p - 3, so a*x ≡ -3*x mod p
  let three_x : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_add(three_x, x, x) |> ignore
  let tmp : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_copy(tmp, three_x)
  bn_add(three_x, tmp, x) |> ignore

  let p = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0xFFFFFFFFFFFFFFFFUL
      1 => 0xFFFFFFFF00000000UL
      2 => 0xFFFFFFFFFFFFFFFFUL
      3 => 0xFFFFFFFEFFFFFFFFUL
      _ => abort("unreachable")
    }
  })
  let three_x_mod = FixedArray::makei(4, fn(_) { 0UL })
  bn_copy(three_x_mod, three_x)
  if !bn_lt(three_x_mod, p) {
    bn_sub(three_x_mod, three_x_mod, p) |> ignore
  }

  let ax : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  if bn_is_zero(three_x_mod) {
    bn_zero(ax)
  } else {
    bn_sub(ax, p, three_x_mod) |> ignore
  }

  let rhs : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(rhs, x3, ax)

  let b_limbs = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0xDDBCBD414D940E93UL
      1 => 0xF39789F515AB8F92UL
      2 => 0x4D5A9E4BCF6509A7UL
      3 => 0x28E9FA9E9D9F5E34UL
      _ => abort("unreachable")
    }
  })
  bn_addmod_p(rhs, rhs, b_limbs)

  bn_eq(y2, rhs)
}

///|
/// Point doubling: p = 2 * p (in place, Jacobian coordinates)
pub fn point_double(p : SM2Point) -> Unit {
  if point_is_infinity(p) {
    return
  }

  let t1 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let t2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let t3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let t4 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })

  // t1 = Z^2
  bn_modsqr_p(t1, p.z)
  // t2 = Y^2
  bn_modsqr_p(t2, p.y)
  // t3 = X - t1
  bn_submod_p(t3, p.x, t1)
  // t4 = X + t1
  bn_addmod_p(t4, p.x, t1)
  // t1 = t3 * t4 mod p
  bn_modmul_p(t1, t3, t4)
  // t3 = 3 * t1 mod p
  bn_addmod_p(t3, t1, t1)
  bn_addmod_p(t3, t3, t1)
  // t4 = Y * Z
  bn_modmul_p(t4, p.y, p.z)
  // t4 = 2 * t4 mod p
  bn_addmod_p(t4, t4, t4)

  // Z3 = 2 * Y * Z mod p = t4
  bn_copy(p.z, t4)

  // t2 = 4 * X * t2 mod p
  bn_modmul_p(t2, p.x, t2)
  bn_addmod_p(t2, t2, t2)
  bn_addmod_p(t2, t2, t2)

  // X3 = t3^2 - 2 * t2
  bn_modsqr_p(p.x, t3)
  let two_t2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(two_t2, t2, t2)
  bn_submod_p(p.x, p.x, two_t2)

  // t2 = t2 - X3
  bn_submod_p(t2, t2, p.x)
  // t2 = t3 * t2
  bn_modmul_p(t2, t3, t2)
  // t2 = t2 - 8 * Y^4
  let y2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(y2, p.y)
  let y4 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(y4, y2)
  let eight_y4 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(eight_y4, y4, y4)
  bn_addmod_p(eight_y4, eight_y4, eight_y4)
  bn_addmod_p(eight_y4, eight_y4, eight_y4)
  bn_submod_p(p.y, t2, eight_y4)
}

///|
/// Point addition: p = p + q (both in Jacobian coordinates, full J+J)
pub fn point_add(p : SM2Point, q : SM2Point) -> Unit {
  if point_is_infinity(q) {
    return
  }
  if point_is_infinity(p) {
    point_copy(p, q)
    return
  }

  let u1 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let u2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let s1 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let s2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let h : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let r_val : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })

  let z2_sq : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(z2_sq, q.z)
  bn_modmul_p(u1, p.x, z2_sq)

  let z1_sq : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(z1_sq, p.z)
  bn_modmul_p(u2, q.x, z1_sq)

  bn_submod_p(h, u2, u1)

  let z2_cu : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(z2_cu, z2_sq, q.z)
  bn_modmul_p(s1, p.y, z2_cu)

  let z1_cu : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(z1_cu, z1_sq, p.z)
  bn_modmul_p(s2, q.y, z1_cu)

  bn_submod_p(r_val, s2, s1)

  if bn_is_zero(h) {
    if bn_is_zero(r_val) {
      point_double(p)
      return
    }
    point_set_infinity(p)
    return
  }

  let h_sq : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(h_sq, h)
  let h_cu : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(h_cu, h_sq, h)

  let r_sq : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(r_sq, r_val)
  let u1h2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(u1h2, u1, h_sq)
  let two_u1h2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(two_u1h2, u1h2, u1h2)

  let x3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_submod_p(x3, r_sq, h_cu)
  bn_submod_p(x3, x3, two_u1h2)

  let y3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_submod_p(u1h2, u1h2, x3)
  bn_modmul_p(y3, r_val, u1h2)
  let s1h3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(s1h3, s1, h_cu)
  bn_submod_p(y3, y3, s1h3)

  let z3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(z3, h, p.z)
  bn_modmul_p(z3, z3, q.z)

  bn_copy(p.x, x3)
  bn_copy(p.y, y3)
  bn_copy(p.z, z3)
}

///|
/// Point addition where q has z=1 (affine or mixed addition) — optimized
pub fn point_add_affine(p : SM2Point, qx : FixedArray[UInt64], qy : FixedArray[UInt64]) -> Unit {
  if point_is_infinity(p) {
    bn_copy(p.x, qx)
    bn_copy(p.y, qy)
    bn_zero(p.z)
    p.z[0] = 1UL
    return
  }

  let t1 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let t2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let t3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let t4 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })

  bn_modsqr_p(t1, p.z)
  bn_modmul_p(t2, t1, p.z)
  bn_modmul_p(t1, t1, qx)
  bn_modmul_p(t2, t2, qy)
  bn_submod_p(t1, t1, p.x)
  bn_submod_p(t2, t2, p.y)

  if bn_is_zero(t1) {
    if bn_is_zero(t2) {
      point_double(p)
      return
    }
    point_set_infinity(p)
    return
  }

  bn_modsqr_p(t3, t1)
  bn_modmul_p(t4, t3, t1)
  let u1h2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(u1h2, p.x, t3)

  let r2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modsqr_p(r2, t2)
  bn_submod_p(p.x, r2, t4)
  let two_u1h2 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(two_u1h2, u1h2, u1h2)
  bn_submod_p(p.x, p.x, two_u1h2)

  bn_submod_p(u1h2, u1h2, p.x)
  bn_modmul_p(u1h2, u1h2, t2)
  let s1h3 : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(s1h3, p.y, t4)
  bn_submod_p(p.y, u1h2, s1h3)

  bn_modmul_p(p.z, t1, p.z)
}

///|
/// Scalar multiplication: result = k * point, using double-and-add
pub fn scalar_mult(
  result : SM2Point,
  k : FixedArray[UInt64],
  p : SM2Point,
) -> Unit {
  point_set_infinity(result)

  let other : SM2Point = point_infinity()
  point_copy(other, p)

  for limb_idx = 3; limb_idx >= 0; limb_idx = limb_idx - 1 {
    let mut k_val = k[limb_idx]
    for _bit = 0; _bit < 64; _bit = _bit + 1 {
      if !point_is_infinity(result) {
        point_double(result)
      }

      let bit_val = (k_val >> 63) & 1UL
      k_val = k_val << 1

      if bit_val == 1UL {
        if point_is_infinity(result) {
          point_copy(result, other)
        } else {
          point_add(result, other)
        }
      }
    }
  }
}

///|
/// Scalar multiplication with base point G
pub fn scalar_base_mult(
  result : SM2Point,
  k : FixedArray[UInt64],
) -> Unit {
  let g = SM2Point::{
    x: FixedArray::makei(4, fn(i) {
      match i {
        0 => 0x715A4589334C74C7UL
        1 => 0x8FE30BBFF2660BE1UL
        2 => 0x5F9904466A39C994UL
        3 => 0x32C4AE2C1F198119UL
        _ => abort("unreachable")
      }
    }),
    y: FixedArray::makei(4, fn(i) {
      match i {
        0 => 0x02DF32E52139F0A0UL
        1 => 0xD0A9877CC62A4740UL
        2 => 0x59BDCEE36B692153UL
        3 => 0xBC3736A2F4F6779CUL
        _ => abort("unreachable")
      }
    }),
    z: FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } }),
  }
  scalar_mult(result, k, g)
}

///|
/// Negate a point: y = -y mod p
pub fn point_neg(p : SM2Point) -> Unit {
  if point_is_infinity(p) {
    return
  }
  let pp = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0xFFFFFFFFFFFFFFFFUL
      1 => 0xFFFFFFFF00000000UL
      2 => 0xFFFFFFFFFFFFFFFFUL
      3 => 0xFFFFFFFEFFFFFFFFUL
      _ => abort("unreachable")
    }
  })
  let neg_y : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_sub(neg_y, pp, p.y) |> ignore
  bn_copy(p.y, neg_y)
}

///|
/// Compare two points for equality (in affine)
pub fn point_eq(a : SM2Point, b : SM2Point) -> Bool {
  let (ax, ay) = point_to_affine(a)
  let (bx, by) = point_to_affine(b)
  bn_eq(ax, bx) && bn_eq(ay, by)
}
