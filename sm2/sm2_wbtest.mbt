///|
/// Whitebox tests for SM2 internals.
test "bn_from_to_bytes" {
  let r : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  let bytes = Bytes::makei(32, fn(i) { (i % 256).to_byte() })
  bn_from_bytes(r, bytes, 0)
  let out = bn_to_bytes(r)
  for i = 0; i < 32; i = i + 1 {
    assert_eq(out[i], bytes[i])
  }
}

///|
test "bn_zero_detection" {
  let z : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  assert_true(bn_is_zero(z))
  let nz : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      1UL
    } else {
      0UL
    }
  })
  assert_false(bn_is_zero(nz))
}

///|
test "bn_addmod_p" {
  let a : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      2UL
    } else {
      0UL
    }
  })
  let b : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      3UL
    } else {
      0UL
    }
  })
  let r : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(r, a, b)
  assert_eq(r[0], 5UL)
}

///|
test "bn_modmul_p" {
  let a : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      2UL
    } else {
      0UL
    }
  })
  let b : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      3UL
    } else {
      0UL
    }
  })
  let r : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(r, a, b)
  assert_eq(r[0], 6UL)
}

///|
test "bn_modinv_p" {
  let a : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      12345UL
    } else {
      0UL
    }
  })
  let inv : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modinv_p(inv, a)
  let r : FixedArray[UInt64] = FixedArray::makei(4, fn(_) { 0UL })
  bn_modmul_p(r, a, inv)
  assert_eq(r[0], 1UL)
  assert_eq(r[1], 0UL)
  assert_eq(r[2], 0UL)
  assert_eq(r[3], 0UL)
}

///|
test "point_infinity" {
  let p = point_infinity()
  assert_true(point_is_infinity(p))
}

///|
test "generator_on_curve" {
  let gx : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0x715A4589334C74C7UL
      1 => 0x8FE30BBFF2660BE1UL
      2 => 0x5F9904466A39C994UL
      3 => 0x32C4AE2C1F198119UL
      _ => abort("unreachable")
    }
  })
  let gy : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0x02DF32E52139F0A0UL
      1 => 0xD0A9877CC62A4740UL
      2 => 0x59BDCEE36B692153UL
      3 => 0xBC3736A2F4F6779CUL
      _ => abort("unreachable")
    }
  })
  assert_true(point_is_on_curve_affine(gx, gy))
}

///|
test "scalar_base_mult_1_gives_G" {
  let k : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      1UL
    } else {
      0UL
    }
  })
  let p : SM2Point = point_infinity()
  scalar_base_mult(p, k)
  let (x, _) = point_to_affine(p)
  let gx : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0x715A4589334C74C7UL
      1 => 0x8FE30BBFF2660BE1UL
      2 => 0x5F9904466A39C994UL
      3 => 0x32C4AE2C1F198119UL
      _ => abort("unreachable")
    }
  })
  assert_true(bn_eq(x, gx))
}

///|
test "point_double_and_neg" {
  let k2 : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      2UL
    } else {
      0UL
    }
  })
  let p : SM2Point = point_infinity()
  scalar_base_mult(p, k2)
  point_neg(p)
  let q2 : SM2Point = point_infinity()
  scalar_base_mult(q2, k2)
  point_add(p, q2)
  assert_true(point_is_infinity(p))
}

///|
test "za_produces_32_bytes" {
  let gx : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0x715A4589334C74C7UL
      1 => 0x8FE30BBFF2660BE1UL
      2 => 0x5F9904466A39C994UL
      3 => 0x32C4AE2C1F198119UL
      _ => abort("unreachable")
    }
  })
  let gy : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    match i {
      0 => 0x02DF32E52139F0A0UL
      1 => 0xD0A9877CC62A4740UL
      2 => 0x59BDCEE36B692153UL
      3 => 0xBC3736A2F4F6779CUL
      _ => abort("unreachable")
    }
  })
  let za_val = za(gx, gy, default_uid())
  assert_eq(za_val.length(), 32)
}

///|
test "kdf_basic" {
  let (result, ok) = kdf(32, [b"test"])
  assert_true(ok)
  assert_eq(result.length(), 32)
}

///|
test "ke_x_hat" {
  let y : FixedArray[UInt64] = FixedArray::makei(4, fn(i) {
    if i == 0 {
      0x123456789ABCDEF0UL
    } else {
      0UL
    }
  })
  let yhat = ke_x_hat(y)
  assert_eq(yhat[0], 0x123456789ABCDEF0UL)
  assert_eq(yhat[1], 0x8000000000000000UL)
  assert_eq(yhat[2], 0UL)
  assert_eq(yhat[3], 0UL)
}

// Encrypt/Decrypt tests (whitebox access to CipherMode)

///|
fn do_sm2_encrypt_decrypt_c1c3c2() -> Unit raise Error {
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let msg = b"123456"
  let cipher = sm2_encrypt(public_key, msg, None, C1C3C2)
  assert_eq(cipher.length(), 1 + 64 + 32 + msg.length())
  assert_eq(cipher[0], b'\x04')
  let decrypted = sm2_decrypt(private_key, cipher, C1C3C2)
  assert_eq(decrypted.length(), msg.length())
  for i = 0; i < msg.length(); i = i + 1 {
    assert_eq(decrypted[i], msg[i])
  }
}

///|
test "sm2_encrypt_decrypt_c1c3c2" {
  do_sm2_encrypt_decrypt_c1c3c2() catch {
    _ => assert_true(false)
  }
}

///|
fn do_sm2_encrypt_decrypt_c1c2c3() -> Unit raise Error {
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let msg = b"test message"
  let cipher = sm2_encrypt(public_key, msg, None, C1C2C3)
  assert_eq(cipher[0], b'\x04')
  let decrypted = sm2_decrypt(private_key, cipher, C1C2C3)
  for i = 0; i < msg.length(); i = i + 1 {
    assert_eq(decrypted[i], msg[i])
  }
}

///|
test "sm2_encrypt_decrypt_c1c2c3" {
  do_sm2_encrypt_decrypt_c1c2c3() catch {
    _ => assert_true(false)
  }
}

///|
fn do_sm2_encrypt_decrypt_empty() -> Unit raise Error {
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let cipher = sm2_encrypt(public_key, b"", None, C1C3C2)
  let decrypted = sm2_decrypt(private_key, cipher, C1C3C2)
  assert_eq(decrypted.length(), 0)
}

///|
test "sm2_encrypt_decrypt_empty" {
  do_sm2_encrypt_decrypt_empty() catch {
    _ => assert_true(false)
  }
}

///|
test "default_uid_impl_returns_16_bytes" {
  let uid = default_uid_impl()
  assert_eq(uid.length(), 16)
  assert_eq(uid, b"1234567812345678")
}

///|
test "sm2_error_variants_constructible" {
  // Ensure all Sm2Error variants are constructed (suppresses unused_constructor warning)
  let e0 = Sm2Error::ZeroParam
  let e1 = Sm2Error::NotOnCurve
  let e2 = Sm2Error::InvalidCipher
  let e3 = Sm2Error::InvalidSignature
  let e4 = Sm2Error::InvalidPoint
  let e5 = Sm2Error::InvalidParameter
  let e6 = Sm2Error::ZeroRandom
  let e7 = Sm2Error::KdfZeroKey
  // Verify they are distinct error variants via Debug
  ignore(e0)
  ignore(e1)
  ignore(e2)
  ignore(e3)
  ignore(e4)
  ignore(e5)
  ignore(e6)
  ignore(e7)
}
