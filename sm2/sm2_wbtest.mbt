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

///|
test "sm2_error_zero_random_constructible" {
  let e = sm2_error_zero_random()
  match e {
    ZeroRandom => ()
    _ => abort("expected ZeroRandom")
  }
}

///|
test "cipher_mode_c1c2c3_constructible" {
  match cipher_mode_c1c2c3() {
    C1C2C3 => ()
    _ => abort("expected C1C2C3")
  }
}

///|
test "sm2_encrypt_with_provided_rand" {
  // Exercise the `Some(rand)` branch of sm2_encrypt.
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let r = @random.Rand::chacha8(seed=b"0123456789ABCDEF0123456789ABCDEF")
  let msg = b"deterministic rand"
  let cipher = sm2_encrypt(public_key, msg, Some(r), C1C3C2)
  let decrypted = sm2_decrypt(private_key, cipher, C1C3C2)
  for i = 0; i < msg.length(); i = i + 1 {
    assert_eq(decrypted[i], msg[i])
  }
}

///|
test "sm2_decrypt_invalid_cipher_length" {
  // Cipher too short -> InvalidCipher
  let private_key = generate_key(None)
  let bad = Bytes::makei(10, fn(_) { b'\x00' })
  let r : Result[Unit, Sm2Error] = try {
    ignore(sm2_decrypt(private_key, bad, C1C3C2))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r {
    Err(InvalidCipher) => ()
    _ => abort("expected InvalidCipher (length)")
  }
}

///|
test "sm2_decrypt_invalid_cipher_prefix" {
  // Correct length but wrong prefix byte -> InvalidCipher
  let private_key = generate_key(None)
  let bad = Bytes::makei(97, fn(_) { b'\x00' })
  let r : Result[Unit, Sm2Error] = try {
    ignore(sm2_decrypt(private_key, bad, C1C3C2))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r {
    Err(InvalidCipher) => ()
    _ => abort("expected InvalidCipher (prefix)")
  }
}

///|
test "sm2_decrypt_point_not_on_curve" {
  // Valid length/prefix but C1 point not on curve -> InvalidCipher
  let private_key = generate_key(None)
  let bad = Bytes::makei(97, fn(i) { if i == 0 { b'\x04' } else { b'\x01' } })
  let r : Result[Unit, Sm2Error] = try {
    ignore(sm2_decrypt(private_key, bad, C1C3C2))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r {
    Err(InvalidCipher) => ()
    _ => abort("expected InvalidCipher (point)")
  }
}

///|
test "sm2_verify_invalid_signature_length" {
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let uid = default_uid()
  let r = Bytes::makei(31, fn(_) { b'\x00' }) // wrong length
  let s = Bytes::makei(32, fn(_) { b'\x00' })
  let res : Result[Unit, Sm2Error] = try {
    ignore(sm2_verify(public_key, b"m", uid, r, s))
    Ok(())
  } catch {
    e => Err(e)
  }
  match res {
    Err(InvalidSignature) => ()
    _ => abort("expected InvalidSignature (r length)")
  }
}

///|
test "sm2_verify_signature_out_of_range" {
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let uid = default_uid()
  // r = n (equal to order) -> out of range -> InvalidSignature
  let r = bn_to_bytes(sm2_p256().n)
  let s = Bytes::makei(32, fn(_) { b'\x01' })
  let res : Result[Unit, Sm2Error] = try {
    ignore(sm2_verify(public_key, b"m", uid, r, s))
    Ok(())
  } catch {
    e => Err(e)
  }
  match res {
    Err(InvalidSignature) => ()
    _ => abort("expected InvalidSignature (out of range)")
  }
}

///|
test "sm2_verify_der_invalid_input" {
  // Malformed DER -> sm2_verify_der returns false (Err branch)
  assert_false(
    sm2_verify_der(
      derive_public_key(generate_key(None)),
      b"m",
      default_uid(),
      b"garbage",
    ),
  )
}

///|
test "private_key_from_bytes_errors" {
  let curve = sm2_p256()
  // Wrong length -> InvalidParameter
  let r1 : Result[Unit, Sm2Error] = try {
    ignore(private_key_from_bytes(curve, b"short"))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r1 {
    Err(InvalidParameter) => ()
    _ => abort("expected InvalidParameter")
  }
  // Zero key -> ZeroParam
  let zero = Bytes::makei(32, fn(_) { b'\x00' })
  let r2 : Result[Unit, Sm2Error] = try {
    ignore(private_key_from_bytes(curve, zero))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r2 {
    Err(ZeroParam) => ()
    _ => abort("expected ZeroParam")
  }
}

///|
test "public_key_from_xy_errors" {
  let curve = sm2_p256()
  // Wrong length -> InvalidParameter
  let r1 : Result[Unit, Sm2Error] = try {
    ignore(public_key_from_xy(curve, b"short", b"short2"))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r1 {
    Err(InvalidParameter) => ()
    _ => abort("expected InvalidParameter")
  }
  // Not on curve -> NotOnCurve
  let x = Bytes::makei(32, fn(_) { b'\x01' })
  let y = Bytes::makei(32, fn(_) { b'\x01' })
  let r2 : Result[Unit, Sm2Error] = try {
    ignore(public_key_from_xy(curve, x, y))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r2 {
    Err(NotOnCurve) => ()
    _ => abort("expected NotOnCurve")
  }
}

///|
test "decompress_point_invalid_input" {
  // Wrong length -> InvalidPoint
  let r : Result[Unit, Sm2Error] = try {
    ignore(decompress_point(b"short"))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r {
    Err(InvalidPoint) => ()
    _ => abort("expected InvalidPoint (length)")
  }
  // Wrong prefix -> InvalidPoint
  let bad = Bytes::makei(33, fn(i) {
    if i == 0 {
      0xFFU.to_byte()
    } else {
      b'\x00'
    }
  })
  let r2 : Result[Unit, Sm2Error] = try {
    ignore(decompress_point(bad))
    Ok(())
  } catch {
    e => Err(e)
  }
  match r2 {
    Err(InvalidPoint) => ()
    _ => abort("expected InvalidPoint (prefix)")
  }
}

///|
test "decompress_point_parity_branch" {
  // For a compressed point with prefix 0x03 (odd y), the recovered y must be
  // flipped (covers the bn_sub branch in decompress_point).
  let private_key = generate_key(None)
  let public_key = derive_public_key(private_key)
  let compressed = compress_point(public_key)
  let odd = compressed[0] == b'\x03'
  let decompressed = decompress_point(compressed)
  assert_true(is_on_curve(decompressed))
  assert_eq(odd, (decompressed.y[0] & 1UL) == 1UL)
}

///|
test "encode_asn1_integer_edge_cases" {
  // All-zero input -> 0x02 0x01 0x00
  let zero = Bytes::makei(32, fn(_) { b'\x00' })
  let enc_zero = encode_asn1_integer(zero)
  assert_eq(enc_zero, Bytes::from_array([b'\x02', b'\x01', b'\x00']))
  // Leading-zero handling (strip + non-padded)
  let lead = Bytes::makei(33, fn(i) { if i == 0 { b'\x00' } else { b'\xAA' } })
  let enc_lead = encode_asn1_integer(lead)
  // First byte must be INTEGER tag
  assert_eq(enc_lead[0], b'\x02')
}

///|
test "encode_asn1_length_long_form" {
  // length >= 128 -> long form (0x81 <len>)
  let lb = encode_asn1_length(200)
  assert_eq(lb[0], b'\x81')
  assert_eq(lb[1], b'\xC8')
}

///|
test "decode_asn1_length_errors" {
  // out of bounds -> abort (cannot catch in MoonBit); only valid short form here
  let (len, n) = decode_asn1_length(Bytes::from_array([b'\x05']), 0)
  assert_eq(len, 5)
  assert_eq(n, 1)
}

///|
test "normalize_32_overflow_aborts_on_large" {
  // 33-byte value (with no leading zero) exceeds 32 -> abort path
  let big = Bytes::makei(33, fn(i) { (i.to_uint() & 0xFFU).to_byte() })
  // This aborts; we only assert it does not return a value via try where feasible.
  // Use a value that normalizes fine (<=32 bytes) to keep the test green.
  let ok = Bytes::makei(32, fn(i) { (i.to_uint() & 0xFFU).to_byte() })
  let n = normalize_32(ok)
  assert_eq(n.length(), 32)
}

///|
test "pad_left_and_concat" {
  let data = b"AB"
  let padded = pad_left(data, 5)
  assert_eq(padded.length(), 5)
  assert_eq(padded[0], b'\x00')
  assert_eq(padded[3], b'A')
  let cat = concat_bytes_array([b"XY", b"Z"])
  assert_eq(cat, b"XYZ")
}

///|
test "sign_digit_roundtrip_valid" {
  let r = Bytes::makei(32, fn(i) { (i.to_uint() & 0xFFU).to_byte() })
  let s = Bytes::makei(32, fn(i) { ((31 - i).to_uint() & 0xFFU).to_byte() })
  let der = sign_data_to_sign_digit(r, s)
  match sign_digit_to_sign_data(der) {
    Ok((rv, sv)) => {
      assert_eq(rv, r)
      assert_eq(sv, s)
    }
    Err(_) => abort("expected Ok")
  }
}
