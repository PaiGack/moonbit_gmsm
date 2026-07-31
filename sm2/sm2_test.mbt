///|
/// SM2 public API tests (blackbox).
test "sm2_generate_key" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  assert_true(@sm2.is_on_curve(public_key))
}

///|
test "sm2_sign_verify_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  assert_eq(r.length(), 32)
  assert_eq(s.length(), 32)
  assert_true(@sm2.sm2_verify(public_key, msg, uid, r, s))
}

///|
test "sm2_verify_tampered_fails" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  let r_tampered = Bytes::makei(32, fn(i) {
    if i == 0 {
      (r[0].to_int() ^ 1).to_byte()
    } else {
      r[i]
    }
  })
  assert_false(@sm2.sm2_verify(public_key, msg, uid, r_tampered, s))
  let s_tampered = Bytes::makei(32, fn(i) {
    if i == 15 {
      (s[15].to_int() ^ 1).to_byte()
    } else {
      s[i]
    }
  })
  assert_false(@sm2.sm2_verify(public_key, msg, uid, r, s_tampered))
}

///|
test "sm2_sign_verify_der_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2 der"
  let uid = @sm2.default_uid()
  let der = @sm2.sm2_sign_der(private_key, msg, uid, None)
  assert_true(@sm2.sm2_verify_der(public_key, msg, uid, der))
}

///|
test "sm2_compress_decompress_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let compressed = @sm2.compress_point(public_key)
  assert_eq(compressed.length(), 33)
  assert_true(compressed[0] == b'\x02' || compressed[0] == b'\x03')
  let decompressed = @sm2.decompress_point(compressed)
  assert_true(@sm2.is_on_curve(decompressed))
  assert_eq(compressed[0] == b'\x02', (decompressed.y[0] & 1UL) == 0UL)
}

///|
test "sm2_key_exchange" {
  let priv_a = @sm2.generate_key(None)
  let pub_a = @sm2.derive_public_key(priv_a)
  let rpriv_a = @sm2.generate_key(None)
  let rpub_a = @sm2.derive_public_key(rpriv_a)
  let priv_b = @sm2.generate_key(None)
  let pub_b = @sm2.derive_public_key(priv_b)
  let rpriv_b = @sm2.generate_key(None)
  let rpub_b = @sm2.derive_public_key(rpriv_b)
  let ida = b"1234567812345678"
  let idb = b"1234567812345678"
  let klen = 16
  let (ka, s1a, s2a) = @sm2.key_exchange_a(
    klen, ida, idb, priv_a, pub_b, rpriv_a, rpub_b,
  )
  let (kb, s1b, s2b) = @sm2.key_exchange_b(
    klen, ida, idb, priv_b, pub_a, rpriv_b, rpub_a,
  )
  // the four static/ephemeral keys must really be different, otherwise the
  // agreement below would hold trivially
  assert_false(bn_equal(priv_a.d, priv_b.d))
  assert_false(bn_equal(rpriv_a.d, rpriv_b.d))
  assert_false(bn_equal(priv_a.d, rpriv_a.d))
  assert_eq(ka.length(), klen)
  for i in 0..<klen {
    assert_eq(ka[i], kb[i])
  }
  // the key-confirmation words must agree as well
  assert_eq(s1a.length(), 32)
  assert_eq(s2a.length(), 32)
  for i in 0..<32 {
    assert_eq(s1a[i], s1b[i])
    assert_eq(s2a[i], s2b[i])
  }
  // S1 and S2 are derived from different prefixes, so they must differ
  assert_false(bytes_same(s1a, s2a))
}

///|
/// Helper: byte-wise equality without aborting.
fn bytes_same(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// Helper: compare two 4-limb scalars.
fn bn_equal(a : FixedArray[UInt64], b : FixedArray[UInt64]) -> Bool {
  for i in 0..<4 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
test "sm2_cipher_marshal_unmarshal" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"asn1 test"
  let der = @sm2.sm2_encrypt_asn1(public_key, msg, None)
  let decrypted = @sm2.sm2_decrypt_asn1(private_key, der)
  for i in 0..<msg.length() {
    assert_eq(decrypted[i], msg[i])
  }
}

///|
/// The exported ASN.1 signature converters round-trip and interoperate with
/// `sm2_sign_der` / `sm2_verify_der`.
test "sm2_sign_digit_data_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"digit/data conversion"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  let der = @sm2.sign_digit_to_sign_data(r, s)
  assert_true(@sm2.sm2_verify_der(public_key, msg, uid, der))
  let (r2, s2) = @sm2.sign_data_to_sign_digit(der)
  assert_eq(r2.length(), 32)
  assert_eq(s2.length(), 32)
  assert_true(bytes_same(r, r2))
  assert_true(bytes_same(s, s2))
  assert_true(@sm2.sm2_verify(public_key, msg, uid, r2, s2))
  // and the DER produced here is exactly what sm2_sign_der emits
  let der2 = @sm2.sign_digit_to_sign_data(r2, s2)
  assert_true(bytes_same(der, der2))
}

///|
/// `sign_data_to_sign_digit` rejects malformed DER.
test "sm2_sign_data_to_sign_digit_invalid" {
  let bad : Array[Bytes] = [
    b"",
    b"abc",
    Bytes::from_array([b'\x30', b'\x03', b'\xAA', b'\xBB', b'\xCC']),
    Bytes::from_array([b'\x30', b'\x04', b'\x02', b'\x01', b'\x00', b'\x03']),
  ]
  for der in bad {
    let r : Result[(Bytes, Bytes), @sm2.Sm2Error] = Ok(
      @sm2.sign_data_to_sign_digit(der),
    ) catch {
      e => Err(e)
    }
    match r {
      Ok(_) => abort("sign_data_to_sign_digit: expected InvalidSignature")
      Err(e) => assert_true(e is @sm2.Sm2Error::InvalidSignature)
    }
  }
}

///|
/// Both raw ciphertext layouts round-trip.
test "sm2_raw_cipher_modes" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"raw layout roundtrip"
  let c132 = @sm2.sm2_encrypt(public_key, msg, None, @sm2.C1C3C2)
  let c123 = @sm2.sm2_encrypt(public_key, msg, None, @sm2.C1C2C3)
  assert_eq(c132.length(), 1 + 64 + 32 + msg.length())
  assert_eq(c132[0], b'\x04')
  assert_true(bytes_same(@sm2.sm2_decrypt(private_key, c132, @sm2.C1C3C2), msg))
  assert_true(bytes_same(@sm2.sm2_decrypt(private_key, c123, @sm2.C1C2C3), msg))
  // the two layouts differ only in the order of C2 and C3
  assert_true(
    bytes_same(
      @sm2.sm2_decrypt(private_key, c132, @sm2.C1C3C2),
      @sm2.sm2_decrypt(
        private_key,
        @sm2.cipher_unmarshal(@sm2.cipher_marshal(c132)),
        @sm2.C1C3C2,
      ),
    ),
  )
}

///|
test "sm2_verify_rejects_wrong_message" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"correct message"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  assert_false(@sm2.sm2_verify(public_key, b"wrong message", uid, r, s))
}
