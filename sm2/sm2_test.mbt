/// SM2 public API tests (blackbox).

test "sm2_generate_key" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  assert_true!(@sm2.is_on_curve(public_key))
}

test "sm2_sign_verify_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  assert_eq!(r.length(), 32)
  assert_eq!(s.length(), 32)
  assert_true!(@sm2.sm2_verify(public_key, msg, uid, r, s))
}

test "sm2_verify_tampered_fails" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  let r_tampered = Bytes::makei(32, fn(i) { if i == 0 { (r[0].to_int() ^ 1).to_byte() } else { r[i] } })
  assert_false!(@sm2.sm2_verify(public_key, msg, uid, r_tampered, s))
  let s_tampered = Bytes::makei(32, fn(i) { if i == 15 { (s[15].to_int() ^ 1).to_byte() } else { s[i] } })
  assert_false!(@sm2.sm2_verify(public_key, msg, uid, r, s_tampered))
}

test "sm2_sign_verify_der_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2 der"
  let uid = @sm2.default_uid()
  let der = @sm2.sm2_sign_der(private_key, msg, uid, None)
  assert_true!(@sm2.sm2_verify_der(public_key, msg, uid, der))
}

test "sm2_compress_decompress_roundtrip" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let compressed = @sm2.compress_point(public_key)
  assert_eq!(compressed.length(), 33)
  assert_true!(compressed[0] == b'\x02' || compressed[0] == b'\x03')
  let decompressed = @sm2.decompress_point(compressed)
  assert_true!(@sm2.is_on_curve(decompressed))
  assert_eq!(compressed[0] == b'\x02', (decompressed.y[0] & 1UL) == 0UL)
}

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
  let (ka, _, _) = @sm2.key_exchange_a(klen, ida, idb, priv_a, pub_b, rpriv_a, rpub_b)
  let (kb, _, _) = @sm2.key_exchange_b(klen, ida, idb, priv_b, pub_a, rpriv_b, rpub_a)
  for i = 0; i < 16; i = i + 1 { assert_eq!(ka[i], kb[i]) }
}

test "sm2_cipher_marshal_unmarshal" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"asn1 test"
  let der = @sm2.sm2_encrypt_asn1(public_key, msg, None)
  let decrypted = @sm2.sm2_decrypt_asn1(private_key, der)
  for i = 0; i < msg.length(); i = i + 1 { assert_eq!(decrypted[i], msg[i]) }
}

test "sm2_verify_rejects_wrong_message" {
  let private_key = @sm2.generate_key(None)
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"correct message"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, None)
  assert_false!(@sm2.sm2_verify(public_key, b"wrong message", uid, r, s))
}
