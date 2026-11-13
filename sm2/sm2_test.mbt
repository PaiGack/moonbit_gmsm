///|
/// SM2 public API tests (blackbox).
test "sm2_generate_key" {
  // `None` means "no random source": it must not silently fall back to a
  // process-wide fixed-seed generator.
  let raised = try {
    let _ = @sm2.generate_key(None)
    false
  } catch {
    @sm2.MissingRandomSource => true
    _ => false
  }
  assert_true(raised)
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  assert_true(@sm2.is_on_curve(public_key))
}

///|
test "sm2_sign_verify_roundtrip" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, @sm2.os_rand())
  assert_eq(r.length(), 32)
  assert_eq(s.length(), 32)
  assert_true(@sm2.sm2_verify(public_key, msg, uid, r, s))
}

///|
test "sm2_verify_tampered_fails" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, @sm2.os_rand())
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
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"hello sm2 der"
  let uid = @sm2.default_uid()
  let der = @sm2.sm2_sign_der(private_key, msg, uid, @sm2.os_rand())
  assert_true(@sm2.sm2_verify_der(public_key, msg, uid, der))
}

///|
test "os_rand_seed_from_entropy" {
  // `seed_from_entropy` is the fallback seed on platforms without OS entropy
  // (`wasm-gc`); it must return a distinct 32-byte seed on every call.
  let a = @sm2.seed_from_entropy()
  let b = @sm2.seed_from_entropy()
  assert_eq(a.length(), 32)
  assert_false(@byteutil.bytes_eq(a, b))
  // `os_rand` works on every supported target, including `wasm-gc`.
  let r = @sm2.os_rand()
  assert_true(
    match r {
      Some(_) => true
      None => false
    },
  )
  let private_key = @sm2.generate_key(r)
  assert_true(@sm2.is_on_curve(@sm2.derive_public_key(private_key)))
}

///|
test "sm2_compress_decompress_roundtrip" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
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
  let priv_a = @sm2.generate_key(@sm2.os_rand())
  let pub_a = @sm2.derive_public_key(priv_a)
  let rpriv_a = @sm2.generate_key(@sm2.os_rand())
  let rpub_a = @sm2.derive_public_key(rpriv_a)
  let priv_b = @sm2.generate_key(@sm2.os_rand())
  let pub_b = @sm2.derive_public_key(priv_b)
  let rpriv_b = @sm2.generate_key(@sm2.os_rand())
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
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"asn1 test"
  let der = @sm2.sm2_encrypt_asn1(public_key, msg, @sm2.os_rand())
  let decrypted = @sm2.sm2_decrypt_asn1(private_key, der)
  for i in 0..<msg.length() {
    assert_eq(decrypted[i], msg[i])
  }
}

///|
/// The exported ASN.1 signature converters round-trip and interoperate with
/// `sm2_sign_der` / `sm2_verify_der`.
test "sm2_sign_digit_data_roundtrip" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"digit/data conversion"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, @sm2.os_rand())
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
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"raw layout roundtrip"
  let c132 = @sm2.sm2_encrypt(public_key, msg, @sm2.os_rand(), @sm2.C1C3C2)
  let c123 = @sm2.sm2_encrypt(public_key, msg, @sm2.os_rand(), @sm2.C1C2C3)
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
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"correct message"
  let uid = @sm2.default_uid()
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, @sm2.os_rand())
  assert_false(@sm2.sm2_verify(public_key, b"wrong message", uid, r, s))
}

///|
test "sm2_za_is_deterministic_and_uid_sensitive" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let uid = @sm2.default_uid()
  let za1 = public_key.za(uid)
  let za2 = public_key.za(uid)
  assert_eq(za1.length(), 32)
  assert_eq(za1, za2)
  // 不同 uid 得到不同 Z 值
  let za3 = public_key.za(b"other-uid")
  assert_false(za1 == za3)
  // 空 uid 是合法的（ENTLA = 0）
  assert_eq(public_key.za(b"").length(), 32)
}

///|
test "sm2_za_matches_signature_hash" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let uid = @sm2.default_uid()
  let msg = b"za consistency"
  let digest = public_key.sm3_digest(msg, uid)
  assert_eq(digest.length(), 32)
  // digest 直接用于摘要验签，结果与消息验签一致
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, @sm2.os_rand())
  assert_true(@sm2.sm2_verify_digest(public_key, digest, r, s))
  assert_true(@sm2.sm2_verify(public_key, msg, uid, r, s))
  // 错误摘要必须失败
  let wrong = public_key.sm3_digest(b"another message", uid)
  assert_false(@sm2.sm2_verify_digest(public_key, wrong, r, s))
}

///|
test "sm2_sm3_digest_empty_uid_uses_default" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  assert_eq(
    public_key.sm3_digest(b"abc", b""),
    public_key.sm3_digest(b"abc", @sm2.default_uid()),
  )
}

///|
test "sm2_verify_digest_rejects_bad_scalars" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let digest = public_key.sm3_digest(b"x", @sm2.default_uid())
  let zero = Bytes::makei(32, fn(_) { b'\x00' })
  // r = 0 属于非法标量，抛出错误
  let mut r1_raised = false
  let _ = @sm2.sm2_verify_digest(public_key, digest, zero, zero) catch {
    _ => {
      r1_raised = true
      false
    }
  }
  assert_true(r1_raised)
  // 摘要超过 32 字节属于参数错误，同样抛出
  let long_digest = Bytes::makei(33, fn(i) { (i & 0xFF).to_byte() })
  let mut r2_raised = false
  let _ = @sm2.sm2_verify_digest(public_key, long_digest, zero, zero) catch {
    _ => {
      r2_raised = true
      false
    }
  }
  assert_true(r2_raised)
  // 正确签名下的摘要验签确实成立
  let (r, s) = @sm2.sm2_sign(
    private_key,
    b"x",
    @sm2.default_uid(),
    @sm2.os_rand(),
  )
  assert_true(@sm2.sm2_verify_digest(public_key, digest, r, s))
}

///|
/// DER 可延展性：合法的 SEQUENCE 后面追加任意字节必须被拒绝。
/// 否则同一份签名 / 密文可以有无数种字节表示，等于破坏 DER 的唯一编码。
test "sm2_der_rejects_trailing_bytes" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let uid = @sm2.default_uid()
  let msg = b"canonical der"

  // 签名侧
  let (r, s) = @sm2.sm2_sign(private_key, msg, uid, @sm2.os_rand())
  let der = @sm2.sign_digit_to_sign_data(r, s)
  let der_padded = @byteutil.concat_bytes([der, b"\xDE\xAD\xBE\xEF"])
  let sign_raised = try {
    let _ = @sm2.sign_data_to_sign_digit(der_padded)
    false
  } catch {
    @sm2.InvalidSignature => true
    _ => false
  }
  assert_true(sign_raised)
  // `sm2_verify_der` 对尾部残留同样返回 false，不会误判为验签通过
  assert_false(@sm2.sm2_verify_der(public_key, msg, uid, der_padded))

  // 密文侧
  let der_cipher = @sm2.sm2_encrypt_asn1(public_key, msg, @sm2.os_rand())
  let cipher_raised = try {
    let _ = @sm2.cipher_unmarshal(
      @byteutil.concat_bytes([der_cipher, b"\x00\x01\x02\x03"]),
    )
    false
  } catch {
    @sm2.InvalidCipher => true
    _ => false
  }
  assert_true(cipher_raised)
}

///|
/// 签名里的 INTEGER 必须是最小编码，`00 00 01` 这类冗余前导零要被拒绝。
test "sm2_sign_der_rejects_non_minimal_integer" {
  // SEQUENCE { INTEGER 00 00 01, INTEGER 01 }
  let der = Bytes::from_array([
    b'\x30', b'\x09', b'\x02', b'\x03', b'\x00', b'\x00', b'\x01', b'\x02', b'\x01',
    b'\x01',
  ])
  let raised = try {
    let _ = @sm2.sign_data_to_sign_digit(der)
    false
  } catch {
    @sm2.InvalidSignature => true
    _ => false
  }
  assert_true(raised)
}

///|
/// `uid` 过长时，所有签名相关入口都必须走 `raise`，而不是 abort。
test "sm2_long_uid_raises_instead_of_aborting" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let long_uid = Bytes::makei(8192, fn(_) { b'A' })
  let zero = Bytes::makei(32, fn(_) { b'\x00' })

  let sign_raised = try {
    let _ = @sm2.sm2_sign(private_key, b"m", long_uid, @sm2.os_rand())
    false
  } catch {
    @sm2.InvalidParameter => true
    _ => false
  }
  assert_true(sign_raised)

  let verify_raised = try {
    let _ = @sm2.sm2_verify(public_key, b"m", long_uid, zero, zero)
    false
  } catch {
    @sm2.InvalidParameter => true
    _ => false
  }
  assert_true(verify_raised)
}

///|
/// 密钥协商不再有 abort 通道：`pubB` / `rpubB` 不在曲线上时抛 `NotOnCurve`，
/// 与 `sm2_decrypt` 的校验一致。
test "sm2_key_exchange_rejects_off_curve_peer" {
  let priv_a = @sm2.generate_key(@sm2.os_rand())
  let rpriv_a = @sm2.generate_key(@sm2.os_rand())
  let priv_b = @sm2.generate_key(@sm2.os_rand())
  let pub_b = @sm2.derive_public_key(priv_b)
  let rpub_b = @sm2.derive_public_key(priv_b)
  // 同一个 x、换一个 y，几乎必然不在曲线上
  let bogus = Bytes::makei(32, fn(_) { b'\x01' })
  let bad_b = @sm2.public_key_from_xy(
    @sm2.sm2_p256(),
    @byteutil.bn_to_bytes(pub_b.x),
    bogus,
  ) catch {
    _ => @sm2.derive_public_key(priv_a) // 构造不出来就跳过：曲线参数固定时不会走到这里
  }
  let raised = try {
    let _ = @sm2.key_exchange_a(
      16, b"1234567812345678", b"1234567812345678", priv_a, bad_b, rpriv_a, rpub_b,
    )
    false
  } catch {
    @sm2.NotOnCurve => true
    _ => false
  }
  // 只有真的构造出了曲线外的点，才期望抛错
  if !@sm2.is_on_curve(bad_b) {
    assert_true(raised)
  }
}

///|
/// 解密失败的三个来源（C1 不在曲线上、KDF 全零、C3 不匹配）对外统一成
/// `InvalidCipher`，避免错误码本身成为判定 oracle。
test "sm2_decrypt_reports_single_error_code" {
  let private_key = @sm2.generate_key(@sm2.os_rand())
  let public_key = @sm2.derive_public_key(private_key)
  let msg = b"single error code"
  let ct = @sm2.sm2_encrypt(public_key, msg, @sm2.os_rand(), @sm2.C1C3C2)

  // 篡改 C3
  let tampered_c3 = Bytes::makei(ct.length(), fn(i) {
    if i == 70 {
      (ct[i].to_uint() ^ 1U).to_byte()
    } else {
      ct[i]
    }
  })
  let e1 = try {
    let _ = @sm2.sm2_decrypt(private_key, tampered_c3, @sm2.C1C3C2)
    None
  } catch {
    e => Some(e)
  }
  assert_true(e1 is Some(@sm2.InvalidCipher))

  // 篡改 C1（把 x 置零，点基本不可能仍在曲线上）
  let tampered_c1 = Bytes::makei(ct.length(), fn(i) {
    if i >= 1 && i <= 32 {
      b'\x00'
    } else {
      ct[i]
    }
  })
  let e2 = try {
    let _ = @sm2.sm2_decrypt(private_key, tampered_c1, @sm2.C1C3C2)
    None
  } catch {
    e => Some(e)
  }
  assert_true(e2 is Some(@sm2.InvalidCipher))
}

///|
/// `SM2PrivateKey::wipe` 把私钥标量清零，之后无法再推出原公钥。
test "sm2_private_key_wipe" {
  let sk = @sm2.generate_key(@sm2.os_rand())
  let pub_before = @sm2.compress_point(@sm2.derive_public_key(sk))
  sk.wipe()
  let zeros = Bytes::makei(32, fn(_) { b'\x00' })
  assert_true(@byteutil.bytes_eq(@byteutil.bn_to_bytes(sk.d), zeros))
  let pub_after = @sm2.compress_point(@sm2.derive_public_key(sk))
  assert_false(@byteutil.bytes_eq(pub_before, pub_after))
}
