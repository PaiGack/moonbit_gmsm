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
  assert_eq(compressed[0] == b'\x02', (decompressed.y_bytes()[31] & 1) == 0)
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
  assert_false(@byteutil.bytes_eq(priv_a.to_bytes(), priv_b.to_bytes()))
  assert_false(@byteutil.bytes_eq(rpriv_a.to_bytes(), rpriv_b.to_bytes()))
  assert_false(@byteutil.bytes_eq(priv_a.to_bytes(), rpriv_a.to_bytes()))
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
/// 审计 S3：密钥协商对对方静态 / 临时公钥做曲线校验，并要求四把密钥的
/// 曲线参数完全一致。
///
/// 公开 API 无法直接构造「curve 是 p256、但坐标不在 p256 上」的公钥
/// （`public_key_from_xy` 会拒绝），能构造出的近似威胁是「在篡改过的
/// 曲线副本下合法」的公钥；这类密钥的参数与 p256 不一致，因此必须被
/// `InvalidParameter` 拦下，而不能静默算出一个对方无法复现的共享密钥。
/// `NotOnCurve` 这一半由白盒测试 `check_peer_point_rejects_off_curve_inputs`
/// 直接覆盖。
test "sm2_key_exchange_rejects_foreign_curve_keys" {
  let ida = b"1234567812345678"
  let idb = b"1234567812345678"
  let priv_a = @sm2.generate_key(@sm2.os_rand())
  let rpriv_a = @sm2.generate_key(@sm2.os_rand())
  let priv_b = @sm2.generate_key(@sm2.os_rand())
  let rpriv_b = @sm2.generate_key(@sm2.os_rand())
  let pub_a = @sm2.derive_public_key(priv_a)
  let rpub_a = @sm2.derive_public_key(rpriv_a)
  let pub_b = @sm2.derive_public_key(priv_b)
  let rpub_b = @sm2.derive_public_key(rpriv_b)

  // 控制组：未经改动的四把密钥照常协商
  let (ka, _, _) = @sm2.key_exchange_a(
    16, ida, idb, priv_a, pub_b, rpriv_a, rpub_b,
  )
  let (kb, _, _) = @sm2.key_exchange_b(
    16, ida, idb, priv_b, pub_a, rpriv_b, rpub_a,
  )
  assert_true(@byteutil.bytes_eq(ka, kb))

  let expect_invalid_parameter = fn(f : () -> Unit raise) {
    try {
      f()
      abort("expected InvalidParameter")
    } catch {
      @sm2.InvalidParameter => ()
      e => abort("expected InvalidParameter, got \{e}")
    }
  }

  // 只改 b 的曲线副本：n / gx / a 都不变，只有 `b` 不同。
  // `same_curve` 必须比较 `b`，否则这条用例会落到曲线方程检查上。
  let tweaked_curve = @sm2.sm2_p256()
  tweaked_curve.b[0] = tweaked_curve.b[0] ^ 1UL
  let off_b = @sm2.public_key_from_xy(
    tweaked_curve,
    pub_b.x_bytes(),
    pub_b.y_bytes(),
  )
  let off_rpub_b = @sm2.public_key_from_xy(
    tweaked_curve,
    rpub_b.x_bytes(),
    rpub_b.y_bytes(),
  )
  // 探针前提：这些点自称「在曲线上」（按篡改后的 b），但在 p256 上不成立
  assert_true(@sm2.is_on_curve(off_b))
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_a(16, ida, idb, priv_a, off_b, rpriv_a, rpub_b)
  })
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_a(
      16, ida, idb, priv_a, pub_b, rpriv_a, off_rpub_b,
    )
  })
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_b(16, ida, idb, priv_b, off_b, rpriv_b, rpub_a)
  })
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_b(
      16, ida, idb, priv_b, pub_a, rpriv_b, off_rpub_b,
    )
  })

  // 改 n / gx 的副本：参数检查同样先命中
  let forged_curve = @sm2.sm2_p256()
  forged_curve.n[0] = forged_curve.n[0] ^ 1UL
  forged_curve.gx[0] = forged_curve.gx[0] ^ 1UL
  let forged = @sm2.public_key_from_xy(
    forged_curve,
    pub_b.x_bytes(),
    pub_b.y_bytes(),
  )
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_a(16, ida, idb, priv_a, forged, rpriv_a, rpub_b)
  })
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_b(16, ida, idb, priv_b, forged, rpriv_b, rpub_a)
  })

  // 本方的密钥自带别的曲线时，同样拒绝
  let tweaked_pri_a = @sm2.private_key_from_bytes(
    tweaked_curve,
    priv_a.to_bytes(),
  )
  let tweaked_rpri_b = @sm2.private_key_from_bytes(
    tweaked_curve,
    rpriv_b.to_bytes(),
  )
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_a(
      16, ida, idb, tweaked_pri_a, pub_b, rpriv_a, rpub_b,
    )
  })
  expect_invalid_parameter(fn() raise {
    let _ = @sm2.key_exchange_b(
      16, ida, idb, priv_b, pub_a, tweaked_rpri_b, rpub_a,
    )
  })
}

///|
/// 审计 M2：`sm2_p256()` 每次返回独立的数组，调用方改写副本不会影响后续
/// 构造的密钥与协商。
test "sm2_p256_returns_fresh_arrays" {
  let copy = @sm2.sm2_p256()
  copy.n[0] = 0UL
  copy.gx[0] = 0UL
  copy.b[0] = 0UL
  let fresh = @sm2.sm2_p256()
  assert_true(fresh.n[0] != 0UL)
  assert_true(fresh.gx[0] != 0UL)
  assert_true(fresh.b[0] != 0UL)

  let priv_a = @sm2.generate_key(@sm2.os_rand())
  let rpriv_a = @sm2.generate_key(@sm2.os_rand())
  let priv_b = @sm2.generate_key(@sm2.os_rand())
  let rpriv_b = @sm2.generate_key(@sm2.os_rand())
  let (ka, _, _) = @sm2.key_exchange_a(
    16,
    b"1234567812345678",
    b"1234567812345678",
    priv_a,
    @sm2.derive_public_key(priv_b),
    rpriv_a,
    @sm2.derive_public_key(rpriv_b),
  )
  let (kb, _, _) = @sm2.key_exchange_b(
    16,
    b"1234567812345678",
    b"1234567812345678",
    priv_b,
    @sm2.derive_public_key(priv_a),
    rpriv_b,
    @sm2.derive_public_key(rpriv_a),
  )
  assert_true(@byteutil.bytes_eq(ka, kb))
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
  assert_true(@byteutil.bytes_eq(sk.to_bytes(), zeros))
  let pub_after = @sm2.compress_point(@sm2.derive_public_key(sk))
  assert_false(@byteutil.bytes_eq(pub_before, pub_after))
}

///|
/// 审计 S4：空 `uid` 在签名 / 验签 / 摘要三条路径上语义一致，
/// 即一律等价于 `default_uid()`（与 gmsm 的 `Sm2Sign` / `Sm3Digest` 一致）。
///
/// 修复前 `sm2_sign` / `sm2_verify` 把空串原样使用，而 `sm3_digest`
/// 换成默认值，导致「sign(空) 之后 verify(default) / verify_digest 套
/// sm3_digest(msg, 空)」失败。
///
/// `za` 不在其列：gmsm 的 `sm2.ZA(pub, uid)` 对空 uid 是原样使用的
/// （ENTLA = 0），向量 `go_sm2_za_empty-*` 锁定这一点。
test "sm2_empty_uid_means_default_uid_in_sign_verify_digest" {
  let sk = @sm2.generate_key(@sm2.os_rand())
  let pub_key = @sm2.derive_public_key(sk)
  let msg = b"empty uid semantics"
  let default_uid = @sm2.default_uid()

  // sign(空) 可被 verify(空) 与 verify(default) 同时接受，反之亦然
  let (r, s) = @sm2.sm2_sign(sk, msg, b"", @sm2.os_rand())
  assert_true(@sm2.sm2_verify(pub_key, msg, b"", r, s))
  assert_true(@sm2.sm2_verify(pub_key, msg, default_uid, r, s))

  let (r2, s2) = @sm2.sm2_sign(sk, msg, default_uid, @sm2.os_rand())
  assert_true(@sm2.sm2_verify(pub_key, msg, b"", r2, s2))

  // 摘要路径与签名路径一致：sign(空) 的 e 即 sm3_digest(msg, 空) = sm3_digest(msg, default)
  let digest_empty = pub_key.sm3_digest(msg, b"")
  assert_true(
    @byteutil.bytes_eq(digest_empty, pub_key.sm3_digest(msg, default_uid)),
  )
  assert_true(@sm2.sm2_verify_digest(pub_key, digest_empty, r, s))

  // 非空 uid 仍按原样区分，不能被空串语义「吃掉」
  let other = b"another-uid"
  assert_false(@sm2.sm2_verify(pub_key, msg, other, r, s))

  // za 保持 gmsm 的原始语义：空 uid 原样使用（ENTLA = 0），不等于默认 uid 的
  // Z 值；而上面的 sm3_digest(msg, 空) 用的是默认 uid 的 Z 值。
  assert_false(@byteutil.bytes_eq(pub_key.za(b""), pub_key.za(default_uid)))
}
