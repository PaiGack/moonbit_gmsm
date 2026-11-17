/// SM4 密钥 PEM 读写的白盒测试（含 AES-256-CBC 的 FIPS-197 已知答案）。

///|
/// 固定种子的确定性随机源，使加密用例在 wasm-gc 等没有 OS 熵源的
/// 目标上也能运行。
fn test_rand() -> @random.Rand? {
  Some(@random.Rand::chacha8(seed=Bytes::makei(32, fn(_) { b'\x07' })))
}

///|
test "aes256_fips197_block" {
  // FIPS-197 附录 C.3：AES-256 单块
  let key = @byteutil.hex_to_bytes_unchecked(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let pt = @byteutil.hex_to_bytes_unchecked("00112233445566778899aabbccddeeff")
  let w = aes256_expand_key(key)
  let ct = aes256_encrypt_block(w, pt)
  assert_eq(@byteutil.bytes_to_hex(ct), "8ea2b7ca516745bfeafc49904b496089")
  assert_eq(
    @byteutil.bytes_to_hex(aes256_decrypt_block(w, ct)),
    "00112233445566778899aabbccddeeff",
  )
}

///|
test "aes256_cbc_roundtrip" {
  let key = @byteutil.hex_to_bytes_unchecked(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let iv = @byteutil.hex_to_bytes_unchecked("0f0e0d0c0b0a09080706050403020100")
  for len in 1..<5 {
    let pt = Bytes::makei(len * 16, fn(i) { ((i * 13 + 7) & 0xFF).to_byte() })
    let ct = aes256_cbc_encrypt_raw(key, iv, pt)
    assert_eq(ct.length(), pt.length())
    assert_eq(aes256_cbc_decrypt_raw(key, iv, ct), pt)
  }
}

///|
test "pkcs7_pad_unpad_key" {
  let key = b"0123456789abcdef"
  let padded = pkcs7_pad_key(key)
  assert_eq(padded.length(), 32)
  assert_eq(padded[31].to_int(), 16)
  assert_eq(pkcs7_unpad_key(padded), key)
  // 非对齐长度
  let short = b"short"
  let p2 = pkcs7_pad_key(short)
  assert_eq(p2.length(), 16)
  assert_eq(p2[15].to_int(), 11)
  assert_eq(pkcs7_unpad_key(p2), short)
}

///|
test "pkcs7_unpad_key_rejects_bad_padding" {
  let bad = Bytes::makei(16, fn(i) { if i < 15 { b'\x01' } else { b'\x00' } })
  let r1 = pkcs7_unpad_key(bad) catch { _ => b"" }
  assert_eq(r1.length(), 0)
  let bad2 = Bytes::makei(16, fn(i) { if i < 15 { b'\x02' } else { b'\x03' } })
  let r2 = pkcs7_unpad_key(bad2) catch { _ => b"" }
  assert_eq(r2.length(), 0)
}

///|
test "sm4_pem_plain_roundtrip" {
  let key : SM4Key = b"0123456789abcdef"
  let pem = write_key_to_pem(key, b"", None)
  assert_eq(
    pem, "-----BEGIN SM4 KEY-----\nMDEyMzQ1Njc4OWFiY2RlZg==\n-----END SM4 KEY-----\n",
  )
  assert_eq(read_key_from_pem(pem, b""), key)
}

///|
test "sm4_pem_encrypted_roundtrip" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"sm4-pwd"
  let pem = write_key_to_pem(key, pwd, test_rand())
  let block = @byteutil.pem_decode(pem)
  assert_eq(block.type_, "SM4 ENCRYPTED KEY")
  assert_eq(block.get_header("Proc-Type"), Some("4,ENCRYPTED"))
  // 默认格式为 PBKDF2-HMAC-SM3，密文 = 1 个分组 + 32 字节 tag
  let dek = block.get_header("DEK-Info").unwrap()
  assert_true(dek.has_prefix("SM4-CBC,PBKDF2-HMAC-SM3,"))
  assert_eq(
    block.get_header("SM4-KDF-Iterations"),
    Some(sm4_pem_default_iterations.to_string()),
  )
  // 16 字节密钥 PKCS#7 填充到 32 字节（1 个填充块），再拼 32 字节 tag
  assert_eq(block.bytes.length(), 32 + sm4_pem_tag_len)
  assert_eq(read_key_from_pem(pem, pwd), key)
}

///|
test "sm4_pem_encrypted_uses_fresh_salt" {
  let key : SM4Key = b"0123456789abcdef"
  let r = test_rand().unwrap()
  let a = write_key_to_pem(key, b"pwd", Some(r))
  let b = write_key_to_pem(key, b"pwd", Some(r))
  // 同一个随机源连续两次写出，salt 不同，输出（含头部）必然不同
  assert_true(a != b)
}

///|
test "sm4_pem_encrypted_custom_iterations" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"pwd"
  let pem = write_key_to_pem_with(
    key,
    pwd,
    test_rand(),
    Sm4PemEncryption::Pbkdf2HmacSm3(200_000),
  )
  let block = @byteutil.pem_decode(pem)
  assert_eq(block.get_header("SM4-KDF-Iterations"), Some("200000"))
  assert_eq(read_key_from_pem(pem, pwd), key)
}

///|
test "sm4_pem_encrypted_wrong_password" {
  let key : SM4Key = b"0123456789abcdef"
  let pem = write_key_to_pem(key, b"right", test_rand())
  // 错误口令在 HMAC 校验阶段就被拒绝
  let e1 = try {
    ignore(read_key_from_pem(pem, b"wrong"))
    None
  } catch {
    e => Some(e)
  }
  assert_eq(e1, Some(SM4Error::InvalidTag))
  // 缺少口令
  let e2 = try {
    ignore(read_key_from_pem(pem, b""))
    None
  } catch {
    e => Some(e)
  }
  assert_eq(e2, Some(SM4Error::InvalidData))
}

///|
test "sm4_pem_encrypted_rejects_tampered_ciphertext" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"pwd"
  let pem = write_key_to_pem_with(
    key,
    pwd,
    test_rand(),
    Sm4PemEncryption::Pbkdf2HmacSm3(200_000),
  )
  let block = @byteutil.pem_decode(pem)
  // 翻转密文首字节
  let ct = Bytes::makei(block.bytes.length(), fn(i) {
    if i == 0 {
      (block.bytes[i].to_int() ^ 0x01).to_byte()
    } else {
      block.bytes[i]
    }
  })
  let headers : @byteutil.Headers = [
    ("Proc-Type", "4,ENCRYPTED"),
    ("DEK-Info", block.get_header("DEK-Info").unwrap()),
    ("SM4-KDF-Iterations", "200000"),
  ]
  let bad = @byteutil.pem_encode("SM4 ENCRYPTED KEY", headers, ct)
  let e = try {
    ignore(read_key_from_pem(bad, pwd))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidTag))
}

///|
test "sm4_pem_encrypted_rejects_bad_kdf_params" {
  let key : SM4Key = b"0123456789abcdef"
  let pem = write_key_to_pem_with(
    key,
    b"pwd",
    test_rand(),
    Sm4PemEncryption::Pbkdf2HmacSm3(200_000),
  )
  let block = @byteutil.pem_decode(pem)
  let dek = block.get_header("DEK-Info").unwrap()
  // 迭代次数缺失
  let missing = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [("Proc-Type", "4,ENCRYPTED"), ("DEK-Info", dek)],
    block.bytes,
  )
  let e1 = try {
    ignore(read_key_from_pem(missing, b"pwd"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e1, Some(SM4Error::InvalidKdfParams))
  // 低于下限：接受它等于默默接受一个几乎不设防的口令加密
  let weak = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [
      ("Proc-Type", "4,ENCRYPTED"),
      ("DEK-Info", dek),
      ("SM4-KDF-Iterations", "1000"),
    ],
    block.bytes,
  )
  let e_weak = try {
    ignore(read_key_from_pem(weak, b"pwd"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e_weak, Some(SM4Error::InvalidKdfParams))
  // 写入端同样拒绝过小的迭代次数
  let e_write = try {
    ignore(
      write_key_to_pem_with(
        key,
        b"pwd",
        test_rand(),
        Sm4PemEncryption::Pbkdf2HmacSm3(1000),
      ),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e_write, Some(SM4Error::InvalidKdfParams))
  // 超出上限
  let huge = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [
      ("Proc-Type", "4,ENCRYPTED"),
      ("DEK-Info", dek),
      ("SM4-KDF-Iterations", (sm4_pem_max_iterations + 1).to_string()),
    ],
    block.bytes,
  )
  let e2 = try {
    ignore(read_key_from_pem(huge, b"pwd"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e2, Some(SM4Error::InvalidKdfParams))
  // 非数字
  let nan = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [
      ("Proc-Type", "4,ENCRYPTED"),
      ("DEK-Info", dek),
      ("SM4-KDF-Iterations", "1x"),
    ],
    block.bytes,
  )
  let e3 = try {
    ignore(read_key_from_pem(nan, b"pwd"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e3, Some(SM4Error::InvalidKdfParams))
}

///|
test "sm4_pem_encrypted_rejects_bad_salt" {
  let key : SM4Key = b"0123456789abcdef"
  let pem = write_key_to_pem(key, b"pwd", test_rand())
  let block = @byteutil.pem_decode(pem)
  // salt 十六进制长度为奇数
  let bad = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [
      ("Proc-Type", "4,ENCRYPTED"),
      ("DEK-Info", "SM4-CBC,PBKDF2-HMAC-SM3,00112233"),
      ("SM4-KDF-Iterations", "10"),
    ],
    block.bytes,
  )
  let e = try {
    ignore(read_key_from_pem(bad, b"pwd"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidData))
}

///|
test "sm4_pem_legacy_roundtrip_by_default_reader" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"legacy-pwd"
  let pem = write_key_to_pem_legacy(key, pwd, test_rand())
  let block = @byteutil.pem_decode(pem)
  assert_eq(block.type_, "SM4 ENCRYPTED KEY")
  assert_true(block.get_header("DEK-Info").unwrap().has_prefix("AES-256-CBC,"))
  assert_eq(block.get_header("SM4-KDF-Iterations"), None)
  assert_eq(block.bytes.length(), 32)
  // 读取端按 DEK-Info 自动识别旧格式
  assert_eq(read_key_from_pem(pem, pwd), key)
  // 旧格式没有 MAC：口令错误与填充错误必须给出同一个错误，
  // 否则错误码本身就是 padding oracle。
  let e = try {
    ignore(read_key_from_pem(pem, b"wrong"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::LegacyPemDecryptFailed))
}

///|
test "sm4_pem_legacy_passphrase_longer_than_32_bytes_is_truncated" {
  let key : SM4Key = b"0123456789abcdef"
  // 33 字节与 40 字节口令：Go `x509.EncryptPEMBlock` 的 copy 语义会把它们
  // 都截断成同一个 32 字节 AES 密钥，所以文件可互相解密。
  let pwd33 = Bytes::makei(33, fn(i) { (('a'.to_int() + i) & 0xFF).to_byte() })
  let pwd40 = Bytes::makei(40, fn(i) { (('a'.to_int() + i) & 0xFF).to_byte() })
  let pem = write_key_to_pem_legacy(key, pwd33, test_rand())
  assert_eq(read_key_from_pem(pem, pwd33), key)
  assert_eq(read_key_from_pem(pem, pwd40), key)
  // 截断后的前 32 字节仍然是区分口令的依据
  let pwd_other = Bytes::makei(33, fn(i) {
    (('a'.to_int() + i + 1) & 0xFF).to_byte()
  })
  let r = read_key_from_pem(pem, pwd_other) catch { _ => b"" }
  assert_eq(r.length(), 0)
  // 恰好 32 字节与不足 32 字节的口令
  let pwd32 = Bytes::makei(32, fn(i) { (('a'.to_int() + i) & 0xFF).to_byte() })
  let pem32 = write_key_to_pem_legacy(key, pwd32, test_rand())
  assert_eq(read_key_from_pem(pem32, pwd40), key)
  let pem_short = write_key_to_pem_legacy(key, b"short", test_rand())
  assert_eq(read_key_from_pem(pem_short, b"short"), key)
}

///|
test "sm4_pem_legacy_decrypt_failures_are_indistinguishable" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"legacy-pwd"
  let pem = write_key_to_pem_legacy(key, pwd, test_rand())
  let block = @byteutil.pem_decode(pem)
  let err_of = fn(data : String, p : Bytes) {
    try {
      ignore(read_key_from_pem_legacy(data, p))
      None
    } catch {
      err => Some(err)
    }
  }
  // 错误口令
  assert_eq(err_of(pem, b"wrong"), Some(SM4Error::LegacyPemDecryptFailed))
  // 密文长度不是 16 的倍数
  let short_ct = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    block.headers,
    block.bytes[:16].to_owned(),
  )
  assert_eq(err_of(short_ct, pwd), Some(SM4Error::LegacyPemDecryptFailed))
  // 密文长度不是 16 的倍数之外的畸形长度同样不能泄露原因
  let half = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    block.headers,
    block.bytes[:20].to_owned(),
  )
  assert_eq(err_of(half, pwd), Some(SM4Error::LegacyPemDecryptFailed))
}

///|
test "sm4_pem_legacy_reader_only_accepts_legacy_blocks" {
  let key : SM4Key = b"0123456789abcdef"
  let err_of = fn(data : String, p : Bytes) {
    try {
      ignore(read_key_from_pem_legacy(data, p))
      None
    } catch {
      err => Some(err)
    }
  }
  // 明文块
  assert_eq(
    err_of(write_key_to_pem(key, b"", None), b"pwd"),
    Some(SM4Error::InvalidData),
  )
  // 安全格式（含 SM4-KDF-Iterations 头）
  let secure = write_key_to_pem(key, b"pwd", test_rand())
  assert_eq(err_of(secure, b"pwd"), Some(SM4Error::InvalidData))
  // 空口令
  assert_eq(
    err_of(write_key_to_pem_legacy(key, b"p", test_rand()), b""),
    Some(SM4Error::InvalidData),
  )
  // 真正的旧格式可以读
  let legacy = write_key_to_pem_legacy(key, b"pwd", test_rand())
  assert_eq(read_key_from_pem_legacy(legacy, b"pwd"), key)
}

///|
test "pkcs7_unpad_key_ct_matches_reference" {
  for n in 0..<4 {
    let body = Bytes::makei(n * 16, fn(i) { ((i * 11 + 3) & 0xFF).to_byte() })
    let padded = pkcs7_pad_key(body)
    let (out, ok) = pkcs7_unpad_key_ct(padded)
    assert_true(ok)
    assert_eq(out, body)
  }
  // 非法填充：0 值填充、超过 16、尾部字节互不一致
  for
    bad in [
      Bytes::makei(16, fn(_) { b'\x00' }),
      @byteutil.concat_bytes([Bytes::makei(15, fn(_) { b'\x01' }), b"\x11"]),
      @byteutil.concat_bytes([Bytes::makei(14, fn(_) { b'\x02' }), b"\x03\x03"]),
    ] {
    let (_, ok) = pkcs7_unpad_key_ct(bad)
    assert_false(ok)
  }
}

///|
test "sm4_pem_encrypted_requires_random" {
  let r = write_key_to_pem(b"0123456789abcdef", b"pwd", None) catch { _ => "" }
  assert_eq(r, "")
  let e = try {
    ignore(write_key_to_pem(b"0123456789abcdef", b"pwd", None))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::MissingRandomSource))
}

///|
test "sm4_pem_with_rejects_bad_iterations" {
  let key : SM4Key = b"0123456789abcdef"
  let e = try {
    ignore(
      write_key_to_pem_with(
        key,
        b"pwd",
        test_rand(),
        Sm4PemEncryption::Pbkdf2HmacSm3(0),
      ),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidKdfParams))
}

///|
test "sm4_pem_rejects_unknown_type" {
  let pem = "-----BEGIN SOMETHING ELSE-----\nAQIDBAUGBwgJCgsMDQ4PEA==\n-----END SOMETHING ELSE-----\n"
  let r = read_key_from_pem(pem, b"") catch { _ => b"" }
  assert_eq(r.length(), 0)
}

///|
test "sm4_pem_rejects_malformed" {
  let r = read_key_from_pem("not a pem", b"") catch { _ => b"" }
  assert_eq(r.length(), 0)
}

///|
test "write_key_to_pem_rejects_bad_length" {
  let r = write_key_to_pem(b"short", b"", None) catch { _ => "" }
  assert_eq(r, "")
}

///|
test "sm4_pem_strict_rejects_plaintext_block" {
  let key : SM4Key = b"0123456789abcdef"
  // 攻击者把块内容替换成自己选的明文密钥
  let forged = @byteutil.pem_encode_simple("SM4 KEY", b"attacker-key-0000")
  // 宽松入口照单全收——这正是需要严格入口的原因
  assert_eq(read_key_from_pem(forged, b""), b"attacker-key-0000")
  let e = try {
    ignore(
      read_key_from_pem_strict(forged, b"pwd", Sm4PemReadPolicy::EncryptedOnly),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidData))
  // 本库自己写出的明文块在严格模式下同样被拒绝
  let plain = write_key_to_pem(key, b"", None)
  let e2 = try {
    ignore(
      read_key_from_pem_strict(plain, b"", Sm4PemReadPolicy::EncryptedOnly),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e2, Some(SM4Error::InvalidData))
}

///|
test "sm4_pem_strict_rejects_legacy_downgrade" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"pwd"
  // 从安全格式的块上剥掉 Proc-Type，再谎报为旧格式 DEK-Info
  let pem = write_key_to_pem(key, pwd, test_rand())
  let block = @byteutil.pem_decode(pem)
  let downgraded = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [
      ("Proc-Type", "4,ENCRYPTED"),
      ("DEK-Info", "AES-256-CBC,000102030405060708090A0B0C0D0E0F"),
    ],
    block.bytes,
  )
  let e = try {
    ignore(
      read_key_from_pem_strict(downgraded, pwd, Sm4PemReadPolicy::EncryptedOnly),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidData))
  // 真正的旧格式文件也被拒绝
  let legacy = write_key_to_pem_legacy(key, pwd, test_rand())
  let e2 = try {
    ignore(
      read_key_from_pem_strict(legacy, pwd, Sm4PemReadPolicy::EncryptedOnly),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e2, Some(SM4Error::InvalidData))
}

///|
test "sm4_pem_strict_accepts_secure_format" {
  let key : SM4Key = b"0123456789abcdef"
  let pwd = b"pwd"
  let pem = write_key_to_pem(key, pwd, test_rand())
  assert_eq(
    read_key_from_pem_strict(pem, pwd, Sm4PemReadPolicy::EncryptedOnly),
    key,
  )
  // 严格模式与宽松模式对安全格式的结果一致
  assert_eq(
    read_key_from_pem_strict(pem, pwd, Sm4PemReadPolicy::AcceptAny),
    key,
  )
  // 缺少口令
  let e = try {
    ignore(read_key_from_pem_strict(pem, b"", Sm4PemReadPolicy::EncryptedOnly))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidData))
}

///|
test "sm4_pem_strict_rejects_missing_proc_type" {
  // 去掉 Proc-Type 后块不再被识别为加密块；严格模式必须报错，不能退回
  // 明文路径（宽松入口会因块类型不是 `SM4 KEY` 同样报错）。
  let key : SM4Key = b"0123456789abcdef"
  let pem = write_key_to_pem(key, b"pwd", test_rand())
  let block = @byteutil.pem_decode(pem)
  let no_proc = @byteutil.pem_encode(
    "SM4 ENCRYPTED KEY",
    [("DEK-Info", block.get_header("DEK-Info").unwrap())],
    block.bytes,
  )
  let e = try {
    ignore(
      read_key_from_pem_strict(no_proc, b"pwd", Sm4PemReadPolicy::EncryptedOnly),
    )
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidData))
}
