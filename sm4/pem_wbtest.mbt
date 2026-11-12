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
  let key = @byteutil.hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let pt = @byteutil.hex_to_bytes("00112233445566778899aabbccddeeff")
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
  let key = @byteutil.hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let iv = @byteutil.hex_to_bytes("0f0e0d0c0b0a09080706050403020100")
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
    Sm4PemEncryption::Pbkdf2HmacSm3(1000),
  )
  let block = @byteutil.pem_decode(pem)
  assert_eq(block.get_header("SM4-KDF-Iterations"), Some("1000"))
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
    Sm4PemEncryption::Pbkdf2HmacSm3(100),
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
    ("SM4-KDF-Iterations", "100"),
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
    Sm4PemEncryption::Pbkdf2HmacSm3(100),
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
  // 旧格式错误口令必须是 InvalidPadding（解密后填充校验失败）
  let e = try {
    ignore(read_key_from_pem(pem, b"wrong"))
    None
  } catch {
    err => Some(err)
  }
  assert_eq(e, Some(SM4Error::InvalidPadding))
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
