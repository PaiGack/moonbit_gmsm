/// SM4 密钥 PEM 读写的白盒测试（含 AES-256-CBC 的 FIPS-197 已知答案）。

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
  let pem = write_key_to_pem(key, pwd, None)
  let block = @byteutil.pem_decode(pem)
  assert_eq(block.type_, "SM4 ENCRYPTED KEY")
  assert_eq(block.get_header("Proc-Type"), Some("4,ENCRYPTED"))
  assert_eq(block.bytes.length(), 32)
  assert_eq(read_key_from_pem(pem, pwd), key)
}

///|
test "sm4_pem_encrypted_wrong_password" {
  let key : SM4Key = b"0123456789abcdef"
  let pem = write_key_to_pem(key, b"right", None)
  let r = read_key_from_pem(pem, b"wrong") catch { _ => b"" }
  assert_eq(r.length(), 0)
  // 缺少口令
  let r2 = read_key_from_pem(pem, b"") catch { _ => b"" }
  assert_eq(r2.length(), 0)
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
