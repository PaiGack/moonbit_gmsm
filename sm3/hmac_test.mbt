/// HMAC-SM3 / PBKDF2-HMAC-SM3 已知答案测试。
///
/// SM3 各长度消息的用例为公开标准向量（如 GB/T 32905-2016 附录 A 中
/// "abc" 的摘要），HMAC 与 PBKDF2 期望值由独立的 Python 参考实现
/// （同一 SM3，先与 `hashlib` 的 sm3 交叉验证）生成。

///|
test "sm3_known_answers" {
  assert_eq(
    @byteutil.bytes_to_hex(@sm3.sm3_sum(b"abc")),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  assert_eq(
    @byteutil.bytes_to_hex(
      @sm3.sm3_sum(
        b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
      ),
    ),
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
}

///|
test "hmac_sm3_known_answers" {
  assert_eq(
    @byteutil.bytes_to_hex(@sm3.hmac_sm3(b"key", b"data")),
    "88a5a14b0fcf4a8a7b0c5084b8ee36e70efca4e8467fa264c3231bf16463b425",
  )
  // 长于 64 字节的密钥先做 SM3
  assert_eq(
    @byteutil.bytes_to_hex(
      @sm3.hmac_sm3(Bytes::makei(100, fn(_) { b'k' }), b"data"),
    ),
    "d2e3191973421dc0792b6ec5e1a5b5c26652d764b024ba8c20221f0396fedfe8",
  )
}

///|
test "hmac_sm3_empty_key" {
  // 空密钥等价于全零块；只校验长度与确定性
  let a = @sm3.hmac_sm3(b"", b"")
  let b = @sm3.hmac_sm3(b"", b"")
  assert_eq(a.length(), 32)
  assert_true(@byteutil.ct_eq(a, b))
}

///|
test "pbkdf2_hmac_sm3_known_answers" {
  assert_eq(
    @byteutil.bytes_to_hex(@sm3.pbkdf2_hmac_sm3(b"password", b"salt", 1, 32)),
    "4612f922a1fdcefaf4312fc6f8f3322b489cbf24f2ea361b44c2bd8fa2c6dcb0",
  )
  assert_eq(
    @byteutil.bytes_to_hex(@sm3.pbkdf2_hmac_sm3(b"password", b"salt", 1000, 32)),
    "e8b635a41dfe5aaab7cf828cff6f3608e22cac59ba16edd70e000b293d00bc91",
  )
  assert_eq(
    @byteutil.bytes_to_hex(
      @sm3.pbkdf2_hmac_sm3(
        b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096,
        40,
      ),
    ),
    "3b6282ac8519f059e465abff0ea37b0dbfe6c672a76e6b805312d53900db630732ccc1a88fa5512a",
  )
  assert_eq(
    @byteutil.bytes_to_hex(@sm3.pbkdf2_hmac_sm3(b"", b"", 1, 16)),
    "311c191a8c3676b7b0e5ab0b9e1a7b66",
  )
}

///|
test "pbkdf2_hmac_sm3_32_matches_generic" {
  assert_true(
    @byteutil.ct_eq(
      @sm3.pbkdf2_hmac_sm3_32(b"pwd", b"0123456789abcdef", 10),
      @sm3.pbkdf2_hmac_sm3(b"pwd", b"0123456789abcdef", 10, 32),
    ),
  )
}

///|
test "pbkdf2_hmac_sm3_rejects_bad_params" {
  let r1 = @sm3.pbkdf2_hmac_sm3(b"pwd", b"salt", 0, 32) catch { _ => b"" }
  assert_eq(r1.length(), 0)
  let r2 = @sm3.pbkdf2_hmac_sm3(b"pwd", b"salt", 1, -1) catch { _ => b"" }
  assert_eq(r2.length(), 0)
  // dk_len = 0 合法，返回空
  assert_eq(@sm3.pbkdf2_hmac_sm3(b"pwd", b"salt", 1, 0).length(), 0)
}
