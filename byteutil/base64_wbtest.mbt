/// base64 编解码的白盒测试。

///|
/// 判断解码是否按预期失败。
fn decode_fails(s : String) -> Bool {
  let r = base64_decode(s) catch { _ => b"" }
  r.length() == 0 && s != ""
}

///|
test "base64_rfc4648_vectors" {
  // RFC 4648 第 10 节的测试向量
  let cases : Array[(Bytes, String)] = [
    (b"", ""),
    (b"f", "Zg=="),
    (b"fo", "Zm8="),
    (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg=="),
    (b"fooba", "Zm9vYmE="),
    (b"foobar", "Zm9vYmFy"),
  ]
  for pair in cases {
    assert_eq(base64_encode(pair.0), pair.1)
    assert_eq(base64_encode(base64_decode(pair.1)), pair.1)
  }
}

///|
test "base64_roundtrip_all_lengths" {
  for len in 0..<40 {
    let data = Bytes::makei(len, fn(i) { ((i * 37 + 11) & 0xFF).to_byte() })
    let enc = base64_encode(data)
    assert_eq(enc.length() % 4, 0)
    let back = base64_decode(enc)
    assert_eq(back.length(), len)
    for i = 0; i < len; i = i + 1 {
      assert_eq(back[i], data[i])
    }
  }
}

///|
test "base64_high_bytes" {
  // 高半字节 >= 8 的字节，检查没有符号扩展
  let data : Bytes = b"\x80\x9f\xa0\xff\x7f\x00"
  let enc = base64_encode(data)
  assert_eq(enc, "gJ+g/38A")
  let back = base64_decode(enc)
  for i = 0; i < data.length(); i = i + 1 {
    assert_eq(back[i], data[i])
  }
}

///|
test "base64_decode_ignores_whitespace" {
  let a = base64_decode("Zm9v\nYmFy")
  let b = base64_decode("Zm9vYmFy")
  assert_eq(a, b)
}

///|
test "base64_decode_rejects_bad_input" {
  assert_true(decode_fails("Zm9$")) // 非法字符
  assert_true(decode_fails("Zm9vY")) // 长度不是 4 的倍数
  assert_true(decode_fails("Zg==Zg==")) // 填充之后还有数据
  assert_true(decode_fails("Z===")) // 填充超过 2 个
}

///|
/// Padding 可省略（Go 的 `StdEncoding` 读取端接受不带 `=` 的输入），
/// 但一旦出现 `=`，就必须完整且位于末尾。
test "base64_decode_padding_rules" {
  // 省略 padding
  assert_eq(base64_decode("YWJjZA") catch { _ => b"" }, b"abcd")
  assert_eq(base64_decode("YWJjZA==") catch { _ => b"" }, b"abcd")
  assert_eq(base64_decode("YWJjZGU") catch { _ => b"" }, b"abcde")
  assert_eq(base64_decode("YWJjZGU=") catch { _ => b"" }, b"abcde")
  // 残留一个字符无法构成完整字节
  assert_true(b64_error("YWJjZ") is Some(ByteUtilError::InvalidBase64))
  // `=` 出现在数据中间 / 数量过多
  assert_true(b64_error("YW=jZA==") is Some(ByteUtilError::InvalidBase64))
  assert_true(b64_error("YQ===") is Some(ByteUtilError::InvalidBase64))
  assert_true(b64_error("Y===") is Some(ByteUtilError::InvalidBase64))
  // 非字母表字符
  assert_true(b64_error("YWJj!_==") is Some(ByteUtilError::InvalidBase64))
  // 空串是合法的
  assert_eq(base64_decode("") catch { _ => b"x" }, b"")
}

///|
fn b64_error(s : String) -> ByteUtilError? {
  let _ = base64_decode(s) catch { e => return Some(e) }
  None
}
