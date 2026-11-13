/// PEM 编解码的白盒测试。

///|
let pem_sample_data : Bytes = b"\x01\x02\x03\x04\x05"

///|
/// 判断解码是否按预期失败。
fn pem_decode_fails(s : String) -> Bool {
  let r = pem_decode(s) catch { _ => return true }
  let _ = r
  false
}

///|
test "pem_roundtrip_simple" {
  let pem = pem_encode_simple("SAMPLE", pem_sample_data)
  assert_eq(pem, "-----BEGIN SAMPLE-----\nAQIDBAU=\n-----END SAMPLE-----\n")
  let block = pem_decode(pem)
  assert_eq(block.type_, "SAMPLE")
  assert_eq(block.bytes, pem_sample_data)
  assert_eq(block.headers.length(), 0)
}

///|
test "pem_roundtrip_with_headers" {
  let headers : Headers = [
    ("Proc-Type", "4,ENCRYPTED"),
    ("DEK-Info", "AES-256-CBC,00112233445566778899AABBCCDDEEFF"),
  ]
  let pem = pem_encode("ENC", headers, pem_sample_data)
  // 头部之后、正文之前有一个空行
  assert_eq(
    pem, "-----BEGIN ENC-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\nAQIDBAU=\n-----END ENC-----\n",
  )
  let block = pem_decode(pem)
  assert_eq(block.type_, "ENC")
  assert_eq(block.get_header("Proc-Type"), Some("4,ENCRYPTED"))
  assert_eq(
    block.get_header("DEK-Info"),
    Some("AES-256-CBC,00112233445566778899AABBCCDDEEFF"),
  )
  assert_eq(block.get_header("Missing"), None)
  assert_eq(block.bytes, pem_sample_data)
}

///|
test "pem_wraps_long_body_at_64" {
  let data = Bytes::makei(100, fn(i) { (i & 0xFF).to_byte() })
  let pem = pem_encode_simple("LONG", data)
  let lines = pem.split("\n").collect()
  // 100 字节的 base64 为 136 个字符：64 + 64 + 8
  // 第 0 行是 BEGIN，末行前是 END，末尾是空串
  assert_eq(lines[1].length(), 64)
  assert_eq(lines[2].length(), 64)
  assert_eq(lines[3].length(), 8)
  let block = pem_decode(pem)
  assert_eq(block.bytes.length(), 100)
}

///|
test "pem_skips_surrounding_text" {
  let pem = "some junk\n-----BEGIN X-----\nAQID\n-----END X-----\ntrailing junk\n"
  let block = pem_decode(pem)
  assert_eq(block.type_, "X")
  assert_eq(block.bytes, b"\x01\x02\x03")
}

///|
test "pem_decode_all_multiple" {
  let pem = pem_encode_simple("A", b"\x01") +
    pem_encode_simple("B", b"\x02\x03")
  let blocks = pem_decode_all(pem)
  assert_eq(blocks.length(), 2)
  assert_eq(blocks[0].type_, "A")
  assert_eq(blocks[1].type_, "B")
  assert_eq(blocks[1].bytes, b"\x02\x03")
  // 单块入口遇到多块时报错
  assert_true(pem_decode_fails(pem))
}

///|
test "pem_decode_rejects_malformed" {
  assert_true(pem_decode_fails("nothing here")) // 无块
  assert_true(pem_decode_fails("-----BEGIN X-----\nAQID\n-----END Y-----\n")) // 类型不一致
  assert_true(pem_decode_fails("-----BEGIN X-----\nAQID\n")) // 缺少 END
  assert_true(pem_decode_fails("-----BEGIN X-----\n!!!!\n-----END X-----\n")) // 非法 base64
}

///|
test "pem_crlf" {
  let pem = "-----BEGIN X-----\r\nAQID\r\n-----END X-----\r\n"
  let block = pem_decode(pem)
  assert_eq(block.type_, "X")
  assert_eq(block.bytes, b"\x01\x02\x03")
}

///|
/// 正文里带冒号的行不会被当成 header 静默吃掉：header 段必须以空行结束。
test "pem_body_line_with_colon_is_not_a_header" {
  // 没有空行分隔 -> 拒绝，而不是"解析成功但 bytes 为空"
  let no_blank = "-----BEGIN X-----\nAQ: ID\n-----END X-----\n"
  let raised = try {
    let _ = pem_decode(no_blank)
    false
  } catch {
    ByteUtilError::InvalidBase64 => true
    _ => false
  }
  assert_true(raised)
  // 有空行分隔 -> 只有空行之前的那一行是 header
  let with_blank = "-----BEGIN X-----\nAQ: ID\n\nQUJD\n-----END X-----\n"
  let block = pem_decode(with_blank) catch {
    _ => abort("expected a decodable block")
  }
  assert_eq(block.headers.length(), 1)
  assert_eq(block.get_header("AQ"), Some("ID"))
  assert_eq(block.bytes, b"ABC")
}
