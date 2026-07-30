//| SM3 demo (GM/T 0004-2012): one-shot hash and streaming hash.
//| Run with `moon run cmd/sm3`.

///|
fn main {
  println("========== SM3 Demo (GM/T 0004-2012) ==========")

  // Known-answer vectors from GM/T 0004-2012.
  let cases : Array[(String, Bytes, String)] = [
    (
      "\"\" (empty)", b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
    ),
    (
      "\"abc\"", b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    ),
    (
      "\"abcd\" x16 (64 bytes)", b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
      "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    ),
  ]

  for i = 0; i < cases.length(); i = i + 1 {
    let (name, data, expected) = cases[i]
    let hash = @gmsm_sm3.sm3_sum(data)
    let got = @byteutil.bytes_to_hex(hash)
    let ok = got == expected
    println(
      name + " -> " + got + "  [" + (if ok { "OK" } else { "FAIL" }) + "]",
    )
  }

  // Streaming hash example: feed "abc" then "def" should equal sm3_sum("abcdef")
  let ctx = @gmsm_sm3.new()
  let ctx = ctx.write(b"abc")
  let ctx = ctx.write(b"def")
  let stream_hash = ctx.finish()
  let direct_hash = @gmsm_sm3.sm3_sum(b"abcdef")
  let stream_ok = @byteutil.bytes_eq(stream_hash, direct_hash)
  let stream_msg = "Streaming sm3(\"abcdef\"): " +
    @byteutil.bytes_to_hex(stream_hash) +
    "  [" +
    (if stream_ok { "OK" } else { "FAIL" }) +
    "]"
  println("")
  println(stream_msg)

  println("========== SM3 Demo Done ==========")
}
