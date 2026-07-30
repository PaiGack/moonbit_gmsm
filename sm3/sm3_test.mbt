/// SM3 hash algorithm tests.
/// Test vectors from GM/T 0004-2012 standard.

///|
/// Helper: convert bytes to hex string (lowercase).
fn bytes_to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    buf.write_string(byte_to_hex(b[i]))
  }
  buf.to_string()
}

///|
fn byte_to_hex(b : Byte) -> String {
  let hi = (b.to_int() >> 4) & 0xF
  let lo = b.to_int() & 0xF
  let buf = StringBuilder::new()
  buf.write_char(nibble_to_char(hi))
  buf.write_char(nibble_to_char(lo))
  buf.to_string()
}

///|
fn nibble_to_char(n : Int) -> Char {
  if n < 10 {
    Int::unsafe_to_char(n + '0'.to_int())
  } else {
    Int::unsafe_to_char(n - 10 + 'a'.to_int())
  }
}

///|
/// SM3("abc") from GM/T 0004-2012, A.1
test "sm3_abc" {
  let msg = b"abc"
  let hash = @sm3.sm3_sum(msg)
  let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
  assert_eq(bytes_to_hex(hash), expected)
}

///|
/// SM3("abcdabcd...") (64 bytes) from GM/T 0004-2012, A.2
test "sm3_64_bytes" {
  let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  let hash = @sm3.sm3_sum(msg)
  let expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
  assert_eq(bytes_to_hex(hash), expected)
}

///|
/// SM3("") — empty message
test "sm3_empty" {
  let hash = @sm3.sm3_sum(b"")
  let expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
  assert_eq(bytes_to_hex(hash), expected)
}

///|
/// SM3 of a single block (less than 64 bytes)
test "sm3_short" {
  let msg = b"hello"
  let hash = @sm3.sm3_sum(msg)
  let expected = "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
  assert_eq(bytes_to_hex(hash), expected)
}

///|
/// SM3 streaming API: write in multiple chunks
test "sm3_streaming" {
  let ctx = @sm3.new()
  let ctx = ctx.write(b"abc")
  let ctx = ctx.write(b"def")
  let hash = ctx.finish()
  let expected = @sm3.sm3_sum(b"abcdef")
  assert_eq(bytes_to_hex(hash), bytes_to_hex(expected))
}

///|
/// SM3 of a large message via streaming
test "sm3_streaming_large" {
  let msg = Bytes::makei(200, fn(i) { (i % 256).to_byte() })
  let ctx = @sm3.new()
  let ctx = ctx.write(msg[0:100].to_owned())
  let ctx = ctx.write(msg[100:200].to_owned())
  let hash_stream = ctx.finish()
  let hash_direct = @sm3.sm3_sum(msg)
  assert_eq(bytes_to_hex(hash_stream), bytes_to_hex(hash_direct))
}

///|
/// SM3 incremental: one byte at a time
test "sm3_byte_by_byte" {
  let msg = b"1234567890abcdef"
  let mut ctx = @sm3.new()
  for i = 0; i < msg.length(); i = i + 1 {
    ctx = ctx.write(msg[i:i + 1].to_owned())
  }
  let hash = ctx.finish()
  let expected = @sm3.sm3_sum(msg)
  assert_eq(bytes_to_hex(hash), bytes_to_hex(expected))
}

///|
/// SM3 with 64-byte boundary crossing
test "sm3_boundary" {
  // 63 bytes + 1 byte crossing the block boundary
  let msg1 = Bytes::makei(63, fn(_i) { b'a' })
  let msg2 = b"a"
  let msg_all = Bytes::makei(64, fn(_i) { b'a' })
  let ctx = @sm3.new()
  let ctx = ctx.write(msg1)
  let ctx = ctx.write(msg2)
  let hash = ctx.finish()
  let expected = @sm3.sm3_sum(msg_all)
  assert_eq(bytes_to_hex(hash), bytes_to_hex(expected))
}

///|
/// SM3 with exactly 64 bytes (one full block)
test "sm3_one_block" {
  let msg = Bytes::makei(64, fn(i) { (i % 256).to_byte() })
  let hash = @sm3.sm3_sum(msg)
  // Verify it doesn't crash and produces 32 bytes
  assert_eq(hash.length(), 32)
}

///|
/// `sm3_sum_multi` hashes the concatenation of its chunks.
test "sm3_sum_multi" {
  let chunks : Array[Bytes] = [b"abc", b"", b"defgh", b"ijklmnopqrstuvwxyz"]
  let expected = @sm3.sm3_sum(b"abcdefghijklmnopqrstuvwxyz")
  assert_eq(bytes_to_hex(@sm3.sm3_sum_multi(chunks)), bytes_to_hex(expected))
  // an empty chunk list hashes the empty message
  assert_eq(
    bytes_to_hex(@sm3.sm3_sum_multi([])),
    bytes_to_hex(@sm3.sm3_sum(b"")),
  )
  // a single chunk behaves like sm3_sum
  assert_eq(
    bytes_to_hex(@sm3.sm3_sum_multi([b"abc"])),
    bytes_to_hex(@sm3.sm3_sum(b"abc")),
  )
}

///|
/// `sum` does not consume the context: it can be called repeatedly and the
/// context can still be extended afterwards.
test "sm3_sum_is_not_destructive" {
  let ctx = @sm3.new().write(b"abc")
  let first = ctx.sum()
  let second = ctx.sum()
  assert_eq(bytes_to_hex(first), bytes_to_hex(second))
  assert_eq(bytes_to_hex(first), bytes_to_hex(@sm3.sm3_sum(b"abc")))
  let ctx = ctx.write(b"def")
  assert_eq(bytes_to_hex(ctx.sum()), bytes_to_hex(@sm3.sm3_sum(b"abcdef")))
}

///|
/// `reset` brings the context back to the initial state.
test "sm3_reset" {
  let ctx = @sm3.new().write(b"garbage data that must be discarded")
  let ctx = ctx.reset()
  assert_eq(bytes_to_hex(ctx.sum()), bytes_to_hex(@sm3.sm3_sum(b"")))
  let ctx = ctx.write(b"abc")
  assert_eq(bytes_to_hex(ctx.sum()), bytes_to_hex(@sm3.sm3_sum(b"abc")))
  // reset also works after crossing a block boundary
  let ctx = ctx.write(Bytes::makei(200, fn(_i) { b'z' })).reset().write(b"abc")
  assert_eq(bytes_to_hex(ctx.sum()), bytes_to_hex(@sm3.sm3_sum(b"abc")))
}

///|
/// `size` / `block_size` mirror Go's `hash.Hash`.
test "sm3_size_and_block_size" {
  let ctx = @sm3.new()
  assert_eq(ctx.size(), 32)
  assert_eq(ctx.block_size(), 64)
  assert_eq(ctx.sum().length(), ctx.size())
}

///|
/// SM3 hash output length is always 32 bytes
test "sm3_output_length" {
  let test_cases : Array[Bytes] = [
    b"",
    b"a",
    b"hello world",
    Bytes::makei(128, fn(_i) { b'x' }),
  ]
  for i = 0; i < test_cases.length(); i = i + 1 {
    let hash = @sm3.sm3_sum(test_cases[i])
    assert_eq(hash.length(), 32)
  }
}
