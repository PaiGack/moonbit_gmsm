///| SM3 cryptographic hash function (GM/T 0004-2012)

///| Produces a 256-bit (32-byte) hash value.

///|
/// SM3 initial value (IV)
let sm3_iv : FixedArray[UInt] = [
  0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U, 0xa96f30bcU, 0x163138aaU, 0xe38dee4dU,
  0xb0fb0e4eU,
]

///|
/// 32-bit left rotation
fn sm3_rotl(x : UInt, n : UInt) -> UInt {
  let ni : Int = n.reinterpret_as_int()
  ((x << ni) | (x >> (32 - ni))) & 0xFFFFFFFFU
}

///|
/// Permutation function P0
fn sm3_p0(x : UInt) -> UInt {
  x ^ sm3_rotl(x, 9U) ^ sm3_rotl(x, 17U)
}

///|
/// Permutation function P1
fn sm3_p1(x : UInt) -> UInt {
  x ^ sm3_rotl(x, 15U) ^ sm3_rotl(x, 23U)
}

///|
/// Boolean function FF_j for j < 16
fn sm3_ff0(x : UInt, y : UInt, z : UInt) -> UInt {
  x ^ y ^ z
}

///|
/// Boolean function FF_j for j >= 16
fn sm3_ff1(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) | (x & z) | (y & z)
}

///|
/// Boolean function GG_j for j < 16
fn sm3_gg0(x : UInt, y : UInt, z : UInt) -> UInt {
  x ^ y ^ z
}

///|
/// Boolean function GG_j for j >= 16
fn sm3_gg1(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) | (x.lnot() & z)
}

///|
/// Convert top 4 bytes of block from offset to UInt (big-endian)
fn sm3_get_uint(block : BytesView, offset : Int) -> UInt {
  (block[offset].to_uint() << 24) |
  (block[offset + 1].to_uint() << 16) |
  (block[offset + 2].to_uint() << 8) |
  block[offset + 3].to_uint()
}

///|
/// Process one 64-byte block through the SM3 compression function.
fn sm3_compress(state : FixedArray[UInt], block : BytesView) -> Unit {
  // Message expansion: W[0..67] and W'[0..63]
  let w : Array[UInt] = Array::make(68, 0U)
  let w1 : Array[UInt] = Array::make(64, 0U)

  // Fill W[0..15] from block
  for j = 0; j < 16; j = j + 1 {
    w[j] = sm3_get_uint(block, j * 4)
  }

  // Expand W[16..67]
  for j = 16; j < 68; j = j + 1 {
    let wj = sm3_p1(w[j - 16] ^ w[j - 9] ^ sm3_rotl(w[j - 3], 15U)) ^
      sm3_rotl(w[j - 13], 7U) ^
      w[j - 6]
    w[j] = wj
  }

  // Compute W'[0..63]
  for j = 0; j < 64; j = j + 1 {
    w1[j] = w[j] ^ w[j + 4]
  }

  // Initialize working variables
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  // 64 rounds
  for j = 0; j < 64; j = j + 1 {
    let (_, _, tt1, tt2) = if j < 16 {
      let s1 = sm3_rotl(
        sm3_rotl(a, 12U) + e + sm3_rotl(0x79cc4519U, j.reinterpret_as_uint()),
        7U,
      )
      let s2 = s1 ^ sm3_rotl(a, 12U)
      let t1 = sm3_ff0(a, b, c) + d + s2 + w1[j]
      let t2 = sm3_gg0(e, f, g) + h + s1 + w[j]
      (s1, s2, t1, t2)
    } else {
      let s1 = sm3_rotl(
        sm3_rotl(a, 12U) + e + sm3_rotl(0x7a879d8aU, j.reinterpret_as_uint()),
        7U,
      )
      let s2 = s1 ^ sm3_rotl(a, 12U)
      let t1 = sm3_ff1(a, b, c) + d + s2 + w1[j]
      let t2 = sm3_gg1(e, f, g) + h + s1 + w[j]
      (s1, s2, t1, t2)
    }

    d = c
    c = sm3_rotl(b, 9U)
    b = a
    a = tt1
    h = g
    g = sm3_rotl(f, 19U)
    f = e
    e = sm3_p0(tt2)
  }

  // Update state
  state[0] = state[0] ^ a
  state[1] = state[1] ^ b
  state[2] = state[2] ^ c
  state[3] = state[3] ^ d
  state[4] = state[4] ^ e
  state[5] = state[5] ^ f
  state[6] = state[6] ^ g
  state[7] = state[7] ^ h
}

///| Compute SM3 hash of the given data.

///|
/// Returns a 32-byte hash value.
pub fn sm3_sum(data : Bytes) -> Bytes {
  let state : FixedArray[UInt] = [
    sm3_iv[0],
    sm3_iv[1],
    sm3_iv[2],
    sm3_iv[3],
    sm3_iv[4],
    sm3_iv[5],
    sm3_iv[6],
    sm3_iv[7],
  ]

  let len = data.length()
  let bit_len : UInt64 = len.to_uint64() * 8UL

  // Process complete blocks
  let block_count = len / 64
  for i = 0; i < block_count; i = i + 1 {
    let block = data[i * 64:(i + 1) * 64]
    sm3_compress(state, block)
  }

  // Padding
  let remaining = len - block_count * 64
  let pad_len : Int = if remaining < 56 { 64 } else { 128 }

  // Build padded block using FixedArray
  let pad_block = FixedArray::make(pad_len, b'\x00')
  for j = 0; j < remaining; j = j + 1 {
    pad_block[j] = data[block_count * 64 + j]
  }
  pad_block[remaining] = b'\x80'

  // Append bit length in big-endian at the end
  let len_pos = pad_len - 8
  pad_block[len_pos] = ((bit_len >> 56) & 0xFFUL).to_byte()
  pad_block[len_pos + 1] = ((bit_len >> 48) & 0xFFUL).to_byte()
  pad_block[len_pos + 2] = ((bit_len >> 40) & 0xFFUL).to_byte()
  pad_block[len_pos + 3] = ((bit_len >> 32) & 0xFFUL).to_byte()
  pad_block[len_pos + 4] = ((bit_len >> 24) & 0xFFUL).to_byte()
  pad_block[len_pos + 5] = ((bit_len >> 16) & 0xFFUL).to_byte()
  pad_block[len_pos + 6] = ((bit_len >> 8) & 0xFFUL).to_byte()
  pad_block[len_pos + 7] = (bit_len & 0xFFUL).to_byte()

  // Process padded block(s)
  if pad_len == 128 {
    let block1 = FixedArray::unsafe_reinterpret_as_bytes(pad_block)
    let block1_view = block1[0:64]
    sm3_compress(state, block1_view)
    let block2_view = block1[64:128]
    sm3_compress(state, block2_view)
  } else {
    let block = FixedArray::unsafe_reinterpret_as_bytes(pad_block)
    sm3_compress(state, block)
  }

  // Output hash as Bytes
  let result = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let v = state[i]
    let base = i * 4
    result[base] = ((v >> 24) & 0xFFU).to_byte()
    result[base + 1] = ((v >> 16) & 0xFFU).to_byte()
    result[base + 2] = ((v >> 8) & 0xFFU).to_byte()
    result[base + 3] = (v & 0xFFU).to_byte()
  }
  FixedArray::unsafe_reinterpret_as_bytes(result)
}
