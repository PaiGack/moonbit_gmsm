/// SM3 cryptographic hash algorithm (GM/T 0004-2012).
/// Produces a 256-bit (32-byte) hash value.

///|
/// SM3 initial value (IV)
let iv : FixedArray[UInt] = [
  0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U, 0xa96f30bcU, 0x163138aaU, 0xe38dee4dU,
  0xb0fb0e4eU,
]

///|
/// SM3 streaming hash context.
pub struct SM3 {
  state : FixedArray[UInt]
  buf : FixedArray[Byte]
  buf_len : Int
  total : UInt64
}

///|
/// Create a new SM3 context initialized with the standard IV.
pub fn new() -> SM3 {
  SM3::{
    state: FixedArray::makei(8, fn(i) { iv[i] }),
    buf: FixedArray::makei(64, fn(_i) { b'\x00' }),
    buf_len: 0,
    total: 0UL,
  }
}

///|
/// Compute the SM3 hash of `data` in a single call.
pub fn sm3_sum(data : Bytes) -> Bytes {
  let ctx = new()
  let ctx = ctx.write(data)
  ctx.finish()
}

///|
/// Compute the SM3 hash of several chunks as if they were concatenated.
/// Mirrors `Sm3SumMulti` from the Go reference implementation.
pub fn sm3_sum_multi(chunks : Array[Bytes]) -> Bytes {
  let mut ctx = new()
  for chunk in chunks {
    ctx = ctx.write(chunk)
  }
  ctx.finish()
}

///|
/// Feed `data` into the hash context. Returns the updated context.
pub fn SM3::write(self : SM3, data : Bytes) -> SM3 {
  let len = data.length()
  let total = self.total + len.to_uint64()
  let mut buf_len = self.buf_len
  let buf = self.buf
  let state = self.state
  let mut offset = 0

  // If there is partial data in the buffer, fill it first
  if buf_len > 0 {
    let fill = 64 - buf_len
    if len < fill {
      for i in 0..<len {
        buf[buf_len + i] = data[offset + i]
      }
      buf_len = buf_len + len
      offset = len
    } else {
      for i in 0..<fill {
        buf[buf_len + i] = data[offset + i]
      }
      offset = offset + fill
      compress_fixed(state, buf, offset=0)
      buf_len = 0
    }
  }

  // Process full blocks from data
  while offset + 64 <= len {
    compress(state, data, offset~)
    offset = offset + 64
  }

  // Copy remaining bytes to buffer
  let remaining = len - offset
  if remaining > 0 {
    for i in 0..<remaining {
      buf[i] = data[offset + i]
    }
    buf_len = remaining
  }

  SM3::{ state, buf, buf_len, total }
}

///|
/// Return the digest length in bytes (32), mirroring `hash.Hash.Size`.
pub fn SM3::size(_self : SM3) -> Int {
  32
}

///|
/// Return the internal block length in bytes (64), mirroring
/// `hash.Hash.BlockSize`.
pub fn SM3::block_size(_self : SM3) -> Int {
  64
}

///|
/// Reset the context back to the standard IV so it can be reused.
/// Mirrors `hash.Hash.Reset`.
pub fn SM3::reset(self : SM3) -> SM3 {
  let state = self.state
  let buf = self.buf
  for i in 0..<8 {
    state[i] = iv[i]
  }
  for i in 0..<64 {
    buf[i] = b'\x00'
  }
  SM3::{ state, buf, buf_len: 0, total: 0UL }
}

///|
/// Return the 32-byte digest of everything written so far without consuming
/// the context. Mirrors `hash.Hash.Sum`.
pub fn SM3::sum(self : SM3) -> Bytes {
  let state = FixedArray::makei(8, fn(i) { self.state[i] })
  let buf = FixedArray::makei(64, fn(i) { self.buf[i] })
  finalize(state, buf, self.buf_len, self.total)
}

///|
/// Finalize the hash computation and return the 32-byte digest.
pub fn SM3::finish(self : SM3) -> Bytes {
  self.sum()
}

///|
/// Shared finalization: apply the SM3 padding rules to `buf` and emit the
/// big-endian digest of `state`.
fn finalize(
  state : FixedArray[UInt],
  buf : FixedArray[Byte],
  buf_len_init : Int,
  total : UInt64,
) -> Bytes {
  let mut buf_len = buf_len_init

  // Append padding byte 0x80
  buf[buf_len] = b'\x80'
  buf_len = buf_len + 1

  // If there is not enough room for the 64-bit length field, pad and compress
  if buf_len > 56 {
    while buf_len < 64 {
      buf[buf_len] = b'\x00'
      buf_len = buf_len + 1
    }
    compress_fixed(state, buf, offset=0)
    buf_len = 0
  }

  // Pad to 56 bytes (448 bits) with zeros
  while buf_len < 56 {
    buf[buf_len] = b'\x00'
    buf_len = buf_len + 1
  }

  // Append total message length in bits as 64-bit big-endian integer
  let total_bits_bytes = (total * 8UL).to_be_bytes()
  for i in 0..<8 {
    buf[56 + i] = total_bits_bytes[i]
  }
  compress_fixed(state, buf, offset=0)

  // Convert state to 32-byte big-endian result
  Bytes::makei(32, fn(i) {
    let word = state[i / 4]
    let shift = 24 - i % 4 * 8
    (word >> shift).to_byte()
  })
}

///|
/// Read a 32-bit unsigned integer from a FixedArray[Byte] at the given offset.
fn get_u32_be_fa(buf : FixedArray[Byte], offset : Int) -> UInt {
  (buf[offset].to_uint().land(0xffU) << 24) |
  (buf[offset + 1].to_uint().land(0xffU) << 16) |
  (buf[offset + 2].to_uint().land(0xffU) << 8) |
  buf[offset + 3].to_uint().land(0xffU)
}

///|
/// SM3 constant T_j.
fn tj(j : Int) -> UInt {
  if j < 16 {
    0x79cc4519U
  } else {
    0x7a879d8aU
  }
}

///|
/// SM3 boolean function FF_j.
fn ff(j : Int, x : UInt, y : UInt, z : UInt) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x & z) | (y & z)
  }
}

///|
/// SM3 boolean function GG_j.
fn gg(j : Int, x : UInt, y : UInt, z : UInt) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x.lnot() & z)
  }
}

///|
/// SM3 permutation function P_0.
fn p0(x : UInt) -> UInt {
  x ^ @byteutil.rotl(x, 9) ^ @byteutil.rotl(x, 17)
}

///|
/// SM3 permutation function P_1.
fn p1(x : UInt) -> UInt {
  x ^ @byteutil.rotl(x, 15) ^ @byteutil.rotl(x, 23)
}

///|
/// SM3 compression function. Processes one 64-byte block from a Bytes source.
fn compress(state : FixedArray[UInt], block : Bytes, offset? : Int = 0) -> Unit {
  // Message expansion: W[0..67]
  let w : FixedArray[UInt] = FixedArray::makei(68, fn(_i) { 0U })
  // Message expansion: W'[0..63]
  let w1 : FixedArray[UInt] = FixedArray::makei(64, fn(_i) { 0U })

  for j in 0..<16 {
    w[j] = @byteutil.get_u32_be(block, offset + j * 4)
  }

  for j in 16..<68 {
    w[j] = p1(w[j - 16] ^ w[j - 9] ^ @byteutil.rotl(w[j - 3], 15)) ^
      @byteutil.rotl(w[j - 13], 7) ^
      w[j - 6]
  }

  for j in 0..<64 {
    w1[j] = w[j] ^ w[j + 4]
  }

  compress_rounds(state, w, w1)
}

///|
/// SM3 compression function for FixedArray[Byte].
fn compress_fixed(
  state : FixedArray[UInt],
  block : FixedArray[Byte],
  offset? : Int = 0,
) -> Unit {
  // Message expansion: W[0..67]
  let w : FixedArray[UInt] = FixedArray::makei(68, fn(_i) { 0U })
  // Message expansion: W'[0..63]
  let w1 : FixedArray[UInt] = FixedArray::makei(64, fn(_i) { 0U })

  for j in 0..<16 {
    w[j] = get_u32_be_fa(block, offset + j * 4)
  }

  for j in 16..<68 {
    w[j] = p1(w[j - 16] ^ w[j - 9] ^ @byteutil.rotl(w[j - 3], 15)) ^
      @byteutil.rotl(w[j - 13], 7) ^
      w[j - 6]
  }

  for j in 0..<64 {
    w1[j] = w[j] ^ w[j + 4]
  }

  compress_rounds(state, w, w1)
}

///|
/// SM3 compression rounds (shared between Bytes and FixedArray paths).
fn compress_rounds(
  state : FixedArray[UInt],
  w : FixedArray[UInt],
  w1 : FixedArray[UInt],
) -> Unit {
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  for j in 0..<64 {
    let ss1 = @byteutil.rotl(
      @byteutil.rotl(a, 12) + e + @byteutil.rotl(tj(j), j),
      7,
    )
    let ss2 = ss1 ^ @byteutil.rotl(a, 12)
    let tt1 = ff(j, a, b, c) + d + ss2 + w1[j]
    let tt2 = gg(j, e, f, g) + h + ss1 + w[j]
    d = c
    c = @byteutil.rotl(b, 9)
    b = a
    a = tt1
    h = g
    g = @byteutil.rotl(f, 19)
    f = e
    e = p0(tt2)
  }

  // Update state by XOR
  state[0] = state[0] ^ a
  state[1] = state[1] ^ b
  state[2] = state[2] ^ c
  state[3] = state[3] ^ d
  state[4] = state[4] ^ e
  state[5] = state[5] ^ f
  state[6] = state[6] ^ g
  state[7] = state[7] ^ h
}
