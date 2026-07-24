/// SM3 cryptographic hash algorithm (GB/T 32905-2016).
/// Produces a 256-bit (32-byte) hash value.

///|
/// SM3 digest producing a 32-byte hash.
pub fn sm3_sum(data : Bytes) -> Bytes {
  let h = SM3::new()
  h.write(data)
  h.sum()
}

///|
/// SM3 digest for combined data sources.
pub fn sm3_sum_multi(data : Array[Bytes]) -> Bytes {
  let h = SM3::new()
  for d in data {
    h.write(d)
  }
  h.sum()
}

///|
/// SM3 hash state.
pub(all) struct SM3 {
  mut digest : Array[UInt]
  mut data : Array[Byte]
  mut datalen : Int
  mut total : Int64
}

/// Initial values for SM3 (now inline to avoid shared reference)

///|
/// T values for SM3
fn t_val(j : Int) -> UInt {
  if j < 16 {
    0x79cc4519
  } else {
    0x7a879d8a
  }
}

///|
pub fn SM3::new() -> SM3 {
  {
    digest: [
      0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
      0xb0fb0e4e,
    ],
    data: Array::make(64, b'\x00'),
    datalen: 0,
    total: 0,
  }
}

///|
pub fn SM3::write(self : SM3, data : Bytes) -> Unit {
  let len = data.length()
  self.total = self.total + len.to_int64()
  let mut offset : Int = 0
  while offset < len {
    let remaining = 64 - self.datalen
    let copy_len = if len - offset < remaining {
      len - offset
    } else {
      remaining
    }
    for i in 0..<copy_len {
      self.data[self.datalen + i] = data[offset + i]
    }
    self.datalen = self.datalen + copy_len
    offset = offset + copy_len
    if self.datalen == 64 {
      self._process_block()
      self.datalen = 0
    }
  }
}

///|
/// Reset the SM3 hash state for reuse.
pub fn SM3::reset(self : SM3) -> Unit {
  self.digest = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
    0xb0fb0e4e,
  ]
  self.datalen = 0
  self.total = 0
}

///|
/// Finalize and return the 32-byte hash.
pub fn SM3::sum(self : SM3) -> Bytes {
  self._finalize()
  let result_bytes : Array[Byte] = Array::make(0, b'\x00')
  for di in self.digest {
    let w = di
    result_bytes.push((w >> 24).to_byte())
    result_bytes.push((w >> 16).to_byte())
    result_bytes.push((w >> 8).to_byte())
    result_bytes.push(w.to_byte())
  }
  Bytes::from_array(result_bytes)
}

///|
fn SM3::_finalize(self : SM3) -> Unit {
  let bitlen : Int64 = self.total * 8
  // Append 0x80
  self.data[self.datalen] = b'\x80'
  self.datalen = self.datalen + 1

  let remaining = 64 - self.datalen
  if remaining < 8 {
    for i in self.datalen..<64 {
      self.data[i] = b'\x00'
    }
    self._process_block()
    self.datalen = 0
    for i in 0..<56 {
      self.data[i] = b'\x00'
    }
  } else {
    for i in self.datalen..<56 {
      self.data[i] = b'\x00'
    }
  }
  // Append bit length as big-endian 64-bit
  for i in 0..<8 {
    self.data[63 - i] = (bitlen >> (i * 8)).to_byte()
  }
  self._process_block()
}

///|
fn SM3::_process_block(self : SM3) -> Unit {
  let w : Array[UInt] = Array::make(68, 0)
  let w1 : Array[UInt] = Array::make(64, 0)

  // Expand message
  for i in 0..<16 {
    let b0 : UInt = self.data[i * 4].to_uint()
    let b1 : UInt = self.data[i * 4 + 1].to_uint()
    let b2 : UInt = self.data[i * 4 + 2].to_uint()
    let b3 : UInt = self.data[i * 4 + 3].to_uint()
    w[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }
  for j in 16..<68 {
    let x16 = w[j - 16]
    let x9 = w[j - 9]
    let x3 = w[j - 3]
    let x13 = w[j - 13]
    let x6 = w[j - 6]
    let tmp = x16 ^ x9 ^ _rotl(x3, 15)
    w[j] = _p1(tmp) ^ _rotl(x13, 7) ^ x6
  }
  for j in 0..<64 {
    w1[j] = w[j] ^ w[j + 4]
  }

  let mut a : UInt = self.digest[0]
  let mut b : UInt = self.digest[1]
  let mut c : UInt = self.digest[2]
  let mut d : UInt = self.digest[3]
  let mut e : UInt = self.digest[4]
  let mut f : UInt = self.digest[5]
  let mut g : UInt = self.digest[6]
  let mut h : UInt = self.digest[7]

  for j in 0..<64 {
    let ss1 = _rotl(_rotl(a, 12) + e + _rotl(t_val(j), j % 32), 7)
    let ss2 = ss1 ^ _rotl(a, 12)
    let tt1 = _ff(j, a, b, c) + d + ss2 + w1[j]
    let tt2 = _gg(j, e, f, g) + h + ss1 + w[j]
    d = c
    c = _rotl(b, 9)
    b = a
    a = tt1
    h = g
    g = _rotl(f, 19)
    f = e
    e = _p0(tt2)
  }

  self.digest[0] = self.digest[0] ^ a
  self.digest[1] = self.digest[1] ^ b
  self.digest[2] = self.digest[2] ^ c
  self.digest[3] = self.digest[3] ^ d
  self.digest[4] = self.digest[4] ^ e
  self.digest[5] = self.digest[5] ^ f
  self.digest[6] = self.digest[6] ^ g
  self.digest[7] = self.digest[7] ^ h
}

///|
/// 32-bit left rotation
fn _rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn _ff(j : Int, x : UInt, y : UInt, z : UInt) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x & z) | (y & z)
  }
}

///|
fn _gg(j : Int, x : UInt, y : UInt, z : UInt) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x.lnot() & z)
  }
}

///|
fn _p0(x : UInt) -> UInt {
  x ^ _rotl(x, 9) ^ _rotl(x, 17)
}

///|
fn _p1(x : UInt) -> UInt {
  x ^ _rotl(x, 15) ^ _rotl(x, 23)
}
