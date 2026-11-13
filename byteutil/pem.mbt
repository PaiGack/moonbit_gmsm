/// PEM (RFC 7468 style) encoding and decoding.
///
/// A PEM block is
///
/// ```text
/// -----BEGIN <type>-----
/// [Key: Value]...          (optional headers, separated by ':')
///                          (blank line)
/// <base64 body, wrapped>
/// -----END <type>-----
/// ```
///
/// The parser skips any text before `-----BEGIN`, accepts bare-LF or CRLF line
/// endings, and ignores the optional headers unless the caller asks for them.
///
/// Headers are only recognised when they are separated from the base64 body
/// by a blank line, as RFC 1421 / Go's `encoding/pem` require. A `Key: Value`
/// looking line inside the body is *not* silently consumed as a header: a
/// block that starts with such a line but never ends the header section with
/// a blank line is rejected.
///
/// Implementation note: every helper below takes an owned `String`. Passing a
/// `StringView` across function boundaries is unreliable in the current
/// toolchain (a view handed to a callee compared unequal with the same text),
/// so `pem_lines` materialises owned lines up front.

///|
/// Header list of a PEM block, in file order.
pub type Headers = Array[(String, String)]

///|
/// A decoded PEM block.
pub(all) struct PemBlock {
  type_ : String
  headers : Headers
  bytes : Bytes
}

///|
/// Encode a PEM block. When headers are present a blank line separates them
/// from the body, as in Go's `encoding/pem`. Lines are wrapped at 64
/// characters with `\n`; a trailing newline is added.
pub fn pem_encode(type_ : String, headers : Headers, data : Bytes) -> String {
  let sb = StringBuilder()
  sb.write_string("-----BEGIN ")
  sb.write_string(type_)
  sb.write_string("-----\n")
  for pair in headers {
    sb.write_string(pair.0)
    sb.write_string(": ")
    sb.write_string(pair.1)
    sb.write_string("\n")
  }
  if headers.length() > 0 {
    sb.write_string("\n")
  }
  let body = base64_encode(data)
  let mut i = 0
  while i < body.length() {
    let end = if i + 64 < body.length() { i + 64 } else { body.length() }
    sb.write_string(body[i:end].to_owned())
    sb.write_string("\n")
    i = i + 64
  }
  sb.write_string("-----END ")
  sb.write_string(type_)
  sb.write_string("-----\n")
  sb.to_string()
}

///|
/// Encode a PEM block without headers.
pub fn pem_encode_simple(type_ : String, data : Bytes) -> String {
  pem_encode(type_, [], data)
}

///|
/// Split `s` into owned lines on `\n`, dropping a trailing `\r` from each.
fn pem_lines(s : String) -> Array[String] {
  let lines : Array[String] = []
  let n = s.length()
  let mut start = 0
  for i = 0; i <= n; i = i + 1 {
    if i == n || s[i] == '\n' {
      let mut end = i
      if end > start && s[end - 1] == '\r' {
        end = end - 1
      }
      lines.push(s[start:end].to_owned())
      start = i + 1
    }
  }
  lines
}

///|
/// Whether `s` begins with the ASCII text `prefix`.
fn starts_with(s : String, prefix : String) -> Bool {
  if s.length() < prefix.length() {
    return false
  }
  let mut i = 0
  while i < prefix.length() {
    if s[i] != prefix[i] {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Whether `s` ends with the ASCII text `suffix`.
fn ends_with(s : String, suffix : String) -> Bool {
  if s.length() < suffix.length() {
    return false
  }
  let off = s.length() - suffix.length()
  let mut i = 0
  while i < suffix.length() {
    if s[off + i] != suffix[i] {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Decode the first PEM block in `s`. Text before `-----BEGIN` and after
/// `-----END` is ignored.
///
/// Raises `InvalidBase64` when there is no block or it is malformed, and
/// `InvalidLength` when more than one block is present (use
/// `pem_decode_all` for multi-block input).
pub fn pem_decode(s : String) -> PemBlock raise ByteUtilError {
  let lines = pem_lines(s)
  let n = lines.length()
  let starts : Array[Int32] = []
  let mut i = 0
  while i < n {
    if begin_type(lines[i]) is Some(_) {
      starts.push(i)
    }
    i = i + 1
  }
  if starts.length() == 0 {
    raise ByteUtilError::InvalidBase64
  }
  if starts.length() > 1 {
    raise ByteUtilError::InvalidLength
  }
  parse_block_at(lines, starts[0])
}

///|
/// Parse the single PEM block whose BEGIN line is at `lines[start]`.
fn parse_block_at(
  lines : Array[String],
  start : Int32,
) -> PemBlock raise ByteUtilError {
  let n = lines.length()
  let type_ = match begin_type(lines[start]) {
    Some(t) => t
    None => raise ByteUtilError::InvalidBase64
  }
  let mut i = start + 1
  let headers : Headers = []
  // Header section: zero or more "Key: Value" lines. It must be terminated
  // by a blank line -- otherwise a base64 body that happens to contain a
  // colon would be swallowed as a header, and the block would "parse" into
  // nothing at all.
  let mut in_headers = true
  while i < n && in_headers {
    let h = lines[i]
    if h.length() == 0 || starts_with(h, "-") {
      in_headers = false
    } else {
      match header_pair(h) {
        Some(pair) => {
          headers.push(pair)
          i = i + 1
        }
        None => in_headers = false
      }
    }
  }
  if headers.length() > 0 {
    // Every header must be followed by the blank separator line.
    if i >= n || lines[i].length() != 0 {
      raise ByteUtilError::InvalidBase64
    }
  }
  if i < n && lines[i].length() == 0 {
    i = i + 1
  }
  let body = StringBuilder()
  let mut closed = false
  while i < n && !closed {
    let l = lines[i]
    i = i + 1
    if starts_with(l, "-----END ") {
      if !ends_with(l, type_ + "-----") {
        raise ByteUtilError::InvalidBase64
      }
      closed = true
    } else {
      body.write_string(l)
    }
  }
  if !closed {
    raise ByteUtilError::InvalidBase64
  }
  { type_, headers, bytes: base64_decode(body.to_string()), }
}

///|
/// Decode every PEM block in `s`, in order.
pub fn pem_decode_all(s : String) -> Array[PemBlock] raise ByteUtilError {
  let lines = pem_lines(s)
  let n = lines.length()
  let blocks : Array[PemBlock] = []
  let mut i = 0
  while i < n {
    if begin_type(lines[i]) is Some(_) {
      blocks.push(parse_block_at(lines, i))
    }
    i = i + 1
  }
  blocks
}

///|
/// If `line` is `-----BEGIN <type>-----`, return `<type>`.
fn begin_type(line : String) -> String? {
  let is_begin = starts_with(line, "-----BEGIN ") && ends_with(line, "-----")
  if !is_begin {
    return None
  }
  // "-----BEGIN " (11) + type + "-----" (5); the type must be non-empty.
  if line.length() <= 16 {
    return None
  }
  Some(line[11:line.length() - 5].to_owned())
}

///|
/// Parse one `Key: Value` header line (value trimmed of leading blanks).
fn header_pair(line : String) -> (String, String)? {
  for i = 0; i < line.length(); i = i + 1 {
    if line[i] == ':' {
      let key = line[0:i].to_owned()
      let mut vstart = i + 1
      while vstart < line.length() && line[vstart] == ' ' {
        vstart = vstart + 1
      }
      return Some((key, line[vstart:].to_owned()))
    }
  }
  None
}

///|
/// Look up a header value by key.
pub fn PemBlock::get_header(self : PemBlock, key : String) -> String? {
  for pair in self.headers {
    if pair.0 == key {
      return Some(pair.1)
    }
  }
  None
}
