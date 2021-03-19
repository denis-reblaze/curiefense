#[inline]
fn from_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// decodes an url encoded string into a binary vector
pub fn urldecode(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = input.as_bytes().iter().copied();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            if let Some(h) = bytes.next() {
                if let Some(l) = bytes.next() {
                    match from_hex_digit(h).and_then(|hv| from_hex_digit(l).map(|lv| (hv, lv))) {
                        None => {
                            out.push(b);
                            out.push(h);
                            out.push(l);
                        }
                        Some((hv, lv)) => {
                            out.push(hv * 16 + lv);
                        }
                    }
                } else {
                    out.push(b);
                    out.push(h);
                }
            } else {
                out.push(b);
            }
        } else {
            out.push(b);
        }
    }
    out
}

/// decodes an url encoded string into a string, which can contain REPLACEMENT CHARACTER on decoding failure
pub fn urldecode_str(input: &str) -> String {
    String::from_utf8_lossy(&urldecode(input)).into_owned()
}
