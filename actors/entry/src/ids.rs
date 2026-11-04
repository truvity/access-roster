//! The correlation id of a request: a random UUID version 4 (RFC 9562 section 5.4) from the
//! operating system's generator (contracts.md "Every call").

/// 36 characters of lower-case hex and hyphens, so it is a valid id for the kit and the emitter
/// (1 to 64 of `[A-Za-z0-9_-]`).
pub(crate) fn new_correlation_id() -> String {
    let mut b = [0u8; 16];
    os_random(&mut b);
    b[6] = b[6] & 0x0f | 0x40; // version 4
    b[8] = b[8] & 0x3f | 0x80; // variant 10
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Fills `buf` from the operating system's random generator and nothing else.
fn os_random(buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        match rustix::rand::getrandom(&mut buf[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            // Stop rather than go on with an id that is not random.
            Err(e) => panic!("the operating system's random generator failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_a_v4_uuid_and_a_valid_correlation_id() {
        let a = new_correlation_id();
        let b = new_correlation_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'4');
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    }
}
