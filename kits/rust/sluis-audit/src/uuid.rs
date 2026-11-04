//! UUIDv7 (RFC 9562 section 5.7) with the fixed-length dedicated counter of section 6.2 (method 1),
//! so that values made in one millisecond increase: 48 bits of Unix milliseconds, the version, a
//! 12-bit counter in `rand_a`, the variant and 62 random bits.

use std::sync::Mutex;

struct State {
    last_ms: u64,
    counter: u16,
}

static STATE: Mutex<State> = Mutex::new(State {
    last_ms: 0,
    counter: 0,
});

/// Keeps the starting counter below 2048, so at least 2048 values fit in one millisecond before the
/// timestamp has to move on (section 6.2: when the counter would overflow, increase the timestamp).
const COUNTER_SEED_MASK: u16 = 0x7ff;

/// Fills `buf` from the operating system's random generator and nothing else.
pub(crate) fn os_random(buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        match rustix::rand::getrandom(&mut buf[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            // getrandom does not fail on a supported platform; the program stops rather than go on
            // with a value that is not random.
            Err(e) => panic!("the operating system's random generator failed: {e}"),
        }
    }
}

/// A UUIDv7 for `now_ms` (Unix milliseconds), as 36 characters. Values made by one process
/// increase, also within one millisecond and also if the clock steps back.
#[must_use]
pub fn new_uuid_v7(now_ms: i64) -> String {
    let mut seed = [0u8; 10];
    os_random(&mut seed);
    let seed_counter = u16::from_be_bytes([seed[8], seed[9]]) & COUNTER_SEED_MASK;
    let ms = u64::try_from(now_ms).unwrap_or(0);
    let mut st = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ms = if ms > st.last_ms {
        st.last_ms = ms;
        st.counter = seed_counter;
        ms
    } else {
        st.counter += 1;
        if st.counter > 0xfff {
            st.last_ms += 1;
            st.counter = seed_counter;
        }
        st.last_ms
    };
    let mut rand_b = [0u8; 8];
    rand_b.copy_from_slice(&seed[..8]);
    uuid_v7(ms, st.counter, rand_b)
}

/// Lays out the 128 bits: 48 bits ms, 0111, 12 bits counter, 10, 62 bits `rand_b`.
pub(crate) fn uuid_v7(ms: u64, counter: u16, rand_b: [u8; 8]) -> String {
    let mut u = [0u8; 16];
    u[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    u[6] = 0x70 | (counter >> 8) as u8 & 0x0f;
    u[7] = (counter & 0xff) as u8;
    u[8..].copy_from_slice(&rand_b);
    u[8] = 0x80 | (u[8] & 0x3f);
    let h: String = u.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}
