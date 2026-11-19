//! CRC-32 (IEEE 802.3), the checksum RFC 5389 §15.5 fixes for `FINGERPRINT`.
//!
//! Hand-rolled table-driven CRC instead of a dependency: the only user is the
//! four-byte `FINGERPRINT` attribute, and the runtime dependency list of this
//! crate is deliberately five crates long (see `README.md`, 「依赖面」). The
//! table is built by `const fn` at compile time, so the request path does no
//! lazy initialisation.
//!
//! The polynomial is the reflected IEEE one (`0xEDB88320`), i.e. the same
//! constant as the standard "CRC-32" (`iso-hdlc`) that `zlib.crc32` and RFC
//! 5769 §2.1's `FINGERPRINT` value use:
//!
//! ```text
//! crc = 0xFFFFFFFF
//! for byte in data: crc = (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]
//! return crc ^ 0xFFFFFFFF
//! ```

/// Reflected IEEE 802.3 polynomial (`0x04C11DB7` reversed).
const POLYNOMIAL: u32 = 0xEDB8_8320;

/// Build the 256-entry lookup table: one CRC step per possible low byte.
const fn build_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

static TABLE: [u32; 256] = build_table();

/// CRC-32 (IEEE 802.3) of `data`.
///
/// `crc32(b"123456789") == 0xCBF43926` is the standard check value every CRC-32
/// catalogue lists; RFC 5769 §2.1's `FINGERPRINT` is the STUN-specific vector
/// (see `protocol::tests::fingerprint_matches_rfc5769`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ u32::from(*byte)) & 0xFF) as usize];
    }
    crc ^ u32::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_check_values() {
        // The three values every CRC-32 implementation is expected to produce.
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn rfc5769_section_2_1_fingerprint_vector() {
        // RFC 5769 §2.1's Sample Request ends with `8028 0004 e57a3bcf`. The
        // fingerprint covers the message up to (excluding) that attribute; per
        // RFC 5389 §15.5 the header Length keeps counting the attribute (0x58),
        // which is exactly what the RFC's bytes encode. The point of this test
        // is the polynomial / init / final-XOR matching the STUN ecosystem.
        let prefix: Vec<u8> = {
            let hex: String = "
                000100582112a442b7e7a701bc34d686fa87dfae
                802200105354554e207465737420636c69656e74
                002400046e0001ff
                80290008932ff9b151263b36
                000600096576746a3a68367659202020
                000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2
            "
            .split_whitespace()
            .collect();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect()
        };
        assert_eq!(prefix.len(), 100, "20-byte header + 80 bytes of attributes");
        assert_eq!(crc32(&prefix) ^ 0x5354_554e, 0xE57A_3BCF);
    }

    #[test]
    fn table_driven_result_matches_the_bitwise_definition() {
        // The table is an optimisation of the definition, so the two must agree
        // on a long, unaligned input (the FINGERPRINT caller feeds it a header
        // followed by a body, i.e. every byte value shows up).
        fn bitwise(data: &[u8]) -> u32 {
            let mut crc = u32::MAX;
            for byte in data {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ POLYNOMIAL
                    } else {
                        crc >> 1
                    };
                }
            }
            crc ^ u32::MAX
        }

        let data: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        assert_eq!(crc32(&data), bitwise(&data));
        assert_eq!(crc32(b""), bitwise(b""));
        assert_eq!(crc32(b"123456789"), bitwise(b"123456789"));
    }
}
