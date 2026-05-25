/// compute the md5 digest of some input message bytes
pub fn md5(input: &[u8]) -> [u8; 16] {
    // "precompute" sine table
    // length of 65 is because T is 1-indexed in the RFC
    let t: [u32; 65] = std::array::from_fn(sine_table);

    // 1. padding
    let mut padded: Vec<u8> = input.to_vec();
    // a single 1 bit followed by zeroes
    padded.push(0x80);
    // then, zero padding out to 448 mod 512 bits
    let padding_bytes = (56usize.wrapping_sub(padded.len() % 64)) % 64;
    padded.resize(padded.len() + padding_bytes, 0u8);

    // 2. length
    // append the length of the input
    padded.extend_from_slice(&(input.len() as u64 * 8).to_le_bytes());
    // split into words
    let m: Vec<u32> = padded
        .chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let n = m.len();
    assert!(n % 16 == 0);

    // 3. MD buffer "registers"
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    // 4. process blocks
    // see aux_f, aux_g, aux_h, aux_i, t, operation definitions elsewhere
    for i in 0..=n / 16 - 1 {
        let mut x = [0u32; 16];
        for j in 0..=15 {
            x[j] = m[i * 16 + j];
        }

        // save registers
        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        // run all 4 rounds
        for round in ROUNDS {
            // run all 16 operations for that round
            for &(k, s, i) in round.ksi {
                a = operation(a, b, c, d, k, s, i, &x, &t, round.aux);
                (a, b, c, d) = (d, a, b, c);
            }
        }

        // update registers
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut result = [0u8; 16];
    for (i, word) in [a, b, c, d].iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    result
}

struct Round {
    aux: fn(u32, u32, u32) -> u32,
    ksi: &'static [(usize, u32, usize); 16],
}

const ROUNDS: &[Round; 4] = &[
    Round {
        aux: aux_f,
        ksi: &[
            (0, 7, 1),
            (1, 12, 2),
            (2, 17, 3),
            (3, 22, 4),
            (4, 7, 5),
            (5, 12, 6),
            (6, 17, 7),
            (7, 22, 8),
            (8, 7, 9),
            (9, 12, 10),
            (10, 17, 11),
            (11, 22, 12),
            (12, 7, 13),
            (13, 12, 14),
            (14, 17, 15),
            (15, 22, 16),
        ],
    },
    Round {
        aux: aux_g,
        ksi: &[
            (1, 5, 17),
            (6, 9, 18),
            (11, 14, 19),
            (0, 20, 20),
            (5, 5, 21),
            (10, 9, 22),
            (15, 14, 23),
            (4, 20, 24),
            (9, 5, 25),
            (14, 9, 26),
            (3, 14, 27),
            (8, 20, 28),
            (13, 5, 29),
            (2, 9, 30),
            (7, 14, 31),
            (12, 20, 32),
        ],
    },
    Round {
        aux: aux_h,
        ksi: &[
            (5, 4, 33),
            (8, 11, 34),
            (11, 16, 35),
            (14, 23, 36),
            (1, 4, 37),
            (4, 11, 38),
            (7, 16, 39),
            (10, 23, 40),
            (13, 4, 41),
            (0, 11, 42),
            (3, 16, 43),
            (6, 23, 44),
            (9, 4, 45),
            (12, 11, 46),
            (15, 16, 47),
            (2, 23, 48),
        ],
    },
    Round {
        aux: aux_i,
        ksi: &[
            (0, 6, 49),
            (7, 10, 50),
            (14, 15, 51),
            (5, 21, 52),
            (12, 6, 53),
            (3, 10, 54),
            (10, 15, 55),
            (1, 21, 56),
            (8, 6, 57),
            (15, 10, 58),
            (6, 15, 59),
            (13, 21, 60),
            (4, 6, 61),
            (11, 10, 62),
            (2, 15, 63),
            (9, 21, 64),
        ],
    },
];

// auxiliary functions
fn aux_f(x: u32, y: u32, z: u32) -> u32 {
    x & y | !x & z
}

fn aux_g(x: u32, y: u32, z: u32) -> u32 {
    x & z | y & !z
}

fn aux_h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn aux_i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

// the sine table T
// can't be const because sin() isn't const
// could be precomputed, but this seemed fine
fn sine_table(i: usize) -> u32 {
    (4294967296.0 * (i as f64).sin().abs()) as u32
}

// run an individual operation from the 16 per round
fn operation(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    k: usize,
    s: u32,
    i: usize,
    x: &[u32],
    t: &[u32],
    aux_func: fn(u32, u32, u32) -> u32,
) -> u32 {
    b.wrapping_add(
        a.wrapping_add(aux_func(b, c, d))
            .wrapping_add(x[k])
            .wrapping_add(t[i])
            .rotate_left(s),
    )
}

// tests, from the "MD5 test suite" in RFC 1321

#[cfg(test)]
fn md5_hex(input: &[u8]) -> String {
    md5(input).map(|b| format!("{:02x}", b)).join("")
}

#[test]
fn empty() {
    assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn a() {
    assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
}

#[test]
fn abc() {
    assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn message_digest() {
    assert_eq!(
        md5_hex(b"message digest"),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );
}

#[test]
fn alphabet() {
    assert_eq!(
        md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
        "c3fcd3d76192e4007dfb496cca67e13b"
    );
}

#[test]
fn long_alphanumeric() {
    assert_eq!(
        md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
        "d174ab98d277d9f5a5611c2c9f419d9f"
    );
}

#[test]
fn long_numeric() {
    assert_eq!(
        md5_hex(
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        ),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
}
