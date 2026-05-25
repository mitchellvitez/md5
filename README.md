# md5

This is an implementation of the md5 algorithm in Rust,
based on the original RFC 1321 (1992).

See `rfc1321.txt` for the "spec" (with reference implementation removed).

This is a hand-rolled implementation so caveat emptor, and obviously don't use it for cryptography. Probably just don't use it for anything.

Try it out with `cargo test`

See the corresponding blog post at [vitez.me/implementing-md5](https://vitez.me/implementing-md5)
