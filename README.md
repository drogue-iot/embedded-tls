# Drogue-TLS

[![CI](https://github.com/drogue-iot/drogue-tls/actions/workflows/ci.yaml/badge.svg)](https://github.com/drogue-iot/drogue-tls/actions/workflows/ci.yaml)
[![crates.io](https://img.shields.io/crates/v/drogue-tls.svg)](https://crates.io/crates/drogue-tls)
[![docs.rs](https://docs.rs/drogue-tls/badge.svg)](https://docs.rs/drogue-tls)
[![Matrix](https://img.shields.io/matrix/drogue-iot:matrix.org)](https://matrix.to/#/#drogue-iot:matrix.org)

Drogue-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The
implementation is work in progress, but the [example clients](https://github.com/drogue-iot/drogue-tls/tree/main/examples) should work against the [rustls](https://github.com/ctz/rustls) echo server.

The client supports both async and blocking modes. By default, the `async` and `std` features are enabled. The `async` feature requires Rust nightly, while the blocking feature works on Rust stable.

To use the async mode, import `drogue_tls::*`. To use the blocking mode, import `drogue_tls::blocking::*`.

Some features like certificate validation are still not implemented, have a look at [open issues](https://github.com/drogue-iot/drogue-tls/issues).
Only supports writing/receiving one frame at a time, hence using a frame buffer larger than 16k is not currently needed.  You may use a lower frame buffer size, but there is no guarantee that it will be able to parse any TLS 1.3 frame.

Usage of this crate should fit in 20 kB of RAM assuming a frame buffer of 16 kB (max TLS record size). This is not including the space used to hold the CA and any client certificates, which is not yet supported.

NOTE: This is very fresh and is probably not meeting all parts of the TLS 1.3 spec. Things like certificate validation and client certificate support is not complete.
If you find anything you'd like to get implemented, feel free to raise an issue.

## Community

* [Drogue IoT Matrix Chat Room](https://matrix.to/#/#drogue-iot:matrix.org)
* We have bi-weekly calls at 9:00 AM (GMT). [Check the calendar](https://calendar.google.com/calendar/u/0/embed?src=ofuctjec399jr6kara7n0uidqg@group.calendar.google.com&pli=1) to see which week we are having the next call, and feel free to join!
* [Drogue IoT Forum](https://discourse.drogue.io/)
* [Drogue IoT YouTube channel](https://www.youtube.com/channel/UC7GZUy2hKidvY6V_3QZfCcA)
* [Follow us on Twitter!](https://twitter.com/DrogueIoT)
