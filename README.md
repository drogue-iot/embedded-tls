# Drogue-TLS

[![CI](https://github.com/drogue-iot/drogue-tls/actions/workflows/ci.yaml/badge.svg)](https://github.com/drogue-iot/drogue-tls/actions/workflows/ci.yaml)
[![crates.io](https://img.shields.io/crates/v/drogue-tls.svg)](https://crates.io/crates/drogue-tls)
[![docs.rs](https://docs.rs/drogue-tls/badge.svg)](https://docs.rs/drogue-tls)
[![Matrix](https://img.shields.io/matrix/drogue-iot:matrix.org)](https://matrix.to/#/#drogue-iot:matrix.org)

Drogue-TLS is a Rust-native TLS 1.3 implementation that works in a no-std environment. The
implementation is work in progress, but the [example clients](https://github.com/drogue-iot/drogue-tls/tree/main/examples) should work against the [rustls](https://github.com/ctz/rustls) echo server.

NOTE: This crate has been replaced by [embedded-tls](https://crates.io/crates/embedded-tls).
