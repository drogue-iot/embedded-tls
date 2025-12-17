# Blocking

This example show how you can use embedded-tls with standard std Read/Write traits. It will attempt to connect to an endpoint, send a "ping" message, and expect a "pong" response.

You can use the [rustls-mio](https://github.com/rustls/rustls/tree/main/examples) server example to test it as follows:


```sh
# In the rustls-mio folder
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 -nodes -x509 -keyout key.pem -out cert.pem -batch
cargo run --bin tlsserver-mio -- -p 12345 --certs cert.pem --key key.pem --protover 1.3 --tickets --verbose echo

# In this folder
RUST_LOG=trace cargo run
```
