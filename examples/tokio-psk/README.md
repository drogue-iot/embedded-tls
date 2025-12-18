# Tokio runtime example with pre-shared key

This example show how you can use embedded-tls with the tokio async runtime. It will attempt to connect to an endpoint, send a "ping" message, and expect a "pong" response.

You can use the openssl command line utility to test it as follows:

```sh
# Start the server in another terminal window
# Note: the generated Keys are only there to make openssl happy. The provided example does not support RSA and will instead use the PSK for the DH-Key-exchange
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout key.pem -out cert.pem -batch
openssl s_server -tls1_3 -psk_identity vader -psk aabbccdd -key key.pem -cert cert.pem -ciphersuites TLS_AES_128_GCM_SHA256

# Run the example
RUST_LOG=trace cargo run

# Then type 'pong' in the openssl server window to 'respond' to the client
```
