# Embassy runtime example

This example show how you can use drogue-tls with the embassy async runtime. It will attempt to connect to an endpoint, send a "ping" message, and expect a "pong" response.

First, create the tap0 interface. You only need to do this once.

```sh
sudo ip tuntap add name tap0 mode tap user $USER
sudo ip link set tap0 up
sudo ip addr add 192.168.69.100/24 dev tap0
sudo ip -6 addr add fe80::100/64 dev tap0
sudo ip -6 addr add fdaa::100/64 dev tap0
sudo ip -6 route add fe80::/64 dev tap0
sudo ip -6 route add fdaa::/64 dev tap0

You can use the [rustls-mio](https://github.com/ctz/rustls/tree/main/rustls-mio) server example to test it as follows:

```
# In the rustls-mio folder
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout key.pem -out cert.pem -batch
cargo run --example tlsserver -- -p 12345 --certs cert.pem --key key.pem --protover 1.3 --tickets --verbose echo

# In this folder
RUST_LOG=trace cargo run
```
