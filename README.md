# Drogue-TLS

## What is it?

A heapless/no_std version of mbedTLS for embedded environments, particularly ARM Cortex-M devices.
This should reduce the amount of configuration required in a `Cargo.toml` in order to use the crate.

## Usage

Set up the `SslPlatform` during board initialization by providing some heap-ish memory, configuring an entropy source and seeding the RNG.

```rust
let mut ssl_platform = SslPlatform::setup(
    cortex_m_rt::heap_start() as usize,
    1024 * 64).unwrap();

ssl_platform.entropy_context_mut().add_source(StaticEntropySource);

ssl_platform.seed_rng().unwrap();

```

When you're ready to use it, you can borrow an underlying network stack to create a secure network stack:

```rust
let mut ssl_config = ssl_platform.new_client_config(Transport::Stream, Preset::Default).unwrap();
ssl_config.authmode(Verify::None);

// consume the config, take a non-mutable ref to the underlying network.
let secure_network = SslTcpStack::new(ssl_config, &network);
```

And then use it as one does:

```rust
let socket = secure_network.open(Mode::Blocking).unwrap();
let socket_addr = SocketAddr::new(
    IpAddr::from_str("192.168.1.220").unwrap(),
    443,
);

let mut socket = secure_network.connect(socket, socket_addr).unwrap();

let result = secure_network.write(&mut socket, b"GET / HTTP/1.1\r\nhost:192.168.1.220\r\n\r\n").unwrap();

```

## Development

Clang 10 is required to re-generate the bindings.  This is not done during a normal build due to the Cargo [`host_dep` issue](https://github.com/rust-lang/cargo/issues/7915).

```shell
cargo build --features=generate
```

### Fedora

You will need to install:

~~~shell
sudo dnf install clang lld
~~~

When you build, use:

~~~
env CC=/usr/bin/clang cargo embed --release 
~~~
