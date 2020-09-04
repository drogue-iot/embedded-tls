# Drogue-TLS

## What is it?

This is a fork/port of the `mbed-tls` set of crates that can generate with newer devependencies, and a newer `clang`. 
Additionally, it _only_ targets `no_std` environments, particularly ARM Cortex-M devices.
This should reduce the amount of configuration required in a `Cargo.toml` in order to use the crate.

## Requirements

### LLVM v10.x

```shell
$ llvm-config --version
10.0.1
```

## Usage

```toml

```
