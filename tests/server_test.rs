#![cfg(feature = "server")]

//! TLS 1.3 server compliance tests.
//!
//! All compliance tests use `openssl s_client` as the client.
//! Each test runs against BOTH the blocking and async server implementations
//! to ensure identical behavior.
//!
//! **Certificates:** Run `tests/data/gen_test_certs.sh` before testing.

use embedded_tls::*;
use rand::rngs::OsRng;
use rand_core::CryptoRngCore;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Once;

static LOG_INIT: Once = Once::new();
fn init_log() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

fn load_certs_der(path: &std::path::Path) -> Vec<Vec<u8>> {
    let f = std::fs::File::open(path).expect("cannot open cert file");
    rustls_pemfile::certs(&mut std::io::BufReader::new(f)).unwrap()
}

fn load_private_key_der(path: &std::path::Path) -> Vec<u8> {
    let f = std::fs::File::open(path).expect("cannot open key file");
    let mut r = std::io::BufReader::new(f);
    loop {
        match rustls_pemfile::read_one(&mut r).expect("cannot parse PEM key") {
            Some(rustls_pemfile::Item::ECKey(key)) => return key,
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return key,
            Some(rustls_pemfile::Item::RSAKey(key)) => return key,
            None => break,
            _ => {}
        }
    }
    panic!("no private key found");
}

fn listen_random() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

// ---------------------------------------------------------------------------
// Crypto provider
// ---------------------------------------------------------------------------

struct EcProvider {
    rng: OsRng,
    priv_key: Vec<u8>,
}

impl CryptoProvider for EcProvider {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;
    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }
    fn signer(
        &mut self,
    ) -> Result<(impl signature::SignerMut<Self::Signature>, SignatureScheme), TlsError> {
        use ecdsa::elliptic_curve::SecretKey;
        use p256::ecdsa::SigningKey;
        let sk =
            SecretKey::from_sec1_der(&self.priv_key).map_err(|_| TlsError::InvalidPrivateKey)?;
        Ok((SigningKey::from(&sk), SignatureScheme::EcdsaSecp256r1Sha256))
    }
}

fn provider() -> (Vec<Vec<u8>>, Vec<u8>) {
    (
        load_certs_der(&data_dir().join("chain-cert.pem")),
        load_private_key_der(&data_dir().join("im-server-key.pem")),
    )
}

// ---------------------------------------------------------------------------
// Server launchers — blocking and async, same interface
// ---------------------------------------------------------------------------

fn run_blocking_server(
    listener: TcpListener,
    config_fn: impl FnOnce(TlsServerConfig<'_>) -> TlsServerConfig<'_> + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let (certs, key) = provider();
    std::thread::spawn(move || {
        use embedded_io::Read as ER;
        use embedded_io::Write as EW;
        use embedded_io_adapters::std::FromStd;
        let (stream, _) = listener.accept().unwrap();
        let refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
        let cfg = config_fn(TlsServerConfig::new(&refs));
        let ctx = TlsServerContext::new(
            &cfg,
            EcProvider {
                rng: OsRng,
                priv_key: key,
            },
        );
        let mut rb = [0u8; 16384];
        let mut wb = [0u8; 16384];
        let mut tls: blocking::TlsConnection<FromStd<TcpStream>, Aes128GcmSha256> =
            blocking::TlsConnection::new(FromStd::new(stream), &mut rb, &mut wb);
        tls.open_server(ctx).expect("blocking handshake failed");
        let mut rx = [0u8; 4096];
        let n = ER::read(&mut tls, &mut rx).expect("blocking read failed");
        EW::write(&mut tls, &rx[..n]).expect("blocking write failed");
        EW::flush(&mut tls).expect("blocking flush failed");
        let _ = tls.close();
    })
}

fn run_async_server(
    listener: TcpListener,
    config_fn: impl FnOnce(TlsServerConfig<'_>) -> TlsServerConfig<'_> + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let (certs, key) = provider();
    std::thread::spawn(move || {
        use embedded_io_adapters::tokio_1::FromTokio;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (std_stream, _) = listener.accept().unwrap();
            std_stream.set_nonblocking(true).unwrap();
            let stream = tokio::net::TcpStream::from_std(std_stream).unwrap();
            let refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
            let cfg = config_fn(TlsServerConfig::new(&refs));
            let ctx = TlsServerContext::new(
                &cfg,
                EcProvider {
                    rng: OsRng,
                    priv_key: key,
                },
            );
            let mut rb = [0u8; 16384];
            let mut wb = [0u8; 16384];
            let mut tls: TlsConnection<FromTokio<tokio::net::TcpStream>, Aes128GcmSha256> =
                TlsConnection::new(FromTokio::new(stream), &mut rb, &mut wb);
            tls.open_server(ctx).await.expect("async handshake failed");
            let mut rx = [0u8; 4096];
            let n = tls.read(&mut rx).await.expect("async read failed");
            tls.write(&rx[..n]).await.expect("async write failed");
            embedded_io_async::Write::flush(&mut tls)
                .await
                .expect("async flush failed");
            let _ = tls.close().await;
        });
    })
}

// ---------------------------------------------------------------------------
// OpenSSL helpers
// ---------------------------------------------------------------------------

/// Run openssl s_client, send msg, read echo. No sleeps — openssl buffers
/// stdin until the handshake completes, and the reader blocks until data arrives.
fn openssl_echo(addr: SocketAddr, extra_args: &[&str], msg: &[u8]) -> (bool, Vec<u8>, String) {
    let ca = data_dir().join("ca-cert.pem").to_str().unwrap().to_string();
    let conn = format!("127.0.0.1:{}", addr.port());
    let mut args: Vec<String> = vec![
        "s_client".into(),
        "-connect".into(),
        conn,
        "-CAfile".into(),
        ca,
        "-tls1_3".into(),
        "-verify_return_error".into(),
        "-quiet".into(),
    ];
    for a in extra_args {
        args.push(a.to_string());
    }

    let mut child = Command::new("openssl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl failed to start");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Write immediately — openssl buffers until handshake completes
    let _ = stdin.write_all(msg);
    let _ = stdin.flush();

    // Read echo — blocks until server sends data back
    let expect = msg.len();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 16384];
        let mut out = Vec::new();
        let mut r = BufReader::new(stdout);
        loop {
            let n = r.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            if out.len() >= expect {
                break;
            }
        }
        out
    });

    // Close stdin after reader is done (triggers openssl shutdown)
    let resp = reader.join().unwrap();
    drop(stdin);

    let mut se = String::new();
    BufReader::new(stderr).read_to_string(&mut se).ok();
    let status = child.wait().unwrap();
    (status.success(), resp, se)
}

/// Run openssl s_client, send a byte to trigger the handshake, return status.
/// Works for both positive and negative tests — the handshake either succeeds
/// or fails, and openssl exits either way.
fn openssl_connect(addr: SocketAddr, ca: &str, extra_args: &[&str]) -> (bool, String) {
    let conn = format!("127.0.0.1:{}", addr.port());
    let mut args: Vec<String> = vec![
        "s_client".into(),
        "-connect".into(),
        conn,
        "-CAfile".into(),
        ca.to_string(),
        "-tls1_3".into(),
        "-verify_return_error".into(),
        "-quiet".into(),
    ];
    for a in extra_args {
        args.push(a.to_string());
    }
    let mut child = Command::new("openssl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl failed to start");
    // Send a byte then close — triggers handshake, then openssl sends data and reads echo or fails
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let se = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), se)
}

// ---------------------------------------------------------------------------
// Test runner: runs the same test against both blocking and async servers
// ---------------------------------------------------------------------------

/// Run a test function against both blocking and async servers.
/// If `expect_server_ok` is true, panics if the server thread panics.
fn test_both_inner(
    config_fn: impl FnOnce(TlsServerConfig<'_>) -> TlsServerConfig<'_> + Send + Clone + 'static,
    client_fn: impl Fn(SocketAddr),
    expect_server_ok: bool,
) {
    for mode in ["blocking", "async"] {
        let (l, a) = listen_random();
        let s = if mode == "blocking" {
            run_blocking_server(l, config_fn.clone())
        } else {
            run_async_server(l, config_fn.clone())
        };
        client_fn(a);
        if expect_server_ok {
            s.join()
                .unwrap_or_else(|_| panic!("{mode} server panicked"));
        } else {
            s.join().ok();
        }
    }
}

/// Run a test against both servers, expecting success.
fn test_both(
    config_fn: impl FnOnce(TlsServerConfig<'_>) -> TlsServerConfig<'_> + Send + Clone + 'static,
    client_fn: impl Fn(SocketAddr),
) {
    test_both_inner(config_fn, client_fn, true);
}

/// Run a test against both servers, server may fail (negative tests).
fn test_both_server_may_fail(
    config_fn: impl FnOnce(TlsServerConfig<'_>) -> TlsServerConfig<'_> + Send + Clone + 'static,
    client_fn: impl Fn(SocketAddr),
) {
    test_both_inner(config_fn, client_fn, false);
}

// ===========================================================================
// Tests — each runs against both blocking and async
// ===========================================================================

#[test]
fn test_handshake_and_echo() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(
                addr,
                &["-ciphersuites", "TLS_AES_128_GCM_SHA256"],
                b"hello\n",
            );
            assert!(ok, "failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("hello"), "no echo");
        },
    );
}

#[test]
fn test_protocol_and_cipher() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, _resp, se) = openssl_echo(
                addr,
                &["-ciphersuites", "TLS_AES_128_GCM_SHA256"],
                b"cipher check\n",
            );
            assert!(ok, "failed.\nstderr: {se}");
            // -quiet still shows verify info on stderr
            assert!(
                se.contains("TLSv1.3") || se.contains("verify return:1"),
                "no verification in:\n{se}"
            );
        },
    );
}

#[test]
fn test_wrong_ca_rejected() {
    init_log();
    let wrong_ca = data_dir()
        .join("rsa-ca-cert.pem")
        .to_str()
        .unwrap()
        .to_string();
    test_both_server_may_fail(
        |c| c,
        |addr| {
            let (ok, _) = openssl_connect(addr, &wrong_ca, &[]);
            assert!(!ok, "should reject wrong CA");
        },
    );
}

#[test]
fn test_large_payload() {
    init_log();
    // Large payload needs custom server that reads in a loop
    for mode in ["blocking", "async"] {
        let (l, a) = listen_random();
        let (certs, key) = provider();

        let s = if mode == "blocking" {
            std::thread::spawn(move || {
                use embedded_io::Read as ER;
                use embedded_io::Write as EW;
                use embedded_io_adapters::std::FromStd;
                let (stream, _) = l.accept().unwrap();
                let refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
                let cfg = TlsServerConfig::new(&refs);
                let ctx = TlsServerContext::new(
                    &cfg,
                    EcProvider {
                        rng: OsRng,
                        priv_key: key,
                    },
                );
                let mut rb = [0u8; 16384];
                let mut wb = [0u8; 16384];
                let mut tls: blocking::TlsConnection<FromStd<TcpStream>, Aes128GcmSha256> =
                    blocking::TlsConnection::new(FromStd::new(stream), &mut rb, &mut wb);
                tls.open_server(ctx).expect("handshake failed");
                let mut all = Vec::new();
                let mut buf = [0u8; 4096];
                while all.len() < 8000 {
                    match ER::read(&mut tls, &mut buf) {
                        Ok(0) => break,
                        Ok(n) => all.extend_from_slice(&buf[..n]),
                        Err(e) => panic!("read: {e:?}"),
                    }
                }
                let mut w = 0;
                while w < all.len() {
                    w += EW::write(&mut tls, &all[w..]).unwrap();
                }
                EW::flush(&mut tls).unwrap();
                let _ = tls.close();
            })
        } else {
            std::thread::spawn(move || {
                use embedded_io_adapters::tokio_1::FromTokio;
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let (ss, _) = l.accept().unwrap();
                    ss.set_nonblocking(true).unwrap();
                    let stream = tokio::net::TcpStream::from_std(ss).unwrap();
                    let refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
                    let cfg = TlsServerConfig::new(&refs);
                    let ctx = TlsServerContext::new(
                        &cfg,
                        EcProvider {
                            rng: OsRng,
                            priv_key: key,
                        },
                    );
                    let mut rb = [0u8; 16384];
                    let mut wb = [0u8; 16384];
                    let mut tls: TlsConnection<FromTokio<tokio::net::TcpStream>, Aes128GcmSha256> =
                        TlsConnection::new(FromTokio::new(stream), &mut rb, &mut wb);
                    tls.open_server(ctx).await.expect("handshake failed");
                    let mut all = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = tls.read(&mut buf).await.expect("read failed");
                        if n == 0 {
                            break;
                        }
                        all.extend_from_slice(&buf[..n]);
                        if all.len() >= 8000 {
                            break;
                        }
                    }
                    let mut w = 0;
                    while w < all.len() {
                        w += tls.write(&all[w..]).await.unwrap();
                    }
                    embedded_io_async::Write::flush(&mut tls).await.unwrap();
                    let _ = tls.close().await;
                });
            })
        };

        let payload = vec![b'A'; 8000];
        let (ok, resp, se) = openssl_echo(a, &[], &payload);
        assert!(ok, "{mode} large payload failed.\nstderr: {se}");
        assert_eq!(payload.len(), resp.len(), "{mode} length mismatch");
        assert_eq!(payload, resp, "{mode} data mismatch");
        s.join().ok();
    }
}

#[test]
fn test_hrr() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            // Default groups → X25519 first → server accepts directly (or HRR if x25519 disabled)
            let (ok, resp, se) =
                openssl_echo(addr, &["-ciphersuites", "TLS_AES_128_GCM_SHA256"], b"hrr\n");
            assert!(ok, "HRR failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("hrr"));
        },
    );
}

#[test]
fn test_x25519_direct() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(
                addr,
                &[
                    "-ciphersuites",
                    "TLS_AES_128_GCM_SHA256",
                    "-groups",
                    "X25519",
                ],
                b"x25519\n",
            );
            assert!(ok, "X25519 failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("x25519"));
        },
    );
}

#[test]
fn test_default_openssl_no_flags() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(addr, &[], b"default\n");
            assert!(ok, "default failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("default"));
        },
    );
}

#[test]
fn test_client_cert_auth() {
    init_log();
    let cert = data_dir()
        .join("client-cert.pem")
        .to_str()
        .unwrap()
        .to_string();
    let key = data_dir()
        .join("client-key.pem")
        .to_str()
        .unwrap()
        .to_string();
    test_both(
        |c| c.with_client_auth(),
        move |addr| {
            let (ok, resp, se) = openssl_echo(addr, &["-cert", &cert, "-key", &key], b"mtls\n");
            assert!(ok, "mTLS failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("mtls"));
        },
    );
}

#[test]
fn test_client_no_cert() {
    init_log();
    test_both_server_may_fail(
        |c| c.with_client_auth(),
        |addr| {
            // No -cert → empty cert message
            let (ok, _resp, se) = openssl_echo(addr, &[], b"no cert\n");
            log::info!("no-cert: ok={ok}, stderr={se}");
        },
    );
}

#[test]
fn test_alpn() {
    init_log();
    test_both(
        |c| c.with_alpn(&[b"h2", b"http/1.1"]),
        |addr| {
            let (ok, resp, se) = openssl_echo(addr, &["-alpn", "h2,http/1.1"], b"alpn test\n");
            assert!(ok, "ALPN failed.\nstderr: {se}");
            assert!(
                String::from_utf8_lossy(&resp).contains("alpn test"),
                "no echo"
            );
        },
    );
}

#[test]
fn test_close_notify() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(
                addr,
                &["-ciphersuites", "TLS_AES_128_GCM_SHA256"],
                b"close\n",
            );
            assert!(ok, "should exit cleanly.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("close"));
            assert!(
                !se.contains("unexpected eof"),
                "missing close_notify.\nstderr: {se}"
            );
        },
    );
}

/// P-256 explicit.
#[test]
fn test_p256_direct() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(addr, &["-groups", "P-256"], b"p256\n");
            assert!(ok, "P-256 failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("p256"));
        },
    );
}

/// Multiple groups offered — server picks the best.
#[test]
fn test_multiple_groups() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(addr, &["-groups", "X25519:P-256"], b"multi\n");
            assert!(ok, "multi groups failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("multi"));
        },
    );
}

/// ALPN mismatch — client offers protocols the server doesn't support.
#[test]
fn test_alpn_mismatch() {
    init_log();
    test_both(
        |c| c.with_alpn(&[b"mqtt"]),
        |addr| {
            // Client offers grpc, server only has mqtt — no match, but handshake succeeds
            let (ok, resp, _se) = openssl_echo(addr, &["-alpn", "grpc"], b"mismatch\n");
            assert!(ok, "handshake should still succeed");
            assert!(String::from_utf8_lossy(&resp).contains("mismatch"));
        },
    );
}

/// RFC 8446 Section 9.3: server MUST ignore unrecognized cipher suites,
/// extensions, and other parameters. Unknown named groups in the
/// SupportedGroups extension must be skipped, not rejected (fixes #163).
#[test]
fn test_unknown_named_groups_ignored() {
    init_log();
    // ffdhe2048 is a valid TLS 1.3 group but our server doesn't support it.
    // Server must ignore it and negotiate P-256 from the same list.
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) =
                openssl_echo(addr, &["-groups", "ffdhe2048:P-256"], b"unknown groups\n");
            assert!(
                ok,
                "should ignore unknown group and use P-256.\nstderr: {se}"
            );
            assert!(String::from_utf8_lossy(&resp).contains("unknown groups"));
        },
    );
}

/// RFC 8446 Section 4.1.4: HelloRetryRequest. When the client's key_share
/// contains no groups the server supports, the server sends HRR with the
/// selected group. The client retries with that group.
/// Also validates RFC 8446 Section 4.2.8: KeyShareHelloRetryRequest contains
/// only the selected_group (2 bytes), not a full KeyShareEntry.
#[test]
fn test_hrr_unsupported_group_only() {
    init_log();
    // P-384 only — server doesn't support it, must HRR for P-256
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(addr, &["-groups", "P-384:P-256"], b"hrr p384\n");
            assert!(ok, "HRR with P-384 fallback failed.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("hrr p384"));
        },
    );
}

/// Chain verification depth=2 — validates the full CA → intermediate → leaf chain.
#[test]
fn test_verify_depth() {
    init_log();
    test_both(
        |c| c,
        |addr| {
            let (ok, resp, se) = openssl_echo(addr, &["-verify", "2"], b"depth2\n");
            assert!(ok, "depth=2 should pass.\nstderr: {se}");
            assert!(String::from_utf8_lossy(&resp).contains("depth2"));
        },
    );
}

/// Run openssl s_client without forcing TLS 1.3, so the ClientHello can be
/// made deliberately unacceptable to the server.
fn openssl_connect_no_tls13(addr: SocketAddr, extra_args: &[&str]) -> (bool, String) {
    let ca = data_dir().join("ca-cert.pem").to_str().unwrap().to_string();
    let conn = format!("127.0.0.1:{}", addr.port());
    let mut args: Vec<String> = vec![
        "s_client".into(),
        "-connect".into(),
        conn,
        "-CAfile".into(),
        ca,
        "-quiet".into(),
    ];
    for a in extra_args {
        args.push(a.to_string());
    }
    let mut child = Command::new("openssl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl failed to start");
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let se = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), se)
}

#[test]
fn test_alert_sent_when_client_hello_is_unacceptable() {
    init_log();
    let (l, a) = listen_random();
    let s = run_blocking_server(l, |c| c);

    // TLS 1.2-only client: the server cannot proceed and must say so with an
    // alert rather than dropping the connection.
    let (ok, stderr) = openssl_connect_no_tls13(a, &["-tls1_2"]);

    const EXPECTED_HANDSHAKE_OK: bool = false;
    assert_eq!(ok, EXPECTED_HANDSHAKE_OK);
    assert!(
        stderr.contains("alert"),
        "expected a TLS alert from the server, got: {stderr}"
    );
    s.join().ok();
}
