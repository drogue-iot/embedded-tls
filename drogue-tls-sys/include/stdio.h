/*
 * Can be added in order to debug internally in mbedtls. In this case you also need to change (src/ssl/config.rs):
 *
 * ~~~rust
 * #[no_mangle]
 * pub unsafe extern "C" fn debug(
 * ~~~
 */
// extern int snprintf(char *, unsigned int, const char *, ...);