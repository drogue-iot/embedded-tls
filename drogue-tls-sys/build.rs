
use cmake::Config;


fn main() {
  let _dst = Config::new("vendor/mbedtls-2.23.0/")
                   .very_verbose(true)
                   .always_configure(true)
                   .define("ENABLE_TESTING", "OFF")
                   .define("ENABLE_PROGRAMS", "OFF")
                   .cflag("--specs=nosys.specs")
                   .build();
}

