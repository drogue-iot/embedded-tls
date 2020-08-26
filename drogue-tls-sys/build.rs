
use cmake::Config;

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").unwrap();

    let _dst = Config::new("vendor/mbedtls-2.23.0/")
                     .very_verbose(true)
                     .always_configure(true)
                     .define("ENABLE_TESTING", "OFF")
                     .define("ENABLE_PROGRAMS", "OFF")
                     .cflag("--specs=nosys.specs")
                     .build();

    println!("cargo:rustc-link-lib=tls");
    println!("cargo:rustc-link-lib=x509");
    println!("cargo:rustc-link-lib=crypto");

    let bindings = bindgen::Builder::default()
        .clang_arg("-I./vendor/mbedtls-2.23.0/include")
        .clang_arg( "-target" )
        .clang_arg( target )
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

   let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
   bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

}

