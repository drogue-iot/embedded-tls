use cmake::Config;

use std::{env, path::PathBuf};

#[cfg(feature = "bindgen")]
extern crate bindgen;

#[cfg(feature = "bindgen")]
use bindgen::{
    callbacks::{EnumVariantValue, ParseCallbacks},
    EnumVariation,
};

#[cfg(feature = "bindgen")]
#[derive(Debug)]
pub struct Callbacks {}

#[cfg(feature = "bindgen")]
impl ParseCallbacks for Callbacks {
    fn item_name(&self, original: &str) -> Option<String> {
        if original.starts_with("MBEDTLS_") || original.starts_with("mbedtls_") {
            Some(String::from(&original[8..original.len()]))
        } else {
            None
        }
    }

    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        original: &str,
        _variant_value: EnumVariantValue,
    ) -> Option<String> {
        if original.starts_with("MBEDTLS_") || original.starts_with("mbedtls_") {
            Some(String::from(&original[8..original.len()]))
        } else {
            None
        }
    }
}

fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let include_dir = PathBuf::from(&project_dir).join("include");

    let dst = Config::new("vendor/mbedtls/")
        //.very_verbose(true)
        .always_configure(true)
        .define("ENABLE_TESTING", "OFF")
        .define("ENABLE_PROGRAMS", "OFF")
        .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
        .cflag("-DMBEDTLS_CONFIG_FILE=\\\"drogue_config.h\\\"")
        .cflag(format!("-I{}", include_dir.display()))
        .build();

    let search_dir = dst
        .parent()
        .unwrap()
        .join("out")
        .join("build")
        .join("library");
    //println!("cargo:rustc-link-search={}", _dst.parent().unwrap().display()); // the "-L" flag
    println!(
        "cargo:rustc-link-search={}",
        search_dir.as_path().to_str().unwrap()
    );

    //println!("cargo:rustc-link-lib=tls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=mbedtls");

    #[cfg(feature = "bindgen")]
    do_bindgen();
}

#[cfg(feature = "bindgen")]
fn do_bindgen() {
    let callbacks = Callbacks {};

    let bindings = bindgen::Builder::default()
        .clang_arg("--verbose")
        .clang_arg("-DMBEDTLS_CONFIG_FILE=\"drogue_config.h\"")
        .clang_arg("-I./include")
        .clang_arg("-I./vendor/mbedtls/include")
        .clang_arg("-target")
        .clang_arg(target)
        .header("src/wrapper.h")
        .ctypes_prefix("crate::types")
        .parse_callbacks(Box::new(callbacks))
        .derive_copy(true)
        .derive_default(true)
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
        .blacklist_item("__va_list")
        .size_t_is_usize(true)
        .prepend_enum_name(false)
        .use_core()
        .raw_line("use drogue_ffi_compat::va_list as __va_list;")
        .generate()
        .expect("Unable to generate bindings");

    let _out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(PathBuf::from(&project_dir).join("src").join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
