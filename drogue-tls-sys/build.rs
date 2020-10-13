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

fn has_feature(feature: &str) -> bool {
    let feature = feature.to_uppercase().replace('-', "_");
    let feature = format!("CARGO_FEATURE_{}", feature);
    env::var_os(feature).is_some()
}

enum CustomBufferSize {
    Size1k,
    Size2k,
    Size4k,
    Size8k,
    Size16k,
}

impl CustomBufferSize {
    fn as_num(&self) -> usize {
        match self {
            CustomBufferSize::Size1k => 1024,
            CustomBufferSize::Size2k => 2 * 1024,
            CustomBufferSize::Size4k => 4 * 1024,
            CustomBufferSize::Size8k => 8 * 1024,
            CustomBufferSize::Size16k => 16 * 1024,
        }
    }
}

fn buffer_size(direction: &str) -> Option<CustomBufferSize> {
    match (
        has_feature(&format!("{}_buffer_1k", direction)),
        has_feature(&format!("{}_buffer_2k", direction)),
        has_feature(&format!("{}_buffer_4k", direction)),
        has_feature(&format!("{}_buffer_8k", direction)),
        has_feature(&format!("{}_buffer_16k", direction)),
    ) {
        (true, false, false, false, false) => Some(CustomBufferSize::Size1k),
        (false, true, false, false, false) => Some(CustomBufferSize::Size2k),
        (false, false, true, false, false) => Some(CustomBufferSize::Size4k),
        (false, false, false, true, false) => Some(CustomBufferSize::Size8k),
        (false, false, false, false, true) => Some(CustomBufferSize::Size16k),
        (false, false, false, false, false) => None,
        _ => panic!(
            "More than one buffer size selected for the direction '{}'. You must not select more than one buffer size.",
            direction
        ),
    }
}

fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let include_dir = PathBuf::from(&project_dir).join("include");

    let mut config = Config::new("vendor/mbedtls/");

    config
        //.very_verbose(true)
        .always_configure(true)
        .define("ENABLE_TESTING", "OFF")
        .define("ENABLE_PROGRAMS", "OFF")
        .define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY")
        .cflag("-DMBEDTLS_CONFIG_FILE=\\\"drogue_config.h\\\"")
        .cflag(format!("-I{}", include_dir.display()));

    if has_feature("fewer-tables") {
        config.cflag("-DMBEDTLS_AES_FEWER_TABLES");
    }
    if let Some(size) = buffer_size("in") {
        config.cflag(format!("-DMBEDTLS_SSL_IN_CONTENT_LEN={}", size.as_num()));
    }
    if let Some(size) = buffer_size("out") {
        config.cflag(format!("-DMBEDTLS_SSL_OUT_CONTENT_LEN={}", size.as_num()));
    }

    let dst = config.build();

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
