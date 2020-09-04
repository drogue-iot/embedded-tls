
use cmake::Config;
use std::{
    env,
    path::PathBuf,
};

extern crate bindgen;
use bindgen::{
    EnumVariation,
    callbacks::{ParseCallbacks, EnumVariantValue}
};

#[derive(Debug)]
pub struct Callbacks{

}

impl ParseCallbacks for Callbacks {
    fn item_name(&self, original: &str) -> Option<String> {
        if original.starts_with( "MBEDTLS_") {
            Some( String::from(&original[8..original.len()]))
        } else if original.starts_with( "mbedtls_") {
            Some(String::from(&original[8..original.len()]))
        } else {
            None
        }
    }

    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        original: &str,
        _variant_value: EnumVariantValue
    ) -> Option<String> {
        if original.starts_with( "MBEDTLS_") {
            Some( String::from(&original[8..original.len()]))
        } else if original.starts_with( "mbedtls_") {
            Some(String::from(&original[8..original.len()]))
        } else {
            None
        }
    }
}

fn main() {
    let target = env::var("TARGET").unwrap();

    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let include_dir = PathBuf::from(&project_dir).join("include");

    let dst = Config::new("vendor/mbedtls-2.23.0/")
                     .very_verbose(true)
                     .always_configure(true)
                     .define("ENABLE_TESTING", "OFF")
                     .define("ENABLE_PROGRAMS", "OFF")
                     .cflag("--specs=nosys.specs")
                     .cflag(format!("-I{}", include_dir.display()))
                     .build();

    let search_dir = dst.parent().unwrap().join("out").join("build").join("library");
    //println!("cargo:rustc-link-search={}", _dst.parent().unwrap().display()); // the "-L" flag
    println!("cargo:rustc-link-search={}", search_dir.as_path().to_str().unwrap());

    //println!("cargo:rustc-link-lib=tls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=mbedtls");


    let callbacks = Callbacks{};

    let bindings = bindgen::Builder::default()
        .clang_arg("--verbose")
        .clang_arg("-I./vendor/mbedtls-2.23.0/include")
        .clang_arg("-I./include")
        .clang_arg( "-target" )
        .clang_arg( target )
        .header("src/wrapper.h")
        .ctypes_prefix("crate::types")
        .parse_callbacks( Box::new( callbacks ) )
        .derive_copy(true)
        .derive_default(true)
        .default_enum_style(EnumVariation::Rust{ non_exhaustive: false })
        //.blacklist_type("size_t")
        .size_t_is_usize(true)
        .prepend_enum_name(false)
        .use_core()
        //.raw_line("#![allow(non_camel_case_types)]")
        //.raw_line("#![allow(non_upper_case_globals)]")
        //.raw_line("#![allow(non_snake_case)]")
        //.raw_line("#![allow(dead_code)]")
        //.parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let _out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(PathBuf::from(&project_dir).join("src").join("bindings.rs"))
        .expect("Couldn't write bindings!");

   //bindings.write_to_file("src/bindings.rs")
        //.expect("Couldn't write bindings!");

}

