use std::env;
use cmake::Config;

fn main() {
    let profile = env::var("PROFILE").unwrap();
    let cmake_build_type = if profile == "debug" { "Debug" } else { "Release" };

    println!("cargo:rerun-if-changed=CMakeLists.txt");
    println!("cargo:rerun-if-changed=src/liblief.cpp");
    println!("cargo:rerun-if-changed=build.rs");

    let install_dir = Config::new(".")
        .define("BUILD_SHARED_LIBS", "OFF")
        .static_crt(false)
        .no_build_target(true)
        .build();

    // main LIEF library
    let lief_lib_path = install_dir.join("build").join("LIEF").join("lib");
    println!("cargo:rustc-link-search=native={}", lief_lib_path.to_str().unwrap());
    println!("cargo:rustc-link-lib=static=LIEF");

    // lief-sys library
    let mut lib_path = install_dir.join("build").join("lib");

    if cfg!(windows) {
        lib_path = lib_path.join(cmake_build_type);
    }

    println!("cargo:rustc-link-search=native={}", lib_path.to_str().unwrap());
    println!("cargo:rustc-link-lib=static=lief-sys");

    println!("cargo:root={}", install_dir.to_str().unwrap());
}
