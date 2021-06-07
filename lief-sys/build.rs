use cmake::Config;

fn main() {
    println!("cargo:rerun-if-changed=CMakeLists.txt");
    println!("cargo:rerun-if-changed=src/liblief.cpp");
    println!("cargo:rerun-if-changed=build.rs");

    let install_dir = Config::new(".")
        .define("BUILD_SHARED_LIBS", "OFF")
        .static_crt(false)
        .no_build_target(true)
        .build();

    let lib_path = install_dir.join("build");

    if cfg!(windows) {
        let _build_dir_postfix = if cfg!(debug_assertions) {
            "Debug"
        } else {
            "Release"
        };

        println!(
            "cargo:rustc-link-search=native={}/{}",
            lib_path.to_str().unwrap(),
            _build_dir_postfix
        );
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            lib_path.to_str().unwrap(),
        );
    }

    println!("cargo:rustc-link-lib=static=LIEF_SYS");
    println!("cargo:root={}", install_dir.to_str().unwrap());
}
