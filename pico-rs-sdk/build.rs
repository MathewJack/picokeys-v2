fn main() {
    println!("cargo:rustc-env=SDK_VERSION={}", env!("CARGO_PKG_VERSION"));
}
