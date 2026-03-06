fn main() {
    // Export firmware version as build-time constant
    println!(
        "cargo:rustc-env=FIRMWARE_VERSION={}",
        env!("CARGO_PKG_VERSION")
    );
    println!("cargo:rustc-env=BUILD_DATE={}", chrono_lite_date());
}

fn chrono_lite_date() -> String {
    // Simple date from environment or fallback
    std::env::var("SOURCE_DATE_EPOCH")
        .map(|_| "reproducible".to_string())
        .unwrap_or_else(|_| "dev".to_string())
}
