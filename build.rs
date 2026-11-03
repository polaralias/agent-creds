fn main() {
    println!("cargo:rerun-if-changed=VERSION");
    let version = std::fs::read_to_string("VERSION").expect("VERSION must be present");
    assert_eq!(
        version.trim(),
        std::env::var("CARGO_PKG_VERSION").expect("Cargo package version must be set"),
        "VERSION and Cargo.toml differ; run python scripts/version.py --set X.Y.Z"
    );
}
