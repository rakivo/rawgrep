use rustc_version::{version_meta, Channel};

fn main() {
    if matches!(version_meta().map(|v| v.channel), Ok(Channel::Nightly)) {
        println!("cargo:rustc-cfg=nightly");
    }

    if std::process::Command::new("mold")
        .arg("--version")
        .output()
        .is_ok()
    {
        println!("cargo:rustc-link-arg=-fuse-ld=mold");
    }
}
