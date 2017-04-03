extern crate gcc;
extern crate os_type;
extern crate pkg_config;

use std::path::Path;
use std::process::Command;
use std::env;

fn main() {
    if Command::new("pkg-config").output().is_ok()
        && pkg_config::Config::new().atleast_version("1.0.0").probe("unicorn").is_ok() {
        return;
    }

    if !Path::new("unicorn/.git").exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init", "--depth", "5"])
            .status();
    }
    let out_dir = env::var("OUT_DIR").unwrap();

    let make_args = match os_type::current_platform() {
        os_type::OSType::OSX => ["macos-universal-no"],
        _ => [""],
    };

    // TODO(sduquette): the package build should fail if this command fails.
    let _ = Command::new("./make.sh").args(&make_args).current_dir("unicorn").status();

    let unicorn = "libunicorn.a";
    let _ = Command::new("cp").current_dir("unicorn").arg(&unicorn).arg(&out_dir).status();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=unicorn");
}
