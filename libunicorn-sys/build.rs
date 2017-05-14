extern crate gcc;
extern crate os_type;
extern crate pkg_config;

use std::path::Path;
use std::process::Command;
use std::env;
use std::io::ErrorKind;
use std::fs;

fn main() {
    let target = env::var("TARGET").unwrap();
    let windows = target.contains("windows");

    if !target.contains("windows") {
        if Command::new("pkg-config").output().is_ok()
            && pkg_config::Config::new().atleast_version("1.0.0").probe("unicorn").is_ok() {
            return;
        }
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
    if !target.contains("msvc") {
        let _ = Command::new("./make.sh").args(&make_args).current_dir("unicorn").status();

        let unicorn = "libunicorn.a";
        let _ = Command::new("cp").current_dir("unicorn").arg(&unicorn).arg(&out_dir).status();
        
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=unicorn");
    } else {
        let libpath = env::var("LIB").unwrap();
        env::set_var("LIB", libpath + ";" + &out_dir);
        
        let platformToolSet = match env::var("PLATFORMTOOLSET") {
            Ok(x) => format!("PlatformToolset={};", x),
            Err(_) => "".to_owned(),
        };

        let properties = "/p:OutDir=".to_owned() + &out_dir + "/;" + &platformToolSet + "useenv=true;Configuration=Release";
        let status = match Command::new("msbuild")
                            .args(&["msvc/unicorn.sln", &properties])
                            .current_dir("unicorn").status() {
            Ok(status) => status,
            Err(e) => fail(&format!("failed to execute command: {}", e)),
        };
        if !status.success() {
            fail(&format!("command did not execute successfully, got {}", status));
        }

        println!("cargo:rustc-link-search=native={}", &out_dir);
        println!("cargo:rustc-link-lib=static=unicorn_static");
    }    
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s)
}
