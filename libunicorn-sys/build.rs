extern crate build_helper;
extern crate gcc;
extern crate os_type;
extern crate pkg_config;

use std::path::Path;
use std::process::Command;
use std::env;

use build_helper::rustc::{link_search, link_lib};

fn main() {
    if !build_helper::windows() {
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

    if build_helper::target::triple().env().unwrap_or("").contains("msvc") {
        let libpath = env::var("LIB").unwrap();
        env::set_var("LIB", libpath + ";" + &out_dir);
        
        let platform_toolset = match env::var("PLATFORMTOOLSET") {
            Ok(x) => format!("PlatformToolset={};", x),
            Err(_) => "".to_owned(),
        };

        let properties = "/p:OutDir=".to_owned() + &out_dir + "/;" + &platform_toolset
                         + "useenv=true;Configuration=Release";
        let status = match Command::new("msbuild")
                            .args(&["msvc/unicorn.sln", "/t:unicorn_static", &properties])
                            .current_dir("unicorn").status() {
            Ok(status) => status,
            Err(e) => fail(&format!("failed to execute command: {}", e)),
        };
        if !status.success() {
            fail(&format!("command did not execute successfully, got {}", status));
        }

        link_search(Some(build_helper::SearchKind::Native), build_helper::out_dir());
        link_lib(Some(build_helper::LibKind::Static), "unicorn_static");
    } else {
        // TODO(sduquette): the package build should fail if this command fails.
        let _ = Command::new("./make.sh").args(&make_args).current_dir("unicorn").status();

        let unicorn = "libunicorn.a";
        let _ = Command::new("cp").current_dir("unicorn").arg(&unicorn).arg(&out_dir).status();
        
        link_search(Some(build_helper::SearchKind::Native), build_helper::out_dir());
        link_lib(Some(build_helper::LibKind::Static), "unicorn");
    }
}

fn fail(s: &str) -> ! {
    panic!("\n{}\n\nbuild script failed, must exit now", s)
}
