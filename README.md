# unicorn-rs
Rust bindings for the [unicorn](http://www.unicorn-engine.org/) CPU emulator.

```rust
extern crate unicorn;

use unicorn::{Cpu, CpuX86, uc_handle};

fn main() {
    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL); 
    emu.mem_write(0x1000, &x86_code32); 
    emu.reg_write_i32(unicorn::RegisterX86::ECX, -10);
    emu.reg_write_i32(unicorn::RegisterX86::EDX, -50);

    emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000);
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX), Ok((-9)));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX), Ok((-51)));
}
```

## Installation

This project has been tested on Linux. The bindings are built for the master version of the unicorn
git (currently at 1.0).

To use this package, first install the packages needed to build unicorn : gcc, make, git, python.

Then simply add it as dependency to the Cargo.toml of your program.

```
[dependencies]
unicorn = "0.4.0"
```

## Changelog

### 0.4.0

unicorn is now compiled as part of the build process of unicorn-rs.

### 0.3.0

The handling of callbacks has been modified, callbacks should be implemented using closures. See the
tests for examples.

- added support for interrupt, in/out and sysenter callbacks


## Contributing

Contributions to this project are super appreciated. Pull requests, bug reports, code review, tests,
documentation or feedback on your use of the bindings, nothing is too small. Don't hesitate to open
an issue if you have questions.

Contributors:

- Sébastien Duquette (@ekse)
- Israel Hallé (@isra17) for redesigning the callbacks API
- Richo Healey (@richo)
- petevine for reviewing the project and adding tests
- jschievink for his help with the API design
- m4b for the build.rs script
