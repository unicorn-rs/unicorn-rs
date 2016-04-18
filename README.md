# unicorn-rs
Rust bindings for the [unicorn](http://www.unicorn-engine.org/) CPU emulator.

```rust
extern crate unicorn;

use unicorn::{Unicorn, uc_handle};

fn main() {
    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL); 
    emu.mem_write(0x1000, &x86_code32); 
    emu.reg_write_i32(unicorn::RegisterX86::ECX as i32, -10);
    emu.reg_write_i32(unicorn::RegisterX86::EDX as i32, -50);

    emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000);
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX as i32), Ok((-9)));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX as i32), Ok((-51)));
}
```

## Installation

This project has been tested on Linux. The bindings are built for the master version of the unicorn
git (currently at 1.0).

To test this project, follow these steps :

1. Clone unicorn from git with `git clone https://github.com/unicorn-engine/unicorn`.
2. Build and install normally with `make.sh` and `make.sh install`. 
2. Clone this project, `cd unicorn-rs` and `cargo build`.
3. `cargo test` to make sure it works as expected.

To use this package simply add it as dependency to the Cargo.toml of your program.

```
[dependencies]
unicorn = "0.1.0"
```

## Notes

The bindings do not currently support callbacks for tracing interrupts and IN/OUT instructions for x86. Please create
an issue (or a pull request) if this something you would like to be added.

## Contributing

Contributions to this project are super appreciated. Pull requests, bug reports, code review, tests, documentation or feedback on your use of the bindings, nothing is too small. Don't hesitate to open an issue if you have questions.

Contributors :

- Sébastien Duquette (@ekse)
- Richo Healey (@richo)
