extern crate unicorn;

use unicorn::{Unicorn, uc_handle};

#[test]
fn emulate_x86() {
    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX as i32, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EAX as i32), Ok((123)));
    
    // Attempt to write to memory before mapping it.
    assert_eq!(emu.mem_write(0x1000, &x86_code32), (Err(unicorn::Error::WRITE_UNMAPPED))); 
    
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(())); 
    assert_eq!(emu.mem_read(0x1000, x86_code32.len()), Ok(x86_code32.clone()));  
    
    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX as i32, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX as i32, 50), Ok(()));
    
    assert_eq!(emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX as i32), Ok((11)));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX as i32), Ok((49)));
}

#[test]
fn emulate_amd64_negative_values() {
    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(())); 
    
    assert_eq!(emu.reg_write_i32(unicorn::RegisterX86::ECX as i32, -10), Ok(()));
    assert_eq!(emu.reg_write_i32(unicorn::RegisterX86::EDX as i32, -50), Ok(()));
    
    assert_eq!(emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000), Ok(()));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX as i32), Ok((-9)));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX as i32), Ok((-51)));
}


#[test]
fn x86_callback() {
    #[allow(unused_variables)]
    extern fn callback(engine : uc_handle, address : u64, size : u32, user_data : *mut u64) {
        println!("in callback at 0x{:08x}!", address);
    }
    
    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    
    let hook = emu.add_code_hook(unicorn::HookType::BLOCK, 0x1000, 0x2000, callback).expect("failed to add code hook");
    assert_eq!(emu.emu_start(0x1000, 0x1001, 10 * unicorn::SECOND_SCALE, 1000), Ok(()));
    assert_eq!(emu.hook_del(hook), Ok(()));

}

#[test] 
fn emulate_mips() {
    let mips_code32 = vec![0x56, 0x34, 0x21, 0x34]; // ori $at, $at, 0x3456;
    
    let emu = Unicorn::new(unicorn::Arch::MIPS, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &mips_code32), Ok(())); 
    assert_eq!(emu.mem_read(0x1000, mips_code32.len()), Ok(mips_code32.clone()));  
    assert_eq!(emu.reg_write(unicorn::RegisterMIPS::AT as i32, 0), Ok(()));
    assert_eq!(emu.emu_start(0x1000, (0x1000 + mips_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterMIPS::AT as i32), Ok((0x3456)));
}

#[test]
fn mem_unmapping() {
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(())); 
}
