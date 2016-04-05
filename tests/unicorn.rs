extern crate unicorn;

use unicorn::{Unicorn, uc_handle, uc_hook};

#[test]
fn emulate_x86() {
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EAX), Ok((123)));
   
    //let bytes : Vec<u8> = vec![0xAA, 0xBB];
    let X86_CODE32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    
    // attempt to write to memory before mapping it
    assert_eq!(emu.mem_write(0x1000, &X86_CODE32), (Err(unicorn::Error::WRITE_UNMAPPED))); 
    
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &X86_CODE32), Ok(())); 
    
    assert_eq!(emu.mem_read(0x1000, X86_CODE32.len()), Ok(X86_CODE32.clone()));  
    
    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX, 50), Ok(()));
    
    assert_eq!(emu.emu_start(0x1000, (0x1000 + X86_CODE32.len()) as u64, (10 * unicorn::SECOND_SCALE) as u64, 1000), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX), Ok((11)));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX), Ok((49)));
}

#[test]
fn emulate_amd64_negative_values() {
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
   
    //let bytes : Vec<u8> = vec![0xAA, 0xBB];
    let X86_CODE32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &X86_CODE32), Ok(())); 
    
    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX, -10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX, -50), Ok(()));
    
    assert_eq!(emu.emu_start(0x1000, (0x1000 + X86_CODE32.len()) as u64, (10 * unicorn::SECOND_SCALE) as u64, 1000), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX), Ok((-9)));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX), Ok((-51)));
}


#[test]
fn x86_callback() {
    // typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
    extern fn callback(engine : uc_handle, address : u64, size : u32, user_data : *mut u64) {
        println!("in callback!");
    }
    
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    let X86_CODE32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &X86_CODE32), Ok(()));
    
    let hook = emu.add_code_hook(unicorn::HookType::CODE, callback).expect("failed to add code hook");
    
    assert_eq!(emu.emu_start(0x1000, (0x1000 + X86_CODE32.len()) as u64, (10 * unicorn::SECOND_SCALE) as u64, 1000), Ok(()));
    assert_eq!(emu.hook_del(hook), Ok(()));

}

#[test]
fn mem_unmapping() {
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(())); 
}
