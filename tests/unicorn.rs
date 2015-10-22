extern crate unicorn;

use unicorn::Unicorn;

const kOneSecond : usize = 1000000;

#[test]
fn emulate_x86() {
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX as u64, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EAX as u64), Ok((123)));
   
    //let bytes : Vec<u8> = vec![0xAA, 0xBB];
    let X86_CODE32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
    
    // attempt to write to memory before mapping it
    assert_eq!(emu.mem_write(0x1000, &X86_CODE32), (Err(unicorn::Error::WRITE_UNMAPPED))); 
    
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    assert_eq!(emu.mem_write(0x1000, &X86_CODE32), Ok(())); 
    
    assert_eq!(emu.mem_read(0x1000, X86_CODE32.len()), Ok(X86_CODE32.clone()));  
    
    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX as u64, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX as u64, 50), Ok(()));
    
    assert_eq!(emu.emu_start(0x1000, (0x1000 + X86_CODE32.len()) as u64, (10 * kOneSecond) as u64, 1000), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX as u64), Ok((11)));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX as u64), Ok((49)));


}

#[test]
#[ignore]
fn mem_unmapping_crash() {
    let emu = Unicorn::new(unicorn::Arch::X86, unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(())); 
    // TODO: this is crashing, test further
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(())); 
}
