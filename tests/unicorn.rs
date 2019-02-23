extern crate unicorn;

use std::cell::RefCell;
use std::rc::Rc;
use unicorn::{Cpu, CpuARM, CpuMIPS, CpuX86};

pub static X86_REGISTERS: [unicorn::RegisterX86; 145] = [
    unicorn::RegisterX86::AH,
    unicorn::RegisterX86::AL,
    unicorn::RegisterX86::AX,
    unicorn::RegisterX86::BH,
    unicorn::RegisterX86::BL,
    unicorn::RegisterX86::BP,
    unicorn::RegisterX86::BPL,
    unicorn::RegisterX86::BX,
    unicorn::RegisterX86::CH,
    unicorn::RegisterX86::CL,
    unicorn::RegisterX86::CS,
    unicorn::RegisterX86::CX,
    unicorn::RegisterX86::DH,
    unicorn::RegisterX86::DI,
    unicorn::RegisterX86::DIL,
    unicorn::RegisterX86::DL,
    unicorn::RegisterX86::DS,
    unicorn::RegisterX86::DX,
    unicorn::RegisterX86::EAX,
    unicorn::RegisterX86::EBP,
    unicorn::RegisterX86::EBX,
    unicorn::RegisterX86::ECX,
    unicorn::RegisterX86::EDI,
    unicorn::RegisterX86::EDX,
    unicorn::RegisterX86::EFLAGS,
    unicorn::RegisterX86::EIP,
    unicorn::RegisterX86::EIZ,
    unicorn::RegisterX86::ES,
    unicorn::RegisterX86::ESI,
    unicorn::RegisterX86::ESP,
    unicorn::RegisterX86::FPSW,
    unicorn::RegisterX86::FS,
    unicorn::RegisterX86::GS,
    unicorn::RegisterX86::IP,
    unicorn::RegisterX86::RAX,
    unicorn::RegisterX86::RBP,
    unicorn::RegisterX86::RBX,
    unicorn::RegisterX86::RCX,
    unicorn::RegisterX86::RDI,
    unicorn::RegisterX86::RDX,
    unicorn::RegisterX86::RIP,
    unicorn::RegisterX86::RIZ,
    unicorn::RegisterX86::RSI,
    unicorn::RegisterX86::RSP,
    unicorn::RegisterX86::SI,
    unicorn::RegisterX86::SIL,
    unicorn::RegisterX86::SP,
    unicorn::RegisterX86::SPL,
    unicorn::RegisterX86::SS,
    unicorn::RegisterX86::CR0,
    unicorn::RegisterX86::CR1,
    unicorn::RegisterX86::CR2,
    unicorn::RegisterX86::CR3,
    unicorn::RegisterX86::CR4,
    unicorn::RegisterX86::CR5,
    unicorn::RegisterX86::CR6,
    unicorn::RegisterX86::CR7,
    unicorn::RegisterX86::CR8,
    unicorn::RegisterX86::CR9,
    unicorn::RegisterX86::CR10,
    unicorn::RegisterX86::CR11,
    unicorn::RegisterX86::CR12,
    unicorn::RegisterX86::CR13,
    unicorn::RegisterX86::CR14,
    unicorn::RegisterX86::CR15,
    unicorn::RegisterX86::DR0,
    unicorn::RegisterX86::DR1,
    unicorn::RegisterX86::DR2,
    unicorn::RegisterX86::DR3,
    unicorn::RegisterX86::DR4,
    unicorn::RegisterX86::DR5,
    unicorn::RegisterX86::DR6,
    unicorn::RegisterX86::DR7,
    unicorn::RegisterX86::DR8,
    unicorn::RegisterX86::DR9,
    unicorn::RegisterX86::DR10,
    unicorn::RegisterX86::DR11,
    unicorn::RegisterX86::DR12,
    unicorn::RegisterX86::DR13,
    unicorn::RegisterX86::DR14,
    unicorn::RegisterX86::DR15,
    unicorn::RegisterX86::FP0,
    unicorn::RegisterX86::FP1,
    unicorn::RegisterX86::FP2,
    unicorn::RegisterX86::FP3,
    unicorn::RegisterX86::FP4,
    unicorn::RegisterX86::FP5,
    unicorn::RegisterX86::FP6,
    unicorn::RegisterX86::FP7,
    unicorn::RegisterX86::K0,
    unicorn::RegisterX86::K1,
    unicorn::RegisterX86::K2,
    unicorn::RegisterX86::K3,
    unicorn::RegisterX86::K4,
    unicorn::RegisterX86::K5,
    unicorn::RegisterX86::K6,
    unicorn::RegisterX86::K7,
    unicorn::RegisterX86::MM0,
    unicorn::RegisterX86::MM1,
    unicorn::RegisterX86::MM2,
    unicorn::RegisterX86::MM3,
    unicorn::RegisterX86::MM4,
    unicorn::RegisterX86::MM5,
    unicorn::RegisterX86::MM6,
    unicorn::RegisterX86::MM7,
    unicorn::RegisterX86::R8,
    unicorn::RegisterX86::R9,
    unicorn::RegisterX86::R10,
    unicorn::RegisterX86::R11,
    unicorn::RegisterX86::R12,
    unicorn::RegisterX86::R13,
    unicorn::RegisterX86::R14,
    unicorn::RegisterX86::R15,
    unicorn::RegisterX86::ST0,
    unicorn::RegisterX86::ST1,
    unicorn::RegisterX86::ST2,
    unicorn::RegisterX86::ST3,
    unicorn::RegisterX86::ST4,
    unicorn::RegisterX86::ST5,
    unicorn::RegisterX86::ST6,
    unicorn::RegisterX86::ST7,
    unicorn::RegisterX86::R8B,
    unicorn::RegisterX86::R9B,
    unicorn::RegisterX86::R10B,
    unicorn::RegisterX86::R11B,
    unicorn::RegisterX86::R12B,
    unicorn::RegisterX86::R13B,
    unicorn::RegisterX86::R14B,
    unicorn::RegisterX86::R15B,
    unicorn::RegisterX86::R8D,
    unicorn::RegisterX86::R9D,
    unicorn::RegisterX86::R10D,
    unicorn::RegisterX86::R11D,
    unicorn::RegisterX86::R12D,
    unicorn::RegisterX86::R13D,
    unicorn::RegisterX86::R14D,
    unicorn::RegisterX86::R15D,
    unicorn::RegisterX86::R8W,
    unicorn::RegisterX86::R9W,
    unicorn::RegisterX86::R10W,
    unicorn::RegisterX86::R11W,
    unicorn::RegisterX86::R12W,
    unicorn::RegisterX86::R13W,
    unicorn::RegisterX86::R14W,
    unicorn::RegisterX86::R15W,
];

#[test]
fn emulate_x86() {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EAX), Ok(123));

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &x86_code32),
        (Err(unicorn::Error::WRITE_UNMAPPED))
    );

    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, x86_code32.len()),
        Ok(x86_code32.clone())
    );

    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX, 50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX), Ok(11));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX), Ok(49));
}

#[test]
fn emulate_x86_negative_values() {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");

    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    assert_eq!(emu.reg_write_i32(unicorn::RegisterX86::ECX, -10), Ok(()));
    assert_eq!(emu.reg_write_i32(unicorn::RegisterX86::EDX, -50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX), Ok(-9));
    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX), Ok(-51));
}

fn callback_lifetime_init() -> unicorn::CpuX86 {
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let callback = move |uc: &unicorn::Unicorn, _: u64, _: u32| {
        let ecx = uc.reg_read(unicorn::RegisterX86::ECX as i32).unwrap();
        println!("ecx: {}", ecx);
    };

    emu.add_code_hook(unicorn::CodeHookType::CODE, 0x1000, 0x2000, callback)
        .expect("failed to add code hook");
    emu
}

#[test]
fn test_callback_lifetime() {
    // Regression test for https://github.com/ekse/unicorn-rs/issues/13
    let emu = callback_lifetime_init();
    println!("Foobar");
    assert_eq!(
        emu.emu_start(0x1000, 0x1002, 10 * unicorn::SECOND_SCALE, 1000),
        Ok(())
    );
}

#[test]
fn x86_code_callback() {
    #[derive(PartialEq, Debug)]
    struct CodeExpectation(u64, u32);
    let expects = vec![CodeExpectation(0x1000, 1), CodeExpectation(0x1001, 1)];
    let codes: Vec<CodeExpectation> = Vec::new();
    let codes_cell = Rc::new(RefCell::new(codes));

    let callback_codes = codes_cell.clone();
    let callback = move |_: &unicorn::Unicorn, address: u64, size: u32| {
        let mut codes = callback_codes.borrow_mut();
        codes.push(CodeExpectation(address, size));
    };

    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_code_hook(unicorn::CodeHookType::CODE, 0x1000, 0x2000, callback)
        .expect("failed to add code hook");
    assert_eq!(
        emu.emu_start(0x1000, 0x1002, 10 * unicorn::SECOND_SCALE, 1000),
        Ok(())
    );
    assert_eq!(expects, *codes_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_intr_callback() {
    #[derive(PartialEq, Debug)]
    struct IntrExpectation(u32);
    let expect = IntrExpectation(0x80);
    let intr_cell = Rc::new(RefCell::new(IntrExpectation(0)));

    let callback_intr = intr_cell.clone();
    let callback = move |_: &unicorn::Unicorn, intno: u32| {
        *callback_intr.borrow_mut() = IntrExpectation(intno);
    };

    let x86_code32: Vec<u8> = vec![0xcd, 0x80]; // INT 0x80;

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_intr_hook(callback)
        .expect("failed to add intr hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *intr_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_mem_callback() {
    #[derive(PartialEq, Debug)]
    struct MemExpectation(unicorn::MemType, u64, usize, i64);
    let expects = vec![
        MemExpectation(unicorn::MemType::WRITE, 0x2000, 4, 0xdeadbeef),
        MemExpectation(unicorn::MemType::READ_UNMAPPED, 0x10000, 4, 0),
    ];
    let mems: Vec<MemExpectation> = Vec::new();
    let mems_cell = Rc::new(RefCell::new(mems));

    let callback_mems = mems_cell.clone();
    let callback = move |_: &unicorn::Unicorn,
                         mem_type: unicorn::MemType,
                         address: u64,
                         size: usize,
                         value: i64| {
        let mut mems = callback_mems.borrow_mut();
        mems.push(MemExpectation(mem_type, address, size, value));
        false
    };

    // mov eax, 0xdeadbeef;
    // mov [0x2000], eax;
    // mov eax, [0x10000];
    let x86_code32: Vec<u8> = vec![
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xA3, 0x00, 0x20, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x01, 0x00
    ];

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_mem_hook(unicorn::MemHookType::MEM_ALL, 0, std::u64::MAX, callback)
        .expect("failed to add memory hook");
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EAX, 0x123), Ok(()));
    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * unicorn::SECOND_SCALE,
            0x1000
        ),
        Err(unicorn::Error::READ_UNMAPPED)
    );

    assert_eq!(expects, *mems_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_insn_in_callback() {
    #[derive(PartialEq, Debug)]
    struct InsnInExpectation(u32, usize);
    let expect = InsnInExpectation(0x10, 4);
    let insn_cell = Rc::new(RefCell::new(InsnInExpectation(0, 0)));

    let callback_insn = insn_cell.clone();
    let callback = move |_: &unicorn::Unicorn, port: u32, size: usize| {
        *callback_insn.borrow_mut() = InsnInExpectation(port, size);
        return 0;
    };

    let x86_code32: Vec<u8> = vec![0xe5, 0x10]; // IN eax, 0x10;

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_insn_in_hook(callback)
        .expect("failed to add in hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *insn_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_insn_out_callback() {
    #[derive(PartialEq, Debug)]
    struct InsnOutExpectation(u32, usize, u32);
    let expect = InsnOutExpectation(0x46, 1, 0x32);
    let insn_cell = Rc::new(RefCell::new(InsnOutExpectation(0, 0, 0)));

    let callback_insn = insn_cell.clone();
    let callback = move |_: &unicorn::Unicorn, port: u32, size: usize, value: u32| {
        *callback_insn.borrow_mut() = InsnOutExpectation(port, size, value);
    };

    let x86_code32: Vec<u8> = vec![0xb0, 0x32, 0xe6, 0x46]; // MOV al, 0x32; OUT  0x46, al;

    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));

    let hook = emu.add_insn_out_hook(callback)
        .expect("failed to add in hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code32.len() as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *insn_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn x86_insn_sys_callback() {
    #[derive(PartialEq, Debug)]
    struct InsnSysExpectation(u64);
    let expect = InsnSysExpectation(0xdeadbeef);
    let insn_cell = Rc::new(RefCell::new(InsnSysExpectation(0)));

    let callback_insn = insn_cell.clone();
    let callback = move |uc: &unicorn::Unicorn| {
        println!("!!!!");
        let rax = uc.reg_read(unicorn::RegisterX86::RAX as i32).unwrap();
        *callback_insn.borrow_mut() = InsnSysExpectation(rax);
    };

    // MOV rax, 0xdeadbeef; SYSCALL;
    let x86_code: Vec<u8> = vec![
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05
    ];

    let mut emu = CpuX86::new(unicorn::Mode::MODE_64).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));

    let hook = emu.add_insn_sys_hook(unicorn::InsnSysX86::SYSCALL, 1, 0, callback)
        .expect("failed to add in hook");

    assert_eq!(
        emu.emu_start(
            0x1000,
            0x1000 + x86_code.len() as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(expect, *insn_cell.borrow());
    assert_eq!(emu.remove_hook(hook), Ok(()));
}

#[test]
fn emulate_arm() {
    let arm_code32: Vec<u8> = vec![0x83, 0xb0]; // sub    sp, #0xc

    let emu = CpuARM::new(unicorn::Mode::THUMB).expect("failed to instantiate emulator");
    assert_eq!(emu.reg_write(unicorn::RegisterARM::R1, 123), Ok(()));
    assert_eq!(emu.reg_read(unicorn::RegisterARM::R1), Ok(123));

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &arm_code32),
        (Err(unicorn::Error::WRITE_UNMAPPED))
    );

    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::PROT_ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &arm_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, arm_code32.len()),
        Ok(arm_code32.clone())
    );

    assert_eq!(emu.reg_write(unicorn::RegisterARM::SP, 12), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterARM::R0, 10), Ok(()));

    // ARM checks the least significant bit of the address to know
    // if the code is in Thumb mode.
    assert_eq!(
        emu.emu_start(
            0x1000 | 0x01,
            (0x1000 | (0x01 + arm_code32.len())) as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(unicorn::RegisterARM::SP), Ok(0));
    assert_eq!(emu.reg_read(unicorn::RegisterARM::R0), Ok(10));
}

#[test]
fn emulate_mips() {
    let mips_code32 = vec![0x56, 0x34, 0x21, 0x34]; // ori $at, $at, 0x3456;

    let emu = CpuMIPS::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_write(0x1000, &mips_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, mips_code32.len()),
        Ok(mips_code32.clone())
    );
    assert_eq!(emu.reg_write(unicorn::RegisterMIPS::AT, 0), Ok(()));
    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + mips_code32.len()) as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(unicorn::RegisterMIPS::AT), Ok(0x3456));
}

#[test]
fn mem_unmapping() {
    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
    assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));
}

#[test]
fn mem_map_ptr() {
    // Use an array for the emulator memory.
    let mut mem: [u8; 4000] = [0; 4000];
    let x86_code32: Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx

    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &x86_code32),
        (Err(unicorn::Error::WRITE_UNMAPPED))
    );

    assert_eq!(
        unsafe { emu.mem_map_ptr(0x1000, 0x4000, unicorn::Protection::ALL, mem.as_mut_ptr()) },
        Ok(())
    );
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, x86_code32.len()),
        Ok(x86_code32.clone())
    );

    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX, 50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX), Ok(11));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX), Ok(49));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));

    // Use a Vec for the emulator memory.
    let mut mem: Vec<u8> = Vec::new();
    mem.reserve(4000);

    // Attempt to write to memory before mapping it.
    assert_eq!(
        emu.mem_write(0x1000, &x86_code32),
        (Err(unicorn::Error::WRITE_UNMAPPED))
    );

    assert_eq!(
        unsafe { emu.mem_map_ptr(0x1000, 0x4000, unicorn::Protection::ALL, mem.as_mut_ptr()) },
        Ok(())
    );
    assert_eq!(emu.mem_write(0x1000, &x86_code32), Ok(()));
    assert_eq!(
        emu.mem_read_as_vec(0x1000, x86_code32.len()),
        Ok(x86_code32.clone())
    );

    assert_eq!(emu.reg_write(unicorn::RegisterX86::ECX, 10), Ok(()));
    assert_eq!(emu.reg_write(unicorn::RegisterX86::EDX, 50), Ok(()));

    assert_eq!(
        emu.emu_start(
            0x1000,
            (0x1000 + x86_code32.len()) as u64,
            10 * unicorn::SECOND_SCALE,
            1000
        ),
        Ok(())
    );
    assert_eq!(emu.reg_read(unicorn::RegisterX86::ECX), Ok(11));
    assert_eq!(emu.reg_read(unicorn::RegisterX86::EDX), Ok(49));
    assert_eq!(emu.mem_unmap(0x1000, 0x4000), Ok(()));
}

#[test]
fn x86_context_save_and_restore () {
    for mode in vec![ unicorn::Mode::MODE_32, unicorn::Mode::MODE_64 ] {
        let x86_code: Vec<u8> = vec![
            0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05
        ];
        let emu = CpuX86::new(mode).expect("failed to instantiate emulator");
        assert_eq!(emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL), Ok(()));
        assert_eq!(emu.mem_write(0x1000, &x86_code), Ok(()));
        let _ = emu.emu_start(0x1000,
                              (0x1000 + x86_code.len()) as u64,
                              10 * unicorn::SECOND_SCALE,
                              1000);

        /* now, save the context... */
        let context = emu.context_save();
        let context = context.unwrap();
        
        /* and create a new emulator, into which we will "restore" that context */
        let emu2 = CpuX86::new(mode).expect("failed to instantiate emu2");
        assert_eq!(emu2.context_restore(&context), Ok(()));
        for register in X86_REGISTERS.iter() {
            println!("Testing register {:?}", register);
            assert_eq!(emu2.reg_read(*register), emu.reg_read(*register));
        }
    }
}
