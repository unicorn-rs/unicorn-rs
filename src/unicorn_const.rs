// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [unicorn_const.rs]

pub const API_MAJOR: u32 = 0;
pub const API_MINOR: u32 = 9;
pub const SECOND_SCALE: u32 = 1000000;
pub const MILISECOND_SCALE: u32 = 1000;

// Architecture type
#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum Arch {
    ARM = 1, // ARM architecture (including Thumb, Thumb-2)
    ARM64, // ARM-64, also called AArch64
    MIPS, // Mips architecture
    X86, // X86 architecture (including x86 & x86-64)
    PPC, // PowerPC architecture
    SPARC, // Sparc architecture
    M68K, // M68K architecture
    MAX,
}

// Mode type
// TODO : allow alias modes
#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum Mode {
    LITTLE_ENDIAN = 0, // little-endian mode (default mode)
    // UC_MODE_ARM = 0,    // 32-bit ARM
    MODE_16 = 1 << 1, // 16-bit mode (X86)
    MODE_32 = 1 << 2, // 32-bit mode (X86)
    MODE_64 = 1 << 3, // 64-bit mode (X86, PPC)
    THUMB = 1 << 4, // ARM's Thumb mode, including Thumb-2
    MCLASS = 1 << 5, // ARM's Cortex-M series
    V8 = 1 << 6, // ARMv8 A32 encodings for ARM
    // MICRO = 1 << 4, // MicroMips mode (MIPS)
    // MIPS3 = 1 << 5, // Mips III ISA
    // MIPS32R6 = 1 << 6, // Mips32r6 ISA
    // V9 = 1 << 4, // SparcV9 mode (Sparc)
    // QPX = 1 << 4, // Quad Processing eXtensions mode (PPC)
    BIG_ENDIAN = 1 << 30, /* big-endian mode
                           * UC_MODE_MIPS32 = UC_MODE_32,    // Mips32 ISA (Mips)
                           * UC_MODE_MIPS64 = UC_MODE_64,    // Mips64 ISA (Mips) */
}

pub const MODE_LITTLE_ENDIAN: u32 = 0;
pub const MODE_ARM: u32 = 0;
pub const MODE_16: u32 = 2;
pub const MODE_32: u32 = 4;
pub const MODE_64: u32 = 8;
pub const MODE_THUMB: u32 = 16;
pub const MODE_MCLASS: u32 = 32;
pub const MODE_V8: u32 = 64;
pub const MODE_MICRO: u32 = 16;
pub const MODE_MIPS3: u32 = 32;
pub const MODE_MIPS32R6: u32 = 64;
pub const MODE_V9: u32 = 16;
pub const MODE_QPX: u32 = 16;
pub const MODE_BIG_ENDIAN: u32 = 1073741824;
pub const MODE_MIPS32: u32 = 4;
pub const MODE_MIPS64: u32 = 8;

// All type of errors encountered by Unicorn API.
// These are values returned by uc_errno()
#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum Error {
    OK = 0, // No error: everything was fine
    NOMEM, // Out-Of-Memory error: uc_open(), uc_emulate()
    ARCH, // Unsupported architecture: uc_open()
    HANDLE, // Invalid handle
    MODE, // Invalid/unsupported mode: uc_open()
    VERSION, // Unsupported version (bindings)
    READ_UNMAPPED, // Quit emulation due to READ on unmapped memory: uc_emu_start()
    WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    ETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    HOOK, // Invalid hook type: uc_hook_add()
    INSN_INVALID, // Quit emulation due to invalid instruction: uc_emu_start()
    MAP, // Invalid memory mapping: uc_mem_map()
    WRITE_PROT, // Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    READ_PROT, // Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    FETCH_PROT, // Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    ARG, // Inavalid argument provided to uc_xxx function (See specific function API)
    READ_UNALIGNED, // Unaligned read
    WRITE_UNALIGNED, // Unaligned write
    FETCH_UNALIGNED, // Unaligned fetch
    HOOK_EXIST, // hook for this event already existed
}

#[repr(C)]
bitflags! {
    flags Protection : u32 {
        const PROT_NONE = 0,
        const PROT_READ = 1,
        const PROT_WRITE = 2,
        const PROT_EXEC = 4,
        const PROT_ALL = 7,
    }
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum HookType {
    INTR = 1 << 0, // Hook all interrupt/syscall events
    INSN = 1 << 1, // Hook a particular instruction
    CODE = 1 << 2, // Hook a range of code
    BLOCK = 1 << 3, // Hook basic blocks
    MEM_READ_UNMAPPED = 1 << 4, // Hook for memory read on unmapped memory
    MEM_WRITE_UNMAPPED = 1 << 5, // Hook for invalid memory write events
    MEM_FETCH_UNMAPPED = 1 << 6, // Hook for invalid memory fetch for execution events
    MEM_READ_PROT = 1 << 7, // Hook for memory read on read-protected memory
    MEM_WRITE_PROT = 1 << 8, // Hook for memory write on write-protected memory
    MEM_FETCH_PROT = 1 << 9, // Hook for memory fetch on non-executable memory
    MEM_READ = 1 << 10, // Hook memory read events.
    MEM_WRITE = 1 << 11, // Hook memory write events.
    MEM_FETCH = 1 << 12, // Hook memory fetch for execution events
}
