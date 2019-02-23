//! Bindings for the Unicorn emulator.
//!
//! You most likely want to use one of the Cpu structs (`CpuX86`, `CpuARM`, etc.).
//!
//! # Example use
//!
//! ```rust
//! extern crate unicorn;
//!
//! use unicorn::{Cpu, CpuX86, uc_handle};
//!
//! fn main() {
//!    let x86_code32 : Vec<u8> = vec![0x41, 0x4a]; // INC ecx; DEC edx
//!
//!    let mut emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate emulator");
//!    emu.mem_map(0x1000, 0x4000, unicorn::Protection::ALL);
//!    emu.mem_write(0x1000, &x86_code32);
//!    emu.reg_write_i32(unicorn::RegisterX86::ECX, -10);
//!    emu.reg_write_i32(unicorn::RegisterX86::EDX, -50);
//!
//!    emu.emu_start(0x1000, (0x1000 + x86_code32.len()) as u64, 10 * unicorn::SECOND_SCALE, 1000);
//!    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::ECX), Ok((-9)));
//!    assert_eq!(emu.reg_read_i32(unicorn::RegisterX86::EDX), Ok((-51)));
//! }
//! ```
//!
use libunicorn_sys as ffi;

mod arm64_const;
mod arm_const;
mod m68k_const;
mod mips_const;
mod sparc_const;
mod x86_const;

#[macro_use]
mod macros;

use std::{
    mem,
    collections::HashMap,
};

pub use crate::{
    arm64_const::*,
    arm_const::*,
    m68k_const::*,
    mips_const::*,
    sparc_const::*,
    ffi::{
        unicorn_const::*,
        *
    },
    x86_const::*,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Context {
    context: uc_context
}

impl Context {
    pub fn new() -> Self { Context { context: 0 } }
    pub fn is_initialized(&self) -> bool { self.context != 0 }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { uc_free(self.context) };
    }
}


pub trait Register {
    fn to_i32(&self) -> i32;
}

implement_register!(RegisterARM);
implement_register!(RegisterARM64);
implement_register!(RegisterM68K);
implement_register!(RegisterMIPS);
implement_register!(RegisterSPARC);
implement_register!(RegisterX86);

pub trait Cpu {
    type Reg: Register;

    fn emu(&self) -> &Unicorn;

    fn mut_emu(&mut self) -> &mut Unicorn;

    /// Read an unsigned value from a register.
    fn reg_read(&self, reg: Self::Reg) -> Result<u64> {
        self.emu().reg_read(reg.to_i32())
    }

    /// Read a signed 32-bit value from a register.
    fn reg_read_i32(&self, reg: Self::Reg) -> Result<i32> {
        self.emu().reg_read_i32(reg.to_i32())
    }

    /// Write an unsigned value register.
    fn reg_write(&self, reg: Self::Reg, value: u64) -> Result<()> {
        self.emu().reg_write(reg.to_i32(), value)
    }

    /// Write a signed 32-bit value to a register.
    fn reg_write_i32(&self, reg: Self::Reg, value: i32) -> Result<()> {
        self.emu().reg_write_i32(reg.to_i32(), value)
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    fn mem_map(&self, address: u64, size: libc::size_t, perms: Protection) -> Result<()> {
        self.emu().mem_map(address, size, perms)
    }

    /// Map an existing memory region in the emulator at the specified address.
    ///
    /// This function is marked unsafe because it is the responsibility of the caller to
    /// ensure that `size` matches the size of the passed buffer, an invalid `size` value will
    /// likely cause a crash in unicorn.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    ///
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    ///
    /// `ptr` is a pointer to the provided memory region that will be used by the emulator.
    unsafe fn mem_map_ptr<T>(
        &self,
        address: u64,
        size: libc::size_t,
        perms: Protection,
        ptr: *mut T,
    ) -> Result<()> {
        self.emu().mem_map_ptr(address, size, perms, ptr)
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    fn mem_unmap(&self, address: u64, size: libc::size_t) -> Result<()> {
        self.emu().mem_unmap(address, size)
    }

    /// Write a range of bytes to memory at the specified address.
    fn mem_write(&self, address: u64, bytes: &[u8]) -> Result<()> {
        self.emu().mem_write(address, bytes)
    }

    /// Read a range of bytes from memory at the specified address.
    fn mem_read(&self, address: u64, bytes: &mut [u8]) -> Result<()> {
        self.emu().mem_read(address, bytes)
    }

    /// Read a range of bytes from memory at the specified address; return the bytes read as a
    /// `Vec`.
    fn mem_read_as_vec(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        self.emu().mem_read_as_vec(address, size)
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    fn mem_protect(&self, address: u64, size: usize, perms: Protection) -> Result<()> {
        self.emu().mem_protect(address, size, perms)
    }

    /// Returns a vector with the memory regions that are mapped in the emulator.
    fn mem_regions(&self) -> Result<Vec<MemRegion>> {
        self.emu().mem_regions()
    }

    /// Emulate machine code for a specified duration.
    ///
    /// `begin` is the address where to start the emulation. The emulation stops if `until`
    /// is hit. `timeout` specifies a duration in microseconds after which the emulation is
    /// stopped (infinite execution if set to 0). `count` is the maximum number of instructions
    /// to emulate (emulate all the available instructions if set to 0).
    fn emu_start(&self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()> {
        self.emu().emu_start(begin, until, timeout, count)
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    fn emu_stop(&self) -> Result<()> {
        self.emu().emu_stop()
    }

    /// Add a code hook.
    fn add_code_hook<F>(
        &mut self,
        hook_type: CodeHookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u64, u32) -> () + 'static,
    {
        self.mut_emu()
            .add_code_hook(hook_type, begin, end, callback)
    }

    /// Add an interrupt hook.
    fn add_intr_hook<F>(&mut self, callback: F) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u32) + 'static,
    {
        self.mut_emu().add_intr_hook(callback)
    }

    /// Add a memory hook.
    fn add_mem_hook<F>(
        &mut self,
        hook_type: MemHookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, MemType, u64, usize, i64) -> bool + 'static,
    {
        self.mut_emu().add_mem_hook(hook_type, begin, end, callback)
    }

    /// Add an "in" instruction hook.
    fn add_insn_in_hook<F>(&mut self, callback: F) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u32, usize) -> u32 + 'static,
    {
        self.mut_emu().add_insn_in_hook(callback)
    }

    /// Add an "out" instruction hook.
    fn add_insn_out_hook<F>(&mut self, callback: F) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u32, usize, u32) + 'static,
    {
        self.mut_emu().add_insn_out_hook(callback)
    }

    /// Add a "syscall" or "sysenter" instruction hook.
    fn add_insn_sys_hook<F>(
        &mut self,
        insn_type: InsnSysX86,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<uc_hook>
    where
        F: Fn(&Unicorn) + 'static,
    {
        self.mut_emu()
            .add_insn_sys_hook(insn_type, begin, end, callback)
    }


    /// Remove a hook.
    ///
    /// `hook` is the value returned by either `add_code_hook` or `add_mem_hook`.
    fn remove_hook(&mut self, hook: uc_hook) -> Result<()> {
        self.mut_emu().remove_hook(hook)
    }

    /// Return the last error code when an API function failed.
    ///
    /// Like glibc errno(), this function might not retain its old value once accessed.
    fn errno(&self) -> Error {
        self.emu().errno()
    }

    /// Query the internal status of the engine.
    ///
    /// Supported queries :
    ///
    /// - `Query::PAGE_SIZE` : the page size used by the emulator.
    /// - `Query::MODE` : the current hardware mode.
    fn query(&self, query: Query) -> Result<usize> {
        self.emu().query(query)
    }

    /// Save the CPU context into an opaque struct.
    fn context_save(&self) -> Result<Context> {
        self.emu().context_save()
    }

    fn context_restore(&self, context: &Context) -> Result<()> {
        self.emu().context_restore(context)
    }
}

implement_emulator!(doc="An ARM emulator instance.",
                    doc="Create an ARM emulator instance for the specified hardware mode.",
                    CpuARM, Arch::ARM, RegisterARM);

implement_emulator!(doc="An ARM64 emulator instance.",
                    doc="Create an ARM64 emulator instance for the specified hardware mode.",
                    CpuARM64, Arch::ARM64, RegisterARM64);

implement_emulator!(doc="A M68K emulator instance.",
                    doc="Create a M68K emulator instance for the specified hardware mode.",
                    CpuM68K, Arch::M68K, RegisterM68K);

implement_emulator!(doc="A MIPS emulator instance.",
                    doc="Create an MIPS emulator instance for the specified hardware mode.",
                    CpuMIPS, Arch::MIPS, RegisterMIPS);

implement_emulator!(doc="A SPARC emulator instance.",
                    doc="Create a SPARC emulator instance for the specified hardware mode.",
                    CpuSPARC, Arch::SPARC, RegisterSPARC);

implement_emulator!(doc="An X86 emulator instance.",
                    doc="Create an X86 emulator instance for the specified hardware mode.",
                    CpuX86, Arch::X86, RegisterX86);

/// Struct to bind a unicorn instance to a callback.
pub struct UnicornHook<F> {
    unicorn: *const Unicorn,
    callback: F,
}

extern "C" fn code_hook_proxy(_: uc_handle, address: u64, size: u32, user_data: *mut CodeHook) {
    let (unicorn, callback) = destructure_hook!(CodeHook, user_data);
    callback(unicorn, address, size)
}

extern "C" fn intr_hook_proxy(_: uc_handle, intno: u32, user_data: *mut IntrHook) {
    let (unicorn, callback) = destructure_hook!(IntrHook, user_data);
    callback(unicorn, intno)
}

extern "C" fn mem_hook_proxy(
    _: uc_handle,
    mem_type: MemType,
    address: u64,
    size: usize,
    value: i64,
    user_data: *mut MemHook,
) -> bool {
    let (unicorn, callback) = destructure_hook!(MemHook, user_data);
    callback(unicorn, mem_type, address, size, value)
}

extern "C" fn insn_in_hook_proxy(
    _: uc_handle,
    port: u32,
    size: usize,
    user_data: *mut InsnInHook,
) -> u32 {
    let (unicorn, callback) = destructure_hook!(InsnInHook, user_data);
    callback(unicorn, port, size)
}

extern "C" fn insn_out_hook_proxy(
    _: uc_handle,
    port: u32,
    size: usize,
    value: u32,
    user_data: *mut InsnOutHook,
) {
    let (unicorn, callback) = destructure_hook!(InsnOutHook, user_data);
    callback(unicorn, port, size, value)
}

extern "C" fn insn_sys_hook_proxy(_: uc_handle, user_data: *mut InsnSysHook) {
    let (unicorn, callback) = destructure_hook!(InsnSysHook, user_data);
    callback(unicorn)
}

type CodeHook = UnicornHook<Box<FnMut(&Unicorn, u64, u32)>>;
type IntrHook = UnicornHook<Box<FnMut(&Unicorn, u32)>>;
type MemHook = UnicornHook<Box<FnMut(&Unicorn, MemType, u64, usize, i64) -> bool>>;
type InsnInHook = UnicornHook<Box<FnMut(&Unicorn, u32, usize) -> u32>>;
type InsnOutHook = UnicornHook<Box<FnMut(&Unicorn, u32, usize, u32)>>;
type InsnSysHook = UnicornHook<Box<FnMut(&Unicorn)>>;

/// Internal : A Unicorn emulator instance, use one of the Cpu structs instead.
pub struct Unicorn {
    handle: libc::size_t, // Opaque handle to uc_engine
    code_callbacks: HashMap<uc_hook, Box<CodeHook>>,
    intr_callbacks: HashMap<uc_hook, Box<IntrHook>>,
    mem_callbacks: HashMap<uc_hook, Box<MemHook>>,
    insn_in_callbacks: HashMap<uc_hook, Box<InsnInHook>>,
    insn_out_callbacks: HashMap<uc_hook, Box<InsnOutHook>>,
    insn_sys_callbacks: HashMap<uc_hook, Box<InsnSysHook>>,
}

/// Returns a tuple `(major, minor)` for the bindings version number.
pub fn bindings_version() -> (u32, u32) {
    (BINDINGS_MAJOR, BINDINGS_MINOR)
}

/// Returns a tuple `(major, minor)` for the unicorn version number.
pub fn unicorn_version() -> (u32, u32) {
    let mut major: u32 = Default::default();
    let mut minor: u32 = Default::default();
    let p_major: *mut _ = &mut major;
    let p_minor: *mut _ = &mut minor;
    unsafe {
        uc_version(p_major, p_minor);
    }
    (major, minor)
}

/// Returns `true` if the architecture is supported by this build of unicorn.
pub fn arch_supported(arch: Arch) -> bool {
    unsafe { uc_arch_supported(arch) }
}

impl Unicorn {
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    pub fn new(arch: Arch, mode: Mode) -> Result<Box<Unicorn>> {
        // Verify bindings compatibility with the core before going further.
        let (major, minor) = unicorn_version();
        if major != BINDINGS_MAJOR || minor != BINDINGS_MINOR {
            return Err(Error::VERSION);
        }

        let mut handle: libc::size_t = Default::default();
        let err = unsafe { uc_open(arch, mode, &mut handle) };
        if err == Error::OK {
            Ok(Box::new(Unicorn {
                handle,
                code_callbacks: Default::default(),
                intr_callbacks: Default::default(),
                mem_callbacks: Default::default(),
                insn_in_callbacks: Default::default(),
                insn_out_callbacks: Default::default(),
                insn_sys_callbacks: Default::default(),
            }))
        } else {
            Err(err)
        }
    }

    unsafe fn reg_write_generic<T: Sized>(&self, regid: i32, value: T) -> Result<()> {
        let p_value: *const T = &value;
        let err = uc_reg_write(self.handle, regid, p_value as *const libc::c_void);
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Write an unsigned value register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    /// You need to cast the register with `as i32`.
    pub fn reg_write(&self, regid: i32, value: u64) -> Result<()> {
        unsafe { Self::reg_write_generic::<_>(&self, regid, value) }
    }

    /// Write a signed 32-bit value to a register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    /// You need to cast the register with `as i32`.
    pub fn reg_write_i32(&self, regid: i32, value: i32) -> Result<()> {
        unsafe { Self::reg_write_generic::<_>(&self, regid, value) }
    }

    unsafe fn reg_read_generic<T: Sized>(&self, regid: i32) -> Result<T> {
        // deprecating in Rust 2.0.0: use mem::MaybeUninit::zeroed() instead
        let mut value: T = mem::zeroed();
        let err = uc_reg_read(
            self.handle,
            regid as libc::c_int,
            &mut value as *mut _ as *mut libc::c_void,
        );
        if err == Error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    /// Read an unsigned value from a register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    /// You need to cast the register with `as i32`.
    pub fn reg_read(&self, regid: i32) -> Result<u64> {
        unsafe { Self::reg_read_generic::<_>(&self, regid) }
    }

    /// Read a signed 32-bit value from a register.
    ///
    /// Note : The register is defined as an i32 to be able to support the
    /// different register types (`RegisterX86`, `RegisterARM`, `RegisterMIPS` etc.).
    /// You need to cast the register with `as i32`.
    pub fn reg_read_i32(&self, regid: i32) -> Result<i32> {
        unsafe { Self::reg_read_generic::<_>(&self, regid) }
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_map(
        &self,
        address: u64,
        size: libc::size_t,
        perms: Protection,
    ) -> Result<()> {
        let err = unsafe { uc_mem_map(self.handle, address, size, perms.bits()) };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Map an existing memory region in the emulator at the specified address.
    ///
    /// This function is marked unsafe because it is the responsibility of the caller to
    /// ensure that `size` matches the size of the passed buffer, an invalid `size` value will
    /// likely cause a crash in unicorn.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    ///
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    ///
    /// `ptr` is a pointer to the provided memory region that will be used by the emulator.
    pub unsafe fn mem_map_ptr<T>(
        &self,
        address: u64,
        size: libc::size_t,
        perms: Protection,
        ptr: *mut T,
    ) -> Result<()> {
        let err = uc_mem_map_ptr(
            self.handle,
            address,
            size,
            perms.bits(),
            ptr as *mut libc::c_void,
        );
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_unmap(&self, address: u64, size: libc::size_t) -> Result<()> {
        let err = unsafe { uc_mem_unmap(self.handle, address, size) };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Write a range of bytes to memory at the specified address.
    pub fn mem_write(&self, address: u64, bytes: &[u8]) -> Result<()> {
        let err = unsafe {
            uc_mem_write(
                self.handle,
                address,
                bytes.as_ptr(),
                bytes.len() as libc::size_t,
            )
        };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Read a range of bytes from memory at the specified address.
    pub fn mem_read(&self, address: u64, bytes: &mut [u8]) -> Result<()> {
        let err = unsafe {
            uc_mem_read(
                self.handle,
                address,
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Read a range of bytes from memory at the specified address; return the bytes read as a
    /// `Vec`.
    pub fn mem_read_as_vec(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::with_capacity(size);
        unsafe { self.mem_read(address, bytes.get_unchecked_mut(0..size)) }.map(|()| unsafe {
            bytes.set_len(size);
            bytes
        })
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_protect(&self, address: u64, size: usize, perms: Protection) -> Result<()> {
        let err =
            unsafe { uc_mem_protect(self.handle, address, size as libc::size_t, perms.bits()) };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Returns a vector with the memory regions that are mapped in the emulator.
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>> {
        // We make a copy of the MemRegion structs that are returned by uc_mem_regions()
        // as they have to be freed to the caller. It is simpler to make a copy and free()
        // the originals right away.
        let mut nb_regions: u32 = 0;
        let p_nb_regions: *mut u32 = &mut nb_regions;
        let p_regions: *const MemRegion = std::ptr::null();
        let pp_regions: *const *const MemRegion = &p_regions;
        let err = unsafe { uc_mem_regions(self.handle, pp_regions, p_nb_regions) };
        if err == Error::OK {
            let mut regions: Vec<MemRegion> = Vec::new();
            let mut i: isize = 0;
            while i < nb_regions as isize {
                unsafe {
                    let region: MemRegion = mem::transmute_copy(&*p_regions.offset(i));
                    regions.push(region);
                }
                i += 1;
            }
            unsafe { libc::free(*pp_regions as *mut libc::c_void) };
            Ok(regions)
        } else {
            Err(err)
        }
    }

    /// Emulate machine code for a specified duration.
    ///
    /// `begin` is the address where to start the emulation. The emulation stops if `until`
    /// is hit. `timeout` specifies a duration in microseconds after which the emulation is
    /// stopped (infinite execution if set to 0). `count` is the maximum number of instructions
    /// to emulate (emulate all the available instructions if set to 0).
    pub fn emu_start(
        &self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> Result<()> {
        let err =
            unsafe { uc_emu_start(self.handle, begin, until, timeout, count as libc::size_t) };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    pub fn emu_stop(&self) -> Result<()> {
        let err = unsafe { uc_emu_stop(self.handle) };
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Add a code hook.
    pub fn add_code_hook<F>(
        &mut self,
        hook_type: CodeHookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u64, u32) + 'static,
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(CodeHook {
            unicorn: self as *mut _,
            callback: Box::new(callback),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = code_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(
                self.handle,
                p_hook,
                mem::transmute(hook_type),
                _callback,
                p_user_data,
                begin,
                end,
            )
        };
        if err == Error::OK {
            self.code_callbacks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add an interrupt hook.
    pub fn add_intr_hook<F>(&mut self, callback: F) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u32) + 'static,
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(IntrHook {
            unicorn: self as *mut _,
            callback: Box::new(callback),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = intr_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(
                self.handle,
                p_hook,
                HookType::INTR,
                _callback,
                p_user_data,
                0,
                0,
            )
        };

        if err == Error::OK {
            self.intr_callbacks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add a memory hook.
    pub fn add_mem_hook<F>(
        &mut self,
        hook_type: MemHookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, MemType, u64, usize, i64) -> bool + 'static,
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(MemHook {
            unicorn: self as *mut _,
            callback: Box::new(callback),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = mem_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(
                self.handle,
                p_hook,
                mem::transmute(hook_type),
                _callback,
                p_user_data,
                begin,
                end,
            )
        };

        if err == Error::OK {
            self.mem_callbacks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add an "in" instruction hook.
    pub fn add_insn_in_hook<F>(&mut self, callback: F) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u32, usize) -> u32 + 'static,
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(InsnInHook {
            unicorn: self as *mut _,
            callback: Box::new(callback),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = insn_in_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(
                self.handle,
                p_hook,
                HookType::INSN,
                _callback,
                p_user_data,
                0,
                0,
                x86_const::InsnX86::IN,
            )
        };

        if err == Error::OK {
            self.insn_in_callbacks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Add an "out" instruction hook.
    pub fn add_insn_out_hook<F>(&mut self, callback: F) -> Result<uc_hook>
    where
        F: Fn(&Unicorn, u32, usize, u32) + 'static,
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(InsnOutHook {
            unicorn: self as *mut _,
            callback: Box::new(callback),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = insn_out_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(
                self.handle,
                p_hook,
                HookType::INSN,
                _callback,
                p_user_data,
                0,
                0,
                x86_const::InsnX86::OUT,
            )
        };

        if err == Error::OK {
            self.insn_out_callbacks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    // (Currently only supports x86 architectures. TODO: Add support for ARM.)
    /// Add a "syscall" or "sysenter" instruction hook.
    pub fn add_insn_sys_hook<F>(
        &mut self,
        insn_type: InsnSysX86,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<uc_hook>
    where
        F: Fn(&Unicorn) + 'static,
    {
        let mut hook: uc_hook = 0;
        let p_hook: *mut libc::size_t = &mut hook;

        let user_data = Box::new(InsnSysHook {
            unicorn: self as *mut _,
            callback: Box::new(callback),
        });
        let p_user_data: *mut libc::size_t = unsafe { mem::transmute(&*user_data) };
        let _callback: libc::size_t = insn_sys_hook_proxy as usize;

        let err = unsafe {
            uc_hook_add(
                self.handle,
                p_hook,
                HookType::INSN,
                _callback,
                p_user_data,
                begin,
                end,
                insn_type,
            )
        };

        if err == Error::OK {
            self.insn_sys_callbacks.insert(hook, user_data);
            Ok(hook)
        } else {
            Err(err)
        }
    }

    /// Remove a hook.
    ///
    /// `hook` is the value returned by either `add_code_hook` or `add_mem_hook`.
    pub fn remove_hook(&mut self, hook: uc_hook) -> Result<()> {
        let err = unsafe { uc_hook_del(self.handle, hook) } as Error;
        // Check in all maps to find which one has the hook.
        macro_rules! ignore { () => { |_| () } };
        self.code_callbacks.remove(&hook).map(ignore!())
            .or_else(|| self.intr_callbacks.remove(&hook).map(ignore!()))
            .or_else(|| self.mem_callbacks.remove(&hook).map(ignore!()))
            .or_else(|| self.insn_in_callbacks.remove(&hook).map(ignore!()))
            .or_else(|| self.insn_out_callbacks.remove(&hook).map(ignore!()))
            .or_else(|| self.insn_sys_callbacks.remove(&hook).map(ignore!()));

        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// Return the last error code when an API function failed.
    ///
    /// Like glibc errno(), this function might not retain its old value once accessed.
    pub fn errno(&self) -> Error {
        unsafe { uc_errno(self.handle) }
    }

    /// Query the internal status of the engine.
    ///
    /// Supported queries :
    ///
    /// - `Query::PAGE_SIZE` : the page size used by the emulator.
    /// - `Query::MODE` : the current hardware mode.
    pub fn query(&self, query: Query) -> Result<usize> {
        let mut result: libc::size_t = 0;
        let p_result: *mut libc::size_t = &mut result;
        let err = unsafe { uc_query(self.handle, query, p_result) };
        if err == Error::OK {
            Ok(result)
        } else {
            Err(err)
        }
    }

    /// Save and return the current CPU Context, which can
    /// later be passed to restore_context to roll back changes
    /// in the emulator.
    pub fn context_save(&self) -> Result<Context> {
        let mut context: uc_context = 0;
        let p_context: *mut uc_context = &mut context;

        let err = unsafe { uc_context_alloc(self.handle, p_context) };
        if err != Error::OK {
            return Err(err)
        };
        let err = unsafe { uc_context_save(self.handle, context) };
        if err != Error::OK {
            return Err(err)
        };

        Ok(Context{context})
    }

    /// Restore a saved context. This can be used to roll back changes in
    /// a CPU's register state (but not memory), or to duplicate a register
    /// state across multiple CPUs.
    pub fn context_restore(&self, context: &Context) -> Result<()> {
        let err = unsafe {uc_context_restore(self.handle, context.context)};
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }
}

impl Drop for Unicorn {
    fn drop(&mut self) {
        unsafe { uc_close(self.handle) };
    }
}
