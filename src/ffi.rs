use libc;

use unicorn_const::{Arch, Mode, Error};
use uc_handle;

#[link(name = "unicorn")]
extern "C" {
    pub fn uc_version(major : *const libc::size_t, minor : *const libc::size_t) -> libc::size_t;
    pub fn uc_arch_supported(arch : Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine : *mut uc_handle) -> Error;
    pub fn uc_close(engine : uc_handle) -> Error;
    pub fn uc_errno(engine : uc_handle) -> Error;
    // TODO: const char *uc_strerror(uc_err code);
    pub fn uc_reg_write(engine : uc_handle, regid : libc::size_t, value : *const u64) -> Error;
    pub fn uc_reg_read(engine : uc_handle, regid : libc::size_t, value : *mut u64) -> Error;
    pub fn uc_mem_write(engine : uc_handle, address : u64, bytes : *const u8, size : libc::size_t) -> Error; 
    pub fn uc_mem_read(engine : uc_handle, address : u64, bytes : *mut u8, size : libc::size_t) -> Error; 
    pub fn uc_mem_map(engine : uc_handle, address : u64, size : libc::size_t, perms : u32) -> Error; 
    pub fn uc_mem_unmap(engine : uc_handle, address : u64, size : libc::size_t) -> Error; 
    pub fn uc_mem_protect(engine : uc_handle, address : u64, size : libc::size_t, perms : u32) -> Error;
    pub fn uc_emu_start(engine : uc_handle, begin : u64, until : u64, timeout : u64, count : libc::size_t) -> Error;
    pub fn uc_emu_stop(engine : uc_handle) -> Error;
}
