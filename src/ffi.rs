use libc;
use std::os::raw::c_char;
use unicorn_const::{Arch, Mode, Error, HookType, Query};
use {uc_handle, uc_hook};

#[link(name = "unicorn")]
extern "C" {
    pub fn uc_version(major: *const libc::size_t, minor: *const libc::size_t) -> libc::size_t;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> Error;
    pub fn uc_close(engine: uc_handle) -> Error;
    pub fn uc_errno(engine: uc_handle) -> Error;
    pub fn uc_strerror(error_code: Error) -> *const c_char;
    pub fn uc_reg_write(engine: uc_handle,
                        regid: libc::c_int,
                        value: *const libc::c_void)
                        -> Error;
    pub fn uc_reg_read(engine: uc_handle, regid: libc::c_int, value: *mut libc::c_void) -> Error;
    pub fn uc_mem_write(engine: uc_handle,
                        address: u64,
                        bytes: *const u8,
                        size: libc::size_t)
                        -> Error;
    pub fn uc_mem_read(engine: uc_handle,
                       address: u64,
                       bytes: *mut u8,
                       size: libc::size_t)
                       -> Error;
    pub fn uc_mem_map(engine: uc_handle, address: u64, size: libc::size_t, perms: u32) -> Error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> Error;
    pub fn uc_mem_protect(engine: uc_handle,
                          address: u64,
                          size: libc::size_t,
                          perms: u32)
                          -> Error;
    pub fn uc_emu_start(engine: uc_handle,
                        begin: u64,
                        until: u64,
                        timeout: u64,
                        count: libc::size_t)
                        -> Error;
    pub fn uc_emu_stop(engine: uc_handle) -> Error;
    // TODO: uc_hook_add currently only supports hookcode callbacks.
    pub fn uc_hook_add(engine: uc_handle,
                       hook: *mut uc_hook,
                       hook_type: HookType,
                       callback: extern "C" fn(uc_handle, u64, u32, *mut u64),
                       user_data: *mut libc::size_t,
                       ...)
                       -> Error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> Error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> Error;
}
