#![cfg_attr(not(feature = "std"), no_std)]

pub mod unicorn_const;

use core::{fmt, slice};
use libc::c_char;
use crate::unicorn_const::{Arch, MemRegion, Mode, Error, HookType, Query};

#[allow(non_camel_case_types)]
pub type uc_handle = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_hook = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_context = libc::size_t;

extern "C" {
    pub fn uc_version(major: *const u32, minor: *const u32) -> u32;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> Error;
    pub fn uc_close(engine: uc_handle) -> Error;
    pub fn uc_free(mem: libc::size_t) -> Error;
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
    pub fn uc_mem_map_ptr(engine: uc_handle,
                          address: u64,
                          size: libc::size_t,
                          perms: u32,
                          ptr: *mut libc::c_void)
                          -> Error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> Error;
    pub fn uc_mem_protect(engine: uc_handle,
                          address: u64,
                          size: libc::size_t,
                          perms: u32)
                          -> Error;
    pub fn uc_mem_regions(engine: uc_handle,
                          regions: *const *const MemRegion,
                          count: *mut u32)
                          -> Error;
    pub fn uc_emu_start(engine: uc_handle,
                        begin: u64,
                        until: u64,
                        timeout: u64,
                        count: libc::size_t)
                        -> Error;
    pub fn uc_emu_stop(engine: uc_handle) -> Error;
    pub fn uc_hook_add(engine: uc_handle,
                       hook: *mut uc_hook,
                       hook_type: HookType,
                       callback: libc::size_t,
                       user_data: *mut libc::size_t,
                       begin: u64,
                       end: u64,
                       ...)
                       -> Error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> Error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> Error;
    pub fn uc_context_alloc(engine: uc_handle, context: *mut uc_context) -> Error;
    pub fn uc_context_save(engine: uc_handle, context: uc_context) -> Error;
    pub fn uc_context_restore(engine: uc_handle, context: uc_context) -> Error;
}


impl Error {
    pub fn msg(self) -> &'static str {
        unsafe {
            let s = uc_strerror(self) as *const u8;
            core::str::from_utf8(slice::from_raw_parts(s, cstr_len(s))).unwrap_or("")
        }
    }
}

unsafe fn cstr_len(s: *const u8) -> usize {
    let mut p = s;
    while 0 != *p { p = p.add(1); }
    p as usize - s as usize
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { self.msg().fmt(fmt) }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn description(&self) -> &str { self.msg().as_bytes() }

    fn cause(&self) -> Option<&std::error::Error> { None }
}
