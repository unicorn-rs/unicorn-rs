#![deny(rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod unicorn_const;

use crate::unicorn_const::{Arch, Error, HookType, MemRegion, Mode, Query};
use core::{fmt, slice};
use libc::{c_char, c_int, c_void};

#[allow(non_camel_case_types)]
pub type uc_handle = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_hook = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_context = libc::size_t;

extern "C" {
    pub fn uc_version(major: *mut u32, minor: *mut u32) -> u32;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> Error;
    pub fn uc_close(engine: uc_handle) -> Error;
    pub fn uc_free(mem: libc::size_t) -> Error;
    pub fn uc_errno(engine: uc_handle) -> Error;
    pub fn uc_strerror(error_code: Error) -> *const c_char;
    pub fn uc_reg_write(engine: uc_handle, regid: c_int, value: *const c_void) -> Error;
    pub fn uc_reg_read(engine: uc_handle, regid: c_int, value: *mut c_void) -> Error;
    pub fn uc_mem_write(
        engine: uc_handle,
        address: u64,
        bytes: *const u8,
        size: libc::size_t,
    ) -> Error;
    pub fn uc_mem_read(
        engine: uc_handle,
        address: u64,
        bytes: *mut u8,
        size: libc::size_t,
    ) -> Error;
    pub fn uc_mem_map(engine: uc_handle, address: u64, size: libc::size_t, perms: u32) -> Error;
    pub fn uc_mem_map_ptr(
        engine: uc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
        ptr: *mut c_void,
    ) -> Error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> Error;
    pub fn uc_mem_protect(engine: uc_handle, address: u64, size: libc::size_t, perms: u32)
        -> Error;
    pub fn uc_mem_regions(
        engine: uc_handle,
        regions: *const *const MemRegion,
        count: *mut u32,
    ) -> Error;
    pub fn uc_emu_start(
        engine: uc_handle,
        begin: u64,
        until: u64,
        timeout: u64,
        count: libc::size_t,
    ) -> Error;
    pub fn uc_emu_stop(engine: uc_handle) -> Error;
    pub fn uc_hook_add(
        engine: uc_handle,
        hook: *mut uc_hook,
        hook_type: HookType,
        callback: libc::size_t,
        user_data: *mut libc::size_t,
        begin: u64,
        end: u64,
        ...
    ) -> Error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> Error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> Error;
    pub fn uc_context_alloc(engine: uc_handle, context: *mut uc_context) -> Error;
    pub fn uc_context_save(engine: uc_handle, context: uc_context) -> Error;
    pub fn uc_context_restore(engine: uc_handle, context: uc_context) -> Error;
}

impl Error {
    pub fn msg(self) -> &'static str {
        unsafe {
            let ptr = uc_strerror(self);
            let len = libc::strlen(ptr);
            let s = slice::from_raw_parts(ptr as *const u8, len);
            // We believe that strings returned by `uc_strerror` are always valid ASCII chars.
            // Hence they also must be a valid Rust str.
            core::str::from_utf8_unchecked(s)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.msg().fmt(fmt)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
