#![feature(libc)]
extern crate libc;
#[macro_use]
extern crate bitflags;

pub mod ffi;
pub mod unicorn_const;
pub mod x86_const;

use ffi::*;
pub use unicorn_const::*;
pub use x86_const::*;

pub struct Unicorn {
    handle: libc::size_t, // Opaque handle to uc_engine
}

#[allow(non_camel_case_types)]
pub type uc_handle = libc::size_t;
pub type uc_hook = libc::size_t;

pub fn version() -> (libc::size_t, libc::size_t) {
    let mut major: libc::size_t = 0;
    let mut minor: libc::size_t = 0;
    let p_major: *mut libc::size_t = &mut major;
    let p_minor: *mut libc::size_t = &mut minor;
    unsafe {
        uc_version(p_major, p_minor);
    }
    (major, minor)
}

pub fn arch_supported(arch: Arch) -> bool {
    unsafe { uc_arch_supported(arch) }
}

impl Unicorn {
    pub fn new(arch: Arch, mode: Mode) -> Option<Unicorn> {
        let mut handle: libc::size_t = 0;
        if let Error::OK = unsafe { uc_open(arch, mode, &mut handle) } {
            Some(Unicorn { handle: handle })
        } else {
            None
        }
    }

    // TODO: use Reg trait
    pub fn reg_write(&self, regid: RegisterX86, value: i32) -> Result<(), Error> {
        let p_value: *const i32 = &value;
        let err = unsafe {
            uc_reg_write(self.handle,
                         regid as libc::c_int,
                         p_value as *const libc::c_void)
        } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    // TODO: use Reg trait
    pub fn reg_read(&self, regid: RegisterX86) -> Result<i32, Error> {
        let mut value: i32 = 0;
        let p_value: *mut i32 = &mut value;
        let err = unsafe {
            uc_reg_read(self.handle,
                        regid as libc::c_int,
                        p_value as *mut libc::c_void)
        } as Error;
        if err == Error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    pub fn mem_map(&self,
                   address: u64,
                   size: libc::size_t,
                   perms: Protection)
                   -> Result<(), Error> {
        let err = unsafe { uc_mem_map(self.handle, address, size, perms.bits()) } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_unmap(&self, address: u64, size: libc::size_t) -> Result<(), Error> {
        let err = unsafe { uc_mem_unmap(self.handle, address, size) } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_write(&self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        let err = unsafe {
            uc_mem_write(self.handle,
                         address,
                         bytes.as_ptr(),
                         bytes.len() as libc::size_t)
        } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_read(&self, address: u64, size: usize) -> Result<(Vec<u8>), Error> {
        let mut bytes: Vec<u8> = Vec::with_capacity(size);
        let err = unsafe {
            uc_mem_read(self.handle,
                        address,
                        bytes.as_mut_ptr(),
                        size as libc::size_t)
        } as Error;
        if err == Error::OK {
            unsafe {
                bytes.set_len(size);
            }
            Ok((bytes))
        } else {
            Err(err)
        }
    }

    pub fn mem_protect(&self, address: u64, size: usize, perms: Protection) -> Result<(), Error> {
        let err = unsafe {
            uc_mem_protect(self.handle, address, size as libc::size_t, perms.bits())
        } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn emu_start(&self,
                     begin: u64,
                     until: u64,
                     timeout: u64,
                     count: usize)
                     -> Result<(), Error> {
        let err = unsafe {
            uc_emu_start(self.handle, begin, until, timeout, count as libc::size_t)
        } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn emu_stop(&self) -> Result<(), Error> {
        let err = unsafe { uc_emu_stop(self.handle) } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }
    pub fn add_code_hook(&self,
                         hook_type: HookType,
                         callback: extern "C" fn(uc_handle, u64, u32, *mut u64))
                         -> Result<uc_hook, Error> {
        let mut hook: libc::size_t = 0;
        let mut user_data: libc::size_t = 0;
        let p_hook: *mut libc::size_t = &mut hook;
        let p_user_data: *mut libc::size_t = &mut user_data;

        let err = unsafe {
            uc_hook_add(self.handle, p_hook, hook_type, callback, p_user_data)
        } as Error;
        if err == Error::OK {
            Ok(hook)
        } else {
            Err(err)
        }
    }

    pub fn hook_del(&self, hook: uc_hook) -> Result<(), Error> {
        let err = unsafe { uc_hook_del(self.handle, hook) } as Error;
        if err == Error::OK {
            Ok(())
        } else {
            Err(err)
        }

    }

    pub fn errno(&self) -> Error {
        unsafe { uc_errno(self.handle) }
    }
}

impl Drop for Unicorn {
    fn drop(&mut self) {
        unsafe { uc_close(self.handle) };
    }
}
