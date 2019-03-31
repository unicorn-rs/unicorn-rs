macro_rules! implement_register {
    ($reg_arch:ty) => {
        impl Register for $reg_arch {
            fn to_i32(&self) -> i32 {
                *self as i32
            }
        }
    };
}

macro_rules! implement_emulator {
    ($emu_type_doc:meta, $emu_instance_doc:meta, $cpu:ident, $arch:expr, $reg:ty) => {
        #[$emu_type_doc]
        pub struct $cpu {
            emu: Box<Unicorn>,
        }

        impl $cpu {
            #[$emu_instance_doc]
            pub fn new(mode: Mode) -> Result<Self> {
                let emu = Unicorn::new($arch, mode);
                match emu {
                    Ok(x) => Ok(Self { emu: x }),
                    Err(x) => Err(x),
                }
            }
        }

        impl Cpu for $cpu {
            type Reg = $reg;

            fn emu(&self) -> &Unicorn {
                &self.emu
            }

            fn mut_emu(&mut self) -> &mut Unicorn {
                &mut self.emu
            }
        }
    };
}

macro_rules! destructure_hook {
    ($hook_type:path, $hook:ident) => {{
        let $hook_type {
            unicorn,
            ref mut callback,
        } = unsafe { &mut *$hook };
        (unsafe { &**unicorn }, callback)
    }};
}
