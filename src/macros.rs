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
        pub struct $cpu<'a> {
            emu: Box<Unicorn<'a>>,
        }

        impl<'a> $cpu<'a> {
            #[$emu_instance_doc]
            pub fn new(mode: Mode) -> Result<Self> {
                let emu = Unicorn::new($arch, mode);
                match emu {
                    Ok(x) => Ok(Self { emu: x }),
                    Err(x) => Err(x),
                }
            }
        }

        impl<'a> Cpu<'a> for $cpu<'a> {
            type Reg = $reg;

            fn emu(&self) -> &Unicorn<'a> {
                &self.emu
            }
        }
    };
}

macro_rules! destructure_hook {
    ($hook_type:path, $hook:ident) => {{
        let $hook_type { unicorn, callback } = unsafe { &mut *$hook };
        (unsafe { &**unicorn }, callback)
    }};
}
