use unicorn_engine_sys::{Mode, RegisterX86, uc_error};

use crate::arch::{Register, UcArch};

pub enum X86 {}

impl_arch!(X86, RegisterX86, unicorn_engine_sys::Arch::X86);

impl Register for RegisterX86 {
    fn id(self) -> i32 {
        self as i32
    }

    fn pc(mode: Mode) -> Result<Self, uc_error> {
        match mode {
            Mode::MODE_16 => Ok(RegisterX86::IP as _),
            Mode::MODE_32 => Ok(RegisterX86::EIP as _),
            Mode::MODE_64 => Ok(RegisterX86::RIP as _),
            _ => Err(uc_error::ARCH),
        }
    }
}
