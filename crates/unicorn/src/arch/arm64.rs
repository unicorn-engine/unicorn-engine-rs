use unicorn_engine_sys::{
    Mode, RegisterARM64, RegisterARM64CP, uc_error, uc_reg_read, uc_reg_write,
};

use crate::{
    Unicorn,
    arch::{Register, UcArch},
};

pub enum Arm64 {}

impl_arch!(Arm64, RegisterARM64, unicorn_engine_sys::Arch::ARM64);
impl_reg_pc_counter!(RegisterARM64);

// todo: find out if coprocessor functions can fail if the arch is correct
// if they are infallible, Result is not needed
impl<D> Unicorn<'_, D, Arm64> {
    /// Read ARM64 Coprocessor register
    pub fn reg_read_arm64_coproc(&self, reg: &mut RegisterARM64CP) -> Result<(), uc_error> {
        unsafe {
            uc_reg_read(
                self.get_handle(),
                RegisterARM64::CP_REG.into(),
                core::ptr::from_mut(reg).cast(),
            )
        }
        .and(Ok(()))
    }

    /// Write ARM64 Coprocessor register
    pub fn reg_write_arm64_coproc(&mut self, reg: &RegisterARM64CP) -> Result<(), uc_error> {
        unsafe {
            uc_reg_write(
                self.get_handle(),
                RegisterARM64::CP_REG.into(),
                core::ptr::from_ref(reg).cast(),
            )
        }
        .and(Ok(()))
    }
}
