use unicorn_engine_sys::{Mode, RegisterARM, RegisterARMCP, uc_error, uc_reg_read, uc_reg_write};

use crate::{
    Unicorn,
    arch::{Register, UcArch},
};

pub enum Arm {}

impl_arch!(Arm, RegisterARM, unicorn_engine_sys::Arch::ARM);
impl_reg_pc_counter!(RegisterARM);

// todo: find out if coprocessor functions can fail if the arch is correct
// if they are infallible, Result is not needed
impl<D> Unicorn<'_, D, Arm> {
    /// Read ARM Coprocessor register
    pub fn reg_read_arm_coproc(&self, reg: &mut RegisterARMCP) -> Result<(), uc_error> {
        unsafe {
            uc_reg_read(
                self.get_handle(),
                RegisterARM::CP_REG.into(),
                core::ptr::from_mut(reg).cast(),
            )
        }
        .into()
    }

    /// Write ARM Coprocessor register
    pub fn reg_write_arm_coproc(&mut self, reg: &RegisterARMCP) -> Result<(), uc_error> {
        unsafe {
            uc_reg_write(
                self.get_handle(),
                RegisterARM::CP_REG.into(),
                core::ptr::from_ref(reg).cast(),
            )
        }
        .into()
    }
}
