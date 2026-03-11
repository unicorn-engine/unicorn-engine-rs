pub mod long_register;

use alloc::{boxed::Box, rc::Rc};
use unicorn_engine_sys::{
    Arm64Insn, HookType, Mode, RegisterARM64, RegisterARM64CP, uc_error, uc_hook_add, uc_reg_read,
    uc_reg_write,
};

use crate::{
    UcHookId, Unicorn,
    arch::{Register, UcArch},
    hook,
};

pub enum Arm64 {}

impl_arch!(Arm64, RegisterARM64, unicorn_engine_sys::Arch::ARM64);
impl_reg_pc_counter!(RegisterARM64);

// todo: find out if coprocessor functions can fail if the arch is correct
// if they are infallible, Result is not needed
impl<'a, D> Unicorn<'a, D, Arm64> {
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

    /// Add hook for ARM MRS/MSR/SYS/SYSL instructions.
    ///
    /// If the callback returns true, the read/write to system registers would be skipped (even
    /// though that may cause exceptions!). Note one callback per instruction is allowed.
    pub fn add_insn_sys_hook<F>(
        &mut self,
        insn_type: Arm64Insn,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D, Arm64>, RegisterARM64, &RegisterARM64CP) -> bool + 'a,
    {
        let mut hook_id = 0;
        let mut user_data = Box::new(hook::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            uc_hook_add(
                self.get_handle(),
                (&raw mut hook_id).cast(),
                HookType::INSN.0 as i32,
                hook::insn_sys_hook_proxy_arm64::<D, F, Arm64> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                begin,
                end,
                insn_type,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }
}
