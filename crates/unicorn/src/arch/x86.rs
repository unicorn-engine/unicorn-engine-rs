use alloc::{boxed::Box, rc::Rc};
use unicorn_engine_sys::{HookType, Mode, RegisterX86, X86Insn, uc_error, uc_hook_add};

use crate::{
    UcHookId, Unicorn,
    arch::{Register, UcArch},
    hook,
};

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

impl<'a, D> Unicorn<'a, D, X86> {
    /// Add hook for x86 SYSCALL or SYSENTER.
    pub fn add_insn_sys_hook<F>(
        &mut self,
        insn_type: X86Insn,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D, X86>) + 'a,
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
                hook::insn_sys_hook_proxy::<D, F, X86> as _,
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
