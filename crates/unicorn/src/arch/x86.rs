use alloc::{boxed::Box, rc::Rc};
use unicorn_engine_sys::{
    HookType, Mode, RegisterX86, X86Insn, uc_error, uc_hook_add, uc_reg_read,
};

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

    /// Add hook for x86 IN instruction.
    pub fn add_insn_in_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D, X86>, u32, usize) -> u32 + 'a,
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
                hook::insn_in_hook_proxy::<D, F, X86> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                0,
                0,
                X86Insn::IN,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 OUT instruction.
    pub fn add_insn_out_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D, X86>, u32, usize, u32) + 'a,
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
                hook::insn_out_hook_proxy::<D, F, X86> as _,
                core::ptr::from_mut(user_data.as_mut()).cast(),
                0,
                0,
                X86Insn::OUT,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    fn value_size(curr_reg_id: i32) -> Result<usize, uc_error> {
        match curr_reg_id {
            r if (RegisterX86::XMM0 as i32..=RegisterX86::XMM31 as i32).contains(&r) => Ok(16),
            r if (RegisterX86::YMM0 as i32..=RegisterX86::YMM31 as i32).contains(&r) => Ok(32),
            r if (RegisterX86::ZMM0 as i32..=RegisterX86::ZMM31 as i32).contains(&r) => Ok(64),
            r if r == RegisterX86::GDTR as i32
                || r == RegisterX86::IDTR as i32
                || (RegisterX86::ST0 as i32..=RegisterX86::ST7 as i32).contains(&r) =>
            {
                Ok(10)
            }
            _ => Err(uc_error::ARG),
        }
    }

    /// Read 128, 256 or 512 bit register value into heap allocated byte array.
    ///
    /// This adds safe support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM, ST
    // todo: reg should be limited to large registers only
    pub fn reg_read_long(&self, reg: RegisterX86) -> Result<Box<[u8]>, uc_error> {
        let curr_reg_id = reg.id();

        let value_size = Self::value_size(curr_reg_id)?;
        let mut value = vec![0; value_size];
        unsafe { uc_reg_read(self.get_handle(), curr_reg_id, value.as_mut_ptr().cast()) }
            .and_then(|| Ok(value.into_boxed_slice()))
    }
}
