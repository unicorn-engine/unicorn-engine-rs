#![allow(non_camel_case_types)]

use core::ffi::c_void;

pub use unicorn_engine_sys::{self as sys, uc_context, uc_engine, uc_hook};

use crate::HookContext;

pub struct UcHook<'a, D: 'a, F: 'a> {
    pub callback: F,
    // No value of `D` is stored in the hook. This marker keeps the `D`
    // type parameter and callback lifetime visible to the type system
    // while hook storage is erased behind `IsUcHook`.
    pub marker: core::marker::PhantomData<&'a D>,
}

pub trait IsUcHook<'a> {}

impl<'a, D, F> IsUcHook<'a> for UcHook<'a, D, F> {}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub extern "C" fn mmio_read_callback_proxy<D, F>(
    uc: *mut uc_engine,
    offset: u64,
    size: u32,
    // user_data: *mut UcHook<D, F>,
    user_data: *mut c_void,
) -> u64
where
    F: FnMut(&mut HookContext, u64, usize) -> u64,
{
    let user_data = unsafe { &mut *user_data.cast::<UcHook<D, F>>() };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, offset, size as usize)
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn mmio_write_callback_proxy<D, F>(
    uc: *mut uc_engine,
    offset: u64,
    size: u32,
    value: u64,
    user_data: *mut c_void,
) where
    F: FnMut(&mut HookContext, u64, usize, u64),
{
    let user_data = unsafe { &mut *user_data.cast::<UcHook<D, F>>() };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, offset, size as usize, value);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn code_hook_proxy<D, F>(
    uc: *mut uc_engine,
    address: u64,
    size: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut HookContext, u64, u32),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, address, size);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn block_hook_proxy<D, F>(
    uc: *mut uc_engine,
    address: u64,
    size: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut HookContext, u64, u32),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, address, size);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn mem_hook_proxy<D, F>(
    uc: *mut uc_engine,
    mem_type: sys::MemType,
    address: u64,
    size: u32,
    value: i64,
    user_data: *mut UcHook<D, F>,
) -> bool
where
    F: FnMut(&mut HookContext, sys::MemType, u64, usize, i64) -> bool,
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, mem_type, address, size as usize, value)
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn intr_hook_proxy<D, F>(
    uc: *mut uc_engine,
    value: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut HookContext, u32),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, value);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn insn_in_hook_proxy<D, F>(
    uc: *mut uc_engine,
    port: u32,
    size: usize,
    user_data: *mut UcHook<D, F>,
) -> u32
where
    F: FnMut(&mut HookContext, u32, usize) -> u32,
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, port, size)
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn insn_invalid_hook_proxy<D, F>(
    uc: *mut uc_engine,
    user_data: *mut UcHook<D, F>,
) -> bool
where
    F: FnMut(&mut HookContext) -> bool,
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context)
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn insn_out_hook_proxy<D, F>(
    uc: *mut uc_engine,
    port: u32,
    size: usize,
    value: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut HookContext, u32, usize, u32),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, port, size, value);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn insn_sys_hook_proxy<D, F>(uc: *mut uc_engine, user_data: *mut UcHook<D, F>)
where
    F: FnMut(&mut HookContext),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
#[cfg(feature = "arch_aarch64")]
pub unsafe extern "C" fn insn_sys_hook_proxy_arm64<D, F>(
    uc: *mut uc_engine,
    reg: sys::RegisterARM64,
    cp_reg: *const sys::RegisterARM64CP,
    user_data: *mut UcHook<D, F>,
) -> bool
where
    F: FnMut(&mut HookContext, sys::RegisterARM64, &sys::RegisterARM64CP) -> bool,
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    let cp_reg = unsafe { cp_reg.as_ref() }.unwrap();
    (user_data.callback)(&mut context, reg, cp_reg)
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn tlb_lookup_hook_proxy<D, F>(
    uc: *mut uc_engine,
    vaddr: u64,
    mem_type: sys::MemType,
    result: *mut sys::TlbEntry,
    user_data: *mut UcHook<D, F>,
) -> bool
where
    F: FnMut(&mut HookContext, u64, sys::MemType) -> Option<sys::TlbEntry>,
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    let r = (user_data.callback)(&mut context, vaddr, mem_type);
    if let Some(ref e) = r {
        let ref_result: &mut sys::TlbEntry = unsafe { &mut *result };
        *ref_result = *e;
    }
    r.is_some()
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn tcg_proxy<D, F>(
    uc: *mut uc_engine,
    addr: u64,
    arg1: u64,
    arg2: u64,
    size: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut HookContext, u64, u64, u64, usize),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, addr, arg1, arg2, size as usize);
}

/// # Safety
///
/// This function is unsafe because it dereferences the `user_data` pointer.
pub unsafe extern "C" fn edge_gen_hook_proxy<D, F>(
    uc: *mut uc_engine,
    cur_tb: *mut sys::TranslationBlock,
    prev_tb: *mut sys::TranslationBlock,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut HookContext, &mut sys::TranslationBlock, &mut sys::TranslationBlock),
{
    let user_data = unsafe { &mut *user_data };
    let mut context = HookContext::from_handle(uc);
    (user_data.callback)(&mut context, unsafe { &mut *cur_tb }, unsafe {
        &mut *prev_tb
    });
}
