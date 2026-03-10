use unicorn_engine_sys::{Mode, RegisterM68K, uc_error};

use crate::arch::{Register, UcArch};

pub enum M68K {}

impl_arch!(M68K, RegisterM68K, unicorn_engine_sys::Arch::M68K);
impl_reg_pc_counter!(RegisterM68K);
