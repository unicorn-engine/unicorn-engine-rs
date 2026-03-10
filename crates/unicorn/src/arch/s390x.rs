use unicorn_engine_sys::{Mode, RegisterS390X, uc_error};

use crate::arch::{Register, UcArch};

pub enum S390X {}

impl_arch!(S390X, RegisterS390X, unicorn_engine_sys::Arch::S390X);
impl_reg_pc_counter!(RegisterS390X);
