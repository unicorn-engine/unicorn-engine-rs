use unicorn_engine_sys::{Mode, RegisterTRICORE, uc_error};

use crate::arch::{Register, UcArch};

pub enum Tricore {}

impl_arch!(Tricore, RegisterTRICORE, unicorn_engine_sys::Arch::TRICORE);
impl_reg_pc_counter!(RegisterTRICORE);
