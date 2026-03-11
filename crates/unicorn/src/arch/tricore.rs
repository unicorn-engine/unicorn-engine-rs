use unicorn_engine_sys::{Mode, RegisterTRICORE};

use crate::arch::{Register, UcArch, UcResult};

pub enum Tricore {}

impl_arch!(Tricore, RegisterTRICORE, unicorn_engine_sys::Arch::TRICORE);
impl_reg_pc_counter!(RegisterTRICORE);
