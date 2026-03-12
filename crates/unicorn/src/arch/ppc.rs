use unicorn_engine_sys::{Mode, RegisterPPC};

use crate::arch::{Register, UcArch, UcResult};

pub enum Ppc {}

impl_arch!(Ppc, RegisterPPC, unicorn_engine_sys::Arch::PPC);
impl_reg_pc_counter!(RegisterPPC);
