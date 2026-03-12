use unicorn_engine_sys::{Mode, RegisterSPARC};

use crate::arch::{Register, UcArch, UcResult};

pub enum Sparc {}

impl_arch!(Sparc, RegisterSPARC, unicorn_engine_sys::Arch::SPARC);
impl_reg_pc_counter!(RegisterSPARC);
