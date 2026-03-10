use unicorn_engine_sys::{Mode, RegisterSPARC, uc_error};

use crate::arch::{Register, UcArch};

pub enum Sparc {}

impl_arch!(Sparc, RegisterSPARC, unicorn_engine_sys::Arch::SPARC);
impl_reg_pc_counter!(RegisterSPARC);
