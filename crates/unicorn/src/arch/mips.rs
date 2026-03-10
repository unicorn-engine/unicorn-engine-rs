use unicorn_engine_sys::{Mode, RegisterMIPS, uc_error};

use crate::arch::{Register, UcArch};

pub enum Mips {}

impl_arch!(Mips, RegisterMIPS, unicorn_engine_sys::Arch::MIPS);
impl_reg_pc_counter!(RegisterMIPS);
