use unicorn_engine_sys::{Mode, RegisterRISCV, uc_error};

use crate::arch::{Register, UcArch};

pub enum RiscV {}

impl_arch!(RiscV, RegisterRISCV, unicorn_engine_sys::Arch::RISCV);
impl_reg_pc_counter!(RegisterRISCV);
