use unicorn_engine_sys::{Mode, RegisterRISCV};

use crate::arch::{Register, UcArch, UcResult};

pub enum RiscV {}

impl_arch!(RiscV, RegisterRISCV, unicorn_engine_sys::Arch::RISCV);
impl_reg_pc_counter!(RegisterRISCV);
