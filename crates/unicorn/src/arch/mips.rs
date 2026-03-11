use unicorn_engine_sys::{Mode, RegisterMIPS};

use crate::arch::{Register, UcArch, UcResult};

pub enum Mips {}

impl_arch!(Mips, RegisterMIPS, unicorn_engine_sys::Arch::MIPS);
impl_reg_pc_counter!(RegisterMIPS);
