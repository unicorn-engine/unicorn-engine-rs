use unicorn_engine_sys::{Mode, RegisterARM64, uc_error};

use crate::arch::{Register, UcArch};

pub enum Arm64 {}

impl_arch!(Arm64, RegisterARM64, unicorn_engine_sys::Arch::ARM64);
impl_reg_pc_counter!(RegisterARM64);
