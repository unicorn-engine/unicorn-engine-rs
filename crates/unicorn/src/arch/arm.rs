use unicorn_engine_sys::{Mode, RegisterARM, uc_error};

use crate::arch::{Register, UcArch};

pub enum Arm {}

impl_arch!(Arm, RegisterARM, unicorn_engine_sys::Arch::ARM);
impl_reg_pc_counter!(RegisterARM);
