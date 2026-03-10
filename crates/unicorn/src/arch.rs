use unicorn_engine_sys::{Mode, uc_error};

// 'static bound here so we don't need to repeat it in functions that accept callbacks
// Arch is an empty enum, so it's trivially 'static
pub trait UcArch: 'static {
    type Reg: Register;

    fn arch() -> unicorn_engine_sys::Arch;
}

pub trait Register: Copy {
    fn id(self) -> i32;

    // todo: make Mode a generic parameter, so Result return type isn't needed
    fn pc(mode: Mode) -> Result<Self, uc_error>;
}

#[macro_export]
macro_rules! impl_arch {
    ($name:path, $reg:path, $arch:path) => {
        impl UcArch for $name {
            type Reg = $reg;

            fn arch() -> unicorn_engine_sys::Arch {
                $arch
            }
        }
    };
}

#[macro_export]
macro_rules! impl_reg_pc_counter {
    ($reg:path) => {
        impl Register for $reg {
            fn id(self) -> i32 {
                self as i32
            }

            fn pc(_: Mode) -> Result<Self, uc_error> {
                Ok(Self::PC)
            }
        }
    };
}

#[cfg(feature = "arch_arm")]
pub mod arm;
#[cfg(feature = "arch_arm")]
pub use arm::Arm;

#[cfg(feature = "arch_aarch64")]
pub mod arm64;
#[cfg(feature = "arch_aarch64")]
pub use arm64::Arm64;

#[cfg(feature = "arch_m68k")]
pub mod m68k;
#[cfg(feature = "arch_m68k")]
pub use m68k::M68K;

#[cfg(feature = "arch_mips")]
pub mod mips;
#[cfg(feature = "arch_mips")]
pub use mips::Mips;

#[cfg(feature = "arch_ppc")]
pub mod ppc;
#[cfg(feature = "arch_ppc")]
pub use ppc::Ppc;

#[cfg(feature = "arch_riscv")]
pub mod riscv;
#[cfg(feature = "arch_riscv")]
pub use riscv::RiscV;

#[cfg(feature = "arch_s390x")]
pub mod s390x;
#[cfg(feature = "arch_s390x")]
pub use s390x::S390X;

#[cfg(feature = "arch_sparc")]
pub mod sparc;
#[cfg(feature = "arch_sparc")]
pub use sparc::Sparc;

#[cfg(feature = "arch_tricore")]
pub mod tricore;
#[cfg(feature = "arch_tricore")]
pub use tricore::Tricore;

#[cfg(feature = "arch_x86")]
pub mod x86;
#[cfg(feature = "arch_x86")]
pub use x86::X86;
