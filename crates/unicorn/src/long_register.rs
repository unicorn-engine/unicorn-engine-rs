use unicorn_engine_sys::{uc_reg_read, uc_reg_write};

use crate::{RawUcErrorExt, Register, UcArch, Unicorn};

// generic_const_exprs are unstable, so we have to be generic over a constant here and not use an associated constant
pub trait LongRegister<const SIZE: usize>: Copy {
    type Arch: UcArch;

    fn reg(self) -> <Self::Arch as UcArch>::Reg;
}

impl<D, A: UcArch> Unicorn<'_, D, A> {
    /// Read variable sized register.
    ///
    /// This adds safe support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM, ST (x86); Q, V
    /// (arm64)).
    pub fn reg_read_long<const N: usize, T: LongRegister<N, Arch = A>>(&self, long: T) -> [u8; N] {
        let curr_reg_id = long.reg().id();

        let mut value = [0; N];
        unsafe { uc_reg_read(self.get_handle(), curr_reg_id, value.as_mut_ptr().cast()) }
            .result()
            .expect("read of a valid register should never fail");
        value
    }

    /// Write variable sized values into registers.
    ///
    /// This adds support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_write_long<const N: usize, T: LongRegister<N, Arch = A>>(
        &self,
        long: T,
        value: [u8; N],
    ) {
        unsafe { uc_reg_write(self.get_handle(), long.reg().id(), value.as_ptr().cast()) }
            .result()
            .expect("write to a valid register should never fail");
    }
}

#[macro_export]
macro_rules! mk_long_regs {
    ($name:ident, $arch:path, $size:literal, $($reg:ident),*) => {
        #[derive(Debug, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
        pub enum $name {
            $($reg),*
        }

        impl LongRegister<$size> for $name {
            type Arch = $arch;

            fn reg(self) -> <Self::Arch as UcArch>::Reg {
                match self {
                     $($name::$reg => <Self::Arch as UcArch>::Reg::$reg),*
                }
        }
    }
    };
}
