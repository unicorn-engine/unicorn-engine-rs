use thiserror::Error;
use unicorn_engine_sys::uc_error;

pub type UcResult<T> = Result<T, UcError>;

// descriptions taken from unicorn.h, not sure if mapping error description is good enough
#[derive(Error, Debug, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub enum UcError {
    #[error("out of memory")]
    NoMemory,

    #[error("unsupported architecture")]
    UnsupportedArchitecture,

    #[error("invalid handle")]
    InvalidHandle,

    #[error("invalid or unsupported mode")]
    InvalidMode,

    #[error("unsupported version")]
    UnsupportedVersion,

    #[error("read from unmapped memory")]
    ReadUnmapped,

    #[error("write to unmapped memory")]
    WriteUnmapped,

    #[error("fetch from unmapped memory")]
    FetchUnmapped,

    #[error("invalid hook type")]
    InvalidHook,

    #[error("invalid instruction")]
    InvalidInstruction,

    #[error("invalid memory mapping")]
    InvalidMap,

    #[error("write protection violation")]
    WriteProt,

    #[error("read protection violation")]
    ReadProt,

    #[error("fetch protection violation")]
    FetchProt,

    #[error("invalid argument")]
    InvalidArgument,

    #[error("unaligned read")]
    UnalignedRead,

    #[error("unaligned write")]
    UnalignedWrite,

    #[error("unaligned fetch")]
    UnalignedFetch,

    #[error("hook for this event already exists")]
    DuplicateHook,

    #[error("insufficient resource")]
    NoResource,

    #[error("unhandled CPU exception")]
    CpuException,

    #[error("provided buffer is not large enough")]
    Overflow,

    #[error("TLB fill hook returned false for read access")]
    MmuRead,

    #[error("TLB fill hook returned false for write access")]
    MmuWrite,

    #[error("TLB fill hook returned false for fetch")]
    MmuFetch,
}

pub trait RawUcErrorExt: Sized {
    fn result(self) -> Result<(), UcError>;

    fn result_with<T>(self, value: T) -> Result<T, UcError> {
        self.result().map(|()| value)
    }
}

// try trait is unstable, sad
impl RawUcErrorExt for uc_error {
    fn result(self) -> Result<(), UcError> {
        match self {
            uc_error::OK => Ok(()),
            uc_error::NOMEM => Err(UcError::NoMemory),
            uc_error::ARCH => Err(UcError::UnsupportedArchitecture),
            uc_error::HANDLE => Err(UcError::InvalidHandle),
            uc_error::MODE => Err(UcError::InvalidMode),
            uc_error::VERSION => Err(UcError::UnsupportedVersion),
            uc_error::READ_UNMAPPED => Err(UcError::ReadUnmapped),
            uc_error::WRITE_UNMAPPED => Err(UcError::WriteUnmapped),
            uc_error::FETCH_UNMAPPED => Err(UcError::FetchUnmapped),
            uc_error::HOOK => Err(UcError::InvalidHook),
            uc_error::INSN_INVALID => Err(UcError::InvalidInstruction),
            uc_error::MAP => Err(UcError::InvalidMap),
            uc_error::WRITE_PROT => Err(UcError::WriteProt),
            uc_error::READ_PROT => Err(UcError::ReadProt),
            uc_error::FETCH_PROT => Err(UcError::FetchProt),
            uc_error::ARG => Err(UcError::InvalidArgument),
            uc_error::READ_UNALIGNED => Err(UcError::UnalignedRead),
            uc_error::WRITE_UNALIGNED => Err(UcError::UnalignedWrite),
            uc_error::FETCH_UNALIGNED => Err(UcError::UnalignedFetch),
            uc_error::HOOK_EXIST => Err(UcError::DuplicateHook),
            uc_error::RESOURCE => Err(UcError::NoResource),
            uc_error::EXCEPTION => Err(UcError::CpuException),
            uc_error::OVERFLOW => Err(UcError::Overflow),
            uc_error::MMU_READ => Err(UcError::MmuRead),
            uc_error::MMU_WRITE => Err(UcError::MmuWrite),
            uc_error::MMU_FETCH => Err(UcError::MmuFetch),
        }
    }
}

pub trait RawUcResultExt<T>: Sized {
    fn result(self) -> Result<T, UcError>;
}

impl<T> RawUcResultExt<T> for Result<T, uc_error> {
    fn result(self) -> Result<T, UcError> {
        self.map_err(|e| {
            e.result()
                .expect_err("error variant of Result<T, uc_error> can't have OK value")
        })
    }
}
