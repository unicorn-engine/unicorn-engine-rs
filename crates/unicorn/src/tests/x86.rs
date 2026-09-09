use super::*;
use crate::{MemType, RegisterX86, TcgOpCode, TcgOpFlag, X86CpuModel, X86Insn};

const MEM_BASE: u64 = 0x4000_0000;
const MEM_SIZE: u64 = 1024 * 1024;
const MEM_STACK: u64 = MEM_BASE + (MEM_SIZE / 2);
const MEM_TEXT: u64 = MEM_STACK + 4096;

struct QuickTest<'a> {
    mode: Mode,
    code: &'a [u8],
    in_regs: &'a [(RegisterX86, u64)],
    out_regs: &'a [(RegisterX86, u64)],
}

impl QuickTest<'_> {
    fn run(&self) {
        let is_64 = self.mode == Mode::MODE_64;
        let mut uc = Unicorn::new(Arch::X86, self.mode).unwrap();

        uc.mem_map(MEM_BASE, MEM_SIZE, Prot::ALL).unwrap();
        uc.mem_write(MEM_TEXT, self.code).unwrap();

        let stack_reg = if is_64 {
            RegisterX86::RSP
        } else {
            RegisterX86::ESP
        };
        uc.reg_write(stack_reg, MEM_STACK).unwrap();

        for &(reg, value) in self.in_regs {
            let value = if is_64 { value } else { value & 0xFFFF_FFFF };
            uc.reg_write(reg, value).unwrap();
        }

        uc.emu_start(MEM_TEXT, MEM_TEXT + self.code.len() as u64, 0, 0)
            .unwrap();

        for &(reg, expected) in self.out_regs {
            let expected = if is_64 {
                expected
            } else {
                expected & 0xFFFF_FFFF
            };
            assert_eq!(uc.reg_read(reg).unwrap(), expected);
        }

        uc.mem_unmap(MEM_BASE, MEM_SIZE).unwrap();
    }
}

#[test]
fn test_x86_in() {
    let code = b"\xe5\x10"; // IN eax, 0x10

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, (0u32, 0usize));
    let hook = uc
        .add_insn_in_hook(|uc, port, size| {
            let eip = uc.reg_read(RegisterX86::EIP).unwrap();
            assert_eq!(eip, CODE_START);
            *uc.get_data_mut() = (port, size);
            0
        })
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let (port, size) = *uc.get_data();
    assert_eq!(port, 0x10);
    assert_eq!(size, 4);

    uc.remove_hook(hook).unwrap();
}

#[test]
fn test_x86_out() {
    let code = b"\xb0\x32\xe6\x46"; // MOV al, 0x32; OUT 0x46, al

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, (0u32, 0usize, 0u32));
    let hook = uc
        .add_insn_out_hook(|uc, port, size, value| {
            *uc.get_data_mut() = (port, size, value);
        })
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let (port, size, value) = *uc.get_data();
    assert_eq!(port, 0x46);
    assert_eq!(size, 1);
    assert_eq!(value, 0x32);

    uc.remove_hook(hook).unwrap();
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct MemHookResult {
    mem_type: MemType,
    address: u64,
    size: usize,
    value: i64,
}

#[test]
fn test_x86_mem_hook_all() {
    #[rustfmt::skip]
    let code = &[
        0xb8, 0xef, 0xbe, 0xad, 0xde,       // mov eax, 0xdeadbeef
        0xa3, 0x00, 0x80, 0x00, 0x00,       // mov [0x8000], eax
        0xa1, 0x00, 0x00, 0x01, 0x00,       // mov eax, [0x10000]
    ];
    let expects = [
        MemHookResult {
            mem_type: MemType::WRITE,
            address: 0x8000,
            size: 4,
            value: 0xdead_beef,
        },
        MemHookResult {
            mem_type: MemType::READ_UNMAPPED,
            address: 0x10000,
            size: 4,
            value: 0,
        },
        MemHookResult {
            mem_type: MemType::READ,
            address: 0x10000,
            size: 4,
            value: 0,
        },
    ];

    let mut uc = uc_common_setup(
        Arch::X86,
        Mode::MODE_32,
        None,
        code,
        (0usize, [None::<MemHookResult>; 16]),
    );
    uc.mem_map(0x8000, 0x1000, Prot::ALL).unwrap();

    let hook = uc
        .add_mem_hook(
            HookType::MEM_VALID | HookType::MEM_INVALID,
            1,
            0,
            |uc, mem_type, address, size, value| {
                let (count, results) = uc.get_data_mut();
                assert!(*count < results.len());
                results[*count] = Some(MemHookResult {
                    mem_type,
                    address,
                    size,
                    value,
                });
                *count += 1;

                if mem_type == MemType::READ_UNMAPPED {
                    uc.mem_map(address, 0x1000, Prot::ALL).unwrap();
                }

                true
            },
        )
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let (count, results) = uc.get_data();
    assert_eq!(*count, 3);
    for (expect, result) in expects.iter().zip(results.iter()) {
        assert_eq!(Some(*expect), *result);
    }

    uc.remove_hook(hook).unwrap();
}

#[test]
fn test_x86_inc_dec_pxor() {
    #[rustfmt::skip]
    let code = &[
        0x41,                   // inc ecx
        0x4a,                   // dec edx
        0x66, 0x0f, 0xef, 0xc1, // pxor xmm0, xmm1
    ];
    let r_xmm0 = [0x0809_0a0b_0c0d_0e0fu64, 0x0001_0203_0405_0607u64];
    let r_xmm1 = [0x8090_a0b0_c0d0_e0f0u64, 0x0010_2030_4050_6070u64];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.ctl_set_cpu_model(X86CpuModel::HASWELL as i32).unwrap();
    uc.mem_map(CODE_START, CODE_LEN, Prot::ALL).unwrap();
    uc.mem_write(CODE_START, code).unwrap();

    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();
    uc.reg_write_long(RegisterX86::XMM0, &xmm_bytes(r_xmm0))
        .unwrap();
    uc.reg_write_long(RegisterX86::XMM1, &xmm_bytes(r_xmm1))
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1235);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);

    let xmm0 = xmm_words(&uc.reg_read_long(RegisterX86::XMM0).unwrap());
    assert_eq!(xmm0[0], 0x8899_aabb_ccdd_eeff);
    assert_eq!(xmm0[1], 0x0011_2233_4455_6677);
}

fn xmm_bytes(words: [u64; 2]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&words[0].to_le_bytes());
    bytes[8..].copy_from_slice(&words[1].to_le_bytes());
    bytes
}

fn xmm_words(bytes: &[u8]) -> [u64; 2] {
    [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
    ]
}

#[test]
fn test_x86_relative_jump() {
    // jmp 4; nop; nop; nop; nop; nop; nop
    let code = b"\xeb\x02\x90\x90\x90\x90\x90\x90";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());

    uc.emu_start(CODE_START, CODE_START + 4, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EIP).unwrap(), CODE_START + 4);
}

#[test]
fn test_x86_loop() {
    let code = b"\x41\x4a\xeb\xfe"; // inc ecx; dec edx; jmp $

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 1_000_000, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1235);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);
}

#[test]
fn test_x86_invalid_mem_read() {
    let code = b"\x8b\x0d\xaa\xaa\xaa\xaa"; // mov ecx, [0xAAAAAAAA]

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::READ_UNMAPPED);
}

#[test]
fn test_x86_invalid_mem_write() {
    let code = b"\x89\x0d\xaa\xaa\xaa\xaa"; // mov [0xAAAAAAAA], ecx

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::WRITE_UNMAPPED);
}

#[test]
fn test_x86_invalid_jump() {
    let code = b"\xe9\xe9\xee\xee\xee"; // jmp 0xEEEEEEEE

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);
}

#[test]
fn test_x86_64_syscall() {
    let code = b"\x0f\x05"; // syscall

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, false);
    uc.reg_write(RegisterX86::RAX, 0x100).unwrap();
    let hook = uc
        .add_insn_sys_hook(X86Insn::SYSCALL, 1, 0, |uc| {
            assert_eq!(uc.reg_read(RegisterX86::RAX).unwrap(), 0x100);
            *uc.get_data_mut() = true;
        })
        .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert!(*uc.get_data());

    uc.remove_hook(hook).unwrap();
}

#[test]
fn test_x86_16_add() {
    let code = b"\x00\x00"; // add byte ptr [bx + si], al
    let r_bx = 5;
    let r_si = 6;

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_16, None, code, ());
    uc.mem_map(0, 0x1000, Prot::ALL).unwrap();
    uc.reg_write(RegisterX86::AX, 7).unwrap();
    uc.reg_write(RegisterX86::BX, r_bx).unwrap();
    uc.reg_write(RegisterX86::SI, r_si).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let mut result = [0u8; 1];
    uc.mem_read(r_bx + r_si, &mut result).unwrap();
    assert_eq!(result[0], 7);
}

#[test]
fn test_x86_reg_save() {
    let code = b"\x40"; // inc eax

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::EAX, 1).unwrap();

    let mut ctx = uc.context_alloc().unwrap();
    uc.context_save(&mut ctx).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EAX).unwrap(), 2);

    uc.context_restore(&ctx).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EAX).unwrap(), 1);
}

#[test]
fn test_x86_invalid_mem_read_stop_in_cb() {
    // inc eax; mov ebx, [0x100000]; inc edx
    let code = b"\x40\x8b\x1d\x00\x00\x10\x00\x42";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    // False indicates that we fail to handle this ERROR and let the emulation stop.
    uc.add_mem_hook(HookType::MEM_READ, 1, 0, |_, _, _, _, _| false)
        .unwrap();
    uc.reg_write(RegisterX86::EAX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x5678).unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::READ_UNMAPPED);

    // The state of Unicorn should be correct at this time.
    assert_eq!(uc.reg_read(RegisterX86::EIP).unwrap(), CODE_START + 1);
    assert_eq!(uc.reg_read(RegisterX86::EAX).unwrap(), 0x1235);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x5678);
}

#[test]
fn test_x86_x87_fnstenv() {
    // fnop; fnstenv [eax]; fld dword ptr [eax]; fnstenv [eax]
    let code = b"\xd9\xd0\xd9\x30\xd9\x00\xd9\x30";
    let base = CODE_START + 3 * CODE_LEN;

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, 0u32);
    uc.mem_map(base, CODE_LEN, Prot::ALL).unwrap();
    uc.reg_write(RegisterX86::EAX, base).unwrap();

    uc.add_code_hook(1, 0, move |uc, address, _| {
        if address == CODE_START + 4 {
            // The first fnstenv executed: save the address of the fld.
            let eip = uc.reg_read(RegisterX86::EIP).unwrap();
            *uc.get_data_mut() = eip as u32;

            let eax = uc.reg_read(RegisterX86::EAX).unwrap();
            // Don't update FCS:FIP for fnop.
            assert_eq!(read_fnstenv(uc, eax)[3], 0);
        }
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    // But update FCS:FIP for fld.
    let last_eip = *uc.get_data();
    assert_eq!(read_fnstenv(&uc, base)[3], last_eip);
}

fn read_fnstenv<D>(uc: &Unicorn<D>, address: u64) -> [u32; 7] {
    let mut buf = [0u8; 28];
    uc.mem_read(address, &mut buf).unwrap();
    let mut fnstenv = [0u32; 7];
    for (word, chunk) in fnstenv.iter_mut().zip(buf.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    fnstenv
}

#[test]
fn test_x86_mmio() {
    // mov [0x20004], ecx; mov ecx, [0x20004]
    let code = b"\x89\x0d\x04\x00\x02\x00\x8b\x0d\x04\x00\x02\x00";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::ECX, 0xdead_beef).unwrap();
    uc.mmio_map(
        0x20000,
        0x1000,
        Some(|_: &mut Unicorn<()>, offset, size| {
            assert_eq!(offset, 4);
            assert_eq!(size, 4);
            0x1926_0817
        }),
        Some(|_: &mut Unicorn<()>, offset, size, value| {
            assert_eq!(offset, 4);
            assert_eq!(size, 4);
            assert_eq!(value, 0xdead_beef);
        }),
    )
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1926_0817);
}

#[test]
fn test_x86_missing_code() {
    // Don't write any code by design.
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, size, _| {
        let code = b"\x41\x4a"; // inc ecx; dec edx
        let aligned_address = address & !0xfffu64;
        let aligned_size = ((size / 0x1000) + 1) * 0x1000;

        uc.mem_map(aligned_address, aligned_size as u64, Prot::ALL)
            .unwrap();
        uc.mem_write(aligned_address, code).unwrap();

        true
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + 2, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1235);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);
}

#[test]
fn test_x86_smc_xor() {
    // 0x1000 xor dword ptr [edi+0x3], eax ; edi=0x1000, eax=0xbc4177e6
    // 0x1003 dw 0x3ea98b13
    let code = b"\x31\x47\x03\x13\x8b\xa9\x3e";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::EDI, CODE_START).unwrap();
    uc.reg_write(RegisterX86::EAX, 0xbc41_77e6).unwrap();

    uc.emu_start(CODE_START, CODE_START + 3, 0, 0).unwrap();

    let mut result = [0u8; 4];
    uc.mem_read(CODE_START + 3, &mut result).unwrap();

    assert_eq!(u32::from_le_bytes(result), 0x3ea9_8b13 ^ 0xbc41_77e6);
}

#[test]
fn test_x86_smc_add() {
    // mov qword ptr [rip+0x10], rax
    // mov word ptr [rip], 0x0548
    // [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] add rax, 0x12345678
    // hlt
    let code = b"\x48\x89\x05\x10\x00\x00\x00\x66\xc7\x05\x00\x00\x00\x00\x48\
                 \x05\x8b\x80\x78\x56\x34\x12\xf4";
    let stack_base = 0x20000;

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, ());
    uc.mem_map(stack_base, 0x2000, Prot::ALL).unwrap();
    uc.reg_write(RegisterX86::RSP, stack_base + 0x1800).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 0).unwrap();
}

#[test]
fn test_x86_smc_mem_hook() {
    // mov qword ptr [rip+0x29], rax
    // mov word ptr [rip], 0x0548
    // [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] add rax, 0x12345678
    // nop; nop; nop
    // mov qword ptr [rip-0x08], rax
    // mov word ptr [rip], 0x0548
    // [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] add rax, 0x12345678
    // hlt
    let code = b"\x48\x89\x05\x29\x00\x00\x00\x66\xC7\x05\x00\x00\x00\x00\x48\x05\x8B\
                 \x80\x78\x56\x34\x12\x90\x90\x90\x48\x89\x05\xF8\xFF\xFF\xFF\x66\xC7\
                 \x05\x00\x00\x00\x00\x48\x05\x8B\x80\x78\x56\x34\x12\xF4";
    let stack_base = 0x20000;
    let write_addresses = [0x1030u64, 0x1010, 0x1010, 0x1018, 0x1018, 0x1029, 0x1029];

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, 0usize);
    uc.add_mem_hook(HookType::MEM_WRITE, 1, 0, move |uc, _, addr, _, _| {
        let i = uc.get_data_mut();
        assert!(*i < write_addresses.len());
        assert_eq!(write_addresses[*i], addr);
        *i += 1;
        true
    })
    .unwrap();
    uc.mem_map(stack_base, 0x2000, Prot::ALL).unwrap();
    uc.reg_write(RegisterX86::RSP, stack_base + 0x1800).unwrap();

    uc.emu_start(CODE_START, u64::MAX, 0, 0).unwrap();
}

#[test]
fn test_x86_mmio_uc_mem_rw() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();

    uc.mmio_map(
        0x20000,
        0x1000,
        Some(|_: &mut Unicorn<()>, offset, size| {
            assert_eq!(offset, 8);
            assert_eq!(size, 4);
            0x1926_0817
        }),
        Some(|_: &mut Unicorn<()>, offset, size, value| {
            assert_eq!(offset, 4);
            assert_eq!(size, 4);
            assert_eq!(value, 0xdead_beef);
        }),
    )
    .unwrap();

    uc.mem_write(0x20004, &0xdead_beefu32.to_le_bytes())
        .unwrap();

    let mut data = [0u8; 4];
    uc.mem_read(0x20008, &mut data).unwrap();

    assert_eq!(u32::from_le_bytes(data), 0x1926_0817);
}

#[test]
fn test_x86_sysenter() {
    let code = b"\x0F\x34"; // sysenter

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, 0u32);
    uc.add_insn_sys_hook(X86Insn::SYSENTER, 1, 0, |uc| {
        *uc.get_data_mut() += 1;
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(*uc.get_data(), 1);
}

#[test]
fn test_x86_486_cpuid() {
    let code = &[0x31, 0xC0, 0x0F, 0xA2]; // xor eax, eax; cpuid

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.ctl_set_cpu_model(X86CpuModel::Model_486 as i32).unwrap();
    uc.mem_map(0, 4 * 1024, Prot::ALL).unwrap();
    uc.mem_write(0, code).unwrap();
    uc.emu_start(0, code.len() as u64, 0, 0).unwrap();

    // Read eax after emulation
    assert_ne!(uc.reg_read(RegisterX86::EAX).unwrap(), 0);
    // magic string "Genu" for intel cpu
    assert_eq!(uc.reg_read(RegisterX86::EBX).unwrap(), 0x756e_6547);
}

// This is a regression bug.
#[test]
fn test_x86_clear_tb_cache() {
    let code = b"\x83\xc1\x01\x4a\x00"; // add ecx, 1; dec edx
    let code_start = 0x1240; // Choose this address by design
    let code_len = 0x1000;

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.mem_map(code_start & (1 << 12), code_len, Prot::ALL)
        .unwrap();
    uc.mem_write(code_start, code).unwrap();
    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();

    // This emulation should take no effect at all.
    uc.emu_start(code_start, code_start, 0, 0).unwrap();

    // Emulate ADD ecx, 1.
    uc.emu_start(code_start, code_start + 3, 0, 0).unwrap();

    // If tb cache is not cleared, edx would be still 0x7890
    uc.emu_start(code_start, code_start + code.len() as u64 - 1, 0, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1236);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);
}

#[test]
fn test_x86_clear_count_cache() {
    // uc_emu_start will clear last TB when exiting so generating a tb at last by design
    //   add ecx, 1; dec edx; jmp t; t: add ebx, 1
    let code = b"\x83\xc1\x01\x4a\xeb\x00\x83\xc3\x01";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 2)
        .unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1236);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788e);
}

// This is a regression bug.
#[test]
fn test_x86_clear_empty_tb() {
    // lb:
    //    add ecx, 1;
    //    cmp ecx, 0;
    //    jz lb;
    //    dec edx;
    let code = b"\x83\xc1\x01\x83\xf9\x00\x74\xf8\x4a\x00";
    let code_start = 0x1240; // Choose this address by design
    let code_len = 0x1000;

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.mem_map(code_start & (1 << 12), code_len, Prot::ALL)
        .unwrap();
    uc.mem_write(code_start, code).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();

    // Make sure we generate an empty tb at the exit address by stopping at dec edx.
    uc.emu_start(code_start, code_start + 8, 0, 0).unwrap();

    // If tb cache is not cleared, edx would be still 0x7890
    uc.emu_start(code_start, code_start + code.len() as u64 - 1, 0, 0)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);
}

#[test]
fn test_x86_hook_tcg_op() {
    #[rustfmt::skip]
    let code = &[
        0x2b, 0x35, 0x00, 0x10, 0x00, 0x00, // sub esi, [0x1000]
        0x29, 0xd8,                         // sub eax, ebx
        0x83, 0xe8, 0x01,                   // sub eax, 1
        0x83, 0xf8, 0x00,                   // cmp eax, 0
        0x39, 0xd3,                         // cmp ebx, edx
        0x3b, 0x35, 0x00, 0x10, 0x00, 0x00, // cmp esi, [0x1000]
    ];

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, 0usize);
    uc.reg_write(RegisterX86::EAX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EBX, 2).unwrap();

    for (flag, expected) in [
        (TcgOpFlag(0), 6),
        (TcgOpFlag::DIRECT, 3),
        (TcgOpFlag::CMP, 3),
    ] {
        *uc.get_data_mut() = 0;
        let hook = uc
            .add_tcg_hook(TcgOpCode::SUB, flag, 0, u64::MAX, |uc, _, _, _, _| {
                *uc.get_data_mut() += 1;
            })
            .unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();
        uc.remove_hook(hook).unwrap();

        assert_eq!(*uc.get_data(), expected);
    }
}

#[test]
fn test_x86_cmpxchg() {
    let code = b"\x0F\xC7\x0D\xE0\xBE\xAD\xDE"; // cmpxchg8b [0xdeadbee0]
    let r_aaaa = 0x4141_4141;

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, 0u8);
    uc.mem_map(0xdeadb000, 0x1000, Prot::ALL).unwrap();
    uc.add_mem_hook(
        HookType::MEM_READ | HookType::MEM_WRITE,
        1,
        0,
        |uc, mem_type, _, _, _| {
            *uc.get_data_mut() |= if mem_type == MemType::READ { 1 } else { 2 };
            true
        },
    )
    .unwrap();

    uc.reg_write(RegisterX86::EDX, 0).unwrap();
    uc.reg_write(RegisterX86::EAX, 0).unwrap();
    uc.reg_write(RegisterX86::ECX, r_aaaa).unwrap();
    uc.reg_write(RegisterX86::EBX, r_aaaa).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let mut mem = [0u8; 8];
    uc.mem_read(0xdeadbee0, &mut mem).unwrap();

    assert_eq!(u64::from_le_bytes(mem), 0x4141_4141_4141_4141);

    // Both read and write happened.
    assert_eq!(*uc.get_data(), 3);
}

#[test]
fn test_x86_nested_emu_start() {
    let code = b"\x41\x4a"; // inc ecx; dec edx

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();
    // Emulate DEC in the nested hook.
    uc.add_code_hook(CODE_START, CODE_START, |uc, _, _| {
        uc.emu_start(CODE_START + 1, CODE_START + 2, 0, 0).unwrap();
    })
    .unwrap();

    // Emulate INC
    uc.emu_start(CODE_START, CODE_START + 1, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1235);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);
}

#[test]
fn test_x86_nested_emu_stop() {
    let code = b"\x41\x4a\x4a"; // inc ecx; dec edx; dec edx

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.reg_write(RegisterX86::ECX, 0x1234).unwrap();
    uc.reg_write(RegisterX86::EDX, 0x7890).unwrap();
    // Emulate DEC in the nested hook.
    uc.add_code_hook(CODE_START, CODE_START, |uc, _, _| {
        uc.emu_start(CODE_START + 1, CODE_START + 2, 0, 0).unwrap();
        // ecx shouldn't be changed!
        uc.emu_stop().unwrap();
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + 3, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::ECX).unwrap(), 0x1234);
    assert_eq!(uc.reg_read(RegisterX86::EDX).unwrap(), 0x788f);
}

#[test]
fn test_x86_64_nested_emu_start_error() {
    // nop; nop; mov rax, [0x10000]
    let code = b"\x90\x90\x48\xa1\x00\x00\x01\x00\x00\x00\x00\x00";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, ());
    uc.add_code_hook(CODE_START, CODE_START, |uc, _, _| {
        let err = uc.emu_start(CODE_START + 2, 0, 0, 0).unwrap_err();
        assert_eq!(err, uc_error::READ_UNMAPPED);
    })
    .unwrap();

    // This call shouldn't fail!
    uc.emu_start(CODE_START, CODE_START + 2, 0, 0).unwrap();
}

#[test]
fn test_x86_eflags_reserved_bit() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();

    let r_eflags = uc.reg_read(RegisterX86::EFLAGS).unwrap();
    assert_ne!(r_eflags & 2, 0);

    uc.reg_write(RegisterX86::EFLAGS, r_eflags).unwrap();

    let r_eflags = uc.reg_read(RegisterX86::EFLAGS).unwrap();
    assert_ne!(r_eflags & 2, 0);
}

#[test]
fn test_x86_nested_uc_emu_start_exits() {
    //  cmp eax, 0
    //  jnz t
    //  nop <-- nested emu_start
    // t:mov dword ptr [eax], 0
    let code = b"\x83\xf8\x00\x75\x01\x90\xc7\x00\x00\x00\x00\x00";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.add_code_hook(CODE_START, CODE_START, |uc, _, _| {
        uc.emu_start(CODE_START + 5, CODE_START + 6, 0, 0).unwrap();
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + 5, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EIP).unwrap(), CODE_START + 5);
}

#[test]
fn test_x86_correct_address_in_small_jump_hook() {
    // movabs $0x7F00, %rax; jmp *%rax
    let code = b"\x48\xb8\x00\x7F\x00\x00\x00\x00\x00\x00\xff\xe0";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, ());
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, _, _| {
        // Check registers
        assert_eq!(uc.reg_read(RegisterX86::RAX).unwrap(), 0x7F00);
        assert_eq!(uc.reg_read(RegisterX86::RIP).unwrap(), 0x7F00);
        // Check address
        assert_eq!(address, 0x7F00);

        false
    })
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    assert_eq!(uc.reg_read(RegisterX86::RAX).unwrap(), 0x7F00);
    assert_eq!(uc.reg_read(RegisterX86::RIP).unwrap(), 0x7F00);
}

#[test]
fn test_x86_correct_address_in_long_jump_hook() {
    // movabs $0x7FFFFFFFFFFFFF00, %rax; jmp *%rax
    let code = b"\x48\xb8\x00\xff\xff\xff\xff\xff\xff\x7f\xff\xe0";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, ());
    uc.ctl_set_tlb_type(TlbType::VIRTUAL).unwrap();
    uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _, address, _, _| {
        // Check registers
        assert_eq!(
            uc.reg_read(RegisterX86::RAX).unwrap(),
            0x7FFF_FFFF_FFFF_FF00
        );
        assert_eq!(
            uc.reg_read(RegisterX86::RIP).unwrap(),
            0x7FFF_FFFF_FFFF_FF00
        );
        // Check address
        assert_eq!(address, 0x7FFF_FFFF_FFFF_FF00);

        false
    })
    .unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::FETCH_UNMAPPED);

    assert_eq!(
        uc.reg_read(RegisterX86::RAX).unwrap(),
        0x7FFF_FFFF_FFFF_FF00
    );
    assert_eq!(
        uc.reg_read(RegisterX86::RIP).unwrap(),
        0x7FFF_FFFF_FFFF_FF00
    );
}

#[test]
fn test_x86_invalid_vex_l() {
    let code = &[0xC5, 0xFE, 0x6F, 0x09]; // vmovdqu ymm1, [rcx]

    // initialize memory and run emulation
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    uc.mem_map(0, 2 * 1024 * 1024, Prot::ALL).unwrap();
    uc.mem_write(0, code).unwrap();

    let err = uc.emu_start(0, code.len() as u64, 0, 0).unwrap_err();
    assert_eq!(err, uc_error::INSN_INVALID);
}

// AARCH64 inlines the read while s390x won't split the access. Mirrors the
// `!defined(TARGET_READ_INLINED) && defined(BOOST_LITTLE_ENDIAN)` guard in
// tests/unit/test_x86.c: upstream sets TARGET_READ_INLINED for aarch64 and ppc hosts.
#[cfg(all(
    target_endian = "little",
    not(any(
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    ))
))]
mod unaligned {
    use super::*;

    type WriteLog = [(u64, usize); 10];

    fn log_access(log: &mut WriteLog, address: u64, size: usize) {
        assert_ne!(size, 0);
        for entry in log.iter_mut() {
            if entry.1 == 0 {
                *entry = (address, size);
                return;
            }
        }
        panic!("write log overflow");
    }

    #[test]
    fn test_x86_unaligned_access() {
        // mov dword ptr [0x200001], eax; mov eax, dword ptr [0x200001]
        let code = b"\xa3\x01\x00\x20\x00\xa1\x01\x00\x20\x00";

        let mut uc = uc_common_setup(
            Arch::X86,
            Mode::MODE_32,
            None,
            code,
            ([(0u64, 0usize); 10], [(0u64, 0usize); 10]),
        );
        uc.mem_map(0x200000, 0x1000, Prot::ALL).unwrap();
        uc.add_mem_hook(HookType::MEM_WRITE, 1, 0, |uc, _, address, size, _| {
            log_access(&mut uc.get_data_mut().0, address, size);
            true
        })
        .unwrap();
        uc.add_mem_hook(HookType::MEM_READ, 1, 0, |uc, _, address, size, _| {
            log_access(&mut uc.get_data_mut().1, address, size);
            true
        })
        .unwrap();

        uc.reg_write(RegisterX86::EAX, 0x4142_4344).unwrap();
        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
            .unwrap();

        let (write_log, read_log) = uc.get_data();
        assert_eq!(write_log[0], (0x200001, 4));
        assert_eq!(write_log[1].1, 0);
        assert_eq!(read_log[0], (0x200001, 4));
        assert_eq!(read_log[1].1, 0);

        for (offset, expected) in [(1, 0x44), (2, 0x43), (3, 0x42), (4, 0x41)] {
            let mut b = [0u8; 1];
            uc.mem_read(0x200000 + offset, &mut b).unwrap();
            assert_eq!(b[0], expected);
        }
    }

    #[test]
    fn test_x86_64_unaligned_access() {
        #[rustfmt::skip]
        let code = &[
            0x48, 0x89, 0x01, // mov qword ptr [rcx], rax
            0x48, 0x8b, 0x00, // mov rax, qword ptr [rax]
            0xcc,             // int3
        ];

        let mut uc = uc_common_setup(
            Arch::X86,
            Mode::MODE_64,
            None,
            code,
            ([(0u64, 0usize); 10], [(0u64, 0usize); 10]),
        );
        uc.mem_map(0x200000, 0x200000, Prot::ALL).unwrap();
        uc.add_mem_hook(HookType::MEM_WRITE, 1, 0, |uc, _, address, size, _| {
            log_access(&mut uc.get_data_mut().0, address, size);
            true
        })
        .unwrap();
        uc.add_mem_hook(HookType::MEM_READ, 1, 0, |uc, _, address, size, _| {
            log_access(&mut uc.get_data_mut().1, address, size);
            true
        })
        .unwrap();

        uc.reg_write(RegisterX86::RAX, 0x2fffff).unwrap();
        uc.reg_write(RegisterX86::RCX, 0x2fffff).unwrap();

        uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 2)
            .unwrap();

        let (write_log, read_log) = uc.get_data();
        assert_eq!(write_log[0], (0x2fffff, 8));
        assert_eq!(write_log[1].1, 0);
        assert_eq!(read_log[0], (0x2fffff, 8));
        assert_eq!(read_log[1].1, 0);

        let mut b = [0u8; 8];
        uc.mem_read(0x2fffff, &mut b).unwrap();
        assert_eq!(u64::from_le_bytes(b), 0x2fffff);
    }
}

#[test]
fn test_x86_lazy_mapping() {
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, 0usize).unwrap();
    uc.add_mem_hook(HookType::MEM_FETCH_UNMAPPED, 1, 0, |uc, _, _, _, _| {
        uc.mem_map(0x1000, 0x1000, Prot::ALL).unwrap();
        uc.mem_write(0x1000, b"\x90\x90").unwrap(); // nop; nop

        // Handled!
        true
    })
    .unwrap();
    uc.add_block_hook(1, 0, |uc, _, _| {
        *uc.get_data_mut() += 1;
    })
    .unwrap();

    uc.emu_start(0x1000, 0x1002, 0, 0).unwrap();

    assert_eq!(*uc.get_data(), 1);
}

#[test]
fn test_x86_16_incorrect_ip() {
    let code = b"\x41"; // inc cx

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_16, None, code, ());
    uc.add_block_hook(1, 0, check_16_bit_ip).unwrap();
    uc.add_code_hook(1, 0, check_16_bit_ip).unwrap();

    uc.reg_write(RegisterX86::CS, 0x20).unwrap();

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}

fn check_16_bit_ip(uc: &mut Unicorn<()>, address: u64, _: u32) {
    let cs = uc.reg_read(RegisterX86::CS).unwrap();
    let ip = uc.reg_read(RegisterX86::IP).unwrap();

    assert_eq!(cs, 0x20);
    assert_eq!(address, (cs << 4) + ip);
}

#[test]
fn test_x86_vtlb() {
    // jmp 4; nop; nop; nop; nop; nop; nop
    let code = b"\xeb\x02\x90\x90\x90\x90\x90\x90";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());

    uc.ctl_set_tlb_type(TlbType::VIRTUAL).unwrap();
    uc.add_tlb_hook(1, 0, |_, addr, _| {
        Some(TlbEntry {
            paddr: addr,
            perms: Prot::ALL,
        })
    })
    .unwrap();

    uc.emu_start(CODE_START, CODE_START + 4, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EIP).unwrap(), CODE_START + 4);
}

// This aborts prior to a7a5d187e77f7853755eff4768658daf8095c3b7
#[test]
fn test_x86_0xff_lcall() {
    // Taken from unicorn#1842
    // 0:  b8 01 00 00 00          mov    eax,0x1
    // 5:  bb 01 00 00 00          mov    ebx,0x1
    // a:  b9 01 00 00 00          mov    ecx,0x1
    // f:  ff                      (bad)
    // 10: dd ba 01 00 00 00       fnstsw WORD PTR [edx+0x1]
    // 16: b8 02 00 00 00          mov    eax,0x2
    // 1b: bb 02 00 00 00          mov    ebx,0x2
    let code = b"\xB8\x01\x00\x00\x00\xBB\x01\x00\x00\x00\xB9\x01\x00\x00\x00\xFF\xDD\
                 \xBA\x01\x00\x00\x00\xB8\x02\x00\x00\x00\xBB\x02\x00\x00\x00";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());
    uc.add_code_hook(1, 0, |_, _, _| {}).unwrap();

    let err = uc
        .emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap_err();
    assert_eq!(err, uc_error::INSN_INVALID);
}

// https://github.com/unicorn-engine/unicorn/issues/1717
// https://github.com/unicorn-engine/unicorn/issues/1862
#[test]
fn test_x86_64_not_overwriting_tmp0_for_pc_update() {
    // 0x1000: movabs  rcx, 0xffffffffffffffff
    // 0x100a: mov     qword ptr [rsp], rcx
    // 0x100e: shl     qword ptr [rsp], cl ; (Shift to CF=1)
    // 0x1012: jae     0xd ; this jump should not be taken! (CF=1 but jae expects CF=0)
    let code = b"\x48\xb9\xff\xff\xff\xff\xff\xff\xff\xff\x48\x89\x0c\
                 \x24\x48\xd3\x24\x24\x73\x0a";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, ());
    uc.add_mem_hook(
        HookType::MEM_READ | HookType::MEM_WRITE,
        1,
        0,
        |_, _, _, _, _| true,
    )
    .unwrap();

    uc.reg_write(RegisterX86::RSP, 0x2000).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 4)
        .unwrap();

    assert_eq!(uc.reg_read(RegisterX86::RIP).unwrap(), 0x1014);
    assert_eq!(uc.reg_read(RegisterX86::EFLAGS).unwrap() & 0x1, 1);
}

#[test]
fn test_fxsave_fpip_x86() {
    const X86_NOP_OFFSET: u64 = 4;

    // note: fxsave was introduced in Pentium II
    #[rustfmt::skip]
    let code = &[
        // help testing through NOP offset      [disassembly in at&t syntax]
        0x90, 0x90, 0x90, 0x90,             // nop nop nop nop
        // run a floating point instruction
        0xdb, 0xc9,                         // fcmovne %st(1), %st
        // fxsave needs 512 bytes of storage space
        0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // subl $512, %esp
        // fxsave needs a 16-byte aligned address for storage
        0x83, 0xe4, 0xf0,                   // andl $0xfffffff0, %esp
        // store fxsave data on the stack
        0x0f, 0xae, 0x04, 0x24,             // fxsave (%esp)
        // fxsave stores FPIP at an 8-byte offset, move FPIP to eax register
        0x8b, 0x44, 0x24, 0x08,             // movl 0x8(%esp), %eax
    ];

    // initialize emulator in X86-32bit mode
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();

    // map 1MB of memory for this emulation
    uc.mem_map(MEM_BASE, MEM_SIZE, Prot::ALL).unwrap();
    uc.mem_write(MEM_TEXT, code).unwrap();
    uc.reg_write(RegisterX86::ESP, MEM_STACK).unwrap();
    uc.emu_start(MEM_TEXT, MEM_TEXT + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        uc.reg_read(RegisterX86::EAX).unwrap(),
        MEM_TEXT + X86_NOP_OFFSET
    );

    uc.mem_unmap(MEM_BASE, MEM_SIZE).unwrap();
}

#[test]
fn test_fxsave_fpip_x64() {
    const X64_NOP_OFFSET: u64 = 8;

    #[rustfmt::skip]
    let code = &[
        // help testing through NOP offset     [disassembly in at&t]
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops
        // run a floating point instruction
        0xdb, 0xc9,                                     // fcmovne %st(1), %st
        // fxsave64 needs 512 bytes of storage space
        0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00,       // subq $512, %rsp
        // fxsave needs a 16-byte aligned address for storage
        0x48, 0x83, 0xe4, 0xf0,                         // andq 0xfffffffffffffff0, %rsp
        // store fxsave64 data on the stack
        0x48, 0x0f, 0xae, 0x04, 0x24,                   // fxsave64 (%rsp)
        // fxsave64 stores FPIP at an 8-byte offset, move FPIP to rax register
        0x48, 0x8b, 0x44, 0x24, 0x08,                   // movq 0x8(%rsp), %rax
    ];

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();

    // map 1MB of memory for this emulation
    uc.mem_map(MEM_BASE, MEM_SIZE, Prot::ALL).unwrap();
    uc.mem_write(MEM_TEXT, code).unwrap();
    uc.reg_write(RegisterX86::RSP, MEM_STACK).unwrap();
    uc.emu_start(MEM_TEXT, MEM_TEXT + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(
        uc.reg_read(RegisterX86::RAX).unwrap(),
        MEM_TEXT + X64_NOP_OFFSET
    );

    uc.mem_unmap(MEM_BASE, MEM_SIZE).unwrap();
}

// References:
// - https://gynvael.coldwind.pl/?id=268
// - https://github.com/JonathanSalwan/Triton/issues/1131
#[test]
fn test_bswap_ax() {
    QuickTest {
        mode: Mode::MODE_32,
        code: &[0x66, 0x0F, 0xC8], // bswap ax
        in_regs: &[(RegisterX86::EAX, 0x4433_2211)],
        out_regs: &[(RegisterX86::EAX, 0x4433_0000)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x66, 0x0F, 0xC8], // bswap ax
        in_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_2211)],
        out_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_0000)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x66, 0x48, 0x0F, 0xC8], // bswap rax (66h ignored)
        in_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_2211)],
        out_regs: &[(RegisterX86::RAX, 0x1122_3344_5566_7788)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x48, 0x66, 0x0F, 0xC8], // bswap ax (rex ignored)
        in_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_2211)],
        out_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_0000)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_32,
        code: &[0x0F, 0xC8], // bswap eax
        in_regs: &[(RegisterX86::EAX, 0x4433_2211)],
        out_regs: &[(RegisterX86::EAX, 0x1122_3344)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x0F, 0xC8], // bswap eax
        in_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_2211)],
        out_regs: &[(RegisterX86::RAX, 0x0000_0000_1122_3344)],
    }
    .run();
}

#[test]
fn test_rex_x64() {
    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x48, 0x66, 0x89, 0xD8], // mov ax, bx (rex.w ignored)
        in_regs: &[
            (RegisterX86::RAX, 0x8877_6655_4433_2211),
            (RegisterX86::RBX, 0x1122_3344_5566_7788),
        ],
        out_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_7788)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x66, 0x48, 0x89, 0xD8], // mov rax, rbx (66h ignored)
        in_regs: &[
            (RegisterX86::RAX, 0x8877_6655_4433_2211),
            (RegisterX86::RBX, 0x1122_3344_5566_7788),
        ],
        out_regs: &[(RegisterX86::RAX, 0x1122_3344_5566_7788)],
    }
    .run();

    QuickTest {
        mode: Mode::MODE_64,
        code: &[0x66, 0x89, 0xD8], // mov ax, bx (expected encoding)
        in_regs: &[
            (RegisterX86::RAX, 0x8877_6655_4433_2211),
            (RegisterX86::RBX, 0x1122_3344_5566_7788),
        ],
        out_regs: &[(RegisterX86::RAX, 0x8877_6655_4433_7788)],
    }
    .run();
}

#[test]
fn test_x86_ro_segfault() {
    // mov eax, [0x1000]
    // mov eax, [0x1000]
    let code = b"\xA1\x00\x10\x00\x00\xA1\x00\x10\x00\x00";

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).unwrap();
    uc.mem_map(0, 0x1000, Prot::ALL).unwrap();
    uc.mem_write(0, code).unwrap();
    uc.mem_map(0x1000, 0x1000, Prot::READ).unwrap();

    uc.add_mem_hook(HookType::MEM_READ, 1, 0, move |uc, _, address, _, _| {
        uc.mem_write(address, code).unwrap();
        true
    })
    .unwrap();
    uc.emu_start(0, code.len() as u64, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterX86::EAX).unwrap(), 0x0010_00a1);
}

#[test]
fn test_x86_dr7() {
    // mov rax, 0x10005; mov dr7, rax
    let code = b"\x48\xC7\xC0\x05\x00\x01\x00\x0F\x23\xF8";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_64, None, code, ());
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}

#[test]
fn test_x86_hook_block() {
    // jmp 4; nop; nop; nop; nop; nop; nop
    let code = b"\xeb\x02\x90\x90\x90\x90\x90\x90";

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, 0u64);
    uc.add_block_hook(1, 0, |uc, address, _| {
        let pc = uc.reg_read(RegisterX86::EIP).unwrap();
        assert_eq!(pc, address);
        *uc.get_data_mut() += 1;
    })
    .unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    assert_eq!(*uc.get_data(), 2);
}

#[test]
fn test_x86_mem_hooks_pc_guarantee() {
    // bs, _ = ks.asm("inc edx; t: mov eax, [ebx]; inc ebx; cmp ebx, ecx; jnz t;")
    let code = b"\x42\x8b\x03\x43\x39\xcb\x75\xf9";
    let ebx = CODE_START + CODE_LEN;
    let ecx = CODE_START + CODE_LEN + 0x10;

    let mut uc = uc_common_setup(Arch::X86, Mode::MODE_32, None, code, ());

    uc.mem_map(CODE_START + CODE_LEN, 0x1000, Prot::ALL)
        .unwrap();
    uc.add_mem_hook(HookType::MEM_READ, 1, 0, |uc, _, addr, _, _| {
        if addr >= CODE_START + CODE_LEN {
            let eip = uc.reg_read(RegisterX86::EIP).unwrap();
            assert_eq!(eip, CODE_START + 1);
        }
        true
    })
    .unwrap();
    uc.reg_write(RegisterX86::EBX, ebx).unwrap();
    uc.reg_write(RegisterX86::ECX, ecx).unwrap();
    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();
}
