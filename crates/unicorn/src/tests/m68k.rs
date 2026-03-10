use unicorn_engine_sys::RegisterM68K;

use crate::arch::m68k::M68K;

use super::*;

#[test]
fn test_move_to_sr() {
    let code = [
        0x46, 0xfc, 0x27, 0x00, // move #$2700, sr
    ];

    let mut uc = uc_common_setup::<_, M68K>(Mode::BIG_ENDIAN, None, &code, ());

    let mut sr = uc.reg_read(RegisterM68K::SR);
    sr |= 0x2000;
    uc.reg_write(RegisterM68K::SR, sr); // Set supervisor mode

    uc.emu_start(CODE_START, CODE_START + code.len() as u64, 0, 0)
        .unwrap();

    let sr = uc.reg_read(RegisterM68K::SR);
    assert_eq!(sr, 0x2700);
}

#[test]
fn test_sr_contains_flags() {
    let code = [
        0x76, 0xed, // moveq #-19, %d3
    ];

    let mut uc = uc_common_setup::<_, M68K>(Mode::BIG_ENDIAN, None, &code, ());
    let code_start_u64: usize = CODE_START.try_into().unwrap();
    let code_len_addition: usize = code_start_u64 + code.len();
    uc.emu_start(CODE_START, code_len_addition.try_into().unwrap(), 0, 0)
        .unwrap();

    let d3 = uc.reg_read(RegisterM68K::D3);
    assert_eq!(d3, 0xffffffed);

    let sr = uc.reg_read(RegisterM68K::SR);
    let is_negative = sr & 0x8 == 0x8;
    assert!(is_negative, "SR should contain negative flag");
}
