use crate::{Arm64, UcArch, long_register::LongRegister, mk_long_regs};

// those are aliases for the same registers, maybe remove the Q's?
mk_long_regs!(
    RegisterQ, Arm64, 16, Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15,
    Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31
);

mk_long_regs!(
    RegisterV, Arm64, 16, V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15,
    V16, V17, V18, V19, V20, V21, V22, V23, V24, V25, V26, V27, V28, V29, V30, V31
);
