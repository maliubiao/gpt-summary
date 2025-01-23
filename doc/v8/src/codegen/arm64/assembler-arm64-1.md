Response: The user wants me to summarize the functionality of the provided C++ code snippet, which is part of the `assembler-arm64.cc` file in the V8 JavaScript engine. This part of the code seems to define various ARM64 assembly instructions, specifically focusing on NEON (Advanced SIMD) instructions for vector processing.

To summarize effectively, I need to identify the categories of NEON instructions being implemented here. I see functions related to:

1. **Immediate shifts:** Left and right shifts with immediate values.
2. **Register shifts:** Shifts with the shift amount specified in a register.
3. **Lane manipulation:** Inserting and extracting elements from vector registers.
4. **Reduction operations:** Operations that combine elements within a vector.
5. **Table lookups:**  Instructions for indexing into tables.
6. **Floating-point conversions:** Converting between floating-point and integer types.
7. **Floating-point arithmetic:** Addition, subtraction, multiplication, division, comparisons.
8. **Bitwise operations:** AND, OR, XOR, NOT.
9. **By-element operations:** Performing operations between a vector and a specific element of another vector.
10. **Structure loads and stores:** Loading and storing multiple elements to/from memory.

Regarding the relationship with JavaScript, these low-level assembly instructions are used by the V8 engine to implement JavaScript's features efficiently. Specifically, they are crucial for optimizing operations on arrays and typed arrays, and potentially for implementing some built-in functions.

I will go through the code and categorize the functions based on the operations they perform. Then, I will try to connect these operations to potential JavaScript use cases with examples.
```cpp
void Assembler::NEONShiftImmediate(const VRegister& vd, const VRegister& vn,
                                       NEONShiftImmediateOp op, int immh_immb) {
  Instr q, scalar;
  if (vn.IsScalar()) {
    DCHECK(vd.IsScalar());
    q = NEON_Q;
    scalar = NEONScalar;
  } else {
    q = vd.IsD() ? 0 : NEON_Q;
    scalar = 0;
  }
  Emit(q | op | scalar | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::NEONShiftLeftImmediate(const VRegister& vd, const VRegister& vn,
                                       int shift, NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 0) && (shift < laneSizeInBits));
  NEONShiftImmediate(vd, vn, op, (laneSizeInBits + shift) << 16);
}

void Assembler::NEONShiftRightImmediate(const VRegister& vd,
                                        const VRegister& vn, int shift,
                                        NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 1) && (shift <= laneSizeInBits));
  NEONShiftImmediate(vd, vn, op, ((2 * laneSizeInBits) - shift) << 16);
}

void Assembler::NEONShiftImmediateL(const VRegister& vd, const VRegister& vn,
                                    int shift, NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 0) && (shift < laneSizeInBits));
  int immh_immb = (laneSizeInBits + shift) << 16;

  DCHECK((vn.Is8B() && vd.Is8H()) || (vn.Is4H() && vd.Is4S()) ||
         (vn.Is2S() && vd.Is2D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Instr q;
  q = vn.IsD() ? 0 : NEON_Q;
  Emit(q | op | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::NEONShiftImmediateN(const VRegister& vd, const VRegister& vn,
                                    int shift, NEONShiftImmediateOp op) {
  Instr q, scalar;
  int laneSizeInBits = vd.LaneSizeInBits();
  DCHECK((shift >= 1) && (shift <= laneSizeInBits));
  int immh_immb = (2 * laneSizeInBits - shift) << 16;

  if (vn.IsScalar()) {
    DCHECK((vd.Is1B() && vn.Is1H()) || (vd.Is1H() && vn.Is1S()) ||
           (vd.Is1S() && vn.Is1D()));
    q = NEON_Q;
    scalar = NEONScalar;
  } else {
    DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
           (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vd.Is8H()) ||
           (vd.Is8H() && vd.Is4S()) || (vd.Is4S() && vd.Is2D()));
    scalar = 0;
    q = vd.IsD() ? 0 : NEON_Q;
  }
  Emit(q | op | scalar | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::shl(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SHL);
}

void Assembler::sli(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SLI);
}

void Assembler::sqshl(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SQSHL_imm);
}

void Assembler::sqshlu(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SQSHLU);
}

void Assembler::uqshl(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_UQSHL_imm);
}

void Assembler::sshll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsD());
  NEONShiftImmediateL(vd, vn, shift, NEON_SSHLL);
}

void Assembler::sshll2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsQ());
  NEONShiftImmediateL(vd, vn, shift, NEON_SSHLL);
}

void Assembler::sxtl(const VRegister& vd, const VRegister& vn) {
  sshll(vd, vn, 0);
}

void Assembler::sxtl2(const VRegister& vd, const VRegister& vn) {
  sshll2(vd, vn, 0);
}

void Assembler::ushll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsD());
  NEONShiftImmediateL(vd, vn, shift, NEON_USHLL);
}

void Assembler::ushll2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsQ());
  NEONShiftImmediateL(vd, vn, shift, NEON_USHLL);
}

void Assembler::uxtl(const VRegister& vd, const VRegister& vn) {
  ushll(vd, vn, 0);
}

void Assembler::uxtl2(const VRegister& vd, const VRegister& vn) {
  ushll2(vd, vn, 0);
}

void Assembler::sri(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRI);
}

void Assembler::sshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SSHR);
}

void Assembler::ushr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_USHR);
}

void Assembler::srshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRSHR);
}

void Assembler::urshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_URSHR);
}

void Assembler::ssra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SSRA);
}

void Assembler::usra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_USRA);
}

void Assembler::srsra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRSRA);
}

void Assembler::ursra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_URSRA);
}

void Assembler::shrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsD());
  NEONShiftImmediateN(vd, vn, shift, NEON_SHRN);
}

void Assembler::shrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SHRN);
}

void Assembler::rshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsD());
  NEONShiftImmediateN(vd, vn, shift, NEON_RSHRN);
}

void Assembler::rshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_RSHRN);
}

void Assembler::sqshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRN);
}

void Assembler::sqshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRN);
}

void Assembler::sqrshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRN);
}

void Assembler::sqrshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRN);
}

void Assembler::sqshrun(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRUN);
}

void Assembler::sqshrun2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRUN);
}

void Assembler::sqrshrun(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRUN);
}

void Assembler::sqrshrun2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRUN);
}

void Assembler::uqshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_UQSHRN);
}

void Assembler::uqshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_UQSHRN);
}

void Assembler::uqrshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_UQRSHRN);
}

void Assembler::uqrshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_UQRSHRN);
}

void Assembler::uaddw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_UADDW);
}

void Assembler::uaddw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_UADDW2);
}

void Assembler::saddw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_SADDW);
}

void Assembler::saddw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_SADDW2);
}

void Assembler::usubw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_USUBW);
}

void Assembler::usubw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_USUBW2);
}

void Assembler::ssubw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_SSUBW);
}

void Assembler::ssubw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_SSUBW2);
}

void Assembler::mov(const Register& rd, const Register& rm) {
  // Moves involving the stack pointer are encoded as add immediate with
  // second operand of zero. Otherwise, orr with first operand zr is
  // used.
  if (rd.IsSP() || rm.IsSP()) {
    add(rd, rm, 0);
  } else {
    orr(rd, AppropriateZeroRegFor(rd), rm);
  }
}

void Assembler::ins(const VRegister& vd, int vd_index, const Register& rn) {
  // We support vd arguments of the form vd.VxT() or vd.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vd.LaneSizeInBytes();
  NEONFormatField format;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      DCHECK(rn.IsW());
      break;
    case 2:
      format = NEON_8H;
      DCHECK(rn.IsW());
      break;
    case 4:
      format = NEON_4S;
      DCHECK(rn.IsW());
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      DCHECK(rn.IsX());
      format = NEON_2D;
      break;
  }

  DCHECK((0 <= vd_index) &&
         (vd_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(NEON_INS_GENERAL | ImmNEON5(format, vd_index) | Rn(rn) | Rd(vd));
}

void Assembler::mov(const Register& rd, const VRegister& vn, int vn_index) {
  DCHECK_GE(vn.SizeInBytes(), 4);
  umov(rd, vn, vn_index);
}

void Assembler::smov(const Register& rd, const VRegister& vn, int vn_index) {
  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  Instr q = 0;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      break;
    case 2:
      format = NEON_8H;
      break;
    default:
      DCHECK_EQ(lane_size, 4);
      DCHECK(rd.IsX());
      format = NEON_4S;
      break;
  }
  q = rd.IsW() ? 0 : NEON_Q;
  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(q | NEON_SMOV | ImmNEON5(format, vn_index) | Rn(vn) | Rd(rd));
}

void Assembler::cls(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_CLS | Rn(vn) | Rd(vd));
}

void Assembler::clz(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_CLZ | Rn(vn) | Rd(vd));
}

void Assembler::cnt(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | NEON_CNT | Rn(vn) | Rd(vd));
}

void Assembler::rev16(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | NEON_REV16 | Rn(vn) | Rd(vd));
}

void Assembler::rev32(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B() || vd.Is4H() || vd.Is8H());
  Emit(VFormat(vn) | NEON_REV32 | Rn(vn) | Rd(vd));
}

void Assembler::rev64(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_REV64 | Rn(vn) | Rd(vd));
}

void Assembler::ursqrte(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is2S() || vd.Is4S());
  Emit(VFormat(vn) | NEON_URSQRTE | Rn(vn) | Rd(vd));
}

void Assembler::urecpe(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is2S() || vd.Is4S());
  Emit(VFormat(vn) | NEON_URECPE | Rn(vn) | Rd(vd));
}

void Assembler::NEONAddlp(const VRegister& vd, const VRegister& vn,
                          NEON2RegMiscOp op) {
  DCHECK((op == NEON_SADDLP) || (op == NEON_UADDLP) || (op == NEON_SADALP) ||
         (op == NEON_UADALP));

  DCHECK((vn.Is8B() && vd.Is4H()) || (vn.Is4H() && vd.Is2S()) ||
         (vn.Is2S() && vd.Is1D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::saddlp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_SADDLP);
}

void Assembler::uaddlp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_UADDLP);
}

void Assembler::sadalp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_SADALP);
}

void Assembler::uadalp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_UADALP);
}

void Assembler::NEONAcrossLanesL(const VRegister& vd, const VRegister& vn,
                                 NEONAcrossLanesOp op) {
  DCHECK((vn.Is8B() && vd.Is1H()) || (vn.Is16B() && vd.Is1H()) ||
         (vn.Is4H() && vd.Is1S()) || (vn.Is8H() && vd.Is1S()) ||
         (vn.Is4S() && vd.Is1D()));
  Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::saddlv(const VRegister& vd, const VRegister& vn) {
  NEONAcrossLanesL(vd, vn, NEON_SADDLV);
}

void Assembler::uaddlv(const VRegister& vd, const VRegister& vn) {
  NEONAcrossLanesL(vd, vn, NEON_UADDLV);
}

void Assembler::NEONAcrossLanes(const VRegister& vd, const VRegister& vn,
                                NEONAcrossLanesOp op) {
  DCHECK((vn.Is8B() && vd.Is1B()) || (vn.Is16B() && vd.Is1B()) ||
         (vn.Is4H() && vd.Is1H()) || (vn.Is8H() && vd.Is1H()) ||
         (vn.Is4S() && vd.Is1S()));
  if ((op & NEONAcrossLanesFPFMask) == NEONAcrossLanesFPFixed) {
    Emit(FPFormat(vn) | op | Rn(vn) | Rd(vd));
  } else {
    Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
  }
}

#define NEON_ACROSSLANES_LIST(V)      \
  V(fmaxv, NEON_FMAXV, vd.Is1S())     \
  V(fminv, NEON_FMINV, vd.Is1S())     \
  V(fmaxnmv, NEON_FMAXNMV, vd.Is1S()) \
  V(fminnmv, NEON_FMINNMV, vd.Is1S()) \
  V(addv, NEON_ADDV, true)            \
  V(smaxv, NEON_SMAXV, true)          \
  V(sminv, NEON_SMINV, true)          \
  V(umaxv, NEON_UMAXV, true)          \
  V(uminv, NEON_UMINV, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                              \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    DCHECK(AS);                                                  \
    NEONAcrossLanes(vd, vn, OP);                                 \
  }
NEON_ACROSSLANES_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::mov(const VRegister& vd, int vd_index, const Register& rn) {
  ins(vd, vd_index, rn);
}

void Assembler::umov(const Register& rd, const VRegister& vn, int vn_index) {
  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  Instr q = 0;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      DCHECK(rd.IsW());
      break;
    case 2:
      format = NEON_8H;
      DCHECK(rd.IsW());
      break;
    case 4:
      format = NEON_4S;
      DCHECK(rd.IsW());
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      DCHECK(rd.IsX());
      format = NEON_2D;
      q = NEON_Q;
      break;
  }

  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(q | NEON_UMOV | ImmNEON5(format, vn_index) | Rn(vn) | Rd(rd));
}

void Assembler::mov(const VRegister& vd, const VRegister& vn, int vn_index) {
  DCHECK(vd.IsScalar());
  dup(vd, vn, vn_index);
}

void Assembler::dup(const VRegister& vd, const Register& rn) {
  DCHECK(!vd.Is1D());
  DCHECK_EQ(vd.Is2D(), rn.IsX());
  Instr q = vd.IsD() ? 0 : NEON_Q;
  Emit(q | NEON_DUP_GENERAL | ImmNEON5(VFormat(vd), 0) | Rn(rn) | Rd(vd));
}

void Assembler::ins(const VRegister& vd, int vd_index, const VRegister& vn,
                    int vn_index) {
  DCHECK(AreSameFormat(vd, vn));
  // We support vd arguments of the form vd.VxT() or vd.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vd.LaneSizeInBytes();
  NEONFormatField format;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      break;
    case 2:
      format = NEON_8H;
      break;
    case 4:
      format = NEON_4S;
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      format = NEON_2D;
      break;
  }

  DCHECK((0 <= vd_index) &&
         (vd_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(NEON_INS_ELEMENT | ImmNEON5(format, vd_index) |
       ImmNEON4(format, vn_index) | Rn(vn) | Rd(vd));
}

void Assembler::NEONTable(const VRegister& vd, const VRegister& vn,
                          const VRegister& vm, NEONTableOp op) {
  DCHECK(vd.Is16B() || vd.Is8B());
  DCHECK(vn.Is16B());
  DCHECK(AreSameFormat(vd, vm));
  Emit(op | (vd.IsQ() ? NEON_Q : 0) | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm) {
  NEONTable(vd, vn, vm, NEON_TBL_1v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vm) {
  USE(vn2);
  DCHECK(AreSameFormat(vn, vn2));
  DCHECK(AreConsecutive(vn, vn2));
  NEONTable(vd, vn, vm, NEON_TBL_2v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  DCHECK(AreSameFormat(vn, vn2, vn3));
  DCHECK(AreConsecutive(vn, vn2, vn3));
  NEONTable(vd, vn, vm, NEON_TBL_3v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vn4, const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  USE(vn4);
  DCHECK(AreSameFormat(vn, vn2, vn3, vn4));
  DCHECK(AreConsecutive(vn, vn2, vn3, vn4));
  NEONTable(vd, vn, vm, NEON_TBL_4v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm) {
  NEONTable(vd, vn, vm, NEON_TBX_1v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vm) {
  USE(vn2);
  DCHECK(AreSameFormat(vn, vn2));
  DCHECK(AreConsecutive(vn, vn2));
  NEONTable(vd, vn, vm, NEON_TBX_2v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  DCHECK(AreSameFormat(vn, vn2, vn3));
  DCHECK(AreConsecutive(vn, vn2, vn3));
  NEONTable(vd, vn, vm, NEON_TBX_3v);
}

void Assembler::tbx(
### 提示词
```
这是目录为v8/src/codegen/arm64/assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
Scalar;
  } else {
    q = vd.IsD() ? 0 : NEON_Q;
    scalar = 0;
  }
  Emit(q | op | scalar | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::NEONShiftLeftImmediate(const VRegister& vd, const VRegister& vn,
                                       int shift, NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 0) && (shift < laneSizeInBits));
  NEONShiftImmediate(vd, vn, op, (laneSizeInBits + shift) << 16);
}

void Assembler::NEONShiftRightImmediate(const VRegister& vd,
                                        const VRegister& vn, int shift,
                                        NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 1) && (shift <= laneSizeInBits));
  NEONShiftImmediate(vd, vn, op, ((2 * laneSizeInBits) - shift) << 16);
}

void Assembler::NEONShiftImmediateL(const VRegister& vd, const VRegister& vn,
                                    int shift, NEONShiftImmediateOp op) {
  int laneSizeInBits = vn.LaneSizeInBits();
  DCHECK((shift >= 0) && (shift < laneSizeInBits));
  int immh_immb = (laneSizeInBits + shift) << 16;

  DCHECK((vn.Is8B() && vd.Is8H()) || (vn.Is4H() && vd.Is4S()) ||
         (vn.Is2S() && vd.Is2D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Instr q;
  q = vn.IsD() ? 0 : NEON_Q;
  Emit(q | op | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::NEONShiftImmediateN(const VRegister& vd, const VRegister& vn,
                                    int shift, NEONShiftImmediateOp op) {
  Instr q, scalar;
  int laneSizeInBits = vd.LaneSizeInBits();
  DCHECK((shift >= 1) && (shift <= laneSizeInBits));
  int immh_immb = (2 * laneSizeInBits - shift) << 16;

  if (vn.IsScalar()) {
    DCHECK((vd.Is1B() && vn.Is1H()) || (vd.Is1H() && vn.Is1S()) ||
           (vd.Is1S() && vn.Is1D()));
    q = NEON_Q;
    scalar = NEONScalar;
  } else {
    DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
           (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vn.Is8H()) ||
           (vd.Is8H() && vn.Is4S()) || (vd.Is4S() && vn.Is2D()));
    scalar = 0;
    q = vd.IsD() ? 0 : NEON_Q;
  }
  Emit(q | op | scalar | immh_immb | Rn(vn) | Rd(vd));
}

void Assembler::shl(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SHL);
}

void Assembler::sli(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SLI);
}

void Assembler::sqshl(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SQSHL_imm);
}

void Assembler::sqshlu(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_SQSHLU);
}

void Assembler::uqshl(const VRegister& vd, const VRegister& vn, int shift) {
  NEONShiftLeftImmediate(vd, vn, shift, NEON_UQSHL_imm);
}

void Assembler::sshll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsD());
  NEONShiftImmediateL(vd, vn, shift, NEON_SSHLL);
}

void Assembler::sshll2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsQ());
  NEONShiftImmediateL(vd, vn, shift, NEON_SSHLL);
}

void Assembler::sxtl(const VRegister& vd, const VRegister& vn) {
  sshll(vd, vn, 0);
}

void Assembler::sxtl2(const VRegister& vd, const VRegister& vn) {
  sshll2(vd, vn, 0);
}

void Assembler::ushll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsD());
  NEONShiftImmediateL(vd, vn, shift, NEON_USHLL);
}

void Assembler::ushll2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsQ());
  NEONShiftImmediateL(vd, vn, shift, NEON_USHLL);
}

void Assembler::uxtl(const VRegister& vd, const VRegister& vn) {
  ushll(vd, vn, 0);
}

void Assembler::uxtl2(const VRegister& vd, const VRegister& vn) {
  ushll2(vd, vn, 0);
}

void Assembler::sri(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRI);
}

void Assembler::sshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SSHR);
}

void Assembler::ushr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_USHR);
}

void Assembler::srshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRSHR);
}

void Assembler::urshr(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_URSHR);
}

void Assembler::ssra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SSRA);
}

void Assembler::usra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_USRA);
}

void Assembler::srsra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_SRSRA);
}

void Assembler::ursra(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEONShiftRightImmediate(vd, vn, shift, NEON_URSRA);
}

void Assembler::shrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsD());
  NEONShiftImmediateN(vd, vn, shift, NEON_SHRN);
}

void Assembler::shrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SHRN);
}

void Assembler::rshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsD());
  NEONShiftImmediateN(vd, vn, shift, NEON_RSHRN);
}

void Assembler::rshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_RSHRN);
}

void Assembler::sqshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRN);
}

void Assembler::sqshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRN);
}

void Assembler::sqrshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRN);
}

void Assembler::sqrshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRN);
}

void Assembler::sqshrun(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRUN);
}

void Assembler::sqshrun2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQSHRUN);
}

void Assembler::sqrshrun(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRUN);
}

void Assembler::sqrshrun2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_SQRSHRUN);
}

void Assembler::uqshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_UQSHRN);
}

void Assembler::uqshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_UQSHRN);
}

void Assembler::uqrshrn(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vd.IsD() || (vn.IsScalar() && vd.IsScalar()));
  NEONShiftImmediateN(vd, vn, shift, NEON_UQRSHRN);
}

void Assembler::uqrshrn2(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK(vn.IsVector() && vd.IsQ());
  NEONShiftImmediateN(vd, vn, shift, NEON_UQRSHRN);
}

void Assembler::uaddw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_UADDW);
}

void Assembler::uaddw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_UADDW2);
}

void Assembler::saddw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_SADDW);
}

void Assembler::saddw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_SADDW2);
}

void Assembler::usubw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_USUBW);
}

void Assembler::usubw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_USUBW2);
}

void Assembler::ssubw(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(vm.IsD());
  NEON3DifferentW(vd, vn, vm, NEON_SSUBW);
}

void Assembler::ssubw2(const VRegister& vd, const VRegister& vn,
                       const VRegister& vm) {
  DCHECK(vm.IsQ());
  NEON3DifferentW(vd, vn, vm, NEON_SSUBW2);
}

void Assembler::mov(const Register& rd, const Register& rm) {
  // Moves involving the stack pointer are encoded as add immediate with
  // second operand of zero. Otherwise, orr with first operand zr is
  // used.
  if (rd.IsSP() || rm.IsSP()) {
    add(rd, rm, 0);
  } else {
    orr(rd, AppropriateZeroRegFor(rd), rm);
  }
}

void Assembler::ins(const VRegister& vd, int vd_index, const Register& rn) {
  // We support vd arguments of the form vd.VxT() or vd.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vd.LaneSizeInBytes();
  NEONFormatField format;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      DCHECK(rn.IsW());
      break;
    case 2:
      format = NEON_8H;
      DCHECK(rn.IsW());
      break;
    case 4:
      format = NEON_4S;
      DCHECK(rn.IsW());
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      DCHECK(rn.IsX());
      format = NEON_2D;
      break;
  }

  DCHECK((0 <= vd_index) &&
         (vd_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(NEON_INS_GENERAL | ImmNEON5(format, vd_index) | Rn(rn) | Rd(vd));
}

void Assembler::mov(const Register& rd, const VRegister& vn, int vn_index) {
  DCHECK_GE(vn.SizeInBytes(), 4);
  umov(rd, vn, vn_index);
}

void Assembler::smov(const Register& rd, const VRegister& vn, int vn_index) {
  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  Instr q = 0;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      break;
    case 2:
      format = NEON_8H;
      break;
    default:
      DCHECK_EQ(lane_size, 4);
      DCHECK(rd.IsX());
      format = NEON_4S;
      break;
  }
  q = rd.IsW() ? 0 : NEON_Q;
  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(q | NEON_SMOV | ImmNEON5(format, vn_index) | Rn(vn) | Rd(rd));
}

void Assembler::cls(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_CLS | Rn(vn) | Rd(vd));
}

void Assembler::clz(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_CLZ | Rn(vn) | Rd(vd));
}

void Assembler::cnt(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | NEON_CNT | Rn(vn) | Rd(vd));
}

void Assembler::rev16(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B());
  Emit(VFormat(vn) | NEON_REV16 | Rn(vn) | Rd(vd));
}

void Assembler::rev32(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B() || vd.Is16B() || vd.Is4H() || vd.Is8H());
  Emit(VFormat(vn) | NEON_REV32 | Rn(vn) | Rd(vd));
}

void Assembler::rev64(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(!vd.Is1D() && !vd.Is2D());
  Emit(VFormat(vn) | NEON_REV64 | Rn(vn) | Rd(vd));
}

void Assembler::ursqrte(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is2S() || vd.Is4S());
  Emit(VFormat(vn) | NEON_URSQRTE | Rn(vn) | Rd(vd));
}

void Assembler::urecpe(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is2S() || vd.Is4S());
  Emit(VFormat(vn) | NEON_URECPE | Rn(vn) | Rd(vd));
}

void Assembler::NEONAddlp(const VRegister& vd, const VRegister& vn,
                          NEON2RegMiscOp op) {
  DCHECK((op == NEON_SADDLP) || (op == NEON_UADDLP) || (op == NEON_SADALP) ||
         (op == NEON_UADALP));

  DCHECK((vn.Is8B() && vd.Is4H()) || (vn.Is4H() && vd.Is2S()) ||
         (vn.Is2S() && vd.Is1D()) || (vn.Is16B() && vd.Is8H()) ||
         (vn.Is8H() && vd.Is4S()) || (vn.Is4S() && vd.Is2D()));
  Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::saddlp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_SADDLP);
}

void Assembler::uaddlp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_UADDLP);
}

void Assembler::sadalp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_SADALP);
}

void Assembler::uadalp(const VRegister& vd, const VRegister& vn) {
  NEONAddlp(vd, vn, NEON_UADALP);
}

void Assembler::NEONAcrossLanesL(const VRegister& vd, const VRegister& vn,
                                 NEONAcrossLanesOp op) {
  DCHECK((vn.Is8B() && vd.Is1H()) || (vn.Is16B() && vd.Is1H()) ||
         (vn.Is4H() && vd.Is1S()) || (vn.Is8H() && vd.Is1S()) ||
         (vn.Is4S() && vd.Is1D()));
  Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::saddlv(const VRegister& vd, const VRegister& vn) {
  NEONAcrossLanesL(vd, vn, NEON_SADDLV);
}

void Assembler::uaddlv(const VRegister& vd, const VRegister& vn) {
  NEONAcrossLanesL(vd, vn, NEON_UADDLV);
}

void Assembler::NEONAcrossLanes(const VRegister& vd, const VRegister& vn,
                                NEONAcrossLanesOp op) {
  DCHECK((vn.Is8B() && vd.Is1B()) || (vn.Is16B() && vd.Is1B()) ||
         (vn.Is4H() && vd.Is1H()) || (vn.Is8H() && vd.Is1H()) ||
         (vn.Is4S() && vd.Is1S()));
  if ((op & NEONAcrossLanesFPFMask) == NEONAcrossLanesFPFixed) {
    Emit(FPFormat(vn) | op | Rn(vn) | Rd(vd));
  } else {
    Emit(VFormat(vn) | op | Rn(vn) | Rd(vd));
  }
}

#define NEON_ACROSSLANES_LIST(V)      \
  V(fmaxv, NEON_FMAXV, vd.Is1S())     \
  V(fminv, NEON_FMINV, vd.Is1S())     \
  V(fmaxnmv, NEON_FMAXNMV, vd.Is1S()) \
  V(fminnmv, NEON_FMINNMV, vd.Is1S()) \
  V(addv, NEON_ADDV, true)            \
  V(smaxv, NEON_SMAXV, true)          \
  V(sminv, NEON_SMINV, true)          \
  V(umaxv, NEON_UMAXV, true)          \
  V(uminv, NEON_UMINV, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                              \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    DCHECK(AS);                                                  \
    NEONAcrossLanes(vd, vn, OP);                                 \
  }
NEON_ACROSSLANES_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::mov(const VRegister& vd, int vd_index, const Register& rn) {
  ins(vd, vd_index, rn);
}

void Assembler::umov(const Register& rd, const VRegister& vn, int vn_index) {
  // We support vn arguments of the form vn.VxT() or vn.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vn.LaneSizeInBytes();
  NEONFormatField format;
  Instr q = 0;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      DCHECK(rd.IsW());
      break;
    case 2:
      format = NEON_8H;
      DCHECK(rd.IsW());
      break;
    case 4:
      format = NEON_4S;
      DCHECK(rd.IsW());
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      DCHECK(rd.IsX());
      format = NEON_2D;
      q = NEON_Q;
      break;
  }

  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(q | NEON_UMOV | ImmNEON5(format, vn_index) | Rn(vn) | Rd(rd));
}

void Assembler::mov(const VRegister& vd, const VRegister& vn, int vn_index) {
  DCHECK(vd.IsScalar());
  dup(vd, vn, vn_index);
}

void Assembler::dup(const VRegister& vd, const Register& rn) {
  DCHECK(!vd.Is1D());
  DCHECK_EQ(vd.Is2D(), rn.IsX());
  Instr q = vd.IsD() ? 0 : NEON_Q;
  Emit(q | NEON_DUP_GENERAL | ImmNEON5(VFormat(vd), 0) | Rn(rn) | Rd(vd));
}

void Assembler::ins(const VRegister& vd, int vd_index, const VRegister& vn,
                    int vn_index) {
  DCHECK(AreSameFormat(vd, vn));
  // We support vd arguments of the form vd.VxT() or vd.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  int lane_size = vd.LaneSizeInBytes();
  NEONFormatField format;
  switch (lane_size) {
    case 1:
      format = NEON_16B;
      break;
    case 2:
      format = NEON_8H;
      break;
    case 4:
      format = NEON_4S;
      break;
    default:
      DCHECK_EQ(lane_size, 8);
      format = NEON_2D;
      break;
  }

  DCHECK((0 <= vd_index) &&
         (vd_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  DCHECK((0 <= vn_index) &&
         (vn_index < LaneCountFromFormat(static_cast<VectorFormat>(format))));
  Emit(NEON_INS_ELEMENT | ImmNEON5(format, vd_index) |
       ImmNEON4(format, vn_index) | Rn(vn) | Rd(vd));
}

void Assembler::NEONTable(const VRegister& vd, const VRegister& vn,
                          const VRegister& vm, NEONTableOp op) {
  DCHECK(vd.Is16B() || vd.Is8B());
  DCHECK(vn.Is16B());
  DCHECK(AreSameFormat(vd, vm));
  Emit(op | (vd.IsQ() ? NEON_Q : 0) | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm) {
  NEONTable(vd, vn, vm, NEON_TBL_1v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vm) {
  USE(vn2);
  DCHECK(AreSameFormat(vn, vn2));
  DCHECK(AreConsecutive(vn, vn2));
  NEONTable(vd, vn, vm, NEON_TBL_2v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  DCHECK(AreSameFormat(vn, vn2, vn3));
  DCHECK(AreConsecutive(vn, vn2, vn3));
  NEONTable(vd, vn, vm, NEON_TBL_3v);
}

void Assembler::tbl(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vn4, const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  USE(vn4);
  DCHECK(AreSameFormat(vn, vn2, vn3, vn4));
  DCHECK(AreConsecutive(vn, vn2, vn3, vn4));
  NEONTable(vd, vn, vm, NEON_TBL_4v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vm) {
  NEONTable(vd, vn, vm, NEON_TBX_1v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vm) {
  USE(vn2);
  DCHECK(AreSameFormat(vn, vn2));
  DCHECK(AreConsecutive(vn, vn2));
  NEONTable(vd, vn, vm, NEON_TBX_2v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  DCHECK(AreSameFormat(vn, vn2, vn3));
  DCHECK(AreConsecutive(vn, vn2, vn3));
  NEONTable(vd, vn, vm, NEON_TBX_3v);
}

void Assembler::tbx(const VRegister& vd, const VRegister& vn,
                    const VRegister& vn2, const VRegister& vn3,
                    const VRegister& vn4, const VRegister& vm) {
  USE(vn2);
  USE(vn3);
  USE(vn4);
  DCHECK(AreSameFormat(vn, vn2, vn3, vn4));
  DCHECK(AreConsecutive(vn, vn2, vn3, vn4));
  NEONTable(vd, vn, vm, NEON_TBX_4v);
}

void Assembler::mov(const VRegister& vd, int vd_index, const VRegister& vn,
                    int vn_index) {
  ins(vd, vd_index, vn, vn_index);
}

void Assembler::mvn(const Register& rd, const Operand& operand) {
  orn(rd, AppropriateZeroRegFor(rd), operand);
}

void Assembler::mrs(const Register& rt, SystemRegister sysreg) {
  DCHECK(rt.Is64Bits());
  Emit(MRS | ImmSystemRegister(sysreg) | Rt(rt));
}

void Assembler::msr(SystemRegister sysreg, const Register& rt) {
  DCHECK(rt.Is64Bits());
  Emit(MSR | Rt(rt) | ImmSystemRegister(sysreg));
}

void Assembler::hint(SystemHint code) { Emit(HINT | ImmHint(code) | Rt(xzr)); }

// NEON structure loads and stores.
Instr Assembler::LoadStoreStructAddrModeField(const MemOperand& addr) {
  Instr addr_field = RnSP(addr.base());

  if (addr.IsPostIndex()) {
    static_assert(NEONLoadStoreMultiStructPostIndex ==
                      static_cast<NEONLoadStoreMultiStructPostIndexOp>(
                          NEONLoadStoreSingleStructPostIndex),
                  "Opcodes must match for NEON post index memop.");

    addr_field |= NEONLoadStoreMultiStructPostIndex;
    if (addr.offset() == 0) {
      addr_field |= RmNot31(addr.regoffset());
    } else {
      // The immediate post index addressing mode is indicated by rm = 31.
      // The immediate is implied by the number of vector registers used.
      addr_field |= (0x1F << Rm_offset);
    }
  } else {
    DCHECK(addr.IsImmediateOffset() && (addr.offset() == 0));
  }
  return addr_field;
}

void Assembler::LoadStoreStructVerify(const VRegister& vt,
                                      const MemOperand& addr, Instr op) {
#ifdef DEBUG
  // Assert that addressing mode is either offset (with immediate 0), post
  // index by immediate of the size of the register list, or post index by a
  // value in a core register.
  if (addr.IsImmediateOffset()) {
    DCHECK_EQ(addr.offset(), 0);
  } else {
    int offset = vt.SizeInBytes();
    switch (op) {
      case NEON_LD1_1v:
      case NEON_ST1_1v:
        offset *= 1;
        break;
      case NEONLoadStoreSingleStructLoad1:
      case NEONLoadStoreSingleStructStore1:
      case NEON_LD1R:
        offset = (offset / vt.LaneCount()) * 1;
        break;

      case NEON_LD1_2v:
      case NEON_ST1_2v:
      case NEON_LD2:
      case NEON_ST2:
        offset *= 2;
        break;
      case NEONLoadStoreSingleStructLoad2:
      case NEONLoadStoreSingleStructStore2:
      case NEON_LD2R:
        offset = (offset / vt.LaneCount()) * 2;
        break;

      case NEON_LD1_3v:
      case NEON_ST1_3v:
      case NEON_LD3:
      case NEON_ST3:
        offset *= 3;
        break;
      case NEONLoadStoreSingleStructLoad3:
      case NEONLoadStoreSingleStructStore3:
      case NEON_LD3R:
        offset = (offset / vt.LaneCount()) * 3;
        break;

      case NEON_LD1_4v:
      case NEON_ST1_4v:
      case NEON_LD4:
      case NEON_ST4:
        offset *= 4;
        break;
      case NEONLoadStoreSingleStructLoad4:
      case NEONLoadStoreSingleStructStore4:
      case NEON_LD4R:
        offset = (offset / vt.LaneCount()) * 4;
        break;
      default:
        UNREACHABLE();
    }
    DCHECK(addr.regoffset() != NoReg || addr.offset() == offset);
  }
#else
  USE(vt);
  USE(addr);
  USE(op);
#endif
}

void Assembler::LoadStoreStruct(const VRegister& vt, const MemOperand& addr,
                                NEONLoadStoreMultiStructOp op) {
  LoadStoreStructVerify(vt, addr, op);
  DCHECK(vt.IsVector() || vt.Is1D());
  Emit(op | LoadStoreStructAddrModeField(addr) | LSVFormat(vt) | Rt(vt));
}

void Assembler::LoadStoreStructSingleAllLanes(const VRegister& vt,
                                              const MemOperand& addr,
                                              NEONLoadStoreSingleStructOp op) {
  LoadStoreStructVerify(vt, addr, op);
  Emit(op | LoadStoreStructAddrModeField(addr) | LSVFormat(vt) | Rt(vt));
}

void Assembler::ld1(const VRegister& vt, const MemOperand& src) {
  LoadStoreStruct(vt, src, NEON_LD1_1v);
}

void Assembler::ld1(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, src, NEON_LD1_2v);
}

void Assembler::ld1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, src, NEON_LD1_3v);
}

void Assembler::ld1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, src, NEON_LD1_4v);
}

void Assembler::ld2(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, src, NEON_LD2);
}

void Assembler::ld2(const VRegister& vt, const VRegister& vt2, int lane,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad2);
}

void Assembler::ld2r(const VRegister& vt, const VRegister& vt2,
                     const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD2R);
}

void Assembler::ld3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, src, NEON_LD3);
}

void Assembler::ld3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, int lane, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad3);
}

void Assembler::ld3r(const VRegister& vt, const VRegister& vt2,
                     const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD3R);
}

void Assembler::ld4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, src, NEON_LD4);
}

void Assembler::ld4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4, int lane,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad4);
}

void Assembler::ld4r(const VRegister& vt, const VRegister& vt2,
                     const VRegister& vt3, const VRegister& vt4,
                     const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD4R);
}

void Assembler::st1(const VRegister& vt, const MemOperand& src) {
  LoadStoreStruct(vt, src, NEON_ST1_1v);
}

void Assembler::st1(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& src) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, src, NEON_ST1_2v);
}

void Assembler::st1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, src, NEON_ST1_3v);
}

void Assembler::st1(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& src) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, src, NEON_ST1_4v);
}

void Assembler::st2(const VRegister& vt, const VRegister& vt2,
                    const MemOperand& dst) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStruct(vt, dst, NEON_ST2);
}

void Assembler::st2(const VRegister& vt, const VRegister& vt2, int lane,
                    const MemOperand& dst) {
  USE(vt2);
  DCHECK(AreSameFormat(vt, vt2));
  DCHECK(AreConsecutive(vt, vt2));
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore2);
}

void Assembler::st3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStruct(vt, dst, NEON_ST3);
}

void Assembler::st3(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, int lane, const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  DCHECK(AreSameFormat(vt, vt2, vt3));
  DCHECK(AreConsecutive(vt, vt2, vt3));
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore3);
}

void Assembler::st4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4,
                    const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStruct(vt, dst, NEON_ST4);
}

void Assembler::st4(const VRegister& vt, const VRegister& vt2,
                    const VRegister& vt3, const VRegister& vt4, int lane,
                    const MemOperand& dst) {
  USE(vt2);
  USE(vt3);
  USE(vt4);
  DCHECK(AreSameFormat(vt, vt2, vt3, vt4));
  DCHECK(AreConsecutive(vt, vt2, vt3, vt4));
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore4);
}

void Assembler::LoadStoreStructSingle(const VRegister& vt, uint32_t lane,
                                      const MemOperand& addr,
                                      NEONLoadStoreSingleStructOp op) {
  LoadStoreStructVerify(vt, addr, op);

  // We support vt arguments of the form vt.VxT() or vt.T(), where x is the
  // number of lanes, and T is b, h, s or d.
  unsigned lane_size = vt.LaneSizeInBytes();
  DCHECK_LT(lane, kQRegSize / lane_size);

  // Lane size is encoded in the opcode field. Lane index is encoded in the Q,
  // S and size fields.
  lane *= lane_size;

  // Encodings for S[0]/D[0] and S[2]/D[1] are distinguished using the least-
  // significant bit of the size field, so we increment lane here to account for
  // that.
  if (lane_size == 8) lane++;

  Instr size = (lane << NEONLSSize_offset) & NEONLSSize_mask;
  Instr s = (lane << (NEONS_offset - 2)) & NEONS_mask;
  Instr q = (lane << (NEONQ_offset - 3)) & NEONQ_mask;

  Instr instr = op;
  switch (lane_size) {
    case 1:
      instr |= NEONLoadStoreSingle_b;
      break;
    case 2:
      instr |= NEONLoadStoreSingle_h;
      break;
    case 4:
      instr |= NEONLoadStoreSingle_s;
      break;
    default:
      DCHECK_EQ(lane_size, 8U);
      instr |= NEONLoadStoreSingle_d;
  }

  Emit(instr | LoadStoreStructAddrModeField(addr) | q | size | s | Rt(vt));
}

void Assembler::ld1(const VRegister& vt, int lane, const MemOperand& src) {
  LoadStoreStructSingle(vt, lane, src, NEONLoadStoreSingleStructLoad1);
}

void Assembler::ld1r(const VRegister& vt, const MemOperand& src) {
  LoadStoreStructSingleAllLanes(vt, src, NEON_LD1R);
}

void Assembler::st1(const VRegister& vt, int lane, const MemOperand& dst) {
  LoadStoreStructSingle(vt, lane, dst, NEONLoadStoreSingleStructStore1);
}

void Assembler::dmb(BarrierDomain domain, BarrierType type) {
  Emit(DMB | ImmBarrierDomain(domain) | ImmBarrierType(type));
}

void Assembler::dsb(BarrierDomain domain, BarrierType type) {
  Emit(DSB | ImmBarrierDomain(domain) | ImmBarrierType(type));
}

void Assembler::isb() {
  Emit(ISB | ImmBarrierDomain(FullSystem) | ImmBarrierType(BarrierAll));
}

void Assembler::csdb() { hint(CSDB); }

void Assembler::fmov(const VRegister& vd, double imm) {
  if (vd.IsScalar()) {
    DCHECK(vd.Is1D());
    Emit(FMOV_d_imm | Rd(vd) | ImmFP(imm));
  } else {
    DCHECK(vd.Is2D());
    Instr op = NEONModifiedImmediate_MOVI | NEONModifiedImmediateOpBit;
    Emit(NEON_Q | op | ImmNEONFP(imm) | NEONCmode(0xF) | Rd(vd));
  }
}

void Assembler::fmov(const VRegister& vd, float imm) {
  if (vd.IsScalar()) {
    DCHECK(vd.Is1S());
    Emit(FMOV_s_imm | Rd(vd) | ImmFP(imm));
  } else {
    DCHECK(vd.Is2S() || vd.Is4S());
    Instr op = NEONModifiedImmediate_MOVI;
    Instr q = vd.Is4S() ? NEON_Q : 0;
    Emit(q | op | ImmNEONFP(imm) | NEONCmode(0xF) | Rd(vd));
  }
}

void Assembler::fmov(const Register& rd, const VRegister& fn) {
  DCHECK_EQ(rd.SizeInBits(), fn.SizeInBits());
  FPIntegerConvertOp op = rd.Is32Bits() ? FMOV_ws : FMOV_xd;
  Emit(op | Rd(rd) | Rn(fn));
}

void Assembler::fmov(const VRegister& vd, const Register& rn) {
  DCHECK_EQ(vd.SizeInBits(), rn.SizeInBits());
  FPIntegerConvertOp op = vd.Is32Bits() ? FMOV_sw : FMOV_dx;
  Emit(op | Rd(vd) | Rn(rn));
}

void Assembler::fmov(const VRegister& vd, const VRegister& vn) {
  DCHECK_EQ(vd.SizeInBits(), vn.SizeInBits());
  Emit(FPType(vd) | FMOV | Rd(vd) | Rn(vn));
}

void Assembler::fmov(const VRegister& vd, int index, const Register& rn) {
  DCHECK((index == 1) && vd.Is1D() && rn.IsX());
  USE(index);
  Emit(FMOV_d1_x | Rd(vd) | Rn(rn));
}

void Assembler::fmov(const Register& rd, const VRegister& vn, int index) {
  DCHECK((index == 1) && vn.Is1D() && rd.IsX());
  USE(index);
  Emit(FMOV_x_d1 | Rd(rd) | Rn(vn));
}

void Assembler::fmadd(const VRegister& fd, const VRegister& fn,
                      const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FMADD_s : FMADD_d);
}

void Assembler::fmsub(const VRegister& fd, const VRegister& fn,
                      const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FMSUB_s : FMSUB_d);
}

void Assembler::fnmadd(const VRegister& fd, const VRegister& fn,
                       const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FNMADD_s : FNMADD_d);
}

void Assembler::fnmsub(const VRegister& fd, const VRegister& fn,
                       const VRegister& fm, const VRegister& fa) {
  FPDataProcessing3Source(fd, fn, fm, fa, fd.Is32Bits() ? FNMSUB_s : FNMSUB_d);
}

void Assembler::fnmul(const VRegister& vd, const VRegister& vn,
                      const VRegister& vm) {
  DCHECK(AreSameSizeAndType(vd, vn, vm));
  Instr op = vd.Is1S() ? FNMUL_s : FNMUL_d;
  Emit(FPType(vd) | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::fcmp(const VRegister& fn, const VRegister& fm) {
  DCHECK_EQ(fn.SizeInBits(), fm.SizeInBits());
  Emit(FPType(fn) | FCMP | Rm(fm) | Rn(fn));
}

void Assembler::fcmp(const VRegister& fn, double value) {
  USE(value);
  // Although the fcmp instruction can strictly only take an immediate value of
  // +0.0, we don't need to check for -0.0 because the sign of 0.0 doesn't
  // affect the result of the comparison.
  DCHECK_EQ(value, 0.0);
  Emit(FPType(fn) | FCMP_zero | Rn(fn));
}

void Assembler::fccmp(const VRegister& fn, const VRegister& fm,
                      StatusFlags nzcv, Condition cond) {
  DCHECK_EQ(fn.SizeInBits(), fm.SizeInBits());
  Emit(FPType(fn) | FCCMP | Rm(fm) | Cond(cond) | Rn(fn) | Nzcv(nzcv));
}

void Assembler::fcsel(const VRegister& fd, const VRegister& fn,
                      const VRegister& fm, Condition cond) {
  DCHECK_EQ(fd.SizeInBits(), fn.SizeInBits());
  DCHECK_EQ(fd.SizeInBits(), fm.SizeInBits());
  Emit(FPType(fd) | FCSEL | Rm(fm) | Cond(cond) | Rn(fn) | Rd(fd));
}

void Assembler::NEONFPConvertToInt(const Register& rd, const VRegister& vn,
                                   Instr op) {
  Emit(SF(rd) | FPType(vn) | op | Rn(vn) | Rd(rd));
}

void Assembler::NEONFPConvertToInt(const VRegister& vd, const VRegister& vn,
                                   Instr op) {
  if (vn.IsScalar()) {
    DCHECK((vd.Is1S() && vn.Is1S()) || (vd.Is1D() && vn.Is1D()));
    op |= NEON_Q | NEONScalar;
  }
  Emit(FPFormat(vn) | op | Rn(vn) | Rd(vd));
}

void Assembler::fcvt(const VRegister& vd, const VRegister& vn) {
  FPDataProcessing1SourceOp op;
  if (vd.Is1D()) {
    DCHECK(vn.Is1S() || vn.Is1H());
    op = vn.Is1S() ? FCVT_ds : FCVT_dh;
  } else if (vd.Is1S()) {
    DCHECK(vn.Is1D() || vn.Is1H());
    op = vn.Is1D() ? FCVT_sd : FCVT_sh;
  } else {
    DCHECK(vd.Is1H());
    DCHECK(vn.Is1D() || vn.Is1S());
    op = vn.Is1D() ? FCVT_hd : FCVT_hs;
  }
  FPDataProcessing1Source(vd, vn, op);
}

void Assembler::fcvtl(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is4S() && vn.Is4H()) || (vd.Is2D() && vn.Is2S()));
  Instr format = vd.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(format | NEON_FCVTL | Rn(vn) | Rd(vd));
}

void Assembler::fcvtl2(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is4S() && vn.Is8H()) || (vd.Is2D() && vn.Is4S()));
  Instr format = vd.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(NEON_Q | format | NEON_FCVTL | Rn(vn) | Rd(vd));
}

void Assembler::fcvtn(const VRegister& vd, const VRegister& vn) {
  DCHECK((vn.Is4S() && vd.Is4H()) || (vn.Is2D() && vd.Is2S()));
  Instr format = vn.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(format | NEON_FCVTN | Rn(vn) | Rd(vd));
}

void Assembler::fcvtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK((vn.Is4S() && vd.Is8H()) || (vn.Is2D() && vd.Is4S()));
  Instr format = vn.Is2D() ? (1 << NEONSize_offset) : 0;
  Emit(NEON_Q | format | NEON_FCVTN | Rn(vn) | Rd(vd));
}

void Assembler::fcvtxn(const VRegister& vd, const VRegister& vn) {
  Instr format = 1 << NEONSize_offset;
  if (vd.IsScalar()) {
    DCHECK(vd.Is1S() && vn.Is1D());
    Emit(format | NEON_FCVTXN_scalar | Rn(vn) | Rd(vd));
  } else {
    DCHECK(vd.Is2S() && vn.Is2D());
    Emit(format | NEON_FCVTXN | Rn(vn) | Rd(vd));
  }
}

void Assembler::fcvtxn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.Is4S() && vn.Is2D());
  Instr format = 1 << NEONSize_offset;
  Emit(NEON_Q | format | NEON_FCVTXN | Rn(vn) | Rd(vd));
}

void Assembler::fjcvtzs(const Register& rd, const VRegister& vn) {
  DCHECK(rd.IsW() && vn.Is1D());
  Emit(FJCVTZS | Rn(vn) | Rd(rd));
}

#define NEON_FP2REGMISC_FCVT_LIST(V) \
  V(fcvtnu, NEON_FCVTNU, FCVTNU)     \
  V(fcvtns, NEON_FCVTNS, FCVTNS)     \
  V(fcvtpu, NEON_FCVTPU, FCVTPU)     \
  V(fcvtps, NEON_FCVTPS, FCVTPS)     \
  V(fcvtmu, NEON_FCVTMU, FCVTMU)     \
  V(fcvtms, NEON_FCVTMS, FCVTMS)     \
  V(fcvtau, NEON_FCVTAU, FCVTAU)     \
  V(fcvtas, NEON_FCVTAS, FCVTAS)

#define DEFINE_ASM_FUNCS(FN, VEC_OP, SCA_OP)                     \
  void Assembler::FN(const Register& rd, const VRegister& vn) {  \
    NEONFPConvertToInt(rd, vn, SCA_OP);                          \
  }                                                              \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    NEONFPConvertToInt(vd, vn, VEC_OP);                          \
  }
NEON_FP2REGMISC_FCVT_LIST(DEFINE_ASM_FUNCS)
#undef DEFINE_ASM_FUNCS

void Assembler::scvtf(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_SCVTF, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_SCVTF_imm);
  }
}

void Assembler::ucvtf(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_UCVTF, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_UCVTF_imm);
  }
}

void Assembler::scvtf(const VRegister& vd, const Register& rn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    Emit(SF(rn) | FPType(vd) | SCVTF | Rn(rn) | Rd(vd));
  } else {
    Emit(SF(rn) | FPType(vd) | SCVTF_fixed | FPScale(64 - fbits) | Rn(rn) |
         Rd(vd));
  }
}

void Assembler::ucvtf(const VRegister& fd, const Register& rn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    Emit(SF(rn) | FPType(fd) | UCVTF | Rn(rn) | Rd(fd));
  } else {
    Emit(SF(rn) | FPType(fd) | UCVTF_fixed | FPScale(64 - fbits) | Rn(rn) |
         Rd(fd));
  }
}

void Assembler::NEON3Same(const VRegister& vd, const VRegister& vn,
                          const VRegister& vm, NEON3SameOp vop) {
  DCHECK(AreSameFormat(vd, vn, vm));
  DCHECK(vd.IsVector() || !vd.IsQ());

  Instr format, op = vop;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
    format = SFormat(vd);
  } else {
    format = VFormat(vd);
  }

  Emit(format | op | Rm(vm) | Rn(vn) | Rd(vd));
}

void Assembler::NEONFP3Same(const VRegister& vd, const VRegister& vn,
                            const VRegister& vm, Instr op) {
  DCHECK(AreSameFormat(vd, vn, vm));
  if (vd.Is4H() || vd.Is8H()) {
    op |= NEON_sz;
    op ^= NEON3SameHPMask;
  }
  Emit(FPFormat(vd) | op | Rm(vm) | Rn(vn) | Rd(vd));
}

#define NEON_FP2REGMISC_LIST(V)                 \
  V(fabs, NEON_FABS, FABS)                      \
  V(fneg, NEON_FNEG, FNEG)                      \
  V(fsqrt, NEON_FSQRT, FSQRT)                   \
  V(frintn, NEON_FRINTN, FRINTN)                \
  V(frinta, NEON_FRINTA, FRINTA)                \
  V(frintp, NEON_FRINTP, FRINTP)                \
  V(frintm, NEON_FRINTM, FRINTM)                \
  V(frintx, NEON_FRINTX, FRINTX)                \
  V(frintz, NEON_FRINTZ, FRINTZ)                \
  V(frinti, NEON_FRINTI, FRINTI)                \
  V(frsqrte, NEON_FRSQRTE, NEON_FRSQRTE_scalar) \
  V(frecpe, NEON_FRECPE, NEON_FRECPE_scalar)

#define DEFINE_ASM_FUNC(FN, VEC_OP, SCA_OP)                      \
  void Assembler::FN(const VRegister& vd, const VRegister& vn) { \
    if (vd.IsScalar()) {                                         \
      DCHECK(vd.Is1S() || vd.Is1D());                            \
      NEONFP2RegMisc(vd, vn, SCA_OP);                            \
    } else {                                                     \
      NEONFP2RegMisc(vd, vn, VEC_OP, 0.0);                       \
    }                                                            \
  }
NEON_FP2REGMISC_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::shll(const VRegister& vd, const VRegister& vn, int shift) {
  DCHECK((vd.Is8H() && vn.Is8B() && shift == 8) ||
         (vd.Is4S() && vn.Is4H() && shift == 16) ||
         (vd.Is2D() && vn.Is2S() && shift == 32));
  USE(shift);
  Emit(VFormat(vn) | NEON_SHLL | Rn(vn) | Rd(vd));
}

void Assembler::shll2(const VRegister& vd, const VRegister& vn, int shift) {
  USE(shift);
  DCHECK((vd.Is8H() && vn.Is16B() && shift == 8) ||
         (vd.Is4S() && vn.Is8H() && shift == 16) ||
         (vd.Is2D() && vn.Is4S() && shift == 32));
  Emit(VFormat(vn) | NEON_SHLL | Rn(vn) | Rd(vd));
}

void Assembler::NEONFP2RegMisc(const VRegister& vd, const VRegister& vn,
                               NEON2RegMiscOp vop, double value) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK_EQ(value, 0.0);
  USE(value);

  Instr op = vop;
  if (vd.IsScalar()) {
    DCHECK(vd.Is1S() || vd.Is1D());
    op |= NEON_Q | NEONScalar;
  } else if (vd.Is4H() || vd.Is8H()) {
    op |= NEON_sz | NEON2RegMiscHPFixed;
  } else {
    DCHECK(vd.Is2S() || vd.Is2D() || vd.Is4S());
  }

  Emit(FPFormat(vd) | op | Rn(vn) | Rd(vd));
}

void Assembler::fcmeq(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMEQ_zero, value);
}

void Assembler::fcmge(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMGE_zero, value);
}

void Assembler::fcmgt(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMGT_zero, value);
}

void Assembler::fcmle(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMLE_zero, value);
}

void Assembler::fcmlt(const VRegister& vd, const VRegister& vn, double value) {
  NEONFP2RegMisc(vd, vn, NEON_FCMLT_zero, value);
}

void Assembler::frecpx(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar());
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is1S() || vd.Is1D());
  Emit(FPFormat(vd) | NEON_FRECPX_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fcvtzs(const Register& rd, const VRegister& vn, int fbits) {
  DCHECK(vn.Is1S() || vn.Is1D());
  DCHECK((fbits >= 0) && (fbits <= rd.SizeInBits()));
  if (fbits == 0) {
    Emit(SF(rd) | FPType(vn) | FCVTZS | Rn(vn) | Rd(rd));
  } else {
    Emit(SF(rd) | FPType(vn) | FCVTZS_fixed | FPScale(64 - fbits) | Rn(vn) |
         Rd(rd));
  }
}

void Assembler::fcvtzs(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_FCVTZS, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_FCVTZS_imm);
  }
}

void Assembler::fcvtzu(const Register& rd, const VRegister& vn, int fbits) {
  DCHECK(vn.Is1S() || vn.Is1D());
  DCHECK((fbits >= 0) && (fbits <= rd.SizeInBits()));
  if (fbits == 0) {
    Emit(SF(rd) | FPType(vn) | FCVTZU | Rn(vn) | Rd(rd));
  } else {
    Emit(SF(rd) | FPType(vn) | FCVTZU_fixed | FPScale(64 - fbits) | Rn(vn) |
         Rd(rd));
  }
}

void Assembler::fcvtzu(const VRegister& vd, const VRegister& vn, int fbits) {
  DCHECK_GE(fbits, 0);
  if (fbits == 0) {
    NEONFP2RegMisc(vd, vn, NEON_FCVTZU, 0.0);
  } else {
    DCHECK(vd.Is1D() || vd.Is1S() || vd.Is2D() || vd.Is2S() || vd.Is4S());
    NEONShiftRightImmediate(vd, vn, fbits, NEON_FCVTZU_imm);
  }
}

void Assembler::NEONFP2RegMisc(const VRegister& vd, const VRegister& vn,
                               Instr op) {
  DCHECK(AreSameFormat(vd, vn));
  Emit(FPFormat(vd) | op | Rn(vn) | Rd(vd));
}

void Assembler::NEON2RegMisc(const VRegister& vd, const VRegister& vn,
                             NEON2RegMiscOp vop, int value) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK_EQ(value, 0);
  USE(value);

  Instr format, op = vop;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
    format = SFormat(vd);
  } else {
    format = VFormat(vd);
  }

  Emit(format | op | Rn(vn) | Rd(vd));
}

void Assembler::cmeq(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMEQ_zero, value);
}

void Assembler::cmge(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMGE_zero, value);
}

void Assembler::cmgt(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMGT_zero, value);
}

void Assembler::cmle(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMLE_zero, value);
}

void Assembler::cmlt(const VRegister& vd, const VRegister& vn, int value) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_CMLT_zero, value);
}

#define NEON_3SAME_LIST(V)                                         \
  V(add, NEON_ADD, vd.IsVector() || vd.Is1D())                     \
  V(addp, NEON_ADDP, vd.IsVector() || vd.Is1D())                   \
  V(sub, NEON_SUB, vd.IsVector() || vd.Is1D())                     \
  V(cmeq, NEON_CMEQ, vd.IsVector() || vd.Is1D())                   \
  V(cmge, NEON_CMGE, vd.IsVector() || vd.Is1D())                   \
  V(cmgt, NEON_CMGT, vd.IsVector() || vd.Is1D())                   \
  V(cmhi, NEON_CMHI, vd.IsVector() || vd.Is1D())                   \
  V(cmhs, NEON_CMHS, vd.IsVector() || vd.Is1D())                   \
  V(cmtst, NEON_CMTST, vd.IsVector() || vd.Is1D())                 \
  V(sshl, NEON_SSHL, vd.IsVector() || vd.Is1D())                   \
  V(ushl, NEON_USHL, vd.IsVector() || vd.Is1D())                   \
  V(srshl, NEON_SRSHL, vd.IsVector() || vd.Is1D())                 \
  V(urshl, NEON_URSHL, vd.IsVector() || vd.Is1D())                 \
  V(sqdmulh, NEON_SQDMULH, vd.IsLaneSizeH() || vd.IsLaneSizeS())   \
  V(sqrdmulh, NEON_SQRDMULH, vd.IsLaneSizeH() || vd.IsLaneSizeS()) \
  V(shadd, NEON_SHADD, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(uhadd, NEON_UHADD, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(srhadd, NEON_SRHADD, vd.IsVector() && !vd.IsLaneSizeD())       \
  V(urhadd, NEON_URHADD, vd.IsVector() && !vd.IsLaneSizeD())       \
  V(shsub, NEON_SHSUB, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(uhsub, NEON_UHSUB, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(smax, NEON_SMAX, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(smaxp, NEON_SMAXP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(smin, NEON_SMIN, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(sminp, NEON_SMINP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(umax, NEON_UMAX, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(umaxp, NEON_UMAXP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(umin, NEON_UMIN, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(uminp, NEON_UMINP, vd.IsVector() && !vd.IsLaneSizeD())         \
  V(saba, NEON_SABA, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(sabd, NEON_SABD, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(uaba, NEON_UABA, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(uabd, NEON_UABD, vd.IsVector() && !vd.IsLaneSizeD())           \
  V(mla, NEON_MLA, vd.IsVector() && !vd.IsLaneSizeD())             \
  V(mls, NEON_MLS, vd.IsVector() && !vd.IsLaneSizeD())             \
  V(mul, NEON_MUL, vd.IsVector() && !vd.IsLaneSizeD())             \
  V(and_, NEON_AND, vd.Is8B() || vd.Is16B())                       \
  V(orr, NEON_ORR, vd.Is8B() || vd.Is16B())                        \
  V(orn, NEON_ORN, vd.Is8B() || vd.Is16B())                        \
  V(eor, NEON_EOR, vd.Is8B() || vd.Is16B())                        \
  V(bic, NEON_BIC, vd.Is8B() || vd.Is16B())                        \
  V(bit, NEON_BIT, vd.Is8B() || vd.Is16B())                        \
  V(bif, NEON_BIF, vd.Is8B() || vd.Is16B())                        \
  V(bsl, NEON_BSL, vd.Is8B() || vd.Is16B())                        \
  V(pmul, NEON_PMUL, vd.Is8B() || vd.Is16B())                      \
  V(uqadd, NEON_UQADD, true)                                       \
  V(sqadd, NEON_SQADD, true)                                       \
  V(uqsub, NEON_UQSUB, true)                                       \
  V(sqsub, NEON_SQSUB, true)                                       \
  V(sqshl, NEON_SQSHL, true)                                       \
  V(uqshl, NEON_UQSHL, true)                                       \
  V(sqrshl, NEON_SQRSHL, true)                                     \
  V(uqrshl, NEON_UQRSHL, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm) {                    \
    DCHECK(AS);                                                \
    NEON3Same(vd, vn, vm, OP);                                 \
  }
NEON_3SAME_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_FP3SAME_LIST_V2(V)                 \
  V(fadd, NEON_FADD, FADD)                      \
  V(fsub, NEON_FSUB, FSUB)                      \
  V(fmul, NEON_FMUL, FMUL)                      \
  V(fdiv, NEON_FDIV, FDIV)                      \
  V(fmax, NEON_FMAX, FMAX)                      \
  V(fmaxnm, NEON_FMAXNM, FMAXNM)                \
  V(fmin, NEON_FMIN, FMIN)                      \
  V(fminnm, NEON_FMINNM, FMINNM)                \
  V(fmulx, NEON_FMULX, NEON_FMULX_scalar)       \
  V(frecps, NEON_FRECPS, NEON_FRECPS_scalar)    \
  V(frsqrts, NEON_FRSQRTS, NEON_FRSQRTS_scalar) \
  V(fabd, NEON_FABD, NEON_FABD_scalar)          \
  V(fmla, NEON_FMLA, 0)                         \
  V(fmls, NEON_FMLS, 0)                         \
  V(facge, NEON_FACGE, NEON_FACGE_scalar)       \
  V(facgt, NEON_FACGT, NEON_FACGT_scalar)       \
  V(fcmeq, NEON_FCMEQ, NEON_FCMEQ_scalar)       \
  V(fcmge, NEON_FCMGE, NEON_FCMGE_scalar)       \
  V(fcmgt, NEON_FCMGT, NEON_FCMGT_scalar)       \
  V(faddp, NEON_FADDP, 0)                       \
  V(fmaxp, NEON_FMAXP, 0)                       \
  V(fminp, NEON_FMINP, 0)                       \
  V(fmaxnmp, NEON_FMAXNMP, 0)                   \
  V(fminnmp, NEON_FMINNMP, 0)

#define DEFINE_ASM_FUNC(FN, VEC_OP, SCA_OP)                                  \
  void Assembler::FN(const VRegister& vd, const VRegister& vn,               \
                     const VRegister& vm) {                                  \
    Instr op;                                                                \
    if ((SCA_OP != 0) && vd.IsScalar()) {                                    \
      DCHECK(vd.Is1S() || vd.Is1D());                                        \
      op = SCA_OP;                                                           \
    } else {                                                                 \
      DCHECK(vd.IsVector());                                                 \
      DCHECK(vd.Is2S() || vd.Is2D() || vd.Is4S() || vd.Is4H() || vd.Is8H()); \
      op = VEC_OP;                                                           \
    }                                                                        \
    NEONFP3Same(vd, vn, vm, op);                                             \
  }
NEON_FP3SAME_LIST_V2(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::addp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1D() && vn.Is2D()));
  Emit(SFormat(vd) | NEON_ADDP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::faddp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FADDP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fmaxp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMAXP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fminp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMINP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fmaxnmp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMAXNMP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::fminnmp(const VRegister& vd, const VRegister& vn) {
  DCHECK((vd.Is1S() && vn.Is2S()) || (vd.Is1D() && vn.Is2D()));
  Emit(FPFormat(vd) | NEON_FMINNMP_scalar | Rn(vn) | Rd(vd));
}

void Assembler::orr(const VRegister& vd, const int imm8, const int left_shift) {
  NEONModifiedImmShiftLsl(vd, imm8, left_shift, NEONModifiedImmediate_ORR);
}

void Assembler::mov(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  if (vd.IsD()) {
    orr(vd.V8B(), vn.V8B(), vn.V8B());
  } else {
    DCHECK(vd.IsQ());
    orr(vd.V16B(), vn.V16B(), vn.V16B());
  }
}

void Assembler::bic(const VRegister& vd, const int imm8, const int left_shift) {
  NEONModifiedImmShiftLsl(vd, imm8, left_shift, NEONModifiedImmediate_BIC);
}

void Assembler::movi(const VRegister& vd, const uint64_t imm, Shift shift,
                     const int shift_amount) {
  DCHECK((shift == LSL) || (shift == MSL));
  if (vd.Is2D() || vd.Is1D()) {
    DCHECK_EQ(shift_amount, 0);
    int imm8 = 0;
    for (int i = 0; i < 8; ++i) {
      int byte = (imm >> (i * 8)) & 0xFF;
      DCHECK((byte == 0) || (byte == 0xFF));
      if (byte == 0xFF) {
        imm8 |= (1 << i);
      }
    }
    Instr q = vd.Is2D() ? NEON_Q : 0;
    Emit(q | NEONModImmOp(1) | NEONModifiedImmediate_MOVI |
         ImmNEONabcdefgh(imm8) | NEONCmode(0xE) | Rd(vd));
  } else if (shift == LSL) {
    DCHECK(is_uint8(imm));
    NEONModifiedImmShiftLsl(vd, static_cast<int>(imm), shift_amount,
                            NEONModifiedImmediate_MOVI);
  } else {
    DCHECK(is_uint8(imm));
    NEONModifiedImmShiftMsl(vd, static_cast<int>(imm), shift_amount,
                            NEONModifiedImmediate_MOVI);
  }
}

void Assembler::mvn(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  if (vd.IsD()) {
    not_(vd.V8B(), vn.V8B());
  } else {
    DCHECK(vd.IsQ());
    not_(vd.V16B(), vn.V16B());
  }
}

void Assembler::mvni(const VRegister& vd, const int imm8, Shift shift,
                     const int shift_amount) {
  DCHECK((shift == LSL) || (shift == MSL));
  if (shift == LSL) {
    NEONModifiedImmShiftLsl(vd, imm8, shift_amount, NEONModifiedImmediate_MVNI);
  } else {
    NEONModifiedImmShiftMsl(vd, imm8, shift_amount, NEONModifiedImmediate_MVNI);
  }
}

void Assembler::NEONFPByElement(const VRegister& vd, const VRegister& vn,
                                const VRegister& vm, int vm_index,
                                NEONByIndexedElementOp vop) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK((vd.Is2S() && vm.Is1S()) || (vd.Is4S() && vm.Is1S()) ||
         (vd.Is1S() && vm.Is1S()) || (vd.Is2D() && vm.Is1D()) ||
         (vd.Is1D() && vm.Is1D()));
  DCHECK((vm.Is1S() && (vm_index < 4)) || (vm.Is1D() && (vm_index < 2)));

  Instr op = vop;
  int index_num_bits = vm.Is1S() ? 2 : 1;
  if (vd.IsScalar()) {
    op |= NEON_Q | NEONScalar;
  }

  Emit(FPFormat(vd) | op | ImmNEONHLM(vm_index, index_num_bits) | Rm(vm) |
       Rn(vn) | Rd(vd));
}

void Assembler::NEONByElement(const VRegister& vd, const VRegister& vn,
                              const VRegister& vm, int vm_index,
                              NEONByIndexedElementOp vop) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK((vd.Is4H() && vm.Is1H()) || (vd.Is8H() && vm.Is1H()) ||
         (vd.Is1H() && vm.Is1H()) || (vd.Is2S() && vm.Is1S()) ||
         (vd.Is4S() && vm.Is1S()) || (vd.Is1S() && vm.Is1S()));
  DCHECK((vm.Is1H() && (vm.code() < 16) && (vm_index < 8)) ||
         (vm.Is1S() && (vm_index < 4)));

  Instr format, op = vop;
  int index_num_bits = vm.Is1H() ? 3 : 2;
  if (vd.IsScalar()) {
    op |= NEONScalar | NEON_Q;
    format = SFormat(vn);
  } else {
    format = VFormat(vn);
  }
  Emit(format | op | ImmNEONHLM(vm_index, index_num_bits) | Rm(vm) | Rn(vn) |
       Rd(vd));
}

void Assembler::NEONByElementL(const VRegister& vd, const VRegister& vn,
                               const VRegister& vm, int vm_index,
                               NEONByIndexedElementOp vop) {
  DCHECK((vd.Is4S() && vn.Is4H() && vm.Is1H()) ||
         (vd.Is4S() && vn.Is8H() && vm.Is1H()) ||
         (vd.Is1S() && vn.Is1H() && vm.Is1H()) ||
         (vd.Is2D() && vn.Is2S() && vm.Is1S()) ||
         (vd.Is2D() && vn.Is4S() && vm.Is1S()) ||
         (vd.Is1D() && vn.Is1S() && vm.Is1S()));

  DCHECK((vm.Is1H() && (vm.code() < 16) && (vm_index < 8)) ||
         (vm.Is1S() && (vm_index < 4)));

  Instr format, op = vop;
  int index_num_bits = vm.Is1H() ? 3 : 2;
  if (vd.IsScalar()) {
    op |= NEONScalar | NEON_Q;
    format = SFormat(vn);
  } else {
    format = VFormat(vn);
  }
  Emit(format | op | ImmNEONHLM(vm_index, index_num_bits) | Rm(vm) | Rn(vn) |
       Rd(vd));
}

#define NEON_BYELEMENT_LIST(V)              \
  V(mul, NEON_MUL_byelement, vn.IsVector()) \
  V(mla, NEON_MLA_byelement, vn.IsVector()) \
  V(mls, NEON_MLS_byelement, vn.IsVector()) \
  V(sqdmulh, NEON_SQDMULH_byelement, true)  \
  V(sqrdmulh, NEON_SQRDMULH_byelement, true)

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm, int vm_index) {      \
    DCHECK(AS);                                                \
    NEONByElement(vd, vn, vm, vm_index, OP);                   \
  }
NEON_BYELEMENT_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_FPBYELEMENT_LIST(V) \
  V(fmul, NEON_FMUL_byelement)   \
  V(fmla, NEON_FMLA_byelement)   \
  V(fmls, NEON_FMLS_byelement)   \
  V(fmulx, NEON_FMULX_byelement)

#define DEFINE_ASM_FUNC(FN, OP)                                \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm, int vm_index) {      \
    NEONFPByElement(vd, vn, vm, vm_index, OP);                 \
  }
NEON_FPBYELEMENT_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

#define NEON_BYELEMENT_LONG_LIST(V)                              \
  V(sqdmull, NEON_SQDMULL_byelement, vn.IsScalar() || vn.IsD())  \
  V(sqdmull2, NEON_SQDMULL_byelement, vn.IsVector() && vn.IsQ()) \
  V(sqdmlal, NEON_SQDMLAL_byelement, vn.IsScalar() || vn.IsD())  \
  V(sqdmlal2, NEON_SQDMLAL_byelement, vn.IsVector() && vn.IsQ()) \
  V(sqdmlsl, NEON_SQDMLSL_byelement, vn.IsScalar() || vn.IsD())  \
  V(sqdmlsl2, NEON_SQDMLSL_byelement, vn.IsVector() && vn.IsQ()) \
  V(smull, NEON_SMULL_byelement, vn.IsVector() && vn.IsD())      \
  V(smull2, NEON_SMULL_byelement, vn.IsVector() && vn.IsQ())     \
  V(umull, NEON_UMULL_byelement, vn.IsVector() && vn.IsD())      \
  V(umull2, NEON_UMULL_byelement, vn.IsVector() && vn.IsQ())     \
  V(smlal, NEON_SMLAL_byelement, vn.IsVector() && vn.IsD())      \
  V(smlal2, NEON_SMLAL_byelement, vn.IsVector() && vn.IsQ())     \
  V(umlal, NEON_UMLAL_byelement, vn.IsVector() && vn.IsD())      \
  V(umlal2, NEON_UMLAL_byelement, vn.IsVector() && vn.IsQ())     \
  V(smlsl, NEON_SMLSL_byelement, vn.IsVector() && vn.IsD())      \
  V(smlsl2, NEON_SMLSL_byelement, vn.IsVector() && vn.IsQ())     \
  V(umlsl, NEON_UMLSL_byelement, vn.IsVector() && vn.IsD())      \
  V(umlsl2, NEON_UMLSL_byelement, vn.IsVector() && vn.IsQ())

#define DEFINE_ASM_FUNC(FN, OP, AS)                            \
  void Assembler::FN(const VRegister& vd, const VRegister& vn, \
                     const VRegister& vm, int vm_index) {      \
    DCHECK(AS);                                                \
    NEONByElementL(vd, vn, vm, vm_index, OP);                  \
  }
NEON_BYELEMENT_LONG_LIST(DEFINE_ASM_FUNC)
#undef DEFINE_ASM_FUNC

void Assembler::suqadd(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_SUQADD);
}

void Assembler::usqadd(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_USQADD);
}

void Assembler::abs(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_ABS);
}

void Assembler::sqabs(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_SQABS);
}

void Assembler::neg(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() || vd.Is1D());
  NEON2RegMisc(vd, vn, NEON_NEG);
}

void Assembler::sqneg(const VRegister& vd, const VRegister& vn) {
  NEON2RegMisc(vd, vn, NEON_SQNEG);
}

void Assembler::NEONXtn(const VRegister& vd, const VRegister& vn,
                        NEON2RegMiscOp vop) {
  Instr format, op = vop;
  if (vd.IsScalar()) {
    DCHECK((vd.Is1B() && vn.Is1H()) || (vd.Is1H() && vn.Is1S()) ||
           (vd.Is1S() && vn.Is1D()));
    op |= NEON_Q | NEONScalar;
    format = SFormat(vd);
  } else {
    DCHECK((vd.Is8B() && vn.Is8H()) || (vd.Is4H() && vn.Is4S()) ||
           (vd.Is2S() && vn.Is2D()) || (vd.Is16B() && vn.Is8H()) ||
           (vd.Is8H() && vn.Is4S()) || (vd.Is4S() && vn.Is2D()));
    format = VFormat(vd);
  }
  Emit(format | op | Rn(vn) | Rd(vd));
}

void Assembler::xtn(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsD());
  NEONXtn(vd, vn, NEON_XTN);
}

void Assembler::xtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_XTN);
}

void Assembler::sqxtn(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar() || vd.IsD());
  NEONXtn(vd, vn, NEON_SQXTN);
}

void Assembler::sqxtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_SQXTN);
}

void Assembler::sqxtun(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar() || vd.IsD());
  NEONXtn(vd, vn, NEON_SQXTUN);
}

void Assembler::sqxtun2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_SQXTUN);
}

void Assembler::uqxtn(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsScalar() || vd.IsD());
  NEONXtn(vd, vn, NEON_UQXTN);
}

void Assembler::uqxtn2(const VRegister& vd, const VRegister& vn) {
  DCHECK(vd.IsVector() && vd.IsQ());
  NEONXtn(vd, vn, NEON_UQXTN);
}

// NEON NOT and RBIT are distinguised by bit 22, the bottom bit of "size".
void Assembler::not_(const VRegister& vd, const VRegister& vn) {
  DCHECK(AreSameFormat(vd, vn));
  DCHECK(vd.Is8B(
```