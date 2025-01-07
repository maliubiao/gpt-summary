Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/arm64/simulator-arm64.cc`.

Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Functionality:** The code is within a `Simulator` class and contains methods named `Visit...`. This strongly suggests that the code simulates the execution of ARM64 instructions. Each `Visit` method likely corresponds to a different instruction or instruction category.

2. **Categorize the `Visit` Methods:**  Scan through the `Visit` methods and look for patterns in their names and the operations they perform. Common categories emerge:
    * **Data Processing:** Instructions that perform arithmetic, logical, and bitwise operations on registers (`VisitMoveImmediate`, `VisitConditionalSelect`, `VisitDataProcessing1Source`, `VisitDataProcessing2Source`, `VisitDataProcessing3Source`, `VisitBitfield`, `VisitExtract`).
    * **Floating-Point Operations:** Instructions for floating-point arithmetic, comparison, conversion, and manipulation (`VisitFPImmediate`, `VisitFPIntegerConvert`, `VisitFPFixedPointConvert`, `VisitFPCompare`, `VisitFPConditionalCompare`, `VisitFPConditionalSelect`, `VisitFPDataProcessing1Source`, `VisitFPDataProcessing2Source`, `VisitFPDataProcessing3Source`).
    * **System Instructions:** Instructions that interact with the system or control processor state (`VisitSystem`).
    * **Debug/Utility Functions:** Functions for debugging and examining the simulator's state (`GetValue`, `PrintValue`, `Debug`, `ExecDebugCommand`).

3. **Look for Connections to JavaScript (as requested):** While the simulator itself doesn't directly *execute* JavaScript, it's a *part* of the V8 engine, which *does* execute JavaScript. The simulator is used for testing and development of the ARM64 backend for V8. Therefore, its functionality is *related* to how JavaScript code would eventually be executed on ARM64. Think about high-level JavaScript concepts and how they might map to low-level operations. For example, JavaScript numbers rely on floating-point representation, so the FP-related instructions are relevant. Bitwise operators in JavaScript correspond to the bitwise operations simulated here.

4. **Address the `.tq` Check:** The prompt explicitly asks about `.tq` files. The code provided is `.cc`, so it's C++. Torque is a different language within V8. State clearly that this file is C++, not Torque.

5. **Provide JavaScript Examples (if applicable):**  For categories with a clear JavaScript connection (like data processing and floating-point), provide simple JavaScript examples to illustrate the higher-level concept.

6. **Illustrate Code Logic with Input/Output:** Choose a simple `Visit` method (like `VisitMoveImmediate`) and demonstrate its logic with a clear input state (register values, immediate value) and the resulting output state (updated register value). Make sure to cover different cases within the instruction type (like different `mov_op` values).

7. **Give Examples of Common Programming Errors:** Think about common pitfalls when working with the types of operations being simulated. Integer overflow, division by zero, and incorrect bitwise operations are good candidates. Show simple C++ examples that would trigger these errors (and thus might be something the simulator needs to handle or model).

8. **Focus on Summarizing:**  The prompt specifically asks for a summary. Avoid going into excessive detail about every single instruction. Group related functionalities and describe them concisely.

9. **Structure the Answer:** Organize the information logically with clear headings to address each part of the prompt.

10. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness, addressing all parts of the user's request. For instance, double-check if the JavaScript examples are relevant and the input/output examples make sense. Ensure the summary is concise and captures the essence of the code.
```cpp
  // Compute the shifted immediate value.
  uint64_t shift = instr->ImmNEONShiftAmount() * 16;
  uint64_t shifted_imm16 = static_cast<uint64_t>(instr->ImmMoveWide()) << shift;

  // Compute the new value.
  switch (mov_op) {
    case MOVN_w:
    case MOVN_x: {
      new_xn_val = ~shifted_imm16;
      if (!is_64_bits) new_xn_val &= kWRegMask;
      break;
    }
    case MOVK_w:
    case MOVK_x: {
      unsigned reg_code = instr->Rd();
      int64_t prev_xn_val = is_64_bits ? xreg(reg_code) : wreg(reg_code);
      new_xn_val = (prev_xn_val & ~(INT64_C(0xFFFF) << shift)) | shifted_imm16;
      break;
    }
    case MOVZ_w:
    case MOVZ_x: {
      new_xn_val = shifted_imm16;
      break;
    }
    default:
      UNREACHABLE();
  }

  // Update the destination register.
  set_xreg(instr->Rd(), new_xn_val);
}

void Simulator::VisitConditionalSelect(Instruction* instr) {
  uint64_t new_val = xreg(instr->Rn());
  if (ConditionFailed(static_cast<Condition>(instr->Condition()))) {
    new_val = xreg(instr->Rm());
    switch (instr->Mask(ConditionalSelectMask)) {
      case CSEL_w:
      case CSEL_x:
        break;
      case CSINC_w:
      case CSINC_x:
        new_val++;
        break;
      case CSINV_w:
      case CSINV_x:
        new_val = ~new_val;
        break;
      case CSNEG_w:
      case CSNEG_x:
        // Simulate two's complement (instead of casting to signed and negating)
        // to avoid undefined behavior on signed overflow.
        new_val = (~new_val) + 1;
        break;
      default:
        UNIMPLEMENTED();
    }
  }
  if (instr->SixtyFourBits()) {
    set_xreg(instr->Rd(), new_val);
  } else {
    set_wreg(instr->Rd(), static_cast<uint32_t>(new_val));
  }
}

void Simulator::VisitDataProcessing1Source(Instruction* instr) {
  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();

  switch (instr->Mask(DataProcessing1SourceMask)) {
    case RBIT_w:
      set_wreg(dst, base::bits::ReverseBits(wreg(src)));
      break;
    case RBIT_x:
      set_xreg(dst, base::bits::ReverseBits(xreg(src)));
      break;
    case REV16_w:
      set_wreg(dst, ReverseBytes(wreg(src), 1));
      break;
    case REV16_x:
      set_xreg(dst, ReverseBytes(xreg(src), 1));
      break;
    case REV_w:
      set_wreg(dst, ReverseBytes(wreg(src), 2));
      break;
    case REV32_x:
      set_xreg(dst, ReverseBytes(xreg(src), 2));
      break;
    case REV_x:
      set_xreg(dst, ReverseBytes(xreg(src), 3));
      break;
    case CLZ_w:
      set_wreg(dst, CountLeadingZeros(wreg(src), kWRegSizeInBits));
      break;
    case CLZ_x:
      set_xreg(dst, CountLeadingZeros(xreg(src), kXRegSizeInBits));
      break;
    case CLS_w: {
      set_wreg(dst, CountLeadingSignBits(wreg(src), kWRegSizeInBits));
      break;
    }
    case CLS_x: {
      set_xreg(dst, CountLeadingSignBits(xreg(src), kXRegSizeInBits));
      break;
    }
    default:
      UNIMPLEMENTED();
  }
}

template <typename T>
void Simulator::DataProcessing2Source(Instruction* instr) {
  Shift shift_op = NO_SHIFT;
  T result = 0;
  switch (instr->Mask(DataProcessing2SourceMask)) {
    case SDIV_w:
    case SDIV_x: {
      T rn = reg<T>(instr->Rn());
      T rm = reg<T>(instr->Rm());
      if ((rn == std::numeric_limits<T>::min()) && (rm == -1)) {
        result = std::numeric_limits<T>::min();
      } else if (rm == 0) {
        // Division by zero can be trapped, but not on A-class processors.
        result = 0;
      } else {
        result = rn / rm;
      }
      break;
    }
    case UDIV_w:
    case UDIV_x: {
      using unsignedT = typename std::make_unsigned<T>::type;
      unsignedT rn = static_cast<unsignedT>(reg<T>(instr->Rn()));
      unsignedT rm = static_cast<unsignedT>(reg<T>(instr->Rm()));
      if (rm == 0) {
        // Division by zero can be trapped, but not on A-class processors.
        result = 0;
      } else {
        result = rn / rm;
      }
      break;
    }
    case LSLV_w:
    case LSLV_x:
      shift_op = LSL;
      break;
    case LSRV_w:
    case LSRV_x:
      shift_op = LSR;
      break;
    case ASRV_w:
    case ASRV_x:
      shift_op = ASR;
      break;
    case RORV_w:
    case RORV_x:
      shift_op = ROR;
      break;
    default:
      UNIMPLEMENTED();
  }

  if (shift_op != NO_SHIFT) {
    // Shift distance encoded in the least-significant five/six bits of the
    // register.
    unsigned shift = wreg(instr->Rm());
    if (sizeof(T) == kWRegSize) {
      shift &= kShiftAmountWRegMask;
    } else {
      shift &= kShiftAmountXRegMask;
    }
    result = ShiftOperand(reg<T>(instr->Rn()), shift_op, shift);
  }
  set_reg<T>(instr->Rd(), result);
}

void Simulator::VisitDataProcessing2Source(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    DataProcessing2Source<int64_t>(instr);
  } else {
    DataProcessing2Source<int32_t>(instr);
  }
}

void Simulator::VisitDataProcessing3Source(Instruction* instr) {
  int64_t result = 0;
  // Extract and sign- or zero-extend 32-bit arguments for widening operations.
  uint64_t rn_u32 = reg<uint32_t>(instr->Rn());
  uint64_t rm_u32 = reg<uint32_t>(instr->Rm());
  int64_t rn_s32 = reg<int32_t>(instr->Rn());
  int64_t rm_s32 = reg<int32_t>(instr->Rm());
  switch (instr->Mask(DataProcessing3SourceMask)) {
    case MADD_w:
    case MADD_x:
      result = base::AddWithWraparound(
          xreg(instr->Ra()),
          base::MulWithWraparound(xreg(instr->Rn()), xreg(instr->Rm())));
      break;
    case MSUB_w:
    case MSUB_x:
      result = base::SubWithWraparound(
          xreg(instr->Ra()),
          base::MulWithWraparound(xreg(instr->Rn()), xreg(instr->Rm())));
      break;
    case SMADDL_x:
      result = base::AddWithWraparound(xreg(instr->Ra()), (rn_s32 * rm_s32));
      break;
    case SMSUBL_x:
      result = base::SubWithWraparound(xreg(instr->Ra()), (rn_s32 * rm_s32));
      break;
    case UMADDL_x:
      result = static_cast<uint64_t>(xreg(instr->Ra())) + (rn_u32 * rm_u32);
      break;
    case UMSUBL_x:
      result = static_cast<uint64_t>(xreg(instr->Ra())) - (rn_u32 * rm_u32);
      break;
    case SMULH_x:
      DCHECK_EQ(instr->Ra(), kZeroRegCode);
      result =
          base::bits::SignedMulHigh64(xreg(instr->Rn()), xreg(instr->Rm()));
      break;
    case UMULH_x:
      DCHECK_EQ(instr->Ra(), kZeroRegCode);
      result =
          base::bits::UnsignedMulHigh64(xreg(instr->Rn()), xreg(instr->Rm()));
      break;
    default:
      UNIMPLEMENTED();
  }

  if (instr->SixtyFourBits()) {
    set_xreg(instr->Rd(), result);
  } else {
    set_wreg(instr->Rd(), static_cast<int32_t>(result));
  }
}

template <typename T>
void Simulator::BitfieldHelper(Instruction* instr) {
  using unsignedT = typename std::make_unsigned<T>::type;
  T reg_size = sizeof(T) * 8;
  T R = instr->ImmR();
  T S = instr->ImmS();
  T diff = S - R;
  T mask;
  if (diff >= 0) {
    mask = diff < reg_size - 1 ? (static_cast<unsignedT>(1) << (diff + 1)) - 1
                               : static_cast<T>(-1);
  } else {
    uint64_t umask = ((1ULL << (S + 1)) - 1);
    umask = (umask >> R) | (umask << (reg_size - R));
    mask = static_cast<T>(umask);
    diff += reg_size;
  }

  // inzero indicates if the extracted bitfield is inserted into the
  // destination register value or in zero.
  // If extend is true, extend the sign of the extracted bitfield.
  bool inzero = false;
  bool extend = false;
  switch (instr->Mask(BitfieldMask)) {
    case BFM_x:
    case BFM_w:
      break;
    case SBFM_x:
    case SBFM_w:
      inzero = true;
      extend = true;
      break;
    case UBFM_x:
    case UBFM_w:
      inzero = true;
      break;
    default:
      UNIMPLEMENTED();
  }

  T dst = inzero ? 0 : reg<T>(instr->Rd());
  T src = reg<T>(instr->Rn());
  // Rotate source bitfield into place.
  T result = R == 0 ? src
                    : (static_cast<unsignedT>(src) >> R) |
                          (static_cast<unsignedT>(src) << (reg_size - R));
  // Determine the sign extension.
  T topbits_preshift = (static_cast<unsignedT>(1) << (reg_size - diff - 1)) - 1;
  T signbits =
      diff >= reg_size - 1
          ? 0
          : ((extend && ((src >> S) & 1) ? topbits_preshift : 0) << (diff + 1));

  // Merge sign extension, dest/zero and bitfield.
  result = signbits | (result & mask) | (dst & ~mask);

  set_reg<T>(instr->Rd(), result);
}

void Simulator::VisitBitfield(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    BitfieldHelper<int64_t>(instr);
  } else {
    BitfieldHelper<int32_t>(instr);
  }
}

void Simulator::VisitExtract(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    Extract<uint64_t>(instr);
  } else {
    Extract<uint32_t>(instr);
  }
}

void Simulator::VisitFPImmediate(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dest = instr->Rd();
  switch (instr->Mask(FPImmediateMask)) {
    case FMOV_s_imm:
      set_sreg(dest, instr->ImmFP32());
      break;
    case FMOV_d_imm:
      set_dreg(dest, instr->ImmFP64());
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPIntegerConvert(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();

  FPRounding round = fpcr().RMode();

  switch (instr->Mask(FPIntegerConvertMask)) {
    case FCVTAS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPTieAway));
      break;
    case FCVTAS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPTieAway));
      break;
    case FCVTAS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPTieAway));
      break;
    case FCVTAS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPTieAway));
      break;
    case FCVTAU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPTieAway));
      break;
    case FCVTAU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPTieAway));
      break;
    case FCVTAU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPTieAway));
      break;
    case FCVTAU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPTieAway));
      break;
    case FCVTMS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPNegativeInfinity));
      break;
    case FCVTNS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPTieEven));
      break;
    case FCVTNS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPTieEven));
      break;
    case FCVTNS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPTieEven));
      break;
    case FCVTNS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPTieEven));
      break;
    case FCVTNU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPTieEven));
      break;
    case FCVTNU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPTieEven));
      break;
    case FCVTNU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPTieEven));
      break;
    case FCVTNU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPTieEven));
      break;
    case FCVTZS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPZero));
      break;
    case FCVTZS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPZero));
      break;
    case FCVTZS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPZero));
      break;
    case FCVTZS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPZero));
      break;
    case FCVTZU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPZero));
      break;
    case FCVTZU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPZero));
      break;
    case FCVTZU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPZero));
      break;
    case FCVTZU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPZero));
      break;
    case FJCVTZS:
      set_wreg(dst, FPToFixedJS(dreg(src)));
      break;
    case FMOV_ws:
      set_wreg(dst, sreg_bits(src));
      break;
    case FMOV_xd:
      set_xreg(dst, dreg_bits(src));
      break;
    case FMOV_sw:
      set_sreg_bits(dst, wreg(src));
      break;
    case FMOV_dx:
      set_dreg_bits(dst, xreg(src));
      break;

    // A 32-bit input can be handled in the same way as a 64-bit input, since
    // the sign- or zero-extension will not affect the conversion.
    case SCVTF_dx:
      set_dreg(dst, FixedToDouble(xreg(src), 0, round));
      break;
    case SCVTF_dw:
      set_dreg(dst, FixedToDouble(wreg(src), 0, round));
      break;
    case UCVTF_dx:
      set_dreg(dst, UFixedToDouble(xreg(src), 0, round));
      break;
    case UCVTF_dw: {
      set_dreg(dst, UFixedToDouble(reg<uint32_t>(src), 0, round));
      break;
    }
    case SCVTF_sx:
      set_sreg(dst, FixedToFloat(xreg(src), 0, round));
      break;
    case SCVTF_sw:
      set_sreg(dst, FixedToFloat(wreg(src), 0, round));
      break;
    case UCVTF_sx:
      set_sreg(dst, UFixedToFloat(xreg(src), 0, round));
      break;
    case UCVTF_sw: {
      set_sreg(dst, UFixedToFloat(reg<uint32_t>(src), 0, round));
      break;
    }

    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPFixedPointConvert(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();
  int fbits = 64 - instr->FPScale();

  FPRounding round = fpcr().RMode();

  switch (instr->Mask(FPFixedPointConvertMask)) {
    // A 32-bit input can be handled in the same way as a 64-bit input, since
    // the sign- or zero-extension will not affect the conversion.
    case SCVTF_dx_fixed:
      set_dreg(dst, FixedToDouble(xreg(src), fbits, round));
      break;
    case SCVTF_dw_fixed:
      set_dreg(dst, FixedToDouble(wreg(src), fbits, round));
      break;
    case UCVTF_dx_fixed:
      set_dreg(dst, UFixedToDouble(xreg(src), fbits, round));
      break;
    case UCVTF_dw_fixed: {
      set_dreg(dst, UFixedToDouble(reg<uint32_t>(src), fbits, round));
      break;
    }
    case SCVTF_sx_fixed:
      set_sreg(dst, FixedToFloat(xreg(src), fbits, round));
      break;
    case SCVTF_sw_fixed:
      set_sreg(dst, FixedToFloat(wreg(src), fbits, round));
      break;
    case UCVTF_sx_fixed:
      set_sreg(dst, UFixedToFloat(xreg(src), fbits, round));
      break;
    case UCVTF_sw_fixed: {
      set_sreg(dst, UFixedToFloat(reg<uint32_t>(src), fbits, round));
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPCompare(Instruction* instr) {
  AssertSupportedFPCR();

  switch (instr->Mask(FPCompareMask)) {
    case FCMP_s:
      FPCompare(sreg(instr->Rn()), sreg(instr->Rm()));
      break;
    case FCMP_d:
      FPCompare(dreg(instr->Rn()), dreg(instr->Rm()));
      break;
    case FCMP_s_zero:
      FPCompare(sreg(instr->Rn()), 0.0f);
      break;
    case FCMP_d_zero:
      FPCompare(dreg(instr->Rn()), 0.0);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPConditionalCompare(Instruction* instr) {
  AssertSupportedFPCR();

  switch (instr->Mask(FPConditionalCompareMask)) {
    case FCCMP_s:
      if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
        FPCompare(sreg(instr->Rn()), sreg(instr->Rm()));
      } else {
        nzcv().SetFlags(instr->Nzcv());
        LogSystemRegister(NZCV);
      }
      break;
    case FCCMP_d: {
      if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
        FPCompare(dreg(instr->Rn()), dreg(instr->Rm()));
      } else {
        // If the condition fails, set the status flags to the nzcv immediate.
        nzcv().SetFlags(instr->Nzcv());
        LogSystemRegister(NZCV);
      }
      break;
    }
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPConditionalSelect(Instruction* instr) {
  AssertSupportedFPCR();

  Instr selected;
  if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
    selected = instr->Rn();
  } else {
    selected = instr->Rm();
  }

  switch (instr->Mask(FPConditionalSelectMask)) {
    case FCSEL_s:
      set_sreg(instr->Rd(), sreg(selected));
      break;
    case FCSEL_d:
      set_dreg(instr->Rd(), dreg(selected));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPDataProcessing1Source(Instruction* instr) {
  AssertSupportedFPCR();

  FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());
  VectorFormat vform = (instr->Mask(FP64) == FP64) ? kFormatD : kFormatS;
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  bool inexact_exception = false;

  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();

  switch (instr->Mask(FPDataProcessing1SourceMask)) {
    case FMOV_s:
      set_sreg(fd, sreg(fn));
      return;
    case FMOV_d:
      set_dreg(fd, dreg(fn));
      return;
    case FABS_s:
    case FABS_d:
      fabs_(vform, vreg(fd), vreg(fn));
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FNEG_s:
    case FNEG_d:
      fneg(vform, vreg(fd), vreg(fn));
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FCVT_ds:
      set_dreg(fd, FPToDouble(sreg(fn)));
      return;
    case FCVT_sd:
      set_sreg(fd, FPToFloat(dreg(fn), FPTieEven));
      return;
    case FCVT_hs:
      set_hreg(fd, FPToFloat16(sreg(fn), FPTieEven));
      return;
    case FCVT_sh:
      set_sreg(fd, FPToFloat(hreg(fn)));
      return;
    case FCVT_dh:
      set_dreg(fd, FPToDouble(FPToFloat(hreg(fn))));
      return;
    case FCVT_hd:
      set_hreg(fd, FPToFloat16(dreg(fn), FPTieEven));
      return;
    case FSQRT_s:
    case FSQRT_d:
      fsqrt(vform, rd, rn);
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FRINTI_s:
    case FRINTI_d:
      break;  // Use FPCR rounding mode.
    case FRINTX_s:
    case FRINTX_d:
      inexact_exception = true;
      break;
    case FRINTA_s:
    case FRINTA_d:
      fpcr_rounding = FPTieAway;
      break;
    case FRINTM_s:
    case FRINTM_d:
      fpcr_rounding = FPNegativeInfinity;
      break;
    case FRINTN_s:
    case FRINTN_d:
      fpcr_rounding = FPTieEven;
      break;
    case FRINTP_s:
    case FRINTP_d:
      fpcr_rounding = FPPositiveInfinity;
      break;
    case FRINTZ_s:
    case FRINTZ_d:
      fpcr_rounding = FPZero;
      break;
    default:
      UNIMPLEMENTED();
  }

  // Only FRINT* instructions fall through the switch above.
  frint(vform, rd, rn, fpcr_rounding, inexact_exception);
  // Explicitly log the register update whilst we have type information
  LogVRegister(fd, GetPrintRegisterFormatFP(vform));
}

void Simulator::VisitFPDataProcessing2Source(Instruction* instr) {
  AssertSupportedFPCR();

  VectorFormat vform = (instr->Mask(FP64) == FP64) ? kFormatD : kFormatS;
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());

  switch (instr->Mask(FPDataProcessing2SourceMask)) {
    case FADD_s:
    case FADD_d:
      fadd(vform, rd, rn, rm);
      break;
    case FSUB_s:
    case FSUB_d:
      fsub(vform, rd, rn, rm);
      break;
    case FMUL_s:
    case FMUL_d:
      fmul(vform, rd, rn, rm);
      break;
    case FNMUL_s:
    case FNMUL_d:
      fnmul(vform, rd, rn, rm);
      break;
    case FDIV_s:
    case FDIV_d:
      fdiv(vform, rd, rn, rm);
      break;
    case FMAX_s:
    case FMAX_d:
      fmax(vform, rd, rn, rm);
      break;
    case FMIN_s:
Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
64_t>(instr->ImmMoveWide()) << shift;

  // Compute the new value.
  switch (mov_op) {
    case MOVN_w:
    case MOVN_x: {
      new_xn_val = ~shifted_imm16;
      if (!is_64_bits) new_xn_val &= kWRegMask;
      break;
    }
    case MOVK_w:
    case MOVK_x: {
      unsigned reg_code = instr->Rd();
      int64_t prev_xn_val = is_64_bits ? xreg(reg_code) : wreg(reg_code);
      new_xn_val = (prev_xn_val & ~(INT64_C(0xFFFF) << shift)) | shifted_imm16;
      break;
    }
    case MOVZ_w:
    case MOVZ_x: {
      new_xn_val = shifted_imm16;
      break;
    }
    default:
      UNREACHABLE();
  }

  // Update the destination register.
  set_xreg(instr->Rd(), new_xn_val);
}

void Simulator::VisitConditionalSelect(Instruction* instr) {
  uint64_t new_val = xreg(instr->Rn());
  if (ConditionFailed(static_cast<Condition>(instr->Condition()))) {
    new_val = xreg(instr->Rm());
    switch (instr->Mask(ConditionalSelectMask)) {
      case CSEL_w:
      case CSEL_x:
        break;
      case CSINC_w:
      case CSINC_x:
        new_val++;
        break;
      case CSINV_w:
      case CSINV_x:
        new_val = ~new_val;
        break;
      case CSNEG_w:
      case CSNEG_x:
        // Simulate two's complement (instead of casting to signed and negating)
        // to avoid undefined behavior on signed overflow.
        new_val = (~new_val) + 1;
        break;
      default:
        UNIMPLEMENTED();
    }
  }
  if (instr->SixtyFourBits()) {
    set_xreg(instr->Rd(), new_val);
  } else {
    set_wreg(instr->Rd(), static_cast<uint32_t>(new_val));
  }
}

void Simulator::VisitDataProcessing1Source(Instruction* instr) {
  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();

  switch (instr->Mask(DataProcessing1SourceMask)) {
    case RBIT_w:
      set_wreg(dst, base::bits::ReverseBits(wreg(src)));
      break;
    case RBIT_x:
      set_xreg(dst, base::bits::ReverseBits(xreg(src)));
      break;
    case REV16_w:
      set_wreg(dst, ReverseBytes(wreg(src), 1));
      break;
    case REV16_x:
      set_xreg(dst, ReverseBytes(xreg(src), 1));
      break;
    case REV_w:
      set_wreg(dst, ReverseBytes(wreg(src), 2));
      break;
    case REV32_x:
      set_xreg(dst, ReverseBytes(xreg(src), 2));
      break;
    case REV_x:
      set_xreg(dst, ReverseBytes(xreg(src), 3));
      break;
    case CLZ_w:
      set_wreg(dst, CountLeadingZeros(wreg(src), kWRegSizeInBits));
      break;
    case CLZ_x:
      set_xreg(dst, CountLeadingZeros(xreg(src), kXRegSizeInBits));
      break;
    case CLS_w: {
      set_wreg(dst, CountLeadingSignBits(wreg(src), kWRegSizeInBits));
      break;
    }
    case CLS_x: {
      set_xreg(dst, CountLeadingSignBits(xreg(src), kXRegSizeInBits));
      break;
    }
    default:
      UNIMPLEMENTED();
  }
}

template <typename T>
void Simulator::DataProcessing2Source(Instruction* instr) {
  Shift shift_op = NO_SHIFT;
  T result = 0;
  switch (instr->Mask(DataProcessing2SourceMask)) {
    case SDIV_w:
    case SDIV_x: {
      T rn = reg<T>(instr->Rn());
      T rm = reg<T>(instr->Rm());
      if ((rn == std::numeric_limits<T>::min()) && (rm == -1)) {
        result = std::numeric_limits<T>::min();
      } else if (rm == 0) {
        // Division by zero can be trapped, but not on A-class processors.
        result = 0;
      } else {
        result = rn / rm;
      }
      break;
    }
    case UDIV_w:
    case UDIV_x: {
      using unsignedT = typename std::make_unsigned<T>::type;
      unsignedT rn = static_cast<unsignedT>(reg<T>(instr->Rn()));
      unsignedT rm = static_cast<unsignedT>(reg<T>(instr->Rm()));
      if (rm == 0) {
        // Division by zero can be trapped, but not on A-class processors.
        result = 0;
      } else {
        result = rn / rm;
      }
      break;
    }
    case LSLV_w:
    case LSLV_x:
      shift_op = LSL;
      break;
    case LSRV_w:
    case LSRV_x:
      shift_op = LSR;
      break;
    case ASRV_w:
    case ASRV_x:
      shift_op = ASR;
      break;
    case RORV_w:
    case RORV_x:
      shift_op = ROR;
      break;
    default:
      UNIMPLEMENTED();
  }

  if (shift_op != NO_SHIFT) {
    // Shift distance encoded in the least-significant five/six bits of the
    // register.
    unsigned shift = wreg(instr->Rm());
    if (sizeof(T) == kWRegSize) {
      shift &= kShiftAmountWRegMask;
    } else {
      shift &= kShiftAmountXRegMask;
    }
    result = ShiftOperand(reg<T>(instr->Rn()), shift_op, shift);
  }
  set_reg<T>(instr->Rd(), result);
}

void Simulator::VisitDataProcessing2Source(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    DataProcessing2Source<int64_t>(instr);
  } else {
    DataProcessing2Source<int32_t>(instr);
  }
}

void Simulator::VisitDataProcessing3Source(Instruction* instr) {
  int64_t result = 0;
  // Extract and sign- or zero-extend 32-bit arguments for widening operations.
  uint64_t rn_u32 = reg<uint32_t>(instr->Rn());
  uint64_t rm_u32 = reg<uint32_t>(instr->Rm());
  int64_t rn_s32 = reg<int32_t>(instr->Rn());
  int64_t rm_s32 = reg<int32_t>(instr->Rm());
  switch (instr->Mask(DataProcessing3SourceMask)) {
    case MADD_w:
    case MADD_x:
      result = base::AddWithWraparound(
          xreg(instr->Ra()),
          base::MulWithWraparound(xreg(instr->Rn()), xreg(instr->Rm())));
      break;
    case MSUB_w:
    case MSUB_x:
      result = base::SubWithWraparound(
          xreg(instr->Ra()),
          base::MulWithWraparound(xreg(instr->Rn()), xreg(instr->Rm())));
      break;
    case SMADDL_x:
      result = base::AddWithWraparound(xreg(instr->Ra()), (rn_s32 * rm_s32));
      break;
    case SMSUBL_x:
      result = base::SubWithWraparound(xreg(instr->Ra()), (rn_s32 * rm_s32));
      break;
    case UMADDL_x:
      result = static_cast<uint64_t>(xreg(instr->Ra())) + (rn_u32 * rm_u32);
      break;
    case UMSUBL_x:
      result = static_cast<uint64_t>(xreg(instr->Ra())) - (rn_u32 * rm_u32);
      break;
    case SMULH_x:
      DCHECK_EQ(instr->Ra(), kZeroRegCode);
      result =
          base::bits::SignedMulHigh64(xreg(instr->Rn()), xreg(instr->Rm()));
      break;
    case UMULH_x:
      DCHECK_EQ(instr->Ra(), kZeroRegCode);
      result =
          base::bits::UnsignedMulHigh64(xreg(instr->Rn()), xreg(instr->Rm()));
      break;
    default:
      UNIMPLEMENTED();
  }

  if (instr->SixtyFourBits()) {
    set_xreg(instr->Rd(), result);
  } else {
    set_wreg(instr->Rd(), static_cast<int32_t>(result));
  }
}

template <typename T>
void Simulator::BitfieldHelper(Instruction* instr) {
  using unsignedT = typename std::make_unsigned<T>::type;
  T reg_size = sizeof(T) * 8;
  T R = instr->ImmR();
  T S = instr->ImmS();
  T diff = S - R;
  T mask;
  if (diff >= 0) {
    mask = diff < reg_size - 1 ? (static_cast<unsignedT>(1) << (diff + 1)) - 1
                               : static_cast<T>(-1);
  } else {
    uint64_t umask = ((1ULL << (S + 1)) - 1);
    umask = (umask >> R) | (umask << (reg_size - R));
    mask = static_cast<T>(umask);
    diff += reg_size;
  }

  // inzero indicates if the extracted bitfield is inserted into the
  // destination register value or in zero.
  // If extend is true, extend the sign of the extracted bitfield.
  bool inzero = false;
  bool extend = false;
  switch (instr->Mask(BitfieldMask)) {
    case BFM_x:
    case BFM_w:
      break;
    case SBFM_x:
    case SBFM_w:
      inzero = true;
      extend = true;
      break;
    case UBFM_x:
    case UBFM_w:
      inzero = true;
      break;
    default:
      UNIMPLEMENTED();
  }

  T dst = inzero ? 0 : reg<T>(instr->Rd());
  T src = reg<T>(instr->Rn());
  // Rotate source bitfield into place.
  T result = R == 0 ? src
                    : (static_cast<unsignedT>(src) >> R) |
                          (static_cast<unsignedT>(src) << (reg_size - R));
  // Determine the sign extension.
  T topbits_preshift = (static_cast<unsignedT>(1) << (reg_size - diff - 1)) - 1;
  T signbits =
      diff >= reg_size - 1
          ? 0
          : ((extend && ((src >> S) & 1) ? topbits_preshift : 0) << (diff + 1));

  // Merge sign extension, dest/zero and bitfield.
  result = signbits | (result & mask) | (dst & ~mask);

  set_reg<T>(instr->Rd(), result);
}

void Simulator::VisitBitfield(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    BitfieldHelper<int64_t>(instr);
  } else {
    BitfieldHelper<int32_t>(instr);
  }
}

void Simulator::VisitExtract(Instruction* instr) {
  if (instr->SixtyFourBits()) {
    Extract<uint64_t>(instr);
  } else {
    Extract<uint32_t>(instr);
  }
}

void Simulator::VisitFPImmediate(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dest = instr->Rd();
  switch (instr->Mask(FPImmediateMask)) {
    case FMOV_s_imm:
      set_sreg(dest, instr->ImmFP32());
      break;
    case FMOV_d_imm:
      set_dreg(dest, instr->ImmFP64());
      break;
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPIntegerConvert(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();

  FPRounding round = fpcr().RMode();

  switch (instr->Mask(FPIntegerConvertMask)) {
    case FCVTAS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPTieAway));
      break;
    case FCVTAS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPTieAway));
      break;
    case FCVTAS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPTieAway));
      break;
    case FCVTAS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPTieAway));
      break;
    case FCVTAU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPTieAway));
      break;
    case FCVTAU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPTieAway));
      break;
    case FCVTAU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPTieAway));
      break;
    case FCVTAU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPTieAway));
      break;
    case FCVTMS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPNegativeInfinity));
      break;
    case FCVTMU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPNegativeInfinity));
      break;
    case FCVTNS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPTieEven));
      break;
    case FCVTNS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPTieEven));
      break;
    case FCVTNS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPTieEven));
      break;
    case FCVTNS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPTieEven));
      break;
    case FCVTNU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPTieEven));
      break;
    case FCVTNU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPTieEven));
      break;
    case FCVTNU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPTieEven));
      break;
    case FCVTNU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPTieEven));
      break;
    case FCVTZS_ws:
      set_wreg(dst, FPToInt32(sreg(src), FPZero));
      break;
    case FCVTZS_xs:
      set_xreg(dst, FPToInt64(sreg(src), FPZero));
      break;
    case FCVTZS_wd:
      set_wreg(dst, FPToInt32(dreg(src), FPZero));
      break;
    case FCVTZS_xd:
      set_xreg(dst, FPToInt64(dreg(src), FPZero));
      break;
    case FCVTZU_ws:
      set_wreg(dst, FPToUInt32(sreg(src), FPZero));
      break;
    case FCVTZU_xs:
      set_xreg(dst, FPToUInt64(sreg(src), FPZero));
      break;
    case FCVTZU_wd:
      set_wreg(dst, FPToUInt32(dreg(src), FPZero));
      break;
    case FCVTZU_xd:
      set_xreg(dst, FPToUInt64(dreg(src), FPZero));
      break;
    case FJCVTZS:
      set_wreg(dst, FPToFixedJS(dreg(src)));
      break;
    case FMOV_ws:
      set_wreg(dst, sreg_bits(src));
      break;
    case FMOV_xd:
      set_xreg(dst, dreg_bits(src));
      break;
    case FMOV_sw:
      set_sreg_bits(dst, wreg(src));
      break;
    case FMOV_dx:
      set_dreg_bits(dst, xreg(src));
      break;

    // A 32-bit input can be handled in the same way as a 64-bit input, since
    // the sign- or zero-extension will not affect the conversion.
    case SCVTF_dx:
      set_dreg(dst, FixedToDouble(xreg(src), 0, round));
      break;
    case SCVTF_dw:
      set_dreg(dst, FixedToDouble(wreg(src), 0, round));
      break;
    case UCVTF_dx:
      set_dreg(dst, UFixedToDouble(xreg(src), 0, round));
      break;
    case UCVTF_dw: {
      set_dreg(dst, UFixedToDouble(reg<uint32_t>(src), 0, round));
      break;
    }
    case SCVTF_sx:
      set_sreg(dst, FixedToFloat(xreg(src), 0, round));
      break;
    case SCVTF_sw:
      set_sreg(dst, FixedToFloat(wreg(src), 0, round));
      break;
    case UCVTF_sx:
      set_sreg(dst, UFixedToFloat(xreg(src), 0, round));
      break;
    case UCVTF_sw: {
      set_sreg(dst, UFixedToFloat(reg<uint32_t>(src), 0, round));
      break;
    }

    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPFixedPointConvert(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned dst = instr->Rd();
  unsigned src = instr->Rn();
  int fbits = 64 - instr->FPScale();

  FPRounding round = fpcr().RMode();

  switch (instr->Mask(FPFixedPointConvertMask)) {
    // A 32-bit input can be handled in the same way as a 64-bit input, since
    // the sign- or zero-extension will not affect the conversion.
    case SCVTF_dx_fixed:
      set_dreg(dst, FixedToDouble(xreg(src), fbits, round));
      break;
    case SCVTF_dw_fixed:
      set_dreg(dst, FixedToDouble(wreg(src), fbits, round));
      break;
    case UCVTF_dx_fixed:
      set_dreg(dst, UFixedToDouble(xreg(src), fbits, round));
      break;
    case UCVTF_dw_fixed: {
      set_dreg(dst, UFixedToDouble(reg<uint32_t>(src), fbits, round));
      break;
    }
    case SCVTF_sx_fixed:
      set_sreg(dst, FixedToFloat(xreg(src), fbits, round));
      break;
    case SCVTF_sw_fixed:
      set_sreg(dst, FixedToFloat(wreg(src), fbits, round));
      break;
    case UCVTF_sx_fixed:
      set_sreg(dst, UFixedToFloat(xreg(src), fbits, round));
      break;
    case UCVTF_sw_fixed: {
      set_sreg(dst, UFixedToFloat(reg<uint32_t>(src), fbits, round));
      break;
    }
    default:
      UNREACHABLE();
  }
}

void Simulator::VisitFPCompare(Instruction* instr) {
  AssertSupportedFPCR();

  switch (instr->Mask(FPCompareMask)) {
    case FCMP_s:
      FPCompare(sreg(instr->Rn()), sreg(instr->Rm()));
      break;
    case FCMP_d:
      FPCompare(dreg(instr->Rn()), dreg(instr->Rm()));
      break;
    case FCMP_s_zero:
      FPCompare(sreg(instr->Rn()), 0.0f);
      break;
    case FCMP_d_zero:
      FPCompare(dreg(instr->Rn()), 0.0);
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPConditionalCompare(Instruction* instr) {
  AssertSupportedFPCR();

  switch (instr->Mask(FPConditionalCompareMask)) {
    case FCCMP_s:
      if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
        FPCompare(sreg(instr->Rn()), sreg(instr->Rm()));
      } else {
        nzcv().SetFlags(instr->Nzcv());
        LogSystemRegister(NZCV);
      }
      break;
    case FCCMP_d: {
      if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
        FPCompare(dreg(instr->Rn()), dreg(instr->Rm()));
      } else {
        // If the condition fails, set the status flags to the nzcv immediate.
        nzcv().SetFlags(instr->Nzcv());
        LogSystemRegister(NZCV);
      }
      break;
    }
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPConditionalSelect(Instruction* instr) {
  AssertSupportedFPCR();

  Instr selected;
  if (ConditionPassed(static_cast<Condition>(instr->Condition()))) {
    selected = instr->Rn();
  } else {
    selected = instr->Rm();
  }

  switch (instr->Mask(FPConditionalSelectMask)) {
    case FCSEL_s:
      set_sreg(instr->Rd(), sreg(selected));
      break;
    case FCSEL_d:
      set_dreg(instr->Rd(), dreg(selected));
      break;
    default:
      UNIMPLEMENTED();
  }
}

void Simulator::VisitFPDataProcessing1Source(Instruction* instr) {
  AssertSupportedFPCR();

  FPRounding fpcr_rounding = static_cast<FPRounding>(fpcr().RMode());
  VectorFormat vform = (instr->Mask(FP64) == FP64) ? kFormatD : kFormatS;
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  bool inexact_exception = false;

  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();

  switch (instr->Mask(FPDataProcessing1SourceMask)) {
    case FMOV_s:
      set_sreg(fd, sreg(fn));
      return;
    case FMOV_d:
      set_dreg(fd, dreg(fn));
      return;
    case FABS_s:
    case FABS_d:
      fabs_(vform, vreg(fd), vreg(fn));
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FNEG_s:
    case FNEG_d:
      fneg(vform, vreg(fd), vreg(fn));
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FCVT_ds:
      set_dreg(fd, FPToDouble(sreg(fn)));
      return;
    case FCVT_sd:
      set_sreg(fd, FPToFloat(dreg(fn), FPTieEven));
      return;
    case FCVT_hs:
      set_hreg(fd, FPToFloat16(sreg(fn), FPTieEven));
      return;
    case FCVT_sh:
      set_sreg(fd, FPToFloat(hreg(fn)));
      return;
    case FCVT_dh:
      set_dreg(fd, FPToDouble(FPToFloat(hreg(fn))));
      return;
    case FCVT_hd:
      set_hreg(fd, FPToFloat16(dreg(fn), FPTieEven));
      return;
    case FSQRT_s:
    case FSQRT_d:
      fsqrt(vform, rd, rn);
      // Explicitly log the register update whilst we have type information.
      LogVRegister(fd, GetPrintRegisterFormatFP(vform));
      return;
    case FRINTI_s:
    case FRINTI_d:
      break;  // Use FPCR rounding mode.
    case FRINTX_s:
    case FRINTX_d:
      inexact_exception = true;
      break;
    case FRINTA_s:
    case FRINTA_d:
      fpcr_rounding = FPTieAway;
      break;
    case FRINTM_s:
    case FRINTM_d:
      fpcr_rounding = FPNegativeInfinity;
      break;
    case FRINTN_s:
    case FRINTN_d:
      fpcr_rounding = FPTieEven;
      break;
    case FRINTP_s:
    case FRINTP_d:
      fpcr_rounding = FPPositiveInfinity;
      break;
    case FRINTZ_s:
    case FRINTZ_d:
      fpcr_rounding = FPZero;
      break;
    default:
      UNIMPLEMENTED();
  }

  // Only FRINT* instructions fall through the switch above.
  frint(vform, rd, rn, fpcr_rounding, inexact_exception);
  // Explicitly log the register update whilst we have type information
  LogVRegister(fd, GetPrintRegisterFormatFP(vform));
}

void Simulator::VisitFPDataProcessing2Source(Instruction* instr) {
  AssertSupportedFPCR();

  VectorFormat vform = (instr->Mask(FP64) == FP64) ? kFormatD : kFormatS;
  SimVRegister& rd = vreg(instr->Rd());
  SimVRegister& rn = vreg(instr->Rn());
  SimVRegister& rm = vreg(instr->Rm());

  switch (instr->Mask(FPDataProcessing2SourceMask)) {
    case FADD_s:
    case FADD_d:
      fadd(vform, rd, rn, rm);
      break;
    case FSUB_s:
    case FSUB_d:
      fsub(vform, rd, rn, rm);
      break;
    case FMUL_s:
    case FMUL_d:
      fmul(vform, rd, rn, rm);
      break;
    case FNMUL_s:
    case FNMUL_d:
      fnmul(vform, rd, rn, rm);
      break;
    case FDIV_s:
    case FDIV_d:
      fdiv(vform, rd, rn, rm);
      break;
    case FMAX_s:
    case FMAX_d:
      fmax(vform, rd, rn, rm);
      break;
    case FMIN_s:
    case FMIN_d:
      fmin(vform, rd, rn, rm);
      break;
    case FMAXNM_s:
    case FMAXNM_d:
      fmaxnm(vform, rd, rn, rm);
      break;
    case FMINNM_s:
    case FMINNM_d:
      fminnm(vform, rd, rn, rm);
      break;
    default:
      UNREACHABLE();
  }
  // Explicitly log the register update whilst we have type information.
  LogVRegister(instr->Rd(), GetPrintRegisterFormatFP(vform));
}

void Simulator::VisitFPDataProcessing3Source(Instruction* instr) {
  AssertSupportedFPCR();

  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();
  unsigned fm = instr->Rm();
  unsigned fa = instr->Ra();

  switch (instr->Mask(FPDataProcessing3SourceMask)) {
    // fd = fa +/- (fn * fm)
    case FMADD_s:
      set_sreg(fd, FPMulAdd(sreg(fa), sreg(fn), sreg(fm)));
      break;
    case FMSUB_s:
      set_sreg(fd, FPMulAdd(sreg(fa), -sreg(fn), sreg(fm)));
      break;
    case FMADD_d:
      set_dreg(fd, FPMulAdd(dreg(fa), dreg(fn), dreg(fm)));
      break;
    case FMSUB_d:
      set_dreg(fd, FPMulAdd(dreg(fa), -dreg(fn), dreg(fm)));
      break;
    // Negated variants of the above.
    case FNMADD_s:
      set_sreg(fd, FPMulAdd(-sreg(fa), -sreg(fn), sreg(fm)));
      break;
    case FNMSUB_s:
      set_sreg(fd, FPMulAdd(-sreg(fa), sreg(fn), sreg(fm)));
      break;
    case FNMADD_d:
      set_dreg(fd, FPMulAdd(-dreg(fa), -dreg(fn), dreg(fm)));
      break;
    case FNMSUB_d:
      set_dreg(fd, FPMulAdd(-dreg(fa), dreg(fn), dreg(fm)));
      break;
    default:
      UNIMPLEMENTED();
  }
}

bool Simulator::FPProcessNaNs(Instruction* instr) {
  unsigned fd = instr->Rd();
  unsigned fn = instr->Rn();
  unsigned fm = instr->Rm();
  bool done = false;

  if (instr->Mask(FP64) == FP64) {
    double result = FPProcessNaNs(dreg(fn), dreg(fm));
    if (std::isnan(result)) {
      set_dreg(fd, result);
      done = true;
    }
  } else {
    float result = FPProcessNaNs(sreg(fn), sreg(fm));
    if (std::isnan(result)) {
      set_sreg(fd, result);
      done = true;
    }
  }

  return done;
}

// clang-format off
#define PAUTH_SYSTEM_MODES(V)                            \
  V(B1716, 17, xreg(16),                      kPACKeyIB) \
  V(BSP,   30, xreg(31, Reg31IsStackPointer), kPACKeyIB)
// clang-format on

void Simulator::VisitSystem(Instruction* instr) {
  // Some system instructions hijack their Op and Cp fields to represent a
  // range of immediates instead of indicating a different instruction. This
  // makes the decoding tricky.
  if (instr->Mask(SystemPAuthFMask) == SystemPAuthFixed) {
    // The BType check for PACIBSP happens in CheckBType().
    switch (instr->Mask(SystemPAuthMask)) {
#define DEFINE_PAUTH_FUNCS(SUFFIX, DST, MOD, KEY)                     \
  case PACI##SUFFIX:                                                  \
    set_xreg(DST, AddPAC(xreg(DST), MOD, KEY, kInstructionPointer));  \
    break;                                                            \
  case AUTI##SUFFIX:                                                  \
    set_xreg(DST, AuthPAC(xreg(DST), MOD, KEY, kInstructionPointer)); \
    break;

      PAUTH_SYSTEM_MODES(DEFINE_PAUTH_FUNCS)
#undef DEFINE_PAUTH_FUNCS
#undef PAUTH_SYSTEM_MODES
    }
  } else if (instr->Mask(SystemSysRegFMask) == SystemSysRegFixed) {
    switch (instr->Mask(SystemSysRegMask)) {
      case MRS: {
        switch (instr->ImmSystemRegister()) {
          case NZCV:
            set_xreg(instr->Rt(), nzcv().RawValue());
            break;
          case FPCR:
            set_xreg(instr->Rt(), fpcr().RawValue());
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
      }
      case MSR: {
        switch (instr->ImmSystemRegister()) {
          case NZCV:
            nzcv().SetRawValue(wreg(instr->Rt()));
            LogSystemRegister(NZCV);
            break;
          case FPCR:
            fpcr().SetRawValue(wreg(instr->Rt()));
            LogSystemRegister(FPCR);
            break;
          default:
            UNIMPLEMENTED();
        }
        break;
      }
    }
  } else if (instr->Mask(SystemHintFMask) == SystemHintFixed) {
    DCHECK(instr->Mask(SystemHintMask) == HINT);
    switch (instr->ImmHint()) {
      case NOP:
      case YIELD:
      case CSDB:
      case BTI_jc:
      case BTI:
      case BTI_c:
      case BTI_j:
        // The BType checks happen in CheckBType().
        break;
      default:
        UNIMPLEMENTED();
    }
  } else if (instr->Mask(MemBarrierFMask) == MemBarrierFixed) {
    std::atomic_thread_fence(std::memory_order_seq_cst);
  } else {
    UNIMPLEMENTED();
  }
}

bool Simulator::GetValue(const char* desc, int64_t* value) {
  int regnum = CodeFromName(desc);
  if (regnum >= 0) {
    unsigned code = regnum;
    if (code == kZeroRegCode) {
      // Catch the zero register and return 0.
      *value = 0;
      return true;
    } else if (code == kSPRegInternalCode) {
      // Translate the stack pointer code to 31, for Reg31IsStackPointer.
      code = 31;
    }
    if (desc[0] == 'w') {
      *value = wreg(code, Reg31IsStackPointer);
    } else {
      *value = xreg(code, Reg31IsStackPointer);
    }
    return true;
  } else if (strncmp(desc, "0x", 2) == 0) {
    return SScanF(desc + 2, "%" SCNx64, reinterpret_cast<uint64_t*>(value)) ==
           1;
  } else {
    return SScanF(desc, "%" SCNu64, reinterpret_cast<uint64_t*>(value)) == 1;
  }
}

bool Simulator::PrintValue(const char* desc) {
  if (strcmp(desc, "sp") == 0) {
    DCHECK(CodeFromName(desc) == static_cast<int>(kSPRegInternalCode));
    PrintF(stream_, "%s sp:%s 0x%016" PRIx64 "%s\n", clr_reg_name,
           clr_reg_value, xreg(31, Reg31IsStackPointer), clr_normal);
    return true;
  } else if (strcmp(desc, "wsp") == 0) {
    DCHECK(CodeFromName(desc) == static_cast<int>(kSPRegInternalCode));
    PrintF(stream_, "%s wsp:%s 0x%08" PRIx32 "%s\n", clr_reg_name,
           clr_reg_value, wreg(31, Reg31IsStackPointer), clr_normal);
    return true;
  }

  int i = CodeFromName(desc);
  static_assert(kNumberOfRegisters == kNumberOfVRegisters,
                "Must be same number of Registers as VRegisters.");
  if (i < 0 || static_cast<unsigned>(i) >= kNumberOfVRegisters) return false;

  if (desc[0] == 'v') {
    struct qreg_t reg = qreg(i);
    PrintF(stream_, "%s %s:%s (%s0x%02x%s", clr_vreg_name, VRegNameForCode(i),
           clr_normal, clr_vreg_value, reg.val[0], clr_normal);
    for (int b = 1; b < kQRegSize; b++) {
      PrintF(stream_, ", %s0x%02x%s", clr_vreg_value, reg.val[b], clr_normal);
    }
    PrintF(stream_, ")\n");
    return true;
  } else if (desc[0] == 'd') {
    PrintF(stream_, "%s %s:%s %g%s\n", clr_vreg_name, DRegNameForCode(i),
           clr_vreg_value, dreg(i), clr_normal);
    return true;
  } else if (desc[0] == 's') {
    PrintF(stream_, "%s %s:%s %g%s\n", clr_vreg_name, SRegNameForCode(i),
           clr_vreg_value, sreg(i), clr_normal);
    return true;
  } else if (desc[0] == 'w') {
    PrintF(stream_, "%s %s:%s 0x%08" PRIx32 "%s\n", clr_reg_name,
           WRegNameForCode(i), clr_reg_value, wreg(i), clr_normal);
    return true;
  } else {
    // X register names have a wide variety of starting characters, but anything
    // else will be an X register.
    PrintF(stream_, "%s %s:%s 0x%016" PRIx64 "%s\n", clr_reg_name,
           XRegNameForCode(i), clr_reg_value, xreg(i), clr_normal);
    return true;
  }
}

void Simulator::Debug() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    PrintF("Debugger disabled for differential fuzzing.\n");
    return;
  }
  bool done = false;
  while (!done) {
    // Disassemble the next instruction to execute before doing anything else.
    PrintInstructionsAt(pc_, 1);
    // Read the command line.
    ArrayUniquePtr<char> line(ReadLine("sim> "));
    done = ExecDebugCommand(std::move(line));
  }
}

bool Simulator::ExecDebugCommand(ArrayUniquePtr<char> line_ptr) {
#define COMMAND_SIZE 63
#define ARG_SIZE 255

#define STR(a) #a
#define XSTR(a) STR(a)

  char cmd[COMMAND_SIZE + 1];
  char arg1[ARG_SIZE + 1];
  char arg2[ARG_SIZE + 1];
  char* argv[3] = {cmd, arg1, arg2};

  // Make sure to have a proper terminating character if reaching the limit.
  cmd[COMMAND_SIZE] = 0;
  arg1[ARG_SIZE] = 0;
  arg2[ARG_SIZE] = 0;

  bool cleared_log_disasm_bit = false;

  if (line_ptr == nullptr) return false;

  // Repeat last command by default.
  const char* line = line_ptr.get();
  const char* last_input = last_debugger_input();
  if (strcmp(line, "\n") == 0 && (last_input != nullptr)) {
    line_ptr.reset();
    line = last_input;
  } else {
    // Update the latest command ran
    set_last_debugger_input(std::move(line_ptr));
  }

  // Use sscanf to parse the individual parts of the command line. At the
  // moment no command expects more than two parameters.
  int argc = SScanF(line,
                      "%" XSTR(COMMAND_SIZE) "s "
                      "%" XSTR(ARG_SIZE) "s "
                      "%" XSTR(ARG_SIZE) "s",
                      cmd, arg1, arg2);

  // stepi / si ------------------------------------------------------------
  if ((strcmp(cmd, "si") == 0) || (strcmp(cmd, "stepi") == 0)) {
    // We are about to execute instructions, after which by default we
    // should increment the pc_. If it was set when reaching this debug
    // instruction, it has not been cleared because this instruction has not
    // completed yet. So clear it manually.
    pc_modified_ = false;

    if (argc == 1) {
      ExecuteInstruction();
    } else {
      int64_t number_of_instructions_to_execute = 1;
      GetValue(arg1, &number_of_instructions_to_execute);

      set_log_parameters(log_parameters() | LOG_DISASM);
      while (number_of_instructions_to_execute-- > 0) {
        ExecuteInstruction();
      }
      set_log_parameters(log_parameters() & ~LOG_DISASM);
      PrintF("\n");
    }

    // If it was necessary, the pc has already been updated or incremented
    // when executing the instruction. So we do not want it to be updated
    // again. It will be cleared when exiting.
    pc_modified_ = true;

    // next / n
    // --------------------------------------------------------------
  } else if ((strcmp(cmd, "next") == 0) || (strcmp(cmd, "n") == 0)) {
    // Tell the simulator to break after the next executed BL.
    break_on_next_ = true;
    // Continue.
    return true;

    // continue / cont / c
    // ---------------------------------------------------
  } else if ((strcmp(cmd, "continue") == 0) || (strcmp(cmd, "cont") == 0) ||
             (strcmp(cmd, "c") == 0)) {
    // Leave the debugger shell.
    return true;

    // disassemble / disasm / di
    // ---------------------------------------------
  } else if (strcmp(cmd, "disassemble") == 0 || strcmp(cmd, "disasm") == 0 ||
             strcmp(cmd, "di") == 0) {
    int64_t n_of_instrs_to_disasm = 10;                // default value.
    int64_t address = reinterpret_cast<int64_t>(pc_);  // default value.
    if (argc >= 2) {                                   // disasm <n of instrs>
      GetValue(arg1, &n_of_instrs_to_disasm);
    }
    if (argc >= 3) {  // disasm <n of instrs> <address>
      GetValue(arg2, &address);
    }

    // Disassemble.
    PrintInstructionsAt(reinterpret_cast<Instruction*>(address),
                        n_of_instrs_to_disasm);
    PrintF("\n");

    // print / p
    // -------------------------------------------------------------
  } else if ((strcmp(cmd, "print") == 0) || (strcmp(cmd, "p") == 0)) {
    if (argc == 2) {
      if (strcmp(arg1, "all") == 0) {
        PrintRegisters();
        PrintVRegisters();
      } else {
        if (!PrintValue(arg1)) {
          PrintF("%s unrecognized\n", arg1);
        }
      }
    } else {
      PrintF(
          "print <register>\n"
          "    Print the content of a register. (alias 'p')\n"
          "    'print all' will print all registers.\n"
          "    Use 'printobject' to get more details about the value.\n");
    }

    // printobject / po
    // ------------------------------------------------------
  } else if ((strcmp(cmd, "printobject") == 0) || (strcmp(cmd, "po") == 0)) {
    if (argc == 2) {
      int64_t value;
      StdoutStream os;
      if (GetValue(arg1, &value)) {
        Tagged<Object> obj(value);
        os << arg1 << ": \n";
#ifdef DEBUG
        Print(obj, os);
        os << "\n";
#else
        os << Brief(obj) << "\n";
#endif
      } else {
        os << arg1 << " unrecognized\n";
      }
    } else {
      PrintF(
          "printobject <value>\n"
          "printobject <register>\n"
          "    Print details about the value. (alias 'po')\n");
    }

    // stack / mem
    // ----------------------------------------------------------
  } else if (strcmp(cmd, "stack") == 0 || strcmp(cmd, "mem") == 0 ||
             strcmp(cmd, "dump") == 0) {
    int64_t* cur = nullptr;
    int64_t* end = nullptr;
    int next_arg = 1;

    if (strcmp(cmd, "stack") == 0) {
      cur = reinterpret_cast<int64_t*>(sp());

    } else {  // "mem"
      int64_t value;
      if (!GetValue(arg1, &value)) {
        Prin
"""


```