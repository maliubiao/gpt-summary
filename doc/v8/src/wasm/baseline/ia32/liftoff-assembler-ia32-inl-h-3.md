Response:
The user is asking for a summary of the provided C++ code snippet from V8. Here's a breakdown of the thinking process to generate the response:

1. **Identify the Core Functionality:** The code is a header file (`.h`) containing inline functions. It's located in the `v8/src/wasm/baseline/ia32/` directory, suggesting it's specific to the IA-32 architecture and related to the baseline compiler for WebAssembly. The filename `liftoff-assembler-ia32-inl.h` strongly indicates it provides helper functions for the Liftoff assembler on IA-32. The functions inside seem to generate assembly code snippets.

2. **Analyze Individual Functions/Templates:** Go through the code block by block:
    * **`CheckSmi`:** This function checks if a value is a Smi (small integer) and conditionally jumps based on the result. This is a fundamental operation in V8 for handling tagged values.
    * **`EmitSimdCommutativeBinOp` and `EmitSimdNonCommutativeBinOp`:** These templates handle binary SIMD operations (like addition, multiplication) with AVX and SSE optimizations. The "commutative" and "non-commutative" distinctions are key for optimizing register usage.
    * **`EmitSimdShiftOp` and `EmitSimdShiftOpImm`:** These templates handle SIMD shift operations, with variants for register-based and immediate shift counts.
    * **`EmitAnyTrue` and `EmitAllTrue`:** These functions check if any or all elements within a SIMD vector are true.
    * **`LoadTransform`:**  This function loads data from memory with optional transformations like sign/zero extension or splatting (duplicating a value across the vector).
    * **`LoadLane` and `StoreLane`:** These functions load or store a single "lane" (element) of a SIMD vector to/from memory.
    * **`emit_i8x16_shuffle` and `emit_i8x16_swizzle` (and relaxed variants):** These functions implement SIMD shuffle operations, rearranging elements within or between vectors. The "relaxed" variants likely have less strict validation or different behavior.
    * **`emit_i32x4_relaxed_trunc_f32x4_s/u` and `emit_i32x4_relaxed_trunc_f64x2_s_zero/u_zero`:** These functions perform relaxed truncation of floating-point SIMD vectors to integer vectors. The "relaxed" and "zero" suffixes suggest different handling of out-of-range values or rounding.
    * **`emit_s128_relaxed_laneselect`:** This function performs a lane-wise selection between two SIMD vectors based on a mask.
    * **`emit_i8x16_popcnt`:** This function calculates the population count (number of set bits) in each byte of a SIMD vector.
    * **`emit_*_splat` functions:** These functions create SIMD vectors by replicating a scalar value across all lanes.
    * **`emit_*_eq/ne/gt_s/gt_u/ge_s/ge_u` functions:** These functions implement SIMD comparison operations. The suffixes `_s` and `_u` indicate signed and unsigned comparisons, respectively.
    * **`emit_s128_const`:** This function loads a constant 128-bit value into a SIMD register.
    * **`emit_s128_not/and/or/xor`:** These functions implement bitwise logical operations on SIMD vectors.
    * **`emit_s128_select`:** This function selects elements from two SIMD vectors based on a mask.
    * **`emit_i8x16_neg`:** This function negates the elements of a SIMD vector.
    * **`emit_v128_anytrue` and `emit_i8x16_alltrue`:** Reiteration of previously seen functionalities.
    * **`emit_i8x16_bitmask`:**  Extracts the most significant bit of each byte in a SIMD vector into a general-purpose register.
    * **`emit_i8x16_shl/shli/shr_s/shri_s/shr_u/shri_u`:** SIMD shift left and right operations (arithmetic and logical) with both register and immediate shift counts.
    * **`emit_i8x16_add/add_sat_s/add_sat_u/sub/sub_sat_s/sub_sat_u`:** SIMD addition and subtraction operations, including saturating versions.
    * **`emit_i8x16_min_s`:** Beginning of another SIMD min operation, suggesting more will follow.

3. **Categorize Functionality:**  Group the functions by their purpose:
    * **Basic Operations:** Checking Smi, conditional jumps.
    * **SIMD Arithmetic:** Addition, subtraction, negation, min, max (inferred from usage).
    * **SIMD Bitwise:** AND, OR, XOR, NOT, shifts, bitmask, population count.
    * **SIMD Comparisons:** Equality, inequality, greater than, greater than or equal to (signed and unsigned).
    * **SIMD Data Manipulation:** Splatting, shuffling, swizzling, lane extraction/insertion, selecting.
    * **SIMD Conversions:**  Truncation from floating-point to integer.
    * **Memory Access:** Loading and storing SIMD values and lanes.
    * **Helper Functions:**  Managing CPU feature scopes.

4. **Address Specific Questions:**
    * **Functionality:** Summarize the categorized functionalities.
    * **`.tq` Extension:** Explain that `.tq` indicates Torque code, and this file is `.h`, so it's not Torque.
    * **JavaScript Relation:**  Connect the SIMD operations to the `WebAssembly.SIMD` object in JavaScript, providing illustrative examples.
    * **Code Logic/Assumptions:**  For `CheckSmi`, provide a simple example with a Smi and a non-Smi value and the expected control flow.
    * **Common Programming Errors:** Explain how incorrect lane indexing or data types can lead to errors in SIMD operations, using a JavaScript example.

5. **Synthesize the Summary:** Combine the categorized functionalities and answers to the specific questions into a concise summary, keeping in mind that this is "part 4 of 6". Focus on the core purpose of the file within the larger context of Liftoff and IA-32.

6. **Review and Refine:** Ensure the summary is accurate, well-organized, and easy to understand. Check for any inconsistencies or missing information. For instance, initially, I might just list all the functions. However, grouping them by functionality makes the summary more insightful. Also, double-check the JavaScript examples for correctness and clarity. Make sure the explanation about Torque is accurate.
```cpp
             SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  test_b(obj, Immediate(kSmiTagMask));
  Condition condition = mode == kJumpOnSmi ? zero : not_zero;
  j(condition, target);
}

namespace liftoff {
template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, XMMRegister),
          void (Assembler::*sse_op)(XMMRegister, XMMRegister)>
void EmitSimdCommutativeBinOp(
    LiftoffAssembler* assm, LiftoffRegister dst, LiftoffRegister lhs,
    LiftoffRegister rhs, std::optional<CpuFeature> feature = std::nullopt) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), lhs.fp(), rhs.fp());
    return;
  }

  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  if (dst.fp() == rhs.fp()) {
    (assm->*sse_op)(dst.fp(), lhs.fp());
  } else {
    if (dst.fp() != lhs.fp()) (assm->movaps)(dst.fp(), lhs.fp());
    (assm->*sse_op)(dst.fp(), rhs.fp());
  }
}

template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, XMMRegister),
          void (Assembler::*sse_op)(XMMRegister, XMMRegister)>
void EmitSimdNonCommutativeBinOp(
    LiftoffAssembler* assm, LiftoffRegister dst, LiftoffRegister lhs,
    LiftoffRegister rhs, std::optional<CpuFeature> feature = std::nullopt) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), lhs.fp(), rhs.fp());
    return;
  }

  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  if (dst.fp() == rhs.fp()) {
    assm->movaps(kScratchDoubleReg, rhs.fp());
    assm->movaps(dst.fp(), lhs.fp());
    (assm->*sse_op)(dst.fp(), kScratchDoubleReg);
  } else {
    if (dst.fp() != lhs.fp()) assm->movaps(dst.fp(), lhs.fp());
    (assm->*sse_op)(dst.fp(), rhs.fp());
  }
}

template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, XMMRegister),
          void (Assembler::*sse_op)(XMMRegister, XMMRegister), uint8_t width>
void EmitSimdShiftOp(LiftoffAssembler* assm, LiftoffRegister dst,
                     LiftoffRegister operand, LiftoffRegister count) {
  static constexpr RegClass tmp_rc = reg_class_for(kI32);
  LiftoffRegister tmp = assm->GetUnusedRegister(tmp_rc, LiftoffRegList{count});
  constexpr int mask = (1 << width) - 1;

  assm->mov(tmp.gp(), count.gp());
  assm->and_(tmp.gp(), Immediate(mask));
  assm->Movd(kScratchDoubleReg, tmp.gp());
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), operand.fp(), kScratchDoubleReg);
  } else {
    if (dst.fp() != operand.fp()) assm->movaps(dst.fp(), operand.fp());
    (assm->*sse_op)(dst.fp(), kScratchDoubleReg);
  }
}

template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, uint8_t),
          void (Assembler::*sse_op)(XMMRegister, uint8_t), uint8_t width>
void EmitSimdShiftOpImm(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister operand, int32_t count) {
  constexpr int mask = (1 << width) - 1;
  uint8_t shift = static_cast<uint8_t>(count & mask);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), operand.fp(), shift);
  } else {
    if (dst.fp() != operand.fp()) assm->movaps(dst.fp(), operand.fp());
    (assm->*sse_op)(dst.fp(), shift);
  }
}

inline void EmitAnyTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src) {
  Register tmp = assm->GetUnusedRegister(kGpReg, LiftoffRegList{dst}).gp();
  assm->xor_(tmp, tmp);
  assm->mov(dst.gp(), Immediate(1));
  assm->Ptest(src.fp(), src.fp());
  assm->cmov(zero, dst.gp(), tmp);
}

template <void (SharedMacroAssemblerBase::*pcmp)(XMMRegister, XMMRegister)>
inline void EmitAllTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src,
                        std::optional<CpuFeature> feature = std::nullopt) {
  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  Register tmp = assm->GetUnusedRegister(kGpReg, LiftoffRegList{dst}).gp();
  XMMRegister tmp_simd = liftoff::kScratchDoubleReg;
  assm->mov(tmp, Immediate(1));
  assm->xor_(dst.gp(), dst.gp());
  assm->Pxor(tmp_simd, tmp_simd);
  (assm->*pcmp)(tmp_simd, src.fp());
  assm->Ptest(tmp_simd, tmp_simd());
  assm->cmov(zero, dst.gp(), tmp);
}

}  // namespace liftoff

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand src_op{src_addr, offset_reg, times_1,
                 static_cast<int32_t>(offset_imm)};
  *protected_load_pc = pc_offset();

  MachineType memtype = type.mem_type();
  if (transform == LoadTransformationKind::kExtend) {
    if (memtype == MachineType::Int8()) {
      Pmovsxbw(dst.fp(), src_op);
    } else if (memtype == MachineType::Uint8()) {
      Pmovzxbw(dst.fp(), src_op);
    } else if (memtype == MachineType::Int16()) {
      Pmovsxwd(dst.fp(), src_op);
    } else if (memtype == MachineType::Uint16()) {
      Pmovzxwd(dst.fp(), src_op);
    } else if (memtype == MachineType::Int32()) {
      Pmovsxdq(dst.fp(), src_op);
    } else if (memtype == MachineType::Uint32()) {
      Pmovzxdq(dst.fp(), src_op);
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    if (memtype == MachineType::Int32()) {
      Movss(dst.fp(), src_op);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      Movsd(dst.fp(), src_op);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      S128Load8Splat(dst.fp(), src_op, liftoff::kScratchDoubleReg);
    } else if (memtype == MachineType::Int16()) {
      S128Load16Splat(dst.fp(), src_op, liftoff::kScratchDoubleReg);
    } else if (memtype == MachineType::Int32()) {
      S128Load32Splat(dst.fp(), src_op);
    } else if (memtype == MachineType::Int64()) {
      Movddup(dst.fp(), src_op);
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool /* i64_offset */) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand src_op{addr, offset_reg, times_1, static_cast<int32_t>(offset_imm)};
  *protected_load_pc = pc_offset();

  MachineType mem_type = type.mem_type();
  if (mem_type == MachineType::Int8()) {
    Pinsrb(dst.fp(), src.fp(), src_op, laneidx);
  } else if (mem_type == MachineType::Int16()) {
    Pinsrw(dst.fp(), src.fp(), src_op, laneidx);
  } else if (mem_type == MachineType::Int32()) {
    Pinsrd(dst.fp(), src.fp(), src_op, laneidx);
  } else {
    DCHECK_EQ(MachineType::Int64(), mem_type);
    if (laneidx == 0) {
      Movlps(dst.fp(), src.fp(), src_op);
    } else {
      DCHECK_EQ(1, laneidx);
      Movhps(dst.fp(), src.fp(), src_op);
    }
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool /* i64_offset */) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand dst_op = Operand(dst, offset, times_1, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();

  MachineRepresentation rep = type.mem_rep();
  if (rep == MachineRepresentation::kWord8) {
    Pextrb(dst_op, src.fp(), lane);
  } else if (rep == MachineRepresentation::kWord16) {
    Pextrw(dst_op, src.fp(), lane);
  } else if (rep == MachineRepresentation::kWord32) {
    S128Store32Lane(dst_op, src.fp(), lane);
  } else {
    DCHECK_EQ(MachineRepresentation::kWord64, rep);
    S128Store64Lane(dst_op, src.fp(), lane);
  }
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  LiftoffRegister tmp = GetUnusedRegister(kGpReg, {});
  // Prepare 16 byte aligned buffer for shuffle control mask.
  mov(tmp.gp(), esp);
  and_(esp, -16);

  if (is_swizzle) {
    uint32_t imms[4];
    // Shuffles that use just 1 operand are called swizzles, rhs can be ignored.
    wasm::SimdShuffle::Pack16Lanes(imms, shuffle);
    for (int i = 3; i >= 0; i--) {
      push_imm32(imms[i]);
    }
    Pshufb(dst.fp(), lhs.fp(), Operand(esp, 0));
    mov(esp, tmp.gp());
    return;
  }

  movups(liftoff::kScratchDoubleReg, lhs.fp());
  for (int i = 3; i >= 0; i--) {
    uint32_t mask = 0;
    for (int j = 3; j >= 0; j--) {
      uint8_t lane = shuffle[i * 4 + j];
      mask <<= 8;
      mask |= lane < kSimd128Size ? lane : 0x80;
    }
    push(Immediate(mask));
  }
  Pshufb(liftoff::kScratchDoubleReg, lhs.fp(), Operand(esp, 0));

  for (int i = 3; i >= 0; i--) {
    uint32_t mask = 0;
    for (int j = 3; j >= 0; j--) {
      uint8_t lane = shuffle[i * 4 + j];
      mask <<= 8;
      mask |= lane >= kSimd128Size ? (lane & 0x0F) : 0x80;
    }
    push(Immediate(mask));
  }
  Pshufb(dst.fp(), rhs.fp(), Operand(esp, 0));
  Por(dst.fp(), liftoff::kScratchDoubleReg);
  mov(esp, tmp.gp());
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  Register scratch = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  I8x16Swizzle(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg,
               scratch);
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  Register tmp = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  I8x16Swizzle(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg, tmp,
               true);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  Cvttps2dq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  emit_i32x4_uconvert_f32x4(dst, src);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  Cvttpd2dq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  emit_i32x4_trunc_sat_f64x2_u_zero(dst, src);
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  // Passing {src2} first is not a typo: the x86 instructions copy from the
  // second operand when the mask is 1, contrary to the Wasm instruction.
  if (lane_width == 8) {
    Pblendvb(dst.fp(), src2.fp(), src1.fp(), mask.fp());
  } else if (lane_width == 32) {
    Blendvps(dst.fp(), src2.fp(), src1.fp(), mask.fp());
  } else if (lane_width == 64) {
    Blendvpd(dst.fp(), src2.fp(), src1.fp(), mask.fp());
  } else {
    UNREACHABLE();
  }
}

void LiftoffAssembler::emit_i8x16_popcnt(LiftoffRegister dst,
                                         LiftoffRegister src) {
  Register scratch = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  XMMRegister tmp =
      GetUnusedRegister(RegClass::kFpReg, LiftoffRegList{dst, src}).fp();
  I8x16Popcnt(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, tmp, scratch);
}

void LiftoffAssembler::emit_i8x16_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  I8x16Splat(dst.fp(), src.gp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  I16x8Splat(dst.fp(), src.gp());
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Movd(dst.fp(), src.gp());
  Pshufd(dst.fp(), dst.fp(), uint8_t{0});
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Pinsrd(dst.fp(), src.low_gp(), 0);
  Pinsrd(dst.fp(), src.high_gp(), 1);
  Pshufd(dst.fp(), dst.fp(), uint8_t{0x44});
}

void LiftoffAssembler::emit_f32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  F32x4Splat(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_f64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Movddup(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i8x16_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqb, &Assembler::pcmpeqb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqb, &Assembler::pcmpeqb>(
      this, dst, lhs, rhs);
  Pcmpeqb(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpcmpgtb,
                                       &Assembler::pcmpgtb>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i8x16_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxub, &Assembler::pmaxub>(
      this, dst, lhs, rhs);
  Pcmpeqb(dst.fp(), ref);
  Pcmpeqb(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsb, &Assembler::pminsb>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqb(dst.fp(), ref);
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminub, &Assembler::pminub>(
      this, dst, lhs, rhs);
  Pcmpeqb(dst.fp(), ref);
}

void LiftoffAssembler::emit_i16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqw, &Assembler::pcmpeqw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqw, &Assembler::pcmpeqw>(
      this, dst, lhs, rhs);
  Pcmpeqw(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpcmpgtw,
                                       &Assembler::pcmpgtw>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i16x8_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxuw, &Assembler::pmaxuw>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqw(dst.fp(), ref);
  Pcmpeqw(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsw, &Assembler::pminsw>(
      this, dst, lhs, rhs);
  Pcmpeqw(dst.fp(), ref);
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminuw, &Assembler::pminuw>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqw(dst.fp(), ref);
}

void LiftoffAssembler::emit_i32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqd, &Assembler::pcmpeqd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqd, &Assembler::pcmpeqd>(
      this, dst, lhs, rhs);
  Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpcmpgtd,
                                       &Assembler::pcmpgtd>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i32x4_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxud, &Assembler::pmaxud>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqd(dst.fp(), ref);
  Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDouble
### 提示词
```
这是目录为v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  test_b(obj, Immediate(kSmiTagMask));
  Condition condition = mode == kJumpOnSmi ? zero : not_zero;
  j(condition, target);
}

namespace liftoff {
template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, XMMRegister),
          void (Assembler::*sse_op)(XMMRegister, XMMRegister)>
void EmitSimdCommutativeBinOp(
    LiftoffAssembler* assm, LiftoffRegister dst, LiftoffRegister lhs,
    LiftoffRegister rhs, std::optional<CpuFeature> feature = std::nullopt) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), lhs.fp(), rhs.fp());
    return;
  }

  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  if (dst.fp() == rhs.fp()) {
    (assm->*sse_op)(dst.fp(), lhs.fp());
  } else {
    if (dst.fp() != lhs.fp()) (assm->movaps)(dst.fp(), lhs.fp());
    (assm->*sse_op)(dst.fp(), rhs.fp());
  }
}

template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, XMMRegister),
          void (Assembler::*sse_op)(XMMRegister, XMMRegister)>
void EmitSimdNonCommutativeBinOp(
    LiftoffAssembler* assm, LiftoffRegister dst, LiftoffRegister lhs,
    LiftoffRegister rhs, std::optional<CpuFeature> feature = std::nullopt) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), lhs.fp(), rhs.fp());
    return;
  }

  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  if (dst.fp() == rhs.fp()) {
    assm->movaps(kScratchDoubleReg, rhs.fp());
    assm->movaps(dst.fp(), lhs.fp());
    (assm->*sse_op)(dst.fp(), kScratchDoubleReg);
  } else {
    if (dst.fp() != lhs.fp()) assm->movaps(dst.fp(), lhs.fp());
    (assm->*sse_op)(dst.fp(), rhs.fp());
  }
}

template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, XMMRegister),
          void (Assembler::*sse_op)(XMMRegister, XMMRegister), uint8_t width>
void EmitSimdShiftOp(LiftoffAssembler* assm, LiftoffRegister dst,
                     LiftoffRegister operand, LiftoffRegister count) {
  static constexpr RegClass tmp_rc = reg_class_for(kI32);
  LiftoffRegister tmp = assm->GetUnusedRegister(tmp_rc, LiftoffRegList{count});
  constexpr int mask = (1 << width) - 1;

  assm->mov(tmp.gp(), count.gp());
  assm->and_(tmp.gp(), Immediate(mask));
  assm->Movd(kScratchDoubleReg, tmp.gp());
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), operand.fp(), kScratchDoubleReg);
  } else {
    if (dst.fp() != operand.fp()) assm->movaps(dst.fp(), operand.fp());
    (assm->*sse_op)(dst.fp(), kScratchDoubleReg);
  }
}

template <void (Assembler::*avx_op)(XMMRegister, XMMRegister, uint8_t),
          void (Assembler::*sse_op)(XMMRegister, uint8_t), uint8_t width>
void EmitSimdShiftOpImm(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister operand, int32_t count) {
  constexpr int mask = (1 << width) - 1;
  uint8_t shift = static_cast<uint8_t>(count & mask);
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(assm, AVX);
    (assm->*avx_op)(dst.fp(), operand.fp(), shift);
  } else {
    if (dst.fp() != operand.fp()) assm->movaps(dst.fp(), operand.fp());
    (assm->*sse_op)(dst.fp(), shift);
  }
}

inline void EmitAnyTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src) {
  Register tmp = assm->GetUnusedRegister(kGpReg, LiftoffRegList{dst}).gp();
  assm->xor_(tmp, tmp);
  assm->mov(dst.gp(), Immediate(1));
  assm->Ptest(src.fp(), src.fp());
  assm->cmov(zero, dst.gp(), tmp);
}

template <void (SharedMacroAssemblerBase::*pcmp)(XMMRegister, XMMRegister)>
inline void EmitAllTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src,
                        std::optional<CpuFeature> feature = std::nullopt) {
  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  Register tmp = assm->GetUnusedRegister(kGpReg, LiftoffRegList{dst}).gp();
  XMMRegister tmp_simd = liftoff::kScratchDoubleReg;
  assm->mov(tmp, Immediate(1));
  assm->xor_(dst.gp(), dst.gp());
  assm->Pxor(tmp_simd, tmp_simd);
  (assm->*pcmp)(tmp_simd, src.fp());
  assm->Ptest(tmp_simd, tmp_simd);
  assm->cmov(zero, dst.gp(), tmp);
}

}  // namespace liftoff

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand src_op{src_addr, offset_reg, times_1,
                 static_cast<int32_t>(offset_imm)};
  *protected_load_pc = pc_offset();

  MachineType memtype = type.mem_type();
  if (transform == LoadTransformationKind::kExtend) {
    if (memtype == MachineType::Int8()) {
      Pmovsxbw(dst.fp(), src_op);
    } else if (memtype == MachineType::Uint8()) {
      Pmovzxbw(dst.fp(), src_op);
    } else if (memtype == MachineType::Int16()) {
      Pmovsxwd(dst.fp(), src_op);
    } else if (memtype == MachineType::Uint16()) {
      Pmovzxwd(dst.fp(), src_op);
    } else if (memtype == MachineType::Int32()) {
      Pmovsxdq(dst.fp(), src_op);
    } else if (memtype == MachineType::Uint32()) {
      Pmovzxdq(dst.fp(), src_op);
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    if (memtype == MachineType::Int32()) {
      Movss(dst.fp(), src_op);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      Movsd(dst.fp(), src_op);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      S128Load8Splat(dst.fp(), src_op, liftoff::kScratchDoubleReg);
    } else if (memtype == MachineType::Int16()) {
      S128Load16Splat(dst.fp(), src_op, liftoff::kScratchDoubleReg);
    } else if (memtype == MachineType::Int32()) {
      S128Load32Splat(dst.fp(), src_op);
    } else if (memtype == MachineType::Int64()) {
      Movddup(dst.fp(), src_op);
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool /* i64_offset */) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand src_op{addr, offset_reg, times_1, static_cast<int32_t>(offset_imm)};
  *protected_load_pc = pc_offset();

  MachineType mem_type = type.mem_type();
  if (mem_type == MachineType::Int8()) {
    Pinsrb(dst.fp(), src.fp(), src_op, laneidx);
  } else if (mem_type == MachineType::Int16()) {
    Pinsrw(dst.fp(), src.fp(), src_op, laneidx);
  } else if (mem_type == MachineType::Int32()) {
    Pinsrd(dst.fp(), src.fp(), src_op, laneidx);
  } else {
    DCHECK_EQ(MachineType::Int64(), mem_type);
    if (laneidx == 0) {
      Movlps(dst.fp(), src.fp(), src_op);
    } else {
      DCHECK_EQ(1, laneidx);
      Movhps(dst.fp(), src.fp(), src_op);
    }
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool /* i64_offset */) {
  DCHECK_LE(offset_imm, std::numeric_limits<int32_t>::max());
  Operand dst_op = Operand(dst, offset, times_1, offset_imm);
  if (protected_store_pc) *protected_store_pc = pc_offset();

  MachineRepresentation rep = type.mem_rep();
  if (rep == MachineRepresentation::kWord8) {
    Pextrb(dst_op, src.fp(), lane);
  } else if (rep == MachineRepresentation::kWord16) {
    Pextrw(dst_op, src.fp(), lane);
  } else if (rep == MachineRepresentation::kWord32) {
    S128Store32Lane(dst_op, src.fp(), lane);
  } else {
    DCHECK_EQ(MachineRepresentation::kWord64, rep);
    S128Store64Lane(dst_op, src.fp(), lane);
  }
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  LiftoffRegister tmp = GetUnusedRegister(kGpReg, {});
  // Prepare 16 byte aligned buffer for shuffle control mask.
  mov(tmp.gp(), esp);
  and_(esp, -16);

  if (is_swizzle) {
    uint32_t imms[4];
    // Shuffles that use just 1 operand are called swizzles, rhs can be ignored.
    wasm::SimdShuffle::Pack16Lanes(imms, shuffle);
    for (int i = 3; i >= 0; i--) {
      push_imm32(imms[i]);
    }
    Pshufb(dst.fp(), lhs.fp(), Operand(esp, 0));
    mov(esp, tmp.gp());
    return;
  }

  movups(liftoff::kScratchDoubleReg, lhs.fp());
  for (int i = 3; i >= 0; i--) {
    uint32_t mask = 0;
    for (int j = 3; j >= 0; j--) {
      uint8_t lane = shuffle[i * 4 + j];
      mask <<= 8;
      mask |= lane < kSimd128Size ? lane : 0x80;
    }
    push(Immediate(mask));
  }
  Pshufb(liftoff::kScratchDoubleReg, lhs.fp(), Operand(esp, 0));

  for (int i = 3; i >= 0; i--) {
    uint32_t mask = 0;
    for (int j = 3; j >= 0; j--) {
      uint8_t lane = shuffle[i * 4 + j];
      mask <<= 8;
      mask |= lane >= kSimd128Size ? (lane & 0x0F) : 0x80;
    }
    push(Immediate(mask));
  }
  Pshufb(dst.fp(), rhs.fp(), Operand(esp, 0));
  Por(dst.fp(), liftoff::kScratchDoubleReg);
  mov(esp, tmp.gp());
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  Register scratch = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  I8x16Swizzle(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg,
               scratch);
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  Register tmp = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  I8x16Swizzle(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg, tmp,
               true);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  Cvttps2dq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  emit_i32x4_uconvert_f32x4(dst, src);
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  Cvttpd2dq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  emit_i32x4_trunc_sat_f64x2_u_zero(dst, src);
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  // Passing {src2} first is not a typo: the x86 instructions copy from the
  // second operand when the mask is 1, contrary to the Wasm instruction.
  if (lane_width == 8) {
    Pblendvb(dst.fp(), src2.fp(), src1.fp(), mask.fp());
  } else if (lane_width == 32) {
    Blendvps(dst.fp(), src2.fp(), src1.fp(), mask.fp());
  } else if (lane_width == 64) {
    Blendvpd(dst.fp(), src2.fp(), src1.fp(), mask.fp());
  } else {
    UNREACHABLE();
  }
}

void LiftoffAssembler::emit_i8x16_popcnt(LiftoffRegister dst,
                                         LiftoffRegister src) {
  Register scratch = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  XMMRegister tmp =
      GetUnusedRegister(RegClass::kFpReg, LiftoffRegList{dst, src}).fp();
  I8x16Popcnt(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, tmp, scratch);
}

void LiftoffAssembler::emit_i8x16_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  I8x16Splat(dst.fp(), src.gp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  I16x8Splat(dst.fp(), src.gp());
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Movd(dst.fp(), src.gp());
  Pshufd(dst.fp(), dst.fp(), uint8_t{0});
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Pinsrd(dst.fp(), src.low_gp(), 0);
  Pinsrd(dst.fp(), src.high_gp(), 1);
  Pshufd(dst.fp(), dst.fp(), uint8_t{0x44});
}

void LiftoffAssembler::emit_f32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  F32x4Splat(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_f64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Movddup(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i8x16_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqb, &Assembler::pcmpeqb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqb, &Assembler::pcmpeqb>(
      this, dst, lhs, rhs);
  Pcmpeqb(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpcmpgtb,
                                       &Assembler::pcmpgtb>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i8x16_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxub, &Assembler::pmaxub>(
      this, dst, lhs, rhs);
  Pcmpeqb(dst.fp(), ref);
  Pcmpeqb(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsb, &Assembler::pminsb>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqb(dst.fp(), ref);
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminub, &Assembler::pminub>(
      this, dst, lhs, rhs);
  Pcmpeqb(dst.fp(), ref);
}

void LiftoffAssembler::emit_i16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqw, &Assembler::pcmpeqw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqw, &Assembler::pcmpeqw>(
      this, dst, lhs, rhs);
  Pcmpeqw(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpcmpgtw,
                                       &Assembler::pcmpgtw>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i16x8_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxuw, &Assembler::pmaxuw>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqw(dst.fp(), ref);
  Pcmpeqw(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsw, &Assembler::pminsw>(
      this, dst, lhs, rhs);
  Pcmpeqw(dst.fp(), ref);
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminuw, &Assembler::pminuw>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqw(dst.fp(), ref);
}

void LiftoffAssembler::emit_i32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqd, &Assembler::pcmpeqd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqd, &Assembler::pcmpeqd>(
      this, dst, lhs, rhs);
  Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpcmpgtd,
                                       &Assembler::pcmpgtd>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i32x4_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxud, &Assembler::pmaxud>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqd(dst.fp(), ref);
  Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminsd, &Assembler::pminsd>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqd(dst.fp(), ref);
}

void LiftoffAssembler::emit_i32x4_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  DoubleRegister ref = rhs.fp();
  if (dst == rhs) {
    Movaps(liftoff::kScratchDoubleReg, rhs.fp());
    ref = liftoff::kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpminud, &Assembler::pminud>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqd(dst.fp(), ref);
}

void LiftoffAssembler::emit_i64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqq, &Assembler::pcmpeqq>(
      this, dst, lhs, rhs, SSE4_1);
}

void LiftoffAssembler::emit_i64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpcmpeqq, &Assembler::pcmpeqq>(
      this, dst, lhs, rhs, SSE4_1);
  Pcmpeqq(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
  Pxor(dst.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i64x2_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Different register alias requirements depending on CpuFeatures supported:
  if (CpuFeatures::IsSupported(AVX) || CpuFeatures::IsSupported(SSE4_2)) {
    // 1. AVX, or SSE4_2 no requirements (I64x2GtS takes care of aliasing).
    I64x2GtS(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
  } else {
    // 2. Else, dst != lhs && dst != rhs (lhs == rhs is ok).
    if (dst == lhs || dst == rhs) {
      LiftoffRegister tmp =
          GetUnusedRegister(RegClass::kFpReg, LiftoffRegList{lhs, rhs});
      I64x2GtS(tmp.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
      movaps(dst.fp(), tmp.fp());
    } else {
      I64x2GtS(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
    }
  }
}

void LiftoffAssembler::emit_i64x2_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Different register alias requirements depending on CpuFeatures supported:
  if (CpuFeatures::IsSupported(AVX)) {
    // 1. AVX, no requirements.
    I64x2GeS(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
  } else if (CpuFeatures::IsSupported(SSE4_2)) {
    // 2. SSE4_2, dst != lhs.
    if (dst == lhs) {
      LiftoffRegister tmp =
          GetUnusedRegister(RegClass::kFpReg, {rhs}, LiftoffRegList{lhs});
      // macro-assembler uses kScratchDoubleReg, so don't use it.
      I64x2GeS(tmp.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
      movaps(dst.fp(), tmp.fp());
    } else {
      I64x2GeS(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
    }
  } else {
    // 3. Else, dst != lhs && dst != rhs (lhs == rhs is ok).
    if (dst == lhs || dst == rhs) {
      LiftoffRegister tmp =
          GetUnusedRegister(RegClass::kFpReg, LiftoffRegList{lhs, rhs});
      I64x2GeS(tmp.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
      movaps(dst.fp(), tmp.fp());
    } else {
      I64x2GeS(dst.fp(), lhs.fp(), rhs.fp(), liftoff::kScratchDoubleReg);
    }
  }
}

void LiftoffAssembler::emit_f32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vcmpeqps, &Assembler::cmpeqps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vcmpneqps,
                                    &Assembler::cmpneqps>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vcmpltps,
                                       &Assembler::cmpltps>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_f32x4_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vcmpleps,
                                       &Assembler::cmpleps>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_f64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vcmpeqpd, &Assembler::cmpeqpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vcmpneqpd,
                                    &Assembler::cmpneqpd>(this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vcmpltpd,
                                       &Assembler::cmpltpd>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_f64x2_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vcmplepd,
                                       &Assembler::cmplepd>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
  MacroAssembler::Move(dst.fp(), vals[0]);

  uint64_t high = vals[1];
  Register tmp = GetUnusedRegister(RegClass::kGpReg, {}).gp();
  MacroAssembler::Move(tmp, Immediate(high & 0xffff'ffff));
  Pinsrd(dst.fp(), tmp, 2);

  MacroAssembler::Move(tmp, Immediate(high >> 32));
  Pinsrd(dst.fp(), tmp, 3);
}

void LiftoffAssembler::emit_s128_not(LiftoffRegister dst, LiftoffRegister src) {
  S128Not(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_s128_and(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpand, &Assembler::pand>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_s128_or(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpor, &Assembler::por>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_s128_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpxor, &Assembler::pxor>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  // Ensure that we don't overwrite any inputs with the movaps below.
  DCHECK_NE(dst, src1);
  DCHECK_NE(dst, src2);
  if (!CpuFeatures::IsSupported(AVX) && dst != mask) {
    movaps(dst.fp(), mask.fp());
    S128Select(dst.fp(), dst.fp(), src1.fp(), src2.fp(),
               liftoff::kScratchDoubleReg);
  } else {
    S128Select(dst.fp(), mask.fp(), src1.fp(), src2.fp(),
               liftoff::kScratchDoubleReg);
  }
}

void LiftoffAssembler::emit_i8x16_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  if (dst.fp() == src.fp()) {
    Pcmpeqd(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);
    Psignb(dst.fp(), liftoff::kScratchDoubleReg);
  } else {
    Pxor(dst.fp(), dst.fp());
    Psubb(dst.fp(), src.fp());
  }
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  liftoff::EmitAnyTrue(this, dst, src);
}

void LiftoffAssembler::emit_i8x16_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue<&MacroAssembler::Pcmpeqb>(this, dst, src);
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  Pmovmskb(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i8x16_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  LiftoffRegister tmp = GetUnusedRegister(kGpReg, LiftoffRegList{rhs});
  LiftoffRegister tmp_simd =
      GetUnusedRegister(kFpReg, LiftoffRegList{dst, lhs});
  I8x16Shl(dst.fp(), lhs.fp(), rhs.gp(), tmp.gp(), liftoff::kScratchDoubleReg,
           tmp_simd.fp());
}

void LiftoffAssembler::emit_i8x16_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  LiftoffRegister tmp = GetUnusedRegister(kGpReg, {});
  I8x16Shl(dst.fp(), lhs.fp(), rhs, tmp.gp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Register tmp = GetUnusedRegister(kGpReg, LiftoffRegList{rhs}).gp();
  XMMRegister tmp_simd =
      GetUnusedRegister(kFpReg, LiftoffRegList{dst, lhs}).fp();
  I8x16ShrS(dst.fp(), lhs.fp(), rhs.gp(), tmp, liftoff::kScratchDoubleReg,
            tmp_simd);
}

void LiftoffAssembler::emit_i8x16_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  I8x16ShrS(dst.fp(), lhs.fp(), rhs, liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  Register tmp = GetUnusedRegister(kGpReg, LiftoffRegList{rhs}).gp();
  XMMRegister tmp_simd =
      GetUnusedRegister(kFpReg, LiftoffRegList{dst, lhs}).fp();
  I8x16ShrU(dst.fp(), lhs.fp(), rhs.gp(), tmp, liftoff::kScratchDoubleReg,
            tmp_simd);
}

void LiftoffAssembler::emit_i8x16_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  I8x16ShrU(dst.fp(), lhs.fp(), rhs, tmp, liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddb, &Assembler::paddb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_add_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddsb, &Assembler::paddsb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_add_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddusb, &Assembler::paddusb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubb, &Assembler::psubb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_sub_sat_s(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubsb, &Assembler::psubsb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_sub_sat_u(LiftoffRegister dst,
                                            LiftoffRegister lhs,
                                            LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubusb,
                                       &Assembler::psubusb>(this, dst, lhs,
                                                            rhs);
}

void LiftoffAssembler::emit_i8x16_min_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
```