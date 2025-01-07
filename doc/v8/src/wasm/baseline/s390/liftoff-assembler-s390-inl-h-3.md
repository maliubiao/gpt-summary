Response:
The user wants a summary of the functionality of the provided C++ code snippet from the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The code is part of the `LiftoffAssembler` for the s390 architecture within V8's WebAssembly baseline compiler. The name itself suggests it's involved in generating machine code instructions. The `_INL_H_` suffix usually indicates inline functions or helper functions.

2. **Analyze the function names:**  The function names are highly descriptive and provide strong clues about their functionality. Look for patterns and keywords like:
    * `Load...`:  Reading data from memory.
    * `Store...`: Writing data to memory.
    * `emit_...`: Generating specific assembly instructions (often for SIMD operations).
    * `StackCheck`, `PushRegisters`, `PopRegisters`: Stack management.
    * `CallC`, `CallNativeWasmCode`, `CallIndirect`, `CallBuiltin`: Function call mechanisms.
    * `AllocateStackSlot`, `DeallocateStackSlot`: Stack allocation.

3. **Examine the parameters and types:** The parameters to the functions often reveal the types of data being manipulated (e.g., `LiftoffRegister`, `Register`, `MemOperand`, `MachineType`, `ValueKind`). The presence of `LiftoffRegister` suggests a higher-level abstraction over physical registers. `MemOperand` indicates memory access operations.

4. **Focus on SIMD operations:**  A significant portion of the code involves functions starting with `emit_` and dealing with types like `i64x2`, `i32x4`, `i16x8`, `i8x16`, `f64x2`, `f32x4`, and `s128`. This clearly indicates support for SIMD (Single Instruction, Multiple Data) instructions for vector processing, common in WebAssembly.

5. **Look for conditional logic:** The `Load` functions have `if-else if` blocks based on `memtype` and `transform`. This means the code can perform different kinds of loads depending on the data type and required transformation (e.g., sign extension, zero extension, splatting).

6. **Trace data flow:** For functions like `LoadLane` and `StoreLane`, observe how the `laneidx` parameter is used to access specific elements within a vector. The bit manipulation (`15 - laneidx`, `7 - laneidx`, etc.) is likely related to the endianness and layout of SIMD registers on the s390 architecture.

7. **Identify utility functions:** Functions like `StackCheck`, `PushRegisters`, `PopRegisters`, `AllocateStackSlot`, and `DeallocateStackSlot` are standard parts of function prologues and epilogues for managing the call stack.

8. **Consider the context:**  The code resides in `v8/src/wasm/baseline/s390/`. This confirms it's part of the baseline compiler for WebAssembly on the s390 architecture. Baseline compilers aim for quick compilation with reasonable performance.

9. **Address specific user questions:**
    * **File extension:** The filename ends in `.h`, so it's a C++ header file, not a Torque file.
    * **JavaScript relation:**  WebAssembly code is executed within a JavaScript environment. The operations in this file correspond to low-level implementations of WebAssembly instructions. Provide a simple JavaScript example of an operation that would ultimately use some of these functions (e.g., adding two SIMD vectors).
    * **Code logic and assumptions:** Pick a simpler function, like `emit_i64x2_mul`, and describe its input and output based on its name and parameters.
    * **Common programming errors:** Consider typical mistakes related to memory access, type mismatches, or incorrect usage of SIMD instructions.

10. **Summarize the functionality:**  Combine the observations into a concise summary highlighting the key responsibilities of the code: generating s390 assembly for WebAssembly, handling memory operations, implementing SIMD instructions, and managing the call stack.

11. **Review and refine:**  Ensure the answer is clear, accurate, and addresses all parts of the user's request. Organize the information logically.
```cpp
  LoadAndExtend8x8SLE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Uint8()) {
      LoadAndExtend8x8ULE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int16()) {
      LoadAndExtend16x4SLE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Uint16()) {
      LoadAndExtend16x4ULE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int32()) {
      LoadAndExtend32x2SLE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Uint32()) {
      LoadAndExtend32x2ULE(dst.fp(), src_op, r1);
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    if (memtype == MachineType::Int32()) {
      LoadV32ZeroLE(dst.fp(), src_op, r1);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      LoadV64ZeroLE(dst.fp(), src_op, r1);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      LoadAndSplat8x16LE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int16()) {
      LoadAndSplat16x8LE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int32()) {
      LoadAndSplat32x4LE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int64()) {
      LoadAndSplat64x2LE(dst.fp(), src_op, r1);
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  MemOperand src_op =
      MemOperand(addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);

  MachineType mem_type = type.mem_type();
  if (dst != src) {
    vlr(dst.fp(), src.fp(), Condition(0), Condition(0), Condition(0));
  }

  if (protected_load_pc) *protected_load_pc = pc_offset();
  if (mem_type == MachineType::Int8()) {
    LoadLane8LE(dst.fp(), src_op, 15 - laneidx, r1);
  } else if (mem_type == MachineType::Int16()) {
    LoadLane16LE(dst.fp(), src_op, 7 - laneidx, r1);
  } else if (mem_type == MachineType::Int32()) {
    LoadLane32LE(dst.fp(), src_op, 3 - laneidx, r1);
  } else {
    DCHECK_EQ(MachineType::Int64(), mem_type);
    LoadLane64LE(dst.fp(), src_op, 1 - laneidx, r1);
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  PREP_MEM_OPERAND(offset, offset_imm, ip)
  MemOperand dst_op =
      MemOperand(dst, offset == no_reg ? r0 : offset, offset_imm);

  if (protected_store_pc) *protected_store_pc = pc_offset();

  MachineRepresentation rep = type.mem_rep();
  if (rep == MachineRepresentation::kWord8) {
    StoreLane8LE(src.fp(), dst_op, 15 - lane, r1);
  } else if (rep == MachineRepresentation::kWord16) {
    StoreLane16LE(src.fp(), dst_op, 7 - lane, r1);
  } else if (rep == MachineRepresentation::kWord32) {
    StoreLane32LE(src.fp(), dst_op, 3 - lane, r1);
  } else {
    DCHECK_EQ(MachineRepresentation::kWord64, rep);
    StoreLane64LE(src.fp(), dst_op, 1 - lane, r1);
  }
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  I64x2Mul(dst.fp(), lhs.fp(), rhs.fp(), r0, r1, ip);
}

void LiftoffAssembler::emit_i32x4_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I32x4GeU(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I16x8GeU(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I8x16GeU(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  Simd128Register src1 = lhs.fp();
  Simd128Register src2 = rhs.fp();
  Simd128Register dest = dst.fp();
  I8x16Swizzle(dest, src1, src2, r0, r1, kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_promote_low_f32x4(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  F64x2PromoteLowF32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0, r1, ip);
}

void LiftoffAssembler::emit_i64x2_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I64x2BitMask(dst.gp(), src.fp(), r0, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I32x4BitMask(dst.gp(), src.fp(), r0, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_dot_i16x8_s(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  I32x4DotI16x8S(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I16x8BitMask(dst.gp(), src.fp(), r0, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_q15mulr_sat_s(LiftoffRegister dst,
                                                LiftoffRegister src1,
                                                LiftoffRegister src2) {
  Simd128Register s1 = src1.fp();
  Simd128Register s2 = src2.fp();
  Simd128Register dest = dst.fp();
  // Make sure temp registers are unique.
  Simd128Register temp1 =
      GetUnusedRegister(kFpReg, LiftoffRegList{dest, s1, s2}).fp();
  Simd128Register temp2 =
      GetUnusedRegister(kFpReg, LiftoffRegList{dest, s1, s2, temp1}).fp();
  I16x8Q15MulRSatS(dest, s1, s2, kScratchDoubleReg, temp1, temp2);
}

void LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s(LiftoffRegister dst,
                                                    LiftoffRegister lhs,
                                                    LiftoffRegister rhs) {
  I16x8DotI8x16S(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_dot_i8x16_i7x16_add_s(LiftoffRegister dst,
                                                        LiftoffRegister lhs,
                                                        LiftoffRegister rhs,
                                                        LiftoffRegister acc) {
  // Make sure temp register is unique.
  Simd128Register temp =
      GetUnusedRegister(kFpReg, LiftoffRegList{dst, lhs, rhs, acc}).fp();
  I32x4DotI8x16AddS(dst.fp(), lhs.fp(), rhs.fp(), acc.fp(), kScratchDoubleReg,
                    temp);
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  // Remap the shuffle indices to match IBM lane numbering.
  // TODO(miladfarca): Put this in a function and share it with the instrction
  // selector.
  int max_index = 15;
  int total_lane_count = 2 * kSimd128Size;
  uint8_t shuffle_remapped[kSimd128Size];
  for (int i = 0; i < kSimd128Size; i++) {
    uint8_t current_index = shuffle[i];
    shuffle_remapped[i] = (current_index <= max_index
                               ? max_index - current_index
                               : total_lane_count - current_index + max_index);
  }
  uint64_t vals[2];
  memcpy(vals, shuffle_remapped, sizeof(shuffle_remapped));
#ifdef V8_TARGET_BIG_ENDIAN
  vals[0] = ByteReverse(vals[0]);
  vals[1] = ByteReverse(vals[1]);
#endif
  I8x16Shuffle(dst.fp(), lhs.fp(), rhs.fp(), vals[1], vals[0], r0, ip,
               kScratchDoubleReg);
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  V128AnyTrue(dst.gp(), src.fp(), r0);
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I8x16BitMask(dst.gp(), src.fp(), r0, ip, kScratchDoubleReg);
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
#ifdef V8_TARGET_BIG_ENDIAN
  vals[0] = ByteReverse(vals[0]);
  vals[1] = ByteReverse(vals[1]);
#endif
  S128Const(dst.fp(), vals[1], vals[0], r0, ip);
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  S128Select(dst.fp(), src1.fp(), src2.fp(), mask.fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  I32x4SConvertF32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  I32x4UConvertF32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  F32x4SConvertI32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  F32x4UConvertI32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_f32x4_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  F32x4DemoteF64x2Zero(dst.fp(), src.fp(), kScratchDoubleReg, r0, r1, ip);
}

void LiftoffAssembler::emit_i8x16_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I8x16SConvertI16x8(dst.fp(), lhs.fp(), rhs.fp());
}

void LiftoffAssembler::emit_i8x16_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I8x16UConvertI16x8(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I16x8SConvertI32x4(dst.fp(), lhs.fp(), rhs.fp());
}

void LiftoffAssembler::emit_i16x8_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I16x8UConvertI32x4(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  I32x4TruncSatF64x2SZero(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  I32x4TruncSatF64x2UZero(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  // S390 uses bytewise selection for all lane widths.
  emit_s128_select(dst, src1, src2, mask);
}

void LiftoffAssembler::StackCheck(Label* ool_code) {
  Register limit_address = ip;
  LoadStackLimit(limit_address, StackLimitKind::kInterruptStackLimit);
  CmpU64(sp, limit_address);
  b(le, ool_code);
}

void LiftoffAssembler::AssertUnreachable(AbortReason reason) {
  // Asserts unreachable within the wasm code.
  MacroAssembler::AssertUnreachable(reason);
}

void LiftoffAssembler::PushRegisters(LiftoffRegList regs) {
  MultiPush(regs.GetGpList());
  MultiPushF64OrV128(regs.GetFpList(), ip);
}

void LiftoffAssembler::PopRegisters(LiftoffRegList regs) {
  MultiPopF64OrV128(regs.GetFpList(), ip);
  MultiPop(regs.GetGpList());
}

void LiftoffAssembler::RecordSpillsInSafepoint(
    SafepointTableBuilder::Safepoint& safepoint, LiftoffRegList all_spills,
    LiftoffRegList ref_spills, int spill_offset) {
  LiftoffRegList fp_spills = all_spills & kFpCacheRegList;
  int spill_space_size = fp_spills.GetNumRegsSet() * kSimd128Size;
  LiftoffRegList gp_spills = all_spills & kGpCacheRegList;
  while (!gp_spills.is_empty()) {
    LiftoffRegister reg = gp_spills.GetLastRegSet();
    if (ref_spills.has(reg)) {
      safepoint.DefineTaggedStackSlot(spill_offset);
    }
    gp_spills.clear(reg);
    ++spill_offset;
    spill_space_size += kSystemPointerSize;
  }
  // Record the number of additional spill slots.
  RecordOolSpillSpaceSize(spill_space_size);
}

void LiftoffAssembler::DropStackSlotsAndRet(uint32_t num_stack_slots) {
  Drop(num_stack_slots);
  Ret();
}

void LiftoffAssembler::CallCWithStackBuffer(
    const std::initializer_list<VarState> args, const LiftoffRegister* rets,
    ValueKind return_kind, ValueKind out_argument_kind, int stack_bytes,
    ExternalReference ext_ref) {
  int total_size = RoundUp(stack_bytes, 8);

  int size = total_size;
  constexpr int kStackPageSize = 4 * KB;

  // Reserve space in the stack.
  while (size > kStackPageSize) {
    lay(sp, MemOperand(sp, -kStackPageSize));
    StoreU64(r0, MemOperand(sp));
    size -= kStackPageSize;
  }

  lay(sp, MemOperand(sp, -size));

  int arg_offset = 0;
  for (const VarState& arg : args) {
    MemOperand dst{sp, arg_offset};
    liftoff::StoreToMemory(this, dst, arg, ip);
    arg_offset += value_kind_size(arg.kind());
  }
  DCHECK_LE(arg_offset, stack_bytes);

  // Pass a pointer to the buffer with the arguments to the C function.
  mov(r2, sp);

  // Now call the C function.
  constexpr int kNumCCallArgs = 1;
  PrepareCallCFunction(kNumCCallArgs, no_reg);
  CallCFunction(ext_ref, kNumCCallArgs);

  // Move return value to the right register.
  const LiftoffRegister* result_reg = rets;
  if (return_kind != kVoid) {
    constexpr Register kReturnReg = r2;
    if (kReturnReg != rets->gp()) {
      Move(*rets, LiftoffRegister(kReturnReg), return_kind);
    }
    result_reg++;
  }

  // Load potential output value from the buffer on the stack.
  if (out_argument_kind != kVoid) {
    switch (out_argument_kind) {
      case kI16:
        LoadS16(result_reg->gp(), MemOperand(sp));
        break;
      case kI32:
        LoadS32(result_reg->gp(), MemOperand(sp));
        break;
      case kI64:
      case kRefNull:
      case kRef:
      case kRtt:
        LoadU64(result_reg->gp(), MemOperand(sp));
        break;
      case kF32:
        LoadF32(result_reg->fp(), MemOperand(sp));
        break;
      case kF64:
        LoadF64(result_reg->fp(), MemOperand(sp));
        break;
      case kS128:
        LoadV128(result_reg->fp(), MemOperand(sp), ip);
        break;
      default:
        UNREACHABLE();
    }
  }
  lay(sp, MemOperand(sp, total_size));
}

void LiftoffAssembler::CallC(const std::initializer_list<VarState> args,
                             ExternalReference ext_ref) {
  // First, prepare the stack for the C call.
  int num_args = static_cast<int>(args.size());
  PrepareCallCFunction(num_args, r0);

  // Then execute the parallel register move and also move values to parameter
  // stack slots.
  int reg_args = 0;
  int stack_args = 0;
  ParallelMove parallel_move{this};
  for (const VarState& arg : args) {
    if (reg_args < int{arraysize(kCArgRegs)}) {
      parallel_move.LoadIntoRegister(LiftoffRegister{kCArgRegs[reg_args]}, arg);
      ++reg_args;
    } else {
      int bias = 0;
      // On BE machines values with less than 8 bytes are right justified.
      // bias here is relative to the stack pointer.
      if (arg.kind() == kI32 || arg.kind() == kF32) bias = -stack_bias;
      int offset =
          (kStackFrameExtraParamSlot + stack_args) * kSystemPointerSize;
      MemOperand dst{sp, offset + bias};
      liftoff::StoreToMemory(this, dst, arg, ip);
      ++stack_args;
    }
  }
  parallel_move.Execute();

  // Now call the C function.
  CallCFunction(ext_ref, num_args);
}

void LiftoffAssembler::CallNativeWasmCode(Address addr) {
  Call(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::TailCallNativeWasmCode(Address addr) {
  Jump(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::CallIndirect(const ValueKindSig* sig,
                                    compiler::CallDescriptor* call_descriptor,
                                    Register target) {
  DCHECK(target != no_reg);
  Call(target);
}

void LiftoffAssembler::TailCallIndirect(Register target) {
  DCHECK(target != no_reg);
  Jump(target);
}

void LiftoffAssembler::CallBuiltin(Builtin builtin) {
  // A direct call to a builtin. Just encode the builtin index. This will be
  // patched at relocation.
  Call(static_cast<Address>(builtin), RelocInfo::WASM_STUB_CALL);
}

void LiftoffAssembler::AllocateStackSlot(Register addr, uint32_t size) {
  lay(sp, MemOperand(sp, -size));
  MacroAssembler::Move(addr, sp);
}

void LiftoffAssembler::DeallocateStackSlot(uint32_t size) {
  lay(sp, MemOperand(sp, size));
}

void LiftoffAssembler::MaybeOSR() {}

void LiftoffAssembler::emit_set_if_nan(Register dst, DoubleRegister src,
                                       ValueKind kind) {
  Label return_nan, done;
  if (kind == kF32) {
    cebr(src, src);
    bunordered(&return_nan);
  } else {
    DCHECK_EQ(kind, kF64);
    cdbr(src, src);
    bunordered(&return_nan);
  }
  b(&done);
  bind(&return_nan);
  StoreF32(src, MemOperand(dst));
  bind(&done);
}

void LiftoffAssembler::emit_s128_set_if_nan(Register dst, LiftoffRegister src,
                                            Register tmp_gp,
                                            LiftoffRegister tmp_s128,
                                            ValueKind lane_kind) {
  Label return_nan, done;
  if (lane_kind == kF32) {
    vfce(tmp_s128.fp(), src.fp(), src.fp(), Condition(1), Condition(0),
         Condition(2));
    b(Condition(0x5), &return_nan);  // If any or all are NaN.
  } else {
    DCHECK_EQ(lane_kind, kF64);
    vfce(tmp_s128.fp(), src.fp(), src.fp(), Condition(1), Condition(0),
         Condition(3));
    b(Condition(0x5), &return_nan);
  }
  b(&done);
  bind(&return_nan);
  mov(r0, Operand(1));
  StoreU32(r0, MemOperand(dst));
  bind(&done);
}

void LiftoffStackSlots::Construct(int param_slots) {
  DCHECK_LT(0, slots_.size());
  SortInPushOrder();
  int last_stack_slot = param_slots;
  for (auto& slot : slots_) {
    const int stack_slot = slot.dst_slot_;
    int stack_decrement = (last_stack_slot - stack_slot) * kSystemPointerSize;
    DCHECK_LT(0, stack_decrement);
    last_stack_slot = stack_slot;
    const LiftoffAssembler::VarState& src = slot.src_;
    switch (src.loc()) {
      case LiftoffAssembler::VarState::kStack: {
        switch (src.kind()) {
          case kI32:
          case kRef:
          case kRefNull:
          case kRtt:
          case kI64: {
            asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->LoadU64(scratch, liftoff::GetStackSlot(slot.src_offset_));
            asm_->Push(scratch);
            break;
          }
          case kF32: {
            asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
            asm_->LoadF32(kScratchDoubleReg,
                          liftoff::GetStackSlot(slot.src_offset_ + stack_bias));
            asm_->lay(sp, MemOperand(sp, -kSystemPointerSize));
            asm_->StoreF32(kScratchDoubleReg, MemOperand(sp));
            break;
          }
          case kF64: {
            asm_->AllocateStackSpace(stack_decrement - kDoubleSize);
            asm_->LoadF64(kScratchDoubleReg,
                          liftoff::GetStackSlot(slot.src_offset_));
            asm_->push(kScratchDoubleReg);
            break;
          }
          case kS128: {
            asm_->AllocateStackSpace(stack_decrement - kSimd128Size);
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->LoadV128(kScratchDoubleReg,
                           liftoff::GetStackSlot(slot.src_offset_), scratch);
            asm_->lay(sp, MemOperand(sp, -kSimd128Size));
            asm_->StoreV128(kScratchDoubleReg, MemOperand(sp), scratch);
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
      }
      case LiftoffAssembler::VarState::kRegister: {
        int pushed_bytes = SlotSizeInBytes(slot);
        asm_->AllocateStackSpace(stack_decrement - pushed_bytes);
        switch (src.kind()) {
          case kI64:
          case kI32:
          case kRef:
          case kRefNull:
          case kRtt:
            asm_->push(src.reg().gp());
            break;
          case kF32:
            asm_->lay(sp, MemOperand(sp, -kSystemPointerSize));
            asm_->StoreF32(src.reg().fp(), MemOperand(sp));
            break;
          case kF64:
            asm_->push(src.reg().fp());
            break;
          case kS128: {
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->lay(sp, MemOperand(sp, -kSimd128Size));
            asm_->StoreV128(src.reg().fp(), MemOperand(sp), scratch);
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
Prompt: 
```
这是目录为v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/s390/liftoff-assembler-s390-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
  LoadAndExtend8x8SLE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Uint8()) {
      LoadAndExtend8x8ULE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int16()) {
      LoadAndExtend16x4SLE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Uint16()) {
      LoadAndExtend16x4ULE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int32()) {
      LoadAndExtend32x2SLE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Uint32()) {
      LoadAndExtend32x2ULE(dst.fp(), src_op, r1);
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    if (memtype == MachineType::Int32()) {
      LoadV32ZeroLE(dst.fp(), src_op, r1);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      LoadV64ZeroLE(dst.fp(), src_op, r1);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      LoadAndSplat8x16LE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int16()) {
      LoadAndSplat16x8LE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int32()) {
      LoadAndSplat32x4LE(dst.fp(), src_op, r1);
    } else if (memtype == MachineType::Int64()) {
      LoadAndSplat64x2LE(dst.fp(), src_op, r1);
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool i64_offset) {
  PREP_MEM_OPERAND(offset_reg, offset_imm, ip)
  MemOperand src_op =
      MemOperand(addr, offset_reg == no_reg ? r0 : offset_reg, offset_imm);

  MachineType mem_type = type.mem_type();
  if (dst != src) {
    vlr(dst.fp(), src.fp(), Condition(0), Condition(0), Condition(0));
  }

  if (protected_load_pc) *protected_load_pc = pc_offset();
  if (mem_type == MachineType::Int8()) {
    LoadLane8LE(dst.fp(), src_op, 15 - laneidx, r1);
  } else if (mem_type == MachineType::Int16()) {
    LoadLane16LE(dst.fp(), src_op, 7 - laneidx, r1);
  } else if (mem_type == MachineType::Int32()) {
    LoadLane32LE(dst.fp(), src_op, 3 - laneidx, r1);
  } else {
    DCHECK_EQ(MachineType::Int64(), mem_type);
    LoadLane64LE(dst.fp(), src_op, 1 - laneidx, r1);
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  PREP_MEM_OPERAND(offset, offset_imm, ip)
  MemOperand dst_op =
      MemOperand(dst, offset == no_reg ? r0 : offset, offset_imm);

  if (protected_store_pc) *protected_store_pc = pc_offset();

  MachineRepresentation rep = type.mem_rep();
  if (rep == MachineRepresentation::kWord8) {
    StoreLane8LE(src.fp(), dst_op, 15 - lane, r1);
  } else if (rep == MachineRepresentation::kWord16) {
    StoreLane16LE(src.fp(), dst_op, 7 - lane, r1);
  } else if (rep == MachineRepresentation::kWord32) {
    StoreLane32LE(src.fp(), dst_op, 3 - lane, r1);
  } else {
    DCHECK_EQ(MachineRepresentation::kWord64, rep);
    StoreLane64LE(src.fp(), dst_op, 1 - lane, r1);
  }
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  I64x2Mul(dst.fp(), lhs.fp(), rhs.fp(), r0, r1, ip);
}

void LiftoffAssembler::emit_i32x4_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I32x4GeU(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I16x8GeU(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  I8x16GeU(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  Simd128Register src1 = lhs.fp();
  Simd128Register src2 = rhs.fp();
  Simd128Register dest = dst.fp();
  I8x16Swizzle(dest, src1, src2, r0, r1, kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_promote_low_f32x4(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  F64x2PromoteLowF32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0, r1, ip);
}

void LiftoffAssembler::emit_i64x2_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I64x2BitMask(dst.gp(), src.fp(), r0, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I32x4BitMask(dst.gp(), src.fp(), r0, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_dot_i16x8_s(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  I32x4DotI16x8S(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I16x8BitMask(dst.gp(), src.fp(), r0, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_q15mulr_sat_s(LiftoffRegister dst,
                                                LiftoffRegister src1,
                                                LiftoffRegister src2) {
  Simd128Register s1 = src1.fp();
  Simd128Register s2 = src2.fp();
  Simd128Register dest = dst.fp();
  // Make sure temp registers are unique.
  Simd128Register temp1 =
      GetUnusedRegister(kFpReg, LiftoffRegList{dest, s1, s2}).fp();
  Simd128Register temp2 =
      GetUnusedRegister(kFpReg, LiftoffRegList{dest, s1, s2, temp1}).fp();
  I16x8Q15MulRSatS(dest, s1, s2, kScratchDoubleReg, temp1, temp2);
}

void LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s(LiftoffRegister dst,
                                                    LiftoffRegister lhs,
                                                    LiftoffRegister rhs) {
  I16x8DotI8x16S(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_dot_i8x16_i7x16_add_s(LiftoffRegister dst,
                                                        LiftoffRegister lhs,
                                                        LiftoffRegister rhs,
                                                        LiftoffRegister acc) {
  // Make sure temp register is unique.
  Simd128Register temp =
      GetUnusedRegister(kFpReg, LiftoffRegList{dst, lhs, rhs, acc}).fp();
  I32x4DotI8x16AddS(dst.fp(), lhs.fp(), rhs.fp(), acc.fp(), kScratchDoubleReg,
                    temp);
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  // Remap the shuffle indices to match IBM lane numbering.
  // TODO(miladfarca): Put this in a function and share it with the instrction
  // selector.
  int max_index = 15;
  int total_lane_count = 2 * kSimd128Size;
  uint8_t shuffle_remapped[kSimd128Size];
  for (int i = 0; i < kSimd128Size; i++) {
    uint8_t current_index = shuffle[i];
    shuffle_remapped[i] = (current_index <= max_index
                               ? max_index - current_index
                               : total_lane_count - current_index + max_index);
  }
  uint64_t vals[2];
  memcpy(vals, shuffle_remapped, sizeof(shuffle_remapped));
#ifdef V8_TARGET_BIG_ENDIAN
  vals[0] = ByteReverse(vals[0]);
  vals[1] = ByteReverse(vals[1]);
#endif
  I8x16Shuffle(dst.fp(), lhs.fp(), rhs.fp(), vals[1], vals[0], r0, ip,
               kScratchDoubleReg);
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  V128AnyTrue(dst.gp(), src.fp(), r0);
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  I8x16BitMask(dst.gp(), src.fp(), r0, ip, kScratchDoubleReg);
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
#ifdef V8_TARGET_BIG_ENDIAN
  vals[0] = ByteReverse(vals[0]);
  vals[1] = ByteReverse(vals[1]);
#endif
  S128Const(dst.fp(), vals[1], vals[0], r0, ip);
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  S128Select(dst.fp(), src1.fp(), src2.fp(), mask.fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  I32x4SConvertF32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  I32x4UConvertF32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  F32x4SConvertI32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  F32x4UConvertI32x4(dst.fp(), src.fp(), kScratchDoubleReg, r0);
}

void LiftoffAssembler::emit_f32x4_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  F32x4DemoteF64x2Zero(dst.fp(), src.fp(), kScratchDoubleReg, r0, r1, ip);
}

void LiftoffAssembler::emit_i8x16_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I8x16SConvertI16x8(dst.fp(), lhs.fp(), rhs.fp());
}

void LiftoffAssembler::emit_i8x16_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I8x16UConvertI16x8(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I16x8SConvertI32x4(dst.fp(), lhs.fp(), rhs.fp());
}

void LiftoffAssembler::emit_i16x8_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  I16x8UConvertI32x4(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  I32x4TruncSatF64x2SZero(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  I32x4TruncSatF64x2UZero(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  // S390 uses bytewise selection for all lane widths.
  emit_s128_select(dst, src1, src2, mask);
}

void LiftoffAssembler::StackCheck(Label* ool_code) {
  Register limit_address = ip;
  LoadStackLimit(limit_address, StackLimitKind::kInterruptStackLimit);
  CmpU64(sp, limit_address);
  b(le, ool_code);
}

void LiftoffAssembler::AssertUnreachable(AbortReason reason) {
  // Asserts unreachable within the wasm code.
  MacroAssembler::AssertUnreachable(reason);
}

void LiftoffAssembler::PushRegisters(LiftoffRegList regs) {
  MultiPush(regs.GetGpList());
  MultiPushF64OrV128(regs.GetFpList(), ip);
}

void LiftoffAssembler::PopRegisters(LiftoffRegList regs) {
  MultiPopF64OrV128(regs.GetFpList(), ip);
  MultiPop(regs.GetGpList());
}

void LiftoffAssembler::RecordSpillsInSafepoint(
    SafepointTableBuilder::Safepoint& safepoint, LiftoffRegList all_spills,
    LiftoffRegList ref_spills, int spill_offset) {
  LiftoffRegList fp_spills = all_spills & kFpCacheRegList;
  int spill_space_size = fp_spills.GetNumRegsSet() * kSimd128Size;
  LiftoffRegList gp_spills = all_spills & kGpCacheRegList;
  while (!gp_spills.is_empty()) {
    LiftoffRegister reg = gp_spills.GetLastRegSet();
    if (ref_spills.has(reg)) {
      safepoint.DefineTaggedStackSlot(spill_offset);
    }
    gp_spills.clear(reg);
    ++spill_offset;
    spill_space_size += kSystemPointerSize;
  }
  // Record the number of additional spill slots.
  RecordOolSpillSpaceSize(spill_space_size);
}

void LiftoffAssembler::DropStackSlotsAndRet(uint32_t num_stack_slots) {
  Drop(num_stack_slots);
  Ret();
}

void LiftoffAssembler::CallCWithStackBuffer(
    const std::initializer_list<VarState> args, const LiftoffRegister* rets,
    ValueKind return_kind, ValueKind out_argument_kind, int stack_bytes,
    ExternalReference ext_ref) {
  int total_size = RoundUp(stack_bytes, 8);

  int size = total_size;
  constexpr int kStackPageSize = 4 * KB;

  // Reserve space in the stack.
  while (size > kStackPageSize) {
    lay(sp, MemOperand(sp, -kStackPageSize));
    StoreU64(r0, MemOperand(sp));
    size -= kStackPageSize;
  }

  lay(sp, MemOperand(sp, -size));

  int arg_offset = 0;
  for (const VarState& arg : args) {
    MemOperand dst{sp, arg_offset};
    liftoff::StoreToMemory(this, dst, arg, ip);
    arg_offset += value_kind_size(arg.kind());
  }
  DCHECK_LE(arg_offset, stack_bytes);

  // Pass a pointer to the buffer with the arguments to the C function.
  mov(r2, sp);

  // Now call the C function.
  constexpr int kNumCCallArgs = 1;
  PrepareCallCFunction(kNumCCallArgs, no_reg);
  CallCFunction(ext_ref, kNumCCallArgs);

  // Move return value to the right register.
  const LiftoffRegister* result_reg = rets;
  if (return_kind != kVoid) {
    constexpr Register kReturnReg = r2;
    if (kReturnReg != rets->gp()) {
      Move(*rets, LiftoffRegister(kReturnReg), return_kind);
    }
    result_reg++;
  }

  // Load potential output value from the buffer on the stack.
  if (out_argument_kind != kVoid) {
    switch (out_argument_kind) {
      case kI16:
        LoadS16(result_reg->gp(), MemOperand(sp));
        break;
      case kI32:
        LoadS32(result_reg->gp(), MemOperand(sp));
        break;
      case kI64:
      case kRefNull:
      case kRef:
      case kRtt:
        LoadU64(result_reg->gp(), MemOperand(sp));
        break;
      case kF32:
        LoadF32(result_reg->fp(), MemOperand(sp));
        break;
      case kF64:
        LoadF64(result_reg->fp(), MemOperand(sp));
        break;
      case kS128:
        LoadV128(result_reg->fp(), MemOperand(sp), ip);
        break;
      default:
        UNREACHABLE();
    }
  }
  lay(sp, MemOperand(sp, total_size));
}

void LiftoffAssembler::CallC(const std::initializer_list<VarState> args,
                             ExternalReference ext_ref) {
  // First, prepare the stack for the C call.
  int num_args = static_cast<int>(args.size());
  PrepareCallCFunction(num_args, r0);

  // Then execute the parallel register move and also move values to parameter
  // stack slots.
  int reg_args = 0;
  int stack_args = 0;
  ParallelMove parallel_move{this};
  for (const VarState& arg : args) {
    if (reg_args < int{arraysize(kCArgRegs)}) {
      parallel_move.LoadIntoRegister(LiftoffRegister{kCArgRegs[reg_args]}, arg);
      ++reg_args;
    } else {
      int bias = 0;
      // On BE machines values with less than 8 bytes are right justified.
      // bias here is relative to the stack pointer.
      if (arg.kind() == kI32 || arg.kind() == kF32) bias = -stack_bias;
      int offset =
          (kStackFrameExtraParamSlot + stack_args) * kSystemPointerSize;
      MemOperand dst{sp, offset + bias};
      liftoff::StoreToMemory(this, dst, arg, ip);
      ++stack_args;
    }
  }
  parallel_move.Execute();

  // Now call the C function.
  CallCFunction(ext_ref, num_args);
}

void LiftoffAssembler::CallNativeWasmCode(Address addr) {
  Call(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::TailCallNativeWasmCode(Address addr) {
  Jump(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::CallIndirect(const ValueKindSig* sig,
                                    compiler::CallDescriptor* call_descriptor,
                                    Register target) {
  DCHECK(target != no_reg);
  Call(target);
}

void LiftoffAssembler::TailCallIndirect(Register target) {
  DCHECK(target != no_reg);
  Jump(target);
}

void LiftoffAssembler::CallBuiltin(Builtin builtin) {
  // A direct call to a builtin. Just encode the builtin index. This will be
  // patched at relocation.
  Call(static_cast<Address>(builtin), RelocInfo::WASM_STUB_CALL);
}

void LiftoffAssembler::AllocateStackSlot(Register addr, uint32_t size) {
  lay(sp, MemOperand(sp, -size));
  MacroAssembler::Move(addr, sp);
}

void LiftoffAssembler::DeallocateStackSlot(uint32_t size) {
  lay(sp, MemOperand(sp, size));
}

void LiftoffAssembler::MaybeOSR() {}

void LiftoffAssembler::emit_set_if_nan(Register dst, DoubleRegister src,
                                       ValueKind kind) {
  Label return_nan, done;
  if (kind == kF32) {
    cebr(src, src);
    bunordered(&return_nan);
  } else {
    DCHECK_EQ(kind, kF64);
    cdbr(src, src);
    bunordered(&return_nan);
  }
  b(&done);
  bind(&return_nan);
  StoreF32(src, MemOperand(dst));
  bind(&done);
}

void LiftoffAssembler::emit_s128_set_if_nan(Register dst, LiftoffRegister src,
                                            Register tmp_gp,
                                            LiftoffRegister tmp_s128,
                                            ValueKind lane_kind) {
  Label return_nan, done;
  if (lane_kind == kF32) {
    vfce(tmp_s128.fp(), src.fp(), src.fp(), Condition(1), Condition(0),
         Condition(2));
    b(Condition(0x5), &return_nan);  // If any or all are NaN.
  } else {
    DCHECK_EQ(lane_kind, kF64);
    vfce(tmp_s128.fp(), src.fp(), src.fp(), Condition(1), Condition(0),
         Condition(3));
    b(Condition(0x5), &return_nan);
  }
  b(&done);
  bind(&return_nan);
  mov(r0, Operand(1));
  StoreU32(r0, MemOperand(dst));
  bind(&done);
}

void LiftoffStackSlots::Construct(int param_slots) {
  DCHECK_LT(0, slots_.size());
  SortInPushOrder();
  int last_stack_slot = param_slots;
  for (auto& slot : slots_) {
    const int stack_slot = slot.dst_slot_;
    int stack_decrement = (last_stack_slot - stack_slot) * kSystemPointerSize;
    DCHECK_LT(0, stack_decrement);
    last_stack_slot = stack_slot;
    const LiftoffAssembler::VarState& src = slot.src_;
    switch (src.loc()) {
      case LiftoffAssembler::VarState::kStack: {
        switch (src.kind()) {
          case kI32:
          case kRef:
          case kRefNull:
          case kRtt:
          case kI64: {
            asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->LoadU64(scratch, liftoff::GetStackSlot(slot.src_offset_));
            asm_->Push(scratch);
            break;
          }
          case kF32: {
            asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
            asm_->LoadF32(kScratchDoubleReg,
                          liftoff::GetStackSlot(slot.src_offset_ + stack_bias));
            asm_->lay(sp, MemOperand(sp, -kSystemPointerSize));
            asm_->StoreF32(kScratchDoubleReg, MemOperand(sp));
            break;
          }
          case kF64: {
            asm_->AllocateStackSpace(stack_decrement - kDoubleSize);
            asm_->LoadF64(kScratchDoubleReg,
                          liftoff::GetStackSlot(slot.src_offset_));
            asm_->push(kScratchDoubleReg);
            break;
          }
          case kS128: {
            asm_->AllocateStackSpace(stack_decrement - kSimd128Size);
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->LoadV128(kScratchDoubleReg,
                           liftoff::GetStackSlot(slot.src_offset_), scratch);
            asm_->lay(sp, MemOperand(sp, -kSimd128Size));
            asm_->StoreV128(kScratchDoubleReg, MemOperand(sp), scratch);
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
      }
      case LiftoffAssembler::VarState::kRegister: {
        int pushed_bytes = SlotSizeInBytes(slot);
        asm_->AllocateStackSpace(stack_decrement - pushed_bytes);
        switch (src.kind()) {
          case kI64:
          case kI32:
          case kRef:
          case kRefNull:
          case kRtt:
            asm_->push(src.reg().gp());
            break;
          case kF32:
            asm_->lay(sp, MemOperand(sp, -kSystemPointerSize));
            asm_->StoreF32(src.reg().fp(), MemOperand(sp));
            break;
          case kF64:
            asm_->push(src.reg().fp());
            break;
          case kS128: {
            UseScratchRegisterScope temps(asm_);
            Register scratch = temps.Acquire();
            asm_->lay(sp, MemOperand(sp, -kSimd128Size));
            asm_->StoreV128(src.reg().fp(), MemOperand(sp), scratch);
            break;
          }
          default:
            UNREACHABLE();
        }
        break;
      }
      case LiftoffAssembler::VarState::kIntConst: {
        asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
        DCHECK(src.kind() == kI32 || src.kind() == kI64);
        UseScratchRegisterScope temps(asm_);
        Register scratch = temps.Acquire();

        switch (src.kind()) {
          case kI32:
            asm_->mov(scratch, Operand(src.i32_const()));
            break;
          case kI64:
            asm_->mov(scratch, Operand(int64_t{slot.src_.i32_const()}));
            break;
          default:
            UNREACHABLE();
        }
        asm_->push(scratch);
        break;
      }
    }
  }
}

}  // namespace v8::internal::wasm

#undef BAILOUT

#endif  // V8_WASM_BASELINE_S390_LIFTOFF_ASSEMBLER_S390_INL_H_

"""


```