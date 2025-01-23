Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/s390/macro-assembler-s390.cc`. I need to break down the code and identify its purpose.

Here's a plan:
1. **Overall Functionality:** Determine the main goal of this code. It seems to be about low-level operations, likely related to memory access and manipulation on the s390 architecture.
2. **Individual Functions:**  Analyze each function to understand what it does. Pay attention to the instructions being used (e.g., `lrv`, `strvg`, `ldgr`). These likely correspond to specific s390 assembly instructions.
3. **LE Suffix:**  Note the functions with the "LE" suffix (e.g., `LoadU32LE`). This likely indicates Little-Endian byte order handling.
4. **Relationship to JavaScript:** Consider how these low-level operations might be used in the context of a JavaScript engine. This could involve memory management, data representation, or handling different data types.
5. **Example with JavaScript:** If there's a clear connection to JavaScript, create a simple JavaScript example to illustrate the concept.
6. **Code Logic Inference:** Look for functions where the output depends on the input in a non-trivial way (beyond just direct memory access). Provide hypothetical inputs and outputs.
7. **Common Programming Errors:** Think about common mistakes programmers might make when dealing with memory access, byte ordering, or low-level operations, and relate them to the functions in the code.
8. **Summarize Functionality:** Provide a concise summary of the code's purpose.

**Constraint Checklist & Confidence Score:**
1. 列举一下它的功能: Yes
2. 如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码: Yes
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第5部分，共8部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I am confident I can address all the user's requirements.

**Mental Sandbox Simulation:**
- I've identified several functions related to loading and storing data in little-endian format. This is a key aspect of the code.
- The `MacroAssembler` class suggests this code is part of the code generation process for the s390 architecture in V8.
- I need to be careful to differentiate between little-endian and big-endian operations, as indicated by the `#ifdef V8_TARGET_LITTLE_ENDIAN` blocks.
- For the JavaScript example, I'll focus on scenarios where byte order matters, such as typed arrays or data views.
- For code logic inference, the bit manipulation functions (e.g., `ShiftLeftU32`, `ClearRightImm`) are good candidates.
- Common errors could involve incorrect memory offsets, wrong data types, or misunderstanding byte order.

Strategizing complete. I will now generate the response based on the above plan.
```cpp
oadS32(dst, dst);
}

void MacroAssembler::LoadU32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(dst, opnd);
  LoadU32(dst, dst);
}

void MacroAssembler::LoadU16LE(Register dst, const MemOperand& opnd) {
  lrvh(dst, opnd);
  LoadU16(dst, dst);
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& opnd) {
  lrvh(dst, opnd);
  LoadS16(dst, dst);
}

void MacroAssembler::LoadV128LE(DoubleRegister dst, const MemOperand& opnd,
                                Register scratch0, Register scratch1) {
  bool use_vlbr = CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
                  is_uint12(opnd.offset());
  if (use_vlbr) {
    vlbr(dst, opnd, Condition(4));
  } else {
    lrvg(scratch0, opnd);
    lrvg(scratch1,
         MemOperand(opnd.rx(), opnd.rb(), opnd.offset() + kSystemPointerSize));
    vlvgp(dst, scratch1, scratch0);
  }
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  lrvg(scratch, opnd);
  ldgr(dst, scratch);
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(scratch, opnd);
  ShiftLeftU64(scratch, scratch, Operand(32));
  ldgr(dst, scratch);
}

void MacroAssembler::StoreU64LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strvg(src, MemOperand(mem.rb(), scratch));
  } else {
    strvg(src, mem);
  }
}

void MacroAssembler::StoreU32LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strv(src, MemOperand(mem.rb(), scratch));
  } else {
    strv(src, mem);
  }
}

void MacroAssembler::StoreU16LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strvh(src, MemOperand(mem.rb(), scratch));
  } else {
    strvh(src, mem);
  }
}

void MacroAssembler::StoreF64LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  DCHECK(is_uint12(opnd.offset()));
  lgdr(scratch, src);
  strvg(scratch, opnd);
}

void MacroAssembler::StoreF32LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  DCHECK(is_uint12(opnd.offset()));
  lgdr(scratch, src);
  ShiftRightU64(scratch, scratch, Operand(32));
  strv(scratch, opnd);
}

void MacroAssembler::StoreV128LE(Simd128Register src, const MemOperand& mem,
                                 Register scratch1, Register scratch2) {
  bool use_vstbr = CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
                   is_uint12(mem.offset());
  if (use_vstbr) {
    vstbr(src, mem, Condition(4));
  } else {
    vlgv(scratch1, src, MemOperand(r0, 1), Condition(3));
    vlgv(scratch2, src, MemOperand(r0, 0), Condition(3));
    strvg(scratch1, mem);
    strvg(scratch2,
          MemOperand(mem.rx(), mem.rb(), mem.offset() + kSystemPointerSize));
  }
}

#else
void MacroAssembler::LoadU64LE(Register dst, const MemOperand& mem,
                               Register scratch) {
  LoadU64(dst, mem, scratch);
}

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  LoadS32(dst, opnd, scratch);
}

void MacroAssembler::LoadU32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  LoadU32(dst, opnd, scratch);
}

void MacroAssembler::LoadU16LE(Register dst, const MemOperand& opnd) {
  LoadU16(dst, opnd);
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& opnd) {
  LoadS16(dst, opnd);
}

void MacroAssembler::LoadV128LE(DoubleRegister dst, const MemOperand& opnd,
                                Register scratch0, Register scratch1) {
  USE(scratch1);
  LoadV128(dst, opnd, scratch0);
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  USE(scratch);
  LoadF64(dst, opnd);
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  USE(scratch);
  LoadF32(dst, opnd);
}

void MacroAssembler::StoreU64LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU64(src, mem, scratch);
}

void MacroAssembler::StoreU32LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU32(src, mem, scratch);
}

void MacroAssembler::StoreU16LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU16(src, mem, scratch);
}

void MacroAssembler::StoreF64LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  StoreF64(src, opnd);
}

void MacroAssembler::StoreF32LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  StoreF32(src, opnd);
}

void MacroAssembler::StoreV128LE(Simd128Register src, const MemOperand& mem,
                                 Register scratch1, Register scratch2) {
  StoreV128(src, mem, scratch1);
}

#endif

// Load And Test (Reg <- Reg)
void MacroAssembler::LoadAndTest32(Register dst, Register src) {
  ltr(dst, src);
}

// Load And Test Pointer Sized (Reg <- Reg)
void MacroAssembler::LoadAndTestP(Register dst, Register src) {
  ltgr(dst, src);
}

// Load And Test 32-bit (Reg <- Mem)
void MacroAssembler::LoadAndTest32(Register dst, const MemOperand& mem) {
  lt_z(dst, mem);
}

// Load And Test Pointer Sized (Reg <- Mem)
void MacroAssembler::LoadAndTestP(Register dst, const MemOperand& mem) {
  ltg(dst, mem);
}

// Load On Condition Pointer Sized (Reg <- Reg)
void MacroAssembler::LoadOnConditionP(Condition cond, Register dst,
                                      Register src) {
  locgr(cond, dst, src);
}

// Load Double Precision (64-bit) Floating Point number from memory
void MacroAssembler::LoadF64(DoubleRegister dst, const MemOperand& mem) {
  // for 32bit and 64bit we all use 64bit floating point regs
  if (is_uint12(mem.offset())) {
    ld(dst, mem);
  } else {
    ldy(dst, mem);
  }
}

// Load Single Precision (32-bit) Floating Point number from memory
void MacroAssembler::LoadF32(DoubleRegister dst, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    le_z(dst, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    ley(dst, mem);
  }
}

void MacroAssembler::LoadV128(Simd128Register dst, const MemOperand& mem,
                              Register scratch) {
  DCHECK(scratch != r0);
  if (is_uint12(mem.offset())) {
    vl(dst, mem, Condition(0));
  } else {
    DCHECK(is_int20(mem.offset()));
    lay(scratch, mem);
    vl(dst, MemOperand(scratch), Condition(0));
  }
}

// Store Double Precision (64-bit) Floating Point number to memory
void MacroAssembler::StoreF64(DoubleRegister dst, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    std(dst, mem);
  } else {
    stdy(dst, mem);
  }
}

// Store Single Precision (32-bit) Floating Point number to memory
void MacroAssembler::StoreF32(DoubleRegister src, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    ste(src, mem);
  } else {
    stey(src, mem);
  }
}

void MacroAssembler::StoreV128(Simd128Register src, const MemOperand& mem,
                               Register scratch) {
  DCHECK(scratch != r0);
  if (is_uint12(mem.offset())) {
    vst(src, mem, Condition(0));
  } else {
    DCHECK(is_int20(mem.offset()));
    lay(scratch, mem);
    vst(src, MemOperand(scratch), Condition(0));
  }
}

void MacroAssembler::AddF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    aebr(dst, rhs);
  } else if (dst == rhs) {
    aebr(dst, lhs);
  } else {
    ler(dst, lhs);
    aebr(dst, rhs);
  }
}

void MacroAssembler::SubF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    sebr(dst, rhs);
  } else if (dst == rhs) {
    sebr(dst, lhs);
    lcebr(dst, dst);
  } else {
    ler(dst, lhs);
    sebr(dst, rhs);
  }
}

void MacroAssembler::MulF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    meebr(dst, rhs);
  } else if (dst == rhs) {
    meebr(dst, lhs);
  } else {
    ler(dst, lhs);
    meebr(dst, rhs);
  }
}

void MacroAssembler::DivF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    debr(dst, rhs);
  } else if (dst == rhs) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF32(dst, MemOperand(sp));
    ler(dst, lhs);
    deb(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  } else {
    ler(dst, lhs);
    debr(dst, rhs);
  }
}

void MacroAssembler::AddF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    adbr(dst, rhs);
  } else if (dst == rhs) {
    adbr(dst, lhs);
  } else {
    ldr(dst, lhs);
    adbr(dst, rhs);
  }
}

void MacroAssembler::SubF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    sdbr(dst, rhs);
  } else if (dst == rhs) {
    sdbr(dst, lhs);
    lcdbr(dst, dst);
  } else {
    ldr(dst, lhs);
    sdbr(dst, rhs);
  }
}

void MacroAssembler::MulF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    mdbr(dst, rhs);
  } else if (dst == rhs) {
    mdbr(dst, lhs);
  } else {
    ldr(dst, lhs);
    mdbr(dst, rhs);
  }
}

void MacroAssembler::DivF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    ddbr(dst, rhs);
  } else if (dst == rhs) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF64(dst, MemOperand(sp));
    ldr(dst, lhs);
    ddb(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  } else {
    ldr(dst, lhs);
    ddbr(dst, rhs);
  }
}

void MacroAssembler::AddFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    aeb(dst, opnd);
  } else {
    ley(scratch, opnd);
    aebr(dst, scratch);
  }
}

void MacroAssembler::AddFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    adb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    adbr(dst, scratch);
  }
}

void MacroAssembler::SubFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    seb(dst, opnd);
  } else {
    ley(scratch, opnd);
    sebr(dst, scratch);
  }
}

void MacroAssembler::SubFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    sdb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    sdbr(dst, scratch);
  }
}

void MacroAssembler::MulFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    meeb(dst, opnd);
  } else {
    ley(scratch, opnd);
    meebr(dst, scratch);
  }
}

void MacroAssembler::MulFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    mdb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    mdbr(dst, scratch);
  }
}

void MacroAssembler::DivFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    deb(dst, opnd);
  } else {
    ley(scratch, opnd);
    debr(dst, scratch);
  }
}

void MacroAssembler::DivFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    ddb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    ddbr(dst, scratch);
  }
}

void MacroAssembler::LoadF32AsF64(DoubleRegister dst, const MemOperand& opnd) {
  if (is_uint12(opnd.offset())) {
    ldeb(dst, opnd);
  } else {
    ley(dst, opnd);
    ldebr(dst, dst);
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand of RX or RXY format
void MacroAssembler::StoreU32(Register src, const MemOperand& mem,
                              Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  bool use_RXform = false;
  bool use_RXYform = false;

  if (is_uint12(offset)) {
    // RX-format supports unsigned 12-bits offset.
    use_RXform = true;
  } else if (is_int20(offset)) {
    // RXY-format supports signed 20-bits offset.
    use_RXYform = true;
  } else if (scratch != no_reg) {
    // Materialize offset into scratch register.
    mov(scratch, Operand(offset));
  } else {
    // scratch is no_reg
    DCHECK(false);
  }

  if (use_RXform) {
    st(src, mem);
  } else if (use_RXYform) {
    sty(src, mem);
  } else {
    StoreU32(src, MemOperand(base, scratch));
  }
}

void MacroAssembler::LoadS16(Register dst, Register src) {
  lghr(dst, src);
}

// Loads 16-bits half-word value from memory and sign extends to pointer
// sized register
void MacroAssembler::LoadS16(Register dst, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    lgh(dst, MemOperand(base, scratch));
  } else {
    lgh(dst, mem);
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand current only supports d-form
void MacroAssembler::StoreU16(Register src, const MemOperand& mem,
                              Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_uint12(offset)) {
    sth(src, mem);
  } else if (is_int20(offset)) {
    sthy(src, mem);
  } else {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    sth(src, MemOperand(base, scratch));
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand current only supports d-form
void MacroAssembler::StoreU8(Register src, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_uint12(offset)) {
    stc(src, mem);
  } else if (is_int20(offset)) {
    stcy(src, mem);
  } else {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    stc(src, MemOperand(base, scratch));
  }
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU32(Register dst, Register src,
                                  const Operand& val) {
  ShiftLeftU32(dst, src, r0, val);
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU32(Register dst, Register src, Register val,
                                  const Operand& val2) {
  if (dst == src) {
    sll(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    sllk(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/sll path clobbers val.
    lr(dst, src);
    sll(dst, val, val2);
  }
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU64(Register dst, Register src,
                                  const Operand& val) {
  ShiftLeftU64(dst, src, r0, val);
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU64(Register dst, Register src, Register val,
                                  const Operand& val2) {
  sllg(dst, src, val, val2);
}

// Shift right logical for 32-bit integer types.
void MacroAssembler::ShiftRightU32(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightU32(dst, src, r0, val);
}

// Shift right logical for 32-bit integer types.
void MacroAssembler::ShiftRightU32(Register dst, Register src, Register val,
                                   const Operand& val2) {
  if (dst == src) {
    srl(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srlk(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/srl path clobbers val.
    lr(dst, src);
    srl(dst, val, val2);
  }
}

void MacroAssembler::ShiftRightU64(Register dst, Register src, Register val,
                                   const Operand& val2) {
  srlg(dst, src, val, val2);
}

// Shift right logical for 64-bit integer types.
void MacroAssembler::ShiftRightU64(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightU64(dst, src, r0, val);
}

// Shift right arithmetic for 32-bit integer types.
void MacroAssembler::ShiftRightS32(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightS32(dst, src, r0, val);
}

// Shift right arithmetic for 32-bit integer types.
void MacroAssembler::ShiftRightS32(Register dst, Register src, Register val,
                                   const Operand& val2) {
  if (dst == src) {
    sra(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srak(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/sra path clobbers val.
    lr(dst, src);
    sra(dst, val, val2);
  }
}

// Shift right arithmetic for 64-bit integer types.
void MacroAssembler::ShiftRightS64(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightS64(dst, src, r0, val);
}

// Shift right arithmetic for 64-bit integer types.
void MacroAssembler::ShiftRightS64(Register dst, Register src, Register val,
                                   const Operand& val2) {
  srag(dst, src, val, val2);
}

// Clear right most # of bits
void MacroAssembler::ClearRightImm(Register dst, Register src,
                                   const Operand& val) {
  int numBitsToClear = val.immediate() % (kSystemPointerSize * 8);

  // Try to use RISBG if possible
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
    int endBit = 63 - numBitsToClear;
    RotateInsertSelectBits(dst, src, Operand::Zero(), Operand(endBit),
                           Operand::Zero(), true);
    return;
  }

  uint64_t hexMask = ~((1L << numBitsToClear) - 1);

  // S390 AND instr clobbers source. Make a copy if necessary
  if (dst != src) mov(dst, src);

  if (numBitsToClear <= 16) {
    nill(dst, Operand(static_cast<uint16_t>(hexMask)));
  } else if (numBitsToClear <= 32) {
    nilf(dst, Operand(static_cast<uint32_t>(hexMask)));
  } else if (numBitsToClear <= 64) {
    nilf(dst, Operand(static_cast<intptr_t>(0)));
    nihf(dst, Operand(hexMask >> 32));
  }
}

void MacroAssembler::Popcnt32(Register dst, Register src) {
  DCHECK(src != r0);
  DCHECK(dst != r0);

  popcnt(dst, src);
  ShiftRightU32(r0, dst, Operand(16));
  ar(dst, r0);
  ShiftRightU32(r0, dst, Operand(8));
  ar(dst, r0);
  llgcr(dst, dst);
}

void MacroAssembler::Popcnt64(Register dst, Register src) {
  DCHECK(src != r0);
  DCHECK(dst != r0);

  popcnt(dst, src);
  ShiftRightU64(r0, dst, Operand(32));
  AddS64(dst, r0);
  ShiftRightU64(r0, dst, Operand(16));
  AddS64(dst, r0);
  ShiftRightU64(r0, dst, Operand(8));
  AddS64(dst, r0);
  LoadU8(dst, dst);
}

void MacroAssembler::SwapP(Register src, Register dst, Register scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  mov(scratch, src);
  mov(src, dst);
  mov(dst, scratch);
}

void MacroAssembler::SwapP(Register src, MemOperand dst, Register scratch) {
  if (dst.rx() != r0) DCHECK(!AreAliased(src, dst.rx(), scratch));
  if (dst.rb() != r0) DCHECK(!AreAliased(src, dst.rb(), scratch));
  DCHECK(!AreAliased(src, scratch));
  mov(scratch, src);
  LoadU64(src, dst);
  StoreU64(scratch, dst);
}

void MacroAssembler::SwapP(MemOperand src, MemOperand dst, Register scratch_0,
                           Register scratch_1) {
  if (src.rx() != r0) DCHECK(!AreAliased(src.rx(), scratch_0, scratch_1));
  if (src.rb() != r0) DCHECK(!AreAliased(src.rb(), scratch_0, scratch_1));
  if (dst.rx() != r0) DCHECK(!AreAliased(dst.rx(), scratch_0, scratch_1));
  if (dst.rb() != r0) DCHECK(!AreAliased(dst.rb(), scratch_0, scratch_1));
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadU64(scratch_0, src);
  LoadU64(scratch_1, dst);
  StoreU64(scratch_0, dst);
  StoreU64(scratch_1, src);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, DoubleRegister dst,
                                 DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  ldr(scratch, src);
  ldr(src, dst);
  ldr(dst, scratch);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, MemOperand dst,
                                 DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  ldr(scratch, src);
  LoadF32(src, dst);
  StoreF32(scratch, dst);
}

void MacroAssembler::SwapFloat32(MemOperand src, MemOperand dst,
                                 DoubleRegister scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(d0, MemOperand(sp));
  LoadF32(scratch, src);
  LoadF32(d0, dst);
  StoreF32(scratch, dst);
  StoreF32(d0, src);
  // restore d0
  LoadF64(d0, MemOperand(sp));
  lay(sp, MemOperand(sp, kDoubleSize));
}

void MacroAssembler::SwapDouble(DoubleRegister src, DoubleRegister dst,
                                DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  ldr(scratch, src);
  ldr(src, dst);
  ldr(dst, scratch);
}

void MacroAssembler::SwapDouble(DoubleRegister src, MemOperand dst,
                                DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  ldr(scratch, src);
  LoadF64(src, dst);
  StoreF64(scratch, dst);
}

void MacroAssembler::SwapDouble(MemOperand src, MemOperand dst,
                                DoubleRegister scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(d0, MemOperand(sp));
  LoadF64(scratch, src);
  LoadF64(d0,
### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
oadS32(dst, dst);
}

void MacroAssembler::LoadU32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(dst, opnd);
  LoadU32(dst, dst);
}

void MacroAssembler::LoadU16LE(Register dst, const MemOperand& opnd) {
  lrvh(dst, opnd);
  LoadU16(dst, dst);
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& opnd) {
  lrvh(dst, opnd);
  LoadS16(dst, dst);
}

void MacroAssembler::LoadV128LE(DoubleRegister dst, const MemOperand& opnd,
                                Register scratch0, Register scratch1) {
  bool use_vlbr = CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
                  is_uint12(opnd.offset());
  if (use_vlbr) {
    vlbr(dst, opnd, Condition(4));
  } else {
    lrvg(scratch0, opnd);
    lrvg(scratch1,
         MemOperand(opnd.rx(), opnd.rb(), opnd.offset() + kSystemPointerSize));
    vlvgp(dst, scratch1, scratch0);
  }
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  lrvg(scratch, opnd);
  ldgr(dst, scratch);
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  lrv(scratch, opnd);
  ShiftLeftU64(scratch, scratch, Operand(32));
  ldgr(dst, scratch);
}

void MacroAssembler::StoreU64LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strvg(src, MemOperand(mem.rb(), scratch));
  } else {
    strvg(src, mem);
  }
}

void MacroAssembler::StoreU32LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strv(src, MemOperand(mem.rb(), scratch));
  } else {
    strv(src, mem);
  }
}

void MacroAssembler::StoreU16LE(Register src, const MemOperand& mem,
                                Register scratch) {
  if (!is_int20(mem.offset())) {
    DCHECK(scratch != no_reg);
    DCHECK(scratch != r0);
    mov(scratch, Operand(mem.offset()));
    strvh(src, MemOperand(mem.rb(), scratch));
  } else {
    strvh(src, mem);
  }
}

void MacroAssembler::StoreF64LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  DCHECK(is_uint12(opnd.offset()));
  lgdr(scratch, src);
  strvg(scratch, opnd);
}

void MacroAssembler::StoreF32LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  DCHECK(is_uint12(opnd.offset()));
  lgdr(scratch, src);
  ShiftRightU64(scratch, scratch, Operand(32));
  strv(scratch, opnd);
}

void MacroAssembler::StoreV128LE(Simd128Register src, const MemOperand& mem,
                                 Register scratch1, Register scratch2) {
  bool use_vstbr = CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2) &&
                   is_uint12(mem.offset());
  if (use_vstbr) {
    vstbr(src, mem, Condition(4));
  } else {
    vlgv(scratch1, src, MemOperand(r0, 1), Condition(3));
    vlgv(scratch2, src, MemOperand(r0, 0), Condition(3));
    strvg(scratch1, mem);
    strvg(scratch2,
          MemOperand(mem.rx(), mem.rb(), mem.offset() + kSystemPointerSize));
  }
}

#else
void MacroAssembler::LoadU64LE(Register dst, const MemOperand& mem,
                               Register scratch) {
  LoadU64(dst, mem, scratch);
}

void MacroAssembler::LoadS32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  LoadS32(dst, opnd, scratch);
}

void MacroAssembler::LoadU32LE(Register dst, const MemOperand& opnd,
                               Register scratch) {
  LoadU32(dst, opnd, scratch);
}

void MacroAssembler::LoadU16LE(Register dst, const MemOperand& opnd) {
  LoadU16(dst, opnd);
}

void MacroAssembler::LoadS16LE(Register dst, const MemOperand& opnd) {
  LoadS16(dst, opnd);
}

void MacroAssembler::LoadV128LE(DoubleRegister dst, const MemOperand& opnd,
                                Register scratch0, Register scratch1) {
  USE(scratch1);
  LoadV128(dst, opnd, scratch0);
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  USE(scratch);
  LoadF64(dst, opnd);
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& opnd,
                               Register scratch) {
  USE(scratch);
  LoadF32(dst, opnd);
}

void MacroAssembler::StoreU64LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU64(src, mem, scratch);
}

void MacroAssembler::StoreU32LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU32(src, mem, scratch);
}

void MacroAssembler::StoreU16LE(Register src, const MemOperand& mem,
                                Register scratch) {
  StoreU16(src, mem, scratch);
}

void MacroAssembler::StoreF64LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  StoreF64(src, opnd);
}

void MacroAssembler::StoreF32LE(DoubleRegister src, const MemOperand& opnd,
                                Register scratch) {
  StoreF32(src, opnd);
}

void MacroAssembler::StoreV128LE(Simd128Register src, const MemOperand& mem,
                                 Register scratch1, Register scratch2) {
  StoreV128(src, mem, scratch1);
}

#endif

// Load And Test (Reg <- Reg)
void MacroAssembler::LoadAndTest32(Register dst, Register src) {
  ltr(dst, src);
}

// Load And Test Pointer Sized (Reg <- Reg)
void MacroAssembler::LoadAndTestP(Register dst, Register src) {
  ltgr(dst, src);
}

// Load And Test 32-bit (Reg <- Mem)
void MacroAssembler::LoadAndTest32(Register dst, const MemOperand& mem) {
  lt_z(dst, mem);
}

// Load And Test Pointer Sized (Reg <- Mem)
void MacroAssembler::LoadAndTestP(Register dst, const MemOperand& mem) {
  ltg(dst, mem);
}

// Load On Condition Pointer Sized (Reg <- Reg)
void MacroAssembler::LoadOnConditionP(Condition cond, Register dst,
                                      Register src) {
  locgr(cond, dst, src);
}

// Load Double Precision (64-bit) Floating Point number from memory
void MacroAssembler::LoadF64(DoubleRegister dst, const MemOperand& mem) {
  // for 32bit and 64bit we all use 64bit floating point regs
  if (is_uint12(mem.offset())) {
    ld(dst, mem);
  } else {
    ldy(dst, mem);
  }
}

// Load Single Precision (32-bit) Floating Point number from memory
void MacroAssembler::LoadF32(DoubleRegister dst, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    le_z(dst, mem);
  } else {
    DCHECK(is_int20(mem.offset()));
    ley(dst, mem);
  }
}

void MacroAssembler::LoadV128(Simd128Register dst, const MemOperand& mem,
                              Register scratch) {
  DCHECK(scratch != r0);
  if (is_uint12(mem.offset())) {
    vl(dst, mem, Condition(0));
  } else {
    DCHECK(is_int20(mem.offset()));
    lay(scratch, mem);
    vl(dst, MemOperand(scratch), Condition(0));
  }
}

// Store Double Precision (64-bit) Floating Point number to memory
void MacroAssembler::StoreF64(DoubleRegister dst, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    std(dst, mem);
  } else {
    stdy(dst, mem);
  }
}

// Store Single Precision (32-bit) Floating Point number to memory
void MacroAssembler::StoreF32(DoubleRegister src, const MemOperand& mem) {
  if (is_uint12(mem.offset())) {
    ste(src, mem);
  } else {
    stey(src, mem);
  }
}

void MacroAssembler::StoreV128(Simd128Register src, const MemOperand& mem,
                               Register scratch) {
  DCHECK(scratch != r0);
  if (is_uint12(mem.offset())) {
    vst(src, mem, Condition(0));
  } else {
    DCHECK(is_int20(mem.offset()));
    lay(scratch, mem);
    vst(src, MemOperand(scratch), Condition(0));
  }
}

void MacroAssembler::AddF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    aebr(dst, rhs);
  } else if (dst == rhs) {
    aebr(dst, lhs);
  } else {
    ler(dst, lhs);
    aebr(dst, rhs);
  }
}

void MacroAssembler::SubF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    sebr(dst, rhs);
  } else if (dst == rhs) {
    sebr(dst, lhs);
    lcebr(dst, dst);
  } else {
    ler(dst, lhs);
    sebr(dst, rhs);
  }
}

void MacroAssembler::MulF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    meebr(dst, rhs);
  } else if (dst == rhs) {
    meebr(dst, lhs);
  } else {
    ler(dst, lhs);
    meebr(dst, rhs);
  }
}

void MacroAssembler::DivF32(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    debr(dst, rhs);
  } else if (dst == rhs) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF32(dst, MemOperand(sp));
    ler(dst, lhs);
    deb(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  } else {
    ler(dst, lhs);
    debr(dst, rhs);
  }
}

void MacroAssembler::AddF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    adbr(dst, rhs);
  } else if (dst == rhs) {
    adbr(dst, lhs);
  } else {
    ldr(dst, lhs);
    adbr(dst, rhs);
  }
}

void MacroAssembler::SubF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    sdbr(dst, rhs);
  } else if (dst == rhs) {
    sdbr(dst, lhs);
    lcdbr(dst, dst);
  } else {
    ldr(dst, lhs);
    sdbr(dst, rhs);
  }
}

void MacroAssembler::MulF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    mdbr(dst, rhs);
  } else if (dst == rhs) {
    mdbr(dst, lhs);
  } else {
    ldr(dst, lhs);
    mdbr(dst, rhs);
  }
}

void MacroAssembler::DivF64(DoubleRegister dst, DoubleRegister lhs,
                            DoubleRegister rhs) {
  if (dst == lhs) {
    ddbr(dst, rhs);
  } else if (dst == rhs) {
    lay(sp, MemOperand(sp, -kSystemPointerSize));
    StoreF64(dst, MemOperand(sp));
    ldr(dst, lhs);
    ddb(dst, MemOperand(sp));
    la(sp, MemOperand(sp, kSystemPointerSize));
  } else {
    ldr(dst, lhs);
    ddbr(dst, rhs);
  }
}

void MacroAssembler::AddFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    aeb(dst, opnd);
  } else {
    ley(scratch, opnd);
    aebr(dst, scratch);
  }
}

void MacroAssembler::AddFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    adb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    adbr(dst, scratch);
  }
}

void MacroAssembler::SubFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    seb(dst, opnd);
  } else {
    ley(scratch, opnd);
    sebr(dst, scratch);
  }
}

void MacroAssembler::SubFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    sdb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    sdbr(dst, scratch);
  }
}

void MacroAssembler::MulFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    meeb(dst, opnd);
  } else {
    ley(scratch, opnd);
    meebr(dst, scratch);
  }
}

void MacroAssembler::MulFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    mdb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    mdbr(dst, scratch);
  }
}

void MacroAssembler::DivFloat32(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    deb(dst, opnd);
  } else {
    ley(scratch, opnd);
    debr(dst, scratch);
  }
}

void MacroAssembler::DivFloat64(DoubleRegister dst, const MemOperand& opnd,
                                DoubleRegister scratch) {
  if (is_uint12(opnd.offset())) {
    ddb(dst, opnd);
  } else {
    ldy(scratch, opnd);
    ddbr(dst, scratch);
  }
}

void MacroAssembler::LoadF32AsF64(DoubleRegister dst, const MemOperand& opnd) {
  if (is_uint12(opnd.offset())) {
    ldeb(dst, opnd);
  } else {
    ley(dst, opnd);
    ldebr(dst, dst);
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand of RX or RXY format
void MacroAssembler::StoreU32(Register src, const MemOperand& mem,
                              Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  bool use_RXform = false;
  bool use_RXYform = false;

  if (is_uint12(offset)) {
    // RX-format supports unsigned 12-bits offset.
    use_RXform = true;
  } else if (is_int20(offset)) {
    // RXY-format supports signed 20-bits offset.
    use_RXYform = true;
  } else if (scratch != no_reg) {
    // Materialize offset into scratch register.
    mov(scratch, Operand(offset));
  } else {
    // scratch is no_reg
    DCHECK(false);
  }

  if (use_RXform) {
    st(src, mem);
  } else if (use_RXYform) {
    sty(src, mem);
  } else {
    StoreU32(src, MemOperand(base, scratch));
  }
}

void MacroAssembler::LoadS16(Register dst, Register src) {
  lghr(dst, src);
}

// Loads 16-bits half-word value from memory and sign extends to pointer
// sized register
void MacroAssembler::LoadS16(Register dst, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (!is_int20(offset)) {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    lgh(dst, MemOperand(base, scratch));
  } else {
    lgh(dst, mem);
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand current only supports d-form
void MacroAssembler::StoreU16(Register src, const MemOperand& mem,
                              Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_uint12(offset)) {
    sth(src, mem);
  } else if (is_int20(offset)) {
    sthy(src, mem);
  } else {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    sth(src, MemOperand(base, scratch));
  }
}

// Variable length depending on whether offset fits into immediate field
// MemOperand current only supports d-form
void MacroAssembler::StoreU8(Register src, const MemOperand& mem,
                             Register scratch) {
  Register base = mem.rb();
  int offset = mem.offset();

  if (is_uint12(offset)) {
    stc(src, mem);
  } else if (is_int20(offset)) {
    stcy(src, mem);
  } else {
    DCHECK(scratch != no_reg);
    mov(scratch, Operand(offset));
    stc(src, MemOperand(base, scratch));
  }
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU32(Register dst, Register src,
                                  const Operand& val) {
  ShiftLeftU32(dst, src, r0, val);
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU32(Register dst, Register src, Register val,
                                  const Operand& val2) {
  if (dst == src) {
    sll(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    sllk(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/sll path clobbers val.
    lr(dst, src);
    sll(dst, val, val2);
  }
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU64(Register dst, Register src,
                                  const Operand& val) {
  ShiftLeftU64(dst, src, r0, val);
}

// Shift left logical for 32-bit integer types.
void MacroAssembler::ShiftLeftU64(Register dst, Register src, Register val,
                                  const Operand& val2) {
  sllg(dst, src, val, val2);
}

// Shift right logical for 32-bit integer types.
void MacroAssembler::ShiftRightU32(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightU32(dst, src, r0, val);
}

// Shift right logical for 32-bit integer types.
void MacroAssembler::ShiftRightU32(Register dst, Register src, Register val,
                                   const Operand& val2) {
  if (dst == src) {
    srl(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srlk(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/srl path clobbers val.
    lr(dst, src);
    srl(dst, val, val2);
  }
}

void MacroAssembler::ShiftRightU64(Register dst, Register src, Register val,
                                   const Operand& val2) {
  srlg(dst, src, val, val2);
}

// Shift right logical for 64-bit integer types.
void MacroAssembler::ShiftRightU64(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightU64(dst, src, r0, val);
}

// Shift right arithmetic for 32-bit integer types.
void MacroAssembler::ShiftRightS32(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightS32(dst, src, r0, val);
}

// Shift right arithmetic for 32-bit integer types.
void MacroAssembler::ShiftRightS32(Register dst, Register src, Register val,
                                   const Operand& val2) {
  if (dst == src) {
    sra(dst, val, val2);
  } else if (CpuFeatures::IsSupported(DISTINCT_OPS)) {
    srak(dst, src, val, val2);
  } else {
    DCHECK(dst != val || val == r0);  // The lr/sra path clobbers val.
    lr(dst, src);
    sra(dst, val, val2);
  }
}

// Shift right arithmetic for 64-bit integer types.
void MacroAssembler::ShiftRightS64(Register dst, Register src,
                                   const Operand& val) {
  ShiftRightS64(dst, src, r0, val);
}

// Shift right arithmetic for 64-bit integer types.
void MacroAssembler::ShiftRightS64(Register dst, Register src, Register val,
                                   const Operand& val2) {
  srag(dst, src, val, val2);
}

// Clear right most # of bits
void MacroAssembler::ClearRightImm(Register dst, Register src,
                                   const Operand& val) {
  int numBitsToClear = val.immediate() % (kSystemPointerSize * 8);

  // Try to use RISBG if possible
  if (CpuFeatures::IsSupported(GENERAL_INSTR_EXT)) {
    int endBit = 63 - numBitsToClear;
    RotateInsertSelectBits(dst, src, Operand::Zero(), Operand(endBit),
                           Operand::Zero(), true);
    return;
  }

  uint64_t hexMask = ~((1L << numBitsToClear) - 1);

  // S390 AND instr clobbers source.  Make a copy if necessary
  if (dst != src) mov(dst, src);

  if (numBitsToClear <= 16) {
    nill(dst, Operand(static_cast<uint16_t>(hexMask)));
  } else if (numBitsToClear <= 32) {
    nilf(dst, Operand(static_cast<uint32_t>(hexMask)));
  } else if (numBitsToClear <= 64) {
    nilf(dst, Operand(static_cast<intptr_t>(0)));
    nihf(dst, Operand(hexMask >> 32));
  }
}

void MacroAssembler::Popcnt32(Register dst, Register src) {
  DCHECK(src != r0);
  DCHECK(dst != r0);

  popcnt(dst, src);
  ShiftRightU32(r0, dst, Operand(16));
  ar(dst, r0);
  ShiftRightU32(r0, dst, Operand(8));
  ar(dst, r0);
  llgcr(dst, dst);
}

void MacroAssembler::Popcnt64(Register dst, Register src) {
  DCHECK(src != r0);
  DCHECK(dst != r0);

  popcnt(dst, src);
  ShiftRightU64(r0, dst, Operand(32));
  AddS64(dst, r0);
  ShiftRightU64(r0, dst, Operand(16));
  AddS64(dst, r0);
  ShiftRightU64(r0, dst, Operand(8));
  AddS64(dst, r0);
  LoadU8(dst, dst);
}

void MacroAssembler::SwapP(Register src, Register dst, Register scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  mov(scratch, src);
  mov(src, dst);
  mov(dst, scratch);
}

void MacroAssembler::SwapP(Register src, MemOperand dst, Register scratch) {
  if (dst.rx() != r0) DCHECK(!AreAliased(src, dst.rx(), scratch));
  if (dst.rb() != r0) DCHECK(!AreAliased(src, dst.rb(), scratch));
  DCHECK(!AreAliased(src, scratch));
  mov(scratch, src);
  LoadU64(src, dst);
  StoreU64(scratch, dst);
}

void MacroAssembler::SwapP(MemOperand src, MemOperand dst, Register scratch_0,
                           Register scratch_1) {
  if (src.rx() != r0) DCHECK(!AreAliased(src.rx(), scratch_0, scratch_1));
  if (src.rb() != r0) DCHECK(!AreAliased(src.rb(), scratch_0, scratch_1));
  if (dst.rx() != r0) DCHECK(!AreAliased(dst.rx(), scratch_0, scratch_1));
  if (dst.rb() != r0) DCHECK(!AreAliased(dst.rb(), scratch_0, scratch_1));
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadU64(scratch_0, src);
  LoadU64(scratch_1, dst);
  StoreU64(scratch_0, dst);
  StoreU64(scratch_1, src);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, DoubleRegister dst,
                                 DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  ldr(scratch, src);
  ldr(src, dst);
  ldr(dst, scratch);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, MemOperand dst,
                                 DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  ldr(scratch, src);
  LoadF32(src, dst);
  StoreF32(scratch, dst);
}

void MacroAssembler::SwapFloat32(MemOperand src, MemOperand dst,
                                 DoubleRegister scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(d0, MemOperand(sp));
  LoadF32(scratch, src);
  LoadF32(d0, dst);
  StoreF32(scratch, dst);
  StoreF32(d0, src);
  // restore d0
  LoadF64(d0, MemOperand(sp));
  lay(sp, MemOperand(sp, kDoubleSize));
}

void MacroAssembler::SwapDouble(DoubleRegister src, DoubleRegister dst,
                                DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  ldr(scratch, src);
  ldr(src, dst);
  ldr(dst, scratch);
}

void MacroAssembler::SwapDouble(DoubleRegister src, MemOperand dst,
                                DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  ldr(scratch, src);
  LoadF64(src, dst);
  StoreF64(scratch, dst);
}

void MacroAssembler::SwapDouble(MemOperand src, MemOperand dst,
                                DoubleRegister scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kDoubleSize));
  StoreF64(d0, MemOperand(sp));
  LoadF64(scratch, src);
  LoadF64(d0, dst);
  StoreF64(scratch, dst);
  StoreF64(d0, src);
  // restore d0
  LoadF64(d0, MemOperand(sp));
  lay(sp, MemOperand(sp, kDoubleSize));
}

void MacroAssembler::SwapSimd128(Simd128Register src, Simd128Register dst,
                                 Simd128Register scratch) {
  if (src == dst) return;
  vlr(scratch, src, Condition(0), Condition(0), Condition(0));
  vlr(src, dst, Condition(0), Condition(0), Condition(0));
  vlr(dst, scratch, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::SwapSimd128(Simd128Register src, MemOperand dst,
                                 Simd128Register scratch) {
  DCHECK(!AreAliased(src, scratch));
  vlr(scratch, src, Condition(0), Condition(0), Condition(0));
  LoadV128(src, dst, ip);
  StoreV128(scratch, dst, ip);
}

void MacroAssembler::SwapSimd128(MemOperand src, MemOperand dst,
                                 Simd128Register scratch) {
  // push d0, to be used as scratch
  lay(sp, MemOperand(sp, -kSimd128Size));
  StoreV128(d0, MemOperand(sp), ip);
  LoadV128(scratch, src, ip);
  LoadV128(d0, dst, ip);
  StoreV128(scratch, dst, ip);
  StoreV128(d0, src, ip);
  // restore d0
  LoadV128(d0, MemOperand(sp), ip);
  lay(sp, MemOperand(sp, kSimd128Size));
}

void MacroAssembler::ComputeCodeStartAddress(Register dst) {
  larl(dst, Operand(-pc_offset() / 2));
}

void MacroAssembler::LoadPC(Register dst) {
  Label current_pc;
  larl(dst, &current_pc);
  bind(&current_pc);
}

void MacroAssembler::JumpIfEqual(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y));
  beq(dest);
}

void MacroAssembler::JumpIfLessThan(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y));
  blt(dest);
}

void MacroAssembler::LoadEntryFromBuiltinIndex(Register builtin_index,
                                               Register target) {
  static_assert(kSystemPointerSize == 8);
  static_assert(kSmiTagSize == 1);
  static_assert(kSmiTag == 0);
  // The builtin_index register contains the builtin index as a Smi.
  if (SmiValuesAre32Bits()) {
    ShiftRightS64(target, builtin_index,
                  Operand(kSmiShift - kSystemPointerSizeLog2));
  } else {
    DCHECK(SmiValuesAre31Bits());
    ShiftLeftU64(target, builtin_index,
                 Operand(kSystemPointerSizeLog2 - kSmiShift));
  }
  LoadU64(target, MemOperand(kRootRegister, target,
                             IsolateData::builtin_entry_table_offset()));
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index,
                                        Register target) {
  LoadEntryFromBuiltinIndex(builtin_index, target);
  Call(target);
}

void MacroAssembler::LoadEntryFromBuiltin(Builtin builtin,
                                          Register destination) {
  ASM_CODE_COMMENT(this);
  LoadU64(destination, EntryFromBuiltinAsOperand(builtin));
}

MemOperand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  return MemOperand(kRootRegister,
                    IsolateData::BuiltinEntrySlotOffset(builtin));
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
  LoadU64(destination,
          FieldMemOperand(code_object, Code::kInstructionStartOffset));
}

void MacroAssembler::CallCodeObject(Register code_object) {
  ASM_CODE_COMMENT(this);
  LoadCodeInstructionStart(code_object, code_object);
  Call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, JumpMode jump_mode) {
  ASM_CODE_COMMENT(this);
  DCHECK_EQ(JumpMode::kJump, jump_mode);
  LoadCodeInstructionStart(code_object, code_object);
  Jump(code_object);
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  Register code = kJavaScriptCallCodeStartRegister;
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(code);
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
  LoadTaggedField(code,
                  FieldMemOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(code, jump_mode);
}

#if V8_OS_ZOS
// Helper for CallApiFunctionAndReturn().
void MacroAssembler::zosStoreReturnAddressAndCall(Register target,
                                                  Register scratch) {
  DCHECK(target == r3 || target == r4);
  // Shuffle the arguments from Linux arg register to XPLINK arg regs
  mov(r1, r2);
  if (target == r3) {
    mov(r2, r3);
  } else {
    mov(r2, r3);
    mov(r3, r4);
  }

  // Update System Stack Pointer with the appropriate XPLINK stack bias.
  lay(r4, MemOperand(sp, -kStackPointerBias));

  // Preserve r7 by placing into callee-saved register r13
  mov(r13, r7);

  // Load function pointer from slot 1 of fn desc.
  LoadU64(ip, MemOperand(scratch, kSystemPointerSize));
  // Load environment from slot 0 of fn desc.
  LoadU64(r5, MemOperand(scratch));

  StoreReturnAddressAndCall(ip);

  // Restore r7 from r13
  mov(r7, r13);
}
#endif  // V8_OS_ZOS

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

#if V8_OS_ZOS
  Register ra = r7;
#else
  Register ra = r14;
#endif
  Label return_label;
  larl(ra, &return_label);  // Generate the return addr of call later.
#if V8_OS_ZOS
  // Mimic the XPLINK expected no-op (2-byte) instruction at the return point.
  // When the C call returns, the 2 bytes are skipped and then the proper
  // instruction is executed.
  lay(ra, MemOperand(ra, -2));
#endif
  StoreU64(ra, MemOperand(sp, kStackFrameRASlot * kSystemPointerSize));

  // zLinux ABI requires caller's frame to have sufficient space for callee
  // preserved regsiter save area.
  b(target);
  bind(&return_label);
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized(Register scratch) {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadTaggedField(scratch,
                  MemOperand(kJavaScriptCallCodeStartRegister, offset));
  TestCodeIsMarkedForDeoptimization(scratch, scratch);
  Jump(BUILTIN_CODE(isolate(), CompileLazyDeoptimizedCode),
       RelocInfo::CODE_TARGET, ne);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  ASM_CODE_COMMENT(this);
  LoadU64(ip, MemOperand(kRootRegister,
                         IsolateData::BuiltinEntrySlotOffset(target)));
  Call(ip);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::CountLeadingZerosU32(Register dst, Register src,
                                          Register scratch_pair) {
  llgfr(dst, src);
  flogr(scratch_pair,
        dst);  // will modify a register pair scratch and scratch + 1
  AddS32(dst, scratch_pair, Operand(-32));
}

void MacroAssembler::CountLeadingZerosU64(Register dst, Register src,
                                          Register scratch_pair) {
  flogr(scratch_pair,
        src);  // will modify a register pair scratch and scratch + 1
  mov(dst, scratch_pair);
}

void MacroAssembler::CountTrailingZerosU32(Register dst, Register src,
                                           Register scratch_pair) {
  Register scratch0 = scratch_pair;
  Register scratch1 = Register::from_code(scratch_pair.code() + 1);
  DCHECK(!AreAliased(dst, scratch0, scratch1));
  DCHECK(!AreAliased(src, scratch0, scratch1));

  Label done;
  // Check if src is all zeros.
  ltr(scratch1, src);
  mov(dst, Operand(32));
  beq(&done);
  llgfr(scratch1, scratch1);
  lcgr(scratch0, scratch1);
  ngr(scratch1, scratch0);
  flogr(scratch0, scratch1);
  mov(dst, Operand(63));
  SubS64(dst, scratch0);
  bind(&done);
}

void MacroAssembler::CountTrailingZerosU64(Register dst, Register src,
                                           Register scratch_pair) {
  Register scratch0 = scratch_pair;
  Register scratch1 = Register::from_code(scratch_pair.code() + 1);
  DCHECK(!AreAliased(dst, scratch0, scratch1));
  DCHECK(!AreAliased(src, scratch0, scratch1));

  Label done;
  // Check if src is all zeros.
  ltgr(scratch1, src);
  mov(dst, Operand(64));
  beq(&done);
  lcgr(scratch0, scratch1);
  ngr(scratch0, scratch1);
  flogr(scratch0, scratch0);
  mov(dst, Operand(63));
  SubS64(dst, scratch0);
  bind(&done);
}

void MacroAssembler::AtomicCmpExchangeHelper(Register addr, Register output,
                                             Register old_value,
                                             Register new_value, int start,
                                             int end, int shift_amount,
                                             int offset, Register temp0,
                                             Register temp1) {
  LoadU32(temp0, MemOperand(addr, offset));
  llgfr(temp1, temp0);
  RotateInsertSelectBits(temp0, old_value, Operand(start), Ope
```