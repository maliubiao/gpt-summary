Response:
The user wants a summary of the provided C++ code snippet from `v8/src/codegen/s390/macro-assembler-s390.cc`.

Here's a breakdown of the thought process to achieve the requested summary:

1. **Identify the Core Functionality:** The code primarily defines methods within the `MacroAssembler` class for the s390 architecture. The names of the methods strongly suggest they are related to atomic operations (like compare-and-exchange, exchange) and SIMD (Single Instruction, Multiple Data) operations.

2. **Categorize the Functions:**  Group the functions based on their purpose. Obvious categories are:
    * Atomic operations (with variations for different data sizes - U8, U16).
    * SIMD operations (further broken down by data type and operation type like splat, extract, replace, arithmetic, logical, comparisons, shifts, etc.).

3. **Analyze Atomic Operations:**  Notice the `AtomicCmpExchangeHelper` and `AtomicExchangeHelper` functions. These likely contain the core logic for the atomic operations, while the specific `AtomicCmpExchangeU8`, `AtomicCmpExchangeU16`, `AtomicExchangeU8`, and `AtomicExchangeU16` methods handle byte ordering and alignment concerns for different endianness. The use of `tmll` and conditional branches based on address alignment is a key observation.

4. **Analyze SIMD Operations:**
    * **Splat:**  Functions like `F64x2Splat`, `I32x4Splat` take a single value (or an element from a vector) and replicate it across the vector.
    * **Extract Lane:**  Functions like `F64x2ExtractLane`, `I32x4ExtractLane` retrieve a specific element from a SIMD vector.
    * **Replace Lane:** Functions like `F64x2ReplaceLane`, `I32x4ReplaceLane` modify a specific element in a SIMD vector.
    * **Unary Operations:**  Look for patterns like `F64x2Abs`, `I32x4Neg`. The `#define` macros `SIMD_UNOP_LIST_VRR_A` are crucial for identifying these.
    * **Binary Operations:** Look for patterns like `F64x2Add`, `I32x4Sub`, `S128And`. The `#define` macros `SIMD_BINOP_LIST_VRR_B` and `SIMD_BINOP_LIST_VRR_C` are important here.
    * **Shift Operations:** Identify the `I64x2Shl`, `I32x4ShrS` functions and the `SIMD_SHIFT_LIST` macro.
    * **Extended Multiply:**  Notice functions like `I64x2ExtMulLowI32x4S` and the `SIMD_EXT_MUL_LIST` macro.
    * **Comparisons:** Functions like `I64x2Eq`, `F64x2Ne`, `I32x4GtS`.
    * **Bit Manipulation:**  Functions like `I64x2BitMask`.
    * **Conversions:** Functions like `F64x2ConvertLowI32x4S`.
    * **Other Logical Operations:** `S128Not`, `S128Zero`, `S128AllOnes`, `S128Select`.

5. **Check for Torque (.tq):** The prompt specifically asks if the file ends with `.tq`. Since the provided code is C++, the answer is no.

6. **Relate to JavaScript:** Consider how these low-level operations might be used in JavaScript. Atomic operations are used for shared memory concurrency. SIMD operations are used to optimize numerical computations and multimedia processing, often exposed through JavaScript's Typed Arrays and SIMD APIs.

7. **Provide JavaScript Examples:**  Create simple JavaScript snippets illustrating the concepts of atomic operations (using `Atomics`) and SIMD operations (using `Float64Array` and performing element-wise operations, even if the exact underlying SIMD instruction is abstracted away).

8. **Code Logic Inference and Examples:**  For the atomic operations, provide a simple scenario demonstrating the compare-and-swap logic, showing how the output reflects the old value. For SIMD, a simple addition example shows how the operation is applied element-wise.

9. **Common Programming Errors:** Think about typical mistakes users make when dealing with atomic operations (race conditions due to incorrect usage) and SIMD operations (data type mismatches, incorrect lane indexing).

10. **Address Part Number:**  The prompt indicates this is part 6 of 8. Consider what the overall context might be. It's likely a series of code snippets from different parts of the `macro-assembler-s390.cc` file. Therefore, the summary should focus on the functionality present in *this specific snippet*.

11. **Synthesize the Summary:** Combine the observations into a concise summary, covering the main functionalities, mentioning the lack of `.tq`, providing JavaScript examples, code logic demonstrations, and common error examples. Emphasize that this part focuses on atomic and SIMD operations.
```cpp
rand(end),
                         Operand(shift_amount), false);
  RotateInsertSelectBits(temp1, new_value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  CmpAndSwap(temp0, temp1, MemOperand(addr, offset));
  RotateInsertSelectBits(output, temp0, Operand(start + shift_amount),
                         Operand(end + shift_amount),
                         Operand(64 - shift_amount), true);
}

void MacroAssembler::AtomicCmpExchangeU8(Register addr, Register output,
                                         Register old_value, Register new_value,
                                         Register temp0, Register temp1) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_COMP_EXCHANGE_BYTE(i)                                        \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 8 * idx;                                     \
    constexpr int end = start + 7;                                          \
    constexpr int shift_amount = (3 - idx) * 8;                             \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx, temp0, temp1);              \
  }
#else
#define ATOMIC_COMP_EXCHANGE_BYTE(i)                                        \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 8 * (3 - idx);                               \
    constexpr int end = start + 7;                                          \
    constexpr int shift_amount = idx * 8;                                   \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx, temp0, temp1);              \
  }
#endif

  Label one, two, three, done;
  tmll(addr, Operand(3));
  b(Condition(1), &three);
  b(Condition(2), &two);
  b(Condition(4), &one);
  /* ending with 0b00 */
  ATOMIC_COMP_EXCHANGE_BYTE(0);
  b(&done);
  /* ending with 0b01 */
  bind(&one);
  ATOMIC_COMP_EXCHANGE_BYTE(1);
  b(&done);
  /* ending with 0b10 */
  bind(&two);
  ATOMIC_COMP_EXCHANGE_BYTE(2);
  b(&done);
  /* ending with 0b11 */
  bind(&three);
  ATOMIC_COMP_EXCHANGE_BYTE(3);
  bind(&done);
}

void MacroAssembler::AtomicCmpExchangeU16(Register addr, Register output,
                                          Register old_value,
                                          Register new_value, Register temp0,
                                          Register temp1) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_COMP_EXCHANGE_HALFWORD(i)                                    \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 16 * idx;                                    \
    constexpr int end = start + 15;                                         \
    constexpr int shift_amount = (1 - idx) * 16;                            \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx * 2, temp0, temp1);          \
  }
#else
#define ATOMIC_COMP_EXCHANGE_HALFWORD(i)                                    \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 16 * (1 - idx);                              \
    constexpr int end = start + 15;                                         \
    constexpr int shift_amount = idx * 16;                                  \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx * 2, temp0, temp1);          \
  }
#endif

  Label two, done;
  tmll(addr, Operand(3));
  b(Condition(2), &two);
  ATOMIC_COMP_EXCHANGE_HALFWORD(0);
  b(&done);
  bind(&two);
  ATOMIC_COMP_EXCHANGE_HALFWORD(1);
  bind(&done);
}

void MacroAssembler::AtomicExchangeHelper(Register addr, Register value,
                                          Register output, int start, int end,
                                          int shift_amount, int offset,
                                          Register scratch) {
  Label do_cs;
  LoadU32(output, MemOperand(addr, offset));
  bind(&do_cs);
  llgfr(scratch, output);
  RotateInsertSelectBits(scratch, value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  csy(output, scratch, MemOperand(addr, offset));
  bne(&do_cs, Label::kNear);
  srl(output, Operand(shift_amount));
}

void MacroAssembler::AtomicExchangeU8(Register addr, Register value,
                                      Register output, Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_EXCHANGE_BYTE(i)                                               \
  {                                                                           \
    constexpr int idx = (i);                                                  \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");              \
    constexpr int start = 32 + 8 * idx;                                       \
    constexpr int end = start + 7;                                            \
    constexpr int shift_amount = (3 - idx) * 8;                               \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, -idx, \
                         scratch);                                            \
  }
#else
#define ATOMIC_EXCHANGE_BYTE(i)                                               \
  {                                                                           \
    constexpr int idx = (i);                                                  \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");              \
    constexpr int start = 32 + 8 * (3 - idx);                                 \
    constexpr int end = start + 7;                                            \
    constexpr int shift_amount = idx * 8;                                     \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, -idx, \
                         scratch);                                            \
  }
#endif
  Label three, two, one, done;
  tmll(addr, Operand(3));
  b(Condition(1), &three);
  b(Condition(2), &two);
  b(Condition(4), &one);

  // end with 0b00
  ATOMIC_EXCHANGE_BYTE(0);
  b(&done);

  // ending with 0b01
  bind(&one);
  ATOMIC_EXCHANGE_BYTE(1);
  b(&done);

  // ending with 0b10
  bind(&two);
  ATOMIC_EXCHANGE_BYTE(2);
  b(&done);

  // ending with 0b11
  bind(&three);
  ATOMIC_EXCHANGE_BYTE(3);

  bind(&done);
}

void MacroAssembler::AtomicExchangeU16(Register addr, Register value,
                                       Register output, Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_EXCHANGE_HALFWORD(i)                                     \
  {                                                                     \
    constexpr int idx = (i);                                            \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");        \
    constexpr int start = 32 + 16 * idx;                                \
    constexpr int end = start + 15;                                     \
    constexpr int shift_amount = (1 - idx) * 16;                        \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, \
                         -idx * 2, scratch);                            \
  }
#else
#define ATOMIC_EXCHANGE_HALFWORD(i)                                     \
  {                                                                     \
    constexpr int idx = (i);                                            \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");        \
    constexpr int start = 32 + 16 * (1 - idx);                          \
    constexpr int end = start + 15;                                     \
    constexpr int shift_amount = idx * 16;                              \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, \
                         -idx * 2, scratch);                            \
  }
#endif
  Label two, done;
  tmll(addr, Operand(3));
  b(Condition(2), &two);

  // end with 0b00
  ATOMIC_EXCHANGE_HALFWORD(0);
  b(&done);

  // ending with 0b10
  bind(&two);
  ATOMIC_EXCHANGE_HALFWORD(1);

  bind(&done);
}

// Simd Support.
void MacroAssembler::F64x2Splat(Simd128Register dst, Simd128Register src) {
  vrep(dst, src, Operand(0), Condition(3));
}

void MacroAssembler::F32x4Splat(Simd128Register dst, Simd128Register src) {
  vrep(dst, src, Operand(0), Condition(2));
}

void MacroAssembler::I64x2Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(3));
  vrep(dst, dst, Operand(0), Condition(3));
}

void MacroAssembler::I32x4Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(2));
  vrep(dst, dst, Operand(0), Condition(2));
}

void MacroAssembler::I16x8Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(1));
  vrep(dst, dst, Operand(0), Condition(1));
}

void MacroAssembler::I8x16Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(0));
  vrep(dst, dst, Operand(0), Condition(0));
}

void MacroAssembler::F64x2ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vrep(dst, src, Operand(1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::F32x4ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vrep(dst, src, Operand(3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I64x2ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::I32x4ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I16x8ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
}

void MacroAssembler::I16x8ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register scratch) {
  vlgv(scratch, src, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
  lghr(dst, scratch);
}

void MacroAssembler::I8x16ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
}

void MacroAssembler::I8x16ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register scratch) {
  vlgv(scratch, src, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
  lgbr(dst, scratch);
}

void MacroAssembler::F64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch) {
  vlgv(scratch, src2, MemOperand(r0, 0), Condition(3));
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, scratch, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::F32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch) {
  vlgv(scratch, src2, MemOperand(r0, 0), Condition(2));
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, scratch, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::I32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I16x8ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
}

void MacroAssembler::I8x16ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
}

void MacroAssembler::S128Not(Simd128Register dst, Simd128Register src) {
  vno(dst, src, src, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::S128Zero(Simd128Register dst, Simd128Register src) {
  vx(dst, src, src, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::S128AllOnes(Simd128Register dst, Simd128Register src) {
  vceq(dst, src, src, Condition(0), Condition(3));
}

void MacroAssembler::S128Select(Simd128Register dst, Simd128Register src1,
                                Simd128Register src2, Simd128Register mask) {
  vsel(dst, src1, src2, mask, Condition(0), Condition(0));
}

#define SIMD_UNOP_LIST_VRR_A(V)             \
  V(F64x2Abs, vfpso, 2, 0, 3)               \
  V(F64x2Neg, vfpso, 0, 0, 3)               \
  V(F64x2Sqrt, vfsq, 0, 0, 3)               \
  V(F64x2Ceil, vfi, 6, 0, 3)                \
  V(F64x2Floor, vfi, 7, 0, 3)               \
  V(F64x2Trunc, vfi, 5, 0, 3)               \
  V(F64x2NearestInt, vfi, 4, 0, 3)          \
  V(F32x4Abs, vfpso, 2, 0, 2)               \
  V(F32x4Neg, vfpso, 0, 0, 2)               \
  V(F32x4Sqrt, vfsq, 0, 0, 2)               \
  V(F32x4Ceil, vfi, 6, 0, 2)                \
  V(F32x4Floor, vfi, 7, 0, 2)               \
  V(F32x4Trunc, vfi, 5, 0, 2)               \
  V(F32x4NearestInt, vfi, 4, 0, 2)          \
  V(I64x2Abs, vlp, 0, 0, 3)                 \
  V(I64x2Neg, vlc, 0, 0, 3)                 \
  V(I64x2SConvertI32x4Low, vupl, 0, 0, 2)   \
  V(I64x2SConvertI32x4High, vuph, 0, 0, 2)  \
  V(I64x2UConvertI32x4Low, vupll, 0, 0, 2)  \
  V(I64x2UConvertI32x4High, vuplh, 0, 0, 2) \
  V(I32x4Abs, vlp, 0, 0, 2)                 \
  V(I32x4Neg, vlc, 0, 0, 2)                 \
  V(I32x4SConvertI16x8Low, vupl, 0, 0, 1)   \
  V(I32x4SConvertI16x8High, vuph, 0, 0, 1)  \
  V(I32x4UConvertI16x8Low, vupll, 0, 0, 1)  \
  V(I32x4UConvertI16x8High, vuplh, 0, 0, 1) \
  V(I16x8Abs, vlp, 0, 0, 1)                 \
  V(I16x8Neg, vlc, 0, 0, 1)                 \
  V(I16x8SConvertI8x16Low, vupl, 0, 0, 0)   \
  V(I16x8SConvertI8x16High, vuph, 0, 0, 0)  \
  V(I16x8UConvertI8x16Low, vupll, 0, 0, 0)  \
  V(I16x8UConvertI8x16High, vuplh, 0, 0, 0) \
  V(I8x16Abs, vlp, 0, 0, 0)                 \
  V(I8x16Neg, vlc, 0, 0, 0)                 \
  V(I8x16Popcnt, vpopct, 0, 0, 0)

#define EMIT_SIMD_UNOP_VRR_A(name, op, c1, c2, c3)                      \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src) { \
    op(dst, src, Condition(c1), Condition(c2), Condition(c3));          \
  }
SIMD_UNOP_LIST_VRR_A(EMIT_SIMD_UNOP_VRR_A)
#undef EMIT_SIMD_UNOP_VRR_A
#undef SIMD_UNOP_LIST_VRR_A

#define SIMD_BINOP_LIST_VRR_B(V) \
  V(I64x2Eq, vceq, 0, 3)         \
  V(I64x2GtS, vch, 0, 3)         \
  V(I32x4Eq, vceq, 0, 2)         \
  V(I32x4GtS, vch, 0, 2)         \
  V(I32x4GtU, vchl, 0, 2)        \
  V(I16x8Eq, vceq, 0, 1)         \
  V(I16x8GtS, vch, 0, 1)         \
  V(I16x8GtU, vchl, 0, 1)        \
  V(I8x16Eq, vceq, 0, 0)         \
  V(I8x16GtS, vch, 0, 0)         \
  V(I8x16GtU, vchl, 0, 0)

#define EMIT_SIMD_BINOP_VRR_B(name, op, c1, c2)                        \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Simd128Register src2) {                    \
    op(dst, src1, src2, Condition(c1), Condition(c2));                 \
  }
SIMD_BINOP_LIST_VRR_B(EMIT_SIMD_BINOP_VRR_B)
#undef EMIT_SIMD_BINOP_VRR_B
#undef SIMD_BINOP_LIST_VRR_B

#define SIMD_BINOP_LIST_VRR_C(V)           \
  V(F64x2Add, vfa, 0, 0, 3)                \
  V(F64x2Sub, vfs, 0, 0, 3)                \
  V(F64x2Mul, vfm, 0, 0, 3)                \
  V(F64x2Div, vfd, 0, 0, 3)                \
  V(F64x2Min, vfmin, 1, 0, 3)              \
  V(F64x2Max, vfmax, 1, 0, 3)              \
  V(F64x2Eq, vfce, 0, 0, 3)                \
  V(F64x2Pmin, vfmin, 3, 0, 3)             \
  V(F64x2Pmax, vfmax, 3, 0, 3)             \
  V(F32x4Add, vfa, 0, 0, 2)                \
  V(F32x4Sub, vfs, 0, 0, 2)                \
  V(F32x4Mul, vfm, 0, 0, 2)                \
  V(F32x4Div, vfd, 0, 0, 2)                \
  V(F32x4Min, vfmin, 1, 0, 2)              \
  V(F32x4Max, vfmax, 1, 0, 2)              \
  V(F32x4Eq, vfce, 0, 0, 2)                \
  V(F32x4Pmin, vfmin, 3, 0, 2)             \
  V(F32x4Pmax, vfmax, 3, 0, 2)             \
  V(I64x2Add, va, 0, 0, 3)                 \
  V(I64x2Sub, vs, 0, 0, 3)                 \
  V(I32x4Add, va, 0, 0, 2)                 \
  V(I32x4Sub, vs, 0, 0, 2)                 \
  V(I32x4Mul, vml, 0, 0, 2)                \
  V(I32x4MinS, vmn, 0, 0, 2)               \
  V(I32x4MinU, vmnl, 0, 0, 2)              \
  V(I32x4MaxS, vmx, 0, 0, 2)               \
  V(I32x4MaxU, vmxl, 0, 0, 2)              \
  V(I16x8Add, va, 0, 0, 1)                 \
  V(I16x8Sub, vs, 0, 0, 1)                 \
  V(I16x8Mul, vml, 0, 0, 1)                \
  V(I16x8MinS, vmn, 0, 0, 1)               \
  V(I16x8MinU, vmnl, 0, 0, 1)              \
  V(I16x8MaxS, vmx, 0, 0, 1)               \
  V(I16x8MaxU, vmxl, 0, 0, 1)              \
  V(I16x8RoundingAverageU, vavgl, 0, 0, 1) \
  V(I8x16Add, va, 0, 0, 0)                 \
  V(I8x16Sub, vs, 0, 0, 0)                 \
  V(I8x16MinS, vmn, 0, 0, 0)               \
  V(I8x16MinU, vmnl, 0, 0, 0)              \
  V(I8x16MaxS, vmx, 0, 0, 0)               \
  V(I8x16MaxU, vmxl, 0, 0, 0)              \
  V(I8x16RoundingAverageU, vavgl, 0, 0, 0) \
  V(S128And, vn, 0, 0, 0)                  \
  V(S128Or, vo, 0, 0, 0)                   \
  V(S128Xor, vx, 0, 0, 0)                  \
  V(S128AndNot, vnc, 0, 0, 0)

#define EMIT_SIMD_BINOP_VRR_C(name, op, c1, c2, c3)                    \
  void MacroAssembler::name(Simd128Register dst, Sim
### 提示词
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/s390/macro-assembler-s390.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
rand(end),
                         Operand(shift_amount), false);
  RotateInsertSelectBits(temp1, new_value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  CmpAndSwap(temp0, temp1, MemOperand(addr, offset));
  RotateInsertSelectBits(output, temp0, Operand(start + shift_amount),
                         Operand(end + shift_amount),
                         Operand(64 - shift_amount), true);
}

void MacroAssembler::AtomicCmpExchangeU8(Register addr, Register output,
                                         Register old_value, Register new_value,
                                         Register temp0, Register temp1) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_COMP_EXCHANGE_BYTE(i)                                        \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 8 * idx;                                     \
    constexpr int end = start + 7;                                          \
    constexpr int shift_amount = (3 - idx) * 8;                             \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx, temp0, temp1);              \
  }
#else
#define ATOMIC_COMP_EXCHANGE_BYTE(i)                                        \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 8 * (3 - idx);                               \
    constexpr int end = start + 7;                                          \
    constexpr int shift_amount = idx * 8;                                   \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx, temp0, temp1);              \
  }
#endif

  Label one, two, three, done;
  tmll(addr, Operand(3));
  b(Condition(1), &three);
  b(Condition(2), &two);
  b(Condition(4), &one);
  /* ending with 0b00 */
  ATOMIC_COMP_EXCHANGE_BYTE(0);
  b(&done);
  /* ending with 0b01 */
  bind(&one);
  ATOMIC_COMP_EXCHANGE_BYTE(1);
  b(&done);
  /* ending with 0b10 */
  bind(&two);
  ATOMIC_COMP_EXCHANGE_BYTE(2);
  b(&done);
  /* ending with 0b11 */
  bind(&three);
  ATOMIC_COMP_EXCHANGE_BYTE(3);
  bind(&done);
}

void MacroAssembler::AtomicCmpExchangeU16(Register addr, Register output,
                                          Register old_value,
                                          Register new_value, Register temp0,
                                          Register temp1) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_COMP_EXCHANGE_HALFWORD(i)                                    \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 16 * idx;                                    \
    constexpr int end = start + 15;                                         \
    constexpr int shift_amount = (1 - idx) * 16;                            \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx * 2, temp0, temp1);          \
  }
#else
#define ATOMIC_COMP_EXCHANGE_HALFWORD(i)                                    \
  {                                                                         \
    constexpr int idx = (i);                                                \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");            \
    constexpr int start = 32 + 16 * (1 - idx);                              \
    constexpr int end = start + 15;                                         \
    constexpr int shift_amount = idx * 16;                                  \
    AtomicCmpExchangeHelper(addr, output, old_value, new_value, start, end, \
                            shift_amount, -idx * 2, temp0, temp1);          \
  }
#endif

  Label two, done;
  tmll(addr, Operand(3));
  b(Condition(2), &two);
  ATOMIC_COMP_EXCHANGE_HALFWORD(0);
  b(&done);
  bind(&two);
  ATOMIC_COMP_EXCHANGE_HALFWORD(1);
  bind(&done);
}

void MacroAssembler::AtomicExchangeHelper(Register addr, Register value,
                                          Register output, int start, int end,
                                          int shift_amount, int offset,
                                          Register scratch) {
  Label do_cs;
  LoadU32(output, MemOperand(addr, offset));
  bind(&do_cs);
  llgfr(scratch, output);
  RotateInsertSelectBits(scratch, value, Operand(start), Operand(end),
                         Operand(shift_amount), false);
  csy(output, scratch, MemOperand(addr, offset));
  bne(&do_cs, Label::kNear);
  srl(output, Operand(shift_amount));
}

void MacroAssembler::AtomicExchangeU8(Register addr, Register value,
                                      Register output, Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_EXCHANGE_BYTE(i)                                               \
  {                                                                           \
    constexpr int idx = (i);                                                  \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");              \
    constexpr int start = 32 + 8 * idx;                                       \
    constexpr int end = start + 7;                                            \
    constexpr int shift_amount = (3 - idx) * 8;                               \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, -idx, \
                         scratch);                                            \
  }
#else
#define ATOMIC_EXCHANGE_BYTE(i)                                               \
  {                                                                           \
    constexpr int idx = (i);                                                  \
    static_assert(idx <= 3 && idx >= 0, "idx is out of range!");              \
    constexpr int start = 32 + 8 * (3 - idx);                                 \
    constexpr int end = start + 7;                                            \
    constexpr int shift_amount = idx * 8;                                     \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, -idx, \
                         scratch);                                            \
  }
#endif
  Label three, two, one, done;
  tmll(addr, Operand(3));
  b(Condition(1), &three);
  b(Condition(2), &two);
  b(Condition(4), &one);

  // end with 0b00
  ATOMIC_EXCHANGE_BYTE(0);
  b(&done);

  // ending with 0b01
  bind(&one);
  ATOMIC_EXCHANGE_BYTE(1);
  b(&done);

  // ending with 0b10
  bind(&two);
  ATOMIC_EXCHANGE_BYTE(2);
  b(&done);

  // ending with 0b11
  bind(&three);
  ATOMIC_EXCHANGE_BYTE(3);

  bind(&done);
}

void MacroAssembler::AtomicExchangeU16(Register addr, Register value,
                                       Register output, Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
#define ATOMIC_EXCHANGE_HALFWORD(i)                                     \
  {                                                                     \
    constexpr int idx = (i);                                            \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");        \
    constexpr int start = 32 + 16 * idx;                                \
    constexpr int end = start + 15;                                     \
    constexpr int shift_amount = (1 - idx) * 16;                        \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, \
                         -idx * 2, scratch);                            \
  }
#else
#define ATOMIC_EXCHANGE_HALFWORD(i)                                     \
  {                                                                     \
    constexpr int idx = (i);                                            \
    static_assert(idx <= 1 && idx >= 0, "idx is out of range!");        \
    constexpr int start = 32 + 16 * (1 - idx);                          \
    constexpr int end = start + 15;                                     \
    constexpr int shift_amount = idx * 16;                              \
    AtomicExchangeHelper(addr, value, output, start, end, shift_amount, \
                         -idx * 2, scratch);                            \
  }
#endif
  Label two, done;
  tmll(addr, Operand(3));
  b(Condition(2), &two);

  // end with 0b00
  ATOMIC_EXCHANGE_HALFWORD(0);
  b(&done);

  // ending with 0b10
  bind(&two);
  ATOMIC_EXCHANGE_HALFWORD(1);

  bind(&done);
}

// Simd Support.
void MacroAssembler::F64x2Splat(Simd128Register dst, Simd128Register src) {
  vrep(dst, src, Operand(0), Condition(3));
}

void MacroAssembler::F32x4Splat(Simd128Register dst, Simd128Register src) {
  vrep(dst, src, Operand(0), Condition(2));
}

void MacroAssembler::I64x2Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(3));
  vrep(dst, dst, Operand(0), Condition(3));
}

void MacroAssembler::I32x4Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(2));
  vrep(dst, dst, Operand(0), Condition(2));
}

void MacroAssembler::I16x8Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(1));
  vrep(dst, dst, Operand(0), Condition(1));
}

void MacroAssembler::I8x16Splat(Simd128Register dst, Register src) {
  vlvg(dst, src, MemOperand(r0, 0), Condition(0));
  vrep(dst, dst, Operand(0), Condition(0));
}

void MacroAssembler::F64x2ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vrep(dst, src, Operand(1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::F32x4ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vrep(dst, src, Operand(3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I64x2ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::I32x4ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I16x8ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
}

void MacroAssembler::I16x8ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register scratch) {
  vlgv(scratch, src, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
  lghr(dst, scratch);
}

void MacroAssembler::I8x16ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register) {
  vlgv(dst, src, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
}

void MacroAssembler::I8x16ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx, Register scratch) {
  vlgv(scratch, src, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
  lgbr(dst, scratch);
}

void MacroAssembler::F64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch) {
  vlgv(scratch, src2, MemOperand(r0, 0), Condition(3));
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, scratch, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::F32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch) {
  vlgv(scratch, src2, MemOperand(r0, 0), Condition(2));
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, scratch, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 1 - imm_lane_idx), Condition(3));
}

void MacroAssembler::I32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 3 - imm_lane_idx), Condition(2));
}

void MacroAssembler::I16x8ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 7 - imm_lane_idx), Condition(1));
}

void MacroAssembler::I8x16ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Register) {
  if (src1 != dst) {
    vlr(dst, src1, Condition(0), Condition(0), Condition(0));
  }
  vlvg(dst, src2, MemOperand(r0, 15 - imm_lane_idx), Condition(0));
}

void MacroAssembler::S128Not(Simd128Register dst, Simd128Register src) {
  vno(dst, src, src, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::S128Zero(Simd128Register dst, Simd128Register src) {
  vx(dst, src, src, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::S128AllOnes(Simd128Register dst, Simd128Register src) {
  vceq(dst, src, src, Condition(0), Condition(3));
}

void MacroAssembler::S128Select(Simd128Register dst, Simd128Register src1,
                                Simd128Register src2, Simd128Register mask) {
  vsel(dst, src1, src2, mask, Condition(0), Condition(0));
}

#define SIMD_UNOP_LIST_VRR_A(V)             \
  V(F64x2Abs, vfpso, 2, 0, 3)               \
  V(F64x2Neg, vfpso, 0, 0, 3)               \
  V(F64x2Sqrt, vfsq, 0, 0, 3)               \
  V(F64x2Ceil, vfi, 6, 0, 3)                \
  V(F64x2Floor, vfi, 7, 0, 3)               \
  V(F64x2Trunc, vfi, 5, 0, 3)               \
  V(F64x2NearestInt, vfi, 4, 0, 3)          \
  V(F32x4Abs, vfpso, 2, 0, 2)               \
  V(F32x4Neg, vfpso, 0, 0, 2)               \
  V(F32x4Sqrt, vfsq, 0, 0, 2)               \
  V(F32x4Ceil, vfi, 6, 0, 2)                \
  V(F32x4Floor, vfi, 7, 0, 2)               \
  V(F32x4Trunc, vfi, 5, 0, 2)               \
  V(F32x4NearestInt, vfi, 4, 0, 2)          \
  V(I64x2Abs, vlp, 0, 0, 3)                 \
  V(I64x2Neg, vlc, 0, 0, 3)                 \
  V(I64x2SConvertI32x4Low, vupl, 0, 0, 2)   \
  V(I64x2SConvertI32x4High, vuph, 0, 0, 2)  \
  V(I64x2UConvertI32x4Low, vupll, 0, 0, 2)  \
  V(I64x2UConvertI32x4High, vuplh, 0, 0, 2) \
  V(I32x4Abs, vlp, 0, 0, 2)                 \
  V(I32x4Neg, vlc, 0, 0, 2)                 \
  V(I32x4SConvertI16x8Low, vupl, 0, 0, 1)   \
  V(I32x4SConvertI16x8High, vuph, 0, 0, 1)  \
  V(I32x4UConvertI16x8Low, vupll, 0, 0, 1)  \
  V(I32x4UConvertI16x8High, vuplh, 0, 0, 1) \
  V(I16x8Abs, vlp, 0, 0, 1)                 \
  V(I16x8Neg, vlc, 0, 0, 1)                 \
  V(I16x8SConvertI8x16Low, vupl, 0, 0, 0)   \
  V(I16x8SConvertI8x16High, vuph, 0, 0, 0)  \
  V(I16x8UConvertI8x16Low, vupll, 0, 0, 0)  \
  V(I16x8UConvertI8x16High, vuplh, 0, 0, 0) \
  V(I8x16Abs, vlp, 0, 0, 0)                 \
  V(I8x16Neg, vlc, 0, 0, 0)                 \
  V(I8x16Popcnt, vpopct, 0, 0, 0)

#define EMIT_SIMD_UNOP_VRR_A(name, op, c1, c2, c3)                      \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src) { \
    op(dst, src, Condition(c1), Condition(c2), Condition(c3));          \
  }
SIMD_UNOP_LIST_VRR_A(EMIT_SIMD_UNOP_VRR_A)
#undef EMIT_SIMD_UNOP_VRR_A
#undef SIMD_UNOP_LIST_VRR_A

#define SIMD_BINOP_LIST_VRR_B(V) \
  V(I64x2Eq, vceq, 0, 3)         \
  V(I64x2GtS, vch, 0, 3)         \
  V(I32x4Eq, vceq, 0, 2)         \
  V(I32x4GtS, vch, 0, 2)         \
  V(I32x4GtU, vchl, 0, 2)        \
  V(I16x8Eq, vceq, 0, 1)         \
  V(I16x8GtS, vch, 0, 1)         \
  V(I16x8GtU, vchl, 0, 1)        \
  V(I8x16Eq, vceq, 0, 0)         \
  V(I8x16GtS, vch, 0, 0)         \
  V(I8x16GtU, vchl, 0, 0)

#define EMIT_SIMD_BINOP_VRR_B(name, op, c1, c2)                        \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Simd128Register src2) {                    \
    op(dst, src1, src2, Condition(c1), Condition(c2));                 \
  }
SIMD_BINOP_LIST_VRR_B(EMIT_SIMD_BINOP_VRR_B)
#undef EMIT_SIMD_BINOP_VRR_B
#undef SIMD_BINOP_LIST_VRR_B

#define SIMD_BINOP_LIST_VRR_C(V)           \
  V(F64x2Add, vfa, 0, 0, 3)                \
  V(F64x2Sub, vfs, 0, 0, 3)                \
  V(F64x2Mul, vfm, 0, 0, 3)                \
  V(F64x2Div, vfd, 0, 0, 3)                \
  V(F64x2Min, vfmin, 1, 0, 3)              \
  V(F64x2Max, vfmax, 1, 0, 3)              \
  V(F64x2Eq, vfce, 0, 0, 3)                \
  V(F64x2Pmin, vfmin, 3, 0, 3)             \
  V(F64x2Pmax, vfmax, 3, 0, 3)             \
  V(F32x4Add, vfa, 0, 0, 2)                \
  V(F32x4Sub, vfs, 0, 0, 2)                \
  V(F32x4Mul, vfm, 0, 0, 2)                \
  V(F32x4Div, vfd, 0, 0, 2)                \
  V(F32x4Min, vfmin, 1, 0, 2)              \
  V(F32x4Max, vfmax, 1, 0, 2)              \
  V(F32x4Eq, vfce, 0, 0, 2)                \
  V(F32x4Pmin, vfmin, 3, 0, 2)             \
  V(F32x4Pmax, vfmax, 3, 0, 2)             \
  V(I64x2Add, va, 0, 0, 3)                 \
  V(I64x2Sub, vs, 0, 0, 3)                 \
  V(I32x4Add, va, 0, 0, 2)                 \
  V(I32x4Sub, vs, 0, 0, 2)                 \
  V(I32x4Mul, vml, 0, 0, 2)                \
  V(I32x4MinS, vmn, 0, 0, 2)               \
  V(I32x4MinU, vmnl, 0, 0, 2)              \
  V(I32x4MaxS, vmx, 0, 0, 2)               \
  V(I32x4MaxU, vmxl, 0, 0, 2)              \
  V(I16x8Add, va, 0, 0, 1)                 \
  V(I16x8Sub, vs, 0, 0, 1)                 \
  V(I16x8Mul, vml, 0, 0, 1)                \
  V(I16x8MinS, vmn, 0, 0, 1)               \
  V(I16x8MinU, vmnl, 0, 0, 1)              \
  V(I16x8MaxS, vmx, 0, 0, 1)               \
  V(I16x8MaxU, vmxl, 0, 0, 1)              \
  V(I16x8RoundingAverageU, vavgl, 0, 0, 1) \
  V(I8x16Add, va, 0, 0, 0)                 \
  V(I8x16Sub, vs, 0, 0, 0)                 \
  V(I8x16MinS, vmn, 0, 0, 0)               \
  V(I8x16MinU, vmnl, 0, 0, 0)              \
  V(I8x16MaxS, vmx, 0, 0, 0)               \
  V(I8x16MaxU, vmxl, 0, 0, 0)              \
  V(I8x16RoundingAverageU, vavgl, 0, 0, 0) \
  V(S128And, vn, 0, 0, 0)                  \
  V(S128Or, vo, 0, 0, 0)                   \
  V(S128Xor, vx, 0, 0, 0)                  \
  V(S128AndNot, vnc, 0, 0, 0)

#define EMIT_SIMD_BINOP_VRR_C(name, op, c1, c2, c3)                    \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Simd128Register src2) {                    \
    op(dst, src1, src2, Condition(c1), Condition(c2), Condition(c3));  \
  }
SIMD_BINOP_LIST_VRR_C(EMIT_SIMD_BINOP_VRR_C)
#undef EMIT_SIMD_BINOP_VRR_C
#undef SIMD_BINOP_LIST_VRR_C

#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl, veslv, 3)    \
  V(I64x2ShrS, vesrav, 3)  \
  V(I64x2ShrU, vesrlv, 3)  \
  V(I32x4Shl, veslv, 2)    \
  V(I32x4ShrS, vesrav, 2)  \
  V(I32x4ShrU, vesrlv, 2)  \
  V(I16x8Shl, veslv, 1)    \
  V(I16x8ShrS, vesrav, 1)  \
  V(I16x8ShrU, vesrlv, 1)  \
  V(I8x16Shl, veslv, 0)    \
  V(I8x16ShrS, vesrav, 0)  \
  V(I8x16ShrU, vesrlv, 0)

#define EMIT_SIMD_SHIFT(name, op, c1)                                  \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Register src2, Simd128Register scratch) {  \
    vlvg(scratch, src2, MemOperand(r0, 0), Condition(c1));             \
    vrep(scratch, scratch, Operand(0), Condition(c1));                 \
    op(dst, src1, scratch, Condition(0), Condition(0), Condition(c1)); \
  }                                                                    \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            const Operand& src2, Register scratch1,    \
                            Simd128Register scratch2) {                \
    mov(scratch1, src2);                                               \
    name(dst, src1, scratch1, scratch2);                               \
  }
SIMD_SHIFT_LIST(EMIT_SIMD_SHIFT)
#undef EMIT_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_EXT_MUL_LIST(V)                    \
  V(I64x2ExtMulLowI32x4S, vme, vmo, vmrl, 2)    \
  V(I64x2ExtMulHighI32x4S, vme, vmo, vmrh, 2)   \
  V(I64x2ExtMulLowI32x4U, vmle, vmlo, vmrl, 2)  \
  V(I64x2ExtMulHighI32x4U, vmle, vmlo, vmrh, 2) \
  V(I32x4ExtMulLowI16x8S, vme, vmo, vmrl, 1)    \
  V(I32x4ExtMulHighI16x8S, vme, vmo, vmrh, 1)   \
  V(I32x4ExtMulLowI16x8U, vmle, vmlo, vmrl, 1)  \
  V(I32x4ExtMulHighI16x8U, vmle, vmlo, vmrh, 1) \
  V(I16x8ExtMulLowI8x16S, vme, vmo, vmrl, 0)    \
  V(I16x8ExtMulHighI8x16S, vme, vmo, vmrh, 0)   \
  V(I16x8ExtMulLowI8x16U, vmle, vmlo, vmrl, 0)  \
  V(I16x8ExtMulHighI8x16U, vmle, vmlo, vmrh, 0)

#define EMIT_SIMD_EXT_MUL(name, mul_even, mul_odd, merge, mode)                \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1,         \
                            Simd128Register src2, Simd128Register scratch) {   \
    mul_even(scratch, src1, src2, Condition(0), Condition(0),                  \
             Condition(mode));                                                 \
    mul_odd(dst, src1, src2, Condition(0), Condition(0), Condition(mode));     \
    merge(dst, scratch, dst, Condition(0), Condition(0), Condition(mode + 1)); \
  }
SIMD_EXT_MUL_LIST(EMIT_SIMD_EXT_MUL)
#undef EMIT_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue, 3)          \
  V(I32x4AllTrue, 2)          \
  V(I16x8AllTrue, 1)          \
  V(I8x16AllTrue, 0)

#define EMIT_SIMD_ALL_TRUE(name, mode)                                     \
  void MacroAssembler::name(Register dst, Simd128Register src,             \
                            Register scratch1, Simd128Register scratch2) { \
    mov(scratch1, Operand(1));                                             \
    xgr(dst, dst);                                                         \
    vx(scratch2, scratch2, scratch2, Condition(0), Condition(0),           \
       Condition(2));                                                      \
    vceq(scratch2, src, scratch2, Condition(0), Condition(mode));          \
    vtm(scratch2, scratch2, Condition(0), Condition(0), Condition(0));     \
    locgr(Condition(8), dst, scratch1);                                    \
  }
SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma, vfma, 3)  \
  V(F64x2Qfms, vfnms, 3) \
  V(F32x4Qfma, vfma, 2)  \
  V(F32x4Qfms, vfnms, 2)

#define EMIT_SIMD_QFM(name, op, c1)                                       \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1,    \
                            Simd128Register src2, Simd128Register src3) { \
    op(dst, src1, src2, src3, Condition(c1), Condition(0));               \
  }
SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

void MacroAssembler::I64x2Mul(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Register scratch1,
                              Register scratch2, Register scratch3) {
  Register scratch_1 = scratch1;
  Register scratch_2 = scratch2;
  for (int i = 0; i < 2; i++) {
    vlgv(scratch_1, src1, MemOperand(r0, i), Condition(3));
    vlgv(scratch_2, src2, MemOperand(r0, i), Condition(3));
    MulS64(scratch_1, scratch_2);
    scratch_1 = scratch2;
    scratch_2 = scratch3;
  }
  vlvgp(dst, scratch1, scratch2);
}

void MacroAssembler::F64x2Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfce(dst, src1, src2, Condition(0), Condition(0), Condition(3));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::F64x2Lt(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfch(dst, src2, src1, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::F64x2Le(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfche(dst, src2, src1, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::F32x4Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfce(dst, src1, src2, Condition(0), Condition(0), Condition(2));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::F32x4Lt(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfch(dst, src2, src1, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::F32x4Le(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vfche(dst, src2, src1, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I64x2Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(3));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::I64x2GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(3));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(3));
}

void MacroAssembler::I32x4Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(2));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I32x4GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(2));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I32x4GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vceq(scratch, src1, src2, Condition(0), Condition(2));
  vchl(dst, src1, src2, Condition(0), Condition(2));
  vo(dst, dst, scratch, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I16x8Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(1));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I16x8GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(1));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I16x8GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vceq(scratch, src1, src2, Condition(0), Condition(1));
  vchl(dst, src1, src2, Condition(0), Condition(1));
  vo(dst, dst, scratch, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I8x16Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  vceq(dst, src1, src2, Condition(0), Condition(0));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::I8x16GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  // Compute !(B > A) which is equal to A >= B.
  vch(dst, src2, src1, Condition(0), Condition(0));
  vno(dst, dst, dst, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::I8x16GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vceq(scratch, src1, src2, Condition(0), Condition(0));
  vchl(dst, src1, src2, Condition(0), Condition(0));
  vo(dst, dst, scratch, Condition(0), Condition(0), Condition(0));
}

void MacroAssembler::I64x2BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Simd128Register scratch2) {
  mov(scratch1, Operand(0x8080808080800040));
  vlvg(scratch2, scratch1, MemOperand(r0, 1), Condition(3));
  vbperm(scratch2, src, scratch2, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch2, MemOperand(r0, 7), Condition(0));
}

void MacroAssembler::I32x4BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Simd128Register scratch2) {
  mov(scratch1, Operand(0x8080808000204060));
  vlvg(scratch2, scratch1, MemOperand(r0, 1), Condition(3));
  vbperm(scratch2, src, scratch2, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch2, MemOperand(r0, 7), Condition(0));
}

void MacroAssembler::I16x8BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Simd128Register scratch2) {
  mov(scratch1, Operand(0x10203040506070));
  vlvg(scratch2, scratch1, MemOperand(r0, 1), Condition(3));
  vbperm(scratch2, src, scratch2, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch2, MemOperand(r0, 7), Condition(0));
}

void MacroAssembler::F64x2ConvertLowI32x4S(Simd128Register dst,
                                           Simd128Register src) {
  vupl(dst, src, Condition(0), Condition(0), Condition(2));
  vcdg(dst, dst, Condition(4), Condition(0), Condition(3));
}

void MacroAssembler::F64x2ConvertLowI32x4U(Simd128Register dst,
                                           Simd128Register src) {
  vupll(dst, src, Condition(0), Condition(0), Condition(2));
  vcdlg(dst, dst, Condition(4), Condition(0), Condition(3));
}

void MacroAssembler::I8x16BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Register scratch2,
                                  Simd128Register scratch3) {
  mov(scratch1, Operand(0x4048505860687078));
  mov(scratch2, Operand(0x8101820283038));
  vlvgp(scratch3, scratch2, scratch1);
  vbperm(scratch3, src, scratch3, Condition(0), Condition(0), Condition(0));
  vlgv(dst, scratch3, MemOperand(r0, 3), Condition(1));
}

void MacroAssembler::V128AnyTrue(Register dst, Simd128Register src,
                                 Register scratch) {
  mov(dst, Operand(1));
  xgr(scratch, scratch);
  vtm(src, src, Condition(0), Condition(0), Condition(0));
  locgr(Condition(8), dst, scratch);
}

#define CONVERT_FLOAT_TO_INT32(convert, dst, src, scratch1, scratch2) \
  for (int index = 0; index < 4; index++) {                           \
    vlgv(scratch2, src, MemOperand(r0, index), Condition(2));         \
    MovIntToFloat(scratch1, scratch2);                                \
    convert(scratch2, scratch1, kRoundToZero);                        \
    vlvg(dst, scratch2, MemOperand(r0, index), Condition(2));         \
  }
void MacroAssembler::I32x4SConvertF32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
                                        Register scratch2) {
  // NaN to 0.
  vfce(scratch1, src, src, Condition(0), Condition(0), Condition(2));
  vn(dst, src, scratch1, Condition(0), Condition(0), Condition(0));
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vcgd(dst, dst, Condition(5), Condition(0), Condition(2));
  } else {
    CONVERT_FLOAT_TO_INT32(ConvertFloat32ToInt32, dst, dst, scratch1, scratch2)
  }
}

void MacroAssembler::I32x4UConvertF32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
```