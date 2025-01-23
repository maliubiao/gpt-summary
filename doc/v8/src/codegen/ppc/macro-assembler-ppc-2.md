Response: The user wants a summary of the provided C++ code snippet.
This is the third part of a four-part file.
The code is for the PowerPC architecture within the V8 JavaScript engine.
It defines several `MacroAssembler` methods, which are used for generating machine code.

Looking at the code, it seems to handle:
1. **Little-endian memory access**: Functions like `LoadU16LE`, `LoadF64LE`, `StoreF64LE` suggest handling of different endianness.
2. **SIMD (Single Instruction, Multiple Data) operations**: A significant portion of the code deals with SIMD instructions, including binary operations (`F64x2Add`, `I32x4Mul`), shift operations (`I64x2Shl`), unary operations (`F64x2Abs`, `I32x4Neg`), extended multiplication (`I32x4ExtMulLowI16x8S`), all true checks (`I64x2AllTrue`), bitmask extraction (`I64x2BitMask`), and fused multiply-add/subtract (`F64x2Qfma`).
3. **SIMD lane manipulation**: Functions like `F64x2Splat`, `F64x2ExtractLane`, `F64x2ReplaceLane` are used to work with individual lanes of SIMD registers.
4. **SIMD comparisons**:  Functions like `F64x2Min`, `F64x2Max`, `F64x2Lt`, `I64x2Ne` implement comparison operations for SIMD vectors.
5. **SIMD type conversions**: Functions like `I32x4SConvertF32x4`, `F64x2ConvertLowI32x4S` handle conversions between different SIMD vector types.
6. **Other SIMD operations**:  Functions like `I32x4DotI16x8S`, `I8x16Swizzle`, `I8x16Shuffle` implement more complex SIMD operations.
7. **Little-endian SIMD load/store with lane operations**: Functions like `LoadLane64LE`, `StoreLane32LE`, `LoadAndSplat64x2LE`.
8. **Generic register and memory manipulation**: Functions like `SwapP`, `SwapFloat32`, `SwapSimd128`, `ByteReverseU16`.
9. **Control flow**: Functions like `JumpIfEqual`, `JumpIfLessThan`.
10. **Interaction with V8 internals**: Functions like `LoadEntryFromBuiltinIndex`, `CallBuiltinByIndex`, `CallJSFunction`, `BailoutIfDeoptimized`.
11. **Bit manipulation**: Functions like `Popcnt32`, `CountLeadingZerosU32`, `CountTrailingZerosU64`, `ReverseBitsU64`.

The code provides low-level building blocks for the V8 engine to execute JavaScript efficiently on the PowerPC architecture, especially leveraging SIMD capabilities for performance.

To illustrate the connection with JavaScript, consider a simple example using SIMD operations:

```javascript
// JavaScript code
const a = SIMD.float32x4(1.0, 2.0, 3.0, 4.0);
const b = SIMD.float32x4(5.0, 6.0, 7.0, 8.0);
const sum = SIMD.float32x4.add(a, b);
// sum will be SIMD.float32x4(6.0, 8.0, 10.0, 12.0)
```

The C++ code in this file provides the underlying implementation for the `SIMD.float32x4.add` operation. The `MacroAssembler::F32x4Add` function (defined using the `EMIT_SIMD_BINOP` macro) would generate the specific PowerPC instruction (`vaddfp`) to perform this addition on the SIMD registers.
This C++ code snippet, part 3 of 4 of the `macro-assembler-ppc.cc` file in the V8 JavaScript engine, primarily focuses on implementing **SIMD (Single Instruction, Multiple Data) operations** and **endianness handling** for the PowerPC architecture. It also includes functions for basic memory access and manipulation, as well as interactions with the V8 runtime.

Here's a breakdown of the functionality:

**1. Endianness Handling:**

*   It defines functions for loading and storing different data types (16-bit, 32-bit, 64-bit floating-point numbers) in **little-endian** format (`LoadU16LE`, `LoadF64LE`, `StoreF64LE`).
*   These functions use preprocessor directives (`#ifdef V8_TARGET_BIG_ENDIAN`) to handle both big-endian and little-endian architectures. On big-endian systems, they might involve byte swapping or using temporary stack storage to achieve the little-endian effect.

**2. SIMD Operations:**

*   A significant portion of the code defines functions for various SIMD instructions. These functions operate on 128-bit SIMD registers.
*   It uses macros (`SIMD_BINOP_LIST`, `SIMD_SHIFT_LIST`, `SIMD_UNOP_LIST`, etc.) to define lists of SIMD operations and then generate the corresponding `MacroAssembler` methods using `EMIT_SIMD_BINOP`, `EMIT_SIMD_SHIFT`, etc.
*   The defined SIMD operations cover a wide range of functionalities, including:
    *   **Arithmetic:** Addition (`F64x2Add`, `I32x4Add`), subtraction (`F64x2Sub`, `I32x4Sub`), multiplication (`F64x2Mul`, `I32x4Mul`), division (`F64x2Div`, `F32x4Div`).
    *   **Comparison:** Equality (`F64x2Eq`, `I32x4Eq`), greater than (`I64x2GtS`, `I32x4GtU`), less than, less than or equal to, not equal to.
    *   **Bitwise:** AND (`S128And`), OR (`S128Or`), XOR (`S128Xor`), AND NOT (`S128AndNot`).
    *   **Shift:** Left shift (`I64x2Shl`, `I32x4Shl`), right shift (signed and unsigned) (`I64x2ShrS`, `I32x4ShrU`).
    *   **Unary operations:** Absolute value (`F64x2Abs`, `I32x4Abs`), negation (`F64x2Neg`, `I32x4Neg`), square root (`F64x2Sqrt`), ceiling, floor, truncation.
    *   **Extended multiplication:** Producing wider results from multiplication (`I32x4ExtMulLowI16x8S`).
    *   **Lane manipulation:** Splatting (creating a vector with all lanes having the same value), extracting lanes, replacing lanes.
    *   **Type conversion:** Converting between different SIMD vector types (e.g., floating-point to integer).
    *   **Other operations:**  Fused multiply-add/subtract, dot product, swizzle, shuffle, pairwise addition.
    *   **All true/Bitmask:** Checking if all lanes satisfy a condition or extracting a bitmask from the lanes.

**3. SIMD Load and Store with Endianness and Lane Specificity:**

*   It provides functions to load and store entire SIMD registers (`LoadSimd128LE`, `StoreSimd128LE`) while handling potential byte reversal for little-endian systems on big-endian architectures.
*   It also includes functions to load and store individual lanes of SIMD registers (`LoadLane64LE`, `StoreLane32LE`) with little-endian conversion.
*   Functions like `LoadAndSplat64x2LE` efficiently load a value from memory and replicate it across all lanes of a SIMD register.
*   Functions for loading and extending smaller integer types into SIMD registers (`LoadAndExtend32x2SLE`, `LoadAndExtend16x4ULE`).
*   Functions to load and zero-extend values into SIMD registers (`LoadV64ZeroLE`, `LoadV32ZeroLE`).

**4. Basic Memory and Register Manipulation:**

*   Functions like `SwapP` are provided for swapping the contents of registers and memory locations. These functions handle different data types (general-purpose registers, floating-point registers, SIMD registers).
*   Functions for byte reversal (`ByteReverseU16`, `ByteReverseU32`, `ByteReverseU64`) are implemented, potentially utilizing optimized instructions if available on the target architecture.
*   Functions for zero-extending smaller data types to fit into larger registers (`ZeroExtByte`, `ZeroExtHalfWord`, `ZeroExtWord32`).

**5. Control Flow:**

*   Functions like `JumpIfEqual` and `JumpIfLessThan` provide conditional branching capabilities within the generated code.

**6. Interaction with V8 Internals:**

*   Functions like `LoadEntryFromBuiltinIndex`, `CallBuiltinByIndex`, `LoadEntryFromBuiltin`, `CallCodeObject`, `JumpCodeObject`, `CallJSFunction`, and `JumpJSFunction` demonstrate how the macro assembler interacts with the V8 runtime to call built-in functions, JavaScript functions, and handle code objects.
*   `BailoutIfDeoptimized` checks if a code object is marked for deoptimization and jumps to the appropriate built-in if necessary.

**7. Bit Manipulation:**

*   Functions for counting set bits (`Popcnt32`, `Popcnt64`), counting leading zeros (`CountLeadingZerosU32`, `CountLeadingZerosU64`), and counting trailing zeros (`CountTrailingZerosU32`, `CountTrailingZerosU64`).
*   Functions for clearing specific bytes within a 64-bit register (`ClearByteU64`).
*   Functions for reversing the bits within a register (`ReverseBitsU64`, `ReverseBitsU32`, `ReverseBitsInSingleByteU64`).

**Relationship to JavaScript:**

This code is fundamental to the performance of JavaScript execution in V8 on PowerPC. When JavaScript code uses features that can be optimized with SIMD, the V8 engine will use these `MacroAssembler` methods to generate the low-level machine instructions.

**JavaScript Example:**

```javascript
// Example using TypedArrays and SIMD (hypothetical more direct mapping)
const arrayA = new Float32Array([1, 2, 3, 4]);
const arrayB = new Float32Array([5, 6, 7, 8]);

// Hypothetical direct SIMD operation in JavaScript (not standard)
const simdA = SIMD.float32x4(arrayA[0], arrayA[1], arrayA[2], arrayA[3]);
const simdB = SIMD.float32x4(arrayB[0], arrayB[1], arrayB[2], arrayB[3]);
const sum = SIMD.float32x4.add(simdA, simdB);

// Internally, V8 would use MacroAssembler::F32x4Add
// to generate the 'vaddfp' instruction for PowerPC.
```

In reality, the interaction is more complex, with V8's optimizing compiler deciding when and how to utilize SIMD instructions based on the JavaScript code. However, the functions in this C++ file provide the necessary building blocks for those optimizations to occur on the PowerPC architecture. For example, array operations or computationally intensive tasks in JavaScript can benefit from the SIMD capabilities implemented here.

### 提示词
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
  LoadU16LE(dst, mem, scratch);
  extsh(dst, dst);
#else
  LoadS16(dst, mem, scratch);
#endif
}

void MacroAssembler::LoadF64LE(DoubleRegister dst, const MemOperand& mem,
                               Register scratch, Register scratch2) {
#ifdef V8_TARGET_BIG_ENDIAN
  LoadU64LE(scratch, mem, scratch2);
  push(scratch);
  LoadF64(dst, MemOperand(sp), scratch2);
  pop(scratch);
#else
  LoadF64(dst, mem, scratch);
#endif
}

void MacroAssembler::LoadF32LE(DoubleRegister dst, const MemOperand& mem,
                               Register scratch, Register scratch2) {
#ifdef V8_TARGET_BIG_ENDIAN
  LoadU32LE(scratch, mem, scratch2);
  push(scratch);
  LoadF32(dst, MemOperand(sp, 4), scratch2);
  pop(scratch);
#else
  LoadF32(dst, mem, scratch);
#endif
}

void MacroAssembler::StoreF64LE(DoubleRegister dst, const MemOperand& mem,
                                Register scratch, Register scratch2) {
#ifdef V8_TARGET_BIG_ENDIAN
  StoreF64(dst, mem, scratch2);
  LoadU64(scratch, mem, scratch2);
  StoreU64LE(scratch, mem, scratch2);
#else
  StoreF64(dst, mem, scratch);
#endif
}

void MacroAssembler::StoreF32LE(DoubleRegister dst, const MemOperand& mem,
                                Register scratch, Register scratch2) {
#ifdef V8_TARGET_BIG_ENDIAN
  StoreF32(dst, mem, scratch2);
  LoadU32(scratch, mem, scratch2);
  StoreU32LE(scratch, mem, scratch2);
#else
  StoreF32(dst, mem, scratch);
#endif
}

// Simd Support.
#define SIMD_BINOP_LIST(V)         \
  V(F64x2Add, xvadddp)             \
  V(F64x2Sub, xvsubdp)             \
  V(F64x2Mul, xvmuldp)             \
  V(F64x2Div, xvdivdp)             \
  V(F64x2Eq, xvcmpeqdp)            \
  V(F32x4Add, vaddfp)              \
  V(F32x4Sub, vsubfp)              \
  V(F32x4Mul, xvmulsp)             \
  V(F32x4Div, xvdivsp)             \
  V(F32x4Min, vminfp)              \
  V(F32x4Max, vmaxfp)              \
  V(F32x4Eq, xvcmpeqsp)            \
  V(I64x2Add, vaddudm)             \
  V(I64x2Sub, vsubudm)             \
  V(I64x2Eq, vcmpequd)             \
  V(I64x2GtS, vcmpgtsd)            \
  V(I32x4Add, vadduwm)             \
  V(I32x4Sub, vsubuwm)             \
  V(I32x4Mul, vmuluwm)             \
  V(I32x4MinS, vminsw)             \
  V(I32x4MinU, vminuw)             \
  V(I32x4MaxS, vmaxsw)             \
  V(I32x4MaxU, vmaxuw)             \
  V(I32x4Eq, vcmpequw)             \
  V(I32x4GtS, vcmpgtsw)            \
  V(I32x4GtU, vcmpgtuw)            \
  V(I16x8Add, vadduhm)             \
  V(I16x8Sub, vsubuhm)             \
  V(I16x8MinS, vminsh)             \
  V(I16x8MinU, vminuh)             \
  V(I16x8MaxS, vmaxsh)             \
  V(I16x8MaxU, vmaxuh)             \
  V(I16x8Eq, vcmpequh)             \
  V(I16x8GtS, vcmpgtsh)            \
  V(I16x8GtU, vcmpgtuh)            \
  V(I16x8AddSatS, vaddshs)         \
  V(I16x8SubSatS, vsubshs)         \
  V(I16x8AddSatU, vadduhs)         \
  V(I16x8SubSatU, vsubuhs)         \
  V(I16x8RoundingAverageU, vavguh) \
  V(I8x16Add, vaddubm)             \
  V(I8x16Sub, vsububm)             \
  V(I8x16MinS, vminsb)             \
  V(I8x16MinU, vminub)             \
  V(I8x16MaxS, vmaxsb)             \
  V(I8x16MaxU, vmaxub)             \
  V(I8x16Eq, vcmpequb)             \
  V(I8x16GtS, vcmpgtsb)            \
  V(I8x16GtU, vcmpgtub)            \
  V(I8x16AddSatS, vaddsbs)         \
  V(I8x16SubSatS, vsubsbs)         \
  V(I8x16AddSatU, vaddubs)         \
  V(I8x16SubSatU, vsububs)         \
  V(I8x16RoundingAverageU, vavgub) \
  V(S128And, vand)                 \
  V(S128Or, vor)                   \
  V(S128Xor, vxor)                 \
  V(S128AndNot, vandc)

#define EMIT_SIMD_BINOP(name, op)                                      \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Simd128Register src2) {                    \
    op(dst, src1, src2);                                               \
  }
SIMD_BINOP_LIST(EMIT_SIMD_BINOP)
#undef EMIT_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl, vsld)        \
  V(I64x2ShrS, vsrad)      \
  V(I64x2ShrU, vsrd)       \
  V(I32x4Shl, vslw)        \
  V(I32x4ShrS, vsraw)      \
  V(I32x4ShrU, vsrw)       \
  V(I16x8Shl, vslh)        \
  V(I16x8ShrS, vsrah)      \
  V(I16x8ShrU, vsrh)       \
  V(I8x16Shl, vslb)        \
  V(I8x16ShrS, vsrab)      \
  V(I8x16ShrU, vsrb)

#define EMIT_SIMD_SHIFT(name, op)                                      \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1, \
                            Register src2, Simd128Register scratch) {  \
    mtvsrd(scratch, src2);                                             \
    vspltb(scratch, scratch, Operand(7));                              \
    op(dst, src1, scratch);                                            \
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

#define SIMD_UNOP_LIST(V)            \
  V(F64x2Abs, xvabsdp)               \
  V(F64x2Neg, xvnegdp)               \
  V(F64x2Sqrt, xvsqrtdp)             \
  V(F64x2Ceil, xvrdpip)              \
  V(F64x2Floor, xvrdpim)             \
  V(F64x2Trunc, xvrdpiz)             \
  V(F32x4Abs, xvabssp)               \
  V(F32x4Neg, xvnegsp)               \
  V(F32x4Sqrt, xvsqrtsp)             \
  V(F32x4Ceil, xvrspip)              \
  V(F32x4Floor, xvrspim)             \
  V(F32x4Trunc, xvrspiz)             \
  V(F32x4SConvertI32x4, xvcvsxwsp)   \
  V(F32x4UConvertI32x4, xvcvuxwsp)   \
  V(I64x2Neg, vnegd)                 \
  V(I64x2SConvertI32x4Low, vupklsw)  \
  V(I64x2SConvertI32x4High, vupkhsw) \
  V(I32x4Neg, vnegw)                 \
  V(I32x4SConvertI16x8Low, vupklsh)  \
  V(I32x4SConvertI16x8High, vupkhsh) \
  V(I32x4UConvertF32x4, xvcvspuxws)  \
  V(I16x8SConvertI8x16Low, vupklsb)  \
  V(I16x8SConvertI8x16High, vupkhsb) \
  V(I8x16Popcnt, vpopcntb)

#define EMIT_SIMD_UNOP(name, op)                                        \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src) { \
    op(dst, src);                                                       \
  }
SIMD_UNOP_LIST(EMIT_SIMD_UNOP)
#undef EMIT_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define EXT_MUL(dst_even, dst_odd, mul_even, mul_odd) \
  mul_even(dst_even, src1, src2);                     \
  mul_odd(dst_odd, src1, src2);
#define SIMD_EXT_MUL_LIST(V)                         \
  V(I32x4ExtMulLowI16x8S, vmulesh, vmulosh, vmrglw)  \
  V(I32x4ExtMulHighI16x8S, vmulesh, vmulosh, vmrghw) \
  V(I32x4ExtMulLowI16x8U, vmuleuh, vmulouh, vmrglw)  \
  V(I32x4ExtMulHighI16x8U, vmuleuh, vmulouh, vmrghw) \
  V(I16x8ExtMulLowI8x16S, vmulesb, vmulosb, vmrglh)  \
  V(I16x8ExtMulHighI8x16S, vmulesb, vmulosb, vmrghh) \
  V(I16x8ExtMulLowI8x16U, vmuleub, vmuloub, vmrglh)  \
  V(I16x8ExtMulHighI8x16U, vmuleub, vmuloub, vmrghh)

#define EMIT_SIMD_EXT_MUL(name, mul_even, mul_odd, merge)                    \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1,       \
                            Simd128Register src2, Simd128Register scratch) { \
    EXT_MUL(scratch, dst, mul_even, mul_odd)                                 \
    merge(dst, scratch, dst);                                                \
  }
SIMD_EXT_MUL_LIST(EMIT_SIMD_EXT_MUL)
#undef EMIT_SIMD_EXT_MUL
#undef SIMD_EXT_MUL_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue, vcmpgtud)   \
  V(I32x4AllTrue, vcmpgtuw)   \
  V(I16x8AllTrue, vcmpgtuh)   \
  V(I8x16AllTrue, vcmpgtub)

#define EMIT_SIMD_ALL_TRUE(name, op)                              \
  void MacroAssembler::name(Register dst, Simd128Register src,    \
                            Register scratch1, Register scratch2, \
                            Simd128Register scratch3) {           \
    constexpr uint8_t fxm = 0x2; /* field mask. */                \
    constexpr int bit_number = 24;                                \
    li(scratch1, Operand(0));                                     \
    li(scratch2, Operand(1));                                     \
    /* Check if all lanes > 0, if not then return false.*/        \
    vxor(scratch3, scratch3, scratch3);                           \
    mtcrf(scratch1, fxm); /* Clear cr6.*/                         \
    op(scratch3, src, scratch3, SetRC);                           \
    isel(dst, scratch2, scratch1, bit_number);                    \
  }
SIMD_ALL_TRUE_LIST(EMIT_SIMD_ALL_TRUE)
#undef EMIT_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_BITMASK_LIST(V)                      \
  V(I64x2BitMask, vextractdm, 0x8080808080800040) \
  V(I32x4BitMask, vextractwm, 0x8080808000204060) \
  V(I16x8BitMask, vextracthm, 0x10203040506070)

#define EMIT_SIMD_BITMASK(name, op, indicies)                              \
  void MacroAssembler::name(Register dst, Simd128Register src,             \
                            Register scratch1, Simd128Register scratch2) { \
    if (CpuFeatures::IsSupported(PPC_10_PLUS)) {                           \
      op(dst, src);                                                        \
    } else {                                                               \
      mov(scratch1, Operand(indicies)); /* Select 0 for the high bits. */  \
      mtvsrd(scratch2, scratch1);                                          \
      vbpermq(scratch2, src, scratch2);                                    \
      vextractub(scratch2, scratch2, Operand(6));                          \
      mfvsrd(dst, scratch2);                                               \
    }                                                                      \
  }
SIMD_BITMASK_LIST(EMIT_SIMD_BITMASK)
#undef EMIT_SIMD_BITMASK
#undef SIMD_BITMASK_LIST

#define SIMD_QFM_LIST(V)   \
  V(F64x2Qfma, xvmaddmdp)  \
  V(F64x2Qfms, xvnmsubmdp) \
  V(F32x4Qfma, xvmaddmsp)  \
  V(F32x4Qfms, xvnmsubmsp)

#define EMIT_SIMD_QFM(name, op)                                         \
  void MacroAssembler::name(Simd128Register dst, Simd128Register src1,  \
                            Simd128Register src2, Simd128Register src3, \
                            Simd128Register scratch) {                  \
    Simd128Register dest = dst;                                         \
    if (dst != src1) {                                                  \
      vor(scratch, src1, src1);                                         \
      dest = scratch;                                                   \
    }                                                                   \
    op(dest, src2, src3);                                               \
    if (dest != dst) {                                                  \
      vor(dst, dest, dest);                                             \
    }                                                                   \
  }
SIMD_QFM_LIST(EMIT_SIMD_QFM)
#undef EMIT_SIMD_QFM
#undef SIMD_QFM_LIST

void MacroAssembler::I64x2ExtMulLowI32x4S(Simd128Register dst,
                                          Simd128Register src1,
                                          Simd128Register src2,
                                          Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  EXT_MUL(scratch, dst, vmulesw, vmulosw)
  vextractd(scratch, scratch, Operand(1 * lane_width_in_bytes));
  vinsertd(dst, scratch, Operand(0));
}

void MacroAssembler::I64x2ExtMulHighI32x4S(Simd128Register dst,
                                           Simd128Register src1,
                                           Simd128Register src2,
                                           Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  EXT_MUL(scratch, dst, vmulesw, vmulosw)
  vinsertd(scratch, dst, Operand(1 * lane_width_in_bytes));
  vor(dst, scratch, scratch);
}

void MacroAssembler::I64x2ExtMulLowI32x4U(Simd128Register dst,
                                          Simd128Register src1,
                                          Simd128Register src2,
                                          Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  EXT_MUL(scratch, dst, vmuleuw, vmulouw)
  vextractd(scratch, scratch, Operand(1 * lane_width_in_bytes));
  vinsertd(dst, scratch, Operand(0));
}

void MacroAssembler::I64x2ExtMulHighI32x4U(Simd128Register dst,
                                           Simd128Register src1,
                                           Simd128Register src2,
                                           Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  EXT_MUL(scratch, dst, vmuleuw, vmulouw)
  vinsertd(scratch, dst, Operand(1 * lane_width_in_bytes));
  vor(dst, scratch, scratch);
}
#undef EXT_MUL

void MacroAssembler::LoadSimd128LE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch) {
#ifdef V8_TARGET_BIG_ENDIAN
  LoadSimd128(dst, mem, scratch);
  xxbrq(dst, dst);
#else
  LoadSimd128(dst, mem, scratch);
#endif
}

void MacroAssembler::StoreSimd128LE(Simd128Register src, const MemOperand& mem,
                                    Register scratch1,
                                    Simd128Register scratch2) {
#ifdef V8_TARGET_BIG_ENDIAN
  xxbrq(scratch2, src);
  StoreSimd128(scratch2, mem, scratch1);
#else
  StoreSimd128(src, mem, scratch1);
#endif
}

void MacroAssembler::F64x2Splat(Simd128Register dst, DoubleRegister src,
                                Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  MovDoubleToInt64(scratch, src);
  mtvsrd(dst, scratch);
  vinsertd(dst, dst, Operand(1 * lane_width_in_bytes));
}

void MacroAssembler::F32x4Splat(Simd128Register dst, DoubleRegister src,
                                DoubleRegister scratch1, Register scratch2) {
  MovFloatToInt(scratch2, src, scratch1);
  mtvsrd(dst, scratch2);
  vspltw(dst, dst, Operand(1));
}

void MacroAssembler::I64x2Splat(Simd128Register dst, Register src) {
  constexpr int lane_width_in_bytes = 8;
  mtvsrd(dst, src);
  vinsertd(dst, dst, Operand(1 * lane_width_in_bytes));
}

void MacroAssembler::I32x4Splat(Simd128Register dst, Register src) {
  mtvsrd(dst, src);
  vspltw(dst, dst, Operand(1));
}

void MacroAssembler::I16x8Splat(Simd128Register dst, Register src) {
  mtvsrd(dst, src);
  vsplth(dst, dst, Operand(3));
}

void MacroAssembler::I8x16Splat(Simd128Register dst, Register src) {
  mtvsrd(dst, src);
  vspltb(dst, dst, Operand(7));
}

void MacroAssembler::F64x2ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx,
                                      Simd128Register scratch1,
                                      Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  vextractd(scratch1, src, Operand((1 - imm_lane_idx) * lane_width_in_bytes));
  mfvsrd(scratch2, scratch1);
  MovInt64ToDouble(dst, scratch2);
}

void MacroAssembler::F32x4ExtractLane(DoubleRegister dst, Simd128Register src,
                                      uint8_t imm_lane_idx,
                                      Simd128Register scratch1,
                                      Register scratch2, Register scratch3) {
  constexpr int lane_width_in_bytes = 4;
  vextractuw(scratch1, src, Operand((3 - imm_lane_idx) * lane_width_in_bytes));
  mfvsrd(scratch2, scratch1);
  MovIntToFloat(dst, scratch2, scratch3);
}

void MacroAssembler::I64x2ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx,
                                      Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  vextractd(scratch, src, Operand((1 - imm_lane_idx) * lane_width_in_bytes));
  mfvsrd(dst, scratch);
}

void MacroAssembler::I32x4ExtractLane(Register dst, Simd128Register src,
                                      uint8_t imm_lane_idx,
                                      Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 4;
  vextractuw(scratch, src, Operand((3 - imm_lane_idx) * lane_width_in_bytes));
  mfvsrd(dst, scratch);
}

void MacroAssembler::I16x8ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx,
                                       Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 2;
  vextractuh(scratch, src, Operand((7 - imm_lane_idx) * lane_width_in_bytes));
  mfvsrd(dst, scratch);
}

void MacroAssembler::I16x8ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx,
                                       Simd128Register scratch) {
  I16x8ExtractLaneU(dst, src, imm_lane_idx, scratch);
  extsh(dst, dst);
}

void MacroAssembler::I8x16ExtractLaneU(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx,
                                       Simd128Register scratch) {
  vextractub(scratch, src, Operand(15 - imm_lane_idx));
  mfvsrd(dst, scratch);
}

void MacroAssembler::I8x16ExtractLaneS(Register dst, Simd128Register src,
                                       uint8_t imm_lane_idx,
                                       Simd128Register scratch) {
  I8x16ExtractLaneU(dst, src, imm_lane_idx, scratch);
  extsb(dst, dst);
}

void MacroAssembler::F64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch1,
                                      Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  if (src1 != dst) {
    vor(dst, src1, src1);
  }
  MovDoubleToInt64(scratch1, src2);
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vinsd(dst, scratch1, Operand((1 - imm_lane_idx) * lane_width_in_bytes));
  } else {
    mtvsrd(scratch2, scratch1);
    vinsertd(dst, scratch2, Operand((1 - imm_lane_idx) * lane_width_in_bytes));
  }
}

void MacroAssembler::F32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      DoubleRegister src2, uint8_t imm_lane_idx,
                                      Register scratch1,
                                      DoubleRegister scratch2,
                                      Simd128Register scratch3) {
  constexpr int lane_width_in_bytes = 4;
  if (src1 != dst) {
    vor(dst, src1, src1);
  }
  MovFloatToInt(scratch1, src2, scratch2);
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vinsw(dst, scratch1, Operand((3 - imm_lane_idx) * lane_width_in_bytes));
  } else {
    mtvsrd(scratch3, scratch1);
    vinsertw(dst, scratch3, Operand((3 - imm_lane_idx) * lane_width_in_bytes));
  }
}

void MacroAssembler::I64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  if (src1 != dst) {
    vor(dst, src1, src1);
  }
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vinsd(dst, src2, Operand((1 - imm_lane_idx) * lane_width_in_bytes));
  } else {
    mtvsrd(scratch, src2);
    vinsertd(dst, scratch, Operand((1 - imm_lane_idx) * lane_width_in_bytes));
  }
}

void MacroAssembler::I32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 4;
  if (src1 != dst) {
    vor(dst, src1, src1);
  }
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vinsw(dst, src2, Operand((3 - imm_lane_idx) * lane_width_in_bytes));
  } else {
    mtvsrd(scratch, src2);
    vinsertw(dst, scratch, Operand((3 - imm_lane_idx) * lane_width_in_bytes));
  }
}

void MacroAssembler::I16x8ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Simd128Register scratch) {
  constexpr int lane_width_in_bytes = 2;
  if (src1 != dst) {
    vor(dst, src1, src1);
  }
  mtvsrd(scratch, src2);
  vinserth(dst, scratch, Operand((7 - imm_lane_idx) * lane_width_in_bytes));
}

void MacroAssembler::I8x16ReplaceLane(Simd128Register dst, Simd128Register src1,
                                      Register src2, uint8_t imm_lane_idx,
                                      Simd128Register scratch) {
  if (src1 != dst) {
    vor(dst, src1, src1);
  }
  mtvsrd(scratch, src2);
  vinsertb(dst, scratch, Operand(15 - imm_lane_idx));
}

void MacroAssembler::I64x2Mul(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Register scratch1,
                              Register scratch2, Register scratch3,
                              Simd128Register scratch4) {
  constexpr int lane_width_in_bytes = 8;
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vmulld(dst, src1, src2);
  } else {
    Register scratch_1 = scratch1;
    Register scratch_2 = scratch2;
    for (int i = 0; i < 2; i++) {
      if (i > 0) {
        vextractd(scratch4, src1, Operand(1 * lane_width_in_bytes));
        vextractd(dst, src2, Operand(1 * lane_width_in_bytes));
        src1 = scratch4;
        src2 = dst;
      }
      mfvsrd(scratch_1, src1);
      mfvsrd(scratch_2, src2);
      mulld(scratch_1, scratch_1, scratch_2);
      scratch_1 = scratch2;
      scratch_2 = scratch3;
    }
    mtvsrdd(dst, scratch1, scratch2);
  }
}

void MacroAssembler::I16x8Mul(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2) {
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vmladduhm(dst, src1, src2, kSimd128RegZero);
}

#define F64X2_MIN_MAX_NAN(result)                        \
  xvcmpeqdp(scratch2, src1, src1);                       \
  vsel(result, src1, result, scratch2);                  \
  xvcmpeqdp(scratch2, src2, src2);                       \
  vsel(dst, src2, result, scratch2);                     \
  /* Use xvmindp to turn any selected SNANs to QNANs. */ \
  xvmindp(dst, dst, dst);
void MacroAssembler::F64x2Min(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch1,
                              Simd128Register scratch2) {
  xvmindp(scratch1, src1, src2);
  // We need to check if an input is NAN and preserve it.
  F64X2_MIN_MAX_NAN(scratch1)
}

void MacroAssembler::F64x2Max(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch1,
                              Simd128Register scratch2) {
  xvmaxdp(scratch1, src1, src2);
  // We need to check if an input is NAN and preserve it.
  F64X2_MIN_MAX_NAN(scratch1)
}
#undef F64X2_MIN_MAX_NAN

void MacroAssembler::F64x2Lt(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  xvcmpgtdp(dst, src2, src1);
}

void MacroAssembler::F64x2Le(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  xvcmpgedp(dst, src2, src1);
}

void MacroAssembler::F64x2Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2, Simd128Register scratch) {
  xvcmpeqdp(scratch, src1, src2);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::F32x4Lt(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  xvcmpgtsp(dst, src2, src1);
}

void MacroAssembler::F32x4Le(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2) {
  xvcmpgesp(dst, src2, src1);
}

void MacroAssembler::F32x4Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2, Simd128Register scratch) {
  xvcmpeqsp(scratch, src1, src2);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I64x2Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2, Simd128Register scratch) {
  vcmpequd(scratch, src1, src2);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I64x2GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpgtsd(scratch, src2, src1);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I32x4Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2, Simd128Register scratch) {
  vcmpequw(scratch, src1, src2);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I32x4GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpgtsw(scratch, src2, src1);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I32x4GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpequw(scratch, src1, src2);
  vcmpgtuw(dst, src1, src2);
  vor(dst, dst, scratch);
}

void MacroAssembler::I16x8Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2, Simd128Register scratch) {
  vcmpequh(scratch, src1, src2);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I16x8GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpgtsh(scratch, src2, src1);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I16x8GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpequh(scratch, src1, src2);
  vcmpgtuh(dst, src1, src2);
  vor(dst, dst, scratch);
}

void MacroAssembler::I8x16Ne(Simd128Register dst, Simd128Register src1,
                             Simd128Register src2, Simd128Register scratch) {
  vcmpequb(scratch, src1, src2);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I8x16GeS(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpgtsb(scratch, src2, src1);
  vnor(dst, scratch, scratch);
}

void MacroAssembler::I8x16GeU(Simd128Register dst, Simd128Register src1,
                              Simd128Register src2, Simd128Register scratch) {
  vcmpequb(scratch, src1, src2);
  vcmpgtub(dst, src1, src2);
  vor(dst, dst, scratch);
}

void MacroAssembler::I64x2Abs(Simd128Register dst, Simd128Register src,
                              Simd128Register scratch) {
  constexpr int shift_bits = 63;
  xxspltib(scratch, Operand(shift_bits));
  vsrad(scratch, src, scratch);
  vxor(dst, src, scratch);
  vsubudm(dst, dst, scratch);
}
void MacroAssembler::I32x4Abs(Simd128Register dst, Simd128Register src,
                              Simd128Register scratch) {
  constexpr int shift_bits = 31;
  xxspltib(scratch, Operand(shift_bits));
  vsraw(scratch, src, scratch);
  vxor(dst, src, scratch);
  vsubuwm(dst, dst, scratch);
}
void MacroAssembler::I16x8Abs(Simd128Register dst, Simd128Register src,
                              Simd128Register scratch) {
  constexpr int shift_bits = 15;
  xxspltib(scratch, Operand(shift_bits));
  vsrah(scratch, src, scratch);
  vxor(dst, src, scratch);
  vsubuhm(dst, dst, scratch);
}
void MacroAssembler::I16x8Neg(Simd128Register dst, Simd128Register src,
                              Simd128Register scratch) {
  vspltish(scratch, Operand(1));
  vnor(dst, src, src);
  vadduhm(dst, scratch, dst);
}
void MacroAssembler::I8x16Abs(Simd128Register dst, Simd128Register src,
                              Simd128Register scratch) {
  constexpr int shift_bits = 7;
  xxspltib(scratch, Operand(shift_bits));
  vsrab(scratch, src, scratch);
  vxor(dst, src, scratch);
  vsububm(dst, dst, scratch);
}
void MacroAssembler::I8x16Neg(Simd128Register dst, Simd128Register src,
                              Simd128Register scratch) {
  xxspltib(scratch, Operand(1));
  vnor(dst, src, src);
  vaddubm(dst, scratch, dst);
}

void MacroAssembler::F64x2Pmin(Simd128Register dst, Simd128Register src1,
                               Simd128Register src2, Simd128Register scratch) {
  xvcmpgtdp(kScratchSimd128Reg, src1, src2);
  vsel(dst, src1, src2, kScratchSimd128Reg);
}

void MacroAssembler::F64x2Pmax(Simd128Register dst, Simd128Register src1,
                               Simd128Register src2, Simd128Register scratch) {
  xvcmpgtdp(kScratchSimd128Reg, src2, src1);
  vsel(dst, src1, src2, kScratchSimd128Reg);
}

void MacroAssembler::F32x4Pmin(Simd128Register dst, Simd128Register src1,
                               Simd128Register src2, Simd128Register scratch) {
  xvcmpgtsp(kScratchSimd128Reg, src1, src2);
  vsel(dst, src1, src2, kScratchSimd128Reg);
}

void MacroAssembler::F32x4Pmax(Simd128Register dst, Simd128Register src1,
                               Simd128Register src2, Simd128Register scratch) {
  xvcmpgtsp(kScratchSimd128Reg, src2, src1);
  vsel(dst, src1, src2, kScratchSimd128Reg);
}

void MacroAssembler::I32x4SConvertF32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch) {
  // NaN to 0
  xvcmpeqsp(scratch, src, src);
  vand(scratch, src, scratch);
  xvcvspsxws(dst, scratch);
}

void MacroAssembler::I16x8SConvertI32x4(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpkswss(dst, src2, src1);
}

void MacroAssembler::I16x8UConvertI32x4(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpkswus(dst, src2, src1);
}

void MacroAssembler::I8x16SConvertI16x8(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpkshss(dst, src2, src1);
}

void MacroAssembler::I8x16UConvertI16x8(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpkshus(dst, src2, src1);
}

void MacroAssembler::F64x2ConvertLowI32x4S(Simd128Register dst,
                                           Simd128Register src) {
  vupklsw(dst, src);
  xvcvsxddp(dst, dst);
}

void MacroAssembler::F64x2ConvertLowI32x4U(Simd128Register dst,
                                           Simd128Register src,
                                           Register scratch1,
                                           Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  vupklsw(dst, src);
  // Zero extend.
  mov(scratch1, Operand(0xFFFFFFFF));
  mtvsrd(scratch2, scratch1);
  vinsertd(scratch2, scratch2, Operand(1 * lane_width_in_bytes));
  vand(dst, scratch2, dst);
  xvcvuxddp(dst, dst);
}

void MacroAssembler::I64x2UConvertI32x4Low(Simd128Register dst,
                                           Simd128Register src,
                                           Register scratch1,
                                           Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  vupklsw(dst, src);
  // Zero extend.
  mov(scratch1, Operand(0xFFFFFFFF));
  mtvsrd(scratch2, scratch1);
  vinsertd(scratch2, scratch2, Operand(1 * lane_width_in_bytes));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I64x2UConvertI32x4High(Simd128Register dst,
                                            Simd128Register src,
                                            Register scratch1,
                                            Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  vupkhsw(dst, src);
  // Zero extend.
  mov(scratch1, Operand(0xFFFFFFFF));
  mtvsrd(scratch2, scratch1);
  vinsertd(scratch2, scratch2, Operand(1 * lane_width_in_bytes));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I32x4UConvertI16x8Low(Simd128Register dst,
                                           Simd128Register src,
                                           Register scratch1,
                                           Simd128Register scratch2) {
  vupklsh(dst, src);
  // Zero extend.
  mov(scratch1, Operand(0xFFFF));
  mtvsrd(scratch2, scratch1);
  vspltw(scratch2, scratch2, Operand(1));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I32x4UConvertI16x8High(Simd128Register dst,
                                            Simd128Register src,
                                            Register scratch1,
                                            Simd128Register scratch2) {
  vupkhsh(dst, src);
  // Zero extend.
  mov(scratch1, Operand(0xFFFF));
  mtvsrd(scratch2, scratch1);
  vspltw(scratch2, scratch2, Operand(1));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I16x8UConvertI8x16Low(Simd128Register dst,
                                           Simd128Register src,
                                           Register scratch1,
                                           Simd128Register scratch2) {
  vupklsb(dst, src);
  // Zero extend.
  li(scratch1, Operand(0xFF));
  mtvsrd(scratch2, scratch1);
  vsplth(scratch2, scratch2, Operand(3));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I16x8UConvertI8x16High(Simd128Register dst,
                                            Simd128Register src,
                                            Register scratch1,
                                            Simd128Register scratch2) {
  vupkhsb(dst, src);
  // Zero extend.
  li(scratch1, Operand(0xFF));
  mtvsrd(scratch2, scratch1);
  vsplth(scratch2, scratch2, Operand(3));
  vand(dst, scratch2, dst);
}

void MacroAssembler::I8x16BitMask(Register dst, Simd128Register src,
                                  Register scratch1, Register scratch2,
                                  Simd128Register scratch3) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    vextractbm(dst, src);
  } else {
    mov(scratch1, Operand(0x8101820283038));
    mov(scratch2, Operand(0x4048505860687078));
    mtvsrdd(scratch3, scratch1, scratch2);
    vbpermq(scratch3, src, scratch3);
    mfvsrd(dst, scratch3);
  }
}

void MacroAssembler::I32x4DotI16x8S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2) {
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vmsumshm(dst, src1, src2, kSimd128RegZero);
}

void MacroAssembler::I32x4DotI8x16AddS(Simd128Register dst,
                                       Simd128Register src1,
                                       Simd128Register src2,
                                       Simd128Register src3) {
  vmsummbm(dst, src1, src2, src3);
}

void MacroAssembler::I16x8DotI8x16S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2,
                                    Simd128Register scratch) {
  vmulesb(scratch, src1, src2);
  vmulosb(dst, src1, src2);
  vadduhm(dst, scratch, dst);
}

void MacroAssembler::I16x8Q15MulRSatS(Simd128Register dst, Simd128Register src1,
                                      Simd128Register src2) {
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vmhraddshs(dst, src1, src2, kSimd128RegZero);
}

void MacroAssembler::I8x16Swizzle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch) {
  // Saturate the indices to 5 bits. Input indices more than 31 should
  // return 0.
  xxspltib(scratch, Operand(31));
  vminub(scratch, src2, scratch);
  // Input needs to be reversed.
  xxbrq(dst, src1);
  vxor(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  vperm(dst, dst, kSimd128RegZero, scratch);
}

void MacroAssembler::I8x16Shuffle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2, uint64_t high,
                                  uint64_t low, Register scratch1,
                                  Register scratch2, Simd128Register scratch3) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  mtvsrdd(scratch3, scratch2, scratch1);
  vperm(dst, src1, src2, scratch3);
}

#define EXT_ADD_PAIRWISE(splat, mul_even, mul_odd, add) \
  splat(scratch1, Operand(1));                          \
  mul_even(scratch2, src, scratch1);                    \
  mul_odd(scratch1, src, scratch1);                     \
  add(dst, scratch2, scratch1);
void MacroAssembler::I32x4ExtAddPairwiseI16x8S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(vspltish, vmulesh, vmulosh, vadduwm)
}
void MacroAssembler::I32x4ExtAddPairwiseI16x8U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(vspltish, vmuleuh, vmulouh, vadduwm)
}
void MacroAssembler::I16x8ExtAddPairwiseI8x16S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(xxspltib, vmulesb, vmulosb, vadduhm)
}
void MacroAssembler::I16x8ExtAddPairwiseI8x16U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(xxspltib, vmuleub, vmuloub, vadduhm)
}
#undef EXT_ADD_PAIRWISE

void MacroAssembler::F64x2PromoteLowF32x4(Simd128Register dst,
                                          Simd128Register src) {
  constexpr int lane_number = 8;
  vextractd(dst, src, Operand(lane_number));
  vinsertw(dst, dst, Operand(lane_number));
  xvcvspdp(dst, dst);
}

void MacroAssembler::F32x4DemoteF64x2Zero(Simd128Register dst,
                                          Simd128Register src,
                                          Simd128Register scratch) {
  constexpr int lane_number = 8;
  xvcvdpsp(scratch, src);
  vextractuw(dst, scratch, Operand(lane_number));
  vinsertw(scratch, dst, Operand(4));
  vxor(dst, dst, dst);
  vinsertd(dst, scratch, Operand(lane_number));
}

void MacroAssembler::I32x4TruncSatF64x2SZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  constexpr int lane_number = 8;
  // NaN to 0.
  xvcmpeqdp(scratch, src, src);
  vand(scratch, src, scratch);
  xvcvdpsxws(scratch, scratch);
  vextractuw(dst, scratch, Operand(lane_number));
  vinsertw(scratch, dst, Operand(4));
  vxor(dst, dst, dst);
  vinsertd(dst, scratch, Operand(lane_number));
}

void MacroAssembler::I32x4TruncSatF64x2UZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  constexpr int lane_number = 8;
  xvcvdpuxws(scratch, src);
  vextractuw(dst, scratch, Operand(lane_number));
  vinsertw(scratch, dst, Operand(4));
  vxor(dst, dst, dst);
  vinsertd(dst, scratch, Operand(lane_number));
}

#if V8_TARGET_BIG_ENDIAN
#define MAYBE_REVERSE_BYTES(reg, instr) instr(reg, reg);
#else
#define MAYBE_REVERSE_BYTES(reg, instr)
#endif
void MacroAssembler::LoadLane64LE(Simd128Register dst, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  LoadSimd128Uint64(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrd)
  vinsertd(dst, scratch2, Operand((1 - lane) * lane_width_in_bytes));
}

void MacroAssembler::LoadLane32LE(Simd128Register dst, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 4;
  LoadSimd128Uint32(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrw)
  vinsertw(dst, scratch2, Operand((3 - lane) * lane_width_in_bytes));
}

void MacroAssembler::LoadLane16LE(Simd128Register dst, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 2;
  LoadSimd128Uint16(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrh)
  vinserth(dst, scratch2, Operand((7 - lane) * lane_width_in_bytes));
}

void MacroAssembler::LoadLane8LE(Simd128Register dst, const MemOperand& mem,
                                 int lane, Register scratch1,
                                 Simd128Register scratch2) {
  LoadSimd128Uint8(scratch2, mem, scratch1);
  vinsertb(dst, scratch2, Operand((15 - lane)));
}

void MacroAssembler::StoreLane64LE(Simd128Register src, const MemOperand& mem,
                                   int lane, Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  vextractd(scratch2, src, Operand((1 - lane) * lane_width_in_bytes));
  MAYBE_REVERSE_BYTES(scratch2, xxbrd)
  StoreSimd128Uint64(scratch2, mem, scratch1);
}

void MacroAssembler::StoreLane32LE(Simd128Register src, const MemOperand& mem,
                                   int lane, Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 4;
  vextractuw(scratch2, src, Operand((3 - lane) * lane_width_in_bytes));
  MAYBE_REVERSE_BYTES(scratch2, xxbrw)
  StoreSimd128Uint32(scratch2, mem, scratch1);
}

void MacroAssembler::StoreLane16LE(Simd128Register src, const MemOperand& mem,
                                   int lane, Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 2;
  vextractuh(scratch2, src, Operand((7 - lane) * lane_width_in_bytes));
  MAYBE_REVERSE_BYTES(scratch2, xxbrh)
  StoreSimd128Uint16(scratch2, mem, scratch1);
}

void MacroAssembler::StoreLane8LE(Simd128Register src, const MemOperand& mem,
                                  int lane, Register scratch1,
                                  Simd128Register scratch2) {
  vextractub(scratch2, src, Operand(15 - lane));
  StoreSimd128Uint8(scratch2, mem, scratch1);
}

void MacroAssembler::LoadAndSplat64x2LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  constexpr int lane_width_in_bytes = 8;
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vinsertd(dst, dst, Operand(1 * lane_width_in_bytes));
}

void MacroAssembler::LoadAndSplat32x4LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  LoadSimd128Uint32(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrw)
  vspltw(dst, dst, Operand(1));
}

void MacroAssembler::LoadAndSplat16x8LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  LoadSimd128Uint16(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrh)
  vsplth(dst, dst, Operand(3));
}

void MacroAssembler::LoadAndSplat8x16LE(Simd128Register dst,
                                        const MemOperand& mem,
                                        Register scratch) {
  LoadSimd128Uint8(dst, mem, scratch);
  vspltb(dst, dst, Operand(7));
}

void MacroAssembler::LoadAndExtend32x2SLE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch) {
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vupkhsw(dst, dst);
}

void MacroAssembler::LoadAndExtend32x2ULE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch1,
                                          Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  LoadAndExtend32x2SLE(dst, mem, scratch1);
  // Zero extend.
  mov(scratch1, Operand(0xFFFFFFFF));
  mtvsrd(scratch2, scratch1);
  vinsertd(scratch2, scratch2, Operand(1 * lane_width_in_bytes));
  vand(dst, scratch2, dst);
}

void MacroAssembler::LoadAndExtend16x4SLE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch) {
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vupkhsh(dst, dst);
}

void MacroAssembler::LoadAndExtend16x4ULE(Simd128Register dst,
                                          const MemOperand& mem,
                                          Register scratch1,
                                          Simd128Register scratch2) {
  LoadAndExtend16x4SLE(dst, mem, scratch1);
  // Zero extend.
  mov(scratch1, Operand(0xFFFF));
  mtvsrd(scratch2, scratch1);
  vspltw(scratch2, scratch2, Operand(1));
  vand(dst, scratch2, dst);
}

void MacroAssembler::LoadAndExtend8x8SLE(Simd128Register dst,
                                         const MemOperand& mem,
                                         Register scratch) {
  LoadSimd128Uint64(dst, mem, scratch);
  MAYBE_REVERSE_BYTES(dst, xxbrd)
  vupkhsb(dst, dst);
}

void MacroAssembler::LoadAndExtend8x8ULE(Simd128Register dst,
                                         const MemOperand& mem,
                                         Register scratch1,
                                         Simd128Register scratch2) {
  LoadAndExtend8x8SLE(dst, mem, scratch1);
  // Zero extend.
  li(scratch1, Operand(0xFF));
  mtvsrd(scratch2, scratch1);
  vsplth(scratch2, scratch2, Operand(3));
  vand(dst, scratch2, dst);
}

void MacroAssembler::LoadV64ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 8;
  LoadSimd128Uint64(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrd)
  vxor(dst, dst, dst);
  vinsertd(dst, scratch2, Operand(1 * lane_width_in_bytes));
}

void MacroAssembler::LoadV32ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch1,
                                   Simd128Register scratch2) {
  constexpr int lane_width_in_bytes = 4;
  LoadSimd128Uint32(scratch2, mem, scratch1);
  MAYBE_REVERSE_BYTES(scratch2, xxbrw)
  vxor(dst, dst, dst);
  vinsertw(dst, scratch2, Operand(3 * lane_width_in_bytes));
}
#undef MAYBE_REVERSE_BYTES

void MacroAssembler::V128AnyTrue(Register dst, Simd128Register src,
                                 Register scratch1, Register scratch2,
                                 Simd128Register scratch3) {
  constexpr uint8_t fxm = 0x2;  // field mask.
  constexpr int bit_number = 24;
  li(scratch1, Operand(0));
  li(scratch2, Operand(1));
  // Check if both lanes are 0, if so then return false.
  vxor(scratch3, scratch3, scratch3);
  mtcrf(scratch1, fxm);  // Clear cr6.
  vcmpequd(scratch3, src, scratch3, SetRC);
  isel(dst, scratch1, scratch2, bit_number);
}

void MacroAssembler::S128Not(Simd128Register dst, Simd128Register src) {
  vnor(dst, src, src);
}

void MacroAssembler::S128Const(Simd128Register dst, uint64_t high, uint64_t low,
                               Register scratch1, Register scratch2) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  mtvsrdd(dst, scratch2, scratch1);
}

void MacroAssembler::S128Select(Simd128Register dst, Simd128Register src1,
                                Simd128Register src2, Simd128Register mask) {
  vsel(dst, src2, src1, mask);
}

Register GetRegisterThatIsNotOneOf(Register reg1, Register reg2, Register reg3,
                                   Register reg4, Register reg5,
                                   Register reg6) {
  RegList regs = {reg1, reg2, reg3, reg4, reg5, reg6};

  const RegisterConfiguration* config = RegisterConfiguration::Default();
  for (int i = 0; i < config->num_allocatable_general_registers(); ++i) {
    int code = config->GetAllocatableGeneralCode(i);
    Register candidate = Register::from_code(code);
    if (regs.has(candidate)) continue;
    return candidate;
  }
  UNREACHABLE();
}

void MacroAssembler::SwapP(Register src, Register dst, Register scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  mr(scratch, src);
  mr(src, dst);
  mr(dst, scratch);
}

void MacroAssembler::SwapP(Register src, MemOperand dst, Register scratch) {
  if (dst.ra() != r0 && dst.ra().is_valid())
    DCHECK(!AreAliased(src, dst.ra(), scratch));
  if (dst.rb() != r0 && dst.rb().is_valid())
    DCHECK(!AreAliased(src, dst.rb(), scratch));
  DCHECK(!AreAliased(src, scratch));
  mr(scratch, src);
  LoadU64(src, dst, r0);
  StoreU64(scratch, dst, r0);
}

void MacroAssembler::SwapP(MemOperand src, MemOperand dst, Register scratch_0,
                           Register scratch_1) {
  if (src.ra() != r0 && src.ra().is_valid())
    DCHECK(!AreAliased(src.ra(), scratch_0, scratch_1));
  if (src.rb() != r0 && src.rb().is_valid())
    DCHECK(!AreAliased(src.rb(), scratch_0, scratch_1));
  if (dst.ra() != r0 && dst.ra().is_valid())
    DCHECK(!AreAliased(dst.ra(), scratch_0, scratch_1));
  if (dst.rb() != r0 && dst.rb().is_valid())
    DCHECK(!AreAliased(dst.rb(), scratch_0, scratch_1));
  DCHECK(!AreAliased(scratch_0, scratch_1));
  if (is_int16(src.offset()) || is_int16(dst.offset())) {
    if (!is_int16(src.offset())) {
      // swap operand
      MemOperand temp = src;
      src = dst;
      dst = temp;
    }
    LoadU64(scratch_1, dst, scratch_0);
    LoadU64(scratch_0, src);
    StoreU64(scratch_1, src);
    StoreU64(scratch_0, dst, scratch_1);
  } else {
    LoadU64(scratch_1, dst, scratch_0);
    push(scratch_1);
    LoadU64(scratch_0, src, scratch_1);
    StoreU64(scratch_0, dst, scratch_1);
    pop(scratch_1);
    StoreU64(scratch_1, src, scratch_0);
  }
}

void MacroAssembler::SwapFloat32(DoubleRegister src, DoubleRegister dst,
                                 DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  fmr(scratch, src);
  fmr(src, dst);
  fmr(dst, scratch);
}

void MacroAssembler::SwapFloat32(DoubleRegister src, MemOperand dst,
                                 DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  fmr(scratch, src);
  LoadF32(src, dst, r0);
  StoreF32(scratch, dst, r0);
}

void MacroAssembler::SwapFloat32(MemOperand src, MemOperand dst,
                                 DoubleRegister scratch_0,
                                 DoubleRegister scratch_1) {
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadF32(scratch_0, src, r0);
  LoadF32(scratch_1, dst, r0);
  StoreF32(scratch_0, dst, r0);
  StoreF32(scratch_1, src, r0);
}

void MacroAssembler::SwapDouble(DoubleRegister src, DoubleRegister dst,
                                DoubleRegister scratch) {
  if (src == dst) return;
  DCHECK(!AreAliased(src, dst, scratch));
  fmr(scratch, src);
  fmr(src, dst);
  fmr(dst, scratch);
}

void MacroAssembler::SwapDouble(DoubleRegister src, MemOperand dst,
                                DoubleRegister scratch) {
  DCHECK(!AreAliased(src, scratch));
  fmr(scratch, src);
  LoadF64(src, dst, r0);
  StoreF64(scratch, dst, r0);
}

void MacroAssembler::SwapDouble(MemOperand src, MemOperand dst,
                                DoubleRegister scratch_0,
                                DoubleRegister scratch_1) {
  DCHECK(!AreAliased(scratch_0, scratch_1));
  LoadF64(scratch_0, src, r0);
  LoadF64(scratch_1, dst, r0);
  StoreF64(scratch_0, dst, r0);
  StoreF64(scratch_1, src, r0);
}

void MacroAssembler::SwapSimd128(Simd128Register src, Simd128Register dst,
                                 Simd128Register scratch) {
  if (src == dst) return;
  vor(scratch, src, src);
  vor(src, dst, dst);
  vor(dst, scratch, scratch);
}

void MacroAssembler::SwapSimd128(Simd128Register src, MemOperand dst,
                                 Simd128Register scratch1, Register scratch2) {
  DCHECK(src != scratch1);
  LoadSimd128(scratch1, dst, scratch2);
  StoreSimd128(src, dst, scratch2);
  vor(src, scratch1, scratch1);
}

void MacroAssembler::SwapSimd128(MemOperand src, MemOperand dst,
                                 Simd128Register scratch1,
                                 Simd128Register scratch2, Register scratch3) {
  LoadSimd128(scratch1, src, scratch3);
  LoadSimd128(scratch2, dst, scratch3);

  StoreSimd128(scratch1, dst, scratch3);
  StoreSimd128(scratch2, src, scratch3);
}

void MacroAssembler::ByteReverseU16(Register dst, Register val,
                                    Register scratch) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    brh(dst, val);
    ZeroExtHalfWord(dst, dst);
    return;
  }
  rlwinm(scratch, val, 8, 16, 23);
  rlwinm(dst, val, 24, 24, 31);
  orx(dst, scratch, dst);
  ZeroExtHalfWord(dst, dst);
}

void MacroAssembler::ByteReverseU32(Register dst, Register val,
                                    Register scratch) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    brw(dst, val);
    ZeroExtWord32(dst, dst);
    return;
  }
  rotlwi(scratch, val, 8);
  rlwimi(scratch, val, 24, 0, 7);
  rlwimi(scratch, val, 24, 16, 23);
  ZeroExtWord32(dst, scratch);
}

void MacroAssembler::ByteReverseU64(Register dst, Register val, Register) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    brd(dst, val);
    return;
  }
  subi(sp, sp, Operand(kSystemPointerSize));
  std(val, MemOperand(sp));
  ldbrx(dst, MemOperand(r0, sp));
  addi(sp, sp, Operand(kSystemPointerSize));
}

void MacroAssembler::JumpIfEqual(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y), r0);
  beq(dest);
}

void MacroAssembler::JumpIfLessThan(Register x, int32_t y, Label* dest) {
  CmpS32(x, Operand(y), r0);
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
  AddS64(target, target, Operand(IsolateData::builtin_entry_table_offset()));
  LoadU64(target, MemOperand(kRootRegister, target));
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
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination,
      FieldMemOperand(code_object, Code::kSelfIndirectPointerOffset), r0);
#else
  LoadU64(destination,
          FieldMemOperand(code_object, Code::kInstructionStartOffset), r0);
#endif
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
                                    uint16_t argument_count, Register scratch) {
  DCHECK_WITH_MSG(!V8_ENABLE_LEAPTIERING_BOOL,
                  "argument_count is only used with Leaptiering");
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  Call(code);
#else
  LoadTaggedField(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  CallCodeObject(code);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object, Register scratch,
                                    JumpMode jump_mode) {
  Register code = kJavaScriptCallCodeStartRegister;
#ifdef V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  DCHECK_EQ(code, r5);
  Jump(code);
#else
  LoadTaggedField(
      code, FieldMemOperand(function_object, JSFunction::kCodeOffset), scratch);
  JumpCodeObject(code, jump_mode);
#endif
}

void MacroAssembler::StoreReturnAddressAndCall(Register target) {
  // This generates the final instruction sequence for calls to C functions
  // once an exit frame has been constructed.
  //
  // Note that this assumes the caller code (i.e. the InstructionStream object
  // currently being generated) is immovable or that the callee function cannot
  // trigger GC, since the callee function will return to it.

  static constexpr int after_call_offset = 5 * kInstrSize;
  Label start_call;
  Register dest = target;

  if (ABI_USES_FUNCTION_DESCRIPTORS) {
    // AIX/PPC64BE Linux uses a function descriptor. When calling C code be
    // aware of this descriptor and pick up values from it
    LoadU64(ToRegister(ABI_TOC_REGISTER),
            MemOperand(target, kSystemPointerSize));
    LoadU64(ip, MemOperand(target, 0));
    dest = ip;
  } else if (ABI_CALL_VIA_IP && dest != ip) {
    Move(ip, target);
    dest = ip;
  }

  LoadPC(r7);
  bind(&start_call);
  addi(r7, r7, Operand(after_call_offset));
  StoreU64(r7, MemOperand(sp, kStackFrameExtraParamSlot * kSystemPointerSize));
  Call(dest);

  DCHECK_EQ(after_call_offset - kInstrSize,
            SizeOfCodeGeneratedSince(&start_call));
}

// Check if the code object is marked for deoptimization. If it is, then it
// jumps to the CompileLazyDeoptimizedCode builtin. In order to do this we need
// to:
//    1. read from memory the word that contains that bit, which can be found in
//       the flags in the referenced {Code} object;
//    2. test kMarkedForDeoptimizationBit in those flags; and
//    3. if it is not zero then it jumps to the builtin.
void MacroAssembler::BailoutIfDeoptimized() {
  int offset = InstructionStream::kCodeOffset - InstructionStream::kHeaderSize;
  LoadTaggedField(r11, MemOperand(kJavaScriptCallCodeStartRegister, offset),
                     r0);
  LoadU32(r11, FieldMemOperand(r11, Code::kFlagsOffset), r0);
  TestBit(r11, Code::kMarkedForDeoptimizationBit);
  TailCallBuiltin(Builtin::kCompileLazyDeoptimizedCode, ne, cr0);
}

void MacroAssembler::CallForDeoptimization(Builtin target, int, Label* exit,
                                           DeoptimizeKind kind, Label* ret,
                                           Label*) {
  BlockTrampolinePoolScope block_trampoline_pool(this);
  CHECK_LE(target, Builtins::kLastTier0);
  LoadU64(ip, MemOperand(kRootRegister,
                         IsolateData::BuiltinEntrySlotOffset(target)));
  Call(ip);
  DCHECK_EQ(SizeOfCodeGeneratedSince(exit),
            (kind == DeoptimizeKind::kLazy) ? Deoptimizer::kLazyDeoptExitSize
                                            : Deoptimizer::kEagerDeoptExitSize);
}

void MacroAssembler::ZeroExtByte(Register dst, Register src) {
  clrldi(dst, src, Operand(56));
}

void MacroAssembler::ZeroExtHalfWord(Register dst, Register src) {
  clrldi(dst, src, Operand(48));
}

void MacroAssembler::ZeroExtWord32(Register dst, Register src) {
  clrldi(dst, src, Operand(32));
}

void MacroAssembler::Trap() { stop(); }
void MacroAssembler::DebugBreak() { stop(); }

void MacroAssembler::Popcnt32(Register dst, Register src) { popcntw(dst, src); }

void MacroAssembler::Popcnt64(Register dst, Register src) { popcntd(dst, src); }

void MacroAssembler::CountLeadingZerosU32(Register dst, Register src, RCBit r) {
  cntlzw(dst, src, r);
}

void MacroAssembler::CountLeadingZerosU64(Register dst, Register src, RCBit r) {
  cntlzd(dst, src, r);
}

#define COUNT_TRAILING_ZEROES_SLOW(max_count, scratch1, scratch2) \
  Label loop, done;                                               \
  li(scratch1, Operand(max_count));                               \
  mtctr(scratch1);                                                \
  mr(scratch1, src);                                              \
  li(dst, Operand::Zero());                                       \
  bind(&loop); /* while ((src & 1) == 0) */                       \
  andi(scratch2, scratch1, Operand(1));                           \
  bne(&done, cr0);                                                \
  srdi(scratch1, scratch1, Operand(1)); /* src >>= 1;*/           \
  addi(dst, dst, Operand(1));           /* dst++ */               \
  bdnz(&loop);                                                    \
  bind(&done);
void MacroAssembler::CountTrailingZerosU32(Register dst, Register src,
                                           Register scratch1, Register scratch2,
                                           RCBit r) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    cnttzw(dst, src, r);
  } else {
    COUNT_TRAILING_ZEROES_SLOW(32, scratch1, scratch2);
  }
}

void MacroAssembler::CountTrailingZerosU64(Register dst, Register src,
                                           Register scratch1, Register scratch2,
                                           RCBit r) {
  if (CpuFeatures::IsSupported(PPC_9_PLUS)) {
    cnttzd(dst, src, r);
  } else {
    COUNT_TRAILING_ZEROES_SLOW(64, scratch1, scratch2);
  }
}
#undef COUNT_TRAILING_ZEROES_SLOW

void MacroAssembler::ClearByteU64(Register dst, int byte_idx) {
  CHECK(0 <= byte_idx && byte_idx <= 7);
  int shift = byte_idx*8;
  rldicl(dst, dst, shift, 8);
  rldicl(dst, dst, 64-shift, 0);
}

void MacroAssembler::ReverseBitsU64(Register dst, Register src,
                                    Register scratch1, Register scratch2) {
  ByteReverseU64(dst, src);
  for (int i = 0; i < 8; i++) {
    ReverseBitsInSingleByteU64(dst, dst, scratch1, scratch2, i);
  }
}

void MacroAssembler::ReverseBitsU32(Register dst, Register src,
                                    Register scratch1, Register scratch2) {
  ByteReverseU32(dst, src, scratch1);
  for (int i = 4; i < 8; i++) {
    ReverseBitsInSingleByteU64(dst, dst, scratch1, scratch2, i);
  }
}

// byte_idx=7 refers to least significant byte
void MacroAssembler::ReverseBitsInSingleByteU64(Register dst, Register src,
                                                Register scratch1,
                                                Register scratch2,
                                                int byte_idx) {
  CHECK(0 <= byte_idx && byte_idx <= 7);
  int j = byte_idx;
  // zero all bits of scratch1
  li(scratch2, Operand(0));
  for (int i = 0; i <= 7; i++) {
    // zero all bits of scratch1
    li(scratch1, Operand(0));
    // move bit (j+1)*8-i-1 of src to bit j*8+i of scratch1, erase bits
    // (j*8+i+1):end of scratch1
    int shift = 7 - (2*i);
    if (shift < 0) shift += 64;
    rldicr(scratch1, src, shift, j*8+i);
    // erase bits start:(j*8-1+i) of scratch1 (inclusive)
    rldicl(scratch1, scratch1, 0, j*8+i);
    // scratch2 = scratch2|scratch1
    orx(scratch2, scratch2, scratch1);
  }
  // clear jth byte of dst and insert jth byte of scratch2
  ClearByteU64(dst, j);
  orx(dst, dst, scratch2);
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for t
```