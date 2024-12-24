Response: The user wants a summary of the C++ code provided. This is the 4th part of a 4-part file. The filename suggests it's related to code generation for the s390 architecture within the V8 JavaScript engine. It seems to define macro assembler functions, likely for generating machine code.

The code includes operations on SIMD (Single Instruction, Multiple Data) registers, conversions between integer and floating-point types, packing and unpacking of data, and saturated arithmetic. It also contains functions for loading constants into SIMD registers, shuffling and swizzling data within registers, and dot products.

The latter part of the code deals with loading and storing data with endianness considerations (LE - Little Endian), including splatting, extending, and accessing individual lanes of SIMD registers. Finally, it has functions for managing stack limits, implementing switch statements, checking code object properties (deoptimization, turbofan), and calling API functions.

Given the context of a macro assembler and the operations being performed, the code likely translates high-level SIMD and other operations into sequences of machine instructions for the s390 architecture.

To illustrate the connection to JavaScript, I should provide examples of JavaScript code that could potentially trigger the execution of these assembler functions. This will likely involve Typed Arrays and SIMD operations in JavaScript.
这个C++代码文件（`v8/src/codegen/s390/macro-assembler-s390.cc`的第4部分）是V8 JavaScript引擎中用于s390架构的宏汇编器实现的一部分。 **其主要功能是定义了一系列用于生成s390机器码的C++函数，这些函数对应于各种SIMD（单指令多数据）和常规操作。**

**具体来说，这部分代码的功能包括：**

1. **SIMD 向量数据类型转换:** 提供了在不同SIMD向量类型之间进行转换的函数，例如：
    * 浮点数到整数和无符号整数的转换 (`F32x4SConvertI32x4`, `F32x4UConvertI32x4`)
    * 整数到浮点数的转换 (`F32x4SConvertI32x4`, `F32x4UConvertI32x4`)
    * 不同位宽整数之间的转换和饱和操作 (`I16x8SConvertI32x4`, `I8x16SConvertI16x8`, `I16x8UConvertI32x4`, `I8x16UConvertI16x8`)
    * 双精度浮点数和单精度浮点数之间的转换 (`F64x2PromoteLowF32x4`, `F32x4DemoteF64x2Zero`)

2. **SIMD 向量算术和逻辑运算:** 实现了各种SIMD向量的算术运算，例如：
    * 饱和加法和减法 (`I16x8AddSatS`, `I16x8SubSatS`, `I16x8AddSatU`, `I16x8SubSatU`, `I8x16AddSatS`, `I8x16SubSatS`, `I8x16AddSatU`, `I8x16SubSatU`)
    * 成对加法 (`I32x4ExtAddPairwiseI16x8S`, `I32x4ExtAddPairwiseI16x8U`, `I16x8ExtAddPairwiseI8x16S`, `I16x8ExtAddPairwiseI8x16U`)
    * 点积运算 (`I32x4DotI16x8S`, `I32x4DotI8x16AddS`, `I16x8DotI8x16S`)
    * Q15 乘法饱和 (`I16x8Q15MulRSatS`)

3. **SIMD 常量加载和数据操作:**
    * 加载SIMD常量 (`S128Const`)
    * 向量元素混洗和置换 (`I8x16Swizzle`, `I8x16Shuffle`)

4. **SIMD 加载和存储的变体 (针对小端序):** 提供了特定的加载和存储指令，用于处理小端序数据，包括：
    * 加载并填充 (`LoadAndSplat<Type>LE`)
    * 加载并扩展 (`LoadAndExtend<Type>LE`)
    * 加载部分向量并填充零 (`LoadV32ZeroLE`, `LoadV64ZeroLE`)
    * 加载和存储向量的特定通道 (`LoadLane<Size>LE`, `StoreLane<Size>LE`)

5. **常规代码生成辅助函数:**
    * 加载堆栈限制 (`LoadStackLimit`)
    * 实现 Switch 语句 (`Switch`)
    * 检查代码对象的状态（是否标记为需要反优化，是否已进行TurboFan优化） (`JumpIfCodeIsMarkedForDeoptimization`, `JumpIfCodeIsTurbofanned`)
    * 尝试加载优化的OSR（On-Stack Replacement）代码 (`TryLoadOptimizedOsrCode`)
    * 调用 API 函数并处理返回值和异常 (`CallApiFunctionAndReturn`)

**与 JavaScript 的关系和示例:**

这部分代码直接服务于 V8 引擎执行 JavaScript 代码。当 JavaScript 代码涉及到 SIMD 操作或者需要调用 V8 内部的 API 函数时，V8 的代码生成器会根据目标架构（这里是 s390）选择相应的宏汇编器函数来生成机器码。

**JavaScript SIMD 示例:**

```javascript
// 创建一个 Int32x4 类型的数组
const a = Int32x4(1, 2, 3, 4);
const b = Int32x4(5, 6, 7, 8);

// 执行 SIMD 加法
const sum = a.add(b); // sum 将会是 Int32x4(6, 8, 10, 12)

// 访问 SIMD 向量的通道
const x = sum.x; // x 将是 6
```

当执行上述 JavaScript 代码时，V8 引擎会识别出 `Int32x4.add()` 操作，并调用 `v8/src/codegen/s390/macro-assembler-s390.cc` 中相应的函数（例如，对于整数加法，可能会有对应的 `I32x4Add` 或类似的函数，虽然这段代码中没有直接体现 `I32x4Add`，但原理类似）。这些宏汇编器函数会将 `Int32x4.add()` 操作转化为 s390 架构的向量加法指令。

**JavaScript API 调用示例:**

```javascript
// 假设有一个 C++ 扩展，它通过 V8 的 C++ API 暴露给 JavaScript
// 这个 C++ 扩展可能包含一个函数 MyExtensionFunction

// 在 JavaScript 中调用这个扩展函数
const result = myExtensionFunction(10, "hello");
```

当 JavaScript 调用 `myExtensionFunction` 时，V8 会通过 `CallApiFunctionAndReturn` 函数来调用 C++ 扩展中的函数。`CallApiFunctionAndReturn` 会负责设置必要的环境（例如 HandleScope），调用 C++ 函数，并处理返回值和可能的异常。

**总结:**

这部分 C++ 代码是 V8 引擎将 JavaScript 代码（特别是涉及 SIMD 和 API 调用的部分）转化为高效的 s390 机器码的关键组成部分。它提供了构建这些机器码指令所需的底层操作。由于这是第4部分，它可能涵盖了较为复杂或特定的 SIMD 操作和一些辅助性的代码生成功能。

Prompt: 
```
这是目录为v8/src/codegen/s390/macro-assembler-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
                  Register scratch2) {
  // vclgd or ConvertFloat32ToUnsignedInt32 will convert NaN to 0, negative to 0
  // automatically.
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vclgd(dst, src, Condition(5), Condition(0), Condition(2));
  } else {
    CONVERT_FLOAT_TO_INT32(ConvertFloat32ToUnsignedInt32, dst, src, scratch1,
                           scratch2)
  }
}
#undef CONVERT_FLOAT_TO_INT32

#define CONVERT_INT32_TO_FLOAT(convert, dst, src, scratch1, scratch2) \
  for (int index = 0; index < 4; index++) {                           \
    vlgv(scratch2, src, MemOperand(r0, index), Condition(2));         \
    convert(scratch1, scratch2);                                      \
    MovFloatToInt(scratch2, scratch1);                                \
    vlvg(dst, scratch2, MemOperand(r0, index), Condition(2));         \
  }
void MacroAssembler::F32x4SConvertI32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
                                        Register scratch2) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vcdg(dst, src, Condition(4), Condition(0), Condition(2));
  } else {
    CONVERT_INT32_TO_FLOAT(ConvertIntToFloat, dst, src, scratch1, scratch2)
  }
}
void MacroAssembler::F32x4UConvertI32x4(Simd128Register dst,
                                        Simd128Register src,
                                        Simd128Register scratch1,
                                        Register scratch2) {
  if (CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)) {
    vcdlg(dst, src, Condition(4), Condition(0), Condition(2));
  } else {
    CONVERT_INT32_TO_FLOAT(ConvertUnsignedIntToFloat, dst, src, scratch1,
                           scratch2)
  }
}
#undef CONVERT_INT32_TO_FLOAT

void MacroAssembler::I16x8SConvertI32x4(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpks(dst, src2, src1, Condition(0), Condition(2));
}

void MacroAssembler::I8x16SConvertI16x8(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2) {
  vpks(dst, src2, src1, Condition(0), Condition(1));
}

#define VECTOR_PACK_UNSIGNED(dst, src1, src2, scratch, mode)       \
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), \
     Condition(0), Condition(mode));                               \
  vmx(scratch, src1, kDoubleRegZero, Condition(0), Condition(0),   \
      Condition(mode));                                            \
  vmx(dst, src2, kDoubleRegZero, Condition(0), Condition(0), Condition(mode));
void MacroAssembler::I16x8UConvertI32x4(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2,
                                        Simd128Register scratch) {
  // treat inputs as signed, and saturate to unsigned (negative to 0).
  VECTOR_PACK_UNSIGNED(dst, src1, src2, scratch, 2)
  vpkls(dst, dst, scratch, Condition(0), Condition(2));
}

void MacroAssembler::I8x16UConvertI16x8(Simd128Register dst,
                                        Simd128Register src1,
                                        Simd128Register src2,
                                        Simd128Register scratch) {
  // treat inputs as signed, and saturate to unsigned (negative to 0).
  VECTOR_PACK_UNSIGNED(dst, src1, src2, scratch, 1)
  vpkls(dst, dst, scratch, Condition(0), Condition(1));
}
#undef VECTOR_PACK_UNSIGNED

#define BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, op, extract_high, \
                      extract_low, mode)                                     \
  DCHECK(dst != scratch1 && dst != scratch2);                                \
  DCHECK(dst != src1 && dst != src2);                                        \
  extract_high(scratch1, src1, Condition(0), Condition(0), Condition(mode)); \
  extract_high(scratch2, src2, Condition(0), Condition(0), Condition(mode)); \
  op(dst, scratch1, scratch2, Condition(0), Condition(0),                    \
     Condition(mode + 1));                                                   \
  extract_low(scratch1, src1, Condition(0), Condition(0), Condition(mode));  \
  extract_low(scratch2, src2, Condition(0), Condition(0), Condition(mode));  \
  op(scratch1, scratch1, scratch2, Condition(0), Condition(0),               \
     Condition(mode + 1));
void MacroAssembler::I16x8AddSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuph, vupl, 1)
  vpks(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I16x8SubSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuph, vupl, 1)
  vpks(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I16x8AddSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuplh, vupll, 1)
  vpkls(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I16x8SubSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuplh, vupll, 1)
  // negative intermediate values to 0.
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(0));
  vmx(dst, kDoubleRegZero, dst, Condition(0), Condition(0), Condition(2));
  vmx(scratch1, kDoubleRegZero, scratch1, Condition(0), Condition(0),
      Condition(2));
  vpkls(dst, dst, scratch1, Condition(0), Condition(2));
}

void MacroAssembler::I8x16AddSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuph, vupl, 0)
  vpks(dst, dst, scratch1, Condition(0), Condition(1));
}

void MacroAssembler::I8x16SubSatS(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuph, vupl, 0)
  vpks(dst, dst, scratch1, Condition(0), Condition(1));
}

void MacroAssembler::I8x16AddSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, va, vuplh, vupll, 0)
  vpkls(dst, dst, scratch1, Condition(0), Condition(1));
}

void MacroAssembler::I8x16SubSatU(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2,
                                  Simd128Register scratch1,
                                  Simd128Register scratch2) {
  BINOP_EXTRACT(dst, src1, src2, scratch1, scratch2, vs, vuplh, vupll, 0)
  // negative intermediate values to 0.
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(0));
  vmx(dst, kDoubleRegZero, dst, Condition(0), Condition(0), Condition(1));
  vmx(scratch1, kDoubleRegZero, scratch1, Condition(0), Condition(0),
      Condition(1));
  vpkls(dst, dst, scratch1, Condition(0), Condition(1));
}
#undef BINOP_EXTRACT

void MacroAssembler::F64x2PromoteLowF32x4(Simd128Register dst,
                                          Simd128Register src,
                                          Simd128Register scratch1,
                                          Register scratch2, Register scratch3,
                                          Register scratch4) {
  Register holder = scratch3;
  for (int index = 0; index < 2; ++index) {
    vlgv(scratch2, src, MemOperand(scratch2, index + 2), Condition(2));
    MovIntToFloat(scratch1, scratch2);
    ldebr(scratch1, scratch1);
    MovDoubleToInt64(holder, scratch1);
    holder = scratch4;
  }
  vlvgp(dst, scratch3, scratch4);
}

void MacroAssembler::F32x4DemoteF64x2Zero(Simd128Register dst,
                                          Simd128Register src,
                                          Simd128Register scratch1,
                                          Register scratch2, Register scratch3,
                                          Register scratch4) {
  Register holder = scratch3;
  for (int index = 0; index < 2; ++index) {
    vlgv(scratch2, src, MemOperand(r0, index), Condition(3));
    MovInt64ToDouble(scratch1, scratch2);
    ledbr(scratch1, scratch1);
    MovFloatToInt(holder, scratch1);
    holder = scratch4;
  }
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(2));
  vlvg(dst, scratch3, MemOperand(r0, 2), Condition(2));
  vlvg(dst, scratch4, MemOperand(r0, 3), Condition(2));
}

#define EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, lane_size, mul_even, \
                         mul_odd)                                           \
  CHECK_NE(src, scratch2);                                                  \
  vrepi(scratch2, Operand(1), Condition(lane_size));                        \
  mul_even(scratch1, src, scratch2, Condition(0), Condition(0),             \
           Condition(lane_size));                                           \
  mul_odd(scratch2, src, scratch2, Condition(0), Condition(0),              \
          Condition(lane_size));                                            \
  va(dst, scratch1, scratch2, Condition(0), Condition(0),                   \
     Condition(lane_size + 1));
void MacroAssembler::I32x4ExtAddPairwiseI16x8S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, 1, vme, vmo)
}

void MacroAssembler::I32x4ExtAddPairwiseI16x8U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register /* scratch1 */,
                                               Simd128Register /* scratch2 */) {
  // Unnamed scratch parameters are still kept to make this function
  // have the same signature as the other ExtAddPairwise functions.
  // TF and Liftoff use a uniform Macro for all of them.
  // TODO(miladfarca): Add a default argument or separate them in TF and
  // Liftoff.
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(3));
  vsum(dst, src, kDoubleRegZero, Condition(0), Condition(0), Condition(1));
}

void MacroAssembler::I16x8ExtAddPairwiseI8x16S(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, 0, vme, vmo)
}

void MacroAssembler::I16x8ExtAddPairwiseI8x16U(Simd128Register dst,
                                               Simd128Register src,
                                               Simd128Register scratch1,
                                               Simd128Register scratch2) {
  EXT_ADD_PAIRWISE(dst, src, scratch1, scratch2, 0, vmle, vmlo)
}
#undef EXT_ADD_PAIRWISE

void MacroAssembler::I32x4TruncSatF64x2SZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  // NaN to 0.
  vfce(scratch, src, src, Condition(0), Condition(0), Condition(3));
  vn(scratch, src, scratch, Condition(0), Condition(0), Condition(0));
  vcgd(scratch, scratch, Condition(5), Condition(0), Condition(3));
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(2));
  vpks(dst, dst, scratch, Condition(0), Condition(3));
}

void MacroAssembler::I32x4TruncSatF64x2UZero(Simd128Register dst,
                                             Simd128Register src,
                                             Simd128Register scratch) {
  vclgd(scratch, src, Condition(5), Condition(0), Condition(3));
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(2));
  vpkls(dst, dst, scratch, Condition(0), Condition(3));
}

void MacroAssembler::S128Const(Simd128Register dst, uint64_t high, uint64_t low,
                               Register scratch1, Register scratch2) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  vlvgp(dst, scratch2, scratch1);
}

void MacroAssembler::I8x16Swizzle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2, Register scratch1,
                                  Register scratch2, Simd128Register scratch3) {
  DCHECK(!AreAliased(src1, src2, scratch3));
  // Saturate the indices to 5 bits. Input indices more than 31 should
  // return 0.
  vrepi(scratch3, Operand(31), Condition(0));
  vmnl(scratch3, src2, scratch3, Condition(0), Condition(0), Condition(0));
  // Input needs to be reversed.
  vlgv(scratch1, src1, MemOperand(r0, 0), Condition(3));
  vlgv(scratch2, src1, MemOperand(r0, 1), Condition(3));
  lrvgr(scratch1, scratch1);
  lrvgr(scratch2, scratch2);
  vlvgp(dst, scratch2, scratch1);
  vx(kDoubleRegZero, kDoubleRegZero, kDoubleRegZero, Condition(0), Condition(0),
     Condition(0));
  vperm(dst, dst, kDoubleRegZero, scratch3, Condition(0), Condition(0));
}

void MacroAssembler::I8x16Shuffle(Simd128Register dst, Simd128Register src1,
                                  Simd128Register src2, uint64_t high,
                                  uint64_t low, Register scratch1,
                                  Register scratch2, Simd128Register scratch3) {
  mov(scratch1, Operand(low));
  mov(scratch2, Operand(high));
  vlvgp(scratch3, scratch2, scratch1);
  vperm(dst, src1, src2, scratch3, Condition(0), Condition(0));
}

void MacroAssembler::I32x4DotI16x8S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2,
                                    Simd128Register scratch) {
  vme(scratch, src1, src2, Condition(0), Condition(0), Condition(1));
  vmo(dst, src1, src2, Condition(0), Condition(0), Condition(1));
  va(dst, scratch, dst, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I32x4DotI8x16AddS(
    Simd128Register dst, Simd128Register src1, Simd128Register src2,
    Simd128Register src3, Simd128Register scratch1, Simd128Register scratch2) {
  DCHECK_NE(dst, src3);
  // I8 -> I16.
  vme(scratch1, src1, src2, Condition(0), Condition(0), Condition(0));
  vmo(dst, src1, src2, Condition(0), Condition(0), Condition(0));
  va(dst, scratch1, dst, Condition(0), Condition(0), Condition(1));
  // I16 -> I32.
  vrepi(scratch2, Operand(1), Condition(1));
  vme(scratch1, dst, scratch2, Condition(0), Condition(0), Condition(1));
  vmo(dst, dst, scratch2, Condition(0), Condition(0), Condition(1));
  va(dst, scratch1, dst, Condition(0), Condition(0), Condition(2));
  // Add src3.
  va(dst, dst, src3, Condition(0), Condition(0), Condition(2));
}

void MacroAssembler::I16x8DotI8x16S(Simd128Register dst, Simd128Register src1,
                                    Simd128Register src2,
                                    Simd128Register scratch) {
  vme(scratch, src1, src2, Condition(0), Condition(0), Condition(0));
  vmo(dst, src1, src2, Condition(0), Condition(0), Condition(0));
  va(dst, scratch, dst, Condition(0), Condition(0), Condition(1));
}

#define Q15_MUL_ROAUND(accumulator, src1, src2, const_val, scratch, unpack) \
  unpack(scratch, src1, Condition(0), Condition(0), Condition(1));          \
  unpack(accumulator, src2, Condition(0), Condition(0), Condition(1));      \
  vml(accumulator, scratch, accumulator, Condition(0), Condition(0),        \
      Condition(2));                                                        \
  va(accumulator, accumulator, const_val, Condition(0), Condition(0),       \
     Condition(2));                                                         \
  vrepi(scratch, Operand(15), Condition(2));                                \
  vesrav(accumulator, accumulator, scratch, Condition(0), Condition(0),     \
         Condition(2));
void MacroAssembler::I16x8Q15MulRSatS(Simd128Register dst, Simd128Register src1,
                                      Simd128Register src2,
                                      Simd128Register scratch1,
                                      Simd128Register scratch2,
                                      Simd128Register scratch3) {
  DCHECK(!AreAliased(src1, src2, scratch1, scratch2, scratch3));
  vrepi(scratch1, Operand(0x4000), Condition(2));
  Q15_MUL_ROAUND(scratch2, src1, src2, scratch1, scratch3, vupl)
  Q15_MUL_ROAUND(dst, src1, src2, scratch1, scratch3, vuph)
  vpks(dst, dst, scratch2, Condition(0), Condition(2));
}
#undef Q15_MUL_ROAUND

// Vector LE Load and Transform instructions.
#ifdef V8_TARGET_BIG_ENDIAN
#define IS_BIG_ENDIAN true
#else
#define IS_BIG_ENDIAN false
#endif

#define CAN_LOAD_STORE_REVERSE \
  IS_BIG_ENDIAN&& CpuFeatures::IsSupported(VECTOR_ENHANCE_FACILITY_2)

#define LOAD_SPLAT_LIST(V)       \
  V(64x2, vlbrrep, LoadU64LE, 3) \
  V(32x4, vlbrrep, LoadU32LE, 2) \
  V(16x8, vlbrrep, LoadU16LE, 1) \
  V(8x16, vlrep, LoadU8, 0)

#define LOAD_SPLAT(name, vector_instr, scalar_instr, condition)       \
  void MacroAssembler::LoadAndSplat##name##LE(                        \
      Simd128Register dst, const MemOperand& mem, Register scratch) { \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {          \
      vector_instr(dst, mem, Condition(condition));                   \
      return;                                                         \
    }                                                                 \
    scalar_instr(scratch, mem);                                       \
    vlvg(dst, scratch, MemOperand(r0, 0), Condition(condition));      \
    vrep(dst, dst, Operand(0), Condition(condition));                 \
  }
LOAD_SPLAT_LIST(LOAD_SPLAT)
#undef LOAD_SPLAT
#undef LOAD_SPLAT_LIST

#define LOAD_EXTEND_LIST(V) \
  V(32x2U, vuplh, 2)        \
  V(32x2S, vuph, 2)         \
  V(16x4U, vuplh, 1)        \
  V(16x4S, vuph, 1)         \
  V(8x8U, vuplh, 0)         \
  V(8x8S, vuph, 0)

#define LOAD_EXTEND(name, unpack_instr, condition)                            \
  void MacroAssembler::LoadAndExtend##name##LE(                               \
      Simd128Register dst, const MemOperand& mem, Register scratch) {         \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {                  \
      vlebrg(dst, mem, Condition(0));                                         \
    } else {                                                                  \
      LoadU64LE(scratch, mem);                                                \
      vlvg(dst, scratch, MemOperand(r0, 0), Condition(3));                    \
    }                                                                         \
    unpack_instr(dst, dst, Condition(0), Condition(0), Condition(condition)); \
  }
LOAD_EXTEND_LIST(LOAD_EXTEND)
#undef LOAD_EXTEND
#undef LOAD_EXTEND

void MacroAssembler::LoadV32ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch) {
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(0));
  if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {
    vlebrf(dst, mem, Condition(3));
    return;
  }
  LoadU32LE(scratch, mem);
  vlvg(dst, scratch, MemOperand(r0, 3), Condition(2));
}

void MacroAssembler::LoadV64ZeroLE(Simd128Register dst, const MemOperand& mem,
                                   Register scratch) {
  vx(dst, dst, dst, Condition(0), Condition(0), Condition(0));
  if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {
    vlebrg(dst, mem, Condition(1));
    return;
  }
  LoadU64LE(scratch, mem);
  vlvg(dst, scratch, MemOperand(r0, 1), Condition(3));
}

#define LOAD_LANE_LIST(V)     \
  V(64, vlebrg, LoadU64LE, 3) \
  V(32, vlebrf, LoadU32LE, 2) \
  V(16, vlebrh, LoadU16LE, 1) \
  V(8, vleb, LoadU8, 0)

#define LOAD_LANE(name, vector_instr, scalar_instr, condition)             \
  void MacroAssembler::LoadLane##name##LE(Simd128Register dst,             \
                                          const MemOperand& mem, int lane, \
                                          Register scratch) {              \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {               \
      vector_instr(dst, mem, Condition(lane));                             \
      return;                                                              \
    }                                                                      \
    scalar_instr(scratch, mem);                                            \
    vlvg(dst, scratch, MemOperand(r0, lane), Condition(condition));        \
  }
LOAD_LANE_LIST(LOAD_LANE)
#undef LOAD_LANE
#undef LOAD_LANE_LIST

#define STORE_LANE_LIST(V)      \
  V(64, vstebrg, StoreU64LE, 3) \
  V(32, vstebrf, StoreU32LE, 2) \
  V(16, vstebrh, StoreU16LE, 1) \
  V(8, vsteb, StoreU8, 0)

#define STORE_LANE(name, vector_instr, scalar_instr, condition)             \
  void MacroAssembler::StoreLane##name##LE(Simd128Register src,             \
                                           const MemOperand& mem, int lane, \
                                           Register scratch) {              \
    if (CAN_LOAD_STORE_REVERSE && is_uint12(mem.offset())) {                \
      vector_instr(src, mem, Condition(lane));                              \
      return;                                                               \
    }                                                                       \
    vlgv(scratch, src, MemOperand(r0, lane), Condition(condition));         \
    scalar_instr(scratch, mem);                                             \
  }
STORE_LANE_LIST(STORE_LANE)
#undef STORE_LANE
#undef STORE_LANE_LIST
#undef CAN_LOAD_STORE_REVERSE
#undef IS_BIG_ENDIAN

void MacroAssembler::LoadStackLimit(Register destination, StackLimitKind kind) {
  ASM_CODE_COMMENT(this);
  DCHECK(root_array_available());
  intptr_t offset = kind == StackLimitKind::kRealStackLimit
                        ? IsolateData::real_jslimit_offset()
                        : IsolateData::jslimit_offset();
  CHECK(is_int32(offset));
  LoadU64(destination, MemOperand(kRootRegister, offset));
}

void MacroAssembler::Switch(Register scratch, Register value,
                            int case_value_base, Label** labels,
                            int num_labels) {
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    SubS64(value, value, Operand(case_value_base));
  }
  CmpU64(value, Operand(num_labels));
  bge(&fallthrough);

  int entry_size_log2 = 3;
  ShiftLeftU32(value, value, Operand(entry_size_log2));
  larl(r1, &jump_table);
  lay(r1, MemOperand(value, r1));
  b(r1);

  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    b(labels[i]);
    dh(0);
  }
  bind(&fallthrough);
}

void MacroAssembler::JumpIfCodeIsMarkedForDeoptimization(
    Register code, Register scratch, Label* if_marked_for_deoptimization) {
  TestCodeIsMarkedForDeoptimization(code, scratch);
  bne(if_marked_for_deoptimization);
}

void MacroAssembler::JumpIfCodeIsTurbofanned(Register code, Register scratch,
                                             Label* if_turbofanned) {
  LoadU32(scratch, FieldMemOperand(code, Code::kFlagsOffset));
  TestBit(scratch, Code::kIsTurbofannedBit, scratch);
  bne(if_turbofanned);
}

void MacroAssembler::TryLoadOptimizedOsrCode(Register scratch_and_result,
                                             CodeKind min_opt_level,
                                             Register feedback_vector,
                                             FeedbackSlot slot,
                                             Label* on_result,
                                             Label::Distance) {
  Label fallthrough, clear_slot;
  LoadTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));
  LoadWeakValue(scratch_and_result, scratch_and_result, &fallthrough);

  // Is it marked_for_deoptimization? If yes, clear the slot.
  {
    // The entry references a CodeWrapper object. Unwrap it now.
    LoadTaggedField(
        scratch_and_result,
        FieldMemOperand(scratch_and_result, CodeWrapper::kCodeOffset));

    UseScratchRegisterScope temps(this);
    Register temp = temps.Acquire();
    JumpIfCodeIsMarkedForDeoptimization(scratch_and_result, temp, &clear_slot);
    if (min_opt_level == CodeKind::TURBOFAN_JS) {
      JumpIfCodeIsTurbofanned(scratch_and_result, temp, on_result);
      b(&fallthrough);
    } else {
      b(on_result);
    }
  }

  bind(&clear_slot);
  mov(scratch_and_result, ClearedValue());
  StoreTaggedField(
      scratch_and_result,
      FieldMemOperand(feedback_vector,
                      FeedbackVector::OffsetOfElementAt(slot.ToInt())));

  bind(&fallthrough);
  mov(scratch_and_result, Operand::Zero());
}

// Calls an API function. Allocates HandleScope, extracts returned value
// from handle and propagates exceptions. Clobbers C argument registers
// and C caller-saved registers. Restores context. On return removes
//   (*argc_operand + slots_to_drop_on_return) * kSystemPointerSize
// (GCed, includes the call JS arguments space and the additional space
// allocated for the fast call).
void CallApiFunctionAndReturn(MacroAssembler* masm, bool with_profiling,
                              Register function_address,
                              ExternalReference thunk_ref, Register thunk_arg,
                              int slots_to_drop_on_return,
                              MemOperand* argc_operand,
                              MemOperand return_value_operand) {
  using ER = ExternalReference;

  Isolate* isolate = masm->isolate();
  MemOperand next_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_next_address(isolate), no_reg);
  MemOperand limit_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_limit_address(isolate), no_reg);
  MemOperand level_mem_op = __ ExternalReferenceAsOperand(
      ER::handle_scope_level_address(isolate), no_reg);

  Register return_value = r2;
#if V8_OS_ZOS
  Register scratch = r6;
#else
  Register scratch = ip;
#endif
  Register scratch2 = r1;

  // Allocate HandleScope in callee-saved registers.
  // We will need to restore the HandleScope after the call to the API function,
  // by allocating it in callee-saved registers it'll be preserved by C code.
#if V8_OS_ZOS
  Register prev_next_address_reg = r14;
#else
  Register prev_next_address_reg = r6;
#endif
  Register prev_limit_reg = r7;
  Register prev_level_reg = r8;

  // C arguments (kCArgRegs[0/1]) are expected to be initialized outside, so
  // this function must not corrupt them (return_value overlaps with
  // kCArgRegs[0] but that's ok because we start using it only after the C
  // call).
  DCHECK(!AreAliased(kCArgRegs[0], kCArgRegs[1],  // C args
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  // function_address and thunk_arg might overlap but this function must not
  // corrupted them until the call is made (i.e. overlap with return_value is
  // fine).
  DCHECK(!AreAliased(function_address,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  DCHECK(!AreAliased(thunk_arg,  // incoming parameters
                     scratch, scratch2, prev_next_address_reg, prev_limit_reg));
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Allocate HandleScope in callee-save registers.");
    __ LoadU64(prev_next_address_reg, next_mem_op);
    __ LoadU64(prev_limit_reg, limit_mem_op);
    __ LoadU32(prev_level_reg, level_mem_op);
    __ AddS64(scratch, prev_level_reg, Operand(1));
    __ StoreU32(scratch, level_mem_op);
  }

  Label profiler_or_side_effects_check_enabled, done_api_call;
  if (with_profiling) {
    __ RecordComment("Check if profiler or side effects check is enabled");
    __ LoadU8(scratch,
              __ ExternalReferenceAsOperand(IsolateFieldId::kExecutionMode));
    __ CmpS64(scratch, Operand::Zero());
    __ bne(&profiler_or_side_effects_check_enabled, Label::kNear);
#ifdef V8_RUNTIME_CALL_STATS
    __ RecordComment("Check if RCS is enabled");
    __ Move(scratch, ER::address_of_runtime_stats_flag());
    __ LoadU32(scratch, MemOperand(scratch, 0));
    __ CmpS64(scratch, Operand::Zero());
    __ bne(&profiler_or_side_effects_check_enabled, Label::kNear);
#endif  // V8_RUNTIME_CALL_STATS
  }

  __ RecordComment("Call the api function directly.");
#if V8_OS_ZOS
  __ mov(scratch, function_address);
  __ zosStoreReturnAddressAndCall(function_address, scratch);
#else
  __ StoreReturnAddressAndCall(function_address);
#endif
  __ bind(&done_api_call);

  Label propagate_exception;
  Label delete_allocated_handles;
  Label leave_exit_frame;

  __ RecordComment("Load the value from ReturnValue");
  __ LoadU64(r2, return_value_operand);

  {
    ASM_CODE_COMMENT_STRING(
        masm,
        "No more valid handles (the result handle was the last one)."
        "Restore previous handle scope.");
    __ StoreU64(prev_next_address_reg, next_mem_op);
    if (v8_flags.debug_code) {
      __ LoadU32(scratch, level_mem_op);
      __ SubS64(scratch, Operand(1));
      __ CmpS64(scratch, prev_level_reg);
      __ Check(eq, AbortReason::kUnexpectedLevelAfterReturnFromApiCall);
    }
    __ StoreU32(prev_level_reg, level_mem_op);
    __ CmpS64(prev_limit_reg, limit_mem_op);
    __ bne(&delete_allocated_handles, Label::kNear);
  }

  __ RecordComment("Leave the API exit frame.");
  __ bind(&leave_exit_frame);
  Register argc_reg = prev_limit_reg;
  if (argc_operand != nullptr) {
    // Load the number of stack slots to drop before LeaveExitFrame modifies sp.
    __ LoadU64(argc_reg, *argc_operand);
  }
  __ LeaveExitFrame(scratch);

  // Check if the function scheduled an exception.
  {
    ASM_CODE_COMMENT_STRING(masm,
                            "Check if the function scheduled an exception.");
    __ LoadU64(scratch2, __ ExternalReferenceAsOperand(
                             ER::exception_address(isolate), no_reg));
    __ CompareRoot(scratch2, RootIndex::kTheHoleValue);
    __ bne(&propagate_exception, Label::kNear);
  }

  __ AssertJSAny(return_value, scratch, scratch2,
                 AbortReason::kAPICallReturnedInvalidObject);

  if (argc_operand == nullptr) {
    DCHECK_NE(slots_to_drop_on_return, 0);
    __ AddS64(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));

  } else {
    // {argc_operand} was loaded into {argc_reg} above.
    __ AddS64(sp, sp, Operand(slots_to_drop_on_return * kSystemPointerSize));
    __ ShiftLeftU64(r0, argc_reg, Operand(kSystemPointerSizeLog2));
    __ AddS64(sp, sp, r0);
  }

  __ b(r14);

  if (with_profiling) {
    ASM_CODE_COMMENT_STRING(masm, "Call the api function via thunk wrapper.");
    __ bind(&profiler_or_side_effects_check_enabled);
    // Additional parameter is the address of the actual callback function.
    if (thunk_arg.is_valid()) {
      MemOperand thunk_arg_mem_op = __ ExternalReferenceAsOperand(
          IsolateFieldId::kApiCallbackThunkArgument);
      __ StoreU64(thunk_arg, thunk_arg_mem_op);
    }
    __ Move(scratch, thunk_ref);
#if V8_OS_ZOS
    __ zosStoreReturnAddressAndCall(function_address, scratch);
#else
    __ StoreReturnAddressAndCall(scratch);
#endif
    __ b(&done_api_call);
  }

  __ RecordComment("An exception was thrown. Propagate it.");
  __ bind(&propagate_exception);
  __ TailCallRuntime(Runtime::kPropagateException);

  // HandleScope limit has changed. Delete allocated extensions.
  {
    ASM_CODE_COMMENT_STRING(
        masm, "HandleScope limit has changed. Delete allocated extensions.");
    __ bind(&delete_allocated_handles);
    __ StoreU64(prev_limit_reg, limit_mem_op);
    // Save the return value in a callee-save register.
    Register saved_result = prev_limit_reg;
    __ mov(saved_result, return_value);
    __ PrepareCallCFunction(1, scratch);
    __ Move(kCArgRegs[0], ER::isolate_address());
    __ CallCFunction(ER::delete_handle_scope_extensions(), 1);
    __ mov(return_value, saved_result);
    __ b(&leave_exit_frame, Label::kNear);
  }
}

}  // namespace internal
}  // namespace v8

#undef __

#endif  // V8_TARGET_ARCH_S390X

"""


```