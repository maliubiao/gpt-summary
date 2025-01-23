Response: The user wants a summary of the functionality of the C++ code snippet provided. This is the second part of a three-part file, suggesting the whole file implements a `MacroAssembler` for the x64 architecture in V8.

The code snippet focuses on:

1. **Vector instructions (AVX/AVX2/FMA3/F16C/AVX_VNNI/AVX_VNNI_INT8):**  It defines functions for performing various packed arithmetic, comparison, conversion, and manipulation operations on YMM and XMM registers. These operations are crucial for optimizing numerical and SIMD-like computations.
2. **Smi (Small Integer) handling:**  Functions for tagging, untagging, comparing, and converting between Smis and regular integers. Smis are a space-optimization in V8 for frequently used small integers.
3. **Object and Handle manipulation:** Functions for moving, comparing, and pushing `HeapObject`s and `Handle`s onto the stack.
4. **Code object and Builtin calls:** Functions for calling and jumping to compiled code objects and built-in functions.
5. **Stack manipulation:** Functions for pushing, popping, and dropping values from the stack.
6. **Type checking:** Functions for checking the `InstanceType` of heap objects.
7. **Utilities:** Helper functions like `Popcntl`, `Lzcntl`, `Tzcntl`, and stack handler management.
8. **Assertions (in debug mode):** Functions to assert conditions are met, helping with debugging.

The connection to JavaScript is that these low-level assembly instructions are the building blocks for implementing JavaScript's semantics efficiently. The `MacroAssembler` provides an abstraction layer over raw assembly, making it easier for V8's compiler to generate optimized machine code for JavaScript.

For the JavaScript examples, I should focus on demonstrating how the C++ functions relate to common JavaScript operations, particularly those involving:

* **Numbers and Math:** Vector instructions are used for optimizing array operations, math functions, and WebAssembly SIMD.
* **Integers:** Smi handling is fundamental to integer arithmetic in JavaScript.
* **Object access and method calls:** The object and code manipulation functions are used for accessing object properties and calling functions.
这是 `v8/src/codegen/x64/macro-assembler-x64.cc` 文件的一部分，主要负责提供 x64 架构下更高级别的汇编指令抽象，构建在底层的 `Assembler` 之上。这部分代码集中在以下功能：

**1. SIMD 向量操作 (AVX/AVX2/FMA3/F16C/AVX_VNNI/AVX_VNNI_INT8 指令集):**

* 提供了大量针对 YMM 和 XMM 寄存器的向量运算指令的封装，用于执行并行计算。这些操作涵盖了：
    * **乘法 (Multiplication):** 例如 `I64x4ExtMul`, `I32x8ExtMul`, `vpmuludq` 等，支持不同位宽的整数和浮点数乘法。
    * **加法 (Addition):** 例如 `vpaddq`, `vpaddd`, `I32x8ExtAddPairwiseI16x16S/U`, `I16x16ExtAddPairwiseI8x32S/U` 等，支持不同位宽的整数加法。
    * **最小值/最大值 (Min/Max):** 例如 `F64x4Min/Max`, `F32x8Min/Max`, `F16x8Min/Max`，用于并行比较并选择最小值或最大值。
    * **扩展乘加/减 (Fused Multiply-Add/Subtract):** 例如 `F16x8Qfma/Qfms`, `F32x8Qfma/Qfms`, `F64x4Qfma/Qfms`，利用 FMA3 指令集提高性能。
    * **类型转换 (Conversion):** 例如 `I32x8SConvertF32x8`, `I16x8SConvertF16x8`, `I16x8TruncF16x8U`，用于在不同数值类型之间进行转换。
    * **Splat (广播):** 例如 `F64x4Splat`, `F32x8Splat` 以及通过宏定义的 `name` 函数，将一个标量值广播到整个向量。
    * **点积 (Dot Product):** 例如 `I32x8DotI8x32I7x32AddS`，利用 AVX_VNNI 指令集执行高效的点积运算。

**2. Smi (小整数) 操作:**

* 提供了处理 V8 中用于表示小整数的 Smi 类型的函数：
    * `SmiTag`: 将普通整数转换为 Smi。
    * `SmiUntag`: 将 Smi 转换为普通整数。
    * `SmiToInt32`: 将 Smi 转换为 32 位整数。
    * `SmiCompare`: 比较两个 Smi。
    * `SmiAddConstant`: 将 Smi 与常量相加。
    * `SmiToIndex`: 将 Smi 转换为数组索引。
    * `CheckSmi`: 检查寄存器或操作数是否为 Smi。
    * `JumpIfSmi`/`JumpIfNotSmi`: 根据是否为 Smi 进行跳转。

**3. 对象和句柄操作:**

* 提供了操作 V8 堆中对象的函数：
    * `Move`: 将对象或句柄移动到寄存器或内存位置。
    * `Cmp`: 比较寄存器中的值与句柄。
    * `Push`: 将句柄或对象推入栈中。
    * `PushArray`: 将数组内容推入栈中。

**4. 代码对象和内置函数调用:**

* 提供了调用和跳转到代码对象的函数：
    * `CallCodeObject`: 调用代码对象。
    * `JumpCodeObject`: 跳转到代码对象。
    * `CallJSFunction`: 调用 JavaScript 函数。
    * `JumpJSFunction`: 跳转到 JavaScript 函数。
    * `CallBuiltin`: 调用内置函数。
    * `TailCallBuiltin`: 尾调用内置函数。
    * `CallBuiltinByIndex`: 通过索引调用内置函数。

**5. 栈操作:**

* 提供了操作栈的函数：
    * `Push`: 将数据推入栈。
    * `Pop`: 从栈中弹出数据。
    * `Drop`: 从栈顶丢弃指定数量的元素。
    * `DropArguments`: 丢弃函数参数。
    * `PushStackHandler`/`PopStackHandler`: 管理栈帧处理器。

**6. 类型检查:**

* 提供了检查对象类型的函数：
    * `IsObjectType`: 检查对象是否为特定类型。
    * `IsObjectTypeInRange`: 检查对象是否为指定类型范围内的类型。
    * `CmpObjectType`: 比较对象的类型与给定类型。
    * `CmpInstanceType`: 比较 Map 的 InstanceType 字段与给定类型。
    * `CmpInstanceTypeRange`: 比较 Map 的 InstanceType 字段是否在给定范围内。

**7. 其他工具函数:**

* `Lzcntl`/`Lzcntq`: 计算前导零的个数。
* `Tzcntl`/`Tzcntq`: 计算后导零的个数。
* `Popcntl`/`Popcntq`: 计算 population count (设置的位的数量)。
* `Ret`: 函数返回。
* `IncsspqIfSupported`:  如果支持 CET-SS 机制，则递增影子栈指针。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这些 C++ 代码直接服务于 V8 引擎执行 JavaScript 代码。`MacroAssembler` 提供的指令最终被编译成机器码，执行 JavaScript 程序的各种操作。

**示例 1: SIMD 向量操作与数组运算**

```javascript
// JavaScript
const arr1 = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
const arr2 = [8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0];
const result = [];
for (let i = 0; i < arr1.length; i++) {
  result.push(Math.min(arr1[i], arr2[i]));
}
console.log(result); // 输出 [1, 2, 3, 4, 4, 3, 2, 1]
```

在 V8 的底层，对于这种数组的并行最小值运算，`MacroAssembler` 中定义的 `F32x8Min` 函数 (如果目标架构支持 AVX/AVX2) 可以被用来高效地实现。它会加载 `arr1` 和 `arr2` 的部分数据到 YMM 寄存器，然后使用 `vminps` 指令并行比较 8 个单精度浮点数，并将结果存储到另一个 YMM 寄存器。

**示例 2: Smi 操作与整数运算**

```javascript
// JavaScript
let count = 10;
count++;
console.log(count); // 输出 11
```

当 JavaScript 执行 `count++` 时，如果 `count` 的值 (10) 可以表示为 Smi，V8 可能会使用 `SmiAddConstant` 这样的函数在底层执行加法操作，避免了创建完整的堆对象。

```c++
// C++ (在 MacroAssembler 中可能生成的代码片段)
  movq(rax, [rbp - offset_of_count]); // 将 count 的值加载到 rax (假设 count 是一个 Smi)
  SmiAddConstant(Operand(rbp, -offset_of_count), Smi::FromInt(1)); // 将 Smi 1 加到 count 上
```

**示例 3: 对象属性访问**

```javascript
// JavaScript
const obj = { x: 5 };
console.log(obj.x); // 输出 5
```

当访问 `obj.x` 时，V8 需要在堆中查找对象 `obj` 的属性 `x`。这可能涉及到 `LoadTaggedField` 等操作，而 `obj` 本身可能是一个句柄。

```c++
// C++ (在 MacroAssembler 中可能生成的代码片段)
  movq(rax, [rbp - offset_of_obj]); // 将 obj 的句柄加载到 rax
  LoadTaggedField(rdx, FieldOperand(rax, JSObject::kPropertiesOrHashOffset)); // 加载属性
  // ... 进一步查找属性 "x" ...
```

**总结:**

这部分 `macro-assembler-x64.cc` 代码是 V8 引擎将 JavaScript 代码转化为高效机器码的关键组成部分。它提供了对 x64 架构特性的抽象，使得编译器能够生成优化的代码，特别是针对 SIMD 运算、整数处理和对象操作等方面。这些底层的 C++ 函数支撑着 JavaScript 语言的各种功能。

### 提示词
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```
mp1, lhs, uint8_t{32});
  vpmuludq(tmp1, tmp1, rhs);
  // 2. Multiply high dword of each qword of right with left.
  vpsrlq(tmp2, rhs, uint8_t{32});
  vpmuludq(tmp2, tmp2, lhs);
  // 3. Add 1 and 2, then shift left by 32 (this is the high dword of result).
  vpaddq(tmp2, tmp2, tmp1);
  vpsllq(tmp2, tmp2, uint8_t{32});
  // 4. Multiply low dwords (this is the low dword of result).
  vpmuludq(dst, lhs, rhs);
  // 5. Add 3 and 4.
  vpaddq(dst, dst, tmp2);
}

#define DEFINE_ISPLAT(name, suffix, instr_mov)                               \
  void MacroAssembler::name(YMMRegister dst, Register src) {                 \
    ASM_CODE_COMMENT(this);                                                  \
    DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2)); \
    CpuFeatureScope avx_scope(this, AVX);                                    \
    CpuFeatureScope avx2_scope(this, AVX2);                                  \
    instr_mov(dst, src);                                                     \
    vpbroadcast##suffix(dst, dst);                                           \
  }                                                                          \
                                                                             \
  void MacroAssembler::name(YMMRegister dst, Operand src) {                  \
    ASM_CODE_COMMENT(this);                                                  \
    DCHECK(CpuFeatures::IsSupported(AVX2));                                  \
    CpuFeatureScope avx2_scope(this, AVX2);                                  \
    vpbroadcast##suffix(dst, src);                                           \
  }

MACRO_ASM_X64_ISPLAT_LIST(DEFINE_ISPLAT)

#undef DEFINE_ISPLAT

void MacroAssembler::F64x4Splat(YMMRegister dst, XMMRegister src) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx2_scope(this, AVX2);
  vbroadcastsd(dst, src);
}

void MacroAssembler::F32x8Splat(YMMRegister dst, XMMRegister src) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx2_scope(this, AVX2);
  vbroadcastss(dst, src);
}

void MacroAssembler::F64x4Min(YMMRegister dst, YMMRegister lhs, YMMRegister rhs,
                              YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  vminpd(scratch, lhs, rhs);
  vminpd(dst, rhs, lhs);
  vorpd(scratch, scratch, dst);
  vcmpunordpd(dst, dst, scratch);
  vorpd(scratch, scratch, dst);
  vpsrlq(dst, dst, uint8_t{13});
  vandnpd(dst, dst, scratch);
}

void MacroAssembler::F64x4Max(YMMRegister dst, YMMRegister lhs, YMMRegister rhs,
                              YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  vmaxpd(scratch, lhs, rhs);
  vmaxpd(dst, rhs, lhs);
  vxorpd(dst, dst, scratch);
  vorpd(scratch, scratch, dst);
  vsubpd(scratch, scratch, dst);
  vcmpunordpd(dst, dst, scratch);
  vpsrlq(dst, dst, uint8_t{13});
  vandnpd(dst, dst, scratch);
}

void MacroAssembler::F32x8Min(YMMRegister dst, YMMRegister lhs, YMMRegister rhs,
                              YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  vminps(scratch, lhs, rhs);
  vminps(dst, rhs, lhs);
  vorps(scratch, scratch, dst);
  vcmpunordps(dst, dst, scratch);
  vorps(scratch, scratch, dst);
  vpsrld(dst, dst, uint8_t{10});
  vandnps(dst, dst, scratch);
}

void MacroAssembler::F32x8Max(YMMRegister dst, YMMRegister lhs, YMMRegister rhs,
                              YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  vmaxps(scratch, lhs, rhs);
  vmaxps(dst, rhs, lhs);
  vxorps(dst, dst, scratch);
  vorps(scratch, scratch, dst);
  vsubps(scratch, scratch, dst);
  vcmpunordps(dst, dst, scratch);
  vpsrld(dst, dst, uint8_t{10});
  vandnps(dst, dst, scratch);
}

void MacroAssembler::F16x8Min(YMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                              YMMRegister scratch, YMMRegister scratch2) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  vcvtph2ps(scratch, lhs);
  vcvtph2ps(scratch2, rhs);
  // The minps instruction doesn't propagate NaNs and +0's in its first
  // operand. Perform minps in both orders, merge the results, and adjust.
  vminps(dst, scratch, scratch2);
  vminps(scratch, scratch2, scratch);
  // Propagate -0's and NaNs, which may be non-canonical.
  vorps(scratch, scratch, dst);
  // Canonicalize NaNs by quieting and clearing the payload.
  vcmpunordps(dst, dst, scratch);
  vorps(scratch, scratch, dst);
  vpsrld(dst, dst, uint8_t{10});
  vandnps(dst, dst, scratch);
  vcvtps2ph(dst, dst, 0);
}

void MacroAssembler::F16x8Max(YMMRegister dst, XMMRegister lhs, XMMRegister rhs,
                              YMMRegister scratch, YMMRegister scratch2) {
  ASM_CODE_COMMENT(this);
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  vcvtph2ps(scratch, lhs);
  vcvtph2ps(scratch2, rhs);
  // The maxps instruction doesn't propagate NaNs and +0's in its first
  // operand. Perform maxps in both orders, merge the results, and adjust.
  vmaxps(dst, scratch, scratch2);
  vmaxps(scratch, scratch2, scratch);
  // Find discrepancies.
  vxorps(dst, dst, scratch);
  // Propagate NaNs, which may be non-canonical.
  vorps(scratch, scratch, dst);
  // Propagate sign discrepancy and (subtle) quiet NaNs.
  vsubps(scratch, scratch, dst);
  // Canonicalize NaNs by clearing the payload. Sign is non-deterministic.
  vcmpunordps(dst, dst, scratch);
  vpsrld(dst, dst, uint8_t{10});
  vandnps(dst, dst, scratch);
  vcvtps2ph(dst, dst, 0);
}

// 1. Zero extend 4 packed 32-bit integers in src1 to 4 packed 64-bit integers
// in scratch
// 2. Zero extend 4 packed 32-bit integers in src2 to 4 packed 64-bit integers
// in dst
// 3. Multiply packed doubleword integers in scratch with dst, the extended zero
// are ignored
void MacroAssembler::I64x4ExtMul(YMMRegister dst, XMMRegister src1,
                                 XMMRegister src2, YMMRegister scratch,
                                 bool is_signed) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX2);
  vpmovzxdq(scratch, src1);
  vpmovzxdq(dst, src2);
  if (is_signed) {
    vpmuldq(dst, scratch, dst);
  } else {
    vpmuludq(dst, scratch, dst);
  }
}

// 1. Extend 8 packed 16-bit integers in src1 to 8 packed 32-bit integers in
// scratch
// 2. Extend 8 packed 16-bit integers in src2 to 8 packed 32-bit integers in dst
// 3. Multiply the packed doubleword integers in scratch and dst and store the
// low 32 bits of each product in dst.
void MacroAssembler::I32x8ExtMul(YMMRegister dst, XMMRegister src1,
                                 XMMRegister src2, YMMRegister scratch,
                                 bool is_signed) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX2);
  is_signed ? vpmovsxwd(scratch, src1) : vpmovzxwd(scratch, src1);
  is_signed ? vpmovsxwd(dst, src2) : vpmovzxwd(dst, src2);
  vpmulld(dst, dst, scratch);
}

void MacroAssembler::I16x16ExtMul(YMMRegister dst, XMMRegister src1,
                                  XMMRegister src2, YMMRegister scratch,
                                  bool is_signed) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX2);
  is_signed ? vpmovsxbw(scratch, src1) : vpmovzxbw(scratch, src1);
  is_signed ? vpmovsxbw(dst, src2) : vpmovzxbw(dst, src2);
  vpmullw(dst, dst, scratch);
}

void MacroAssembler::I32x8ExtAddPairwiseI16x16S(YMMRegister dst,
                                                YMMRegister src,
                                                YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx2_scope(this, AVX2);
  Move(scratch, uint32_t{1});
  vpbroadcastw(scratch, scratch);
  // vpmaddwd multiplies signed words in src and op, producing
  // signed doublewords, then adds pairwise.
  // src = |l0|l1|...|l14|l15|
  // dst = |l0*1+l1*1|l2*1+l3*1|...|l14*1+l15*1|
  vpmaddwd(dst, src, scratch);
}

void MacroAssembler::I32x8ExtAddPairwiseI16x16U(YMMRegister dst,
                                                YMMRegister src,
                                                YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx2_scope(this, AVX2);
  // src = |l0|l1|...l14|l15|
  // scratch = |0|l0|0|l2|...|0|l14|
  vpsrld(scratch, src, 16);
  // dst = |0|l1|0|l3|...|0|l15|
  vpblendw(dst, src, scratch, 0xAA);
  vpaddd(dst, dst, scratch);
}

void MacroAssembler::I16x16ExtAddPairwiseI8x32S(YMMRegister dst,
                                                YMMRegister src,
                                                YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx2_scope(this, AVX2);
  Move(scratch, uint32_t{1});
  vpbroadcastb(scratch, scratch);
  // pmaddubsw treats the first operand as unsigned, so scratch here should
  // be first operand
  // src = |l0|l1|...|l34|l35|
  // dst = |l0*1+l1*1|l2*1+l3*1|...|l34*1+l35*1|
  vpmaddubsw(dst, scratch, src);
}

void MacroAssembler::I16x16ExtAddPairwiseI8x32U(YMMRegister dst,
                                                YMMRegister src,
                                                YMMRegister scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx2_scope(this, AVX2);
  Move(scratch, uint32_t{1});
  vpbroadcastb(scratch, scratch);
  vpmaddubsw(dst, src, scratch);
}

void MacroAssembler::I32x8SConvertF32x8(YMMRegister dst, YMMRegister src,
                                        YMMRegister tmp, Register scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  Operand int32_overflow_as_float = ExternalReferenceAsOperand(
      ExternalReference::address_of_wasm_i32x8_int32_overflow_as_float(),
      scratch);
  // This algorithm works by:
  // 1. lanes with NaNs are zero-ed
  // 2. lanes ge than 2147483648.0f (MAX_INT32+1) set to 0xffff'ffff
  // 3. cvttps2dq sets all out of range lanes to 0x8000'0000
  //   a. correct for underflows (< MIN_INT32)
  //   b. wrong for overflow, and we know which lanes overflow from 2.
  // 4. adjust for 3b by xor-ing 2 and 3
  //   a. 0x8000'0000 xor 0xffff'ffff = 0x7fff'ffff (MAX_INT32)
  vcmpeqps(tmp, src, src);
  vandps(dst, src, tmp);
  vcmpgeps(tmp, src, int32_overflow_as_float);
  vcvttps2dq(dst, dst);
  vpxor(dst, dst, tmp);
}

void MacroAssembler::I16x8SConvertF16x8(YMMRegister dst, XMMRegister src,
                                        YMMRegister tmp, Register scratch) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2) &&
         CpuFeatures::IsSupported(F16C));

  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);

  Operand op = ExternalReferenceAsOperand(
      ExternalReference::address_of_wasm_i32x8_int32_overflow_as_float(),
      scratch);
  // Convert source f16 to f32.
  vcvtph2ps(dst, src);
  // Compare it to itself, NaNs are turn to 0s because don't equal to itself.
  vcmpeqps(tmp, dst, dst);
  // Reset NaNs.
  vandps(dst, dst, tmp);
  // Detect positive Infinity as an overflow above MAX_INT32.
  vcmpgeps(tmp, dst, op);
  // Convert f32 to i32.
  vcvttps2dq(dst, dst);
  // cvttps2dq sets all out of range lanes to 0x8000'0000,
  // but as soon as source values are result of conversion from f16,
  // and so less than MAX_INT32, only +Infinity is an issue.
  // Convert all infinities to MAX_INT32 and let vpackssdw
  // clamp it to MAX_INT16 later.
  // 0x8000'0000 xor 0xffff'ffff(from 2 steps before) = 0x7fff'ffff (MAX_INT32)
  vpxor(dst, dst, tmp);
  // We now have 8 i32 values. Using one character per 16 bits:
  // dst: [AABBCCDDEEFFGGHH]
  // Create a copy of the upper four values in the lower half of {tmp}
  // (so the upper half of the immediate doesn't matter):
  vpermq(tmp, dst, 0x4E);  // 0b01001110
  // tmp: [EEFFGGHHAABBCCDD]
  // Now pack them together as i16s. Note that {vpackssdw} interleaves
  // 128-bit chunks from each input, and takes care of saturating each
  // value to kMinInt16 and kMaxInt16. We will then ignore the upper half
  // of {dst}.
  vpackssdw(dst, dst, tmp);
  // dst: [EFGHABCDABCDEFGH]
  //       <--><--><--><-->
  //         ↑   ↑   ↑   └── from lower half of {dst}
  //         │   │   └────── from lower half of {tmp}
  //         │   └────────── from upper half of {dst} (ignored)
  //         └────────────── from upper half of {tmp} (ignored)
}

void MacroAssembler::I16x8TruncF16x8U(YMMRegister dst, XMMRegister src,
                                      YMMRegister tmp) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2) &&
         CpuFeatures::IsSupported(F16C));

  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);

  Operand op = ExternalReferenceAsOperand(
      ExternalReference::address_of_wasm_i32x8_int32_overflow_as_float(),
      kScratchRegister);
  vcvtph2ps(dst, src);
  // NAN->0, negative->0.
  vpxor(tmp, tmp, tmp);
  vmaxps(dst, dst, tmp);
  // Detect positive Infinity as an overflow above MAX_INT32.
  vcmpgeps(tmp, dst, op);
  // Convert to int.
  vcvttps2dq(dst, dst);
  // cvttps2dq sets all out of range lanes to 0x8000'0000,
  // but as soon as source values are result of conversion from f16,
  // and so less than MAX_INT32, only +Infinity is an issue.
  // Convert all infinities to MAX_INT32 and let vpackusdw
  // clamp it to MAX_INT16 later.
  // 0x8000'0000 xor 0xffff'ffff(from 2 steps before) = 0x7fff'ffff (MAX_INT32)
  vpxor(dst, dst, tmp);
  // Move high part to a spare register.
  // See detailed comment in {I16x8SConvertF16x8} for how this works.
  vpermq(tmp, dst, 0x4E);  // 0b01001110
  vpackusdw(dst, dst, tmp);
}

void MacroAssembler::F16x8Qfma(YMMRegister dst, XMMRegister src1,
                               XMMRegister src2, XMMRegister src3,
                               YMMRegister tmp, YMMRegister tmp2) {
  CpuFeatureScope fma3_scope(this, FMA3);
  CpuFeatureScope f16c_scope(this, F16C);

  if (dst.code() == src2.code()) {
    vcvtph2ps(dst, dst);
    vcvtph2ps(tmp, src1);
    vcvtph2ps(tmp2, src3);
    vfmadd213ps(dst, tmp, tmp2);
  } else if (dst.code() == src3.code()) {
    vcvtph2ps(dst, dst);
    vcvtph2ps(tmp, src2);
    vcvtph2ps(tmp2, src1);
    vfmadd231ps(dst, tmp, tmp2);
  } else {
    vcvtph2ps(dst, src1);
    vcvtph2ps(tmp, src2);
    vcvtph2ps(tmp2, src3);
    vfmadd213ps(dst, tmp, tmp2);
  }
  vcvtps2ph(dst, dst, 0);
}

void MacroAssembler::F16x8Qfms(YMMRegister dst, XMMRegister src1,
                               XMMRegister src2, XMMRegister src3,
                               YMMRegister tmp, YMMRegister tmp2) {
  CpuFeatureScope fma3_scope(this, FMA3);
  CpuFeatureScope f16c_scope(this, F16C);

  if (dst.code() == src2.code()) {
    vcvtph2ps(dst, dst);
    vcvtph2ps(tmp, src1);
    vcvtph2ps(tmp2, src3);
    vfnmadd213ps(dst, tmp, tmp2);
  } else if (dst.code() == src3.code()) {
    vcvtph2ps(dst, dst);
    vcvtph2ps(tmp, src2);
    vcvtph2ps(tmp2, src1);
    vfnmadd231ps(dst, tmp, tmp2);
  } else {
    vcvtph2ps(dst, src1);
    vcvtph2ps(tmp, src2);
    vcvtph2ps(tmp2, src3);
    vfnmadd213ps(dst, tmp, tmp2);
  }
  vcvtps2ph(dst, dst, 0);
}

void MacroAssembler::F32x8Qfma(YMMRegister dst, YMMRegister src1,
                               YMMRegister src2, YMMRegister src3,
                               YMMRegister tmp) {
  QFMA(ps);
}

void MacroAssembler::F32x8Qfms(YMMRegister dst, YMMRegister src1,
                               YMMRegister src2, YMMRegister src3,
                               YMMRegister tmp) {
  QFMS(ps);
}

void MacroAssembler::F64x4Qfma(YMMRegister dst, YMMRegister src1,
                               YMMRegister src2, YMMRegister src3,
                               YMMRegister tmp) {
  QFMA(pd);
}

void MacroAssembler::F64x4Qfms(YMMRegister dst, YMMRegister src1,
                               YMMRegister src2, YMMRegister src3,
                               YMMRegister tmp) {
  QFMS(pd);
}

void MacroAssembler::I32x8DotI8x32I7x32AddS(YMMRegister dst, YMMRegister src1,
                                            YMMRegister src2, YMMRegister src3,
                                            YMMRegister scratch,
                                            YMMRegister splat_reg) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  // It's guaranteed in instruction selector
  DCHECK_EQ(dst, src3);
  if (CpuFeatures::IsSupported(AVX_VNNI_INT8)) {
    CpuFeatureScope avx_vnni_int8_scope(this, AVX_VNNI_INT8);
    vpdpbssd(dst, src2, src1);
    return;
  } else if (CpuFeatures::IsSupported(AVX_VNNI)) {
    CpuFeatureScope avx_scope(this, AVX_VNNI);
    vpdpbusd(dst, src2, src1);
    return;
  }

  DCHECK_NE(scratch, splat_reg);
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);
  // splat_reg = i16x16.splat(1)
  vpcmpeqd(splat_reg, splat_reg, splat_reg);
  vpsrlw(splat_reg, splat_reg, uint8_t{15});
  vpmaddubsw(scratch, src2, src1);
  vpmaddwd(scratch, splat_reg, scratch);
  vpaddd(dst, src3, scratch);
}

void MacroAssembler::I32x8TruncF32x8U(YMMRegister dst, YMMRegister src,
                                      YMMRegister scratch1,
                                      YMMRegister scratch2) {
  ASM_CODE_COMMENT(this);
  DCHECK(CpuFeatures::IsSupported(AVX) && CpuFeatures::IsSupported(AVX2));
  CpuFeatureScope avx_scope(this, AVX);
  CpuFeatureScope avx2_scope(this, AVX2);

  // NAN->0, negative->0.
  vpxor(scratch1, scratch1, scratch1);
  vmaxps(dst, src, scratch1);
  // scratch1: float representation of max_signed.
  vpcmpeqd(scratch1, scratch1, scratch1);
  vpsrld(scratch1, scratch1, uint8_t{1});  // 0x7fffffff
  vcvtdq2ps(scratch1, scratch1);           // 0x4f000000
  // scratch2: convert (src-max_signed).
  // Set positive overflow lanes to 0x7FFFFFFF.
  // Set negative lanes to 0.
  vsubps(scratch2, dst, scratch1);

  vcmpleps(scratch1, scratch1, scratch2);
  vcvttps2dq(scratch2, scratch2);
  vpxor(scratch2, scratch2, scratch1);
  vpxor(scratch1, scratch1, scratch1);
  vpmaxsd(scratch2, scratch2, scratch1);
  // Convert to int. Overflow lanes above max_signed will be 0x80000000.
  vcvttps2dq(dst, dst);
  // Add (src-max_signed) for overflow lanes.
  vpaddd(dst, dst, scratch2);
}

void MacroAssembler::SmiTag(Register reg) {
  static_assert(kSmiTag == 0);
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  if (COMPRESS_POINTERS_BOOL) {
    DCHECK_EQ(kSmiShift, 1);
    addl(reg, reg);
  } else {
    shlq(reg, Immediate(kSmiShift));
  }
#ifdef ENABLE_SLOW_DCHECKS
  ClobberDecompressedSmiBits(reg);
#endif
}

void MacroAssembler::SmiTag(Register dst, Register src) {
  DCHECK(dst != src);
  if (COMPRESS_POINTERS_BOOL) {
    movl(dst, src);
  } else {
    movq(dst, src);
  }
  SmiTag(dst);
}

void MacroAssembler::SmiUntag(Register reg) {
  static_assert(kSmiTag == 0);
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  // TODO(v8:7703): Is there a way to avoid this sign extension when pointer
  // compression is enabled?
  if (COMPRESS_POINTERS_BOOL) {
    sarl(reg, Immediate(kSmiShift));
    movsxlq(reg, reg);
  } else {
    sarq(reg, Immediate(kSmiShift));
  }
}

void MacroAssembler::SmiUntagUnsigned(Register reg) {
  static_assert(kSmiTag == 0);
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  if (COMPRESS_POINTERS_BOOL) {
    AssertSignedBitOfSmiIsZero(reg);
    shrl(reg, Immediate(kSmiShift));
  } else {
    shrq(reg, Immediate(kSmiShift));
  }
}

void MacroAssembler::SmiUntag(Register dst, Register src) {
  DCHECK(dst != src);
  if (COMPRESS_POINTERS_BOOL) {
    movsxlq(dst, src);
  } else {
    movq(dst, src);
  }
  // TODO(v8:7703): Call SmiUntag(reg) if we can find a way to avoid the extra
  // mov when pointer compression is enabled.
  static_assert(kSmiTag == 0);
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  sarq(dst, Immediate(kSmiShift));
}

void MacroAssembler::SmiUntag(Register dst, Operand src) {
  if (SmiValuesAre32Bits()) {
    // Sign extend to 64-bit.
    movsxlq(dst, Operand(src, kSmiShift / kBitsPerByte));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      movsxlq(dst, src);
    } else {
      movq(dst, src);
    }
    sarq(dst, Immediate(kSmiShift));
  }
}

void MacroAssembler::SmiUntagUnsigned(Register dst, Operand src) {
  if (SmiValuesAre32Bits()) {
    // Zero extend to 64-bit.
    movl(dst, Operand(src, kSmiShift / kBitsPerByte));
  } else {
    DCHECK(SmiValuesAre31Bits());
    if (COMPRESS_POINTERS_BOOL) {
      movl(dst, src);
      AssertSignedBitOfSmiIsZero(dst);
      shrl(dst, Immediate(kSmiShift));
    } else {
      movq(dst, src);
      shrq(dst, Immediate(kSmiShift));
    }
  }
}

void MacroAssembler::SmiToInt32(Register reg) {
  AssertSmi(reg);
  static_assert(kSmiTag == 0);
  DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
  if (COMPRESS_POINTERS_BOOL) {
    sarl(reg, Immediate(kSmiShift));
  } else {
    shrq(reg, Immediate(kSmiShift));
  }
}

void MacroAssembler::SmiToInt32(Register dst, Register src) {
  if (dst != src) {
    mov_tagged(dst, src);
  }
  SmiToInt32(dst);
}

void MacroAssembler::SmiCompare(Register smi1, Register smi2) {
  AssertSmi(smi1);
  AssertSmi(smi2);
  cmp_tagged(smi1, smi2);
}

void MacroAssembler::SmiCompare(Register dst, Tagged<Smi> src) {
  AssertSmi(dst);
  Cmp(dst, src);
}

void MacroAssembler::Cmp(Register dst, Tagged<Smi> src) {
  if (src.value() == 0) {
    test_tagged(dst, dst);
  } else if (COMPRESS_POINTERS_BOOL) {
    cmp_tagged(dst, Immediate(src));
  } else {
    DCHECK_NE(dst, kScratchRegister);
    Register constant_reg = GetSmiConstant(src);
    cmp_tagged(dst, constant_reg);
  }
}

void MacroAssembler::SmiCompare(Register dst, Operand src) {
  AssertSmi(dst);
  AssertSmi(src);
  cmp_tagged(dst, src);
}

void MacroAssembler::SmiCompare(Operand dst, Register src) {
  AssertSmi(dst);
  AssertSmi(src);
  cmp_tagged(dst, src);
}

void MacroAssembler::SmiCompare(Operand dst, Tagged<Smi> src) {
  AssertSmi(dst);
  if (SmiValuesAre32Bits()) {
    cmpl(Operand(dst, kSmiShift / kBitsPerByte), Immediate(src.value()));
  } else {
    DCHECK(SmiValuesAre31Bits());
    cmpl(dst, Immediate(src));
  }
}

void MacroAssembler::Cmp(Operand dst, Tagged<Smi> src) {
  // The Operand cannot use the smi register.
  Register smi_reg = GetSmiConstant(src);
  DCHECK(!dst.AddressUsesRegister(smi_reg));
  cmp_tagged(dst, smi_reg);
}

void MacroAssembler::ClobberDecompressedSmiBits(Register src) {
#ifdef V8_COMPRESS_POINTERS
  ASM_CODE_COMMENT(this);
  static constexpr unsigned int clobber_mask = 0x515151;
  static constexpr int rot_to_unused =
      64 - kSmiShiftSize - kSmiTagSize - kSmiValueSize;
  rolq(src, Immediate(rot_to_unused));
  xorq(src, Immediate(clobber_mask));
  rorq(src, Immediate(rot_to_unused));
#endif
}

Condition MacroAssembler::CheckSmi(Register src) {
  static_assert(kSmiTag == 0);
  testb(src, Immediate(kSmiTagMask));
  return zero;
}

Condition MacroAssembler::CheckSmi(Operand src) {
  static_assert(kSmiTag == 0);
  testb(src, Immediate(kSmiTagMask));
  return zero;
}

void MacroAssembler::JumpIfSmi(Register src, Label* on_smi,
                               Label::Distance near_jump) {
  Condition smi = CheckSmi(src);
  j(smi, on_smi, near_jump);
}

void MacroAssembler::JumpIfNotSmi(Register src, Label* on_not_smi,
                                  Label::Distance near_jump) {
  Condition smi = CheckSmi(src);
  j(NegateCondition(smi), on_not_smi, near_jump);
}

void MacroAssembler::JumpIfNotSmi(Operand src, Label* on_not_smi,
                                  Label::Distance near_jump) {
  Condition smi = CheckSmi(src);
  j(NegateCondition(smi), on_not_smi, near_jump);
}

void MacroAssembler::SmiAddConstant(Operand dst, Tagged<Smi> constant) {
  if (constant.value() != 0) {
    if (SmiValuesAre32Bits()) {
      addl(Operand(dst, kSmiShift / kBitsPerByte), Immediate(constant.value()));
    } else {
      DCHECK(SmiValuesAre31Bits());
      if (kTaggedSize == kInt64Size) {
        // Sign-extend value after addition
        movl(kScratchRegister, dst);
        addl(kScratchRegister, Immediate(constant));
        movsxlq(kScratchRegister, kScratchRegister);
        movq(dst, kScratchRegister);
      } else {
        DCHECK_EQ(kTaggedSize, kInt32Size);
        addl(dst, Immediate(constant));
      }
    }
  }
}

SmiIndex MacroAssembler::SmiToIndex(Register dst, Register src, int shift) {
  if (SmiValuesAre32Bits()) {
    DCHECK(is_uint6(shift));
    // There is a possible optimization if shift is in the range 60-63, but that
    // will (and must) never happen.
    if (dst != src) {
      movq(dst, src);
    }
    if (shift < kSmiShift) {
      sarq(dst, Immediate(kSmiShift - shift));
    } else {
      shlq(dst, Immediate(shift - kSmiShift));
    }
    return SmiIndex(dst, times_1);
  } else {
    DCHECK(SmiValuesAre31Bits());
    // We have to sign extend the index register to 64-bit as the SMI might
    // be negative.
    movsxlq(dst, src);
    if (shift < kSmiShift) {
      sarq(dst, Immediate(kSmiShift - shift));
    } else if (shift != kSmiShift) {
      if (shift - kSmiShift <= static_cast<int>(times_8)) {
        return SmiIndex(dst, static_cast<ScaleFactor>(shift - kSmiShift));
      }
      shlq(dst, Immediate(shift - kSmiShift));
    }
    return SmiIndex(dst, times_1);
  }
}

void MacroAssembler::Switch(Register scratch, Register reg, int case_value_base,
                            Label** labels, int num_labels) {
  Register table = scratch;
  Label fallthrough, jump_table;
  if (case_value_base != 0) {
    subq(reg, Immediate(case_value_base));
  }
  cmpq(reg, Immediate(num_labels));
  j(above_equal, &fallthrough);
  leaq(table, MemOperand(&jump_table));
#ifdef V8_ENABLE_CET_IBT
  // Add the notrack prefix to disable landing pad enforcement.
  jmp(MemOperand(table, reg, times_8, 0), /*notrack=*/true);
#else
  jmp(MemOperand(table, reg, times_8, 0));
#endif
  // Emit the jump table inline, under the assumption that it's not too big.
  Align(kSystemPointerSize);
  bind(&jump_table);
  for (int i = 0; i < num_labels; ++i) {
    dq(labels[i]);
  }
  bind(&fallthrough);
}

void MacroAssembler::Push(Tagged<Smi> source) {
  intptr_t smi = static_cast<intptr_t>(source.ptr());
  if (is_int32(smi)) {
    Push(Immediate(static_cast<int32_t>(smi)));
    return;
  }
  int first_byte_set = base::bits::CountTrailingZeros64(smi) / 8;
  int last_byte_set = (63 - base::bits::CountLeadingZeros64(smi)) / 8;
  if (first_byte_set == last_byte_set) {
    // This sequence has only 7 bytes, compared to the 12 bytes below.
    Push(Immediate(0));
    movb(Operand(rsp, first_byte_set),
         Immediate(static_cast<int8_t>(smi >> (8 * first_byte_set))));
    return;
  }
  Register constant = GetSmiConstant(source);
  Push(constant);
}

// ----------------------------------------------------------------------------

void MacroAssembler::Move(Register dst, Tagged<Smi> source) {
  static_assert(kSmiTag == 0);
  int value = source.value();
  if (value == 0) {
    xorl(dst, dst);
  } else if (SmiValuesAre32Bits()) {
    Move(dst, source.ptr(), RelocInfo::NO_INFO);
  } else {
    uint32_t uvalue = static_cast<uint32_t>(source.ptr());
    Move(dst, uvalue);
  }
}

void MacroAssembler::Move(Operand dst, intptr_t x) {
  if (is_int32(x)) {
    movq(dst, Immediate(static_cast<int32_t>(x)));
  } else {
    Move(kScratchRegister, x);
    movq(dst, kScratchRegister);
  }
}

void MacroAssembler::Move(Register dst, ExternalReference ext) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available()) {
    if (ext.IsIsolateFieldId()) {
      leaq(dst, Operand(kRootRegister, ext.offset_from_root_register()));
      return;
    } else if (options().isolate_independent_code) {
      IndirectLoadExternalReference(dst, ext);
      return;
    }
  }
  // External references should not get created with IDs if
  // `!root_array_available()`.
  CHECK(!ext.IsIsolateFieldId());
  movq(dst, Immediate64(ext.address(), RelocInfo::EXTERNAL_REFERENCE));
}

void MacroAssembler::Move(Register dst, Register src) {
  if (dst != src) {
    movq(dst, src);
  }
}

void MacroAssembler::Move(Register dst, Operand src) { movq(dst, src); }
void MacroAssembler::Move(Register dst, Immediate src) {
  if (src.rmode() == RelocInfo::Mode::NO_INFO) {
    Move(dst, src.value());
  } else {
    movl(dst, src);
  }
}

void MacroAssembler::Move(XMMRegister dst, XMMRegister src) {
  if (dst != src) {
    Movaps(dst, src);
  }
}

void MacroAssembler::MovePair(Register dst0, Register src0, Register dst1,
                              Register src1) {
  if (dst0 != src1) {
    // Normal case: Writing to dst0 does not destroy src1.
    Move(dst0, src0);
    Move(dst1, src1);
  } else if (dst1 != src0) {
    // Only dst0 and src1 are the same register,
    // but writing to dst1 does not destroy src0.
    Move(dst1, src1);
    Move(dst0, src0);
  } else {
    // dst0 == src1, and dst1 == src0, a swap is required:
    // dst0 \/ src0
    // dst1 /\ src1
    xchgq(dst0, dst1);
  }
}

void MacroAssembler::MoveNumber(Register dst, double value) {
  int32_t smi;
  if (DoubleToSmiInteger(value, &smi)) {
    Move(dst, Smi::FromInt(smi));
  } else {
    movq_heap_number(dst, value);
  }
}

void MacroAssembler::Move(XMMRegister dst, uint32_t src) {
  if (src == 0) {
    Xorps(dst, dst);
  } else {
    unsigned nlz = base::bits::CountLeadingZeros(src);
    unsigned ntz = base::bits::CountTrailingZeros(src);
    unsigned pop = base::bits::CountPopulation(src);
    DCHECK_NE(0u, pop);
    if (pop + ntz + nlz == 32) {
      Pcmpeqd(dst, dst);
      if (ntz) Pslld(dst, static_cast<uint8_t>(ntz + nlz));
      if (nlz) Psrld(dst, static_cast<uint8_t>(nlz));
    } else {
      movl(kScratchRegister, Immediate(src));
      Movd(dst, kScratchRegister);
    }
  }
}

void MacroAssembler::Move(XMMRegister dst, uint64_t src) {
  if (src == 0) {
    Xorpd(dst, dst);
  } else {
    unsigned nlz = base::bits::CountLeadingZeros(src);
    unsigned ntz = base::bits::CountTrailingZeros(src);
    unsigned pop = base::bits::CountPopulation(src);
    DCHECK_NE(0u, pop);
    if (pop + ntz + nlz == 64) {
      Pcmpeqd(dst, dst);
      if (ntz) Psllq(dst, static_cast<uint8_t>(ntz + nlz));
      if (nlz) Psrlq(dst, static_cast<uint8_t>(nlz));
    } else {
      uint32_t lower = static_cast<uint32_t>(src);
      uint32_t upper = static_cast<uint32_t>(src >> 32);
      if (upper == 0) {
        Move(dst, lower);
      } else {
        movq(kScratchRegister, src);
        Movq(dst, kScratchRegister);
      }
    }
  }
}

void MacroAssembler::Move(XMMRegister dst, uint64_t high, uint64_t low) {
  if (high == low) {
    Move(dst, low);
    Punpcklqdq(dst, dst);
    return;
  }

  Move(dst, low);
  movq(kScratchRegister, high);
  Pinsrq(dst, dst, kScratchRegister, uint8_t{1});
}

// ----------------------------------------------------------------------------

void MacroAssembler::Cmp(Register dst, Handle<Object> source) {
  if (IsSmi(*source)) {
    Cmp(dst, Cast<Smi>(*source));
  } else if (root_array_available_ && options().isolate_independent_code) {
    // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
    // non-isolate-independent code. In many cases it might be cheaper than
    // embedding the relocatable value.
    // TODO(v8:9706): Fix-it! This load will always uncompress the value
    // even when we are loading a compressed embedded object.
    IndirectLoadConstant(kScratchRegister, Cast<HeapObject>(source));
    cmp_tagged(dst, kScratchRegister);
  } else if (COMPRESS_POINTERS_BOOL) {
    EmbeddedObjectIndex index = AddEmbeddedObject(Cast<HeapObject>(source));
    DCHECK(is_uint32(index));
    cmpl(dst, Immediate(static_cast<int>(index),
                        RelocInfo::COMPRESSED_EMBEDDED_OBJECT));
  } else {
    movq(kScratchRegister,
         Immediate64(source.address(), RelocInfo::FULL_EMBEDDED_OBJECT));
    cmpq(dst, kScratchRegister);
  }
}

void MacroAssembler::Cmp(Operand dst, Handle<Object> source) {
  if (IsSmi(*source)) {
    Cmp(dst, Cast<Smi>(*source));
  } else if (root_array_available_ && options().isolate_independent_code) {
    // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
    // non-isolate-independent code. In many cases it might be cheaper than
    // embedding the relocatable value.
    // TODO(v8:9706): Fix-it! This load will always uncompress the value
    // even when we are loading a compressed embedded object.
    IndirectLoadConstant(kScratchRegister, Cast<HeapObject>(source));
    cmp_tagged(dst, kScratchRegister);
  } else if (COMPRESS_POINTERS_BOOL) {
    EmbeddedObjectIndex index = AddEmbeddedObject(Cast<HeapObject>(source));
    DCHECK(is_uint32(index));
    cmpl(dst, Immediate(static_cast<int>(index),
                        RelocInfo::COMPRESSED_EMBEDDED_OBJECT));
  } else {
    Move(kScratchRegister, Cast<HeapObject>(source),
         RelocInfo::FULL_EMBEDDED_OBJECT);
    cmp_tagged(dst, kScratchRegister);
  }
}

void MacroAssembler::CompareRange(Register value, unsigned lower_limit,
                                  unsigned higher_limit) {
  ASM_CODE_COMMENT(this);
  DCHECK_LT(lower_limit, higher_limit);
  if (lower_limit != 0) {
    leal(kScratchRegister, Operand(value, 0u - lower_limit));
    cmpl(kScratchRegister, Immediate(higher_limit - lower_limit));
  } else {
    cmpl(value, Immediate(higher_limit));
  }
}

void MacroAssembler::JumpIfIsInRange(Register value, unsigned lower_limit,
                                     unsigned higher_limit, Label* on_in_range,
                                     Label::Distance near_jump) {
  CompareRange(value, lower_limit, higher_limit);
  j(below_equal, on_in_range, near_jump);
}

void MacroAssembler::Push(Handle<HeapObject> source) {
  Move(kScratchRegister, source);
  Push(kScratchRegister);
}

void MacroAssembler::PushArray(Register array, Register size, Register scratch,
                               PushArrayOrder order) {
  DCHECK(!AreAliased(array, size, scratch));
  Register counter = scratch;
  Label loop, entry;
  if (order == PushArrayOrder::kReverse) {
    Move(counter, 0);
    jmp(&entry);
    bind(&loop);
    Push(Operand(array, counter, times_system_pointer_size, 0));
    incq(counter);
    bind(&entry);
    cmpq(counter, size);
    j(less, &loop, Label::kNear);
  } else {
    movq(counter, size);
    jmp(&entry);
    bind(&loop);
    Push(Operand(array, counter, times_system_pointer_size, 0));
    bind(&entry);
    decq(counter);
    j(greater_equal, &loop, Label::kNear);
  }
}

void MacroAssembler::Move(Register result, Handle<HeapObject> object,
                          RelocInfo::Mode rmode) {
  // TODO(jgruber,v8:8887): Also consider a root-relative load when generating
  // non-isolate-independent code. In many cases it might be cheaper than
  // embedding the relocatable value.
  if (root_array_available_ && options().isolate_independent_code) {
    // TODO(v8:9706): Fix-it! This load will always uncompress the value
    // even when we are loading a compressed embedded object.
    IndirectLoadConstant(result, object);
  } else if (RelocInfo::IsCompressedEmbeddedObject(rmode)) {
    EmbeddedObjectIndex index = AddEmbeddedObject(object);
    DCHECK(is_uint32(index));
    movl(result, Immediate(static_cast<int>(index), rmode));
  } else {
    DCHECK(RelocInfo::IsFullEmbeddedObject(rmode));
    movq(result, Immediate64(object.address(), rmode));
  }
}

void MacroAssembler::Move(Operand dst, Handle<HeapObject> object,
                          RelocInfo::Mode rmode) {
  Move(kScratchRegister, object, rmode);
  movq(dst, kScratchRegister);
}

void MacroAssembler::Drop(int stack_elements) {
  if (stack_elements > 0) {
    addq(rsp, Immediate(stack_elements * kSystemPointerSize));
  }
}

void MacroAssembler::DropUnderReturnAddress(int stack_elements,
                                            Register scratch) {
  DCHECK_GT(stack_elements, 0);
  if (stack_elements == 1) {
    popq(MemOperand(rsp, 0));
    return;
  }

  PopReturnAddressTo(scratch);
  Drop(stack_elements);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArguments(Register count) {
  leaq(rsp, Operand(rsp, count, times_system_pointer_size, 0));
}

void MacroAssembler::DropArguments(Register count, Register scratch) {
  DCHECK(!AreAliased(count, scratch));
  PopReturnAddressTo(scratch);
  DropArguments(count);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Register receiver,
                                                     Register scratch) {
  DCHECK(!AreAliased(argc, receiver, scratch));
  PopReturnAddressTo(scratch);
  DropArguments(argc);
  Push(receiver);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::DropArgumentsAndPushNewReceiver(Register argc,
                                                     Operand receiver,
                                                     Register scratch) {
  DCHECK(!AreAliased(argc, scratch));
  DCHECK(!receiver.AddressUsesRegister(scratch));
  PopReturnAddressTo(scratch);
  DropArguments(argc);
  Push(receiver);
  PushReturnAddressFrom(scratch);
}

void MacroAssembler::Push(Register src) { pushq(src); }

void MacroAssembler::Push(Operand src) { pushq(src); }

void MacroAssembler::PushQuad(Operand src) { pushq(src); }

void MacroAssembler::Push(Immediate value) { pushq(value); }

void MacroAssembler::PushImm32(int32_t imm32) { pushq_imm32(imm32); }

void MacroAssembler::Pop(Register dst) { popq(dst); }

void MacroAssembler::Pop(Operand dst) { popq(dst); }

void MacroAssembler::PopQuad(Operand dst) { popq(dst); }

void MacroAssembler::Jump(const ExternalReference& reference) {
  DCHECK(root_array_available());
  jmp(Operand(kRootRegister, RootRegisterOffsetForExternalReferenceTableEntry(
                                 isolate(), reference)));
}

void MacroAssembler::Jump(Operand op) { jmp(op); }

void MacroAssembler::Jump(Operand op, Condition cc) {
  Label skip;
  j(NegateCondition(cc), &skip, Label::kNear);
  Jump(op);
  bind(&skip);
}

void MacroAssembler::Jump(Address destination, RelocInfo::Mode rmode) {
  Move(kScratchRegister, destination, rmode);
  jmp(kScratchRegister);
}

void MacroAssembler::Jump(Address destination, RelocInfo::Mode rmode,
                          Condition cc) {
  Label skip;
  j(NegateCondition(cc), &skip, Label::kNear);
  Jump(destination, rmode);
  bind(&skip);
}

void MacroAssembler::Jump(Handle<Code> code_object, RelocInfo::Mode rmode) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code_object));
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code_object, &builtin)) {
    TailCallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  jmp(code_object, rmode);
}

void MacroAssembler::Jump(Handle<Code> code_object, RelocInfo::Mode rmode,
                          Condition cc) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code_object));
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code_object, &builtin)) {
    TailCallBuiltin(builtin, cc);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  j(cc, code_object, rmode);
}

void MacroAssembler::Call(ExternalReference ext) {
  LoadAddress(kScratchRegister, ext);
  call(kScratchRegister);
}

void MacroAssembler::Call(Operand op) {
  if (!CpuFeatures::IsSupported(INTEL_ATOM)) {
    call(op);
  } else {
    movq(kScratchRegister, op);
    call(kScratchRegister);
  }
}

void MacroAssembler::Call(Address destination, RelocInfo::Mode rmode) {
  Move(kScratchRegister, destination, rmode);
  call(kScratchRegister);
}

void MacroAssembler::Call(Handle<Code> code_object, RelocInfo::Mode rmode) {
  DCHECK_IMPLIES(options().isolate_independent_code,
                 Builtins::IsIsolateIndependentBuiltin(*code_object));
  Builtin builtin = Builtin::kNoBuiltinId;
  if (isolate()->builtins()->IsBuiltinHandle(code_object, &builtin)) {
    CallBuiltin(builtin);
    return;
  }
  DCHECK(RelocInfo::IsCodeTarget(rmode));
  call(code_object, rmode);
}

Operand MacroAssembler::EntryFromBuiltinAsOperand(Builtin builtin) {
  DCHECK(root_array_available());
  return Operand(kRootRegister, IsolateData::BuiltinEntrySlotOffset(builtin));
}

Operand MacroAssembler::EntryFromBuiltinIndexAsOperand(Register builtin_index) {
  if (SmiValuesAre32Bits()) {
    // The builtin_index register contains the builtin index as a Smi.
    Move(kScratchRegister, builtin_index);  // Callee checks for equality.
    SmiUntagUnsigned(kScratchRegister);
    return Operand(kRootRegister, kScratchRegister, times_system_pointer_size,
                   IsolateData::builtin_entry_table_offset());
  } else {
    DCHECK(SmiValuesAre31Bits());

    // The builtin_index register contains the builtin index as a Smi.
    // Untagging is folded into the indexing operand below (we use
    // times_half_system_pointer_size since smis are already shifted by one).
    return Operand(kRootRegister, builtin_index, times_half_system_pointer_size,
                   IsolateData::builtin_entry_table_offset());
  }
}

void MacroAssembler::CallBuiltinByIndex(Register builtin_index) {
  Call(EntryFromBuiltinIndexAsOperand(builtin_index));
}

void MacroAssembler::CallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this, CommentForOffHeapTrampoline("call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute:
      Call(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET);
      break;
    case BuiltinCallJumpMode::kPCRelative:
      near_call(static_cast<intptr_t>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect:
      Call(EntryFromBuiltinAsOperand(builtin));
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      call(code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute:
      Jump(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET);
      break;
    case BuiltinCallJumpMode::kPCRelative:
      near_jmp(static_cast<intptr_t>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect:
      Jump(EntryFromBuiltinAsOperand(builtin));
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      jmp(code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::TailCallBuiltin(Builtin builtin, Condition cc) {
  ASM_CODE_COMMENT_STRING(this,
                          CommentForOffHeapTrampoline("tail call", builtin));
  switch (options().builtin_call_jump_mode) {
    case BuiltinCallJumpMode::kAbsolute:
      Jump(BuiltinEntry(builtin), RelocInfo::OFF_HEAP_TARGET, cc);
      break;
    case BuiltinCallJumpMode::kPCRelative:
      near_j(cc, static_cast<intptr_t>(builtin), RelocInfo::NEAR_BUILTIN_ENTRY);
      break;
    case BuiltinCallJumpMode::kIndirect:
      Jump(EntryFromBuiltinAsOperand(builtin), cc);
      break;
    case BuiltinCallJumpMode::kForMksnapshot: {
      Handle<Code> code = isolate()->builtins()->code_handle(builtin);
      j(cc, code, RelocInfo::CODE_TARGET);
      break;
    }
  }
}

void MacroAssembler::LoadCodeInstructionStart(Register destination,
                                              Register code_object,
                                              CodeEntrypointTag tag) {
  ASM_CODE_COMMENT(this);
#ifdef V8_ENABLE_SANDBOX
  LoadCodeEntrypointViaCodePointer(
      destination, FieldOperand(code_object, Code::kSelfIndirectPointerOffset),
      tag);
#else
  movq(destination, FieldOperand(code_object, Code::kInstructionStartOffset));
#endif
}

void MacroAssembler::CallCodeObject(Register code_object,
                                    CodeEntrypointTag tag) {
  LoadCodeInstructionStart(code_object, code_object, tag);
  call(code_object);
}

void MacroAssembler::JumpCodeObject(Register code_object, CodeEntrypointTag tag,
                                    JumpMode jump_mode) {
  // TODO(saelo): can we avoid using this for JavaScript functions
  // (kJSEntrypointTag) and instead use a variant that ensures that the caller
  // and callee agree on the signature (i.e. parameter count)?
  LoadCodeInstructionStart(code_object, code_object, tag);
  switch (jump_mode) {
    case JumpMode::kJump:
      jmp(code_object);
      return;
    case JumpMode::kPushAndReturn:
      pushq(code_object);
      Ret();
      return;
  }
}

void MacroAssembler::CallJSFunction(Register function_object,
                                    uint16_t argument_count) {
#if V8_ENABLE_LEAPTIERING
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  static_assert(kJavaScriptCallDispatchHandleRegister == r15, "ABI mismatch");
  movl(r15, FieldOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointAndParameterCountFromJSDispatchTable(rcx, rbx, r15);
  // Force a safe crash if the parameter count doesn't match.
  cmpl(rbx, Immediate(argument_count));
  SbxCheck(less_equal, AbortReason::kJSSignatureMismatch);
  call(rcx);
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      rcx, FieldOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  call(rcx);
#else
  LoadTaggedField(rcx, FieldOperand(function_object, JSFunction::kCodeOffset));
  CallCodeObject(rcx, kJSEntrypointTag);
#endif
}

void MacroAssembler::JumpJSFunction(Register function_object,
                                    JumpMode jump_mode) {
#if V8_ENABLE_LEAPTIERING
  static_assert(kJavaScriptCallCodeStartRegister == rcx, "ABI mismatch");
  static_assert(kJavaScriptCallDispatchHandleRegister == r15, "ABI mismatch");
  movl(r15, FieldOperand(function_object, JSFunction::kDispatchHandleOffset));
  LoadEntrypointFromJSDispatchTable(rcx, r15);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  jmp(rcx);
  // This implementation is not currently used because callers usually need
  // to load both entry point and parameter count and then do something with
  // the latter before the actual call.
  // TODO(ishell): remove the above code once it's clear it's not needed.
  UNREACHABLE();
#elif V8_ENABLE_SANDBOX
  // When the sandbox is enabled, we can directly fetch the entrypoint pointer
  // from the code pointer table instead of going through the Code object. In
  // this way, we avoid one memory load on this code path.
  LoadCodeEntrypointViaCodePointer(
      rcx, FieldOperand(function_object, JSFunction::kCodeOffset),
      kJSEntrypointTag);
  DCHECK_EQ(jump_mode, JumpMode::kJump);
  jmp(rcx);
#else
  LoadTaggedField(rcx, FieldOperand(function_object, JSFunction::kCodeOffset));
  JumpCodeObject(rcx, kJSEntrypointTag, jump_mode);
#endif
}

void MacroAssembler::ResolveWasmCodePointer(Register target) {
#ifdef V8_ENABLE_WASM_CODE_POINTER_TABLE
  ExternalReference global_jump_table =
      ExternalReference::wasm_code_pointer_table();
  Move(kScratchRegister, global_jump_table);
  static_assert(sizeof(wasm::WasmCodePointerTableEntry) == 8);
  movq(target, Operand(kScratchRegister, target, ScaleFactor::times_8, 0));
#endif
}

void MacroAssembler::CallWasmCodePointer(Register target,
                                         CallJumpMode call_jump_mode) {
  ResolveWasmCodePointer(target);
  if (call_jump_mode == CallJumpMode::kTailCall) {
    jmp(target);
  } else {
    call(target);
  }
}

void MacroAssembler::LoadWasmCodePointer(Register dst, Operand src) {
  if constexpr (V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL) {
    static_assert(!V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 4);
    movl(dst, src);
  } else {
    static_assert(V8_ENABLE_WASM_CODE_POINTER_TABLE_BOOL ||
                  sizeof(WasmCodePointer) == 8);
    movq(dst, src);
  }
}

void MacroAssembler::PextrdPreSse41(Register dst, XMMRegister src,
                                    uint8_t imm8) {
  if (imm8 == 0) {
    Movd(dst, src);
    return;
  }
  DCHECK_EQ(1, imm8);
  movq(dst, src);
  shrq(dst, Immediate(32));
}

namespace {
template <typename Op>
void PinsrdPreSse41Helper(MacroAssembler* masm, XMMRegister dst, Op src,
                          uint8_t imm8, uint32_t* load_pc_offset) {
  masm->Movd(kScratchDoubleReg, src);
  if (load_pc_offset) *load_pc_offset = masm->pc_offset();
  if (imm8 == 1) {
    masm->punpckldq(dst, kScratchDoubleReg);
  } else {
    DCHECK_EQ(0, imm8);
    masm->Movss(dst, kScratchDoubleReg);
  }
}
}  // namespace

void MacroAssembler::PinsrdPreSse41(XMMRegister dst, Register src, uint8_t imm8,
                                    uint32_t* load_pc_offset) {
  PinsrdPreSse41Helper(this, dst, src, imm8, load_pc_offset);
}

void MacroAssembler::PinsrdPreSse41(XMMRegister dst, Operand src, uint8_t imm8,
                                    uint32_t* load_pc_offset) {
  PinsrdPreSse41Helper(this, dst, src, imm8, load_pc_offset);
}

void MacroAssembler::Pinsrq(XMMRegister dst, XMMRegister src1, Register src2,
                            uint8_t imm8, uint32_t* load_pc_offset) {
  PinsrHelper(this, &Assembler::vpinsrq, &Assembler::pinsrq, dst, src1, src2,
              imm8, load_pc_offset, {SSE4_1});
}

void MacroAssembler::Pinsrq(XMMRegister dst, XMMRegister src1, Operand src2,
                            uint8_t imm8, uint32_t* load_pc_offset) {
  PinsrHelper(this, &Assembler::vpinsrq, &Assembler::pinsrq, dst, src1, src2,
              imm8, load_pc_offset, {SSE4_1});
}

void MacroAssembler::Lzcntl(Register dst, Register src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsrl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 63);  // 63^31 == 32
  bind(&not_zero_src);
  xorl(dst, Immediate(31));  // for x in [0..31], 31^x == 31 - x
}

void MacroAssembler::Lzcntl(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsrl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 63);  // 63^31 == 32
  bind(&not_zero_src);
  xorl(dst, Immediate(31));  // for x in [0..31], 31^x == 31 - x
}

void MacroAssembler::Lzcntq(Register dst, Register src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsrq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 127);  // 127^63 == 64
  bind(&not_zero_src);
  xorl(dst, Immediate(63));  // for x in [0..63], 63^x == 63 - x
}

void MacroAssembler::Lzcntq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(LZCNT)) {
    CpuFeatureScope scope(this, LZCNT);
    lzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsrq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 127);  // 127^63 == 64
  bind(&not_zero_src);
  xorl(dst, Immediate(63));  // for x in [0..63], 63^x == 63 - x
}

void MacroAssembler::Tzcntq(Register dst, Register src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsfq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  // Define the result of tzcnt(0) separately, because bsf(0) is undefined.
  Move(dst, 64);
  bind(&not_zero_src);
}

void MacroAssembler::Tzcntq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntq(dst, src);
    return;
  }
  Label not_zero_src;
  bsfq(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  // Define the result of tzcnt(0) separately, because bsf(0) is undefined.
  Move(dst, 64);
  bind(&not_zero_src);
}

void MacroAssembler::Tzcntl(Register dst, Register src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsfl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 32);  // The result of tzcnt is 32 if src = 0.
  bind(&not_zero_src);
}

void MacroAssembler::Tzcntl(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(BMI1)) {
    CpuFeatureScope scope(this, BMI1);
    tzcntl(dst, src);
    return;
  }
  Label not_zero_src;
  bsfl(dst, src);
  j(not_zero, &not_zero_src, Label::kNear);
  Move(dst, 32);  // The result of tzcnt is 32 if src = 0.
  bind(&not_zero_src);
}

void MacroAssembler::Popcntl(Register dst, Register src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntl(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::Popcntl(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntl(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::Popcntq(Register dst, Register src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntq(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::Popcntq(Register dst, Operand src) {
  if (CpuFeatures::IsSupported(POPCNT)) {
    CpuFeatureScope scope(this, POPCNT);
    popcntq(dst, src);
    return;
  }
  UNREACHABLE();
}

void MacroAssembler::PushStackHandler() {
  // Adjust this code if not the case.
  static_assert(StackHandlerConstants::kSize == 2 * kSystemPointerSize);
  static_assert(StackHandlerConstants::kNextOffset == 0);

  Push(Immediate(0));  // Padding.

  // Link the current handler as the next handler.
  ExternalReference handler_address =
      ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate());
  Push(ExternalReferenceAsOperand(handler_address));

  // Set this new handler as the current one.
  movq(ExternalReferenceAsOperand(handler_address), rsp);
}

void MacroAssembler::PopStackHandler() {
  static_assert(StackHandlerConstants::kNextOffset == 0);
  ExternalReference handler_address =
      ExternalReference::Create(IsolateAddressId::kHandlerAddress, isolate());
  Pop(ExternalReferenceAsOperand(handler_address));
  addq(rsp, Immediate(StackHandlerConstants::kSize - kSystemPointerSize));
}

void MacroAssembler::Ret() { ret(0); }

void MacroAssembler::Ret(int bytes_dropped, Register scratch) {
  if (is_uint16(bytes_dropped)) {
    ret(bytes_dropped);
  } else {
    PopReturnAddressTo(scratch);
    addq(rsp, Immediate(bytes_dropped));
    PushReturnAddressFrom(scratch);
    ret(0);
  }
}

void MacroAssembler::IncsspqIfSupported(Register number_of_words,
                                        Register scratch) {
  // Optimized code can validate at runtime whether the cpu supports the
  // incsspq instruction, so it shouldn't use this method.
  CHECK(isolate()->IsGeneratingEmbeddedBuiltins());
  DCHECK_NE(number_of_words, scratch);
  Label not_supported;
  ExternalReference supports_cetss =
      ExternalReference::supports_cetss_address();
  Operand supports_cetss_operand =
      ExternalReferenceAsOperand(supports_cetss, scratch);
  cmpb(supports_cetss_operand, Immediate(0));
  j(equal, &not_supported, Label::kNear);
  incsspq(number_of_words);
  bind(&not_supported);
}

#if V8_STATIC_ROOTS_BOOL
void MacroAssembler::CompareInstanceTypeWithUniqueCompressedMap(
    Register map, InstanceType type) {
  std::optional<RootIndex> expected =
      InstanceTypeChecker::UniqueMapOfInstanceType(type);
  CHECK(expected);
  Tagged_t expected_ptr = ReadOnlyRootPtr(*expected);
  cmp_tagged(map, Immediate(expected_ptr));
}

void MacroAssembler::IsObjectTypeFast(Register object, InstanceType type,
                                      Register compressed_map_scratch) {
  ASM_CODE_COMMENT(this);
  CHECK(InstanceTypeChecker::UniqueMapOfInstanceType(type));
  LoadCompressedMap(compressed_map_scratch, object);
  CompareInstanceTypeWithUniqueCompressedMap(compressed_map_scratch, type);
}
#endif  // V8_STATIC_ROOTS_BOOL

void MacroAssembler::IsObjectType(Register heap_object, InstanceType type,
                                  Register map) {
#if V8_STATIC_ROOTS_BOOL
  if (InstanceTypeChecker::UniqueMapOfInstanceType(type)) {
    LoadCompressedMap(map, heap_object);
    CompareInstanceTypeWithUniqueCompressedMap(map, type);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  CmpObjectType(heap_object, type, map);
}

void MacroAssembler::IsObjectTypeInRange(Register heap_object,
                                         InstanceType lower_limit,
                                         InstanceType higher_limit,
                                         Register scratch) {
  DCHECK_LT(lower_limit, higher_limit);
#if V8_STATIC_ROOTS_BOOL
  if (auto range = InstanceTypeChecker::UniqueMapRangeOfInstanceTypeRange(
          lower_limit, higher_limit)) {
    LoadCompressedMap(scratch, heap_object);
    CompareRange(scratch, range->first, range->second);
    return;
  }
#endif  // V8_STATIC_ROOTS_BOOL
  LoadMap(scratch, heap_object);
  CmpInstanceTypeRange(scratch, scratch, lower_limit, higher_limit);
}

void MacroAssembler::JumpIfJSAnyIsNotPrimitive(Register heap_object,
                                               Register scratch, Label* target,
                                               Label::Distance distance,
                                               Condition cc) {
  CHECK(cc == Condition::kUnsignedLessThan ||
        cc == Condition::kUnsignedGreaterThanEqual);
  if (V8_STATIC_ROOTS_BOOL) {
#ifdef DEBUG
    Label ok;
    LoadMap(scratch, heap_object);
    CmpInstanceTypeRange(scratch, scratch, FIRST_JS_RECEIVER_TYPE,
                         LAST_JS_RECEIVER_TYPE);
    j(Condition::kUnsignedLessThanEqual, &ok, Label::Distance::kNear);
    LoadMap(scratch, heap_object);
    CmpInstanceTypeRange(scratch, scratch, FIRST_PRIMITIVE_HEAP_OBJECT_TYPE,
                         LAST_PRIMITIVE_HEAP_OBJECT_TYPE);
    j(Condition::kUnsignedLessThanEqual, &ok, Label::Distance::kNear);
    Abort(AbortReason::kInvalidReceiver);
    bind(&ok);
#endif  // DEBUG

    // All primitive object's maps are allocated at the start of the read only
    // heap. Thus JS_RECEIVER's must have maps with larger (compressed)
    // addresses.
    LoadCompressedMap(scratch, heap_object);
    cmp_tagged(scratch, Immediate(InstanceTypeChecker::kNonJsReceiverMapLimit));
  } else {
    static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
    CmpObjectType(heap_object, FIRST_JS_RECEIVER_TYPE, scratch);
  }
  j(cc, target, distance);
}

void MacroAssembler::CmpObjectType(Register heap_object, InstanceType type,
                                   Register map) {
  LoadMap(map, heap_object);
  CmpInstanceType(map, type);
}

void MacroAssembler::CmpInstanceType(Register map, InstanceType type) {
  cmpw(FieldOperand(map, Map::kInstanceTypeOffset), Immediate(type));
}

void MacroAssembler::CmpInstanceTypeRange(Register map,
                                          Register instance_type_out,
                                          InstanceType lower_limit,
                                          InstanceType higher_limit) {
  DCHECK_LT(lower_limit, higher_limit);
  movzxwl(instance_type_out, FieldOperand(map, Map::kInstanceTypeOffset));
  CompareRange(instance_type_out, lower_limit, higher_limit);
}

void MacroAssembler::TestCodeIsMarkedForDeoptimization(Register code) {
  const int kByteWithDeoptBitOffset = 0 * kByteSize;
  const int kByteWithDeoptBitOffsetInBits = kByteWithDeoptBitOffset * 8;
  static_assert(V8_TARGET_LITTLE_ENDIAN == 1);
  static_assert(FIELD_SIZE(Code::kFlagsOffset) * kBitsPerByte == 32);
  static_assert(Code::kMarkedForDeoptimizationBit >
                kByteWithDeoptBitOffsetInBits);
  testb(FieldOperand(code, Code::kFlagsOffset + kByteWithDeoptBitOffset),
        Immediate(1 << (Code::kMarkedForDeoptimizationBit -
                        kByteWithDeoptBitOffsetInBits)));
}

void MacroAssembler::TestCodeIsTurbofanned(Register code) {
  testl(FieldOperand(code, Code::kFlagsOffset),
        Immediate(1 << Code::kIsTurbofannedBit));
}

Immediate MacroAssembler::ClearedValue() const {
  return Immediate(static_cast<int32_t>(i::ClearedValue(isolate()).ptr()));
}

#ifdef V8_ENABLE_DEBUG_CODE
void MacroAssembler::AssertNotSmi(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Condition is_smi = CheckSmi(object);
  Check(NegateCondition(is_smi), AbortReason::kOperandIsASmi);
}

void MacroAssembler::AssertSmi(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Condition is_smi = CheckSmi(object);
  Check(is_smi, AbortReason::kOperandIsNotASmi);
#ifdef ENABLE_SLOW_DCHECKS
  ClobberDecompressedSmiBits(object);
#endif
}

void MacroAssembler::AssertSmi(Operand object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Condition is_smi = CheckSmi(object);
  Check(is_smi, AbortReason::kOperandIsNotASmi);
}

void MacroAssembler::AssertZeroExtended(Register int32_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  DCHECK_NE(int32_register, kScratchRegister);
  movl(kScratchRegister, Immediate(kMaxUInt32));  // zero-extended
  cmpq(int32_register, kScratchRegister);
  Check(below_equal, AbortReason::k32BitValueInRegisterIsNotZeroExtended);
}

void MacroAssembler::AssertSignedBitOfSmiIsZero(Register smi_register) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  DCHECK(COMPRESS_POINTERS_BOOL);
  testl(smi_register, Immediate(int32_t{0x10000000}));
  Check(zero, AbortReason::kSignedBitOfSmiIsNotZero);
}

void MacroAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsNotAMap);
  Push(object);
  LoadMap(object, object);
  CmpInstanceType(object, MAP_TYPE);
  popq(object);
  Check(equal, AbortReason::kOperandIsNotAMap);
}

void MacroAssembler::AssertCode(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsNotACode);
  Push(object);
  LoadMap(object, object);
  CmpInstanceType(object, CODE_TYPE);
  popq(object);
  Check(equal, AbortReason::kOperandIsNotACode);
}

void MacroAssembler::AssertSmiOrHeapObjectInMainCompressionCage(
    Register object) {
  if (!PointerCompressionIsEnabled()) return;
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  Label ok;
  // We may not have any scratch registers so we preserve our input register.
  pushq(object);
  j(CheckSmi(object), &ok);
  // Clear the lower 32 bits.
  shrq(object, Immediate(32));
  shlq(object, Immediate(32));
  // Either the value is now equal to the pointer compression cage base or it's
  // zero if we got a compressed pointer register as input.
  j(zero, &ok);
  cmpq(object, kPtrComprCageBaseRegister);
  Check(equal, AbortReason::kObjectNotTagged);
  bind(&ok);
  popq(object);
}

void MacroAssembler::AssertConstructor(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortReason::kOperandIsASmiAndNotAConstructor);
  Push(object);
  LoadMap(object, object);
  testb(FieldOperand(object, Map::kBitFieldOffset),
        Immediate(Map::Bits1::IsConstructorBit::kMask));
  Pop(object);
  Check(not_zero, AbortReason::kOperandIsNotAConstructor);
}

void MacroAssembler::AssertFunction(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  testb(object, Immediate(kSmiTagMask));
  Check(not_equal, AbortR
```