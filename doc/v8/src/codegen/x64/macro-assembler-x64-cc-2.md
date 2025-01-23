Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/x64/macro-assembler-x64.cc`. The summary should adhere to the following constraints:

1. **List Functionalities:** Identify the primary actions performed by the code.
2. **Torque Check:** Determine if the file would be considered a Torque file based on its extension (it's not, as it's `.cc`).
3. **JavaScript Relevance:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there are logical operations, provide a hypothetical input and output.
5. **Common Programming Errors:**  Illustrate potential user errors related to the code's functionality.
6. **Part Number:** Acknowledge that this is part 3 of a 6-part series.
7. **Summarize Functionality:** Provide a concise overview of the code's purpose.

**Analysis of the Code Snippet:**

The code snippet consists of several methods within the `MacroAssembler` class, focusing on SIMD (Single Instruction, Multiple Data) operations using AVX/AVX2 and FMA3 instructions. These operations include:

* **Vectorized Multiplication:**  Functions like `MulHighAndLow`, `I64x4ExtMul`, `I32x8ExtMul`, `I16x16ExtMul`.
* **Vectorized Splatting:** Functions like `name` (using a macro), `F64x4Splat`, `F32x8Splat`. These are for replicating a single value across a vector.
* **Vectorized Min/Max:** Functions like `F64x4Min`, `F64x4Max`, `F32x8Min`, `F32x8Max`, `F16x8Min`, `F16x8Max`.
* **Vectorized Pairwise Addition:** Functions like `I32x8ExtAddPairwiseI16x16S`, `I32x8ExtAddPairwiseI16x16U`, `I16x16ExtAddPairwiseI8x32S`, `I16x16ExtAddPairwiseI8x32U`.
* **Vectorized Conversions:** Functions like `I32x8SConvertF32x8`, `I16x8SConvertF16x8`, `I16x8TruncF16x8U`, `I32x8TruncF32x8U`. These handle conversions between integer and floating-point vector types.
* **Vectorized Fused Multiply-Add/Subtract:** Functions like `F16x8Qfma`, `F16x8Qfms`, `F32x8Qfma`, `F32x8Qfms`, `F64x4Qfma`, `F64x4Qfms`.
* **Vectorized Dot Product:** Function `I32x8DotI8x32I7x32AddS`.
* **Smi (Small Integer) Manipulation:** Functions for tagging, untagging, comparing, adding, and converting Smis.
* **General Data Movement:** Functions like `Move`.
* **Comparison:** Function `Cmp`.
* **Control Flow:** Function `Switch`.

**JavaScript Relevance:**

These low-level SIMD operations are often exposed to JavaScript through WebAssembly or through specific JavaScript APIs that leverage SIMD for performance-critical tasks.

**Code Logic Inference:**

Many of the functions implement standard SIMD operations. For example, the `F64x4Min` function finds the minimum of corresponding elements in two double-precision floating-point vectors.

**Common Programming Errors:**

Incorrectly using SIMD intrinsics or making assumptions about data alignment can lead to errors.

**Plan for Response:**

1. List the major categories of functionalities present in the code.
2. Confirm that the file is not a Torque file.
3. Provide JavaScript examples for relevant functionalities (e.g., WebAssembly SIMD operations).
4. Give examples of input/output for a couple of functions, like `F64x4Min`.
5. Illustrate a common programming error, like misaligned memory access with SIMD.
6. State that this is part 3 of 6.
7. Provide a concise summary of the code's overall purpose.
这是 `v8/src/codegen/x64/macro-assembler-x64.cc` 文件的第三部分代码，主要包含以下功能：

1. **SIMD 向量运算 (AVX/AVX2/FMA3 指令集):**
    * **向量乘法:** 实现了多个向量乘法操作，包括高低位分离的乘法 (`MulHighAndLow`)，以及针对不同数据类型的扩展乘法 (`I64x4ExtMul`, `I32x8ExtMul`, `I16x16ExtMul`)。
    * **向量元素广播 (Splat):** 提供了将寄存器或内存中的单个值广播到整个 YMM 寄存器的功能 (`name` 宏定义, `F64x4Splat`, `F32x8Splat`)。
    * **向量最小值/最大值:** 实现了查找两个向量对应元素的最小值和最大值操作 (`F64x4Min`, `F64x4Max`, `F32x8Min`, `F32x8Max`, `F16x8Min`, `F16x8Max`)，并考虑了 NaN 值的处理。
    * **向量成对加法:** 提供了将向量中相邻元素成对相加的功能 (`I32x8ExtAddPairwiseI16x16S`, `I32x8ExtAddPairwiseI16x16U`, `I16x16ExtAddPairwiseI8x32S`, `I16x16ExtAddPairwiseI8x32U`)。
    * **向量类型转换:** 实现了浮点向量到整型向量的转换 (`I32x8SConvertF32x8`, `I16x8SConvertF16x8`, `I16x8TruncF16x8U`, `I32x8TruncF32x8U`)，并处理了溢出和 NaN 值。
    * **向量融合乘加/减 (QFMA/QFMS):**  提供了使用 FMA3 指令集的融合乘加和乘减操作，针对不同的浮点数精度 (`F16x8Qfma`, `F16x8Qfms`, `F32x8Qfma`, `F32x8Qfms`, `F64x4Qfma`, `F64x4Qfms`)。
    * **向量点积:** 实现了向量点积运算 (`I32x8DotI8x32I7x32AddS`)，并根据 CPU 特性选择不同的指令。

2. **小整数 (Smi) 操作:**
    * **Smi 标记和取消标记:** 提供了将普通整数标记为 Smi (`SmiTag`) 和将 Smi 转换回普通整数 (`SmiUntag`, `SmiUntagUnsigned`, `SmiToInt32`) 的功能。
    * **Smi 比较:** 实现了两个 Smi 的比较操作 (`SmiCompare`, `Cmp`)。
    * **Smi 加法:** 提供了 Smi 加法运算 (`SmiAddConstant`)。
    * **Smi 转换为索引:**  将 Smi 转换为可用于内存寻址的索引 (`SmiToIndex`)。
    * **Smi 类型检查:**  检查一个寄存器或操作数是否是 Smi (`CheckSmi`, `JumpIfSmi`, `JumpIfNotSmi`)。

3. **通用数据移动:**
    * 提供了在寄存器之间、寄存器和内存之间移动数据的函数 (`Move`, `MovePair`, `MoveNumber`)，并能处理立即数和外部引用。

4. **比较操作:**
    * 提供了比较寄存器和立即数或内存操作数的函数 (`Cmp`)。

5. **跳转表 (Switch):**
    * 实现了基于寄存器值的多路分支跳转 (`Switch`).

如果 `v8/src/codegen/x64/macro-assembler-x64.cc` 以 `.tq` 结尾，那它将是一个 v8 Torque 源代码。但根据提供的信息，它的结尾是 `.cc`，所以它是一个 **C++** 源代码。

**与 JavaScript 功能的关系 (示例):**

这些底层的汇编代码是 V8 引擎执行 JavaScript 代码的基础。例如，当 JavaScript 执行 SIMD 操作时，V8 会生成相应的汇编代码来调用这些 `MacroAssembler` 中的函数。

**JavaScript 示例 (WebAssembly SIMD):**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const i32a = new Int32Array(memory.buffer);
i32a[0] = 1;
i32a[1] = 2;
i32a[2] = 3;
i32a[3] = 4;

const i32b = new Int32Array(memory.buffer);
i32b[4] = 5;
i32b[5] = 6;
i32b[6] = 7;
i32b[7] = 8;

const f64a = new Float64Array(memory.buffer);
f64a[2] = 2.5;
f64a[3] = 3.5;

const f64b = new Float64Array(memory.buffer);
f64b[4] = 1.5;
f64b[5] = 4.5;

const wasmCode = `
  (module
    (memory (import "env" "memory") 1)
    (func (export "i32x4_min") (param $p i32) (param $q i32) (result v128)
      local.get $p
      v128.load
      local.get $q
      v128.load
      i32x4.min
    )
    (func (export "f64x2_max") (param $p i32) (param $q i32) (result v128)
      local.get $p
      v128.load
      local.get $q
      v128.load
      f64x2.max
    )
  )
`;
const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule, { env: { memory: memory } });

const i32x4_result = wasmInstance.exports.i32x4_min(0, 4); // 比较 i32a 和 i32b 的前 4 个元素
console.log(WebAssembly.I32x4.extractLane(i32x4_result, 0)); // 输出 1
console.log(WebAssembly.I32x4.extractLane(i32x4_result, 1)); // 输出 2
console.log(WebAssembly.I32x4.extractLane(i32x4_result, 2)); // 输出 3
console.log(WebAssembly.I32x4.extractLane(i32x4_result, 3)); // 输出 4

const f64x2_result = wasmInstance.exports.f64x2_max(2 * Float64Array.BYTES_PER_ELEMENT, 4 * Float64Array.BYTES_PER_ELEMENT); // 比较 f64a 和 f64b 的前 2 个元素
console.log(WebAssembly.Float64x2.extractLane(f64x2_result, 0)); // 输出 2.5
console.log(WebAssembly.Float64x2.extractLane(f64x2_result, 1)); // 输出 4.5
```

在这个例子中，WebAssembly 的 SIMD 指令 `i32x4.min` 和 `f64x2.max` 的执行最终会依赖于 `macro-assembler-x64.cc` 中实现的类似 `F32x8Min` 或 `F64x4Max` 这样的函数。

**代码逻辑推理 (示例):**

**函数:** `MacroAssembler::F64x4Min(YMMRegister dst, YMMRegister lhs, YMMRegister rhs, YMMRegister scratch)`

**假设输入:**

* `lhs` 寄存器包含双精度浮点数: `[3.0, 1.0, 4.0, 2.0]`
* `rhs` 寄存器包含双精度浮点数: `[2.0, 4.0, 1.0, 3.0]`
* `scratch` 寄存器为临时寄存器，内容不重要

**输出 (`dst` 寄存器):**

* `dst` 寄存器将包含双精度浮点数: `[2.0, 1.0, 1.0, 2.0]` (对应位置的最小值)

**用户常见的编程错误 (示例):**

在使用 SIMD 指令时，一个常见的错误是**数据类型不匹配**。例如，尝试将一个包含单精度浮点数的 XMM 寄存器直接用于需要双精度浮点数 YMM 寄存器的操作，或者在整数和浮点数之间进行不正确的转换。

```c++
// 错误示例 (假设用户直接调用 MacroAssembler 的方法)
// 假设 ym1 包含双精度浮点数，xm1 包含单精度浮点数
// assembler->F64x4Min(ym1, ym1, xm1, ym2); // 错误：类型不匹配
```

另一个常见的错误是在使用 Smi 操作时**忘记进行标记或取消标记**，导致将指针值当做整数进行运算，或者反之。

```c++
// 错误示例
Register reg1 = rax;
Register reg2 = rbx;
assembler->Move(reg1, Smi::FromInt(5)); // reg1 现在包含标记后的 Smi
assembler->addq(reg1, Immediate(3));     // 错误：直接将 Smi 当作普通整数加法
assembler->SmiUntag(reg1);             // 正确的做法是先取消标记
assembler->addq(reg1, Immediate(3));     // 现在是正确的整数加法
```

**功能归纳 (针对第三部分):**

这部分代码主要负责实现 x64 架构下针对向量 (SIMD) 运算和小型整数 (Smi) 操作的底层汇编指令序列。它提供了高性能的数值计算和类型转换功能，是 V8 引擎执行 JavaScript 中涉及数值计算和类型转换的关键组成部分。特别是针对现代 CPU 的 AVX、AVX2 和 FMA3 指令集进行了优化，以提升执行效率。此外，还包含了一些通用的数据移动和控制流操作。

这是第 **3** 部分，共 **6** 部分。

### 提示词
```
这是目录为v8/src/codegen/x64/macro-assembler-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/x64/macro-assembler-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    IndirectLoadConstant(kScratchRegis
```