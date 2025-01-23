Response:
Let's break down the thought process for analyzing this C++ header file snippet.

1. **Identify the Core Purpose:** The filename `liftoff-assembler-x64-inl.h` strongly suggests this code is related to assembly code generation for the x64 architecture within the Liftoff compiler (a baseline compiler for WebAssembly in V8). The `.inl.h` suffix indicates inline implementations, meaning these are likely small, frequently used functions meant to be inserted directly into the calling code.

2. **Recognize the Domain:**  The frequent appearance of terms like `i32x4`, `i64x2`, `f32x4`, `f64x2`, `emit_`, `LiftoffRegister`, and the use of SIMD instruction mnemonics (like `Pmovsxdq`, `Absps`, `Vpaddq`) immediately points to the domain of **SIMD (Single Instruction, Multiple Data) operations** for different data types (integers and floats of various sizes) within a compiler's code generation phase. The "emit_" prefix further reinforces the idea of generating assembly instructions.

3. **Categorize the Functionality (High-Level):**  Scanning the function names reveals a pattern: `emit_<type>_<operation>`. This suggests that the code provides functions to emit assembly instructions for various SIMD operations on different data types. Common operations like `add`, `sub`, `mul`, `div`, `neg`, `abs`, `sqrt`, `shl`, `shr`, `convert`, `extract`, `replace`, etc., are present. This forms the basis of the functional summary.

4. **Analyze Specific Function Examples (Mid-Level):**
    * **Integer Operations:**  Functions like `emit_i32x4_add`, `emit_i64x2_shl`, `emit_i32x4_extmul_low_i16x8_s` are examples of integer SIMD operations. Notice the suffixes like `_s` (signed) and `_u` (unsigned), `_low` and `_high` (for extended multiplication). This reveals nuances in the integer operations.
    * **Floating-Point Operations:** Functions like `emit_f32x4_abs`, `emit_f64x2_sqrt`, `emit_f32x4_min` demonstrate floating-point SIMD operations. The presence of `relaxed_min/max` and `pmin/pmax` suggests different interpretations of min/max, possibly related to NaN handling.
    * **Conversions:**  A significant number of functions deal with data type conversions, such as `emit_i64x2_sconvert_i32x4_low`, `emit_f32x4_sconvert_i32x4`. This is crucial for interoperability between different data types.
    * **Lane Operations:**  Functions like `emit_i8x16_extract_lane_s` and `emit_i8x16_replace_lane` indicate the ability to access and modify individual elements (lanes) within SIMD vectors.
    * **Bitwise Operations:**  `emit_s128_and_not` demonstrates bitwise logical operations on SIMD vectors.
    * **Conditional Compilation:**  The `DCHECK(CpuFeatures::IsSupported(...))` lines and `CpuFeatureScope` indicate that the code adapts to different CPU capabilities (like SSE4.1, AVX, F16C).

5. **Consider JavaScript Relevance:**  WebAssembly is designed to be a compilation target for languages like C, C++, and Rust, but it's also executed in web browsers within a JavaScript environment. Therefore, the SIMD operations exposed here directly correspond to WebAssembly's SIMD instructions, which can be used by JavaScript code through the WebAssembly API. This leads to the JavaScript example showing how to create and manipulate SIMD values.

6. **Infer Code Logic (Simple Cases):** For basic operations like addition or negation, the logic is straightforward: take the input registers, perform the corresponding assembly instruction, and store the result in the destination register. For more complex operations like extended multiplication, helper functions (`liftoff::I32x4ExtMulHelper`) are used, suggesting internal implementation details.

7. **Identify Potential Programming Errors:** Common errors in SIMD programming often revolve around:
    * **Type mismatches:** Applying operations to incompatible data types.
    * **Lane index errors:** Accessing non-existent lanes.
    * **Unintended side effects:** Modifying source registers when not intended.
    * **Incorrect NaN handling:**  Different min/max implementations might behave differently with NaNs.

8. **Check for Torque:** The prompt specifically asks about `.tq` files. Since the file ends in `.h`, it is **not** a Torque file.

9. **Synthesize the Summary:** Combine the observations from the previous steps to create a concise summary of the file's purpose and functionality. Emphasize the code generation aspect, the target architecture (x64), the focus on SIMD operations, and the relationship to WebAssembly.

10. **Review and Refine:**  Read through the analysis and ensure it's clear, accurate, and addresses all aspects of the prompt. For example, explicitly stating that it's *not* a Torque file is important. Making sure the JavaScript example is relevant and easy to understand is also crucial.

By following this structured approach, we can effectively analyze and understand the purpose and functionality of this C++ header file snippet within the larger context of the V8 JavaScript engine.
这是V8 JavaScript引擎中用于x64架构的Liftoff编译器的汇编器头文件（inline实现部分）。它定义了用于生成x64汇编代码以执行WebAssembly (Wasm) SIMD (Single Instruction, Multiple Data) 操作的内联函数。

**功能列举:**

该文件主要包含了一系列 `emit_` 开头的内联函数，每个函数对应一个特定的Wasm SIMD 指令，并负责生成相应的x64汇编代码。这些函数覆盖了多种SIMD操作，包括：

* **整数运算 (Integer Arithmetic):**
    * 加法 (`add`)
    * 减法 (`sub`)
    * 乘法 (`mul`)
    * 否定 (`neg`)
    * 所有位为真 (`alltrue`)
    * 左移 (`shl`, `shli`)
    * 有符号右移 (`shr_s`, `shri_s`)
    * 无符号右移 (`shr_u`, `shri_u`)
    * 扩展乘法 (`extmul_low`, `extmul_high`)
    * 按位与非 (`and_not`)
    * 四舍五入平均值 (`rounding_average_u`)
    * 绝对值 (`abs`)
* **浮点数运算 (Floating-Point Arithmetic):**
    * 绝对值 (`abs`)
    * 否定 (`neg`)
    * 平方根 (`sqrt`)
    * 向上取整 (`ceil`)
    * 向下取整 (`floor`)
    * 向零取整 (`trunc`)
    * 四舍五入到最近整数 (`nearest_int`)
    * 加法 (`add`)
    * 减法 (`sub`)
    * 乘法 (`mul`)
    * 除法 (`div`)
    * 最小值 (`min`, `pmin`, `relaxed_min`)
    * 最大值 (`max`, `pmax`, `relaxed_max`)
    * 融合乘法加法/减法 (`qfma`, `qfms`)
* **类型转换 (Conversions):**
    * 整数类型之间的转换 (例如，i16x8 到 i8x16)
    * 浮点数类型之间的转换 (例如，f32x4 到 f64x2)
    * 整数到浮点数的转换
    * 浮点数到整数的转换 (包括饱和截断)
* **位操作 (Bitwise Operations):**
    * 位掩码 (`bitmask`)
* **通道操作 (Lane Operations):**
    * 提取通道 (`extract_lane`)
    * 替换通道 (`replace_lane`)
    * 广播/填充 (`splat`，仅限 f16x8)
* **数据打包和解包 (Pack and Unpack):**
    * 有符号/无符号饱和打包 (`sconvert`, `uconvert`)
* **其他:**
    * 获取位掩码 (`bitmask`)

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 以 `.h` 结尾，这是一个C++头文件，包含了内联函数的声明和定义。因此，它**不是** Torque 源代码。

* **与 JavaScript 的关系:** 这个文件直接关系到 JavaScript 的功能，因为它实现了 WebAssembly 的 SIMD 指令支持。JavaScript 可以通过 `WebAssembly` API 加载和执行 WebAssembly 模块。如果 WebAssembly 模块使用了 SIMD 指令，V8 的 Liftoff 编译器会使用这个头文件中定义的函数来生成高效的 x64 汇编代码，从而在 JavaScript 引擎中执行这些 SIMD 操作。

**JavaScript 示例:**

假设一个 WebAssembly 模块包含一个将两个 i32x4 向量相加的函数。在 JavaScript 中，我们可以这样调用它：

```javascript
const wasmCode = new Uint8Array([
  // ... WebAssembly 字节码，包含 i32x4.add 指令 ...
]);

WebAssembly.instantiate(wasmCode)
  .then(module => {
    const addVectors = module.instance.exports.addVectors;
    const a = new Int32Array([1, 2, 3, 4]);
    const b = new Int32Array([5, 6, 7, 8]);
    const result = addVectors(a, b); // 内部会使用 LiftoffAssembler 生成的代码
    console.log(result); // 输出类似 [6, 8, 10, 12] 的结果
  });
```

在这个例子中，当 `addVectors` 函数被调用时，如果它是用 Liftoff 编译的，V8 内部就会使用 `emit_i32x4_add` 函数生成 x64 汇编指令来执行向量加法。

**代码逻辑推理 (以 `emit_i32x4_add` 为例):**

**假设输入:**

* `dst`: 目标 `LiftoffRegister`，用于存储结果。
* `lhs`: 左操作数 `LiftoffRegister`。
* `rhs`: 右操作数 `LiftoffRegister`。

**代码逻辑:**

```c++
void LiftoffAssembler::emit_i32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddd, &Assembler::paddd>(
      this, dst, lhs, rhs);
}
```

1. `liftoff::EmitSimdCommutativeBinOp` 是一个辅助函数，用于处理可交换的 SIMD 二元运算。
2. `&Assembler::vpaddd` 和 `&Assembler::paddd` 是指向 `MacroAssembler` 类中 AVX 和 SSE4.1 指令 `vpaddd` 和 `paddd` 的函数指针。`vpaddd` 是 AVX 指令，`paddd` 是 SSE4.1 指令，用于执行 32 位整数的向量加法。
3. 根据 CPU 的特性支持情况，这个辅助函数会选择合适的指令 (`vpaddd` 如果支持 AVX，否则使用 `paddd`)，并将操作数 `lhs` 和 `rhs` 的内容相加，然后将结果存储到 `dst` 寄存器中。

**输出:**

生成相应的 x64 汇编代码，例如 (如果支持 AVX)：

```assembly
vpaddd dst_register, lhs_register, rhs_register
```

或者 (如果不支持 AVX，使用 SSE4.1)：

```assembly
paddd dst_register, rhs_register
```

**用户常见的编程错误:**

在与这类底层代码交互的场景中（例如，编写 WebAssembly 代码或 V8 引擎的底层部分），常见的错误包括：

1. **类型不匹配:**  尝试对不兼容的数据类型执行 SIMD 操作。例如，尝试将 `i32x4` 向量与 `f32x4` 向量相加。WebAssembly 的类型系统会在编译时捕获这类错误，但如果手动编写汇编或进行底层的编译器开发，就需要格外注意。

2. **寄存器分配错误:** 在更底层的汇编代码编写中，错误地使用或覆盖寄存器会导致不可预测的行为。虽然 Liftoff 汇编器抽象了一部分寄存器管理的复杂性，但在实现新的操作时仍然需要小心。

3. **指令使用不当:** 错误地使用 SIMD 指令，例如，使用有符号的移位指令处理无符号数，或者混淆不同的 `min`/`max` 指令（例如 `minps` vs `pminps` 的 NaN 处理方式可能不同）。

4. **内存访问错误:** 当 SIMD 操作涉及到内存加载或存储时，错误的内存地址或对齐方式会导致崩溃或其他问题。

**第 5 部分功能归纳:**

这部分代码主要定义了 `LiftoffAssembler` 类中用于生成 x64 汇编代码的内联函数，专注于实现 WebAssembly SIMD 指令集的各种操作。这些操作涵盖了整数和浮点数的算术运算、类型转换、位操作以及通道操作。它使得 Liftoff 编译器能够将 WebAssembly 的 SIMD 指令高效地翻译成底层的 x64 机器码，从而提升 WebAssembly 在 V8 引擎中的执行性能。该文件是 V8 引擎支持 WebAssembly SIMD 功能的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
chDoubleReg, low, is_signed);
  } else {
    // dst == src2
    // Extended multiplication is commutative,
    assm->movaps(dst, src2);
    assm->I32x4ExtMul(dst, dst, src1, kScratchDoubleReg, low, is_signed);
  }
}
}  // namespace liftoff

void LiftoffAssembler::emit_i32x4_extmul_low_i16x8_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(), /*low=*/true,
                             /*is_signed=*/true);
}

void LiftoffAssembler::emit_i32x4_extmul_low_i16x8_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(), /*low=*/true,
                             /*is_signed=*/false);
}

void LiftoffAssembler::emit_i32x4_extmul_high_i16x8_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(),
                             /*low=*/false,
                             /*is_signed=*/true);
}

void LiftoffAssembler::emit_i32x4_extmul_high_i16x8_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  liftoff::I32x4ExtMulHelper(this, dst.fp(), src1.fp(), src2.fp(),
                             /*low=*/false,
                             /*is_signed=*/false);
}

void LiftoffAssembler::emit_i64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  I64x2Neg(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i64x2_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue<&MacroAssembler::Pcmpeqq>(this, dst, src, SSE4_1);
}

void LiftoffAssembler::emit_i64x2_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsllq, &Assembler::psllq, 6>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsllq, &Assembler::psllq, 6>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  I64x2ShrS(dst.fp(), lhs.fp(), rhs.gp(), kScratchDoubleReg,
            liftoff::kScratchDoubleReg2, kScratchRegister);
}

void LiftoffAssembler::emit_i64x2_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  I64x2ShrS(dst.fp(), lhs.fp(), rhs & 0x3F, kScratchDoubleReg);
}

void LiftoffAssembler::emit_i64x2_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  liftoff::EmitSimdShiftOp<&Assembler::vpsrlq, &Assembler::psrlq, 6>(this, dst,
                                                                     lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_shri_u(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  liftoff::EmitSimdShiftOpImm<&Assembler::vpsrlq, &Assembler::psrlq, 6>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpaddq, &Assembler::paddq>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpsubq, &Assembler::psubq>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  static constexpr RegClass tmp_rc = reg_class_for(kS128);
  LiftoffRegister tmp1 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, lhs, rhs});
  LiftoffRegister tmp2 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, lhs, rhs, tmp1});
  I64x2Mul(dst.fp(), lhs.fp(), rhs.fp(), tmp1.fp(), tmp2.fp());
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_s(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), kScratchDoubleReg, /*low=*/true,
              /*is_signed=*/true);
}

void LiftoffAssembler::emit_i64x2_extmul_low_i32x4_u(LiftoffRegister dst,
                                                     LiftoffRegister src1,
                                                     LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), kScratchDoubleReg, /*low=*/true,
              /*is_signed=*/false);
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), kScratchDoubleReg, /*low=*/false,
              /*is_signed=*/true);
}

void LiftoffAssembler::emit_i64x2_extmul_high_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src1,
                                                      LiftoffRegister src2) {
  I64x2ExtMul(dst.fp(), src1.fp(), src2.fp(), kScratchDoubleReg, /*low=*/false,
              /*is_signed=*/false);
}

void LiftoffAssembler::emit_i64x2_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  Movmskpd(dst.gp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovsxdq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_sconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I64x2SConvertI32x4High(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovzxdq(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_uconvert_i32x4_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I64x2UConvertI32x4High(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Absps(dst.fp(), src.fp(), kScratchRegister);
}

void LiftoffAssembler::emit_f32x4_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Negps(dst.fp(), src.fp(), kScratchRegister);
}

void LiftoffAssembler::emit_f32x4_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Sqrtps(dst.fp(), src.fp());
}

bool LiftoffAssembler::emit_f32x4_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f32x4_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f32x4_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f32x4_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundps(dst.fp(), src.fp(), kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f32x4_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vaddps, &Assembler::addps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vsubps, &Assembler::subps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vmulps, &Assembler::mulps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vdivps, &Assembler::divps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F32x4Min(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F32x4Max(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way minps works, pmin(a, b) = minps(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminps, &Assembler::minps>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f32x4_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way maxps works, pmax(a, b) = maxps(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxps, &Assembler::maxps>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f32x4_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminps, &Assembler::minps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f32x4_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxps, &Assembler::maxps>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Abspd(dst.fp(), src.fp(), kScratchRegister);
}

void LiftoffAssembler::emit_f64x2_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Negpd(dst.fp(), src.fp(), kScratchRegister);
}

void LiftoffAssembler::emit_f64x2_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  Sqrtpd(dst.fp(), src.fp());
}

bool LiftoffAssembler::emit_f64x2_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f64x2_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f64x2_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f64x2_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  DCHECK(CpuFeatures::IsSupported(SSE4_1));
  Roundpd(dst.fp(), src.fp(), kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f64x2_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vaddpd, &Assembler::addpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vsubpd, &Assembler::subpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vmulpd, &Assembler::mulpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vdivpd, &Assembler::divpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F64x2Min(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  F64x2Max(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_relaxed_min(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminpd, &Assembler::minpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_relaxed_max(LiftoffRegister dst,
                                              LiftoffRegister lhs,
                                              LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxpd, &Assembler::maxpd>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_f64x2_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way minpd works, pmin(a, b) = minpd(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vminpd, &Assembler::minpd>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f64x2_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  // Due to the way maxpd works, pmax(a, b) = maxpd(b, a).
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vmaxpd, &Assembler::maxpd>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_s(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  Cvtdq2pd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_f64x2_convert_low_i32x4_u(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  F64x2ConvertLowI32x4U(dst.fp(), src.fp(), kScratchRegister);
}

void LiftoffAssembler::emit_f64x2_promote_low_f32x4(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  Cvtps2pd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  I32x4SConvertF32x4(dst.fp(), src.fp(), kScratchDoubleReg, kScratchRegister);
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  I32x4TruncF32x4U(dst.fp(), src.fp(), kScratchDoubleReg,
                   liftoff::kScratchDoubleReg2);
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Cvtdq2ps(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Pxor(kScratchDoubleReg, kScratchDoubleReg);           // Zeros.
  Pblendw(kScratchDoubleReg, src.fp(), uint8_t{0x55});  // Get lo 16 bits.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpsubd(dst.fp(), src.fp(), kScratchDoubleReg);  // Get hi 16 bits.
  } else {
    if (dst.fp() != src.fp()) movaps(dst.fp(), src.fp());
    psubd(dst.fp(), kScratchDoubleReg);
  }
  Cvtdq2ps(kScratchDoubleReg, kScratchDoubleReg);  // Convert lo exactly.
  Psrld(dst.fp(), uint8_t{1});         // Divide by 2 to get in unsigned range.
  Cvtdq2ps(dst.fp(), dst.fp());        // Convert hi, exactly.
  Addps(dst.fp(), dst.fp());           // Double hi, exactly.
  Addps(dst.fp(), kScratchDoubleReg);  // Add hi and lo, may round.
}

void LiftoffAssembler::emit_f32x4_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  Cvtpd2ps(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i8x16_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpacksswb,
                                       &Assembler::packsswb>(this, dst, lhs,
                                                             rhs);
}

void LiftoffAssembler::emit_i8x16_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpackuswb,
                                       &Assembler::packuswb>(this, dst, lhs,
                                                             rhs);
}

void LiftoffAssembler::emit_i16x8_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpackssdw,
                                       &Assembler::packssdw>(this, dst, lhs,
                                                             rhs);
}

void LiftoffAssembler::emit_i16x8_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vpackusdw,
                                       &Assembler::packusdw>(this, dst, lhs,
                                                             rhs, SSE4_1);
}

void LiftoffAssembler::emit_i16x8_sconvert_i8x16_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovsxbw(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i16x8_sconvert_i8x16_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I16x8SConvertI8x16High(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i16x8_uconvert_i8x16_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovzxbw(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i16x8_uconvert_i8x16_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I16x8UConvertI8x16High(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_sconvert_i16x8_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovsxwd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_sconvert_i16x8_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I32x4SConvertI16x8High(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_uconvert_i16x8_low(LiftoffRegister dst,
                                                     LiftoffRegister src) {
  Pmovzxwd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_uconvert_i16x8_high(LiftoffRegister dst,
                                                      LiftoffRegister src) {
  I32x4UConvertI16x8High(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  I32x4TruncSatF64x2SZero(dst.fp(), src.fp(), kScratchDoubleReg,
                          kScratchRegister);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  I32x4TruncSatF64x2UZero(dst.fp(), src.fp(), kScratchDoubleReg,
                          kScratchRegister);
}

void LiftoffAssembler::emit_s128_and_not(LiftoffRegister dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  liftoff::EmitSimdNonCommutativeBinOp<&Assembler::vandnps, &Assembler::andnps>(
      this, dst, rhs, lhs);
}

void LiftoffAssembler::emit_i8x16_rounding_average_u(LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpavgb, &Assembler::pavgb>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i16x8_rounding_average_u(LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpavgw, &Assembler::pavgw>(
      this, dst, lhs, rhs);
}

void LiftoffAssembler::emit_i8x16_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Pabsb(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Pabsw(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i32x4_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  Pabsd(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_i64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  I64x2Abs(dst.fp(), src.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Pextrb(dst.gp(), lhs.fp(), imm_lane_idx);
  movsxbl(dst.gp(), dst.gp());
}

void LiftoffAssembler::emit_i8x16_extract_lane_u(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Pextrb(dst.gp(), lhs.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_i16x8_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Pextrw(dst.gp(), lhs.fp(), imm_lane_idx);
  movsxwl(dst.gp(), dst.gp());
}

void LiftoffAssembler::emit_i16x8_extract_lane_u(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Pextrw(dst.gp(), lhs.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_i32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  Pextrd(dst.gp(), lhs.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_i64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  Pextrq(dst.gp(), lhs.fp(), static_cast<int8_t>(imm_lane_idx));
}

void LiftoffAssembler::emit_f32x4_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  F32x4ExtractLane(dst.fp(), lhs.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_f64x2_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  F64x2ExtractLane(dst.fp(), lhs.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_i8x16_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpinsrb(dst.fp(), src1.fp(), src2.gp(), imm_lane_idx);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    if (dst.fp() != src1.fp()) movaps(dst.fp(), src1.fp());
    pinsrb(dst.fp(), src2.gp(), imm_lane_idx);
  }
}

void LiftoffAssembler::emit_i16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpinsrw(dst.fp(), src1.fp(), src2.gp(), imm_lane_idx);
  } else {
    if (dst.fp() != src1.fp()) movaps(dst.fp(), src1.fp());
    pinsrw(dst.fp(), src2.gp(), imm_lane_idx);
  }
}

void LiftoffAssembler::emit_i32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpinsrd(dst.fp(), src1.fp(), src2.gp(), imm_lane_idx);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    if (dst.fp() != src1.fp()) movaps(dst.fp(), src1.fp());
    pinsrd(dst.fp(), src2.gp(), imm_lane_idx);
  }
}

void LiftoffAssembler::emit_i64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpinsrq(dst.fp(), src1.fp(), src2.gp(), imm_lane_idx);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    if (dst.fp() != src1.fp()) movaps(dst.fp(), src1.fp());
    pinsrq(dst.fp(), src2.gp(), imm_lane_idx);
  }
}

void LiftoffAssembler::emit_f32x4_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vinsertps(dst.fp(), src1.fp(), src2.fp(), (imm_lane_idx << 4) & 0x30);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    if (dst.fp() != src1.fp()) movaps(dst.fp(), src1.fp());
    insertps(dst.fp(), src2.fp(), (imm_lane_idx << 4) & 0x30);
  }
}

void LiftoffAssembler::emit_f64x2_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  F64x2ReplaceLane(dst.fp(), src1.fp(), src2.fp(), imm_lane_idx);
}

void LiftoffAssembler::emit_f32x4_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F32x4Qfma(dst.fp(), src1.fp(), src2.fp(), src3.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F32x4Qfms(dst.fp(), src1.fp(), src2.fp(), src3.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F64x2Qfma(dst.fp(), src1.fp(), src2.fp(), src3.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F64x2Qfms(dst.fp(), src1.fp(), src2.fp(), src3.fp(), kScratchDoubleReg);
}

bool LiftoffAssembler::emit_f16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(F16C) || !CpuFeatures::IsSupported(AVX2)) {
    return false;
  }
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx2_scope(this, AVX2);
  vcvtps2ph(dst.fp(), src.fp(), 0);
  vpbroadcastw(dst.fp(), dst.fp());
  return true;
}

bool LiftoffAssembler::emit_f16x8_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  if (!CpuFeatures::IsSupported(F16C) || !CpuFeatures::IsSupported(AVX)) {
    return false;
  }
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  Pextrw(kScratchRegister, lhs.fp(), imm_lane_idx);
  vmovd(dst.fp(), kScratchRegister);
  vcvtph2ps(dst.fp(), dst.fp());
  return true;
}

bool LiftoffAssembler::emit_f16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  if (!CpuFeatures::IsSupported(F16C) || !CpuFeatures::IsSupported(AVX)) {
    return false;
  }
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  vcvtps2ph(kScratchDoubleReg, src2.fp(), 0);
  vmovd(kScratchRegister, kScratchDoubleReg);
  vpinsrw(dst.fp(), src1.fp(), kScratchRegister, imm_lane_idx);
  return true;
}

bool LiftoffAssembler::emit_f16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(AVX)) {
    return false;
  }
  CpuFeatureScope avx_scope(this, AVX);
  Absph(dst.fp(), src.fp(), kScratchRegister);
  return true;
}

bool LiftoffAssembler::emit_f16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(AVX)) {
    return false;
  }
  CpuFeatureScope avx_scope(this, AVX);
  Negph(dst.fp(), src.fp(), kScratchRegister);
  return true;
}

bool LiftoffAssembler::emit_f16x8_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(F16C) || !CpuFeatures::IsSupported(AVX)) {
    return false;
  }
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  YMMRegister ydst = YMMRegister::from_code(dst.fp().code());
  vcvtph2ps(ydst, src.fp());
  vsqrtps(ydst, ydst);
  vcvtps2ph(dst.fp(), ydst, 0);
  return true;
}

bool LiftoffAssembler::emit_f16x8_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  if (!CpuFeatures::IsSupported(F16C) || !CpuFeatures::IsSupported(AVX)) {
    return false;
  }
  CpuFeatureScope f16c_scope(this, F16C);
  CpuFeatureScope avx_scope(this, AVX);
  YMMRegister ydst = YMMRegister::from_code(dst.fp().code());
  vcvtph2ps(ydst, src.fp());
  vroundps(ydst, ydst, kRoundUp);
  vcvtps2ph(dst.fp(), ydst, 0);
  return true;
}

bool LiftoffAssembler::emit_f16x8_floor(LiftoffRegister ds
```