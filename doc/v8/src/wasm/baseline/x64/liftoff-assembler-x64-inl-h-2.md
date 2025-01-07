Response:
The user wants me to analyze a C++ header file from the V8 JavaScript engine. I need to identify the functionality of the code provided. The prompt also includes specific instructions for different scenarios, like if the file were a Torque file, its relation to JavaScript, code logic examples, common programming errors, and a summary.

Here's a breakdown of my plan:

1. **Identify the Core Functionality:**  Scan the provided C++ code snippets and look for patterns, function names, and operations that indicate the purpose of the code. The presence of functions like `emit_f64_min`, `emit_f64_max`, `emit_f64_abs`, `emit_type_conversion`, `emit_i32_signextend_i8`, `emit_jump`, `emit_cond_jump`, and various SIMD-related functions suggests this file deals with low-level code generation for WebAssembly within the Liftoff compiler.

2. **Address the ".tq" scenario:**  The prompt explicitly asks what would happen if the file ended in ".tq". I know that ".tq" signifies a Torque source file in V8. Therefore, I need to state that and explain the difference between C++ and Torque in this context (higher-level, type-safe code generation).

3. **JavaScript Relation:** Determine if and how the provided C++ code relates to JavaScript functionality. Since this is part of the WebAssembly baseline compiler, it directly impacts the execution of WebAssembly code within a JavaScript environment. I need to illustrate this with a JavaScript example that calls WebAssembly.

4. **Code Logic Examples:** Choose a few representative functions and provide hypothetical inputs and outputs to demonstrate their behavior. Good candidates are arithmetic operations, comparisons, and type conversions.

5. **Common Programming Errors:** Consider the types of errors a programmer might make when interacting with or relying on the functionality in this header file. This might involve misunderstandings of floating-point behavior, incorrect type conversions, or issues with conditional jumps.

6. **Functionality Summary:**  Synthesize the identified functionalities into a concise summary.

7. **Part Numbering:** Acknowledge that this is part 3 of a 6-part series.

**Detailed Steps and Reasoning:**

* **Core Functionality:**  The `LiftoffAssembler` class clearly has methods for generating machine code instructions. The prefixes "emit_" and the names of the functions directly correspond to WebAssembly operations (e.g., `f64.min`, `f64.copysign`, type conversions, integer sign extensions, jumps, conditional jumps, SIMD operations). The presence of `MacroAssembler` indicates interaction with V8's assembly generation infrastructure.

* **Torque Scenario:** If the file ended in `.tq`, it would be a Torque file. Torque is a domain-specific language used in V8 for generating optimized code. It offers higher-level abstractions and type safety compared to raw assembly or C++.

* **JavaScript Relation:**  WebAssembly allows executing code written in languages other than JavaScript within the browser. JavaScript uses the WebAssembly API to load, instantiate, and call WebAssembly modules. The C++ code here is responsible for *how* those WebAssembly instructions are translated into machine code.

* **Code Logic Examples:**
    * `emit_f64_div`:  Simple division.
    * `emit_f64_min`:  Finding the minimum.
    * `emit_type_conversion` (e.g., `kExprI32SConvertF64`): Converting a double to a signed 32-bit integer. I need to consider the truncation behavior.
    * `emit_cond_jump`:  Illustrate a simple conditional branch.

* **Common Programming Errors:**
    * Floating-point comparisons (NaN issues).
    * Integer overflow during conversions.
    * Incorrect conditional jump logic (e.g., using the wrong condition).

* **Functionality Summary:**  The file defines helper functions within the `LiftoffAssembler` class to generate x64 machine code for various WebAssembly operations. It includes operations for floating-point arithmetic, comparisons, type conversions, control flow (jumps), and SIMD instructions.

* **Part Numbering:**  Simply acknowledge the "Part 3 of 6" instruction.

By following these steps, I can provide a comprehensive and accurate analysis of the given V8 source code snippet.
这是文件 `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 的第三部分代码，它定义了 `LiftoffAssembler` 类的一些内联成员函数，用于在 x64 架构上生成 WebAssembly Liftoff 编译器的汇编代码。

**功能归纳:**

这部分代码主要负责实现以下功能：

1. **浮点数运算操作:** 提供了用于生成双精度浮点数 (f64) 运算指令的函数，例如：
   - 除法 (`emit_f64_div`)
   - 取最小值 (`emit_f64_min`)
   - 复制符号位 (`emit_f64_copysign`)
   - 取最大值 (`emit_f64_max`)
   - 取绝对值 (`emit_f64_abs`)
   - 取负数 (`emit_f64_neg`)
   - 向上取整 (`emit_f64_ceil`)
   - 向下取整 (`emit_f64_floor`)
   - 向零取整 (`emit_f64_trunc`)
   - 四舍五入到最接近的整数 (`emit_f64_nearest_int`)
   - 平方根 (`emit_f64_sqrt`)

2. **类型转换:**  提供了一个通用的 `emit_type_conversion` 函数，根据给定的 WebAssembly 操作码 (`WasmOpcode`) 生成不同类型之间的转换指令，例如：
   - 整数类型之间的转换 (i32 到 i64，反之亦然)
   - 浮点数到整数的转换 (f32/f64 到 i32/i64，包括截断和饱和截断)
   - 整数到浮点数的转换 (i32/i64 到 f32/f64)
   - 浮点数之间的转换 (f32 到 f64，反之亦然)
   - 重新解释类型 (将浮点数的二进制表示解释为整数，反之亦然)

3. **整数符号扩展:** 提供了用于生成整数符号扩展指令的函数，将较小的整数类型扩展到较大的整数类型，并保留其符号：
   - `emit_i32_signextend_i8` (将 8 位有符号整数扩展为 32 位有符号整数)
   - `emit_i32_signextend_i16` (将 16 位有符号整数扩展为 32 位有符号整数)
   - `emit_i64_signextend_i8` (将 8 位有符号整数扩展为 64 位有符号整数)
   - `emit_i64_signextend_i16` (将 16 位有符号整数扩展为 64 位有符号整数)
   - `emit_i64_signextend_i32` (将 32 位有符号整数扩展为 64 位有符号整数)

4. **控制流:**  提供了用于生成控制流指令的函数：
   - 无条件跳转 (`emit_jump`)，可以跳转到标签或寄存器指定的地址。
   - 条件跳转 (`emit_cond_jump`)，根据条件码的值跳转到标签。
   - 与立即数比较的条件跳转 (`emit_i32_cond_jumpi`, `emit_ptrsize_cond_jumpi`)

5. **比较和设置:**  提供了用于生成比较指令并根据比较结果设置寄存器的函数：
   - 比较是否为零 (`emit_i32_eqz`, `emit_i64_eqz`)
   - 根据条件设置寄存器 (`emit_i32_set_cond`, `emit_i64_set_cond`)
   - 浮点数比较并设置寄存器 (`emit_f32_set_cond`, `emit_f64_set_cond`)，需要处理 NaN 的情况。

6. **选择 (Select):**  提供了 `emit_select` 函数，根据条件寄存器的值选择两个寄存器中的一个值并将其移动到目标寄存器。

7. **Smi 检查:** 提供了 `emit_smi_check` 函数，用于检查寄存器中的值是否为 Smi (Small Integer)。

8. **SIMD 操作:**  提供了一系列用于生成 SIMD (Single Instruction, Multiple Data) 指令的函数，用于并行处理多个数据元素，包括：
   - 通用的 SIMD 二元运算模板 (`EmitSimdCommutativeBinOp`, `EmitSimdNonCommutativeBinOp`)
   - SIMD 移位操作模板 (`EmitSimdShiftOp`, `EmitSimdShiftOpImm`)
   - 检查 SIMD 寄存器中是否有任何位为真 (`EmitAnyTrue`)
   - 检查 SIMD 寄存器中所有位是否为真 (`EmitAllTrue`)
   - SIMD 加载和存储操作 (`LoadTransform`, `LoadLane`, `StoreLane`)
   - SIMD 数据重排操作 (`emit_i8x16_shuffle`, `emit_i8x16_swizzle`, `emit_i8x16_relaxed_swizzle`)
   - SIMD 类型转换 (`emit_i32x4_relaxed_trunc_f32x4_s`, `emit_i32x4_relaxed_trunc_f32x4_u`, 等)
   - SIMD 选择 (`emit_s128_relaxed_laneselect`)
   - SIMD 位计数 (`emit_i8x16_popcnt`)
   - SIMD 填充操作 (`emit_i8x16_splat`, `emit_i16x8_splat`, `emit_i32x4_splat`, `emit_i64x2_splat`, `emit_f32x4_splat`, `emit_f64x2_splat`)
   - SIMD 比较操作 (`emit_i8x16_eq`, `emit_i8x16_ne`, `emit_i8x16_gt_s`, `emit_i8x16_gt_u`)

**如果 `v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是一种用于 V8 开发的领域特定语言，用于定义运行时函数的实现。Torque 代码会被编译成 C++ 代码，然后再进行编译。与 C++ 代码相比，Torque 提供了更高的抽象级别和更强的类型安全性。

**与 JavaScript 的功能关系以及 JavaScript 示例:**

`LiftoffAssembler` 生成的汇编代码直接用于执行 WebAssembly 代码。当 JavaScript 代码调用 WebAssembly 模块时，Liftoff 编译器会将 WebAssembly 指令快速编译成本地机器码，这些机器码的生成就依赖于 `LiftoffAssembler` 中定义的函数。

**JavaScript 示例:**

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x10, 0x01,
  0x07, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x02, 0x6d, 0x65, 0x6d,
  0x6f, 0x72, 0x79, 0x02, 0x01, 0x7f, 0x00, 0x0a, 0x08, 0x01, 0x06, 0x00,
  0x20, 0x00, 0x41, 0x01, 0x6a, 0x0b,
]);

WebAssembly.instantiate(wasmCode).then(instance => {
  // 这个 WebAssembly 模块可能包含一个将局部变量与常量相加的函数。
  // LiftoffAssembler 会生成相应的机器码，例如加载局部变量、加载常量、执行加法操作。
  // const result = instance.exports.add(5);
  // console.log(result);
});
```

在这个例子中，当 `WebAssembly.instantiate` 加载和编译 WebAssembly 代码时，如果使用了 Liftoff 编译器，`LiftoffAssembler` 中的函数就会被调用来生成执行诸如加载局部变量、加载常量、执行整数加法等操作的 x64 汇编指令。

**代码逻辑推理示例:**

**假设输入:** 调用 `emit_f64_div(xmm0, xmm1, xmm2)`。

**输出:**  生成的汇编指令将 `xmm1` 寄存器中的双精度浮点数除以 `xmm2` 寄存器中的双精度浮点数，并将结果存储在 `xmm0` 寄存器中。如果 `dst != lhs`，则会先将 `lhs` 移动到 `dst`。生成的指令可能是 `movsd %xmm1, %xmm0` (如果 `xmm0 != xmm1`) 和 `divsd %xmm2, %xmm0`。

**用户常见的编程错误示例:**

1. **浮点数比较错误:**  用户可能会直接使用 `emit_f64_set_cond` 生成的比较指令的结果进行逻辑判断，而没有考虑到 NaN (Not-a-Number) 的情况。NaN 与任何浮点数的比较结果都为 false (除了不等于)。

   ```c++
   // C++ 代码示例（假设 condition 是一个通用寄存器）
   Label nan_case;
   asm_.emit_f64_set_cond(kEqual, condition, lhs, rhs);
   asm_.emit_cond_jump(kZero, &nan_case); // 如果相等则跳转

   // ... 后续代码假设 lhs 和 rhs 相等才能到达这里 ...
   ```

   如果 `lhs` 或 `rhs` 是 NaN，`emit_f64_set_cond` 会设置 parity flag，但 `kZero` 条件检查的是 zero flag，因此不会跳转到 `nan_case`，导致逻辑错误。正确的处理方式需要检查 parity flag。

2. **整数类型转换溢出:** 在使用 `emit_type_conversion` 进行浮点数到整数的截断转换时，如果浮点数的值超出了目标整数类型的表示范围，可能会发生溢出，导致不可预测的结果。

   ```c++
   // 假设将一个很大的双精度浮点数转换为 i32
   DoubleRegister large_double; // 包含一个超出 i32 范围的值
   Register i32_result;
   Label trap_label;
   asm_.emit_type_conversion(kExprI32SConvertF64, LiftoffRegister(i32_result), LiftoffRegister(large_double), &trap_label);
   // 如果没有正确处理溢出，i32_result 的值可能不是预期的。
   ```

   WebAssembly 提供了饱和截断操作 (`kExprI32SConvertSatF64`) 来避免溢出，但如果用户使用了普通的截断操作，则需要注意潜在的溢出问题。

总而言之，这部分代码是 WebAssembly Liftoff 编译器在 x64 架构上生成高效机器码的关键组成部分，涵盖了多种算术运算、类型转换、控制流和 SIMD 操作的汇编代码生成。

Prompt: 
```
这是目录为v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/x64/liftoff-assembler-x64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
dst != lhs) movsd(dst, lhs);
    divsd(dst, rhs);
  }
}

void LiftoffAssembler::emit_f64_min(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<double>(this, dst, lhs, rhs,
                                     liftoff::MinOrMax::kMin);
}

void LiftoffAssembler::emit_f64_copysign(DoubleRegister dst, DoubleRegister lhs,
                                         DoubleRegister rhs) {
  // Extract sign bit from {rhs} into {kScratchRegister2}.
  Movq(liftoff::kScratchRegister2, rhs);
  shrq(liftoff::kScratchRegister2, Immediate(63));
  shlq(liftoff::kScratchRegister2, Immediate(63));
  // Reset sign bit of {lhs} (in {kScratchRegister}).
  Movq(kScratchRegister, lhs);
  btrq(kScratchRegister, Immediate(63));
  // Combine both values into {kScratchRegister} and move into {dst}.
  orq(kScratchRegister, liftoff::kScratchRegister2);
  Movq(dst, kScratchRegister);
}

void LiftoffAssembler::emit_f64_max(DoubleRegister dst, DoubleRegister lhs,
                                    DoubleRegister rhs) {
  liftoff::EmitFloatMinOrMax<double>(this, dst, lhs, rhs,
                                     liftoff::MinOrMax::kMax);
}

void LiftoffAssembler::emit_f64_abs(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint64_t kSignBit = uint64_t{1} << 63;
  if (dst == src) {
    MacroAssembler::Move(kScratchDoubleReg, kSignBit - 1);
    Andpd(dst, kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit - 1);
    Andpd(dst, src);
  }
}

void LiftoffAssembler::emit_f64_neg(DoubleRegister dst, DoubleRegister src) {
  static constexpr uint64_t kSignBit = uint64_t{1} << 63;
  if (dst == src) {
    MacroAssembler::Move(kScratchDoubleReg, kSignBit);
    Xorpd(dst, kScratchDoubleReg);
  } else {
    MacroAssembler::Move(dst, kSignBit);
    Xorpd(dst, src);
  }
}

bool LiftoffAssembler::emit_f64_ceil(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundsd(dst, src, kRoundUp);
  return true;
}

bool LiftoffAssembler::emit_f64_floor(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundsd(dst, src, kRoundDown);
  return true;
}

bool LiftoffAssembler::emit_f64_trunc(DoubleRegister dst, DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundsd(dst, src, kRoundToZero);
  return true;
}

bool LiftoffAssembler::emit_f64_nearest_int(DoubleRegister dst,
                                            DoubleRegister src) {
  RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
  Roundsd(dst, src, kRoundToNearest);
  return true;
}

void LiftoffAssembler::emit_f64_sqrt(DoubleRegister dst, DoubleRegister src) {
  Sqrtsd(dst, src);
}

namespace liftoff {
#define __ assm->
// Used for float to int conversions. If the value in {converted_back} equals
// {src} afterwards, the conversion succeeded.
template <typename dst_type, typename src_type>
inline void ConvertFloatToIntAndBack(LiftoffAssembler* assm, Register dst,
                                     DoubleRegister src,
                                     DoubleRegister converted_back) {
  if (std::is_same<double, src_type>::value) {     // f64
    if (std::is_same<int32_t, dst_type>::value) {  // f64 -> i32
      __ Cvttsd2si(dst, src);
      __ Cvtlsi2sd(converted_back, dst);
    } else if (std::is_same<uint32_t, dst_type>::value) {  // f64 -> u32
      __ Cvttsd2siq(dst, src);
      __ movl(dst, dst);
      __ Cvtqsi2sd(converted_back, dst);
    } else if (std::is_same<int64_t, dst_type>::value) {  // f64 -> i64
      __ Cvttsd2siq(dst, src);
      __ Cvtqsi2sd(converted_back, dst);
    } else {
      UNREACHABLE();
    }
  } else {                                         // f32
    if (std::is_same<int32_t, dst_type>::value) {  // f32 -> i32
      __ Cvttss2si(dst, src);
      __ Cvtlsi2ss(converted_back, dst);
    } else if (std::is_same<uint32_t, dst_type>::value) {  // f32 -> u32
      __ Cvttss2siq(dst, src);
      __ movl(dst, dst);
      __ Cvtqsi2ss(converted_back, dst);
    } else if (std::is_same<int64_t, dst_type>::value) {  // f32 -> i64
      __ Cvttss2siq(dst, src);
      __ Cvtqsi2ss(converted_back, dst);
    } else {
      UNREACHABLE();
    }
  }
}

template <typename dst_type, typename src_type>
inline bool EmitTruncateFloatToInt(LiftoffAssembler* assm, Register dst,
                                   DoubleRegister src, Label* trap) {
  if (!CpuFeatures::IsSupported(SSE4_1)) {
    __ bailout(kMissingCPUFeature, "no SSE4.1");
    return true;
  }
  CpuFeatureScope feature(assm, SSE4_1);

  DoubleRegister rounded = kScratchDoubleReg;
  DoubleRegister converted_back = kScratchDoubleReg2;

  if (std::is_same<double, src_type>::value) {  // f64
    __ Roundsd(rounded, src, kRoundToZero);
  } else {  // f32
    __ Roundss(rounded, src, kRoundToZero);
  }
  ConvertFloatToIntAndBack<dst_type, src_type>(assm, dst, rounded,
                                               converted_back);
  if (std::is_same<double, src_type>::value) {  // f64
    __ Ucomisd(converted_back, rounded);
  } else {  // f32
    __ Ucomiss(converted_back, rounded);
  }

  // Jump to trap if PF is 0 (one of the operands was NaN) or they are not
  // equal.
  __ j(parity_even, trap);
  __ j(not_equal, trap);
  return true;
}

template <typename dst_type, typename src_type>
inline bool EmitSatTruncateFloatToInt(LiftoffAssembler* assm, Register dst,
                                      DoubleRegister src) {
  if (!CpuFeatures::IsSupported(SSE4_1)) {
    __ bailout(kMissingCPUFeature, "no SSE4.1");
    return true;
  }
  CpuFeatureScope feature(assm, SSE4_1);

  Label done;
  Label not_nan;
  Label src_positive;

  DoubleRegister rounded = kScratchDoubleReg;
  DoubleRegister converted_back = kScratchDoubleReg2;
  DoubleRegister zero_reg = kScratchDoubleReg;

  if (std::is_same<double, src_type>::value) {  // f64
    __ Roundsd(rounded, src, kRoundToZero);
  } else {  // f32
    __ Roundss(rounded, src, kRoundToZero);
  }

  ConvertFloatToIntAndBack<dst_type, src_type>(assm, dst, rounded,
                                               converted_back);
  if (std::is_same<double, src_type>::value) {  // f64
    __ Ucomisd(converted_back, rounded);
  } else {  // f32
    __ Ucomiss(converted_back, rounded);
  }

  // Return 0 if PF is 0 (one of the operands was NaN)
  __ j(parity_odd, &not_nan);
  __ xorl(dst, dst);
  __ jmp(&done);

  __ bind(&not_nan);
  // If rounding is as expected, return result
  __ j(equal, &done);

  __ xorpd(zero_reg, zero_reg);

  // if out-of-bounds, check if src is positive
  if (std::is_same<double, src_type>::value) {  // f64
    __ Ucomisd(src, zero_reg);
  } else {  // f32
    __ Ucomiss(src, zero_reg);
  }
  __ j(above, &src_positive);
  if (std::is_same<int32_t, dst_type>::value ||
      std::is_same<uint32_t, dst_type>::value) {  // i32
    __ movl(
        dst,
        Immediate(static_cast<int32_t>(std::numeric_limits<dst_type>::min())));
  } else if (std::is_same<int64_t, dst_type>::value) {  // i64s
    __ movq(dst, Immediate64(std::numeric_limits<dst_type>::min()));
  } else {
    UNREACHABLE();
  }
  __ jmp(&done);

  __ bind(&src_positive);
  if (std::is_same<int32_t, dst_type>::value ||
      std::is_same<uint32_t, dst_type>::value) {  // i32
    __ movl(
        dst,
        Immediate(static_cast<int32_t>(std::numeric_limits<dst_type>::max())));
  } else if (std::is_same<int64_t, dst_type>::value) {  // i64s
    __ movq(dst, Immediate64(std::numeric_limits<dst_type>::max()));
  } else {
    UNREACHABLE();
  }

  __ bind(&done);
  return true;
}

template <typename src_type>
inline bool EmitSatTruncateFloatToUInt64(LiftoffAssembler* assm, Register dst,
                                         DoubleRegister src) {
  if (!CpuFeatures::IsSupported(SSE4_1)) {
    __ bailout(kMissingCPUFeature, "no SSE4.1");
    return true;
  }
  CpuFeatureScope feature(assm, SSE4_1);

  Label done;
  Label neg_or_nan;
  Label overflow;

  DoubleRegister zero_reg = kScratchDoubleReg;

  __ xorpd(zero_reg, zero_reg);
  if (std::is_same<double, src_type>::value) {  // f64
    __ Ucomisd(src, zero_reg);
  } else {  // f32
    __ Ucomiss(src, zero_reg);
  }
  // Check if NaN
  __ j(parity_even, &neg_or_nan);
  __ j(below, &neg_or_nan);
  if (std::is_same<double, src_type>::value) {  // f64
    __ Cvttsd2uiq(dst, src, &overflow);
  } else {  // f32
    __ Cvttss2uiq(dst, src, &overflow);
  }
  __ jmp(&done);

  __ bind(&neg_or_nan);
  __ movq(dst, zero_reg);
  __ jmp(&done);

  __ bind(&overflow);
  __ movq(dst, Immediate64(std::numeric_limits<uint64_t>::max()));
  __ bind(&done);
  return true;
}
#undef __
}  // namespace liftoff

bool LiftoffAssembler::emit_type_conversion(WasmOpcode opcode,
                                            LiftoffRegister dst,
                                            LiftoffRegister src, Label* trap) {
  switch (opcode) {
    case kExprI32ConvertI64:
      movl(dst.gp(), src.gp());
      return true;
    case kExprI32SConvertF32:
      return liftoff::EmitTruncateFloatToInt<int32_t, float>(this, dst.gp(),
                                                             src.fp(), trap);
    case kExprI32UConvertF32:
      return liftoff::EmitTruncateFloatToInt<uint32_t, float>(this, dst.gp(),
                                                              src.fp(), trap);
    case kExprI32SConvertF64:
      return liftoff::EmitTruncateFloatToInt<int32_t, double>(this, dst.gp(),
                                                              src.fp(), trap);
    case kExprI32UConvertF64:
      return liftoff::EmitTruncateFloatToInt<uint32_t, double>(this, dst.gp(),
                                                               src.fp(), trap);
    case kExprI32SConvertSatF32:
      return liftoff::EmitSatTruncateFloatToInt<int32_t, float>(this, dst.gp(),
                                                                src.fp());
    case kExprI32UConvertSatF32:
      return liftoff::EmitSatTruncateFloatToInt<uint32_t, float>(this, dst.gp(),
                                                                 src.fp());
    case kExprI32SConvertSatF64:
      return liftoff::EmitSatTruncateFloatToInt<int32_t, double>(this, dst.gp(),
                                                                 src.fp());
    case kExprI32UConvertSatF64:
      return liftoff::EmitSatTruncateFloatToInt<uint32_t, double>(
          this, dst.gp(), src.fp());
    case kExprI32ReinterpretF32:
      Movd(dst.gp(), src.fp());
      return true;
    case kExprI64SConvertI32:
      movsxlq(dst.gp(), src.gp());
      return true;
    case kExprI64SConvertF32:
      return liftoff::EmitTruncateFloatToInt<int64_t, float>(this, dst.gp(),
                                                             src.fp(), trap);
    case kExprI64UConvertF32: {
      RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
      Cvttss2uiq(dst.gp(), src.fp(), trap);
      return true;
    }
    case kExprI64SConvertF64:
      return liftoff::EmitTruncateFloatToInt<int64_t, double>(this, dst.gp(),
                                                              src.fp(), trap);
    case kExprI64UConvertF64: {
      RETURN_FALSE_IF_MISSING_CPU_FEATURE(SSE4_1);
      Cvttsd2uiq(dst.gp(), src.fp(), trap);
      return true;
    }
    case kExprI64SConvertSatF32:
      return liftoff::EmitSatTruncateFloatToInt<int64_t, float>(this, dst.gp(),
                                                                src.fp());
    case kExprI64UConvertSatF32: {
      return liftoff::EmitSatTruncateFloatToUInt64<float>(this, dst.gp(),
                                                          src.fp());
    }
    case kExprI64SConvertSatF64:
      return liftoff::EmitSatTruncateFloatToInt<int64_t, double>(this, dst.gp(),
                                                                 src.fp());
    case kExprI64UConvertSatF64: {
      return liftoff::EmitSatTruncateFloatToUInt64<double>(this, dst.gp(),
                                                           src.fp());
    }
    case kExprI64UConvertI32:
      emit_u32_to_uintptr(dst.gp(), src.gp());
      return true;
    case kExprI64ReinterpretF64:
      Movq(dst.gp(), src.fp());
      return true;
    case kExprF32SConvertI32:
      Cvtlsi2ss(dst.fp(), src.gp());
      return true;
    case kExprF32UConvertI32:
      movl(kScratchRegister, src.gp());
      Cvtqsi2ss(dst.fp(), kScratchRegister);
      return true;
    case kExprF32SConvertI64:
      Cvtqsi2ss(dst.fp(), src.gp());
      return true;
    case kExprF32UConvertI64:
      Cvtqui2ss(dst.fp(), src.gp());
      return true;
    case kExprF32ConvertF64:
      Cvtsd2ss(dst.fp(), src.fp());
      return true;
    case kExprF32ReinterpretI32:
      Movd(dst.fp(), src.gp());
      return true;
    case kExprF64SConvertI32:
      Cvtlsi2sd(dst.fp(), src.gp());
      return true;
    case kExprF64UConvertI32:
      movl(kScratchRegister, src.gp());
      Cvtqsi2sd(dst.fp(), kScratchRegister);
      return true;
    case kExprF64SConvertI64:
      Cvtqsi2sd(dst.fp(), src.gp());
      return true;
    case kExprF64UConvertI64:
      Cvtqui2sd(dst.fp(), src.gp());
      return true;
    case kExprF64ConvertF32:
      Cvtss2sd(dst.fp(), src.fp());
      return true;
    case kExprF64ReinterpretI64:
      Movq(dst.fp(), src.gp());
      return true;
    default:
      UNREACHABLE();
  }
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  movsxbl(dst, src);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  movsxwl(dst, src);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  movsxbq(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  movsxwq(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  movsxlq(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_jump(Label* label) { jmp(label); }

void LiftoffAssembler::emit_jump(Register target) { jmp(target); }

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  if (rhs != no_reg) {
    switch (kind) {
      case kI32:
        cmpl(lhs, rhs);
        break;
      case kRef:
      case kRefNull:
      case kRtt:
        DCHECK(cond == kEqual || cond == kNotEqual);
#if defined(V8_COMPRESS_POINTERS)
        // It's enough to do a 32-bit comparison. This is also necessary for
        // null checks which only compare against a 32 bit value, not a full
        // pointer.
        cmpl(lhs, rhs);
#else
        cmpq(lhs, rhs);
#endif
        break;
      case kI64:
        cmpq(lhs, rhs);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    DCHECK_EQ(kind, kI32);
    testl(lhs, lhs);
  }

  j(cond, label);
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int imm,
                                           const FreezeCacheState& frozen) {
  cmpl(lhs, Immediate(imm));
  j(cond, label);
}

void LiftoffAssembler::emit_ptrsize_cond_jumpi(Condition cond, Label* label,
                                               Register lhs, int32_t imm,
                                               const FreezeCacheState& frozen) {
  cmpq(lhs, Immediate(imm));
  j(cond, label);
}

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  testl(src, src);
  setcc(equal, dst);
  movzxbl(dst, dst);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  cmpl(lhs, rhs);
  setcc(cond, dst);
  movzxbl(dst, dst);
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  testq(src.gp(), src.gp());
  setcc(equal, dst);
  movzxbl(dst, dst);
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  cmpq(lhs.gp(), rhs.gp());
  setcc(cond, dst);
  movzxbl(dst, dst);
}

namespace liftoff {
template <void (SharedMacroAssemblerBase::*cmp_op)(DoubleRegister,
                                                   DoubleRegister)>
void EmitFloatSetCond(LiftoffAssembler* assm, Condition cond, Register dst,
                      DoubleRegister lhs, DoubleRegister rhs) {
  Label cont;
  Label not_nan;

  (assm->*cmp_op)(lhs, rhs);
  // If PF is one, one of the operands was NaN. This needs special handling.
  assm->j(parity_odd, &not_nan, Label::kNear);
  // Return 1 for f32.ne, 0 for all other cases.
  if (cond == not_equal) {
    assm->movl(dst, Immediate(1));
  } else {
    assm->xorl(dst, dst);
  }
  assm->jmp(&cont, Label::kNear);
  assm->bind(&not_nan);

  assm->setcc(cond, dst);
  assm->movzxbl(dst, dst);
  assm->bind(&cont);
}
}  // namespace liftoff

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  liftoff::EmitFloatSetCond<&MacroAssembler::Ucomiss>(this, cond, dst, lhs,
                                                      rhs);
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  liftoff::EmitFloatSetCond<&MacroAssembler::Ucomisd>(this, cond, dst, lhs,
                                                      rhs);
}

bool LiftoffAssembler::emit_select(LiftoffRegister dst, Register condition,
                                   LiftoffRegister true_value,
                                   LiftoffRegister false_value,
                                   ValueKind kind) {
  if (kind != kI32 && kind != kI64) return false;

  testl(condition, condition);

  if (kind == kI32) {
    if (dst == false_value) {
      cmovl(not_zero, dst.gp(), true_value.gp());
    } else {
      if (dst != true_value) movl(dst.gp(), true_value.gp());
      cmovl(zero, dst.gp(), false_value.gp());
    }
  } else {
    if (dst == false_value) {
      cmovq(not_zero, dst.gp(), true_value.gp());
    } else {
      if (dst != true_value) movq(dst.gp(), true_value.gp());
      cmovq(zero, dst.gp(), false_value.gp());
    }
  }

  return true;
}

void LiftoffAssembler::emit_smi_check(Register obj, Label* target,
                                      SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  testb(obj, Immediate(kSmiTagMask));
  Condition condition = mode == kJumpOnSmi ? zero : not_zero;
  j(condition, target);
}

// TODO(fanchenk): Distinguish mov* if data bypass delay matter.
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
  constexpr int mask = (1 << width) - 1;
  assm->movq(kScratchRegister, count.gp());
  assm->andq(kScratchRegister, Immediate(mask));
  assm->Movq(kScratchDoubleReg, kScratchRegister);
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
  assm->xorq(dst.gp(), dst.gp());
  assm->Ptest(src.fp(), src.fp());
  assm->setcc(not_equal, dst.gp());
}

template <void (SharedMacroAssemblerBase::*pcmp)(XMMRegister, XMMRegister)>
inline void EmitAllTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src,
                        std::optional<CpuFeature> feature = std::nullopt) {
  std::optional<CpuFeatureScope> sse_scope;
  if (feature.has_value()) sse_scope.emplace(assm, *feature);

  XMMRegister tmp = kScratchDoubleReg;
  assm->xorq(dst.gp(), dst.gp());
  assm->Pxor(tmp, tmp);
  (assm->*pcmp)(tmp, src.fp());
  assm->Ptest(tmp, tmp);
  assm->setcc(equal, dst.gp());
}

}  // namespace liftoff

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  Operand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm);
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
      S128Load8Splat(dst.fp(), src_op, kScratchDoubleReg);
    } else if (memtype == MachineType::Int16()) {
      S128Load16Splat(dst.fp(), src_op, kScratchDoubleReg);
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
                                bool i64_offset) {
  if (offset_reg != no_reg && !i64_offset) AssertZeroExtended(offset_reg);
  Operand src_op = liftoff::GetMemOp(this, addr, offset_reg, offset_imm);

  MachineType mem_type = type.mem_type();
  if (mem_type == MachineType::Int8()) {
    Pinsrb(dst.fp(), src.fp(), src_op, laneidx, protected_load_pc);
  } else if (mem_type == MachineType::Int16()) {
    Pinsrw(dst.fp(), src.fp(), src_op, laneidx, protected_load_pc);
  } else if (mem_type == MachineType::Int32()) {
    Pinsrd(dst.fp(), src.fp(), src_op, laneidx, protected_load_pc);
  } else {
    DCHECK_EQ(MachineType::Int64(), mem_type);
    Pinsrq(dst.fp(), src.fp(), src_op, laneidx, protected_load_pc);
  }
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  if (offset != no_reg && !i64_offset) AssertZeroExtended(offset);
  Operand dst_op = liftoff::GetMemOp(this, dst, offset, offset_imm);
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
  if (is_swizzle) {
    uint32_t imms[4];
    // Shuffles that use just 1 operand are called swizzles, rhs can be ignored.
    wasm::SimdShuffle::Pack16Lanes(imms, shuffle);
    MacroAssembler::Move(kScratchDoubleReg, make_uint64(imms[3], imms[2]),
                         make_uint64(imms[1], imms[0]));
    Pshufb(dst.fp(), lhs.fp(), kScratchDoubleReg);
    return;
  }

  uint64_t mask1[2] = {};
  for (int i = 15; i >= 0; i--) {
    uint8_t lane = shuffle[i];
    int j = i >> 3;
    mask1[j] <<= 8;
    mask1[j] |= lane < kSimd128Size ? lane : 0x80;
  }
  MacroAssembler::Move(liftoff::kScratchDoubleReg2, mask1[1], mask1[0]);
  Pshufb(kScratchDoubleReg, lhs.fp(), liftoff::kScratchDoubleReg2);

  uint64_t mask2[2] = {};
  for (int i = 15; i >= 0; i--) {
    uint8_t lane = shuffle[i];
    int j = i >> 3;
    mask2[j] <<= 8;
    mask2[j] |= lane >= kSimd128Size ? (lane & 0x0F) : 0x80;
  }
  MacroAssembler::Move(liftoff::kScratchDoubleReg2, mask2[1], mask2[0]);

  Pshufb(dst.fp(), rhs.fp(), liftoff::kScratchDoubleReg2);
  Por(dst.fp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  I8x16Swizzle(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg,
               kScratchRegister);
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  I8x16Swizzle(dst.fp(), lhs.fp(), rhs.fp(), kScratchDoubleReg,
               kScratchRegister, true);
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
  I8x16Popcnt(dst.fp(), src.fp(), kScratchDoubleReg,
              liftoff::kScratchDoubleReg2, kScratchRegister);
}

void LiftoffAssembler::emit_i8x16_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  I8x16Splat(dst.fp(), src.gp(), kScratchDoubleReg);
}

void LiftoffAssembler::emit_i16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  I16x8Splat(dst.fp(), src.gp());
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Movd(dst.fp(), src.gp());
  Pshufd(dst.fp(), dst.fp(), static_cast<uint8_t>(0));
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  Movq(dst.fp(), src.gp());
  Movddup(dst.fp(), dst.fp());
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
  Pcmpeqb(kScratchDoubleReg, kScratchDoubleReg);
  Pxor(dst.fp(), kScratchDoubleReg);
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
    Movaps(kScratchDoubleReg, rhs.fp());
    ref = kScratchDoubleReg;
  }
  liftoff::EmitSimdCommutativeBinOp<&Assembler::vpmaxub, 
"""


```