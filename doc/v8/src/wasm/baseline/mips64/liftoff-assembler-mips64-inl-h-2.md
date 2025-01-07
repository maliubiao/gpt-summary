Response:
The user wants to understand the functionality of a C++ header file (`liftoff-assembler-mips64-inl.h`) within the V8 JavaScript engine. The request is broken down into several parts, requiring an analysis of the provided code snippet.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose of the file:** The name `liftoff-assembler` strongly suggests this file is responsible for generating machine code. The `mips64` part indicates the target architecture. The `-inl.h` suffix usually signifies inline implementations of class methods. Therefore, this file likely provides architecture-specific implementations for an assembler used in the "Liftoff" tier of the V8 WebAssembly compiler.

2. **Analyze the code snippet for functionalities:** Iterate through the provided code, focusing on the different cases within the `emit_typed_conversion` function and the other `emit_` functions.

    * **`emit_typed_conversion`:**  This function handles conversions between different numeric types (integers and floating-point numbers) with saturation. The different `kExpr` cases indicate various conversion operations (e.g., float to signed int32, double to unsigned int64). Notice the handling of NaN and boundary conditions (min/max values). The code also checks for CPU feature support (`MIPS_SIMD`), suggesting it might leverage SIMD instructions for optimization.

    * **`emit_i32_signextend_i8/i16` and `emit_i64_signextend_i8/i16/i32`:** These functions perform sign extension, converting smaller integer types to larger ones while preserving their sign.

    * **`emit_jump` and `emit_cond_jump`:** These are standard assembler functions for unconditional and conditional jumps, respectively.

    * **`emit_i32_eqz`, `emit_i32_set_cond`, `emit_i64_eqz`, `emit_i64_set_cond`:** These functions implement comparisons and set the destination register based on the result. `eqz` checks for equality with zero.

    * **`ConditionToConditionCmpFPU`:** This helper function translates V8's `Condition` enum to MIPS FPU condition codes.

    * **`EmitAnyTrue`, `EmitAllTrue`:** These seem to be helper functions for SIMD operations, checking if any or all elements in a vector are true.

    * **`StoreToMemory`:** This function handles storing values to memory, accommodating different value types (registers, constants, stack slots).

    * **`emit_f32_set_cond`, `emit_f64_set_cond`:**  These handle floating-point comparisons, including special handling for NaN values.

    * **`emit_select`:**  This function implements a conditional select operation (like a ternary operator), but the provided code always returns `false`, suggesting it might not be fully implemented or supported in this context.

    * **`emit_smi_check`:** This function checks if a value is a "Small Integer" (Smi), a tagged integer representation used in V8.

    * **`LoadTransform`, `LoadLane`, `StoreLane`:** These functions deal with loading and storing data, potentially involving SIMD registers and specific lanes within them. `LoadTransform` hints at operations like zero-extension or sign-extension during loading.

    * **`emit_i8x16_shuffle`, `emit_i8x16_swizzle`, `emit_i8x16_relaxed_swizzle`:** These functions implement SIMD shuffle and swizzle operations, rearranging elements within a vector. The "relaxed" version suggests a potentially less strict or optimized implementation.

    * **`emit_i32x4_relaxed_trunc_f32x4_s/u`, `emit_i32x4_relaxed_trunc_f64x2_s_zero/u_zero`, `emit_s128_relaxed_laneselect`:** These functions appear to be related to relaxed SIMD semantics, likely involving type conversions and lane selection. The `bailout` calls indicate that these features might not be fully implemented or optimized for this architecture.

    * **`emit_i8x16_splat`, `emit_i16x8_splat`, `emit_i32x4_splat`, `emit_i64x2_splat`, `emit_f32x4_splat`, `emit_f64x2_splat`:** These functions implement "splatting," where a scalar value is replicated across all lanes of a SIMD vector.

    * **`emit_..._extmul_low/high_...` and `emit_..._extadd_pairwise_...`:** These functions perform extended multiplication and pairwise addition on SIMD vectors.

    * **`emit_i16x8_q15mulr_sat_s` and `emit_i16x8_relaxed_q15mulr_s`:** These functions perform a specific type of saturated multiplication for SIMD vectors. The "relaxed" version again suggests potential differences in implementation.

    * **`emit_i16x8_dot_i8x16_i7x16_s` and `emit_i32x4_dot_i8x16_i7x16_add_s`:** These are likely implementing dot product operations for SIMD vectors.

    * **`emit_i8x16_eq/ne/gt_s/u/ge_s/u`, `emit_i16x8_eq/ne/gt_s/u/ge_s/u`, `emit_i32x4_eq/ne/gt_s/u/ge_s/u`, `emit_f32x4_eq/ne/lt/le`, `emit_i64x2_eq/ne/abs`, `emit_f64x2_eq/ne/lt/le`:** These functions implement element-wise comparison operations for various SIMD vector types.

    * **`emit_s128_const`, `emit_s128_not`, `emit_s128_and/or/xor/and_not/select`:** These functions handle constant loading and bitwise logical operations for SIMD vectors.

    * **`emit_i8x16_neg`:** Implements negation for a SIMD vector.

    * **`emit_v128_anytrue`, `emit_i8x16_alltrue`, `emit_i8x16_bitmask`:**  These perform checks for true values within a SIMD vector and extract a bitmask.

    * **`emit_i8x16_shl/shli/shr_s/shri_s/shr_u/shri_u`:** These implement shift operations (left, right arithmetic, right logical) for SIMD vectors.

3. **Address the specific questions:**

    * **Functionality:** Summarize the identified functionalities, emphasizing the role of the file in generating MIPS64 assembly code for WebAssembly liftoff compilation, including type conversions, arithmetic operations, control flow, memory access, and SIMD operations.

    * **Torque:** Check the file extension. Since it's `.h`, it's a C++ header file, not a Torque (`.tq`) file.

    * **JavaScript Relationship:**  Identify the connection to WebAssembly. Explain that WebAssembly allows running code written in other languages within a JavaScript environment. Provide a JavaScript example that would trigger WebAssembly execution and thus potentially involve this assembler.

    * **Code Logic Reasoning (Example):** Choose a simple function like `emit_i32_signextend_i8`. Provide a hypothetical input (a register containing a small 8-bit value) and the expected output (the same value sign-extended to 32 bits in the destination register).

    * **Common Programming Errors:**  Focus on errors related to type conversions, especially when dealing with saturation. Provide a C++ example showing a potential overflow issue when converting a large float to an integer without proper handling.

4. **Synthesize the summary:** Combine the identified functionalities into a concise summary that highlights the file's role in the WebAssembly liftoff compilation process on the MIPS64 architecture. Emphasize the low-level nature of the code and its responsibility for generating efficient machine instructions.

5. **Review and Refine:**  Ensure the answer is clear, accurate, and addresses all parts of the user's request. Check for any inconsistencies or areas where more explanation might be needed. For example, initially, the explanation of SIMD operations might be too technical. Refine it to be more understandable for someone who might not be deeply familiar with SIMD.
这是v8源代码文件 `v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h` 的第三部分，其功能是为 **Liftoff 编译器** 在 **MIPS64 架构** 上生成 **内联的汇编代码**。

**功能归纳:**

这部分代码主要负责实现以下功能：

* **类型转换指令的生成 (部分):**  它定义了如何将浮点数转换为整数，并处理饱和转换（超出目标类型范围的值会被钳制到最大或最小值）。它涵盖了从 `float` 和 `double` 转换为 `int32_t` 和 `int64_t` 的带符号和无符号版本，以及饱和转换。
* **符号扩展指令的生成:** 提供了将较小的整数类型（`i8`, `i16`, `i32`）符号扩展到较大的整数类型（`i32`, `i64`）的指令生成方法。
* **跳转指令的生成:** 实现了无条件跳转和条件跳转的汇编代码生成。
* **条件设置指令的生成:** 定义了如何根据比较结果设置寄存器的值（例如，比较两个寄存器是否相等，并将结果 0 或 1 写入目标寄存器）。
* **浮点数条件比较指令的生成:** 提供了用于浮点数比较并根据比较结果设置寄存器值的汇编代码生成。
* **选择指令的生成 (未完全实现):** `emit_select` 函数目前总是返回 `false`，可能意味着这个功能在这个架构或上下文中没有被完全实现或需要特殊处理。
* **Smi (Small Integer) 检查指令的生成:**  用于检查一个值是否是 Smi 类型。
* **SIMD (Single Instruction, Multiple Data) 加载和存储指令的生成 (部分):**  包含加载和存储 SIMD 向量的特定元素（lane）以及加载时进行类型转换或扩展的功能。
* **SIMD Shuffle 和 Swizzle 指令的生成:**  实现了 SIMD 向量元素的重新排列操作。
* **SIMD 常量加载指令的生成:** 用于将常量值加载到 SIMD 寄存器中。
* **SIMD 逻辑运算指令的生成:**  实现了 SIMD 向量的位运算（AND, OR, XOR, NOT）。
* **SIMD 选择指令的生成:**  根据掩码从两个 SIMD 向量中选择元素。
* **SIMD 求反指令的生成:**  计算 SIMD 向量的负值。
* **SIMD 判断真值指令的生成:**  检查 SIMD 向量中是否存在或全部为真值。
* **SIMD 位掩码指令的生成:**  从 SIMD 向量中提取位掩码。
* **SIMD 移位指令的生成:**  实现 SIMD 向量的左移和右移操作。

**关于文件类型和 JavaScript 关系：**

`v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h` **不是**以 `.tq` 结尾，因此它不是一个 V8 Torque 源代码文件，而是一个 **C++ 头文件**。

它与 JavaScript 的功能有直接关系，因为它参与了 **WebAssembly** 代码的编译和执行。当 JavaScript 代码调用 WebAssembly 模块时，V8 引擎会使用 Liftoff 编译器（以及其他更优化的编译器）将 WebAssembly 的字节码转换为机器码，然后执行。这个 `.h` 文件中的代码就是用来生成 MIPS64 架构上的机器码指令的。

**JavaScript 示例:**

```javascript
// 假设有一个 WebAssembly 模块，其中包含一个将浮点数转换为整数的函数
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm magic & version
  0x01, 0x07, 0x01, 0x00, 0x04, 064, 109, 117, 108, 102, 105, // Import section (示例中为空)
  0x03, 0x02, 0x01, 0x00, 0x06, 0x40, // Function section: one function, no parameters, no results
  0x0a, 0x08, 0x01, 0x06, 0x00, 0x44, 0x00, 0x00, 0x00, 0x10, 0x0b, // Code section: function body (加载浮点数 0.0)
  0x07, 0x0a, 0x01, 0x06, 0x6d, 101, 109, 111, 114, 121, 0x02, 0x00, 0x00, 0x00, // Export section: export memory
]);

WebAssembly.instantiate(wasmCode).then(instance => {
  // 假设 WebAssembly 模块导出了一个名为 'floatToInt' 的函数
  // 该函数接受一个浮点数并返回一个整数 (这里只是一个简化的例子)
  // 在实际的 wasmCode 中需要定义这样的函数

  // 这里的例子只是为了说明 LiftoffAssembler 的工作场景
  // 实际的 wasmCode 需要包含类型转换的指令

  // console.log(instance.exports.floatToInt(3.14));
});
```

当 WebAssembly 模块被实例化时，V8 的 Liftoff 编译器会处理其中的函数。如果 WebAssembly 代码中包含了将浮点数转换为整数的操作，那么 `liftoff-assembler-mips64-inl.h` 中的相关代码（例如 `emit_typed_conversion` 中 `kExprI32SConvertSatF32` 等 case）就会被用来生成对应的 MIPS64 汇编指令。

**代码逻辑推理示例:**

**假设输入:**

* `src` (源浮点数寄存器): 包含浮点数 `3.7`
* `dst` (目标通用寄存器): 用于存储转换后的整数
* 正在处理的 WebAssembly 指令是 `kExprI32SConvertSatF32` (将 `float` 转换为带符号 `int32_t`，并进行饱和处理)

**输出:**

* `dst` 寄存器将包含整数值 `3`。

**推理过程:**

`kExprI32SConvertSatF32` 分支的代码会执行以下步骤：

1. 检查 CPU 是否支持 `MIPS_SIMD`。如果支持，使用 SIMD 指令 `trunc_w_s` 将浮点数截断为整数。
2. 如果不支持 SIMD，则执行更详细的步骤：
   * 初始化 `dst` 寄存器为 0。
   * 检查源浮点数是否为 NaN。如果是 NaN，则跳转到 `done` 标签，`dst` 保持为 0。
   * 将 `dst` 寄存器加载为 `std::numeric_limits<int32_t>::min()`。
   * 将浮点最小值加载到 `kScratchDoubleReg`。
   * 比较源浮点数是否小于浮点最小值。如果小于，则跳转到 `done` 标签，`dst` 保持为最小值（饱和处理）。
   * 使用 `trunc_w_s` 指令将浮点数截断为整数，并将结果放入 `kScratchDoubleReg`。
   * 使用 `mfc1` 指令将 `kScratchDoubleReg` 中的整数值移动到目标寄存器 `dst`。
   * 绑定 `done` 标签。

在这个例子中，由于 `3.7` 不是 NaN，并且在 `int32_t` 的范围内，`trunc_w_s` 指令会将其截断为 `3`，然后通过 `mfc1` 移动到 `dst` 寄存器。

**用户常见的编程错误示例:**

在 WebAssembly 或使用类似底层操作时，一个常见的错误是在进行类型转换时 **忽略了溢出或精度损失**。

例如，如果 WebAssembly 代码尝试将一个非常大的浮点数（超过 `int32_t` 的最大值）转换为 `i32` 且没有进行饱和处理，那么结果将是未定义的或者会发生截断，导致意想不到的值。

**C++ 示例 (模拟 WebAssembly 的类型转换):**

```c++
#include <iostream>
#include <limits>

int main() {
  float large_float = 2147483900.0f; // 超过 int32_t 最大值
  int32_t int_value = static_cast<int32_t>(large_float);
  std::cout << "转换后的整数值 (无饱和): " << int_value << std::endl;

  // 模拟饱和转换 (类似于 Liftoff 的处理)
  int32_t saturated_value;
  if (large_float > std::numeric_limits<int32_t>::max()) {
    saturated_value = std::numeric_limits<int32_t>::max();
  } else if (large_float < std::numeric_limits<int32_t>::min()) {
    saturated_value = std::numeric_limits<int32_t>::min();
  } else {
    saturated_value = static_cast<int32_t>(large_float);
  }
  std::cout << "转换后的整数值 (饱和): " << saturated_value << std::endl;

  return 0;
}
```

在这个 C++ 例子中，直接使用 `static_cast` 进行转换可能会导致溢出或截断。而 Liftoff 编译器生成的代码会包含饱和处理逻辑，避免这种未定义行为，确保结果在目标类型的有效范围内。

**总结一下这部分代码的功能：**

这部分 `liftoff-assembler-mips64-inl.h` 代码是 V8 引擎中 Liftoff 编译器在 MIPS64 架构上的核心组件，负责生成执行 WebAssembly 代码所需的各种汇编指令，包括类型转换、符号扩展、跳转、条件设置以及 SIMD 向量操作。它确保了 WebAssembly 代码能够在 MIPS64 架构上正确高效地执行，并处理了类型转换中的饱和等细节，避免常见的编程错误。

Prompt: 
```
这是目录为v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/mips64/liftoff-assembler-mips64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
ueShortF(&done);
        trunc_w_s(kScratchDoubleReg, src.fp());
        mfc1(dst.gp(), kScratchDoubleReg);
        bind(&done);
      }
      return true;
    }
    case kExprI32UConvertSatF32: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<float>(0.0));
      CompareF32(ULE, src.fp(), kScratchDoubleReg);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Trunc_uw_s(dst.gp(), src.fp(), kScratchDoubleReg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    case kExprI32SConvertSatF64: {
      if (CpuFeatures::IsSupported(MIPS_SIMD)) {
        trunc_w_d(kScratchDoubleReg, src.fp());
        mfc1(dst.gp(), kScratchDoubleReg);
      } else {
        Label done;
        mov(dst.gp(), zero_reg);
        CompareIsNanF64(src.fp(), src.fp());
        BranchTrueShortF(&done);
        li(dst.gp(), static_cast<int32_t>(std::numeric_limits<int32_t>::min()));
        MacroAssembler::Move(
            kScratchDoubleReg,
            static_cast<double>(std::numeric_limits<int32_t>::min()));
        CompareF64(OLT, src.fp(), kScratchDoubleReg);
        BranchTrueShortF(&done);
        trunc_w_d(kScratchDoubleReg, src.fp());
        mfc1(dst.gp(), kScratchDoubleReg);
        bind(&done);
      }
      return true;
    }
    case kExprI32UConvertSatF64: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<double>(0.0));
      CompareF64(ULE, src.fp(), kScratchDoubleReg);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Trunc_uw_d(dst.gp(), src.fp(), kScratchDoubleReg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    case kExprI64SConvertSatF32: {
      if (CpuFeatures::IsSupported(MIPS_SIMD)) {
        trunc_l_s(kScratchDoubleReg, src.fp());
        dmfc1(dst.gp(), kScratchDoubleReg);
      } else {
        Label done;
        mov(dst.gp(), zero_reg);
        CompareIsNanF32(src.fp(), src.fp());
        BranchTrueShortF(&done);
        li(dst.gp(), static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        MacroAssembler::Move(
            kScratchDoubleReg,
            static_cast<float>(std::numeric_limits<int64_t>::min()));
        CompareF32(OLT, src.fp(), kScratchDoubleReg);
        BranchTrueShortF(&done);
        trunc_l_s(kScratchDoubleReg, src.fp());
        dmfc1(dst.gp(), kScratchDoubleReg);
        bind(&done);
      }
      return true;
    }
    case kExprI64UConvertSatF32: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<float>(0.0));
      CompareF32(ULE, src.fp(), kScratchDoubleReg);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Trunc_ul_s(dst.gp(), src.fp(), kScratchDoubleReg, no_reg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    case kExprI64SConvertSatF64: {
      if (CpuFeatures::IsSupported(MIPS_SIMD)) {
        trunc_l_d(kScratchDoubleReg, src.fp());
        dmfc1(dst.gp(), kScratchDoubleReg);
      } else {
        Label done;
        mov(dst.gp(), zero_reg);
        CompareIsNanF64(src.fp(), src.fp());
        BranchTrueShortF(&done);
        li(dst.gp(), static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        MacroAssembler::Move(
            kScratchDoubleReg,
            static_cast<double>(std::numeric_limits<int64_t>::min()));
        CompareF64(OLT, src.fp(), kScratchDoubleReg);
        BranchTrueShortF(&done);
        trunc_l_d(kScratchDoubleReg, src.fp());
        dmfc1(dst.gp(), kScratchDoubleReg);
        bind(&done);
      }
      return true;
    }
    case kExprI64UConvertSatF64: {
      Label isnan_or_lessthan_or_equal_zero;
      mov(dst.gp(), zero_reg);
      MacroAssembler::Move(kScratchDoubleReg, static_cast<double>(0.0));
      CompareF64(ULE, src.fp(), kScratchDoubleReg);
      BranchTrueShortF(&isnan_or_lessthan_or_equal_zero);
      Trunc_ul_d(dst.gp(), src.fp(), kScratchDoubleReg, no_reg);
      bind(&isnan_or_lessthan_or_equal_zero);
      return true;
    }
    default:
      return false;
  }
}

void LiftoffAssembler::emit_i32_signextend_i8(Register dst, Register src) {
  seb(dst, src);
}

void LiftoffAssembler::emit_i32_signextend_i16(Register dst, Register src) {
  seh(dst, src);
}

void LiftoffAssembler::emit_i64_signextend_i8(LiftoffRegister dst,
                                              LiftoffRegister src) {
  seb(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i16(LiftoffRegister dst,
                                               LiftoffRegister src) {
  seh(dst.gp(), src.gp());
}

void LiftoffAssembler::emit_i64_signextend_i32(LiftoffRegister dst,
                                               LiftoffRegister src) {
  sll(dst.gp(), src.gp(), 0);
}

void LiftoffAssembler::emit_jump(Label* label) {
  MacroAssembler::Branch(label);
}

void LiftoffAssembler::emit_jump(Register target) {
  MacroAssembler::Jump(target);
}

void LiftoffAssembler::emit_cond_jump(Condition cond, Label* label,
                                      ValueKind kind, Register lhs,
                                      Register rhs,
                                      const FreezeCacheState& frozen) {
  if (rhs == no_reg) {
    DCHECK(kind == kI32 || kind == kI64);
    MacroAssembler::Branch(label, cond, lhs, Operand(zero_reg));
  } else {
    DCHECK((kind == kI32 || kind == kI64) ||
           (is_reference(kind) && (cond == kEqual || cond == kNotEqual)));
    MacroAssembler::Branch(label, cond, lhs, Operand(rhs));
  }
}

void LiftoffAssembler::emit_i32_cond_jumpi(Condition cond, Label* label,
                                           Register lhs, int32_t imm,
                                           const FreezeCacheState& frozen) {
  MacroAssembler::Branch(label, cond, lhs, Operand(imm));
}

void LiftoffAssembler::emit_ptrsize_cond_jumpi(Condition cond, Label* label,
                                               Register lhs, int32_t imm,
                                               const FreezeCacheState& frozen) {
  MacroAssembler::Branch(label, cond, lhs, Operand(imm));
}

void LiftoffAssembler::emit_i32_eqz(Register dst, Register src) {
  sltiu(dst, src, 1);
}

void LiftoffAssembler::emit_i32_set_cond(Condition cond, Register dst,
                                         Register lhs, Register rhs) {
  CompareWord(cond, dst, lhs, Operand(rhs));
}

void LiftoffAssembler::emit_i64_eqz(Register dst, LiftoffRegister src) {
  sltiu(dst, src.gp(), 1);
}

void LiftoffAssembler::emit_i64_set_cond(Condition cond, Register dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  CompareWord(cond, dst, lhs.gp(), Operand(rhs.gp()));
}

namespace liftoff {

inline FPUCondition ConditionToConditionCmpFPU(Condition condition,
                                               bool* predicate) {
  switch (condition) {
    case kEqual:
      *predicate = true;
      return EQ;
    case kNotEqual:
      *predicate = false;
      return EQ;
    case kUnsignedLessThan:
      *predicate = true;
      return OLT;
    case kUnsignedGreaterThanEqual:
      *predicate = false;
      return OLT;
    case kUnsignedLessThanEqual:
      *predicate = true;
      return OLE;
    case kUnsignedGreaterThan:
      *predicate = false;
      return OLE;
    default:
      *predicate = true;
      break;
  }
  UNREACHABLE();
}

inline void EmitAnyTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src) {
  Label all_false;
  assm->BranchMSA(&all_false, MSA_BRANCH_V, all_zero, src.fp().toW(),
                  USE_DELAY_SLOT);
  assm->li(dst.gp(), 0l);
  assm->li(dst.gp(), 1);
  assm->bind(&all_false);
}

inline void EmitAllTrue(LiftoffAssembler* assm, LiftoffRegister dst,
                        LiftoffRegister src, MSABranchDF msa_branch_df) {
  Label all_true;
  assm->BranchMSA(&all_true, msa_branch_df, all_not_zero, src.fp().toW(),
                  USE_DELAY_SLOT);
  assm->li(dst.gp(), 1);
  assm->li(dst.gp(), 0l);
  assm->bind(&all_true);
}

inline void StoreToMemory(LiftoffAssembler* assm, MemOperand dst,
                          const LiftoffAssembler::VarState& src) {
  if (src.is_reg()) {
    Store(assm, dst, src.reg(), src.kind());
    return;
  }

  UseScratchRegisterScope temps(assm);
  Register temp = temps.Acquire();
  if (src.is_const()) {
    if (src.i32_const() == 0) {
      temp = zero_reg;
    } else {
      assm->li(temp, src.i32_const());
    }
  } else {
    DCHECK(src.is_stack());
    if (value_kind_size(src.kind()) == 4) {
      assm->Lw(temp, liftoff::GetStackSlot(src.offset()));
    } else {
      assm->Ld(temp, liftoff::GetStackSlot(src.offset()));
    }
  }

  if (value_kind_size(src.kind()) == 4) {
    assm->Sw(temp, dst);
  } else {
    DCHECK_EQ(8, value_kind_size(src.kind()));
    assm->Sd(temp, dst);
  }
}

}  // namespace liftoff

void LiftoffAssembler::emit_f32_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  Label not_nan, cont;
  MacroAssembler::CompareIsNanF32(lhs, rhs);
  MacroAssembler::BranchFalseF(&not_nan);
  // If one of the operands is NaN, return 1 for f32.ne, else 0.
  if (cond == ne) {
    MacroAssembler::li(dst, 1);
  } else {
    MacroAssembler::Move(dst, zero_reg);
  }
  MacroAssembler::Branch(&cont);

  bind(&not_nan);

  MacroAssembler::li(dst, 1);
  bool predicate;
  FPUCondition fcond = liftoff::ConditionToConditionCmpFPU(cond, &predicate);
  MacroAssembler::CompareF32(fcond, lhs, rhs);
  if (predicate) {
    MacroAssembler::LoadZeroIfNotFPUCondition(dst);
  } else {
    MacroAssembler::LoadZeroIfFPUCondition(dst);
  }

  bind(&cont);
}

void LiftoffAssembler::emit_f64_set_cond(Condition cond, Register dst,
                                         DoubleRegister lhs,
                                         DoubleRegister rhs) {
  Label not_nan, cont;
  MacroAssembler::CompareIsNanF64(lhs, rhs);
  MacroAssembler::BranchFalseF(&not_nan);
  // If one of the operands is NaN, return 1 for f64.ne, else 0.
  if (cond == ne) {
    MacroAssembler::li(dst, 1);
  } else {
    MacroAssembler::Move(dst, zero_reg);
  }
  MacroAssembler::Branch(&cont);

  bind(&not_nan);

  MacroAssembler::li(dst, 1);
  bool predicate;
  FPUCondition fcond = liftoff::ConditionToConditionCmpFPU(cond, &predicate);
  MacroAssembler::CompareF64(fcond, lhs, rhs);
  if (predicate) {
    MacroAssembler::LoadZeroIfNotFPUCondition(dst);
  } else {
    MacroAssembler::LoadZeroIfFPUCondition(dst);
  }

  bind(&cont);
}

bool LiftoffAssembler::emit_select(LiftoffRegister dst, Register condition,
                                   LiftoffRegister true_value,
                                   LiftoffRegister false_value,
                                   ValueKind kind) {
  return false;
}

void LiftoffAssembler::emit_smi_check(Register obj, Label* target,
                                      SmiCheckMode mode,
                                      const FreezeCacheState& frozen) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  And(scratch, obj, Operand(kSmiTagMask));
  Condition condition = mode == kJumpOnSmi ? eq : ne;
  Branch(target, condition, scratch, Operand(zero_reg));
}

void LiftoffAssembler::LoadTransform(LiftoffRegister dst, Register src_addr,
                                     Register offset_reg, uintptr_t offset_imm,
                                     LoadType type,
                                     LoadTransformationKind transform,
                                     uint32_t* protected_load_pc) {
  UseScratchRegisterScope temps(this);
  Register scratch = temps.Acquire();
  MemOperand src_op = liftoff::GetMemOp(this, src_addr, offset_reg, offset_imm);
  MSARegister dst_msa = dst.fp().toW();
  *protected_load_pc = pc_offset();
  MachineType memtype = type.mem_type();

  if (transform == LoadTransformationKind::kExtend) {
    Ld(scratch, src_op);
    if (memtype == MachineType::Int8()) {
      fill_d(dst_msa, scratch);
      clti_s_b(kSimd128ScratchReg, dst_msa, 0);
      ilvr_b(dst_msa, kSimd128ScratchReg, dst_msa);
    } else if (memtype == MachineType::Uint8()) {
      xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      fill_d(dst_msa, scratch);
      ilvr_b(dst_msa, kSimd128RegZero, dst_msa);
    } else if (memtype == MachineType::Int16()) {
      fill_d(dst_msa, scratch);
      clti_s_h(kSimd128ScratchReg, dst_msa, 0);
      ilvr_h(dst_msa, kSimd128ScratchReg, dst_msa);
    } else if (memtype == MachineType::Uint16()) {
      xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      fill_d(dst_msa, scratch);
      ilvr_h(dst_msa, kSimd128RegZero, dst_msa);
    } else if (memtype == MachineType::Int32()) {
      fill_d(dst_msa, scratch);
      clti_s_w(kSimd128ScratchReg, dst_msa, 0);
      ilvr_w(dst_msa, kSimd128ScratchReg, dst_msa);
    } else if (memtype == MachineType::Uint32()) {
      xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
      fill_d(dst_msa, scratch);
      ilvr_w(dst_msa, kSimd128RegZero, dst_msa);
    }
  } else if (transform == LoadTransformationKind::kZeroExtend) {
    xor_v(dst_msa, dst_msa, dst_msa);
    if (memtype == MachineType::Int32()) {
      Lwu(scratch, src_op);
      insert_w(dst_msa, 0, scratch);
    } else {
      DCHECK_EQ(MachineType::Int64(), memtype);
      Ld(scratch, src_op);
      insert_d(dst_msa, 0, scratch);
    }
  } else {
    DCHECK_EQ(LoadTransformationKind::kSplat, transform);
    if (memtype == MachineType::Int8()) {
      Lb(scratch, src_op);
      fill_b(dst_msa, scratch);
    } else if (memtype == MachineType::Int16()) {
      Lh(scratch, src_op);
      fill_h(dst_msa, scratch);
    } else if (memtype == MachineType::Int32()) {
      Lw(scratch, src_op);
      fill_w(dst_msa, scratch);
    } else if (memtype == MachineType::Int64()) {
      Ld(scratch, src_op);
      fill_d(dst_msa, scratch);
    }
  }
}

void LiftoffAssembler::LoadLane(LiftoffRegister dst, LiftoffRegister src,
                                Register addr, Register offset_reg,
                                uintptr_t offset_imm, LoadType type,
                                uint8_t laneidx, uint32_t* protected_load_pc,
                                bool i64_offset) {
  MemOperand src_op =
      liftoff::GetMemOp(this, addr, offset_reg, offset_imm, i64_offset);
  *protected_load_pc = pc_offset();
  LoadStoreLaneParams load_params(type.mem_type().representation(), laneidx);
  MacroAssembler::LoadLane(load_params.sz, dst.fp().toW(), laneidx, src_op);
}

void LiftoffAssembler::StoreLane(Register dst, Register offset,
                                 uintptr_t offset_imm, LiftoffRegister src,
                                 StoreType type, uint8_t lane,
                                 uint32_t* protected_store_pc,
                                 bool i64_offset) {
  MemOperand dst_op =
      liftoff::GetMemOp(this, dst, offset, offset_imm, i64_offset);
  if (protected_store_pc) *protected_store_pc = pc_offset();
  LoadStoreLaneParams store_params(type.mem_rep(), lane);
  MacroAssembler::StoreLane(store_params.sz, src.fp().toW(), lane, dst_op);
}

void LiftoffAssembler::emit_i8x16_shuffle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs,
                                          const uint8_t shuffle[16],
                                          bool is_swizzle) {
  MSARegister dst_msa = dst.fp().toW();
  MSARegister lhs_msa = lhs.fp().toW();
  MSARegister rhs_msa = rhs.fp().toW();

  uint64_t control_hi = 0;
  uint64_t control_low = 0;
  for (int i = 7; i >= 0; i--) {
    control_hi <<= 8;
    control_hi |= shuffle[i + 8];
    control_low <<= 8;
    control_low |= shuffle[i];
  }

  if (dst_msa == lhs_msa) {
    move_v(kSimd128ScratchReg, lhs_msa);
    lhs_msa = kSimd128ScratchReg;
  } else if (dst_msa == rhs_msa) {
    move_v(kSimd128ScratchReg, rhs_msa);
    rhs_msa = kSimd128ScratchReg;
  }

  li(kScratchReg, control_low);
  insert_d(dst_msa, 0, kScratchReg);
  li(kScratchReg, control_hi);
  insert_d(dst_msa, 1, kScratchReg);
  vshf_b(dst_msa, rhs_msa, lhs_msa);
}

void LiftoffAssembler::emit_i8x16_swizzle(LiftoffRegister dst,
                                          LiftoffRegister lhs,
                                          LiftoffRegister rhs) {
  MSARegister dst_msa = dst.fp().toW();
  MSARegister lhs_msa = lhs.fp().toW();
  MSARegister rhs_msa = rhs.fp().toW();

  if (dst == lhs) {
    move_v(kSimd128ScratchReg, lhs_msa);
    lhs_msa = kSimd128ScratchReg;
  }
  xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  move_v(dst_msa, rhs_msa);
  vshf_b(dst_msa, kSimd128RegZero, lhs_msa);
}

void LiftoffAssembler::emit_i8x16_relaxed_swizzle(LiftoffRegister dst,
                                                  LiftoffRegister lhs,
                                                  LiftoffRegister rhs) {
  bailout(kRelaxedSimd, "emit_i8x16_relaxed_swizzle");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f32x4_s");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u(LiftoffRegister dst,
                                                        LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f32x4_u");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f64x2_s_zero");
}

void LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero(
    LiftoffRegister dst, LiftoffRegister src) {
  bailout(kRelaxedSimd, "emit_i32x4_relaxed_trunc_f64x2_u_zero");
}

void LiftoffAssembler::emit_s128_relaxed_laneselect(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2,
                                                    LiftoffRegister mask,
                                                    int lane_width) {
  bailout(kRelaxedSimd, "emit_s128_relaxed_laneselect");
}

void LiftoffAssembler::emit_i8x16_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  fill_b(dst.fp().toW(), src.gp());
}

void LiftoffAssembler::emit_i16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  fill_h(dst.fp().toW(), src.gp());
}

void LiftoffAssembler::emit_i32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  fill_w(dst.fp().toW(), src.gp());
}

void LiftoffAssembler::emit_i64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  fill_d(dst.fp().toW(), src.gp());
}

void LiftoffAssembler::emit_f32x4_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  MacroAssembler::FmoveLow(kScratchReg, src.fp());
  fill_w(dst.fp().toW(), kScratchReg);
}

void LiftoffAssembler::emit_f64x2_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  MacroAssembler::Move(kScratchReg, src.fp());
  fill_d(dst.fp().toW(), kScratchReg);
}

#define SIMD_BINOP(name1, name2, type)                                   \
  void LiftoffAssembler::emit_##name1##_extmul_low_##name2(              \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2) { \
    MacroAssembler::ExtMulLow(type, dst.fp().toW(), src1.fp().toW(),     \
                              src2.fp().toW());                          \
  }                                                                      \
  void LiftoffAssembler::emit_##name1##_extmul_high_##name2(             \
      LiftoffRegister dst, LiftoffRegister src1, LiftoffRegister src2) { \
    MacroAssembler::ExtMulHigh(type, dst.fp().toW(), src1.fp().toW(),    \
                               src2.fp().toW());                         \
  }

SIMD_BINOP(i16x8, i8x16_s, MSAS8)
SIMD_BINOP(i16x8, i8x16_u, MSAU8)

SIMD_BINOP(i32x4, i16x8_s, MSAS16)
SIMD_BINOP(i32x4, i16x8_u, MSAU16)

SIMD_BINOP(i64x2, i32x4_s, MSAS32)
SIMD_BINOP(i64x2, i32x4_u, MSAU32)

#undef SIMD_BINOP

#define SIMD_BINOP(name1, name2, type)                                    \
  void LiftoffAssembler::emit_##name1##_extadd_pairwise_##name2(          \
      LiftoffRegister dst, LiftoffRegister src) {                         \
    MacroAssembler::ExtAddPairwise(type, dst.fp().toW(), src.fp().toW()); \
  }

SIMD_BINOP(i16x8, i8x16_s, MSAS8)
SIMD_BINOP(i16x8, i8x16_u, MSAU8)
SIMD_BINOP(i32x4, i16x8_s, MSAS16)
SIMD_BINOP(i32x4, i16x8_u, MSAU16)
#undef SIMD_BINOP

void LiftoffAssembler::emit_i16x8_q15mulr_sat_s(LiftoffRegister dst,
                                                LiftoffRegister src1,
                                                LiftoffRegister src2) {
  mulr_q_h(dst.fp().toW(), src1.fp().toW(), src2.fp().toW());
}

void LiftoffAssembler::emit_i16x8_relaxed_q15mulr_s(LiftoffRegister dst,
                                                    LiftoffRegister src1,
                                                    LiftoffRegister src2) {
  bailout(kRelaxedSimd, "emit_i16x8_relaxed_q15mulr_s");
}

void LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s(LiftoffRegister dst,
                                                    LiftoffRegister lhs,
                                                    LiftoffRegister rhs) {
  bailout(kSimd, "emit_i16x8_dot_i8x16_i7x16_s");
}

void LiftoffAssembler::emit_i32x4_dot_i8x16_i7x16_add_s(LiftoffRegister dst,
                                                        LiftoffRegister lhs,
                                                        LiftoffRegister rhs,
                                                        LiftoffRegister acc) {
  bailout(kSimd, "emit_i32x4_dot_i8x16_i7x16_add_s");
}

void LiftoffAssembler::emit_i8x16_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_b(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_i8x16_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_b(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
  nor_v(dst.fp().toW(), dst.fp().toW(), dst.fp().toW());
}

void LiftoffAssembler::emit_i8x16_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  clt_s_b(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i8x16_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  clt_u_b(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i8x16_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  cle_s_b(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i8x16_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  cle_u_b(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_h(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_i16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_h(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
  nor_v(dst.fp().toW(), dst.fp().toW(), dst.fp().toW());
}

void LiftoffAssembler::emit_i16x8_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  clt_s_h(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i16x8_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  clt_u_h(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i16x8_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  cle_s_h(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i16x8_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  cle_u_h(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_w(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_i32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_w(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
  nor_v(dst.fp().toW(), dst.fp().toW(), dst.fp().toW());
}

void LiftoffAssembler::emit_i32x4_gt_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  clt_s_w(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i32x4_gt_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  clt_u_w(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i32x4_ge_s(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  cle_s_w(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_i32x4_ge_u(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  cle_u_w(dst.fp().toW(), rhs.fp().toW(), lhs.fp().toW());
}

void LiftoffAssembler::emit_f32x4_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fceq_w(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_f32x4_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fcune_w(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_f32x4_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fclt_w(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_f32x4_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fcle_w(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_i64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_d(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_i64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  ceq_d(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
  nor_v(dst.fp().toW(), dst.fp().toW(), dst.fp().toW());
}

void LiftoffAssembler::emit_i64x2_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  add_a_d(dst.fp().toW(), src.fp().toW(), kSimd128RegZero);
}

void LiftoffAssembler::emit_f64x2_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fceq_d(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_f64x2_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fcune_d(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_f64x2_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fclt_d(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_f64x2_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  fcle_d(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_s128_const(LiftoffRegister dst,
                                       const uint8_t imms[16]) {
  MSARegister dst_msa = dst.fp().toW();
  uint64_t vals[2];
  memcpy(vals, imms, sizeof(vals));
  li(kScratchReg, vals[0]);
  insert_d(dst_msa, 0, kScratchReg);
  li(kScratchReg, vals[1]);
  insert_d(dst_msa, 1, kScratchReg);
}

void LiftoffAssembler::emit_s128_not(LiftoffRegister dst, LiftoffRegister src) {
  nor_v(dst.fp().toW(), src.fp().toW(), src.fp().toW());
}

void LiftoffAssembler::emit_s128_and(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  and_v(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_s128_or(LiftoffRegister dst, LiftoffRegister lhs,
                                    LiftoffRegister rhs) {
  or_v(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_s128_xor(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  xor_v(dst.fp().toW(), lhs.fp().toW(), rhs.fp().toW());
}

void LiftoffAssembler::emit_s128_and_not(LiftoffRegister dst,
                                         LiftoffRegister lhs,
                                         LiftoffRegister rhs) {
  nor_v(kSimd128ScratchReg, rhs.fp().toW(), rhs.fp().toW());
  and_v(dst.fp().toW(), kSimd128ScratchReg, lhs.fp().toW());
}

void LiftoffAssembler::emit_s128_select(LiftoffRegister dst,
                                        LiftoffRegister src1,
                                        LiftoffRegister src2,
                                        LiftoffRegister mask) {
  if (dst == mask) {
    bsel_v(dst.fp().toW(), src2.fp().toW(), src1.fp().toW());
  } else {
    xor_v(kSimd128ScratchReg, src1.fp().toW(), src2.fp().toW());
    and_v(kSimd128ScratchReg, kSimd128ScratchReg, mask.fp().toW());
    xor_v(dst.fp().toW(), kSimd128ScratchReg, src2.fp().toW());
  }
}

void LiftoffAssembler::emit_i8x16_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  xor_v(kSimd128RegZero, kSimd128RegZero, kSimd128RegZero);
  subv_b(dst.fp().toW(), kSimd128RegZero, src.fp().toW());
}

void LiftoffAssembler::emit_v128_anytrue(LiftoffRegister dst,
                                         LiftoffRegister src) {
  liftoff::EmitAnyTrue(this, dst, src);
}

void LiftoffAssembler::emit_i8x16_alltrue(LiftoffRegister dst,
                                          LiftoffRegister src) {
  liftoff::EmitAllTrue(this, dst, src, MSA_BRANCH_B);
}

void LiftoffAssembler::emit_i8x16_bitmask(LiftoffRegister dst,
                                          LiftoffRegister src) {
  MSARegister scratch0 = kSimd128RegZero;
  MSARegister scratch1 = kSimd128ScratchReg;
  srli_b(scratch0, src.fp().toW(), 7);
  srli_h(scratch1, scratch0, 7);
  or_v(scratch0, scratch0, scratch1);
  srli_w(scratch1, scratch0, 14);
  or_v(scratch0, scratch0, scratch1);
  srli_d(scratch1, scratch0, 28);
  or_v(scratch0, scratch0, scratch1);
  shf_w(scratch1, scratch0, 0x0E);
  ilvev_b(scratch0, scratch1, scratch0);
  copy_u_h(dst.gp(), scratch0, 0);
}

void LiftoffAssembler::emit_i8x16_shl(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  fill_b(kSimd128ScratchReg, rhs.gp());
  sll_b(dst.fp().toW(), lhs.fp().toW(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i8x16_shli(LiftoffRegister dst, LiftoffRegister lhs,
                                       int32_t rhs) {
  slli_b(dst.fp().toW(), lhs.fp().toW(), rhs & 7);
}

void LiftoffAssembler::emit_i8x16_shr_s(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  fill_b(kSimd128ScratchReg, rhs.gp());
  sra_b(dst.fp().toW(), lhs.fp().toW(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i8x16_shri_s(LiftoffRegister dst,
                                         LiftoffRegister lhs, int32_t rhs) {
  srai_b(dst.fp().toW(), lhs.fp().toW(), rhs & 7);
}

void LiftoffAssembler::emit_i8x16_shr_u(LiftoffRegister dst,
                                        LiftoffRegister lhs,
                                        LiftoffRegister rhs) {
  fill_b(kSimd128ScratchReg, rhs.gp());
  srl_b(dst.fp().toW(), lhs.fp().toW(), kSimd128ScratchReg);
}

void LiftoffAssembler::emit_i8x16_shri_u(LiftoffRegister dst,
                                   
"""


```