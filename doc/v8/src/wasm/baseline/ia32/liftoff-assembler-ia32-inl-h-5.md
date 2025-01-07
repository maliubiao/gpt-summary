Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and High-Level Understanding:**

* **Filename:** `liftoff-assembler-ia32-inl.h` immediately tells us it's related to assembly generation (`assembler`), specifically for the IA-32 architecture (`ia32`) within the Liftoff compiler (`liftoff`) of V8's WebAssembly (`wasm`) implementation. The `.inl.h` suggests it's an inline header, meaning the function definitions are included directly in the header for potential optimization.
* **Namespace:** `v8::internal::wasm` confirms the context within V8's internal WebAssembly workings.
* **Core Functionality:** The code primarily consists of numerous functions named `emit_...`. This strongly suggests the file's purpose is to emit specific IA-32 assembly instructions for various WebAssembly operations.

**2. Analyzing Function Signatures and Operations:**

* **`emit_i32x4_sconvert_f32x4(...)`:**  This function name clearly indicates an instruction to convert a `f32x4` (four 32-bit floats) to an `i32x4` (four 32-bit integers), with 's' likely denoting a signed conversion. The arguments `LiftoffRegister dst, LiftoffRegister src` suggest it operates on registers. The internal call `I32x4SConvertF32x4(...)` hints at a lower-level or architecture-specific implementation detail.
* **Pattern Recognition:**  As you go through the functions, you see a consistent naming pattern: `emit_<wasm_type>_<operation>_<operand_types>`. This makes it easier to infer the purpose of each function. Examples:
    * `emit_f32x4_sconvert_i32x4`: Convert `i32x4` to `f32x4` (signed).
    * `emit_i8x16_sconvert_i16x8`: Convert `i16x8` to `i8x16` (signed).
    * `emit_f32x4_abs`: Absolute value of `f32x4`.
    * `emit_i8x16_extract_lane_s`: Extract a signed byte from an `i8x16`.
    * `emit_i8x16_replace_lane`: Replace a byte within an `i8x16`.
* **SIMD Focus:**  The frequent use of types like `i32x4`, `f32x4`, `i8x16`, etc., clearly points to Single Instruction, Multiple Data (SIMD) operations, which are crucial for performance in media processing and other parallel tasks.
* **Conversion Types:**  There are various conversion functions (e.g., `sconvert`, `uconvert`, `demote`, `promote`). The 's' and 'u' likely indicate signed and unsigned conversions, respectively. `demote` and `promote` likely refer to changing the precision of floating-point numbers.
* **Arithmetic and Logical Operations:**  Functions like `emit_s128_and_not`, `emit_i8x16_rounding_average_u`, `emit_i8x16_abs` indicate support for bitwise, arithmetic, and absolute value operations.
* **Lane Operations:** The `extract_lane` and `replace_lane` functions allow accessing and modifying individual elements within the SIMD vectors.
* **Fused Multiply-Add (FMA):**  The `qfma` and `qfms` functions suggest support for fused multiply-add operations (and possibly multiply-subtract), which are performance-critical for many numerical algorithms.
* **Conditional Compilation:** The `if (CpuFeatures::IsSupported(AVX))` blocks indicate that the code adapts based on the availability of CPU features like AVX (Advanced Vector Extensions) for optimization.
* **Helper Functions:**  Functions like `GetUnusedRegister`, `EmitSimdNonCommutativeBinOp`, `EmitSimdCommutativeBinOp` suggest the presence of helper functions to simplify the code generation process.
* **Stack Management:** Functions like `StackCheck`, `PushRegisters`, `PopRegisters`, `AllocateStackSpace`, and `DeallocateStackSlot` deal with managing the call stack.
* **Function Calls:** `CallC`, `CallNativeWasmCode`, `CallIndirect`, and `CallBuiltin` handle different types of function calls within the WebAssembly environment.

**3. Inferring the Overall Purpose:**

Based on the individual function analyses, it becomes clear that this header file provides a set of building blocks for generating IA-32 assembly code for WebAssembly's Liftoff compiler. It focuses heavily on SIMD operations and provides a relatively low-level interface for emitting instructions.

**4. Addressing Specific Questions from the Prompt:**

* **Functionality:**  List the categories of operations observed (conversions, arithmetic, logical, lane operations, FMA, stack management, function calls).
* **Torque:** The filename doesn't end in `.tq`, so it's not Torque.
* **JavaScript Relationship:**  Think about which JavaScript features benefit from WebAssembly and SIMD. Array manipulation, graphics, and numerical computations are good examples. Create a simple JavaScript example using TypedArrays that could potentially be optimized by the WebAssembly code generated using this assembler.
* **Code Logic Inference:** Choose a simple function (e.g., `emit_i32x4_sconvert_f32x4`) and demonstrate its behavior with hypothetical register values. Explain the signed conversion.
* **Common Programming Errors:** Consider errors related to SIMD programming, like incorrect lane indexing or type mismatches, and provide illustrative examples.
* **Part of a Series:**  Since this is part 6 of 6, the purpose is likely to provide the low-level assembly emission capabilities for the IA-32 architecture within the broader Liftoff compilation pipeline. The other parts probably handle higher-level compilation stages, register allocation, etc.

**5. Refinement and Organization:**

Organize the findings into clear sections based on the prompt's questions. Use precise language and provide concrete examples where necessary. Explain any assumptions made (e.g., the meaning of 's' and 'u' in function names).

By following this detailed breakdown, we can systematically analyze the C++ header file and accurately address all the points raised in the prompt. The key is to start with a high-level overview and then progressively delve into the details of individual functions and code blocks, looking for patterns and connecting the dots.
好的，让我们来分析一下 `v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 这个文件的功能。

**文件功能概览**

这个头文件定义了 `LiftoffAssembler` 类在 IA-32 (x86) 架构下的内联函数实现。`LiftoffAssembler` 是 V8 的 WebAssembly (Wasm) 引擎 Liftoff 的一个组件，它的主要职责是生成目标架构（这里是 IA-32）的机器码。该文件中的函数对应于 Wasm 指令到 IA-32 汇编指令的映射。

**详细功能列表**

这个文件中的函数主要负责生成各种 Wasm SIMD (Single Instruction, Multiple Data) 操作的 IA-32 汇编代码。具体来说，它实现了以下功能：

1. **类型转换指令生成:**
   - `emit_i32x4_sconvert_f32x4`: 将 4 个 f32 转换为有符号的 4 个 i32。
   - `emit_i32x4_uconvert_f32x4`: 将 4 个 f32 转换为无符号的 4 个 i32。
   - `emit_f32x4_sconvert_i32x4`: 将 4 个 i32 转换为 f32。
   - `emit_f32x4_uconvert_i32x4`: 将 4 个 i32 转换为 f32 (需要特殊处理无符号转换)。
   - `emit_f32x4_demote_f64x2_zero`: 将 2 个 f64 降级为 f32 (取低位)。
   - `emit_i8x16_sconvert_i16x8`, `emit_i8x16_uconvert_i16x8`, `emit_i16x8_sconvert_i32x4`, `emit_i16x8_uconvert_i32x4`: 不同大小整数向量之间的有符号和无符号转换。
   - `emit_i16x8_sconvert_i8x16_low/high`, `emit_i16x8_uconvert_i8x16_low/high`, `emit_i32x4_sconvert_i16x8_low/high`, `emit_i32x4_uconvert_i16x8_low/high`: 将较小整数向量转换为较大整数向量，并处理低位和高位部分。
   - `emit_i32x4_trunc_sat_f64x2_s_zero`, `emit_i32x4_trunc_sat_f64x2_u_zero`: 将 f64 截断为 i32，并进行饱和处理。

2. **位运算指令生成:**
   - `emit_s128_and_not`: 执行 SIMD 的 AND NOT 操作。

3. **算术运算指令生成:**
   - `emit_i8x16_rounding_average_u`, `emit_i16x8_rounding_average_u`: 计算 SIMD 向量的平均值（带舍入）。
   - `emit_i8x16_abs`, `emit_i16x8_abs`, `emit_i32x4_abs`, `emit_i64x2_abs`: 计算 SIMD 向量的绝对值。

4. **元素提取和替换指令生成:**
   - `emit_i8x16_extract_lane_s/u`, `emit_i16x8_extract_lane_s/u`, `emit_i32x4_extract_lane`, `emit_i64x2_extract_lane`, `emit_f32x4_extract_lane`, `emit_f64x2_extract_lane`: 从 SIMD 向量中提取指定索引的元素。
   - `emit_i8x16_replace_lane`, `emit_i16x8_replace_lane`, `emit_i32x4_replace_lane`, `emit_i64x2_replace_lane`, `emit_f32x4_replace_lane`, `emit_f64x2_replace_lane`: 将 SIMD 向量中指定索引的元素替换为新值。

5. **融合乘加/减指令生成:**
   - `emit_f32x4_qfma`, `emit_f32x4_qfms`, `emit_f64x2_qfma`, `emit_f64x2_qfms`: 生成 SIMD 的融合乘加和融合乘减指令。

6. **`f16x8` 相关指令（部分未实现或返回 false）:**
   - 许多以 `emit_f16x8_` 开头的函数，例如 `emit_f16x8_splat`, `emit_f16x8_extract_lane` 等，这些函数目前返回 `false` 或为空，表示 IA-32 架构可能不支持或尚未实现这些 `f16x8` (半精度浮点数向量) 的操作。

7. **其他辅助功能:**
   - `StackCheck`: 检查栈空间是否足够。
   - `AssertUnreachable`: 生成断言失败的代码。
   - `PushRegisters`, `PopRegisters`: 保存和恢复寄存器。
   - `RecordSpillsInSafepoint`: 记录在安全点需要保存的寄存器信息。
   - `DropStackSlotsAndRet`: 释放栈空间并返回。
   - `CallCWithStackBuffer`, `CallC`: 调用 C 函数。
   - `CallNativeWasmCode`, `TailCallNativeWasmCode`: 调用原生 Wasm 代码。
   - `CallIndirect`, `TailCallIndirect`: 间接调用。
   - `CallBuiltin`: 调用内置函数。
   - `AllocateStackSlot`, `DeallocateStackSlot`: 分配和释放栈空间。
   - `MaybeOSR`: 可能的 On-Stack Replacement (OSR) 的占位符。
   - `emit_set_if_nan`: 如果浮点数是 NaN，则设置寄存器。
   - `emit_s128_set_if_nan`: 如果 SIMD 向量中的任何元素是 NaN，则设置寄存器。

8. **`LiftoffStackSlots` 类:**
   - 用于管理栈上的变量，并在需要时将数据从寄存器或旧的栈位置移动到新的栈位置。

**关于文件后缀 `.tq`**

根据您的描述，如果 `v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 以 `.tq` 结尾，那么它将是一个 v8 Torque 源代码文件。Torque 是一种 V8 自定义的语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。但是，由于该文件名以 `.h` 结尾，它是一个 C++ 头文件，包含了内联函数的定义。

**与 JavaScript 的关系**

这个文件直接参与了 V8 执行 WebAssembly 代码的过程。当 JavaScript 调用 WebAssembly 模块时，Liftoff 编译器会快速生成基线代码，以便快速启动执行。`LiftoffAssembler` 和这个 `.inl.h` 文件中定义的函数负责将 Wasm 的 SIMD 指令转换为能够在 IA-32 架构上执行的机器码。

**JavaScript 示例**

```javascript
// 创建一个类型化的数组，模拟 WebAssembly 中的数据
const array1 = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const array2 = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const result = new Int32Array(4);

// 假设一个 WebAssembly 函数 (实际中需要编译) 对应于 emit_i32x4_sconvert_f32x4
function wasmConvertAndStore(floatArray, intArray) {
  // 模拟 WebAssembly 将 floatArray 转换为 intArray (有符号)
  for (let i = 0; i < floatArray.length; i++) {
    intArray[i] = Math.trunc(floatArray[i]); // 模拟有符号截断
  }
}

wasmConvertAndStore(array1, result);
console.log(result); // 输出: Int32Array [ 1, 2, 3, 4 ]

// 假设另一个 WebAssembly 函数对应于 emit_f32x4_abs
function wasmAbs(floatArray) {
  for (let i = 0; i < floatArray.length; i++) {
    floatArray[i] = Math.abs(floatArray[i]);
  }
}

wasmAbs(array2);
console.log(array2); // 输出: Float32Array [ 5, 6, 7, 8 ]
```

在这个例子中，`wasmConvertAndStore` 函数模拟了 `emit_i32x4_sconvert_f32x4` 的功能，将浮点数数组转换为整数数组。`wasmAbs` 模拟了计算绝对值的功能。实际的 WebAssembly 执行会使用 `LiftoffAssembler` 生成相应的 IA-32 汇编指令来完成这些操作。

**代码逻辑推理示例**

**假设输入:**

- `dst` 寄存器表示目标 SIMD 寄存器 (例如，xmm0)。
- `src` 寄存器表示源 SIMD 寄存器 (例如，xmm1)，其包含四个 f32 值：`[1.5, -2.3, 3.8, -4.1]`。

**调用函数:** `emit_i32x4_sconvert_f32x4(dst, src)`

**代码逻辑 (简化):**

该函数内部会调用 `I32x4SConvertF32x4(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, tmp);`。这条指令（或者一系列指令）在 IA-32 架构上会执行以下操作：

1. 从 `src` 寄存器 (xmm1) 中读取四个 f32 值。
2. 对每个 f32 值进行有符号截断，将其转换为 i32。
   - `1.5` 截断为 `1`
   - `-2.3` 截断为 `-2`
   - `3.8` 截断为 `3`
   - `-4.1` 截断为 `-4`
3. 将转换后的四个 i32 值存储到 `dst` 寄存器 (xmm0) 中。

**输出:**

- `dst` 寄存器 (xmm0) 现在包含四个 i32 值：`[1, -2, 3, -4]`。

**用户常见的编程错误示例**

在使用 WebAssembly SIMD 指令时，常见的编程错误包括：

1. **类型不匹配:** 尝试将不兼容的类型进行转换，例如将有符号整数误认为无符号整数进行转换，可能导致意外的结果。

   ```javascript
   // WebAssembly (假设)
   // i32x4.uconvert_sat_f32x4  // 无符号饱和转换

   // JavaScript 模拟
   const floatArray = new Float32Array([-1.0, 2.0, -3.0, 4.0]);
   const uintArray = new Uint32Array(4);

   function simulateUnsignedConvert(floatArray, uintArray) {
     for (let i = 0; i < floatArray.length; i++) {
       // 负数会被转换为非常大的正数，因为是无符号转换
       uintArray[i] = Math.max(0, Math.trunc(floatArray[i]));
     }
   }

   simulateUnsignedConvert(floatArray, uintArray);
   console.log(uintArray); // 输出类似: Uint32Array [ 0, 2, 0, 4 ]，而不是预期的有符号截断
   ```

2. **车道索引错误:** 在提取或替换车道时，使用了超出范围的索引，导致访问了错误的内存位置或产生了未定义的行为。

   ```javascript
   // WebAssembly (假设)
   // i32x4.extract_lane 4  // 尝试提取索引为 4 的车道，但 i32x4 只有 4 个车道 (0-3)

   // JavaScript 模拟
   const intArray = new Int32Array([1, 2, 3, 4]);

   function simulateExtractLaneError(array, index) {
     if (index >= array.length) {
       console.error("车道索引超出范围");
       return undefined;
     }
     return array[index];
   }

   console.log(simulateExtractLaneError(intArray, 4)); // 输出: "车道索引超出范围" 和 undefined
   ```

3. **对 NaN 值的未处理:** 浮点数运算中出现 NaN (Not a Number) 值，如果没有正确处理，可能会导致整个 SIMD 运算的结果变为 NaN。

   ```javascript
   // WebAssembly (假设)
   // f32x4.add

   // JavaScript 模拟
   const floatArray1 = new Float32Array([1.0, NaN, 3.0, 4.0]);
   const floatArray2 = new Float32Array([5.0, 6.0, 7.0, 8.0]);
   const result = new Float32Array(4);

   function simulateSimdAdd(arr1, arr2, res) {
     for (let i = 0; i < arr1.length; i++) {
       res[i] = arr1[i] + arr2[i];
     }
   }

   simulateSimdAdd(floatArray1, floatArray2, result);
   console.log(result); // 输出类似: Float32Array [ 6, NaN, 10, 12 ]，第二个元素为 NaN
   ```

**归纳其功能（作为第 6 部分，共 6 部分）**

作为 Liftoff 编译器的最后一部分（假设是生成代码的阶段），`v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 的主要功能是：

1. **提供 IA-32 架构特定的机器码生成能力，用于实现 WebAssembly 的 SIMD 操作。** 它将 Wasm 的高级 SIMD 指令转换为可以直接在 x86 处理器上执行的低级汇编指令。

2. **作为 `LiftoffAssembler` 类的内联实现，优化了代码生成过程。** 内联函数可以减少函数调用开销，提高性能。

3. **与其他 Liftoff 编译器的组件协同工作。** 前面的部分可能负责词法分析、语法分析、类型检查、中间代码生成和寄存器分配等任务。这一部分专注于将中间表示转换为最终的机器码。

4. **为 V8 引擎执行 WebAssembly 代码提供基线支持。** Liftoff 编译器旨在快速生成代码，虽然可能不如优化编译器生成的代码高效，但它可以实现快速启动。

5. **处理栈管理、函数调用和一些辅助操作。** 除了核心的 SIMD 指令生成，它还负责一些与执行环境相关的操作。

总而言之，`v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h` 是 V8 的 WebAssembly 引擎 Liftoff 在 IA-32 架构上的代码生成引擎的核心组成部分，专门负责将 Wasm 的 SIMD 指令翻译成可执行的机器码。它是整个编译流程的最终环节之一，确保了 WebAssembly 代码能够在特定的硬件平台上运行。

Prompt: 
```
这是目录为v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/ia32/liftoff-assembler-ia32-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
                            LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  I32x4SConvertF32x4(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, tmp);
}

void LiftoffAssembler::emit_i32x4_uconvert_f32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  static constexpr RegClass tmp_rc = reg_class_for(kS128);
  DoubleRegister scratch2 =
      GetUnusedRegister(tmp_rc, LiftoffRegList{dst, src}).fp();
  I32x4TruncF32x4U(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, scratch2);
}

void LiftoffAssembler::emit_f32x4_sconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Cvtdq2ps(dst.fp(), src.fp());
}

void LiftoffAssembler::emit_f32x4_uconvert_i32x4(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  Pxor(liftoff::kScratchDoubleReg, liftoff::kScratchDoubleReg);  // Zeros.
  Pblendw(liftoff::kScratchDoubleReg, src.fp(),
          uint8_t{0x55});  // Get lo 16 bits.
  if (CpuFeatures::IsSupported(AVX)) {
    CpuFeatureScope scope(this, AVX);
    vpsubd(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);  // Get hi 16 bits.
  } else {
    if (dst.fp() != src.fp()) movaps(dst.fp(), src.fp());
    psubd(dst.fp(), liftoff::kScratchDoubleReg);
  }
  Cvtdq2ps(liftoff::kScratchDoubleReg,
           liftoff::kScratchDoubleReg);   // Convert lo exactly.
  Psrld(dst.fp(), dst.fp(), uint8_t{1});  // Div by 2 to get in unsigned range.
  Cvtdq2ps(dst.fp(), dst.fp());           // Convert hi, exactly.
  Addps(dst.fp(), dst.fp(), dst.fp());    // Double hi, exactly.
  Addps(dst.fp(), dst.fp(),
        liftoff::kScratchDoubleReg);  // Add hi and lo, may round.
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
  I16x8UConvertI8x16High(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
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
  I32x4UConvertI16x8High(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  I32x4TruncSatF64x2SZero(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, tmp);
}

void LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero(LiftoffRegister dst,
                                                         LiftoffRegister src) {
  Register tmp = GetUnusedRegister(kGpReg, {}).gp();
  I32x4TruncSatF64x2UZero(dst.fp(), src.fp(), liftoff::kScratchDoubleReg, tmp);
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
  I64x2Abs(dst.fp(), src.fp(), liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_i8x16_extract_lane_s(LiftoffRegister dst,
                                                 LiftoffRegister lhs,
                                                 uint8_t imm_lane_idx) {
  Register byte_reg = liftoff::GetTmpByteRegister(this, dst.gp());
  Pextrb(byte_reg, lhs.fp(), imm_lane_idx);
  movsx_b(dst.gp(), byte_reg);
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
  movsx_w(dst.gp(), dst.gp());
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
  Pextrd(dst.low_gp(), lhs.fp(), imm_lane_idx * 2);
  Pextrd(dst.high_gp(), lhs.fp(), imm_lane_idx * 2 + 1);
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
    vpinsrd(dst.fp(), src1.fp(), src2.low_gp(), imm_lane_idx * 2);
    vpinsrd(dst.fp(), dst.fp(), src2.high_gp(), imm_lane_idx * 2 + 1);
  } else {
    CpuFeatureScope scope(this, SSE4_1);
    if (dst.fp() != src1.fp()) movaps(dst.fp(), src1.fp());
    pinsrd(dst.fp(), src2.low_gp(), imm_lane_idx * 2);
    pinsrd(dst.fp(), src2.high_gp(), imm_lane_idx * 2 + 1);
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
  F32x4Qfma(dst.fp(), src1.fp(), src2.fp(), src3.fp(),
            liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f32x4_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F32x4Qfms(dst.fp(), src1.fp(), src2.fp(), src3.fp(),
            liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F64x2Qfma(dst.fp(), src1.fp(), src2.fp(), src3.fp(),
            liftoff::kScratchDoubleReg);
}

void LiftoffAssembler::emit_f64x2_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  F64x2Qfms(dst.fp(), src1.fp(), src2.fp(), src3.fp(),
            liftoff::kScratchDoubleReg);
}

bool LiftoffAssembler::emit_f16x8_splat(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_extract_lane(LiftoffRegister dst,
                                               LiftoffRegister lhs,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_replace_lane(LiftoffRegister dst,
                                               LiftoffRegister src1,
                                               LiftoffRegister src2,
                                               uint8_t imm_lane_idx) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_abs(LiftoffRegister dst,
                                      LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_neg(LiftoffRegister dst,
                                      LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_sqrt(LiftoffRegister dst,
                                       LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_ceil(LiftoffRegister dst,
                                       LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_floor(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_trunc(LiftoffRegister dst,
                                        LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_nearest_int(LiftoffRegister dst,
                                              LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_eq(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_ne(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_lt(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_le(LiftoffRegister dst, LiftoffRegister lhs,
                                     LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_add(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_sub(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_mul(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_div(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_min(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_max(LiftoffRegister dst, LiftoffRegister lhs,
                                      LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_pmin(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_pmax(LiftoffRegister dst, LiftoffRegister lhs,
                                       LiftoffRegister rhs) {
  return false;
}

bool LiftoffAssembler::emit_i16x8_sconvert_f16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_i16x8_uconvert_f16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_sconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_uconvert_i16x8(LiftoffRegister dst,
                                                 LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_demote_f32x4_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_demote_f64x2_zero(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f32x4_promote_low_f16x8(LiftoffRegister dst,
                                                    LiftoffRegister src) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfma(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

bool LiftoffAssembler::emit_f16x8_qfms(LiftoffRegister dst,
                                       LiftoffRegister src1,
                                       LiftoffRegister src2,
                                       LiftoffRegister src3) {
  return false;
}

bool LiftoffAssembler::supports_f16_mem_access() { return false; }

void LiftoffAssembler::StackCheck(Label* ool_code) {
  CompareStackLimit(esp, StackLimitKind::kInterruptStackLimit);
  j(below_equal, ool_code);
}

void LiftoffAssembler::AssertUnreachable(AbortReason reason) {
  MacroAssembler::AssertUnreachable(reason);
}

void LiftoffAssembler::PushRegisters(LiftoffRegList regs) {
  LiftoffRegList gp_regs = regs & kGpCacheRegList;
  while (!gp_regs.is_empty()) {
    LiftoffRegister reg = gp_regs.GetFirstRegSet();
    push(reg.gp());
    gp_regs.clear(reg);
  }
  LiftoffRegList fp_regs = regs & kFpCacheRegList;
  unsigned num_fp_regs = fp_regs.GetNumRegsSet();
  if (num_fp_regs) {
    AllocateStackSpace(num_fp_regs * kSimd128Size);
    unsigned offset = 0;
    while (!fp_regs.is_empty()) {
      LiftoffRegister reg = fp_regs.GetFirstRegSet();
      Movdqu(Operand(esp, offset), reg.fp());
      fp_regs.clear(reg);
      offset += kSimd128Size;
    }
    DCHECK_EQ(offset, num_fp_regs * kSimd128Size);
  }
}

void LiftoffAssembler::PopRegisters(LiftoffRegList regs) {
  LiftoffRegList fp_regs = regs & kFpCacheRegList;
  unsigned fp_offset = 0;
  while (!fp_regs.is_empty()) {
    LiftoffRegister reg = fp_regs.GetFirstRegSet();
    Movdqu(reg.fp(), Operand(esp, fp_offset));
    fp_regs.clear(reg);
    fp_offset += kSimd128Size;
  }
  if (fp_offset) add(esp, Immediate(fp_offset));
  LiftoffRegList gp_regs = regs & kGpCacheRegList;
  while (!gp_regs.is_empty()) {
    LiftoffRegister reg = gp_regs.GetLastRegSet();
    pop(reg.gp());
    gp_regs.clear(reg);
  }
}

void LiftoffAssembler::RecordSpillsInSafepoint(
    SafepointTableBuilder::Safepoint& safepoint, LiftoffRegList all_spills,
    LiftoffRegList ref_spills, int spill_offset) {
  LiftoffRegList fp_spills = all_spills & kFpCacheRegList;
  int spill_space_size = fp_spills.GetNumRegsSet() * kSimd128Size;
  LiftoffRegList gp_spills = all_spills & kGpCacheRegList;
  while (!gp_spills.is_empty()) {
    LiftoffRegister reg = gp_spills.GetFirstRegSet();
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
  DCHECK_LT(num_stack_slots,
            (1 << 16) / kSystemPointerSize);  // 16 bit immediate
  ret(static_cast<int>(num_stack_slots * kSystemPointerSize));
}

void LiftoffAssembler::CallCWithStackBuffer(
    const std::initializer_list<VarState> args, const LiftoffRegister* rets,
    ValueKind return_kind, ValueKind out_argument_kind, int stack_bytes,
    ExternalReference ext_ref) {
  AllocateStackSpace(stack_bytes);

  int arg_offset = 0;
  for (const VarState& arg : args) {
    if (arg.is_reg()) {
      liftoff::Store(this, esp, arg_offset, arg.reg(), arg.kind());
    } else if (arg.is_const()) {
      DCHECK_EQ(kI32, arg.kind());
      mov(Operand(esp, arg_offset), Immediate(arg.i32_const()));
    } else if (value_kind_size(arg.kind()) == 4) {
      // We do not have a scratch register, so move via the stack. Note that
      // {push} decrements {esp} by 4 and {pop} increments it again, but the
      // destionation operand uses the {esp} value after increasing.
      push(liftoff::GetStackSlot(arg.offset()));
      pop(Operand(esp, arg_offset));
    } else {
      DCHECK_EQ(8, value_kind_size(arg.kind()));
      push(liftoff::GetStackSlot(arg.offset()));
      pop(Operand(esp, arg_offset + 4));
      push(liftoff::GetStackSlot(arg.offset() + 4));
      pop(Operand(esp, arg_offset));
    }
    arg_offset += value_kind_size(arg.kind());
  }
  DCHECK_LE(arg_offset, stack_bytes);

  constexpr Register kScratch = eax;
  constexpr Register kArgumentBuffer = ecx;
  constexpr int kNumCCallArgs = 1;
  mov(kArgumentBuffer, esp);
  PrepareCallCFunction(kNumCCallArgs, kScratch);

  // Pass a pointer to the buffer with the arguments to the C function. ia32
  // does not use registers here, so push to the stack.
  mov(Operand(esp, 0), kArgumentBuffer);

  // Now call the C function.
  CallCFunction(ext_ref, kNumCCallArgs);

  // Move return value to the right register.
  const LiftoffRegister* next_result_reg = rets;
  if (return_kind != kVoid) {
    constexpr Register kReturnReg = eax;
    if (kReturnReg != next_result_reg->gp()) {
      Move(*next_result_reg, LiftoffRegister(kReturnReg), return_kind);
    }
    ++next_result_reg;
  }

  // Load potential output value from the buffer on the stack.
  if (out_argument_kind != kVoid) {
    liftoff::Load(this, *next_result_reg, esp, 0, out_argument_kind);
  }

  add(esp, Immediate(stack_bytes));
}

void LiftoffAssembler::CallC(const std::initializer_list<VarState> args,
                             ExternalReference ext_ref) {
  LiftoffRegList arg_regs;
  for (const VarState arg : args) {
    if (arg.is_reg()) arg_regs.set(arg.reg());
  }

  RegList usable_regs = kLiftoffAssemblerGpCacheRegs - arg_regs.GetGpList();
  Register scratch = usable_regs.first();
  int num_lowered_args = 0;
  // i64 arguments are lowered to two actual arguments (taking two stack slots).
  for (const VarState& arg : args) {
    num_lowered_args += arg.kind() == kI64 ? 2 : 1;
  }
  PrepareCallCFunction(num_lowered_args, scratch);

  // Ia32 passes all arguments via the stack. Store them now in the stack space
  // allocated by {PrepareCallCFunction}.

  // GetNextOperand returns the operand for the next stack slot on each
  // invocation.
  auto GetNextOperand = [arg_offset = 0, num_lowered_args]() mutable {
    // Check that we don't exceed the pre-computed {num_stack_slots}.
    DCHECK_GE(num_lowered_args, arg_offset);
    USE(num_lowered_args);
    return Operand{esp, arg_offset++ * kSystemPointerSize};
  };
  for (const VarState& arg : args) {
    Operand dst = GetNextOperand();
    if (arg.is_reg()) {
      LiftoffRegister reg = arg.reg();
      if (arg.kind() == kI64) {
        mov(dst, reg.low_gp());
        mov(GetNextOperand(), reg.high_gp());
      } else {
        mov(dst, reg.gp());
      }
    } else if (arg.is_const()) {
      DCHECK_EQ(kI32, arg.kind());
      mov(dst, Immediate(arg.i32_const()));
    } else {
      DCHECK(arg.is_stack());
      if (arg.kind() == kI64) {
        mov(scratch, liftoff::GetStackSlot(arg.offset()));
        mov(dst, scratch);
        mov(scratch, liftoff::GetStackSlot(arg.offset() + kSystemPointerSize));
        mov(GetNextOperand(), scratch);
      } else {
        mov(scratch, liftoff::GetStackSlot(arg.offset()));
        mov(dst, scratch);
      }
    }
  }

  // Now call the C function.
  CallCFunction(ext_ref, num_lowered_args);
}

void LiftoffAssembler::CallNativeWasmCode(Address addr) {
  wasm_call(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::TailCallNativeWasmCode(Address addr) {
  jmp(addr, RelocInfo::WASM_CALL);
}

void LiftoffAssembler::CallIndirect(const ValueKindSig* sig,
                                    compiler::CallDescriptor* call_descriptor,
                                    Register target) {
  // Since we have more cache registers than parameter registers, the
  // {LiftoffCompiler} should always be able to place {target} in a register.
  DCHECK(target.is_valid());
  CallWasmCodePointer(target);
}

void LiftoffAssembler::TailCallIndirect(Register target) {
  // Since we have more cache registers than parameter registers, the
  // {LiftoffCompiler} should always be able to place {target} in a register.
  DCHECK(target.is_valid());
  CallWasmCodePointer(target, CallJumpMode::kTailCall);
}

void LiftoffAssembler::CallBuiltin(Builtin builtin) {
  // A direct call to a builtin. Just encode the builtin index. This will be
  // patched at relocation.
  wasm_call(static_cast<Address>(builtin), RelocInfo::WASM_STUB_CALL);
}

void LiftoffAssembler::AllocateStackSlot(Register addr, uint32_t size) {
  AllocateStackSpace(size);
  mov(addr, esp);
}

void LiftoffAssembler::DeallocateStackSlot(uint32_t size) {
  add(esp, Immediate(size));
}

void LiftoffAssembler::MaybeOSR() {}

void LiftoffAssembler::emit_set_if_nan(Register dst, DoubleRegister src,
                                       ValueKind kind) {
  if (kind == kF32) {
    ucomiss(src, src);
  } else {
    DCHECK_EQ(kind, kF64);
    ucomisd(src, src);
  }
  Label ret;
  j(parity_odd, &ret);
  mov(Operand(dst, 0), Immediate(1));
  bind(&ret);
}

void LiftoffAssembler::emit_s128_set_if_nan(Register dst, LiftoffRegister src,
                                            Register tmp_gp,
                                            LiftoffRegister tmp_s128,
                                            ValueKind lane_kind) {
  if (lane_kind == kF32) {
    movaps(tmp_s128.fp(), src.fp());
    cmpunordps(tmp_s128.fp(), tmp_s128.fp());
  } else {
    DCHECK_EQ(lane_kind, kF64);
    movapd(tmp_s128.fp(), src.fp());
    cmpunordpd(tmp_s128.fp(), tmp_s128.fp());
  }
  pmovmskb(tmp_gp, tmp_s128.fp());
  or_(Operand(dst, 0), tmp_gp);
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
      case LiftoffAssembler::VarState::kStack:
        // The combination of AllocateStackSpace and 2 movdqu is usually smaller
        // in code size than doing 4 pushes.
        if (src.kind() == kS128) {
          asm_->AllocateStackSpace(stack_decrement);
          asm_->movdqu(liftoff::kScratchDoubleReg,
                       liftoff::GetStackSlot(slot.src_offset_));
          asm_->movdqu(Operand(esp, 0), liftoff::kScratchDoubleReg);
          break;
        }
        if (src.kind() == kF64) {
          asm_->AllocateStackSpace(stack_decrement - kDoubleSize);
          DCHECK_EQ(kLowWord, slot.half_);
          asm_->push(liftoff::GetHalfStackSlot(slot.src_offset_, kHighWord));
          stack_decrement = kSystemPointerSize;
        }
        asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
        asm_->push(liftoff::GetHalfStackSlot(slot.src_offset_, slot.half_));
        break;
      case LiftoffAssembler::VarState::kRegister:
        if (src.kind() == kI64) {
          liftoff::push(
              asm_, slot.half_ == kLowWord ? src.reg().low() : src.reg().high(),
              kI32, stack_decrement - kSystemPointerSize);
        } else {
          int pushed_bytes = SlotSizeInBytes(slot);
          liftoff::push(asm_, src.reg(), src.kind(),
                        stack_decrement - pushed_bytes);
        }
        break;
      case LiftoffAssembler::VarState::kIntConst:
        asm_->AllocateStackSpace(stack_decrement - kSystemPointerSize);
        // The high word is the sign extension of the low word.
        asm_->push(Immediate(slot.half_ == kLowWord ? src.i32_const()
                                                    : src.i32_const() >> 31));
        break;
    }
  }
}

#undef RETURN_FALSE_IF_MISSING_CPU_FEATURE

}  // namespace v8::internal::wasm

#endif  // V8_WASM_BASELINE_IA32_LIFTOFF_ASSEMBLER_IA32_INL_H_

"""


```