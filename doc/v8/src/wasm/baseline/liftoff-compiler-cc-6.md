Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/baseline/liftoff-compiler.cc`. I need to analyze the code and explain its purpose.

Here's a breakdown of the thought process:

1. **Identify the core function:** The code snippet is within a larger function or method, likely responsible for handling different WebAssembly (Wasm) opcodes. The `switch (opcode)` statement is the key to understanding which operations are being handled here.

2. **Focus on the `case` statements:** Each `case` corresponds to a specific Wasm instruction (e.g., `wasm::kExprI16x8ExtMulHighI8x16S`). The code within each case is responsible for generating the corresponding machine code for that Wasm instruction.

3. **Recognize patterns:**  Several patterns emerge:
    * **`EmitBinOp`:** This template function appears to handle binary operations (two inputs, one output) for SIMD types. It takes a pointer to a member function of `LiftoffAssembler` as an argument.
    * **`EmitUnOp`:**  Similar to `EmitBinOp`, but for unary operations (one input, one output).
    * **`EmitSimdShiftOp`:** Handles SIMD shift operations, potentially with immediate values.
    * **`EmitSimdFloatRoundingOpWithCFallback`:** Deals with floating-point SIMD operations that might require a fallback to a C implementation.
    * **`EmitSimdFloatBinOpWithCFallback`:** Handles binary floating-point SIMD operations with potential C fallback.
    * **`LiftoffAssembler`:** This class is crucial. It seems to provide the low-level assembly instructions needed to implement the Wasm operations. The methods called on `LiftoffAssembler` (e.g., `emit_i16x8_extmul_high_i8x16_s`) likely generate the actual machine code.

4. **Infer data types:** The template arguments to `EmitBinOp`, `EmitUnOp`, etc. (e.g., `kS128`, `kI32`, `kF32`) indicate the data types involved in the operations. `kS128` likely represents a 128-bit SIMD vector, `kI32` a 32-bit integer, and `kF32` a 32-bit float.

5. **Consider the context:** The code is in `v8/src/wasm/baseline/liftoff-compiler.cc`. This suggests that this code is part of the "Liftoff" compiler, which is V8's baseline compiler for Wasm. Baseline compilers are typically designed for fast compilation speed, even if the generated code isn't the most optimized.

6. **Address specific requests:**
    * **Functionality:** List the Wasm SIMD operations handled by this code.
    * **`.tq` extension:**  The code is C++, not Torque.
    * **JavaScript relation:**  The Wasm SIMD instructions map directly to JavaScript's SIMD API (e.g., `Int32x4`, `Float32x4`).
    * **Code logic/Input-Output:** Choose a simple case (e.g., `wasm::kExprI32x4Add`) and provide an example of the Wasm instruction and its effect.
    * **Common programming errors:**  Think about potential issues when working with SIMD in JavaScript, such as type mismatches or incorrect lane access.
    * **Part 7 of 13:**  This section likely focuses on handling a specific subset of Wasm SIMD instructions.

7. **Structure the answer:** Organize the information logically, starting with the core functionality and then addressing each specific requirement. Use clear and concise language. Provide examples where requested.

8. **Self-Correction/Refinement:**  Review the generated answer. Ensure the explanations are accurate and easy to understand. Double-check the JavaScript examples for correctness. Make sure the summary aligns with the content of the code snippet. For example, initially, I might have just listed the instructions. But a more insightful answer connects them to the broader purpose of the Liftoff compiler and the relationship to JavaScript. I also need to explicitly state that the file is C++ and not a Torque file.
这是 `v8/src/wasm/baseline/liftoff-compiler.cc` 文件的**第 7 部分**，负责处理 **WebAssembly SIMD (Single Instruction, Multiple Data)** 指令的编译。

**功能概括:**

这部分代码的核心功能是：**针对给定的 WebAssembly SIMD 操作码 (opcode)，生成相应的机器码指令，以便在 V8 引擎中执行这些 SIMD 操作。** 它通过 `switch` 语句根据不同的 opcode 调用 `LiftoffAssembler` 类中相应的 `emit_` 方法来完成机器码的生成。

**详细功能分解:**

1. **SIMD 操作码分发:** 代码使用一个大的 `switch` 语句来处理各种 WebAssembly SIMD 操作码，例如：
    * 整数 SIMD 操作：加法、减法、乘法、位运算、移位、扩展、饱和运算等 (例如 `kExprI8x16Add`, `kExprI16x8Shl`, `kExprI32x4ExtMulLowI16x8S`)
    * 浮点数 SIMD 操作：绝对值、取反、平方根、舍入、加法、减法、乘法、除法、最小值、最大值等 (例如 `kExprF32x4Abs`, `kExprF64x2Add`, `kExprF16x8Min`)
    * 类型转换 SIMD 操作：整数和浮点数之间的转换，不同位宽 SIMD 类型之间的转换 (例如 `kExprI32x4SConvertF32x4`, `kExprF16x8DemoteF32x4Zero`)
    * Lane 操作：提取和替换 SIMD 向量中的特定元素 (例如 `kExprI32x4ExtractLane`, `kExprF16x8ReplaceLane`)
    * 其他 SIMD 操作：`select` (根据掩码选择元素), `shuffle` (重排向量元素),  点积运算 (`dot`), `qfma`/`qfms` (Fused Multiply-Add/Subtract), Relaxed SIMD 指令等。

2. **调用 `LiftoffAssembler` 方法:** 对于每个支持的 SIMD 操作码，代码会调用 `LiftoffAssembler` 类中相应的方法（通常以 `emit_` 开头）。`LiftoffAssembler` 负责生成特定目标架构（例如 x64, ARM）的机器码指令来实现该 SIMD 操作。

3. **使用模板简化代码:**  代码使用了模板 (`EmitBinOp`, `EmitUnOp`, `EmitSimdShiftOp` 等) 来减少重复代码，并根据操作数的类型和操作的特性来选择合适的 `LiftoffAssembler` 方法。

4. **处理需要 C 函数回退的情况:** 对于一些复杂的浮点数 SIMD 操作 (例如涉及舍入的运算)，如果硬件没有直接支持，代码会使用 `EmitSimdFloatRoundingOpWithCFallback` 和 `EmitSimdFloatBinOpWithCFallback`，这意味着在某些情况下，V8 会调用 C++ 函数来模拟这些 SIMD 操作。

**关于文件类型:**

`v8/src/wasm/baseline/liftoff-compiler.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件的后缀是 `.tq`）。

**与 JavaScript 的关系及举例:**

WebAssembly 的 SIMD 指令与 JavaScript 的 [SIMD API](https://developer.mozilla.org/en-US/docs/Web/API/SIMD) 有着直接的对应关系。JavaScript 开发者可以使用 `Int8x16`, `Uint8x16`, `Int16x8`, `Uint16x8`, `Int32x4`, `Uint32x4`, `Float32x4`, `Float64x2` 等对象来创建和操作 SIMD 数据。

例如，WebAssembly 的 `i32x4.add` 指令对应于 JavaScript 的 `Int32x4.add()` 方法：

```javascript
// JavaScript SIMD 代码
const a = Int32x4(1, 2, 3, 4);
const b = Int32x4(5, 6, 7, 8);
const result = Int32x4.add(a, b);
// result 的值为 Int32x4(6, 8, 10, 12)

// 对应的 WebAssembly (抽象语法树层面) 可能包含类似的操作:
// (i32x4.add (local.get 0) (local.get 1))
```

当 V8 执行包含 `i32x4.add` 指令的 WebAssembly 代码时，`liftoff-compiler.cc` 中的相应 `case wasm::kExprI32x4Add:` 代码会被执行，并生成相应的机器码指令来执行向量加法。

**代码逻辑推理及假设输入输出:**

假设执行的 WebAssembly 指令是 `i32x4.add`，其操作码为 `wasm::kExprI32x4Add`。

**假设输入:**

* 栈顶的两个操作数是两个 `kS128` 类型的 SIMD 向量，分别存储在 Liftoff 寄存器 `lhs` 和 `rhs` 中。例如：
    * `lhs` 包含 `[1, 2, 3, 4]`
    * `rhs` 包含 `[5, 6, 7, 8]`

**代码逻辑:**

当执行到 `case wasm::kExprI32x4Add:` 时，会调用 `EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_add);`。

* `EmitBinOp` 模板函数会从栈中弹出两个 `kS128` 类型的操作数到寄存器 `lhs` 和 `rhs`。
* `LiftoffAssembler::emit_i32x4_add(dst, lhs, rhs)` 方法会被调用，生成机器码指令，将 `lhs` 和 `rhs` 中的四个 32 位整数分别相加，并将结果存储到寄存器 `dst` 中。
* 结果 `dst` 会被压回栈顶，类型为 `kS128`。

**假设输出:**

* 栈顶的 `kS128` 类型的 SIMD 向量包含 `[6, 8, 10, 12]`。

**涉及用户常见的编程错误及举例:**

在使用 JavaScript SIMD API 或编写 WebAssembly 代码时，用户可能会遇到以下常见的编程错误：

1. **类型不匹配:** 尝试对不同类型的 SIMD 向量进行操作，例如将 `Int32x4` 与 `Float32x4` 相加。

   ```javascript
   const intVec = Int32x4(1, 2, 3, 4);
   const floatVec = Float32x4(1.0, 2.0, 3.0, 4.0);
   // 错误：不能直接将 Int32x4 和 Float32x4 相加
   // const result = Int32x4.add(intVec, floatVec);
   ```

2. **Lane 索引越界:** 在提取或替换 Lane 时，使用了超出向量边界的索引。

   ```javascript
   const vec = Int32x4(1, 2, 3, 4);
   // 错误：索引 4 超出了 Int32x4 的范围 (0-3)
   // const element = vec.extractLane(4);
   ```

3. **位运算的误用:** 对浮点数 SIMD 向量使用位运算，或者对有符号整数使用无符号位运算，反之亦然。

   ```javascript
   const floatVec = Float32x4(1.0, 2.0, 3.0, 4.0);
   // 错误：不能对浮点数向量直接使用按位与运算
   // const result = Float32x4.and(floatVec, floatVec);

   const signedVec = Int32x4(1, -2, 3, -4);
   // 错误：可能不希望对有符号数使用无符号右移
   // const result = Uint32x4.shiftRightLogicalBy(signedVec, 1);
   ```

4. **混淆有符号和无符号扩展/转换:** 在进行类型转换时，错误地使用了有符号或无符号扩展/转换指令，导致结果不符合预期。

**总结:**

`v8/src/wasm/baseline/liftoff-compiler.cc` 的第 7 部分专注于实现 WebAssembly SIMD 指令的快速编译。它通过一个大的 `switch` 语句分发不同的 SIMD 操作码，并调用 `LiftoffAssembler` 中相应的方法来生成目标平台的机器码。这部分代码是 V8 引擎支持 WebAssembly SIMD 功能的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
inOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_high_i8x16_s);
      case wasm::kExprI16x8ExtMulHighI8x16U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_extmul_high_i8x16_u);
      case wasm::kExprI16x8Q15MulRSatS:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_q15mulr_sat_s);
      case wasm::kExprI32x4Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_neg);
      case wasm::kExprI32x4AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i32x4_alltrue);
      case wasm::kExprI32x4BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i32x4_bitmask);
      case wasm::kExprI32x4Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i32x4_shl,
                               &LiftoffAssembler::emit_i32x4_shli);
      case wasm::kExprI32x4ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i32x4_shr_s,
                               &LiftoffAssembler::emit_i32x4_shri_s);
      case wasm::kExprI32x4ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i32x4_shr_u,
                               &LiftoffAssembler::emit_i32x4_shri_u);
      case wasm::kExprI32x4Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_add);
      case wasm::kExprI32x4Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_sub);
      case wasm::kExprI32x4Mul:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_mul);
      case wasm::kExprI32x4MinS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_min_s);
      case wasm::kExprI32x4MinU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_min_u);
      case wasm::kExprI32x4MaxS:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_max_s);
      case wasm::kExprI32x4MaxU:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_max_u);
      case wasm::kExprI32x4DotI16x8S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_dot_i16x8_s);
      case wasm::kExprI32x4ExtAddPairwiseI16x8S:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_s);
      case wasm::kExprI32x4ExtAddPairwiseI16x8U:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extadd_pairwise_i16x8_u);
      case wasm::kExprI32x4ExtMulLowI16x8S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_low_i16x8_s);
      case wasm::kExprI32x4ExtMulLowI16x8U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_low_i16x8_u);
      case wasm::kExprI32x4ExtMulHighI16x8S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_high_i16x8_s);
      case wasm::kExprI32x4ExtMulHighI16x8U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_extmul_high_i16x8_u);
      case wasm::kExprI64x2Neg:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_neg);
      case wasm::kExprI64x2AllTrue:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i64x2_alltrue);
      case wasm::kExprI64x2Shl:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i64x2_shl,
                               &LiftoffAssembler::emit_i64x2_shli);
      case wasm::kExprI64x2ShrS:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i64x2_shr_s,
                               &LiftoffAssembler::emit_i64x2_shri_s);
      case wasm::kExprI64x2ShrU:
        return EmitSimdShiftOp(&LiftoffAssembler::emit_i64x2_shr_u,
                               &LiftoffAssembler::emit_i64x2_shri_u);
      case wasm::kExprI64x2Add:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_add);
      case wasm::kExprI64x2Sub:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_sub);
      case wasm::kExprI64x2Mul:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_mul);
      case wasm::kExprI64x2ExtMulLowI32x4S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_low_i32x4_s);
      case wasm::kExprI64x2ExtMulLowI32x4U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_low_i32x4_u);
      case wasm::kExprI64x2ExtMulHighI32x4S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_high_i32x4_s);
      case wasm::kExprI64x2ExtMulHighI32x4U:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_extmul_high_i32x4_u);
      case wasm::kExprI64x2BitMask:
        return EmitUnOp<kS128, kI32>(&LiftoffAssembler::emit_i64x2_bitmask);
      case wasm::kExprI64x2SConvertI32x4Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_sconvert_i32x4_low);
      case wasm::kExprI64x2SConvertI32x4High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_sconvert_i32x4_high);
      case wasm::kExprI64x2UConvertI32x4Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_uconvert_i32x4_low);
      case wasm::kExprI64x2UConvertI32x4High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i64x2_uconvert_i32x4_high);
      case wasm::kExprF16x8Abs:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_abs,
            &ExternalReference::wasm_f16x8_abs);
      case wasm::kExprF16x8Neg:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_neg,
            &ExternalReference::wasm_f16x8_neg);
      case wasm::kExprF16x8Sqrt:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_sqrt,
            &ExternalReference::wasm_f16x8_sqrt);
      case wasm::kExprF16x8Ceil:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_ceil,
            &ExternalReference::wasm_f16x8_ceil);
      case wasm::kExprF16x8Floor:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_floor,
            ExternalReference::wasm_f16x8_floor);
      case wasm::kExprF16x8Trunc:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_trunc,
            ExternalReference::wasm_f16x8_trunc);
      case wasm::kExprF16x8NearestInt:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_nearest_int,
            ExternalReference::wasm_f16x8_nearest_int);
      case wasm::kExprF16x8Add:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_add,
            ExternalReference::wasm_f16x8_add);
      case wasm::kExprF16x8Sub:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_sub,
            ExternalReference::wasm_f16x8_sub);
      case wasm::kExprF16x8Mul:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_mul,
            ExternalReference::wasm_f16x8_mul);
      case wasm::kExprF16x8Div:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_div,
            ExternalReference::wasm_f16x8_div);
      case wasm::kExprF16x8Min:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_min,
            ExternalReference::wasm_f16x8_min);
      case wasm::kExprF16x8Max:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_max,
            ExternalReference::wasm_f16x8_max);
      case wasm::kExprF16x8Pmin:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_pmin,
            ExternalReference::wasm_f16x8_pmin);
      case wasm::kExprF16x8Pmax:
        return EmitSimdFloatBinOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_pmax,
            ExternalReference::wasm_f16x8_pmax);
      case wasm::kExprF32x4Abs:
        return EmitUnOp<kS128, kS128, kF32>(&LiftoffAssembler::emit_f32x4_abs);
      case wasm::kExprF32x4Neg:
        return EmitUnOp<kS128, kS128, kF32>(&LiftoffAssembler::emit_f32x4_neg);
      case wasm::kExprF32x4Sqrt:
        return EmitUnOp<kS128, kS128, kF32>(&LiftoffAssembler::emit_f32x4_sqrt);
      case wasm::kExprF32x4Ceil:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_ceil,
            &ExternalReference::wasm_f32x4_ceil);
      case wasm::kExprF32x4Floor:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_floor,
            ExternalReference::wasm_f32x4_floor);
      case wasm::kExprF32x4Trunc:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_trunc,
            ExternalReference::wasm_f32x4_trunc);
      case wasm::kExprF32x4NearestInt:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_nearest_int,
            ExternalReference::wasm_f32x4_nearest_int);
      case wasm::kExprF32x4Add:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_add);
      case wasm::kExprF32x4Sub:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_sub);
      case wasm::kExprF32x4Mul:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_mul);
      case wasm::kExprF32x4Div:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_div);
      case wasm::kExprF32x4Min:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_min);
      case wasm::kExprF32x4Max:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_max);
      case wasm::kExprF32x4Pmin:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_pmin);
      case wasm::kExprF32x4Pmax:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_pmax);
      case wasm::kExprF64x2Abs:
        return EmitUnOp<kS128, kS128, kF64>(&LiftoffAssembler::emit_f64x2_abs);
      case wasm::kExprF64x2Neg:
        return EmitUnOp<kS128, kS128, kF64>(&LiftoffAssembler::emit_f64x2_neg);
      case wasm::kExprF64x2Sqrt:
        return EmitUnOp<kS128, kS128, kF64>(&LiftoffAssembler::emit_f64x2_sqrt);
      case wasm::kExprF64x2Ceil:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_ceil,
            &ExternalReference::wasm_f64x2_ceil);
      case wasm::kExprF64x2Floor:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_floor,
            ExternalReference::wasm_f64x2_floor);
      case wasm::kExprF64x2Trunc:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_trunc,
            ExternalReference::wasm_f64x2_trunc);
      case wasm::kExprF64x2NearestInt:
        return EmitSimdFloatRoundingOpWithCFallback<kF64>(
            &LiftoffAssembler::emit_f64x2_nearest_int,
            ExternalReference::wasm_f64x2_nearest_int);
      case wasm::kExprF64x2Add:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_add);
      case wasm::kExprF64x2Sub:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_sub);
      case wasm::kExprF64x2Mul:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_mul);
      case wasm::kExprF64x2Div:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_div);
      case wasm::kExprF64x2Min:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_min);
      case wasm::kExprF64x2Max:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_max);
      case wasm::kExprF64x2Pmin:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_pmin);
      case wasm::kExprF64x2Pmax:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_pmax);
      case wasm::kExprI32x4SConvertF32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_i32x4_sconvert_f32x4);
      case wasm::kExprI32x4UConvertF32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_i32x4_uconvert_f32x4);
      case wasm::kExprF32x4SConvertI32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_f32x4_sconvert_i32x4);
      case wasm::kExprF32x4UConvertI32x4:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_f32x4_uconvert_i32x4);
      case wasm::kExprF32x4PromoteLowF16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kF32>(
            &LiftoffAssembler::emit_f32x4_promote_low_f16x8,
            &ExternalReference::wasm_f32x4_promote_low_f16x8);
      case wasm::kExprF16x8DemoteF32x4Zero:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_demote_f32x4_zero,
            &ExternalReference::wasm_f16x8_demote_f32x4_zero);
      case wasm::kExprF16x8DemoteF64x2Zero:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_demote_f64x2_zero,
            &ExternalReference::wasm_f16x8_demote_f64x2_zero);
      case wasm::kExprI16x8SConvertF16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_i16x8_sconvert_f16x8,
            &ExternalReference::wasm_i16x8_sconvert_f16x8);
      case wasm::kExprI16x8UConvertF16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kI16>(
            &LiftoffAssembler::emit_i16x8_uconvert_f16x8,
            &ExternalReference::wasm_i16x8_uconvert_f16x8);
      case wasm::kExprF16x8SConvertI16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_sconvert_i16x8,
            &ExternalReference::wasm_f16x8_sconvert_i16x8);
      case wasm::kExprF16x8UConvertI16x8:
        return EmitSimdFloatRoundingOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_uconvert_i16x8,
            &ExternalReference::wasm_f16x8_uconvert_i16x8);
      case wasm::kExprI8x16SConvertI16x8:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i8x16_sconvert_i16x8);
      case wasm::kExprI8x16UConvertI16x8:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i8x16_uconvert_i16x8);
      case wasm::kExprI16x8SConvertI32x4:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_sconvert_i32x4);
      case wasm::kExprI16x8UConvertI32x4:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_uconvert_i32x4);
      case wasm::kExprI16x8SConvertI8x16Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_sconvert_i8x16_low);
      case wasm::kExprI16x8SConvertI8x16High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_sconvert_i8x16_high);
      case wasm::kExprI16x8UConvertI8x16Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_uconvert_i8x16_low);
      case wasm::kExprI16x8UConvertI8x16High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_uconvert_i8x16_high);
      case wasm::kExprI32x4SConvertI16x8Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_sconvert_i16x8_low);
      case wasm::kExprI32x4SConvertI16x8High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_sconvert_i16x8_high);
      case wasm::kExprI32x4UConvertI16x8Low:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_uconvert_i16x8_low);
      case wasm::kExprI32x4UConvertI16x8High:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_uconvert_i16x8_high);
      case wasm::kExprS128AndNot:
        return EmitBinOp<kS128, kS128>(&LiftoffAssembler::emit_s128_and_not);
      case wasm::kExprI8x16RoundingAverageU:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i8x16_rounding_average_u);
      case wasm::kExprI16x8RoundingAverageU:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_rounding_average_u);
      case wasm::kExprI8x16Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i8x16_abs);
      case wasm::kExprI16x8Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i16x8_abs);
      case wasm::kExprI32x4Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i32x4_abs);
      case wasm::kExprI64x2Abs:
        return EmitUnOp<kS128, kS128>(&LiftoffAssembler::emit_i64x2_abs);
      case wasm::kExprF64x2ConvertLowI32x4S:
        return EmitUnOp<kS128, kS128, kF64>(
            &LiftoffAssembler::emit_f64x2_convert_low_i32x4_s);
      case wasm::kExprF64x2ConvertLowI32x4U:
        return EmitUnOp<kS128, kS128, kF64>(
            &LiftoffAssembler::emit_f64x2_convert_low_i32x4_u);
      case wasm::kExprF64x2PromoteLowF32x4:
        return EmitUnOp<kS128, kS128, kF64>(
            &LiftoffAssembler::emit_f64x2_promote_low_f32x4);
      case wasm::kExprF32x4DemoteF64x2Zero:
        return EmitUnOp<kS128, kS128, kF32>(
            &LiftoffAssembler::emit_f32x4_demote_f64x2_zero);
      case wasm::kExprI32x4TruncSatF64x2SZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_s_zero);
      case wasm::kExprI32x4TruncSatF64x2UZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_trunc_sat_f64x2_u_zero);
      case wasm::kExprF16x8Qfma:
        return EmitSimdFmaOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_qfma,
            &ExternalReference::wasm_f16x8_qfma);
      case wasm::kExprF16x8Qfms:
        return EmitSimdFmaOpWithCFallback<kF16>(
            &LiftoffAssembler::emit_f16x8_qfms,
            &ExternalReference::wasm_f16x8_qfms);
      case wasm::kExprF32x4Qfma:
        return EmitSimdFmaOp<kF32>(&LiftoffAssembler::emit_f32x4_qfma);
      case wasm::kExprF32x4Qfms:
        return EmitSimdFmaOp<kF32>(&LiftoffAssembler::emit_f32x4_qfms);
      case wasm::kExprF64x2Qfma:
        return EmitSimdFmaOp<kF64>(&LiftoffAssembler::emit_f64x2_qfma);
      case wasm::kExprF64x2Qfms:
        return EmitSimdFmaOp<kF64>(&LiftoffAssembler::emit_f64x2_qfms);
      case wasm::kExprI16x8RelaxedLaneSelect:
      case wasm::kExprI8x16RelaxedLaneSelect:
        // There is no special hardware instruction for 16-bit wide lanes on
        // any of our platforms, so fall back to bytewise selection for i16x8.
        return EmitRelaxedLaneSelect(8);
      case wasm::kExprI32x4RelaxedLaneSelect:
        return EmitRelaxedLaneSelect(32);
      case wasm::kExprI64x2RelaxedLaneSelect:
        return EmitRelaxedLaneSelect(64);
      case wasm::kExprF32x4RelaxedMin:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_relaxed_min);
      case wasm::kExprF32x4RelaxedMax:
        return EmitBinOp<kS128, kS128, false, kF32>(
            &LiftoffAssembler::emit_f32x4_relaxed_max);
      case wasm::kExprF64x2RelaxedMin:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_relaxed_min);
      case wasm::kExprF64x2RelaxedMax:
        return EmitBinOp<kS128, kS128, false, kF64>(
            &LiftoffAssembler::emit_f64x2_relaxed_max);
      case wasm::kExprI16x8RelaxedQ15MulRS:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_relaxed_q15mulr_s);
      case wasm::kExprI32x4RelaxedTruncF32x4S:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_s);
      case wasm::kExprI32x4RelaxedTruncF32x4U:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f32x4_u);
      case wasm::kExprI32x4RelaxedTruncF64x2SZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_s_zero);
      case wasm::kExprI32x4RelaxedTruncF64x2UZero:
        return EmitUnOp<kS128, kS128>(
            &LiftoffAssembler::emit_i32x4_relaxed_trunc_f64x2_u_zero);
      case wasm::kExprI16x8DotI8x16I7x16S:
        return EmitBinOp<kS128, kS128>(
            &LiftoffAssembler::emit_i16x8_dot_i8x16_i7x16_s);
      case wasm::kExprI32x4DotI8x16I7x16AddS: {
        // There is no helper for an instruction with 3 SIMD operands
        // and we do not expect to add any more, so inlining it here.
        static constexpr RegClass res_rc = reg_class_for(kS128);
        LiftoffRegList pinned;
        LiftoffRegister acc = pinned.set(__ PopToRegister(pinned));
        LiftoffRegister rhs = pinned.set(__ PopToRegister(pinned));
        LiftoffRegister lhs = pinned.set(__ PopToRegister(pinned));
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
        // x86 platforms save a move when dst == acc, so prefer that.
        LiftoffRegister dst =
            __ GetUnusedRegister(res_rc, {acc}, LiftoffRegList{lhs, rhs});
#else
        // On other platforms, for simplicity, we ensure that none of the
        // registers alias. (If we cared, it would probably be feasible to
        // allow {dst} to alias with {lhs} or {rhs}, but that'd be brittle.)
        LiftoffRegister dst = __ GetUnusedRegister(res_rc, pinned);
#endif

        __ emit_i32x4_dot_i8x16_i7x16_add_s(dst, lhs, rhs, acc);
        __ PushRegister(kS128, dst);
        return;
      }
      default:
        UNREACHABLE();
    }
  }

  template <ValueKind src_kind, ValueKind result_kind, typename EmitFn>
  void EmitSimdExtractLaneOp(EmitFn fn, const SimdLaneImmediate& imm) {
    static constexpr RegClass src_rc = reg_class_for(src_kind);
    static constexpr RegClass result_rc = reg_class_for(result_kind);
    LiftoffRegister lhs = __ PopToRegister();
    LiftoffRegister dst = src_rc == result_rc
                              ? __ GetUnusedRegister(result_rc, {lhs}, {})
                              : __ GetUnusedRegister(result_rc, {});
    fn(dst, lhs, imm.lane);
    __ PushRegister(result_kind, dst);
  }

  template <ValueKind src2_kind, typename EmitFn>
  void EmitSimdReplaceLaneOp(EmitFn fn, const SimdLaneImmediate& imm) {
    static constexpr RegClass src1_rc = reg_class_for(kS128);
    static constexpr RegClass src2_rc = reg_class_for(src2_kind);
    static constexpr RegClass result_rc = reg_class_for(kS128);
    // On backends which need fp pair, src1_rc and result_rc end up being
    // kFpRegPair, which is != kFpReg, but we still want to pin src2 when it is
    // kFpReg, since it can overlap with those pairs.
    static constexpr bool pin_src2 = kNeedS128RegPair && src2_rc == kFpReg;

    // Does not work for arm
    LiftoffRegister src2 = __ PopToRegister();
    LiftoffRegister src1 = (src1_rc == src2_rc || pin_src2)
                               ? __ PopToRegister(LiftoffRegList{src2})
                               : __
                                 PopToRegister();
    LiftoffRegister dst =
        (src2_rc == result_rc || pin_src2)
            ? __ GetUnusedRegister(result_rc, {src1}, LiftoffRegList{src2})
            : __ GetUnusedRegister(result_rc, {src1}, {});
    fn(dst, src1, src2, imm.lane);
    __ PushRegister(kS128, dst);
  }

  void SimdLaneOp(FullDecoder* decoder, WasmOpcode opcode,
                  const SimdLaneImmediate& imm,
                  base::Vector<const Value> inputs, Value* result) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    switch (opcode) {
#define CASE_SIMD_EXTRACT_LANE_OP(opcode, kind, fn)      \
  case wasm::kExpr##opcode:                              \
    EmitSimdExtractLaneOp<kS128, k##kind>(               \
        [this](LiftoffRegister dst, LiftoffRegister lhs, \
               uint8_t imm_lane_idx) {                   \
          __ emit_##fn(dst, lhs, imm_lane_idx);          \
        },                                               \
        imm);                                            \
    break;
      CASE_SIMD_EXTRACT_LANE_OP(I8x16ExtractLaneS, I32, i8x16_extract_lane_s)
      CASE_SIMD_EXTRACT_LANE_OP(I8x16ExtractLaneU, I32, i8x16_extract_lane_u)
      CASE_SIMD_EXTRACT_LANE_OP(I16x8ExtractLaneS, I32, i16x8_extract_lane_s)
      CASE_SIMD_EXTRACT_LANE_OP(I16x8ExtractLaneU, I32, i16x8_extract_lane_u)
      CASE_SIMD_EXTRACT_LANE_OP(I32x4ExtractLane, I32, i32x4_extract_lane)
      CASE_SIMD_EXTRACT_LANE_OP(I64x2ExtractLane, I64, i64x2_extract_lane)
      CASE_SIMD_EXTRACT_LANE_OP(F32x4ExtractLane, F32, f32x4_extract_lane)
      CASE_SIMD_EXTRACT_LANE_OP(F64x2ExtractLane, F64, f64x2_extract_lane)
#undef CASE_SIMD_EXTRACT_LANE_OP
      case wasm::kExprF16x8ExtractLane:
        EmitSimdExtractLaneOp<kS128, kF32>(
            [this](LiftoffRegister dst, LiftoffRegister lhs,
                   uint8_t imm_lane_idx) {
              if (asm_.emit_f16x8_extract_lane(dst, lhs, imm_lane_idx)) return;
              LiftoffRegister value = __ GetUnusedRegister(kGpReg, {});
              __ emit_i16x8_extract_lane_u(value, lhs, imm_lane_idx);
              auto conv_ref = ExternalReference::wasm_float16_to_float32();
              GenerateCCallWithStackBuffer(
                  &dst, kVoid, kF32, {VarState{kI16, value, 0}}, conv_ref);
            },
            imm);
        break;
#define CASE_SIMD_REPLACE_LANE_OP(opcode, kind, fn)          \
  case wasm::kExpr##opcode:                                  \
    EmitSimdReplaceLaneOp<k##kind>(                          \
        [this](LiftoffRegister dst, LiftoffRegister src1,    \
               LiftoffRegister src2, uint8_t imm_lane_idx) { \
          __ emit_##fn(dst, src1, src2, imm_lane_idx);       \
        },                                                   \
        imm);                                                \
    break;
      CASE_SIMD_REPLACE_LANE_OP(I8x16ReplaceLane, I32, i8x16_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(I16x8ReplaceLane, I32, i16x8_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(I32x4ReplaceLane, I32, i32x4_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(I64x2ReplaceLane, I64, i64x2_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(F32x4ReplaceLane, F32, f32x4_replace_lane)
      CASE_SIMD_REPLACE_LANE_OP(F64x2ReplaceLane, F64, f64x2_replace_lane)
#undef CASE_SIMD_REPLACE_LANE_OP
      case wasm::kExprF16x8ReplaceLane: {
        EmitSimdReplaceLaneOp<kI32>(
            [this](LiftoffRegister dst, LiftoffRegister src1,
                   LiftoffRegister src2, uint8_t imm_lane_idx) {
              if (asm_.emit_f16x8_replace_lane(dst, src1, src2, imm_lane_idx)) {
                return;
              }
              __ PushRegister(kS128, src1);
              LiftoffRegister value = __ GetUnusedRegister(kGpReg, {});
              auto conv_ref = ExternalReference::wasm_float32_to_float16();
              GenerateCCallWithStackBuffer(&value, kVoid, kI16,
                                           {VarState{kF32, src2, 0}}, conv_ref);
              __ PopToFixedRegister(src1);
              __ emit_i16x8_replace_lane(dst, src1, value, imm_lane_idx);
            },
            imm);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    constexpr RegClass result_rc = reg_class_for(kS128);
    LiftoffRegister dst = __ GetUnusedRegister(result_rc, {});
    bool all_zeroes = std::all_of(std::begin(imm.value), std::end(imm.value),
                                  [](uint8_t v) { return v == 0; });
    bool all_ones = std::all_of(std::begin(imm.value), std::end(imm.value),
                                [](uint8_t v) { return v == 0xff; });
    if (all_zeroes) {
      __ LiftoffAssembler::emit_s128_xor(dst, dst, dst);
    } else if (all_ones) {
      // Any SIMD eq will work, i32x4 is efficient on all archs.
      __ LiftoffAssembler::emit_i32x4_eq(dst, dst, dst);
    } else {
      __ LiftoffAssembler::emit_s128_const(dst, imm.value);
    }
    __ PushRegister(kS128, dst);
  }

  void Simd8x16ShuffleOp(FullDecoder* decoder, const Simd128Immediate& imm,
                         const Value& input0, const Value& input1,
                         Value* result) {
    CHECK(CpuFeatures::SupportsWasmSimd128());
    static constexpr RegClass result_rc = reg_class_for(kS128);
    LiftoffRegList pinned;
    LiftoffRegister rhs = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister lhs = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister dst = __ GetUnusedRegister(result_rc, {lhs, rhs}, {});

    uint8_t shuffle[kSimd128Size];
    memcpy(shuffle, imm.value, sizeof(shuffle));
    bool is_swizzle;
    bool needs_swap;
    wasm::SimdShuffle::CanonicalizeShuffle(lhs == rhs, shuffle, &needs_swap,
                                           &is_swizzle);
    if (needs_swap) {
      std::swap(lhs, rhs);
    }
    __ LiftoffAssembler::emit_i8x16_shuffle(dst, lhs, rhs, shuffle, is_swizzle);
    __ PushRegister(kS128, dst);
  }

  void ToSmi(Register reg) {
    if (COMPRESS_POINTERS_BOOL || kSystemPointerSize == 4) {
      __ emit_i32_shli(reg, reg, kSmiShiftSize + kSmiTagSize);
    } else {
      __ emit_i64_shli(LiftoffRegister{reg}, LiftoffRegister{reg},
                       kSmiShiftSize + kSmiTagSize);
    }
  }

  void Store32BitExceptionValue(Register values_array, int* index_in_array,
                                Register value, LiftoffRegList pinned) {
    Register tmp_reg = __ GetUnusedRegister(kGpReg, pinned).gp();
    // Get the lower half word into tmp_reg and extend to a Smi.
    --*index_in_array;
    __ emit_i32_andi(tmp_reg, value, 0xffff);
    ToSmi(tmp_reg);
    __ StoreTaggedPointer(
        values_array, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index_in_array),
        tmp_reg, pinned, nullptr, LiftoffAssembler::kSkipWriteBarrier);

    // Get the upper half word into tmp_reg and extend to a Smi.
    --*index_in_array;
    __ emit_i32_shri(tmp_reg, value, 16);
    ToSmi(tmp_reg);
    __ StoreTaggedPointer(
        values_array, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index_in_array),
        tmp_reg, pinned, nullptr, LiftoffAssembler::kSkipWriteBarrier);
  }

  void Store64BitExceptionValue(Register values_array, int* index_in_array,
                                LiftoffRegister value, LiftoffRegList pinned) {
    if (kNeedI64RegPair) {
      Store32BitExceptionValue(values_array, index_in_array, value.low_gp(),
                               pinned);
      Store32BitExceptionValue(values_array, index_in_array, value.high_gp(),
                               pinned);
    } else {
      Store32BitExceptionValue(values_array, index_in_array, value.gp(),
                               pinned);
      __ emit_i64_shri(value, value, 32);
      Store32BitExceptionValue(values_array, index_in_array, value.gp(),
                               pinned);
    }
  }

  void Load16BitExceptionValue(LiftoffRegister dst,
                               LiftoffRegister values_array, uint32_t* index,
                               LiftoffRegList pinned) {
    __ LoadSmiAsInt32(
        dst, values_array.gp(),
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(*index));
    (*index)++;
  }

  void Load32BitExceptionValue(Register dst, LiftoffRegister values_array,
                               uint32_t* index, LiftoffRegList pinned) {
    LiftoffRegister upper = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    Load16BitExceptionValue(upper, values_array, index, pinned);
    __ emit_i32_shli(upper.gp(), upper.gp(), 16);
    Load16BitExceptionValue(LiftoffRegister(dst), values_array, index, pinned);
    __ emit_i32_or(dst, upper.gp(), dst);
  }

  void Load64BitExceptionValue(LiftoffRegister dst,
                               LiftoffRegister values_array, uint32_t* index,
                               LiftoffRegList pinned) {
    if (kNeedI64RegPair) {
      Load32BitExceptionValue(dst.high_gp(), values_array, index, pinned);
      Load32BitExceptionValue(dst.low_gp(), values_array, index, pinned);
    } el
```