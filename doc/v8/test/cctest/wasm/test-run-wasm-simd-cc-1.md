Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of V8's test suite for WebAssembly SIMD (Single Instruction, Multiple Data) operations.

Here's a breakdown of the thought process:

1. **Identify the Purpose:** The code is in `v8/test/cctest/wasm/test-run-wasm-simd.cc`, indicating it's a C++ test file within the V8 project, specifically for testing WebAssembly SIMD features. The `WASM_EXEC_TEST` macros strongly suggest these are individual test cases.

2. **Analyze Individual Tests:** Each `WASM_EXEC_TEST` block defines a test function. The name of the test function usually corresponds to a specific WebAssembly SIMD instruction. For example, `F64x2Add` tests the `f64x2.add` instruction.

3. **Recognize Test Patterns:**  Notice recurring patterns like `RunF64x2BinOpTest`, `RunF64x2CompareOpTest`, `RunI32x4UnOpTest`, etc. These are helper functions designed to simplify the creation of tests for different categories of SIMD operations (binary, comparison, unary).

4. **Infer Functionality from Test Names and Helper Functions:**
    * Tests starting with `F64x2`, `F32x4` likely involve floating-point SIMD operations with 64-bit (double) and 32-bit (float) elements, respectively.
    * Tests starting with `I64x2`, `I32x4`, `I16x8`, `I8x16` involve integer SIMD operations with different lane widths and counts.
    * Operations like `Add`, `Sub`, `Mul`, `Min`, `Max` are standard arithmetic operations.
    * Operations like `Eq`, `Ne`, `Gt`, `Ge`, `Lt`, `Le` are comparison operations.
    * Operations like `Splat` create a vector with all lanes having the same value.
    * Operations like `ReplaceLane` modify a specific lane in a vector.
    * Operations like `BitMask` create a mask based on the sign of the lanes.
    * Operations like `Convert` perform type conversions between different SIMD vector types.
    * Operations like `Shl`, `ShrS`, `ShrU` are bitwise shift operations.
    * Operations involving `Zero` likely compare against or operate with a zero vector.
    * Operations involving `Sat` (Saturate) perform arithmetic with saturation, preventing overflow/underflow.
    * Operations like `And`, `Or`, `Xor`, `AndNot` are bitwise logical operations.
    * The `execution_tier` argument likely controls which V8 execution engine (e.g., interpreter, compiler) is used for the test.

5. **Consider the Request's Specific Questions:**
    * **Functionality Listing:**  List the tested SIMD operations based on the `WASM_EXEC_TEST` names.
    * **.tq Extension:** Explain that `.tq` indicates Torque source code, and this file is C++, so it's not a Torque file.
    * **JavaScript Relation:**  Illustrate how these SIMD operations conceptually relate to JavaScript's TypedArrays (although direct SIMD support in JavaScript might have evolved). Emphasize that JavaScript doesn't have *direct* SIMD instructions in the same way WASM does, but TypedArrays can be used for similar data manipulation.
    * **Logic Inference:** For simple tests like `I32x4Splat`, provide an example with input and expected output.
    * **Common Errors:**  Think about typical mistakes users make with SIMD, like incorrect lane indexing, type mismatches, or not handling potential overflow/underflow (though saturation can help with the latter).
    * **Overall Function:** Summarize that the code tests the correctness of V8's implementation of various WebAssembly SIMD instructions across different data types.

6. **Structure the Output:** Organize the information logically, starting with a general overview, then addressing the specific points raised in the prompt. Use clear and concise language.

7. **Refine and Review:** Read through the generated explanation to ensure accuracy, clarity, and completeness. For instance, initially, one might directly link WASM SIMD to JavaScript SIMD APIs, but clarifying that JavaScript's approach is different (using TypedArrays) is important for accuracy. Also, ensure the explanation is tailored to the provided code *snippet*, even though the prompt mentions there are other parts.

By following this process, we can systematically analyze the code and generate a comprehensive explanation of its functionality.
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的V8源代码的一部分，它主要的功能是 **测试 V8 引擎中 WebAssembly SIMD (Single Instruction, Multiple Data) 指令的执行是否正确**。

以下是基于代码片段的详细功能归纳：

**1. 测试各种 F64x2 (64位浮点数向量) 的 SIMD 指令:**

* **算术运算:**
    * `F64x2Add`: 测试双精度浮点向量加法。
    * `F64x2Sub`: 测试双精度浮点向量减法。
    * `F64x2Mul`: 测试双精度浮点向量乘法。
    * `F64x2Div`: 测试双精度浮点向量除法。
    * `F64x2Sqrt`: 测试双精度浮点向量平方根。
    * `F64x2Neg`: 测试双精度浮点向量取负。
    * `F64x2Abs`: 测试双精度浮点向量绝对值。
    * `F64x2Min`: 测试双精度浮点向量最小值 (对应 JavaScript 的 `Math.min`)。
    * `F64x2Max`: 测试双精度浮点向量最大值 (对应 JavaScript 的 `Math.max`)。
* **比较运算:**
    * `F64x2Eq`: 测试双精度浮点向量相等比较。
    * `F64x2Ne`: 测试双精度浮点向量不等比较。
    * `F64x2Gt`: 测试双精度浮点向量大于比较。
    * `F64x2Ge`: 测试双精度浮点向量大于等于比较。
    * `F64x2Lt`: 测试双精度浮点向量小于比较。
    * `F64x2Le`: 测试双精度浮点向量小于等于比较。
    * `F64x2EqZero`: 测试双精度浮点向量与零相等比较。
    * `F64x2NeZero`: 测试双精度浮点向量与零不等比较。
    * `F64x2GtZero`: 测试双精度浮点向量与零大于比较。
    * `F64x2GeZero`: 测试双精度浮点向量与零大于等于比较。
    * `F64x2LtZero`: 测试双精度浮点向量与零小于比较。
    * `F64x2LeZero`: 测试双精度浮点向量与零小于等于比较。

**2. 测试各种 I64x2 (64位整数向量) 的 SIMD 指令:**

* `I64x2Mul`: 测试 64 位整数向量乘法 (可能会发生环绕)。

**3. 测试各种 I32x4 (32位整数向量) 的 SIMD 指令:**

* **向量创建和操作:**
    * `I32x4Splat`: 测试将一个 32 位整数广播到向量的所有四个通道。
    * `I32x4ReplaceLane`: 测试替换向量中指定索引的通道值。
* **位掩码操作:**
    * `I32x4BitMask`: 测试基于向量中每个通道的符号位生成位掩码。
* **类型转换:**
    * `I32x4ConvertF32x4`: 测试将 32 位浮点数向量转换为带符号和无符号的 32 位整数向量。
    * `I32x4ConvertI16x8`: 测试将 16 位整数向量扩展转换为带符号和无符号的 32 位整数向量。
    * `I64x2ConvertI32x4`: 测试将 32 位整数向量扩展转换为带符号和无符号的 64 位整数向量。
* **算术运算:**
    * `I32x4Neg`: 测试 32 位整数向量取负 (可能会发生环绕)。
    * `I32x4Abs`: 测试 32 位整数向量绝对值。
    * `I32x4Add`: 测试 32 位整数向量加法 (可能会发生环绕)。
    * `I32x4Sub`: 测试 32 位整数向量减法 (可能会发生环绕)。
    * `I32x4Mul`: 测试 32 位整数向量乘法 (可能会发生环绕)。
    * `I32x4MinS`: 测试带符号 32 位整数向量最小值。
    * `I32x4MaxS`: 测试带符号 32 位整数向量最大值。
    * `I32x4MinU`: 测试无符号 32 位整数向量最小值。
    * `I32x4MaxU`: 测试无符号 32 位整数向量最大值。
* **位运算:**
    * `S128Not`: 测试 128 位向量的按位取反（与 `I32x4Not` 等价）。
    * `S128And`: 测试 128 位向量的按位与（与 `I32x4And` 等价）。
    * `S128Or`: 测试 128 位向量的按位或（与 `I32x4Or` 等价）。
    * `S128Xor`: 测试 128 位向量的按位异或（与 `I32x4Xor` 等价）。
    * `S128AndNot`: 测试 128 位向量的按位与非（与 `I32x4AndNot` 等价）。
* **比较运算:**
    * `I32x4Eq`: 测试 32 位整数向量相等比较。
    * `I32x4Ne`: 测试 32 位整数向量不等比较。
    * `I32x4LtS`: 测试带符号 32 位整数向量小于比较。
    * `I32x4LeS`: 测试带符号 32 位整数向量小于等于比较。
    * `I32x4GtS`: 测试带符号 32 位整数向量大于比较。
    * `I32x4GeS`: 测试带符号 32 位整数向量大于等于比较。
    * `I32x4LtU`: 测试无符号 32 位整数向量小于比较。
    * `I32x4LeU`: 测试无符号 32 位整数向量小于等于比较。
    * `I32x4GtU`: 测试无符号 32 位整数向量大于比较。
    * `I32x4GeU`: 测试无符号 32 位整数向量大于等于比较。
    * `I32x4EqZero`: 测试 32 位整数向量与零相等比较。
    * `I32x4NeZero`: 测试 32 位整数向量与零不等比较。
    * `I32x4GtZero`: 测试带符号 32 位整数向量与零大于比较。
    * `I32x4GeZero`: 测试带符号 32 位整数向量与零大于等于比较。
    * `I32x4LtZero`: 测试带符号 32 位整数向量与零小于比较。
    * `I32x4LeZero`: 测试带符号 32 位整数向量与零小于等于比较。
* **移位运算:**
    * `I32x4Shl`: 测试 32 位整数向量逻辑左移。
    * `I32x4ShrS`: 测试 32 位整数向量算术右移。
    * `I32x4ShrU`: 测试 32 位整数向量逻辑右移。
    * `I32x4ShiftAdd`: 测试移位加法操作。

**4. 测试各种 I16x8 (16位整数向量) 的 SIMD 指令:**

* **向量创建和操作:**
    * `I16x8Splat`: 测试将一个 16 位整数广播到向量的所有八个通道。
    * `I16x8ReplaceLane`: 测试替换向量中指定索引的通道值。
* **位掩码操作:**
    * `I16x8BitMask`: 测试基于向量中每个通道的符号位生成位掩码。
* **类型转换:**
    * `I16x8ConvertI8x16`: 测试将 8 位整数向量扩展转换为带符号和无符号的 16 位整数向量。
    * `I16x8ConvertI32x4`: 测试将 32 位整数向量饱和转换为带符号和无符号的 16 位整数向量。
* **算术运算:**
    * `I16x8Neg`: 测试 16 位整数向量取负 (可能会发生环绕)。
    * `I16x8Abs`: 测试 16 位整数向量绝对值。
    * `I16x8Add`: 测试 16 位整数向量加法 (可能会发生环绕)。
    * `I16x8AddSatS`: 测试带符号 16 位整数向量饱和加法。
    * `I16x8Sub`: 测试 16 位整数向量减法 (可能会发生环绕)。
    * `I16x8SubSatS`: 测试带符号 16 位整数向量饱和减法。
    * `I16x8Mul`: 测试 16 位整数向量乘法 (可能会发生环绕)。
    * `I16x8MinS`: 测试带符号 16 位整数向量最小值。
    * `I16x8MaxS`: 测试带符号 16 位整数向量最大值。
    * `I16x8AddSatU`: 测试无符号 16 位整数向量饱和加法。
    * `I16x8SubSatU`: 测试无符号 16 位整数向量饱和减法。
    * `I16x8MinU`: 测试无符号 16 位整数向量最小值。
    * `I16x8MaxU`: 测试无符号 16 位整数向量最大值。
* **比较运算:**
    * `I16x8Eq`: 测试 16 位整数向量相等比较。
    * `I16x8Ne`: 测试 16 位整数向量不等比较。
    * `I16x8LtS`: 测试带符号 16 位整数向量小于比较。
    * `I16x8LeS`: 测试带符号 16 位整数向量小于等于比较。
    * `I16x8GtS`: 测试带符号 16 位整数向量大于比较。
    * `I16x8GeS`: 测试带符号 16 位整数向量大于等于比较。
    * `I16x8GtU`: 测试无符号 16 位整数向量大于比较。

**5. 测试各种 I8x16 (8位整数向量) 的 SIMD 指令:**

* **向量创建和操作:**
    * `I8x16Splat`: 测试将一个 8 位整数广播到向量的所有十六个通道。
    * `I8x16ReplaceLane`: 测试替换向量中指定索引的通道值。
* **位掩码操作:**
    * `I8x16BitMask`: 测试基于向量中每个通道的符号位生成位掩码。

**关于您的问题的解答:**

* **如果 v8/test/cctest/wasm/test-run-wasm-simd.cc 以 .tq 结尾，那它是个 v8 torque 源代码:** 您的理解是正确的。`.tq` 文件是 V8 的 Torque 语言源代码。然而，`test-run-wasm-simd.cc` 以 `.cc` 结尾，表明它是 **C++ 源代码**，用于编写测试用例。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明:**  WebAssembly SIMD 的目标是提供接近硬件的并行计算能力，这在 JavaScript 中并没有直接对应的原生语法。但是，JavaScript 中可以使用 `TypedArray` 来操作二进制数据，并且一些 JavaScript 引擎 (包括 V8) 可能会在底层利用 SIMD 指令来加速 `TypedArray` 的操作。

   **JavaScript 例子 (概念上的联系，并非直接对应):**

   ```javascript
   // 假设我们有一个包含四个 32 位整数的数组
   const arr1 = new Int32Array([1, 2, 3, 4]);
   const arr2 = new Int32Array([5, 6, 7, 8]);
   const result = new Int32Array(4);

   // 使用循环模拟 I32x4Add 的概念
   for (let i = 0; i < 4; i++) {
       result[i] = arr1[i] + arr2[i];
   }
   console.log(result); // 输出: Int32Array [ 6, 8, 10, 12 ]
   ```

   在 WebAssembly 中，`I32x4Add` 指令可以在一个 CPU 指令中完成四个整数的加法。JavaScript 需要循环遍历数组元素来达到相同的效果。虽然 JavaScript 本身没有 SIMD 指令，但当 JavaScript 引擎执行类似 `TypedArray` 的操作时，可能会在底层使用 SIMD 指令进行优化。

* **如果有代码逻辑推理，请给出假设输入与输出:**

   **例子 (I32x4Splat):**

   **假设输入:** `x = 10`

   **代码逻辑:**  `WASM_GLOBAL_SET(0, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param1)))` 这段代码会将输入参数 `x` (通过 `WASM_LOCAL_GET(param1)`) 广播到 `I32x4` 向量的所有四个通道，并将结果存储到全局变量 `g` 中。

   **预期输出:** 全局变量 `g` 的值为一个 `I32x4` 向量，其四个通道的值都为 `10`。

   ```
   g[0] = 10
   g[1] = 10
   g[2] = 10
   g[3] = 10
   ```

   **例子 (I32x4Add):**

   **假设输入:** 两个 `I32x4` 向量，分别包含 `[1, 2, 3, 4]` 和 `[5, 6, 7, 8]`。

   **代码逻辑:** `RunI32x4BinOpTest(execution_tier, kExprI32x4Add, base::AddWithWraparound);` 这段代码会测试 `I32x4Add` 指令，它将两个输入向量的对应通道相加。

   **预期输出:**  得到一个新的 `I32x4` 向量，其通道值为 `[1+5, 2+6, 3+7, 4+8]`，即 `[6, 8, 10, 12]`。

* **如果涉及用户常见的编程错误，请举例说明:**

   **1. 错误的通道索引:**  在 `I32x4ReplaceLane` 等操作中，如果用户指定了超出向量通道数的索引 (例如，对 `I32x4` 使用索引 4 或更大)，会导致错误。

   **WebAssembly 代码示例 (可能导致错误):**
   ```wasm
   local.get 0 ;; 获取一个 i32x4 向量
   i32.const 5  ;; 尝试替换索引为 5 的通道 (无效)
   local.get 1  ;; 获取要替换的值
   i32x4.replace_lane 5
   ```

   **2. 类型不匹配:**  尝试对不同类型的 SIMD 向量进行操作，例如将 `F32x4` 向量直接与 `I32x4` 向量相加，会导致类型错误。

   **WebAssembly 代码示例 (可能导致错误):**
   ```wasm
   local.get 0 ;; 获取一个 f32x4 向量
   local.get 1 ;; 获取一个 i32x4 向量
   f32x4.add  ;; 尝试将 f32x4 和 i32x4 相加 (无效)
   ```

   **3. 未处理溢出/下溢:** 对于没有饱和运算的整数 SIMD 指令 (如 `I32x4Add`，默认会发生环绕)，如果计算结果超出数据类型的表示范围，可能会得到意想不到的结果。用户需要根据需求选择合适的运算 (例如，使用饱和运算 `I16x8AddSatS`) 或进行额外的溢出检查。

* **这是第2部分，共9部分，请归纳一下它的功能:**

   这部分代码主要专注于 **测试 V8 引擎中对于浮点数 (F64x2) 和整数 (I64x2, I32x4, I16x8, I8x16) 类型的向量 SIMD 指令的基本算术、比较、位运算、类型转换以及向量创建和操作功能的正确性**。它涵盖了多种常见的 SIMD 操作，并通过不同的测试用例来验证这些指令在 V8 中的实现是否符合 WebAssembly 规范。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共9部分，请归纳一下它的功能

"""
areOpTest(execution_tier, kExprF64x2Eq, Equal);
}

WASM_EXEC_TEST(F64x2Ne) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Ne, NotEqual);
}

WASM_EXEC_TEST(F64x2Gt) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Gt, Greater);
}

WASM_EXEC_TEST(F64x2Ge) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Ge, GreaterEqual);
}

WASM_EXEC_TEST(F64x2Lt) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Lt, Less);
}

WASM_EXEC_TEST(F64x2Le) {
  RunF64x2CompareOpTest(execution_tier, kExprF64x2Le, LessEqual);
}

WASM_EXEC_TEST(F64x2EqZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Eq,
                                                kExprF64x2Splat, Equal);
}

WASM_EXEC_TEST(F64x2NeZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Ne,
                                                kExprF64x2Splat, NotEqual);
}

WASM_EXEC_TEST(F64x2GtZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Gt,
                                                kExprF64x2Splat, Greater);
}

WASM_EXEC_TEST(F64x2GeZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Ge,
                                                kExprF64x2Splat, GreaterEqual);
}

WASM_EXEC_TEST(F64x2LtZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Lt,
                                                kExprF64x2Splat, Less);
}

WASM_EXEC_TEST(F64x2LeZero) {
  RunF128CompareOpConstImmTest<double, int64_t>(execution_tier, kExprF64x2Le,
                                                kExprF64x2Splat, LessEqual);
}

WASM_EXEC_TEST(F64x2Min) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Min, JSMin);
}

WASM_EXEC_TEST(F64x2Max) {
  RunF64x2BinOpTest(execution_tier, kExprF64x2Max, JSMax);
}

WASM_EXEC_TEST(I64x2Mul) {
  RunI64x2BinOpTest(execution_tier, kExprI64x2Mul, base::MulWithWraparound);
}

WASM_EXEC_TEST(I32x4Splat) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int32_t expected = x;
    for (int i = 0; i < 4; i++) {
      int32_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I32x4ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_I32V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I32V(0))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_I32V(1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_I32V(2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I32x4_REPLACE_LANE(
                                  3, WASM_LOCAL_GET(temp1), WASM_I32V(3))),
           WASM_ONE});

  r.Call();
  for (int32_t i = 0; i < 4; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

WASM_EXEC_TEST(I16x8Splat) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int16_t expected = x;
    for (int i = 0; i < 8; i++) {
      int16_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }

  // Test values that do not fit in an int16.
  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int16_t expected = truncate_to_int16(x);
    for (int i = 0; i < 8; i++) {
      int16_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I16x8ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_I32V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I32V(0))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_I32V(1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_I32V(2))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     3, WASM_LOCAL_GET(temp1), WASM_I32V(3))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     4, WASM_LOCAL_GET(temp1), WASM_I32V(4))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     5, WASM_LOCAL_GET(temp1), WASM_I32V(5))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_REPLACE_LANE(
                                     6, WASM_LOCAL_GET(temp1), WASM_I32V(6))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I16x8_REPLACE_LANE(
                                  7, WASM_LOCAL_GET(temp1), WASM_I32V(7))),
           WASM_ONE});

  r.Call();
  for (int16_t i = 0; i < 8; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

WASM_EXEC_TEST(I8x16BitMask) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I8x16_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I32V(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I8x16_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(value1), WASM_I32V(-1))),
       WASM_SIMD_UNOP(kExprI8x16BitMask, WASM_LOCAL_GET(value1))});

  FOR_INT8_INPUTS(x) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive), lane 1 is always -1.
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0xFFFE : 0x0002;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I16x8BitMask) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I16x8_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I32V(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I16x8_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(value1), WASM_I32V(-1))),
       WASM_SIMD_UNOP(kExprI16x8BitMask, WASM_LOCAL_GET(value1))});

  FOR_INT16_INPUTS(x) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive), lane 1 is always -1.
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0xFE : 2;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I32x4BitMask) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I32x4_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I32V(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I32x4_REPLACE_LANE(
                                  1, WASM_LOCAL_GET(value1), WASM_I32V(-1))),
       WASM_SIMD_UNOP(kExprI32x4BitMask, WASM_LOCAL_GET(value1))});

  FOR_INT32_INPUTS(x) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive), lane 1 is always -1.
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0xE : 2;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I64x2BitMask) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  uint8_t value1 = r.AllocateLocal(kWasmS128);

  r.Build(
      {WASM_LOCAL_SET(value1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(0))),
       WASM_LOCAL_SET(value1, WASM_SIMD_I64x2_REPLACE_LANE(
                                  0, WASM_LOCAL_GET(value1), WASM_I64V_1(0))),
       WASM_SIMD_UNOP(kExprI64x2BitMask, WASM_LOCAL_GET(value1))});

  for (int64_t x : compiler::ValueHelper::GetVector<int64_t>()) {
    int32_t actual = r.Call(x);
    // Lane 0 is always 0 (positive).
    int32_t expected = std::signbit(static_cast<double>(x)) ? 0x2 : 0x0;
    CHECK_EQ(actual, expected);
  }
}

WASM_EXEC_TEST(I8x16Splat) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Set up a global to hold output vector.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  uint8_t param1 = 0;
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(param1))),
           WASM_ONE});

  FOR_INT8_INPUTS(x) {
    r.Call(x);
    int8_t expected = x;
    for (int i = 0; i < 16; i++) {
      int8_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }

  // Test values that do not fit in an int16.
  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int8_t expected = truncate_to_int8(x);
    for (int i = 0; i < 16; i++) {
      int8_t actual = LANE(g, i);
      CHECK_EQ(actual, expected);
    }
  }
}

WASM_EXEC_TEST(I8x16ReplaceLane) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up a global to hold input/output vector.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  // Build function to replace each lane with its index.
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_I32V(-1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     0, WASM_LOCAL_GET(temp1), WASM_I32V(0))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     1, WASM_LOCAL_GET(temp1), WASM_I32V(1))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     2, WASM_LOCAL_GET(temp1), WASM_I32V(2))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     3, WASM_LOCAL_GET(temp1), WASM_I32V(3))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     4, WASM_LOCAL_GET(temp1), WASM_I32V(4))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     5, WASM_LOCAL_GET(temp1), WASM_I32V(5))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     6, WASM_LOCAL_GET(temp1), WASM_I32V(6))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     7, WASM_LOCAL_GET(temp1), WASM_I32V(7))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     8, WASM_LOCAL_GET(temp1), WASM_I32V(8))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     9, WASM_LOCAL_GET(temp1), WASM_I32V(9))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     10, WASM_LOCAL_GET(temp1), WASM_I32V(10))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     11, WASM_LOCAL_GET(temp1), WASM_I32V(11))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     12, WASM_LOCAL_GET(temp1), WASM_I32V(12))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     13, WASM_LOCAL_GET(temp1), WASM_I32V(13))),
           WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_REPLACE_LANE(
                                     14, WASM_LOCAL_GET(temp1), WASM_I32V(14))),
           WASM_GLOBAL_SET(0, WASM_SIMD_I8x16_REPLACE_LANE(
                                  15, WASM_LOCAL_GET(temp1), WASM_I32V(15))),
           WASM_ONE});

  r.Call();
  for (int8_t i = 0; i < 16; i++) {
    CHECK_EQ(i, LANE(g, i));
  }
}

// Use doubles to ensure exact conversion.
int32_t ConvertToInt(double val, bool unsigned_integer) {
  if (std::isnan(val)) return 0;
  if (unsigned_integer) {
    if (val < 0) return 0;
    if (val > kMaxUInt32) return kMaxUInt32;
    return static_cast<uint32_t>(val);
  } else {
    if (val < kMinInt) return kMinInt;
    if (val > kMaxInt) return kMaxInt;
    return static_cast<int>(val);
  }
}

// Tests both signed and unsigned conversion.
WASM_EXEC_TEST(I32x4ConvertF32x4) {
  WasmRunner<int32_t, float> r(execution_tier);
  // Create two output vectors to hold signed and unsigned results.
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI32x4SConvertF32x4,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI32x4UConvertF32x4,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    r.Call(x);
    int32_t expected_signed = ConvertToInt(x, false);
    int32_t expected_unsigned = ConvertToInt(x, true);
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

// Tests both signed and unsigned conversion from I16x8 (unpacking).
WASM_EXEC_TEST(I32x4ConvertI16x8) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create four output vectors to hold signed and unsigned results.
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g2 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g3 = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI32x4SConvertI16x8High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI32x4SConvertI16x8Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(2, WASM_SIMD_UNOP(kExprI32x4UConvertI16x8High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(3, WASM_SIMD_UNOP(kExprI32x4UConvertI16x8Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int32_t expected_signed = static_cast<int32_t>(x);
    int32_t expected_unsigned = static_cast<int32_t>(static_cast<uint16_t>(x));
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_signed, LANE(g1, i));
      CHECK_EQ(expected_unsigned, LANE(g2, i));
      CHECK_EQ(expected_unsigned, LANE(g3, i));
    }
  }
}

// Tests both signed and unsigned conversion from I32x4 (unpacking).
WASM_EXEC_TEST(I64x2ConvertI32x4) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create four output vectors to hold signed and unsigned results.
  int64_t* g0 = r.builder().AddGlobal<int64_t>(kWasmS128);
  int64_t* g1 = r.builder().AddGlobal<int64_t>(kWasmS128);
  uint64_t* g2 = r.builder().AddGlobal<uint64_t>(kWasmS128);
  uint64_t* g3 = r.builder().AddGlobal<uint64_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI64x2SConvertI32x4High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI64x2SConvertI32x4Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(2, WASM_SIMD_UNOP(kExprI64x2UConvertI32x4High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(3, WASM_SIMD_UNOP(kExprI64x2UConvertI32x4Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int64_t expected_signed = static_cast<int64_t>(x);
    uint64_t expected_unsigned =
        static_cast<uint64_t>(static_cast<uint32_t>(x));
    for (int i = 0; i < 2; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_signed, LANE(g1, i));
      CHECK_EQ(expected_unsigned, LANE(g2, i));
      CHECK_EQ(expected_unsigned, LANE(g3, i));
    }
  }
}

WASM_EXEC_TEST(I32x4Neg) {
  RunI32x4UnOpTest(execution_tier, kExprI32x4Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I32x4Abs) {
  RunI32x4UnOpTest(execution_tier, kExprI32x4Abs, std::abs);
}

WASM_EXEC_TEST(S128Not) {
  RunI32x4UnOpTest(execution_tier, kExprS128Not, [](int32_t x) { return ~x; });
}

template <typename Narrow, typename Wide>
void RunExtAddPairwiseTest(TestExecutionTier execution_tier,
                           WasmOpcode ext_add_pairwise, WasmOpcode splat,
                           Shuffle interleaving_shuffle) {
  constexpr int num_lanes = kSimd128Size / sizeof(Wide);
  WasmRunner<int32_t, Narrow, Narrow> r(execution_tier);
  Wide* g = r.builder().template AddGlobal<Wide>(kWasmS128);

  r.Build({WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, interleaving_shuffle,
                                      WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(0)),
                                      WASM_SIMD_UNOP(splat, WASM_LOCAL_GET(1))),
           WASM_SIMD_OP(ext_add_pairwise), kExprGlobalSet, 0, WASM_ONE});

  auto v = compiler::ValueHelper::GetVector<Narrow>();
  // Iterate vector from both ends to try and splat two different values.
  for (auto i = v.begin(), j = v.end() - 1; i < v.end(); i++, j--) {
    r.Call(*i, *j);
    Wide expected = AddLong<Wide>(*i, *j);
    for (int l = 0; l < num_lanes; l++) {
      CHECK_EQ(expected, LANE(g, l));
    }
  }
}

// interleave even lanes from one input and odd lanes from another.
constexpr Shuffle interleave_16x8_shuffle = {0, 1, 18, 19, 4,  5,  22, 23,
                                             8, 9, 26, 27, 12, 13, 30, 31};
constexpr Shuffle interleave_8x16_shuffle = {0, 17, 2,  19, 4,  21, 6,  23,
                                             8, 25, 10, 27, 12, 29, 14, 31};

WASM_EXEC_TEST(I32x4ExtAddPairwiseI16x8S) {
  RunExtAddPairwiseTest<int16_t, int32_t>(
      execution_tier, kExprI32x4ExtAddPairwiseI16x8S, kExprI16x8Splat,
      interleave_16x8_shuffle);
}

WASM_EXEC_TEST(I32x4ExtAddPairwiseI16x8U) {
  RunExtAddPairwiseTest<uint16_t, uint32_t>(
      execution_tier, kExprI32x4ExtAddPairwiseI16x8U, kExprI16x8Splat,
      interleave_16x8_shuffle);
}

WASM_EXEC_TEST(I16x8ExtAddPairwiseI8x16S) {
  RunExtAddPairwiseTest<int8_t, int16_t>(
      execution_tier, kExprI16x8ExtAddPairwiseI8x16S, kExprI8x16Splat,
      interleave_8x16_shuffle);
}

WASM_EXEC_TEST(I16x8ExtAddPairwiseI8x16U) {
  RunExtAddPairwiseTest<uint8_t, uint16_t>(
      execution_tier, kExprI16x8ExtAddPairwiseI8x16U, kExprI8x16Splat,
      interleave_8x16_shuffle);
}

WASM_EXEC_TEST(I32x4Add) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I32x4Sub) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I32x4Mul) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Mul, base::MulWithWraparound);
}

WASM_EXEC_TEST(I32x4MinS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MinS, Minimum);
}

WASM_EXEC_TEST(I32x4MaxS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MaxS, Maximum);
}

WASM_EXEC_TEST(I32x4MinU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MinU, UnsignedMinimum);
}
WASM_EXEC_TEST(I32x4MaxU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4MaxU,

                    UnsignedMaximum);
}

WASM_EXEC_TEST(S128And) {
  RunI32x4BinOpTest(execution_tier, kExprS128And,
                    [](int32_t x, int32_t y) { return x & y; });
}

enum ConstSide { kConstLeft, kConstRight };

template <typename ScalarType>
using BinOp = ScalarType (*)(ScalarType, ScalarType);
template <typename ScalarType>
void RunS128ConstBinOpTest(TestExecutionTier execution_tier,
                           ConstSide const_side, WasmOpcode binop_opcode,
                           WasmOpcode splat_opcode,
                           BinOp<ScalarType> expected_op) {
  for (ScalarType x : compiler::ValueHelper::GetVector<ScalarType>()) {
    WasmRunner<int32_t, ScalarType> r(execution_tier);
    // Global to hold output.
    ScalarType* g = r.builder().template AddGlobal<ScalarType>(kWasmS128);
    // Build a function to splat one argument into a local,
    // and execute the op with a const as the second argument
    uint8_t value = 0;
    uint8_t temp = r.AllocateLocal(kWasmS128);
    uint8_t const_buffer[16];
    for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
      WriteLittleEndianValue<ScalarType>(
          reinterpret_cast<ScalarType*>(&const_buffer[0]) + i, x);
    }
    switch (const_side) {
      case kConstLeft:
        r.Build({WASM_LOCAL_SET(
                     temp, WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(value))),
                 WASM_GLOBAL_SET(
                     0, WASM_SIMD_BINOP(binop_opcode,
                                        WASM_SIMD_CONSTANT(const_buffer),
                                        WASM_LOCAL_GET(temp))),
                 WASM_ONE});
        break;
      case kConstRight:
        r.Build({WASM_LOCAL_SET(
                     temp, WASM_SIMD_OPN(splat_opcode, WASM_LOCAL_GET(value))),
                 WASM_GLOBAL_SET(
                     0, WASM_SIMD_BINOP(binop_opcode, WASM_LOCAL_GET(temp),
                                        WASM_SIMD_CONSTANT(const_buffer))),
                 WASM_ONE});
        break;
    }
    for (ScalarType y : compiler::ValueHelper::GetVector<ScalarType>()) {
      r.Call(y);
      ScalarType expected =
          (const_side == kConstLeft) ? expected_op(x, y) : expected_op(y, x);
      for (size_t i = 0; i < kSimd128Size / sizeof(ScalarType); i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

WASM_EXEC_TEST(S128AndImm) {
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstLeft, kExprS128And,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & y; });
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstRight, kExprS128And,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & y; });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstLeft, kExprS128And, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & y); });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstRight, kExprS128And, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & y); });
}

WASM_EXEC_TEST(S128Or) {
  RunI32x4BinOpTest(execution_tier, kExprS128Or,
                    [](int32_t x, int32_t y) { return x | y; });
}

WASM_EXEC_TEST(S128Xor) {
  RunI32x4BinOpTest(execution_tier, kExprS128Xor,
                    [](int32_t x, int32_t y) { return x ^ y; });
}

// Bitwise operation, doesn't really matter what simd type we test it with.
WASM_EXEC_TEST(S128AndNot) {
  RunI32x4BinOpTest(execution_tier, kExprS128AndNot,
                    [](int32_t x, int32_t y) { return x & ~y; });
}

WASM_EXEC_TEST(S128AndNotImm) {
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstLeft, kExprS128AndNot,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & ~y; });
  RunS128ConstBinOpTest<int32_t>(execution_tier, kConstRight, kExprS128AndNot,
                                 kExprI32x4Splat,
                                 [](int32_t x, int32_t y) { return x & ~y; });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstLeft, kExprS128AndNot, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & ~y); });
  RunS128ConstBinOpTest<int16_t>(
      execution_tier, kConstRight, kExprS128AndNot, kExprI16x8Splat,
      [](int16_t x, int16_t y) { return static_cast<int16_t>(x & ~y); });
}

WASM_EXEC_TEST(I32x4Eq) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Eq, Equal);
}

WASM_EXEC_TEST(I32x4Ne) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4Ne, NotEqual);
}

WASM_EXEC_TEST(I32x4LtS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LtS, Less);
}

WASM_EXEC_TEST(I32x4LeS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LeS, LessEqual);
}

WASM_EXEC_TEST(I32x4GtS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GtS, Greater);
}

WASM_EXEC_TEST(I32x4GeS) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GeS, GreaterEqual);
}

WASM_EXEC_TEST(I32x4LtU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LtU, UnsignedLess);
}

WASM_EXEC_TEST(I32x4LeU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4LeU, UnsignedLessEqual);
}

WASM_EXEC_TEST(I32x4GtU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I32x4GeU) {
  RunI32x4BinOpTest(execution_tier, kExprI32x4GeU, UnsignedGreaterEqual);
}

WASM_EXEC_TEST(I32x4EqZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4Eq,
                                     kExprI32x4Splat, Equal);
}

WASM_EXEC_TEST(I32x4NeZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4Ne,
                                     kExprI32x4Splat, NotEqual);
}

WASM_EXEC_TEST(I32x4GtZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4GtS,
                                     kExprI32x4Splat, Greater);
}

WASM_EXEC_TEST(I32x4GeZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4GeS,
                                     kExprI32x4Splat, GreaterEqual);
}

WASM_EXEC_TEST(I32x4LtZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4LtS,
                                     kExprI32x4Splat, Less);
}

WASM_EXEC_TEST(I32x4LeZero) {
  RunICompareOpConstImmTest<int32_t>(execution_tier, kExprI32x4LeS,
                                     kExprI32x4Splat, LessEqual);
}

WASM_EXEC_TEST(I32x4Shl) {
  RunI32x4ShiftOpTest(execution_tier, kExprI32x4Shl, LogicalShiftLeft);
}

WASM_EXEC_TEST(I32x4ShrS) {
  RunI32x4ShiftOpTest(execution_tier, kExprI32x4ShrS, ArithmeticShiftRight);
}

WASM_EXEC_TEST(I32x4ShrU) {
  RunI32x4ShiftOpTest(execution_tier, kExprI32x4ShrU, LogicalShiftRight);
}

WASM_EXEC_TEST(I32x4ShiftAdd) {
  for (int imm = 0; imm <= 32; imm++) {
    RunShiftAddTestSequence<int32_t>(execution_tier, kExprI32x4ShrU,
                                     kExprI32x4Add, kExprI32x4Splat, imm,
                                     LogicalShiftRight);
    RunShiftAddTestSequence<int32_t>(execution_tier, kExprI32x4ShrS,
                                     kExprI32x4Add, kExprI32x4Splat, imm,
                                     ArithmeticShiftRight);
  }
}

// Tests both signed and unsigned conversion from I8x16 (unpacking).
WASM_EXEC_TEST(I16x8ConvertI8x16) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create four output vectors to hold signed and unsigned results.
  int16_t* g0 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g1 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g2 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g3 = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(kExprI16x8SConvertI8x16High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_UNOP(kExprI16x8SConvertI8x16Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(2, WASM_SIMD_UNOP(kExprI16x8UConvertI8x16High,
                                             WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(3, WASM_SIMD_UNOP(kExprI16x8UConvertI8x16Low,
                                             WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT8_INPUTS(x) {
    r.Call(x);
    int16_t expected_signed = static_cast<int16_t>(x);
    int16_t expected_unsigned = static_cast<int16_t>(static_cast<uint8_t>(x));
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_signed, LANE(g1, i));
      CHECK_EQ(expected_unsigned, LANE(g2, i));
      CHECK_EQ(expected_unsigned, LANE(g3, i));
    }
  }
}

// Tests both signed and unsigned conversion from I32x4 (packing).
WASM_EXEC_TEST(I16x8ConvertI32x4) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Create output vectors to hold signed and unsigned results.
  int16_t* g0 = r.builder().AddGlobal<int16_t>(kWasmS128);
  int16_t* g1 = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform conversions, and write the results.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(kExprI16x8SConvertI32x4,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_GLOBAL_SET(1, WASM_SIMD_BINOP(kExprI16x8UConvertI32x4,
                                              WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int16_t expected_signed = base::saturated_cast<int16_t>(x);
    int16_t expected_unsigned = base::saturated_cast<uint16_t>(x);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_signed, LANE(g0, i));
      CHECK_EQ(expected_unsigned, LANE(g1, i));
    }
  }
}

WASM_EXEC_TEST(I16x8Neg) {
  RunI16x8UnOpTest(execution_tier, kExprI16x8Neg, base::NegateWithWraparound);
}

WASM_EXEC_TEST(I16x8Abs) {
  RunI16x8UnOpTest(execution_tier, kExprI16x8Abs, Abs);
}

WASM_EXEC_TEST(I16x8Add) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Add, base::AddWithWraparound);
}

WASM_EXEC_TEST(I16x8AddSatS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8AddSatS, SaturateAdd<int16_t>);
}

WASM_EXEC_TEST(I16x8Sub) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Sub, base::SubWithWraparound);
}

WASM_EXEC_TEST(I16x8SubSatS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8SubSatS, SaturateSub<int16_t>);
}

WASM_EXEC_TEST(I16x8Mul) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Mul, base::MulWithWraparound);
}

WASM_EXEC_TEST(I16x8MinS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MinS, Minimum);
}

WASM_EXEC_TEST(I16x8MaxS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MaxS, Maximum);
}

WASM_EXEC_TEST(I16x8AddSatU) {
  RunI16x8BinOpTest<uint16_t>(execution_tier, kExprI16x8AddSatU,
                              SaturateAdd<uint16_t>);
}

WASM_EXEC_TEST(I16x8SubSatU) {
  RunI16x8BinOpTest<uint16_t>(execution_tier, kExprI16x8SubSatU,
                              SaturateSub<uint16_t>);
}

WASM_EXEC_TEST(I16x8MinU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MinU, UnsignedMinimum);
}

WASM_EXEC_TEST(I16x8MaxU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8MaxU, UnsignedMaximum);
}

WASM_EXEC_TEST(I16x8Eq) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Eq, Equal);
}

WASM_EXEC_TEST(I16x8Ne) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8Ne, NotEqual);
}

WASM_EXEC_TEST(I16x8LtS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LtS, Less);
}

WASM_EXEC_TEST(I16x8LeS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8LeS, LessEqual);
}

WASM_EXEC_TEST(I16x8GtS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GtS, Greater);
}

WASM_EXEC_TEST(I16x8GeS) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GeS, GreaterEqual);
}

WASM_EXEC_TEST(I16x8GtU) {
  RunI16x8BinOpTest(execution_tier, kExprI16x8GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I16x
"""


```