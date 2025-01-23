Response:
Let's break down the thought process for analyzing the given C++ code snippet.

1. **Identify the Core Purpose:** The file name `test-run-machops.cc` and the presence of `TEST` macros immediately suggest that this is a testing file. The "machops" part hints at testing low-level machine operations or instructions.

2. **Recognize the Testing Framework:** The `TEST` macros are part of V8's testing framework. The structure `BufferedRawMachineAssemblerTester<...>` is a key component for testing machine code generation. It allows constructing small code snippets and executing them.

3. **Analyze Individual Test Cases:** The code is organized into multiple `TEST` blocks. Each `TEST` block focuses on testing a specific machine operation. The name of the test usually clearly indicates the operation being tested (e.g., `RunFloat64Atan`, `RunFloat64Cos`, `RunCallCFunction0`).

4. **Understand the Test Setup:** Inside each `TEST` block:
    * A `BufferedRawMachineAssemblerTester` is instantiated. The template parameters specify the return type and argument types of the function being tested.
    * The `m.Return(...)` line defines the core operation being tested. It uses methods like `m.Float64Atan`, `m.Float64Cos`, `m.CallCFunction` which correspond to the machine operations.
    * `m.Parameter(0)`, `m.Parameter(1)`, etc., access the input parameters of the generated function.
    * `CHECK_*` macros are used for assertions. They compare the result of the generated code (`m.Call(...)`) with an expected value. The expected value often comes from the `base::ieee754` namespace (for standard math functions) or a direct computation.
    * `FOR_FLOAT64_INPUTS(i)` and `FOR_INT32_INPUTS(i)` are macros (likely defined elsewhere in the V8 codebase) that iterate through a range of representative input values for testing.

5. **Categorize the Tested Operations:**  As you go through the tests, you'll notice patterns:
    * **Floating-point arithmetic:**  `Atan`, `Atanh`, `Atan2`, `Cos`, `Cosh`, `Exp`, `Expm1`, `Log`, `Log1p`, `Log2`, `Log10`, `Cbrt`, `Sin`, `Sinh`, `Tan`, `Tanh`.
    * **Rounding operations:** `RoundDown`, `RoundUp`, `RoundTiesEven`, `RoundTruncate`, `RoundTiesAway`.
    * **Calling C functions:** `CallCFunction0`, `CallCFunction1`, `CallCFunction2`, etc., testing the ability to call external C functions with different numbers of arguments and data types.
    * **Type conversions:** `ChangeFloat64ToInt64`, `ChangeInt64ToFloat64`, `BitcastInt64ToFloat64`.

6. **Address Specific Instructions:**  The prompt asks for specific information:
    * **`.tq` extension:**  The code snippet is `.cc`, not `.tq`, so it's C++, not Torque.
    * **Relationship to JavaScript:** The tested operations directly correspond to JavaScript's built-in Math functions (e.g., `Math.atan()`, `Math.cos()`, `Math.log()`). Calling C functions is also relevant as JavaScript engines often rely on native code for performance-critical operations.
    * **JavaScript examples:** Provide examples of how the tested operations are used in JavaScript.
    * **Code logic推理 (Logic Inference):**  For simple operations, show input/output examples based on standard mathematical definitions. For more complex cases (like `RunFloat64RoundDown2`), explain the underlying logic.
    * **Common programming errors:** Relate the tested operations to potential pitfalls in JavaScript (e.g., incorrect assumptions about floating-point precision, misuse of rounding functions).

7. **Handle Conditional Compilation:** Pay attention to `#if` directives (like `#if !USE_SIMULATOR` and `#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE`). Explain that some tests might be platform-specific or depend on build configurations.

8. **Synthesize the Summary:** Based on the analysis, summarize the overall purpose of the file. Highlight that it's a C++ file for testing low-level machine operations used in V8's compiler, focusing on floating-point arithmetic, rounding, C function calls, and type conversions.

9. **Address the "Part 7 of 8" Instruction:** Acknowledge this information and reiterate that the current snippet is focused on the categories identified above. The complete functionality of the file would be revealed by analyzing all eight parts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This looks like a standard unit testing file."  -> **Refinement:** "It's specifically testing *machine operations*, so it's lower-level than typical application unit tests."
* **Initial thought:** "Just list the tested functions." -> **Refinement:** "Explain *why* these functions are being tested (relationship to JavaScript, underlying machine code)."
* **Concern:** "Some of the test logic is dense (e.g., `RunFloat64RoundDown2`)." -> **Action:** "Break down the logic step-by-step and explain the intent behind the test."
* **Missing detail:** "Need to explain the role of `BufferedRawMachineAssemblerTester`." -> **Action:** "Add a brief explanation of its purpose."

By following this structured approach, combining code analysis with an understanding of testing principles and the V8 architecture, it's possible to generate a comprehensive and accurate description of the given code snippet.
好的，这是对`v8/test/cctest/compiler/test-run-machops.cc` 第 7 部分代码的功能归纳：

**文件功能总览（基于前几部分和当前部分）：**

`v8/test/cctest/compiler/test-run-machops.cc` 是 V8 引擎中用于测试**机器操作 (machine operations)** 实现的 C++ 测试文件。它使用 V8 内部的测试框架，通过 `BufferedRawMachineAssemblerTester` 或 `RawMachineAssemblerTester` 来构建一小段机器码片段，然后执行并验证其结果。  这些测试旨在确保 V8 编译器生成的机器码对于各种算术、逻辑、位操作以及函数调用等操作是正确的。

**第 7 部分代码功能详解：**

这部分代码主要集中在测试以下几类 **`float64` (double)** 类型的数学运算以及调用 C 函数的功能：

1. **`float64`超越函数测试:**
   - `RunFloat64Atan`: 测试 `atan` (反正切) 操作。
   - `RunFloat64Atanh`: 测试 `atanh` (反双曲正切) 操作。
   - `RunFloat64Atan2`: 测试 `atan2` (四象限反正切) 操作。
   - `RunFloat64Cos`: 测试 `cos` (余弦) 操作。
   - `RunFloat64Cosh`: 测试 `cosh` (双曲余弦) 操作。
   - `RunFloat64Exp`: 测试 `exp` (指数) 操作。
   - `RunFloat64Expm1`: 测试 `expm1` (指数减 1) 操作。
   - `RunFloat64Log`: 测试 `log` (自然对数) 操作。
   - `RunFloat64Log1p`: 测试 `log1p` (自然对数加 1) 操作。
   - `RunFloat64Log2`: 测试 `log2` (以 2 为底的对数) 操作。
   - `RunFloat64Log10`: 测试 `log10` (以 10 为底的对数) 操作。
   - `RunFloat64Cbrt`: 测试 `cbrt` (立方根) 操作。
   - `RunFloat64Sin`: 测试 `sin` (正弦) 操作。
   - `RunFloat64Sinh`: 测试 `sinh` (双曲正弦) 操作。
   - `RunFloat64Tan`: 测试 `tan` (正切) 操作。
   - `RunFloat64Tanh`: 测试 `tanh` (双曲正切) 操作。

   对于每个函数，测试用例会覆盖一些特殊输入值（例如 NaN, 正负无穷, 正负零）以及一系列通过 `FOR_FLOAT64_INPUTS` 宏生成的普通浮点数输入。测试会比较 V8 生成的机器码的执行结果与标准库函数（如 `base::ieee754::atan()` 或 `COS_IMPL()`）的结果，使用 `CHECK_DOUBLE_EQ` 来验证精度。

2. **`float32` 和 `float64` 的舍入操作测试:**
   - `RunFloat32RoundDown`/`RunFloat64RoundDown1`: 测试向下取整 (`floor`) 操作。
   - `RunFloat64RoundDown2`:  测试一种特殊的向下取整的实现方式，并使用 `kValues` 数组中的特定值进行测试，实际上它测试的是向上取整 (`ceil`) 的另一种实现方式。
   - `RunFloat32RoundUp`/`RunFloat64RoundUp`: 测试向上取整 (`ceil`) 操作。
   - `RunFloat32RoundTiesEven`/`RunFloat64RoundTiesEven`: 测试四舍五入到最接近的偶数 (`nearbyint`) 操作。
   - `RunFloat32RoundTruncate`/`RunFloat64RoundTruncate`: 测试截断取整 (`trunc`) 操作。
   - `RunFloat64RoundTiesAway`: 测试远离零的四舍五入 (`round`) 操作。

   这些测试会检查不同舍入模式下，机器码的实现是否符合预期。

3. **调用 C 函数测试 (通过 `CallCFunction`)：**
   - `RunCallCFunction0`: 测试调用无参数的 C 函数。
   - `RunCallCFunction1`: 测试调用带一个 `int32_t` 参数的 C 函数。
   - `RunCallCFunction2`: 测试调用带两个 `int32_t` 参数的 C 函数。
   - `RunCallCFunction8`: 测试调用带八个 `uint32_t` 参数的 C 函数。
   - `RunCallCFunction9`: 测试调用带九个 `uint32_t` 参数的 C 函数。

   这些测试验证了 V8 能够正确地生成调用外部 C 函数的机器码，并正确传递参数和接收返回值。这部分代码通常会被条件编译 `!USE_SIMULATOR` 包裹，意味着这些测试可能需要在非模拟器环境下运行。

4. **调用带 `double` 类型参数和返回值的 C 函数测试 (条件编译 `V8_ENABLE_FP_PARAMS_IN_C_LINKAGE`)：**
   - `RunCallDoubleCFunction0` 到 `RunCallDoubleCFunction10` 以及 `RunCallIntCFunction10`: 测试了调用具有不同数量和类型的参数（包括 `double` 和 `int64_t`）以及 `double` 返回值的 C 函数。这些测试验证了 V8 在处理浮点参数和返回值时的正确性，尤其是在 C 函数调用边界。  这部分代码会被条件编译 `V8_ENABLE_FP_PARAMS_IN_C_LINKAGE` 包裹，表示这个特性可能不是在所有平台上都启用。

5. **类型转换测试 (条件编译 `V8_TARGET_ARCH_64_BIT`)：**
   - `RunChangeFloat64ToInt64`: 测试将 `float64` 转换为 `int64_t` 的操作。
   - `RunChangeInt64ToFloat64`: 测试将 `int64_t` 转换为 `float64` 的操作。
   - `RunBitcastInt64ToFloat64`: 测试将 `int64_t` 的位模式重新解释为 `float64` 的操作 (位转换)。

   这些测试主要在 64 位架构下进行（通过 `V8_TARGET_ARCH_64_BIT` 条件编译），验证了 V8 在进行数值类型转换时的正确性。

**如果 `v8/test/cctest/compiler/test-run-machops.cc` 以 `.tq` 结尾：**

如果该文件以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用于定义运行时内置函数和类型系统的领域特定语言。在这种情况下，该文件将包含 Torque 代码，用于定义或测试 V8 内部的某些操作或类型的行为。  然而，根据你提供的信息，该文件是 `.cc` 文件，所以它是 C++ 代码。

**与 JavaScript 功能的关系：**

这些测试直接关系到 JavaScript 中 `Math` 对象提供的各种数学函数，以及 JavaScript 引擎内部的类型转换和函数调用机制。

**JavaScript 示例：**

```javascript
// 对应 RunFloat64Atan
Math.atan(1); // JavaScript 的反正切函数

// 对应 RunFloat64Cos
Math.cos(0);  // JavaScript 的余弦函数

// 对应 RunFloat64Log
Math.log(10); // JavaScript 的自然对数函数

// 对应 RunFloat64RoundDown
Math.floor(3.7); // JavaScript 的向下取整

// 对应 RunFloat64RoundUp
Math.ceil(3.2);  // JavaScript 的向上取整

// 对应类型转换（虽然 JavaScript 是动态类型，但引擎内部有类型转换）
let num = 10;
let floatNum = parseFloat(num); // 模拟 Int64ToFloat64
let intNum = parseInt(floatNum); // 模拟 Float64ToInt64
```

**代码逻辑推理和假设输入/输出：**

以 `RunFloat64Atan` 为例：

**假设输入：** `1.0`

**预期输出：** `base::ieee754::atan(1.0)` 的值，大约为 `0.7853981633974483`。测试会使用 `CHECK_DOUBLE_EQ` 来比较 V8 执行 `Float64Atan` 操作后的结果是否与这个预期值在精度范围内相等。

以 `RunCallCFunction1` 为例：

**C 函数 `foo1` 的定义：** `int32_t foo1(int32_t x) { return x; }`

**假设输入：** `5`

**预期输出：** `5`。 测试会调用 V8 生成的调用 `foo1` 的机器码，并验证其返回值是否为 `5`。

**涉及用户常见的编程错误：**

1. **浮点数精度问题：** 用户可能会期望浮点数运算得到精确的结果，但由于浮点数的表示方式，可能会出现精度丢失。例如，多个浮点数加减运算的顺序可能会影响最终结果。 这些测试用例通过比较到一定的精度来验证实现的正确性。

2. **对特殊浮点数值（NaN，Infinity）的处理不当：**  用户可能没有考虑到 `NaN` 或 `Infinity` 作为输入时，数学函数的行为。这些测试用例会显式地检查这些特殊情况。

3. **不理解舍入模式：** 用户可能混淆不同的舍入模式（向上取整、向下取整、四舍五入等），导致计算结果不符合预期。 相关的测试用例覆盖了各种舍入模式，确保 V8 的实现符合标准。

4. **C 函数调用约定错误：**  在调用 native 代码时，如果参数传递或返回值处理不正确，会导致程序崩溃或产生错误结果。 `RunCallCFunction*` 系列的测试用例验证了 V8 在生成 C 函数调用代码时的正确性。

**总结第 7 部分的功能：**

第 7 部分的 `v8/test/cctest/compiler/test-run-machops.cc` 集中测试了 V8 编译器针对 **`float64` 类型的各种超越函数、舍入操作，以及调用不同参数和返回类型的 C 函数** 生成机器码的正确性。此外，还包含了一些针对 `float32` 的舍入操作以及在 64 位架构下的类型转换测试。 这些测试是 V8 确保其编译器生成的机器码在处理浮点数运算和与 native 代码交互时符合规范和预期的重要组成部分。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```
K_DOUBLE_EQ(-0.0, m.Call(-0.0));
  CHECK_DOUBLE_EQ(0.0, m.Call(0.0));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::atan(i), m.Call(i)); }
}

TEST(RunFloat64Atanh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Atanh(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(), m.Call(1.0));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(-1.0));
  CHECK_DOUBLE_EQ(-0.0, m.Call(-0.0));
  CHECK_DOUBLE_EQ(0.0, m.Call(0.0));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::atanh(i), m.Call(i)); }
}

TEST(RunFloat64Atan2) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Float64());
  m.Return(m.Float64Atan2(m.Parameter(0), m.Parameter(1)));
  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      CHECK_DOUBLE_EQ(base::ieee754::atan2(i, j), m.Call(i, j));
    }
  }
}

TEST(RunFloat64Cos) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Cos(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(COS_IMPL(i), m.Call(i)); }
}

TEST(RunFloat64Cosh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Cosh(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::cosh(i), m.Call(i)); }
}

TEST(RunFloat64Exp) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Exp(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK_EQ(0.0, m.Call(-std::numeric_limits<double>::infinity()));
  CHECK_DOUBLE_EQ(1.0, m.Call(-0.0));
  CHECK_DOUBLE_EQ(1.0, m.Call(0.0));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::exp(i), m.Call(i)); }
}

TEST(RunFloat64Expm1) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Expm1(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK_EQ(-1.0, m.Call(-std::numeric_limits<double>::infinity()));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::expm1(i), m.Call(i)); }
}

TEST(RunFloat64Log) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Log(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK(std::isnan(m.Call(-std::numeric_limits<double>::infinity())));
  CHECK(std::isnan(m.Call(-1.0)));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(-0.0));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(0.0));
  CHECK_DOUBLE_EQ(0.0, m.Call(1.0));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::log(i), m.Call(i)); }
}

TEST(RunFloat64Log1p) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Log1p(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK(std::isnan(m.Call(-std::numeric_limits<double>::infinity())));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(-1.0));
  CHECK_DOUBLE_EQ(0.0, m.Call(0.0));
  CHECK_DOUBLE_EQ(-0.0, m.Call(-0.0));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::log1p(i), m.Call(i)); }
}

TEST(RunFloat64Log2) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Log2(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK(std::isnan(m.Call(-std::numeric_limits<double>::infinity())));
  CHECK(std::isnan(m.Call(-1.0)));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(-0.0));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(0.0));
  CHECK_DOUBLE_EQ(0.0, m.Call(1.0));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::log2(i), m.Call(i)); }
}

TEST(RunFloat64Log10) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Log10(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK(std::isnan(m.Call(-std::numeric_limits<double>::infinity())));
  CHECK(std::isnan(m.Call(-1.0)));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(-0.0));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(), m.Call(0.0));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::log10(i), m.Call(i)); }
}

TEST(RunFloat64Cbrt) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Cbrt(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHECK_DOUBLE_EQ(std::numeric_limits<double>::infinity(),
                  m.Call(std::numeric_limits<double>::infinity()));
  CHECK_DOUBLE_EQ(-std::numeric_limits<double>::infinity(),
                  m.Call(-std::numeric_limits<double>::infinity()));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::cbrt(i), m.Call(i)); }
}

TEST(RunFloat64Sin) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Sin(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(SIN_IMPL(i), m.Call(i)); }
}

TEST(RunFloat64Sinh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Sinh(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::sinh(i), m.Call(i)); }
}

TEST(RunFloat64Tan) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Tan(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::tan(i), m.Call(i)); }
}

TEST(RunFloat64Tanh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Tanh(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::tanh(i), m.Call(i)); }
}

static double two_30 = 1 << 30;             // 2^30 is a smi boundary.
static double two_52 = two_30 * (1 << 22);  // 2^52 is a precision boundary.
static double kValues[] = {0.1,
                           0.2,
                           0.49999999999999994,
                           0.5,
                           0.7,
                           1.0 - std::numeric_limits<double>::epsilon(),
                           -0.1,
                           -0.49999999999999994,
                           -0.5,
                           -0.7,
                           1.1,
                           1.0 + std::numeric_limits<double>::epsilon(),
                           1.5,
                           1.7,
                           -1,
                           -1 + std::numeric_limits<double>::epsilon(),
                           -1 - std::numeric_limits<double>::epsilon(),
                           -1.1,
                           -1.5,
                           -1.7,
                           std::numeric_limits<double>::min(),
                           -std::numeric_limits<double>::min(),
                           std::numeric_limits<double>::max(),
                           -std::numeric_limits<double>::max(),
                           std::numeric_limits<double>::infinity(),
                           -std::numeric_limits<double>::infinity(),
                           two_30,
                           two_30 + 0.1,
                           two_30 + 0.5,
                           two_30 + 0.7,
                           two_30 - 1,
                           two_30 - 1 + 0.1,
                           two_30 - 1 + 0.5,
                           two_30 - 1 + 0.7,
                           -two_30,
                           -two_30 + 0.1,
                           -two_30 + 0.5,
                           -two_30 + 0.7,
                           -two_30 + 1,
                           -two_30 + 1 + 0.1,
                           -two_30 + 1 + 0.5,
                           -two_30 + 1 + 0.7,
                           two_52,
                           two_52 + 0.1,
                           two_52 + 0.5,
                           two_52 + 0.5,
                           two_52 + 0.7,
                           two_52 + 0.7,
                           two_52 - 1,
                           two_52 - 1 + 0.1,
                           two_52 - 1 + 0.5,
                           two_52 - 1 + 0.7,
                           -two_52,
                           -two_52 + 0.1,
                           -two_52 + 0.5,
                           -two_52 + 0.7,
                           -two_52 + 1,
                           -two_52 + 1 + 0.1,
                           -two_52 + 1 + 0.5,
                           -two_52 + 1 + 0.7,
                           two_30,
                           two_30 - 0.1,
                           two_30 - 0.5,
                           two_30 - 0.7,
                           two_30 - 1,
                           two_30 - 1 - 0.1,
                           two_30 - 1 - 0.5,
                           two_30 - 1 - 0.7,
                           -two_30,
                           -two_30 - 0.1,
                           -two_30 - 0.5,
                           -two_30 - 0.7,
                           -two_30 + 1,
                           -two_30 + 1 - 0.1,
                           -two_30 + 1 - 0.5,
                           -two_30 + 1 - 0.7,
                           two_52,
                           two_52 - 0.1,
                           two_52 - 0.5,
                           two_52 - 0.5,
                           two_52 - 0.7,
                           two_52 - 0.7,
                           two_52 - 1,
                           two_52 - 1 - 0.1,
                           two_52 - 1 - 0.5,
                           two_52 - 1 - 0.7,
                           -two_52,
                           -two_52 - 0.1,
                           -two_52 - 0.5,
                           -two_52 - 0.7,
                           -two_52 + 1,
                           -two_52 + 1 - 0.1,
                           -two_52 + 1 - 0.5,
                           -two_52 + 1 - 0.7};


TEST(RunFloat32RoundDown) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  if (!m.machine()->Float32RoundDown().IsSupported()) return;

  m.Return(m.Float32RoundDown(m.Parameter(0)));

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(floorf(i), m.Call(i)); }
}


TEST(RunFloat64RoundDown1) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64RoundDown().IsSupported()) return;

  m.Return(m.Float64RoundDown(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(floor(i), m.Call(i)); }
}


TEST(RunFloat64RoundDown2) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64RoundDown().IsSupported()) return;
  m.Return(m.Float64Sub(m.Float64Constant(-0.0),
                        m.Float64RoundDown(m.Float64Sub(m.Float64Constant(-0.0),
                                                        m.Parameter(0)))));

  for (size_t i = 0; i < arraysize(kValues); ++i) {
    CHECK_EQ(ceil(kValues[i]), m.Call(kValues[i]));
  }
}


TEST(RunFloat32RoundUp) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  if (!m.machine()->Float32RoundUp().IsSupported()) return;
  m.Return(m.Float32RoundUp(m.Parameter(0)));

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(ceilf(i), m.Call(i)); }
}


TEST(RunFloat64RoundUp) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64RoundUp().IsSupported()) return;
  m.Return(m.Float64RoundUp(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(ceil(i), m.Call(i)); }
}


TEST(RunFloat32RoundTiesEven) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  if (!m.machine()->Float32RoundTiesEven().IsSupported()) return;
  m.Return(m.Float32RoundTiesEven(m.Parameter(0)));

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(nearbyint(i), m.Call(i)); }
}


TEST(RunFloat64RoundTiesEven) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64RoundTiesEven().IsSupported()) return;
  m.Return(m.Float64RoundTiesEven(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(nearbyint(i), m.Call(i)); }
}


TEST(RunFloat32RoundTruncate) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  if (!m.machine()->Float32RoundTruncate().IsSupported()) return;

  m.Return(m.Float32RoundTruncate(m.Parameter(0)));

  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(truncf(i), m.Call(i)); }
}


TEST(RunFloat64RoundTruncate) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64RoundTruncate().IsSupported()) return;
  m.Return(m.Float64RoundTruncate(m.Parameter(0)));
  for (size_t i = 0; i < arraysize(kValues); ++i) {
    CHECK_EQ(trunc(kValues[i]), m.Call(kValues[i]));
  }
}


TEST(RunFloat64RoundTiesAway) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  if (!m.machine()->Float64RoundTiesAway().IsSupported()) return;
  m.Return(m.Float64RoundTiesAway(m.Parameter(0)));
  for (size_t i = 0; i < arraysize(kValues); ++i) {
    CHECK_EQ(round(kValues[i]), m.Call(kValues[i]));
  }
}


#if !USE_SIMULATOR

namespace {

int32_t const kMagicFoo0 = 0xDEADBEEF;

int32_t foo0() { return kMagicFoo0; }


int32_t foo1(int32_t x) { return x; }

int32_t foo2(int32_t x, int32_t y) { return base::SubWithWraparound(x, y); }

uint32_t foo8(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e,
              uint32_t f, uint32_t g, uint32_t h) {
  return a + b + c + d + e + f + g + h;
}

uint32_t foo9(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e,
              uint32_t f, uint32_t g, uint32_t h, uint32_t i) {
  return a + b + c + d + e + f + g + h + i;
}

}  // namespace


TEST(RunCallCFunction0) {
  auto* foo0_ptr = &foo0;
  RawMachineAssemblerTester<int32_t> m;
  Node* function = m.LoadFromPointer(&foo0_ptr, MachineType::Pointer());
  m.Return(m.CallCFunction(function, MachineType::Int32()));
  CHECK_EQ(kMagicFoo0, m.Call());
}


TEST(RunCallCFunction1) {
  auto* foo1_ptr = &foo1;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  Node* function = m.LoadFromPointer(&foo1_ptr, MachineType::Pointer());
  m.Return(
      m.CallCFunction(function, MachineType::Int32(),
                      std::make_pair(MachineType::Int32(), m.Parameter(0))));
  FOR_INT32_INPUTS(i) {
    int32_t const expected = i;
    CHECK_EQ(expected, m.Call(expected));
  }
}


TEST(RunCallCFunction2) {
  auto* foo2_ptr = &foo2;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  Node* function = m.LoadFromPointer(&foo2_ptr, MachineType::Pointer());
  m.Return(
      m.CallCFunction(function, MachineType::Int32(),
                      std::make_pair(MachineType::Int32(), m.Parameter(0)),
                      std::make_pair(MachineType::Int32(), m.Parameter(1))));
  FOR_INT32_INPUTS(i) {
    int32_t const x = i;
    FOR_INT32_INPUTS(j) {
      int32_t const y = j;
      CHECK_EQ(base::SubWithWraparound(x, y), m.Call(x, y));
    }
  }
}


TEST(RunCallCFunction8) {
  auto* foo8_ptr = &foo8;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  Node* function = m.LoadFromPointer(&foo8_ptr, MachineType::Pointer());
  Node* param = m.Parameter(0);
  m.Return(m.CallCFunction(function, MachineType::Int32(),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param),
      std::make_pair(MachineType::Int32(), param)));
  FOR_INT32_INPUTS(i) {
    int32_t const x = i;
    CHECK_EQ(base::MulWithWraparound(x, 8), m.Call(x));
  }
}

TEST(RunCallCFunction9) {
  auto* foo9_ptr = &foo9;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  Node* function = m.LoadFromPointer(&foo9_ptr, MachineType::Pointer());
  Node* param = m.Parameter(0);
  m.Return(
      m.CallCFunction(function, MachineType::Int32(),
                      std::make_pair(MachineType::Int32(), param),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(1))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(2))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(3))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(4))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(5))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(6))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(7))),
                      std::make_pair(MachineType::Int32(),
                                     m.Int32Add(param, m.Int32Constant(8)))));
  FOR_INT32_INPUTS(i) {
    int32_t const x = i;
    CHECK_EQ(base::AddWithWraparound(base::MulWithWraparound(x, 9), 36),
             m.Call(x));
  }
}

#endif  // !USE_SIMULATOR

#ifdef V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

namespace {

void CheckEqual(double expected, double actual) {
  if (std::isnan(expected)) {
    CHECK(std::isnan(actual));
  } else {
    CHECK_EQ(actual, expected);
  }
}

void CheckLessOrEqual(double actual, double expected) {
  if (std::isnan(expected)) {
    CHECK(std::isnan(actual));
  } else if (std::isnan(actual)) {
    return;
  } else {
    CHECK_LE(actual, expected);
  }
}

const double foo_result = 3.14;

#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
union Int64OrDoubleUnion {
  int64_t int64_value;
  double double_value;
};

Int64OrDoubleUnion double_foo0() {
  Int64OrDoubleUnion ret;
  ret.double_value = foo_result;
  return ret;
}

Int64OrDoubleUnion double_foo1(Int64OrDoubleUnion x) {
  Int64OrDoubleUnion ret;
  ret.double_value = x.double_value;
  return ret;
}

Int64OrDoubleUnion double_foo2(Int64OrDoubleUnion x, Int64OrDoubleUnion y) {
  Int64OrDoubleUnion ret;
  ret.double_value = x.double_value * 10 + y.double_value;
  return ret;
}

Int64OrDoubleUnion double_foo8(Int64OrDoubleUnion a, Int64OrDoubleUnion b,
                               Int64OrDoubleUnion c, Int64OrDoubleUnion d,
                               Int64OrDoubleUnion e, Int64OrDoubleUnion f,
                               Int64OrDoubleUnion g, Int64OrDoubleUnion h) {
  Int64OrDoubleUnion ret;
  ret.double_value = a.double_value + b.double_value + c.double_value +
                     d.double_value + e.double_value + f.double_value +
                     g.double_value + h.double_value;
  return ret;
}

Int64OrDoubleUnion double_foo9(Int64OrDoubleUnion a, Int64OrDoubleUnion b,
                               Int64OrDoubleUnion c, Int64OrDoubleUnion d,
                               Int64OrDoubleUnion e, Int64OrDoubleUnion f,
                               Int64OrDoubleUnion g, Int64OrDoubleUnion h,
                               Int64OrDoubleUnion i) {
  Int64OrDoubleUnion ret;
  ret.double_value = a.double_value + b.double_value + c.double_value +
                     d.double_value + e.double_value + f.double_value +
                     g.double_value + h.double_value + i.double_value;
  return ret;
}

Int64OrDoubleUnion double_foo10(Int64OrDoubleUnion a, Int64OrDoubleUnion b,
                                Int64OrDoubleUnion c, Int64OrDoubleUnion d,
                                Int64OrDoubleUnion e, Int64OrDoubleUnion f,
                                Int64OrDoubleUnion g, Int64OrDoubleUnion h,
                                Int64OrDoubleUnion i, Int64OrDoubleUnion j) {
  Int64OrDoubleUnion ret;
  ret.double_value = a.double_value + b.double_value + c.double_value +
                     d.double_value + e.double_value + f.double_value +
                     g.double_value + h.double_value + i.double_value +
                     j.int64_value;
  return ret;
}

Int64OrDoubleUnion int_foo10(Int64OrDoubleUnion a, Int64OrDoubleUnion b,
                             Int64OrDoubleUnion c, Int64OrDoubleUnion d,
                             Int64OrDoubleUnion e, Int64OrDoubleUnion f,
                             Int64OrDoubleUnion g, Int64OrDoubleUnion h,
                             Int64OrDoubleUnion i, Int64OrDoubleUnion j) {
  Int64OrDoubleUnion ret;
  ret.double_value = a.int64_value + b.int64_value + c.int64_value +
                     d.int64_value + e.int64_value + f.int64_value +
                     g.int64_value + h.int64_value + i.int64_value +
                     j.double_value;
  return ret;
}
#else   // def V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
double double_foo0() { return foo_result; }

double double_foo1(double x) { return x; }

double double_foo2(double x, double y) { return x * 10 + y; }

double double_foo8(double a, double b, double c, double d, double e, double f,
                   double g, double h) {
  return a + b + c + d + e + f + g + h;
}

double double_foo9(double a, double b, double c, double d, double e, double f,
                   double g, double h, double i) {
  return a + b + c + d + e + f + g + h + i;
}

double double_foo10(double a, double b, double c, double d, double e, double f,
                    double g, double h, double i, int64_t j) {
  return a + b + c + d + e + f + g + h + i + j;
}

double int_foo10(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e,
                 int64_t f, int64_t g, int64_t h, int64_t i, double j) {
  return a + b + c + d + e + f + g + h + i + j;
}
#endif  // V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS

}  // namespace

TEST(RunCallDoubleCFunction0) {
  RawMachineAssemblerTester<double> m;
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(double_foo0));

  Node* function = m.ExternalConstant(ref);
  m.Return(m.CallCFunction(function, MachineType::Float64()));
  CheckEqual(foo_result, m.Call());
}

TEST(RunCallDoubleCFunction1) {
  RawMachineAssemblerTester<double> m(MachineType::Float64());
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(double_foo1));

  Node* function = m.ExternalConstant(ref);
  m.Return(
      m.CallCFunction(function, MachineType::Float64(),
                      std::make_pair(MachineType::Float64(), m.Parameter(0))));
  FOR_FLOAT64_INPUTS(x) { CheckEqual(x, m.Call(x)); }
}

TEST(RunCallDoubleCFunction2) {
  RawMachineAssemblerTester<double> m(MachineType::Float64(),
                                      MachineType::Float64());
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(double_foo2));

  Node* function = m.ExternalConstant(ref);
  m.Return(
      m.CallCFunction(function, MachineType::Float64(),
                      std::make_pair(MachineType::Float64(), m.Parameter(0)),
                      std::make_pair(MachineType::Float64(), m.Parameter(1))));
  FOR_FLOAT64_INPUTS(x) {
    if (std::isnan(x)) continue;
    FOR_FLOAT64_INPUTS(y) { CheckEqual(x * 10 + y, m.Call(x, y)); }
  }
}

TEST(RunCallDoubleCFunction8) {
  RawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Float64(), MachineType::Float64());
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(double_foo8));

  Node* function = m.ExternalConstant(ref);
  Node* param = m.Parameter(0);
  m.Return(m.CallCFunction(function, MachineType::Float64(),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param),
                           std::make_pair(MachineType::Float64(), param)));
  FOR_FLOAT64_INPUTS(x) {
    double diff = std::fabs(x * 8.0 - m.Call(x));
    CheckLessOrEqual(diff, std::numeric_limits<double>::epsilon());
  }
}

TEST(RunCallDoubleCFunction9) {
  RawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64());
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(double_foo9));

  Node* function = m.ExternalConstant(ref);
  Node* param = m.Parameter(0);
  m.Return(m.CallCFunction(
      function, MachineType::Float64(),
      std::make_pair(MachineType::Float64(), param),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(1))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(2))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(3))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(4))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(5))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(6))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(7))),
      std::make_pair(MachineType::Float64(),
                     m.Float64Add(param, m.Float64Constant(8)))));
  FOR_FLOAT64_INPUTS(x) {
    double diff = x * 9.0 + 36.0 - m.Call(x);
    CheckLessOrEqual(diff, std::numeric_limits<double>::epsilon());
  }
}

TEST(RunCallDoubleCFunction10) {
  RawMachineAssemblerTester<double> m(
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Float64(), MachineType::Float64(), MachineType::Float64(),
      MachineType::Int64());
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(double_foo10));

  Node* function = m.ExternalConstant(ref);
  m.Return(
      m.CallCFunction(function, MachineType::Float64(),
                      std::make_pair(MachineType::Float64(), m.Parameter(0)),
                      std::make_pair(MachineType::Float64(), m.Parameter(1)),
                      std::make_pair(MachineType::Float64(), m.Parameter(2)),
                      std::make_pair(MachineType::Float64(), m.Parameter(3)),
                      std::make_pair(MachineType::Float64(), m.Parameter(4)),
                      std::make_pair(MachineType::Float64(), m.Parameter(5)),
                      std::make_pair(MachineType::Float64(), m.Parameter(6)),
                      std::make_pair(MachineType::Float64(), m.Parameter(7)),
                      std::make_pair(MachineType::Float64(), m.Parameter(8)),
                      std::make_pair(MachineType::Int64(), m.Parameter(9))));
  FOR_INT64_INPUTS(x) {
    double c = m.Call(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, x);
    double diff = 45.0 + x - c;
    CheckLessOrEqual(fabs(diff), std::numeric_limits<double>::epsilon());
  }
}

TEST(RunCallIntCFunction10) {
  RawMachineAssemblerTester<double> m(
      MachineType::Int64(), MachineType::Int64(), MachineType::Int64(),
      MachineType::Int64(), MachineType::Int64(), MachineType::Int64(),
      MachineType::Int64(), MachineType::Int64(), MachineType::Int64(),
      MachineType::Float64());
  ExternalReference ref = ExternalRefFromFunc(&m, FUNCTION_ADDR(int_foo10));

  Node* function = m.ExternalConstant(ref);
  m.Return(
      m.CallCFunction(function, MachineType::Float64(),
                      std::make_pair(MachineType::Int64(), m.Parameter(0)),
                      std::make_pair(MachineType::Int64(), m.Parameter(1)),
                      std::make_pair(MachineType::Int64(), m.Parameter(2)),
                      std::make_pair(MachineType::Int64(), m.Parameter(3)),
                      std::make_pair(MachineType::Int64(), m.Parameter(4)),
                      std::make_pair(MachineType::Int64(), m.Parameter(5)),
                      std::make_pair(MachineType::Int64(), m.Parameter(6)),
                      std::make_pair(MachineType::Int64(), m.Parameter(7)),
                      std::make_pair(MachineType::Int64(), m.Parameter(8)),
                      std::make_pair(MachineType::Float64(), m.Parameter(9))));
  FOR_FLOAT64_INPUTS(x) {
    double c = m.Call(static_cast<int64_t>(1), static_cast<int64_t>(2),
                      static_cast<int64_t>(3), static_cast<int64_t>(4),
                      static_cast<int64_t>(5), static_cast<int64_t>(6),
                      static_cast<int64_t>(7), static_cast<int64_t>(8),
                      static_cast<int64_t>(9), x);
    double diff = 45.0 + x - c;
    CheckLessOrEqual(fabs(diff), std::numeric_limits<double>::epsilon());
  }
}
#endif  // V8_ENABLE_FP_PARAMS_IN_C_LINKAGE

#if V8_TARGET_ARCH_64_BIT
// TODO(titzer): run int64 tests on all platforms when supported.

TEST(RunChangeFloat64ToInt64) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  m.Return(m.ChangeFloat64ToInt64(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) {
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      CHECK_EQ(static_cast<int64_t>(i), m.Call(i));
    }
  }
}

TEST(RunChangeInt64ToFloat64) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Int64());
  m.Return(m.ChangeInt64ToFloat64(m.Parameter(0)));
  FOR_INT64_INPUTS(i) {
    double output = static_cast<double>(i);
    CHECK_EQ(output, m.Call(i));
  }
}

TEST(RunBitcastInt64ToFloat64) {
  int64_t input = 1;
  Float64 output;
  RawMachineAssemblerTester<int32_t> m;
  m.StoreToPointer(
      output.get_bits_address(), MachineRepresentation::kFloat64,
      m.BitcastInt64T
```