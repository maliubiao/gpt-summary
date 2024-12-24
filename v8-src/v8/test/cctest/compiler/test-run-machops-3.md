Response: Let's break down the thought process for summarizing this C++ code.

1. **Understand the Goal:** The request asks for a functional summary of a C++ file, specifically the 4th part of a series. The key is to identify what the code *does*, not just the individual operations. It also asks about the relationship to JavaScript and for illustrative JavaScript examples.

2. **High-Level Structure Scan:** Quickly skim the code to identify the major components. The prominent feature here is the extensive use of `TEST(...)`. This immediately signals that the file is about *testing*. The names of the tests often start with "Run", suggesting they are executing or testing certain operations.

3. **Identify the Tested Operations:**  Look at the code *within* each `TEST` block. The patterns are clear:
    * Creation of a `BufferedRawMachineAssemblerTester` (or `RawMachineAssemblerTester`). This suggests they are testing low-level machine operations.
    * Calls to methods like `Float64Atan`, `Float64Cos`, `Int32Add`, `Word64Shr`, etc. These are the machine operations being tested.
    * Use of `CHECK_DOUBLE_EQ`, `CHECK_FLOAT_EQ`, `CHECK_EQ`, etc. These are assertion macros, confirming the output of the tested operation matches the expected result.
    * The presence of `FOR_FLOAT64_INPUTS`, `FOR_INT32_INPUTS`, etc., indicates they are testing these operations with a range of inputs.

4. **Group Similar Tests:** Notice the repetition of patterns. Many tests follow the structure of testing a single machine operation (e.g., `Float64Atan`, `Float64Sinh`). Group these together conceptually. There are also groups related to rounding (`RoundDown`, `RoundUp`, `RoundTiesEven`, `RoundTruncate`), bitcasting, and calling C functions.

5. **Focus on Functionality, Not Implementation Details:**  Avoid getting bogged down in the specifics of `BufferedRawMachineAssemblerTester`. The important point is that it's a tool for testing *machine operations*. Similarly, the exact nature of `FOR_FLOAT64_INPUTS` isn't critical for a high-level summary; the key is that it tests with various inputs.

6. **Connect to JavaScript (if applicable):** The prompt specifically asks about the connection to JavaScript. Think about how these low-level machine operations relate to JavaScript's behavior. Mathematical functions (`Math.atan`, `Math.cos`), type conversions (number to integer, bitwise operations), and calling external C code are all areas where these low-level operations are relevant to JavaScript execution.

7. **Illustrative JavaScript Examples:**  Provide concrete JavaScript examples that directly correspond to the tested C++ machine operations. This makes the connection clear and understandable.

8. **Structure the Summary:** Organize the findings logically. Start with a general overview, then group the tests by the type of operation being tested. Conclude with the connection to JavaScript and provide examples. Given that this is part 4, it's useful to acknowledge that it continues the theme of testing machine operations.

9. **Refine and Iterate:** Read through the summary to ensure clarity and accuracy. Are there any ambiguous statements? Can the language be more concise?  For instance, initially, I might have just listed all the tested functions. However, grouping them by category (mathematical, rounding, bitwise, etc.) makes the summary more insightful.

10. **Address the "Part 4" Constraint:** Explicitly mention that this is the final part and that it continues the theme of testing machine operations. This provides context.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the `BufferedRawMachineAssemblerTester`. I would then realize that the *purpose* of this class is to *facilitate testing machine operations*. The summary should emphasize the *operations being tested* rather than the details of the testing framework itself. This leads to a more focused and relevant summary. Similarly, I might initially forget to provide JavaScript examples and need to go back and add them to address that part of the request.
这是对`v8/test/cctest/compiler/test-run-machops.cc`文件的第4部分内容的总结。考虑到这是一个测试文件，其主要功能是**测试V8编译器中特定机器操作指令的正确性**。

与前几部分一样，这部分继续测试各种底层机器操作，特别是关注**浮点数 (double 和 float) 的数学运算、类型转换以及调用 C 函数**。

**具体功能归纳：**

1. **浮点数数学运算测试 (double):**
   - 测试 `atan`, `atanh`, `atan2`, `cos`, `cosh`, `exp`, `expm1`, `log`, `log1p`, `log2`, `log10`, `cbrt`, `sin`, `sinh`, `tan`, `tanh` 等双精度浮点数数学函数的机器指令实现。
   - 通过 `BufferedRawMachineAssemblerTester<double>` 创建测试环境，模拟传入参数并调用相应的机器指令，然后与标准库函数（例如 `base::ieee754::atan(i)` 或 `COS_IMPL(i)`) 的结果进行比较，验证机器指令的正确性，包括处理 NaN、正负零、无穷大等特殊情况。

2. **浮点数舍入测试 (float 和 double):**
   - 测试 `Float32RoundDown` (向下取整), `Float64RoundDown`, `Float32RoundUp` (向上取整), `Float64RoundUp`, `Float32RoundTiesEven` (四舍五入到最接近的偶数), `Float64RoundTiesEven`, `Float32RoundTruncate` (向零取整), `Float64RoundTruncate`, `Float64RoundTiesAway` (四舍五入远离零) 等浮点数舍入操作的机器指令。
   - 这些测试会检查各种输入值，确保机器指令的舍入行为与预期一致。

3. **调用 C 函数测试:**
   -  测试 `CallCFunction` 指令，用于调用外部 C 函数。
   -  测试了不同参数数量 (0, 1, 2, 8, 9) 的 C 函数调用，验证参数传递和返回值处理的正确性。
   -  在 `V8_ENABLE_FP_PARAMS_IN_C_LINKAGE` 定义的情况下，还测试了包含浮点数参数和返回值的 C 函数调用。

4. **类型转换和位运算测试 (涉及 int64_t, uint64_t, float, double):**
   - 测试了各种类型转换操作，例如 `ChangeFloat64ToInt64`, `ChangeInt64ToFloat64`, `BitcastInt64ToFloat64`, `BitcastFloat64ToInt64`, `TryTruncateFloat32ToInt64` (带和不带检查), `TryTruncateFloat64ToInt64` (带和不带检查), `TryTruncateFloat32ToUint64` (带和不带检查), `TryTruncateFloat64ToUint64` (带和不带检查), `RoundInt64ToFloat32`, `RoundInt64ToFloat64`, `RoundUint64ToFloat64`, `RoundUint64ToFloat32`, `BitcastFloat32ToInt32`, `RoundInt32ToFloat32`, `RoundUint32ToFloat32`, `BitcastInt32ToFloat32`。
   - 这些测试验证了在不同数值范围和精度下，类型转换指令的正确性，包括溢出和截断的处理。
   - 特别地，还测试了 64 位整数和浮点数之间的转换。

5. **其他机器操作测试:**
   - 测试了 `ComputedCodeObject`，验证了动态选择和调用代码对象的能力。
   - 测试了 `ParentFramePointer`，用于访问父帧指针。
   - 包含了一些回归测试，例如 `Regression5923`, `Regression5951`, `Regression6046a`, `Regression6122`, `Regression6046b`, `Regression6122b`, `Regression6028`, `Regression5951_32bit`, `Regression738952`, `Regression12373`，用于确保之前修复的 bug 没有再次出现。

**与 JavaScript 的关系及 JavaScript 示例：**

这个文件测试的机器操作是 V8 引擎执行 JavaScript 代码的基础。JavaScript 中的许多操作最终会被编译成这些底层的机器指令。

**举例说明：**

1. **JavaScript 的 `Math` 对象:**
   - `Math.atan(x)` 在底层可能会使用 `Float64Atan` 机器指令进行计算。
   - `Math.cos(x)` 在底层可能会使用 `Float64Cos` 机器指令进行计算。

   ```javascript
   let x = 1.0;
   let atan_result = Math.atan(x); // 底层可能使用 Float64Atan
   let cos_result = Math.cos(x);  // 底层可能使用 Float64Cos
   ```

2. **JavaScript 的类型转换:**
   - 将 JavaScript Number 类型转换为整数时，例如使用 `parseInt()` 或位运算符，底层可能会使用 `TryTruncateFloat64ToInt32` 或类似的指令。

   ```javascript
   let floatValue = 3.14;
   let intValue = parseInt(floatValue); // 底层可能使用浮点数到整数的截断指令

   let num = 10.5;
   let truncated = num | 0; // 底层可能使用浮点数到整数的截断指令
   ```

3. **JavaScript 调用 C++ 代码 (通过 Native Modules 或 WebAssembly):**
   - 当 JavaScript 调用 Native Modules 中的 C++ 函数时，或者执行 WebAssembly 代码时，参数的传递和返回值的处理可能会涉及到 `CallCFunction` 指令。

   ```javascript
   // 假设有一个 Native Module 提供了 add 函数
   const myModule = require('my_native_module');
   let sum = myModule.add(5, 3); // 底层可能使用 CallCFunction

   // WebAssembly 示例
   // ... 加载和实例化 WebAssembly 模块
   // let result = instance.exports.my_wasm_function(10); // 底层可能使用类似调用 C 函数的机制
   ```

4. **JavaScript 的位运算符:**
   - JavaScript 的位运算符（如 `<<`, `>>`, `&`, `|`）在底层会使用相应的机器指令，例如 `Word32Shr` (无符号右移), `Word32And` (按位与) 等。

   ```javascript
   let num1 = 10;
   let num2 = 3;
   let shifted = num1 >> 1; // 底层可能使用 Word32Shr
   let andResult = num1 & num2; // 底层可能使用 Word32And
   ```

**总结来说，这个文件是 V8 引擎编译器测试套件的关键部分，它确保了生成的机器代码能够正确执行各种基本的操作，这些操作是 JavaScript 语言功能实现的基石。** 这部分特别关注浮点数运算、类型转换以及与外部 C 代码的交互，这些都是现代 JavaScript 应用中非常重要的方面。

Prompt: 
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
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
      m.BitcastInt64ToFloat64(m.LoadFromPointer(&input, MachineType::Int64())));
  m.Return(m.Int32Constant(11));
  FOR_INT64_INPUTS(i) {
    input = i;
    CHECK_EQ(11, m.Call());
    Float64 expected = Float64::FromBits(input);
    CHECK_EQ(expected.get_bits(), output.get_bits());
  }
}


TEST(RunBitcastFloat64ToInt64) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());

  m.Return(m.BitcastFloat64ToInt64(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_EQ(base::bit_cast<int64_t>(i), m.Call(i)); }
}


TEST(RunTryTruncateFloat32ToInt64WithoutCheck) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float32());
  m.Return(m.TryTruncateFloat32ToInt64(m.Parameter(0)));

  FOR_INT64_INPUTS(i) {
    float input = static_cast<float>(i);
    if (input < static_cast<float>(INT64_MAX) &&
        input >= static_cast<float>(INT64_MIN)) {
      CHECK_EQ(static_cast<int64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat32ToInt64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float32());
  Node* trunc = m.TryTruncateFloat32ToInt64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT32_INPUTS(i) {
    if (i < static_cast<float>(INT64_MAX) &&
        i >= static_cast<float>(INT64_MIN)) {
      CHECK_EQ(static_cast<int64_t>(i), m.Call(i));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunTryTruncateFloat64ToInt64WithoutCheck) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  m.Return(m.TryTruncateFloat64ToInt64(m.Parameter(0)));

  FOR_FLOAT64_INPUTS(i) {
    if (base::IsValueInRangeForNumericType<int64_t>(i)) {
      double input = static_cast<double>(i);
      CHECK_EQ(static_cast<int64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat64ToInt64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  Node* trunc = m.TryTruncateFloat64ToInt64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT64_INPUTS(i) {
    if (i < static_cast<double>(INT64_MAX) &&
        i >= static_cast<double>(INT64_MIN)) {
      // Conversions within this range should succeed.
      CHECK_EQ(static_cast<int64_t>(i), m.Call(i));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunTryTruncateFloat32ToUint64WithoutCheck) {
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Float32());
  m.Return(m.TryTruncateFloat32ToUint64(m.Parameter(0)));

  FOR_UINT64_INPUTS(i) {
    float input = static_cast<float>(i);
    // This condition on 'input' is required because
    // static_cast<float>(UINT64_MAX) results in a value outside uint64 range.
    if (input < static_cast<float>(UINT64_MAX)) {
      CHECK_EQ(static_cast<uint64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat32ToUint64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Float32());
  Node* trunc = m.TryTruncateFloat32ToUint64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT32_INPUTS(i) {
    if (i < static_cast<float>(UINT64_MAX) && i > -1.0) {
      // Conversions within this range should succeed.
      CHECK_EQ(static_cast<uint64_t>(i), m.Call(i));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunTryTruncateFloat64ToUint64WithoutCheck) {
  BufferedRawMachineAssemblerTester<uint64_t> m(MachineType::Float64());
  m.Return(m.TryTruncateFloat64ToUint64(m.Parameter(0)));

  FOR_UINT64_INPUTS(j) {
    double input = static_cast<double>(j);

    if (input < static_cast<float>(UINT64_MAX)) {
      CHECK_EQ(static_cast<uint64_t>(input), m.Call(input));
    }
  }
}


TEST(RunTryTruncateFloat64ToUint64WithCheck) {
  int64_t success = 0;
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Float64());
  Node* trunc = m.TryTruncateFloat64ToUint64(m.Parameter(0));
  Node* val = m.Projection(0, trunc);
  Node* check = m.Projection(1, trunc);
  m.StoreToPointer(&success, MachineRepresentation::kWord64, check);
  m.Return(val);

  FOR_FLOAT64_INPUTS(i) {
    if (i < 18446744073709551616.0 && i > -1) {
      // Conversions within this range should succeed.
      CHECK_EQ(static_cast<uint64_t>(i), static_cast<uint64_t>(m.Call(i)));
      CHECK_NE(0, success);
    } else {
      m.Call(i);
      CHECK_EQ(0, success);
    }
  }
}


TEST(RunRoundInt64ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Int64());
  m.Return(m.RoundInt64ToFloat32(m.Parameter(0)));
  FOR_INT64_INPUTS(i) { CHECK_EQ(static_cast<float>(i), m.Call(i)); }
}


TEST(RunRoundInt64ToFloat64) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Int64());
  m.Return(m.RoundInt64ToFloat64(m.Parameter(0)));
  FOR_INT64_INPUTS(i) { CHECK_EQ(static_cast<double>(i), m.Call(i)); }
}


TEST(RunRoundUint64ToFloat64) {
  struct {
    uint64_t input;
    uint64_t expected;
  } values[] = {{0x0, 0x0},
                {0x1, 0x3FF0000000000000},
                {0xFFFFFFFF, 0x41EFFFFFFFE00000},
                {0x1B09788B, 0x41BB09788B000000},
                {0x4C5FCE8, 0x419317F3A0000000},
                {0xCC0DE5BF, 0x41E981BCB7E00000},
                {0x2, 0x4000000000000000},
                {0x3, 0x4008000000000000},
                {0x4, 0x4010000000000000},
                {0x5, 0x4014000000000000},
                {0x8, 0x4020000000000000},
                {0x9, 0x4022000000000000},
                {0xFFFFFFFFFFFFFFFF, 0x43F0000000000000},
                {0xFFFFFFFFFFFFFFFE, 0x43F0000000000000},
                {0xFFFFFFFFFFFFFFFD, 0x43F0000000000000},
                {0x100000000, 0x41F0000000000000},
                {0xFFFFFFFF00000000, 0x43EFFFFFFFE00000},
                {0x1B09788B00000000, 0x43BB09788B000000},
                {0x4C5FCE800000000, 0x439317F3A0000000},
                {0xCC0DE5BF00000000, 0x43E981BCB7E00000},
                {0x200000000, 0x4200000000000000},
                {0x300000000, 0x4208000000000000},
                {0x400000000, 0x4210000000000000},
                {0x500000000, 0x4214000000000000},
                {0x800000000, 0x4220000000000000},
                {0x900000000, 0x4222000000000000},
                {0x273A798E187937A3, 0x43C39D3CC70C3C9C},
                {0xECE3AF835495A16B, 0x43ED9C75F06A92B4},
                {0xB668ECC11223344, 0x43A6CD1D98224467},
                {0x9E, 0x4063C00000000000},
                {0x43, 0x4050C00000000000},
                {0xAF73, 0x40E5EE6000000000},
                {0x116B, 0x40B16B0000000000},
                {0x658ECC, 0x415963B300000000},
                {0x2B3B4C, 0x41459DA600000000},
                {0x88776655, 0x41E10EECCAA00000},
                {0x70000000, 0x41DC000000000000},
                {0x7200000, 0x419C800000000000},
                {0x7FFFFFFF, 0x41DFFFFFFFC00000},
                {0x56123761, 0x41D5848DD8400000},
                {0x7FFFFF00, 0x41DFFFFFC0000000},
                {0x761C4761EEEEEEEE, 0x43DD8711D87BBBBC},
                {0x80000000EEEEEEEE, 0x43E00000001DDDDE},
                {0x88888888DDDDDDDD, 0x43E11111111BBBBC},
                {0xA0000000DDDDDDDD, 0x43E40000001BBBBC},
                {0xDDDDDDDDAAAAAAAA, 0x43EBBBBBBBB55555},
                {0xE0000000AAAAAAAA, 0x43EC000000155555},
                {0xEEEEEEEEEEEEEEEE, 0x43EDDDDDDDDDDDDE},
                {0xFFFFFFFDEEEEEEEE, 0x43EFFFFFFFBDDDDE},
                {0xF0000000DDDDDDDD, 0x43EE0000001BBBBC},
                {0x7FFFFFDDDDDDDD, 0x435FFFFFF7777777},
                {0x3FFFFFAAAAAAAA, 0x434FFFFFD5555555},
                {0x1FFFFFAAAAAAAA, 0x433FFFFFAAAAAAAA},
                {0xFFFFF, 0x412FFFFE00000000},
                {0x7FFFF, 0x411FFFFC00000000},
                {0x3FFFF, 0x410FFFF800000000},
                {0x1FFFF, 0x40FFFFF000000000},
                {0xFFFF, 0x40EFFFE000000000},
                {0x7FFF, 0x40DFFFC000000000},
                {0x3FFF, 0x40CFFF8000000000},
                {0x1FFF, 0x40BFFF0000000000},
                {0xFFF, 0x40AFFE0000000000},
                {0x7FF, 0x409FFC0000000000},
                {0x3FF, 0x408FF80000000000},
                {0x1FF, 0x407FF00000000000},
                {0x3FFFFFFFFFFF, 0x42CFFFFFFFFFFF80},
                {0x1FFFFFFFFFFF, 0x42BFFFFFFFFFFF00},
                {0xFFFFFFFFFFF, 0x42AFFFFFFFFFFE00},
                {0x7FFFFFFFFFF, 0x429FFFFFFFFFFC00},
                {0x3FFFFFFFFFF, 0x428FFFFFFFFFF800},
                {0x1FFFFFFFFFF, 0x427FFFFFFFFFF000},
                {0x8000008000000000, 0x43E0000010000000},
                {0x8000008000000001, 0x43E0000010000000},
                {0x8000000000000400, 0x43E0000000000000},
                {0x8000000000000401, 0x43E0000000000001}};

  BufferedRawMachineAssemblerTester<double> m(MachineType::Uint64());
  m.Return(m.RoundUint64ToFloat64(m.Parameter(0)));

  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(base::bit_cast<double>(values[i].expected),
             m.Call(values[i].input));
  }
}


TEST(RunRoundUint64ToFloat32) {
  struct {
    uint64_t input;
    uint32_t expected;
  } values[] = {{0x0, 0x0},
                {0x1, 0x3F800000},
                {0xFFFFFFFF, 0x4F800000},
                {0x1B09788B, 0x4DD84BC4},
                {0x4C5FCE8, 0x4C98BF9D},
                {0xCC0DE5BF, 0x4F4C0DE6},
                {0x2, 0x40000000},
                {0x3, 0x40400000},
                {0x4, 0x40800000},
                {0x5, 0x40A00000},
                {0x8, 0x41000000},
                {0x9, 0x41100000},
                {0xFFFFFFFFFFFFFFFF, 0x5F800000},
                {0xFFFFFFFFFFFFFFFE, 0x5F800000},
                {0xFFFFFFFFFFFFFFFD, 0x5F800000},
                {0x0, 0x0},
                {0x100000000, 0x4F800000},
                {0xFFFFFFFF00000000, 0x5F800000},
                {0x1B09788B00000000, 0x5DD84BC4},
                {0x4C5FCE800000000, 0x5C98BF9D},
                {0xCC0DE5BF00000000, 0x5F4C0DE6},
                {0x200000000, 0x50000000},
                {0x300000000, 0x50400000},
                {0x400000000, 0x50800000},
                {0x500000000, 0x50A00000},
                {0x800000000, 0x51000000},
                {0x900000000, 0x51100000},
                {0x273A798E187937A3, 0x5E1CE9E6},
                {0xECE3AF835495A16B, 0x5F6CE3B0},
                {0xB668ECC11223344, 0x5D3668ED},
                {0x9E, 0x431E0000},
                {0x43, 0x42860000},
                {0xAF73, 0x472F7300},
                {0x116B, 0x458B5800},
                {0x658ECC, 0x4ACB1D98},
                {0x2B3B4C, 0x4A2CED30},
                {0x88776655, 0x4F087766},
                {0x70000000, 0x4EE00000},
                {0x7200000, 0x4CE40000},
                {0x7FFFFFFF, 0x4F000000},
                {0x56123761, 0x4EAC246F},
                {0x7FFFFF00, 0x4EFFFFFE},
                {0x761C4761EEEEEEEE, 0x5EEC388F},
                {0x80000000EEEEEEEE, 0x5F000000},
                {0x88888888DDDDDDDD, 0x5F088889},
                {0xA0000000DDDDDDDD, 0x5F200000},
                {0xDDDDDDDDAAAAAAAA, 0x5F5DDDDE},
                {0xE0000000AAAAAAAA, 0x5F600000},
                {0xEEEEEEEEEEEEEEEE, 0x5F6EEEEF},
                {0xFFFFFFFDEEEEEEEE, 0x5F800000},
                {0xF0000000DDDDDDDD, 0x5F700000},
                {0x7FFFFFDDDDDDDD, 0x5B000000},
                {0x3FFFFFAAAAAAAA, 0x5A7FFFFF},
                {0x1FFFFFAAAAAAAA, 0x59FFFFFD},
                {0xFFFFF, 0x497FFFF0},
                {0x7FFFF, 0x48FFFFE0},
                {0x3FFFF, 0x487FFFC0},
                {0x1FFFF, 0x47FFFF80},
                {0xFFFF, 0x477FFF00},
                {0x7FFF, 0x46FFFE00},
                {0x3FFF, 0x467FFC00},
                {0x1FFF, 0x45FFF800},
                {0xFFF, 0x457FF000},
                {0x7FF, 0x44FFE000},
                {0x3FF, 0x447FC000},
                {0x1FF, 0x43FF8000},
                {0x3FFFFFFFFFFF, 0x56800000},
                {0x1FFFFFFFFFFF, 0x56000000},
                {0xFFFFFFFFFFF, 0x55800000},
                {0x7FFFFFFFFFF, 0x55000000},
                {0x3FFFFFFFFFF, 0x54800000},
                {0x1FFFFFFFFFF, 0x54000000},
                {0x8000008000000000, 0x5F000000},
                {0x8000008000000001, 0x5F000001},
                {0x8000000000000400, 0x5F000000},
                {0x8000000000000401, 0x5F000000}};

  BufferedRawMachineAssemblerTester<float> m(MachineType::Uint64());
  m.Return(m.RoundUint64ToFloat32(m.Parameter(0)));

  for (size_t i = 0; i < arraysize(values); i++) {
    CHECK_EQ(base::bit_cast<float>(values[i].expected),
             m.Call(values[i].input));
  }
}


#endif


TEST(RunBitcastFloat32ToInt32) {
  float input = 32.25;
  RawMachineAssemblerTester<int32_t> m;
  m.Return(m.BitcastFloat32ToInt32(
      m.LoadFromPointer(&input, MachineType::Float32())));
  FOR_FLOAT32_INPUTS(i) {
    input = i;
    int32_t expected = base::bit_cast<int32_t>(input);
    CHECK_EQ(expected, m.Call());
  }
}


TEST(RunRoundInt32ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Int32());
  m.Return(m.RoundInt32ToFloat32(m.Parameter(0)));
  FOR_INT32_INPUTS(i) {
    volatile float expected = static_cast<float>(i);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunRoundUint32ToFloat32) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Uint32());
  m.Return(m.RoundUint32ToFloat32(m.Parameter(0)));
  FOR_UINT32_INPUTS(i) {
    volatile float expected = static_cast<float>(i);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunBitcastInt32ToFloat32) {
  int32_t input = 1;
  Float32 output;
  RawMachineAssemblerTester<int32_t> m;
  m.StoreToPointer(
      output.get_bits_address(), MachineRepresentation::kFloat32,
      m.BitcastInt32ToFloat32(m.LoadFromPointer(&input, MachineType::Int32())));
  m.Return(m.Int32Constant(11));
  FOR_INT32_INPUTS(i) {
    input = i;
    CHECK_EQ(11, m.Call());
    Float32 expected = Float32::FromBits(input);
    CHECK_EQ(expected.get_bits(), output.get_bits());
  }
}


TEST(RunComputedCodeObject) {
  RawMachineAssemblerTester<int32_t> a;
  a.Return(a.Int32Constant(33));
  CHECK_EQ(33, a.Call());

  RawMachineAssemblerTester<int32_t> b;
  b.Return(b.Int32Constant(44));
  CHECK_EQ(44, b.Call());

  RawMachineAssemblerTester<int32_t> r(MachineType::Int32());
  RawMachineLabel tlabel;
  RawMachineLabel flabel;
  RawMachineLabel merge;
  r.Branch(r.Parameter(0), &tlabel, &flabel);
  r.Bind(&tlabel);
  Node* fa = r.HeapConstant(a.GetCode());
  r.Goto(&merge);
  r.Bind(&flabel);
  Node* fb = r.HeapConstant(b.GetCode());
  r.Goto(&merge);
  r.Bind(&merge);
  Node* phi = r.Phi(MachineRepresentation::kWord32, fa, fb);

  // TODO(titzer): all this descriptor hackery is just to call the above
  // functions as code objects instead of direct addresses.
  CSignatureOf<int32_t> sig;
  CallDescriptor* c = Linkage::GetSimplifiedCDescriptor(r.zone(), &sig);
  LinkageLocation ret[] = {c->GetReturnLocation(0)};
  Signature<LinkageLocation> loc(1, 0, ret);
  auto call_descriptor = r.zone()->New<CallDescriptor>(  // --
      CallDescriptor::kCallCodeObject,                   // kind
      kDefaultCodeEntrypointTag,                         // tag
      MachineType::AnyTagged(),                          // target_type
      c->GetInputLocation(0),                            // target_loc
      &loc,                                              // location_sig
      0,                                                 // stack count
      Operator::kNoProperties,                           // properties
      c->CalleeSavedRegisters(),                         // callee saved
      c->CalleeSavedFPRegisters(),                       // callee saved FP
      CallDescriptor::kNoFlags,                          // flags
      "c-call-as-code");
  Node* call = r.AddNode(r.common()->Call(call_descriptor), phi);
  r.Return(call);

  CHECK_EQ(33, r.Call(1));
  CHECK_EQ(44, r.Call(0));
}

TEST(ParentFramePointer) {
  RawMachineAssemblerTester<int32_t> r(MachineType::Int32());
  RawMachineLabel tlabel;
  RawMachineLabel flabel;
  RawMachineLabel merge;
  Node* frame = r.LoadFramePointer();
  Node* parent_frame = r.LoadParentFramePointer();
  frame = r.Load(MachineType::IntPtr(), frame);
  r.Branch(r.WordEqual(frame, parent_frame), &tlabel, &flabel);
  r.Bind(&tlabel);
  Node* fa = r.Int32Constant(1);
  r.Goto(&merge);
  r.Bind(&flabel);
  Node* fb = r.Int32Constant(0);
  r.Goto(&merge);
  r.Bind(&merge);
  Node* phi = r.Phi(MachineRepresentation::kWord32, fa, fb);
  r.Return(phi);
  CHECK_EQ(1, r.Call(1));
}

#if V8_TARGET_ARCH_64_BIT

TEST(Regression5923) {
  {
    BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64());
    m.Return(m.Int64Add(
        m.Word64Shr(m.Parameter(0), m.Int64Constant(4611686018427387888)),
        m.Parameter(0)));
    int64_t input = 16;
    m.Call(input);
  }
  {
    BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64());
    m.Return(m.Int64Add(
        m.Parameter(0),
        m.Word64Shr(m.Parameter(0), m.Int64Constant(4611686018427387888))));
    int64_t input = 16;
    m.Call(input);
  }
}

TEST(Regression5951) {
  BufferedRawMachineAssemblerTester<int64_t> m(MachineType::Int64());
  m.Return(m.Word64And(m.Word64Shr(m.Parameter(0), m.Int64Constant(0)),
                       m.Int64Constant(0xFFFFFFFFFFFFFFFFl)));
  int64_t input = 1234;
  CHECK_EQ(input, m.Call(input));
}

TEST(Regression6046a) {
  BufferedRawMachineAssemblerTester<int64_t> m;
  m.Return(m.Word64Shr(m.Word64And(m.Int64Constant(0), m.Int64Constant(0)),
                       m.Int64Constant(64)));
  CHECK_EQ(0, m.Call());
}

TEST(Regression6122) {
  BufferedRawMachineAssemblerTester<int64_t> m;
  m.Return(m.Word64Shr(m.Word64And(m.Int64Constant(59), m.Int64Constant(-1)),
                       m.Int64Constant(0)));
  CHECK_EQ(59, m.Call());
}

#endif  // V8_TARGET_ARCH_64_BIT

TEST(Regression6046b) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(0), m.Int32Constant(0)),
                       m.Int32Constant(32)));
  CHECK_EQ(0, m.Call());
}

TEST(Regression6122b) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  m.Return(m.Word32Shr(m.Word32And(m.Int32Constant(59), m.Int32Constant(-1)),
                       m.Int32Constant(0)));
  CHECK_EQ(59, m.Call());
}

TEST(Regression6028) {
  BufferedRawMachineAssemblerTester<int32_t> m;
  m.Return(m.Word32Equal(
      m.Word32And(m.Int32Constant(0x23),
                  m.Word32Sar(m.Int32Constant(1), m.Int32Constant(18))),
      m.Int32Constant(0)));
  CHECK_EQ(1, m.Call());
}

TEST(Regression5951_32bit) {
  BufferedRawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  m.Return(m.Word32And(m.Word32Shr(m.Parameter(0), m.Int32Constant(0)),
                       m.Int32Constant(0xFFFFFFFF)));
  int32_t input = 1234;
  CHECK_EQ(input, m.Call(input));
}

TEST(Regression738952) {
  RawMachineAssemblerTester<int32_t> m;

  int32_t sentinel = 1234;
  // The index can be any value where the lower bits are 0 and the upper bits
  // are not 0;
  int64_t index = 3224;
  index <<= 32;
  double d = static_cast<double>(index);
  m.Return(m.Load(MachineType::Int32(), m.PointerConstant(&sentinel),
                  m.TruncateFloat64ToWord32(m.Float64Constant(d))));
  CHECK_EQ(sentinel, m.Call());
}

#if V8_TARGET_ARCH_64_BIT
TEST(Regression12373) {
  FOR_INT64_INPUTS(i) {
    RawMachineAssemblerTester<int64_t> m(MachineType::Int64(),
                                         MachineType::Int64());
    RawMachineAssemblerTester<int64_t> n(MachineType::Int64());

    Node* mul_rr = m.Int64Mul(m.Parameter(0), m.Parameter(1));
    Node* mul_ri = n.Int64Mul(n.Parameter(0), n.Int64Constant(i));
    m.Return(mul_rr);
    n.Return(mul_ri);
    FOR_INT64_INPUTS(j) { CHECK_EQ(m.Call(j, i), n.Call(j)); }
  }
}
#endif  // V8_TARGET_ARCH_64_BIT

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```