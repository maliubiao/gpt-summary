Response:
The user wants a summary of the provided C++ code snippet.
This code appears to be a series of unit tests for MIPS64 assembly instructions, specifically those related to the MSA (MIPS SIMD Architecture) extension.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The code contains numerous `TEST()` macros, which immediately suggests unit testing. The filenames and keywords like "assembler" and "MIPS64" point to testing assembly instructions for the MIPS64 architecture. The "MSA" prefix further narrows it down to the MIPS SIMD Architecture.

2. **Recognize Test Structure:** Each `TEST()` block generally follows a pattern:
    - Check for architecture and CPU feature support (`kArchVariant != kMips64r6` and `!CpuFeatures::IsSupported(MIPS_SIMD)`).
    - Initialize the VM (`CcTest::InitializeVM()`).
    - Define constants for testing (e.g., `inf_float`, `max_int32`).
    - Define test case structures (e.g., `TestCaseMsa2RF_F_I`).
    - Create arrays of test cases (`tc_s`, `tc_d`).
    - Loop through the test cases.
    - Call `run_msa_2r` (or `run_msa_vector`, `run_msa_bit`), passing a lambda function that defines the assembly instruction to be tested.
    - The `run_msa_...` functions likely execute the generated assembly code with the provided input and compare the result against the expected output (although the comparison logic isn't directly visible in this snippet).

3. **Categorize Tested Instructions:**  Scan through the `TEST()` names and the assembly instructions within the lambdas (e.g., `ftrunc_s_w`, `fsqrt_w`, `flog2_d`, `and_v`, `slli`). Group these instructions by their general function:
    - **Floating-point conversions:** `ftrunc`, `ftint`, `ffint`
    - **Floating-point arithmetic:** `fsqrt`, `frsqrt`, `frcp`, `flog2`
    - **Floating-point manipulation:** `fexupl`, `fexupr`, `ffql`, `ffqr`
    - **Vector logical operations:** `and_v`, `or_v`, `nor_v`, `xor_v`, `bmnz_v`, `bmz_v`, `bsel_v`
    - **Vector bitwise shift operations:** `slli`, `srai`, `srli`

4. **Identify Test Case Structures:** Notice the different `TestCaseMsa2RF...` structs. These seem to define the input values and expected results for the instructions. The suffixes like `_F_I`, `_D_D`, `_U_F` likely indicate the data types involved (Float, Integer, Double, Unsigned).

5. **Infer the Role of `run_msa_...`:** Although the implementation isn't shown, the function names and the way they're used strongly suggest that they:
    - Take test case data.
    - Generate assembly code using the provided lambda.
    - Execute the generated code.
    - Compare the actual output with the expected output stored in the test case.

6. **Address Specific Questions:**
    - **File Type:** The filename ends in `.cc`, so it's C++, not Torque.
    - **JavaScript Relationship:** This code tests low-level assembly instructions. While these instructions are eventually used to implement JavaScript features (especially number operations), the direct relationship isn't immediately obvious from *this specific snippet*. Need to think about examples where these kinds of operations are used in JS (e.g., `Math.trunc`, `Math.sqrt`, bitwise operators).
    - **Code Logic Reasoning:**  The test cases themselves provide the "logic."  For example, for `ftrunc_s_w`, a floating-point number is input, and the expected output is its truncated integer representation.
    - **Common Programming Errors:**  Think about errors related to data type conversions, floating-point precision, and bitwise operations.

7. **Synthesize the Summary:** Combine the observations into a concise description of the file's purpose and functionality. Highlight the key areas being tested and the nature of the tests.

8. **Structure the Output:** Organize the information clearly, addressing each part of the user's request (functionality, Torque status, JavaScript relation, logic reasoning, programming errors, overall function).
这是一个v8源代码文件 `v8/test/cctest/test-assembler-mips64.cc` 的第 9 部分，共 13 部分。从代码片段来看，这个文件主要包含针对 **MIPS64 架构** 的 **汇编器 (Assembler)** 进行单元测试的代码。更具体地说，它测试了 **MSA (MIPS SIMD Architecture)** 扩展指令的功能。

以下是代码片段中体现的功能归纳：

**功能：**

* **测试 MSA 浮点数截断指令:**
    * `ftrunc_s_w`: 将单精度浮点数截断为带符号的 32 位整数。
    * `ftrunc_u_w`: 将单精度浮点数截断为无符号的 32 位整数。
    * `ftrunc_s_d`: 将双精度浮点数截断为带符号的 32 位整数。
    * `ftrunc_u_d`: 将双精度浮点数截断为无符号的 32 位整数。
* **测试 MSA 浮点数平方根指令:**
    * `fsqrt_w`: 计算单精度浮点数的平方根。
    * `fsqrt_d`: 计算双精度浮点数的平方根。
* **测试 MSA 浮点数倒数平方根近似指令:**
    * `frsqrt_w`: 计算单精度浮点数的倒数平方根近似值。
    * `frsqrt_d`: 计算双精度浮点数的倒数平方根近似值。
* **测试 MSA 浮点数倒数近似指令:**
    * `frcp_w`: 计算单精度浮点数的倒数近似值。
    * `frcp_d`: 计算双精度浮点数的倒数近似值。
* **测试 MSA 浮点数舍入到整数指令:**
    * `frint_w`: 将单精度浮点数舍入到最接近的整数，可以指定不同的舍入模式（例如，最近舍入、向零舍入、向上舍入、向下舍入）。
    * `frint_d`: 将双精度浮点数舍入到最接近的整数，可以指定不同的舍入模式。
* **测试 MSA 浮点数以 2 为底的对数指令:**
    * `flog2_w`: 计算单精度浮点数以 2 为底的对数。
    * `flog2_d`: 计算双精度浮点数以 2 为底的对数。
* **测试 MSA 浮点数转换为带符号整数指令:**
    * `ftint_s_w`: 将单精度浮点数转换为带符号的 32 位整数，可以指定不同的舍入模式。
    * `ftint_s_d`: 将双精度浮点数转换为带符号的 32 位整数，可以指定不同的舍入模式。
* **测试 MSA 浮点数转换为无符号整数指令:**
    * `ftint_u_w`: 将单精度浮点数转换为无符号的 32 位整数，可以指定不同的舍入模式。
    * `ftint_u_d`: 将双精度浮点数转换为无符号的 32 位整数，可以指定不同的舍入模式。
* **测试 MSA 从带符号/无符号整数转换为浮点数指令:**
    * `ffint_u_w`: 将无符号 32 位整数转换为单精度浮点数。
    * `ffint_u_d`: 将无符号 64 位整数转换为双精度浮点数。
    * `ffint_s_w`: 将带符号 32 位整数转换为单精度浮点数。
    * `ffint_s_d`: 将带符号 64 位整数转换为双精度浮点数。
* **测试 MSA 浮点数扩展指令:**
    * `fexupl_w`: 从 16 位无符号整数扩展为单精度浮点数 (低半部分)。
    * `fexupl_d`: 从单精度浮点数扩展为双精度浮点数 (低半部分)。
    * `fexupr_w`: 从 16 位无符号整数扩展为单精度浮点数 (高半部分)。
    * `fexupr_d`: 从单精度浮点数扩展为双精度浮点数 (高半部分)。
* **测试 MSA 浮点数四舍五入到最接近偶数指令 (看起来像)：**
    * `ffql_w`:  (根据上下文推测，可能与单精度浮点数的四舍五入到最接近偶数有关)
    * `ffql_d`:  (根据上下文推测，可能与双精度浮点数的四舍五入到最接近偶数有关)
    * `ffqr_w`:  (根据上下文推测，可能与单精度浮点数的四舍五入到最接近偶数有关)
    * `ffqr_d`:  (根据上下文推测，可能与双精度浮点数的四舍五入到最接近偶数有关)
* **测试 MSA 向量逻辑运算指令:**
    * `and_v`: 向量按位与。
    * `or_v`: 向量按位或。
    * `nor_v`: 向量按位或非。
    * `xor_v`: 向量按位异或。
    * `bmnz_v`:  根据掩码进行位合并（如果掩码位为 1，则取源向量的位；否则取目标向量的位）。
    * `bmz_v`:  根据掩码进行位合并（如果掩码位为 0，则取源向量的位；否则取目标向量的位）。
    * `bsel_v`: 向量位选择。
* **测试 MSA 向量移位指令:**
    * `slli`: 向量逻辑左移立即数。
    * `srai`: 向量算术右移立即数。
    * `srli`: 向量逻辑右移立即数。

**关于文件类型:**

`v8/test/cctest/test-assembler-mips64.cc` 以 `.cc` 结尾，因此它是一个 **C++** 源代码文件，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系：**

这个文件中的测试代码直接测试的是 MIPS64 架构的汇编指令。这些指令是 JavaScript 引擎在底层执行 JavaScript 代码的基础。例如：

* **浮点数运算:**  JavaScript 中的 Number 类型使用 IEEE 754 双精度浮点数。当你在 JavaScript 中进行算术运算（例如加减乘除、`Math.sqrt()`、`Math.trunc()` 等）时，V8 引擎最终会将这些操作转换为底层的浮点数汇编指令来执行。
* **位运算:** JavaScript 中的位运算符（例如 `&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`）会直接映射到相应的位操作汇编指令。

**JavaScript 示例：**

```javascript
// 浮点数截断
let floatValue = 3.14;
let truncatedInt = Math.trunc(floatValue); // 相当于 ftrunc 指令
console.log(truncatedInt); // 输出 3

// 浮点数平方根
let number = 9;
let squareRoot = Math.sqrt(number); // 相当于 fsqrt 指令
console.log(squareRoot); // 输出 3

// 位运算
let a = 5;   // 二进制: 0101
let b = 3;   // 二进制: 0011
let andResult = a & b;  // 相当于 and_v 指令 (在向量化的情况下)
console.log(andResult); // 输出 1 (二进制: 0001)
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST(MSA_ftrunc_s)` 中的一个测试用例为例：

```c++
{inf_float, 2.345f, -324.9235f, 30004.51f, max_int32, 2, -324, 30004}
```

* **假设输入 (w0 寄存器):**  由于测试的是 `ftrunc_s_w(w2, w0)`，`w0` 寄存器会加载 `tc_s` 数组中的前四个单精度浮点数。
* **操作:** `ftrunc_s_w` 指令会将 `w0` 寄存器中的每个浮点数截断为带符号的 32 位整数，并将结果放入 `w2` 寄存器中对应的位置。
* **预期输出 (w2 寄存器):**  `w2` 寄存器应该包含 `tc_s` 数组中的后四个整数值。
    * `inf_float` 截断为 `max_int32` (可能会有溢出或饱和行为，这里假设是最大值)
    * `2.345f` 截断为 `2`
    * `-324.9235f` 截断为 `-324`
    * `30004.51f` 截断为 `30004`

**用户常见的编程错误举例：**

* **浮点数到整数的隐式转换导致精度丢失:**

```javascript
let floatNum = 3.999;
let intNum = floatNum; // 隐式转换为整数
console.log(intNum);   // 输出 3，精度丢失，可能与 ftrunc 行为类似但有区别
```

* **位运算中的数据类型错误:**

```javascript
let largeNumber = 0xFFFFFFFF00000000; // 大于 32 位的数字
let maskedValue = largeNumber & 0xFF; // 位运算通常在 32 位整数上进行
console.log(maskedValue); // 结果可能不是你期望的，因为 JavaScript 的位运算符在内部会转换为 32 位整数进行操作。
```

* **不理解浮点数舍入模式的影响:**

```javascript
let num = 4.5;
let roundedUp = Math.round(num);    // 默认四舍五入到最接近的整数
let truncated = Math.trunc(num);   // 向零截断
console.log(roundedUp); // 输出 5
console.log(truncated); // 输出 4
```

**总结第 9 部分的功能：**

这部分代码主要集中测试了 MIPS64 架构 MSA 扩展中的 **浮点数转换、基本运算（平方根、倒数等）、舍入、对数以及向量逻辑和移位指令** 的正确性。它通过定义不同的测试用例，并运行生成的汇编代码，来验证这些指令在各种输入下的行为是否符合预期。这是 V8 引擎确保其在 MIPS64 架构上正确执行 JavaScript 代码的关键组成部分。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
alizeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const float qNaN_float = std::numeric_limits<float>::quiet_NaN();
  const double inf_double = std::numeric_limits<double>::infinity();
  const double qNaN_double = std::numeric_limits<double>::quiet_NaN();
  const int32_t max_int32 = std::numeric_limits<int32_t>::max();
  const int32_t min_int32 = std::numeric_limits<int32_t>::min();
  const int64_t max_int64 = std::numeric_limits<int64_t>::max();
  const int64_t min_int64 = std::numeric_limits<int64_t>::min();

  const struct TestCaseMsa2RF_F_I tc_s[] = {
      {inf_float, 2.345f, -324.9235f, 30004.51f, max_int32, 2, -324, 30004},
      {-inf_float, -0.983f, 0.0832f, static_cast<float>(max_int32) * 3.f,
       min_int32, 0, 0, max_int32},
      {-23.125f, qNaN_float, 2 * static_cast<float>(min_int32), -0.f, -23, 0,
       min_int32, 0}};

  const struct TestCaseMsa2RF_D_I tc_d[] = {
      {inf_double, 2.345, max_int64, 2},
      {-324.9235, 246569139.51, -324, 246569139},
      {-inf_double, -0.983, min_int64, 0},
      {0.0832, 6 * static_cast<double>(max_int64), 0, max_int64},
      {-21453889872.94, qNaN_double, -21453889872, 0},
      {2 * static_cast<double>(min_int64), -0., min_int64, 0}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_I); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ ftrunc_s_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_I); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ ftrunc_s_d(w2, w0); });
  }
}

TEST(MSA_ftrunc_u) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const float qNaN_float = std::numeric_limits<float>::quiet_NaN();
  const double inf_double = std::numeric_limits<double>::infinity();
  const double qNaN_double = std::numeric_limits<double>::quiet_NaN();
  const uint32_t max_uint32 = std::numeric_limits<uint32_t>::max();
  const uint64_t max_uint64 = std::numeric_limits<uint64_t>::max();

  const struct TestCaseMsa2RF_F_U tc_s[] = {
      {inf_float, 2.345f, -324.9235f, 30004.51f, max_uint32, 2, 0, 30004},
      {-inf_float, 0.983f, 0.0832f, static_cast<float>(max_uint32) * 3., 0, 0,
       0, max_uint32},
      {23.125f, qNaN_float, -0.982, -0.f, 23, 0, 0, 0}};

  const struct TestCaseMsa2RF_D_U tc_d[] = {
      {inf_double, 2.345, max_uint64, 2},
      {-324.9235, 246569139.51, 0, 246569139},
      {-inf_double, -0.983, 0, 0},
      {0.0832, 6 * static_cast<double>(max_uint64), 0, max_uint64},
      {21453889872.94, qNaN_double, 21453889872, 0},
      {0.9889, -0., 0, 0}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ ftrunc_u_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ ftrunc_u_d(w2, w0); });
  }
}

struct TestCaseMsa2RF_F_F {
  float ws1;
  float ws2;
  float ws3;
  float ws4;
  float exp_res_1;
  float exp_res_2;
  float exp_res_3;
  float exp_res_4;
};

struct TestCaseMsa2RF_D_D {
  double ws1;
  double ws2;
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_fsqrt) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa2RF_F_F tc_s[] = {
      {81.f, 576.f, inf_float, -0.f, 9.f, 24.f, inf_float, -0.f}};

  const struct TestCaseMsa2RF_D_D tc_d[] = {{81., inf_double, 9., inf_double},
                                            {331776., -0., 576, -0.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ fsqrt_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ fsqrt_d(w2, w0); });
  }
}

TEST(MSA_frsqrt) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa2RF_F_F tc_s[] = {
      {81.f, 576.f, inf_float, -0.f, 1.f / 9.f, 1.f / 24.f, 0.f, -inf_float},
      {0.f, 1.f / 576.f, 1.f / 81.f, 1.f / 4.f, inf_float, 24.f, 9.f, 2.f}};

  const struct TestCaseMsa2RF_D_D tc_d[] = {
      {81., inf_double, 1. / 9., 0.},
      {331776., -0., 1. / 576., -inf_double},
      {0., 1. / 81, inf_double, 9.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ frsqrt_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ frsqrt_d(w2, w0); });
  }
}

TEST(MSA_frcp) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa2RF_F_F tc_s[] = {
      {12.f, 576.f, inf_float, -0.f, 1.f / 12.f, 1.f / 576.f, 0.f, -inf_float},
      {0.f, 1.f / 576.f, -inf_float, 1.f / 400.f, inf_float, 576.f, -0.f,
       400.f}};

  const struct TestCaseMsa2RF_D_D tc_d[] = {
      {81., inf_double, 1. / 81., 0.},
      {331777., -0., 1. / 331777., -inf_double},
      {0., 1. / 80, inf_double, 80.},
      {1. / 40000., -inf_double, 40000., -0.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ frcp_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ frcp_d(w2, w0); });
  }
}

void test_frint_s(size_t data_size, TestCaseMsa2RF_F_F tc_d[],
                  int rounding_mode) {
  for (size_t i = 0; i < data_size / sizeof(TestCaseMsa2RF_F_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [&rounding_mode](MacroAssembler& assm) {
                 MSAControlRegister msareg = {kMSACSRRegister};
                 __ li(t0, static_cast<uint32_t>(rounding_mode));
                 __ cfcmsa(t1, msareg);
                 __ ctcmsa(msareg, t0);
                 __ frint_w(w2, w0);
                 __ ctcmsa(msareg, t1);
               });
  }
}

void test_frint_d(size_t data_size, TestCaseMsa2RF_D_D tc_d[],
                  int rounding_mode) {
  for (size_t i = 0; i < data_size / sizeof(TestCaseMsa2RF_D_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [&rounding_mode](MacroAssembler& assm) {
                 MSAControlRegister msareg = {kMSACSRRegister};
                 __ li(t0, static_cast<uint32_t>(rounding_mode));
                 __ cfcmsa(t1, msareg);
                 __ ctcmsa(msareg, t0);
                 __ frint_d(w2, w0);
                 __ ctcmsa(msareg, t1);
               });
  }
}

TEST(MSA_frint) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2RF_F_F tc_s1[] = {
      {0.f, 4.51f, 1.49f, -12.51f, 0.f, 5.f, 1.f, -13.f},
      {-1.32f, -23.38f, 2.8f, -32.6f, -1.f, -23.f, 3.f, -33.f}};

  struct TestCaseMsa2RF_D_D tc_d1[] = {{0., 4.51, 0., 5.},
                                       {1.49, -12.51, 1., -13.},
                                       {-1.32, -23.38, -1., -23.},
                                       {2.8, -32.6, 3., -33.}};

  test_frint_s(sizeof(tc_s1), tc_s1, kRoundToNearest);
  test_frint_d(sizeof(tc_d1), tc_d1, kRoundToNearest);

  struct TestCaseMsa2RF_F_F tc_s2[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0.f, 4.f, 1.f, -12.f},
      {-1.f, -23.38f, 2.8f, -32.6f, -1.f, -23.f, 2.f, -32.f}};

  struct TestCaseMsa2RF_D_D tc_d2[] = {{0., 4.5, 0., 4.},
                                       {1.49, -12.51, 1., -12.},
                                       {-1., -23.38, -1., -23.},
                                       {2.8, -32.6, 2., -32.}};

  test_frint_s(sizeof(tc_s2), tc_s2, kRoundToZero);
  test_frint_d(sizeof(tc_d2), tc_d2, kRoundToZero);

  struct TestCaseMsa2RF_F_F tc_s3[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0.f, 5.f, 2.f, -12.f},
      {-1.f, -23.38f, 2.8f, -32.6f, -1.f, -23.f, 3.f, -32.f}};

  struct TestCaseMsa2RF_D_D tc_d3[] = {{0., 4.5, 0., 5.},
                                       {1.49, -12.51, 2., -12.},
                                       {-1., -23.38, -1., -23.},
                                       {2.8, -32.6, 3., -32.}};

  test_frint_s(sizeof(tc_s3), tc_s3, kRoundToPlusInf);
  test_frint_d(sizeof(tc_d3), tc_d3, kRoundToPlusInf);

  struct TestCaseMsa2RF_F_F tc_s4[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0.f, 4.f, 1.f, -13.f},
      {-1.f, -23.38f, 2.8f, -32.6f, -1.f, -24.f, 2.f, -33.f}};

  struct TestCaseMsa2RF_D_D tc_d4[] = {{0., 4.5, 0., 4.},
                                       {1.49, -12.51, 1., -13.},
                                       {-1., -23.38, -1., -24.},
                                       {2.8, -32.6, 2., -33.}};

  test_frint_s(sizeof(tc_s4), tc_s4, kRoundToMinusInf);
  test_frint_d(sizeof(tc_d4), tc_d4, kRoundToMinusInf);
}

TEST(MSA_flog2) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  struct TestCaseMsa2RF_F_F tc_s[] = {
      {std::ldexp(0.58f, -48), std::ldexp(0.5f, 110), std::ldexp(1.11f, -130),
       inf_float, -49.f, 109.f, -130.f, inf_float},
      {0.f, -0.f, std::ldexp(0.89f, -12), std::ldexp(0.32f, 126), -inf_float,
       -inf_float, -13.f, 124.f}};

  struct TestCaseMsa2RF_D_D tc_d[] = {
      {std::ldexp(0.58, -48), std::ldexp(0.5, 110), -49., 109.},
      {std::ldexp(1.11, -1050), inf_double, -1050., inf_double},
      {0., -0., -inf_double, -inf_double},
      {std::ldexp(0.32, 1021), std::ldexp(1.23, -123), 1019., -123.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ flog2_w(w2, w0); });
  }

  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ flog2_d(w2, w0); });
  }
}

void test_ftint_s_s(size_t data_size, TestCaseMsa2RF_F_I tc_d[],
                    int rounding_mode) {
  for (size_t i = 0; i < data_size / sizeof(TestCaseMsa2RF_F_I); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [&rounding_mode](MacroAssembler& assm) {
                 MSAControlRegister msareg = {kMSACSRRegister};
                 __ li(t0, static_cast<uint32_t>(rounding_mode));
                 __ cfcmsa(t1, msareg);
                 __ ctcmsa(msareg, t0);
                 __ ftint_s_w(w2, w0);
                 __ ctcmsa(msareg, t1);
               });
  }
}

void test_ftint_s_d(size_t data_size, TestCaseMsa2RF_D_I tc_d[],
                    int rounding_mode) {
  for (size_t i = 0; i < data_size / sizeof(TestCaseMsa2RF_D_I); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [&rounding_mode](MacroAssembler& assm) {
                 MSAControlRegister msareg = {kMSACSRRegister};
                 __ li(t0, static_cast<uint32_t>(rounding_mode));
                 __ cfcmsa(t1, msareg);
                 __ ctcmsa(msareg, t0);
                 __ ftint_s_d(w2, w0);
                 __ ctcmsa(msareg, t1);
               });
  }
}

TEST(MSA_ftint_s) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();
  const int32_t int32_max = std::numeric_limits<int32_t>::max();
  const int32_t int32_min = std::numeric_limits<int32_t>::min();
  const int64_t int64_max = std::numeric_limits<int64_t>::max();
  const int64_t int64_min = std::numeric_limits<int64_t>::min();

  struct TestCaseMsa2RF_F_I tc_s1[] = {
      {0.f, 4.51f, 1.49f, -12.51f, 0, 5, 1, -13},
      {-0.32f, -23.38f, 2.8f, -32.6f, 0, -23, 3, -33},
      {inf_float, -inf_float, 3.f * int32_min, 4.f * int32_max, int32_max,
       int32_min, int32_min, int32_max}};

  struct TestCaseMsa2RF_D_I tc_d1[] = {
      {0., 4.51, 0, 5},
      {1.49, -12.51, 1, -13},
      {-0.32, -23.38, 0, -23},
      {2.8, -32.6, 3, -33},
      {inf_double, -inf_double, int64_max, int64_min},
      {33.23 * int64_min, 4000. * int64_max, int64_min, int64_max}};

  test_ftint_s_s(sizeof(tc_s1), tc_s1, kRoundToNearest);
  test_ftint_s_d(sizeof(tc_d1), tc_d1, kRoundToNearest);

  struct TestCaseMsa2RF_F_I tc_s2[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0, 4, 1, -12},
      {-0.f, -23.38f, 2.8f, -32.6f, -0, -23, 2, -32},
      {inf_float, -inf_float, 3.f * int32_min, 4.f * int32_max, int32_max,
       int32_min, int32_min, int32_max}};

  struct TestCaseMsa2RF_D_I tc_d2[] = {
      {0., 4.5, 0, 4},
      {1.49, -12.51, 1, -12},
      {-0., -23.38, -0, -23},
      {2.8, -32.6, 2, -32},
      {inf_double, -inf_double, int64_max, int64_min},
      {33.23 * int64_min, 4000. * int64_max, int64_min, int64_max}};

  test_ftint_s_s(sizeof(tc_s2), tc_s2, kRoundToZero);
  test_ftint_s_d(sizeof(tc_d2), tc_d2, kRoundToZero);

  struct TestCaseMsa2RF_F_I tc_s3[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0, 5, 2, -12},
      {-0.f, -23.38f, 2.8f, -32.6f, -0, -23, 3, -32},
      {inf_float, -inf_float, 3.f * int32_min, 4.f * int32_max, int32_max,
       int32_min, int32_min, int32_max}};

  struct TestCaseMsa2RF_D_I tc_d3[] = {
      {0., 4.5, 0, 5},
      {1.49, -12.51, 2, -12},
      {-0., -23.38, -0, -23},
      {2.8, -32.6, 3, -32},
      {inf_double, -inf_double, int64_max, int64_min},
      {33.23 * int64_min, 4000. * int64_max, int64_min, int64_max}};

  test_ftint_s_s(sizeof(tc_s3), tc_s3, kRoundToPlusInf);
  test_ftint_s_d(sizeof(tc_d3), tc_d3, kRoundToPlusInf);

  struct TestCaseMsa2RF_F_I tc_s4[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0, 4, 1, -13},
      {-0.f, -23.38f, 2.8f, -32.6f, -0, -24, 2, -33},
      {inf_float, -inf_float, 3.f * int32_min, 4.f * int32_max, int32_max,
       int32_min, int32_min, int32_max}};

  struct TestCaseMsa2RF_D_I tc_d4[] = {
      {0., 4.5, 0, 4},
      {1.49, -12.51, 1, -13},
      {-0., -23.38, -0, -24},
      {2.8, -32.6, 2, -33},
      {inf_double, -inf_double, int64_max, int64_min},
      {33.23 * int64_min, 4000. * int64_max, int64_min, int64_max}};

  test_ftint_s_s(sizeof(tc_s4), tc_s4, kRoundToMinusInf);
  test_ftint_s_d(sizeof(tc_d4), tc_d4, kRoundToMinusInf);
}

void test_ftint_u_s(size_t data_size, TestCaseMsa2RF_F_U tc_d[],
                    int rounding_mode) {
  for (size_t i = 0; i < data_size / sizeof(TestCaseMsa2RF_F_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [&rounding_mode](MacroAssembler& assm) {
                 MSAControlRegister msareg = {kMSACSRRegister};
                 __ li(t0, static_cast<uint32_t>(rounding_mode));
                 __ cfcmsa(t1, msareg);
                 __ ctcmsa(msareg, t0);
                 __ ftint_u_w(w2, w0);
                 __ ctcmsa(msareg, t1);
               });
  }
}

void test_ftint_u_d(size_t data_size, TestCaseMsa2RF_D_U tc_d[],
                    int rounding_mode) {
  for (size_t i = 0; i < data_size / sizeof(TestCaseMsa2RF_D_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [&rounding_mode](MacroAssembler& assm) {
                 MSAControlRegister msareg = {kMSACSRRegister};
                 __ li(t0, static_cast<uint32_t>(rounding_mode));
                 __ cfcmsa(t1, msareg);
                 __ ctcmsa(msareg, t0);
                 __ ftint_u_d(w2, w0);
                 __ ctcmsa(msareg, t1);
               });
  }
}

TEST(MSA_ftint_u) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();
  const uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
  const uint64_t uint64_max = std::numeric_limits<uint64_t>::max();

  struct TestCaseMsa2RF_F_U tc_s1[] = {
      {0.f, 4.51f, 1.49f, -12.51f, 0, 5, 1, 0},
      {-0.32f, 23.38f, 2.8f, 32.6f, 0, 23, 3, 33},
      {inf_float, -inf_float, 0, 4.f * uint32_max, uint32_max, 0, 0,
       uint32_max}};

  struct TestCaseMsa2RF_D_U tc_d1[] = {
      {0., 4.51, 0, 5},
      {1.49, -12.51, 1, 0},
      {-0.32, 23.38, 0, 23},
      {2.8, 32.6, 3, 33},
      {inf_double, -inf_double, uint64_max, 0},
      {-0., 4000. * uint64_max, 0, uint64_max}};

  test_ftint_u_s(sizeof(tc_s1), tc_s1, kRoundToNearest);
  test_ftint_u_d(sizeof(tc_d1), tc_d1, kRoundToNearest);

  struct TestCaseMsa2RF_F_U tc_s2[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0, 4, 1, 0},
      {-0.f, 23.38f, 2.8f, 32.6f, 0, 23, 2, 32},
      {inf_float, -inf_float, 0., 4.f * uint32_max, uint32_max, 0, 0,
       uint32_max}};

  struct TestCaseMsa2RF_D_U tc_d2[] = {
      {0., 4.5, 0, 4},
      {1.49, -12.51, 1, 0},
      {-0., 23.38, 0, 23},
      {2.8, 32.6, 2, 32},
      {inf_double, -inf_double, uint64_max, 0},
      {-0.2345, 4000. * uint64_max, 0, uint64_max}};

  test_ftint_u_s(sizeof(tc_s2), tc_s2, kRoundToZero);
  test_ftint_u_d(sizeof(tc_d2), tc_d2, kRoundToZero);

  struct TestCaseMsa2RF_F_U tc_s3[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0, 5, 2, 0},
      {-0.f, 23.38f, 2.8f, 32.6f, 0, 24, 3, 33},
      {inf_float, -inf_float, 0, 4.f * uint32_max, uint32_max, 0, 0,
       uint32_max}};

  struct TestCaseMsa2RF_D_U tc_d3[] = {
      {0., 4.5, 0, 5},
      {1.49, -12.51, 2, 0},
      {-0., 23.38, -0, 24},
      {2.8, 32.6, 3, 33},
      {inf_double, -inf_double, uint64_max, 0},
      {-0.5252, 4000. * uint64_max, 0, uint64_max}};

  test_ftint_u_s(sizeof(tc_s3), tc_s3, kRoundToPlusInf);
  test_ftint_u_d(sizeof(tc_d3), tc_d3, kRoundToPlusInf);

  struct TestCaseMsa2RF_F_U tc_s4[] = {
      {0.f, 4.5f, 1.49f, -12.51f, 0, 4, 1, 0},
      {-0.f, 23.38f, 2.8f, 32.6f, 0, 23, 2, 32},
      {inf_float, -inf_float, 0, 4.f * uint32_max, uint32_max, 0, 0,
       uint32_max}};

  struct TestCaseMsa2RF_D_U tc_d4[] = {
      {0., 4.5, 0, 4},
      {1.49, -12.51, 1, 0},
      {-0., 23.38, -0, 23},
      {2.8, 32.6, 2, 32},
      {inf_double, -inf_double, uint64_max, 0},
      {-0.098797, 4000. * uint64_max, 0, uint64_max}};

  test_ftint_u_s(sizeof(tc_s4), tc_s4, kRoundToMinusInf);
  test_ftint_u_d(sizeof(tc_d4), tc_d4, kRoundToMinusInf);
}

struct TestCaseMsa2RF_U_F {
  uint32_t ws1;
  uint32_t ws2;
  uint32_t ws3;
  uint32_t ws4;
  float exp_res_1;
  float exp_res_2;
  float exp_res_3;
  float exp_res_4;
};

struct TestCaseMsa2RF_U_D {
  uint64_t ws1;
  uint64_t ws2;
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_ffint_u) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2RF_U_F tc_s[] = {
      {0, 345, 234, 1000, 0.f, 345.f, 234.f, 1000.f}};

  struct TestCaseMsa2RF_U_D tc_d[] = {{0, 345, 0., 345.},
                                      {234, 1000, 234., 1000.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_U_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ ffint_u_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_U_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ ffint_u_d(w2, w0); });
  }
}

struct TestCaseMsa2RF_I_F {
  int32_t ws1;
  int32_t ws2;
  int32_t ws3;
  int32_t ws4;
  float exp_res_1;
  float exp_res_2;
  float exp_res_3;
  float exp_res_4;
};

struct TestCaseMsa2RF_I_D {
  int64_t ws1;
  int64_t ws2;
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_ffint_s) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2RF_I_F tc_s[] = {
      {0, 345, -234, 1000, 0.f, 345.f, -234.f, 1000.f}};

  struct TestCaseMsa2RF_I_D tc_d[] = {{0, 345, 0., 345.},
                                      {-234, 1000, -234., 1000.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_I_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ ffint_s_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_I_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ ffint_s_d(w2, w0); });
  }
}

struct TestCaseMsa2RF_U16_F {
  uint16_t ws1;
  uint16_t ws2;
  uint16_t ws3;
  uint16_t ws4;
  uint16_t ws5;
  uint16_t ws6;
  uint16_t ws7;
  uint16_t ws8;
  float exp_res_1;
  float exp_res_2;
  float exp_res_3;
  float exp_res_4;
};

struct TestCaseMsa2RF_F_D {
  float ws1;
  float ws2;
  float ws3;
  float ws4;
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_fexupl) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  struct TestCaseMsa2RF_U16_F tc_s[] = {
      {1, 2, 0x7C00, 0x0C00, 0, 0x7C00, 0xFC00, 0x8000, 0.f, inf_float,
       -inf_float, -0.f},
      {0xFC00, 0xFFFF, 0x00FF, 0x8000, 0x81FE, 0x8000, 0x0345, 0xAAAA,
       -3.0398368835e-5f, -0.f, 4.9889088e-5f, -5.2062988281e-2f},
      {3, 4, 0x5555, 6, 0x2AAA, 0x8700, 0x7777, 0x6A8B, 5.2062988281e-2f,
       -1.06811523458e-4f, 3.0576e4f, 3.35e3f}};

  struct TestCaseMsa2RF_F_D tc_d[] = {
      {0.f, 123.456f, inf_float, -0.f, inf_double, -0.},
      {-inf_float, -3.f, 0.f, -inf_float, 0., -inf_double},
      {2.3f, 3., 1.37747639043129518071e-41f, -3.22084585277826e35f,
       1.37747639043129518071e-41, -3.22084585277826e35}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_U16_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ fexupl_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_F_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ fexupl_d(w2, w0); });
  }
}

TEST(MSA_fexupr) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  struct TestCaseMsa2RF_U16_F tc_s[] = {
      {0, 0x7C00, 0xFC00, 0x8000, 1, 2, 0x7C00, 0x0C00, 0.f, inf_float,
       -inf_float, -0.f},
      {0x81FE, 0x8000, 0x0345, 0xAAAA, 0xFC00, 0xFFFF, 0x00FF, 0x8000,
       -3.0398368835e-5f, -0.f, 4.9889088e-5f, -5.2062988281e-2f},
      {0x2AAA, 0x8700, 0x7777, 0x6A8B, 3, 4, 0x5555, 6, 5.2062988281e-2f,
       -1.06811523458e-4f, 3.0576e4f, 3.35e3f}};

  struct TestCaseMsa2RF_F_D tc_d[] = {
      {inf_float, -0.f, 0.f, 123.456f, inf_double, -0.},
      {0.f, -inf_float, -inf_float, -3.f, 0., -inf_double},
      {1.37747639043129518071e-41f, -3.22084585277826e35f, 2.3f, 3.,
       1.37747639043129518071e-41, -3.22084585277826e35}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_U16_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ fexupr_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_F_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ fexupr_d(w2, w0); });
  }
}

struct TestCaseMsa2RF_U32_D {
  uint32_t ws1;
  uint32_t ws2;
  uint32_t ws3;
  uint32_t ws4;
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_ffql) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2RF_U16_F tc_s[] = {{0, 3, 0xFFFF, 0x8000, 0x8000, 0xE000,
                                         0x0FF0, 0, -1.f, -0.25f,
                                         0.12451171875f, 0.f}};

  struct TestCaseMsa2RF_U32_D tc_d[] = {
      {0, 45, 0x80000000, 0xE0000000, -1., -0.25},
      {0x28379, 0xAAAA5555, 0x024903D3, 0, 17.853239085525274277e-3, 0.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_U16_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ ffql_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_U32_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ ffql_d(w2, w0); });
  }
}

TEST(MSA_ffqr) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2RF_U16_F tc_s[] = {{0x8000, 0xE000, 0x0FF0, 0, 0, 3,
                                         0xFFFF, 0x8000, -1.f, -0.25f,
                                         0.12451171875f, 0.f}};

  struct TestCaseMsa2RF_U32_D tc_d[] = {
      {0x80000000, 0xE0000000, 0, 45, -1., -0.25},
      {0x024903D3, 0, 0x28379, 0xAAAA5555, 17.853239085525274277e-3, 0.}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_U16_F); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ ffqr_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_U32_D); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ ffqr_d(w2, w0); });
  }
}

struct TestCaseMsaVector {
  uint64_t wd_lo;
  uint64_t wd_hi;
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint64_t wt_lo;
  uint64_t wt_hi;
};

template <typename InstFunc, typename OperFunc>
void run_msa_vector(struct TestCaseMsaVector* input,
                    InstFunc GenerateVectorInstructionFunc,
                    OperFunc GenerateOperationFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(&assm, &(input->ws_lo), w0, t0, t1);
  load_elements_of_vector(&assm, &(input->wt_lo), w2, t0, t1);
  load_elements_of_vector(&assm, &(input->wd_lo), w4, t0, t1);

  GenerateVectorInstructionFunc(assm);

  store_elements_of_vector(&assm, w4, a0);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(GenerateOperationFunc(input->wd_lo, input->ws_lo, input->wt_lo),
           res.d[0]);
  CHECK_EQ(GenerateOperationFunc(input->wd_hi, input->ws_hi, input->wt_hi),
           res.d[1]);
}

TEST(MSA_vector) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaVector tc[] = {
      // wd_lo, wd_hi, ws_lo, ws_hi, wt_lo, wt_hi
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0xDCD39D91F9057627,
       0x64BE4F6DBE9CAA51, 0x6B23DE1A687D9CB9, 0x49547AAD691DA4CA},
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x401614523D830549,
       0xD7C46D613F50EDDD, 0x52284CBC60A1562B, 0x1756ED510D8849CD},
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0xD6E2D2EBCB40D72F,
       0x13A619AFCE67B079, 0x36CCE284343E40F9, 0xB4E8F44FD148BF7F}};

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaVector); ++i) {
    run_msa_vector(
        &tc[i], [](MacroAssembler& assm) { __ and_v(w4, w0, w2); },
        [](uint64_t wd, uint64_t ws, uint64_t wt) { return ws & wt; });
    run_msa_vector(
        &tc[i], [](MacroAssembler& assm) { __ or_v(w4, w0, w2); },
        [](uint64_t wd, uint64_t ws, uint64_t wt) { return ws | wt; });
    run_msa_vector(
        &tc[i], [](MacroAssembler& assm) { __ nor_v(w4, w0, w2); },
        [](uint64_t wd, uint64_t ws, uint64_t wt) { return ~(ws | wt); });
    run_msa_vector(
        &tc[i], [](MacroAssembler& assm) { __ xor_v(w4, w0, w2); },
        [](uint64_t wd, uint64_t ws, uint64_t wt) { return ws ^ wt; });
    run_msa_vector(&tc[i], [](MacroAssembler& assm) { __ bmnz_v(w4, w0, w2); },
                   [](uint64_t wd, uint64_t ws, uint64_t wt) {
                     return (ws & wt) | (wd & ~wt);
                   });
    run_msa_vector(&tc[i], [](MacroAssembler& assm) { __ bmz_v(w4, w0, w2); },
                   [](uint64_t wd, uint64_t ws, uint64_t wt) {
                     return (ws & ~wt) | (wd & wt);
                   });
    run_msa_vector(&tc[i], [](MacroAssembler& assm) { __ bsel_v(w4, w0, w2); },
                   [](uint64_t wd, uint64_t ws, uint64_t wt) {
                     return (ws & ~wd) | (wt & wd);
                   });
  }
}

struct TestCaseMsaBit {
  uint64_t wd_lo;
  uint64_t wd_hi;
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint32_t m;
};

template <typename InstFunc, typename OperFunc>
void run_msa_bit(struct TestCaseMsaBit* input, InstFunc GenerateInstructionFunc,
                 OperFunc GenerateOperationFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(&assm, &(input->ws_lo), w0, t0, t1);
  load_elements_of_vector(&assm, &(input->wd_lo), w2, t0, t1);

  GenerateInstructionFunc(assm, input->m);

  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(GenerateOperationFunc(input->wd_lo, input->ws_lo, input->m),
           res.d[0]);
  CHECK_EQ(GenerateOperationFunc(input->wd_hi, input->ws_hi, input->m),
           res.d[1]);
}

TEST(MSA_slli_srai_srli) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaBit tc[] = {
      // wd_lo, wd_hi     ws_lo,              ws_hi, m
      {0, 0, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 3},
      {0, 0, 0x64BE4F6DBE9CAA51, 0x6B23DE1A687D9CB9, 5},
      {0, 0, 0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 9},
      {0, 0, 0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 13},
      {0, 0, 0x566BE7BA4365B70A, 0x01EBBC1937D76CB4, 21},
      {0, 0, 0x380E2DEB9D3F8AAE, 0x017E0DE0BCC6CA42, 30},
      {0, 0, 0xA46A3A9BCB43F4E5, 0x1C62C8473BDFCFFB, 45},
      {0, 0, 0xF6759D85F23B5A2B, 0x5C042AE42C6D12C1, 61}};

#define SLLI_SRLI_DF(lanes, mask, func)      \
  [](uint64_t wd, uint64_t ws, uint32_t m) { \
    uint64_t res = 0;                        \
    int elem_size = kMSARegSize / lanes;     \
    for (int i = 0; i < lanes / 2; ++i) {    \
      int shift = elem_size * i;             \
      uint64_t elem = (ws >> shift) & mask;  \
      res |= ((func)&mask) << shift;         \
    }                                        \
    return res;                              \
  }

#define SRAI_DF(lanes, mask, func)                                            \
```