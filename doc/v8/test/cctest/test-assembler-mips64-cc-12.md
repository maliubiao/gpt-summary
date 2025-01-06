Response:
Let's break down the thought process to analyze this C++ code snippet and fulfill the request.

1. **Identify the core purpose of the code:** The filename `test-assembler-mips64.cc` and the content clearly indicate this is a *testing* file for the MIPS64 assembler in V8. It focuses on verifying the functionality of specific MIPS SIMD Architecture (MSA) instructions.

2. **Scan for keywords and patterns:**  Look for recurring elements:
    * `TEST(...)`:  This strongly suggests Google Test framework is being used. Each `TEST` block represents an individual test case.
    * `MSA_...`:  This prefix indicates the tests are related to the MIPS SIMD Architecture.
    * Function names like `fmax_w`, `fmin_d`, `mul_q_h`, `fexdo_h`, `ftq_w`: These are the actual MSA instructions being tested. The suffixes likely indicate data types (`w` for word/float, `d` for double, `h` for half-word) and sometimes operation types (`mul` for multiply, `add` for add, etc.).
    * `run_msa_3rf(...)`: This looks like a helper function to execute the assembly instructions and compare results. The `3rf` likely refers to three register operands.
    * Structures like `TestCaseMsa3RF`, `ExpRes_16I`, etc.: These are data structures to hold test inputs and expected outputs. The suffixes like `_16I` and `_32I` probably denote the data type sizes (16-bit integer, 32-bit integer).
    * Loops with `arraysize(...)`: This iterates through sets of test cases.
    * `#define TEST_FP_MIN_MAX_W(...)`, `#define TEST_FIXED_POINT_DF_H(...)`, etc.: These are macros to simplify the test setup for different instructions.

3. **Analyze individual test cases:**  Pick a few `TEST` blocks to understand their structure:
    * **`TEST(MSA_fp_min_max)`:** This tests `fmax` and `fmin` instructions for both single-precision (`w`) and double-precision (`d`) floating-point numbers. It defines test cases (`tc_w`, `tc_d`) and expected results (`exp_res_fmax_w`, etc.). The macros expand into calls to `run_msa_2rf`.
    * **`TEST(MSA_fixed_point_arithmetic)`:** This tests fixed-point arithmetic instructions like `mul_q_h`, `madd_q_h`, `msub_q_h`, etc. It uses similar structures for test cases and expected results. The `_q` likely indicates a saturating arithmetic operation.
    * **`TEST(MSA_fexdo)`:** This test seems to be about floating-point exponent manipulation (`fexdo`). The expected results are integer representations of the manipulated exponents.
    * **`TEST(MSA_ftq)`:** This appears to test floating-point to integer conversion (`ftq`). The expected results are the integer conversions of the input floating-point values.

4. **Infer the overall functionality:** Based on the individual tests, the file's main function is to thoroughly test the correctness of various MIPS MSA instructions related to:
    * Floating-point minimum and maximum operations.
    * Fixed-point arithmetic (multiplication, addition, subtraction, with and without rounding).
    * Floating-point exponent extraction and manipulation.
    * Floating-point to integer conversion (quantization).

5. **Address the specific questions in the prompt:**
    * **Functionality:** List the identified categories of tested instructions.
    * **`.tq` extension:**  Confirm it's a C++ file, not a Torque file.
    * **Relationship to JavaScript:**  Explain that these low-level assembler tests ensure the correctness of underlying operations that *could* be used to implement JavaScript features (like math operations). Provide simple JavaScript examples that would rely on such low-level functions.
    * **Code logic inference:** Choose a simple test case (like `MSA_fp_min_max`) and provide example inputs and expected outputs based on the instruction's definition.
    * **Common programming errors:**  Think about how these instructions could be misused or misunderstood in a higher-level context. Focus on floating-point comparisons (NaNs) and potential overflow/underflow in fixed-point arithmetic.
    * **Final summary:**  Reiterate that it's a comprehensive test suite for MIPS MSA instructions in V8.

6. **Structure the answer:** Organize the findings logically, addressing each point in the prompt clearly. Use headings and bullet points for readability.

7. **Refine and review:** Check for accuracy, clarity, and completeness. Ensure the examples are relevant and easy to understand. For instance, initially, I might have just said "math operations" in JavaScript, but specifying `Math.min`, `Math.max`, and type conversions makes it more concrete.

This detailed breakdown illustrates the systematic approach to understanding and summarizing a piece of code, even without deep, pre-existing knowledge of the specific codebase. It involves pattern recognition, focusing on key elements, inferring purpose from context, and then synthesizing the information to address the given requirements.
好的，让我们来分析一下 `v8/test/cctest/test-assembler-mips64.cc` 这个文件的功能。

**文件功能概述:**

这个 C++ 文件是 V8 JavaScript 引擎的测试套件的一部分，专门用于测试 MIPS64 架构上的汇编器 (assembler) 功能。它包含了多个测试用例，用于验证 MIPS SIMD 架构 (MSA) 指令的正确性。这些指令涵盖了浮点运算、定点运算、浮点数的指数操作以及浮点数到整数的转换等。

**具体功能点:**

1. **浮点数 Min/Max 测试 (`TEST(MSA_fp_min_max)`)**:
   - 测试 `fmax.w`, `fmax_a.w`, `fmin.w`, `fmin_a.w` (单精度浮点数最大/最小值) 指令。
   - 测试 `fmax.d`, `fmax_a.d`, `fmin.d`, `fmin_a.d` (双精度浮点数最大/最小值) 指令。
   - 这些指令用于比较两个浮点数并返回最大值或最小值。带 `_a` 后缀的版本可能涉及对 NaN 值的处理方式不同。

2. **定点算术运算测试 (`TEST(MSA_fixed_point_arithmetic)`)**:
   - 测试 `mulq_h`, `maddq_h`, `msubq_h`, `mulrq_h`, `maddrq_h`, `msubrq_h` (半字定点数乘法、带加法的乘法、带减法的乘法以及它们的舍入版本) 指令。
   - 测试 `mulq_w`, `maddq_w`, `msubq_w`, `mulrq_w`, `maddrq_w`, `msubrq_w` (字定点数乘法、带加法的乘法、带减法的乘法以及它们的舍入版本) 指令。
   - 这些指令用于执行定点数的乘法和乘加/乘减运算，`q` 可能表示饱和运算，防止溢出。

3. **浮点数指数操作测试 (`TEST(MSA_fexdo)`)**:
   - 测试 `fexdo_h` 指令，它可能用于提取或操作浮点数的指数部分 (具体行为需要参考 MIPS MSA 的文档)。
   - 测试 `fexdo_w` 指令，同样用于浮点数指数操作，可能针对不同的数据类型或精度。

4. **浮点数到整数转换测试 (`TEST(MSA_ftq)`)**:
   - 测试 `ftq_h` 指令，将浮点数转换为定点整数 (quantization)。
   - 测试 `ftq_w` 指令，执行类似的浮点数到整数的转换。

**关于文件扩展名和 Torque:**

你提到如果文件以 `.tq` 结尾，那它是个 V8 Torque 源代码。但是，`v8/test/cctest/test-assembler-mips64.cc` 以 `.cc` 结尾，这是一个标准的 C++ 源文件扩展名。因此，它不是 Torque 源代码，而是纯粹的 C++ 代码。

**与 JavaScript 功能的关系:**

虽然这个文件直接测试的是汇编指令，但这些指令是 JavaScript 引擎执行底层操作的基础。例如：

- **浮点数 Min/Max:** JavaScript 的 `Math.min()` 和 `Math.max()` 函数在底层可能依赖于类似的浮点数比较和选择操作。
  ```javascript
  console.log(Math.min(1.5, 2.0)); // 输出 1.5
  console.log(Math.max(-1, -5));  // 输出 -1
  ```

- **定点算术运算:** 虽然 JavaScript 主要使用浮点数，但在某些特定场景或优化的实现中，引擎内部可能会使用定点数进行中间计算。例如，处理某些图形或音频相关的操作。

- **浮点数指数操作:** JavaScript 的 `Math.pow()` 或处理浮点数的内部表示时，可能会涉及到指数的提取和操作。

- **浮点数到整数转换:** JavaScript 中使用 `parseInt()`、`Math.floor()`、`Math.ceil()`、`Math.round()` 等函数将浮点数转换为整数时，底层就需要执行类似的转换操作。
  ```javascript
  console.log(parseInt(3.14));    // 输出 3
  console.log(Math.floor(4.9));   // 输出 4
  console.log(Math.ceil(2.3));    // 输出 3
  console.log(Math.round(5.5));   // 输出 6
  ```

**代码逻辑推理 (以 `TEST(MSA_fp_min_max)` 为例):**

假设 `tc_w` 中有一个测试用例 `{1.0f, 2.0f, -3.0f, -4.0f}`，对应 `exp_res_fmax_w` 的期望结果是 `{2.0f, 2.0f, -3.0f, -3.0f}`。

- **输入:** 宏 `TEST_FP_MIN_MAX_W(fmax_w, &tc_w[i], &exp_res_fmax_w[i])` 会将 `tc_w[i]` 指向的测试用例数据加载到寄存器中。
- **操作:** `__ fmax_w(w2, w0, w1);`  这条汇编指令会比较 `w0` 和 `w1` 寄存器中的单精度浮点数，并将较大值存入 `w2` 寄存器。
- **输出:**  `run_msa_2rf` 函数会将 `w2` 寄存器的结果与 `exp_res_fmax_w[i]` 中的期望值进行比较。如果 `w0` 包含 `1.0f`，`w1` 包含 `2.0f`，那么 `w2` 应该包含 `2.0f`。

**用户常见的编程错误 (可能与这些指令相关的):**

1. **浮点数比较的精度问题:** 直接使用 `==` 比较浮点数可能由于精度问题导致错误。
   ```javascript
   let a = 0.1 + 0.2;
   console.log(a == 0.3); // 输出 false，因为浮点数运算存在精度误差
   ```
   相关的 MSA 指令测试确保了底层浮点数比较操作的正确性。

2. **定点数溢出:** 如果用户尝试在定点数中存储超出其表示范围的值，会导致溢出。虽然 JavaScript 主要使用浮点数，但在一些底层或特定的数值计算场景中，可能会遇到类似的问题。

3. **对 NaN 值的处理不当:** NaN (Not a Number) 是一个特殊的浮点数值。在进行比较或算术运算时，需要特别注意 NaN 的行为。
   ```javascript
   console.log(NaN == NaN);       // 输出 false
   console.log(Math.max(1, NaN));  // 输出 NaN
   ```
   `fmax_a` 和 `fmin_a` 等指令的测试可能就关注了对 NaN 值的特定处理方式。

4. **类型转换错误:** 在将浮点数转换为整数时，如果没有明确指定转换方式 (例如 `parseInt` vs. `Math.floor`)，可能会得到意想不到的结果。MSA 的 `ftq` 指令测试了这种转换的正确性。

**归纳功能 (作为第 13 部分，共 13 部分):**

作为整个测试套件的最后一部分，`v8/test/cctest/test-assembler-mips64.cc` 的功能是**对 MIPS64 架构上汇编器的关键 SIMD 指令进行全面的、底层的正确性验证**。它专注于测试浮点数的基本运算 (min/max)、定点算术运算、浮点数的指数操作以及浮点数到整数的转换。这些测试确保了 V8 引擎在 MIPS64 平台上执行 JavaScript 代码时，能够正确地利用硬件提供的 SIMD 加速功能，保证数值计算的准确性和性能。它是 V8 引擎质量保证流程中至关重要的一环。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共13部分，请归纳一下它的功能

"""
i], &exp_res_fmin_w[i])
    TEST_FP_MIN_MAX_W(fmin_a_w, &tc_w[i], &exp_res_fmin_a_w[i])
  }

  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    TEST_FP_MIN_MAX_D(fmax_d, &tc_d[i], &exp_res_fmax_d[i])
    TEST_FP_MIN_MAX_D(fmax_a_d, &tc_d[i], &exp_res_fmax_a_d[i])
    TEST_FP_MIN_MAX_D(fmin_d, &tc_d[i], &exp_res_fmin_d[i])
    TEST_FP_MIN_MAX_D(fmin_a_d, &tc_d[i], &exp_res_fmin_a_d[i])
  }
#undef TEST_FP_MIN_MAX_W
#undef TEST_FP_MIN_MAX_D
}

struct TestCaseMsa3RF_16I {
  int16_t ws_1, ws_2, ws_3, ws_4, ws_5, ws_6, ws_7, ws_8;
  int16_t wt_1, wt_2, wt_3, wt_4, wt_5, wt_6, wt_7, wt_8;
  int16_t wd_1, wd_2, wd_3, wd_4, wd_5, wd_6, wd_7, wd_8;
};
struct ExpRes_16I {
  int16_t exp_res_1;
  int16_t exp_res_2;
  int16_t exp_res_3;
  int16_t exp_res_4;
  int16_t exp_res_5;
  int16_t exp_res_6;
  int16_t exp_res_7;
  int16_t exp_res_8;
};

struct TestCaseMsa3RF_32I {
  int32_t ws_1, ws_2, ws_3, ws_4;
  int32_t wt_1, wt_2, wt_3, wt_4;
  int32_t wd_1, wd_2, wd_3, wd_4;
};

TEST(MSA_fixed_point_arithmetic) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const struct TestCaseMsa3RF tc_h[]{
      {0x800080007FFF7FFF, 0xE1ED8000FAD3863A, 0x80007FFF00AF7FFF,
       0x800015A77FFFA0EB, 0x7FFF800080007FFF, 0x80007FFF1F207364},
      {0x800080007FFF006A, 0x002AFFC4329AD87B, 0x80007FFF7FFF00F3,
       0xFFECFFB4D0D7F429, 0x80007FFF80007C33, 0x54AC6BBCE53B8C91}};

  const struct TestCaseMsa3RF tc_w[]{
      {0x8000000080000000, 0x7FFFFFFF7FFFFFFF, 0x800000007FFFFFFF,
       0x00001FF37FFFFFFF, 0x7FFFFFFF80000000, 0x800000007FFFFFFF},
      {0xE1ED035580000000, 0xFAD3863AED462C0B, 0x8000000015A70AEC,
       0x7FFFFFFFA0EBD354, 0x800000007FFFFFFF, 0xD0D7F4291F207364},
      {0x8000000080000000, 0x7FFFFFFF0000DA1F, 0x800000007FFFFFFF,
       0x7FFFFFFF00F39C3B, 0x800000007FFFFFFF, 0x800000007C33F2FD},
      {0x0000AC33FFFF329A, 0x54AC6BBCE53BD87B, 0xFFFFE2B4D0D7F429,
       0x0355ED462C0B1FF3, 0xB5DEB625939DD3F9, 0xE642ADFA69519596}};

  const struct ExpectedResult_MSA3RF exp_res_mul_q_h[] = {
      {0x7FFF800100AE7FFE, 0x1E13EA59FAD35A74},
      {0x7FFF80017FFE0000, 0xFFFF0000ED5B03A7}};
  const struct ExpectedResult_MSA3RF exp_res_madd_q_h[] = {
      {0x7FFF800080AE7FFF, 0x9E136A5819F37FFF},
      {0x00000000FFFE7C33, 0x54AB6BBCD2969038}};
  const struct ExpectedResult_MSA3RF exp_res_msub_q_h[] = {
      {0xFFFFFFFF80000000, 0x80007FFF244C18EF},
      {0x80007FFF80007C32, 0x54AC6BBBF7DF88E9}};
  const struct ExpectedResult_MSA3RF exp_res_mulr_q_h[] = {
      {0x7FFF800100AF7FFE, 0x1E13EA59FAD35A75},
      {0x7FFF80017FFE0001, 0x00000000ED5B03A8}};
  const struct ExpectedResult_MSA3RF exp_res_maddr_q_h[] = {
      {0x7FFF800080AF7FFF, 0x9E136A5819F37FFF},
      {0x00000000FFFE7C34, 0x54AC6BBCD2969039}};
  const struct ExpectedResult_MSA3RF exp_res_msubr_q_h[] = {
      {0xFFFFFFFF80000001, 0x80007FFF244D18EF},
      {0x80007FFF80007C32, 0x54AC6BBCF7E088E9}};

  const struct ExpectedResult_MSA3RF exp_res_mul_q_w[] = {
      {0x7FFFFFFF80000001, 0x00001FF27FFFFFFE},
      {0x1E12FCABEA58F514, 0xFAD3863A0DE8DEE1},
      {0x7FFFFFFF80000001, 0x7FFFFFFE0000019F},
      {0xFFFFFFFF00004BAB, 0x0234E1FBF6CA3EE0}};
  const struct ExpectedResult_MSA3RF exp_res_madd_q_w[] = {
      {0x7FFFFFFF80000000, 0x80001FF27FFFFFFF},
      {0x9E12FCAB6A58F513, 0xCBAB7A632D095245},
      {0x0000000000000000, 0xFFFFFFFE7C33F49C},
      {0xB5DEB624939E1FA4, 0xE8778FF5601BD476}};
  const struct ExpectedResult_MSA3RF exp_res_msub_q_w[] = {
      {0xFFFFFFFFFFFFFFFF, 0x8000000000000000},
      {0x800000007FFFFFFF, 0xD6046DEE11379482},
      {0x800000007FFFFFFF, 0x800000007C33F15D},
      {0xB5DEB625939D884D, 0xE40DCBFE728756B5}};
  const struct ExpectedResult_MSA3RF exp_res_mulr_q_w[] = {
      {0x7FFFFFFF80000001, 0x00001FF37FFFFFFE},
      {0x1E12FCABEA58F514, 0xFAD3863A0DE8DEE2},
      {0x7FFFFFFF80000001, 0x7FFFFFFE0000019F},
      {0x0000000000004BAC, 0x0234E1FCF6CA3EE1}};
  const struct ExpectedResult_MSA3RF exp_res_maddr_q_w[] = {
      {0x7FFFFFFF80000000, 0x80001FF37FFFFFFF},
      {0x9E12FCAB6A58F513, 0xCBAB7A632D095246},
      {0x0000000000000000, 0xFFFFFFFE7C33F49C},
      {0xB5DEB625939E1FA5, 0xE8778FF6601BD477}};
  const struct ExpectedResult_MSA3RF exp_res_msubr_q_w[] = {
      {0xFFFFFFFFFFFFFFFF, 0x8000000000000001},
      {0x800000007FFFFFFF, 0xD6046DEF11379482},
      {0x800000007FFFFFFF, 0x800000007C33F15E},
      {0xB5DEB625939D884D, 0xE40DCBFE728756B5}};

#define TEST_FIXED_POINT_DF_H(instruction, src, exp_res) \
  run_msa_3rf((src), (exp_res),                          \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FIXED_POINT_DF_W(instruction, src, exp_res) \
  run_msa_3rf((src), (exp_res),                          \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_h); i++) {
    TEST_FIXED_POINT_DF_H(mul_q_h, &tc_h[i], &exp_res_mul_q_h[i])
    TEST_FIXED_POINT_DF_H(madd_q_h, &tc_h[i], &exp_res_madd_q_h[i])
    TEST_FIXED_POINT_DF_H(msub_q_h, &tc_h[i], &exp_res_msub_q_h[i])
    TEST_FIXED_POINT_DF_H(mulr_q_h, &tc_h[i], &exp_res_mulr_q_h[i])
    TEST_FIXED_POINT_DF_H(maddr_q_h, &tc_h[i], &exp_res_maddr_q_h[i])
    TEST_FIXED_POINT_DF_H(msubr_q_h, &tc_h[i], &exp_res_msubr_q_h[i])
  }

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FIXED_POINT_DF_W(mul_q_w, &tc_w[i], &exp_res_mul_q_w[i])
    TEST_FIXED_POINT_DF_W(madd_q_w, &tc_w[i], &exp_res_madd_q_w[i])
    TEST_FIXED_POINT_DF_W(msub_q_w, &tc_w[i], &exp_res_msub_q_w[i])
    TEST_FIXED_POINT_DF_W(mulr_q_w, &tc_w[i], &exp_res_mulr_q_w[i])
    TEST_FIXED_POINT_DF_W(maddr_q_w, &tc_w[i], &exp_res_maddr_q_w[i])
    TEST_FIXED_POINT_DF_W(msubr_q_w, &tc_w[i], &exp_res_msubr_q_w[i])
  }
#undef TEST_FIXED_POINT_DF_H
#undef TEST_FIXED_POINT_DF_W
}

TEST(MSA_fexdo) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_float = std::numeric_limits<float>::infinity();
  const float nan_float = std::numeric_limits<float>::quiet_NaN();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa3RF_F tc_w[] = {
      // ws_1, ws_2, ws_3, ws_4, wt_1, wt_2, wt_3, wt_4, wd_1, wd_2, wd_3, wd_4
      {inf_float, nan_float, 66505.f, 65504.f, 6.2e-5f, 5e-5f, -32.42f,
       -inf_float, 0, 0, 0, 0},
      {-0.f, 0.f, 123.567f, -765.321f, -6e-8f, 5.9e-8f, 1e-7f, -1e-20f, 0, 0, 0,
       0},
      {1e-36f, 1e20f, -1e20f, 2e-20f, 6e-8f, -2.9e-8f, -66505.f, -65504.f, 0, 0,
       0, 0}};

  const struct TestCaseMsa3RF_D tc_d[] = {
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {inf_double, -1234., 4e38, 3.4e38, 0, 0},
      {1.2e-38, 1.1e-39, -38.92f, -inf_double, 0, 0},
      {-0., 0., 123.567e31, -765.321e33, 0, 0},
      {-1.5e-45, 1.3e-45, 1e-42, -1e-200, 0, 0},
      {1e-202, 1e158, -1e159, 1e14, 0, 0},
      {1.5e-42, 1.3e-46, -123.567e31, 765.321e33, 0, 0}};

  const struct ExpRes_16I exp_res_fexdo_w[] = {
      {static_cast<int16_t>(0x0410), static_cast<int16_t>(0x0347),
       static_cast<int16_t>(0xD00D), static_cast<int16_t>(0xFC00),
       static_cast<int16_t>(0x7C00), static_cast<int16_t>(0x7DFF),
       static_cast<int16_t>(0x7C00), static_cast<int16_t>(0x7BFF)},
      {static_cast<int16_t>(0x8001), static_cast<int16_t>(0x0001),
       static_cast<int16_t>(0x0002), static_cast<int16_t>(0x8000),
       static_cast<int16_t>(0x8000), static_cast<int16_t>(0x0000),
       static_cast<int16_t>(0x57B9), static_cast<int16_t>(0xE1FB)},
      {static_cast<int16_t>(0x0001), static_cast<int16_t>(0x8000),
       static_cast<int16_t>(0xFC00), static_cast<int16_t>(0xFBFF),
       static_cast<int16_t>(0x0000), static_cast<int16_t>(0x7C00),
       static_cast<int16_t>(0xFC00), static_cast<int16_t>(0x0000)}};

  const struct ExpRes_32I exp_res_fexdo_d[] = {
      {base::bit_cast<int32_t>(0x7F800000), base::bit_cast<int32_t>(0x7F7FC99E),
       base::bit_cast<int32_t>(0x7F800000),
       base::bit_cast<int32_t>(0xC49A4000)},
      {base::bit_cast<int32_t>(0xC21BAE14), base::bit_cast<int32_t>(0xFF800000),
       base::bit_cast<int32_t>(0x0082AB1E),
       base::bit_cast<int32_t>(0x000BFA5A)},
      {base::bit_cast<int32_t>(0x7673B164), base::bit_cast<int32_t>(0xFB13653D),
       base::bit_cast<int32_t>(0x80000000),
       base::bit_cast<int32_t>(0x00000000)},
      {base::bit_cast<int32_t>(0x000002CA), base::bit_cast<int32_t>(0x80000000),
       base::bit_cast<int32_t>(0x80000001),
       base::bit_cast<int32_t>(0x00000001)},
      {base::bit_cast<int32_t>(0xFF800000), base::bit_cast<int32_t>(0x56B5E621),
       base::bit_cast<int32_t>(0x00000000),
       base::bit_cast<int32_t>(0x7F800000)},
      {base::bit_cast<int32_t>(0xF673B164), base::bit_cast<int32_t>(0x7B13653D),
       base::bit_cast<int32_t>(0x0000042E),
       base::bit_cast<int32_t>(0x00000000)}};

#define TEST_FEXDO_H(instruction, src, exp_res)                               \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FEXDO_W(instruction, src, exp_res)                               \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FEXDO_H(fexdo_h, &tc_w[i], &exp_res_fexdo_w[i])
  }

  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    TEST_FEXDO_W(fexdo_w, &tc_d[i], &exp_res_fexdo_d[i])
  }

#undef TEST_FEXDO_H
#undef TEST_FEXDO_W
}

TEST(MSA_ftq) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float nan_float = std::numeric_limits<float>::quiet_NaN();
  const float inf_float = std::numeric_limits<float>::infinity();
  const double nan_double = std::numeric_limits<double>::quiet_NaN();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa3RF_F tc_w[] = {
      {1.f, -0.999f, 1.5f, -31e-6, 1e-7, -0.598, 0.0023, -0.f, 0, 0, 0, 0},
      {100.f, -102.f, -1.1f, 1.3f, 0.f, -1.f, 0.9999f, -0.000322, 0, 0, 0, 0},
      {nan_float, inf_float, -inf_float, -nan_float, -1e-40, 3e-44, 8.3e36,
       -0.00003, 0, 0, 0, 0}};

  const struct TestCaseMsa3RF_D tc_d[] = {
      {1., -0.999, 1.5, -31e-6, 0, 0},
      {1e-7, -0.598, 0.0023, -0.f, 0, 0},
      {100.f, -102.f, -1.1f, 1.3f, 0, 0},
      {0.f, -1.f, 0.9999f, -0.000322, 0, 0},
      {nan_double, inf_double, -inf_double, -nan_double, 0, 0},
      {-3e306, 2e-307, 9e307, 2e-307, 0, 0}};

  const struct ExpRes_16I exp_res_ftq_w[] = {
      {static_cast<int16_t>(0x0000), static_cast<int16_t>(0xB375),
       static_cast<int16_t>(0x004B), static_cast<int16_t>(0x0000),
       static_cast<int16_t>(0x7FFF), static_cast<int16_t>(0x8021),
       static_cast<int16_t>(0x7FFF), static_cast<int16_t>(0xFFFF)},
      {static_cast<int16_t>(0x0000), static_cast<int16_t>(0x8000),
       static_cast<int16_t>(0x7FFD), static_cast<int16_t>(0xFFF5),
       static_cast<int16_t>(0x7FFF), static_cast<int16_t>(0x8000),
       static_cast<int16_t>(0x8000), static_cast<int16_t>(0x7FFF)},
      {static_cast<int16_t>(0x0000), static_cast<int16_t>(0x0000),
       static_cast<int16_t>(0x7FFF), static_cast<int16_t>(0xFFFF),
       static_cast<int16_t>(0x0000), static_cast<int16_t>(0x7FFF),
       static_cast<int16_t>(0x8000), static_cast<int16_t>(0x0000)}};

  const struct ExpRes_32I exp_res_ftq_d[] = {
      {base::bit_cast<int32_t>(0x7FFFFFFF), base::bit_cast<int32_t>(0xFFFEFBF4),
       base::bit_cast<int32_t>(0x7FFFFFFF),
       base::bit_cast<int32_t>(0x8020C49C)},
      {base::bit_cast<int32_t>(0x004B5DCC), base::bit_cast<int32_t>(0x00000000),
       base::bit_cast<int32_t>(0x000000D7),
       base::bit_cast<int32_t>(0xB374BC6A)},
      {base::bit_cast<int32_t>(0x80000000), base::bit_cast<int32_t>(0x7FFFFFFF),
       base::bit_cast<int32_t>(0x7FFFFFFF),
       base::bit_cast<int32_t>(0x80000000)},
      {base::bit_cast<int32_t>(0x7FFCB900), base::bit_cast<int32_t>(0xFFF572DE),
       base::bit_cast<int32_t>(0x00000000),
       base::bit_cast<int32_t>(0x80000000)},
      {base::bit_cast<int32_t>(0x80000000), base::bit_cast<int32_t>(0x00000000),
       base::bit_cast<int32_t>(0x00000000),
       base::bit_cast<int32_t>(0x7FFFFFFF)},
      {base::bit_cast<int32_t>(0x7FFFFFFF), base::bit_cast<int32_t>(0x00000000),
       base::bit_cast<int32_t>(0x80000000),
       base::bit_cast<int32_t>(0x00000000)}};

#define TEST_FTQ_H(instruction, src, exp_res)                                 \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FTQ_W(instruction, src, exp_res)                                 \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FTQ_H(ftq_h, &tc_w[i], &exp_res_ftq_w[i])
  }

  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    TEST_FTQ_W(ftq_w, &tc_d[i], &exp_res_ftq_d[i])
  }

#undef TEST_FTQ_H
#undef TEST_FTQ_W
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```