Response: Let's break down the thought process for analyzing this C++ test file for V8.

1. **Identify the Core Purpose:** The file name `test-assembler-mips64.cc` immediately tells us this is a test file for the MIPS64 assembler within the V8 JavaScript engine. The `cctest` directory further confirms it's a C++ component test.

2. **Scan for Keywords and Patterns:** Look for recurring keywords and patterns. I see:
    * `TEST(...)`: This is a common pattern for defining unit tests in Google Test (gtest), which V8 uses.
    * `if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD)) return;`: This conditional check appears at the beginning of many tests. It strongly suggests these tests are specifically for MIPS64 architecture with SIMD (Single Instruction, Multiple Data) support. The `kMips64r6` further narrows it down to a specific revision of the MIPS64 architecture.
    * `CcTest::InitializeVM();`: This indicates the tests interact with a simulated or real V8 virtual machine environment.
    * `run_msa_3rf(...)`:  This function is used extensively. The `msa` part likely refers to MIPS SIMD Architecture. The `3rf` might stand for "three register format," a common instruction format. The function probably executes some assembly code and compares results.
    *  `__ instruction(...)`: The double underscore `__` often precedes assembly instruction mnemonics in V8's assembler. This confirms the tests are directly exercising assembly instructions.
    *  Data structures like `TestCaseMsa3RF_F`, `ExpRes_F`, etc.: These structures hold input values and expected results for the assembly instructions being tested. The suffixes `_F`, `_D`, `_16I`, `_32I` suggest different data types (float, double, 16-bit integer, 32-bit integer).
    * Specific assembly instruction mnemonics: `fmax_w`, `fmin_d`, `mul_q_h`, `fexdo_w`, `ftq_d`, etc. These are the actual MIPS SIMD instructions being tested.

3. **Group Tests by Functionality:** Notice that the tests are grouped logically. Each `TEST(...)` block focuses on a specific category of MIPS SIMD instructions:
    * Floating-point min/max (`TEST(MSA_fp_min_max)`)
    * Fixed-point arithmetic (`TEST(MSA_fixed_point_arithmetic)`)
    * Floating-point exponent manipulation (`TEST(MSA_fexdo)`)
    * Floating-point to integer conversion (`TEST(MSA_ftq)`)

4. **Understand the Test Structure:**  Within each test:
    *  There's an architecture check.
    *  The V8 VM is initialized.
    *  Test case data (inputs and expected outputs) is defined in arrays of structs.
    *  A loop iterates through the test cases.
    *  The `run_msa_3rf` function is called. This function takes the test case data and a lambda function.
    *  The lambda function contains the specific assembly instruction being tested, using the `__ instruction(...)` syntax.
    *  The `run_msa_3rf` function likely executes the assembly instruction with the input data and compares the actual result with the expected result.

5. **Infer the Relationship to JavaScript:**  While this file doesn't *directly* contain JavaScript code, it's a crucial part of the V8 engine, which *executes* JavaScript. The MIPS SIMD instructions being tested are the low-level building blocks that V8 might use to optimize certain JavaScript operations, especially those involving numerical computations on arrays or other data structures.

6. **Construct the Summary (Initial Draft):** Based on the above observations, a first draft of the summary might look like this:

    > This C++ file `test-assembler-mips64.cc` in the V8 project contains unit tests for the MIPS64 assembler. Specifically, it tests MIPS SIMD instructions. Each test verifies the correct behavior of a particular instruction by providing input values and comparing the output to expected values. It initializes the V8 VM before running the assembly code. The tests are for floating-point min/max, fixed-point arithmetic, floating-point exponent manipulation, and floating-point to integer conversion instructions.

7. **Refine the Summary (Adding JavaScript Connection):** Now, let's connect this to JavaScript. Think about what kind of JavaScript code might benefit from these low-level optimizations:

    * Array operations:  Operations on large arrays of numbers (e.g., finding the minimum/maximum, performing element-wise arithmetic).
    * Typed Arrays: JavaScript's `Float32Array`, `Float64Array`, `Int32Array`, etc., are prime candidates for SIMD optimization.
    * Graphics and multimedia processing:  These often involve heavy numerical computations.

8. **Construct the JavaScript Example:** Create a simple JavaScript example that demonstrates a scenario where these kinds of optimizations might be used. A basic array manipulation is a good starting point. Show how a seemingly simple JavaScript operation could potentially be implemented using the underlying SIMD instructions.

9. **Finalize the Summary:**  Combine the observations and the JavaScript example into a comprehensive summary, similar to the example output you provided. Ensure it's clear, concise, and addresses the "what," "why," and "how" of the file's purpose and its relationship to JavaScript. Emphasize that this is the *last* part of a larger test suite.

This detailed thought process, moving from the general purpose to specific details and then connecting it back to the broader context of JavaScript execution, allows for a thorough understanding and accurate summarization of the C++ test file.
这个C++源代码文件 `test-assembler-mips64.cc` 是V8 JavaScript引擎的一部分，专门用于测试MIPS64架构上的汇编器功能。作为第7部分（共7部分），这很可能是该测试套件的最后一个文件，意味着它可能包含了对一些较为复杂或特定功能的测试。

**功能归纳:**

总的来说，这个文件的主要功能是：

1. **测试MIPS64架构的SIMD (Single Instruction, Multiple Data) 指令的正确实现:**  从代码中大量的 `TEST(MSA_...)` 和涉及特定MSA指令（例如 `fmax_w`, `fmin_d`, `mul_q_h`, `fexdo_w`, `ftq_w` 等）可以看出，这个文件专注于测试MIPS SIMD扩展指令的正确性。SIMD指令允许一条指令操作多个数据，从而提高并行计算能力。

2. **测试特定的浮点和定点运算指令:**  代码中测试了浮点数的最大值、最小值 (`fmax`, `fmin`)，以及定点数的乘法、加法、减法等运算 (`mul_q_h`, `madd_q_h`, `msub_q_h`)。这些是CPU进行数值计算的基本操作。

3. **测试浮点数的指数操作和类型转换指令:** `fexdo` 指令可能涉及到浮点数的指数部分的操作，而 `ftq` 指令则是将浮点数转换为定点数（可能是截断或量化）。

4. **使用C++进行单元测试:** 文件使用了 V8 内部的测试框架 (`CcTest`) 和 Google Test 框架 (`TEST`) 来编写单元测试。每个 `TEST` 宏定义了一个独立的测试用例，用于验证特定指令的行为。

5. **提供测试用例和期望结果:**  文件中定义了大量的 `struct TestCaseMsa3RF...` 和 `struct ExpRes...`，用于存储测试的输入数据和预期的输出结果。测试代码会执行汇编指令，并将实际结果与期望结果进行比较，以判断指令是否正确工作。

6. **仅在支持MIPS SIMD的架构上运行:** 每个测试用例的开头都有 `if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD)) return;` 这样的条件判断，确保这些特定的SIMD测试只在支持MIPS SIMD扩展的MIPS64 R6架构上运行。

**与JavaScript的关系以及JavaScript示例:**

这个文件直接测试的是底层的汇编指令，但这些指令是V8引擎执行JavaScript代码的基础。当JavaScript代码执行一些特定的数值计算或数据处理时，V8可能会利用这些底层的SIMD指令来提高性能。

例如，JavaScript中的 `Math.max()` 和 `Math.min()` 函数在底层就可能利用了类似 `fmax` 和 `fmin` 的指令。对于数组的数值计算，例如对一个 `Float32Array` 或 `Float64Array` 进行元素级的最大值或最小值查找，或者进行向量运算，SIMD指令就能发挥很大的作用。

**JavaScript 示例 (模拟 `fmax` 的效果):**

```javascript
function findMax(arr1, arr2) {
  if (arr1.length !== arr2.length) {
    throw new Error("Arrays must have the same length");
  }
  const result = new Array(arr1.length);
  for (let i = 0; i < arr1.length; i++) {
    result[i] = Math.max(arr1[i], arr2[i]);
  }
  return result;
}

const array1 = [1.5, -2.3, 0.7, 4.1];
const array2 = [-0.5, 3.1, 1.2, -1.8];
const maxArray = findMax(array1, array2);
console.log(maxArray); // 输出: [ 1.5, 3.1, 1.2, 4.1 ]
```

在这个 JavaScript 示例中，`findMax` 函数的功能是逐个比较两个数组的元素，并返回一个包含较大元素的新数组。在 V8 引擎的底层实现中，如果目标架构支持 MIPS SIMD，它可能会将这个循环操作转化为使用类似 `fmax_w` (针对单精度浮点数) 或 `fmax_d` (针对双精度浮点数) 的指令，一次性处理多个元素的比较，从而提高效率。

**总结:**

作为测试套件的最后一部分，这个 `test-assembler-mips64.cc` 文件专注于验证V8引擎在MIPS64架构上实现的SIMD浮点和定点运算指令的正确性。这些底层的汇编指令是V8引擎高效执行JavaScript数值计算的关键组成部分。通过编写细致的测试用例，V8的开发者可以确保在MIPS64平台上JavaScript代码能够正确且高效地运行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共7部分，请归纳一下它的功能

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