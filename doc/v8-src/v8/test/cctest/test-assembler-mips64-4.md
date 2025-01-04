Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-assembler-mips64.cc`, specifically part 5 of 7. They also want to know if it relates to JavaScript and, if so, see a JavaScript example.

**Plan:**

1. **Analyze the code:** Focus on the test functions and the operations they perform. Identify the MIPS64 instructions being tested.
2. **Summarize the functionality:** Describe the purpose of the code based on the analysis.
3. **Determine the relationship with JavaScript:** Consider how the tested assembly instructions might be used in the V8 JavaScript engine.
4. **Provide a JavaScript example:** If a connection exists, create a simple JavaScript snippet that might trigger the execution of the tested instructions (or a similar operation).
这是 `v8/test/cctest/test-assembler-mips64.cc` 文件的第 5 部分，主要功能是 **测试 MIPS64 架构上 MSA (MIPS SIMD Architecture) 的各种浮点和向量指令的正确性**。

具体来说，这部分测试了以下 MSA 指令：

* **浮点转换指令:**
    * `ftrunc_s_w`, `ftrunc_s_d`: 将浮点数截断为有符号整数。
    * `ftrunc_u_w`, `ftrunc_u_d`: 将浮点数截断为无符号整数。
* **浮点算术指令:**
    * `fsqrt_w`, `fsqrt_d`: 计算浮点数的平方根。
    * `frsqrt_w`, `frsqrt_d`: 计算浮点数的倒数平方根的近似值。
    * `frcp_w`, `frcp_d`: 计算浮点数的倒数的近似值。
    * `frint_w`, `frint_d`: 将浮点数四舍五入到最接近的整数（受舍入模式控制）。
    * `flog2_w`, `flog2_d`: 计算以 2 为底的浮点数的对数。
    * `ftint_s_w`, `ftint_s_d`: 将浮点数转换为有符号整数（受舍入模式控制）。
    * `ftint_u_w`, `ftint_u_d`: 将浮点数转换为无符号整数（受舍入模式控制）。
    * `ffint_u_w`, `ffint_u_d`: 将无符号整数转换为浮点数。
    * `ffint_s_w`, `ffint_s_d`: 将有符号整数转换为浮点数。
    * `fexupl_w`, `fexupl_d`: 将半精度浮点数扩展为单精度或双精度浮点数（取低位）。
    * `fexupr_w`, `fexupr_d`: 将半精度浮点数扩展为单精度或双精度浮点数（取高位）。
    * `ffql_w`, `ffql_d`: 将定点数转换为浮点数（取低位）。
    * `ffqr_w`, `ffqr_d`: 将定点数转换为浮点数（取高位）。
* **向量逻辑指令:**
    * `and_v`, `or_v`, `nor_v`, `xor_v`, `bmnz_v`, `bmz_v`, `bsel_v`: 执行向量按位逻辑运算。
* **向量移位指令:**
    * `slli_b`, `slli_h`, `slli_w`, `slli_d`: 向量逻辑左移。
    * `srli_b`, `srli_h`, `srli_w`, `srli_d`: 向量逻辑右移。
    * `srlri_b`, `srlri_h`, `srlri_w`, `srlri_d`: 向量逻辑右移并插入舍入位。
    * `srai_b`, `srai_h`, `srai_w`, `srai_d`: 向量算术右移。
    * `srari_b`, `srari_h`, `srari_w`, `srari_d`: 向量算术右移并插入舍入位。
* **向量位操作指令:**
    * `bclri_b`, `bclri_h`, `bclri_w`, `bclri_d`: 向量清除指定位。
    * `bseti_b`, `bseti_h`, `bseti_w`, `bseti_d`: 向量设置指定位。
    * `bnegi_b`, `bnegi_h`, `bnegi_w`, `bnegi_d`: 向量取反指定位。
    * `binsli_b`, `binsli_h`, `binsli_w`, `binsli_d`: 向量位插入（左侧）。
    * `binsri_b`, `binsri_h`, `binsri_w`, `binsri_d`: 向量位插入（右侧）。
* **向量饱和指令:**
    * `sat_u_b`, `sat_u_h`, `sat_u_w`, `sat_u_d`: 向量无符号饱和。
    * `sat_s_b`, `sat_s_h`, `sat_s_w`, `sat_s_d`: 向量有符号饱和。
* **向量立即数加载指令:**
    * `ldi_b`, `ldi_h`, `ldi_w`, `ldi_d`: 将立即数加载到向量寄存器。
* **向量加载和存储指令:**
    * `ld_b`, `ld_h`, `ld_w`, `ld_d`: 从内存加载向量。
    * `st_b`, `st_h`, `st_w`, `st_d`: 将向量存储到内存。
* **三操作数向量指令 (仅在非 R6 版本中):**
    * `sll_v`, `sra_v`, `srl_v`, `bcrl_v`, `bset_v`, `bneg_v`, `binsl_v`:  一些向量移位和位操作指令。

**与 JavaScript 的关系:**

V8 引擎负责执行 JavaScript 代码。为了提高性能，V8 会将 JavaScript 代码编译成机器码。当 JavaScript 代码中涉及到一些数学运算，特别是涉及到浮点数和需要并行处理的运算时，V8 可能会利用 CPU 提供的 SIMD (Single Instruction, Multiple Data) 指令来加速这些运算。

MSA 是 MIPS 架构的 SIMD 扩展，因此这部分测试的代码直接关系到 V8 引擎在 MIPS64 架构上执行 JavaScript 代码的效率和正确性。例如，当 JavaScript 中进行大量的浮点数计算或者处理图像、音频等多媒体数据时，V8 可能会使用这些 MSA 指令。

**JavaScript 示例:**

虽然 JavaScript 本身没有直接对应于这些底层汇编指令的操作符，但某些 JavaScript 操作在 V8 引擎的底层实现中可能会用到类似的指令。

例如，考虑以下 JavaScript 代码：

```javascript
function processFloatArray(arr) {
  const result = new Float32Array(arr.length);
  for (let i = 0; i < arr.length; i++) {
    result[i] = Math.sqrt(arr[i]);
  }
  return result;
}

const data = new Float32Array([1.0, 4.0, 9.0, 16.0]);
const squaredRoots = processFloatArray(data);
console.log(squaredRoots); // 输出: Float32Array [ 1, 2, 3, 4 ]
```

在这个例子中，`Math.sqrt()` 函数计算数组中每个元素的平方根。在 MIPS64 架构上，V8 引擎可能会使用 `fsqrt_w` 这条 MSA 指令来并行计算多个元素的平方根，从而提高 `processFloatArray` 函数的执行效率。

再例如，考虑位运算：

```javascript
function bitwiseAnd(a, b) {
  return a & b;
}

const num1 = 0b10101010;
const num2 = 0b11001100;
const result = bitwiseAnd(num1, num2);
console.log(result.toString(2)); // 输出: 10001000
```

当对大的数据块进行位运算时，V8 可能会使用 `and_v` 等向量指令来并行处理多个位的运算。

总而言之，这部分 C++ 代码通过编写测试用例来验证 V8 引擎在生成 MIPS64 机器码时，能够正确地使用 MSA 指令来实现各种浮点和向量操作，从而确保 JavaScript 代码在 MIPS64 架构上高效且正确地执行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共7部分，请归纳一下它的功能

"""
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
  [](uint64_t wd, uint64_t ws, uint32_t m) {                                  \
    uint64_t res = 0;                                                         \
    int elem_size = kMSARegSize / lanes;                                      \
    for (int i = 0; i < lanes / 2; ++i) {                                     \
      int shift = elem_size * i;                                              \
      int64_t elem =                                                          \
          static_cast<int64_t>(((ws >> shift) & mask) << (64 - elem_size)) >> \
          (64 - elem_size);                                                   \
      res |= static_cast<uint64_t>((func)&mask) << shift;                     \
    }                                                                         \
    return res;                                                               \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaBit); ++i) {
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ slli_b(w2, w0, m % 8); },
        SLLI_SRLI_DF(kMSALanesByte, UINT8_MAX, (elem << (m % elem_size))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ slli_h(w2, w0, m % 16); },
        SLLI_SRLI_DF(kMSALanesHalf, UINT16_MAX, (elem << (m % elem_size))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ slli_w(w2, w0, m % 32); },
        SLLI_SRLI_DF(kMSALanesWord, UINT32_MAX, (elem << (m % elem_size))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ slli_d(w2, w0, m % 64); },
        SLLI_SRLI_DF(kMSALanesDword, UINT64_MAX, (elem << (m % elem_size))));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srli_b(w2, w0, m % 8); },
        SLLI_SRLI_DF(kMSALanesByte, UINT8_MAX, (elem >> (m % elem_size))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srli_h(w2, w0, m % 16); },
        SLLI_SRLI_DF(kMSALanesHalf, UINT16_MAX, (elem >> (m % elem_size))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srli_w(w2, w0, m % 32); },
        SLLI_SRLI_DF(kMSALanesWord, UINT32_MAX, (elem >> (m % elem_size))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srli_d(w2, w0, m % 64); },
        SLLI_SRLI_DF(kMSALanesDword, UINT64_MAX, (elem >> (m % elem_size))));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srlri_b(w2, w0, m % 8); },
        SLLI_SRLI_DF(
            kMSALanesByte, UINT8_MAX,
            (elem >> (m % elem_size)) + ((elem >> (m % elem_size - 1)) & 0x1)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srlri_h(w2, w0, m % 16); },
        SLLI_SRLI_DF(
            kMSALanesHalf, UINT16_MAX,
            (elem >> (m % elem_size)) + ((elem >> (m % elem_size - 1)) & 0x1)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srlri_w(w2, w0, m % 32); },
        SLLI_SRLI_DF(
            kMSALanesWord, UINT32_MAX,
            (elem >> (m % elem_size)) + ((elem >> (m % elem_size - 1)) & 0x1)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srlri_d(w2, w0, m % 64); },
        SLLI_SRLI_DF(
            kMSALanesDword, UINT64_MAX,
            (elem >> (m % elem_size)) + ((elem >> (m % elem_size - 1)) & 0x1)));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srai_b(w2, w0, m % 8); },
        SRAI_DF(kMSALanesByte, UINT8_MAX,
                ArithmeticShiftRight(elem, m % elem_size)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srai_h(w2, w0, m % 16); },
        SRAI_DF(kMSALanesHalf, UINT16_MAX,
                ArithmeticShiftRight(elem, m % elem_size)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srai_w(w2, w0, m % 32); },
        SRAI_DF(kMSALanesWord, UINT32_MAX,
                ArithmeticShiftRight(elem, m % elem_size)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srai_d(w2, w0, m % 64); },
        SRAI_DF(kMSALanesDword, UINT64_MAX,
                ArithmeticShiftRight(elem, m % elem_size)));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srari_b(w2, w0, m % 8); },
        SRAI_DF(kMSALanesByte, UINT8_MAX,
                ArithmeticShiftRight(elem, m % elem_size) +
                    ((elem >> (m % elem_size - 1)) & 0x1)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srari_h(w2, w0, m % 16); },
        SRAI_DF(kMSALanesHalf, UINT16_MAX,
                ArithmeticShiftRight(elem, m % elem_size) +
                    ((elem >> (m % elem_size - 1)) & 0x1)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srari_w(w2, w0, m % 32); },
        SRAI_DF(kMSALanesWord, UINT32_MAX,
                ArithmeticShiftRight(elem, m % elem_size) +
                    ((elem >> (m % elem_size - 1)) & 0x1)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ srari_d(w2, w0, m % 64); },
        SRAI_DF(kMSALanesDword, UINT64_MAX,
                ArithmeticShiftRight(elem, m % elem_size) +
                    ((elem >> (m % elem_size - 1)) & 0x1)));
  }
#undef SLLI_SRLI_DF
#undef SRAI_DF
}

TEST(MSA_bclri_bseti_bnegi) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaBit tc[] = {
      // wd_lo, wd_hi,    ws_lo,              ws_hi, m
      {0, 0, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 3},
      {0, 0, 0x64BE4F6DBE9CAA51, 0x6B23DE1A687D9CB9, 5},
      {0, 0, 0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 9},
      {0, 0, 0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 13},
      {0, 0, 0x566BE7BA4365B70A, 0x01EBBC1937D76CB4, 21},
      {0, 0, 0x380E2DEB9D3F8AAE, 0x017E0DE0BCC6CA42, 30},
      {0, 0, 0xA46A3A9BCB43F4E5, 0x1C62C8473BDFCFFB, 45},
      {0, 0, 0xF6759D85F23B5A2B, 0x5C042AE42C6D12C1, 61}};

#define BCLRI_BSETI_BNEGI_DF(lanes, mask, func) \
  [](uint64_t wd, uint64_t ws, uint32_t m) {    \
    uint64_t res = 0;                           \
    int elem_size = kMSARegSize / lanes;        \
    for (int i = 0; i < lanes / 2; ++i) {       \
      int shift = elem_size * i;                \
      uint64_t elem = (ws >> shift) & mask;     \
      res |= ((func)&mask) << shift;            \
    }                                           \
    return res;                                 \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaBit); ++i) {
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bclri_b(w2, w0, m % 8); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesByte, UINT8_MAX,
                             (~(1ull << (m % elem_size)) & elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bclri_h(w2, w0, m % 16); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesHalf, UINT16_MAX,
                             (~(1ull << (m % elem_size)) & elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bclri_w(w2, w0, m % 32); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesWord, UINT32_MAX,
                             (~(1ull << (m % elem_size)) & elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bclri_d(w2, w0, m % 64); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesDword, UINT64_MAX,
                             (~(1ull << (m % elem_size)) & elem)));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bseti_b(w2, w0, m % 8); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesByte, UINT8_MAX,
                             ((1ull << (m % elem_size)) | elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bseti_h(w2, w0, m % 16); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesHalf, UINT16_MAX,
                             ((1ull << (m % elem_size)) | elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bseti_w(w2, w0, m % 32); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesWord, UINT32_MAX,
                             ((1ull << (m % elem_size)) | elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bseti_d(w2, w0, m % 64); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesDword, UINT64_MAX,
                             ((1ull << (m % elem_size)) | elem)));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bnegi_b(w2, w0, m % 8); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesByte, UINT8_MAX,
                             ((1ull << (m % elem_size)) ^ elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bnegi_h(w2, w0, m % 16); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesHalf, UINT16_MAX,
                             ((1ull << (m % elem_size)) ^ elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bnegi_w(w2, w0, m % 32); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesWord, UINT32_MAX,
                             ((1ull << (m % elem_size)) ^ elem)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ bnegi_d(w2, w0, m % 64); },
        BCLRI_BSETI_BNEGI_DF(kMSALanesDword, UINT64_MAX,
                             ((1ull << (m % elem_size)) ^ elem)));
  }
#undef BCLRI_BSETI_BNEGI_DF
}

TEST(MSA_binsli_binsri) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaBit tc[] = {// wd_lo, wd_hi, ws_lo, ws_hi, m
                                {0x53F4457553BBD5B4, 0x5FB8250EACC296B2,
                                 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 3},
                                {0xF61BFDB0F312E6FC, 0xC9437568DD1EA925,
                                 0x64BE4F6DBE9CAA51, 0x6B23DE1A687D9CB9, 5},
                                {0x53F4457553BBD5B4, 0x5FB8250EACC296B2,
                                 0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 9},
                                {0xF61BFDB0F312E6FC, 0xC9437568DD1EA925,
                                 0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 13},
                                {0x53F4457553BBD5B4, 0x5FB8250EACC296B2,
                                 0x566BE7BA4365B70A, 0x01EBBC1937D76CB4, 21},
                                {0xF61BFDB0F312E6FC, 0xC9437568DD1EA925,
                                 0x380E2DEB9D3F8AAE, 0x017E0DE0BCC6CA42, 30},
                                {0x53F4457553BBD5B4, 0x5FB8250EACC296B2,
                                 0xA46A3A9BCB43F4E5, 0x1C62C8473BDFCFFB, 45},
                                {0xF61BFDB0F312E6FC, 0xC9437568DD1EA925,
                                 0xF6759D85F23B5A2B, 0x5C042AE42C6D12C1, 61}};

#define BINSLI_BINSRI_DF(lanes, mask, func)             \
  [](uint64_t wd, uint64_t ws, uint32_t m) {            \
    uint64_t res = 0;                                   \
    int elem_size = kMSARegSize / lanes;                \
    int bits = m % elem_size + 1;                       \
    for (int i = 0; i < lanes / 2; ++i) {               \
      int shift = elem_size * i;                        \
      uint64_t ws_elem = (ws >> shift) & mask;          \
      if (bits == elem_size) {                          \
        res |= (ws_elem & mask) << shift;               \
      } else {                                          \
        uint64_t r_mask = (1ull << bits) - 1;           \
        uint64_t l_mask = r_mask << (elem_size - bits); \
        USE(l_mask);                                    \
        uint64_t wd_elem = (wd >> shift) & mask;        \
        res |= ((func)&mask) << shift;                  \
      }                                                 \
    }                                                   \
    return res;                                         \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaBit); ++i) {
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsli_b(w2, w0, m % 8); },
        BINSLI_BINSRI_DF(kMSALanesByte, UINT8_MAX,
                         ((ws_elem & l_mask) | (wd_elem & ~l_mask))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsli_h(w2, w0, m % 16); },
        BINSLI_BINSRI_DF(kMSALanesHalf, UINT16_MAX,
                         ((ws_elem & l_mask) | (wd_elem & ~l_mask))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsli_w(w2, w0, m % 32); },
        BINSLI_BINSRI_DF(kMSALanesWord, UINT32_MAX,
                         ((ws_elem & l_mask) | (wd_elem & ~l_mask))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsli_d(w2, w0, m % 64); },
        BINSLI_BINSRI_DF(kMSALanesDword, UINT64_MAX,
                         ((ws_elem & l_mask) | (wd_elem & ~l_mask))));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsri_b(w2, w0, m % 8); },
        BINSLI_BINSRI_DF(kMSALanesByte, UINT8_MAX,
                         ((ws_elem & r_mask) | (wd_elem & ~r_mask))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsri_h(w2, w0, m % 16); },
        BINSLI_BINSRI_DF(kMSALanesHalf, UINT16_MAX,
                         ((ws_elem & r_mask) | (wd_elem & ~r_mask))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsri_w(w2, w0, m % 32); },
        BINSLI_BINSRI_DF(kMSALanesWord, UINT32_MAX,
                         ((ws_elem & r_mask) | (wd_elem & ~r_mask))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ binsri_d(w2, w0, m % 64); },
        BINSLI_BINSRI_DF(kMSALanesDword, UINT64_MAX,
                         ((ws_elem & r_mask) | (wd_elem & ~r_mask))));
  }
#undef BINSLI_BINSRI_DF
}

TEST(MSA_sat_s_sat_u) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaBit tc[] = {
      // wd_lo, wd_hi,    ws_lo,              ws_hi, m
      {0, 0, 0xF35862E13E3808B0, 0x4F41FFDEF2BFE636, 3},
      {0, 0, 0x64BE4F6DBE9CAA51, 0x6B23DE1A687D9CB9, 5},
      {0, 0, 0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 9},
      {0, 0, 0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 13},
      {0, 0, 0x566BE7BA4365B70A, 0x01EBBC1937D76CB4, 21},
      {0, 0, 0x380E2DEB9D3F8AAE, 0x017E0DE0BCC6CA42, 30},
      {0, 0, 0xA46A3A9BCB43F4E5, 0x1C62C8473BDFCFFB, 45},
      {0, 0, 0xF6759D85F23B5A2B, 0x5C042AE42C6D12C1, 61}};

#define SAT_DF(lanes, mask, func)                                              \
  [](uint64_t wd, uint64_t ws, uint32_t m) {                                   \
    uint64_t res = 0;                                                          \
    int elem_size = kMSARegSize / lanes;                                       \
    m %= elem_size;                                                            \
    for (int i = 0; i < lanes / 2; ++i) {                                      \
      int shift = elem_size * i;                                               \
      uint64_t elem_u64 = (ws >> shift) & mask;                                \
      int64_t elem_i64 = static_cast<int64_t>(elem_u64 << (64 - elem_size)) >> \
                         (64 - elem_size);                                     \
      USE(elem_i64);                                                           \
      res |= ((func)&mask) << shift;                                           \
    }                                                                          \
    return res;                                                                \
  }

#define M_MAX_INT(x) static_cast<int64_t>((1LL << ((x)-1)) - 1)
#define M_MIN_INT(x) static_cast<int64_t>(-(1LL << ((x)-1)))
#define M_MAX_UINT(x) static_cast<uint64_t>(-1ULL >> (64 - (x)))

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaBit); ++i) {
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_u_b(w2, w0, m % 8); },
        SAT_DF(kMSALanesByte, UINT8_MAX,
               (elem_u64 < M_MAX_UINT(m + 1) ? elem_u64 : M_MAX_UINT(m + 1))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_u_h(w2, w0, m % 16); },
        SAT_DF(kMSALanesHalf, UINT16_MAX,
               (elem_u64 < M_MAX_UINT(m + 1) ? elem_u64 : M_MAX_UINT(m + 1))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_u_w(w2, w0, m % 32); },
        SAT_DF(kMSALanesWord, UINT32_MAX,
               (elem_u64 < M_MAX_UINT(m + 1) ? elem_u64 : M_MAX_UINT(m + 1))));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_u_d(w2, w0, m % 64); },
        SAT_DF(kMSALanesDword, UINT64_MAX,
               (elem_u64 < M_MAX_UINT(m + 1) ? elem_u64 : M_MAX_UINT(m + 1))));

    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_s_b(w2, w0, m % 8); },
        SAT_DF(
            kMSALanesByte, UINT8_MAX,
            (elem_i64 < M_MIN_INT(m + 1)
                 ? M_MIN_INT(m + 1)
                 : elem_i64 > M_MAX_INT(m + 1) ? M_MAX_INT(m + 1) : elem_i64)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_s_h(w2, w0, m % 16); },
        SAT_DF(
            kMSALanesHalf, UINT16_MAX,
            (elem_i64 < M_MIN_INT(m + 1)
                 ? M_MIN_INT(m + 1)
                 : elem_i64 > M_MAX_INT(m + 1) ? M_MAX_INT(m + 1) : elem_i64)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_s_w(w2, w0, m % 32); },
        SAT_DF(
            kMSALanesWord, UINT32_MAX,
            (elem_i64 < M_MIN_INT(m + 1)
                 ? M_MIN_INT(m + 1)
                 : elem_i64 > M_MAX_INT(m + 1) ? M_MAX_INT(m + 1) : elem_i64)));
    run_msa_bit(
        &tc[i],
        [](MacroAssembler& assm, uint32_t m) { __ sat_s_d(w2, w0, m % 64); },
        SAT_DF(
            kMSALanesDword, UINT64_MAX,
            (elem_i64 < M_MIN_INT(m + 1)
                 ? M_MIN_INT(m + 1)
                 : elem_i64 > M_MAX_INT(m + 1) ? M_MAX_INT(m + 1) : elem_i64)));
  }

#undef SAT_DF
#undef M_MAX_INT
#undef M_MIN_INT
#undef M_MAX_UINT
}

template <typename InstFunc, typename OperFunc>
void run_msa_i10(int32_t input, InstFunc GenerateVectorInstructionFunc,
                 OperFunc GenerateOperationFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  GenerateVectorInstructionFunc(assm, input);

  store_elements_of_vector(&assm, w0, a0);

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

  CHECK_EQ(GenerateOperationFunc(input), res.d[0]);
  CHECK_EQ(GenerateOperationFunc(input), res.d[1]);
}

TEST(MSA_ldi) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // signed 10bit integers: -512 .. 511
  int32_t tc[] = {0, -1, 1, 256, -256, -178, 352, -512, 511};

#define LDI_DF(lanes, mask)                                        \
  [](int32_t s10) {                                                \
    uint64_t res = 0;                                              \
    int elem_size = kMSARegSize / lanes;                           \
    int64_t s10_64 =                                               \
        ArithmeticShiftRight(static_cast<int64_t>(s10) << 54, 54); \
    for (int i = 0; i < lanes / 2; ++i) {                          \
      int shift = elem_size * i;                                   \
      res |= static_cast<uint64_t>(s10_64 & mask) << shift;        \
    }                                                              \
    return res;                                                    \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(int32_t); ++i) {
    run_msa_i10(tc[i],
                [](MacroAssembler& assm, int32_t s10) { __ ldi_b(w0, s10); },
                LDI_DF(kMSALanesByte, UINT8_MAX));
    run_msa_i10(tc[i],
                [](MacroAssembler& assm, int32_t s10) { __ ldi_h(w0, s10); },
                LDI_DF(kMSALanesHalf, UINT16_MAX));
    run_msa_i10(tc[i],
                [](MacroAssembler& assm, int32_t s10) { __ ldi_w(w0, s10); },
                LDI_DF(kMSALanesWord, UINT32_MAX));
    run_msa_i10(tc[i],
                [](MacroAssembler& assm, int32_t s10) { __ ldi_d(w0, s10); },
                LDI_DF(kMSALanesDword, UINT64_MAX));
  }
#undef LDI_DF
}

template <typename T, typename InstFunc>
void run_msa_mi10(InstFunc GenerateVectorInstructionFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  T in_test_vector[1024];
  T out_test_vector[1024];

  T* in_array_middle = in_test_vector + arraysize(in_test_vector) / 2;
  T* out_array_middle = out_test_vector + arraysize(out_test_vector) / 2;

  v8::base::RandomNumberGenerator rand_gen(v8_flags.random_seed);
  for (unsigned int i = 0; i < arraysize(in_test_vector); i++) {
    in_test_vector[i] = static_cast<T>(rand_gen.NextInt());
    out_test_vector[i] = 0;
  }

  GenerateVectorInstructionFunc(assm);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F5>::FromCode(isolate, *code);

  f.Call(in_array_middle, out_array_middle, 0, 0, 0);

  CHECK_EQ(memcmp(in_test_vector, out_test_vector, arraysize(in_test_vector)),
           0);
}

TEST(MSA_load_store_vector) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  run_msa_mi10<uint8_t>([](MacroAssembler& assm) {
    for (int i = -512; i < 512; i += 16) {
      __ ld_b(w0, MemOperand(a0, i));
      __ st_b(w0, MemOperand(a1, i));
    }
  });
  run_msa_mi10<uint16_t>([](MacroAssembler& assm) {
    for (int i = -512; i < 512; i += 8) {
      __ ld_h(w0, MemOperand(a0, i));
      __ st_h(w0, MemOperand(a1, i));
    }
  });
  run_msa_mi10<uint32_t>([](MacroAssembler& assm) {
    for (int i = -512; i < 512; i += 4) {
      __ ld_w(w0, MemOperand(a0, i));
      __ st_w(w0, MemOperand(a1, i));
    }
  });
  run_msa_mi10<uint64_t>([](MacroAssembler& assm) {
    for (int i = -512; i < 512; i += 2) {
      __ ld_d(w0, MemOperand(a0, i));
      __ st_d(w0, MemOperand(a1, i));
    }
  });
}

struct TestCaseMsa3R {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint64_t wt_lo;
  uint64_t wt_hi;
  uint64_t wd_lo;
  uint64_t wd_hi;
};

static const uint64_t Unpredictable = 0x312014017725ll;

template <typename InstFunc, typename OperFunc>
void run_msa_3r(struct TestCaseMsa3R* input, InstFunc GenerateI5InstructionFunc,
                OperFunc GenerateOperationFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(&assm, &(input->wt_lo), w0, t0, t1);
  load_elements_of_vector(&assm, &(input->ws_lo), w1, t0, t1);
  load_elements_of_vector(&assm, &(input->wd_lo), w2, t0, t1);

  GenerateI5InstructionFunc(assm);

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

  GenerateOperationFunc(&input->ws_lo, &input->wt_lo, &input->wd_lo);
  if (input->wd_lo != Unpredictable) {
    CHECK_EQ(input->wd_lo, res.d[0]);
  }
  if (input->wd_hi != Unpredictable) {
    CHECK_EQ(input->wd_hi, res.d[1]);
  }
}

TEST(MSA_3R_instructions) {
  if (kArchVariant == kMips64r6 || !CpuFeatures::IsSupported(MIPS_SIMD)) return;

  CcTest::InitializeVM();

  struct TestCaseMsa3R tc[] = {
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x1169751BB9A7D9C3,
       0xF7A594AEC8EF8A9C, 0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C},
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x2B665362C4E812DF,
       0x3A0D80D68B3F8BC8, 0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8},
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x1169751BB9A7D9C3,
       0xF7A594AEC8EF8A9C, 0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C},
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x2B665362C4E812DF,
       0x3A0D80D68B3F8BC8, 0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8},
      {0xFFAB807F807FFFCD, 0x7F23FF80FF567F80, 0xFFAB807F807FFFCD,
       0x7F23FF80FF567F80, 0xFFAB807F807FFFCD, 0x7F23FF80FF567F80},
      {0x80FFEFFF7F12807F, 0x807F80FF7FDEFF78, 0x80FFEFFF7F12807F,
       0x807F80FF7FDEFF78, 0x80FFEFFF7F12807F, 0x807F80FF7FDEFF78},
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
       0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
      {0x0000000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
       0x0000000000000000, 0x0000000000000000, 0xFFFFFFFFFFFFFFFF},
      {0xFFFF0000FFFF0000, 0xFFFF0000FFFF0000, 0xFFFF0000FFFF0000,
       0xFFFF0000FFFF0000, 0xFFFF0000FFFF0000, 0xFFFF0000FFFF0000},
      {0xFF00FF00FF00FF00, 0xFF00FF00FF00FF00, 0xFF00FF00FF00FF00,
       0xFF00FF00FF00FF00, 0xFF00FF00FF00FF00, 0xFF00FF00FF00FF00},
      {0xF0F0F0F0F0F0F0F0, 0xF0F0F0F0F0F0F0F0, 0xF0F0F0F0F0F0F0F0,
       0xF0F0F0F0F0F0F0F0, 0xF0F0F0F0F0F0F0F0, 0xF0F0F0F0F0F0F0F0},
      {0xFF0000FFFF0000FF, 0xFF0000FFFF0000FF, 0xFF0000FFFF0000FF,
       0xFF0000FFFF0000FF, 0xFF0000FFFF0000FF, 0xFF0000FFFF0000FF},
      {0xFFFF00000000FFFF, 0xFFFF00000000FFFF, 0xFFFF00000000FFFF,
       0xFFFF00000000FFFF, 0xFFFF00000000FFFF, 0xFFFF00000000FFFF}};

#define SLL_DF(T, lanes, mask)                                             \
  int size_in_bits = kMSARegSize / lanes;                                  \
  for (int i = 0; i < 2; i++) {                                            \
    uint64_t res = 0;                                                      \
    for (int j = 0; j < lanes / 2; ++j) {                                  \
      uint64_t shift = size_in_bits * j;                                   \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                  \
      T shift_op = static_cast<T>((wt[i] >> shift) & mask) % size_in_bits; \
      res |= (static_cast<uint64_t>(src_op << shift_op) & mask) << shift;  \
    }                                                                      \
    wd[i] = res;                                                           \
  }

#define SRA_DF(T, lanes, mask)                                               \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      int shift_op = ((wt[i] >> shift) & mask) % size_in_bits;               \
      res |= (static_cast<uint64_t>(ArithmeticShiftRight(src_op, shift_op) & \
                                    mask))                                   \
             << shift;                                                       \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define SRL_DF(T, lanes, mask)                                               \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      T shift_op = static_cast<T>(((wt[i] >> shift) & mask) % size_in_bits); \
      res |= (static_cast<uint64_t>(src_op >> shift_op) & mask) << shift;    \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define BCRL_DF(T, lanes, mask)                                              \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      T shift_op = static_cast<T>(((wt[i] >> shift) & mask) % size_in_bits); \
      T r = (static_cast<T>(~(1ull << shift_op)) & src_op) & mask;           \
      res |= static_cast<uint64_t>(r) << shift;                              \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define BSET_DF(T, lanes, mask)                                              \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      T shift_op = static_cast<T>(((wt[i] >> shift) & mask) % size_in_bits); \
      T r = (static_cast<T>(1ull << shift_op) | src_op) & mask;              \
      res |= static_cast<uint64_t>(r) << shift;                              \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define BNEG_DF(T, lanes, mask)                                              \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      T shift_op = static_cast<T>(((wt[i] >> shift) & mask) % size_in_bits); \
      T r = (static_cast<T>(1ull << shift_op) ^ src_op) & mask;              \
      res |= static_cast<uint64_t>(r) << shift;                              \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define BINSL_DF(T, lanes, mask)                                             \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                     \
      T wd_op = static_cast<T>((wd[i] >> shift) & mask);                     \
      T shift_op = static_cast<T>(((wt[i] >> shift) & mask) % size_in_bits); \
      int64_t bits = shift_op + 1;           
"""


```