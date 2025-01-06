Response:
The user wants to understand the functionality of a C++ file used for testing the RISC-V 32-bit assembler in the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `test-assembler-riscv32.cc` strongly suggests this file contains unit tests for the RISC-V 32-bit assembler within V8. The `cctest` directory further confirms it's part of the V8 testing framework.

2. **Scan for keywords and patterns:** Look for recurring patterns and keywords within the provided code snippet. The `#define UTEST_RVV_*` macros are prominent and indicate a testing structure. Keywords like `TEST`, `CHECK_*`, `GenAndRunTest`, `MacroAssembler`, and RISC-V instruction mnemonics (e.g., `vfwmacc_vv`, `vslidedown_vi`) are crucial.

3. **Analyze the macros:**  The macros are clearly defining test cases for different RISC-V Vector (RVV) instructions. They automate the process of setting up test data, generating assembly code, executing it, and verifying the results. Notice the variations in macro names (`UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES`, `UTEST_RVV_FMA_VV_FORM_WITH_RES`, etc.) which suggest different categories of instructions being tested (e.g., widening fused multiply-add).

4. **Focus on individual test cases:** Examine the structure of a single test case defined by a macro. It generally involves:
    * Checking for RVV support.
    * Initializing the V8 VM.
    * Defining a lambda function (`fn`) that contains the assembly code to be tested. This code uses the `MacroAssembler` to generate RISC-V instructions.
    * Setting up input data (arrays of floats, doubles, integers).
    * Calling `GenAndRunTest` to execute the generated assembly code with the input data.
    * Comparing the actual results with the expected results using `CHECK_*` macros.

5. **Infer the tested functionalities:** Based on the instruction mnemonics within the `fn` lambda functions, identify the specific RISC-V vector instructions being tested. For example, `vfwmacc_vv` and `vfwmacc_vf` relate to widening floating-point fused multiply-add operations. `vslidedown_vi` and `vslideup_vi` are vector slide instructions.

6. **Address the specific questions:**
    * **Functionality:** Summarize the overall purpose as unit testing for the RISC-V 32-bit assembler, specifically focusing on RVV instructions.
    * **.tq extension:**  Confirm that `.cc` indicates C++ source, not Torque.
    * **JavaScript relation:** Explain that while directly unrelated to JavaScript *code*, these tests ensure the correct execution of JavaScript when the underlying architecture utilizes these RISC-V instructions. Provide a conceptual JavaScript example to illustrate a scenario where these instructions might be relevant (e.g., vector operations in numerical computations).
    * **Code logic and assumptions:** For a concrete example, pick a simple test case like `vslidedown_vi`. Define clear input arrays and the expected output based on the slide-down operation.
    * **Common programming errors:**  Think about the types of errors developers might make when working with vector instructions or assembly: incorrect instruction usage, wrong register selection, off-by-one errors in offsets, etc.
    * **Overall summary:**  Reiterate the main purpose of the code as testing the correctness of the RISC-V assembler implementation for vector instructions.

7. **Structure the answer:** Organize the information logically, starting with the main functionality and then addressing each specific question. Use clear and concise language. Use code blocks for the JavaScript example and the code logic example to improve readability.

8. **Review and refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Make any necessary adjustments for better flow and understanding. For instance, ensure the JavaScript example highlights a potential use case for the tested instructions without being overly complex.

By following this process, we can systematically analyze the provided code snippet and generate a comprehensive and informative answer that addresses all aspects of the user's request.
目录 `v8/test/cctest/test-assembler-riscv32.cc` 是 V8 JavaScript 引擎的源代码，专门用于测试 RISC-V 32 位架构的汇编器（assembler）。

**功能归纳:**

这个文件的主要功能是 **对 RISC-V 32 位汇编器的各种指令进行单元测试，特别是 RISC-V Vector (RVV) 扩展指令。** 它通过编写一系列的测试用例，来验证汇编器生成的机器码是否能够正确地执行预期的操作。

**具体功能分解:**

1. **测试宏定义:** 文件中定义了大量的宏 (例如 `UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES`, `UTEST_RVV_FMA_VV_FORM_WITH_RES`, `UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES` 等)。这些宏是测试用例的模板，用于简化编写重复性测试代码的过程。它们通常包含以下步骤：
    * 检查 CPU 是否支持相关的 RISC-V 特性 (`CpuFeatures::IsSupported(RISCV_SIMD)`).
    * 初始化 V8 虚拟机 (`CcTest::InitializeVM()`).
    * 定义一个 lambda 函数 (`fn`)，该函数使用 `MacroAssembler` 生成需要测试的 RISC-V 汇编指令序列。
    * 设置测试所需的输入数据 (例如，浮点数、整数数组)。
    * 调用 `GenAndRunTest` 函数，该函数负责执行生成的汇编代码并返回结果。
    * 使用 `CHECK_*` 宏 (例如 `CHECK_DOUBLE_EQ`, `CHECK_FLOAT_EQ`, `CHECK_EQ`) 来比较实际结果与预期结果是否一致。

2. **测试各种 RVV 指令:**  从宏名称和 lambda 函数中生成的汇编指令可以看出，该文件覆盖了多种 RVV 指令的测试，包括：
    * **浮点数融合乘加 (Fused Multiply-Add - FMA) 指令:** 例如 `vfwmacc_vv`, `vfwmacc_vf`, `vfmadd_vv`, `vfmadd_vf` 等，测试向量与向量、向量与标量之间的单精度和双精度浮点数 FMA 操作。
    * **浮点数规约求和指令 (Reduction Sum):** 例如 `vfwredusum_vs`, `vfwredosum_vs`，测试将向量元素规约求和的操作。
    * **向量截断指令 (Vector Narrowing Clip):** 例如 `vnclipu_vi`, `vnclip_vi`，测试将较大位宽的向量元素截断为较小位宽的操作。
    * **向量整数扩展指令 (Vector Integer Extension):** 例如 `vzext_vf2`, `vsext_vf2` 等，测试将较小位宽的整数向量扩展为较大位宽的操作。
    * **向量合并指令 (Vector Merge):** 例如 `vfmerge_vf`，测试根据掩码条件合并两个向量的操作。
    * **向量滑动指令 (Vector Slide):** 例如 `vslidedown_vi`, `vslideup_vi`, `vslidedown_vx`, `vslideup_vx`，测试在向量中滑动元素的操作。

**关于文件后缀和 JavaScript 关系:**

* 文件的后缀是 `.cc`，这是标准的 C++ 源文件后缀。因此，`v8/test/cctest/test-assembler-riscv32.cc` 不是 Torque 源代码。
* 该文件与 JavaScript 的功能有间接关系。因为它测试的是 RISC-V 32 位架构的汇编器，而 V8 引擎最终会将 JavaScript 代码编译成目标架构的机器码执行。因此，确保汇编器的正确性对于 V8 能够正确高效地执行 JavaScript 代码至关重要。

**JavaScript 举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的汇编指令可能会在 V8 执行某些 JavaScript 操作时被使用。例如，当 JavaScript 代码执行涉及 SIMD (单指令多数据) 操作或者需要高性能数值计算时，V8 可能会利用 RVV 指令。

```javascript
// 假设 JavaScript 引擎底层使用了 RVV 指令来加速向量运算

const a = [1.0, 2.0, 3.0, 4.0];
const b = [5.0, 6.0, 7.0, 8.0];
const c = [0.5, 0.5, 0.5, 0.5];

// 执行向量乘法和加法 (类似于 FMA 指令)
const result = a.map((val, index) => val * b[index] + c[index]);

console.log(result); // 输出: [ 5.5, 12.5, 21.5, 32.5 ]
```

在这个 JavaScript 例子中，`map` 函数执行了对数组元素的逐个操作，这在底层可能会被 V8 优化，利用 RVV 的 FMA 指令一次处理多个元素的乘法和加法，从而提高性能。 `test-assembler-riscv32.cc` 中的测试用例就是为了确保 V8 在生成这些 RVV 指令时的正确性。

**代码逻辑推理和假设输入输出:**

以 `UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, int32_t, 32, ARRAY(int32_t), (i + offset) < n ? src[i + offset] : 0)` 这个测试宏实例为例：

**假设输入:**

* `type`: `int32_t` (32位整数)
* `width`: 32 (每个元素 32 位)
* `array`: 假设 `ARRAY(int32_t)` 返回一个包含 `[1, 2, 3, 4, 5, 6, 7, 8]` 的数组 (假设 `kRvvVLEN / 32` 为 8)。
* `offset`: 2

**代码逻辑:**  测试 `vslidedown_vi` 指令，将向量 `src` 的元素向下移动 `offset` 位。空出的高位用 0 填充。

**预期输出 (`expect_res`):**

对于 `dst[i]`：
* 当 `i = 0` 时， `(0 + 2) < 8` 为真， `expect_res = src[0 + 2] = src[2] = 3`
* 当 `i = 1` 时， `(1 + 2) < 8` 为真， `expect_res = src[1 + 2] = src[3] = 4`
* 当 `i = 2` 时， `(2 + 2) < 8` 为真， `expect_res = src[2 + 2] = src[4] = 5`
* 当 `i = 3` 时， `(3 + 2) < 8` 为真， `expect_res = src[3 + 2] = src[5] = 6`
* 当 `i = 4` 时， `(4 + 2) < 8` 为真， `expect_res = src[4 + 2] = src[6] = 7`
* 当 `i = 5` 时， `(5 + 2) < 8` 为真， `expect_res = src[5 + 2] = src[7] = 8`
* 当 `i = 6` 时， `(6 + 2) < 8` 为假， `expect_res = 0`
* 当 `i = 7` 时， `(7 + 2) < 8` 为假， `expect_res = 0`

因此，预期的 `dst` 数组应该是 `[3, 4, 5, 6, 7, 8, 0, 0]`.

**涉及用户常见的编程错误:**

在手动编写汇编代码或使用 SIMD 指令时，用户容易犯以下错误：

1. **内存访问越界:**  例如，在使用向量加载/存储指令时，指定的内存地址或访问长度超出分配的内存范围。
2. **数据类型不匹配:**  例如，将浮点数加载到整数寄存器，或对不同数据类型的向量进行操作。
3. **指令使用错误:**  误解指令的功能或操作数，例如在 FMA 指令中错误地指定操作数的顺序。
4. **向量长度和跨步 (stride) 计算错误:** 在使用向量指令时，向量的有效长度和访问内存的步长需要正确计算，否则可能导致数据错误或性能下降。
5. **舍入模式错误:**  在浮点数运算中，选择错误的舍入模式可能导致计算结果不准确。例如，使用了截断舍入，但期望的是四舍五入。

**代码示例 (可能导致错误):**

```c++
// 假设要对两个浮点数向量进行加法，并将结果存储到第三个向量

float a[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
float b[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
float result[4]; // 错误：result 数组长度不足

// ... 汇编代码 ...
// 可能会使用 RVV 的向量加法指令将 a 和 b 的前 8 个元素相加
// 并尝试将结果存储到 result 中，但 result 只有 4 个元素的位置，
// 导致内存写入越界。
```

**总结 (针对第 4 部分):**

这部分代码主要集中在 **测试 RISC-V 32 位架构中与向量浮点数运算和向量置换相关的 RVV 指令**。它定义了各种宏来方便地生成和运行测试用例，涵盖了融合乘加、规约求和、截断、扩展、合并和滑动等多种操作。通过这些测试，可以确保 V8 引擎在 RISC-V 32 位平台上能够正确地生成和执行这些复杂的向量指令，从而保证 JavaScript 代码的性能和正确性。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
nt32_t, int32_t>((int32_t)addend_arr,        \
                                          (int32_t)right_mul_arr,     \
                                          (int32_t)left_mul_arr, fn); \
          for (uint32_t i = 0; i < 2; i++) {                          \
            CHECK_DOUBLE_EQ((expect_res), addend_arr[i]);             \
          }                                                           \
        }                                                             \
      }                                                               \
    }                                                                 \
  }

// Tests for vector single-width floating-point fused multiply-add Instructions
// between vectors and scalar
#define UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(instr_name, float_array,    \
                                           double_array, expect_res)   \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                      \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                 \
    CcTest::InitializeVM();                                            \
    double addend_arr[2] = {0};                                        \
    float right_mul_arr[4] = {0};                                      \
    auto fn = [](MacroAssembler& assm) {                               \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                             \
      __ vl(v0, a0, 0, VSew::E32);                                     \
      __ flw(fa1, a1, 0);                                              \
      __ vl(v2, a2, 0, VSew::E32);                                     \
      __ instr_name(v0, fa1, v2);                                      \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                             \
      __ vs(v0, a0, 0, VSew::E64);                                     \
    };                                                                 \
    for (double rs1_dval : double_array) {                             \
      for (float rs2_fval : float_array) {                             \
        for (float rs3_fval : float_array) {                           \
          for (double& src : addend_arr) src = rs1_dval;               \
          for (float& src : right_mul_arr) src = rs3_fval;             \
          double rs2_dval = static_cast<double>(rs2_fval);             \
          double rs3_dval = static_cast<double>(rs3_fval);             \
          GenAndRunTest<int32_t, int32_t>((int32_t)addend_arr,         \
                                          (int32_t)&rs2_fval,          \
                                          (int32_t)right_mul_arr, fn); \
          for (uint32_t i = 0; i < 2; i++) {                           \
            CHECK_DOUBLE_EQ((expect_res), addend_arr[i]);              \
          }                                                            \
        }                                                              \
      }                                                                \
    }                                                                  \
  }

#define ARRAY_FLOAT compiler::ValueHelper::GetVector<float>()
#define ARRAY_DOUBLE compiler::ValueHelper::GetVector<double>()
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwmacc_vv, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, rs3_dval, rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwmacc_vf, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, rs3_dval, rs1_dval))
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwnmacc_vv, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, -rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwnmacc_vf, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, -rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwmsac_vv, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwmsac_vf, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwnmsac_vv, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, -rs3_dval, rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwnmsac_vf, ARRAY_FLOAT, ARRAY_DOUBLE,
                                   std::fma(rs2_dval, -rs3_dval, rs1_dval))

#undef ARRAY_DOUBLE
#undef ARRAY_FLOAT
#undef UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES
#undef UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES

// Tests for vector single-width floating-point fused multiply-add Instructions
// between vectors
#define UTEST_RVV_FMA_VV_FORM_WITH_RES(instr_name, array, expect_res)        \
  TEST(RISCV_UTEST_##instr_name) {                                           \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    auto fn = [](MacroAssembler& assm) {                                     \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                   \
      __ vfmv_vf(v0, fa0);                                                   \
      __ vfmv_vf(v1, fa1);                                                   \
      __ vfmv_vf(v2, fa2);                                                   \
      __ instr_name(v0, v1, v2);                                             \
      __ vfmv_fs(fa0, v0);                                                   \
    };                                                                       \
    for (float rs1_fval : array) {                                           \
      for (float rs2_fval : array) {                                         \
        for (float rs3_fval : array) {                                       \
          auto res =                                                         \
              GenAndRunTest<float, float>(rs1_fval, rs2_fval, rs3_fval, fn); \
          CHECK_FLOAT_EQ(expect_res, res);                                   \
        }                                                                    \
      }                                                                      \
    }                                                                        \
  }

// Tests for vector single-width floating-point fused multiply-add Instructions
// between vectors and scalar
#define UTEST_RVV_FMA_VF_FORM_WITH_RES(instr_name, array, expect_res)        \
  TEST(RISCV_UTEST_##instr_name) {                                           \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    auto fn = [](MacroAssembler& assm) {                                     \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                   \
      __ vfmv_vf(v0, fa0);                                                   \
      __ vfmv_vf(v2, fa2);                                                   \
      __ instr_name(v0, fa1, v2);                                            \
      __ vfmv_fs(fa0, v0);                                                   \
    };                                                                       \
    for (float rs1_fval : array) {                                           \
      for (float rs2_fval : array) {                                         \
        for (float rs3_fval : array) {                                       \
          auto res =                                                         \
              GenAndRunTest<float, float>(rs1_fval, rs2_fval, rs3_fval, fn); \
          CHECK_FLOAT_EQ(expect_res, res);                                   \
        }                                                                    \
      }                                                                      \
    }                                                                        \
  }

#define ARRAY_FLOAT compiler::ValueHelper::GetVector<float>()

UTEST_RVV_FMA_VV_FORM_WITH_RES(vfmadd_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs1_fval, rs3_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfmadd_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs1_fval, rs3_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfnmadd_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs1_fval, -rs3_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfnmadd_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs1_fval, -rs3_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfmsub_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs1_fval, -rs3_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfmsub_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs1_fval, -rs3_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfnmsub_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs1_fval, rs3_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfnmsub_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs1_fval, rs3_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfmacc_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs3_fval, rs1_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfmacc_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs3_fval, rs1_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfnmacc_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs3_fval, -rs1_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfnmacc_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs3_fval, -rs1_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfmsac_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs3_fval, -rs1_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfmsac_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, rs3_fval, -rs1_fval))
UTEST_RVV_FMA_VV_FORM_WITH_RES(vfnmsac_vv, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs3_fval, rs1_fval))
UTEST_RVV_FMA_VF_FORM_WITH_RES(vfnmsac_vf, ARRAY_FLOAT,
                               std::fma(rs2_fval, -rs3_fval, rs1_fval))

#undef ARRAY_FLOAT
#undef UTEST_RVV_FMA_VV_FORM_WITH_RES
#undef UTEST_RVV_FMA_VF_FORM_WITH_RES

// Tests for vector Widening Floating-Point Reduction Instructions
#define UTEST_RVV_VFW_REDSUM_VV_FORM_WITH_RES(instr_name)              \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                      \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                 \
    CcTest::InitializeVM();                                            \
    double result = 0;                                                 \
    auto fn = [&result](MacroAssembler& assm) {                        \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                             \
      __ vfmv_vf(v2, fa0);                                             \
      __ vfmv_vf(v4, fa0);                                             \
      __ instr_name(v0, v2, v4);                                       \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                             \
      __ li(a0, Operand(int32_t(&result)));                            \
      __ vfmv_fs(fa0, v0);                                             \
      __ fsd(fa0, a0, 0);                                              \
    };                                                                 \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) { \
      std::vector<double> temp_arr(kRvvVLEN / 32,                      \
                                   static_cast<double>(rs1_fval));     \
      double expect_res = base::bit_cast<double>(                      \
          (uint64_t)base::bit_cast<uint32_t>(rs1_fval) << 32 |         \
          base::bit_cast<uint32_t>(rs1_fval));                         \
      for (double val : temp_arr) {                                    \
        if (is_invalid_fadd(expect_res, val)) {                        \
          expect_res = std::numeric_limits<float>::quiet_NaN();        \
          break;                                                       \
        }                                                              \
        expect_res += val;                                             \
        if (std::isnan(expect_res)) {                                  \
          expect_res = std::numeric_limits<double>::quiet_NaN();       \
          break;                                                       \
        }                                                              \
      }                                                                \
      GenAndRunTest<int32_t, float>(rs1_fval, fn);                     \
      CHECK_DOUBLE_EQ(UseCanonicalNan<double>(expect_res), result);    \
    }                                                                  \
  }

UTEST_RVV_VFW_REDSUM_VV_FORM_WITH_RES(vfwredusum_vs)
UTEST_RVV_VFW_REDSUM_VV_FORM_WITH_RES(vfwredosum_vs)

#undef UTEST_RVV_VFW_REDSUM_VV_FORM_WITH_RES
// calculate the value of r used in rounding
static inline uint8_t get_round(int vxrm, uint64_t v, uint8_t shift) {
  // uint8_t d = extract64(v, shift, 1);
  uint8_t d = unsigned_bitextract_64(shift, shift, v);
  uint8_t d1;
  uint64_t D1, D2;

  if (shift == 0 || shift > 64) {
    return 0;
  }

  // d1 = extract64(v, shift - 1, 1);
  d1 = unsigned_bitextract_64(shift - 1, shift - 1, v);
  // D1 = extract64(v, 0, shift);
  D1 = unsigned_bitextract_64(shift - 1, 0, v);
  if (vxrm == 0) { /* round-to-nearest-up (add +0.5 LSB) */
    return d1;
  } else if (vxrm == 1) { /* round-to-nearest-even */
    if (shift > 1) {
      // D2 = extract64(v, 0, shift - 1);
      D2 = unsigned_bitextract_64(shift - 2, 0, v);
      return d1 & ((D2 != 0) | d);
    } else {
      return d1 & d;
    }
  } else if (vxrm == 3) { /* round-to-odd (OR bits into LSB, aka "jam") */
    return !d & (D1 != 0);
  }
  return 0; /* round-down (truncate) */
}

#define UTEST_RVV_VNCLIP_E32M2_E16M1(instr_name, sign)                       \
  TEST(RISCV_UTEST_##instr_name##_E32M2_E16M1) {                             \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    constexpr FPURoundingMode vxrm = RNE;                                    \
    CcTest::InitializeVM();                                                  \
    Isolate* isolate = CcTest::i_isolate();                                  \
    HandleScope scope(isolate);                                              \
    for (int32_t x : compiler::ValueHelper::GetVector<int>()) {              \
      for (uint8_t shift = 0; shift < 32; shift++) {                         \
        auto fn = [shift](MacroAssembler& assm) {                            \
          __ VU.set(vxrm);                                                   \
          __ VU.set(t0, VSew::E32, Vlmul::m2);                               \
          __ vl(v2, a0, 0, VSew::E32);                                       \
          __ VU.set(t0, VSew::E16, Vlmul::m1);                               \
          __ instr_name(v4, v2, shift);                                      \
          __ vs(v4, a1, 0, VSew::E16);                                       \
        };                                                                   \
        struct T {                                                           \
          sign##int32_t src[8] = {0};                                        \
          sign##int16_t dst[8] = {0};                                        \
          sign##int16_t ref[8] = {0};                                        \
        } t;                                                                 \
        for (auto& src : t.src) src = static_cast<sign##int32_t>(x);         \
        for (auto& ref : t.ref)                                              \
          ref = base::saturated_cast<sign##int16_t>(                         \
              (static_cast<sign##int32_t>(x) >> shift) +                     \
              get_round(vxrm, x, shift));                                    \
        GenAndRunTest<int32_t, int32_t>((int32_t)t.src, (int32_t)t.dst, fn); \
        CHECK(!memcmp(t.dst, t.ref, sizeof(t.ref)));                         \
      }                                                                      \
    }                                                                        \
  }

UTEST_RVV_VNCLIP_E32M2_E16M1(vnclipu_vi, u)
UTEST_RVV_VNCLIP_E32M2_E16M1(vnclip_vi, )

#undef UTEST_RVV_VNCLIP_E32M2_E16M1

// Tests for vector integer extension instructions
#define UTEST_RVV_VI_VIE_FORM_WITH_RES(instr_name, type, width, frac_width, \
                                       array, expect_res)                   \
  TEST(RISCV_UTEST_##instr_name##_##width##_##frac_width) {                 \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                      \
    constexpr uint32_t n = kRvvVLEN / width;                                \
    CcTest::InitializeVM();                                                 \
    for (int##frac_width##_t x : array) {                                   \
      int##frac_width##_t src[n] = {0};                                     \
      type dst[n] = {0};                                                    \
      for (uint32_t i = 0; i < n; i++) src[i] = x;                          \
      auto fn = [](MacroAssembler& assm) {                                  \
        __ VU.set(t0, VSew::E##frac_width, Vlmul::m1);                      \
        __ vl(v1, a0, 0, VSew::E##frac_width);                              \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                           \
        __ instr_name(v2, v1);                                              \
        __ vs(v2, a1, 0, VSew::E##width);                                   \
      };                                                                    \
      GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);      \
      for (uint32_t i = 0; i < n; i++) {                                    \
        CHECK_EQ(expect_res, dst[i]);                                       \
      }                                                                     \
    }                                                                       \
  }

#define ARRAY(type) compiler::ValueHelper::GetVector<type>()

UTEST_RVV_VI_VIE_FORM_WITH_RES(vzext_vf2, uint64_t, 64, 32, ARRAY(int32_t),
                               static_cast<uint64_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vzext_vf4, uint64_t, 64, 16, ARRAY(int16_t),
                               static_cast<uint64_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vzext_vf8, uint64_t, 64, 8, ARRAY(int8_t),
                               static_cast<uint64_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vzext_vf2, uint32_t, 32, 16, ARRAY(int16_t),
                               static_cast<uint32_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vzext_vf4, uint32_t, 32, 8, ARRAY(int8_t),
                               static_cast<uint32_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vzext_vf2, uint16_t, 16, 8, ARRAY(int8_t),
                               static_cast<uint16_t>(dst[i]))

UTEST_RVV_VI_VIE_FORM_WITH_RES(vsext_vf2, int64_t, 64, 32, ARRAY(int32_t),
                               static_cast<int64_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vsext_vf4, int64_t, 64, 16, ARRAY(int16_t),
                               static_cast<int64_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vsext_vf8, int64_t, 64, 8, ARRAY(int8_t),
                               static_cast<int64_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vsext_vf2, int32_t, 32, 16, ARRAY(int16_t),
                               static_cast<int32_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vsext_vf4, int32_t, 32, 8, ARRAY(int8_t),
                               static_cast<int32_t>(dst[i]))
UTEST_RVV_VI_VIE_FORM_WITH_RES(vsext_vf2, int16_t, 16, 8, ARRAY(int8_t),
                               static_cast<int16_t>(dst[i]))

#undef UTEST_RVV_VI_VIE_FORM_WITH_RES

static constexpr double double_sNaN[] = {
    std::numeric_limits<double>::signaling_NaN(),
    -std::numeric_limits<double>::signaling_NaN()};
static constexpr float float_sNaN[] = {
    std::numeric_limits<float>::signaling_NaN(),
    -std::numeric_limits<float>::signaling_NaN()};
// Tests for vector Floating-Point merge instruction
#define UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES(number, type, int_type, width, \
                                              array, expect_res)             \
  TEST(RISCV_UTEST_vfmerge_vf_##type##_##number) {                           \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    constexpr uint32_t n = kRvvVLEN / width;                                 \
    CcTest::InitializeVM();                                                  \
    for (type fval : array) {                                                \
      int_type rs1_fval = base::bit_cast<int_type>(fval);                    \
      for (uint32_t mask = 0; mask < (1 << n); mask++) {                     \
        int_type src[n] = {0};                                               \
        int_type dst[n] = {0};                                               \
        dst[0] = rs1_fval;                                                   \
        for (uint32_t i = 0; i < n; i++) src[i] = i;                         \
        auto fn = [mask](MacroAssembler& assm) {                             \
          __ VU.set(t0, VSew::E##width, Vlmul::m1);                          \
          __ vl(v1, a0, 0, VSew::E##width);                                  \
          __ vl(v24, a1, 0, VSew::E##width);                                 \
          __ vmv_vi(v0, mask);                                               \
          __ vfmv_fs(ft0, v24);                                              \
          __ vfmerge_vf(v2, ft0, v1);                                        \
          __ vs(v2, a1, 0, VSew::E##width);                                  \
        };                                                                   \
        GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);     \
        for (uint32_t i = 0; i < n; i++) {                                   \
          CHECK_EQ(expect_res, dst[i]);                                      \
        }                                                                    \
      }                                                                      \
    }                                                                        \
  }

UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES(
    1, double, int64_t, 64, compiler::ValueHelper::GetVector<double>(),
    ((mask >> i) & 0x1) ? rs1_fval : src[i])
UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES(2, float, int32_t, 32,
                                      compiler::ValueHelper::GetVector<float>(),
                                      ((mask >> i) & 0x1) ? rs1_fval : src[i])
UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES(3, double, int64_t, 64,
                                      base::ArrayVector(double_sNaN),
                                      ((mask >> i) & 0x1) ? rs1_fval : src[i])
UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES(4, float, int32_t, 32,
                                      base::ArrayVector(float_sNaN),
                                      ((mask >> i) & 0x1) ? rs1_fval : src[i])
#undef UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES

// Tests for vector permutation instructions vector slide instructions
#define UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(instr_name, type, width, array, \
                                             expect_res)                     \
  TEST(RISCV_UTEST_##instr_name##_##type) {                                  \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    constexpr uint32_t n = kRvvVLEN / width;                                 \
    CcTest::InitializeVM();                                                  \
    for (type x : array) {                                                   \
      for (uint32_t offset = 0; offset <= n; offset++) {                     \
        type src[n] = {0};                                                   \
        type dst[n] = {0};                                                   \
        for (uint32_t i = 0; i < n; i++) src[i] = x + i;                     \
        auto fn = [offset](MacroAssembler& assm) {                           \
          __ VU.set(t0, VSew::E##width, Vlmul::m1);                          \
          __ vl(v1, a0, 0, VSew::E##width);                                  \
          __ instr_name(v2, v1, offset);                                     \
          __ vs(v2, a1, 0, VSew::E##width);                                  \
        };                                                                   \
        GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);     \
        for (uint32_t i = 0; i < n; i++) {                                   \
          CHECK_EQ(expect_res, dst[i]);                                      \
        }                                                                    \
      }                                                                      \
    }                                                                        \
  }

// Test for vslidedown_vi
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, int64_t, 64, ARRAY(int64_t),
                                     (i + offset) < n ? src[i + offset] : 0)
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, int32_t, 32, ARRAY(int32_t),
                                     (i + offset) < n ? src[i + offset] : 0)
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, int16_t, 16, ARRAY(int16_t),
                                     (i + offset) < n ? src[i + offset] : 0)
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, int8_t, 8, ARRAY(int8_t),
                                     (i + offset) < n ? src[i + offset] : 0)

UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, uint32_t, 32,
                                     ARRAY(uint32_t),
                                     (i + offset) < n ? src[i + offset] : 0)
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, uint16_t, 16,
                                     ARRAY(uint16_t),
                                     (i + offset) < n ? src[i + offset] : 0)
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslidedown_vi, uint8_t, 8, ARRAY(uint8_t),
                                     (i + offset) < n ? src[i + offset] : 0)

// Test for vslideup_vi
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, int64_t, 64, ARRAY(int64_t),
                                     i < offset ? dst[i] : src[i - offset])
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, int32_t, 32, ARRAY(int32_t),
                                     i < offset ? dst[i] : src[i - offset])
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, int16_t, 16, ARRAY(int16_t),
                                     i < offset ? dst[i] : src[i - offset])
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, int8_t, 8, ARRAY(int8_t),
                                     i < offset ? dst[i] : src[i - offset])

UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, uint32_t, 32, ARRAY(uint32_t),
                                     i < offset ? dst[i] : src[i - offset])
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, uint16_t, 16, ARRAY(uint16_t),
                                     i < offset ? dst[i] : src[i - offset])
UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES(vslideup_vi, uint8_t, 8, ARRAY(uint8_t),
                                     i < offset ? dst[i] : src[i - offset])
#undef UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES

#define UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(instr_name, type, width, array, \
                                             expect_res)                     \
  TEST(RISCV_UTEST_##instr_name##_##type) {                                  \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    constexpr uint32_t n = kRvvVLEN / width;                                 \
    CcTest::InitializeVM();                                                  \
    for (type x : array) {                                                   \
      for (uint32_t offset = 0; offset <= n; offset++) {                     \
        type src[n] = {0};                                                   \
        type dst[n] = {0};                                                   \
        for (uint32_t i = 0; i < n; i++) src[i] = x + i;                     \
        auto fn = [](MacroAssembler& assm) {                                 \
          __ VU.set(t0, VSew::E##width, Vlmul::m1);                          \
          __ vl(v1, a0, 0, VSew::E##width);                                  \
          __ instr_name(v2, v1, a2);                                         \
          __ vs(v2, a1, 0, VSew::E##width);                                  \
        };                                                                   \
        type rs2_val = (type)offset;                                         \
        GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, rs2_val, \
                                        fn);                                 \
        for (uint32_t i = 0; i < n; i++) {                                   \
          CHECK_EQ(expect_res, dst[i]);                                      \
        }                                                                    \
      }                                                                      \
    }                                                                        \
  }

// Test for vslidedown_vx
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, int64_t, 64, ARRAY(int64_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, int32_t, 32, ARRAY(int32_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, int16_t, 16, ARRAY(int16_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, int8_t, 8, ARRAY(int8_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)

UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, uint32_t, 32,
                                     ARRAY(uint32_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, uint16_t, 16,
                                     ARRAY(uint16_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslidedown_vx, uint8_t, 8, ARRAY(uint8_t),
                                     (i + rs2_val) < n ? src[i + rs2_val] : 0)

// Test for vslideup_vx
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, int64_t, 64, ARRAY(int64_t),
                                     (int64_t)i < rs2_val ? dst[i]
                                                          : src[i - rs2_val])
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, int32_t, 32, ARRAY(int32_t),
                                     (int32_t)i < rs2_val ? dst[i]
                                                          : src[i - rs2_val])
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, int16_t, 16, ARRAY(int16_t),
                                     (int16_t)i < rs2_val ? dst[i]
                                                          : src[i - rs2_val])
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, int8_t, 8, ARRAY(int8_t),
                                     (int8_t)i < rs2_val ? dst[i]
                                                         : src[i - rs2_val])

UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, uint32_t, 32, ARRAY(uint32_t),
                                     (uint32_t)i < rs2_val ? dst[i]
                                                           : src[i - rs2_val])
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, uint16_t, 16, ARRAY(uint16_t),
                                     (uint16_t)i < rs2_val ? dst[i]
                                                           : src[i - rs2_val])
UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES(vslideup_vx, uint8_t, 8, ARRAY(uint8_t),
                                     (uint8_t)i < rs2_val ? dst[i]
                                                          : src[i - rs2_val])
#undef UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES

#define UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(instr_name, type, width, array, \
                                              expect_res)                     \
  TEST(RISCV_UTEST_##instr_name##_##type) {                                   \
    if (!CpuFeatures::IsSupported(
"""


```