Response:
The user wants a summary of the provided C++ code snippet, which is part of V8's test suite for the RISC-V 64-bit assembler.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The code is in `v8/test/cctest/test-assembler-riscv64.cc`, indicating it's a C++ test file for the RISC-V 64-bit assembler within the V8 project.

2. **Recognize the testing pattern:** The code heavily uses C++ macros like `TEST`, `CHECK_FLOAT_EQ`, `CHECK_DOUBLE_EQ`, and defines like `UTEST_RVV_...`. This suggests a unit testing framework. The `UTEST_RVV_` prefix strongly implies tests related to RISC-V Vector (RVV) instructions.

3. **Categorize the tests:**  Scan through the macros and their names. Notice patterns like:
    * `RISCV_UTEST_FLOAT_...`:  Tests for floating-point operations.
    * `UTEST_RVV_VF_VF_FORM...`: Tests involving vector and scalar floating-point operations.
    * `UTEST_RVV_VF_VV_FORM...`: Tests involving vector-vector floating-point operations.
    * `UTEST_RVV_VFW_...`: Tests for widening floating-point operations.
    * `UTEST_RVV_FMA_...`: Tests for fused multiply-add operations.
    * `UTEST_RVV_VNCLIP...`: Tests for vector narrow clip instructions.
    * `UTEST_RVV_VI_VIE_FORM...`: Tests for vector integer extension instructions.

4. **Infer functionality from instruction names:**  Many macros include RISC-V assembly instruction names like `vfadd`, `vfsub`, `vfmul`, `vfdiv`, `vfwadd`, `vfwmul`, `vfmadd`, `vfmsub`, `vnclipu`, `vnclip`, `vzext`, `vsext`. This directly points to the functionalities being tested: vector floating-point arithmetic, widening operations, fused multiply-add, and integer conversion/manipulation instructions.

5. **Analyze the testing logic:** The macros typically involve:
    * Checking for RISC-V SIMD support (`CpuFeatures::IsSupported(RISCV_SIMD)`).
    * Initializing the V8 VM (`CcTest::InitializeVM()`).
    * Defining a lambda function (`auto fn = ...`) that uses `MacroAssembler` to generate RISC-V assembly code.
    * Iterating through various input values (often using `compiler::ValueHelper::GetVector`).
    * Executing the generated code (`GenAndRunTest`).
    * Comparing the results with expected values using `CHECK_FLOAT_EQ` and `CHECK_DOUBLE_EQ`.

6. **Address specific user questions:**
    * **`.tq` extension:**  The code snippet is `.cc`, so it's C++, not Torque.
    * **JavaScript relation:**  These are low-level assembler tests. While they underpin JavaScript's floating-point and SIMD capabilities, the direct connection isn't immediately obvious in this snippet. A simple example of JavaScript using floating-point numbers can demonstrate the underlying functionality being tested.
    * **Code logic and assumptions:** The macros implicitly test the correctness of the generated assembly for various inputs. An example can be constructed by picking a simple test case (e.g., `vfadd_vv`) and showing how specific inputs lead to an expected output.
    * **Common programming errors:**  The tests implicitly guard against incorrect implementation of the assembly instructions. A common error in floating-point arithmetic is the handling of NaN and infinity, which some of the `check_fn` predicates address (e.g., `is_invalid_fmul`, `is_invalid_fadd`).

7. **Synthesize the summary:** Combine the observations into a concise description of the file's purpose and the functionalities it tests. Emphasize that it's a unit test file for RISC-V vector instructions.

8. **Refine and structure the answer:** Organize the information logically, addressing each part of the user's request. Use clear and concise language. Provide specific examples where requested.

Self-Correction/Refinement during the process:

* Initially, I might have focused too much on the individual macros. Realized that grouping them by the type of operation (arithmetic, widening, FMA, etc.) provides a better high-level understanding.
* Considered whether to go into detail about the `MacroAssembler` but decided to keep it concise, as the user's primary interest is the *functionality being tested*.
* Made sure to explicitly address each of the user's specific questions (Torque, JavaScript, logic, errors).
* Paid attention to the "part 4 of 5" instruction, indicating a need for a concluding summary based on the provided snippet.
这是 `v8/test/cctest/test-assembler-riscv64.cc` 文件的第 4 部分，它主要的功能是 **测试 V8 的 RISC-V 64 位汇编器中浮点和向量指令的正确性**。

具体来说，这部分代码侧重于测试以下 RISC-V 向量（RVV）指令：

1. **向量单精度浮点算术指令 (Vector-Vector 和 Vector-Scalar 形式):**
   - 加法 (`vfadd_vv`, `vfadd_vf`)
   - 减法 (`vfsub_vv`)
   - 乘法 (`vfmul_vv`)
   - 除法 (`vfdiv_vv`)

2. **向量宽度扩展浮点算术指令 (Vector-Vector 和 Vector-Scalar 形式):** 这些指令将单精度浮点数操作数扩展为双精度浮点数进行计算。
   - 加法 (`vfwadd_vv`, `vfwadd_vf`, `vfwadd_wv`, `vfwadd_wf`)
   - 减法 (`vfwsub_vv`, `vfwsub_vf`, `vfwsub_wv`, `vfwsub_wf`)
   - 乘法 (`vfwmul_vv`, `vfwmul_vf`)

3. **向量宽度扩展浮点融合乘加指令 (Vector-Vector 和 Vector-Scalar 形式):** 这些指令执行 `a * b + c` 的操作，并将结果扩展为双精度浮点数。
   - `vfwmacc_vv`, `vfwmacc_vf`
   - `vfwnmacc_vv`, `vfwnmacc_vf`
   - `vfwmsac_vv`, `vfwmsac_vf`
   - `vfwnmsac_vv`, `vfwnmsac_vf`

4. **向量单精度浮点融合乘加指令 (Vector-Vector 和 Vector-Scalar 形式):**
   - `vfmadd_vv`, `vfmadd_vf`
   - `vfnmadd_vv`, `vfnmadd_vf`
   - `vfmsub_vv`, `vfmsub_vf`
   - `vfnmsub_vv`, `vfnmsub_vf`
   - `vfmacc_vv`, `vfmacc_vf`
   - `vfnmacc_vv`, `vfnmacc_vf`
   - `vfmsac_vv`, `vfmsac_vf`
   - `vfnmsac_vv`, `vfnmsac_vf`

5. **向量宽度扩展浮点规约求和指令:**
   - `vfwredusum_vs`
   - `vfwredosum_vs`

6. **向量窄化无符号/有符号饱和截断指令:** 这些指令将 32 位整数向量窄化为 16 位整数向量。
   - `vnclipu_vi`
   - `vnclip_vi`

7. **向量整数扩展指令:** 这些指令将较小的整数类型向量扩展为较大的整数类型向量。
   - 零扩展 (`vzext_vf2`, `vzext_vf4`, `vzext_vf8`)
   - 符号扩展 (`vsext_vf2`, `vsext_vf4`, `vsext_vf8`)

**关于代码的结构和测试方法：**

- **宏定义:** 代码大量使用了宏 (`#define`) 来简化测试用例的编写。例如，`TEST_FLOAT_VV` 和 `TEST_DOUBLE_VV` 宏用于生成测试单精度和双精度浮点向量运算的测试用例。`UTEST_RVV_VF_VV_FORM_WITH_OP` 等宏进一步抽象了 RVV 指令的测试模式。
- **参数化测试:**  测试用例通常会遍历一系列预定义的输入值（通过 `compiler::ValueHelper::GetVector` 获取），以覆盖不同的场景。
- **代码生成和执行:**  每个测试用例都会创建一个 `MacroAssembler` 对象，用于生成 RISC-V 汇编代码片段，执行特定的 RVV 指令。然后，这段代码会被编译和执行。
- **结果验证:**  测试用例会使用 `CHECK_FLOAT_EQ` 和 `CHECK_DOUBLE_EQ` 等断言宏来比较实际执行结果和预期结果，以验证指令的正确性。`UseCanonicalNan` 用于处理 NaN 值的比较。
- **CPU 特性检查:**  测试用例会检查 CPU 是否支持 RISC-V 向量扩展 (`CpuFeatures::IsSupported(RISCV_SIMD)`)，如果不支持则跳过测试。

**如果 `v8/test/cctest/test-assembler-riscv64.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种用于定义 V8 运行时内置函数和优化的领域特定语言。这个文件中定义的将不是汇编测试，而是用 Torque 编写的，可能涉及到这些 RVV 指令在 V8 运行时中的具体实现逻辑。

**与 JavaScript 的功能关系及示例：**

这些底层的汇编器测试直接关系到 JavaScript 中对数字和 SIMD (Single Instruction, Multiple Data) 操作的支持。当 JavaScript 代码执行浮点运算或使用 SIMD API 时，V8 引擎最终会将其转换为底层的机器码指令，其中就可能包括这里测试的 RISC-V 向量指令。

**JavaScript 示例：**

```javascript
// 浮点数加法
let a = 1.5;
let b = 2.5;
let sum = a + b; // 底层可能使用浮点加法指令 (如 vfadd)

// 使用 SIMD API (需要启用相应特性)
// 假设我们有一个 SIMD 类型 Float32x4
let vectorA = Float32x4(1.0, 2.0, 3.0, 4.0);
let vectorB = Float32x4(5.0, 6.0, 7.0, 8.0);
let vectorSum = vectorA.add(vectorB); // 底层可能使用向量加法指令 (如 vfadd_vv)

console.log(sum);
console.log(vectorSum);
```

**代码逻辑推理与假设输入输出：**

以 `UTEST_RVV_VF_VV_FORM_WITH_OP(vfadd_vv, +)` 为例：

**假设输入：**

- 向量 `v0` 的元素值为 `[1.0, 2.0, 3.0, 4.0]`
- 向量 `v1` 的元素值为 `[5.0, 6.0, 7.0, 8.0]`

**代码逻辑：**

`__ vfadd_vv(v0, v0, v1);` 这条指令会将 `v0` 和 `v1` 对应位置的单精度浮点数相加，结果存储回 `v0`。

**预期输出：**

向量 `v0` 的元素值变为 `[6.0, 8.0, 10.0, 12.0]`

**涉及用户常见的编程错误：**

1. **浮点数精度问题：** 用户可能期望浮点数运算得到精确的结果，但由于浮点数的二进制表示的限制，可能会出现精度损失。测试用例中的 `CHECK_FLOAT_EQ` 使用一定的误差范围来比较浮点数，就是考虑到了这一点。

   ```javascript
   let a = 0.1;
   let b = 0.2;
   let sum = a + b;
   console.log(sum === 0.3); // 输出 false，因为浮点数表示的 0.1 和 0.2 相加并不完全等于 0.3
   ```

2. **对 NaN (Not a Number) 的处理不当：** 某些浮点运算可能产生 NaN，例如 0 除以 0。用户需要正确地检查和处理 NaN 值。测试用例中使用了 `UseCanonicalNan` 来确保 NaN 值的比较是一致的。

   ```javascript
   let result = 0 / 0;
   console.log(result); // 输出 NaN
   console.log(result === NaN); // 输出 false，不能直接用 === 比较 NaN
   console.log(isNaN(result)); // 输出 true
   ```

3. **未检查 CPU 特性就使用 SIMD API：** 如果用户的代码尝试使用 SIMD API，但在不支持相应 CPU 特性的环境中运行，会导致错误。V8 的测试用例首先检查 `RISCV_SIMD` 是否支持，这是一个良好的实践。

   ```javascript
   // 错误示例 (未检查特性)
   let vectorA = Float32x4(1, 2, 3, 4); // 如果环境不支持 Float32x4，会报错
   ```

**功能归纳（针对第 4 部分）：**

这部分 `test-assembler-riscv64.cc` 文件的主要功能是 **全面测试 V8 的 RISC-V 64 位汇编器中关于浮点数和向量运算指令的生成和执行的正确性**。它覆盖了基本的浮点算术运算、宽度扩展运算、融合乘加运算以及整数类型的转换和扩展指令。通过大量的参数化测试，验证了这些指令在不同输入场景下的行为是否符合 RISC-V 的规范。这对于确保 V8 在 RISC-V 架构上正确高效地执行 JavaScript 的浮点数和 SIMD 相关代码至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
0; i < 4; i++) {                                      \
          CHECK_FLOAT_EQ(UseCanonicalNan<float>(expect_res), result[i]);   \
          result[i] = 0.0;                                                 \
        }                                                                  \
      }                                                                    \
    }                                                                      \
  }                                                                        \
  TEST(RISCV_UTEST_DOUBLE_##instr_name) {                                  \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                     \
    CcTest::InitializeVM();                                                \
    double result[2] = {0.0};                                              \
    auto fn = [&result](MacroAssembler& assm) {                            \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                                 \
      __ vfmv_vf(v0, fa0);                                                 \
      __ vfmv_vf(v1, fa1);                                                 \
      __ instr_name(v0, v0, v1);                                           \
      __ vfmv_fs(fa0, v0);                                                 \
      __ li(a3, Operand(int64_t(result)));                                 \
      __ vs(v0, a3, 0, E64);                                               \
    };                                                                     \
    for (double rs1_fval : compiler::ValueHelper::GetVector<double>()) {   \
      for (double rs2_fval : compiler::ValueHelper::GetVector<double>()) { \
        GenAndRunTest<double, double>(rs1_fval, rs2_fval, fn);             \
        for (int i = 0; i < 2; i++) {                                      \
          CHECK_DOUBLE_EQ(UseCanonicalNan<double>(expect_res), result[i]); \
          result[i] = 0.0;                                                 \
        }                                                                  \
      }                                                                    \
    }                                                                      \
  }

// Tests for vector single-width floating-point arithmetic instructions between
// vector and scalar
#define UTEST_RVV_VF_VF_FORM_WITH_RES(instr_name, array, expect_res)    \
  TEST(RISCV_UTEST_##instr_name) {                                      \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                  \
    CcTest::InitializeVM();                                             \
    auto fn = [](MacroAssembler& assm) {                                \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                              \
      __ vfmv_vf(v0, fa0);                                              \
      __ instr_name(v0, v0, fa1);                                       \
      __ vfmv_fs(fa0, v0);                                              \
    };                                                                  \
    for (float rs1_fval : array) {                                      \
      for (float rs2_fval : array) {                                    \
        auto res = GenAndRunTest<float, float>(rs1_fval, rs2_fval, fn); \
        CHECK_FLOAT_EQ(UseCanonicalNan<float>(expect_res), res);        \
      }                                                                 \
    }                                                                   \
  }

#define UTEST_RVV_VF_VV_FORM_WITH_OP(instr_name, tested_op) \
  UTEST_RVV_VF_VV_FORM_WITH_RES(instr_name, ((rs1_fval)tested_op(rs2_fval)))

#define UTEST_RVV_VF_VF_FORM_WITH_OP(instr_name, array, tested_op) \
  UTEST_RVV_VF_VF_FORM_WITH_RES(instr_name, array,                 \
                                ((rs1_fval)tested_op(rs2_fval)))

#define ARRAY_FLOAT compiler::ValueHelper::GetVector<float>()

UTEST_RVV_VF_VV_FORM_WITH_OP(vfadd_vv, +)
UTEST_RVV_VF_VF_FORM_WITH_OP(vfadd_vf, ARRAY_FLOAT, +)
UTEST_RVV_VF_VV_FORM_WITH_OP(vfsub_vv, -)
// UTEST_RVV_VF_VF_FORM_WITH_OP(vfsub_vf, ARRAY_FLOAT, -)
UTEST_RVV_VF_VV_FORM_WITH_OP(vfmul_vv, *)
// UTEST_RVV_VF_VF_FORM_WITH_OP(vfmul_vf, ARRAY_FLOAT, *)
UTEST_RVV_VF_VV_FORM_WITH_OP(vfdiv_vv, /)
// UTEST_RVV_VF_VF_FORM_WITH_OP(vfdiv_vf, ARRAY_FLOAT, /)

#undef ARRAY_FLOAT
#undef UTEST_RVV_VF_VV_FORM_WITH_OP
#undef UTEST_RVV_VF_VF_FORM_WITH_OP

// Tests for vector widening floating-point arithmetic instructions between
// vector and vector
#define UTEST_RVV_VFW_VV_FORM_WITH_RES(instr_name, tested_op, is_first_double, \
                                       check_fn)                               \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                              \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                         \
    CcTest::InitializeVM();                                                    \
    constexpr size_t n = kRvvVLEN / 32;                                        \
    double result[n] = {0.0};                                                  \
    auto fn = [&result](MacroAssembler& assm) {                                \
      if (is_first_double) {                                                   \
        __ fcvt_d_s(fa0, fa0);                                                 \
        __ VU.set(t0, VSew::E64, Vlmul::m2);                                   \
        __ vfmv_vf(v2, fa0);                                                   \
      }                                                                        \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                     \
      if (!is_first_double) {                                                  \
        __ vfmv_vf(v2, fa0);                                                   \
      }                                                                        \
      __ vfmv_vf(v4, fa1);                                                     \
      __ instr_name(v0, v2, v4);                                               \
      __ li(t1, Operand(int64_t(result)));                                     \
      __ vs(v0, t1, 0, VSew::E64);                                             \
    };                                                                         \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) {         \
      for (float rs2_fval : compiler::ValueHelper::GetVector<float>()) {       \
        GenAndRunTest<double, float>(rs1_fval, rs2_fval, fn);                  \
        for (size_t i = 0; i < n; i++) {                                       \
          CHECK_DOUBLE_EQ(                                                     \
              check_fn(rs1_fval, rs2_fval)                                     \
                  ? std::numeric_limits<double>::quiet_NaN()                   \
                  : UseCanonicalNan<double>(static_cast<double>(               \
                        rs1_fval) tested_op static_cast<double>(rs2_fval)),    \
              result[i]);                                                      \
          result[i] = 0.0;                                                     \
        }                                                                      \
      }                                                                        \
    }                                                                          \
  }

// Tests for vector widening floating-point arithmetic instructions between
// vector and scalar
#define UTEST_RVV_VFW_VF_FORM_WITH_RES(instr_name, tested_op, is_first_double, \
                                       check_fn)                               \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                              \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                         \
    CcTest::InitializeVM();                                                    \
    constexpr size_t n = kRvvVLEN / 32;                                        \
    double result[n] = {0.0};                                                  \
    auto fn = [&result](MacroAssembler& assm) {                                \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                     \
      if (is_first_double) {                                                   \
        __ fcvt_d_s(fa0, fa0);                                                 \
        __ VU.set(t0, VSew::E64, Vlmul::m2);                                   \
        __ vfmv_vf(v2, fa0);                                                   \
      }                                                                        \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                     \
      if (!is_first_double) {                                                  \
        __ vfmv_vf(v2, fa0);                                                   \
      }                                                                        \
      __ instr_name(v0, v2, fa1);                                              \
      __ li(t1, Operand(int64_t(result)));                                     \
      __ vs(v0, t1, 0, VSew::E64);                                             \
    };                                                                         \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) {         \
      for (float rs2_fval : compiler::ValueHelper::GetVector<float>()) {       \
        GenAndRunTest<double, float>(rs1_fval, rs2_fval, fn);                  \
        for (size_t i = 0; i < n; i++) {                                       \
          CHECK_DOUBLE_EQ(                                                     \
              check_fn(rs1_fval, rs2_fval)                                     \
                  ? std::numeric_limits<double>::quiet_NaN()                   \
                  : UseCanonicalNan<double>(static_cast<double>(               \
                        rs1_fval) tested_op static_cast<double>(rs2_fval)),    \
              result[i]);                                                      \
          result[i] = 0.0;                                                     \
        }                                                                      \
      }                                                                        \
    }                                                                          \
  }

#define UTEST_RVV_VFW_VV_FORM_WITH_OP(instr_name, tested_op, is_first_double, \
                                      check_fn)                               \
  UTEST_RVV_VFW_VV_FORM_WITH_RES(instr_name, tested_op, is_first_double,      \
                                 check_fn)
#define UTEST_RVV_VFW_VF_FORM_WITH_OP(instr_name, tested_op, is_first_double, \
                                      check_fn)                               \
  UTEST_RVV_VFW_VF_FORM_WITH_RES(instr_name, tested_op, is_first_double,      \
                                 check_fn)

template <typename T>
static inline bool is_invalid_fmul(T src1, T src2) {
  return (isinf(src1) && src2 == static_cast<T>(0.0)) ||
         (src1 == static_cast<T>(0.0) && isinf(src2));
}

template <typename T>
static inline bool is_invalid_fadd(T src1, T src2) {
  return (isinf(src1) && isinf(src2) &&
          std::signbit(src1) != std::signbit(src2));
}

template <typename T>
static inline bool is_invalid_fsub(T src1, T src2) {
  return (isinf(src1) && isinf(src2) &&
          std::signbit(src1) == std::signbit(src2));
}

UTEST_RVV_VFW_VV_FORM_WITH_OP(vfwadd_vv, +, false, is_invalid_fadd)
UTEST_RVV_VFW_VF_FORM_WITH_OP(vfwadd_vf, +, false, is_invalid_fadd)
UTEST_RVV_VFW_VV_FORM_WITH_OP(vfwsub_vv, -, false, is_invalid_fsub)
UTEST_RVV_VFW_VF_FORM_WITH_OP(vfwsub_vf, -, false, is_invalid_fsub)
UTEST_RVV_VFW_VV_FORM_WITH_OP(vfwadd_wv, +, true, is_invalid_fadd)
UTEST_RVV_VFW_VF_FORM_WITH_OP(vfwadd_wf, +, true, is_invalid_fadd)
UTEST_RVV_VFW_VV_FORM_WITH_OP(vfwsub_wv, -, true, is_invalid_fsub)
UTEST_RVV_VFW_VF_FORM_WITH_OP(vfwsub_wf, -, true, is_invalid_fsub)
UTEST_RVV_VFW_VV_FORM_WITH_OP(vfwmul_vv, *, false, is_invalid_fmul)
UTEST_RVV_VFW_VF_FORM_WITH_OP(vfwmul_vf, *, false, is_invalid_fmul)

#undef UTEST_RVV_VF_VV_FORM_WITH_OP
#undef UTEST_RVV_VF_VF_FORM_WITH_OP

// Tests for vector widening floating-point fused multiply-add Instructions
// between vectors
#define UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(instr_name, array, expect_res)     \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                             \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                        \
    CcTest::InitializeVM();                                                   \
    auto fn = [](MacroAssembler& assm) {                                      \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                    \
      __ vfmv_vf(v0, fa0);                                                    \
      __ vfmv_vf(v2, fa1);                                                    \
      __ vfmv_vf(v4, fa2);                                                    \
      __ instr_name(v0, v2, v4);                                              \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                                    \
      __ vfmv_fs(fa0, v0);                                                    \
    };                                                                        \
    for (float rs1_fval : array) {                                            \
      for (float rs2_fval : array) {                                          \
        for (float rs3_fval : array) {                                        \
          double rs1_dval = base::bit_cast<double>(                           \
              (uint64_t)base::bit_cast<uint32_t>(rs1_fval) << 32 |            \
              base::bit_cast<uint32_t>(rs1_fval));                            \
          double rs2_dval = static_cast<double>(rs2_fval);                    \
          double rs3_dval = static_cast<double>(rs3_fval);                    \
          double res =                                                        \
              GenAndRunTest<double, float>(rs1_fval, rs2_fval, rs3_fval, fn); \
          CHECK_DOUBLE_EQ((expect_res), res);                                 \
        }                                                                     \
      }                                                                       \
    }                                                                         \
  }

// Tests for vector single-width floating-point fused multiply-add Instructions
// between vectors and scalar
#define UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(instr_name, array, expect_res)     \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                             \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                        \
    CcTest::InitializeVM();                                                   \
    auto fn = [](MacroAssembler& assm) {                                      \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                    \
      __ vfmv_vf(v0, fa0);                                                    \
      __ vfmv_vf(v2, fa2);                                                    \
      __ instr_name(v0, fa1, v2);                                             \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                                    \
      __ vfmv_fs(fa0, v0);                                                    \
    };                                                                        \
    for (float rs1_fval : array) {                                            \
      for (float rs2_fval : array) {                                          \
        for (float rs3_fval : array) {                                        \
          double rs1_dval = base::bit_cast<double>(                           \
              (uint64_t)base::bit_cast<uint32_t>(rs1_fval) << 32 |            \
              base::bit_cast<uint32_t>(rs1_fval));                            \
          double rs2_dval = static_cast<double>(rs2_fval);                    \
          double rs3_dval = static_cast<double>(rs3_fval);                    \
          double res =                                                        \
              GenAndRunTest<double, float>(rs1_fval, rs2_fval, rs3_fval, fn); \
          CHECK_DOUBLE_EQ((expect_res), res);                                 \
        }                                                                     \
      }                                                                       \
    }                                                                         \
  }

#define ARRAY_FLOAT compiler::ValueHelper::GetVector<float>()
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwmacc_vv, ARRAY_FLOAT,
                                   std::fma(rs2_dval, rs3_dval, rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwmacc_vf, ARRAY_FLOAT,
                                   std::fma(rs2_dval, rs3_dval, rs1_dval))
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwnmacc_vv, ARRAY_FLOAT,
                                   std::fma(rs2_dval, -rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwnmacc_vf, ARRAY_FLOAT,
                                   std::fma(rs2_dval, -rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwmsac_vv, ARRAY_FLOAT,
                                   std::fma(rs2_dval, rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwmsac_vf, ARRAY_FLOAT,
                                   std::fma(rs2_dval, rs3_dval, -rs1_dval))
UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(vfwnmsac_vv, ARRAY_FLOAT,
                                   std::fma(rs2_dval, -rs3_dval, rs1_dval))
UTEST_RVV_VFW_FMA_VF_FORM_WITH_RES(vfwnmsac_vf, ARRAY_FLOAT,
                                   std::fma(rs2_dval, -rs3_dval, rs1_dval))

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
    auto fn = [](MacroAssembler& assm) {                               \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                             \
      __ vfmv_vf(v2, fa0);                                             \
      __ vfmv_vf(v4, fa0);                                             \
      __ instr_name(v0, v2, v4);                                       \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                             \
      __ vfmv_fs(fa0, v0);                                             \
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
      double res = GenAndRunTest<double, float>(rs1_fval, fn);         \
      CHECK_DOUBLE_EQ(UseCanonicalNan<double>(expect_res), res);       \
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
        GenAndRunTest<int32_t, int64_t>((int64_t)t.src, (int64_t)t.dst, fn); \
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
    constexpr uint32_t n = kRvvVLEN / frac_width;                           \
    CcTest::InitializeVM();                                                 \
    for (int##frac_width##_t x : array) {                                   \
      int##frac_width##_t src[n] = {0};                                     \
      type dst[kRvvVLEN / width] = {0};                                     \
      for (uint32_t i = 0; i < n; i++) src[i] = x;                          \
      auto fn = [](MacroAssembler& assm) {                                  \
        __ VU.set(t0, VSew::E##frac_width, Vlmul::m1);                      \
        __ vl(v1, a0, 0, VSew::E##frac_width);                              \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                           \
        __ instr_name(v2, v1);                                              \
        __ vs(v2, a1, 0, VSew::E##width);                                   \
      };                                                                    \
      GenAndRunTest<int64_t, int64_t>((int64_t)src, (int64_t)dst, fn);      \
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
                        
"""


```