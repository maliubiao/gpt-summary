Response: The user wants to understand the functionality of the provided C++ code snippet, which is part of a larger test file for RISC-V vector instructions (RVV) in the V8 JavaScript engine.

The code defines a series of unit tests for various RVV instructions. Each test sets up a scenario, executes the corresponding assembly instruction using V8's MacroAssembler, and then verifies the result.

The main categories of tests in this snippet are:

1. **Load and Store (Scalar and Vector):** Testing basic data movement between memory and vector registers.
2. **Floating-Point Moves (Scalar to Vector):** Testing the `vfmv` instruction to move a scalar floating-point value to all elements of a vector. Includes tests for signaling NaNs.
3. **Floating-Point Negation (Vector):** Testing the `vfneg` instruction for negating floating-point values in a vector, including handling of signaling NaNs.
4. **Floating-Point Move (Vector to/from Scalar):** Testing `vfmv.fs` and `vfmv.sf` for moving between vector and scalar floating-point registers.
5. **Integer Arithmetic (Vector-Vector, Vector-Scalar, Vector-Immediate):** Testing various integer arithmetic operations like addition, subtraction, logical AND, OR, XOR, MIN, MAX with different operand types.
6. **Floating-Point Arithmetic (Vector-Vector, Vector-Scalar):** Testing basic floating-point operations like addition, subtraction, multiplication, and division.
7. **Widening Floating-Point Arithmetic (Vector-Vector, Vector-Scalar):** Testing instructions that operate on single-precision floats and produce double-precision results.
8. **Widening Floating-Point Fused Multiply-Add (FMA) (Vector-Vector, Vector-Scalar):** Testing FMA instructions that combine multiplication and addition into a single operation.
9. **Single-Width Floating-Point FMA (Vector-Vector, Vector-Scalar):** Testing FMA instructions where operands and results are the same width.
10. **Widening Floating-Point Reduction Sum:** Testing instructions that sum elements of a vector into a scalar with widening.
11. **Vector Narrowing and Clipping:** Testing instructions that reduce the width of vector elements, potentially with saturation.
12. **Vector Integer Extension:** Testing instructions that increase the width of integer vector elements (zero-extension and sign-extension).
13. **Floating-Point Merge:** Testing an instruction that conditionally merges elements from two vectors based on a mask.
14. **Vector Slide (Down and Up):** Testing instructions that shift elements within a vector by a specified offset.

Regarding the relationship with JavaScript, these tests are crucial for ensuring the correctness of V8's implementation of WebAssembly and JavaScript features that utilize SIMD (Single Instruction, Multiple Data) operations. When JavaScript code uses TypedArrays and performs SIMD operations, V8 translates those operations into the appropriate machine instructions, including RVV instructions if the target architecture is RISC-V with vector extension support.

Here's a JavaScript example that demonstrates a scenario that might involve the RVV `vadd_vv` instruction (vector-vector addition):

```javascript
// Assume 'a' and 'b' are Float32Array representing vectors
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const result = new Float32Array(4);

// In a real V8 implementation, the following operation would likely be
// translated into a sequence of RVV instructions, including vadd_vv.
for (let i = 0; i < a.length; i++) {
  result[i] = a[i] + b[i];
}

console.log(result); // Output: Float32Array [ 6, 8, 10, 12 ]
```

In this JavaScript example, the element-wise addition of `a` and `b` could be implemented using the `vadd_vv` instruction on a RISC-V processor with the RVV extension. The C++ test `TEST(RISCV_UTEST_vadd_vv_32)` in the provided code snippet specifically validates the correct behavior of this `vadd_vv` instruction for 32-bit integers, which is analogous to the floating-point addition in the JavaScript example at a lower level.

The tests involving `vfmv_vf` are relevant when JavaScript needs to initialize all elements of a SIMD vector with a specific floating-point value.

The tests for FMA instructions like `vfmadd_vv` are important for JavaScript operations that benefit from fused multiply-add, which is a common operation in numerical computations.

In summary, this C++ file tests the low-level RISC-V vector instructions that V8 might use to implement higher-level JavaScript and WebAssembly SIMD operations. These tests ensure that V8 correctly generates and executes these instructions, leading to correct and efficient execution of JavaScript code that leverages SIMD capabilities.

这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个c++源代码文件的一部分，它主要功能是**测试RISC-V向量扩展（RVV）的汇编指令生成和执行的正确性**。

具体来说，这部分代码包含了针对多种RVV指令的单元测试，涵盖了以下功能：

1. **向量加载和存储指令 (`vl`, `vs`)**: 测试从内存加载数据到向量寄存器以及将向量寄存器中的数据存储到内存的功能。
2. **向量浮点数移动指令 (`vfmv_vf`)**: 测试将浮点标量值移动到向量寄存器所有元素的功能，包括对 `signaling NaN` 的处理。
3. **向量浮点数取反指令 (`vfneg_vv`)**: 测试对向量寄存器中的浮点数值取反的功能，包括对 `signaling NaN` 的处理。
4. **向量和标量浮点寄存器之间移动指令 (`vfmv_fs`, `vfmv_sf`)**: 测试向量寄存器和标量浮点寄存器之间的数据移动。
5. **向量整数算术指令 (`vadd_vv`, `vsub_vv`, `vand_vv`, `vor_vv`, `vxor_vv`, `vmax_vv`, `vmin_vv`, `vmaxu_vv`, `vminu_vv`)**: 测试向量和向量、向量和标量、向量和立即数之间的整数加减、逻辑运算以及最大最小值运算。
6. **向量浮点数算术指令 (`vfadd_vv`, `vfsub_vv`, `vfmul_vv`, `vfdiv_vv`)**: 测试向量和向量之间的浮点数加减乘除运算。
7. **向量浮点数扩展算术指令 (`vfwadd_vv`, `vfwsub_vv`, `vfwmul_vv`)**: 测试将单精度浮点数扩展为双精度进行运算的指令。
8. **向量浮点数融合乘加指令 (`vfwmacc_vv`, `vfwnmacc_vv`, `vfwmsac_vv`, `vfwnmsac_vv`, `vfmadd_vv`, `vfnmadd_vv`, `vfmsub_vv`, `vfnmsub_vv`, `vfmacc_vv`, `vfnmacc_vv`, `vfmsac_vv`, `vfnmsac_vv`)**: 测试向量浮点数的各种融合乘加运算，包括扩展和非扩展版本。
9. **向量浮点数扩展归约求和指令 (`vfwredusum_vs`, `vfwredosum_vs`)**: 测试将向量中的浮点数归约求和到标量寄存器的指令。
10. **向量截断指令 (`vnclipu_vi`, `vnclip_vi`)**: 测试将向量中的数据截断到更窄位宽的指令。
11. **向量整数扩展指令 (`vzext_vf2`, `vzext_vf4`, `vzext_vf8`, `vsext_vf2`, `vsext_vf4`, `vsext_vf8`)**: 测试将向量中较窄位宽的整数扩展到较宽位宽的指令（零扩展和符号扩展）。
12. **向量浮点数合并指令 (`vfmerge_vf`)**: 测试根据掩码选择两个向量中的元素进行合并的指令。
13. **向量滑动指令 (`vslidedown_vi`, `vslideup_vi`, `vslidedown_vx`, `vslideup_vx`)**: 测试将向量中的元素按照指定偏移量进行滑动的指令。

这些测试用例会生成相应的RISC-V汇编代码，并在模拟器或者硬件上执行，然后验证执行结果是否符合预期。这对于保证V8引擎在RISC-V架构上正确实现向量运算至关重要。

**与Javascript的关系：**

V8引擎负责执行Javascript代码。当Javascript代码中涉及到SIMD（Single Instruction, Multiple Data）操作时，V8会尝试将这些操作映射到目标架构上的SIMD指令，例如RISC-V的RVV指令。

例如，在Javascript中使用`Float32Array`进行向量加法操作时，V8在RISC-V架构上可能会使用 `vadd_vv` 指令来实现：

```javascript
const a = new Float32Array([1.0, 2.0, 3.0, 4.0]);
const b = new Float32Array([5.0, 6.0, 7.0, 8.0]);
const result = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  result[i] = a[i] + b[i];
}

console.log(result); // 输出: Float32Array [ 6, 8, 10, 12 ]
```

在这个例子中，循环内的加法操作在底层可能会被V8编译成RVV的 `vadd_vv` 指令，将 `a` 和 `b` 对应的向量寄存器中的元素相加，结果存储到 `result` 对应的向量寄存器中。

类似地，`vfmv_vf` 指令可以用于实现Javascript中将一个标量值赋给一个SIMD向量的所有元素的操作。

```javascript
const scalar = 3.14;
const vector = new Float32Array(8).fill(scalar);
console.log(vector); // 输出: Float32Array [ 3.14, 3.14, 3.14, 3.14, 3.14, 3.14, 3.14, 3.14 ]
```

V8在底层可能使用 `vfmv_vf` 指令将 `scalar` 的值复制到 `vector` 对应的向量寄存器的所有元素中。

总而言之，这个C++测试文件通过测试RISC-V的RVV指令，确保了V8引擎能够正确地将Javascript中的SIMD操作翻译成高效的机器码，从而提升Javascript代码在支持RVV的RISC-V架构上的执行效率。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
dleScope scope(isolate);                                              \
    int8_t src[16];                                                          \
    for (size_t i = 0; i < sizeof(src); i++) src[i] = arry[i % arry.size()]; \
    int8_t dst[16];                                                          \
    auto fn = [](MacroAssembler& assm) {                                     \
      __ VU.set(t0, SEW, Vlmul::m1);                                         \
      __ vl(v2, a0, 0, SEW);                                                 \
      __ vs(v2, a1, 0, SEW);                                                 \
    };                                                                       \
    GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);         \
    CHECK(!memcmp(src, dst, sizeof(src)));                                   \
  }

UTEST_LOAD_STORE_RVV(vl, vs, E8, compiler::ValueHelper::GetVector<int8_t>())

TEST(RVV_VFMV) {
  if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  for (float a : compiler::ValueHelper::GetVector<float>()) {
    float src = a;
    float dst[8] = {0};
    float ref[8] = {a, a, a, a, a, a, a, a};
    auto fn = [](MacroAssembler& assm) {
      __ VU.set(t0, VSew::E32, Vlmul::m2);
      __ flw(fa1, a0, 0);
      __ vfmv_vf(v2, fa1);
      __ vs(v2, a1, 0, VSew::E32);
    };
    GenAndRunTest<int32_t, int32_t>((int32_t)&src, (int32_t)dst, fn);
    CHECK(!memcmp(ref, dst, sizeof(ref)));
  }
}

TEST(RVV_VFMV_signaling_NaN) {
  if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;
  CcTest::InitializeVM();

  {
    constexpr uint32_t n = 2;
    int64_t rs1_fval = 0x7FF4000000000000;
    int64_t dst[n] = {0};
    auto fn = [](MacroAssembler& assm) {
      __ VU.set(t0, VSew::E64, Vlmul::m1);
      __ fld(ft0, a0, 0);
      __ vfmv_vf(v1, ft0);
      __ vs(v1, a1, 0, VSew::E64);
    };
    GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval, (int32_t)dst, fn);
    for (uint32_t i = 0; i < n; i++) {
      CHECK_EQ(rs1_fval, dst[i]);
    }
  }

  {
    constexpr uint32_t n = 4;
    int32_t rs1_fval = 0x7F400000;
    int32_t dst[n] = {0};
    auto fn = [](MacroAssembler& assm) {
      __ VU.set(t0, VSew::E32, Vlmul::m1);
      __ flw(ft0, a0, 0);
      __ vfmv_vf(v1, ft0);
      __ vs(v1, a1, 0, VSew::E32);
    };
    GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval, (int32_t)dst, fn);
    for (uint32_t i = 0; i < n; i++) {
      CHECK_EQ(rs1_fval, dst[i]);
    }
  }
}

TEST(RVV_VFNEG_signaling_NaN) {
  if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;
  CcTest::InitializeVM();

  {
    constexpr uint32_t n = 2;
    int64_t rs1_fval = 0x7FF4000000000000;
    int64_t expected_fval = 0xFFF4000000000000;
    int64_t dst[n] = {0};
    auto fn = [](MacroAssembler& assm) {
      __ VU.set(t0, VSew::E64, Vlmul::m1);
      __ fld(ft0, a0, 0);
      __ vfmv_vf(v1, ft0);
      __ vfneg_vv(v2, v1);
      __ vs(v2, a1, 0, VSew::E64);
    };
    GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval, (int32_t)dst, fn);
    for (uint32_t i = 0; i < n; i++) {
      CHECK_EQ(expected_fval, dst[i]);
    }
  }

  {
    constexpr uint32_t n = 4;
    int32_t rs1_fval = 0x7F400000;
    int32_t expected_fval = 0xFF400000;
    int32_t dst[n] = {0};
    auto fn = [](MacroAssembler& assm) {
      __ VU.set(t0, VSew::E32, Vlmul::m1);
      __ flw(ft0, a0, 0);
      __ vfmv_vf(v1, ft0);
      __ vfneg_vv(v2, v1);
      __ vs(v2, a1, 0, VSew::E32);
    };
    GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval, (int32_t)dst, fn);
    for (uint32_t i = 0; i < n; i++) {
      CHECK_EQ(expected_fval, dst[i]);
    }
  }
}

// Tests for Floating-Point scalar move instructions between vector and scalar f
// register
#define UTEST_RVV_VF_MV_FORM_WITH_RES(instr_name, reg1, reg2, width, type)   \
  TEST(RISCV_UTEST_##instr_name##_##width) {                                 \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    constexpr uint32_t n = kRvvVLEN / width;                                 \
    for (type fval : compiler::ValueHelper::GetVector<type>()) {             \
      int##width##_t rs1_fval = base::bit_cast<int##width##_t>(fval);        \
      int##width##_t res[n] = {0};                                           \
      for (uint32_t i = 0; i < n; i++) res[i] = (rs1_fval + i + 1);          \
      auto fn = [](MacroAssembler& assm) {                                   \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                            \
        width == 32 ? __ flw(ft0, a0, 0) : __ fld(ft0, a0, 0);               \
        __ vl(v1, a1, 0, VSew::E##width);                                    \
        __ instr_name(reg1, reg2);                                           \
        width == 32 ? __ fsw(ft0, a0, 0) : __ fsd(ft0, a0, 0);               \
        __ vs(v1, a1, 0, VSew::E##width);                                    \
      };                                                                     \
      GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval, (int32_t)res, fn); \
      for (uint32_t i = 0; i < n; i++) {                                     \
        CHECK_EQ(i == 0 ? rs1_fval : res[i], res[i]);                        \
      }                                                                      \
    }                                                                        \
  }                                                                          \
  TEST(RISCV_UTEST_##instr_name##_##width##_##sNaN) {                        \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    constexpr uint32_t n = kRvvVLEN / width;                                 \
    int##width##_t rs1_fval = width == 32 ? 0x7F400000 : 0x7FF4000000000000; \
    int##width##_t res[n] = {0};                                             \
    for (uint32_t i = 0; i < n; i++) res[i] = (rs1_fval + i + 1);            \
    auto fn = [](MacroAssembler& assm) {                                     \
      __ VU.set(t0, VSew::E##width, Vlmul::m1);                              \
      width == 32 ? __ flw(ft0, a0, 0) : __ fld(ft0, a0, 0);                 \
      __ vl(v1, a1, 0, VSew::E##width);                                      \
      __ instr_name(reg1, reg2);                                             \
      width == 32 ? __ fsw(ft0, a0, 0) : __ fsd(ft0, a0, 0);                 \
      __ vs(v1, a1, 0, VSew::E##width);                                      \
    };                                                                       \
    GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval, (int32_t)res, fn);   \
    for (uint32_t i = 0; i < n; i++) {                                       \
      CHECK_EQ(i == 0 ? rs1_fval : res[i], res[i]);                          \
    }                                                                        \
  }

UTEST_RVV_VF_MV_FORM_WITH_RES(vfmv_fs, ft0, v1, 32, float)
UTEST_RVV_VF_MV_FORM_WITH_RES(vfmv_fs, ft0, v1, 64, double)
UTEST_RVV_VF_MV_FORM_WITH_RES(vfmv_sf, v1, ft0, 32, float)
UTEST_RVV_VF_MV_FORM_WITH_RES(vfmv_sf, v1, ft0, 64, double)
#undef UTEST_RVV_VF_MV_FORM_WITH_RES

inline int32_t ToImm5(int32_t v) {
  int32_t smax = (int32_t)(INT64_MAX >> (64 - 5));
  int32_t smin = (int32_t)(INT64_MIN >> (64 - 5));
  return (v > smax) ? smax : ((v < smin) ? smin : v);
}

// Tests for vector integer arithmetic instructions between vector and vector
#define UTEST_RVV_VI_VV_FORM_WITH_RES(instr_name, width, array, expect_res) \
  TEST(RISCV_UTEST_##instr_name##_##width) {                                \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                      \
    CcTest::InitializeVM();                                                 \
    int##width##_t result[kRvvVLEN / width] = {0};                          \
    auto fn = [&result](MacroAssembler& assm) {                             \
      __ VU.set(t0, VSew::E##width, Vlmul::m1);                             \
      __ vmv_vx(v0, a0);                                                    \
      __ vmv_vx(v1, a1);                                                    \
      __ instr_name(v0, v0, v1);                                            \
      __ li(t1, int64_t(result));                                           \
      __ vs(v0, t1, 0, VSew::E##width);                                     \
    };                                                                      \
    for (int##width##_t rs1_val : array) {                                  \
      for (int##width##_t rs2_val : array) {                                \
        GenAndRunTest<int32_t, int32_t>(rs1_val, rs2_val, fn);              \
        for (int i = 0; i < kRvvVLEN / width; i++)                          \
          CHECK_EQ(static_cast<int##width##_t>(expect_res), result[i]);     \
      }                                                                     \
    }                                                                       \
  }

// Tests for vector integer arithmetic instructions between vector and scalar
#define UTEST_RVV_VI_VX_FORM_WITH_RES(instr_name, width, array, expect_res) \
  TEST(RISCV_UTEST_##instr_name##_##width) {                                \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                      \
    CcTest::InitializeVM();                                                 \
    int##width##_t result[kRvvVLEN / width] = {0};                          \
    auto fn = [&result](MacroAssembler& assm) {                             \
      __ VU.set(t0, VSew::E##width, Vlmul::m1);                             \
      __ vmv_vx(v0, a0);                                                    \
      __ instr_name(v0, v0, a1);                                            \
      __ li(t1, int64_t(result));                                           \
      __ vs(v0, t1, 0, VSew::E##width);                                     \
    };                                                                      \
    for (int##width##_t rs1_val : array) {                                  \
      for (int##width##_t rs2_val : array) {                                \
        GenAndRunTest<int32_t, int32_t>(rs1_val, rs2_val, fn);              \
        for (int i = 0; i < kRvvVLEN / width; i++)                          \
          CHECK_EQ(static_cast<int##width##_t>(expect_res), result[i]);     \
      }                                                                     \
    }                                                                       \
  }

// Tests for vector integer arithmetic instructions between vector and 5-bit
// immediate
#define UTEST_RVV_VI_VI_FORM_WITH_RES(instr_name, width, array, expect_res) \
  TEST(RISCV_UTEST_##instr_name##_##width) {                                \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                      \
    CcTest::InitializeVM();                                                 \
    int##width##_t result[kRvvVLEN / width] = {0};                          \
    for (int##width##_t rs1_val : array) {                                  \
      for (int##width##_t rs2_val : array) {                                \
        auto fn = [rs2_val, &result](MacroAssembler& assm) {                \
          __ VU.set(t0, VSew::E##width, Vlmul::m1);                         \
          __ vmv_vx(v0, a0);                                                \
          __ instr_name(v0, v0, ToImm5(rs2_val));                           \
          __ li(t1, int64_t(result));                                       \
          __ vs(v0, t1, 0, VSew::E##width);                                 \
        };                                                                  \
        GenAndRunTest<int32_t, int32_t>(rs1_val, fn);                       \
        for (int i = 0; i < kRvvVLEN / width; i++)                          \
          CHECK_EQ(static_cast<int##width##_t>(expect_res), result[i]);     \
      }                                                                     \
    }                                                                       \
  }

#define UTEST_RVV_VI_VV_FORM_WITH_OP(instr_name, width, array, tested_op) \
  UTEST_RVV_VI_VV_FORM_WITH_RES(instr_name, width, array,                 \
                                (int##width##_t)((rs1_val)tested_op(rs2_val)))

#define UTEST_RVV_VI_VX_FORM_WITH_OP(instr_name, width, array, tested_op) \
  UTEST_RVV_VI_VX_FORM_WITH_RES(instr_name, width, array,                 \
                                (int##width##_t)((rs1_val)tested_op(rs2_val)))

#define UTEST_RVV_VI_VI_FORM_WITH_OP(instr_name, width, array, tested_op) \
  UTEST_RVV_VI_VI_FORM_WITH_RES(                                          \
      instr_name, width, array,                                           \
      (int##width##_t)((rs1_val)tested_op(ToImm5(rs2_val))))

#define UTEST_RVV_VI_VV_FORM_WITH_FN(instr_name, width, array, tested_fn) \
  UTEST_RVV_VI_VV_FORM_WITH_RES(instr_name, width, array,                 \
                                tested_fn(rs1_val, rs2_val))

#define UTEST_RVV_VI_VX_FORM_WITH_FN(instr_name, width, array, tested_fn) \
  UTEST_RVV_VI_VX_FORM_WITH_RES(instr_name, width, array,                 \
                                tested_fn(rs1_val, rs2_val))

#define ARRAY_INT32 compiler::ValueHelper::GetVector<int32_t>()

#define VV(instr_name, array, tested_op)                         \
  UTEST_RVV_VI_VV_FORM_WITH_OP(instr_name, 8, array, tested_op)  \
  UTEST_RVV_VI_VV_FORM_WITH_OP(instr_name, 16, array, tested_op) \
  UTEST_RVV_VI_VV_FORM_WITH_OP(instr_name, 32, array, tested_op)

#define VX(instr_name, array, tested_op)                         \
  UTEST_RVV_VI_VX_FORM_WITH_OP(instr_name, 8, array, tested_op)  \
  UTEST_RVV_VI_VX_FORM_WITH_OP(instr_name, 16, array, tested_op) \
  UTEST_RVV_VI_VX_FORM_WITH_OP(instr_name, 32, array, tested_op)

#define VI(instr_name, array, tested_op)                         \
  UTEST_RVV_VI_VI_FORM_WITH_OP(instr_name, 8, array, tested_op)  \
  UTEST_RVV_VI_VI_FORM_WITH_OP(instr_name, 16, array, tested_op) \
  UTEST_RVV_VI_VI_FORM_WITH_OP(instr_name, 32, array, tested_op)

VV(vadd_vv, ARRAY_INT32, +)
VX(vadd_vx, ARRAY_INT32, +)
VI(vadd_vi, ARRAY_INT32, +)
VV(vsub_vv, ARRAY_INT32, -)
VX(vsub_vx, ARRAY_INT32, -)
VV(vand_vv, ARRAY_INT32, &)
VX(vand_vx, ARRAY_INT32, &)
VI(vand_vi, ARRAY_INT32, &)
VV(vor_vv, ARRAY_INT32, |)
VX(vor_vx, ARRAY_INT32, |)
VI(vor_vi, ARRAY_INT32, |)
VV(vxor_vv, ARRAY_INT32, ^)
VX(vxor_vx, ARRAY_INT32, ^)
VI(vxor_vi, ARRAY_INT32, ^)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmax_vv, 8, ARRAY_INT32, std::max<int8_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmax_vx, 8, ARRAY_INT32, std::max<int8_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmax_vv, 16, ARRAY_INT32, std::max<int16_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmax_vx, 16, ARRAY_INT32, std::max<int16_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmax_vv, 32, ARRAY_INT32, std::max<int32_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmax_vx, 32, ARRAY_INT32, std::max<int32_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmin_vv, 8, ARRAY_INT32, std::min<int8_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmin_vx, 8, ARRAY_INT32, std::min<int8_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmin_vv, 16, ARRAY_INT32, std::min<int16_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmin_vx, 16, ARRAY_INT32, std::min<int16_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmin_vv, 32, ARRAY_INT32, std::min<int32_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmin_vx, 32, ARRAY_INT32, std::min<int32_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmaxu_vv, 8, ARRAY_INT32, std::max<uint8_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmaxu_vx, 8, ARRAY_INT32, std::max<uint8_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmaxu_vv, 16, ARRAY_INT32, std::max<uint16_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmaxu_vx, 16, ARRAY_INT32, std::max<uint16_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vmaxu_vv, 32, ARRAY_INT32, std::max<uint32_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vmaxu_vx, 32, ARRAY_INT32, std::max<uint32_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vminu_vv, 8, ARRAY_INT32, std::min<uint8_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vminu_vx, 8, ARRAY_INT32, std::min<uint8_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vminu_vv, 16, ARRAY_INT32, std::min<uint16_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vminu_vx, 16, ARRAY_INT32, std::min<uint16_t>)
UTEST_RVV_VI_VV_FORM_WITH_FN(vminu_vv, 32, ARRAY_INT32, std::min<uint32_t>)
UTEST_RVV_VI_VX_FORM_WITH_FN(vminu_vx, 32, ARRAY_INT32, std::min<uint32_t>)

#undef ARRAY_INT32
#undef VV
#undef VX
#undef VI
#undef UTEST_RVV_VI_VV_FORM_WITH_FN
#undef UTEST_RVV_VI_VX_FORM_WITH_FN
#undef UTEST_RVV_VI_VI_FORM_WITH_OP
#undef UTEST_RVV_VI_VX_FORM_WITH_OP
#undef UTEST_RVV_VI_VV_FORM_WITH_OP
#undef UTEST_RVV_VI_VI_FORM
#undef UTEST_RVV_VI_VX_FORM
#undef UTEST_RVV_VI_VV_FORM

// Tests for vector single-width floating-point arithmetic instructions between
// vector and vector
#define UTEST_RVV_VF_VV_FORM_WITH_RES(instr_name, expect_res)              \
  TEST(RISCV_UTEST_FLOAT_##instr_name) {                                   \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                     \
    CcTest::InitializeVM();                                                \
    float result[4] = {0.0};                                               \
    auto fn = [&result](MacroAssembler& assm) {                            \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                                 \
      __ vfmv_vf(v0, fa0);                                                 \
      __ vfmv_vf(v1, fa1);                                                 \
      __ instr_name(v0, v0, v1);                                           \
      __ vfmv_fs(fa0, v0);                                                 \
      __ li(a3, Operand(int32_t(result)));                                 \
      __ vs(v0, a3, 0, E32);                                               \
    };                                                                     \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) {     \
      for (float rs2_fval : compiler::ValueHelper::GetVector<float>()) {   \
        GenAndRunTest<float, float>(rs1_fval, rs2_fval, fn);               \
        for (int i = 0; i < 4; i++) {                                      \
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
      __ fld(fa0, a0, 0);                                                  \
      __ fld(fa1, a1, 0);                                                  \
      __ vfmv_vf(v0, fa0);                                                 \
      __ vfmv_vf(v1, fa1);                                                 \
      __ instr_name(v0, v0, v1);                                           \
      __ vfmv_fs(fa0, v0);                                                 \
      __ li(a3, Operand(int32_t(result)));                                 \
      __ vs(v0, a3, 0, E64);                                               \
    };                                                                     \
    for (double rs1_fval : compiler::ValueHelper::GetVector<double>()) {   \
      for (double rs2_fval : compiler::ValueHelper::GetVector<double>()) { \
        GenAndRunTest<int32_t, int32_t>((int32_t)&rs1_fval,                \
                                        (int32_t)&rs2_fval, fn);           \
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
      __ li(t1, Operand(int32_t(result)));                                     \
      __ vs(v0, t1, 0, VSew::E64);                                             \
    };                                                                         \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) {         \
      for (float rs2_fval : compiler::ValueHelper::GetVector<float>()) {       \
        GenAndRunTest<int32_t, float>(rs1_fval, rs2_fval, fn);                 \
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
      __ li(t1, Operand(int32_t(result)));                                     \
      __ vs(v0, t1, 0, VSew::E64);                                             \
    };                                                                         \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) {         \
      for (float rs2_fval : compiler::ValueHelper::GetVector<float>()) {       \
        GenAndRunTest<int32_t, float>(rs1_fval, rs2_fval, fn);                 \
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
#define UTEST_RVV_VFW_FMA_VV_FORM_WITH_RES(instr_name, float_array,   \
                                           double_array, expect_res)  \
  TEST(RISCV_UTEST_FLOAT_WIDENING_##instr_name) {                     \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                \
    CcTest::InitializeVM();                                           \
    double addend_arr[2] = {0};                                       \
    float right_mul_arr[4] = {0};                                     \
    float left_mul_arr[4] = {0};                                      \
    auto fn = [](MacroAssembler& assm) {                              \
      __ VU.set(t0, VSew::E32, Vlmul::m1);                            \
      __ vl(v0, a0, 0, VSew::E32);                                    \
      __ vl(v2, a1, 0, VSew::E32);                                    \
      __ vl(v4, a2, 0, VSew::E32);                                    \
      __ instr_name(v0, v2, v4);                                      \
      __ VU.set(t0, VSew::E64, Vlmul::m1);                            \
      __ vs(v0, a0, 0, VSew::E64);                                    \
    };                                                                \
    for (double rs1_dval : double_array) {                            \
      for (float rs2_fval : float_array) {                            \
        for (float rs3_fval : float_array) {                          \
          for (double& src : addend_arr) src = rs1_dval;              \
          for (float& src : right_mul_arr) src = rs2_fval;            \
          for (float& src : left_mul_arr) src = rs3_fval;             \
          double rs2_dval = static_cast<double>(rs2_fval);            \
          double rs3_dval = static_cast<double>(rs3_fval);            \
          GenAndRunTest<int32_t, int32_t>((int32_t)addend_arr,        \
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