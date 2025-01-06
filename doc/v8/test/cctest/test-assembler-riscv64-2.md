Response: The user wants a summary of the provided C++ code, which is the third part of a larger file. The code seems to be testing the RISC-V Vector (RVV) extension within the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name (`test-assembler-riscv64.cc`) and the presence of `UTEST_RVV` macros strongly suggest this code is for testing the RISC-V vector instruction set within V8's assembler.

2. **Analyze the Macros:** The numerous `UTEST_RVV_*` macros are the key to understanding the specific functionalities being tested. Each macro likely represents a specific category of RVV instructions. Looking at the macro names reveals the types of instructions:
    * `UTEST_RVV_VI_VSEXT_VF_FORM_WITH_RES`: Vector Integer Sign Extend from Vector to Vector
    * `UTEST_RVV_VI_VIE_FORM_WITH_RES`: Vector Integer Extend from Vector to Integer Register
    * `UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES`: Vector Floating-Point Merge with a scalar Floating-Point value
    * `UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES`: Vector Permutation - Vector Slide with immediate offset
    * `UTEST_RVV_VP_VSLIDE_VX_FORM_WITH_RES`: Vector Permutation - Vector Slide with register offset
    * `UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES`: Vector Permutation - Vector Slide by 1 with register value
    * `UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES`: Vector Permutation - Vector Slide by 1 with floating-point register value
    * `UTEST_VFIRST_M_WITH_WIDTH`: Find the index of the first set bit in a mask register.
    * `UTEST_VCPOP_M_WITH_WIDTH`: Count the number of set bits in a mask register.

3. **Examine the Test Structure:** The general structure within each `TEST` block is consistent:
    * Check for RISC-V SIMD support.
    * Initialize the V8 VM.
    * Set up source and destination arrays.
    * Define a lambda function (`fn`) that uses the `MacroAssembler` to emit the RVV instruction being tested.
    * Use `GenAndRunTest` to execute the generated code.
    * Assert that the results in the destination array match the expected values.

4. **Identify Specific Instructions and Data Types:**  Within each macro usage, the specific RVV instruction mnemonic (e.g., `vsext_vf2`, `vfmerge_vf`, `vslidedown_vi`) and the data types involved (e.g., `int64_t`, `float`, `double`) are clear.

5. **Look for JavaScript Relevance:**  The code interacts with the V8 engine, and the purpose of these tests is to ensure the correctness of the generated assembly code for RVV instructions. This directly relates to how V8 can leverage RVV for potential performance improvements in JavaScript execution, especially for operations on typed arrays or SIMD.js (if supported).

6. **Construct the Summary:** Based on the above analysis, the summary should cover:
    * The file's role in testing RISC-V vector instructions.
    * The categories of RVV instructions being tested (sign extension, merge, slide/permutation).
    * The use of macros for test generation.
    * The general test structure (setup, assembly generation, execution, verification).
    * The connection to JavaScript performance through V8's assembler.

7. **Create a JavaScript Example (If Applicable):** To illustrate the connection to JavaScript, a simple example demonstrating an operation that *could* potentially be optimized using RVV instructions is helpful. Array manipulations or mathematical operations on number arrays are good candidates. Highlighting how V8 *might* use these tested instructions under the hood adds clarity. It's important to note that the *exact* mapping is an implementation detail, so the example focuses on the *kind* of operation.

8. **Review and Refine:** Ensure the summary is clear, concise, and accurately reflects the content of the code. Check for any technical jargon that might need clarification. Make sure the JavaScript example is easy to understand and relevant.
这是 `v8/test/cctest/test-assembler-riscv64.cc` 文件的第三部分，主要功能是**测试 RISC-V 架构下汇编器的向量（RVV）指令生成和执行的正确性**。

具体来说，这部分代码主要测试了以下几类 RVV 指令：

1. **向量整数扩展指令 (Vector Integer Extend):**  测试将向量中的较小元素扩展为较大元素的指令，例如 `vsext_vf2`，`vsext_vf4`。这些指令用于改变向量中元素的数据宽度。

2. **向量浮点合并指令 (Vector Floating-Point Merge):** 测试根据掩码寄存器的值，将一个向量的元素与另一个标量浮点值合并的指令 `vfmerge_vf`。这允许有条件地选择向量元素。

3. **向量排列指令 (Vector Permutation / Vector Slide):** 测试向量滑移指令，这些指令用于在向量内部移动元素。包括：
    * `vslidedown_vi`: 将向量元素向下（索引增加的方向）移动一个立即数偏移量，空出的位置用 0 填充。
    * `vslideup_vi`: 将向量元素向上（索引减小的方向）移动一个立即数偏移量，空出的位置保留目标向量原有的值。
    * `vslidedown_vx`: 与 `vslidedown_vi` 类似，但偏移量来自寄存器。
    * `vslideup_vx`: 与 `vslideup_vi` 类似，但偏移量来自寄存器。
    * `vslide1down_vx`: 将向量元素向下移动一个位置，空出的位置用寄存器的值填充。
    * `vslide1up_vx`: 将向量元素向上移动一个位置，空出的位置用寄存器的值填充。
    * `vfslide1down_vf`: 将浮点向量元素向下移动一个位置，空出的位置用浮点寄存器的值填充。
    * `vfslide1up_vf`: 将浮点向量元素向上移动一个位置，空出的位置用浮点寄存器的值填充。

4. **向量首位查找指令 (Vector First Mask):** 测试 `vfirst_m` 指令，该指令查找向量掩码寄存器中第一个为 1 的位的索引。

5. **向量人口计数指令 (Vector Count Population Mask):** 测试 `vcpop_m` 指令，该指令计算向量掩码寄存器中设置为 1 的位的数量。

6. **Wasm Rvv S128 常量加载测试:** 测试 `WasmRvvS128const` 功能，用于将 128 位常量加载到向量寄存器中，这与 WebAssembly 中使用 RVV 扩展有关。

**与 JavaScript 的关系以及 JavaScript 示例:**

这些测试直接关系到 V8 JavaScript 引擎如何利用 RISC-V 向量扩展来提升 JavaScript 代码的性能。当 JavaScript 代码执行某些特定类型的操作时（尤其是涉及到数组或大量数值计算时），V8 的即时编译器 (JIT) 可能会将这些操作编译成高效的 RVV 指令。

例如，考虑以下 JavaScript 代码，它对两个数组进行元素级别的加法：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const arr1 = [1, 2, 3, 4, 5, 6, 7, 8];
const arr2 = [9, 10, 11, 12, 13, 14, 15, 16];
const sum = addArrays(arr1, arr2);
console.log(sum); // 输出 [10, 12, 14, 16, 18, 20, 22, 24]
```

在支持 RVV 的 RISC-V 架构上，V8 的 JIT 编译器可能会将循环中的加法操作编译成 RVV 指令，例如向量加法指令。

再比如，考虑向量滑移操作，虽然在直接的 JavaScript 代码中不太常见，但在一些图形处理、信号处理或者更底层的操作中会有应用。 假设我们有一个 JavaScript 数组，我们想将其元素整体向右移动一位，并在最左边填充 0：

```javascript
function slideRight(arr) {
  const result = new Array(arr.length);
  for (let i = 0; i < arr.length; i++) {
    if (i === 0) {
      result[i] = 0;
    } else {
      result[i] = arr[i - 1];
    }
  }
  return result;
}

const data = [1, 2, 3, 4];
const shiftedData = slideRight(data);
console.log(shiftedData); // 输出 [0, 1, 2, 3]
```

在底层，V8 可能会利用类似于 `vslidedown_vi` 或其他向量滑移指令来实现这种操作，从而实现更高的效率。

总而言之，这个 C++ 测试文件通过构造各种场景来验证 V8 的 RISC-V 汇编器是否能够正确生成和执行 RVV 指令，这对于 V8 在 RISC-V 平台上利用向量化来提升 JavaScript 性能至关重要。这些测试确保了当 JIT 编译器决定使用 RVV 指令时，生成的代码是正确的并且能够按预期工作。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
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
#define UTEST_RVV_VF_VFMERGE_VF_FORM_WITH_RES(                                 \
    number /*prevent redefinition*/, type, int_type, width, array, expect_res) \
  TEST(RISCV_UTEST_vfmerge_vf_##type##_##number) {                             \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                         \
    constexpr uint32_t n = kRvvVLEN / width;                                   \
    CcTest::InitializeVM();                                                    \
    for (type fval : array) {                                                  \
      int_type rs1_fval = base::bit_cast<int_type>(fval);                      \
      for (uint32_t mask = 0; mask < (1 << n); mask++) {                       \
        int_type src[n] = {0};                                                 \
        int_type dst[n] = {0};                                                 \
        dst[0] = rs1_fval;                                                     \
        for (uint32_t i = 0; i < n; i++) src[i] = i;                           \
        auto fn = [mask](MacroAssembler& assm) {                               \
          __ VU.set(t0, VSew::E##width, Vlmul::m1);                            \
          __ vl(v1, a0, 0, VSew::E##width);                                    \
          __ vl(v24, a1, 0, VSew::E##width);                                   \
          __ vmv_vi(v0, mask);                                                 \
          __ vfmv_fs(ft0, v24);                                                \
          __ vfmerge_vf(v2, ft0, v1);                                          \
          __ vs(v2, a1, 0, VSew::E##width);                                    \
        };                                                                     \
        GenAndRunTest<int64_t, int64_t>((int64_t)src, (int64_t)dst, fn);       \
        for (uint32_t i = 0; i < n; i++) {                                     \
          CHECK_EQ(expect_res, dst[i]);                                        \
        }                                                                      \
      }                                                                        \
    }                                                                          \
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
        GenAndRunTest<int64_t, int64_t>((int64_t)src, (int64_t)dst, fn);     \
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
        GenAndRunTest<int64_t, int64_t>((int64_t)src, (int64_t)dst, rs2_val, \
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
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                        \
    constexpr uint32_t n = kRvvVLEN / width;                                  \
    CcTest::InitializeVM();                                                   \
    for (type x : array) {                                                    \
      type src[n] = {0};                                                      \
      type dst[n] = {0};                                                      \
      for (uint32_t i = 0; i < n; i++) src[i] = x + i;                        \
      auto fn = [](MacroAssembler& assm) {                                    \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                             \
        __ vl(v1, a0, 0, VSew::E##width);                                     \
        __ instr_name(v2, v1, a2);                                            \
        __ vs(v2, a1, 0, VSew::E##width);                                     \
      };                                                                      \
      type rs2_val = x + x;                                                   \
      GenAndRunTest<int64_t, int64_t>((int64_t)src, (int64_t)dst, rs2_val,    \
                                      fn);                                    \
      for (uint32_t i = 0; i < n; i++) {                                      \
        CHECK_EQ(expect_res, dst[i]);                                         \
      }                                                                       \
    }                                                                         \
  }

// Test for vslide1down_vx
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, int64_t, 64,
                                      ARRAY(int64_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, int32_t, 32,
                                      ARRAY(int32_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, int16_t, 16,
                                      ARRAY(int16_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, int8_t, 8, ARRAY(int8_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)

UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, uint32_t, 32,
                                      ARRAY(uint32_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, uint16_t, 16,
                                      ARRAY(uint16_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, uint8_t, 8,
                                      ARRAY(uint8_t),
                                      (i + 1) < n ? src[i + 1] : rs2_val)

// Test for vslide1up_vx
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, int64_t, 64, ARRAY(int64_t),
                                      (int64_t)i < 1 ? rs2_val : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, int32_t, 32, ARRAY(int32_t),
                                      (int32_t)i < 1 ? rs2_val : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, int16_t, 16, ARRAY(int16_t),
                                      (int16_t)i < 1 ? rs2_val : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, int8_t, 8, ARRAY(int8_t),
                                      (int8_t)i < 1 ? rs2_val : src[i - 1])

UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, uint32_t, 32,
                                      ARRAY(uint32_t),
                                      (uint32_t)i < 1 ? rs2_val : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, uint16_t, 16,
                                      ARRAY(uint16_t),
                                      (uint16_t)i < 1 ? rs2_val : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, uint8_t, 8, ARRAY(uint8_t),
                                      (uint8_t)i < 1 ? rs2_val : src[i - 1])
#undef UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES

#define UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(instr_name, type, width, fval, \
                                              array, expect_res)             \
  TEST(RISCV_UTEST_##instr_name##_##width##_##fval) {                        \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    constexpr uint32_t n = kRvvVLEN / width;                                 \
    CcTest::InitializeVM();                                                  \
    for (type x : array) {                                                   \
      type src[n] = {0};                                                     \
      type dst[n] = {0};                                                     \
      src[0] = base::bit_cast<type>(fval);                                   \
      for (uint32_t i = 1; i < n; i++) src[i] = x + i;                       \
      auto fn = [](MacroAssembler& assm) {                                   \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                            \
        __ vl(v1, a0, 0, VSew::E##width);                                    \
        width == 32 ? __ flw(fa0, a0, 0) : __ fld(fa0, a0, 0);               \
        __ instr_name(v2, v1, fa0);                                          \
        __ vs(v2, a1, 0, VSew::E##width);                                    \
      };                                                                     \
      GenAndRunTest<int64_t, int64_t>((int64_t)src, (int64_t)dst, fn);       \
      for (uint32_t i = 0; i < n; i++) {                                     \
        CHECK_EQ(expect_res, dst[i]);                                        \
      }                                                                      \
    }                                                                        \
  }

// Test for vfslide1down_vf
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1down_vf, int64_t, 64,
                                      0x40934A3D70A3D70A /*1234.56*/,
                                      ARRAY(int64_t),
                                      (i + 1) < n ? src[i + 1] : src[0])
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1down_vf, int32_t, 32,
                                      0x449A51EC /*1234.56f*/, ARRAY(int32_t),
                                      (i + 1) < n ? src[i + 1] : src[0])
// Test for vfslide1down_vf_signaling_NaN
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1down_vf, int64_t, 64,
                                      0x7FF4000000000000, ARRAY(int64_t),
                                      (i + 1) < n ? src[i + 1] : src[0])
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1down_vf, int32_t, 32, 0x7F400000,
                                      ARRAY(int32_t),
                                      (i + 1) < n ? src[i + 1] : src[0])
// Test for vfslide1up_vf
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1up_vf, int64_t, 64,
                                      0x40934A3D70A3D70A /*1234.56*/,
                                      ARRAY(int64_t),
                                      (int64_t)i < 1 ? src[0] : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1up_vf, int32_t, 32,
                                      0x449A51EC /*1234.56f*/, ARRAY(int32_t),
                                      (int32_t)i < 1 ? src[0] : src[i - 1])
// Test for vfslide1up_vf_signaling_NaN
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1up_vf, int64_t, 64,
                                      0x7FF4000000000000, ARRAY(int64_t),
                                      (int64_t)i < 1 ? src[0] : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1up_vf, int32_t, 32, 0x7F400000,
                                      ARRAY(int32_t),
                                      (int32_t)i < 1 ? src[0] : src[i - 1])
#undef UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES
#undef ARRAY

#define UTEST_VFIRST_M_WITH_WIDTH(width)                            \
  TEST(RISCV_UTEST_vfirst_m_##width) {                              \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;              \
    constexpr uint32_t vlen = 128;                                  \
    constexpr uint32_t n = vlen / width;                            \
    CcTest::InitializeVM();                                         \
    for (uint32_t i = 0; i <= n; i++) {                             \
      uint64_t src[2] = {0};                                        \
      src[0] = 1 << i;                                              \
      auto fn = [](MacroAssembler& assm) {                          \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                   \
        __ vl(v2, a0, 0, VSew::E##width);                           \
        __ vfirst_m(a0, v2);                                        \
      };                                                            \
      auto res = GenAndRunTest<int64_t, int64_t>((int64_t)src, fn); \
      CHECK_EQ(i < n ? i : (int64_t)-1, res);                       \
    }                                                               \
  }

UTEST_VFIRST_M_WITH_WIDTH(64)
UTEST_VFIRST_M_WITH_WIDTH(32)
UTEST_VFIRST_M_WITH_WIDTH(16)
UTEST_VFIRST_M_WITH_WIDTH(8)

#undef UTEST_VFIRST_M_WITH_WIDTH

#define UTEST_VCPOP_M_WITH_WIDTH(width)                               \
  TEST(RISCV_UTEST_vcpop_m_##width) {                                 \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                \
    uint32_t vlen = 128;                                              \
    uint32_t n = vlen / width;                                        \
    CcTest::InitializeVM();                                           \
    for (uint16_t x : compiler::ValueHelper::GetVector<uint16_t>()) { \
      uint64_t src[2] = {0};                                          \
      src[0] = x >> (16 - n);                                         \
      auto fn = [](MacroAssembler& assm) {                            \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                     \
        __ vl(v2, a0, 0, VSew::E##width);                             \
        __ vcpop_m(a0, v2);                                           \
      };                                                              \
      auto res = GenAndRunTest<int64_t, int64_t>((int64_t)src, fn);   \
      CHECK_EQ(__builtin_popcountl(src[0]), res);                     \
    }                                                                 \
  }

UTEST_VCPOP_M_WITH_WIDTH(64)
UTEST_VCPOP_M_WITH_WIDTH(32)
UTEST_VCPOP_M_WITH_WIDTH(16)
UTEST_VCPOP_M_WITH_WIDTH(8)

TEST(RISCV_UTEST_WasmRvvS128const) {
  if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;
  CcTest::InitializeVM();
  for (uint64_t x : compiler::ValueHelper::GetVector<int64_t>()) {
    for (uint64_t y : compiler::ValueHelper::GetVector<int64_t>()) {
      uint64_t src[2] = {x, y};
      uint8_t vals[16];
      volatile uint64_t result[kRvvVLEN / 64] = {0};
      memcpy(vals, src, sizeof(vals));
      auto fn = [vals, &result](MacroAssembler& assm) {
        __ Push(kScratchReg);
        __ WasmRvvS128const(v10, vals);
        __ li(t1, Operand(int64_t(result)));
        __ VU.set(t0, VSew::E64, Vlmul::m1);
        __ vs(v10, t1, 0, VSew::E64);
        __ Pop(kScratchReg);
      };
      GenAndRunTest(fn);
      CHECK_EQ(result[0], x);
      CHECK_EQ(result[1], y);
    }
  }
}

#undef UTEST_VCPOP_M_WITH_WIDTH

#undef __

}  // namespace internal
}  // namespace v8

"""


```