Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Identify the Core Purpose:** The file name `test-assembler-riscv64.cc` immediately suggests that this code tests the assembler functionality for the RISC-V 64-bit architecture within the V8 JavaScript engine. The `cctest` directory further reinforces that these are component tests for the C++ parts of V8.

2. **Recognize the Testing Framework:** The presence of `TEST(...)` macros indicates a testing framework, likely Google Test or a similar structure used within V8. The `CHECK_EQ(...)` calls confirm this, as they are assertions within the tests.

3. **Look for Patterns and Macros:**  The code heavily utilizes macros like `UTEST_RVV_VI_...`, `UTEST_RVV_VF_...`, and `UTEST_RVV_VP_...`. This is a common technique to generate multiple similar test cases with varying parameters. Understanding these macros is crucial.

4. **Dissect the Macros (Example: `UTEST_RVV_VI_VIE_FORM_WITH_RES`):**
   - `UTEST_RVV_VI_VIE_FORM_WITH_RES`: The prefix `UTEST_RVV` likely means "Unit Test for RISC-V Vector".
   - `VI`:  Could mean "Vector-Immediate" or "Vector-Integer".
   - `VIE`:  Might mean "Vector-Immediate-Element" or "Vector-Integer-Element".
   - `FORM_WITH_RES`: Clearly indicates that the test verifies the result against an expected value.
   - The macro takes arguments like `number`, `type`, `width`, `array`, and `expect_res`. This suggests that it's testing vector instructions with different data types, element widths, and input values, comparing the output to `expect_res`.

5. **Analyze the Instruction Mnemonics:** Inside the macro expansions, look for RISC-V assembly instructions. Examples: `vle`, `vse`, `vsext_vf2`, `vfmerge_vf`, `vslidedown_vi`, `vslideup_vx`, `vfirst_m`, `vcpop_m`, `WasmRvvS128const`. These are the core functionalities being tested. Even without being a RISC-V expert, the names give hints about their purpose (e.g., `vle` likely means "vector load element," `vsext` is "vector sign extend," `vfmerge` is "vector float merge," `vslide` is for sliding elements in a vector).

6. **Connect Instructions to Functionality:**  Based on the instruction names and the macro parameters, infer what each test group is verifying:
   - `vle`, `vse`: Basic vector load and store operations.
   - `vsext`: Vector sign extension with different scaling factors.
   - `vfmerge`: Merging a scalar float into a vector based on a mask.
   - `vslide`:  Sliding vector elements up or down with immediate or register offsets.
   - `vfirst_m`, `vcpop_m`: Instructions related to finding the first set bit in a mask and counting set bits.
   - `WasmRvvS128const`: Loading a 128-bit constant into a vector register.

7. **Understand the Test Structure:**  Each `TEST(...)` block generally follows a pattern:
   - Check if RISC-V SIMD is supported.
   - Initialize the V8 VM (`CcTest::InitializeVM()`).
   - Set up input data (`src`, `dst`, `mask`, `offset`, `rs2_val`, `fval`).
   - Define a lambda function `fn` that contains the assembly code to be tested.
   - Call `GenAndRunTest` to execute the assembly code with the given inputs.
   - Assert that the output (`dst`) matches the expected result (`expect_res`).

8. **Infer Expected Behavior:** The `expect_res` calculation within the macros provides the logic being tested. For example:
   - `vsext_vf2`:  Expects the sign-extended value.
   - `vfmerge`: Expects the scalar value if the corresponding mask bit is set, otherwise the original vector element.
   - `vslidedown`: Expects elements shifted down, with zero-filling.
   - `vslideup`: Expects elements shifted up, with initial elements potentially remaining from the destination.

9. **Consider JavaScript Relevance (If Applicable):** While this particular snippet focuses on the low-level assembler, remember that V8 compiles JavaScript to machine code. These tests ensure that the RISC-V backend of V8 correctly implements vector operations that might be generated when compiling JavaScript code that utilizes SIMD features or other vectorizable operations. *In this specific snippet, the connection is more about testing the *foundation* that higher-level JavaScript SIMD might rely on.*

10. **Identify Potential Programming Errors:** The tests themselves highlight potential errors in the assembler implementation. For example, incorrect handling of boundary conditions in `vslide` instructions, wrong sign extension, or improper masking in `vfmerge`. From a user's perspective, misusing SIMD intrinsics or writing JavaScript code that doesn't vectorize as expected could lead to performance issues or incorrect results.

11. **Synthesize the Summary:** Combine the understanding of the tested instructions, the testing methodology, and the overall goal to create a concise summary of the file's purpose.

**Self-Correction/Refinement During the Process:**

- **Initial thought:**  "Maybe this tests the Torque implementation of these instructions."  **Correction:** The `.cc` extension and the use of `MacroAssembler` strongly indicate C++ assembler tests, not Torque (which uses `.tq`).
- **Initial thought:** "The JavaScript connection is direct." **Correction:**  The connection is more indirect. It's testing the underlying assembler that *enables* potential JavaScript SIMD features.
- **Realization:**  The macros are the key to understanding the test variations. Spending time understanding them is crucial.

By following this systematic approach, one can effectively analyze and understand the functionality of complex C++ code like this, even without deep, immediate knowledge of every RISC-V instruction.
This is the 5th and final part of the analysis of the V8 source code file `v8/test/cctest/test-assembler-riscv64.cc`. Let's summarize the overall functionality based on all five parts.

**Overall Functionality of `v8/test/cctest/test-assembler-riscv64.cc`:**

This C++ file serves as a comprehensive unit test suite for the RISC-V 64-bit assembler within the V8 JavaScript engine. Its primary goal is to ensure the correctness and proper functioning of individual RISC-V instructions and instruction sequences generated by V8's assembler.

Here's a breakdown of the key aspects it tests:

* **RISC-V Vector Extension (RVV) Instructions:**  The vast majority of the tests focus on the RVV instructions. This includes:
    * **Vector Load and Store:** Instructions for moving data between memory and vector registers (`vle`, `vse`).
    * **Vector Integer Arithmetic and Logical Operations:**  Tests for basic integer operations on vectors (not heavily covered in the provided snippets, but present in earlier parts).
    * **Vector Floating-Point Operations:** Tests for floating-point operations like merge (`vfmerge`), and slide (`vfslide`).
    * **Vector Type Conversion:**  Instructions for converting between different element sizes, like sign extension (`vsext`).
    * **Vector Mask Operations:** Instructions that use masks to conditionally operate on vector elements.
    * **Vector Permutation Instructions (Slide Instructions):**  Instructions for shifting or sliding elements within a vector (`vslidedown`, `vslideup`, `vfslide`).
    * **Vector Reduction Operations:** Instructions like `vfirst_m` (find first set bit in mask) and `vcpop_m` (count population of mask).
* **Scalar RISC-V Instructions:** While the focus is on RVV, it likely also tests basic scalar instructions to some extent (though not explicitly shown in this part).
* **Wasm SIMD Support:**  Specific tests like `RISCV_UTEST_WasmRvvS128const` indicate testing of WebAssembly SIMD support on the RISC-V architecture, verifying that constant vectors can be loaded correctly.
* **Instruction Encoding and Decoding:** By generating assembly code and running it, these tests implicitly verify that the assembler correctly encodes RISC-V instructions.
* **Operand Handling:** The tests check that the assembler correctly handles different operand types (registers, immediate values, memory addresses).
* **Edge Cases and Boundary Conditions:** The use of loops and various input values suggests an attempt to cover different scenarios and potential edge cases in instruction behavior.

**Regarding the specific questions:**

* **Is `v8/test/cctest/test-assembler-riscv64.cc` a Torque source file?** No. It has a `.cc` extension, indicating it's a C++ source file. Torque files have a `.tq` extension.

* **Relationship to JavaScript and JavaScript Examples:** This file doesn't directly contain JavaScript code. However, it's crucial for the correct execution of JavaScript on RISC-V 64-bit architectures. When V8 compiles JavaScript code (especially code utilizing SIMD or other performance-sensitive constructs), it generates RISC-V assembly instructions. This test file ensures those generated instructions are correct.

   **Illustrative JavaScript Example (Conceptual):**

   Imagine JavaScript code that performs a SIMD operation, like adding two vectors of numbers:

   ```javascript
   // Hypothetical SIMD API in JavaScript (not standard, for illustration)
   const a = new SIMD.Int32x4(1, 2, 3, 4);
   const b = new SIMD.Int32x4(5, 6, 7, 8);
   const sum = SIMD.add(a, b);
   // Expected: sum = SIMD.Int32x4(6, 8, 10, 12)
   ```

   When V8 compiles this, it might generate RISC-V RVV instructions like `vadd.vv` (vector add vector). The tests in `test-assembler-riscv64.cc` would verify the correct implementation of instructions like `vadd.vv` to ensure the JavaScript code executes as expected on a RISC-V processor.

* **Code Logic Inference, Assumptions, and Outputs:**

   Let's take the `UTEST_RVV_VP_VSLIDE_VI_FORM_WITH_RES` macro for `vslidedown_vi` as an example:

   **Assumption:** The vector length is `n`, and the offset is `offset`.

   **Input (Conceptual):**
   * `src`: A vector of integers, e.g., `[10, 20, 30, 40, 50]`
   * `offset`: An immediate value, e.g., `2`

   **Assembly Instruction being tested:** `vslidedown_vi v2, v1, offset` (Slide down elements in `v1` by `offset`, put the result in `v2`).

   **Expected Output (based on `expect_res`):**
   `dst[i] = (i + offset) < n ? src[i + offset] : 0`

   If `n = 5` and `offset = 2`:
   * `dst[0]`: `(0 + 2) < 5` is true, so `dst[0] = src[2] = 30`
   * `dst[1]`: `(1 + 2) < 5` is true, so `dst[1] = src[3] = 40`
   * `dst[2]`: `(2 + 2) < 5` is true, so `dst[2] = src[4] = 50`
   * `dst[3]`: `(3 + 2) < 5` is false, so `dst[3] = 0`
   * `dst[4]`: `(4 + 2) < 5` is false, so `dst[4] = 0`

   **Output:** `[30, 40, 50, 0, 0]`

* **Common Programming Errors:**

   These tests implicitly help catch errors in the V8 assembler implementation. However, from a user's perspective (someone writing assembly or potentially interacting with low-level APIs), common errors related to the tested instructions could include:

   * **Incorrect Offset Calculation:**  For slide instructions, providing the wrong offset value, leading to accessing the wrong elements.
   * **Type Mismatches:** Using instructions with incompatible data types. For instance, trying to perform a floating-point operation on integer vectors.
   * **Incorrect Masking:** In `vfmerge` and other masked operations, using a mask that doesn't achieve the desired conditional behavior.
   * **Boundary Errors:**  Forgetting about vector lengths and accessing elements beyond the valid range, which might lead to crashes or unexpected results (though RVV often handles this gracefully by ignoring out-of-bounds accesses).
   * **Sign Extension Errors:** Misunderstanding how sign extension works and getting unexpected values after conversion.

**Summary of the Entire File's Functionality (Based on all 5 parts):**

The complete `v8/test/cctest/test-assembler-riscv64.cc` file provides a thorough set of unit tests for the RISC-V 64-bit assembler in V8, with a strong emphasis on the Vector Extension (RVV). It covers various RVV instructions for load/store, arithmetic, logical, floating-point, type conversion, masking, and permutation operations. The tests are designed to verify the correctness of the generated assembly code, ensuring that V8 can effectively utilize the RISC-V architecture for optimal performance when executing JavaScript and WebAssembly code. It plays a crucial role in maintaining the reliability and correctness of V8 on RISC-V platforms.

### 提示词
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```
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
```