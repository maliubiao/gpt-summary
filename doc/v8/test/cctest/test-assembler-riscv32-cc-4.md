Response:
Let's break down the thought process for analyzing this V8 test file.

1. **Understanding the Context:** The file path `v8/test/cctest/test-assembler-riscv32.cc` immediately tells us several things:
    * `v8`:  It's part of the V8 JavaScript engine.
    * `test`: It's a test file.
    * `cctest`:  Suggests a C++ test. This likely uses V8's internal testing framework.
    * `assembler`:  Indicates it tests assembly code generation.
    * `riscv32`: Specifies the target architecture (32-bit RISC-V).
    * `.cc`:  It's a C++ source file.

2. **Initial Scan for Clues:**  A quick scan reveals several recurring patterns and keywords:
    * `RISCV_SIMD`: This strongly suggests the tests are related to SIMD (Single Instruction, Multiple Data) instructions for the RISC-V architecture.
    * `UTEST_RVV_*`:  This naming convention is typical for unit tests in V8. The `RVV` part reinforces the RISC-V Vector extension focus.
    * `MacroAssembler`: This is V8's abstraction for generating machine code. The tests are likely verifying the correctness of the generated RISC-V V instructions.
    * `__ VU.set(...)`, `__ vl(...)`, `__ vs(...)`, `__ instr_name(...)`: These are V8's macro-like interfaces for emitting RISC-V assembly instructions, particularly vector load (`vl`), vector store (`vs`), and setting vector unit parameters (`VU.set`).
    * `vslide1down_vx`, `vslide1up_vx`, `vfslide1down_vf`, `vfslide1up_vf`, `vfirst_m`, `vcpop_m`: These are specific names of RISC-V Vector instructions being tested.
    * `GenAndRunTest`: This looks like a helper function to generate and execute the assembly code for the tests.
    * `CHECK_EQ`: This is a standard assertion macro used in C++ unit tests to verify expected results.

3. **Analyzing the Macros:**  The definitions of macros like `UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES` are crucial. Let's break down what these macros do:
    * `TEST(...)`:  This is the standard C++ test macro that defines a test case.
    * `if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;`: This ensures the test is only run if the RISC-V SIMD features are enabled on the target system.
    * `constexpr uint32_t n = kRvvVLEN / width;`: This calculates the number of vector elements based on the vector length (`kRvvVLEN`) and the element width.
    * `CcTest::InitializeVM();`: This likely initializes the V8 virtual machine for testing.
    * The loops iterating through `array`: This indicates the tests run with different input values.
    * The setup of `src` and `dst` arrays: These are the input and output buffers for the vector operations.
    * The lambda function `fn`: This is where the RISC-V assembly code is generated using `MacroAssembler`.
    * `__ VU.set(...)`: Configures the vector unit, setting the element width and vector length multiplier.
    * `__ vl(...)`: Loads data from memory into a vector register.
    * `__ instr_name(...)`:  This is the core part, emitting the specific RISC-V vector instruction being tested.
    * `__ vs(...)`: Stores data from a vector register back to memory.
    * `GenAndRunTest(...)`:  Executes the generated assembly code.
    * The final loop with `CHECK_EQ`: Verifies that the output in the `dst` array matches the `expect_res`.

4. **Inferring Functionality:** Based on the instructions and the test structure, we can deduce the following functionalities being tested:
    * **Vector Slide Down/Up Instructions:** `vslide1down_vx`, `vslide1up_vx`, `vfslide1down_vf`, `vfslide1up_vf`  shift elements within a vector. The `vx` versions use a scalar register as the fill value for empty slots, while the `vf` versions use a floating-point register.
    * **Vector First Mask Bit:** `vfirst_m` finds the index of the first set bit in a mask.
    * **Vector Count Population Mask:** `vcpop_m` counts the number of set bits (ones) in a mask.
    * **Loading 128-bit Constants:** `WasmRvvS128const` appears to be related to loading constant values into vector registers, possibly for WebAssembly SIMD.

5. **Considering JavaScript Relevance:**  While the code itself is C++, it's testing the *assembler*, which is the component responsible for generating the low-level instructions that V8 will eventually execute when running JavaScript code. Therefore, these tests directly impact the performance and correctness of JavaScript code that leverages SIMD operations (likely through WebAssembly or potential future JavaScript SIMD APIs).

6. **Generating Examples and Scenarios:** Based on the identified functionalities, we can create examples of how these instructions might be used and potential pitfalls.

7. **Addressing the "`.tq`" Question:**  The code has a clear C++ structure. The prompt's suggestion about `.tq` files is a way to check if the user understands the different parts of V8. Since the file is `.cc`, it's definitively *not* a Torque file.

8. **Synthesizing the Summary:**  Finally, the information gathered is organized into a concise summary covering the purpose, testing methods, and connection to JavaScript.

**(Self-Correction/Refinement):**  Initially, I might have focused too much on the specific RISC-V instruction details. However, recognizing the broader context of "testing the assembler" is key. The tests aren't just about the *correctness* of the RISC-V instructions themselves (that's the CPU's job), but rather about V8's ability to *generate the right instructions* for a given high-level operation. Also, recognizing the potential link to WebAssembly SIMD features is important for understanding the motivation behind these tests.
好的，我们来分析一下 `v8/test/cctest/test-assembler-riscv32.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`v8/test/cctest/test-assembler-riscv32.cc` 是 V8 JavaScript 引擎的一个 C++ 测试文件。它的主要功能是**测试 V8 在 RISC-V 32位架构上生成汇编代码的正确性，特别是针对 RISC-V Vector (RVV) 扩展指令**。

更具体地说，这个文件包含了一系列单元测试，用于验证 V8 的 `MacroAssembler` 类（用于生成机器码）能否正确地生成各种 RVV 指令，例如：

* **向量滑动操作 (Vector Slide):** `vslide1down_vx`, `vslide1up_vx`, `vfslide1down_vf`, `vfslide1up_vf`。这些指令用于在向量寄存器内部移动元素。
* **查找第一个 Mask 位 (Find First Mask Bit):** `vfirst_m`。用于查找向量 Mask 中第一个被设置的位的位置。
* **向量计数置位位 (Vector Count Population Mask):** `vcpop_m`。用于计算向量 Mask 中被设置的位的数量。
* **加载 128 位常量 (Load 128-bit Constant):** `WasmRvvS128const`。这可能与 WebAssembly 中使用 RVV SIMD 指令有关。

**关于文件类型**

* **`.tq` 文件:**  你提到如果文件以 `.tq` 结尾，那么它将是 V8 Torque 源代码。 Torque 是一种用于在 V8 中编写高性能运行时代码的领域特定语言。  由于该文件以 `.cc` 结尾，它是一个 **C++ 源代码文件**，而不是 Torque 文件。

**与 JavaScript 的关系**

虽然这个文件本身是 C++ 代码，但它直接关系到 V8 执行 JavaScript 的能力。  当 JavaScript 代码（特别是使用 SIMD 或未来可能利用 RVV 的特性）在 RISC-V 32位架构上运行时，V8 需要将这些高级操作转换为底层的机器码指令。`test-assembler-riscv32.cc` 中的测试确保了 V8 的代码生成器能够正确地将操作转换为相应的 RVV 指令。

**JavaScript 示例 (假设的未来 RVV 支持)**

目前，JavaScript 标准本身并没有直接暴露 RVV 指令。但是，WebAssembly 的固定宽度 SIMD 支持以及未来 JavaScript 可能引入的 SIMD API，可能会在底层使用到类似 RVV 的向量操作。

假设未来 JavaScript 有类似的操作，以下是一个概念性的例子来说明 `vslide1down_vx` 的可能作用：

```javascript
// 假设的 JavaScript SIMD API (与实际 API 可能不同)
const vectorA = new SIMD.Int32x4(1, 2, 3, 4);
const scalarB = 10;

// 概念上对应于 vslide1down_vx 的操作
const result = SIMD.slideDown(vectorA, scalarB); // 结果可能为 [10, 1, 2, 3]

console.log(result);
```

在这个假设的例子中，`SIMD.slideDown` 操作会将 `vectorA` 中的元素向下移动一位，并将 `scalarB` 的值填充到第一个位置。 这与 `vslide1down_vx` 指令的功能类似。

**代码逻辑推理**

该文件中的主要逻辑在各个 `UTEST_RVV_*` 宏定义中。让我们以 `UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES` 宏为例进行推理：

**假设输入:**

* `instr_name`: `vslide1down_vx` (要测试的 RVV 指令名称)
* `type`: `int32_t` (向量元素类型)
* `width`: `32` (向量元素宽度，单位为 bit)
* `array`:  例如 `{1, 2, 3}` (用于测试的初始标量值数组)
* `expect_res`: 一个计算预期结果的表达式，例如 `(i + 1) < n ? src[i + 1] : rs2_val`

**执行流程:**

1. **初始化:**  跳过非 RVV 支持的平台。初始化 V8 虚拟机。计算向量长度 `n`。
2. **循环测试:** 遍历 `array` 中的每个值 `x`。
3. **设置向量:** 创建源向量 `src` 和目标向量 `dst`。将 `x` 加上索引 `i` 填充 `src`。
4. **生成汇编:** 定义一个 lambda 函数，使用 `MacroAssembler` 生成汇编代码：
   * 设置向量单元 (VU) 的配置，例如元素宽度和向量长度。
   * 使用 `vl` (vector load) 指令将 `src` 加载到向量寄存器 `v1`。
   * 使用要测试的指令 `instr_name` (例如 `vslide1down_vx`)，操作数是 `v1` 和标量寄存器 `a2`。
   * 使用 `vs` (vector store) 指令将结果向量 `v2` 存储到 `dst`。
5. **运行测试:** 使用 `GenAndRunTest` 函数执行生成的汇编代码。`rs2_val` 是一个标量值，会被加载到 `a2` 寄存器。
6. **验证结果:** 遍历目标向量 `dst`，使用 `CHECK_EQ` 断言每个元素是否与 `expect_res` 计算出的预期结果一致。

**假设输出:**

对于 `vslide1down_vx, int32_t, 32, ARRAY(int32_t), (i + 1) < n ? src[i + 1] : rs2_val`， 假设 `array` 为 `{1}`， `kRvvVLEN` 为 128，则 `n` 为 128 / 32 = 4。

* 循环开始，`x` 为 1。
* `src` 初始化为 `{1, 2, 3, 4}` (前 n 个元素)。
* `rs2_val` 计算为 1 + 1 = 2。
* 生成的汇编代码会将 `v1` 加载为 `{1, 2, 3, 4}`，然后执行 `vslide1down_vx v2, v1, a2`，其中 `a2` 的值为 2。
* `vslide1down_vx` 指令会将 `v1` 中的元素向下移动一位，并将 `a2` 的值填充到最高位。所以 `v2` 的预期值为 `{2, 1, 2, 3}`。
* `dst` 存储 `v2` 的结果。
* 验证环节会检查 `dst[0]` 是否等于 `(0 + 1) < 4 ? src[1] : 2`，即 `2`。
* 检查 `dst[1]` 是否等于 `(1 + 1) < 4 ? src[2] : 2`，即 `3`。
* 检查 `dst[2]` 是否等于 `(2 + 1) < 4 ? src[3] : 2`，即 `4`。
* 检查 `dst[3]` 是否等于 `(3 + 1) < 4 ? src[4] : 2`，由于 `src` 只有 4 个元素，所以条件不成立，结果为 `2`。

因此，预期 `dst` 的值为 `{2, 1, 2, 3}`。 (**注意：我之前的理解有误，`vslide1down_vx` 是将元素向下移动，用标量值填充最高位**)。

**用户常见的编程错误示例**

这个测试文件主要关注 V8 代码生成器的正确性，而不是用户在编写 JavaScript 时容易犯的错误。但是，理解 RVV 指令的行为对于编写能够有效利用这些指令的底层代码至关重要。

以下是一些与 RVV 指令相关的潜在错误，虽然用户通常不会直接编写这些指令：

1. **向量长度不匹配:**  RVV 指令操作的向量长度由向量长度寄存器（VLEN）和向量乘法器（LMUL）决定。如果操作数的向量长度不一致，会导致未定义的行为或错误的结果。
2. **元素宽度不匹配:**  RVV 指令可以操作不同宽度的元素（例如 8位、16位、32位、64位）。如果指令的操作数具有不同的元素宽度，则会导致错误。
3. **掩码使用错误:** 许多 RVV 指令使用掩码来选择哪些元素参与运算。错误地设置或理解掩码会导致部分元素未被处理或处理错误。 例如，忘记初始化掩码，或者错误地假设掩码的行为。
4. **对齐问题:** 向量加载和存储操作通常需要对齐的内存地址。未对齐的访问可能导致性能下降或程序崩溃。
5. **不理解滑动操作的边界行为:**  像 `vslide1down_vx` 这样的指令在向量的边界处有特定的行为（例如用标量值填充）。不理解这些边界条件可能导致意外的结果。

**第 5 部分归纳**

作为第 5 部分（共 5 部分），这个代码片段主要集中在测试 **RISC-V Vector (RVV) 扩展指令中的向量滑动操作 (`vslide1down_vx`, `vslide1up_vx`, `vfslide1down_vf`, `vfslide1up_vf`)，以及向量掩码相关的操作 (`vfirst_m`, `vcpop_m`) 和加载常量操作 (`WasmRvvS128const`)**。

它使用了宏来简化编写针对不同数据类型和指令的测试用例。 每个测试用例都生成一段汇编代码，执行特定的 RVV 指令，并将结果与预期值进行比较，以此验证 V8 的代码生成器在 RISC-V 32位架构上的正确性。

总而言之，`v8/test/cctest/test-assembler-riscv32.cc` 是 V8 质量保证体系中的重要组成部分，确保了 V8 能够在 RISC-V 平台上正确且高效地执行 JavaScript 代码，尤其是在利用到 RVV 指令的情况下。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
RISCV_SIMD)) return;                        \
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
      GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, rs2_val,    \
                                      fn);                                    \
      for (uint32_t i = 0; i < n; i++) {                                      \
        CHECK_EQ(expect_res, dst[i]);                                         \
      }                                                                       \
    }                                                                         \
  }

// Test for vslide1down_vx
// UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1down_vx, int64_t, 64,
//                                       ARRAY(int64_t),
//                                       (i + 1) < n ? src[i + 1] : rs2_val)
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
// UTEST_RVV_VP_VSLIDE1_VX_FORM_WITH_RES(vslide1up_vx, int64_t, 64,
// ARRAY(int64_t),
//                                       (int64_t)i < 1 ? rs2_val : src[i - 1])
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
      GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);       \
      for (uint32_t i = 0; i < n; i++) {                                     \
        CHECK_EQ(expect_res, dst[i]);                                        \
      }                                                                      \
    }                                                                        \
  }

// Test for vfslide1down_vf
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1down_vf, int64_t, 64,
                                      0x40934A3D70A3D70A, ARRAY(int64_t),
                                      (i + 1) < n ? src[i + 1] : src[0])
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1down_vf, int32_t, 32, 0x449A51EC,
                                      ARRAY(int32_t),
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
                                      0x40934A3D70A3D70A, ARRAY(int64_t),
                                      (int64_t)i < 1 ? src[0] : src[i - 1])
UTEST_RVV_VP_VSLIDE1_VF_FORM_WITH_RES(vfslide1up_vf, int32_t, 32, 0x449A51EC,
                                      ARRAY(int32_t),
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
    constexpr int32_t vlen = 128;                                   \
    constexpr int32_t n = vlen / width;                             \
    CcTest::InitializeVM();                                         \
    for (int32_t i = 0; i <= n; i++) {                              \
      uint64_t src[2] = {0};                                        \
      src[0] = 1 << i;                                              \
      auto fn = [](MacroAssembler& assm) {                          \
        __ VU.set(t0, VSew::E##width, Vlmul::m1);                   \
        __ vl(v2, a0, 0, VSew::E##width);                           \
        __ vfirst_m(a0, v2);                                        \
      };                                                            \
      auto res = GenAndRunTest<int32_t, int32_t>((int32_t)src, fn); \
      CHECK_EQ(i < n ? i : (int32_t)-1, res);                       \
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
      auto res = GenAndRunTest<int32_t, int32_t>((int32_t)src, fn);   \
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
      volatile uint32_t result[kRvvVLEN / 32] = {0};
      memcpy(vals, src, sizeof(vals));
      auto fn = [vals, &result](MacroAssembler& assm) {
        __ Push(kScratchReg);
        __ WasmRvvS128const(v10, vals);
        __ li(t1, Operand(int32_t(result)));
        __ VU.set(t0, VSew::E32, Vlmul::m1);
        __ vs(v10, t1, 0, VSew::E32);
        __ Pop(kScratchReg);
      };
      GenAndRunTest(fn);
      volatile uint64_t* result_addr =
          reinterpret_cast<volatile uint64_t*>(&result[0]);
      CHECK_EQ((uint64_t)*result_addr, x);
      CHECK_EQ((uint64_t) * (result_addr + 1), y);
    }
  }
}

#undef UTEST_VCPOP_M_WITH_WIDTH
#endif  // CAN_USE_RVV_INSTRUCTIONS
#undef __
}  // namespace internal
}  // namespace v8
```