Response:
The user wants a summary of the provided C++ code snippet, focusing on its functionality within the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Code's Purpose:** The code is part of V8's test suite (`v8/test/cctest`). Specifically, it's testing the RISC-V 32-bit assembler (`test-assembler-riscv32.cc`). The presence of `RVV` in many test names strongly suggests it's testing the RISC-V Vector extension (RVV).

2. **Analyze the Structure:** The code consists of multiple `TEST` macros. Each `TEST` seems to focus on verifying the functionality of a specific RISC-V vector instruction or a group of related instructions. The structure within each `TEST` typically involves:
    * Checking if RVV is supported.
    * Initializing the V8 environment.
    * Setting up input data (often using `compiler::ValueHelper::GetVector`).
    * Defining a lambda function `fn` that contains the assembly code to be tested.
    * Using `GenAndRunTest` to execute the generated assembly with the input data.
    * Checking the output against expected results using `CHECK` or `CHECK_EQ`.
    * Macros like `UTEST_LOAD_STORE_RVV`, `UTEST_RVV_VF_MV_FORM_WITH_RES`, `UTEST_RVV_VI_VV_FORM_WITH_RES`, and others are used to generate multiple test cases efficiently.

3. **Categorize Functionality:** Based on the test names and the assembly instructions within the `fn` lambdas, the code tests various categories of RISC-V vector instructions:
    * **Load/Store:** Instructions like `vl` (vector load) and `vs` (vector store).
    * **Floating-Point Moves:** Instructions like `vfmv_vf` (move scalar float to vector).
    * **Floating-Point Negation:** Instructions like `vfneg_vv`.
    * **Floating-Point Scalar-Vector Moves:** Instructions like `vfmv_fs` (move vector to scalar float) and `vfmv_sf` (move scalar float to vector).
    * **Integer Arithmetic:** Instructions like `vadd_vv`, `vsub_vv`, `vand_vv`, `vor_vv`, `vxor_vv`, `vmax_vv`, `vmin_vv`, and their scalar-vector and immediate variants.
    * **Floating-Point Arithmetic:** Instructions like `vfadd_vv`, `vfsub_vv`, `vfmul_vv`, `vfdiv_vv`, and their scalar-vector variants.
    * **Widening Floating-Point Arithmetic:** Instructions like `vfwadd_vv`, `vfwsub_vv`, `vfwmul_vv`, and their scalar-vector variants.
    * **Widening Floating-Point Fused Multiply-Add:** Instructions like `vfmadd_vv`, `vfmsub_vv`, `vfnmadd_vv`, `vfnmsub_vv`.

4. **Address Specific Instructions:**  For each category, identify the specific RISC-V instructions being tested and their operands (registers, immediate values).

5. **Relate to JavaScript (if applicable):** While these tests are low-level, they are indirectly related to JavaScript. V8's optimizing compiler (TurboFan) can generate these RISC-V vector instructions to accelerate JavaScript code execution, especially for operations on arrays and numerical data. Provide a simplified JavaScript example that might benefit from vectorization.

6. **Illustrate with Examples:** For each major category of instructions, provide a simple example with hypothetical input and output values to demonstrate the instruction's behavior.

7. **Highlight Potential Programming Errors:**  Think about common mistakes developers might make when working with vector instructions or similar low-level operations (e.g., incorrect memory alignment, data type mismatches, assuming vector length).

8. **Check for `.tq` Extension:** The code provided is `.cc`, so it's C++, not Torque. State this clearly.

9. **Synthesize the Summary:**  Combine the observations into a concise summary that covers the main functionalities of the code. Emphasize that it's testing the RISC-V vector instruction support in V8's assembler.

10. **Structure the Response:** Organize the information logically using headings and bullet points for clarity. Follow the user's prompt to include specific sections like "JavaScript Example," "Code Logic Inference," and "Common Programming Errors."

11. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Make any necessary corrections or improvements. Specifically ensure all instructions from the prompt are addressed.
这是第 3 部分，它延续了对 V8 在 RISC-V 32 位架构上的汇编器进行测试的功能。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：测试 RISC-V 向量扩展 (RVV) 指令的汇编器实现**

这部分代码主要集中在测试 RISC-V 向量扩展（RVV）中关于以下几个方面的指令：

1. **向量加载和存储指令 (`vl`, `vs`)：**
   - 测试了从内存加载向量到向量寄存器，以及将向量寄存器存储到内存的功能。
   - 使用了不同的数据宽度 (`SEW`)，例如 `E8` 表示 8 位元素。

2. **向量浮点移动指令 (`vfmv_vf`)：**
   - 测试了将浮点标量值移动到向量寄存器的所有元素的功能。
   - 特别测试了处理 signaling NaN (sNaN) 的情况。

3. **向量浮点取反指令 (`vfneg_vv`)：**
   - 测试了对向量寄存器中的浮点数值进行取反的功能。
   - 同样测试了处理 signaling NaN 的情况，确保符号位被正确翻转。

4. **向量和标量浮点寄存器之间的移动指令 (`vfmv_fs`, `vfmv_sf`)：**
   - 测试了向量寄存器的第一个元素移动到浮点标量寄存器，以及浮点标量寄存器的值移动到向量寄存器的功能。
   - 使用了不同的数据宽度 (`E32` 和 `E64`)，对应单精度浮点数和双精度浮点数。
   - 重点测试了当标量值为 signaling NaN 时的情况。

5. **向量整数算术指令（向量-向量，向量-标量，向量-立即数）：**
   - 测试了向量寄存器之间以及向量寄存器和标量寄存器、立即数之间的整数算术运算，包括：
     - 加法 (`vadd_vv`, `vadd_vx`, `vadd_vi`)
     - 减法 (`vsub_vv`, `vsub_vx`)
     - 按位与 (`vand_vv`, `vand_vx`, `vand_vi`)
     - 按位或 (`vor_vv`, `vor_vx`, `vor_vi`)
     - 按位异或 (`vxor_vv`, `vxor_vx`, `vxor_vi`)
     - 最大值 (`vmax_vv`, `vmax_vx`, `vmaxu_vv`, `vmaxu_vx`)
     - 最小值 (`vmin_vv`, `vmin_vx`, `vminu_vv`, `vminu_vx`)
   - 涵盖了不同的数据宽度（8位，16位，32位）。

6. **向量浮点算术指令（向量-向量，向量-标量）：**
   - 测试了向量寄存器之间以及向量寄存器和浮点标量寄存器之间的浮点算术运算，包括：
     - 加法 (`vfadd_vv`, `vfadd_vf`)
     - 减法 (`vfsub_vv`)
     - 乘法 (`vfmul_vv`)
     - 除法 (`vfdiv_vv`)
   - 区分了单精度浮点数和双精度浮点数的情况。

7. **向量扩展浮点算术指令（向量-向量，向量-标量）：**
   - 测试了将较窄的浮点向量扩展为较宽的浮点向量并进行算术运算的功能，包括：
     - 加法 (`vfwadd_vv`, `vfwadd_vf`, `vfwadd_wv`, `vfwadd_wf`)
     - 减法 (`vfwsub_vv`, `vfwsub_vf`, `vfwsub_wv`, `vfwsub_wf`)
     - 乘法 (`vfwmul_vv`, `vfwmul_vf`)

8. **向量扩展浮点融合乘加指令（向量-向量）：**
   - 测试了将两个浮点向量相乘，然后与第三个浮点向量相加（或相减）的融合操作，包括：
     - 乘法-加法 (`vfmadd_vv`)
     - 乘法-减法 (`vfmsub_vv`)
     - 负乘法-加法 (`vfnmadd_vv`)
     - 负乘法-减法 (`vfnmsub_vv`)

**关于代码的特性：**

- **`UTEST_LOAD_STORE_RVV` 宏:**  这是一个自定义宏，用于简化生成加载和存储指令的测试用例。它接受加载和存储指令的名称，元素大小，以及用于生成测试数据的辅助函数作为参数。
- **`GenAndRunTest` 函数:** 这是一个模板函数，用于生成汇编代码并执行测试。它接收输入和输出数据，以及一个生成汇编代码的 lambda 函数作为参数。
- **`compiler::ValueHelper::GetVector<T>()`:**  这是一个辅助函数，用于生成不同类型的测试数据向量。
- **`__ VU.set(t0, ...)`:**  用于设置向量单元的配置，例如向量元素宽度 (`SEW`) 和向量长度乘数 (`Vlmul`).
- **`__ vl(v2, a0, 0, SEW)` 和 `__ vs(v2, a1, 0, SEW)`:**  汇编指令，用于执行向量加载和存储操作。
- **`CHECK(...)` 和 `CHECK_EQ(...)`:**  断言宏，用于验证测试结果是否符合预期。
- **处理 signaling NaN:** 代码中包含专门针对处理 signaling NaN 的测试用例，确保 RVV 指令能够正确处理这些特殊值。

**如果 `v8/test/cctest/test-assembler-riscv32.cc` 以 `.tq` 结尾**

如果文件名以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 用来定义运行时内置函数和一些底层操作的领域特定语言。

**与 JavaScript 的关系**

尽管这些测试是针对底层汇编器的，但它们与 JavaScript 的性能息息相关。V8 的优化编译器（TurboFan）可以将 JavaScript 代码编译成高效的机器码，其中就包括 RISC-V 向量指令（如果目标架构支持）。当 JavaScript 代码执行涉及大量并行数据处理（例如数组操作、数值计算）时，使用向量指令可以显著提高性能。

**JavaScript 示例**

```javascript
function vectorAdd(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const arr1 = [1, 2, 3, 4, 5, 6, 7, 8];
const arr2 = [8, 7, 6, 5, 4, 3, 2, 1];
const sum = vectorAdd(arr1, arr2);
console.log(sum); // 输出: [9, 9, 9, 9, 9, 9, 9, 9]
```

在支持 RVV 的 RISC-V 架构上，V8 的 TurboFan 可能会将 `vectorAdd` 函数中的循环编译成一系列的向量加法指令（如 `vadd_vv`），一次处理多个数组元素，从而加速计算。

**代码逻辑推理**

以 `TEST(RVV_VFMV)` 为例：

**假设输入：**

- `src` (float): 假设值为 `3.14`
- `dst` (float 数组): 初始化为 `{0, 0, 0, 0, 0, 0, 0, 0}`

**汇编代码逻辑：**

1. `__ VU.set(t0, VSew::E32, Vlmul::m2);`: 设置向量配置，元素宽度为 32 位（单精度浮点数），向量长度乘数为 2。
2. `__ flw(fa1, a0, 0);`: 从地址 `a0`（指向 `src`）加载浮点数到浮点寄存器 `fa1`。
3. `__ vfmv_vf(v2, fa1);`: 将 `fa1` 中的浮点数值复制到向量寄存器 `v2` 的所有元素中。根据 `Vlmul::m2`，`v2` 将包含 8 个元素。
4. `__ vs(v2, a1, 0, VSew::E32);`: 将向量寄存器 `v2` 的内容存储到地址 `a1`（指向 `dst`）。

**预期输出：**

- `dst` (float 数组):  `{3.14, 3.14, 3.14, 3.14, 3.14, 3.14, 3.14, 3.14}`

**涉及用户常见的编程错误**

1. **内存对齐错误：**  向量指令通常对内存对齐有要求。如果加载或存储的地址未正确对齐，可能会导致程序崩溃或性能下降。

   ```c++
   // 错误示例：dst 可能未对齐
   int8_t dst[15];
   auto fn = [](MacroAssembler& assm) {
     __ vl(v2, a1, 0, SEW);
   };
   GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);
   ```

2. **数据类型不匹配：**  向量指令操作特定大小的数据元素。如果传递的数据类型与指令期望的不符，可能会导致错误的结果或程序崩溃。

   ```c++
   // 错误示例：尝试将 int32_t 数组加载到 int8_t 向量
   int32_t src[16];
   int8_t dst[16];
   auto fn = [](MacroAssembler& assm) {
     __ VU.set(t0, SEW, Vlmul::m1);
     __ vl(v2, a0, 0, SEW); // 假设 SEW 被设置为 E8
     __ vs(v2, a1, 0, SEW);
   };
   GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);
   ```

3. **向量长度假设错误：** 程序员可能会错误地假设向量寄存器的长度，导致访问越界或计算错误。向量长度由 V 集成电路的配置决定。

   ```c++
   // 错误示例：假设向量长度固定为 8，但实际可能更长或更短
   float src[8] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
   float dst[8];
   auto fn = [](MacroAssembler& assm) {
     __ VU.set(t0, VSew::E32, Vlmul::m1); // 实际向量长度可能影响操作的元素数量
     __ vfmv_vf(v0, fa0);
     // ...
   };
   GenAndRunTest<int32_t, int32_t>((int32_t)src, (int32_t)dst, fn);
   ```

**归纳一下它的功能**

总而言之，这段 `v8/test/cctest/test-assembler-riscv32.cc` 代码片段是 V8 JavaScript 引擎测试套件的一部分，专门用于验证 RISC-V 32 位架构上汇编器生成 RVV（向量扩展）指令的正确性。它覆盖了向量加载/存储、浮点移动、浮点算术、整数算术以及扩展浮点算术和融合乘加等多种类型的 RVV 指令，并通过一系列单元测试确保这些指令在 V8 中的实现符合预期。这对于保证 V8 在 RISC-V 平台上高效且正确地执行 JavaScript 代码至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

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
          GenAndRunTest<i
"""


```