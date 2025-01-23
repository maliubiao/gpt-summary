Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's test suite. The code focuses on testing the `MacroAssembler` class for the MIPS64 architecture.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `test-macro-assembler-mips64.cc` strongly suggests that the code is testing the `MacroAssembler` for the MIPS64 architecture. The presence of `TEST(...)` macros confirms it's a testing file.

2. **Examine the `TEST(...)` blocks:** Each `TEST(...)` block represents a specific test case. Analyze what each test case is doing:
    * **`MinMax`**:  This test case appears to be testing the `Float64Min`, `Float64Max`, `Float32Min`, and `Float32Max` macro-assembler instructions. It sets up inputs, calls a generated code function, and then checks the results. It also handles NaN (Not a Number) cases.
    * **`Unaligned`**: This test uses a template function `run_Unaligned` and focuses on testing unaligned memory access instructions like `Ulh`, `Ush`, `Ulw`, `Usw`, `Uld`, `Usd`, `Ulwc1`, `Uswc1`, `Uldc1`, and `Usdc1`. It iterates through various offsets to simulate unaligned access.
    * **`Ulh`**: Tests the `Ulh` (Unaligned Load Halfword) and `Ush` (Unaligned Store Halfword) instructions in different combinations.
    * **`Ulh_bitextension`**:  Similar to `Ulh`, but explicitly checks the sign-extension behavior of `Ulh` and `Ulhu` (Unaligned Load Halfword Unsigned).
    * **`Ulw`**: Tests `Ulw` (Unaligned Load Word) and `Usw` (Unaligned Store Word).
    * **`Ulw_extension`**: Similar to `Ulw`, but checks the sign-extension of `Ulw` and `Ulwu` (Unaligned Load Word Unsigned).
    * **`Uld`**: Tests `Uld` (Unaligned Load Doubleword) and `Usd` (Unaligned Store Doubleword).
    * **`Ulwc1`**: Tests `Ulwc1` (Unaligned Load Word to FPU) and `Uswc1` (Unaligned Store Word from FPU).
    * **`Uldc1`**: Tests `Uldc1` (Unaligned Load Doubleword to FPU) and `Usdc1` (Unaligned Store Doubleword from FPU).
    * **`Sltu`**: Tests the `Sltu` (Set Less Than Unsigned) instruction.
    * **`macro_float_minmax_f32`**: Tests the `Float32Min` and `Float32Max` *macros* more thoroughly, including out-of-line cases and various input combinations including NaNs. It checks the results for different register aliasing scenarios.
    * **`macro_float_minmax_f64`**: Similar to `macro_float_minmax_f32`, but for `Float64Min` and `Float64Max`.
    * **`DeoptExitSizeIsFixed`**:  This test checks that the size of the code generated for deoptimization exits is constant, depending on whether it's a lazy or eager deoptimization.

3. **Identify Key Concepts:**  The code heavily uses:
    * **`MacroAssembler`**: The core class being tested, responsible for generating machine code.
    * **MIPS64 Instructions**:  Specific instructions for the MIPS64 architecture, like load/store, floating-point min/max, and set less than unsigned.
    * **Unaligned Memory Access**: Loading and storing data at memory addresses that are not multiples of the data size.
    * **Floating-Point Operations**:  Testing the behavior of min and max operations for both single-precision (float) and double-precision (double) floating-point numbers, including handling of NaNs.
    * **Deoptimization**:  A mechanism in V8 to revert to less optimized code.
    * **Test Framework**: The `TEST(...)` macros indicate the use of a testing framework.
    * **Generated Code**: The tests generate machine code dynamically and execute it.

4. **Check for Torque:** The prompt specifically asks about `.tq` files. The filename ends in `.cc`, so this is C++ code, not Torque.

5. **Check for JavaScript Relevance:** While this is low-level assembly testing, it *directly* relates to the implementation of JavaScript features. For example, `Float64Min` and `Float64Max` directly implement `Math.min()` and `Math.max()` in JavaScript for numbers. Unaligned memory access can be relevant in how V8 handles certain data structures internally.

6. **Provide JavaScript Examples:**  Illustrate the connection to JavaScript using `Math.min()`, `Math.max()`, and the concept of typed arrays potentially interacting with unaligned memory (though this is less direct for typical user-level JavaScript).

7. **Look for Code Logic and Assumptions:** The tests often involve setting up specific input values and comparing the output against expected results. The unaligned tests assume that the `run_Unaligned` helper function correctly sets up the memory and calls the generated code. The min/max tests rely on the correct implementation of the comparison and selection logic, especially for edge cases like NaNs and zero.

8. **Identify Potential Programming Errors:** Unaligned memory access is a classic source of errors in C/C++. The tests themselves are designed to verify the *correctness* of the assembler in handling unaligned access, but the concept is error-prone in general programming.

9. **Synthesize the Summary:** Combine the identified information into a concise summary, addressing all points raised in the prompt. Organize the summary logically, starting with the main purpose and then detailing the specifics of the test cases. Ensure to include the JavaScript connection, code logic/assumptions, and potential errors.

10. **Review and Refine:** Read through the generated summary to ensure accuracy, clarity, and completeness. Make any necessary adjustments to improve the overall quality of the response. For instance, initially, I might have focused too much on the assembly instructions themselves. Refinement would involve highlighting the *purpose* of testing these instructions in the context of the V8 engine and JavaScript. Also, ensuring that all parts of the prompt are addressed (like the `.tq` check and the part number) is crucial.
这是目录为v8/test/cctest/test-macro-assembler-mips64.cc的v8源代码的第2部分，是对第1部分的补充，主要功能是**测试V8 JavaScript引擎在MIPS64架构上的`MacroAssembler`类，特别是针对未对齐内存访问指令和浮点数最小值/最大值操作指令的正确性**。

**功能归纳：**

这部分代码延续了第一部分的功能，继续测试 `MacroAssembler` 类在 MIPS64 架构下生成特定指令的能力，并验证这些指令在各种输入情况下的行为是否符合预期。主要测试点包括：

* **未对齐内存访问指令 (Unaligned Memory Access):**  测试 `Ulh` (Unaligned Load Halfword), `Ush` (Unaligned Store Halfword), `Ulw` (Unaligned Load Word), `Usw` (Unaligned Store Word), `Uld` (Unaligned Load Doubleword), `Usd` (Unaligned Store Doubleword), `Ulwc1` (Unaligned Load Word to FPU), `Uswc1` (Unaligned Store Word from FPU), `Uldc1` (Unaligned Load Doubleword to FPU), `Usdc1` (Unaligned Store Doubleword from FPU) 等指令。这些测试会模拟在非自然对齐的内存地址上进行数据加载和存储操作，以确保 `MacroAssembler` 生成的指令能够正确处理这种情况。
* **带符号/无符号扩展的未对齐加载指令:**  特别测试了 `Ulh` 和 `Ulhu`，以及 `Ulw` 和 `Ulwu` 在处理符号扩展上的差异。
* **设置小于无符号指令 (Set Less Than Unsigned):** 测试 `Sltu` 指令，该指令比较两个无符号数，如果第一个小于第二个，则设置目标寄存器的值为 1，否则为 0。
* **浮点数最小值/最大值宏 (Float Min/Max Macros):** 测试 `Float32Min`, `Float32Max`, `Float64Min`, `Float64Max` 这些宏，它们用于生成浮点数最小值和最大值的指令序列。测试覆盖了各种输入情况，包括正负数、零、负零以及 NaN (Not a Number)。为了确保所有代码路径都被测试到，还考虑了寄存器别名的情况。
* **固定大小的Deopt退出代码:**  测试 `DeoptExitSizeIsFixed` 验证了不同类型的反优化出口代码具有预定义的大小。

**关于文件类型和 JavaScript 关系：**

* `v8/test/cctest/test-macro-assembler-mips64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码 (`.tq`)。
* **与 JavaScript 的功能有关系：**  这些测试直接关联到 V8 JavaScript 引擎的底层实现。例如：
    * `Float64Min` 和 `Float64Max` 宏的测试直接对应于 JavaScript 中 `Math.min()` 和 `Math.max()` 函数对数字类型的处理。
    * 未对齐内存访问的测试与 V8 内部如何处理某些数据结构有关。虽然 JavaScript 开发者通常不会直接处理未对齐内存，但 V8 引擎在内部实现中可能会遇到这种情况。

**JavaScript 举例说明：**

```javascript
// JavaScript 中使用 Math.min 和 Math.max
console.log(Math.min(1.5, 2.3)); // 输出 1.5
console.log(Math.max(-0.7, 0.5)); // 输出 0.5

// 这两个 JavaScript 函数的底层实现，在 MIPS64 架构上，
// 就可能涉及到 test-macro-assembler-mips64.cc 中测试的
// Float64Min 和 Float64Max 相关的汇编指令。
```

**代码逻辑推理与假设输入/输出：**

以 `TEST(MinMax)` 为例：

**假设输入：**

* `inputsa`: 包含一些 double 类型数值的数组，例如 `[1.0, -2.0, NaN, ...]`.
* `inputsb`: 包含一些 double 类型数值的数组，例如 `[3.0, 0.5, 5.0, ...]`.
* `inputse`: 包含一些 float 类型数值的数组，例如 `[0.5, -1.0, NaN, ...]`.
* `inputsf`: 包含一些 float 类型数值的数组，例如 `[2.0, 1.5, -0.5, ...]`.

**代码逻辑：**

1. 将 `inputsa` 和 `inputsb` 中的元素加载到浮点寄存器 `f4` 和 `f8`。
2. 使用 `Float64Min` 指令比较 `f4` 和 `f8`，并将最小值存储到 `f10`。如果遇到 NaN，跳转到 `handle_mind_nan` 标签处理。
3. 使用 `Float64Max` 指令比较 `f4` 和 `f8`，并将最大值存储到 `f12`。如果遇到 NaN，跳转到 `handle_maxd_nan` 标签处理。
4. 对 `inputse` 和 `inputsf` 中的 float 类型数据执行类似的操作，使用 `Float32Min` 和 `Float32Max` 指令，并将结果分别存储到 `f14` 和 `f16`。
5. 将 `f10`, `f12`, `f14`, `f16` 的值存储回 `test` 对象的相应字段 (`c`, `d`, `g`, `h`)。
6. 在 `handle_dnan` 和 `handle_snan` 标签中处理 NaN 的情况。

**预期输出：**

* `outputsdmin`: 包含 `inputsa` 和 `inputsb` 中对应元素的最小值的数组。对于 NaN 的情况，根据 IEEE 754 标准，通常 NaN 会作为结果。
* `outputsdmax`: 包含 `inputsa` 和 `inputsb` 中对应元素的最大值的数组。
* `outputsfmin`: 包含 `inputse` 和 `inputsf` 中对应元素的最小值的数组。
* `outputsfmax`: 包含 `inputse` 和 `inputsf` 中对应元素的最大值的数组。

**涉及用户常见的编程错误：**

* **未对齐内存访问错误：** 在 C/C++ 中，尝试在未对齐的地址上直接访问数据会导致程序崩溃或产生不可预测的结果。这些测试确保了 `MacroAssembler` 生成的指令能够安全地处理这种情况，但在用户代码中仍然需要避免。
  ```c++
  // 错误示例 (可能导致崩溃)
  char buffer[7];
  int* unaligned_ptr = reinterpret_cast<int*>(buffer + 1);
  *unaligned_ptr = 10;
  ```
* **浮点数比较的陷阱：**  直接使用 `==` 比较浮点数可能由于精度问题导致错误。此外，对 NaN 的处理也需要特别注意。
  ```javascript
  // JavaScript 浮点数比较的陷阱
  console.log(0.1 + 0.2 == 0.3); // 输出 false，因为浮点数精度问题

  // NaN 的特殊性
  console.log(NaN == NaN); // 输出 false
  console.log(Math.min(1, NaN)); // 输出 NaN
  ```

**总结：**

这部分 `test-macro-assembler-mips64.cc` 代码是 V8 引擎测试框架的关键组成部分，它专注于验证 MIPS64 架构下 `MacroAssembler` 类生成机器码的正确性，特别是在处理未对齐内存访问和浮点数最小值/最大值运算等复杂操作时。这些测试确保了 V8 引擎在 MIPS64 架构上能够可靠地执行 JavaScript 代码。

### 提示词
```
这是目录为v8/test/cctest/test-macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
__ Move(dst, fnan);
    __ Branch(back);
  };

  Label handle_mind_nan, handle_maxd_nan, handle_mins_nan, handle_maxs_nan;
  Label back_mind_nan, back_maxd_nan, back_mins_nan, back_maxs_nan;

  __ push(s6);
  __ InitializeRootRegister();
  __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
  __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
  __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, e)));
  __ Lwc1(f6, MemOperand(a0, offsetof(TestFloat, f)));
  __ Float64Min(f10, f4, f8, &handle_mind_nan);
  __ bind(&back_mind_nan);
  __ Float64Max(f12, f4, f8, &handle_maxd_nan);
  __ bind(&back_maxd_nan);
  __ Float32Min(f14, f2, f6, &handle_mins_nan);
  __ bind(&back_mins_nan);
  __ Float32Max(f16, f2, f6, &handle_maxs_nan);
  __ bind(&back_maxs_nan);
  __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, d)));
  __ Swc1(f14, MemOperand(a0, offsetof(TestFloat, g)));
  __ Swc1(f16, MemOperand(a0, offsetof(TestFloat, h)));
  __ pop(s6);
  __ jr(ra);
  __ nop();

  handle_dnan(f10, &handle_mind_nan, &back_mind_nan);
  handle_dnan(f12, &handle_maxd_nan, &back_maxd_nan);
  handle_snan(f14, &handle_mins_nan, &back_mins_nan);
  handle_snan(f16, &handle_maxs_nan, &back_maxs_nan);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.e = inputse[i];
    test.f = inputsf[i];

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(0, memcmp(&test.c, &outputsdmin[i], sizeof(test.c)));
    CHECK_EQ(0, memcmp(&test.d, &outputsdmax[i], sizeof(test.d)));
    CHECK_EQ(0, memcmp(&test.g, &outputsfmin[i], sizeof(test.g)));
    CHECK_EQ(0, memcmp(&test.h, &outputsfmax[i], sizeof(test.h)));
  }
}

template <typename IN_TYPE, typename Func>
bool run_Unaligned(char* memory_buffer, int32_t in_offset, int32_t out_offset,
                   IN_TYPE value, Func GenerateUnalignedInstructionFunc) {
  using F_CVT = int32_t(char* x0, int x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;
  IN_TYPE res;

  GenerateUnalignedInstructionFunc(masm, in_offset, out_offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);

  MemCopy(memory_buffer + in_offset, &value, sizeof(IN_TYPE));
  f.Call(memory_buffer, 0, 0, 0, 0);
  MemCopy(&res, memory_buffer + out_offset, sizeof(IN_TYPE));

  return res == value;
}

static const std::vector<uint64_t> unsigned_test_values() {
  static const uint64_t kValues[] = {
      0x2180F18A06384414, 0x000A714532102277, 0xBC1ACCCF180649F0,
      0x8000000080008000, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
  };
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset() {
  static const int32_t kValues[] = {// value, offset
                                    -132 * KB, -21 * KB, 0, 19 * KB, 135 * KB};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset_increment() {
  static const int32_t kValues[] = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(Ulh) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ulh(v0, MemOperand(a0, in_offset));
          __ Ush(v0, MemOperand(a0, out_offset), v0);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ulh(a0, MemOperand(a0, in_offset));
          __ Ush(a0, MemOperand(t0, out_offset), v0);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ulhu(a0, MemOperand(a0, in_offset));
          __ Ush(a0, MemOperand(t0, out_offset), t1);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ulhu(v0, MemOperand(a0, in_offset));
          __ Ush(v0, MemOperand(a0, out_offset), t1);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_4));
      }
    }
  }
}

TEST(Ulh_bitextension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ulh(t0, MemOperand(a0, in_offset));
          __ Ulhu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ sra(t0, t0, 15);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ sra(t1, t1, 15);
          __ Branch(&fail, ne, t1, Operand(1));
          __ sra(t0, t0, 15);
          __ addiu(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ulh(t0, MemOperand(a0, in_offset));
          __ Ush(t0, MemOperand(a0, out_offset), v0);
          __ Branch(&end);
          __ bind(&fail);
          __ Ush(zero_reg, MemOperand(a0, out_offset), v0);
          __ bind(&end);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn));
      }
    }
  }
}

TEST(Ulw) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint32_t value = static_cast<uint32_t>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ulw(v0, MemOperand(a0, in_offset));
          __ Usw(v0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ulw(a0, MemOperand(a0, in_offset));
          __ Usw(a0, MemOperand(t0, out_offset));
        };
        CHECK_EQ(true,
                 run_Unaligned<uint32_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ulwu(v0, MemOperand(a0, in_offset));
          __ Usw(v0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ulwu(a0, MemOperand(a0, in_offset));
          __ Usw(a0, MemOperand(t0, out_offset));
        };
        CHECK_EQ(true,
                 run_Unaligned<uint32_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_4));
      }
    }
  }
}

TEST(Ulw_extension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint32_t value = static_cast<uint32_t>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ulw(t0, MemOperand(a0, in_offset));
          __ Ulwu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ dsra(t0, t0, 31);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ dsra(t1, t1, 31);
          __ Branch(&fail, ne, t1, Operand(1));
          __ dsra(t0, t0, 31);
          __ daddiu(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ulw(t0, MemOperand(a0, in_offset));
          __ Usw(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ Usw(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn));
      }
    }
  }
}

TEST(Uld) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint64_t value = *i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Uld(v0, MemOperand(a0, in_offset));
          __ Usd(v0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<uint64_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Uld(a0, MemOperand(a0, in_offset));
          __ Usd(a0, MemOperand(t0, out_offset));
        };
        CHECK_EQ(true,
                 run_Unaligned<uint64_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_2));
      }
    }
  }
}

TEST(Ulwc1) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        float value = static_cast<float>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          __ Ulwc1(f0, MemOperand(a0, in_offset), t0);
          __ Uswc1(f0, MemOperand(a0, out_offset), t0);
        };
        CHECK_EQ(true, run_Unaligned<float>(buffer_middle, in_offset,
                                            out_offset, value, fn));
      }
    }
  }
}

TEST(Uldc1) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        double value = static_cast<double>(*i);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          __ Uldc1(f0, MemOperand(a0, in_offset), t0);
          __ Usdc1(f0, MemOperand(a0, out_offset), t0);
        };
        CHECK_EQ(true, run_Unaligned<double>(buffer_middle, in_offset,
                                             out_offset, value, fn));
      }
    }
  }
}

static const std::vector<uint64_t> sltu_test_values() {
  static const uint64_t kValues[] = {
      0,
      1,
      0x7FFE,
      0x7FFF,
      0x8000,
      0x8001,
      0xFFFE,
      0xFFFF,
      0xFFFFFFFFFFFF7FFE,
      0xFFFFFFFFFFFF7FFF,
      0xFFFFFFFFFFFF8000,
      0xFFFFFFFFFFFF8001,
      0xFFFFFFFFFFFFFFFE,
      0xFFFFFFFFFFFFFFFF,
  };
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

template <typename Func>
bool run_Sltu(uint64_t rs, uint64_t rd, Func GenerateSltuInstructionFunc) {
  using F_CVT = int64_t(uint64_t x0, uint64_t x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;

  GenerateSltuInstructionFunc(masm, rd);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(rs, rd, 0, 0, 0));
  return res == 1;
}

TEST(Sltu) {
  CcTest::InitializeVM();

  FOR_UINT64_INPUTS(i, sltu_test_values) {
    FOR_UINT64_INPUTS(j, sltu_test_values) {
      uint64_t rs = *i;
      uint64_t rd = *j;

      auto fn_1 = [](MacroAssembler* masm, uint64_t imm) {
        __ Sltu(v0, a0, Operand(imm));
      };
      CHECK_EQ(rs < rd, run_Sltu(rs, rd, fn_1));

      auto fn_2 = [](MacroAssembler* masm, uint64_t imm) {
        __ Sltu(v0, a0, a1);
      };
      CHECK_EQ(rs < rd, run_Sltu(rs, rd, fn_2));
    }
  }
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F4> GenerateMacroFloat32MinMax(MacroAssembler* masm) {
  T a = T::from_code(4);  // f4
  T b = T::from_code(6);  // f6
  T c = T::from_code(8);  // f8

  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

#define FLOAT_MIN_MAX(fminmax, res, x, y, done, ool, res_field) \
  __ Lwc1(x, MemOperand(a0, offsetof(Inputs, src1_)));          \
  __ Lwc1(y, MemOperand(a0, offsetof(Inputs, src2_)));          \
  __ fminmax(res, x, y, &ool);                                  \
  __ bind(&done);                                               \
  __ Swc1(a, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float32Min, a, b, c, done_min_abc, ool_min_abc, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float32Min, a, a, b, done_min_aab, ool_min_aab, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float32Min, a, b, a, done_min_aba, ool_min_aba, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float32Max, a, b, c, done_max_abc, ool_max_abc, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float32Max, a, a, b, done_max_aab, ool_max_aab, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float32Max, a, b, a, done_max_aba, ool_max_aba, max_aba_);

#undef FLOAT_MIN_MAX

  __ jr(ra);
  __ nop();

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ Float32MinOutOfLine(a, b, c);
  __ Branch(&done_min_abc);

  __ bind(&ool_min_aab);
  __ Float32MinOutOfLine(a, a, b);
  __ Branch(&done_min_aab);

  __ bind(&ool_min_aba);
  __ Float32MinOutOfLine(a, b, a);
  __ Branch(&done_min_aba);

  __ bind(&ool_max_abc);
  __ Float32MaxOutOfLine(a, b, c);
  __ Branch(&done_max_abc);

  __ bind(&ool_max_aab);
  __ Float32MaxOutOfLine(a, a, b);
  __ Branch(&done_max_aab);

  __ bind(&ool_max_aba);
  __ Float32MaxOutOfLine(a, b, a);
  __ Branch(&done_max_aba);

  CodeDesc desc;
  masm->GetCode(masm->isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(masm->isolate(), desc, CodeKind::FOR_TESTING)
          .Build();
#ifdef DEBUG
  Print(*code);
#endif
  return GeneratedCode<F4>::FromCode(masm->isolate(), *code);
}

TEST(macro_float_minmax_f32) {
  // Test the Float32Min and Float32Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Inputs {
    float src1_;
    float src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  GeneratedCode<F4> f =
      GenerateMacroFloat32MinMax<FPURegister, Inputs, Results>(masm);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  float nan_a = std::numeric_limits<float>::quiet_NaN();
  float nan_b = std::numeric_limits<float>::quiet_NaN();

  CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(0.0f, -1.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
  CHECK_MINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
  CHECK_MINMAX(0.0f, 1.0f, 0.0f, 1.0f);
  CHECK_MINMAX(1.0f, 0.0f, 0.0f, 1.0f);

  CHECK_MINMAX(0.0f, 0.0f, 0.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
  CHECK_MINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
  CHECK_MINMAX(0.0f, -0.0f, -0.0f, 0.0f);

  CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0f, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F4> GenerateMacroFloat64MinMax(MacroAssembler* masm) {
  T a = T::from_code(4);  // f4
  T b = T::from_code(6);  // f6
  T c = T::from_code(8);  // f8

  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

#define FLOAT_MIN_MAX(fminmax, res, x, y, done, ool, res_field) \
  __ Ldc1(x, MemOperand(a0, offsetof(Inputs, src1_)));          \
  __ Ldc1(y, MemOperand(a0, offsetof(Inputs, src2_)));          \
  __ fminmax(res, x, y, &ool);                                  \
  __ bind(&done);                                               \
  __ Sdc1(a, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float64Min, a, b, c, done_min_abc, ool_min_abc, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float64Min, a, a, b, done_min_aab, ool_min_aab, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float64Min, a, b, a, done_min_aba, ool_min_aba, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float64Max, a, b, c, done_max_abc, ool_max_abc, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float64Max, a, a, b, done_max_aab, ool_max_aab, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float64Max, a, b, a, done_max_aba, ool_max_aba, max_aba_);

#undef FLOAT_MIN_MAX

  __ jr(ra);
  __ nop();

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ Float64MinOutOfLine(a, b, c);
  __ Branch(&done_min_abc);

  __ bind(&ool_min_aab);
  __ Float64MinOutOfLine(a, a, b);
  __ Branch(&done_min_aab);

  __ bind(&ool_min_aba);
  __ Float64MinOutOfLine(a, b, a);
  __ Branch(&done_min_aba);

  __ bind(&ool_max_abc);
  __ Float64MaxOutOfLine(a, b, c);
  __ Branch(&done_max_abc);

  __ bind(&ool_max_aab);
  __ Float64MaxOutOfLine(a, a, b);
  __ Branch(&done_max_aab);

  __ bind(&ool_max_aba);
  __ Float64MaxOutOfLine(a, b, a);
  __ Branch(&done_max_aba);

  CodeDesc desc;
  masm->GetCode(masm->isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(masm->isolate(), desc, CodeKind::FOR_TESTING)
          .Build();
#ifdef DEBUG
  Print(*code);
#endif
  return GeneratedCode<F4>::FromCode(masm->isolate(), *code);
}

TEST(macro_float_minmax_f64) {
  // Test the Float64Min and Float64Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Inputs {
    double src1_;
    double src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  GeneratedCode<F4> f =
      GenerateMacroFloat64MinMax<DoubleRegister, Inputs, Results>(masm);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  double nan_a = std::numeric_limits<double>::quiet_NaN();
  double nan_b = std::numeric_limits<double>::quiet_NaN();

  CHECK_MINMAX(1.0, -1.0, -1.0, 1.0);
  CHECK_MINMAX(-1.0, 1.0, -1.0, 1.0);
  CHECK_MINMAX(0.0, -1.0, -1.0, 0.0);
  CHECK_MINMAX(-1.0, 0.0, -1.0, 0.0);
  CHECK_MINMAX(-0.0, -1.0, -1.0, -0.0);
  CHECK_MINMAX(-1.0, -0.0, -1.0, -0.0);
  CHECK_MINMAX(0.0, 1.0, 0.0, 1.0);
  CHECK_MINMAX(1.0, 0.0, 0.0, 1.0);

  CHECK_MINMAX(0.0, 0.0, 0.0, 0.0);
  CHECK_MINMAX(-0.0, -0.0, -0.0, -0.0);
  CHECK_MINMAX(-0.0, 0.0, -0.0, 0.0);
  CHECK_MINMAX(0.0, -0.0, -0.0, 0.0);

  CHECK_MINMAX(0.0, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

TEST(DeoptExitSizeIsFixed) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      buffer->CreateView());
  static_assert(static_cast<int>(kFirstDeoptimizeKind) == 0);
  for (int i = 0; i < kDeoptimizeKindCount; i++) {
    DeoptimizeKind kind = static_cast<DeoptimizeKind>(i);
    Label before_exit;
    masm.bind(&before_exit);
    Builtin target = Deoptimizer::GetDeoptimizationEntry(kind);
    masm.CallForDeoptimization(target, 42, &before_exit, kind, &before_exit,
                               nullptr);
    CHECK_EQ(masm.SizeOfCodeGeneratedSince(&before_exit),
             kind == DeoptimizeKind::kLazy ? Deoptimizer::kLazyDeoptExitSize
                                           : Deoptimizer::kEagerDeoptExitSize);
  }
}

#undef __

}  // namespace internal
}  // namespace v8
```