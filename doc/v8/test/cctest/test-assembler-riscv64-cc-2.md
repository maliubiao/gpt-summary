Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of V8's test suite for the RISC-V 64-bit assembler.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The code is in `v8/test/cctest/test-assembler-riscv64.cc`. This immediately suggests it's testing the RISC-V 64-bit assembler within V8. The presence of `TEST` macros confirms this.

2. **Analyze individual tests:** Go through each `TEST` block and understand what it's doing. Look for key functions and operations:
    * `TARGET_ADDRESS`:  Related to getting the target address from a sequence of instructions. This involves checking how addresses are encoded.
    * `SET_TARGET_ADDR`: Similar to the above but focuses on setting the target address within a buffer and then verifying it.
    * `OUT_OF_RANGE_CVT`:  Tests conversions between floating-point and integer types when the floating-point value is outside the representable range of the integer type (NaN, infinity, very large/small numbers). It examines different `fcvt_*` instructions.
    * `F_NAN`: Tests floating-point comparisons (`feq`, `flt`, `fle`) involving NaN and infinity. This verifies the correct handling of these special floating-point values.
    * `jump_tables1`, `jump_tables2`, `jump_tables3`: These tests focus on the implementation of jump tables in the assembler. They test forward and backward jumps and the interaction with embedded heap objects.
    * `li_estimate`:  This test checks the accuracy of the `RV_li_count` function, which estimates the number of instructions needed to load an immediate value.
    * `UTEST_LOAD_STORE_RVV`: This indicates tests for RISC-V Vector (RVV) load and store instructions. The macro suggests parameterization for different element widths (SEW).
    * `RVV_VFMV`: Tests the `vfmv` instruction, which moves floating-point values between scalar registers and vector registers. It specifically tests with regular values and signaling NaNs.
    * `RVV_VFNEG_signaling_NaN`: Tests the `vfneg` instruction (vector floating-point negation) with signaling NaNs.
    * `UTEST_RVV_VF_MV_FORM_WITH_RES`: Another macro for testing RVV floating-point move instructions between vector and scalar registers, both for normal values and signaling NaNs.
    * `UTEST_RVV_VI_VV_FORM_WITH_RES`, `UTEST_RVV_VI_VX_FORM_WITH_RES`, `UTEST_RVV_VI_VI_FORM_WITH_RES`: These macros, along with the defined `VV`, `VX`, and `VI` macros, test various RVV integer arithmetic instructions with vector-vector, vector-scalar, and vector-immediate operands. Specific instructions like `vadd`, `vsub`, `vand`, `vor`, `vxor`, `vmax`, `vmin`, `vmaxu`, `vminu` are tested for different element widths.
    * `UTEST_RVV_VF_VV_FORM_WITH_RES` (for floats): Tests RVV single-width floating-point arithmetic instructions between vector registers.

3. **Identify general themes:** Group the tests based on the type of functionality they are testing. This leads to categories like:
    * Address manipulation
    * Floating-point conversions
    * Floating-point comparisons (especially with special values)
    * Control flow (jump tables)
    * Instruction encoding estimation
    * RISC-V Vector (RVV) instruction testing (loads, stores, moves, arithmetic)

4. **Consider the file name context:**  The file name `test-assembler-riscv64.cc` reinforces that the focus is on testing the assembler for the RISC-V 64-bit architecture.

5. **Address specific instructions from the prompt:**
    * **`.tq` extension:**  Confirm that this file is `.cc` and not `.tq`, so it's C++ and not Torque.
    * **JavaScript relation:**  Think about how assembler relates to JavaScript. The assembler is used to generate the low-level machine code that executes JavaScript. Provide a simple example of a JavaScript operation that would eventually be translated into assembly instructions.
    * **Code logic and examples:** For each test category, provide a simplified explanation or example of what the code is checking. For the `TARGET_ADDRESS` tests, explain how the instruction sequence encodes an address. For out-of-range conversions, show how NaN or infinity is mapped to the limits of the integer type.
    * **Common programming errors:** Relate the tests to potential errors a programmer might make. For example, failing to handle NaN or infinity correctly in numerical computations or miscalculating jump offsets.

6. **Synthesize the summary:** Combine the analyzed information into a concise summary of the file's purpose and the types of tests it contains.

7. **Review and refine:** Ensure the response is clear, accurate, and addresses all parts of the user's request. Check for any ambiguities or missing information. For instance, emphasize the focus on *unit testing* the assembler's functionality. Also, confirm it's the *third* part as requested.
好的，这是对提供的代码片段的功能归纳：

**功能归纳**

这段代码是 `v8/test/cctest/test-assembler-riscv64.cc` 文件的第三部分，它主要用于测试 V8 JavaScript 引擎中 RISC-V 64 位架构的汇编器 (`MacroAssembler`) 的功能。 具体来说，它涵盖了以下几个方面的测试：

1. **目标地址操作 (`TARGET_ADDRESS`, `SET_TARGET_ADDR`):**
   - 测试汇编器是否能正确地获取和设置指令序列中的目标地址。这对于生成跳转指令或其他需要引用内存地址的代码至关重要。
   - 针对不同的内存模型 (`RISCV_USE_SV39` 宏)，测试了 39 位和 48 位地址的加载和设置。

2. **浮点数到整数的转换 (超出范围处理) (`OUT_OF_RANGE_CVT`):**
   - 测试当浮点数超出目标整数类型范围时（例如，NaN，正负无穷大，非常大/小的数值），汇编器生成的转换指令 (`fcvt_w_d`, `fcvt_w_s`, `fcvt_wu_d`, `fcvt_wu_s`, `fcvt_l_d`, `fcvt_l_s`, `fcvt_lu_d`, `fcvt_lu_s`) 的行为。
   - 验证这些转换指令是否会将超出范围的浮点数正确地转换为目标整数类型的最大值或最小值。

3. **浮点数比较 (特殊值处理) (`F_NAN`):**
   - 测试汇编器生成的浮点数比较指令 (`feq_s`, `flt_s`, `fle_s`, `feq_d`, `flt_d`, `fle_d`) 在处理特殊浮点数值（如 NaN 和正负无穷大）时的行为。
   - 验证比较结果是否符合 IEEE 754 标准中关于 NaN 的定义（与 NaN 的任何比较都为假）。

4. **跳转表 (`jump_tables1`, `jump_tables2`, `jump_tables3`):**
   - 测试汇编器生成跳转表代码的能力。跳转表是一种优化多路分支的技术。
   - 包含了前向跳转、后向跳转以及跳转表中嵌入堆对象的测试用例。
   - 验证了跳转表在不同场景下的正确性。

5. **`li` 指令估计 (`li_estimate`):**
   - 测试汇编器中用于估计加载立即数 (`li`) 指令所需指令数量的功能 (`RV_li_count`) 是否准确。这有助于进行代码大小优化。

6. **RISC-V 向量扩展 (RVV) 指令测试 (`UTEST_LOAD_STORE_RVV`, `RVV_VFMV`, `RVV_VFMV_signaling_NaN`, `RVV_VFNEG_signaling_NaN`, `UTEST_RVV_VF_MV_FORM_WITH_RES`, `UTEST_RVV_VI_VV_FORM_WITH_RES` 等):**
   - 这部分是该代码片段的主要组成部分，专注于测试 RISC-V 向量扩展指令的生成和执行。
   - 测试了向量的加载 (`vl`) 和存储 (`vs`) 指令。
   - 测试了浮点数的向量移动指令 (`vfmv_vf`, `vfmv_fs`, `vfmv_sf`)，包括对 signaling NaN 的处理。
   - 测试了向量浮点数取反指令 (`vfneg_vv`) 对 signaling NaN 的处理。
   - 测试了向量整数算术指令，如加法 (`vadd_vv`, `vadd_vx`, `vadd_vi`)、减法 (`vsub_vv`, `vsub_vx`)、按位与 (`vand_vv`, `vand_vx`, `vand_vi`)、按位或 (`vor_vv`, `vor_vx`, `vor_vi`)、按位异或 (`vxor_vv`, `vxor_vx`, `vxor_vi`)、最大值 (`vmax_vv`, `vmax_vx`, `vmaxu_vv`, `vmaxu_vx`)、最小值 (`vmin_vv`, `vmin_vx`, `vminu_vv`, `vminu_vx`) 等，涵盖了向量-向量、向量-标量和向量-立即数的操作数形式。
   - 测试了向量浮点数算术指令（在本部分只展示了宏定义，具体的测试用例可能在代码的其他部分）。

**与 JavaScript 的关系**

这段代码直接测试的是底层的汇编器，它负责将 V8 的中间表示（IR）转换为 RISC-V 机器码。当 JavaScript 代码执行时，V8 会将其编译成机器码，而汇编器就是这个过程的关键组成部分。

例如，以下 JavaScript 代码中的加法操作：

```javascript
function add(a, b) {
  return a + b;
}
```

在 V8 中，当 `add` 函数被执行时，V8 的编译器可能会生成类似于以下的 RISC-V 汇编指令（简化示例，实际情况更复杂）：

```assembly
  // ... 函数入口 ...
  lw  a0, [sp, #offset_a]  // 将参数 a 加载到寄存器 a0
  lw  a1, [sp, #offset_b]  // 将参数 b 加载到寄存器 a1
  add a0, a0, a1          // 将 a0 和 a1 相加，结果存回 a0
  // ... 函数出口，将 a0 作为返回值 ...
```

`v8/test/cctest/test-assembler-riscv64.cc` 中的测试用例，例如测试 `vadd_vv` 指令，就是为了确保 V8 的汇编器能够正确地生成和处理这种加法指令（特别是对于向量化的场景）。

**代码逻辑推理**

以 `TARGET_ADDRESS` 测试为例，假设输入 `buffer` 数组包含一系列字节，这些字节恰好是 RISC-V 架构中加载一个 39 位地址的指令序列。

**假设输入 (`RISCV_USE_SV39` 为真):**

```c++
uint32_t buffer[4] = {0x304ac537, 0xfe950513, 0x851513, 0x6156513};
```

这段数据表示一系列 RISC-V 指令的机器码。汇编器 (`MacroAssembler`) 会解析这些指令。

**输出:**

`__ target_address_at(static_cast<Address>(addr))` 函数会分析 `buffer` 中的指令序列，提取出其中编码的目标地址。根据 RISC-V 的指令编码规则，这些指令组合起来表示加载地址 `0x00304abfe961L` 的操作。

`CHECK_EQ(0x00304abfe961L, res);` 会验证提取出的地址是否与预期值 `0x00304abfe961L` 相等。

**用户常见的编程错误**

在与汇编器或底层代码交互时，常见的编程错误包括：

1. **地址计算错误:** 手动计算跳转目标地址或内存偏移量时可能出错，导致程序崩溃或行为异常。`TARGET_ADDRESS` 和跳转表相关的测试可以帮助发现汇编器在处理地址时的错误。

2. **浮点数比较的误解:**  不理解 NaN 的特性，认为 `NaN == NaN` 为真。`F_NAN` 测试可以确保汇编器生成的浮点数比较指令符合 IEEE 754 标准。

3. **整数溢出:** 在进行整数运算时没有考虑到溢出的情况，导致结果不正确。虽然这段代码主要测试汇编器，但理解整数溢出对于编写正确的底层代码也很重要。

4. **向量指令的错误使用:**  在使用 SIMD 指令时，可能没有正确地设置向量长度、数据类型或操作数，导致计算错误或性能下降。RVV 相关的测试确保了汇编器能够正确生成这些复杂的向量指令。

**总结**

总而言之，这段 `v8/test/cctest/test-assembler-riscv64.cc` 的第三部分是一个针对 V8 JavaScript 引擎中 RISC-V 64 位汇编器的综合性测试套件。它涵盖了地址操作、浮点数转换和比较、跳转表以及 RISC-V 向量扩展指令的测试，旨在确保汇编器能够正确地生成机器码，从而保证 JavaScript 代码在 RISC-V 架构上的正确执行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
bfe961
  uint32_t buffer[4] = {0x304ac537, 0xfe950513, 0x851513, 0x6156513};
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0x00304abfe961L, res);
#else
  // This is the series of instructions to load 48 bit address 0x0123456789ab
  uint32_t buffer[6] = {0x091ab37,  0x2b330213, 0x00b21213,
                        0x62626213, 0x00621213, 0x02b26213};
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0x0123456789abL, res);
#endif
}

TEST(SET_TARGET_ADDR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

#ifdef RISCV_USE_SV39
  // This is the series of instructions to load 39 bit address 0x00304abfe961
  uint32_t buffer[4] = {0x304ac537, 0xfe950513, 0x851513, 0x6156513};

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  __ set_target_value_at(static_cast<Address>(addr), 0x00304abfe961L,
                         FLUSH_ICACHE_IF_NEEDED);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0x00304abfe961L, res);
#else
  // This is the series of instructions to load 48 bit address 0xba9876543210
  uint32_t buffer[6] = {0x091ab37,  0x2b330213, 0x00b21213,
                        0x62626213, 0x00621213, 0x02b26213};

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  __ set_target_value_at(static_cast<Address>(addr), 0xba9876543210L, nullptr,
                         FLUSH_ICACHE_IF_NEEDED);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0xba9876543210L, res);
#endif
}

// pair.first is the F_TYPE input to test, pair.second is I_TYPE expected
// result
template <typename F_TYPE, typename I_TYPE>
static const std::vector<std::pair<F_TYPE, I_TYPE>> out_of_range_test_values() {
  static const std::pair<F_TYPE, I_TYPE> kValues[] = {
      std::make_pair(std::numeric_limits<F_TYPE>::quiet_NaN(),
                     std::numeric_limits<I_TYPE>::max()),
      std::make_pair(std::numeric_limits<F_TYPE>::signaling_NaN(),
                     std::numeric_limits<I_TYPE>::max()),
      std::make_pair(std::numeric_limits<F_TYPE>::infinity(),
                     std::numeric_limits<I_TYPE>::max()),
      std::make_pair(-std::numeric_limits<F_TYPE>::infinity(),
                     std::numeric_limits<I_TYPE>::min()),
      std::make_pair(
          static_cast<F_TYPE>(std::numeric_limits<I_TYPE>::max()) + 1024,
          std::numeric_limits<I_TYPE>::max()),
      std::make_pair(
          static_cast<F_TYPE>(std::numeric_limits<I_TYPE>::min()) - 1024,
          std::numeric_limits<I_TYPE>::min()),
  };
  return std::vector<std::pair<F_TYPE, I_TYPE>>(&kValues[0],
                                                &kValues[arraysize(kValues)]);
}

// Test conversion from wider to narrower types w/ out-of-range values or from
// nan, inf, -inf
TEST(OUT_OF_RANGE_CVT) {
  CcTest::InitializeVM();

  {  // test fvt_w_d
    auto i_vec = out_of_range_test_values<double, int32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_w_d(a0, fa0); };
      auto res = GenAndRunTest<int32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_w_s
    auto i_vec = out_of_range_test_values<float, int32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_w_s(a0, fa0); };
      auto res = GenAndRunTest<int32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_wu_d
    auto i_vec = out_of_range_test_values<double, uint32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_wu_d(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_wu_s
    auto i_vec = out_of_range_test_values<float, uint32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_wu_s(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_l_d
    auto i_vec = out_of_range_test_values<double, int64_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_l_d(a0, fa0); };
      auto res = GenAndRunTest<int64_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_l_s
    auto i_vec = out_of_range_test_values<float, int64_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_l_s(a0, fa0); };
      auto res = GenAndRunTest<int64_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_lu_d
    auto i_vec = out_of_range_test_values<double, uint64_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_lu_d(a0, fa0); };
      auto res = GenAndRunTest<uint64_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {  // test fvt_lu_s
    auto i_vec = out_of_range_test_values<float, uint64_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_lu_s(a0, fa0); };
      auto res = GenAndRunTest<uint64_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }
}

#define FCMP_TEST_HELPER(F, fn, op)                                         \
  {                                                                         \
    auto res1 = GenAndRunTest<int32_t>(std::numeric_limits<F>::quiet_NaN(), \
                                       static_cast<F>(1.0), fn);            \
    CHECK_EQ(false, res1);                                                  \
    auto res2 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::quiet_NaN(),         \
                               std::numeric_limits<F>::quiet_NaN(), fn);    \
    CHECK_EQ(false, res2);                                                  \
    auto res3 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::signaling_NaN(),     \
                               std::numeric_limits<F>::quiet_NaN(), fn);    \
    CHECK_EQ(false, res3);                                                  \
    auto res4 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::quiet_NaN(),         \
                               std::numeric_limits<F>::infinity(), fn);     \
    CHECK_EQ(false, res4);                                                  \
    auto res5 =                                                             \
        GenAndRunTest<int32_t>(std::numeric_limits<F>::infinity(),          \
                               std::numeric_limits<F>::infinity(), fn);     \
    CHECK_EQ((std::numeric_limits<F>::infinity()                            \
                  op std::numeric_limits<F>::infinity()),                   \
             res5);                                                         \
    auto res6 =                                                             \
        GenAndRunTest<int32_t>(-std::numeric_limits<F>::infinity(),         \
                               std::numeric_limits<F>::infinity(), fn);     \
    CHECK_EQ((-std::numeric_limits<F>::infinity()                           \
                  op std::numeric_limits<F>::infinity()),                   \
             res6);                                                         \
  }

TEST(F_NAN) {
  // test floating-point compare w/ NaN, +/-Inf
  CcTest::InitializeVM();

  // floating compare
  auto fn1 = [](MacroAssembler& assm) { __ feq_s(a0, fa0, fa1); };
  FCMP_TEST_HELPER(float, fn1, ==);
  auto fn2 = [](MacroAssembler& assm) { __ flt_s(a0, fa0, fa1); };
  FCMP_TEST_HELPER(float, fn2, <);
  auto fn3 = [](MacroAssembler& assm) { __ fle_s(a0, fa0, fa1); };
  FCMP_TEST_HELPER(float, fn3, <=);

  // double compare
  auto fn4 = [](MacroAssembler& assm) { __ feq_d(a0, fa0, fa1); };
  FCMP_TEST_HELPER(double, fn4, ==);
  auto fn5 = [](MacroAssembler& assm) { __ flt_d(a0, fa0, fa1); };
  FCMP_TEST_HELPER(double, fn5, <);
  auto fn6 = [](MacroAssembler& assm) { __ fle_d(a0, fa0, fa1); };
  FCMP_TEST_HELPER(double, fn6, <=);
}

TEST(jump_tables1) {
  // Test jump tables with forward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases], done;

  auto fn = [&labels, &done, values](MacroAssembler& assm) {
    __ addi(sp, sp, -8);
    __ Sd(ra, MemOperand(sp));
    __ Align(8);
    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

      __ auipc(ra, 0);
      __ slli(t3, a0, 3);
      __ add(t3, t3, ra);
      __ Ld(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      __ RV_li(a0, values[i]);
      __ j(&done);
    }

    __ bind(&done);
    __ Ld(ra, MemOperand(sp));
    __ addi(sp, sp, 8);

    CHECK_EQ(0, assm.UnboundLabelsCount());
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    CHECK_EQ(values[i], static_cast<int>(res));
  }
}

TEST(jump_tables2) {
  // Test jump tables with backward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases], done, dispatch;

  auto fn = [&labels, &done, &dispatch, values](MacroAssembler& assm) {
    __ addi(sp, sp, -8);
    __ Sd(ra, MemOperand(sp));
    __ j(&dispatch);

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      __ RV_li(a0, values[i]);
      __ j(&done);
    }

    __ Align(8);
    __ bind(&dispatch);

    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

      __ auipc(ra, 0);
      __ slli(t3, a0, 3);
      __ add(t3, t3, ra);
      __ Ld(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }
    __ bind(&done);
    __ Ld(ra, MemOperand(sp));
    __ addi(sp, sp, 8);
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    CHECK_EQ(values[i], res);
  }
}

TEST(jump_tables3) {
  // Test jump tables with backward jumps and embedded heap objects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  Handle<Object> values[kNumCases];
  for (int i = 0; i < kNumCases; ++i) {
    double value = isolate->random_number_generator()->NextDouble();
    values[i] = isolate->factory()->NewHeapNumber<AllocationType::kOld>(value);
  }
  Label labels[kNumCases], done, dispatch;
  Tagged<Object> obj;
  int64_t imm64;

  auto fn = [&labels, &done, &dispatch, values, &obj,
             &imm64](MacroAssembler& assm) {
    __ addi(sp, sp, -8);
    __ Sd(ra, MemOperand(sp));

    __ j(&dispatch);

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      obj = *values[i];
      imm64 = obj.ptr();
      __ nop();  // For 8 byte alignment
      __ RV_li(a0, imm64);
      __ nop();  // For 8 byte alignment
      __ j(&done);
    }

    __ bind(&dispatch);
    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
      __ Align(8);
      __ auipc(ra, 0);
      __ slli(t3, a0, 3);
      __ add(t3, t3, ra);
      __ Ld(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }

    __ bind(&done);
    __ Ld(ra, MemOperand(sp));
    __ addi(sp, sp, 8);
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    Handle<Object> result(
        Tagged<Object>(reinterpret_cast<Address>(f.Call(i, 0, 0, 0, 0))),
        isolate);
#ifdef OBJECT_PRINT
    ::printf("f(%d) = ", i);
    Print(*result, std::cout);
    ::printf("\n");
#endif
    CHECK(values[i].is_identical_to(result));
  }
}

TEST(li_estimate) {
  std::vector<int64_t> immediates = {
      -256,      -255,          0,         255,        8192,      0x7FFFFFFF,
      INT32_MIN, INT32_MAX / 2, INT32_MAX, UINT32_MAX, INT64_MAX, INT64_MAX / 2,
      INT64_MIN, 12312874234};
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  for (auto p : immediates) {
    Label a;
    assm.bind(&a);
    assm.RV_li(t0, p);
    int expected_count = assm.RV_li_count(p, true);
    int count = assm.InstructionsGeneratedSince(&a);
    CHECK_EQ(count, expected_count);
  }
}

#define UTEST_LOAD_STORE_RVV(ldname, stname, SEW, arry)                      \
  TEST(RISCV_UTEST_##stname##ldname##SEW) {                                  \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    Isolate* isolate = CcTest::i_isolate();                                  \
    HandleScope scope(isolate);                                              \
    int8_t src[16];                                                          \
    for (size_t i = 0; i < sizeof(src); i++) src[i] = arry[i % arry.size()]; \
    int8_t dst[16];                                                          \
    auto fn = [](MacroAssembler& assm) {                                     \
      __ VU.set(t0, SEW, Vlmul::m1);                                         \
      __ vl(v2, a0, 0, SEW);                                                 \
      __ vs(v2, a1, 0, SEW);                                                 \
    };                                                                       \
    GenAndRunTest<int32_t, int64_t>((int64_t)src, (int64_t)dst, fn);         \
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
    GenAndRunTest<int32_t, int64_t>((int64_t)&src, (int64_t)dst, fn);
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
      __ fmv_d_x(ft0, a0);
      __ vfmv_vf(v1, ft0);
      __ vs(v1, a1, 0, VSew::E64);
    };
    GenAndRunTest<int64_t, int64_t>((int64_t)rs1_fval, (int64_t)dst, fn);
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
      __ fmv_w_x(ft0, a0);
      __ vfmv_vf(v1, ft0);
      __ vs(v1, a1, 0, VSew::E32);
    };
    GenAndRunTest<int64_t, int64_t>((int64_t)rs1_fval, (int64_t)dst, fn);
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
      __ fmv_d_x(ft0, a0);
      __ vfmv_vf(v1, ft0);
      __ vfneg_vv(v2, v1);
      __ vs(v2, a1, 0, VSew::E64);
    };
    GenAndRunTest<int64_t, int64_t>((int64_t)rs1_fval, (int64_t)dst, fn);
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
      __ fmv_w_x(ft0, a0);
      __ vfmv_vf(v1, ft0);
      __ vfneg_vv(v2, v1);
      __ vs(v2, a1, 0, VSew::E32);
    };
    GenAndRunTest<int64_t, int64_t>((int64_t)rs1_fval, (int64_t)dst, fn);
    for (uint32_t i = 0; i < n; i++) {
      CHECK_EQ(expected_fval, dst[i]);
    }
  }
}

// Tests for Floating-Point scalar move instructions between vector and scalar f
// register
#define UTEST_RVV_VF_MV_FORM_WITH_RES(instr_name, reg1, reg2, width, type)     \
  TEST(RISCV_UTEST_##instr_name##_##width) {                                   \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                         \
    CcTest::InitializeVM();                                                    \
    constexpr uint32_t n = kRvvVLEN / width;                                   \
    for (type fval : compiler::ValueHelper::GetVector<type>()) {               \
      int##width##_t rs1_fval = base::bit_cast<int##width##_t>(fval);          \
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
      GenAndRunTest<int64_t, int64_t>((int64_t) & rs1_fval, (int64_t)res, fn); \
      for (uint32_t i = 0; i < n; i++) {                                       \
        CHECK_EQ(i == 0 ? rs1_fval : res[i], res[i]);                          \
      }                                                                        \
    }                                                                          \
  }                                                                            \
  TEST(RISCV_UTEST_##instr_name##_##width##_##sNaN) {                          \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                         \
    CcTest::InitializeVM();                                                    \
    constexpr uint32_t n = kRvvVLEN / width;                                   \
    int##width##_t rs1_fval = width == 32 ? 0x7F400000 : 0x7FF4000000000000;   \
    int##width##_t res[n] = {0};                                               \
    for (uint32_t i = 0; i < n; i++) res[i] = (rs1_fval + i + 1);              \
    auto fn = [](MacroAssembler& assm) {                                       \
      __ VU.set(t0, VSew::E##width, Vlmul::m1);                                \
      width == 32 ? __ flw(ft0, a0, 0) : __ fld(ft0, a0, 0);                   \
      __ vl(v1, a1, 0, VSew::E##width);                                        \
      __ instr_name(reg1, reg2);                                               \
      width == 32 ? __ fsw(ft0, a0, 0) : __ fsd(ft0, a0, 0);                   \
      __ vs(v1, a1, 0, VSew::E##width);                                        \
    };                                                                         \
    GenAndRunTest<int64_t, int64_t>((int64_t) & rs1_fval, (int64_t)res, fn);   \
    for (uint32_t i = 0; i < n; i++) {                                         \
      CHECK_EQ(i == 0 ? rs1_fval : res[i], res[i]);                            \
    }                                                                          \
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
      __ li(a3, Operand(int64_t(result)));                                 \
      __ vs(v0, a3, 0, E32);                                               \
    };                                                                     \
    for (float rs1_fval : compiler::ValueHelper::GetVector<float>()) {     \
      for (float rs2_fval : compiler::ValueHelper::GetVector<float>()) {   \
        GenAndRunTest<float, float>(rs1_fval, rs2_fval, fn);               \
        for (int i = 
"""


```