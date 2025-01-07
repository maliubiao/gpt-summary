Response: The user wants to understand the functionality of a C++ source code file related to RISC-V 64-bit assembly within the V8 JavaScript engine. This is the second part of a three-part summary.

To address this, I need to:

1. **Analyze the provided C++ code snippets.** Focus on the test cases defined within this part.
2. **Identify the RISC-V assembly instructions being tested.**
3. **Infer the functionality being verified by each test case.**
4. **Relate these functionalities to potential JavaScript use cases if applicable.** Since this is part 2, I should consider the context from the previous part if available and anticipate what might come in the next part.
5. **Provide a concise summary of the functionality.**
这是目录为`v8/test/cctest/test-assembler-riscv64.cc`的C++源代码文件的第二部分，它主要包含了一系列的单元测试，用于验证 RISC-V 64位架构下汇编器（`MacroAssembler`）生成指令的正确性。这些测试覆盖了多种指令类型，包括：

* **地址操作:**  测试 `target_address_at` 和 `set_target_value_at` 这两个方法，用于获取和设置指令序列中目标地址的值。这对于生成需要跳转或访问特定内存地址的代码非常重要。
* **浮点数转换:** 测试从浮点数（`double`, `float`) 转换为整数 (`int32_t`, `uint32_t`, `int64_t`, `uint64_t`) 的指令，并特别关注了超出目标类型范围时的行为，例如 NaN 和无穷大。
* **浮点数比较:** 测试浮点数比较指令 (`feq_s`, `flt_s`, `fle_s`, `feq_d`, `flt_d`, `fle_d`) 在处理 NaN 和正负无穷大时的行为。
* **跳转表:** 测试了跳转表的实现，包括向前跳转和向后跳转的情况，以及在跳转表中嵌入堆对象的情况。跳转表是一种优化技术，用于高效地根据不同的条件跳转到不同的代码块。
* **指令长度估计:** 测试 `RV_li_count` 方法，用于估计加载立即数指令 (`RV_li`) 所需的指令数量。这对于代码大小优化很重要。
* **RVV (RISC-V Vector Extension) 指令:** 包含了大量的测试用例，覆盖了多种 RVV 指令，包括：
    * **加载/存储:**  `vl` (vector load) 和 `vs` (vector store) 指令。
    * **向量移动:** `vfmv_vf` (move scalar float to vector)。
    * **向量取反:** `vfneg_vv` (vector negate)。
    * **向量与标量寄存器之间的移动:** `vfmv_fs`, `vfmv_sf` (move between vector and scalar floating-point register)。
    * **向量整数算术运算:** `vadd_vv`, `vsub_vv`, `vand_vv`, `vor_vv`, `vxor_vv`, `vmax_vv`, `vmin_vv`, `vmaxu_vv`, `vminu_vv` (向量与向量以及向量与标量之间的加减、位运算、最大最小值运算)。
    * **向量浮点算术运算:** `vfadd_vv`, `vfsub_vv`, `vfmul_vv`, `vfdiv_vv` (向量与向量之间的浮点加减乘除)。
    * **向量浮点数扩展算术运算:** `vfwadd_vv`, `vfwsub_vv`, `vfwmul_vv` (对低精度向量进行运算并将结果存储到高精度向量中)。
    * **向量浮点数融合乘加运算:** `vfmadd_vv`, `vfnmadd_vv`, `vfmsub_vv`, `vfnmsub_vv`, `vfmacc_vv`, `vfnmacc_vv`, `vfmsac_vv`, `vfnmsac_vv` (向量与向量以及向量与标量之间的融合乘加运算)。
    * **向量浮点数归约运算:** `vfwredusum_vs`, `vfwredosum_vs` (将向量元素归约求和)。
    * **向量裁剪指令:** `vnclipu_vi`, `vnclip_vi` (将向量元素裁剪到指定位宽)。
    * **向量扩展指令:** `vzext_vf`, `vsext_vf` (将向量元素进行零扩展或符号扩展)。

**与 JavaScript 的关系及示例:**

虽然这些测试直接针对的是底层的汇编器，但它们确保了 V8 引擎在 RISC-V 64位架构上正确地执行 JavaScript 代码。  V8 会将 JavaScript 代码编译成机器码，而 `MacroAssembler` 负责生成这些机器码。

例如，涉及到浮点数运算的 JavaScript 代码会依赖于这些经过测试的浮点数指令：

```javascript
function calculate(a, b) {
  return a + b * 2.5;
}

let result = calculate(1.5, 3.0);
console.log(result); // 输出 9
```

在这个简单的 JavaScript 函数中，乘法和加法运算会最终被编译成 RISC-V 的浮点数乘法和加法指令，而这些指令的正确性正是通过类似 `UTEST_RVV_VF_VV_FORM_WITH_OP` 这样的测试用例来保证的。

对于 RVV 指令，它们可以用于加速 JavaScript 中涉及大量数值计算的场景，例如：

```javascript
// 使用 TypedArray 进行向量计算
const a = new Float32Array([1, 2, 3, 4]);
const b = new Float32Array([5, 6, 7, 8]);
const result = new Float32Array(4);

for (let i = 0; i < a.length; i++) {
  result[i] = a[i] + b[i];
}

console.log(result); // 输出 Float32Array [ 6, 8, 10, 12 ]
```

在支持 RVV 的架构上，V8 可以利用 RVV 指令（例如 `vfadd_vv`）来并行执行 `for` 循环中的加法操作，从而提高性能。

**总结本部分的功能:**

这部分代码专注于测试 RISC-V 64位架构下汇编器的核心功能，特别是对地址操作、浮点数转换和比较、跳转表以及 RVV 向量扩展指令的正确性进行了全面的测试。这些测试是 V8 引擎在 RISC-V 平台上可靠运行 JavaScript 代码的基础。它确保了 V8 能够生成正确的机器码来执行各种 JavaScript 操作，尤其是在数值计算和向量化处理方面。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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