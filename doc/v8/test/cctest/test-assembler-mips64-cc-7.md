Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-assembler-mips64.cc`. They have several specific questions:

1. **Overall functionality:** What does this code do?
2. **Torque source:** Is it a Torque file (ending in `.tq`)?
3. **JavaScript relation:** Does it relate to JavaScript functionality? If so, provide a JavaScript example.
4. **Code logic reasoning:** Are there any test cases with clear input and expected output?
5. **Common programming errors:** Does it highlight potential user errors?
6. **Part of a larger set:** It's part 8 of 13, so what is the overall theme?

**Plan:**

1. **Analyze the code:** Identify the main purpose by looking at the test names and the operations being performed. It seems to be testing MIPS64 assembly instructions for V8.
2. **Check for `.tq`:**  The filename ends in `.cc`, not `.tq`.
3. **JavaScript relation:**  Assembler tests are indirectly related to how JavaScript code is compiled and executed. I need to think of a JavaScript example that might utilize these low-level instructions.
4. **Input/Output:** The `TestCase` structs define input values, and the `CHECK_EQ` calls verify the output. I can extract some of these as examples.
5. **Programming errors:**  The tests are designed to verify correct behavior. They don't directly show user errors, but I can infer some common errors related to the tested instructions (e.g., integer overflow, incorrect bitwise operations).
6. **Overall theme:**  Given the filename and the operations tested, the overarching theme is likely testing the MIPS64 assembler within V8, specifically its SIMD capabilities.

**Self-Correction/Refinement:**

* **JavaScript example:**  A simple numerical operation in JavaScript would be a good example, as the tested instructions are mostly about arithmetic and bitwise operations.
* **Programming errors:** Instead of directly showing errors *in the test code*, I should focus on what kind of user errors *these instructions* might be susceptible to if used incorrectly.
这是 `v8/test/cctest/test-assembler-mips64.cc` 的第 8 部分源代码，主要功能是**测试 V8 JavaScript 引擎在 MIPS64 架构上的汇编器功能，特别是针对 MSA (MIPS SIMD Architecture) 指令的正确性。**

**功能归纳：**

这部分代码包含了多个 C++ 测试用例 (以 `TEST()` 宏定义)，用于验证 MIPS64 架构下 MSA 指令的不同操作。它测试了以下几种类型的指令：

* **按位逻辑立即数操作 (Bitwise Logical Immediate):** `ANDI_B`, `ORI_B`, `NORI_B`, `XORI_B`  （对字节进行操作）
* **按位条件移动立即数操作 (Bitwise Conditional Move Immediate):** `BMNZI_B`, `BMZI_B`, `BSELI_B` (根据立即数的值和输入的位进行条件移动)
* **移位操作 (Shift):** `SHF_B`, `SHF_H`, `SHF_W` (对字节、半字和字进行移位和排列)
* **向量加/减立即数 (Vector Add/Subtract Immediate):** `addvi_b`, `addvi_h`, `addvi_w`, `addvi_d`, `subvi_b`, `subvi_h`, `subvi_w`, `subvi_d` (对向量中的每个元素加或减去一个立即数)
* **向量最大/最小值立即数 (Vector Max/Min Immediate):** `maxi_s_b`, `maxi_s_h`, `maxi_s_w`, `maxi_s_d`, `mini_s_b`, `mini_s_h`, `mini_s_w`, `mini_s_d`, `maxi_u_b`, `maxi_u_h`, `maxi_u_w`, `maxi_u_d`, `mini_u_b`, `mini_u_h`, `mini_u_w`, `mini_u_d` (比较向量元素和立即数，取最大或最小值，区分有符号和无符号)
* **向量比较立即数 (Vector Compare Immediate):** `ceqi_b`, `ceqi_h`, `ceqi_w`, `ceqi_d`, `clti_s_b`, `clti_s_h`, `clti_s_w`, `clti_s_d`, `clei_s_b`, `clei_s_h`, `clei_s_w`, `clei_s_d`, `clti_u_b`, `clti_u_h`, `clti_u_w`, `clti_u_d`, `clei_u_b`, `clei_u_h`, `clei_u_w`, `clei_u_d` (将向量元素与立即数进行比较，结果用全 1 或全 0 表示)
* **向量元素计数 (Vector Element Count):** `pcnt_b`, `pcnt_h`, `pcnt_w`, `pcnt_d` (计算向量中每个字节、半字、字或双字中置位的位数)
* **前导零计数 (Leading Zero Count):** `nlzc_b`, `nlzc_h`, `nlzc_w`, `nlzc_d` (计算向量中每个字节、半字、字或双字前导零的个数)
* **前导一计数 (Leading One Count):** `nloc_b`, `nloc_h`, `nloc_w`, `nloc_d` (计算向量中每个字节、半字、字或双字前导一的个数)
* **浮点数分类 (Floating-point Classify):** `fclass_w`, `fclass_d` (将浮点数分类为 NaN、无穷大、零、规格化数、非规格化数等)
* **浮点数截断为整数 (Floating-point Truncate to Integer):** `ftrunc_s_w`, `ftrunc_s_d` (将单精度和双精度浮点数截断为整数)

**关于代码的提问：**

* **v8/test/cctest/test-assembler-mips64.cc 以 .tq 结尾？**
  不是，这个文件的结尾是 `.cc`，表明它是 C++ 源代码文件。`.tq` 结尾的文件是 V8 的 Torque 语言源代码。

* **与 javascript 的功能有关系吗？**
  有关系。尽管这是 C++ 代码，但它直接测试了 V8 引擎在 MIPS64 架构上生成和执行机器码的能力。当 JavaScript 代码在 V8 引擎上运行时，引擎会将 JavaScript 代码编译成机器码，其中可能就包含这些 MSA 指令（如果代码可以利用 SIMD 优化）。

  **JavaScript 示例：**

  假设 JavaScript 引擎能够将以下 JavaScript 代码优化并使用 MSA 指令：

  ```javascript
  function processArray(a, scalar) {
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
      result[i] = Math.max(a[i], scalar); //  这个操作可能在底层用到类似 maxi 指令
    }
    return result;
  }

  const input = new Uint8Array([10, 20, 5, 30, 15, 25, 8, 35]);
  const threshold = 18;
  const output = processArray(input, threshold);
  console.log(output); // 输出: Uint8Array [ 18, 20, 18, 30, 18, 25, 18, 35 ]
  ```

  在这个例子中，`Math.max` 操作在处理数组时，V8 引擎在 MIPS64 架构下可能会使用 `maxi_u_b` 这样的 MSA 指令来并行比较数组元素和 `scalar` 的值，从而提高效率。

* **代码逻辑推理，给出假设输入与输出:**

  以 `TEST(MSA_andi_ori_nori_xori)` 中的一个测试用例为例：

  **假设输入:**
  `input_lo = 0x1169751BB9A7D9C3` (64位整数)
  `input_hi = 0xF7A594AEC8EF8A9C` (64位整数)
  `i8 = 0xFFu` (8位无符号整数，值为 255)
  测试的指令是 `ANDI_B` (字节与立即数)。

  **代码逻辑:**
  `run_msa_i8(ANDI_B, input_lo, input_hi, i8)` 函数会模拟执行 `ANDI_B` 指令。该指令会将 `input_lo` 和 `input_hi` 视为包含多个字节的向量，并将每个字节与立即数 `i8` (0xFF) 进行按位与操作。由于 0xFF 的所有位都是 1，因此与 0xFF 进行按位与操作不会改变原始字节的值。

  **预期输出:**
  `res.d[0]` (对应 `input_lo` 的结果) 应该等于 `input_lo`。
  `res.d[1]` (对应 `input_hi` 的结果) 应该等于 `input_hi`。

  实际上，`run_msa_i8` 内部会将 `input_lo` 和 `input_hi` 加载到 MSA 寄存器中，执行 `ANDI_B` 指令，然后将结果存储到 `res` 结构体中。`CHECK_EQ` 宏会验证实际结果是否与预期相符。

* **涉及用户常见的编程错误，请举例说明:**

  虽然测试代码本身是为了验证指令的正确性，但它也间接反映了用户在使用 SIMD 指令时可能犯的错误：

  1. **数据类型不匹配:**  例如，将有符号数误用于无符号数的 MSA 指令，可能导致意想不到的结果。测试用例中区分了有符号 (`_s`) 和无符号 (`_u`) 的 `maxi` 和 `mini` 指令，强调了类型的重要性。

     ```c++
     // 假设用户错误地使用了有符号最大值指令处理无符号数
     uint8_t a = 200;
     uint8_t b = 100;
     int8_t sa = a; // 解释为 -56
     int8_t sb = b; // 解释为 100
     int8_t max_val = std::max(sa, sb); // 结果是 100，但用户可能期望 200
     ```

  2. **位运算错误理解:**  对于按位逻辑操作和移位操作，用户可能对立即数的含义或操作的最终效果理解有误。例如，对于 `SHF_B` 指令，立即数的不同位控制着字节的重排，如果立即数设置错误，会导致数据错乱。

     ```c++
     // 假设用户错误地理解了 SHF_B 的立即数
     uint64_t input_val = 0x0102030405060708; // 字节 08 07 06 05 04 03 02 01
     uint8_t shuffle_mask = 0b00010010; //  错误的 mask
     // 用户可能期望得到某种排列，但由于 mask 错误，结果可能不是预期的
     ```

  3. **溢出和截断:**  在使用立即数进行加减运算时，如果结果超出数据类型的范围，会发生溢出或截断。测试用例中使用了各种边界值来测试指令在这些情况下的行为。

     ```c++
     // 假设用户在进行向量加法时没有考虑溢出
     uint8_t arr1[] = {200, 100};
     uint8_t arr2[] = {100, 200};
     uint8_t result[2];
     result[0] = arr1[0] + arr2[0]; // 200 + 100 = 300，超出 uint8_t 范围，发生截断
     result[1] = arr1[1] + arr2[1]; // 100 + 200 = 300，超出 uint8_t 范围，发生截断
     ```

**总结第 8 部分的功能:**

这部分测试代码专注于验证 V8 引擎在 MIPS64 架构下，针对 MSA 指令集中**立即数操作**（Immediate Operands）的汇编器实现是否正确。它涵盖了按位逻辑、条件移动、移位、向量加减、向量比较、向量最大/最小值、元素计数、前导零/一计数以及浮点数分类和截断等多种涉及立即数的 MSA 指令。通过大量的测试用例，确保这些指令在 V8 引擎中的生成和执行符合预期。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共13部分，请归纳一下它的功能

"""
D68B3F8BC8, 0xD9u}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI8); ++i) {
    run_msa_i8(ANDI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(ORI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(NORI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(XORI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
  }
}

TEST(MSA_bmnzi_bmzi_bseli) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI8 tc[] = {
    //         input_lo,           input_hi,    i8
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0xFFu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0u},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x3Bu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0xD9u}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI8); ++i) {
    run_msa_i8(BMNZI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(BMZI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(BSELI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
  }
}

TEST(MSA_shf) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI8 tc[] = {
      //          input_lo,           input_hi,    i8
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0xFFu},  // 3333
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0u},   // 0000
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0xE4u},  // 3210
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x1Bu},  // 0123
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0xB1u},  // 2301
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x4Eu},  // 1032
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x27u}   // 0213
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI8); ++i) {
    run_msa_i8(SHF_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(SHF_H, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(SHF_W, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
  }
}

struct TestCaseMsaI5 {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint32_t i5;
};

template <typename InstFunc, typename OperFunc>
void run_msa_i5(struct TestCaseMsaI5* input, bool i5_sign_ext,
                InstFunc GenerateI5InstructionFunc,
                OperFunc GenerateOperationFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;
  int32_t i5 =
      i5_sign_ext ? static_cast<int32_t>(input->i5 << 27) >> 27 : input->i5;

  load_elements_of_vector(&assm, &(input->ws_lo), w0, t0, t1);

  GenerateI5InstructionFunc(assm, i5);

  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(GenerateOperationFunc(input->ws_lo, input->i5), res.d[0]);
  CHECK_EQ(GenerateOperationFunc(input->ws_hi, input->i5), res.d[1]);
}

TEST(MSA_addvi_subvi) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI5 tc[] = {
    //            ws_lo,              ws_hi,         i5
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x0000001F},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0000000F},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x00000005},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x00000010},
    {0xFFAB807F807FFFCD, 0x7F23FF80FF567F80, 0x0000000F},
    {0x80FFEFFF7F12807F, 0x807F80FF7FDEFF78, 0x00000010}
  };
// clang-format on

#define ADDVI_DF(lanes, mask)                               \
  uint64_t res = 0;                                         \
  for (int i = 0; i < lanes / 2; ++i) {                     \
    int shift = (kMSARegSize / lanes) * i;                  \
    res |= ((((ws >> shift) & mask) + i5) & mask) << shift; \
  }                                                         \
  return res

#define SUBVI_DF(lanes, mask)                               \
  uint64_t res = 0;                                         \
  for (int i = 0; i < lanes / 2; ++i) {                     \
    int shift = (kMSARegSize / lanes) * i;                  \
    res |= ((((ws >> shift) & mask) - i5) & mask) << shift; \
  }                                                         \
  return res

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI5); ++i) {
    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_b(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesByte, UINT8_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_h(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesHalf, UINT16_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_w(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesWord, UINT32_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_d(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesDword, UINT64_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_b(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesByte, UINT8_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_h(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesHalf, UINT16_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_w(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesWord, UINT32_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_d(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesDword, UINT64_MAX); });
  }
#undef ADDVI_DF
#undef SUBVI_DF
}

TEST(MSA_maxi_mini) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI5 tc[] = {
    //            ws_lo,              ws_hi,         i5
    {0x7F80FF3480FF7F00, 0x8D7FFF80FF7F6780, 0x0000001F},
    {0x7F80FF3480FF7F00, 0x8D7FFF80FF7F6780, 0x0000000F},
    {0x7F80FF3480FF7F00, 0x8D7FFF80FF7F6780, 0x00000010},
    {0x80007FFF91DAFFFF, 0x7FFF8000FFFF5678, 0x0000001F},
    {0x80007FFF91DAFFFF, 0x7FFF8000FFFF5678, 0x0000000F},
    {0x80007FFF91DAFFFF, 0x7FFF8000FFFF5678, 0x00000010},
    {0x7FFFFFFF80000000, 0x12345678FFFFFFFF, 0x0000001F},
    {0x7FFFFFFF80000000, 0x12345678FFFFFFFF, 0x0000000F},
    {0x7FFFFFFF80000000, 0x12345678FFFFFFFF, 0x00000010},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x0000001F},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0000000F},
    {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x00000010},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x00000015},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x00000009},
    {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x00000003}
  };
// clang-format on

#define MAXI_MINI_S_DF(lanes, mask, func)                                     \
  [](uint64_t ws, uint32_t ui5) {                                             \
    uint64_t res = 0;                                                         \
    int64_t i5 = ArithmeticShiftRight(static_cast<int64_t>(ui5) << 59, 59);   \
    int elem_size = kMSARegSize / lanes;                                      \
    for (int i = 0; i < lanes / 2; ++i) {                                     \
      int shift = elem_size * i;                                              \
      int64_t elem =                                                          \
          static_cast<int64_t>(((ws >> shift) & mask) << (64 - elem_size)) >> \
          (64 - elem_size);                                                   \
      res |= static_cast<uint64_t>(func(elem, i5) & mask) << shift;           \
    }                                                                         \
    return res;                                                               \
  }

#define MAXI_MINI_U_DF(lanes, mask, func)                              \
  [](uint64_t ws, uint32_t ui5) {                                      \
    uint64_t res = 0;                                                  \
    int elem_size = kMSARegSize / lanes;                               \
    for (int i = 0; i < lanes / 2; ++i) {                              \
      int shift = elem_size * i;                                       \
      uint64_t elem = (ws >> shift) & mask;                            \
      res |= (func(elem, static_cast<uint64_t>(ui5)) & mask) << shift; \
    }                                                                  \
    return res;                                                        \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI5); ++i) {
    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_b(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesByte, UINT8_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_h(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesHalf, UINT16_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_w(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesWord, UINT32_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_d(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesDword, UINT64_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_b(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesByte, UINT8_MAX, std::min));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_h(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesHalf, UINT16_MAX, std::min));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_w(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesWord, UINT32_MAX, std::min));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_d(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesDword, UINT64_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_b(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesByte, UINT8_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_h(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesHalf, UINT16_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_w(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesWord, UINT32_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_d(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesDword, UINT64_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_b(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesByte, UINT8_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_h(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesHalf, UINT16_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_w(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesWord, UINT32_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_d(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesDword, UINT64_MAX, std::min));
  }
#undef MAXI_MINI_S_DF
#undef MAXI_MINI_U_DF
}

TEST(MSA_ceqi_clti_clei) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaI5 tc[] = {
      {0xFF69751BB9A7D9C3, 0xF7A594AEC8FF8A9C, 0x0000001F},
      {0xE669FFFFB9A7D9C3, 0xF7A594AEFFFF8A9C, 0x0000001F},
      {0xFFFFFFFFB9A7D9C3, 0xF7A594AEFFFFFFFF, 0x0000001F},
      {0x2B0B5362C4E812DF, 0x3A0D80D68B3F0BC8, 0x0000000B},
      {0x2B66000BC4E812DF, 0x3A0D000B8B3F8BC8, 0x0000000B},
      {0x0000000BC4E812DF, 0x3A0D80D60000000B, 0x0000000B},
      {0xF38062E13E38F8B0, 0x8041FFDEF2BFE636, 0x00000010},
      {0xF35880003E38F8B0, 0x4F41FFDEF2BF8000, 0x00000010},
      {0xF35862E180000000, 0x80000000F2BFE636, 0x00000010},
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x00000015},
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x00000009},
      {0xF30062E13E38F800, 0x4F00FFDEF2BF0036, 0x00000000}};

#define CEQI_CLTI_CLEI_S_DF(lanes, mask, func)                                \
  [](uint64_t ws, uint32_t ui5) {                                             \
    uint64_t res = 0;                                                         \
    int elem_size = kMSARegSize / lanes;                                      \
    int64_t i5 = ArithmeticShiftRight(static_cast<int64_t>(ui5) << 59, 59);   \
    for (int i = 0; i < lanes / 2; ++i) {                                     \
      int shift = elem_size * i;                                              \
      int64_t elem =                                                          \
          static_cast<int64_t>(((ws >> shift) & mask) << (64 - elem_size)) >> \
          (64 - elem_size);                                                   \
      res |= static_cast<uint64_t>((func)&mask) << shift;                     \
    }                                                                         \
    return res;                                                               \
  }

#define CEQI_CLTI_CLEI_U_DF(lanes, mask, func) \
  [](uint64_t ws, uint64_t ui5) {              \
    uint64_t res = 0;                          \
    int elem_size = kMSARegSize / lanes;       \
    for (int i = 0; i < lanes / 2; ++i) {      \
      int shift = elem_size * i;               \
      uint64_t elem = (ws >> shift) & mask;    \
      res |= ((func)&mask) << shift;           \
    }                                          \
    return res;                                \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI5); ++i) {
    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_b(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesByte, UINT8_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_h(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesHalf, UINT16_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_w(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesWord, UINT32_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_d(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesDword, UINT64_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, i5) == -1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, i5) == -1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, i5) == -1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, i5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, i5) != 1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, i5) != 1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, i5) != 1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, i5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));
  }
#undef CEQI_CLTI_CLEI_S_DF
#undef CEQI_CLTI_CLEI_U_DF
}

struct TestCaseMsa2R {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint64_t exp_res_lo;
  uint64_t exp_res_hi;
};

template <typename Func>
void run_msa_2r(const struct TestCaseMsa2R* input,
                Func Generate2RInstructionFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(&assm, reinterpret_cast<const uint64_t*>(input), w0,
                          t0, t1);
  Generate2RInstructionFunc(assm);
  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(input->exp_res_lo, res.d[0]);
  CHECK_EQ(input->exp_res_hi, res.d[1]);
}

TEST(MSA_pcnt) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2R tc_b[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0808080808080808, 0x0808080808080808},
                                 {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C,
                                  0x0204050405050504, 0x0704030503070304},
                                 {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8,
                                  0x0404040303040207, 0x0403010504060403},
                                 {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636,
                                  0x0603030405030503, 0x0502080605070504}};

  struct TestCaseMsa2R tc_h[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0010001000100010, 0x0010001000100010},
                                 {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C,
                                  0x00060009000A0009, 0x000B0008000A0007},
                                 {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8,
                                  0x0008000700070009, 0x00070006000A0007},
                                 {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636,
                                  0x0009000700080008, 0x0007000E000C0009}};

  struct TestCaseMsa2R tc_w[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0000002000000020, 0x0000002000000020},
                                 {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C,
                                  0x0000000F00000013, 0x0000001300000011},
                                 {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8,
                                  0x0000000F00000010, 0x0000000D00000011},
                                 {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636,
                                  0x0000001000000010, 0x0000001500000015}};

  struct TestCaseMsa2R tc_d[] = {
      // ws_lo, ws_hi, exp_res_lo, exp_res_hi
      {0x0000000000000000, 0x0000000000000000, 0, 0},
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x40, 0x40},
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x22, 0x24},
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x1F, 0x1E},
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x20, 0x2A}};

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseMsa2R); ++i) {
    run_msa_2r(&tc_b[i], [](MacroAssembler& assm) { __ pcnt_b(w2, w0); });
    run_msa_2r(&tc_h[i], [](MacroAssembler& assm) { __ pcnt_h(w2, w0); });
    run_msa_2r(&tc_w[i], [](MacroAssembler& assm) { __ pcnt_w(w2, w0); });
    run_msa_2r(&tc_d[i], [](MacroAssembler& assm) { __ pcnt_d(w2, w0); });
  }
}

TEST(MSA_nlzc) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2R tc_b[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000,
                                  0x0808080808080808, 0x0808080808080808},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
                                 {0x1169350B07030100, 0x7F011402381F0A6C,
                                  0x0301020405060708, 0x0107030602030401},
                                 {0x010806003478121F, 0x03013016073F7B08,
                                  0x0704050802010303, 0x0607020305020104},
                                 {0x0168321100083803, 0x07113F03013F1676,
                                  0x0701020308040206, 0x0503020607020301}};

  struct TestCaseMsa2R tc_h[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000,
                                  0x0010001000100010, 0x0010001000100010},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
                                 {0x00010007000A003C, 0x37A5001E00010002,
                                  0x000F000D000C000A, 0x0002000B000F000E},
                                 {0x0026066200780EDF, 0x003D0003000F00C8,
                                  0x000A000500090004, 0x000A000E000C0008},
                                 {0x335807E100480030, 0x01410FDE12BF5636,
                                  0x000200050009000A, 0x0007000400030001}};

  struct TestCaseMsa2R tc_w[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000,
                                  0x0000002000000020, 0x0000002000000020},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
                                 {0x00000005000007C3, 0x000014AE00006A9C,
                                  0x0000001D00000015, 0x0000001300000011},
                                 {0x00009362000112DF, 0x000380D6003F8BC8,
                                  0x000000100000000F, 0x0000000E0000000A},
                                 {0x135862E17E38F8B0, 0x0061FFDE03BFE636,
                                  0x0000000300000001, 0x0000000900000006}};

  struct TestCaseMsa2R tc_d[] = {
      // ws_lo, ws_hi, exp_res_lo, exp_res_hi
      {0x0000000000000000, 0x0000000000000000, 0x40, 0x40},
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
      {0x000000000000014E, 0x00000000000176DA, 0x37, 0x2F},
      {0x00000062C4E812DF, 0x000065D68B3F8BC8, 0x19, 0x11},
      {0x00000000E338F8B0, 0x0754534ACAB32654, 0x20, 0x5}};

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseMsa2R); ++i) {
    run_msa_2r(&tc_b[i], [](MacroAssembler& assm) { __ nlzc_b(w2, w0); });
    run_msa_2r(&tc_h[i], [](MacroAssembler& assm) { __ nlzc_h(w2, w0); });
    run_msa_2r(&tc_w[i], [](MacroAssembler& assm) { __ nlzc_w(w2, w0); });
    run_msa_2r(&tc_d[i], [](MacroAssembler& assm) { __ nlzc_d(w2, w0); });
  }
}

TEST(MSA_nloc) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2R tc_b[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0808080808080808, 0x0808080808080808},
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xEE96CAF4F8FCFEFF, 0x80FEEBFDC7E0F593,
                                  0x0301020405060708, 0x0107030602030401},
                                 {0xFEF7F9FFCB87EDE0, 0xFCFECFE9F8C084F7,
                                  0x0704050802010303, 0x0607020305020104},
                                 {0xFE97CDEEFFF7C7FC, 0xF8EEC0FCFEC0E989,
                                  0x0701020308040206, 0x0503020607020301}};

  struct TestCaseMsa2R tc_h[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0010001000100010, 0x0010001000100010},
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFEFFF8FFF5FFC3, 0xC85AFFE1FFFEFFFD,
                                  0x000F000D000C000A, 0x0002000B000F000E},
                                 {0xFFD9F99DFF87F120, 0xFFC2FFFCFFF0FF37,
                                  0x000A000500090004, 0x000A000E000C0008},
                                 {0xCCA7F81EFFB7FFCF, 0xFEBEF021ED40A9C9,
                                  0x000200050009000A, 0x0007000400030001}};

  struct TestCaseMsa2R tc_w[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0000002000000020, 0x0000002000000020},
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFAFFFFF83C, 0xFFFFEB51FFFF9563,
                                  0x0000001D00000015, 0x0000001300000011},
                                 {0xFFFF6C9DFFFEED20, 0xFFFC7F29FFC07437,
                                  0x000000100000000F, 0x0000000E0000000A},
                                 {0xECA79D1E81C7074F, 0xFF9E0021FC4019C9,
                                  0x0000000300000001, 0x0000000900000006}};

  struct TestCaseMsa2R tc_d[] = {
      // ws_lo, ws_hi, exp_res_lo, exp_res_hi
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x40, 0x40},
      {0x0000000000000000, 0x0000000000000000, 0, 0},
      {0xFFFFFFFFFFFFFEB1, 0xFFFFFFFFFFFE8925, 0x37, 0x2F},
      {0xFFFFFF9D3B17ED20, 0xFFFF9A2974C07437, 0x19, 0x11},
      {0xFFFFFFFF1CC7074F, 0xF8ABACB5354CD9AB, 0x20, 0x5}};

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseMsa2R); ++i) {
    run_msa_2r(&tc_b[i], [](MacroAssembler& assm) { __ nloc_b(w2, w0); });
    run_msa_2r(&tc_h[i], [](MacroAssembler& assm) { __ nloc_h(w2, w0); });
    run_msa_2r(&tc_w[i], [](MacroAssembler& assm) { __ nloc_w(w2, w0); });
    run_msa_2r(&tc_d[i], [](MacroAssembler& assm) { __ nloc_d(w2, w0); });
  }
}

struct TestCaseMsa2RF_F_U {
  float ws1;
  float ws2;
  float ws3;
  float ws4;
  uint32_t exp_res_1;
  uint32_t exp_res_2;
  uint32_t exp_res_3;
  uint32_t exp_res_4;
};

struct TestCaseMsa2RF_D_U {
  double ws1;
  double ws2;
  uint64_t exp_res_1;
  uint64_t exp_res_2;
};

TEST(MSA_fclass) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

#define BIT(n) (0x1 << n)
#define SNAN_BIT BIT(0)
#define QNAN_BIT BIT(1)
#define NEG_INFINITY_BIT BIT((2))
#define NEG_NORMAL_BIT BIT(3)
#define NEG_SUBNORMAL_BIT BIT(4)
#define NEG_ZERO_BIT BIT(5)
#define POS_INFINITY_BIT BIT(6)
#define POS_NORMAL_BIT BIT(7)
#define POS_SUBNORMAL_BIT BIT(8)
#define POS_ZERO_BIT BIT(9)

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa2RF_F_U tc_s[] = {
      {1.f, -0.00001, 208e10f, -34.8e-30f, POS_NORMAL_BIT, NEG_NORMAL_BIT,
       POS_NORMAL_BIT, NEG_NORMAL_BIT},
      {inf_float, -inf_float, 0, -0.f, POS_INFINITY_BIT, NEG_INFINITY_BIT,
       POS_ZERO_BIT, NEG_ZERO_BIT},
      {3.036e-40f, -6.392e-43f, 1.41e-45f, -1.17e-38f, POS_SUBNORMAL_BIT,
       NEG_SUBNORMAL_BIT, POS_SUBNORMAL_BIT, NEG_SUBNORMAL_BIT}};

  const struct TestCaseMsa2RF_D_U tc_d[] = {
      {1., -0.00000001, POS_NORMAL_BIT, NEG_NORMAL_BIT},
      {208e10, -34.8e-300, POS_NORMAL_BIT, NEG_NORMAL_BIT},
      {inf_double, -inf_double, POS_INFINITY_BIT, NEG_INFINITY_BIT},
      {0, -0., POS_ZERO_BIT, NEG_ZERO_BIT},
      {1.036e-308, -6.392e-309, POS_SUBNORMAL_BIT, NEG_SUBNORMAL_BIT},
      {1.41e-323, -3.17e208, POS_SUBNORMAL_BIT, NEG_NORMAL_BIT}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ fclass_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ fclass_d(w2, w0); });
  }

#undef BIT
#undef SNAN_BIT
#undef QNAN_BIT
#undef NEG_INFINITY_BIT
#undef NEG_NORMAL_BIT
#undef NEG_SUBNORMAL_BIT
#undef NEG_ZERO_BIT
#undef POS_INFINITY_BIT
#undef POS_NORMAL_BIT
#undef POS_SUBNORMAL_BIT
#undef POS_ZERO_BIT
}

struct TestCaseMsa2RF_F_I {
  float ws1;
  float ws2;
  float ws3;
  float ws4;
  int32_t exp_res_1;
  int32_t exp_res_2;
  int32_t exp_res_3;
  int32_t exp_res_4;
};

struct TestCaseMsa2RF_D_I {
  double ws1;
  double ws2;
  int64_t exp_res_1;
  int64_t exp_res_2;
};

TEST(MSA_ftrunc_s) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::Initi
"""


```