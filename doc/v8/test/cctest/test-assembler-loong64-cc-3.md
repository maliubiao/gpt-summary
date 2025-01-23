Response:
The user wants a summary of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite for the LoongArch64 architecture. The code tests the assembler by generating machine code snippets and verifying their behavior.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file name `test-assembler-loong64.cc` and the presence of `TEST` macros strongly suggest this is a unit test file for the LoongArch64 assembler within V8.

2. **Examine individual tests:** Go through each `TEST` block and understand what it's testing. Look for the assembly instructions being used (`__ Fld_d`, `__ ftint_w_d`, `__ jirl`, etc.) and the data structures involved (`struct Test`).

3. **Categorize the tests:** Group similar tests together to identify broader functionalities being tested. For instance, several tests (like `FTINT`, `FTINTRM`, `FTINTRP`, `FTINTRZ`, `FTINTRNE`) are clearly related to converting floating-point numbers to integers. Similarly, `FRINT` tests rounding of floating-point numbers.

4. **Look for patterns and common themes:** Notice the consistent structure of each test: setting up a `Test` struct, loading values into registers, performing assembler operations, storing results, and then `CHECK_EQ` assertions to verify the output.

5. **Check for .tq extension:** The prompt specifically asks about `.tq` files. The filename doesn't end in `.tq`, so this is a C++ test, not a Torque test.

6. **Relate to JavaScript (if applicable):** The instructions being tested are low-level operations. While they don't directly correspond to high-level JavaScript syntax, they are the building blocks of how JavaScript engines perform floating-point and integer arithmetic. Think about when a JavaScript program might need to convert a float to an integer (e.g., using `parseInt`, `Math.floor`, `Math.ceil`, bitwise operators).

7. **Identify code logic and potential inputs/outputs:** For each test, the `inputs_d` and `inputs_s` arrays define the input values, and the `outputs_*` arrays define the expected outputs. This allows for creating example input/output scenarios.

8. **Consider common programming errors:** Think about what mistakes developers might make when dealing with floating-point to integer conversions or using assembly-like operations. Loss of precision, incorrect rounding, and unexpected behavior with NaN/Infinity are common issues.

9. **Address the "part X of 5" instruction:** This indicates that the provided snippet is a portion of a larger file. The summary should acknowledge this and focus on the functionalities present in this specific part.

10. **Structure the response:** Organize the findings into clear sections addressing each part of the prompt: main function, .tq check, JavaScript relation, code logic/inputs/outputs, common errors, and the final summary.

11. **Refine and clarify:**  Review the generated response for clarity, accuracy, and completeness. Ensure the language is precise and easy to understand. For example, explicitly state that the tests are for the *assembler* and its instructions. Make the JavaScript examples relevant and easy to grasp.

By following these steps, we can generate a comprehensive and accurate summary of the provided C++ code snippet.
这是提供的v8源代码文件 `v8/test/cctest/test-assembler-loong64.cc` 的第四部分，它是一个C++文件，用于测试V8 JavaScript引擎在LoongArch64架构上的汇编器功能。

**功能归纳 (针对提供的代码片段):**

这部分代码主要测试了LoongArch64架构上浮点数和整数之间转换以及浮点数舍入相关的汇编指令。具体来说，它包含了以下几个方面的测试：

1. **浮点数到整数的转换指令 (`FTINT`, `FTINTRM`, `FTINTRP`, `FTINTRZ`, `FTINTRNE`)**:
   - 测试了将单精度浮点数 (`float`) 和双精度浮点数 (`double`) 转换为 32 位整数 (`int32_t`) 和 64 位整数 (`int64_t`) 的指令。
   - 针对不同的舍入模式 (由 `fcsr` 寄存器控制或指令本身指定，例如 `rm` - 向负无穷舍入, `rp` - 向正无穷舍入, `rz` - 向零舍入, `rne` - 向最近偶数舍入) 进行了测试。
   - 覆盖了正常数值、边界值 (如最大最小值)、以及特殊浮点数 (NaN, Infinity) 的转换。
   - 通过比较转换后的整数值与预期值来验证指令的正确性。

2. **浮点数舍入指令 (`FRINT`)**:
   - 测试了将单精度和双精度浮点数舍入到最接近的整数值的指令。
   - 同样针对不同的舍入模式 (由 `fcsr` 寄存器控制) 进行了测试，包括向最近偶数舍入、向零舍入、向正无穷舍入和向负无穷舍入。
   - 覆盖了各种浮点数值，包括大数、小数、接近整数的值以及特殊浮点数。

3. **浮点数移动指令 (`FMOV`)**:
   - 测试了浮点数寄存器之间的直接移动指令，用于单精度和双精度浮点数。
   - 验证了数据在移动后保持不变。

4. **浮点数寄存器与通用寄存器之间的数据传输指令 (`LA14`)**:
   - 测试了将浮点数寄存器的内容移动到通用寄存器的指令 (`movfr2gr_s`, `movfrh2gr_s`, `movfr2gr_d`)，以及将通用寄存器的内容移动到浮点数寄存器的指令 (`movgr2fr_w`, `movgr2frh_w`, `movgr2fr_d`)。
   - 这涉及到单精度浮点数的低 32 位和高 32 位，以及双精度浮点数的传输。

5. **条件分支指令 (`BCEQZ`, `BCNEZ`)**:
   - 测试了基于浮点条件码寄存器 (FCC) 的条件分支指令。
   - `BCEQZ` 在 FCC 为零时跳转，`BCNEZ` 在 FCC 非零时跳转。
   - 通过设置不同的 FCC 值和跳转偏移量，验证了分支逻辑的正确性。

6. **跳转表 (`jump_tables1`, `jump_tables2`, `jump_tables3`)**:
   - 测试了使用 PC 相对寻址实现的跳转表。
   - `jump_tables1` 测试向前跳转的情况。
   - `jump_tables2` 测试向后跳转的情况。
   - `jump_tables3` 类似于 `jump_tables2`，但其中嵌入了堆对象 (Heap Objects)，测试跳转表与垃圾回收堆的交互。

**关于其他问题:**

* **`.tq` 结尾:**  `v8/test/cctest/test-assembler-loong64.cc` 以 `.cc` 结尾，因此它是 C++ 源代码文件，而不是 Torque 源代码。

* **与 JavaScript 的关系:** 这些测试直接关系到 JavaScript 引擎在 LoongArch64 架构上执行数值计算的方式。当 JavaScript 代码执行涉及浮点数和整数之间的转换或浮点数舍入操作时，V8 引擎会生成相应的 LoongArch64 汇编指令。例如：
   ```javascript
   let floatValue = 3.14;
   let intValue = parseInt(floatValue); // JavaScript 的 parseInt 会调用底层的浮点数转整数的机制
   console.log(intValue); // 输出 3

   let roundedValue = Math.round(floatValue); // JavaScript 的 Math.round 会调用底层的浮点数舍入机制
   console.log(roundedValue); // 输出 3
   ```
   这些 C++ 测试确保了 V8 在 LoongArch64 平台上正确地实现了这些底层操作，从而保证了 JavaScript 代码的数值计算结果的准确性。

* **代码逻辑推理 (以 `FTINT` 测试为例):**
   - **假设输入:**
     - `test.a` (double): 3.1
     - `test.b` (float): 3.6
     - `test.fcsr` (int): `kRoundToNearest` (假设为 0，表示向最近偶数舍入)
   - **预期输出:**
     - `test.c` (int32_t): 3 (3.1 向最近偶数舍入为 3)
     - `test.d` (int32_t): 4 (3.6 向最近偶数舍入为 4)
     - `test.e` (int64_t): 3 (3.1 向最近偶数舍入为 3)
     - `test.f` (int64_t): 4 (3.6 向最近偶数舍入为 4)
   - 代码会先将 `test.fcsr` 加载到浮点控制状态寄存器，然后执行浮点数到整数的转换指令，并将结果存储回 `test` 结构体的相应字段，最后通过 `CHECK_EQ` 进行断言验证。

* **用户常见的编程错误 (与浮点数转整数相关):**
   ```javascript
   let x = 3.9;
   let y = parseInt(x); // 程序员可能期望得到 4，但 parseInt 会向下取整
   console.log(y); // 输出 3

   let z = parseFloat("not a number");
   let intZ = parseInt(z); // 对 NaN 进行转换，结果是 NaN，再转整数通常得到 0
   console.log(intZ); // 输出 NaN (在某些上下文中可能被转换为 0)

   let largeNumber = 9007199254740992.5; // 大于 JavaScript 安全整数范围的浮点数
   let intLarge = parseInt(largeNumber); // 转换可能丢失精度
   console.log(intLarge); // 输出 9007199254740992 (可能丢失小数部分后的值)
   ```
   这些错误通常源于对浮点数到整数转换的舍入规则、特殊值处理以及精度限制理解不足。

**总结:**

这是 V8 引擎中用于测试 LoongArch64 汇编器中浮点数和整数转换以及相关操作功能的一段 C++ 代码。它通过生成和执行包含特定汇编指令的代码片段，并断言其执行结果的正确性，来确保 V8 引擎在 LoongArch64 架构上能够正确地进行浮点数和整数之间的操作。这段代码是 V8 引擎质量保证的重要组成部分。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
st.ffint_d_l_in));

  test.ffint_s_w_in = std::numeric_limits<int32_t>::min();
  test.ffint_s_l_in = std::numeric_limits<int64_t>::min();
  test.ffint_d_w_in = std::numeric_limits<int32_t>::min();
  test.ffint_d_l_in = std::numeric_limits<int64_t>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.ffint_s_w_out, static_cast<float>(test.ffint_s_w_in));
  CHECK_EQ(test.ffint_s_l_out, static_cast<float>(test.ffint_s_l_in));
  CHECK_EQ(test.ffint_d_w_out, static_cast<double>(test.ffint_d_w_in));
  CHECK_EQ(test.ffint_d_l_out, static_cast<double>(test.ffint_d_l_in));
}

TEST(FTINT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
    int fcsr;
  };
  Test test;

  const int kTableLength = 9;
  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  double outputs_RN_W[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RN_L[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  double outputs_RZ_W[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RZ_L[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  double outputs_RP_W[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RP_L[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  double outputs_RM_W[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_RM_L[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  int fcsr_inputs[4] = {kRoundToNearest, kRoundToZero, kRoundToPlusInf,
                        kRoundToMinusInf};
  double* outputs[8] = {
      outputs_RN_W, outputs_RN_L, outputs_RZ_W, outputs_RZ_L,
      outputs_RP_W, outputs_RP_L, outputs_RM_W, outputs_RM_L,
  };

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ xor_(a5, a5, a5);
  __ Ld_w(a5, MemOperand(a0, offsetof(Test, fcsr)));
  __ movfcsr2gr(a4);
  __ movgr2fcsr(a5);
  __ ftint_w_d(f10, f8);
  __ ftint_w_s(f11, f9);
  __ ftint_l_d(f12, f8);
  __ ftint_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ movgr2fcsr(a4);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int j = 0; j < 4; j++) {
    test.fcsr = fcsr_inputs[j];
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_d[i];
      test.b = inputs_s[i];
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.c, outputs[2 * j][i]);
      CHECK_EQ(test.d, outputs[2 * j][i]);
      CHECK_EQ(test.e, outputs[2 * j + 1][i]);
      CHECK_EQ(test.f, outputs[2 * j + 1][i]);
    }
  }
}

TEST(FTINTRM) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      3.0, 3.0, 3.0, -4.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrm_w_d(f10, f8);
  __ ftintrm_w_s(f11, f9);
  __ ftintrm_l_d(f12, f8);
  __ ftintrm_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FTINTRP) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      4.0, 4.0, 4.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrp_w_d(f10, f8);
  __ ftintrp_w_s(f11, f9);
  __ ftintrp_l_d(f12, f8);
  __ ftintrp_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FTINTRZ) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      3.0, 3.0, 3.0, -3.0, -3.0, -3.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrz_w_d(f10, f8);
  __ ftintrz_w_s(f11, f9);
  __ ftintrz_l_d(f12, f8);
  __ ftintrz_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FTINTRNE) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    int32_t c;
    int32_t d;
    int64_t e;
    int64_t f;
  };
  Test test;

  const int kTableLength = 9;

  // clang-format off
  double inputs_d[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      3.1, 3.6, 3.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
  };
  double outputs_w[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};
  double outputs_l[kTableLength] = {
      3.0, 4.0, 4.0, -3.0, -4.0, -4.0,
      2147483648.0, 0,
      static_cast<double>(kFPU64InvalidResult)};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ ftintrne_w_d(f10, f8);
  __ ftintrne_w_s(f11, f9);
  __ ftintrne_l_d(f12, f8);
  __ ftintrne_l_s(f13, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(Test, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_d[i];
    test.b = inputs_s[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_w[i]);
    CHECK_EQ(test.d, outputs_w[i]);
    CHECK_EQ(test.e, outputs_l[i]);
    CHECK_EQ(test.f, outputs_l[i]);
  }
}

TEST(FRINT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    float b;
    double c;
    float d;
    int fcsr;
  };
  Test test;

  const int kTableLength = 32;

  // clang-format off
  double inputs_d[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E+308, 6.27463370218383111104242366943E-307,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max() - 0.1,
      std::numeric_limits<double>::infinity()
      };
  float inputs_s[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E+38, 6.27463370218383111104242366943E-37,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 0.6,
      std::numeric_limits<float>::infinity()
      };
  float outputs_RN_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
      };
  double outputs_RN_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  float outputs_RZ_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_RZ_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max() - 1,
      std::numeric_limits<double>::infinity()
  };
  float outputs_RP_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_RP_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  float outputs_RM_S[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_RM_D[kTableLength] = {
      18446744073709551617.0, 4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  // clang-format on

  int fcsr_inputs[4] = {kRoundToNearest, kRoundToZero, kRoundToPlusInf,
                        kRoundToMinusInf};
  double* outputs_d[4] = {outputs_RN_D, outputs_RZ_D, outputs_RP_D,
                          outputs_RM_D};
  float* outputs_s[4] = {outputs_RN_S, outputs_RZ_S, outputs_RP_S,
                         outputs_RM_S};

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(Test, b)));
  __ xor_(a5, a5, a5);
  __ Ld_w(a5, MemOperand(a0, offsetof(Test, fcsr)));
  __ movfcsr2gr(a4);
  __ movgr2fcsr(a5);
  __ frint_d(f10, f8);
  __ frint_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(Test, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(Test, d)));
  __ movgr2fcsr(a4);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int j = 0; j < 4; j++) {
    test.fcsr = fcsr_inputs[j];
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_d[i];
      test.b = inputs_s[i];
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.c, outputs_d[j][i]);
      CHECK_EQ(test.d, outputs_s[j][i]);
    }
  }
}

TEST(FMOV) {
  const int kTableLength = 7;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    float b;
    double c;
    float d;
  };

  TestFloat test;

  // clang-format off
  double inputs_D[kTableLength] = {
    5.3, -5.3, 0.29, -0.29, 0,
  std::numeric_limits<double>::max(),
  -std::numeric_limits<double>::max()
  };
  float inputs_S[kTableLength] = {
    4.8, -4.8, 0.29, -0.29, 0,
  std::numeric_limits<float>::max(),
  -std::numeric_limits<float>::max()
  };

  double outputs_D[kTableLength] = {
    5.3, -5.3, 0.29, -0.29, 0,
  std::numeric_limits<double>::max(),
  -std::numeric_limits<double>::max()
  };

  float outputs_S[kTableLength] = {
    4.8, -4.8, 0.29, -0.29, 0,
  std::numeric_limits<float>::max(),
  -std::numeric_limits<float>::max()
  };
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ fmov_d(f10, f8);
  __ fmov_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fst_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.b = inputs_S[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.c, outputs_D[i]);
    CHECK_EQ(test.d, outputs_S[i]);
  }
}

TEST(LA14) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    int64_t high;
    int64_t low;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Fld_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(T, b)));

  __ movfr2gr_s(a4, f8);
  __ movfrh2gr_s(a5, f8);
  __ movfr2gr_d(a6, f9);

  __ movgr2fr_w(f9, a4);
  __ movgr2frh_w(f9, a5);
  __ movgr2fr_d(f8, a6);

  __ Fst_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fst_d(f9, MemOperand(a0, offsetof(T, c)));

  __ Fld_d(f8, MemOperand(a0, offsetof(T, d)));
  __ movfrh2gr_s(a4, f8);
  __ movfr2gr_s(a5, f8);

  __ St_d(a4, MemOperand(a0, offsetof(T, high)));
  __ St_d(a5, MemOperand(a0, offsetof(T, low)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(2.75e11, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFC25001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFBF800000L), t.low);

  t.a = -1.5e22;
  t.b = -2.75e11;
  t.c = 17.17;
  t.d = 274999868928.0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(-2.75e11, t.a);
  CHECK_EQ(-2.75e11, t.b);
  CHECK_EQ(-1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0x425001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0x3F800000L), t.low);
}

uint64_t run_bceqz(int fcc_value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0);
  __ li(t0, fcc_value);
  __ b(&main_block);
  // Block 1
  for (int32_t i = -104; i <= -55; ++i) {
    __ addi_d(a2, a2, 0x1);
  }
  __ b(&L);

  // Block 2
  for (int32_t i = -53; i <= -4; ++i) {
    __ addi_d(a2, a2, 0x10);
  }
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ movcf2gr(t1, FCC0);
  __ movgr2cf(FCC0, t0);
  __ bceqz(FCC0, offset);
  __ bind(&L);
  __ movgr2cf(FCC0, t1);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  for (int32_t i = 4; i <= 53; ++i) {
    __ addi_d(a2, a2, 0x100);
  }
  __ b(&L);

  // Block 5
  for (int32_t i = 55; i <= 104; ++i) {
    __ addi_d(a2, a2, 0x300);
  }
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(BCEQZ) {
  CcTest::InitializeVM();
  struct TestCaseBceqz {
    int fcc;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBceqz tc[] = {
    // fcc, offset, expected_res
    {    0,    -90,         0x24 },
    {    0,    -27,        0x180 },
    {    0,     47,        0x700 },
    {    0,     70,       0x6900 },
    {    1,    -27,            0 },
    {    1,     47,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBceqz);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bceqz(tc[i].fcc, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bcnez(int fcc_value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0);
  __ li(t0, fcc_value);
  __ b(&main_block);
  // Block 1
  for (int32_t i = -104; i <= -55; ++i) {
    __ addi_d(a2, a2, 0x1);
  }
  __ b(&L);

  // Block 2
  for (int32_t i = -53; i <= -4; ++i) {
    __ addi_d(a2, a2, 0x10);
  }
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ movcf2gr(t1, FCC0);
  __ movgr2cf(FCC0, t0);
  __ bcnez(FCC0, offset);
  __ bind(&L);
  __ movgr2cf(FCC0, t1);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  for (int32_t i = 4; i <= 53; ++i) {
    __ addi_d(a2, a2, 0x100);
  }
  __ b(&L);

  // Block 5
  for (int32_t i = 55; i <= 104; ++i) {
    __ addi_d(a2, a2, 0x300);
  }
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(BCNEZ) {
  CcTest::InitializeVM();
  struct TestCaseBcnez {
    int fcc;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBcnez tc[] = {
    // fcc, offset, expected_res
    {    1,    -90,         0x24 },
    {    1,    -27,        0x180 },
    {    1,     47,        0x700 },
    {    1,     70,       0x6900 },
    {    0,    -27,            0 },
    {    0,     47,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBcnez);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bcnez(tc[i].fcc, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

TEST(jump_tables1) {
  // Test jump tables with forward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  __ addi_d(sp, sp, -8);
  __ St_d(ra, MemOperand(sp, 0));
  __ Align(8);

  Label done;
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
    __ pcaddi(ra, 2);
    __ slli_d(t7, a0, 3);
    __ add_d(t7, t7, ra);
    __ Ld_d(t7, MemOperand(t7, 4 * kInstrSize));
    __ jirl(zero_reg, t7, 0);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ lu12i_w(a2, (values[i] >> 12) & 0xFFFFF);
    __ ori(a2, a2, values[i] & 0xFFF);
    __ b(&done);
    __ nop();
  }

  __ bind(&done);
  __ Ld_d(ra, MemOperand(sp, 0));
  __ addi_d(sp, sp, 8);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CHECK_EQ(0, assm.UnboundLabelsCount());

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ((values[i]), static_cast<int>(res));
  }
}

TEST(jump_tables2) {
  // Test jump tables with backward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];

  __ addi_d(sp, sp, -8);
  __ St_d(ra, MemOperand(sp, 0));

  Label done, dispatch;
  __ b(&dispatch);
  __ nop();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ lu12i_w(a2, (values[i] >> 12) & 0xFFFFF);
    __ ori(a2, a2, values[i] & 0xFFF);
    __ b(&done);
    __ nop();
  }

  __ Align(8);
  __ bind(&dispatch);
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
    __ pcaddi(ra, 2);
    __ slli_d(t7, a0, 3);
    __ add_d(t7, t7, ra);
    __ Ld_d(t7, MemOperand(t7, 4 * kInstrSize));
    __ jirl(zero_reg, t7, 0);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  __ bind(&done);
  __ Ld_d(ra, MemOperand(sp, 0));
  __ addi_d(sp, sp, 8);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

TEST(jump_tables3) {
  // Test jump tables with backward jumps and embedded heap objects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumCases = 512;
  Handle<Object> values[kNumCases];
  for (int i = 0; i < kNumCases; ++i) {
    double value = isolate->random_number_generator()->NextDouble();
    values[i] = isolate->factory()->NewHeapNumber<AllocationType::kOld>(value);
  }
  Label labels[kNumCases];
  Tagged<Object> obj;
  int64_t imm64;

  __ addi_d(sp, sp, -8);
  __ St_d(ra, MemOperand(sp, 0));

  Label done, dispatch;
  __ b(&dispatch);
  __ nop();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    obj = *values[i];
    imm64 = obj.ptr();
    __ lu12i_w(a2, (imm64 >> 12) & 0xFFFFF);
    __ ori(a2, a2, imm64 & 0xFFF);
    __ lu32i_d(a2, (imm64 >> 32) & 0xFFFFF);
    __ lu52i_d(a2, a2, (imm64 >> 52) & 0xFFF);
    __ b(&done);
  }

  __ Align(8);
  __ bind(&dispatch);
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
    __ pcaddi(ra, 2);
    __ slli_d(t7, a0, 3);  // In delay slot.
    __ add_d(t7, t7, ra);
    __ Ld_d(t7, MemOperand(t7, 4 * kInstrSize));
    __ jirl(zero_reg, t7, 0);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }
  __ bind(&done);
  __ Ld_d(ra, MemOperand(sp, 0));
  __ addi_d(sp, sp, 8);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
```