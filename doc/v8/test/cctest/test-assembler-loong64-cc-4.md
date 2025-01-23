Response:
Let's break down the request and the provided C++ code to arrive at a comprehensive summary.

**1. Understanding the Goal:**

The primary goal is to analyze a specific V8 source code file (`v8/test/cctest/test-assembler-loong64.cc`) and describe its functionality. The request also includes specific instructions about how to present the information, like checking for `.tq` extension (Torque), Javascript relevance, code logic inference, common programming errors, and finally, a concise summary.

**2. Initial Code Scan - Identifying Key Elements:**

I scanned the provided code and immediately noticed the following:

* **File Name and Path:** `v8/test/cctest/test-assembler-loong64.cc`. This strongly suggests it's a testing file specifically for the LoongArch 64-bit architecture's assembler.
* **Includes:** Standard C++ headers like `<limits>`, `<cmath>`, `<cstring>`, and V8 internal headers. This confirms it's part of the V8 project and involves low-level operations.
* **`TEST()` Macros:**  These are clearly Google Test framework macros, indicating this file contains unit tests.
* **`CcTest::InitializeVM()`:** This function is called at the beginning of most tests, indicating initialization of the V8 test environment.
* **`Isolate* isolate = CcTest::i_isolate();`:**  Accessing the current V8 isolate, which is central to V8's architecture.
* **`HandleScope scope(isolate);`:** Managing V8's garbage collection by creating a scope for handles.
* **`MacroAssembler assm(isolate, ...);`  and `Assembler assm(...);`:**  The core component! This is where LoongArch64 assembly instructions are being generated.
* **Assembly Instructions:**  A plethora of LoongArch64 assembly mnemonics like `li`, `or_`, `jirl`, `addi_d`, `Fld_d`, `fmin_d`, `fadd_s`, etc.
* **Helper Functions:** `run_li_macro` which seems to test the `li` (load immediate) macro.
* **Test Structures:**  `TestCase_li`, `TestFloat`, `TestCaseMaddMsub` are used to structure test inputs and expected outputs.
* **Floating-Point Tests:**  Significant portions of the code are dedicated to testing floating-point instructions (`FMIN_FMAX`, `FMINA_FMAXA`, `FADD`, `FSUB`, `FMUL`, `FDIV`, `FABS`, `FMADD_FMSUB_FNMADD_FNMSUB`).
* **Specific Test Cases:** The tests cover various input ranges, including edge cases, NaN, and infinity for floating-point numbers.
* **Code Generation and Execution:**  The tests generate machine code, execute it using `GeneratedCode`, and then compare the results.
* **Assertions (`CHECK_EQ`, `CHECK`, `CHECK(std::isnan(...))`)**:  Used to verify the correctness of the generated code.

**3. Answering Specific Instructions (Mental Walkthrough):**

* **Functionality:** The core function is clearly testing the LoongArch64 assembler implementation in V8. It verifies the correctness of individual assembly instructions and macros.
* **`.tq` Extension:**  The filename doesn't end with `.tq`, so it's not a Torque file.
* **Javascript Relationship:** Since it's testing the assembler (the code generator), it indirectly relates to Javascript. When V8 compiles Javascript, it often generates machine code using the assembler. I need to think of a simple Javascript example that would eventually lead to assembler instructions being used.
* **Code Logic Inference:**  The `run_li_macro` function is a good candidate. I can trace how different immediate values are handled by the `li` macro and how many instructions are generated. I should consider edge cases and the different `LiFlags`.
* **Common Programming Errors:**  Think about errors related to assembly programming, like incorrect immediate values, wrong register usage (although the tests are structured to avoid these directly in the *test code* itself, it's testing the *assembler's ability* to handle valid and potentially edge-case scenarios). Perhaps errors in understanding instruction behavior or compiler bugs.
* **Part Number:** This is part 5 of 5, implying it's the final summary, so I need to synthesize the information from the previous points.

**4. Structuring the Output:**

Based on the instructions, the output needs to be structured as follows:

* **Functionality:** Start with a high-level description.
* **Torque:** Clearly state it's not a Torque file.
* **Javascript Example:**  Provide a simple Javascript snippet and explain its connection.
* **Code Logic Inference:** Focus on `run_li_macro` with input/output examples.
* **Common Programming Errors:** Give examples in the *context of using an assembler or understanding assembly instructions*.
* **Summary:**  A concise overview of the file's purpose.

**5. Refining the Details (Pre-computation/Analysis):**

* **Javascript Example:** A simple arithmetic operation will suffice. `let a = 1 + 2;`  This will involve loading constants and an addition operation, which the assembler handles.
* **`run_li_macro` Inference:**  Look at the `TestCase_li` structure. Select a few cases and mentally trace how the `li` macro would handle them (e.g., small immediate uses `addi_d`, larger ones use `lu12i_w` and `ori`, etc.). Define some specific input `imm` values and the expected generated instructions (`num_instr`).
* **Common Errors:**  Focus on the *developer using the assembler* and potential pitfalls.

**6. Final Output Generation (Putting it all together):**

Now, based on the analysis and pre-computation, I can generate the final response, ensuring it addresses all parts of the request and is well-organized and clear. I will use the insights gained from analyzing the code and the mental walkthrough to formulate precise and informative answers.
```cpp
auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    Handle<Object> result(
        Tagged<Object>(reinterpret_cast<Address>(f.Call(i, 0, 0, 0, 0))),
        isolate);
#ifdef OBJECT_PRINT
    ::printf("f(%d) = ", i);
    Print(*result);
    ::printf("\n");
#endif
    CHECK(values[i].is_identical_to(result));
  }
}

uint64_t run_li_macro(int64_t imm, LiFlags mode, int32_t num_instr = 0) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ li(a2, imm, mode);
  if (num_instr > 0) {
    CHECK_EQ(assm.InstructionsGeneratedSince(&code_start), num_instr);
    CHECK_EQ(__ InstrCountForLi64Bit(imm), num_instr);
  }
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(li_macro) {
  CcTest::InitializeVM();

  // Test li macro-instruction for border cases.

  struct TestCase_li {
    uint64_t imm;
    int32_t num_instr;
  };
  // clang-format off
  struct TestCase_li tc[] = {
      //              imm, num_instr
      {0xFFFFFFFFFFFFF800,         1},  // min_int12
      // The test case above generates addi_d instruction.
      // This is int12 value and we can load it using just addi_d.
      {             0x800,         1},  // max_int12 + 1
      // Generates ori
      // max_int12 + 1 is not int12 but is uint12, just use ori.
      {0xFFFFFFFFFFFFF7FF,         2},  // min_int12 - 1
      // Generates lu12i + ori
      // We load int32 value using lu12i_w + ori.
      {             0x801,         1},  // max_int12 + 2
      // Generates ori
      // Also an uint1 value, use ori.
      {        0x00001000,         1},  // max_uint12 + 1
      // Generates lu12i_w
      // Low 12 bits are 0, load value using lu12i_w.
      {        0x00001001,         2},  // max_uint12 + 2
      // Generates lu12i_w + ori
      // We have to generate two instructions in this case.
      {0x00000000FFFFFFFF,         2},  // max_uint32
      // addi_w + lu32i_d
      {0x00000000FFFFFFFE,         2},  // max_uint32 - 1
      // addi_w + lu32i_d
      {0xFFFFFFFF80000000,         1},  // min_int32
      // lu12i_w
      {0x0000000080000000,         2},  // max_int32 + 1
      // lu12i_w + lu32i_d
      {0xFFFF0000FFFF8765,         3},
      // lu12i_w + ori + lu32i_d
      {0x1234ABCD87654321,         4},
      // lu12i_w + ori + lu32i_d + lu52i_d
      {0xFFFF789100000000,         2},
      // xor + lu32i_d
      {0xF12F789100000000,         3},
      // xor + lu32i_d + lu52i_d
      {0xF120000000000800,         2},
      // ori + lu52i_d
      {0xFFF0000000000000,         1},
      // lu52i_d
      {0xF100000000000000,         1},
      {0x0122000000000000,         2},
      {0x1234FFFF77654321,         4},
      {0x1230000077654321,         3},
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCase_li);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].imm,
             run_li_macro(tc[i].imm, OPTIMIZE_SIZE, tc[i].num_instr));
    CHECK_EQ(tc[i].imm, run_li_macro(tc[i].imm, CONSTANT_SIZE));
    if (is_int48(tc[i].imm)) {
      CHECK_EQ(tc[i].imm, run_li_macro(tc[i].imm, ADDRESS_LOAD));
    }
  }
}

TEST(FMIN_FMAX) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    double b;
    float c;
    float d;
    double e;
    double f;
    float g;
    float h;
  };

  TestFloat test;
  const double dnan = std::numeric_limits<double>::quiet_NaN();
  const double dinf = std::numeric_limits<double>::infinity();
  const double dminf = -std::numeric_limits<double>::infinity();
  const float fnan = std::numeric_limits<float>::quiet_NaN();
  const float finf = std::numeric_limits<float>::infinity();
  const float fminf = -std::numeric_limits<float>::infinity();
  const int kTableLength = 13;

  // clang-format off
  double inputsa[kTableLength] = {2.0,  3.0,  dnan, 3.0,   -0.0, 0.0, dinf,
                                  dnan, 42.0, dinf, dminf, dinf, dnan};
  double inputsb[kTableLength] = {3.0,  2.0,  3.0,  dnan, 0.0,   -0.0, dnan,
                                  dinf, dinf, 42.0, dinf, dminf, dnan};
  double outputsdmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                      -0.0,  dinf,  dinf, 42.0, 42.0,
                                      dminf, dminf, dnan};
  double outputsdmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, dinf,
                                      dinf, dinf, dinf, dinf, dinf, dnan};

  float inputsc[kTableLength] = {2.0,  3.0,  fnan, 3.0,   -0.0, 0.0, finf,
                                 fnan, 42.0, finf, fminf, finf, fnan};
  float inputsd[kTableLength] = {3.0,  2.0,  3.0,  fnan, 0.0,   -0.0, fnan,
                                 finf, finf, 42.0, finf, fminf, fnan};
  float outputsfmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                     -0.0,  finf,  finf, 42.0, 42.0,
                                     fminf, fminf, fnan};
  float outputsfmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, finf,
                                     finf, finf, finf, finf, finf, fnan};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fmin_d(f12, f8, f9);
  __ fmax_d(f13, f8, f9);
  __ fmin_s(f14, f10, f11);
  __ fmax_s(f15, f10, f11);
  __ Fst_d(f12, MemOperand(a0, offsetof(TestFloat, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, f)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, g)));
  __ Fst_s(f15, MemOperand(a0, offsetof(TestFloat, h)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 4; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.c = inputsc[i];
    test.d = inputsd[i];

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(0, memcmp(&test.e, &outputsdmin[i], sizeof(test.e)));
    CHECK_EQ(0, memcmp(&test.f, &outputsdmax[i], sizeof(test.f)));
    CHECK_EQ(0, memcmp(&test.g, &outputsfmin[i], sizeof(test.g)));
    CHECK_EQ(0, memcmp(&test.h, &outputsfmax[i], sizeof(test.h)));
  }
}

TEST(FMINA_FMAXA) {
  const int kTableLength = 23;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  const double dnan = std::numeric_limits<double>::quiet_NaN();
  const double dinf = std::numeric_limits<double>::infinity();
  const double dminf = -std::numeric_limits<double>::infinity();
  const float fnan = std::numeric_limits<float>::quiet_NaN();
  const float finf = std::numeric_limits<float>::infinity();
  const float fminf = std::numeric_limits<float>::infinity();

  struct TestFloat {
    double a;
    double b;
    double resd1;
    double resd2;
    float c;
    float d;
    float resf1;
    float resf2;
  };

  TestFloat test;
  // clang-format off
  double inputsa[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
    dnan, 3.0, -0.0, 0.0, dinf, dnan, 42.0,  dinf, dminf, dinf,  dnan};
  double inputsb[kTableLength] = {
        4.8, 5.3,  6.1, -10.0, -8.9, -9.8, 9.8,  9.8,  9.8,  -9.8,  -11.2, -9.8,
    3.0, dnan, 0.0, -0.0,  dnan, dinf, dinf, 42.0, dinf, dminf, dnan};
  double resd1[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
    3.0, 3.0, -0.0, -0.0, dinf, dinf, 42.0, 42.0, dminf, dminf, dnan};
  double resd2[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
    3.0, 3.0, 0.0, 0.0,   dinf, dinf, dinf,  dinf, dinf, dinf,  dnan};
  float inputsc[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
    fnan, 3.0, -0.0, 0.0, finf, fnan, 42.0,  finf, fminf, finf,  fnan};
  float inputsd[kTableLength] = {
        4.8,  5.3,  6.1, -10.0, -8.9,  -9.8, 9.8, 9.8, 9.8,  -9.8, -11.2, -9.8,
    3.0,  fnan, -0.0, 0.0, fnan, finf, finf, 42.0, finf, fminf, fnan};
  float resf1[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
    3.0, 3.0, -0.0, -0.0, finf, finf, 42.0, 42.0, fminf, fminf, fnan};
  float resf2[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
    3.0, 3.0, 0.0, 0.0,   finf, finf, finf,  finf, finf, finf,  fnan};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fmina_d(f12, f8, f9);
  __ fmaxa_d(f13, f8, f9);
  __ fmina_s(f14, f10, f11);
  __ fmaxa_s(f15, f10, f11);
  __ Fst_d(f12, MemOperand(a0, offsetof(TestFloat, resd1)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, resd2)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, resf1)));
  __ Fst_s(f15, MemOperand(a0, offsetof(TestFloat, resf2)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.c = inputsc[i];
    test.d = inputsd[i];
    f.Call(&test, 0, 0, 0, 0);
    if (i < kTableLength - 1) {
      CHECK_EQ(test.resd1, resd1[i]);
      CHECK_EQ(test.resd2, resd2[i]);
      CHECK_EQ(test.resf1, resf1[i]);
      CHECK_EQ(test.resf2, resf2[i]);
    } else {
      CHECK(std::isnan(test.resd1));
      CHECK(std::isnan(test.resd2));
      CHECK(std::isnan(test.resf1));
      CHECK(std::isnan(test.resf2));
    }
  }
}

TEST(FADD) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    double b;
    double c;
    float d;
    float e;
    float f;
  };

  TestFloat test;

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ fadd_d(f10, f8, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, c)));

  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ Fld_s(f12, MemOperand(a0, offsetof(TestFloat, e)));
  __ fadd_s(f13, f11, f12);
  __ Fst_s(f13, MemOperand(a0, offsetof(TestFloat, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.a = 2.0;
  test.b = 3.0;
  test.d = 2.0;
  test.e = 3.0;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.c, 5.0);
  CHECK_EQ(test.f, 5.0);

  test.a = std::numeric_limits<double>::max();
  test.b = -std::numeric_limits<double>::max();  // lowest()
  test.d = std::numeric_limits<float>::max();
  test.e = -std::numeric_limits<float>::max();  // lowest()
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.c, 0.0);
  CHECK_EQ(test.f, 0.0);

  test.a = std::numeric_limits<double>::max();
  test.b = std::numeric_limits<double>::max();
  test.d = std::numeric_limits<float>::max();
  test.e = std::numeric_limits<float>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(!std::isfinite(test.c));
  CHECK(!std::isfinite(test.f));

  test.a = 5.0;
  test.b = std::numeric_limits<double>::signaling_NaN();
  test.d = 5.0;
  test.e = std::numeric_limits<float>::signaling_NaN();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.c));
  CHECK(std::isnan(test.f));
}

TEST(FSUB) {
  const int kTableLength = 12;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float a;
    float b;
    float resultS;
    double c;
    double d;
    double resultD;
  };

  TestFloat test;

  // clang-format off
  double inputfs_D[kTableLength] = {
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9,
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9
  };
  double inputft_D[kTableLength] = {
    4.8, 5.3, 2.9, 4.8, 5.3, 2.9,
    -4.8, -5.3, -2.9, -4.8, -5.3, -2.9
  };
  double outputs_D[kTableLength] = {
    0.5, -0.5, 0.0, -10.1, -10.1, -5.8,
    10.1, 10.1, 5.8, -0.5, 0.5, 0.0
  };
  float inputfs_S[kTableLength] = {
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9,
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9
  };
  float inputft_S[kTableLength] = {
    4.8, 5.3, 2.9, 4.8, 5.3, 2.9,
    -4.8, -5.3, -2.9, -4.8, -5.3, -2.9
  };
  float outputs_S[kTableLength] = {
    0.5, -0.5, 0.0, -10.1, -10.1, -5.8,
    10.1, 10.1, 5.8, -0.5, 0.5, 0.0
  };
  // clang-format on

  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_d(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_d(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fsub_s(f12, f8, f9);
  __ fsub_d(f13, f10, f11);
  __ Fst_s(f12, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputfs_S[i];
    test.b = inputft_S[i];
    test.c = inputfs_D[i];
    test.d = inputft_D[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.resultS, outputs_S[i]);
    CHECK_EQ(test.resultD, outputs_D[i]);
  }
}

TEST(FMUL) {
  const int kTableLength = 4;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float a;
    float b;
    float resultS;
    double c;
    double d;
    double resultD;
  };

  TestFloat test;
  // clang-format off
  double inputfs_D[kTableLength] = {
    5.3, -5.3, 5.3, -2.9
  };
  double inputft_D[kTableLength] = {
    4.8, 4.8, -4.8, -0.29
  };

  float inputfs_S[kTableLength] = {
    5.3, -5.3, 5.
### 提示词
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kNumCases; ++i) {
    Handle<Object> result(
        Tagged<Object>(reinterpret_cast<Address>(f.Call(i, 0, 0, 0, 0))),
        isolate);
#ifdef OBJECT_PRINT
    ::printf("f(%d) = ", i);
    Print(*result);
    ::printf("\n");
#endif
    CHECK(values[i].is_identical_to(result));
  }
}

uint64_t run_li_macro(int64_t imm, LiFlags mode, int32_t num_instr = 0) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ li(a2, imm, mode);
  if (num_instr > 0) {
    CHECK_EQ(assm.InstructionsGeneratedSince(&code_start), num_instr);
    CHECK_EQ(__ InstrCountForLi64Bit(imm), num_instr);
  }
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(li_macro) {
  CcTest::InitializeVM();

  // Test li macro-instruction for border cases.

  struct TestCase_li {
    uint64_t imm;
    int32_t num_instr;
  };
  // clang-format off
  struct TestCase_li tc[] = {
      //              imm, num_instr
      {0xFFFFFFFFFFFFF800,         1},  // min_int12
      // The test case above generates addi_d instruction.
      // This is int12 value and we can load it using just addi_d.
      {             0x800,         1},  // max_int12 + 1
      // Generates ori
      // max_int12 + 1 is not int12 but is uint12, just use ori.
      {0xFFFFFFFFFFFFF7FF,         2},  // min_int12 - 1
      // Generates lu12i + ori
      // We load int32 value using lu12i_w + ori.
      {             0x801,         1},  // max_int12 + 2
      // Generates ori
      // Also an uint1 value, use ori.
      {        0x00001000,         1},  // max_uint12 + 1
      // Generates lu12i_w
      // Low 12 bits are 0, load value using lu12i_w.
      {        0x00001001,         2},  // max_uint12 + 2
      // Generates lu12i_w + ori
      // We have to generate two instructions in this case.
      {0x00000000FFFFFFFF,         2},  // max_uint32
      // addi_w + lu32i_d
      {0x00000000FFFFFFFE,         2},  // max_uint32 - 1
      // addi_w + lu32i_d
      {0xFFFFFFFF80000000,         1},  // min_int32
      // lu12i_w
      {0x0000000080000000,         2},  // max_int32 + 1
      // lu12i_w + lu32i_d
      {0xFFFF0000FFFF8765,         3},
      // lu12i_w + ori + lu32i_d
      {0x1234ABCD87654321,         4},
      // lu12i_w + ori + lu32i_d + lu52i_d
      {0xFFFF789100000000,         2},
      // xor + lu32i_d
      {0xF12F789100000000,         3},
      // xor + lu32i_d + lu52i_d
      {0xF120000000000800,         2},
      // ori + lu52i_d
      {0xFFF0000000000000,         1},
      // lu52i_d
      {0xF100000000000000,         1},
      {0x0122000000000000,         2},
      {0x1234FFFF77654321,         4},
      {0x1230000077654321,         3},
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCase_li);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].imm,
             run_li_macro(tc[i].imm, OPTIMIZE_SIZE, tc[i].num_instr));
    CHECK_EQ(tc[i].imm, run_li_macro(tc[i].imm, CONSTANT_SIZE));
    if (is_int48(tc[i].imm)) {
      CHECK_EQ(tc[i].imm, run_li_macro(tc[i].imm, ADDRESS_LOAD));
    }
  }
}

TEST(FMIN_FMAX) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    double b;
    float c;
    float d;
    double e;
    double f;
    float g;
    float h;
  };

  TestFloat test;
  const double dnan = std::numeric_limits<double>::quiet_NaN();
  const double dinf = std::numeric_limits<double>::infinity();
  const double dminf = -std::numeric_limits<double>::infinity();
  const float fnan = std::numeric_limits<float>::quiet_NaN();
  const float finf = std::numeric_limits<float>::infinity();
  const float fminf = -std::numeric_limits<float>::infinity();
  const int kTableLength = 13;

  // clang-format off
  double inputsa[kTableLength] = {2.0,  3.0,  dnan, 3.0,   -0.0, 0.0, dinf,
                                  dnan, 42.0, dinf, dminf, dinf, dnan};
  double inputsb[kTableLength] = {3.0,  2.0,  3.0,  dnan, 0.0,   -0.0, dnan,
                                  dinf, dinf, 42.0, dinf, dminf, dnan};
  double outputsdmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                      -0.0,  dinf,  dinf, 42.0, 42.0,
                                      dminf, dminf, dnan};
  double outputsdmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, dinf,
                                      dinf, dinf, dinf, dinf, dinf, dnan};

  float inputsc[kTableLength] = {2.0,  3.0,  fnan, 3.0,   -0.0, 0.0, finf,
                                 fnan, 42.0, finf, fminf, finf, fnan};
  float inputsd[kTableLength] = {3.0,  2.0,  3.0,  fnan, 0.0,   -0.0, fnan,
                                 finf, finf, 42.0, finf, fminf, fnan};
  float outputsfmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                     -0.0,  finf,  finf, 42.0, 42.0,
                                     fminf, fminf, fnan};
  float outputsfmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, finf,
                                     finf, finf, finf, finf, finf, fnan};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fmin_d(f12, f8, f9);
  __ fmax_d(f13, f8, f9);
  __ fmin_s(f14, f10, f11);
  __ fmax_s(f15, f10, f11);
  __ Fst_d(f12, MemOperand(a0, offsetof(TestFloat, e)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, f)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, g)));
  __ Fst_s(f15, MemOperand(a0, offsetof(TestFloat, h)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 4; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.c = inputsc[i];
    test.d = inputsd[i];

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(0, memcmp(&test.e, &outputsdmin[i], sizeof(test.e)));
    CHECK_EQ(0, memcmp(&test.f, &outputsdmax[i], sizeof(test.f)));
    CHECK_EQ(0, memcmp(&test.g, &outputsfmin[i], sizeof(test.g)));
    CHECK_EQ(0, memcmp(&test.h, &outputsfmax[i], sizeof(test.h)));
  }
}

TEST(FMINA_FMAXA) {
  const int kTableLength = 23;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  const double dnan = std::numeric_limits<double>::quiet_NaN();
  const double dinf = std::numeric_limits<double>::infinity();
  const double dminf = -std::numeric_limits<double>::infinity();
  const float fnan = std::numeric_limits<float>::quiet_NaN();
  const float finf = std::numeric_limits<float>::infinity();
  const float fminf = std::numeric_limits<float>::infinity();

  struct TestFloat {
    double a;
    double b;
    double resd1;
    double resd2;
    float c;
    float d;
    float resf1;
    float resf2;
  };

  TestFloat test;
  // clang-format off
  double inputsa[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
    dnan, 3.0, -0.0, 0.0, dinf, dnan, 42.0,  dinf, dminf, dinf,  dnan};
  double inputsb[kTableLength] = {
        4.8, 5.3,  6.1, -10.0, -8.9, -9.8, 9.8,  9.8,  9.8,  -9.8,  -11.2, -9.8,
    3.0, dnan, 0.0, -0.0,  dnan, dinf, dinf, 42.0, dinf, dminf, dnan};
  double resd1[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
    3.0, 3.0, -0.0, -0.0, dinf, dinf, 42.0, 42.0, dminf, dminf, dnan};
  double resd2[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
    3.0, 3.0, 0.0, 0.0,   dinf, dinf, dinf,  dinf, dinf, dinf,  dnan};
  float inputsc[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
    fnan, 3.0, -0.0, 0.0, finf, fnan, 42.0,  finf, fminf, finf,  fnan};
  float inputsd[kTableLength] = {
        4.8,  5.3,  6.1, -10.0, -8.9,  -9.8, 9.8, 9.8, 9.8,  -9.8, -11.2, -9.8,
    3.0,  fnan, -0.0, 0.0, fnan, finf, finf, 42.0, finf, fminf, fnan};
  float resf1[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
    3.0, 3.0, -0.0, -0.0, finf, finf, 42.0, 42.0, fminf, fminf, fnan};
  float resf2[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
    3.0, 3.0, 0.0, 0.0,   finf, finf, finf,  finf, finf, finf,  fnan};
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fmina_d(f12, f8, f9);
  __ fmaxa_d(f13, f8, f9);
  __ fmina_s(f14, f10, f11);
  __ fmaxa_s(f15, f10, f11);
  __ Fst_d(f12, MemOperand(a0, offsetof(TestFloat, resd1)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, resd2)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, resf1)));
  __ Fst_s(f15, MemOperand(a0, offsetof(TestFloat, resf2)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.c = inputsc[i];
    test.d = inputsd[i];
    f.Call(&test, 0, 0, 0, 0);
    if (i < kTableLength - 1) {
      CHECK_EQ(test.resd1, resd1[i]);
      CHECK_EQ(test.resd2, resd2[i]);
      CHECK_EQ(test.resf1, resf1[i]);
      CHECK_EQ(test.resf2, resf2[i]);
    } else {
      CHECK(std::isnan(test.resd1));
      CHECK(std::isnan(test.resd2));
      CHECK(std::isnan(test.resf1));
      CHECK(std::isnan(test.resf2));
    }
  }
}

TEST(FADD) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    double b;
    double c;
    float d;
    float e;
    float f;
  };

  TestFloat test;

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ fadd_d(f10, f8, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, c)));

  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ Fld_s(f12, MemOperand(a0, offsetof(TestFloat, e)));
  __ fadd_s(f13, f11, f12);
  __ Fst_s(f13, MemOperand(a0, offsetof(TestFloat, f)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.a = 2.0;
  test.b = 3.0;
  test.d = 2.0;
  test.e = 3.0;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.c, 5.0);
  CHECK_EQ(test.f, 5.0);

  test.a = std::numeric_limits<double>::max();
  test.b = -std::numeric_limits<double>::max();  // lowest()
  test.d = std::numeric_limits<float>::max();
  test.e = -std::numeric_limits<float>::max();  // lowest()
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.c, 0.0);
  CHECK_EQ(test.f, 0.0);

  test.a = std::numeric_limits<double>::max();
  test.b = std::numeric_limits<double>::max();
  test.d = std::numeric_limits<float>::max();
  test.e = std::numeric_limits<float>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(!std::isfinite(test.c));
  CHECK(!std::isfinite(test.f));

  test.a = 5.0;
  test.b = std::numeric_limits<double>::signaling_NaN();
  test.d = 5.0;
  test.e = std::numeric_limits<float>::signaling_NaN();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.c));
  CHECK(std::isnan(test.f));
}

TEST(FSUB) {
  const int kTableLength = 12;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float a;
    float b;
    float resultS;
    double c;
    double d;
    double resultD;
  };

  TestFloat test;

  // clang-format off
  double inputfs_D[kTableLength] = {
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9,
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9
  };
  double inputft_D[kTableLength] = {
    4.8, 5.3, 2.9, 4.8, 5.3, 2.9,
    -4.8, -5.3, -2.9, -4.8, -5.3, -2.9
  };
  double outputs_D[kTableLength] = {
    0.5, -0.5, 0.0, -10.1, -10.1, -5.8,
    10.1, 10.1, 5.8, -0.5, 0.5, 0.0
  };
  float inputfs_S[kTableLength] = {
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9,
    5.3, 4.8, 2.9, -5.3, -4.8, -2.9
  };
  float inputft_S[kTableLength] = {
    4.8, 5.3, 2.9, 4.8, 5.3, 2.9,
    -4.8, -5.3, -2.9, -4.8, -5.3, -2.9
  };
  float outputs_S[kTableLength] = {
    0.5, -0.5, 0.0, -10.1, -10.1, -5.8,
    10.1, 10.1, 5.8, -0.5, 0.5, 0.0
  };
  // clang-format on

  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_d(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_d(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fsub_s(f12, f8, f9);
  __ fsub_d(f13, f10, f11);
  __ Fst_s(f12, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputfs_S[i];
    test.b = inputft_S[i];
    test.c = inputfs_D[i];
    test.d = inputft_D[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.resultS, outputs_S[i]);
    CHECK_EQ(test.resultD, outputs_D[i]);
  }
}

TEST(FMUL) {
  const int kTableLength = 4;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float a;
    float b;
    float resultS;
    double c;
    double d;
    double resultD;
  };

  TestFloat test;
  // clang-format off
  double inputfs_D[kTableLength] = {
    5.3, -5.3, 5.3, -2.9
  };
  double inputft_D[kTableLength] = {
    4.8, 4.8, -4.8, -0.29
  };

  float inputfs_S[kTableLength] = {
    5.3, -5.3, 5.3, -2.9
  };
  float inputft_S[kTableLength] = {
    4.8, 4.8, -4.8, -0.29
  };
  // clang-format on
  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_d(f10, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fld_d(f11, MemOperand(a0, offsetof(TestFloat, d)));
  __ fmul_s(f12, f8, f9);
  __ fmul_d(f13, f10, f11);
  __ Fst_s(f12, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputfs_S[i];
    test.b = inputft_S[i];
    test.c = inputfs_D[i];
    test.d = inputft_D[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.resultS, inputfs_S[i] * inputft_S[i]);
    CHECK_EQ(test.resultD, inputfs_D[i] * inputft_D[i]);
  }
}

TEST(FDIV) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double dOp1;
    double dOp2;
    double dRes;
    float fOp1;
    float fOp2;
    float fRes;
  };

  Test test;

  __ movfcsr2gr(a4);
  __ movgr2fcsr(zero_reg);

  __ Fld_d(f8, MemOperand(a0, offsetof(Test, dOp1)));
  __ Fld_d(f9, MemOperand(a0, offsetof(Test, dOp2)));
  __ Fld_s(f10, MemOperand(a0, offsetof(Test, fOp1)));
  __ Fld_s(f11, MemOperand(a0, offsetof(Test, fOp2)));
  __ fdiv_d(f12, f8, f9);
  __ fdiv_s(f13, f10, f11);
  __ Fst_d(f12, MemOperand(a0, offsetof(Test, dRes)));
  __ Fst_s(f13, MemOperand(a0, offsetof(Test, fRes)));

  __ movgr2fcsr(a4);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  f.Call(&test, 0, 0, 0, 0);
  const int test_size = 3;
  // clang-format off
  double dOp1[test_size] = {
    5.0,  DBL_MAX,  DBL_MAX};

  double dOp2[test_size] = {
    2.0,  2.0,  -DBL_MAX};

  double dRes[test_size] = {
    2.5,  DBL_MAX / 2.0,  -1.0};

  float fOp1[test_size] = {
    5.0,  FLT_MAX,  FLT_MAX};

  float fOp2[test_size] = {
    2.0,  2.0,  -FLT_MAX};

  float fRes[test_size] = {
    2.5,  FLT_MAX / 2.0,  -1.0};
  // clang-format on

  for (int i = 0; i < test_size; i++) {
    test.dOp1 = dOp1[i];
    test.dOp2 = dOp2[i];
    test.fOp1 = fOp1[i];
    test.fOp2 = fOp2[i];

    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.dRes, dRes[i]);
    CHECK_EQ(test.fRes, fRes[i]);
  }

  test.dOp1 = DBL_MAX;
  test.dOp2 = -0.0;
  test.fOp1 = FLT_MAX;
  test.fOp2 = -0.0;

  f.Call(&test, 0, 0, 0, 0);
  CHECK(!std::isfinite(test.dRes));
  CHECK(!std::isfinite(test.fRes));

  test.dOp1 = 0.0;
  test.dOp2 = -0.0;
  test.fOp1 = 0.0;
  test.fOp2 = -0.0;

  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.dRes));
  CHECK(std::isnan(test.fRes));

  test.dOp1 = std::numeric_limits<double>::quiet_NaN();
  test.dOp2 = -5.0;
  test.fOp1 = std::numeric_limits<float>::quiet_NaN();
  test.fOp2 = -5.0;

  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.dRes));
  CHECK(std::isnan(test.fRes));
}

TEST(FABS) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    float b;
  };

  TestFloat test;

  __ movfcsr2gr(a4);
  __ movgr2fcsr(zero_reg);

  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ fabs_d(f10, f8);
  __ fabs_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fst_s(f11, MemOperand(a0, offsetof(TestFloat, b)));

  __ movgr2fcsr(a4);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.a = -2.0;
  test.b = -2.0;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, 2.0);
  CHECK_EQ(test.b, 2.0);

  test.a = 2.0;
  test.b = 2.0;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, 2.0);
  CHECK_EQ(test.b, 2.0);

  // Testing biggest positive number
  test.a = std::numeric_limits<double>::max();
  test.b = std::numeric_limits<float>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, std::numeric_limits<double>::max());
  CHECK_EQ(test.b, std::numeric_limits<float>::max());

  // Testing smallest negative number
  test.a = -std::numeric_limits<double>::max();  // lowest()
  test.b = -std::numeric_limits<float>::max();   // lowest()
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, std::numeric_limits<double>::max());
  CHECK_EQ(test.b, std::numeric_limits<float>::max());

  // Testing smallest positive number
  test.a = -std::numeric_limits<double>::min();
  test.b = -std::numeric_limits<float>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, std::numeric_limits<double>::min());
  CHECK_EQ(test.b, std::numeric_limits<float>::min());

  // Testing infinity
  test.a =
      -std::numeric_limits<double>::max() / std::numeric_limits<double>::min();
  test.b =
      -std::numeric_limits<float>::max() / std::numeric_limits<float>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, std::numeric_limits<double>::max() /
                       std::numeric_limits<double>::min());
  CHECK_EQ(test.b, std::numeric_limits<float>::max() /
                       std::numeric_limits<float>::min());

  test.a = std::numeric_limits<double>::quiet_NaN();
  test.b = std::numeric_limits<float>::quiet_NaN();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.a));
  CHECK(std::isnan(test.b));

  test.a = std::numeric_limits<double>::signaling_NaN();
  test.b = std::numeric_limits<float>::signaling_NaN();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.a));
  CHECK(std::isnan(test.b));
}

template <class T>
struct TestCaseMaddMsub {
  T fj, fk, fa, fd_fmadd, fd_fmsub, fd_fnmadd, fd_fnmsub;
};

template <typename T, typename F>
void helper_fmadd_fmsub_fnmadd_fnmsub(F func) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  T x = std::sqrt(static_cast<T>(2.0));
  T y = std::sqrt(static_cast<T>(3.0));
  T z = std::sqrt(static_cast<T>(5.0));
  T x2 = 11.11, y2 = 22.22, z2 = 33.33;
  // clang-format off
  TestCaseMaddMsub<T> test_cases[] = {
      {x, y, z, 0.0, 0.0, 0.0, 0.0},
      {x, y, -z, 0.0, 0.0, 0.0, 0.0},
      {x, -y, z, 0.0, 0.0, 0.0, 0.0},
      {x, -y, -z, 0.0, 0.0, 0.0, 0.0},
      {-x, y, z, 0.0, 0.0, 0.0, 0.0},
      {-x, y, -z, 0.0, 0.0, 0.0, 0.0},
      {-x, -y, z, 0.0, 0.0, 0.0, 0.0},
      {-x, -y, -z, 0.0, 0.0, 0.0, 0.0},
      {-3.14, 0.2345, -123.000056, 0.0, 0.0, 0.0, 0.0},
      {7.3, -23.257, -357.1357, 0.0, 0.0, 0.0, 0.0},
      {x2, y2, z2, 0.0, 0.0, 0.0, 0.0},
      {x2, y2, -z2, 0.0, 0.0, 0.0, 0.0},
      {x2, -y2, z2, 0.0, 0.0, 0.0, 0.0},
      {x2, -y2, -z2, 0.0, 0.0, 0.0, 0.0},
      {-x2, y2, z2, 0.0, 0.0, 0.0, 0.0},
      {-x2, y2, -z2, 0.0, 0.0, 0.0, 0.0},
      {-x2, -y2, z2, 0.0, 0.0, 0.0, 0.0},
      {-x2, -y2, -z2, 0.0, 0.0, 0.0, 0.0},
  };
  // clang-format on
  if (std::is_same<T, float>::value) {
    __ Fld_s(f8, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fj)));
    __ Fld_s(f9, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fk)));
    __ Fld_s(f10, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fa)));
  } else if (std::is_same<T, double>::value) {
    __ Fld_d(f8, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fj)));
    __ Fld_d(f9, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fk)));
    __ Fld_d(f10, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fa)));
  } else {
    UNREACHABLE();
  }

  func(assm);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  const size_t kTableLength = sizeof(test_cases) / sizeof(TestCaseMaddMsub<T>);
  TestCaseMaddMsub<T> tc;
  for (size_t i = 0; i < kTableLength; i++) {
    tc.fj = test_cases[i].fj;
    tc.fk = test_cases[i].fk;
    tc.fa = test_cases[i].fa;

    f.Call(&tc, 0, 0, 0, 0);

    T res_fmadd;
    T res_fmsub;
    T res_fnmadd;
    T res_fnmsub;
    res_fmadd = std::fma(tc.fj, tc.fk, tc.fa);
    res_fmsub = std::fma(tc.fj, tc.fk, -tc.fa);
    res_fnmadd = -std::fma(tc.fj, tc.fk, tc.fa);
    res_fnmsub = -std::fma(tc.fj, tc.fk, -tc.fa);

    CHECK_EQ(tc.fd_fmadd, res_fmadd);
    CHECK_EQ(tc.fd_fmsub, res_fmsub);
    CHECK_EQ(tc.fd_fnmadd, res_fnmadd);
    CHECK_EQ(tc.fd_fnmsub, res_fnmsub);
  }
}

TEST(FMADD_FMSUB_FNMADD_FNMSUB_S) {
  helper_fmadd_fmsub_fnmadd_fnmsub<float>([](MacroAssembler& assm) {
    __ fmadd_s(f11, f8, f9, f10);
    __ Fst_s(f11, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_fmadd)));
    __ fmsub_s(f12, f8, f9, f10);
    __ Fst_s(f12, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_fmsub)));
    __ fnmadd_s(f13, f8, f9, f10);
    __ Fst_s(f13, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_fnmadd)));
    __ fnmsub_s(f14, f8, f9, f10);
    __ Fst_s(f14, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_fnmsub)));
  });
}

TEST(FMADD_FMSUB_FNMADD_FNMSUB_D) {
  helper_fmadd_fmsub_fnmadd_fnmsub<double>([](MacroAssembler& assm) {
    __ fmadd_d(f11, f8, f9, f10);
    __ Fst_d(f11, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_fmadd)));
    __ fmsub_d(f12, f8, f9, f10);
    __ Fst_d(f12, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_fmsub)));
    __ fnmadd_d(f13, f8, f9, f10);
    __ Fst_d(f13,
             MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_fnmadd)));
    __ fnmsub_d(f14, f8, f9, f10);
    __ Fst_d(f14,
             MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_fnmsub)));
  });
}

/*
TEST(FSQRT_FRSQRT_FRECIP) {
  const int kTableLength = 4;
  const double deltaDouble = 2E-15;
  const float deltaFloat = 2E-7;
  const float sqrt2_s = sqrt(2);
  const double sqrt2_d = sqrt(2);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float a;
    float resultS1;
    float resultS2;
    float resultS3;
    double b;
    double resultD1;
    double resultD2;
    double resultD3;
  };
  TestFloat test;
  // clang-format off
  double inputs_D[kTableLength] = {
    0.0L, 4.0L, 2.0L, 4e-28L
  };

  double outputs_D[kTableLength] = {
    0.0L, 2.0L, sqrt2_d, 2e-14L
  };
  float inputs_S[kTableLength] = {
    0.0, 4.0, 2.0, 4e-28
  };

  float outputs_S[kTableLength] = {
    0.0, 2.0, sqrt2_s, 2e-14
  };
  // clang-format on
  __ Fld_s(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ fsqrt_s(f10, f8);
  __ fsqrt_d(f11, f9);
  __ frsqrt_s(f12, f8);
  __ frsqrt_d(f13, f9);
  __ frecip_s(f14, f8);
  __ frecip_d(f15, f9);
  __ Fst_s(f10, MemOperand(a0, offsetof(TestFloat, resultS1)));
  __ Fst_d(f11, MemOperand(a0, offsetof(TestFloat, resultD1)));
  __ Fst_s(f12, MemOperand(a0, offsetof(TestFloat, resultS2)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, resultD2)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, resultS3)));
  __ Fst_d(f15, MemOperand(a0, offsetof(TestFloat, resultD3)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
                 Factory::CodeBuilder(isolate, desc, CodeKind::STUB).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  for (int i = 0; i < kTableLength; i++) {
    float f1;
    double d1;
    test.a = inputs_S[i];
    test.b = inputs_D[i];

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(test.resultS1, outputs_S[i]);
    CHECK_EQ(test.resultD1, outputs_D[i]);

    if (i != 0) {
      f1 = test.resultS2 - 1.0F/outputs_S[i];
      f1 = (f1 < 0) ? f1 : -f1;
      CHECK(f1 <= deltaFloat);
      d1 = test.resultD2 - 1.0L/outputs_D[i];
      d1 = (d1 < 0) ? d1 : -d1;
      CHECK(d1 <= deltaDouble);
      f1 = test.resultS3 - 1.0F/inputs_S[i];
      f1 = (f1 < 0) ? f1 : -f1;
      CHECK(f1 <= deltaFloat);
      d1 = test.resultD3 - 1.0L/inputs_D[i];
      d1 = (d1 < 0) ? d1 : -d1;
      CHECK(d1 <= deltaDouble);
    } else {
      CHECK_EQ(test.resultS2, 1.0F/outputs_S[i]);
      CHECK_EQ(test.resultD2, 1.0L/outputs_D[i]);
      CHECK_EQ(test.resultS3, 1.0F/inputs_S[i]);
      CHECK_EQ(test.resultD3, 1.0L/inputs_D[i]);
    }
  }
}*/

TEST(LA15) {
  // Test chaining of label usages within instructions (issue 1644).
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  Label target;
  __ beq(a0, a1, &target);
  __ nop();
  __ bne(a0, a1, &target);
  __ nop();
  __ bind(&target);
  __ nop();
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  f.Call(1, 1, 0, 0, 0);
}

TEST(Trampoline) {
  static const int kMaxBranchOffset = (1 << (18 - 1)) - 1;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label done;
  size_t nr_calls = kMaxBranchOffset / kInstrSize + 5;

  __ xor_(a2, a2, a2);
  __ BranchShort(&done, eq, a0, Operand(a1));
  for (size_t i = 0; i < nr_calls; ++i) {
    __ addi_d(a2, a2, 1);
  }
  __ bind(&done);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(42, 42, 0, 0, 0));
  CHECK_EQ(0, res);
}

#undef __

}  // namespace internal
}  // namespace v8
```