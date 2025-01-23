Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite for the RISC-V 64-bit assembler.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The code snippet consists of numerous `UTEST_*` and `TEST` macros. This immediately signals that it's a unit testing file. Specifically, it tests the RISC-V 64-bit assembler within V8.

2. **Analyze `UTEST_*` macros:** These macros are designed to test individual instructions or small groups of instructions. Notice the naming patterns like `UTEST_LOAD_STORE_F`, `UTEST_R2_FORM_WITH_OP_F`, `UTEST_CONV_*`, etc. These indicate tests for:
    * Floating-point load and store instructions (`fld`, `fsd`, `flw`, `fsw`).
    * Two-operand floating-point arithmetic operations (`fadd_s`, `fsub_d`, `fmul_d`, etc.).
    * Floating-point conversions (between floats and integers, single and double precision).
    * Comparisons (`feq_s`, `flt_d`, `fle_s`).
    * Bit manipulation (`fsgnj_s`, `fsgnjn_d`, `fsgnjx_s`).
    * Compact instructions (prefixed with `c_`).
    * Pseudo-instructions (`mv`, `not_`, `neg`, `sext_w`, etc.).

3. **Analyze `TEST` macros:** These seem to test more complex sequences or behaviors:
    * `RISCV0`, `RISCVLi`, `RISCVLiEstimate`: Testing the `li` (load immediate) instruction, including recursive versions and comparing its efficiency to LLVM's `li`.
    * `RISCV1`, `RISCV2`: Testing basic integer arithmetic and logical instructions, along with control flow (jumps, branches).
    * `RISCV3`, `RISCV4`, `RISCV5`, `RISCV6`:  Focus on floating-point operations (arithmetic, moves between integer and floating-point registers, conversions) and basic memory load/store operations.
    * `FCLASS`:  Tests the `fclass` instruction for classifying floating-point numbers.
    * `RISCV7`: Tests floating-point comparison and branching instructions.
    * `RISCV9`: Tests optimized branching instructions.
    * `NAN_BOX`: Tests how NaN (Not-a-Number) values are handled and boxed when moved between integer and floating-point registers.
    * `RVC_*`:  Tests the RV64C compressed instruction set extensions, covering various instruction types (arithmetic, load/store, jumps, branches).
    * `TARGET_ADDR`: Tests the generation of instructions to load specific memory addresses.

4. **Check for `.tq` suffix:** The prompt explicitly mentions checking for `.tq`. The filename ends in `.cc`, not `.tq`. This means it's a standard C++ test file, not a Torque file.

5. **Look for JavaScript relevance:**  While this C++ code directly tests the *assembler*, the assembler's job is to generate machine code that *executes* JavaScript. The floating-point and integer operations being tested are fundamental to how JavaScript numbers are handled.

6. **Construct JavaScript examples:** Based on the tested operations, create simple JavaScript snippets that would rely on these underlying assembler instructions. For instance, addition (`+`), subtraction (`-`), multiplication (`*`), division (`/`), comparisons (`<`, `<=`, `==`), and type conversions.

7. **Identify potential programming errors:**  Consider common mistakes related to the tested areas. Integer overflow, incorrect floating-point comparisons (due to precision issues or NaNs), and incorrect bitwise operations are good candidates.

8. **Formulate assumptions for code logic:**  For tests like `RISCV1`, assume an input value and trace the expected execution flow to determine the output.

9. **Summarize the functionality:** Combine the observations from the previous steps into a concise summary. Emphasize that it's a unit test file for the RISC-V 64-bit assembler, covering a wide range of instructions and scenarios.

10. **Structure the response:** Organize the information clearly, addressing each point raised in the prompt (file type, JavaScript relevance, code logic, common errors, summary). Use formatting like bullet points to improve readability.
```cpp
_WITH_OP_F(flt_s, float, -3456.56, -3456.56, <)
UTEST_COMPARE_WITH_OP_F(fle_s, float, -3456.56, -3456.56, <=)
UTEST_CONV_F_FROM_I(fcvt_s_w, int32_t, float, -100, (float)(-100))
UTEST_CONV_F_FROM_I(fcvt_s_wu, uint32_t, float,
                    std::numeric_limits<uint32_t>::max(),
                    (float)(std::numeric_limits<uint32_t>::max()))
UTEST_CONV_I_FROM_F(fcvt_w_s, float, int32_t, RMM, -100.5f, -101)
UTEST_CONV_I_FROM_F(fcvt_wu_s, float, uint32_t, RUP, 256.1f, 257)
UTEST_R2_FORM_WITH_RES_F(fsgnj_s, float, -100.0f, 200.0f, 100.0f)
UTEST_R2_FORM_WITH_RES_F(fsgnjn_s, float, 100.0f, 200.0f, -100.0f)
UTEST_R2_FORM_WITH_RES_F(fsgnjx_s, float, -100.0f, 200.0f, -100.0f)

// -- RV64F Standard Extension (in addition to RV32F) --
UTEST_LOAD_STORE_F(fld, fsd, double, -3456.678)
UTEST_R2_FORM_WITH_OP_F(fadd_d, double, -1012.01, 3456.13, +)
UTEST_R2_FORM_WITH_OP_F(fsub_d, double, -1012.01, 3456.13, -)
UTEST_R2_FORM_WITH_OP_F(fmul_d, double, -10.01, 56.13, *)
UTEST_R2_FORM_WITH_OP_F(fdiv_d, double, -10.01, 34.13, /)
UTEST_R1_FORM_WITH_RES_F(fsqrt_d, double, 34.13, std::sqrt(34.13))
UTEST_R2_FORM_WITH_RES_F(fmin_d, double, -1012.0, 3456.13, -1012.0)
UTEST_R2_FORM_WITH_RES_F(fmax_d, double, -1012.0, 3456.13, 3456.13)

UTEST_R3_FORM_WITH_RES_F(fmadd_d, double, 67.56, -1012.01, 3456.13,
                         std::fma(67.56, -1012.01, 3456.13))
UTEST_R3_FORM_WITH_RES_F(fmsub_d, double, 67.56, -1012.01, 3456.13,
                         std::fma(67.56, -1012.01, -3456.13))
UTEST_R3_FORM_WITH_RES_F(fnmsub_d, double, 67.56, -1012.01, 3456.13,
                         -std::fma(67.56, -1012.01, -3456.13))
UTEST_R3_FORM_WITH_RES_F(fnmadd_d, double, 67.56, -1012.01, 3456.13,
                         -std::fma(67.56, -1012.01, 3456.13))

UTEST_COMPARE_WITH_OP_F(feq_d, double, -3456.56, -3456.56, ==)
UTEST_COMPARE_WITH_OP_F(flt_d, double, -3456.56, -3456.56, <)
UTEST_COMPARE_WITH_OP_F(fle_d, double, -3456.56, -3456.56, <=)

UTEST_CONV_F_FROM_I(fcvt_d_w, int32_t, double, -100, -100.0)
UTEST_CONV_F_FROM_I(fcvt_d_wu, uint32_t, double,
                    std::numeric_limits<uint32_t>::max(),
                    (double)(std::numeric_limits<uint32_t>::max()))
UTEST_CONV_I_FROM_F(fcvt_w_d, double, int32_t, RTZ, -100.0, -100)
UTEST_CONV_I_FROM_F(fcvt_wu_d, double, uint32_t, RTZ,
                    (double)(std::numeric_limits<uint32_t>::max()),
                    std::numeric_limits<uint32_t>::max())

// -- RV64F Standard Extension (in addition to RV32F) --
UTEST_CONV_I_FROM_F(fcvt_l_s, float, int64_t, RDN, -100.5f, -101)
UTEST_CONV_I_FROM_F(fcvt_lu_s, float, uint64_t, RTZ, 1000001.0f, 1000001)
UTEST_CONV_F_FROM_I(fcvt_s_l, int64_t, float, (-0x1234'5678'0000'0001LL),
                    (float)(-0x1234'5678'0000'0001LL))
UTEST_CONV_F_FROM_I(fcvt_s_lu, uint64_t, float,
                    std::numeric_limits<uint64_t>::max(),
                    (float)(std::numeric_limits<uint64_t>::max()))

// -- RV32D Standard Extension --
UTEST_CONV_F_FROM_F(fcvt_s_d, double, float, 100.0, 100.0f)
UTEST_CONV_F_FROM_F(fcvt_d_s, float, double, 100.0f, 100.0)

UTEST_R2_FORM_WITH_RES_F(fsgnj_d, double, -100.0, 200.0, 100.0)
UTEST_R2_FORM_WITH_RES_F(fsgnjn_d, double, 100.0, 200.0, -100.0)
UTEST_R2_FORM_WITH_RES_F(fsgnjx_d, double, -100.0, 200.0, -100.0)

// -- RV64D Standard Extension (in addition to RV32D) --
UTEST_CONV_I_FROM_F(fcvt_l_d, double, int64_t, RNE, -100.5, -100)
UTEST_CONV_I_FROM_F(fcvt_lu_d, double, uint64_t, RTZ, 2456.5, 2456)
UTEST_CONV_F_FROM_I(fcvt_d_l, int64_t, double, (-0x1234'5678'0000'0001LL),
                    (double)(-0x1234'5678'0000'0001LL))
UTEST_CONV_F_FROM_I(fcvt_d_lu, uint64_t, double,
                    std::numeric_limits<uint64_t>::max(),
                    (double)(std::numeric_limits<uint64_t>::max()))

// -- RV64C Standard Extension --
UTEST_R1_FORM_WITH_RES_C(c_mv, int64_t, int64_t, 0x0f5600ab123400,
                         0x0f5600ab123400)

// -- Assembler Pseudo Instructions --
UTEST_R1_FORM_WITH_RES(mv, int64_t, int64_t, 0x0f5600ab123400, 0x0f5600ab123400)
UTEST_R1_FORM_WITH_RES(not_, int64_t, int64_t, 0, ~0)
UTEST_R1_FORM_WITH_RES(neg, int64_t, int64_t, 0x0f5600ab123400LL,
                       -(0x0f5600ab123400LL))
UTEST_R1_FORM_WITH_RES(negw, int32_t, int32_t, 0xab123400, -(0xab123400))
UTEST_R1_FORM_WITH_RES(sext_w, int32_t, int64_t, 0xFA01'1234,
                       static_cast<int64_t>(0xFFFFFFFFFA011234LL))
UTEST_R1_FORM_WITH_RES(seqz, int64_t, int64_t, 20, 20 == 0)
UTEST_R1_FORM_WITH_RES(snez, int64_t, int64_t, 20, 20 != 0)
UTEST_R1_FORM_WITH_RES(sltz, int64_t, int64_t, -20, -20 < 0)
UTEST_R1_FORM_WITH_RES(sgtz, int64_t, int64_t, -20, -20 > 0)

UTEST_R1_FORM_WITH_RES_F(fmv_s, float, -23.5f, -23.5f)
UTEST_R1_FORM_WITH_RES_F(fabs_s, float, -23.5f, 23.5f)
UTEST_R1_FORM_WITH_RES_F(fneg_s, float, 23.5f, -23.5f)
UTEST_R1_FORM_WITH_RES_F(fmv_d, double, -23.5, -23.5)
UTEST_R1_FORM_WITH_RES_F(fabs_d, double, -23.5, 23.5)
UTEST_R1_FORM_WITH_RES_F(fneg_d, double, 23.5, -23.5)

// Test LI
TEST(RISCV0) {
  CcTest::InitializeVM();

  FOR_INT64_INPUTS(i) {
    auto fn = [i](MacroAssembler& assm) { __ RV_li(a0, i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(i, res);
  }
}

TEST(RISCVZicond) {
  if (!CpuFeatures::IsSupported(ZICOND)) return;
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      auto fn = [i, j](MacroAssembler& assm) {
        __ li(a1, i);
        __ li(a0, j);
        __ MoveIfZero(a0, a1, a0);
      };
      auto res = GenAndRunTest(fn);
      CHECK_EQ(j != 0 ? j : i, res);
    }
  }

  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      auto fn = [i, j](MacroAssembler& assm) {
        __ li(a1, i);
        __ li(a2, j);
        __ czero_eqz(a0, a1, a2);
      };
      auto res = GenAndRunTest(fn);
      CHECK_EQ(j == 0 ? 0 : i, res);
    }
  }

  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      auto fn = [i, j](MacroAssembler& assm) {
        __ li(a1, i);
        __ li(a2, j);
        __ czero_nez(a0, a1, a2);
      };
      auto res = GenAndRunTest(fn);
      CHECK_EQ(j != 0 ? 0 : i, res);
    }
  }
}

TEST(RISCVLi) {
  CcTest::InitializeVM();

  FOR_INT64_INPUTS(i) {
    auto fn = [i](MacroAssembler& assm) { __ RecursiveLi(a0, i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(i, res);
  }
  for (int i = 0; i < 64; i++) {
    auto fn = [i](MacroAssembler& assm) { __ RecursiveLi(a0, 1 << i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(1 << i, res);
  }
}

TEST(RISCVLiEstimate) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  FOR_INT64_INPUTS(i) {
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    Label a, b;
    assm.bind(&a);
    assm.RecordComment("V8 RV_li");
    assm.RV_li(a0, i);
    int count_a = assm.InstructionsGeneratedSince(&a);
    assm.bind(&b);
    assm.RecordComment("LLVM li");
    assm.RecursiveLi(a0, i);
    int count_b = assm.InstructionsGeneratedSince(&b);
    CHECK_LE(count_a, count_b);
  }
}

TEST(RISCV1) {
  CcTest::InitializeVM();

  Label L, C;
  auto fn = [&L, &C](MacroAssembler& assm) {
    __ mv(a1, a0);
    __ RV_li(a0, 0l);
    __ j(&C);

    __ bind(&L);
    __ add(a0, a0, a1);
    __ addi(a1, a1, -1);

    __ bind(&C);
    __ xori(a2, a1, 0);
    __ bnez(a2, &L);
  };

  int64_t input = 50;
  int64_t expected_res = 1275L;
  auto res = GenAndRunTest<int64_t>(input, fn);
  CHECK_EQ(expected_res, res);
}

TEST(RISCV2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Label exit, error;
  int64_t expected_res = 0x31415926L;

  // ----- Test all instructions.

  // Test lui, ori, and addiw, used in the
  // li pseudo-instruction. This way we
  // can then safely load registers with
  // chosen values.
  auto fn = [&exit, &error, expected_res](MacroAssembler& assm) {
    __ ori(a4, zero_reg, 0);
    __ lui(a4, 0x12345);
    __ ori(a4, a4, 0);
    __ ori(a4, a4, 0xF0F);
    __ ori(a4, a4, 0x0F0);
    __ addiw(a5, a4, 1);
    __ addiw(a6, a5, -0x10);

    // Load values in temporary registers.
    __ RV_li(a4, 0x00000004);
    __ RV_li(a5, 0x00001234);
    __ RV_li(a6, 0x12345678);
    __ RV_li(a7, 0x7FFFFFFF);
    __ RV_li(t0, 0xFFFFFFFC);
    __ RV_li(t1, 0xFFFFEDCC);
    __ RV_li(t2, 0xEDCBA988);
    __ RV_li(t3, 0x80000000);

    __ srliw(t0, a6, 8);   // 0x00123456
    __ slliw(t0, t0, 11);  // 0x91A2B000
    __ sraiw(t0, t0, 3);   // 0xFFFFFFFF F2345600
    __ sraw(t0, t0, a4);   // 0xFFFFFFFF FF234560
    __ sllw(t0, t0, a4);   // 0xFFFFFFFF F2345600
    __ srlw(t0, t0, a4);   // 0x0F234560
    __ RV_li(t5, 0x0F234560);
    __ bne(t0, t5, &error);

    __ addw(t0, a4, a5);  // 0x00001238
    __ subw(t0, t0, a4);  // 0x00001234
    __ RV_li(t5, 0x00001234);
    __ bne(t0, t5, &error);
    __ addw(a1, a7,
            a4);  // 32bit addu result is sign-extended into 64bit reg.
    __ RV_li(t5, 0xFFFFFFFF80000003);
    __ bne(a1, t5, &error);
    __ subw(a1, t3, a4);  // 0x7FFFFFFC
    __ RV_li(t5, 0x7FFFFFFC);
    __ bne(a1, t5, &error);

    __ and_(t0, a5, a6);  // 0x0000000000001230
    __ or_(t0, t0, a5);   // 0x0000000000001234
    __ xor_(t0, t0, a6);  // 0x000000001234444C
    __ or_(t0, t0, a6);
    __ not_(t0, t0);  // 0xFFFFFFFFEDCBA983
    __ RV_li(t5, 0xFFFFFFFFEDCBA983);
    __ bne(t0, t5, &error);

    // Shift both 32bit number to left, to
    // preserve meaning of next comparison.
    __ slli(a7, a7, 32);
    __ slli(t3, t3, 32);

    __ slt(t0, t3, a7);
    __ RV_li(t5, 1);
    __ bne(t0, t5, &error);
    __ sltu(t0, t3, a7);
    __ bne(t0, zero_reg, &error);

    // Restore original values in registers.
    __ srli(a7, a7, 32);
    __ srli(t3, t3, 32);

    __ RV_li(t0, 0x7421);    // 0x00007421
    __ addi(t0, t0, -0x1);   // 0x00007420
    __ addi(t0, t0, -0x20);  // 0x00007400
    __ RV_li(t5, 0x00007400);
    __ bne(t0, t5, &error);
    __ addiw(a1, a7, 0x1);  // 0x80000000 - result is sign-extended.
    __ RV_li(t5, 0xFFFFFFFF80000000);
    __ bne(a1, t5, &error);

    __ RV_li(t5, 0x00002000);
    __ slt(t0, a5, t5);  // 0x1
    __ RV_li(t6, 0xFFFFFFFFFFFF8000);
    __ slt(t0, t0, t6);  // 0x0
    __ bne(t0, zero_reg, &error);
    __ sltu(t0, a5, t5);  // 0x1
    __ RV_li(t6, 0x00008000);
    __ sltu(t0, t0, t6);  // 0x1
    __ RV_li(t5, 1);
    __ bne(t0, t5, &error);

    __ andi(t0, a5, 0x0F0);  // 0x00000030
    __ ori(t0, t0, 0x200);   // 0x00000230
    __ xori(t0, t0, 0x3CC);  // 0x000001FC
    __ RV_li(t5, 0x000001FC);
    __ bne(t0, t5, &error);
    __ lui(a1, -519628);  // Result is sign-extended into 64bit register.
    __ RV_li(t5, 0xFFFFFFFF81234000);
    __ bne(a1, t5, &error);

    // Everything was correctly executed.
    // Load the expected result.
    __ RV_li(a0, expected_res);
    __ j(&exit);

    __ bind(&error);
    // Got an error. Return a wrong result.
    __ RV_li(a0, 666);

    __ bind(&exit);
  };
  auto res = GenAndRunTest(fn);
  CHECK_EQ(expected_res, res);
}

TEST(RISCV3) {
  // Test floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
    double i;
    float fa;
    float fb;
    float fc;
    float fd;
    float fe;
    float ff;
    float fg;
  } t;

  // Create a function that accepts &t and loads, manipulates, and stores
  // the doubles t.a ... t.f.

  // Double precision floating point instructions.
  auto fn = [](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));
    __ fadd_d(ft2, ft0, ft1);
    __ fsd(ft2, a0, offsetof(T, c));  // c = a + b.

    __ fmv_d(ft3, ft2);   // c
    __ fneg_d(fa0, ft1);  // -b
    __ fsub_d(ft3, ft3, fa0);
    __ fsd(ft3, a0, offsetof(T, d));  // d = c - (-b).

    __ fsd(ft0, a0, offsetof(T, b));  // b = a.

    __ RV_li(a4, 120);
    __ fcvt_d_w(ft5, a4);
    __ fmul_d(ft3, ft3, ft5);
    __ fsd(ft3, a0, offsetof(T, e));  // e = d * 120 = 1.8066e16.

    __ fdiv_d(ft4, ft3, ft0);
    __ fsd(ft4, a0, offsetof(T, f));  // f = e / a = 120.44.

    __ fsqrt_d(ft5, ft4);
    __ fsd(ft5, a0, offsetof(T, g));
    // g = sqrt(f) = 10.97451593465515908537

    __ fld(ft0, a0, offsetof(T, h));
    __ fld(ft1, a0, offsetof(T, i));
    __ fmadd_d(ft5, ft1, ft0, ft1);
    __ fsd(ft5, a0, offsetof(T, h));

    // // Single precision floating point instructions.
    __ flw(ft0, a0, offsetof(T, fa));
    __ flw(ft1, a0, offsetof(T, fb));
    __ fadd_s(ft2, ft0, ft1);
    __ fsw(ft2, a0, offsetof(T, fc));  // fc = fa + fb.

    __ fneg_s(ft3, ft1);  // -fb
    __ fsub_s(ft3, ft2, ft3);
    __ fsw(ft3, a0, offsetof(T, fd));  // fd = fc - (-fb).

    __ fsw(ft0, a0, offsetof(T, fb));  // fb = fa.

    __ RV_li(t0, 120);
    __ fcvt_s_w(ft5, t0);  // ft5 = 120.0.
    __ fmul_s(ft3, ft3, ft5);
    __ fsw(ft3, a0, offsetof(T, fe));  // fe = fd * 120

    __ fdiv_s(ft4, ft3, ft0);
    __ fsw(ft4, a0, offsetof(T, ff));  // ff = fe / fa

    __ fsqrt_s(ft5, ft4);
    __ fsw(ft5, a0, offsetof(T, fg));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  // Double test values.
  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 0.0;
  t.d = 0.0;
  t.e = 0.0;
  t.f = 0.0;
  t.h = 1.5;
  t.i = 2.75;
  // Single test values.
  t.fa = 1.5e6;
  t.fb = 2.75e4;
  t.fc = 0.0;
  t.fd = 0.0;
  t.fe = 0.0;
  t.ff = 0.0;
  f.Call(&t, 0, 0, 0, 0);
  // Expected double results.
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(1.5e14, t.b);
  CHECK_EQ(1.50275e14, t.c);
  CHECK_EQ(1.50550e14, t.d);
  CHECK_EQ(1.8066e16, t.e);
  CHECK_EQ(120.44, t.f);
  CHECK_EQ(10.97451593465515908537, t.g);
  CHECK_EQ(6.875, t
### 提示词
```
这是目录为v8/test/cctest/test-assembler-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
_WITH_OP_F(flt_s, float, -3456.56, -3456.56, <)
UTEST_COMPARE_WITH_OP_F(fle_s, float, -3456.56, -3456.56, <=)
UTEST_CONV_F_FROM_I(fcvt_s_w, int32_t, float, -100, (float)(-100))
UTEST_CONV_F_FROM_I(fcvt_s_wu, uint32_t, float,
                    std::numeric_limits<uint32_t>::max(),
                    (float)(std::numeric_limits<uint32_t>::max()))
UTEST_CONV_I_FROM_F(fcvt_w_s, float, int32_t, RMM, -100.5f, -101)
UTEST_CONV_I_FROM_F(fcvt_wu_s, float, uint32_t, RUP, 256.1f, 257)
UTEST_R2_FORM_WITH_RES_F(fsgnj_s, float, -100.0f, 200.0f, 100.0f)
UTEST_R2_FORM_WITH_RES_F(fsgnjn_s, float, 100.0f, 200.0f, -100.0f)
UTEST_R2_FORM_WITH_RES_F(fsgnjx_s, float, -100.0f, 200.0f, -100.0f)

// -- RV64F Standard Extension (in addition to RV32F) --
UTEST_LOAD_STORE_F(fld, fsd, double, -3456.678)
UTEST_R2_FORM_WITH_OP_F(fadd_d, double, -1012.01, 3456.13, +)
UTEST_R2_FORM_WITH_OP_F(fsub_d, double, -1012.01, 3456.13, -)
UTEST_R2_FORM_WITH_OP_F(fmul_d, double, -10.01, 56.13, *)
UTEST_R2_FORM_WITH_OP_F(fdiv_d, double, -10.01, 34.13, /)
UTEST_R1_FORM_WITH_RES_F(fsqrt_d, double, 34.13, std::sqrt(34.13))
UTEST_R2_FORM_WITH_RES_F(fmin_d, double, -1012.0, 3456.13, -1012.0)
UTEST_R2_FORM_WITH_RES_F(fmax_d, double, -1012.0, 3456.13, 3456.13)

UTEST_R3_FORM_WITH_RES_F(fmadd_d, double, 67.56, -1012.01, 3456.13,
                         std::fma(67.56, -1012.01, 3456.13))
UTEST_R3_FORM_WITH_RES_F(fmsub_d, double, 67.56, -1012.01, 3456.13,
                         std::fma(67.56, -1012.01, -3456.13))
UTEST_R3_FORM_WITH_RES_F(fnmsub_d, double, 67.56, -1012.01, 3456.13,
                         -std::fma(67.56, -1012.01, -3456.13))
UTEST_R3_FORM_WITH_RES_F(fnmadd_d, double, 67.56, -1012.01, 3456.13,
                         -std::fma(67.56, -1012.01, 3456.13))

UTEST_COMPARE_WITH_OP_F(feq_d, double, -3456.56, -3456.56, ==)
UTEST_COMPARE_WITH_OP_F(flt_d, double, -3456.56, -3456.56, <)
UTEST_COMPARE_WITH_OP_F(fle_d, double, -3456.56, -3456.56, <=)

UTEST_CONV_F_FROM_I(fcvt_d_w, int32_t, double, -100, -100.0)
UTEST_CONV_F_FROM_I(fcvt_d_wu, uint32_t, double,
                    std::numeric_limits<uint32_t>::max(),
                    (double)(std::numeric_limits<uint32_t>::max()))
UTEST_CONV_I_FROM_F(fcvt_w_d, double, int32_t, RTZ, -100.0, -100)
UTEST_CONV_I_FROM_F(fcvt_wu_d, double, uint32_t, RTZ,
                    (double)(std::numeric_limits<uint32_t>::max()),
                    std::numeric_limits<uint32_t>::max())

// -- RV64F Standard Extension (in addition to RV32F) --
UTEST_CONV_I_FROM_F(fcvt_l_s, float, int64_t, RDN, -100.5f, -101)
UTEST_CONV_I_FROM_F(fcvt_lu_s, float, uint64_t, RTZ, 1000001.0f, 1000001)
UTEST_CONV_F_FROM_I(fcvt_s_l, int64_t, float, (-0x1234'5678'0000'0001LL),
                    (float)(-0x1234'5678'0000'0001LL))
UTEST_CONV_F_FROM_I(fcvt_s_lu, uint64_t, float,
                    std::numeric_limits<uint64_t>::max(),
                    (float)(std::numeric_limits<uint64_t>::max()))

// -- RV32D Standard Extension --
UTEST_CONV_F_FROM_F(fcvt_s_d, double, float, 100.0, 100.0f)
UTEST_CONV_F_FROM_F(fcvt_d_s, float, double, 100.0f, 100.0)

UTEST_R2_FORM_WITH_RES_F(fsgnj_d, double, -100.0, 200.0, 100.0)
UTEST_R2_FORM_WITH_RES_F(fsgnjn_d, double, 100.0, 200.0, -100.0)
UTEST_R2_FORM_WITH_RES_F(fsgnjx_d, double, -100.0, 200.0, -100.0)

// -- RV64D Standard Extension (in addition to RV32D) --
UTEST_CONV_I_FROM_F(fcvt_l_d, double, int64_t, RNE, -100.5, -100)
UTEST_CONV_I_FROM_F(fcvt_lu_d, double, uint64_t, RTZ, 2456.5, 2456)
UTEST_CONV_F_FROM_I(fcvt_d_l, int64_t, double, (-0x1234'5678'0000'0001LL),
                    (double)(-0x1234'5678'0000'0001LL))
UTEST_CONV_F_FROM_I(fcvt_d_lu, uint64_t, double,
                    std::numeric_limits<uint64_t>::max(),
                    (double)(std::numeric_limits<uint64_t>::max()))

// -- RV64C Standard Extension --
UTEST_R1_FORM_WITH_RES_C(c_mv, int64_t, int64_t, 0x0f5600ab123400,
                         0x0f5600ab123400)

// -- Assembler Pseudo Instructions --
UTEST_R1_FORM_WITH_RES(mv, int64_t, int64_t, 0x0f5600ab123400, 0x0f5600ab123400)
UTEST_R1_FORM_WITH_RES(not_, int64_t, int64_t, 0, ~0)
UTEST_R1_FORM_WITH_RES(neg, int64_t, int64_t, 0x0f5600ab123400LL,
                       -(0x0f5600ab123400LL))
UTEST_R1_FORM_WITH_RES(negw, int32_t, int32_t, 0xab123400, -(0xab123400))
UTEST_R1_FORM_WITH_RES(sext_w, int32_t, int64_t, 0xFA01'1234,
                       static_cast<int64_t>(0xFFFFFFFFFA011234LL))
UTEST_R1_FORM_WITH_RES(seqz, int64_t, int64_t, 20, 20 == 0)
UTEST_R1_FORM_WITH_RES(snez, int64_t, int64_t, 20, 20 != 0)
UTEST_R1_FORM_WITH_RES(sltz, int64_t, int64_t, -20, -20 < 0)
UTEST_R1_FORM_WITH_RES(sgtz, int64_t, int64_t, -20, -20 > 0)

UTEST_R1_FORM_WITH_RES_F(fmv_s, float, -23.5f, -23.5f)
UTEST_R1_FORM_WITH_RES_F(fabs_s, float, -23.5f, 23.5f)
UTEST_R1_FORM_WITH_RES_F(fneg_s, float, 23.5f, -23.5f)
UTEST_R1_FORM_WITH_RES_F(fmv_d, double, -23.5, -23.5)
UTEST_R1_FORM_WITH_RES_F(fabs_d, double, -23.5, 23.5)
UTEST_R1_FORM_WITH_RES_F(fneg_d, double, 23.5, -23.5)

// Test LI
TEST(RISCV0) {
  CcTest::InitializeVM();

  FOR_INT64_INPUTS(i) {
    auto fn = [i](MacroAssembler& assm) { __ RV_li(a0, i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(i, res);
  }
}

TEST(RISCVZicond) {
  if (!CpuFeatures::IsSupported(ZICOND)) return;
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      auto fn = [i, j](MacroAssembler& assm) {
        __ li(a1, i);
        __ li(a0, j);
        __ MoveIfZero(a0, a1, a0);
      };
      auto res = GenAndRunTest(fn);
      CHECK_EQ(j != 0 ? j : i, res);
    }
  }

  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      auto fn = [i, j](MacroAssembler& assm) {
        __ li(a1, i);
        __ li(a2, j);
        __ czero_eqz(a0, a1, a2);
      };
      auto res = GenAndRunTest(fn);
      CHECK_EQ(j == 0 ? 0 : i, res);
    }
  }

  FOR_INT64_INPUTS(i) {
    FOR_INT64_INPUTS(j) {
      auto fn = [i, j](MacroAssembler& assm) {
        __ li(a1, i);
        __ li(a2, j);
        __ czero_nez(a0, a1, a2);
      };
      auto res = GenAndRunTest(fn);
      CHECK_EQ(j != 0 ? 0 : i, res);
    }
  }
}

TEST(RISCVLi) {
  CcTest::InitializeVM();

  FOR_INT64_INPUTS(i) {
    auto fn = [i](MacroAssembler& assm) { __ RecursiveLi(a0, i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(i, res);
  }
  for (int i = 0; i < 64; i++) {
    auto fn = [i](MacroAssembler& assm) { __ RecursiveLi(a0, 1 << i); };
    auto res = GenAndRunTest(fn);
    CHECK_EQ(1 << i, res);
  }
}

TEST(RISCVLiEstimate) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  FOR_INT64_INPUTS(i) {
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    Label a, b;
    assm.bind(&a);
    assm.RecordComment("V8 RV_li");
    assm.RV_li(a0, i);
    int count_a = assm.InstructionsGeneratedSince(&a);
    assm.bind(&b);
    assm.RecordComment("LLVM li");
    assm.RecursiveLi(a0, i);
    int count_b = assm.InstructionsGeneratedSince(&b);
    CHECK_LE(count_a, count_b);
  }
}

TEST(RISCV1) {
  CcTest::InitializeVM();

  Label L, C;
  auto fn = [&L, &C](MacroAssembler& assm) {
    __ mv(a1, a0);
    __ RV_li(a0, 0l);
    __ j(&C);

    __ bind(&L);
    __ add(a0, a0, a1);
    __ addi(a1, a1, -1);

    __ bind(&C);
    __ xori(a2, a1, 0);
    __ bnez(a2, &L);
  };

  int64_t input = 50;
  int64_t expected_res = 1275L;
  auto res = GenAndRunTest<int64_t>(input, fn);
  CHECK_EQ(expected_res, res);
}

TEST(RISCV2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Label exit, error;
  int64_t expected_res = 0x31415926L;

  // ----- Test all instructions.

  // Test lui, ori, and addiw, used in the
  // li pseudo-instruction. This way we
  // can then safely load registers with
  // chosen values.
  auto fn = [&exit, &error, expected_res](MacroAssembler& assm) {
    __ ori(a4, zero_reg, 0);
    __ lui(a4, 0x12345);
    __ ori(a4, a4, 0);
    __ ori(a4, a4, 0xF0F);
    __ ori(a4, a4, 0x0F0);
    __ addiw(a5, a4, 1);
    __ addiw(a6, a5, -0x10);

    // Load values in temporary registers.
    __ RV_li(a4, 0x00000004);
    __ RV_li(a5, 0x00001234);
    __ RV_li(a6, 0x12345678);
    __ RV_li(a7, 0x7FFFFFFF);
    __ RV_li(t0, 0xFFFFFFFC);
    __ RV_li(t1, 0xFFFFEDCC);
    __ RV_li(t2, 0xEDCBA988);
    __ RV_li(t3, 0x80000000);

    __ srliw(t0, a6, 8);   // 0x00123456
    __ slliw(t0, t0, 11);  // 0x91A2B000
    __ sraiw(t0, t0, 3);   // 0xFFFFFFFF F2345600
    __ sraw(t0, t0, a4);   // 0xFFFFFFFF FF234560
    __ sllw(t0, t0, a4);   // 0xFFFFFFFF F2345600
    __ srlw(t0, t0, a4);   // 0x0F234560
    __ RV_li(t5, 0x0F234560);
    __ bne(t0, t5, &error);

    __ addw(t0, a4, a5);  // 0x00001238
    __ subw(t0, t0, a4);  // 0x00001234
    __ RV_li(t5, 0x00001234);
    __ bne(t0, t5, &error);
    __ addw(a1, a7,
            a4);  // 32bit addu result is sign-extended into 64bit reg.
    __ RV_li(t5, 0xFFFFFFFF80000003);
    __ bne(a1, t5, &error);
    __ subw(a1, t3, a4);  // 0x7FFFFFFC
    __ RV_li(t5, 0x7FFFFFFC);
    __ bne(a1, t5, &error);

    __ and_(t0, a5, a6);  // 0x0000000000001230
    __ or_(t0, t0, a5);   // 0x0000000000001234
    __ xor_(t0, t0, a6);  // 0x000000001234444C
    __ or_(t0, t0, a6);
    __ not_(t0, t0);  // 0xFFFFFFFFEDCBA983
    __ RV_li(t5, 0xFFFFFFFFEDCBA983);
    __ bne(t0, t5, &error);

    // Shift both 32bit number to left, to
    // preserve meaning of next comparison.
    __ slli(a7, a7, 32);
    __ slli(t3, t3, 32);

    __ slt(t0, t3, a7);
    __ RV_li(t5, 1);
    __ bne(t0, t5, &error);
    __ sltu(t0, t3, a7);
    __ bne(t0, zero_reg, &error);

    // Restore original values in registers.
    __ srli(a7, a7, 32);
    __ srli(t3, t3, 32);

    __ RV_li(t0, 0x7421);    // 0x00007421
    __ addi(t0, t0, -0x1);   // 0x00007420
    __ addi(t0, t0, -0x20);  // 0x00007400
    __ RV_li(t5, 0x00007400);
    __ bne(t0, t5, &error);
    __ addiw(a1, a7, 0x1);  // 0x80000000 - result is sign-extended.
    __ RV_li(t5, 0xFFFFFFFF80000000);
    __ bne(a1, t5, &error);

    __ RV_li(t5, 0x00002000);
    __ slt(t0, a5, t5);  // 0x1
    __ RV_li(t6, 0xFFFFFFFFFFFF8000);
    __ slt(t0, t0, t6);  // 0x0
    __ bne(t0, zero_reg, &error);
    __ sltu(t0, a5, t5);  // 0x1
    __ RV_li(t6, 0x00008000);
    __ sltu(t0, t0, t6);  // 0x1
    __ RV_li(t5, 1);
    __ bne(t0, t5, &error);

    __ andi(t0, a5, 0x0F0);  // 0x00000030
    __ ori(t0, t0, 0x200);   // 0x00000230
    __ xori(t0, t0, 0x3CC);  // 0x000001FC
    __ RV_li(t5, 0x000001FC);
    __ bne(t0, t5, &error);
    __ lui(a1, -519628);  // Result is sign-extended into 64bit register.
    __ RV_li(t5, 0xFFFFFFFF81234000);
    __ bne(a1, t5, &error);

    // Everything was correctly executed.
    // Load the expected result.
    __ RV_li(a0, expected_res);
    __ j(&exit);

    __ bind(&error);
    // Got an error. Return a wrong result.
    __ RV_li(a0, 666);

    __ bind(&exit);
  };
  auto res = GenAndRunTest(fn);
  CHECK_EQ(expected_res, res);
}

TEST(RISCV3) {
  // Test floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
    double i;
    float fa;
    float fb;
    float fc;
    float fd;
    float fe;
    float ff;
    float fg;
  } t;

  // Create a function that accepts &t and loads, manipulates, and stores
  // the doubles t.a ... t.f.

  // Double precision floating point instructions.
  auto fn = [](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));
    __ fadd_d(ft2, ft0, ft1);
    __ fsd(ft2, a0, offsetof(T, c));  // c = a + b.

    __ fmv_d(ft3, ft2);   // c
    __ fneg_d(fa0, ft1);  // -b
    __ fsub_d(ft3, ft3, fa0);
    __ fsd(ft3, a0, offsetof(T, d));  // d = c - (-b).

    __ fsd(ft0, a0, offsetof(T, b));  // b = a.

    __ RV_li(a4, 120);
    __ fcvt_d_w(ft5, a4);
    __ fmul_d(ft3, ft3, ft5);
    __ fsd(ft3, a0, offsetof(T, e));  // e = d * 120 = 1.8066e16.

    __ fdiv_d(ft4, ft3, ft0);
    __ fsd(ft4, a0, offsetof(T, f));  // f = e / a = 120.44.

    __ fsqrt_d(ft5, ft4);
    __ fsd(ft5, a0, offsetof(T, g));
    // g = sqrt(f) = 10.97451593465515908537

    __ fld(ft0, a0, offsetof(T, h));
    __ fld(ft1, a0, offsetof(T, i));
    __ fmadd_d(ft5, ft1, ft0, ft1);
    __ fsd(ft5, a0, offsetof(T, h));

    // // Single precision floating point instructions.
    __ flw(ft0, a0, offsetof(T, fa));
    __ flw(ft1, a0, offsetof(T, fb));
    __ fadd_s(ft2, ft0, ft1);
    __ fsw(ft2, a0, offsetof(T, fc));  // fc = fa + fb.

    __ fneg_s(ft3, ft1);  // -fb
    __ fsub_s(ft3, ft2, ft3);
    __ fsw(ft3, a0, offsetof(T, fd));  // fd = fc - (-fb).

    __ fsw(ft0, a0, offsetof(T, fb));  // fb = fa.

    __ RV_li(t0, 120);
    __ fcvt_s_w(ft5, t0);  // ft5 = 120.0.
    __ fmul_s(ft3, ft3, ft5);
    __ fsw(ft3, a0, offsetof(T, fe));  // fe = fd * 120

    __ fdiv_s(ft4, ft3, ft0);
    __ fsw(ft4, a0, offsetof(T, ff));  // ff = fe / fa

    __ fsqrt_s(ft5, ft4);
    __ fsw(ft5, a0, offsetof(T, fg));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  // Double test values.
  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 0.0;
  t.d = 0.0;
  t.e = 0.0;
  t.f = 0.0;
  t.h = 1.5;
  t.i = 2.75;
  // Single test values.
  t.fa = 1.5e6;
  t.fb = 2.75e4;
  t.fc = 0.0;
  t.fd = 0.0;
  t.fe = 0.0;
  t.ff = 0.0;
  f.Call(&t, 0, 0, 0, 0);
  // Expected double results.
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(1.5e14, t.b);
  CHECK_EQ(1.50275e14, t.c);
  CHECK_EQ(1.50550e14, t.d);
  CHECK_EQ(1.8066e16, t.e);
  CHECK_EQ(120.44, t.f);
  CHECK_EQ(10.97451593465515908537, t.g);
  CHECK_EQ(6.875, t.h);
  // Expected single results.
  CHECK_EQ(1.5e6, t.fa);
  CHECK_EQ(1.5e6, t.fb);
  CHECK_EQ(1.5275e06, t.fc);
  CHECK_EQ(1.5550e06, t.fd);
  CHECK_EQ(1.866e08, t.fe);
  CHECK_EQ(124.40000152587890625, t.ff);
  CHECK_EQ(11.1534748077392578125, t.fg);
}
TEST(RISCV4) {
  // Test moves between floating point and
  // integer registers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    float d;
    int64_t e;
  } t;

  auto fn = [](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(fa1, a0, offsetof(T, b));

    // Swap ft0 and fa1, by using 2 integer registers, a4-a5,
    __ fmv_x_d(a4, ft0);
    __ fmv_x_d(a5, fa1);

    __ fmv_d_x(fa1, a4);
    __ fmv_d_x(ft0, a5);

    // Store the swapped ft0 and fa1 back to memory.
    __ fsd(ft0, a0, offsetof(T, a));
    __ fsd(fa1, a0, offsetof(T, c));

    // Test sign extension of move operations from coprocessor.
    __ flw(ft0, a0, offsetof(T, d));
    __ fmv_x_w(a4, ft0);

    __ sd(a4, a0, offsetof(T, e));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(2.75e11, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFD2800E8EL), t.e);
}

TEST(RISCV5) {
  // Test conversions between doubles and
  // integers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    int i;
    int j;
  } t;

  auto fn = [](MacroAssembler& assm) {
    // Load all structure elements to registers.
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));
    __ lw(a4, a0, offsetof(T, i));
    __ lw(a5, a0, offsetof(T, j));

    // Convert double in ft0 to int in element i.
    __ fcvt_l_d(a6, ft0);
    __ sw(a6, a0, offsetof(T, i));

    // Convert double in ft1 to int in element j.
    __ fcvt_l_d(a7, ft1);
    __ sw(a7, a0, offsetof(T, j));

    // Convert int in original i (a4) to double in a.
    __ fcvt_d_l(fa0, a4);
    __ fsd(fa0, a0, offsetof(T, a));

    // Convert int in original j (a5) to double in b.
    __ fcvt_d_l(fa1, a5);
    __ fsd(fa1, a0, offsetof(T, b));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e4;
  t.b = 2.75e8;
  t.i = 12345678;
  t.j = -100000;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(12345678.0, t.a);
  CHECK_EQ(-100000.0, t.b);
  CHECK_EQ(15000, t.i);
  CHECK_EQ(275000000, t.j);
}

TEST(RISCV6) {
  // Test simple memory loads and stores.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t ui;
    int32_t si;
    int32_t r1;
    int32_t r2;
    int32_t r3;
    int32_t r4;
    int32_t r5;
    int32_t r6;
  } t;

  auto fn = [](MacroAssembler& assm) {
    // Basic word load/store.
    __ lw(a4, a0, offsetof(T, ui));
    __ sw(a4, a0, offsetof(T, r1));

    // lh with positive data.
    __ lh(a5, a0, offsetof(T, ui));
    __ sw(a5, a0, offsetof(T, r2));

    // lh with negative data.
    __ lh(a6, a0, offsetof(T, si));
    __ sw(a6, a0, offsetof(T, r3));

    // lhu with negative data.
    __ lhu(a7, a0, offsetof(T, si));
    __ sw(a7, a0, offsetof(T, r4));

    // Lb with negative data.
    __ lb(t0, a0, offsetof(T, si));
    __ sw(t0, a0, offsetof(T, r5));

    // sh writes only 1/2 of word.
    __ RV_li(t1, 0x33333333);
    __ sw(t1, a0, offsetof(T, r6));
    __ lhu(t1, a0, offsetof(T, si));
    __ sh(t1, a0, offsetof(T, r6));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.ui = 0x11223344;
  t.si = 0x99AABBCC;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x11223344), t.r1);
  if (kArchEndian == kLittle) {
    CHECK_EQ(static_cast<int32_t>(0x3344), t.r2);
    CHECK_EQ(static_cast<int32_t>(0xFFFFBBCC), t.r3);
    CHECK_EQ(static_cast<int32_t>(0x0000BBCC), t.r4);
    CHECK_EQ(static_cast<int32_t>(0xFFFFFFCC), t.r5);
    CHECK_EQ(static_cast<int32_t>(0x3333BBCC), t.r6);
  } else {
    CHECK_EQ(static_cast<int32_t>(0x1122), t.r2);
    CHECK_EQ(static_cast<int32_t>(0xFFFF99AA), t.r3);
    CHECK_EQ(static_cast<int32_t>(0x000099AA), t.r4);
    CHECK_EQ(static_cast<int32_t>(0xFFFFFF99), t.r5);
    CHECK_EQ(static_cast<int32_t>(0x99AA3333), t.r6);
  }
}

// pair.first is the F_TYPE input to test, pair.second is I_TYPE expected result
template <typename T>
static const std::vector<std::pair<T, uint64_t>> fclass_test_values() {
  static const std::pair<T, uint64_t> kValues[] = {
      std::make_pair(-std::numeric_limits<T>::infinity(), kNegativeInfinity),
      std::make_pair(-10240.56, kNegativeNormalNumber),
      std::make_pair(-(std::numeric_limits<T>::min() / 2),
                     kNegativeSubnormalNumber),
      std::make_pair(-0.0, kNegativeZero),
      std::make_pair(+0.0, kPositiveZero),
      std::make_pair((std::numeric_limits<T>::min() / 2),
                     kPositiveSubnormalNumber),
      std::make_pair(10240.56, kPositiveNormalNumber),
      std::make_pair(std::numeric_limits<T>::infinity(), kPositiveInfinity),
      std::make_pair(std::numeric_limits<T>::signaling_NaN(), kSignalingNaN),
      std::make_pair(std::numeric_limits<T>::quiet_NaN(), kQuietNaN)};
  return std::vector<std::pair<T, uint64_t>>(&kValues[0],
                                             &kValues[arraysize(kValues)]);
}

TEST(FCLASS) {
  CcTest::InitializeVM();
  {
    auto i_vec = fclass_test_values<float>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fclass_s(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  {
    auto i_vec = fclass_test_values<double>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fclass_d(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }
}

TEST(RISCV7) {
  // Test floating point compare and
  // branch instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    int32_t result;
  } t;

  // Create a function that accepts &t,
  // and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  Label neither_is_nan, less_than, outa_here;
  auto fn = [&neither_is_nan, &less_than, &outa_here](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));

    __ fclass_d(t5, ft0);
    __ fclass_d(t6, ft1);
    __ or_(t5, t5, t6);
    __ andi(t5, t5, kSignalingNaN | kQuietNaN);
    __ beq(t5, zero_reg, &neither_is_nan);
    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&neither_is_nan);

    __ flt_d(t5, ft1, ft0);
    __ bne(t5, zero_reg, &less_than);

    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&less_than);
    __ RV_li(a4, 1);
    __ sw(a4, a0, offsetof(T, result));  // Set true.

    // This test-case should have additional
    // tests.

    __ bind(&outa_here);
  };

  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 2.0;
  t.d = -4.0;
  t.e = 0.0;
  t.f = 0.0;
  t.result = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1, t.result);
}

TEST(RISCV9) {
  // Test BRANCH improvements.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label exit, exit2, exit3;

  __ Branch(&exit, ge, a0, Operand(zero_reg));
  __ Branch(&exit2, ge, a0, Operand(0x00001FFF));
  __ Branch(&exit3, ge, a0, Operand(0x0001FFFF));

  __ bind(&exit);
  __ bind(&exit2);
  __ bind(&exit3);
  __ jr(ra);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  USE(code);
}

TEST(NAN_BOX) {
  // Test float NaN-boxing.
  CcTest::InitializeVM();

  // Test NaN boxing in FMV.X.D
  {
    auto fn = [](MacroAssembler& assm) { __ fmv_x_d(a0, fa0); };
    auto res = GenAndRunTest<uint64_t>(1234.56f, fn);
    CHECK_EQ(0xFFFFFFFF00000000 | base::bit_cast<uint32_t>(1234.56f), res);
  }
  // Test NaN boxing in FMV.X.W
  {
    auto fn = [](MacroAssembler& assm) { __ fmv_x_w(a0, fa0); };
    auto res = GenAndRunTest<uint64_t>(1234.56f, fn);
    CHECK_EQ((uint64_t)base::bit_cast<uint32_t>(1234.56f), res);
  }

  // Test signaling NaN in FMV.S
  {
    auto fn = [](MacroAssembler& assm) {
      __ fmv_w_x(fa0, a0);
      __ fmv_s(ft1, fa0);
      __ fmv_s(fa0, ft1);
    };
    auto res = GenAndRunTest<uint32_t>(0x7f400000, fn);
    CHECK_EQ((uint32_t)base::bit_cast<uint32_t>(0x7f400000), res);
  }

  // Test signaling NaN in FMV.D
  {
    auto fn = [](MacroAssembler& assm) {
      __ fmv_d_x(fa0, a0);
      __ fmv_d(ft1, fa0);
      __ fmv_d(fa0, ft1);
    };
    auto res = GenAndRunTest<uint64_t>(0x7ff4000000000000, fn);
    CHECK_EQ((uint64_t)base::bit_cast<uint64_t>(0x7ff4000000000000), res);
  }

  // Test FLW and FSW
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    float a;
    uint64_t box;
    uint64_t res;
  } t;

  auto fn = [](MacroAssembler& assm) {
    // Load all structure elements to registers.
    __ flw(fa0, a0, offsetof(T, a));
    // Check boxing when flw
    __ fsd(fa0, a0, offsetof(T, box));
    // Check only transfer low 32bits when fsw
    __ fsw(fa0, a0, offsetof(T, res));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = -123.45;
  t.box = 0;
  t.res = 0;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(0xFFFFFFFF00000000 | base::bit_cast<int32_t>(t.a), t.box);
  CHECK_EQ((uint64_t)base::bit_cast<uint32_t>(t.a), t.res);
}

TEST(RVC_CI) {
  // Test RV64C extension CI type instructions.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.addi
  {
    auto fn = [](MacroAssembler& assm) { __ c_addi(a0, -15); };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_EXCEED_32_BIT, fn);
    CHECK_EQ(LARGE_INT_EXCEED_32_BIT - 15, res);
  }

  // Test c.addiw
  {
    auto fn = [](MacroAssembler& assm) { __ c_addiw(a0, -20); };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - 20, res);
  }

  // Test c.addi16sp
  {
    auto fn = [](MacroAssembler& assm) {
      __ mv(t1, sp);
      __ mv(sp, a0);
      __ c_addi16sp(-432);
      __ mv(a0, sp);
      __ mv(sp, t1);
    };
    auto res = GenAndRunTest<int64_t>(66666, fn);
    CHECK_EQ(66666 - 432, res);
  }

  // Test c.li
  {
    auto fn = [](MacroAssembler& assm) { __ c_li(a0, -15); };
    auto res = GenAndRunTest<int64_t>(1234543, fn);
    CHECK_EQ(-15, res);
  }

  // Test c.lui
  {
    auto fn = [](MacroAssembler& assm) { __ c_lui(a0, -20); };
    auto res = GenAndRunTest<int64_t>(0x1234567, fn);
    CHECK_EQ(0xfffffffffffec000, (uint64_t)res);
  }

  // Test c.slli
  {
    auto fn = [](MacroAssembler& assm) { __ c_slli(a0, 13); };
    auto res = GenAndRunTest<int64_t>(0x1234'5678ULL, fn);
    CHECK_EQ(0x1234'5678ULL << 13, res);
  }
}

TEST(RVC_CIW) {
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.addi4spn
  {
    auto fn = [](MacroAssembler& assm) {
      __ mv(t1, sp);
      __ mv(sp, a0);
      __ c_addi4spn(a0, 924);
      __ mv(sp, t1);
    };
    auto res = GenAndRunTest<int64_t>(66666, fn);
    CHECK_EQ(66666 + 924, res);
  }
}

TEST(RVC_CR) {
  // Test RV64C extension CR type instructions.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.add
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_add(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_EXCEED_32_BIT, fn);
    CHECK_EQ(LARGE_INT_EXCEED_32_BIT + MIN_VAL_IMM12, res);
  }
}

TEST(RVC_CA) {
  // Test RV64C extension CA type instructions.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.sub
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_sub(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - MIN_VAL_IMM12, res);
  }

  // Test c.xor
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_xor(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT ^ MIN_VAL_IMM12, res);
  }

  // Test c.or
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_or(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT | MIN_VAL_IMM12, res);
  }

  // Test c.and
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_and(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT & MIN_VAL_IMM12, res);
  }

  // Test c.subw
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_subw(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - MIN_VAL_IMM12, res);
  }

  // Test c.addw
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_addw(a0, a1);
    };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT + MIN_VAL_IMM12, res);
  }
}

TEST(RVC_LOAD_STORE_SP) {
  // Test RV64C extension fldsp/fsdsp, lwsp/swsp, ldsp/sdsp.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_fsdsp(fa0, 80);
      __ c_fldsp(fa0, 80);
    };
    auto res = GenAndRunTest<double>(-3456.678, fn);
    CHECK_EQ(-3456.678, res);
  }

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_swsp(a0, 40);
      __ c_lwsp(a0, 40);
    };
    auto res = GenAndRunTest<int32_t>(0x456AF894, fn);
    CHECK_EQ(0x456AF894, res);
  }

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_sdsp(a0, 160);
      __ c_ldsp(a0, 160);
    };
    auto res = GenAndRunTest<uint64_t>(0xFBB10A9C12345678, fn);
    CHECK_EQ(0xFBB10A9C12345678, res);
  }
}

TEST(RVC_LOAD_STORE_COMPRESSED) {
  // Test RV64C extension fld,  lw, ld.
  i::v8_flags.riscv_c_extension = true;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
  } t;

  // c.fld
  {
    auto fn = [](MacroAssembler& assm) {
      __ c_fld(fa0, a0, offsetof(T, a));
      __ c_fld(fa1, a0, offsetof(T, b));
      __ fadd_d(fa2, fa1, fa0);
      __ c_fsd(fa2, a0, offsetof(T, c));  // c = a + b.
    };
    auto f = AssembleCode<F3>(isolate, fn);

    t.a = 1.5e14;
    t.b = 1.5e14;
    t.c = 3.0e14;
    f.Call(&t, 0, 0, 0, 0);
    // Expected double results.
    CHECK_EQ(1.5e14, t.a);
    CHECK_EQ(1.5e14, t.b);
    CHECK_EQ(3.0e14, t.c);
  }

  struct S {
    int32_t a;
    int32_t b;
    int32_t c;
  } s;
  // c.lw
  {
    auto fn = [](MacroAssembler& assm) {
      __ c_lw(a1, a0, offsetof(S, a));
      __ c_lw(a2, a0, offsetof(S, b));
      __ add(a3, a1, a2);
      __ c_sw(a3, a0, offsetof(S, c));  // c = a + b.
    };
    auto f = AssembleCode<F3>(isolate, fn);

    s.a = 1;
    s.b = 2;
    s.c = 3;
    f.Call(&s, 0, 0, 0, 0);
    CHECK_EQ(1, s.a);
    CHECK_EQ(2, s.b);
    CHECK_EQ(3, s.c);
  }

  struct U {
    int64_t a;
    int64_t b;
    int64_t c;
  } u;
  // c.ld
  {
    auto fn = [](MacroAssembler& assm) {
      __ c_ld(a1, a0, offsetof(U, a));
      __ c_ld(a2, a0, offsetof(U, b));
      __ add(a3, a1, a2);
      __ c_sd(a3, a0, offsetof(U, c));  // c = a + b.
    };
    auto f = AssembleCode<F3>(isolate, fn);

    u.a = 1;
    u.b = 2;
    u.c = 3;
    f.Call(&u, 0, 0, 0, 0);
    CHECK_EQ(1, u.a);
    CHECK_EQ(2, u.b);
    CHECK_EQ(3, u.c);
  }
}

TEST(RVC_JUMP) {
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  Label L, C;
  auto fn = [&L, &C](MacroAssembler& assm) {
    __ mv(a1, a0);
    __ RV_li(a0, 0l);
    __ c_j(&C);

    __ bind(&L);
    __ add(a0, a0, a1);
    __ addi(a1, a1, -1);

    __ bind(&C);
    __ xori(a2, a1, 0);
    __ bnez(a2, &L);
  };

  int64_t input = 50;
  int64_t expected_res = 1275L;
  auto res = GenAndRunTest<int64_t>(input, fn);
  CHECK_EQ(expected_res, res);
}

TEST(RVC_CB) {
  // Test RV64C extension CI type instructions.
  v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.srai
  {
    auto fn = [](MacroAssembler& assm) { __ c_srai(a0, 13); };
    auto res = GenAndRunTest<int64_t>(0x1234'5678ULL, fn);
    CHECK_EQ(0x1234'5678ULL >> 13, res);
  }

  // Test c.srli
  {
    auto fn = [](MacroAssembler& assm) { __ c_srli(a0, 13); };
    auto res = GenAndRunTest<int64_t>(0x1234'5678ULL, fn);
    CHECK_EQ(0x1234'5678ULL >> 13, res);
  }

  // Test c.andi
  {
    auto fn = [](MacroAssembler& assm) { __ c_andi(a0, 13); };
    auto res = GenAndRunTest<int64_t>(LARGE_INT_EXCEED_32_BIT, fn);
    CHECK_EQ(LARGE_INT_EXCEED_32_BIT & 13, res);
  }
}

TEST(RVC_CB_BRANCH) {
  v8_flags.riscv_c_extension = true;
  // Test floating point compare and
  // branch instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    int32_t result;
  } t;

  // Create a function that accepts &t,
  // and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  Label neither_is_nan, less_than, outa_here;
  auto fn = [&neither_is_nan, &less_than, &outa_here](MacroAssembler& assm) {
    __ fld(ft0, a0, offsetof(T, a));
    __ fld(ft1, a0, offsetof(T, b));

    __ fclass_d(t5, ft0);
    __ fclass_d(t6, ft1);
    __ or_(a1, t5, t6);
    __ andi(a1, a1, kSignalingNaN | kQuietNaN);
    __ c_beqz(a1, &neither_is_nan);
    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&neither_is_nan);

    __ flt_d(a1, ft1, ft0);
    __ c_bnez(a1, &less_than);

    __ sw(zero_reg, a0, offsetof(T, result));
    __ j(&outa_here);

    __ bind(&less_than);
    __ RV_li(a4, 1);
    __ sw(a4, a0, offsetof(T, result));  // Set true.

    // This test-case should have additional
    // tests.

    __ bind(&outa_here);
  };

  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e14;
  t.b = 2.75e11;
  t.c = 2.0;
  t.d = -4.0;
  t.e = 0.0;
  t.f = 0.0;
  t.result = 0;
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(1.5e14, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1, t.result);
}

TEST(TARGET_ADDR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

#ifdef RISCV_USE_SV39
  // This is the series of instructions to load 39 bit address 0x00304a
```