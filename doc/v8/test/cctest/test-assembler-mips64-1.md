Response: The user wants me to summarize the functionality of the C++ code provided in the text. This is the second part of a seven-part file. The code consists of several independent test cases for MIPS64 assembly instructions, particularly those related to floating-point operations.

Here's a breakdown of the tests in this section:

*   **`TEST(movt_movd)`**: Tests the `movt.s`, `movt.d`, `movf.s`, and `movf.d` instructions, which conditionally move single-precision and double-precision floating-point values based on the floating-point condition codes.
*   **`TEST(cvt_w_d)`**: Tests the `cvt.w.d` instruction, which converts a double-precision floating-point number to a 32-bit integer, respecting different rounding modes set in the FCSR.
*   **`TEST(trunc_w)`**: Tests the `trunc.w.d` and `trunc.w.s` instructions, which truncate double-precision and single-precision floating-point numbers to 32-bit integers.
*   **`TEST(round_w)`**: Tests the `round.w.d` and `round.w.s` instructions, which round double-precision and single-precision floating-point numbers to the nearest 32-bit integer.
*   **`TEST(round_l)`**: Tests the `round.l.d` and `round.l.s` instructions, which round double-precision and single-precision floating-point numbers to the nearest 64-bit integer.
*   **`TEST(sub)`**: Tests the `sub.s` and `sub.d` instructions, which perform subtraction on single-precision and double-precision floating-point numbers.
*   **`TEST(sqrt_rsqrt_recip)`**: Tests the `sqrt.s`, `sqrt.d`, `rsqrt.s`, `rsqrt.d`, `recip.s`, and `recip.d` instructions, which calculate the square root, reciprocal square root, and reciprocal of single-precision and double-precision floating-point numbers.
*   **`TEST(neg)`**: Tests the `neg.s` and `neg.d` instructions, which negate single-precision and double-precision floating-point numbers.
*   **`TEST(mul)`**: Tests the `mul.s` and `mul.d` instructions, which perform multiplication on single-precision and double-precision floating-point numbers.
*   **`TEST(mov)`**: Tests the `mov.s` and `mov.d` instructions, which move single-precision and double-precision floating-point numbers between registers.
*   **`TEST(floor_w)`**: Tests the `floor.w.d` and `floor.w.s` instructions, which round double-precision and single-precision floating-point numbers down to the nearest 32-bit integer.
*   **`TEST(floor_l)`**: Tests the `floor.l.d` and `floor.l.s` instructions, which round double-precision and single-precision floating-point numbers down to the nearest 64-bit integer.
*   **`TEST(ceil_w)`**: Tests the `ceil.w.d` and `ceil.w.s` instructions, which round double-precision and single-precision floating-point numbers up to the nearest 32-bit integer.
*   **`TEST(ceil_l)`**: Tests the `ceil.l.d` and `ceil.l.s` instructions, which round double-precision and single-precision floating-point numbers up to the nearest 64-bit integer.
*   **`TEST(jump_tables1)`**: Tests the creation and execution of jump tables using forward jumps.
*   **`TEST(jump_tables2)`**: Tests the creation and execution of jump tables using backward jumps.
*   **`TEST(jump_tables3)`**: Tests the creation and execution of jump tables with backward jumps and embedded heap objects.
*   **`TEST(BITSWAP)`**: Tests the `bitswap` and `dbitswap` instructions for byte swapping within registers (specific to MIPS64r6).
*   **`TEST(class_fmt)`**: Tests the `class.d` and `class.s` instructions, which determine the class of a floating-point number (specific to MIPS64r6).
*   **`TEST(ABS)`**: Tests the `abs.s` and `abs.d` instructions, which calculate the absolute value of single-precision and double-precision floating-point numbers.
*   **`TEST(ADD_FMT)`**: Tests the `add.s` and `add.d` instructions for floating-point addition.
*   **`TEST(C_COND_FMT)`**: Tests the `c.cond.d` and `c.cond.s` instructions, which compare floating-point numbers and set the floating-point condition codes (specific to MIPS64r2).
*   **`TEST(CMP_COND_FMT)`**: Tests the `cmp.cond.d` and `cmp.cond.s` instructions, which compare floating-point numbers and write a boolean result to a register (specific to MIPS64r6).

These tests are part of the V8 JavaScript engine's testing infrastructure. They ensure the correctness of the generated MIPS64 assembly code for various floating-point operations, which are fundamental to JavaScript number handling. I need to provide a concise summary and a JavaScript example that relates to these floating-point operations.
This C++ code file (part 2 of 7) contains a series of unit tests for the MIPS64 assembler in the V8 JavaScript engine. These tests verify the correct functionality of various MIPS64 instructions, particularly focusing on **floating-point operations**.

Specifically, this section includes tests for:

*   **Conditional moves**: Instructions like `movt.s`, `movt.d`, `movf.s`, `movf.d` which move floating-point values based on the status of floating-point condition codes.
*   **Floating-point conversions to integers**: Instructions like `cvt.w.d`, `trunc.w.d`, `trunc.w.s`, `round.w.d`, `round.w.s`, `round.l.d`, `round.l.s`, `floor.w.d`, `floor.w.s`, `floor.l.d`, `floor.l.s`, `ceil.w.d`, `ceil.w.s`, `ceil.l.d`, `ceil.l.s` which convert floating-point numbers to integers with different rounding behaviors.
*   **Basic arithmetic operations**: Instructions like `sub.s`, `sub.d` (subtraction), `sqrt.s`, `sqrt.d`, `rsqrt.s`, `rsqrt.d`, `recip.s`, `recip.d` (square root, reciprocal square root, reciprocal), `neg.s`, `neg.d` (negation), `mul.s`, `mul.d` (multiplication).
*   **Floating-point moves**: Instructions like `mov.s`, `mov.d` for moving floating-point values between registers.
*   **Jump tables**: Tests for creating and using jump tables, which are used for efficient multi-way branching.
*   **Bit manipulation (MIPS64r6 specific)**: Instructions like `bitswap`, `dbitswap` for byte swapping.
*   **Floating-point classification (MIPS64r6 specific)**: Instructions like `class.d`, `class.s` to determine the category of a floating-point number (e.g., NaN, infinity, zero).
*   **Absolute value**: Instructions like `abs.s`, `abs.d`.
*   **Floating-point addition**: Instructions like `add.s`, `add.d`.
*   **Floating-point comparisons (MIPS64r2 and MIPS64r6 specific)**: Instructions like `c.cond.d`, `c.cond.s`, `cmp.cond.d`, `cmp.cond.s` for comparing floating-point numbers and setting condition codes or writing boolean results.

These tests work by:

1. Defining a C++ structure to hold input and output values for the instruction being tested.
2. Writing a small assembly code snippet using the `MacroAssembler` to perform the operation on the input values.
3. Executing the generated assembly code.
4. Comparing the output values in the structure with expected results.

**Relationship to JavaScript:**

These low-level assembly instructions are crucial for implementing JavaScript's number type, which is based on the IEEE 754 double-precision floating-point format. When JavaScript code performs arithmetic or other operations on numbers, the V8 engine (if targeting MIPS64 architecture) will generate these corresponding MIPS64 assembly instructions.

**JavaScript Example:**

Consider the JavaScript operation of calculating the square root of a number:

```javascript
let x = 16.0;
let y = Math.sqrt(x);
console.log(y); // Output: 4
```

When this JavaScript code is executed on a MIPS64 architecture, the V8 engine will likely generate the `sqrt.d` assembly instruction (tested in this file) to perform the actual square root calculation. Similarly, basic arithmetic operations like addition, subtraction, multiplication, division, and conversions between numbers and integers rely on the correct implementation of the corresponding MIPS64 floating-point instructions verified in these tests. For example, `Math.floor()`, `Math.ceil()`, `Math.round()`, and type conversions to integers (`parseInt()`, bitwise operations) would involve the integer conversion instructions tested here.

Therefore, the functionality tested in this C++ file directly underpins the correct and efficient execution of numerical operations in JavaScript when running on MIPS64 systems.

### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```
le inputsb[kTableLength] = {
        4.8, 5.3,  6.1, -10.0, -8.9, -9.8, 9.8,  9.8,  9.8,  -9.8,  -11.2, -9.8,
        3.0, dnan, 0.0, -0.0,  dnan, dinf, dinf, 42.0, dinf, dminf, dnan};
    double resd[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
        3.0, 3.0, -0.0, -0.0, dinf, dinf, 42.0, 42.0, dminf, dminf, dnan};
    double resd1[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
        3.0, 3.0, 0.0, 0.0,   dinf, dinf, dinf,  dinf, dinf, dinf,  dnan};
    float inputsc[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
        fnan, 3.0, -0.0, 0.0, finf, fnan, 42.0,  finf, fminf, finf,  fnan};
    float inputsd[kTableLength] = {4.8,  5.3,  6.1,  -10.0, -8.9,  -9.8,
                                   9.8,  9.8,  9.8,  -9.8,  -11.2, -9.8,
                                   3.0,  fnan, -0.0, 0.0,   fnan,  finf,
                                   finf, 42.0, finf, fminf, fnan};
    float resf[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
        3.0, 3.0, -0.0, -0.0, finf, finf, 42.0, 42.0, fminf, fminf, fnan};
    float resf1[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
        3.0, 3.0, 0.0, 0.0,   finf, finf, finf,  finf, finf, finf,  fnan};

    __ Ldc1(f2, MemOperand(a0, offsetof(TestFloat, a)));
    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, b)));
    __ Lwc1(f8, MemOperand(a0, offsetof(TestFloat, c)));
    __ Lwc1(f10, MemOperand(a0, offsetof(TestFloat, d)));
    __ mina_d(f6, f2, f4);
    __ mina_s(f12, f8, f10);
    __ maxa_d(f14, f2, f4);
    __ maxa_s(f16, f8, f10);
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, resf)));
    __ Sdc1(f6, MemOperand(a0, offsetof(TestFloat, resd)));
    __ Swc1(f16, MemOperand(a0, offsetof(TestFloat, resf1)));
    __ Sdc1(f14, MemOperand(a0, offsetof(TestFloat, resd1)));
    __ jr(ra);
    __ nop();

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
        CHECK_EQ(test.resd, resd[i]);
        CHECK_EQ(test.resf, resf[i]);
        CHECK_EQ(test.resd1, resd1[i]);
        CHECK_EQ(test.resf1, resf1[i]);
      } else {
        CHECK(std::isnan(test.resd));
        CHECK(std::isnan(test.resf));
        CHECK(std::isnan(test.resd1));
        CHECK(std::isnan(test.resf1));
      }
    }
  }
}



// ----------------------mips64r2 specific tests----------------------
TEST(trunc_l) {
  if (kArchVariant == kMips64r2) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    const double dFPU64InvalidResult = static_cast<double>(kFPU64InvalidResult);
    struct Test {
      uint32_t isNaN2008;
      double a;
      float b;
      int64_t c;  // a trunc result
      int64_t d;  // b trunc result
    };
    const int kTableLength = 15;
    double inputs_D[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity()
        };
    float inputs_S[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()
        };
    double outputs[kTableLength] = {
        2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
        -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
        2147483648.0, dFPU64InvalidResult,
        dFPU64InvalidResult};
    double outputsNaN2008[kTableLength] = {
        2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
        -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
        2147483648.0, dFPU64InvalidResult,
        dFPU64InvalidResult};

    __ cfc1(t1, FCSR);
    __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
    __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
    __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
    __ trunc_l_d(f8, f4);
    __ trunc_l_s(f10, f6);
    __ Sdc1(f8, MemOperand(a0, offsetof(Test, c)));
    __ Sdc1(f10, MemOperand(a0, offsetof(Test, d)));
    __ jr(ra);
    __ nop();
    Test test;
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_D[i];
      test.b = inputs_S[i];
      f.Call(&test, 0, 0, 0, 0);
      if ((test.isNaN2008 & kFCSRNaN2008FlagMask) &&
              kArchVariant == kMips64r6) {
        CHECK_EQ(test.c, outputsNaN2008[i]);
      } else {
        CHECK_EQ(test.c, outputs[i]);
      }
      CHECK_EQ(test.d, test.c);
    }
  }
}


TEST(movz_movn) {
  if (kArchVariant == kMips64r2) {
    const int kTableLength = 4;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      int64_t rt;
      double a;
      double b;
      double bold;
      double b1;
      double bold1;
      float c;
      float d;
      float dold;
      float d1;
      float dold1;
    };

    TestFloat test;
    double inputs_D[kTableLength] = {
      5.3, -5.3, 5.3, -2.9
    };
    double inputs_S[kTableLength] = {
      4.8, 4.8, -4.8, -0.29
    };

    float outputs_S[kTableLength] = {
      4.8, 4.8, -4.8, -0.29
    };
    double outputs_D[kTableLength] = {
      5.3, -5.3, 5.3, -2.9
    };

    __ Ldc1(f2, MemOperand(a0, offsetof(TestFloat, a)));
    __ Lwc1(f6, MemOperand(a0, offsetof(TestFloat, c)));
    __ Ld(t0, MemOperand(a0, offsetof(TestFloat, rt)));
    __ Move(f12, 0.0);
    __ Move(f10, 0.0);
    __ Move(f16, 0.0);
    __ Move(f14, 0.0);
    __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, bold)));
    __ Swc1(f10, MemOperand(a0, offsetof(TestFloat, dold)));
    __ Sdc1(f16, MemOperand(a0, offsetof(TestFloat, bold1)));
    __ Swc1(f14, MemOperand(a0, offsetof(TestFloat, dold1)));
    __ movz_s(f10, f6, t0);
    __ movz_d(f12, f2, t0);
    __ movn_s(f14, f6, t0);
    __ movn_d(f16, f2, t0);
    __ Swc1(f10, MemOperand(a0, offsetof(TestFloat, d)));
    __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, b)));
    __ Swc1(f14, MemOperand(a0, offsetof(TestFloat, d1)));
    __ Sdc1(f16, MemOperand(a0, offsetof(TestFloat, b1)));
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_D[i];
      test.c = inputs_S[i];

      test.rt = 1;
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.b, test.bold);
      CHECK_EQ(test.d, test.dold);
      CHECK_EQ(test.b1, outputs_D[i]);
      CHECK_EQ(test.d1, outputs_S[i]);

      test.rt = 0;
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.b, outputs_D[i]);
      CHECK_EQ(test.d, outputs_S[i]);
      CHECK_EQ(test.b1, test.bold1);
      CHECK_EQ(test.d1, test.dold1);
    }
  }
}


TEST(movt_movd) {
  if (kArchVariant == kMips64r2) {
    const int kTableLength = 4;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    struct TestFloat {
      double srcd;
      double dstd;
      double dstdold;
      double dstd1;
      double dstdold1;
      float srcf;
      float dstf;
      float dstfold;
      float dstf1;
      float dstfold1;
      int32_t cc;
      int32_t fcsr;
    };

    TestFloat test;
    double inputs_D[kTableLength] = {
      5.3, -5.3, 20.8, -2.9
    };
    double inputs_S[kTableLength] = {
      4.88, 4.8, -4.8, -0.29
    };

    float outputs_S[kTableLength] = {
      4.88, 4.8, -4.8, -0.29
    };
    double outputs_D[kTableLength] = {
      5.3, -5.3, 20.8, -2.9
    };
    int condition_flags[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    for (int i = 0; i < kTableLength; i++) {
      test.srcd = inputs_D[i];
      test.srcf = inputs_S[i];

      for (int j = 0; j< 8; j++) {
        test.cc = condition_flags[j];
        if (test.cc == 0) {
          test.fcsr = 1 << 23;
        } else {
          test.fcsr = 1 << (24+condition_flags[j]);
        }
        HandleScope scope(isolate);
        MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
        __ Ldc1(f2, MemOperand(a0, offsetof(TestFloat, srcd)));
        __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, srcf)));
        __ Lw(t1, MemOperand(a0, offsetof(TestFloat, fcsr)));
        __ cfc1(t0, FCSR);
        __ ctc1(t1, FCSR);
        __ li(t2, 0x0l);
        __ mtc1(t2, f12);
        __ mtc1(t2, f10);
        __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, dstdold)));
        __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, dstfold)));
        __ movt_s(f12, f4, test.cc);
        __ movt_d(f10, f2, test.cc);
        __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, dstf)));
        __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, dstd)));
        __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, dstdold1)));
        __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, dstfold1)));
        __ movf_s(f12, f4, test.cc);
        __ movf_d(f10, f2, test.cc);
        __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, dstf1)));
        __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, dstd1)));
        __ ctc1(t0, FCSR);
        __ jr(ra);
        __ nop();

        CodeDesc desc;
        assm.GetCode(isolate, &desc);
        Handle<Code> code =
            Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
        auto f = GeneratedCode<F3>::FromCode(isolate, *code);

        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.dstf, outputs_S[i]);
        CHECK_EQ(test.dstd, outputs_D[i]);
        CHECK_EQ(test.dstf1, test.dstfold1);
        CHECK_EQ(test.dstd1, test.dstdold1);
        test.fcsr = 0;
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.dstf, test.dstfold);
        CHECK_EQ(test.dstd, test.dstdold);
        CHECK_EQ(test.dstf1, outputs_S[i]);
        CHECK_EQ(test.dstd1, outputs_D[i]);
      }
    }
  }
}



// ----------------------tests for all archs--------------------------
TEST(cvt_w_d) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double a;
    int32_t b;
    int fcsr;
  };
  const int kTableLength = 24;
  double inputs[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483637.0, 2147483638.0, 2147483639.0,
      2147483640.0, 2147483641.0, 2147483642.0,
      2147483643.0, 2147483644.0, 2147483645.0,
      2147483646.0, 2147483647.0, 2147483653.0
      };
  double outputs_RN[kTableLength] = {
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      2147483637.0, 2147483638.0, 2147483639.0,
      2147483640.0, 2147483641.0, 2147483642.0,
      2147483643.0, 2147483644.0, 2147483645.0,
      2147483646.0, 2147483647.0, kFPUInvalidResult};
  double outputs_RZ[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      2147483637.0, 2147483638.0, 2147483639.0,
      2147483640.0, 2147483641.0, 2147483642.0,
      2147483643.0, 2147483644.0, 2147483645.0,
      2147483646.0, 2147483647.0, kFPUInvalidResult};
  double outputs_RP[kTableLength] = {
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      2147483637.0, 2147483638.0, 2147483639.0,
      2147483640.0, 2147483641.0, 2147483642.0,
      2147483643.0, 2147483644.0, 2147483645.0,
      2147483646.0, 2147483647.0, kFPUInvalidResult};
  double outputs_RM[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      2147483637.0, 2147483638.0, 2147483639.0,
      2147483640.0, 2147483641.0, 2147483642.0,
      2147483643.0, 2147483644.0, 2147483645.0,
      2147483646.0, 2147483647.0, kFPUInvalidResult};
  int fcsr_inputs[4] =
      {kRoundToNearest, kRoundToZero, kRoundToPlusInf, kRoundToMinusInf};
  double* outputs[4] = {outputs_RN, outputs_RZ, outputs_RP, outputs_RM};
  __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
  __ Lw(t0, MemOperand(a0, offsetof(Test, fcsr)));
  __ cfc1(t1, FCSR);
  __ ctc1(t0, FCSR);
  __ cvt_w_d(f8, f4);
  __ Swc1(f8, MemOperand(a0, offsetof(Test, b)));
  __ ctc1(t1, FCSR);
  __ jr(ra);
  __ nop();
  Test test;
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int j = 0; j < 4; j++) {
    test.fcsr = fcsr_inputs[j];
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs[i];
      f.Call(&test, 0, 0, 0, 0);
      CHECK_EQ(test.b, outputs[j][i]);
    }
  }
}


TEST(trunc_w) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    uint32_t isNaN2008;
    double a;
    float b;
    int32_t c;  // a trunc result
    int32_t d;  // b trunc result
  };
  const int kTableLength = 15;
  double inputs_D[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  float inputs_S[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::infinity()
      };
  double outputs[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, kFPUInvalidResult,
      kFPUInvalidResult};
  double outputsNaN2008[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult,
      0,
      kFPUInvalidResult};

  __ cfc1(t1, FCSR);
  __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
  __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
  __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
  __ trunc_w_d(f8, f4);
  __ trunc_w_s(f10, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(Test, c)));
  __ Swc1(f10, MemOperand(a0, offsetof(Test, d)));
  __ jr(ra);
  __ nop();
  Test test;
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.b = inputs_S[i];
    f.Call(&test, 0, 0, 0, 0);
    if ((test.isNaN2008 & kFCSRNaN2008FlagMask) && kArchVariant == kMips64r6) {
      CHECK_EQ(test.c, outputsNaN2008[i]);
    } else {
      CHECK_EQ(test.c, outputs[i]);
    }
    CHECK_EQ(test.d, test.c);
  }
}


TEST(round_w) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    uint32_t isNaN2008;
    double a;
    float b;
    int32_t c;  // a trunc result
    int32_t d;  // b trunc result
  };
  const int kTableLength = 15;
  double inputs_D[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  float inputs_S[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::infinity()
      };
  double outputs[kTableLength] = {
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      kFPUInvalidResult, kFPUInvalidResult,
      kFPUInvalidResult};
  double outputsNaN2008[kTableLength] = {
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      kFPUInvalidResult, 0,
      kFPUInvalidResult};

  __ cfc1(t1, FCSR);
  __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
  __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
  __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
  __ round_w_d(f8, f4);
  __ round_w_s(f10, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(Test, c)));
  __ Swc1(f10, MemOperand(a0, offsetof(Test, d)));
  __ jr(ra);
  __ nop();
  Test test;
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.b = inputs_S[i];
    f.Call(&test, 0, 0, 0, 0);
    if ((test.isNaN2008 & kFCSRNaN2008FlagMask) && kArchVariant == kMips64r6) {
      CHECK_EQ(test.c, outputsNaN2008[i]);
    } else {
      CHECK_EQ(test.c, outputs[i]);
    }
    CHECK_EQ(test.d, test.c);
  }
}


TEST(round_l) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    const double dFPU64InvalidResult = static_cast<double>(kFPU64InvalidResult);
    struct Test {
      uint32_t isNaN2008;
      double a;
      float b;
      int64_t c;
      int64_t d;
    };
    const int kTableLength = 15;
    double inputs_D[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity()
        };
    float inputs_S[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()
        };
    double outputs[kTableLength] = {
        2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
        -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
        2147483648.0, dFPU64InvalidResult,
        dFPU64InvalidResult};
    double outputsNaN2008[kTableLength] = {
        2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
        -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
        2147483648.0,
        0,
        dFPU64InvalidResult};

    __ cfc1(t1, FCSR);
    __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
    __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
    __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
    __ round_l_d(f8, f4);
    __ round_l_s(f10, f6);
    __ Sdc1(f8, MemOperand(a0, offsetof(Test, c)));
    __ Sdc1(f10, MemOperand(a0, offsetof(Test, d)));
    __ jr(ra);
    __ nop();
    Test test;
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_D[i];
      test.b = inputs_S[i];
      f.Call(&test, 0, 0, 0, 0);
      if ((test.isNaN2008 & kFCSRNaN2008FlagMask) &&
              kArchVariant == kMips64r6) {
        CHECK_EQ(test.c, outputsNaN2008[i]);
      } else {
        CHECK_EQ(test.c, outputs[i]);
      }
      CHECK_EQ(test.d, test.c);
    }
}


TEST(sub) {
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
  __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, a)));
  __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, b)));
  __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, c)));
  __ Ldc1(f10, MemOperand(a0, offsetof(TestFloat, d)));
  __ sub_s(f6, f2, f4);
  __ sub_d(f12, f8, f10);
  __ Swc1(f6, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ jr(ra);
  __ nop();

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


TEST(sqrt_rsqrt_recip) {
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
    float resultS;
    float resultS1;
    float resultS2;
    double c;
    double resultD;
    double resultD1;
    double resultD2;
  };
  TestFloat test;

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

  __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, a)));
  __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, c)));
  __ sqrt_s(f6, f2);
  __ sqrt_d(f12, f8);
  __ rsqrt_d(f14, f8);
  __ rsqrt_s(f16, f2);
  __ recip_d(f18, f8);
  __ recip_s(f4, f2);
  __ Swc1(f6, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ Swc1(f16, MemOperand(a0, offsetof(TestFloat, resultS1)));
  __ Sdc1(f14, MemOperand(a0, offsetof(TestFloat, resultD1)));
  __ Swc1(f4, MemOperand(a0, offsetof(TestFloat, resultS2)));
  __ Sdc1(f18, MemOperand(a0, offsetof(TestFloat, resultD2)));
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  for (int i = 0; i < kTableLength; i++) {
    float f1;
    double d1;
    test.a = inputs_S[i];
    test.c = inputs_D[i];

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(test.resultS, outputs_S[i]);
    CHECK_EQ(test.resultD, outputs_D[i]);

    if (i != 0) {
      f1 = test.resultS1 - 1.0F/outputs_S[i];
      f1 = (f1 < 0) ? f1 : -f1;
      CHECK(f1 <= deltaFloat);
      d1 = test.resultD1 - 1.0L/outputs_D[i];
      d1 = (d1 < 0) ? d1 : -d1;
      CHECK(d1 <= deltaDouble);
      f1 = test.resultS2 - 1.0F/inputs_S[i];
      f1 = (f1 < 0) ? f1 : -f1;
      CHECK(f1 <= deltaFloat);
      d1 = test.resultD2 - 1.0L/inputs_D[i];
      d1 = (d1 < 0) ? d1 : -d1;
      CHECK(d1 <= deltaDouble);
    } else {
      CHECK_EQ(test.resultS1, 1.0F/outputs_S[i]);
      CHECK_EQ(test.resultD1, 1.0L/outputs_D[i]);
      CHECK_EQ(test.resultS2, 1.0F/inputs_S[i]);
      CHECK_EQ(test.resultD2, 1.0L/inputs_D[i]);
    }
  }
}


TEST(neg) {
  const int kTableLength = 2;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float a;
    float resultS;
    double c;
    double resultD;
  };

  TestFloat test;
  double inputs_D[kTableLength] = {
    4.0, -2.0
  };

  double outputs_D[kTableLength] = {
    -4.0, 2.0
  };
  float inputs_S[kTableLength] = {
    4.0, -2.0
  };

  float outputs_S[kTableLength] = {
    -4.0, 2.0
  };
  __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, a)));
  __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, c)));
  __ neg_s(f6, f2);
  __ neg_d(f12, f8);
  __ Swc1(f6, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_S[i];
    test.c = inputs_D[i];
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.resultS, outputs_S[i]);
    CHECK_EQ(test.resultD, outputs_D[i]);
  }
}



TEST(mul) {
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

  __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, a)));
  __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, b)));
  __ Ldc1(f6, MemOperand(a0, offsetof(TestFloat, c)));
  __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, d)));
  __ mul_s(f10, f2, f4);
  __ mul_d(f12, f6, f8);
  __ Swc1(f10, MemOperand(a0, offsetof(TestFloat, resultS)));
  __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, resultD)));
  __ jr(ra);
  __ nop();

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
    CHECK_EQ(test.resultS, inputfs_S[i]*inputft_S[i]);
    CHECK_EQ(test.resultD, inputfs_D[i]*inputft_D[i]);
  }
}


TEST(mov) {
  const int kTableLength = 4;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    double b;
    float c;
    float d;
  };

  TestFloat test;
  double inputs_D[kTableLength] = {
    5.3, -5.3, 5.3, -2.9
  };
  double inputs_S[kTableLength] = {
    4.8, 4.8, -4.8, -0.29
  };

  float outputs_S[kTableLength] = {
    4.8, 4.8, -4.8, -0.29
  };
  double outputs_D[kTableLength] = {
    5.3, -5.3, 5.3, -2.9
  };

  __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
  __ Lwc1(f6, MemOperand(a0, offsetof(TestFloat, c)));
  __ mov_s(f8, f6);
  __ mov_d(f10, f4);
  __ Swc1(f8, MemOperand(a0, offsetof(TestFloat, d)));
  __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, b)));
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.c = inputs_S[i];

    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.b, outputs_D[i]);
    CHECK_EQ(test.d, outputs_S[i]);
  }
}


TEST(floor_w) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    uint32_t isNaN2008;
    double a;
    float b;
    int32_t c;  // a floor result
    int32_t d;  // b floor result
  };
  const int kTableLength = 15;
  double inputs_D[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  float inputs_S[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::infinity()
      };
  double outputs[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      kFPUInvalidResult, kFPUInvalidResult,
      kFPUInvalidResult};
  double outputsNaN2008[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      kFPUInvalidResult,
      0,
      kFPUInvalidResult};

  __ cfc1(t1, FCSR);
  __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
  __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
  __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
  __ floor_w_d(f8, f4);
  __ floor_w_s(f10, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(Test, c)));
  __ Swc1(f10, MemOperand(a0, offsetof(Test, d)));
  __ jr(ra);
  __ nop();
  Test test;
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.b = inputs_S[i];
    f.Call(&test, 0, 0, 0, 0);
    if ((test.isNaN2008 & kFCSRNaN2008FlagMask) && kArchVariant == kMips64r6) {
      CHECK_EQ(test.c, outputsNaN2008[i]);
    } else {
      CHECK_EQ(test.c, outputs[i]);
    }
    CHECK_EQ(test.d, test.c);
  }
}


TEST(floor_l) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    const double dFPU64InvalidResult = static_cast<double>(kFPU64InvalidResult);
    struct Test {
      uint32_t isNaN2008;
      double a;
      float b;
      int64_t c;
      int64_t d;
    };
    const int kTableLength = 15;
    double inputs_D[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity()
        };
    float inputs_S[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()
        };
    double outputs[kTableLength] = {
        2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
        -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
        2147483648.0, dFPU64InvalidResult,
        dFPU64InvalidResult};
    double outputsNaN2008[kTableLength] = {
        2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
        -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
        2147483648.0,
        0,
        dFPU64InvalidResult};

    __ cfc1(t1, FCSR);
    __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
    __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
    __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
    __ floor_l_d(f8, f4);
    __ floor_l_s(f10, f6);
    __ Sdc1(f8, MemOperand(a0, offsetof(Test, c)));
    __ Sdc1(f10, MemOperand(a0, offsetof(Test, d)));
    __ jr(ra);
    __ nop();
    Test test;
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_D[i];
      test.b = inputs_S[i];
      f.Call(&test, 0, 0, 0, 0);
      if ((test.isNaN2008 & kFCSRNaN2008FlagMask) &&
              kArchVariant == kMips64r6) {
        CHECK_EQ(test.c, outputsNaN2008[i]);
      } else {
        CHECK_EQ(test.c, outputs[i]);
      }
      CHECK_EQ(test.d, test.c);
    }
}


TEST(ceil_w) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    uint32_t isNaN2008;
    double a;
    float b;
    int32_t c;  // a floor result
    int32_t d;  // b floor result
  };
  const int kTableLength = 15;
  double inputs_D[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<double>::quiet_NaN(),
      std::numeric_limits<double>::infinity()
      };
  float inputs_S[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      2147483648.0,
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::infinity()
      };
  double outputs[kTableLength] = {
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult, kFPUInvalidResult,
      kFPUInvalidResult};
  double outputsNaN2008[kTableLength] = {
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      kFPUInvalidResult,
      0,
      kFPUInvalidResult};

  __ cfc1(t1, FCSR);
  __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
  __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
  __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
  __ ceil_w_d(f8, f4);
  __ ceil_w_s(f10, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(Test, c)));
  __ Swc1(f10, MemOperand(a0, offsetof(Test, d)));
  __ jr(ra);
  __ nop();
  Test test;
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.b = inputs_S[i];
    f.Call(&test, 0, 0, 0, 0);
    if ((test.isNaN2008 & kFCSRNaN2008FlagMask) && kArchVariant == kMips64r6) {
      CHECK_EQ(test.c, outputsNaN2008[i]);
    } else {
      CHECK_EQ(test.c, outputs[i]);
    }
    CHECK_EQ(test.d, test.c);
  }
}


TEST(ceil_l) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    const double dFPU64InvalidResult = static_cast<double>(kFPU64InvalidResult);
    struct Test {
      uint32_t isNaN2008;
      double a;
      float b;
      int64_t c;
      int64_t d;
    };
    const int kTableLength = 15;
    double inputs_D[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity()
        };
    float inputs_S[kTableLength] = {
        2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
        -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
        2147483648.0,
        std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity()
        };
    double outputs[kTableLength] = {
        3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
        -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
        2147483648.0, dFPU64InvalidResult,
        dFPU64InvalidResult};
    double outputsNaN2008[kTableLength] = {
        3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
        -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
        2147483648.0,
        0,
        dFPU64InvalidResult};

    __ cfc1(t1, FCSR);
    __ Sw(t1, MemOperand(a0, offsetof(Test, isNaN2008)));
    __ Ldc1(f4, MemOperand(a0, offsetof(Test, a)));
    __ Lwc1(f6, MemOperand(a0, offsetof(Test, b)));
    __ ceil_l_d(f8, f4);
    __ ceil_l_s(f10, f6);
    __ Sdc1(f8, MemOperand(a0, offsetof(Test, c)));
    __ Sdc1(f10, MemOperand(a0, offsetof(Test, d)));
    __ jr(ra);
    __ nop();
    Test test;
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputs_D[i];
      test.b = inputs_S[i];
      f.Call(&test, 0, 0, 0, 0);
      if ((test.isNaN2008 & kFCSRNaN2008FlagMask) &&
              kArchVariant == kMips64r6) {
        CHECK_EQ(test.c, outputsNaN2008[i]);
      } else {
        CHECK_EQ(test.c, outputs[i]);
      }
      CHECK_EQ(test.d, test.c);
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

  __ daddiu(sp, sp, -8);
  __ Sd(ra, MemOperand(sp));
  __ Align(8);

  Label done;
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

    __ nal();
    __ dsll(at, a0, 3);  // In delay slot.
    __ daddu(at, at, ra);
    __ Ld(at, MemOperand(at, 4 * kInstrSize));
    __ jr(at);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ lui(v0, (values[i] >> 16) & 0xFFFF);
    __ ori(v0, v0, values[i] & 0xFFFF);
    __ b(&done);
    __ nop();
  }

  __ bind(&done);
  __ Ld(ra, MemOperand(sp));
  __ daddiu(sp, sp, 8);
  __ jr(ra);
  __ nop();

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
    CHECK_EQ(values[i], static_cast<int>(res));
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

  __ daddiu(sp, sp, -8);
  __ Sd(ra, MemOperand(sp));

  Label done, dispatch;
  __ b(&dispatch);
  __ nop();

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ lui(v0, (values[i] >> 16) & 0xFFFF);
    __ ori(v0, v0, values[i] & 0xFFFF);
    __ b(&done);
    __ nop();
  }

  __ Align(8);
  __ bind(&dispatch);
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

    __ nal();
    __ dsll(at, a0, 3);  // In delay slot.
    __ daddu(at, at, ra);
    __ Ld(at, MemOperand(at, 4 * kInstrSize));
    __ jr(at);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  __ bind(&done);
  __ Ld(ra, MemOperand(sp));
  __ daddiu(sp, sp, 8);
  __ jr(ra);
  __ nop();

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

  __ daddiu(sp, sp, -8);
  __ Sd(ra, MemOperand(sp));

  Label done, dispatch;
  __ b(&dispatch);
  __ nop();


  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    obj = *values[i];
    imm64 = obj.ptr();
    __ lui(v0, (imm64 >> 32) & kImm16Mask);
    __ ori(v0, v0, (imm64 >> 16) & kImm16Mask);
    __ dsll(v0, v0, 16);
    __ ori(v0, v0, imm64 & kImm16Mask);
    __ b(&done);
    __ nop();
  }

  __ Align(8);
  __ bind(&dispatch);
  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

    __ nal();
    __ dsll(at, a0, 3);  // In delay slot.
    __ daddu(at, at, ra);
    __ Ld(at, MemOperand(at, 4 * kInstrSize));
    __ jr(at);
    __ nop();
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  __ bind(&done);
  __ Ld(ra, MemOperand(sp));
  __ daddiu(sp, sp, 8);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
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


TEST(BITSWAP) {
  // Test BITSWAP
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);

    struct T {
      int64_t r1;
      int64_t r2;
      int64_t r3;
      int64_t r4;
      int64_t r5;
      int64_t r6;
    };
    T t;

    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    __ Ld(a4, MemOperand(a0, offsetof(T, r1)));
    __ nop();
    __ bitswap(a6, a4);
    __ Sd(a6, MemOperand(a0, offsetof(T, r1)));

    __ Ld(a4, MemOperand(a0, offsetof(T, r2)));
    __ nop();
    __ bitswap(a6, a4);
    __ Sd(a6, MemOperand(a0, offsetof(T, r2)));

    __ Ld(a4, MemOperand(a0, offsetof(T, r3)));
    __ nop();
    __ bitswap(a6, a4);
    __ Sd(a6, MemOperand(a0, offsetof(T, r3)));

    __ Ld(a4, MemOperand(a0, offsetof(T, r4)));
    __ nop();
    __ bitswap(a6, a4);
    __ Sd(a6, MemOperand(a0, offsetof(T, r4)));

    __ Ld(a4, MemOperand(a0, offsetof(T, r5)));
    __ nop();
    __ dbitswap(a6, a4);
    __ Sd(a6, MemOperand(a0, offsetof(T, r5)));

    __ Ld(a4, MemOperand(a0, offsetof(T, r6)));
    __ nop();
    __ dbitswap(a6, a4);
    __ Sd(a6, MemOperand(a0, offsetof(T, r6)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.r1 = 0x00102100781A15C3;
    t.r2 = 0x001021008B71FCDE;
    t.r3 = 0xFF8017FF781A15C3;
    t.r4 = 0xFF8017FF8B71FCDE;
    t.r5 = 0x10C021098B71FCDE;
    t.r6 = 0xFB8017FF781A15C3;
    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(static_cast<int64_t>(0x000000001E58A8C3L), t.r1);
    CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFD18E3F7BL), t.r2);
    CHECK_EQ(static_cast<int64_t>(0x000000001E58A8C3L), t.r3);
    CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFD18E3F7BL), t.r4);
    CHECK_EQ(static_cast<int64_t>(0x08038490D18E3F7BL), t.r5);
    CHECK_EQ(static_cast<int64_t>(0xDF01E8FF1E58A8C3L), t.r6);
  }
}


TEST(class_fmt) {
  if (kArchVariant == kMips64r6) {
    // Test CLASS.fmt instruction.
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);

    struct T {
      double dSignalingNan;
      double dQuietNan;
      double dNegInf;
      double dNegNorm;
      double dNegSubnorm;
      double dNegZero;
      double dPosInf;
      double dPosNorm;
      double dPosSubnorm;
      double dPosZero;
      float  fSignalingNan;
      float  fQuietNan;
      float  fNegInf;
      float  fNegNorm;
      float  fNegSubnorm;
      float  fNegZero;
      float  fPosInf;
      float  fPosNorm;
      float  fPosSubnorm;
      float fPosZero;
    };
    T t;

    // Create a function that accepts &t, and loads, manipulates, and stores
    // the doubles t.a ... t.f.
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dSignalingNan)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dSignalingNan)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dQuietNan)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dQuietNan)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dNegInf)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dNegInf)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dNegNorm)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dNegNorm)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dNegSubnorm)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dNegSubnorm)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dNegZero)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dNegZero)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dPosInf)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dPosInf)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dPosNorm)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dPosNorm)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dPosSubnorm)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dPosSubnorm)));

    __ Ldc1(f4, MemOperand(a0, offsetof(T, dPosZero)));
    __ class_d(f6, f4);
    __ Sdc1(f6, MemOperand(a0, offsetof(T, dPosZero)));

    // Testing instruction CLASS.S
    __ Lwc1(f4, MemOperand(a0, offsetof(T, fSignalingNan)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fSignalingNan)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fQuietNan)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fQuietNan)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fNegInf)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fNegInf)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fNegNorm)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fNegNorm)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fNegSubnorm)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fNegSubnorm)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fNegZero)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fNegZero)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fPosInf)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fPosInf)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fPosNorm)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fPosNorm)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fPosSubnorm)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fPosSubnorm)));

    __ Lwc1(f4, MemOperand(a0, offsetof(T, fPosZero)));
    __ class_s(f6, f4);
    __ Swc1(f6, MemOperand(a0, offsetof(T, fPosZero)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    // Double test values.
    t.dSignalingNan =  std::numeric_limits<double>::signaling_NaN();
    t.dQuietNan = std::numeric_limits<double>::quiet_NaN();
    t.dNegInf       = -1.0 / 0.0;
    t.dNegNorm      = -5.0;
    t.dNegSubnorm   = -DBL_MIN / 2.0;
    t.dNegZero      = -0.0;
    t.dPosInf       = 2.0 / 0.0;
    t.dPosNorm      = 275.35;
    t.dPosSubnorm   = DBL_MIN / 2.0;
    t.dPosZero      = +0.0;
    // Float test values

    t.fSignalingNan = std::numeric_limits<float>::signaling_NaN();
    t.fQuietNan     = std::numeric_limits<float>::quiet_NaN();
    t.fNegInf       = -0.5/0.0;
    t.fNegNorm      = -FLT_MIN;
    t.fNegSubnorm   = -FLT_MIN / 1.5;
    t.fNegZero      = -0.0;
    t.fPosInf       = 100000.0 / 0.0;
    t.fPosNorm      = FLT_MAX;
    t.fPosSubnorm   = FLT_MIN / 20.0;
    t.fPosZero      = +0.0;

    f.Call(&t, 0, 0, 0, 0);
    // Expected double results.
    CHECK_EQ(base::bit_cast<int64_t>(t.dSignalingNan), 0x001);
    CHECK_EQ(base::bit_cast<int64_t>(t.dQuietNan), 0x002);
    CHECK_EQ(base::bit_cast<int64_t>(t.dNegInf), 0x004);
    CHECK_EQ(base::bit_cast<int64_t>(t.dNegNorm), 0x008);
    CHECK_EQ(base::bit_cast<int64_t>(t.dNegSubnorm), 0x010);
    CHECK_EQ(base::bit_cast<int64_t>(t.dNegZero), 0x020);
    CHECK_EQ(base::bit_cast<int64_t>(t.dPosInf), 0x040);
    CHECK_EQ(base::bit_cast<int64_t>(t.dPosNorm), 0x080);
    CHECK_EQ(base::bit_cast<int64_t>(t.dPosSubnorm), 0x100);
    CHECK_EQ(base::bit_cast<int64_t>(t.dPosZero), 0x200);

    // Expected float results.
    CHECK_EQ(base::bit_cast<int32_t>(t.fSignalingNan), 0x001);
    CHECK_EQ(base::bit_cast<int32_t>(t.fQuietNan), 0x002);
    CHECK_EQ(base::bit_cast<int32_t>(t.fNegInf), 0x004);
    CHECK_EQ(base::bit_cast<int32_t>(t.fNegNorm), 0x008);
    CHECK_EQ(base::bit_cast<int32_t>(t.fNegSubnorm), 0x010);
    CHECK_EQ(base::bit_cast<int32_t>(t.fNegZero), 0x020);
    CHECK_EQ(base::bit_cast<int32_t>(t.fPosInf), 0x040);
    CHECK_EQ(base::bit_cast<int32_t>(t.fPosNorm), 0x080);
    CHECK_EQ(base::bit_cast<int32_t>(t.fPosSubnorm), 0x100);
    CHECK_EQ(base::bit_cast<int32_t>(t.fPosZero), 0x200);
  }
}


TEST(ABS) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    int64_t fir;
    double a;
    float b;
    double fcsr;
  };

  TestFloat test;

  // Save FIR.
  __ cfc1(a1, FCSR);
  __ Sd(a1, MemOperand(a0, offsetof(TestFloat, fcsr)));
  // Disable FPU exceptions.
  __ ctc1(zero_reg, FCSR);

  __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
  __ abs_d(f10, f4);
  __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, a)));

  __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, b)));
  __ abs_s(f10, f4);
  __ Swc1(f10, MemOperand(a0, offsetof(TestFloat, b)));

  // Restore FCSR.
  __ ctc1(a1, FCSR);

  __ jr(ra);
  __ nop();

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
  test.a = -std::numeric_limits<double>::max()
          / std::numeric_limits<double>::min();
  test.b = -std::numeric_limits<float>::max()
          / std::numeric_limits<float>::min();
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.a, std::numeric_limits<double>::max()
                 / std::numeric_limits<double>::min());
  CHECK_EQ(test.b, std::numeric_limits<float>::max()
                 / std::numeric_limits<float>::min());

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


TEST(ADD_FMT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    double a;
    double b;
    double c;
    float fa;
    float fb;
    float fc;
  };

  TestFloat test;

  __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
  __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
  __ add_d(f10, f8, f4);
  __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, c)));

  __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, fa)));
  __ Lwc1(f8, MemOperand(a0, offsetof(TestFloat, fb)));
  __ add_s(f10, f8, f4);
  __ Swc1(f10, MemOperand(a0, offsetof(TestFloat, fc)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test.a = 2.0;
  test.b = 3.0;
  test.fa = 2.0;
  test.fb = 3.0;
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.c, 5.0);
  CHECK_EQ(test.fc, 5.0);

  test.a = std::numeric_limits<double>::max();
  test.b = -std::numeric_limits<double>::max();  // lowest()
  test.fa = std::numeric_limits<float>::max();
  test.fb = -std::numeric_limits<float>::max();  // lowest()
  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.c, 0.0);
  CHECK_EQ(test.fc, 0.0);

  test.a = std::numeric_limits<double>::max();
  test.b = std::numeric_limits<double>::max();
  test.fa = std::numeric_limits<float>::max();
  test.fb = std::numeric_limits<float>::max();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(!std::isfinite(test.c));
  CHECK(!std::isfinite(test.fc));

  test.a = 5.0;
  test.b = std::numeric_limits<double>::signaling_NaN();
  test.fa = 5.0;
  test.fb = std::numeric_limits<float>::signaling_NaN();
  f.Call(&test, 0, 0, 0, 0);
  CHECK(std::isnan(test.c));
  CHECK(std::isnan(test.fc));
}


TEST(C_COND_FMT) {
  if (kArchVariant == kMips64r2) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      double dOp1;
      double dOp2;
      uint32_t dF;
      uint32_t dUn;
      uint32_t dEq;
      uint32_t dUeq;
      uint32_t dOlt;
      uint32_t dUlt;
      uint32_t dOle;
      uint32_t dUle;
      float fOp1;
      float fOp2;
      uint32_t fF;
      uint32_t fUn;
      uint32_t fEq;
      uint32_t fUeq;
      uint32_t fOlt;
      uint32_t fUlt;
      uint32_t fOle;
      uint32_t fUle;
    };

    TestFloat test;

    __ li(t1, 1);

    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, dOp1)));
    __ Ldc1(f6, MemOperand(a0, offsetof(TestFloat, dOp2)));

    __ Lwc1(f14, MemOperand(a0, offsetof(TestFloat, fOp1)));
    __ Lwc1(f16, MemOperand(a0, offsetof(TestFloat, fOp2)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(F, f4, f6, 0);
    __ c_s(F, f14, f16, 2);
    __ movt(t2, t1, 0);
    __ movt(t3, t1, 2);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dF)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fF)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(UN, f4, f6, 2);
    __ c_s(UN, f14, f16, 4);
    __ movt(t2, t1, 2);
    __ movt(t3, t1, 4);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dUn)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fUn)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(EQ, f4, f6, 4);
    __ c_s(EQ, f14, f16, 6);
    __ movt(t2, t1, 4);
    __ movt(t3, t1, 6);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dEq)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fEq)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(UEQ, f4, f6, 6);
    __ c_s(UEQ, f14, f16, 0);
    __ movt(t2, t1, 6);
    __ movt(t3, t1, 0);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dUeq)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fUeq)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(OLT, f4, f6, 0);
    __ c_s(OLT, f14, f16, 2);
    __ movt(t2, t1, 0);
    __ movt(t3, t1, 2);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dOlt)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fOlt)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(ULT, f4, f6, 2);
    __ c_s(ULT, f14, f16, 4);
    __ movt(t2, t1, 2);
    __ movt(t3, t1, 4);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dUlt)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fUlt)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(OLE, f4, f6, 4);
    __ c_s(OLE, f14, f16, 6);
    __ movt(t2, t1, 4);
    __ movt(t3, t1, 6);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dOle)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fOle)));

    __ mov(t2, zero_reg);
    __ mov(t3, zero_reg);
    __ c_d(ULE, f4, f6, 6);
    __ c_s(ULE, f14, f16, 0);
    __ movt(t2, t1, 6);
    __ movt(t3, t1, 0);
    __ Sw(t2, MemOperand(a0, offsetof(TestFloat, dUle)));
    __ Sw(t3, MemOperand(a0, offsetof(TestFloat, fUle)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    test.dOp1 = 2.0;
    test.dOp2 = 3.0;
    test.fOp1 = 2.0;
    test.fOp2 = 3.0;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.dF, 0U);
    CHECK_EQ(test.dUn, 0U);
    CHECK_EQ(test.dEq, 0U);
    CHECK_EQ(test.dUeq, 0U);
    CHECK_EQ(test.dOlt, 1U);
    CHECK_EQ(test.dUlt, 1U);
    CHECK_EQ(test.dOle, 1U);
    CHECK_EQ(test.dUle, 1U);
    CHECK_EQ(test.fF, 0U);
    CHECK_EQ(test.fUn, 0U);
    CHECK_EQ(test.fEq, 0U);
    CHECK_EQ(test.fUeq, 0U);
    CHECK_EQ(test.fOlt, 1U);
    CHECK_EQ(test.fUlt, 1U);
    CHECK_EQ(test.fOle, 1U);
    CHECK_EQ(test.fUle, 1U);

    test.dOp1 = std::numeric_limits<double>::max();
    test.dOp2 = std::numeric_limits<double>::min();
    test.fOp1 = std::numeric_limits<float>::min();
    test.fOp2 = -std::numeric_limits<float>::max();  // lowest()
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.dF, 0U);
    CHECK_EQ(test.dUn, 0U);
    CHECK_EQ(test.dEq, 0U);
    CHECK_EQ(test.dUeq, 0U);
    CHECK_EQ(test.dOlt, 0U);
    CHECK_EQ(test.dUlt, 0U);
    CHECK_EQ(test.dOle, 0U);
    CHECK_EQ(test.dUle, 0U);
    CHECK_EQ(test.fF, 0U);
    CHECK_EQ(test.fUn, 0U);
    CHECK_EQ(test.fEq, 0U);
    CHECK_EQ(test.fUeq, 0U);
    CHECK_EQ(test.fOlt, 0U);
    CHECK_EQ(test.fUlt, 0U);
    CHECK_EQ(test.fOle, 0U);
    CHECK_EQ(test.fUle, 0U);

    test.dOp1 = -std::numeric_limits<double>::max();  // lowest()
    test.dOp2 = -std::numeric_limits<double>::max();  // lowest()
    test.fOp1 = std::numeric_limits<float>::max();
    test.fOp2 = std::numeric_limits<float>::max();
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.dF, 0U);
    CHECK_EQ(test.dUn, 0U);
    CHECK_EQ(test.dEq, 1U);
    CHECK_EQ(test.dUeq, 1U);
    CHECK_EQ(test.dOlt, 0U);
    CHECK_EQ(test.dUlt, 0U);
    CHECK_EQ(test.dOle, 1U);
    CHECK_EQ(test.dUle, 1U);
    CHECK_EQ(test.fF, 0U);
    CHECK_EQ(test.fUn, 0U);
    CHECK_EQ(test.fEq, 1U);
    CHECK_EQ(test.fUeq, 1U);
    CHECK_EQ(test.fOlt, 0U);
    CHECK_EQ(test.fUlt, 0U);
    CHECK_EQ(test.fOle, 1U);
    CHECK_EQ(test.fUle, 1U);

    test.dOp1 = std::numeric_limits<double>::quiet_NaN();
    test.dOp2 = 0.0;
    test.fOp1 = std::numeric_limits<float>::quiet_NaN();
    test.fOp2 = 0.0;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.dF, 0U);
    CHECK_EQ(test.dUn, 1U);
    CHECK_EQ(test.dEq, 0U);
    CHECK_EQ(test.dUeq, 1U);
    CHECK_EQ(test.dOlt, 0U);
    CHECK_EQ(test.dUlt, 1U);
    CHECK_EQ(test.dOle, 0U);
    CHECK_EQ(test.dUle, 1U);
    CHECK_EQ(test.fF, 0U);
    CHECK_EQ(test.fUn, 1U);
    CHECK_EQ(test.fEq, 0U);
    CHECK_EQ(test.fUeq, 1U);
    CHECK_EQ(test.fOlt, 0U);
    CHECK_EQ(test.fUlt, 1U);
    CHECK_EQ(test.fOle, 0U);
    CHECK_EQ(test.fUle, 1U);
  }
}


TEST(CMP_COND_FMT) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      double dOp1;
      double dOp2;
      double dF;
      double dUn;
      double dEq;
      double dUeq;
      double dOlt;
      double dUlt;
      double dOle;
      double dUle;
      double dOr;
      double dUne;
      double dNe;
      float fOp1;
      float fOp2;
      float fF;
      float fUn;
      float fEq;
      float fUeq;
      float fOlt;
      float fUlt;
      float fOle;
      float fUle;
      float fOr;
      float fUne;
      float fNe;
    };

    TestFloat test;

    __ li(t1, 1);

    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, dOp1)));
    __ Ldc1(f6, MemOperand(a0, offsetof(TestFloat, dOp2)));

    __ Lwc1(f14, MemOperand(a0, offsetof(TestFloat, fOp1)));
    __ Lwc1(f16, MemOperand(a0, offsetof(TestFloat, fOp2)));

    __ cmp_d(F, f2, f4, f6);
    __ cmp_s(F, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dF)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fF)));

    __ cmp_d(UN, f2, f4, f6);
    __ cmp_s(UN, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dUn)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fUn)));

    __ cmp_d(EQ, f2, f4, f6);
    __ cmp_s(EQ, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dEq)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fEq)));

    __ cmp_d(UEQ, f2, f4, f6);
    __ cmp_s(UEQ, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dUeq)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fUeq)));

    __ cmp_d(LT, f2, f4, f6);
    __ cmp_s(LT, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dOlt)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fOlt)));

    __ cmp_d(ULT, f2, f4, f6);
    __ cmp_s(ULT, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dUlt)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fUlt)));

    __ cmp_d(LE, f2, f4, f6);
    __ cmp_s(LE, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dOle)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fOle)));

    __ cmp_d(ULE, f2, f4, f6);
    __ cmp_s(ULE, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dUle)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fUle)));

    __ cmp_d(ORD, f2, f4, f6);
    __ cmp_s(ORD, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dOr)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fOr)));

    __ cmp_d(UNE, f2, f4, f6);
    __ cmp_s(UNE, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dUne)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fUne)));

    __ cmp_d(NE, f2, f4, f6);
    __ cmp_s(NE, f12, f14, f16);
    __ Sdc1(f2, MemOperand(a0, offsetof(TestFloat, dNe)));
    __ Swc1(f12, MemOperand(a0, offsetof(TestFloat, fNe)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    uint64_t dTrue  = 0xFFFFFFFFFFFFFFFF;
    uint64_t dFalse = 0x0000000000000000;
    uint32_t fTrue  = 0xFFFFFFFF;
    uint32_t fFalse = 0x00000000;

    test.dOp1 = 2.0;
    test.dOp2 = 3.0;
    test.fOp1 = 2.0;
    test.fOp2 = 3.0;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dF), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUn), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dEq), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUeq), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOlt), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUlt), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOle), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUle), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOr), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUne), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dNe), dTrue);
    CHECK_EQ(bas
```