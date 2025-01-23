Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is a part of the V8 JavaScript engine's test suite, specifically for the MIPS64 architecture.
The filename `test-assembler-mips64.cc` suggests it tests the assembler functionality for MIPS64.
The tests seem to focus on individual MIPS64 assembly instructions and their behavior.

Here's a breakdown of the individual tests:

- `floor_w`: Tests the `floor.w.d` and `floor.w.s` instructions, which convert floating-point numbers to integers by rounding towards negative infinity.
- `ceil_w`: Tests the `ceil.w.d` and `ceil.w.s` instructions, which convert floating-point numbers to integers by rounding towards positive infinity.
- `ceil_l`: Tests the `ceil.l.d` and `ceil.l.s` instructions, similar to `ceil_w` but converting to 64-bit integers.
- `jump_tables1`, `jump_tables2`, `jump_tables3`: Tests the functionality of jump tables, including forward and backward jumps and embedding heap objects.
- `BITSWAP`: Tests the `bitswap` and `dbitswap` instructions, which reverse the byte order within a word or doubleword.
- `class_fmt`: Tests the `class.d` and `class.s` instructions, which classify floating-point numbers.
- `ABS`: Tests the `abs.d` and `abs.s` instructions, which compute the absolute value of floating-point numbers.
- `ADD_FMT`: Tests the `add.d` and `add.s` instructions for floating-point addition.
- `C_COND_FMT`: Tests the `c.cond.d` and `c.cond.s` instructions for floating-point comparisons, setting a condition code. This test seems specific to MIPS64r2.
- `CMP_COND_FMT`: Tests the `cmp.cond.d` and `cmp.cond.s` instructions for floating-point comparisons, writing the result to a floating-point register. This test seems specific to MIPS64r6.

Based on the filename and the content, the primary function of this code is to test the correctness of the MIPS64 assembler implementation in V8.

Regarding the specific questions:

- **File extension**: The filename ends with `.cc`, not `.tq`. So, it's a C++ source file, not a Torque file.
- **Relationship with JavaScript**:  These tests verify the low-level assembly instructions that the V8 JavaScript engine uses internally to execute JavaScript code. For example, floating-point operations in JavaScript rely on these underlying assembly instructions.
- **Code logic reasoning**: Each test sets up specific input values and checks if the output of the assembly instructions matches the expected result.
- **User programming errors**: Although this code tests the *implementation* of assembly instructions, incorrect usage of floating-point numbers in JavaScript could expose issues that these tests aim to prevent at the engine level.

Finally, the request asks for a summary of the functionality of *this specific part* (part 4 of 13). This part focuses on testing various floating-point instructions (`floor`, `ceil`, `abs`, `add`, `cmp`) and jump table mechanisms.
这是 V8 JavaScript 引擎中针对 MIPS64 架构的汇编器测试代码的第四部分。它主要功能是测试 MIPS64 架构下汇编器的特定指令的行为和正确性，特别是以下几个方面：

1. **浮点数取整指令 (floor 和 ceil):**
   - `floor_w`: 测试将双精度浮点数和单精度浮点数向下取整到 32 位整数的指令 (`floor.w.d`, `floor.w.s`)。
   - `ceil_w`: 测试将双精度浮点数和单精度浮点数向上取整到 32 位整数的指令 (`ceil.w.d`, `ceil.w.s`)。
   - `ceil_l`: 测试将双精度浮点数和单精度浮点数向上取整到 64 位整数的指令 (`ceil.l.d`, `ceil.l.s`)。

2. **跳转表 (Jump Tables):**
   - `jump_tables1`: 测试使用向前跳转的跳转表实现。
   - `jump_tables2`: 测试使用向后跳转的跳转表实现。
   - `jump_tables3`: 测试使用向后跳转的跳转表，并且在跳转目标中嵌入堆对象的情况。

3. **位反转指令 (BITSWAP):**
   - `BITSWAP`: 测试用于反转 32 位和 64 位整数中字节顺序的指令 (`bitswap`, `dbitswap`)，此测试仅在 `kArchVariant == kMips64r6` 时执行。

4. **浮点数分类指令 (CLASS.fmt):**
   - `class_fmt`: 测试用于对双精度和单精度浮点数进行分类的指令 (`class.d`, `class.s`)，此测试仅在 `kArchVariant == kMips64r6` 时执行。

5. **浮点数绝对值指令 (ABS):**
   - `ABS`: 测试计算双精度和单精度浮点数绝对值的指令 (`abs.d`, `abs.s`)。

6. **浮点数加法指令 (ADD_FMT):**
   - `ADD_FMT`: 测试双精度和单精度浮点数加法指令 (`add.d`, `add.s`)。

7. **浮点数条件比较指令 (C_COND_FMT):**
   - `C_COND_FMT`: 测试基于浮点数比较结果设置条件码的指令 (`c.cond.d`, `c.cond.s`)，此测试仅在 `kArchVariant == kMips64r2` 时执行。

8. **浮点数比较指令 (CMP_COND_FMT):**
   - `CMP_COND_FMT`: 测试直接将浮点数比较结果写入浮点寄存器的指令 (`cmp.cond.d`, `cmp.cond.s`)，此测试仅在 `kArchVariant == kMips64r6` 时执行。

**关于问题：**

* **`.tq` 结尾：**  `v8/test/cctest/test-assembler-mips64.cc` 以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码文件。

* **与 JavaScript 的关系：** 这些测试直接关系到 JavaScript 的浮点数运算和控制流。V8 引擎在执行 JavaScript 代码时，会将 JavaScript 代码编译成机器码，其中就可能包含这些 MIPS64 汇编指令。例如，JavaScript 中的 `Math.floor()`, `Math.ceil()`, `Math.abs()`, 以及加法运算等，底层都可能使用到这些指令。

   **JavaScript 示例：**

   ```javascript
   let num1 = 2.5;
   let num2 = -3.1;

   console.log(Math.floor(num1)); // 输出 2
   console.log(Math.ceil(num2));  // 输出 -3
   console.log(Math.abs(num2));   // 输出 3.1
   console.log(num1 + num2);     // 输出 -0.6
   ```

   当 V8 引擎执行这些 JavaScript 代码时，会生成相应的 MIPS64 汇编指令，例如 `floor.w.d` (用于 `Math.floor`) 或 `ceil.w.d` (用于 `Math.ceil`)，以及 `abs.d` 和 `add.d` 等。

* **代码逻辑推理：**

   以 `floor_w` 测试为例：

   **假设输入：**
   `test.a` (double) = 2.1
   `test.b` (float) = -2.6

   **预期输出：**
   `test.c` (int32_t, `a` 的向下取整结果) = 2
   `test.d` (int32_t, `b` 的向下取整结果) = -3

   代码会加载 `test.a` 和 `test.b`，分别使用 `floor_w_d` 和 `floor_w_s` 指令进行向下取整，并将结果存储到 `test.c` 和 `test.d` 中。最后的 `CHECK_EQ` 宏会验证实际结果是否与预期结果一致。

* **用户常见的编程错误：**

   虽然这个测试文件主要关注汇编器实现的正确性，但它涉及的浮点数运算是用户在 JavaScript 编程中经常遇到的。一些常见的错误包括：

   1. **精度问题：** 浮点数在计算机中以二进制近似表示，可能导致精度丢失。例如，一些看似简单的十进制小数可能无法精确表示。

      ```javascript
      console.log(0.1 + 0.2); // 输出 0.30000000000000004，而不是精确的 0.3
      ```

   2. **NaN 的处理：**  对 NaN（Not a Number）进行运算通常会得到 NaN，需要注意判断和处理 NaN 的情况。

      ```javascript
      console.log(Math.sqrt(-1)); // 输出 NaN
      console.log(NaN + 5);       // 输出 NaN
      console.log(NaN === NaN);   // 输出 false，需要使用 isNaN() 判断
      ```

   3. **Infinity 的处理：**  除以 0 会得到 Infinity 或 -Infinity。需要注意处理这些特殊值。

      ```javascript
      console.log(5 / 0);  // 输出 Infinity
      console.log(-5 / 0); // 输出 -Infinity
      console.log(Infinity + 1); // 输出 Infinity
      ```

   4. **整数溢出：** 虽然 `floor_w` 和 `ceil_w` 将浮点数转换为 32 位整数，但如果浮点数的值超出 32 位整数的范围，会导致溢出或截断。测试代码中也考虑了 `kFPUInvalidResult` 的情况。

**功能归纳：**

作为第 4 部分，这段代码的主要功能是针对 MIPS64 架构，详细测试了汇编器在处理浮点数取整、跳转表、位反转、浮点数分类、绝对值、加法以及条件比较等指令时的正确性和行为。这些测试是确保 V8 引擎在 MIPS64 平台上正确执行 JavaScript 代码的基础。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
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