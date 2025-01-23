Response:
Let's break down the thought process to analyze this C++ code snippet.

1. **Identify the Core Purpose:** The filename `test-assembler-mips64.cc` and the content strongly suggest this is a unit test file for the MIPS64 assembler within the V8 JavaScript engine. The `TEST()` macros confirm this.

2. **Recognize the Architecture-Specific Nature:** The "mips64" part of the filename and the conditional execution based on `kArchVariant` (`kMips64r2`) indicates that these tests are specific to the MIPS64 architecture (and potentially sub-variants like r2).

3. **Understand the Testing Methodology:** The code creates a `MacroAssembler` instance, which is used to generate MIPS64 assembly instructions. It then defines a `struct` (like `TestFloat` or `Test`) to hold input and output values for the assembly code. The assembly code loads input values from the `struct`, performs operations on them, and stores the results back into the `struct`. Finally, the test code compares the computed results with expected values.

4. **Analyze Individual Test Cases:** Go through each `TEST()` function and identify the assembly instructions being tested. For instance:
    * `min_max`: Tests the `mina_d`, `mina_s`, `maxa_d`, `maxa_s` instructions for finding minimum and maximum of floating-point numbers.
    * `trunc_l`: Tests the `trunc_l_d` and `trunc_l_s` instructions for truncating floating-point numbers to 64-bit integers.
    * `movz_movn`: Tests conditional move instructions `movz_s`, `movz_d`, `movn_s`, `movn_d`.
    * `movt_movd`: Tests conditional move instructions `movt_s`, `movt_d`, `movf_s`, `movf_d` based on floating-point condition codes.
    * `cvt_w_d`: Tests converting double-precision floats to single-precision integers (`cvt_w_d`). It also checks different rounding modes by manipulating the FCSR register.
    * `trunc_w`, `round_w`, `round_l`, `floor_w`, `floor_l`: Similar to `trunc_l`, these test different rounding and truncation instructions for both single and double precision floating-point numbers.
    * `sub`, `sqrt_rsqrt_recip`, `neg`, `mul`: Test basic arithmetic and mathematical operations.
    * `mov`: Tests simple move instructions for floating-point registers.

5. **Infer Functionality from Assembly Instructions:**  Based on the assembly mnemonics (like `Ldc1`, `Swc1`, `add_s`, `sqrt_d`), deduce the operation being performed. Knowing MIPS assembly language is helpful here, but even without deep knowledge, the names are often indicative (e.g., `sqrt` for square root).

6. **Connect to JavaScript (if applicable):** Consider if the tested operations have direct counterparts in JavaScript. Floating-point arithmetic, rounding, and truncation are all common in JavaScript. Provide simple examples of how these operations might be used.

7. **Identify Potential Programming Errors:** Think about common mistakes developers make related to the tested operations. For example, assuming a specific rounding behavior without explicitly setting it, or issues with NaN and infinity.

8. **Address Specific Instructions:**  Make sure to handle all parts of the prompt, such as checking for `.tq` extensions (which aren't present here), and acknowledging the "Part 3 of 13" instruction.

9. **Synthesize the Summary:**  Combine the understanding of individual tests into a concise summary of the file's overall purpose. Emphasize that it's testing the MIPS64 assembler's floating-point instruction implementations.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just about math functions."
* **Correction:** "No, it's specifically testing *assembler instructions* that implement those math functions. The focus is on the low-level correctness of the generated machine code."
* **Initial thought:** "Should I explain every single assembly instruction in detail?"
* **Refinement:** "No, the prompt asks for the *functionality* of the file. Focus on the high-level operations being tested and what those operations achieve."
* **Initial thought:** "How do I connect this to JavaScript?"
* **Refinement:** "Think about the JavaScript language features that rely on these underlying floating-point operations. Basic arithmetic, the `Math` object, and type conversions are good examples."

By following this structured approach, one can effectively analyze the provided code snippet and generate a comprehensive and accurate summary.
这是v8 JavaScript引擎中用于测试MIPS64架构汇编器功能的C++源代码文件。

**主要功能归纳:**

这个文件的主要功能是测试 `v8/src/codegen/mips64/assembler-mips64.h` 和 `v8/src/codegen/mips64/macro-assembler-mips64.h` 中实现的 MIPS64 汇编指令的正确性。它通过一系列的单元测试 (`TEST` 宏定义) 来验证各种 MIPS64 浮点运算指令的行为，包括但不限于：

* **浮点数算术运算:** 加法、减法、乘法。
* **浮点数比较和最值:** 查找最小值和最大值。
* **浮点数取整和转换:**  截断、四舍五入到最接近的整数、向下取整、以及浮点数到整数的转换。
* **浮点数特殊运算:** 平方根、倒数平方根、倒数、绝对值。
* **条件移动指令:**  根据条件码移动浮点数。
* **数据移动指令:** 在浮点寄存器之间移动数据。

**关于文件名的说明:**

`v8/test/cctest/test-assembler-mips64.cc` 以 `.cc` 结尾，而不是 `.tq`。因此，它是一个 **C++ 源代码文件**，而不是 V8 的 Torque 源代码文件。 Torque 文件通常用于定义 V8 的内置函数和运行时代码，而 C++ 测试文件则用于验证现有 C++ 代码的功能。

**与 Javascript 功能的关系:**

虽然这个文件本身不是 JavaScript 代码，但它测试的汇编指令是 V8 执行 JavaScript 代码的基础。当 V8 编译 JavaScript 代码时，它会将 JavaScript 代码转换为机器码，其中就包括这些 MIPS64 汇编指令。 因此，这个文件中测试的指令的正确性直接影响着 V8 在 MIPS64 架构上执行 JavaScript 代码的正确性。

**Javascript 举例说明:**

例如，这个文件中可能测试了 `add.s` (单精度浮点加法) 和 `add.d` (双精度浮点加法) 指令。在 JavaScript 中，执行以下加法操作时，V8 在 MIPS64 架构上可能会使用这些指令：

```javascript
let a = 1.5;  // 双精度浮点数
let b = 2.7;
let sum = a + b;

let x = 1.5e-7; // 单精度浮点数 (实际上 JavaScript 中所有 Number 都是双精度，这里为了说明概念)
let y = 2.7e-7;
let sum_single = x + y;
```

**代码逻辑推理 (假设输入与输出):**

让我们看一个 `min_max` 测试用例片段：

```c++
    double inputsa[kTableLength] = {
        4.8, 5.3,  6.1, -10.0, -8.9, -9.8, 9.8,  9.8,  9.8,  -9.8,  -11.2, -9.8,
        3.0, dnan, 0.0, -0.0,  dnan, dinf, dinf, 42.0, dinf, dminf, dnan};
    double inputsb[kTableLength] = {
        4.8, 5.3,  6.1, -10.0, -8.9, -9.8, 9.8,  9.8,  9.8,  -9.8,  -11.2, -9.8,
        3.0, dnan, 0.0, -0.0,  dnan, dinf, dinf, 42.0, dinf, dminf, dnan};
    double resd[kTableLength] = {
        4.8, 4.8, 6.1,  9.8,  -8.9, -9.8, 9.8,  -8.9, -9.8,  -9.8,  -8.9, -9.8,
        3.0, 3.0, -0.0, -0.0, dinf, dinf, 42.0, 42.0, dminf, dminf, dnan};
    double resd1[kTableLength] = {
        5.3, 5.3, 6.1, -10.0, 9.8,  9.8,  -10.0, 9.8,  9.8,  -10.0, -11.2, -9.8,
        3.0, 3.0, 0.0, 0.0,   dinf, dinf, dinf,  dinf, dinf, dinf,  dnan};
    // ... 汇编代码 ...
    for (int i = 0; i < kTableLength; i++) {
      test.a = inputsa[i];
      test.b = inputsb[i];
      // ... 调用汇编代码 ...
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
```

**假设输入与输出:**

* **输入:** `test.a` 和 `test.b` 分别从 `inputsa` 和 `inputsb` 数组中取值。
* **汇编代码:**  `__ mina_d(f6, f2, f4);`  这条指令将寄存器 `f2` 和 `f4` 中的双精度浮点数进行比较，并将较小的绝对值放入 `f6`。 假设 `f2` 中加载的是 `test.a`，`f4` 中加载的是 `test.b`。
* **输出:** `test.resd` 的值应该等于 `resd[i]`。

例如，当 `i = 0` 时：
* **输入:** `test.a = 4.8`, `test.b = 4.8`
* **预期输出 (`resd[0]`):** `4.8` (因为 `mina_d` 取绝对值较小的，如果绝对值相等则取第一个操作数)

当 `i = 3` 时：
* **输入:** `test.a = -10.0`, `test.b = -10.0`
* **预期输出 (`resd[3]`):** `9.8`  （这里可以看到逻辑， `mina_d` 实际上是和第二个操作数比较，然后取第二个操作数对应的结果，  `resd` 数组的生成逻辑似乎是在测试 `mina_d` 时，结果取的是 `inputsb` 对应的数值，但是符号取决于绝对值大小）

**用户常见的编程错误举例说明:**

由于这个文件测试的是底层的汇编指令，与用户直接编写 JavaScript 代码遇到的错误关联性相对较低。但是，了解这些底层的行为可以帮助理解某些 JavaScript 中可能出现的浮点数问题：

1. **浮点数精度问题:**  用户可能会期望浮点数运算得到精确的结果，但由于浮点数的二进制表示限制，可能会出现精度丢失。 这个文件测试了浮点运算指令，可以确保这些指令在硬件层面上的行为符合规范，但无法避免浮点数本身固有的精度问题。

   ```javascript
   let result = 0.1 + 0.2;
   console.log(result); // 输出结果可能不是精确的 0.3
   ```

2. **NaN 和 Infinity 的处理:**  用户可能不熟悉 NaN (Not a Number) 和 Infinity 的概念以及它们在浮点运算中的传播规则。 这个文件测试了包含 NaN 和 Infinity 的浮点数运算，确保 V8 按照 IEEE 754 标准处理这些特殊值。

   ```javascript
   console.log(0 / 0);       // 输出 NaN
   console.log(1 / 0);       // 输出 Infinity
   console.log(NaN + 5);     // 输出 NaN
   ```

3. **不正确的类型转换:**  用户在将浮点数转换为整数时，可能会错误地假设某种特定的取整行为（例如总是向下取整），而没有使用正确的 `Math.floor()`, `Math.ceil()`, `Math.round()` 或位运算符等方法。 这个文件测试了浮点数到整数的转换指令，可以帮助理解 V8 如何进行这些转换。

   ```javascript
   let floatNum = 3.7;
   let intNum1 = parseInt(floatNum); // 结果是 3 (截断)
   let intNum2 = Math.floor(floatNum); // 结果是 3
   let intNum3 = Math.round(floatNum); // 结果是 4
   ```

**总结这个文件的功能 (作为第 3 部分，共 13 部分):**

作为 V8 编译和执行流程中的一部分， `v8/test/cctest/test-assembler-mips64.cc` 这个文件专注于 **验证 MIPS64 架构汇编器生成浮点运算相关指令的正确性**。它是 V8 测试框架中针对特定架构的底层测试部分，确保了 V8 在 MIPS64 平台上能够正确地执行涉及浮点数运算的 JavaScript 代码。其他 12 个部分可能涵盖了其他架构的汇编器测试、其他类型的指令测试、或者更高级别的代码生成和优化测试。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```