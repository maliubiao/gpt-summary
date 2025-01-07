Response:
The user wants a summary of the provided C++ code snippet from V8, specifically the `v8/test/cctest/test-assembler-mips64.cc` file.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the core purpose of the file:** The file name itself is highly indicative: `test-assembler-mips64.cc`. This strongly suggests it's a test file for the MIPS64 assembler within V8.

2. **Recognize the testing methodology:** The code uses the `TEST()` macro, a common pattern in C++ testing frameworks (likely Google Test in this case). Each `TEST()` block represents a specific test case.

3. **Analyze individual test cases:**  Go through each `TEST()` block and determine what it's testing. Look for patterns in the code:
    * Setting up a `MacroAssembler`.
    * Defining a `struct` to hold input and output values.
    * Generating MIPS64 assembly instructions using the `__` prefix.
    * Calling the generated code.
    * Using `CHECK_EQ` (or similar `CHECK` macros) to verify the output against expected values.

4. **Categorize the tests:** Group similar tests together to identify broader functional areas being tested. For instance, several tests deal with floating-point comparisons (`FCmpS`, `FCmpD`), others with floating-point conversions (`CVT`), and yet others with specific MIPS64 instructions like `align`, `dalign`, `aluipc`, `auipc`, `aui`, `daui`, `dahi`, `dati`, `li`, and `lwpc`.

5. **Look for conditional compilation:** The presence of `if (kArchVariant == kMips64r6)` suggests that the tests are designed to be architecture-specific, potentially testing features introduced in the MIPS64 Release 6 architecture.

6. **Address specific instructions:**  When a test clearly focuses on a single or a small set of instructions (like `align` or `li`), note the specific instructions being tested and their purpose. For example, `li` is likely testing the "load immediate" functionality.

7. **Connect to JavaScript (if applicable):**  Consider if any of the tested assembly instructions have a direct equivalent or commonly used pattern in JavaScript. Floating-point operations and integer conversions are good candidates.

8. **Consider common programming errors:** Think about the types of errors developers might make when working with these kinds of operations (e.g., floating-point comparisons, integer conversions, bit manipulation).

9. **Address the `.tq` extension:** The prompt specifically asks about the `.tq` extension. Since this file is `.cc`, it's a standard C++ file, *not* a Torque file.

10. **Address code logic and assumptions:**  For tests that involve more complex logic (like `li_macro`), try to understand the underlying assumptions and how the inputs and outputs are related.

11. **Synthesize the findings:**  Combine the observations from the individual tests and the categorization into a concise summary. Highlight the main areas of functionality being tested.

12. **Organize the response:** Structure the summary logically, addressing each point raised in the prompt (functionality, Torque, JavaScript examples, code logic, common errors, and overall summary).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the specific register names in the assembly. **Correction:** Realize that the general operation being tested is more important than the exact registers used in the test.
* **Overlooking architecture-specific tests:** Initially not paying enough attention to the `kArchVariant` checks. **Correction:** Recognize the significance of these checks and highlight that some tests are specific to MIPS64r6.
* **Difficulty linking to JavaScript:**  Struggling to find direct JavaScript equivalents for some low-level instructions. **Correction:** Focus on general concepts like floating-point and integer conversions, rather than trying to find perfect instruction-level matches.
* **Not explicitly addressing the "part X of Y" information:**  Forgetting to incorporate the "part 5 of 13" information into the final summary. **Correction:** Include this context in the concluding remarks.
好的，让我们来分析一下这段 `v8/test/cctest/test-assembler-mips64.cc` 代码的功能。

**功能列举:**

这段代码是 V8 JavaScript 引擎针对 MIPS64 架构的汇编器 (`Assembler`) 的单元测试。它主要测试了 MIPS64 汇编指令的正确生成和执行，涵盖了以下几个方面：

1. **浮点比较指令 (`FCmpS`, `FCmpD`)**: 测试了单精度 (`float`) 和双精度 (`double`) 浮点数的各种比较操作，包括相等、不等、小于、小于等于、大于、大于等于，以及对 NaN 值的处理。

2. **浮点数类型转换指令 (`CVT`)**: 测试了不同浮点数和整数类型之间的转换，例如：
   - 单精度浮点数转双精度浮点数 (`cvt_d_s`)
   - 整数转双精度浮点数 (`cvt_d_w`, `cvt_d_l`)
   - 双精度浮点数转整数 (`cvt_l_d`, `cvt_w_d`)
   - 单精度浮点数转整数 (`cvt_l_s`, `cvt_w_s`)
   - 双精度浮点数转单精度浮点数 (`cvt_s_d`)
   - 整数转单精度浮点数 (`cvt_s_w`, `cvt_s_l`)

3. **浮点数除法指令 (`DIV_FMT`)**: 测试了单精度和双精度浮点数的除法运算。

4. **MIPS64 Release 6 特有指令 (`r6_align`, `r6_dalign`, `r6_aluipc`, `r6_auipc`, `r6_aui_family`)**: 这部分专门测试了 MIPS64 Release 6 架构引入的一些新指令：
   - `align`:  字节对齐操作。
   - `dalign`: 双字对齐操作。
   - `aluipc`:  加载程序计数器相对地址的高位。
   - `auipc`:   加载程序计数器相对地址的高位。
   - `aui`, `daui`, `dahi`, `dati`:  用于构建大立即数的指令。

5. **`li` 宏指令测试 (`li_macro`)**:  测试了 `li` (load immediate) 宏指令，该指令用于加载各种大小的立即数到寄存器中，并验证了针对不同立即数值，汇编器生成的指令序列是否正确和高效。

6. **`lwpc` 指令测试 (`lwpc`)**: 测试了 `lwpc` (load word from PC-relative address) 指令，用于从相对于程序计数器的地址加载字数据。

**关于 .tq 结尾:**

`v8/test/cctest/test-assembler-mips64.cc` 以 `.cc` 结尾，因此它是一个标准的 C++ 源代码文件，而不是 V8 的 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例:**

这段代码测试的是底层的汇编器，它直接生成机器码。这些机器码最终会被 V8 引擎用来执行 JavaScript 代码。很多 JavaScript 的操作最终都会被编译成类似的汇编指令。

例如，JavaScript 中的浮点数运算：

```javascript
let a = 1.5;
let b = 2.5;
let sum = a + b;
let isGreater = a > b;
```

在 V8 引擎的执行过程中，`a + b` 可能会被编译成类似 `add.d` (双精度浮点数加法) 的 MIPS64 汇编指令，而 `a > b` 可能会被编译成类似 `c.lt.d` (双精度浮点数小于比较) 的指令，这些指令的功能就类似于这段测试代码中 `TEST(FADD_FMT)` 和 `TEST(FCMP)` 中测试的指令。

**代码逻辑推理及假设输入输出:**

以 `TEST(FCmpS)` 中的一个测试为例：

```c++
    test.fOp1 = 1.0f;
    test.fOp2 = 2.0f;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fF), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUn), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fEq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUeq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOlt), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUlt), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOle), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUle), fTrue);
```

**假设输入:**
- `test.fOp1 = 1.0f` (单精度浮点数 1.0)
- `test.fOp2 = 2.0f` (单精度浮点数 2.0)

**代码逻辑:**
这段代码会生成 MIPS64 的浮点比较指令，比较 `fOp1` 和 `fOp2` 的大小，并将比较结果存储到 `test` 结构体中的不同的标志位中 (`fF`, `fUn`, `fEq` 等)。

**预期输出:**
- `fF` (false): 没有发生浮点异常。
- `fUn` (false): 两个操作数都不是 NaN。
- `fEq` (false): `fOp1` 不等于 `fOp2`。
- `fUeq` (false): `fOp1` 不等于 `fOp2` (无序比较，但在这里和有序比较结果相同)。
- `fOlt` (true): `fOp1` 有序地小于 `fOp2`。
- `fUlt` (true): `fOp1` 无序地小于 `fOp2` (在这里和有序比较结果相同)。
- `fOle` (true): `fOp1` 有序地小于等于 `fOp2`。
- `fUle` (true): `fOp1` 无序地小于等于 `fOp2` (在这里和有序比较结果相同)。

**用户常见的编程错误举例:**

1. **浮点数比较使用 `==` 直接比较**:  由于浮点数的精度问题，直接使用 `==` 比较两个浮点数是否相等可能会出错。应该使用一个小的误差范围 (`epsilon`) 来判断是否近似相等。

   ```javascript
   let a = 0.1 + 0.2;
   let b = 0.3;
   if (a == b) { // 这种比较可能不成立
       console.log("Equal");
   }

   const epsilon = 0.00001;
   if (Math.abs(a - b) < epsilon) { // 推荐使用这种方式
       console.log("Approximately equal");
   }
   ```

2. **不理解 NaN 的特性**:  `NaN` (Not a Number) 与任何值（包括自身）比较都不相等。

   ```javascript
   let nanValue = NaN;
   console.log(nanValue == NaN);   // 输出 false
   console.log(nanValue === NaN);  // 输出 false
   console.log(isNaN(nanValue));   // 检查是否为 NaN，应该使用 isNaN()
   ```

3. **整数类型转换溢出**:  在进行整数类型转换时，如果没有考虑到数据范围，可能会发生溢出，导致意想不到的结果。

   ```javascript
   let largeNumber = 2147483647 + 1; // 超过了 32 位有符号整数的最大值
   let intValue = largeNumber;
   console.log(intValue); // 结果可能不是期望的值，取决于环境
   ```

**归纳一下它的功能 (第 5 部分，共 13 部分):**

作为 13 个测试文件中的第 5 个部分，这段代码专注于测试 V8 引擎中 MIPS64 架构汇编器的 **浮点数运算指令**（比较和转换）以及 **MIPS64 Release 6 引入的新指令** 的生成和执行是否正确。它通过构造不同的输入，执行生成的汇编代码，并检查输出结果来验证汇编器的正确性。  这部分测试是确保 V8 引擎在 MIPS64 架构上正确处理浮点数和利用新指令的关键组成部分。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共13部分，请归纳一下它的功能

"""
e::bit_cast<uint32_t>(test.fF), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUn), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fEq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUeq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOlt), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUlt), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOle), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUle), fTrue);

    test.dOp1 = std::numeric_limits<double>::max();
    test.dOp2 = std::numeric_limits<double>::min();
    test.fOp1 = std::numeric_limits<float>::min();
    test.fOp2 = -std::numeric_limits<float>::max();  // lowest()
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dF), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUn), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dEq), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUeq), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOlt), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUlt), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOle), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUle), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOr), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUne), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dNe), dTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fF), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUn), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fEq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUeq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOlt), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUlt), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOle), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUle), fFalse);

    test.dOp1 = -std::numeric_limits<double>::max();  // lowest()
    test.dOp2 = -std::numeric_limits<double>::max();  // lowest()
    test.fOp1 = std::numeric_limits<float>::max();
    test.fOp2 = std::numeric_limits<float>::max();
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dF), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUn), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dEq), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUeq), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOlt), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUlt), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOle), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUle), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOr), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUne), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dNe), dFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fF), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUn), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fEq), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUeq), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOlt), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUlt), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOle), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUle), fTrue);

    test.dOp1 = std::numeric_limits<double>::quiet_NaN();
    test.dOp2 = 0.0;
    test.fOp1 = std::numeric_limits<float>::quiet_NaN();
    test.fOp2 = 0.0;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dF), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUn), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dEq), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUeq), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOlt), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUlt), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOle), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUle), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dOr), dFalse);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dUne), dTrue);
    CHECK_EQ(base::bit_cast<uint64_t>(test.dNe), dFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fF), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUn), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fEq), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUeq), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOlt), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUlt), fTrue);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fOle), fFalse);
    CHECK_EQ(base::bit_cast<uint32_t>(test.fUle), fTrue);
  }
}


TEST(CVT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct TestFloat {
    float    cvt_d_s_in;
    double   cvt_d_s_out;
    int32_t  cvt_d_w_in;
    double   cvt_d_w_out;
    int64_t  cvt_d_l_in;
    double   cvt_d_l_out;

    float    cvt_l_s_in;
    int64_t  cvt_l_s_out;
    double   cvt_l_d_in;
    int64_t  cvt_l_d_out;

    double   cvt_s_d_in;
    float    cvt_s_d_out;
    int32_t  cvt_s_w_in;
    float    cvt_s_w_out;
    int64_t  cvt_s_l_in;
    float    cvt_s_l_out;

    float    cvt_w_s_in;
    int32_t  cvt_w_s_out;
    double   cvt_w_d_in;
    int32_t  cvt_w_d_out;
  };

  TestFloat test;

  // Save FCSR.
  __ cfc1(a1, FCSR);
  // Disable FPU exceptions.
  __ ctc1(zero_reg, FCSR);

#define GENERATE_CVT_TEST(x, y, z) \
  __ y##c1(f0, MemOperand(a0, offsetof(TestFloat, x##_in))); \
  __ x(f0, f0); \
  __ nop(); \
  __ z##c1(f0, MemOperand(a0, offsetof(TestFloat, x##_out)));

  GENERATE_CVT_TEST(cvt_d_s, lw, sd)
  GENERATE_CVT_TEST(cvt_d_w, lw, sd)
  GENERATE_CVT_TEST(cvt_d_l, ld, sd)

  GENERATE_CVT_TEST(cvt_l_s, lw, sd)
  GENERATE_CVT_TEST(cvt_l_d, ld, sd)

  GENERATE_CVT_TEST(cvt_s_d, ld, sw)
  GENERATE_CVT_TEST(cvt_s_w, lw, sw)
  GENERATE_CVT_TEST(cvt_s_l, ld, sw)

  GENERATE_CVT_TEST(cvt_w_s, lw, sw)
  GENERATE_CVT_TEST(cvt_w_d, ld, sw)

  // Restore FCSR.
  __ ctc1(a1, FCSR);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  test.cvt_d_s_in = -0.51;
  test.cvt_d_w_in = -1;
  test.cvt_d_l_in = -1;
  test.cvt_l_s_in = -0.51;
  test.cvt_l_d_in = -0.51;
  test.cvt_s_d_in = -0.51;
  test.cvt_s_w_in = -1;
  test.cvt_s_l_in = -1;
  test.cvt_w_s_in = -0.51;
  test.cvt_w_d_in = -0.51;

  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.cvt_d_s_out, static_cast<double>(test.cvt_d_s_in));
  CHECK_EQ(test.cvt_d_w_out, static_cast<double>(test.cvt_d_w_in));
  CHECK_EQ(test.cvt_d_l_out, static_cast<double>(test.cvt_d_l_in));
  CHECK_EQ(-1, test.cvt_l_s_out);
  CHECK_EQ(-1, test.cvt_l_d_out);
  CHECK_EQ(test.cvt_s_d_out, static_cast<float>(test.cvt_s_d_in));
  CHECK_EQ(test.cvt_s_w_out, static_cast<float>(test.cvt_s_w_in));
  CHECK_EQ(test.cvt_s_l_out, static_cast<float>(test.cvt_s_l_in));
  CHECK_EQ(-1, test.cvt_w_s_out);
  CHECK_EQ(-1, test.cvt_w_d_out);

  test.cvt_d_s_in = 0.49;
  test.cvt_d_w_in = 1;
  test.cvt_d_l_in = 1;
  test.cvt_l_s_in = 0.49;
  test.cvt_l_d_in = 0.49;
  test.cvt_s_d_in = 0.49;
  test.cvt_s_w_in = 1;
  test.cvt_s_l_in = 1;
  test.cvt_w_s_in = 0.49;
  test.cvt_w_d_in = 0.49;

  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.cvt_d_s_out, static_cast<double>(test.cvt_d_s_in));
  CHECK_EQ(test.cvt_d_w_out, static_cast<double>(test.cvt_d_w_in));
  CHECK_EQ(test.cvt_d_l_out, static_cast<double>(test.cvt_d_l_in));
  CHECK_EQ(0, test.cvt_l_s_out);
  CHECK_EQ(0, test.cvt_l_d_out);
  CHECK_EQ(test.cvt_s_d_out, static_cast<float>(test.cvt_s_d_in));
  CHECK_EQ(test.cvt_s_w_out, static_cast<float>(test.cvt_s_w_in));
  CHECK_EQ(test.cvt_s_l_out, static_cast<float>(test.cvt_s_l_in));
  CHECK_EQ(0, test.cvt_w_s_out);
  CHECK_EQ(0, test.cvt_w_d_out);

  test.cvt_d_s_in = std::numeric_limits<float>::max();
  test.cvt_d_w_in = std::numeric_limits<int32_t>::max();
  test.cvt_d_l_in = std::numeric_limits<int64_t>::max();
  test.cvt_l_s_in = std::numeric_limits<float>::max();
  test.cvt_l_d_in = std::numeric_limits<double>::max();
  test.cvt_s_d_in = std::numeric_limits<double>::max();
  test.cvt_s_w_in = std::numeric_limits<int32_t>::max();
  test.cvt_s_l_in = std::numeric_limits<int64_t>::max();
  test.cvt_w_s_in = std::numeric_limits<float>::max();
  test.cvt_w_d_in = std::numeric_limits<double>::max();

  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.cvt_d_s_out, static_cast<double>(test.cvt_d_s_in));
  CHECK_EQ(test.cvt_d_w_out, static_cast<double>(test.cvt_d_w_in));
  CHECK_EQ(test.cvt_d_l_out, static_cast<double>(test.cvt_d_l_in));
  CHECK_EQ(test.cvt_l_s_out, std::numeric_limits<int64_t>::max());
  CHECK_EQ(test.cvt_l_d_out, std::numeric_limits<int64_t>::max());
  CHECK_EQ(test.cvt_s_d_out, static_cast<float>(test.cvt_s_d_in));
  CHECK_EQ(test.cvt_s_w_out, static_cast<float>(test.cvt_s_w_in));
  CHECK_EQ(test.cvt_s_l_out, static_cast<float>(test.cvt_s_l_in));
  CHECK_EQ(test.cvt_w_s_out, std::numeric_limits<int32_t>::max());
  CHECK_EQ(test.cvt_w_d_out, std::numeric_limits<int32_t>::max());


  test.cvt_d_s_in = -std::numeric_limits<float>::max();   // lowest()
  test.cvt_d_w_in = std::numeric_limits<int32_t>::min();  // lowest()
  test.cvt_d_l_in = std::numeric_limits<int64_t>::min();  // lowest()
  test.cvt_l_s_in = -std::numeric_limits<float>::max();   // lowest()
  test.cvt_l_d_in = -std::numeric_limits<double>::max();  // lowest()
  test.cvt_s_d_in = -std::numeric_limits<double>::max();  // lowest()
  test.cvt_s_w_in = std::numeric_limits<int32_t>::min();  // lowest()
  test.cvt_s_l_in = std::numeric_limits<int64_t>::min();  // lowest()
  test.cvt_w_s_in = -std::numeric_limits<float>::max();   // lowest()
  test.cvt_w_d_in = -std::numeric_limits<double>::max();  // lowest()

  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.cvt_d_s_out, static_cast<double>(test.cvt_d_s_in));
  CHECK_EQ(test.cvt_d_w_out, static_cast<double>(test.cvt_d_w_in));
  CHECK_EQ(test.cvt_d_l_out, static_cast<double>(test.cvt_d_l_in));
  // The returned value when converting from fixed-point to float-point
  // is not consistent between board, simulator and specification
  // in this test case, therefore modifying the test
  CHECK(test.cvt_l_s_out == std::numeric_limits<int64_t>::min() ||
       test.cvt_l_s_out == std::numeric_limits<int64_t>::max());
  CHECK(test.cvt_l_d_out == std::numeric_limits<int64_t>::min() ||
        test.cvt_l_d_out == std::numeric_limits<int64_t>::max());
  CHECK_EQ(test.cvt_s_d_out, static_cast<float>(test.cvt_s_d_in));
  CHECK_EQ(test.cvt_s_w_out, static_cast<float>(test.cvt_s_w_in));
  CHECK_EQ(test.cvt_s_l_out, static_cast<float>(test.cvt_s_l_in));
  CHECK(test.cvt_w_s_out == std::numeric_limits<int32_t>::min() ||
        test.cvt_w_s_out == std::numeric_limits<int32_t>::max());
  CHECK(test.cvt_w_d_out == std::numeric_limits<int32_t>::min() ||
        test.cvt_w_d_out == std::numeric_limits<int32_t>::max());


  test.cvt_d_s_in = std::numeric_limits<float>::min();
  test.cvt_d_w_in = std::numeric_limits<int32_t>::min();
  test.cvt_d_l_in = std::numeric_limits<int64_t>::min();
  test.cvt_l_s_in = std::numeric_limits<float>::min();
  test.cvt_l_d_in = std::numeric_limits<double>::min();
  test.cvt_s_d_in = std::numeric_limits<double>::min();
  test.cvt_s_w_in = std::numeric_limits<int32_t>::min();
  test.cvt_s_l_in = std::numeric_limits<int64_t>::min();
  test.cvt_w_s_in = std::numeric_limits<float>::min();
  test.cvt_w_d_in = std::numeric_limits<double>::min();

  f.Call(&test, 0, 0, 0, 0);
  CHECK_EQ(test.cvt_d_s_out, static_cast<double>(test.cvt_d_s_in));
  CHECK_EQ(test.cvt_d_w_out, static_cast<double>(test.cvt_d_w_in));
  CHECK_EQ(test.cvt_d_l_out, static_cast<double>(test.cvt_d_l_in));
  CHECK_EQ(0, test.cvt_l_s_out);
  CHECK_EQ(0, test.cvt_l_d_out);
  CHECK_EQ(test.cvt_s_d_out, static_cast<float>(test.cvt_s_d_in));
  CHECK_EQ(test.cvt_s_w_out, static_cast<float>(test.cvt_s_w_in));
  CHECK_EQ(test.cvt_s_l_out, static_cast<float>(test.cvt_s_l_in));
  CHECK_EQ(0, test.cvt_w_s_out);
  CHECK_EQ(0, test.cvt_w_d_out);
}


TEST(DIV_FMT) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct Test {
    double dOp1;
    double dOp2;
    double dRes;
    float  fOp1;
    float  fOp2;
    float  fRes;
  };

  Test test;

  // Save FCSR.
  __ cfc1(a1, FCSR);
  // Disable FPU exceptions.
  __ ctc1(zero_reg, FCSR);

  __ Ldc1(f4, MemOperand(a0, offsetof(Test, dOp1)));
  __ Ldc1(f2, MemOperand(a0, offsetof(Test, dOp2)));
  __ nop();
  __ div_d(f6, f4, f2);
  __ Sdc1(f6, MemOperand(a0, offsetof(Test, dRes)));

  __ Lwc1(f4, MemOperand(a0, offsetof(Test, fOp1)));
  __ Lwc1(f2, MemOperand(a0, offsetof(Test, fOp2)));
  __ nop();
  __ div_s(f6, f4, f2);
  __ Swc1(f6, MemOperand(a0, offsetof(Test, fRes)));

  // Restore FCSR.
  __ ctc1(a1, FCSR);

  __ jr(ra);
  __ nop();
  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&test, 0, 0, 0, 0);

  const int test_size = 3;

  double dOp1[test_size] = {
    5.0,
    DBL_MAX,
    DBL_MAX,
  };
  double dOp2[test_size] = {
    2.0,
    2.0,
    -DBL_MAX,
  };
  double dRes[test_size] = {
    2.5,
    DBL_MAX / 2.0,
    -1.0,
  };
  float fOp1[test_size] = {
    5.0,
    FLT_MAX,
    FLT_MAX,
  };
  float fOp2[test_size] = {
    2.0,
    2.0,
    -FLT_MAX,
  };
  float fRes[test_size] = {
    2.5,
    FLT_MAX / 2.0,
    -1.0,
  };

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


uint64_t run_align(uint64_t rs_value, uint64_t rt_value, uint8_t bp) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ align(v0, a0, a1, bp);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F4>::FromCode(isolate, *code);

  uint64_t res =
      reinterpret_cast<uint64_t>(f.Call(rs_value, rt_value, 0, 0, 0));

  return res;
}


TEST(r6_align) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAlign {
      uint64_t  rs_value;
      uint64_t  rt_value;
      uint8_t   bp;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseAlign tc[] = {
      // rs_value,    rt_value,    bp, expected_res
      {  0x11223344,  0xAABBCCDD,   0, 0xFFFFFFFFAABBCCDD },
      {  0x11223344,  0xAABBCCDD,   1, 0xFFFFFFFFBBCCDD11 },
      {  0x11223344,  0xAABBCCDD,   2, 0xFFFFFFFFCCDD1122 },
      {  0x11223344,  0xAABBCCDD,   3, 0xFFFFFFFFDD112233 },
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAlign);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      CHECK_EQ(tc[i].expected_res, run_align(tc[i].rs_value,
                                              tc[i].rt_value,
                                              tc[i].bp));
    }
  }
}


uint64_t run_dalign(uint64_t rs_value, uint64_t rt_value, uint8_t bp) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ dalign(v0, a0, a1, bp);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F4>::FromCode(isolate, *code);
  uint64_t res =
      reinterpret_cast<uint64_t>(f.Call(rs_value, rt_value, 0, 0, 0));

  return res;
}


TEST(r6_dalign) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseDalign {
      uint64_t  rs_value;
      uint64_t  rt_value;
      uint8_t   bp;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseDalign tc[] = {
      // rs_value,           rt_value,            bp, expected_res
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   0, 0xAABBCCDDEEFF8899 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   1, 0xBBCCDDEEFF889911 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   2, 0xCCDDEEFF88991122 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   3, 0xDDEEFF8899112233 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   4, 0xEEFF889911223344 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   5, 0xFF88991122334455 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   6, 0x8899112233445566 },
      { 0x1122334455667700,  0xAABBCCDDEEFF8899,   7, 0x9911223344556677 }
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDalign);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      CHECK_EQ(tc[i].expected_res, run_dalign(tc[i].rs_value,
                                              tc[i].rt_value,
                                              tc[i].bp));
    }
  }
}


uint64_t PC;  // The program counter.

uint64_t run_aluipc(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ aluipc(v0, offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  PC = (uint64_t)code->instruction_start();  // Set the program counter.

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_aluipc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAluipc {
      int16_t   offset;
    };

    struct TestCaseAluipc tc[] = {
      // offset
      { -32768 },   // 0x8000
      {     -1 },   // 0xFFFF
      {      0 },
      {      1 },
      {  32767 },   // 0x7FFF
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAluipc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      PC = 0;
      uint64_t res = run_aluipc(tc[i].offset);
      // Now, the program_counter (PC) is set.
      uint64_t expected_res = ~0x0FFFF & (PC + (tc[i].offset << 16));
      CHECK_EQ(expected_res, res);
    }
  }
}


uint64_t run_auipc(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ auipc(v0, offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  PC = (uint64_t)code->instruction_start();  // Set the program counter.

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_auipc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAuipc {
      int16_t   offset;
    };

    struct TestCaseAuipc tc[] = {
      // offset
      { -32768 },   // 0x8000
      {     -1 },   // 0xFFFF
      {      0 },
      {      1 },
      {  32767 },   // 0x7FFF
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAuipc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      PC = 0;
      uint64_t res = run_auipc(tc[i].offset);
      // Now, the program_counter (PC) is set.
      uint64_t expected_res = PC + (tc[i].offset << 16);
      CHECK_EQ(expected_res, res);
    }
  }
}


uint64_t run_aui(uint64_t rs, uint16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(t0, rs);
  __ aui(v0, t0, offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


uint64_t run_daui(uint64_t rs, uint16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(t0, rs);
  __ daui(v0, t0, offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


uint64_t run_dahi(uint64_t rs, uint16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, rs);
  __ dahi(v0, offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


uint64_t run_dati(uint64_t rs, uint16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, rs);
  __ dati(v0, offset);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_aui_family) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAui {
      uint64_t   rs;
      uint16_t   offset;
      uint64_t   ref_res;
    };

    // AUI test cases.
    struct TestCaseAui aui_tc[] = {
        {0xFFFEFFFF, 0x1, 0xFFFFFFFFFFFFFFFF},
        {0xFFFFFFFF, 0x0, 0xFFFFFFFFFFFFFFFF},
        {0, 0xFFFF, 0xFFFFFFFFFFFF0000},
        {0x0008FFFF, 0xFFF7, 0xFFFFFFFFFFFFFFFF},
        {32767, 32767, 0x000000007FFF7FFF},
        {0x00000000FFFFFFFF, 0x1, 0x000000000000FFFF},
        {0xFFFFFFFF, 0xFFFF, 0xFFFFFFFFFFFEFFFF},
    };

    size_t nr_test_cases = sizeof(aui_tc) / sizeof(TestCaseAui);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_aui(aui_tc[i].rs, aui_tc[i].offset);
      CHECK_EQ(aui_tc[i].ref_res, res);
    }

    // DAUI test cases.
    struct TestCaseAui daui_tc[] = {
        {0xFFFFFFFFFFFEFFFF, 0x1, 0xFFFFFFFFFFFFFFFF},
        {0xFFFFFFFFFFFFFFFF, 0x0, 0xFFFFFFFFFFFFFFFF},
        {0, 0xFFFF, 0xFFFFFFFFFFFF0000},
        {0x0008FFFF, 0xFFF7, 0xFFFFFFFFFFFFFFFF},
        {32767, 32767, 0x000000007FFF7FFF},
        {0x00000000FFFFFFFF, 0x1, 0x000000010000FFFF},
        {0xFFFFFFFF, 0xFFFF, 0x00000000FFFEFFFF},
    };

    nr_test_cases = sizeof(daui_tc) / sizeof(TestCaseAui);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_daui(daui_tc[i].rs, daui_tc[i].offset);
      CHECK_EQ(daui_tc[i].ref_res, res);
    }

    // DATI test cases.
    struct TestCaseAui dati_tc[] = {
        {0xFFFFFFFFFFFEFFFF, 0x1, 0x0000FFFFFFFEFFFF},
        {0xFFFFFFFFFFFFFFFF, 0x0, 0xFFFFFFFFFFFFFFFF},
        {0, 0xFFFF, 0xFFFF000000000000},
        {0x0008FFFF, 0xFFF7, 0xFFF700000008FFFF},
        {32767, 32767, 0x7FFF000000007FFF},
        {0x00000000FFFFFFFF, 0x1, 0x00010000FFFFFFFF},
        {0xFFFFFFFFFFFF, 0xFFFF, 0xFFFFFFFFFFFFFFFF},
    };

    nr_test_cases = sizeof(dati_tc) / sizeof(TestCaseAui);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_dati(dati_tc[i].rs, dati_tc[i].offset);
      CHECK_EQ(dati_tc[i].ref_res, res);
    }

    // DAHI test cases.
    struct TestCaseAui dahi_tc[] = {
        {0xFFFFFFFEFFFFFFFF, 0x1, 0xFFFFFFFFFFFFFFFF},
        {0xFFFFFFFFFFFFFFFF, 0x0, 0xFFFFFFFFFFFFFFFF},
        {0, 0xFFFF, 0xFFFFFFFF00000000},
    };

    nr_test_cases = sizeof(dahi_tc) / sizeof(TestCaseAui);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_dahi(dahi_tc[i].rs, dahi_tc[i].offset);
      CHECK_EQ(dahi_tc[i].ref_res, res);
    }
  }
}

uint64_t run_li_macro(uint64_t imm, LiFlags mode, int32_t num_instr = 0) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ li(v0, imm, mode);
  if (num_instr > 0) {
    CHECK_EQ(assm.InstructionsGeneratedSince(&code_start), num_instr);
  }
  __ jr(ra);
  __ nop();

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
    int32_t r2_num_instr;
    int32_t r6_num_instr;
  };

  // We call li(v0, imm) to test cases listed below.
  struct TestCase_li tc[] = {
      //              imm, r2_num_instr, r6_num_instr
      {0xFFFFFFFFFFFF8000, 1, 1},  // min_int16
      // The test case above generates daddiu instruction.
      // This is int16 value and we can load it using just daddiu.
      {0x8000, 1, 1},  // max_int16 + 1
      // Generates ori
      // max_int16 + 1 is not int16 but is uint16, just use ori.
      {0xFFFFFFFFFFFF7FFF, 2, 2},  // min_int16 - 1
      // Generates lui + ori
      // We load int32 value using lui + ori.
      {0x8001, 1, 1},  // max_int16 + 2
      // Generates ori
      // Also an uint16 value, use ori.
      {0x00010000, 1, 1},  // max_uint16 + 1
      // Generates lui
      // Low 16 bits are 0, load value using lui.
      {0x00010001, 2, 2},  // max_uint16 + 2
      // Generates lui + ori
      // We have to generate two instructions in this case.
      {0x00000000FFFFFFFF, 2, 2},  // max_uint32
      // r2 - daddiu + dsrl32
      // r6 - daddiu + dahi
      {0x00000000FFFFFFFE, 3, 2},  // max_uint32 - 1
      // r2 - lui + ori + dsll
      // r6 - daddiu + dahi
      {0x00FFFF000000FFFE, 3, 3},
      // ori + dsll32 + ori
      {0x00000001FFFFFFFE, 4, 2},  // max_uint32 << 1
      // r2 - lui + ori + dsll + ori
      // r6 - daddiu + dahi
      {0x0000FFFFFFFFFFFE, 4, 2},  // max_uint48 - 1
      // r2 - daddiu + dsll32 + ori + dsubu
      // Loading imm directly would require ori + dsll + ori + dsll + ori.
      // Optimized by loading -imm and using dsubu to get imm.
      // r6 - daddiu + dati
      {0xFFFFFFFF00000000, 2, 2},  // max_uint32 << 32
      // r2 - daddiu + dsll32
      // r6 - ori + dahi
      // We need ori to clear register before loading value using dahi.
      {0xFFFFFFFF80000000, 1, 1},  // min_int32
      // The test case above generates lui instruction.
      {0x0000000080000000, 2, 2},  // max_int32 + 1
      // r2 - ori + dsll
      // r6 - lui + dahi
      {0x0000800000000000, 2, 2},
      // ori + dsll32
      {0xFFFF800000000000, 2, 2},
      // r2 - daddiu + dsll32
      // r6 - ori + dahi
      {0xFFFF80000000FFFF, 3, 2},
      // r2 - daddiu + dsll32 + ori
      // r6 - ori + dahi
      {0xFFFFFF123000FFFF, 3, 3},
      // daddiu + dsll + ori
      {0xFFFF00000000FFFF, 3, 2},
      // r2 - daddiu + dsll32 + ori
      // r6 - ori + dati
      {0xFFFF8000FFFF0000, 3, 2},
      // r2 - lui + ori + dsll
      // r6 - lui + dahi
      {0x0000FFFFFFFF0000, 4, 2},
      // r2 - ori + dsll + ori + dsll
      // r6 - lui + dati
      {0x1234FFFF80000000, 3, 2},
      // r2 - lui + ori + dsll
      // r6 - lui + dati
      {0x1234FFFF80010000, 5, 2},
      // r2 - lui + ori + dsll + ori + dsll
      // r6 - lui + dati
      {0xFFFF8000FFFF8000, 2, 2},
      // r2 - daddiu + dinsu
      // r6 - daddiu + dahi
      {0xFFFF0000FFFF8000, 4, 3},
      // r2 - ori + dsll32 + ori + dsubu
      // Loading imm directly would require lui + dsll + ori + dsll + ori.
      // Optimized by loading -imm and using dsubu to get imm.
      // r6 - daddiu + dahi + dati
      {0x8000000080000000, 2, 2},
      // lui + dinsu
      {0xABCD0000ABCD0000, 2, 2},
      // lui + dinsu
      {0x8000800080008000, 3, 3},
      // lui + ori + dinsu
      {0xABCD1234ABCD1234, 3, 3},
      // The test case above generates lui + ori + dinsu instruction sequence.
      {0xFFFF800080008000, 4, 3},
      // r2 - lui + ori + dsll + ori
      // r6 - lui + ori + dahi
      {0xFFFFABCD, 3, 2},
      // r2 - ori + dsll + ori
      // r6 - daddiu + dahi
      {0x1FFFFABCD, 4, 2},
      // r2 - lui + ori + dsll + ori
      // r6 - daddiu + dahi
      {0xFFFFFFFFABCD, 4, 2},
      // r2 - daddiu + dsll32 + ori + dsubu
      // Loading imm directly would require ori + dsll + ori + dsll + ori.
      // Optimized by loading -imm and using dsubu to get imm.
      // r6 - daddiu + dati
      {0x1FFFFFFFFABCD, 4, 2},
      // r2 - daddiu + dsll32 + ori + dsubu
      // Loading imm directly would require lui + ori + dsll + ori + dsll + ori.
      // Optimized by loading -imm and using dsubu to get imm.
      // r6 - daddiu + dati
      {0xFFFF7FFF80010000, 5, 2},
      // r2 - lui + ori + dsll + ori + dsll
      // r6 - lui + dahi
      // Here lui sets high 32 bits to 1 so dahi can be used to get target
      // value.
      {0x00007FFF7FFF0000, 3, 2},
      // r2 - lui + ori + dsll
      // r6 - lui + dahi
      // High 32 bits are not set so dahi can be used to get target value.
      {0xFFFF7FFF7FFF0000, 5, 3},
      // r2 - lui + ori + dsll + ori + dsll
      // r6 - lui + dahi + dati
      // High 32 bits are not set so just dahi can't be used to get target
      // value.
      {0x00007FFF80010000, 3, 3},
      // r2 - lui + ori + dsll
      // r6 - lui + ori + dsll
      // High 32 bits are set so can't just use lui + dahi to get target value.
      {0x1234ABCD87654321, 6, 4},
      // The test case above generates:
      // r2 - lui + ori + dsll + ori + dsll + ori instruction sequence,
      // r6 - lui + ori + dahi + dati.
      // Load using full instruction sequence.
      {0xFFFF0000FFFFFFFF, 3, 3},
      // r2 - ori + dsll32 + nor
      // Loading imm directly would require lui + dsll + ori + dsll + ori.
      // Optimized by loading ~imm and using nor to get imm. Loading -imm would
      // require one instruction more.
      // r6 - daddiu + dahi + dati
  };

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCase_li);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    if (kArchVariant == kMips64r2) {
      CHECK_EQ(tc[i].imm,
               run_li_macro(tc[i].imm, OPTIMIZE_SIZE, tc[i].r2_num_instr));
    } else {
      CHECK_EQ(tc[i].imm,
               run_li_macro(tc[i].imm, OPTIMIZE_SIZE, tc[i].r6_num_instr));
    }
    CHECK_EQ(tc[i].imm, run_li_macro(tc[i].imm, CONSTANT_SIZE));
    if (is_int48(tc[i].imm)) {
      CHECK_EQ(tc[i].imm, run_li_macro(tc[i].imm, ADDRESS_LOAD));
    }
  }
}


uint64_t run_lwpc(int offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // 256k instructions; 2^8k
  // addiu t3, a4, 0xFFFF;  (0x250FFFFF)
  // ...
  // addiu t0, a4, 0x0000;  (0x250C0000)
  uint32_t addiu_start_1 = 0x25000000;
  for (int32_t i = 0xFFFFF; i >= 0xC0000; --i) {
    uint32_t addiu_new = addiu_start_1 + i;
    __ dd(addiu_new);
  }

  __ lwpc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t addiu_start_2 = 0x25000000;
  for (int32_t i = 0x80000; i <= 0xBFFFF; ++i) {
  
"""


```