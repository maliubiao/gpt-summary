Response: The user wants me to summarize the functionality of the provided C++ code snippet and explain its relation to JavaScript if any, using JavaScript examples.

The C++ code is part of the V8 JavaScript engine's test suite, specifically targeting the MIPS64 architecture assembler. It defines various test cases for assembler instructions.

Looking at the code, I can see tests for:
- Floating-point comparison instructions (`CMP.*`)
- Floating-point conversion instructions (`CVT.*`)
- Floating-point division instructions (`DIV_FMT`)
- MIPS64r6 specific instructions like `ALIGN`, `DALIGN`, `ALUIPC`, `AUIPC`, `AUI`, `DAUI`, `DAHI`, `DATI`, `LWPC`, `LWUPC`, `JIC`, `BEQZC`, `JIALC`, `ADDIUPC`, `LDPC`, `BC`, `BALC`, `DSLL`
- General assembler functionalities like `LI` macro, trampolines, and `CALL` with trampoline.
- Floating-point fused multiply-add/subtract instructions (`MADD`, `MSUB`, `MADDF`, `MSUBF`)
- `Subu` instruction.

These tests verify the correct behavior of the assembler when generating machine code for these instructions. Since V8 compiles JavaScript code into machine code, the correctness of the assembler is crucial for the performance and correctness of JavaScript execution.

I can provide JavaScript examples where these assembler instructions might be used after JavaScript code is compiled by V8. For instance, floating-point operations in JavaScript will likely use the floating-point instructions tested here. Integer operations might use the integer arithmetic and bit manipulation instructions. Control flow structures in JavaScript (like `if`, `else`, loops) will rely on the branching instructions.
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件的第3部分，共7部分。**这部分代码主要功能是测试 MIPS64 架构汇编器中各种指令的正确生成和执行。**  它涵盖了浮点运算、数据转换、MIPS64 r6 扩展指令、宏指令、长跳转（trampoline）以及浮点乘加/乘减指令等多个方面。

**具体来说，这部分代码测试了以下功能：**

1. **浮点比较指令 (CMP.\*)**: 测试各种浮点数比较操作，包括相等、不等、小于、大于等，以及有序和无序比较。
2. **浮点转换指令 (CVT\*)**: 测试浮点数与整数之间的各种类型转换，例如单精度浮点数到双精度浮点数，整数到浮点数等。
3. **浮点除法指令 (DIV\_FMT)**: 测试单精度和双精度浮点数的除法运算。
4. **MIPS64 r6 特定指令**:
    *   **数据对齐指令 (ALIGN, DALIGN)**: 测试将两个寄存器的部分内容合并的指令。
    *   **PC 相对地址加载指令 (ALUIPC, AUIPC)**: 测试加载基于程序计数器的地址到寄存器的指令。
    *   **立即数加法指令 (AUI, DAUI, DAHI, DATI)**: 测试将立即数添加到寄存器的指令。
    *   **PC 相对加载指令 (LWPC, LWUPC)**: 测试从程序计数器相对地址加载字到寄存器的指令。
    *   **条件跳转指令 (JIC, BEQZC)**: 测试基于寄存器值的条件跳转指令。
    *   **绝对地址跳转指令 (JIALC)**: 测试跳转到绝对地址的指令。
    *   **PC 相对立即数加法指令 (ADDIUPC)**: 测试将立即数添加到程序计数器的指令。
    *   **PC 相对加载双字指令 (LDPC)**: 测试从程序计数器相对地址加载双字到寄存器的指令。
    *   **无条件跳转指令 (BC, BALC)**: 测试无条件跳转指令。
    *   **逻辑左移指令 (DSLL)**: 测试双字逻辑左移指令。
5. **宏指令 (LI)**: 测试加载立即数的宏指令，涵盖各种边界情况，并验证生成的指令数量。
6. **长跳转 (Trampoline)**: 测试当跳转目标超出指令的直接寻址范围时，汇编器自动插入跳转指令序列（trampoline）的功能。
7. **函数调用 (Call with trampoline)**: 测试当调用目标地址超出范围时，汇编器如何处理函数调用。
8. **浮点乘加/乘减指令 (MADD\*, MSUB\*, MADDF\*, MSUBF\*)**: 测试融合的浮点乘法和加法/减法指令。
9. **减法指令 (Subu)**: 测试无符号减法指令。

**与 JavaScript 的关系及示例：**

这些测试直接关系到 V8 JavaScript 引擎将 JavaScript 代码编译成 MIPS64 机器码的过程。当 JavaScript 代码执行到需要进行浮点运算、类型转换、条件判断或者函数调用时，V8 引擎会生成相应的 MIPS64 汇编指令。

以下是一些 JavaScript 示例，说明这些汇编指令可能在幕后被使用：

**1. 浮点运算 (CMP.\*, CVT\*, DIV\_FMT, MADD\*, MSUB\*, MADDF\*, MSUBF\*)**

```javascript
let a = 3.14;
let b = 2.71;
let c = a + b * 2; // 可能会使用 MADD/MADDF 指令
if (a > b) {      // 可能会使用 CMP 指令
  console.log("a is greater than b");
}
let d = parseInt(a); // 可能会使用 CVT 指令
let e = a / b;      // 可能会使用 DIV 指令
```

**2. 条件判断 (BEQZC, JIC, BC, BALC, JIALC)**

```javascript
let x = 10;
if (x > 5) {       // 可能会使用 BEQZC 等条件跳转指令
  console.log("x is greater than 5");
}

function factorial(n) {
  if (n === 0) {    // 可能会使用 BEQZC 等条件跳转指令
    return 1;
  } else {
    return n * factorial(n - 1); // 函数调用可能会使用 BALC/JIALC
  }
}
```

**3. 函数调用 (Call with trampoline, BAL)**

```javascript
function myFunction() {
  console.log("Hello from myFunction");
}

myFunction(); // 函数调用可能会使用 BAL 指令，如果目标地址较远，则可能涉及 trampoline
```

**4. 数据加载 (LI, LWPC, LWUPC, LDPC)**

```javascript
let arr = [1, 2, 3];
let value = arr[0]; // 从数组中加载数据，可能会使用 LI 或 PC 相对加载指令
```

**5. 位运算 (DSLL)**

```javascript
let num = 5;
let shifted = num << 2; // 位移操作可能会使用 DSLL 指令
```

总而言之，这部分 C++ 代码是对 V8 引擎中 MIPS64 汇编器进行细致的功能测试，确保生成的机器码能够正确地执行 JavaScript 代码。它涵盖了 MIPS64 架构中重要的指令集，并且针对了 MIPS64 r6 的新特性进行了测试。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共7部分，请归纳一下它的功能

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
    uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

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


TEST(r6_lwpc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLwpc {
      int       offset;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseLwpc tc[] = {
      // offset,   expected_res
      { -262144,   0x250FFFFF         },   // offset 0x40000
      {      -4,   0x250C0003         },
      {      -1,   0x250C0000         },
      {       0,   0xFFFFFFFFEF080000 },
      {       1,   0x03001025         },   // mov(v0, t8)
      {       2,   0x25080000         },
      {       4,   0x25080002         },
      {  262143,   0x250BFFFD         },   // offset 0x3FFFF
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLwpc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_lwpc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_lwupc(int offset) {
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

  __ lwupc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t addiu_start_2 = 0x25000000;
  for (int32_t i = 0x80000; i <= 0xBFFFF; ++i) {
    uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

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


TEST(r6_lwupc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLwupc {
      int       offset;
      uint64_t  expected_res;
    };

    // clang-format off
    struct TestCaseLwupc tc[] = {
      // offset,    expected_res
      { -262144,    0x250FFFFF },   // offset 0x40000
      {      -4,    0x250C0003 },
      {      -1,    0x250C0000 },
      {       0,    0xEF100000 },
      {       1,    0x03001025 },   // mov(v0, t8)
      {       2,    0x25080000 },
      {       4,    0x25080002 },
      {  262143,    0x250BFFFD },   // offset 0x3FFFF
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLwupc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_lwupc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_jic(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label stop_execution;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t1, 0x66);

  __ addiu(v0, v0, 0x1);        // <-- offset = -32
  __ addiu(v0, v0, 0x2);
  __ addiu(v0, v0, 0x10);
  __ addiu(v0, v0, 0x20);
  __ beq(v0, t1, &stop_execution);
  __ nop();

  __ nal();  // t0 <- program counter
  __ mov(t0, ra);
  __ jic(t0, offset);

  __ addiu(v0, v0, 0x100);
  __ addiu(v0, v0, 0x200);
  __ addiu(v0, v0, 0x1000);
  __ addiu(v0, v0, 0x2000);   // <--- offset = 16
  __ pop(ra);
  __ jr(ra);
  __ nop();

  __ bind(&stop_execution);
  __ pop(ra);
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


TEST(r6_jic) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseJic {
      // As rt will be used t0 register which will have value of
      // the program counter for the jic instruction.
      int16_t   offset;
      uint32_t  expected_res;
    };

    struct TestCaseJic tc[] = {
      // offset,   expected_result
      {      16,            0x2033 },
      {       4,            0x3333 },
      {     -32,              0x66 },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJic);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_jic(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_beqzc(int32_t value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label stop_execution;
  __ li(v0, 0l);
  __ li(t1, 0x66);

  __ addiu(v0, v0, 0x1);        // <-- offset = -8
  __ addiu(v0, v0, 0x2);
  __ addiu(v0, v0, 0x10);
  __ addiu(v0, v0, 0x20);
  __ beq(v0, t1, &stop_execution);
  __ nop();

  __ beqzc(a0, offset);

  __ addiu(v0, v0,    0x1);
  __ addiu(v0, v0,  0x100);
  __ addiu(v0, v0,  0x200);
  __ addiu(v0, v0, 0x1000);
  __ addiu(v0, v0, 0x2000);   // <--- offset = 4
  __ jr(ra);
  __ nop();

  __ bind(&stop_execution);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}


TEST(r6_beqzc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBeqzc {
      uint32_t  value;
      int32_t   offset;
      uint32_t  expected_res;
    };

    // clang-format off
    struct TestCaseBeqzc tc[] = {
      //    value,    offset,   expected_res
      {       0x0,        -8,           0x66 },
      {       0x0,         0,         0x3334 },
      {       0x0,         1,         0x3333 },
      {     0xABC,         1,         0x3334 },
      {       0x0,         4,         0x2033 },
    };
    // clang-format on

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeqzc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_beqzc(tc[i].value, tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}

void load_elements_of_vector(MacroAssembler* assm_ptr,
                             const uint64_t elements[], MSARegister w,
                             Register t0, Register t1) {
  MacroAssembler& assm = *assm_ptr;
  __ li(t0, static_cast<uint32_t>(elements[0] & 0xFFFFFFFF));
  __ li(t1, static_cast<uint32_t>((elements[0] >> 32) & 0xFFFFFFFF));
  __ insert_w(w, 0, t0);
  __ insert_w(w, 1, t1);
  __ li(t0, static_cast<uint32_t>(elements[1] & 0xFFFFFFFF));
  __ li(t1, static_cast<uint32_t>((elements[1] >> 32) & 0xFFFFFFFF));
  __ insert_w(w, 2, t0);
  __ insert_w(w, 3, t1);
}

inline void store_elements_of_vector(MacroAssembler* assm_ptr, MSARegister w,
                                     Register a) {
  MacroAssembler& assm = *assm_ptr;
  __ st_d(w, MemOperand(a, 0));
}

union msa_reg_t {
  uint8_t b[16];
  uint16_t h[8];
  uint32_t w[4];
  uint64_t d[2];
};

struct TestCaseMsaBranch {
  uint64_t wt_lo;
  uint64_t wt_hi;
};

template <typename Branch>
void run_bz_bnz(TestCaseMsaBranch* input, Branch GenerateBranch,
                bool branched) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t = {0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x0000000000000000,
         0x0000000000000000};
  msa_reg_t res;
  Label do_not_move_w0_to_w2;

  load_elements_of_vector(&assm, &t.ws_lo, w0, t0, t1);
  load_elements_of_vector(&assm, &t.wd_lo, w2, t0, t1);
  load_elements_of_vector(&assm, &input->wt_lo, w1, t0, t1);
  GenerateBranch(assm, do_not_move_w0_to_w2);
  __ nop();
  __ move_v(w2, w0);

  __ bind(&do_not_move_w0_to_w2);
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
  if (branched) {
    CHECK_EQ(t.wd_lo, res.d[0]);
    CHECK_EQ(t.wd_hi, res.d[1]);
  } else {
    CHECK_EQ(t.ws_lo, res.d[0]);
    CHECK_EQ(t.ws_hi, res.d[1]);
  }
}

TEST(MSA_bz_bnz) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  TestCaseMsaBranch tz_v[] = {
      {0x0, 0x0}, {0xABC, 0x0}, {0x0, 0xABC}, {0xABC, 0xABC}};
  for (unsigned i = 0; i < arraysize(tz_v); ++i) {
    run_bz_bnz(
        &tz_v[i],
        [](MacroAssembler& assm, Label& br_target) { __ bz_v(w1, &br_target); },
        tz_v[i].wt_lo == 0 && tz_v[i].wt_hi == 0);
  }

#define TEST_BZ_DF(input_array, lanes, instruction, int_type)         \
  for (unsigned i = 0; i < arraysize(input_array); ++i) {             \
    int j;                                                            \
    int_type* element = reinterpret_cast<int_type*>(&input_array[i]); \
    for (j = 0; j < lanes; ++j) {                                     \
      if (element[j] == 0) {                                          \
        break;                                                        \
      }                                                               \
    }                                                                 \
    run_bz_bnz(&input_array[i],                                       \
               [](MacroAssembler& assm, Label& br_target) {           \
                 __ instruction(w1, &br_target);                      \
               },                                                     \
               j != lanes);                                           \
  }
  TestCaseMsaBranch tz_b[] = {{0x0, 0x0},
                              {0xBC0000, 0x0},
                              {0x0, 0xAB000000000000CD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_b, kMSALanesByte, bz_b, int8_t)

  TestCaseMsaBranch tz_h[] = {{0x0, 0x0},
                              {0xBCDE0000, 0x0},
                              {0x0, 0xABCD00000000ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_h, kMSALanesHalf, bz_h, int16_t)

  TestCaseMsaBranch tz_w[] = {{0x0, 0x0},
                              {0xBCDE123400000000, 0x0},
                              {0x0, 0x000000001234ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_w, kMSALanesWord, bz_w, int32_t)

  TestCaseMsaBranch tz_d[] = {{0x0, 0x0},
                              {0xBCDE0000, 0x0},
                              {0x0, 0xABCD00000000ABCD},
                              {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BZ_DF(tz_d, kMSALanesDword, bz_d, int64_t)
#undef TEST_BZ_DF

  TestCaseMsaBranch tnz_v[] = {
      {0x0, 0x0}, {0xABC, 0x0}, {0x0, 0xABC}, {0xABC, 0xABC}};
  for (unsigned i = 0; i < arraysize(tnz_v); ++i) {
    run_bz_bnz(&tnz_v[i],
               [](MacroAssembler& assm, Label& br_target) {
                 __ bnz_v(w1, &br_target);
               },
               tnz_v[i].wt_lo != 0 || tnz_v[i].wt_hi != 0);
  }

#define TEST_BNZ_DF(input_array, lanes, instruction, int_type)        \
  for (unsigned i = 0; i < arraysize(input_array); ++i) {             \
    int j;                                                            \
    int_type* element = reinterpret_cast<int_type*>(&input_array[i]); \
    for (j = 0; j < lanes; ++j) {                                     \
      if (element[j] == 0) {                                          \
        break;                                                        \
      }                                                               \
    }                                                                 \
    run_bz_bnz(&input_array[i],                                       \
               [](MacroAssembler& assm, Label& br_target) {           \
                 __ instruction(w1, &br_target);                      \
               },                                                     \
               j == lanes);                                           \
  }
  TestCaseMsaBranch tnz_b[] = {{0x0, 0x0},
                               {0xBC0000, 0x0},
                               {0x0, 0xAB000000000000CD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_b, 16, bnz_b, int8_t)

  TestCaseMsaBranch tnz_h[] = {{0x0, 0x0},
                               {0xBCDE0000, 0x0},
                               {0x0, 0xABCD00000000ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_h, 8, bnz_h, int16_t)

  TestCaseMsaBranch tnz_w[] = {{0x0, 0x0},
                               {0xBCDE123400000000, 0x0},
                               {0x0, 0x000000001234ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_w, 4, bnz_w, int32_t)

  TestCaseMsaBranch tnz_d[] = {{0x0, 0x0},
                               {0xBCDE0000, 0x0},
                               {0x0, 0xABCD00000000ABCD},
                               {0x123456789ABCDEF0, 0xAAAAAAAAAAAAAAAA}};
  TEST_BNZ_DF(tnz_d, 2, bnz_d, int64_t)
#undef TEST_BNZ_DF
}

uint64_t run_jialc(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block;
  __ push(ra);
  __ li(v0, 0l);
  __ beq(v0, v0, &main_block);
  __ nop();

  // Block 1
  __ addiu(v0, v0, 0x1);        // <-- offset = -40
  __ addiu(v0, v0, 0x2);
  __ jr(ra);
  __ nop();

  // Block 2
  __ addiu(v0, v0, 0x10);        // <-- offset = -24
  __ addiu(v0, v0, 0x20);
  __ jr(ra);
  __ nop();

  // Block 3 (Main)
  __ bind(&main_block);
  __ nal();  // t0 <- program counter
  __ mov(t0, ra);
  __ jialc(t0, offset);
  __ addiu(v0, v0, 0x4);
  __ pop(ra);
  __ jr(ra);
  __ nop();

  // Block 4
  __ addiu(v0, v0, 0x100);      // <-- offset = 20
  __ addiu(v0, v0, 0x200);
  __ jr(ra);
  __ nop();

  // Block 5
  __ addiu(v0, v0, 0x1000);     // <--- offset = 36
  __ addiu(v0, v0, 0x2000);
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


TEST(r6_jialc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseJialc {
      // As rt will be used t0 register which will have value of
      // the program counter for the jialc instruction.
      int16_t   offset;
      uint32_t  expected_res;
    };

    struct TestCaseJialc tc[] = {
      // offset,   expected_res
      {     -40,            0x7 },
      {     -24,           0x34 },
      {      20,          0x304 },
      {      36,         0x3004 }
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseJialc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_jialc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_addiupc(int32_t imm19) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ addiupc(v0, imm19);
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


TEST(r6_addiupc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseAddiupc {
      int32_t   imm19;
    };

    struct TestCaseAddiupc tc[] = {
      //  imm19
      { -262144 },   // 0x40000
      {      -1 },   // 0x7FFFF
      {       0 },
      {       1 },   // 0x00001
      {  262143 }    // 0x3FFFF
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAddiupc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      PC = 0;
      uint64_t res = run_addiupc(tc[i].imm19);
      // Now, the program_counter (PC) is set.
      uint64_t expected_res = PC + (tc[i].imm19 << 2);
      CHECK_EQ(expected_res, res);
    }
  }
}


uint64_t run_ldpc(int offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // 256k instructions; 2 * 2^7k = 2^8k
  // addiu t3, a4, 0xFFFF;  (0x250FFFFF)
  // ...
  // addiu t0, a4, 0x0000;  (0x250C0000)
  uint32_t addiu_start_1 = 0x25000000;
  for (int32_t i = 0xFFFFF; i >= 0xC0000; --i) {
    uint32_t addiu_new = addiu_start_1 + i;
    __ dd(addiu_new);
  }

  __ ldpc(t8, offset);  // offset 0; 0xEF080000 (t8 register)
  __ mov(v0, t8);

  // 256k instructions; 2 * 2^7k = 2^8k
  // addiu a4, a4, 0x0000;  (0x25080000)
  // ...
  // addiu a7, a4, 0xFFFF;  (0x250BFFFF)
  uint32_t addiu_start_2 = 0x25000000;
  for (int32_t i = 0x80000; i <= 0xBFFFF; ++i) {
    uint32_t addiu_new = addiu_start_2 + i;
    __ dd(addiu_new);
  }

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


TEST(r6_ldpc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseLdpc {
      int       offset;
      uint64_t  expected_res;
    };

    auto doubleword = [](uint32_t word2, uint32_t word1) {
      if (kArchEndian == kLittle)
        return (static_cast<uint64_t>(word2) << 32) + word1;
      else
        return (static_cast<uint64_t>(word1) << 32) + word2;
    };

    TestCaseLdpc tc[] = {
        // offset,  expected_res
        {-131072, doubleword(0x250FFFFE, 0x250FFFFF)},
        {-4, doubleword(0x250C0006, 0x250C0007)},
        {-1, doubleword(0x250C0000, 0x250C0001)},
        {0, doubleword(0x03001025, 0xEF180000)},
        {1, doubleword(0x25080001, 0x25080000)},
        {4, doubleword(0x25080007, 0x25080006)},
        {131071, doubleword(0x250BFFFD, 0x250BFFFC)},
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLdpc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      uint64_t res = run_ldpc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


int64_t run_bc(int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label continue_1, stop_execution;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t8, 0l);
  __ li(t9, 2);   // Condition for the stopping execution.

  for (int32_t i = -100; i <= -11; ++i) {
    __ addiu(v0, v0, 1);
  }

  __ addiu(t8, t8, 1);              // -10

  __ beq(t8, t9, &stop_execution);  // -9
  __ nop();                         // -8
  __ beq(t8, t8, &continue_1);      // -7
  __ nop();                         // -6

  __ bind(&stop_execution);
  __ pop(ra);                       // -5, -4
  __ jr(ra);                        // -3
  __ nop();                         // -2

  __ bind(&continue_1);
  __ bc(offset);                    // -1

  for (int32_t i = 0; i <= 99; ++i) {
    __ addiu(v0, v0, 1);
  }

  __ pop(ra);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_bc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBc {
      int32_t   offset;
      int64_t   expected_res;
    };

    struct TestCaseBc tc[] = {
      //    offset,   expected_result
      {       -100,   (abs(-100) - 10) * 2      },
      {        -11,   (abs(-100) - 10 + 1)      },
      {          0,   (abs(-100) - 10 + 1 + 99) },
      {          1,   (abs(-100) - 10 + 99)     },
      {         99,   (abs(-100) - 10 + 1)      },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      int64_t res = run_bc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


int64_t run_balc(int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label continue_1;
  __ push(ra);
  __ li(v0, 0l);
  __ li(t8, 0l);
  __ li(t9, 2);   // Condition for stopping execution.

  __ beq(t8, t8, &continue_1);
  __ nop();

  uint32_t instruction_addiu = 0x24420001;  // addiu v0, v0, 1
  for (int32_t i = -117; i <= -57; ++i) {
    __ dd(instruction_addiu);
  }
  __ jr(ra);                        // -56
  __ nop();                         // -55

  for (int32_t i = -54; i <= -4; ++i) {
    __ dd(instruction_addiu);
  }
  __ jr(ra);                        // -3
  __ nop();                         // -2

  __ bind(&continue_1);
  __ balc(offset);                    // -1

  __ pop(ra);                         // 0, 1
  __ jr(ra);                          // 2
  __ nop();                           // 3

  for (int32_t i = 4; i <= 44; ++i) {
    __ dd(instruction_addiu);
  }
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}


TEST(r6_balc) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();

    struct TestCaseBalc {
      int32_t   offset;
      int64_t   expected_res;
    };

    struct TestCaseBalc tc[] = {
      //  offset,   expected_result
      {     -117,   61  },
      {      -54,   51  },
      {        0,   0   },
      {        4,   41  },
    };

    size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBalc);
    for (size_t i = 0; i < nr_test_cases; ++i) {
      int64_t res = run_balc(tc[i].offset);
      CHECK_EQ(tc[i].expected_res, res);
    }
  }
}


uint64_t run_dsll(uint64_t rt_value, uint16_t sa_value) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ dsll(v0, a0, sa_value);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F4>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rt_value, 0, 0, 0, 0));

  return res;
}


TEST(dsll) {
  CcTest::InitializeVM();

  struct TestCaseDsll {
    uint64_t  rt_value;
    uint16_t  sa_value;
    uint64_t  expected_res;
  };

  // clang-format off
  struct TestCaseDsll tc[] = {
    // rt_value,           sa_value, expected_res
    {  0xFFFFFFFFFFFFFFFF,    0,      0xFFFFFFFFFFFFFFFF },
    {  0xFFFFFFFFFFFFFFFF,   16,      0xFFFFFFFFFFFF0000 },
    {  0xFFFFFFFFFFFFFFFF,   31,      0xFFFFFFFF80000000 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDsll);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res,
            run_dsll(tc[i].rt_value, tc[i].sa_value));
  }
}


uint64_t run_bal(int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ mov(t0, ra);
  __ bal(offset);       // Equivalent for "BGEZAL zero_reg, offset".
  __ nop();

  __ mov(ra, t0);
  __ jr(ra);
  __ nop();

  __ li(v0, 1);
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


TEST(bal) {
  CcTest::InitializeVM();

  struct TestCaseBal {
    int16_t  offset;
    uint64_t  expected_res;
  };

  // clang-format off
  struct TestCaseBal tc[] = {
    // offset, expected_res
    {       4,            1 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBal);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_bal(tc[i].offset));
  }
}


TEST(Trampoline) {
  // Private member of Assembler class.
  static const int kMaxBranchOffset = (1 << (18 - 1)) - 1;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label done;
  size_t nr_calls = kMaxBranchOffset / (2 * kInstrSize) + 2;

  for (size_t i = 0; i < nr_calls; ++i) {
    __ BranchShort(&done, eq, a0, Operand(a1));
  }
  __ bind(&done);
  __ Ret(USE_DELAY_SLOT);
  __ mov(v0, zero_reg);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t res = reinterpret_cast<int64_t>(f.Call(42, 42, 0, 0, 0));
  CHECK_EQ(0, res);
}

TEST(Trampoline_with_massive_unbound_labels) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  const int kNumSlots =
      MacroAssembler::kMaxBranchOffset / MacroAssembler::kTrampolineSlotsSize;
  Label labels[kNumSlots];

  {
    MacroAssembler::BlockTrampolinePoolScope block_trampoline_pool(&assm);
    for (int i = 0; i < kNumSlots; i++) {
      __ Branch(&labels[i]);
    }
  }

  __ bind(&labels[0]);
}

static void DummyFunction(Object result) {}

TEST(Call_with_trampoline) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  int next_buffer_check_ = v8_flags.force_long_branches
                               ? kMaxInt
                               : MacroAssembler::kMaxBranchOffset -
                                     MacroAssembler::kTrampolineSlotsSize * 16;

  Label done;
  __ Branch(&done);
  next_buffer_check_ -= MacroAssembler::kTrampolineSlotsSize;

  int num_nops = (next_buffer_check_ - __ pc_offset()) / kInstrSize - 1;
  for (int i = 0; i < num_nops; i++) {
    __ nop();
  }

  int pc_offset_before = __ pc_offset();
  {
    // There should be a trampoline after this Call
    __ Call(FUNCTION_ADDR(DummyFunction), RelocInfo::EXTERNAL_REFERENCE);
  }
  int pc_offset_after = __ pc_offset();
  int safepoint_pc_offset = __ pc_offset_for_safepoint();

  // Without trampoline, the Call emits no more than 8 instructions, otherwise
  // more than 8 instructions will be generated.
  int num_instrs = 8;
  // pc_offset_after records the offset after trampoline.
  CHECK_GT(pc_offset_after - pc_offset_before, num_instrs * kInstrSize);
  // safepoint_pc_offset records the offset before trampoline.
  CHECK_LE(safepoint_pc_offset - pc_offset_before, num_instrs * kInstrSize);

  __ bind(&done);
}

template <class T>
struct TestCaseMaddMsub {
  T fr, fs, ft, fd_add, fd_sub;
};

template <typename T, typename F>
void helper_madd_msub_maddf_msubf(F func) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  T x = std::sqrt(static_cast<T>(2.0));
  T y = std::sqrt(static_cast<T>(3.0));
  T z = std::sqrt(static_cast<T>(5.0));
  T x2 = 11.11, y2 = 22.22, z2 = 33.33;
  TestCaseMaddMsub<T> test_cases[] = {
      {x, y, z, 0.0, 0.0},
      {x, y, -z, 0.0, 0.0},
      {x, -y, z, 0.0, 0.0},
      {x, -y, -z, 0.0, 0.0},
      {-x, y, z, 0.0, 0.0},
      {-x, y, -z, 0.0, 0.0},
      {-x, -y, z, 0.0, 0.0},
      {-x, -y, -z, 0.0, 0.0},
      {-3.14, 0.2345, -123.000056, 0.0, 0.0},
      {7.3, -23.257, -357.1357, 0.0, 0.0},
      {x2, y2, z2, 0.0, 0.0},
      {x2, y2, -z2, 0.0, 0.0},
      {x2, -y2, z2, 0.0, 0.0},
      {x2, -y2, -z2, 0.0, 0.0},
      {-x2, y2, z2, 0.0, 0.0},
      {-x2, y2, -z2, 0.0, 0.0},
      {-x2, -y2, z2, 0.0, 0.0},
      {-x2, -y2, -z2, 0.0, 0.0},
  };

  if (std::is_same<T, float>::value) {
    __ Lwc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
    __ Lwc1(f6, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fs)));
    __ Lwc1(f8, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, ft)));
    __ Lwc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
  } else if (std::is_same<T, double>::value) {
    __ Ldc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
    __ Ldc1(f6, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fs)));
    __ Ldc1(f8, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, ft)));
    __ Ldc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<T>, fr)));
  } else {
    UNREACHABLE();
  }

  func(assm);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  const size_t kTableLength = sizeof(test_cases) / sizeof(TestCaseMaddMsub<T>);
  TestCaseMaddMsub<T> tc;
  for (size_t i = 0; i < kTableLength; i++) {
    tc.fr = test_cases[i].fr;
    tc.fs = test_cases[i].fs;
    tc.ft = test_cases[i].ft;

    f.Call(&tc, 0, 0, 0, 0);

    T res_sub;
    T res_add;
    if (kArchVariant != kMips64r6) {
      res_add = tc.fr + (tc.fs * tc.ft);
      res_sub = (tc.fs * tc.ft) - tc.fr;
    } else {
      res_add = std::fma(tc.fs, tc.ft, tc.fr);
      res_sub = std::fma(-tc.fs, tc.ft, tc.fr);
    }

    CHECK_EQ(tc.fd_add, res_add);
    CHECK_EQ(tc.fd_sub, res_sub);
  }
}

TEST(madd_msub_s) {
  if (kArchVariant == kMips64r6) return;
  helper_madd_msub_maddf_msubf<float>([](MacroAssembler& assm) {
    __ Madd_s(f10, f4, f6, f8, f12);
    __ Swc1(f10, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_add)));
    __ Msub_s(f16, f4, f6, f8, f12);
    __ Swc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_sub)));
  });
}

TEST(madd_msub_d) {
  if (kArchVariant == kMips64r6) return;
  helper_madd_msub_maddf_msubf<double>([](MacroAssembler& assm) {
    __ Madd_d(f10, f4, f6, f8, f12);
    __ Sdc1(f10, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_add)));
    __ Msub_d(f16, f4, f6, f8, f12);
    __ Sdc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_sub)));
  });
}

TEST(maddf_msubf_s) {
  if (kArchVariant != kMips64r6) return;
  helper_madd_msub_maddf_msubf<float>([](MacroAssembler& assm) {
    __ maddf_s(f4, f6, f8);
    __ Swc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_add)));
    __ msubf_s(f16, f6, f8);
    __ Swc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<float>, fd_sub)));
  });
}

TEST(maddf_msubf_d) {
  if (kArchVariant != kMips64r6) return;
  helper_madd_msub_maddf_msubf<double>([](MacroAssembler& assm) {
    __ maddf_d(f4, f6, f8);
    __ Sdc1(f4, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_add)));
    __ msubf_d(f16, f6, f8);
    __ Sdc1(f16, MemOperand(a0, offsetof(TestCaseMaddMsub<double>, fd_sub)));
  });
}

uint64_t run_Subu(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ Subu(v0, zero_reg, Operand(imm));
  CHECK_EQ(assm.InstructionsGeneratedSince(&code_start),
"""


```