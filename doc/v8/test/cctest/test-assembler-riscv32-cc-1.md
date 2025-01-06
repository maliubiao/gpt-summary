Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code seems to be testing the RISC-V assembler within the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The code is within `v8/test/cctest/`, indicating it's a unit test. The filename `test-assembler-riscv32.cc` strongly suggests it's testing the RISC-V 32-bit assembler.

2. **Analyze Individual Tests:**  Each `TEST()` block likely focuses on specific aspects of the assembler. Look for patterns in the instructions used and the names of the tests.

3. **Categorize Functionality:** Group similar tests together to identify broader categories of functionality being tested. Examples include integer arithmetic, floating-point operations, memory access, control flow (branches, jumps), and potentially RISC-V C-extension instructions.

4. **Check for `.tq` Files:** The prompt mentions `.tq` files and Torque. This code doesn't have a `.tq` extension, so it's not a Torque test.

5. **Relate to JavaScript (if applicable):**  Consider how the tested assembly instructions might be used in the context of a JavaScript engine. For example, floating-point operations are crucial for number handling in JavaScript.

6. **Look for Logic and Examples:** Note any test cases that demonstrate specific logic, including the setup of input data and expected output checks.

7. **Identify Potential Programming Errors:** See if any tests implicitly highlight common pitfalls or edge cases related to the tested instructions (e.g., signed vs. unsigned operations, NaN handling).

8. **Synthesize the Summary:**  Combine the identified categories and specific examples into a concise summary of the code's functionality.
这是 V8 源代码 `v8/test/cctest/test-assembler-riscv32.cc` 的第二部分，它主要的功能是 **测试 RISC-V 32 位架构的汇编器**。

以下是该部分代码功能的归纳：

**主要功能：测试 RISC-V 汇编指令的正确性**

这部分代码通过定义一系列的 `TEST()` 函数，每个函数都生成一段 RISC-V 汇编代码，并在 V8 虚拟机中执行，然后检查执行结果是否符合预期。  这些测试涵盖了 RISC-V 架构的各种指令，包括：

* **整数运算指令：** `add`, `sub`, `and_`, `or_`, `xor_`, `not_`, `slli`, `slt`, `sltu`, `addi`。
* **浮点运算指令（双精度和单精度）：** `fld`, `fadd_d`, `fsd`, `fmv_d`, `fneg_d`, `fsub_d`, `fcvt_d_w`, `fmul_d`, `fdiv_d`, `fsqrt_d`, `fmadd_d`, `flw`, `fadd_s`, `fsw`, `fneg_s`, `fsub_s`, `fcvt_s_w`, `fmul_s`, `fdiv_s`, `fsqrt_s`.
* **浮点和整数寄存器之间的移动指令：** `fmv_x_w`, `fmv_w_x`.
* **浮点和整数之间的转换指令：** `fcvt_w_d`, `fcvt_w_s`, `fcvt_d_w`, `fcvt_s_w`.
* **内存加载和存储指令：** `lw`, `sw`, `lh`, `lhu`, `lb`, `sh`.
* **浮点数分类指令：** `fclass_s`.
* **浮点比较和分支指令：** `flt_d`, `beq`, `bne`.
* **分支指令的优化测试：** `Branch`.
* **NaN boxing 相关的指令测试：** `fmv_x_w`, `fmv_s`, `flw`, `fsw`.
* **RISC-V C 扩展指令测试（如果启用）：**  `c_addi`, `c_addi16sp`, `c_li`, `c_lui`, `c_slli`, `c_addi4spn`, `c_add`, `c_sub`, `c_xor`, `c_or`, `c_and`, `c_fsdsp`, `c_fldsp`, `c_swsp`, `c_lwsp`, `c_lw`, `c_sw`, `c_j`, `c_srai`, `c_srli`, `c_andi`, `c_beqz`, `c_bnez`.
* **目标地址相关的指令测试：** `target_address_at`, `set_target_value_at`.
* **超出范围的类型转换测试：**  测试浮点数转换为整数时，对于 NaN、无穷大等超出整数范围的值的处理。
* **浮点比较与 NaN 的测试：**  测试浮点比较指令对于 NaN 和无穷值的处理。
* **跳转表测试：** 测试向前和向后跳转的跳转表实现。
* **`li` 指令的指令数量估计测试：**  测试估计加载立即数的指令数量的准确性。

**关于代码特征的说明：**

* **`.tq` 文件：** 代码以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 Torque 源代码。
* **与 JavaScript 的关系：**  虽然这段代码本身是 C++ 汇编测试，但它直接关系到 V8 引擎执行 JavaScript 代码的效率和正确性。JavaScript 中的数值运算最终会被转化为底层的机器指令执行，这些测试确保了 RISC-V 架构下这些指令的正确实现。例如，`TEST(RISCV3)` 测试了浮点运算，这与 JavaScript 中 Number 类型的运算密切相关。
* **代码逻辑推理和假设输入/输出：** 代码中很多 `TEST()` 函数都包含了逻辑推理和预期的输入输出。例如，`TEST(RISCV2)` 中设置了寄存器 `a5` 和 `a6` 的值，然后执行 `and_`, `or_`, `xor_`, `not_` 等指令，并断言结果寄存器 `t0` 的值是否为预期的 `0xEDCBA983`。
* **用户常见的编程错误：**  虽然这段代码主要是测试汇编器，但某些测试也间接涉及了可能导致编程错误的场景，例如：
    * **整数溢出：**  尽管没有直接测试溢出，但整数运算指令是可能发生溢出的地方。
    * **浮点数精度问题：** 浮点运算的测试间接涉及到浮点数的精度问题。
    * **有符号和无符号数的处理：**  `slt` 和 `sltu` 的测试区分了有符号和无符号数的比较。
    * **内存访问错误：** `lw`, `sw` 等指令如果使用不当，可能会导致内存访问错误。

**总结：**

这段代码是 V8 引擎中针对 RISC-V 32 位架构汇编器进行全面单元测试的一部分，它通过构造各种汇编代码片段并执行验证，确保了汇编器能够正确地生成 RISC-V 机器码，从而保证了 V8 引擎在 RISC-V 平台上的正常运行和 JavaScript 代码的正确执行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-riscv32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-riscv32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
_ add(a1, a7,
           a4);  // 32bit addu result is sign-extended into 64bit reg.
    __ RV_li(t5, 0x80000003);
    __ bne(a1, t5, &error);
    __ sub(a1, t3, a4);  // 0x7FFFFFFC
    __ RV_li(t5, 0x7FFFFFFC);
    __ bne(a1, t5, &error);

    __ and_(t0, a5, a6);  // 0x00001230
    __ or_(t0, t0, a5);   // 0x00001234
    __ xor_(t0, t0, a6);  // 0x1234444C
    __ or_(t0, t0, a6);
    __ not_(t0, t0);  // 0xEDCBA983
    __ RV_li(t5, 0xEDCBA983);
    __ bne(t0, t5, &error);

    // Test slli, slt and sltu.
    __ slli(a7, a7, 31);  // 0x80000000
    __ addi(t3, t3, 1);   // 0x80000001
    __ slli(t3, t3, 30);  // 0x40000000
    __ RV_li(t5, 1);

    __ slt(t0, a7, t3);
    __ bne(t0, t5, &error);
    __ sltu(t0, a7, t3);
    __ bne(t0, zero_reg, &error);

    __ RV_li(t0, 0x7421);    // 0x00007421
    __ addi(t0, t0, -0x1);   // 0x00007420
    __ addi(t0, t0, -0x20);  // 0x00007400
    __ RV_li(t5, 0x00007400);
    __ bne(t0, t5, &error);
    __ addi(a1, a7, 0x0);  // 0x80000000 -
    __ RV_li(t5, 0x80000000);
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
    float a;
    float b;
    float c;
    float d;
    int32_t e;
  } t;

  auto fn = [](MacroAssembler& assm) {
    __ flw(ft0, a0, offsetof(T, a));
    __ flw(fa1, a0, offsetof(T, b));

    // Swap ft0 and fa1, by using 2 integer registers, a4-a5,
    __ fmv_x_w(a4, ft0);
    __ fmv_x_w(a5, fa1);

    __ fmv_w_x(fa1, a4);
    __ fmv_w_x(ft0, a5);

    // Store the swapped ft0 and fa1 back to memory.
    __ fsw(ft0, a0, offsetof(T, a));
    __ fsw(fa1, a0, offsetof(T, c));

    __ flw(ft0, a0, offsetof(T, d));
    __ fmv_x_w(a4, ft0);

    __ sw(a4, a0, offsetof(T, e));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(2.75e11f, t.a);
  CHECK_EQ(2.75e11f, t.b);
  CHECK_EQ(1.5e22f, t.c);
  CHECK_EQ(static_cast<int32_t>(0xD2800E8E), t.e);
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
    __ fcvt_w_d(a6, ft0);
    __ sw(a6, a0, offsetof(T, i));

    // Convert double in ft1 to int in element j.
    __ fcvt_w_d(a7, ft1);
    __ sw(a7, a0, offsetof(T, j));

    // Convert int in original i (a4) to double in a.
    __ fcvt_d_w(fa0, a4);
    __ fsd(fa0, a0, offsetof(T, a));

    // Convert int in original j (a5) to double in b.
    __ fcvt_d_w(fa1, a5);
    __ fsd(fa1, a0, offsetof(T, b));
  };
  auto f = AssembleCode<F3>(isolate, fn);

  t.a = 1.5e4;
  t.b = 2.75e4;
  t.i = 24000;
  t.j = -100000;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(24000, t.a);
  CHECK_EQ(-100000.0, t.b);
  CHECK_EQ(15000, t.i);
  CHECK_EQ(27500, t.j);
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
static const std::vector<std::pair<T, uint32_t>> fclass_test_values() {
  static const std::pair<T, uint32_t> kValues[] = {
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
#ifndef USE_SIMULATOR
      std::make_pair(std::numeric_limits<T>::signaling_NaN(), kSignalingNaN),
#endif
      std::make_pair(std::numeric_limits<T>::quiet_NaN(), kQuietNaN)};
  return std::vector<std::pair<T, uint32_t>>(&kValues[0],
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

  // {
  //   auto i_vec = fclass_test_values<double>();
  //   for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
  //     auto input = *i;
  //     auto fn = [](MacroAssembler& assm) { __ fclass_d(a0, fa0); };
  //     auto res = GenAndRunTest<uint32_t>(input.first, fn);
  //     CHECK_EQ(input.second, res);
  //   }
  // }
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
  // Test NaN boxing in FMV.X.W
  {
    auto fn = [](MacroAssembler& assm) { __ fmv_x_w(a0, fa0); };
    auto res = GenAndRunTest<uint32_t>(1234.56f, fn);
    CHECK_EQ((uint32_t)base::bit_cast<uint32_t>(1234.56f), res);
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
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - 15, res);
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
    auto res = GenAndRunTest<int32_t>(66666, fn);
    CHECK_EQ(66666 - 432, res);
  }

  // Test c.li
  {
    auto fn = [](MacroAssembler& assm) { __ c_li(a0, -15); };
    auto res = GenAndRunTest<int32_t>(1234543, fn);
    CHECK_EQ(-15, res);
  }

  // Test c.lui
  {
    auto fn = [](MacroAssembler& assm) { __ c_lui(a0, -20); };
    auto res = GenAndRunTest<int32_t>(0x1234567, fn);
    CHECK_EQ(0xfffec000, (uint32_t)res);
  }

  // Test c.slli
  {
    auto fn = [](MacroAssembler& assm) { __ c_slli(a0, 13); };
    auto res = GenAndRunTest<int32_t>(0x12345678, fn);
    CHECK_EQ(0x8acf0000, (uint32_t)res);
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
    auto res = GenAndRunTest<int32_t>(66666, fn);
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
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT + MIN_VAL_IMM12, res);
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
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT - MIN_VAL_IMM12, res);
  }

  // Test c.xor
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_xor(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT ^ MIN_VAL_IMM12, res);
  }

  // Test c.or
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_or(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT | MIN_VAL_IMM12, res);
  }

  // Test c.and
  {
    auto fn = [](MacroAssembler& assm) {
      __ RV_li(a1, MIN_VAL_IMM12);
      __ c_and(a0, a1);
    };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT & MIN_VAL_IMM12, res);
  }
}

TEST(RVC_LOAD_STORE_SP) {
  // Test RV32C extension flwsp/fswsp, lwsp/swsp.
  i::v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_fsdsp(fa0, 80);
      __ c_fldsp(fa0, 80);
    };
    auto res = GenAndRunTest<float>(-3456.678f, fn);
    CHECK_EQ(-3456.678f, res);
  }

  {
    auto fn = [](MacroAssembler& assm) {
      __ c_swsp(a0, 40);
      __ c_lwsp(a0, 40);
    };
    auto res = GenAndRunTest<int32_t>(0x456AF894, fn);
    CHECK_EQ(0x456AF894, res);
  }
}

TEST(RVC_LOAD_STORE_COMPRESSED) {
  // Test RV64C extension fld,  lw, ld.
  i::v8_flags.riscv_c_extension = true;

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

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

  int32_t input = 50;
  int32_t expected_res = 1275L;
  auto res = GenAndRunTest<int32_t>(input, fn);
  CHECK_EQ(expected_res, res);
}

TEST(RVC_CB) {
  // Test RV64C extension CI type instructions.
  v8_flags.riscv_c_extension = true;
  CcTest::InitializeVM();

  // Test c.srai
  {
    auto fn = [](MacroAssembler& assm) { __ c_srai(a0, 13); };
    auto res = GenAndRunTest<int32_t>(0x12345678, fn);
    CHECK_EQ(0x12345678UL >> 13, res);
  }

  // Test c.srli
  {
    auto fn = [](MacroAssembler& assm) { __ c_srli(a0, 13); };
    auto res = GenAndRunTest<int32_t>(0x12345678, fn);
    CHECK_EQ(0x1234'5678ULL >> 13, res);
  }

  // Test c.andi
  {
    auto fn = [](MacroAssembler& assm) { __ c_andi(a0, 13); };
    auto res = GenAndRunTest<int32_t>(LARGE_INT_UNDER_32_BIT, fn);
    CHECK_EQ(LARGE_INT_UNDER_32_BIT & 13, res);
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

  // This is the series of instructions to load 32 bit address 0x01234567 to a6
  // (li a6,0x1234567)
  uint32_t buffer[2] = {0x01234837,   // lui     a6,0x1234
                        0x56780813};  // addi    a6,a6,1383

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0x01234567L, res);
}

TEST(SET_TARGET_ADDR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  // This is the series of instructions to load 48 bit address 0xba9876543210
  uint32_t buffer[6] = {0x091ab37,  0x2b330213, 0x00b21213,
                        0x62626213, 0x00621213, 0x02b26213};

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  uintptr_t addr = reinterpret_cast<uintptr_t>(&buffer[0]);
  __ set_target_value_at(static_cast<Address>(addr), 0xba987654L, nullptr,
                         FLUSH_ICACHE_IF_NEEDED);
  Address res = __ target_address_at(static_cast<Address>(addr));
  CHECK_EQ(0xba987654L, res);
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

  // {  // test fvt_w_d
  //   auto i_vec = out_of_range_test_values<double, int32_t>();
  //   for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
  //     auto input = *i;
  //     auto fn = [](MacroAssembler& assm) { __ fcvt_w_d(a0, fa0); };
  //     auto res = GenAndRunTest<int32_t>(input.first, fn);
  //     CHECK_EQ(input.second, res);
  //   }
  // }

  {  // test fvt_w_s
    auto i_vec = out_of_range_test_values<float, int32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_w_s(a0, fa0); };
      auto res = GenAndRunTest<int32_t>(input.first, fn);
      CHECK_EQ(input.second, res);
    }
  }

  // {  // test fvt_wu_d
  //   auto i_vec = out_of_range_test_values<double, uint32_t>();
  //   for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
  //     auto input = *i;
  //     auto fn = [](MacroAssembler& assm) { __ fcvt_wu_d(a0, fa0); };
  //     auto res = GenAndRunTest<uint32_t>(input.first, fn);
  //     CHECK_EQ(input.second, res);
  //   }
  // }

  {  // test fvt_wu_s
    auto i_vec = out_of_range_test_values<float, uint32_t>();
    for (auto i = i_vec.begin(); i != i_vec.end(); ++i) {
      auto input = *i;
      auto fn = [](MacroAssembler& assm) { __ fcvt_wu_s(a0, fa0); };
      auto res = GenAndRunTest<uint32_t>(input.first, fn);
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
  // auto fn4 = [](MacroAssembler& assm) { __ feq_d(a0, fa0, fa1); };
  // FCMP_TEST_HELPER(double, fn4, ==);
  // auto fn5 = [](MacroAssembler& assm) { __ flt_d(a0, fa0, fa1); };
  // FCMP_TEST_HELPER(double, fn5, <);
  // auto fn6 = [](MacroAssembler& assm) { __ fle_d(a0, fa0, fa1); };
  // FCMP_TEST_HELPER(double, fn6, <=);
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
    __ addi(sp, sp, -4);
    __ Sw(ra, MemOperand(sp));
    __ Align(4);
    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

      __ auipc(ra, 0);
      __ slli(t3, a0, 2);
      __ add(t3, t3, ra);
      __ Lw(t3, MemOperand(t3, 6 * kInstrSize));
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
    __ Lw(ra, MemOperand(sp));
    __ addi(sp, sp, 4);

    CHECK_EQ(0, assm.UnboundLabelsCount());
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    int32_t res = reinterpret_cast<int32_t>(f.Call(i, 0, 0, 0, 0));
    CHECK_EQ(values[i], static_cast<int>(res));
  }
}

TEST(jump_tables2) {
  // Test jump tables with backward jumps.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  const int kNumCases = 128;
  int32_t values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases], done, dispatch;

  auto fn = [&labels, &done, &dispatch, values](MacroAssembler& assm) {
    __ addi(sp, sp, -4);
    __ Sw(ra, MemOperand(sp));
    __ j(&dispatch);

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      __ RV_li(a0, values[i]);
      __ j(&done);
    }

    __ Align(4);
    __ bind(&dispatch);

    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);

      __ auipc(ra, 0);
      __ slli(t3, a0, 2);
      __ add(t3, t3, ra);
      __ Lw(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }
    __ bind(&done);
    __ Lw(ra, MemOperand(sp));
    __ addi(sp, sp, 4);
  };
  auto f = AssembleCode<F1>(isolate, fn);

  for (int i = 0; i < kNumCases; ++i) {
    int32_t res = reinterpret_cast<int32_t>(f.Call(i, 0, 0, 0, 0));
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
  int32_t imm32;

  auto fn = [&labels, &done, &dispatch, values, &obj,
             &imm32](MacroAssembler& assm) {
    __ addi(sp, sp, -4);
    __ Sw(ra, MemOperand(sp));

    __ j(&dispatch);

    for (int i = 0; i < kNumCases; ++i) {
      __ bind(&labels[i]);
      obj = *values[i];
      imm32 = obj.ptr();
      __ nop();  // For 8 byte alignment
      __ RV_li(a0, imm32);
      __ nop();  // For 8 byte alignment
      __ j(&done);
    }

    __ bind(&dispatch);
    {
      __ BlockTrampolinePoolFor(kNumCases * 2 + 6);
      __ Align(4);
      __ auipc(ra, 0);
      __ slli(t3, a0, 2);
      __ add(t3, t3, ra);
      __ Lw(t3, MemOperand(t3, 6 * kInstrSize));
      __ jr(t3);
      __ nop();  // For 16-byte alignment
      for (int i = 0; i < kNumCases; ++i) {
        __ dd(&labels[i]);
      }
    }

    __ bind(&done);
    __ Lw(ra, MemOperand(sp));
    __ addi(sp, sp, 4);
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
      INT64_MIN};
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

#ifdef CAN_USE_RVV_INSTRUCTIONS
#define UTEST_LOAD_STORE_RVV(ldname, stname, SEW, arry)                      \
  TEST(RISCV_UTEST_##stname##ldname##SEW) {                                  \
    if (!CpuFeatures::IsSupported(RISCV_SIMD)) return;                       \
    CcTest::InitializeVM();                                                  \
    Isolate* isolate = CcTest::i_isolate();                                  \
    Han
"""


```