Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-macro-assembler-loong64.cc`. This is the second part of the file.
The file seems to be testing the `MacroAssembler` class for the LoongArch64 architecture in V8. It contains a series of unit tests for various assembly instructions and macro instructions.

Based on the provided code, I can identify the following categories of tests:
- **Sub:** Tests the subtraction instruction with immediate operands.
- **Move:** Tests moving immediate values into floating-point registers.
- **Movz_Movn:** Tests conditional move instructions based on zero/non-zero condition.
- **macro_instructions1:** Tests 32-bit arithmetic and logical macro instructions.
- **macro_instructions2:** Tests 64-bit arithmetic and logical macro instructions.
- **macro_instructions3:** Tests more 64-bit logical and comparison macro instructions.
- **Rotr_w:** Tests 32-bit rotate right instruction.
- **Rotr_d:** Tests 64-bit rotate right instruction.
- **macro_instructions4:** Tests floating-point conversion macro instructions (floor, ceil, trunc, round).
- **ExtractBits:** Tests extracting bit fields from a register.
- **InsertBits:** Tests inserting bit fields into a register.
- **Popcnt:** Tests population count instructions (counting set bits).
- **DeoptExitSizeIsFixed:** Tests that the size of the deoptimization exit code is as expected.

To illustrate the connection with JavaScript, I can choose one of the tested instructions/macros and show how a similar operation can be performed in JavaScript. For example, the `Rotr_w` instruction (rotate right word) can be related to bitwise operations in JavaScript.
这是 `v8/test/cctest/test-macro-assembler-loong64.cc` 文件的第二部分，延续了第一部分的功能，**主要用于测试 V8 引擎在 LoongArch64 架构下的 `MacroAssembler` 类的正确性**。

具体来说，这部分代码包含了以下功能的测试：

* **`Sub` 测试:**  测试带立即数的减法指令 (`sub_d`) 的各种情况，包括不同大小的立即数，并检查生成的指令数量是否符合预期。
* **`Move` 测试:** 测试将立即数移动到浮点寄存器的指令 (`Move`)，并验证移动后的值是否正确。
* **`Movz_Movn` 测试:** 测试条件移动指令 (`Movz` 和 `Movn`)，根据条件寄存器的值来决定是否移动数据。
* **`macro_instructions1` 测试:**  测试一系列 32 位整型算术和逻辑宏指令，例如 `add_w`, `mul_w`, `mulh_w`, `div_w`, `mod_w` 等。通过设置不同的输入值，检查宏指令生成的代码是否正确执行并得到预期的结果。
* **`macro_instructions2` 测试:** 测试一系列 64 位整型算术宏指令，例如 `add_d`, `Mul_d`, `Mulh_d`, `Div_d`, `Mod_d` 等。
* **`macro_instructions3` 测试:** 测试更多 64 位整型逻辑和比较宏指令，例如 `And`, `Or`, `Orn`, `Xor`, `Nor`, `Andn`, `Neg`, `Slt`, `Sle`, `Sleu`, `Sge`, `Sgeu`, `Sgt`, `Sgtu`。
* **`Rotr_w` 测试:** 测试 32 位字的循环右移指令 (`Rotr_w`)，包括立即数移位和寄存器移位两种形式。
* **`Rotr_d` 测试:** 测试 64 位字的循环右移指令 (`Rotr_d`)。
* **`macro_instructions4` 测试:** 测试浮点数取整相关的宏指令，例如 `Floor_d/s` (向下取整), `Ceil_d/s` (向上取整), `Trunc_d/s` (截断取整), `Round_d/s` (四舍五入)。
* **`ExtractBits` 测试:** 测试从一个 64 位寄存器中提取指定位置和大小的位域的指令 (`ExtractBits`)，并可以选择是否进行符号扩展。
* **`InsertBits` 测试:** 测试将一个 64 位寄存器的指定位域插入到另一个寄存器的指定位置的指令 (`InsertBits`)。
* **`Popcnt` 测试:** 测试计算 32 位和 64 位寄存器中二进制表示中 1 的个数的指令 (`Popcnt_w` 和 `Popcnt_d`)。
* **`DeoptExitSizeIsFixed` 测试:** 验证特定类型的反优化出口代码的大小是否是固定的，这对于 V8 引擎的性能和稳定性非常重要。

**与 JavaScript 的关系示例 (以 `Rotr_w` 为例):**

虽然 JavaScript 本身没有直接的循环右移指令，但我们可以使用位运算来模拟类似的功能。

C++ 代码中 `Rotr_w(a5, a4, 4)` 的作用是将寄存器 `a4` 中的 32 位值循环右移 4 位，并将结果存储到 `a5` 中。

在 JavaScript 中，我们可以使用位运算和移位操作来模拟：

```javascript
function rotateRight(n, bits) {
  const mask = 0xFFFFFFFF; // 确保只处理 32 位
  bits = bits & 31;      // 确保移位位数在 0-31 之间
  return (n >>> bits) | ((n << (32 - bits)) & mask);
}

let num = 0x12345678;
let rotatedNum = rotateRight(num, 4);
console.log(rotatedNum.toString(16)); // 输出: 81234567
```

**解释:**

1. `n >>> bits`:  无符号右移 `bits` 位。
2. `n << (32 - bits)`: 左移 `32 - bits` 位，将移出的高位补到低位。
3. `& mask`:  与 `0xFFFFFFFF` 进行按位与运算，确保结果是 32 位。
4. `|`:  将两个结果进行按位或运算，合并成循环右移的结果。

这个 JavaScript 示例展示了如何使用位运算来达到与 LoongArch64 架构的 `Rotr_w` 指令类似的效果。V8 引擎在底层实现 JavaScript 的位运算时，会使用类似的机器指令。这些测试用例确保了 V8 引擎能够正确地生成和执行这些底层的机器指令。

总而言之，这部分代码是 V8 引擎在 LoongArch64 架构下进行单元测试的关键部分，它验证了代码生成器 (`MacroAssembler`) 能否为各种指令和宏指令生成正确的机器码，从而保证 JavaScript 代码在该架构上的正确执行。

Prompt: 
```
这是目录为v8/test/cctest/test-macro-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
 use ori.
      {0xFFFFFFFFFFFFF7FF,              0x801,         2},  // min_int12 - 1
      // Generates ori + add_d
      {             0x801, 0xFFFFFFFFFFFFF7FF,         2},  // max_int12 + 2
      // Generates ori + add_d
      {        0x00001000, 0xFFFFFFFFFFFFF000,         2},  // max_uint12 + 1
      // Generates lu12i_w + sub_d
      {        0x00001001, 0xFFFFFFFFFFFFEFFF,         3},  // max_uint12 + 2
      // Generates lu12i_w + ori + sub_d
      {0x00000000FFFFFFFF, 0xFFFFFFFF00000001,         3},  // max_uint32
      // Generates addi_w + li32i_d + sub_d
      {0x00000000FFFFFFFE, 0xFFFFFFFF00000002,         3},  // max_uint32 - 1
      // Generates addi_w + li32i_d + sub_d
      {0xFFFFFFFF80000000,         0x80000000,         2},  // min_int32
      // Generates lu12i_w + sub_d
      {0x0000000080000000, 0xFFFFFFFF80000000,         2},  // max_int32 + 1
      // Generates lu12i_w + add_d
      {0xFFFF0000FFFF8765, 0x0000FFFF0000789B,         4},
      // Generates lu12i_w + ori + lu32i_d + sub
      {0x1234ABCD87654321, 0xEDCB5432789ABCDF,         5},
      // Generates lu12i_w + ori + lu32i_d + lu52i_d + sub
      {0xFFFF789100000000,     0x876F00000000,         3},
      // Generates xor + lu32i_d + sub
      {0xF12F789100000000,  0xED0876F00000000,         4},
      // Generates xor + lu32i_d + lu52i_d + sub
      {0xF120000000000800,  0xEDFFFFFFFFFF800,         3},
      // Generates ori + lu52i_d + sub
      {0xFFF0000000000000,   0x10000000000000,         2}
      // Generates lu52i_d + sub
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseSub);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Sub_d(tc[i].imm, tc[i].num_instr));
  }
}

TEST(Move) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct T {
    float a;
    float b;
    float result_a;
    float result_b;
    double c;
    double d;
    double e;
    double result_c;
    double result_d;
    double result_e;
  };
  T t;
  __ li(a4, static_cast<int32_t>(0x80000000));
  __ St_w(a4, MemOperand(a0, offsetof(T, a)));
  __ li(a5, static_cast<int32_t>(0x12345678));
  __ St_w(a5, MemOperand(a0, offsetof(T, b)));
  __ li(a6, static_cast<int64_t>(0x8877665544332211));
  __ St_d(a6, MemOperand(a0, offsetof(T, c)));
  __ li(a7, static_cast<int64_t>(0x1122334455667788));
  __ St_d(a7, MemOperand(a0, offsetof(T, d)));
  __ li(t0, static_cast<int64_t>(0));
  __ St_d(t0, MemOperand(a0, offsetof(T, e)));

  __ Move(f8, static_cast<uint32_t>(0x80000000));
  __ Move(f9, static_cast<uint32_t>(0x12345678));
  __ Move(f10, static_cast<uint64_t>(0x8877665544332211));
  __ Move(f11, static_cast<uint64_t>(0x1122334455667788));
  __ Move(f12, static_cast<uint64_t>(0));
  __ Fst_s(f8, MemOperand(a0, offsetof(T, result_a)));
  __ Fst_s(f9, MemOperand(a0, offsetof(T, result_b)));
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_c)));
  __ Fst_d(f11, MemOperand(a0, offsetof(T, result_d)));
  __ Fst_d(f12, MemOperand(a0, offsetof(T, result_e)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  f.Call(&t, 0, 0, 0, 0);
  CHECK_EQ(t.a, t.result_a);
  CHECK_EQ(t.b, t.result_b);
  CHECK_EQ(t.c, t.result_c);
  CHECK_EQ(t.d, t.result_d);
  CHECK_EQ(t.e, t.result_e);
}

TEST(Movz_Movn) {
  const int kTableLength = 4;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Test {
    int64_t rt;
    int64_t a;
    int64_t b;
    int64_t bold;
    int64_t b1;
    int64_t bold1;
    int32_t c;
    int32_t d;
    int32_t dold;
    int32_t d1;
    int32_t dold1;
  };

  Test test;
  // clang-format off
    int64_t inputs_D[kTableLength] = {
      7, 8, -9, -10
    };
    int32_t inputs_W[kTableLength] = {
      3, 4, -5, -6
    };

    int32_t outputs_W[kTableLength] = {
      3, 4, -5, -6
    };
    int64_t outputs_D[kTableLength] = {
      7, 8, -9, -10
    };
  // clang-format on

  __ Ld_d(a4, MemOperand(a0, offsetof(Test, a)));
  __ Ld_w(a5, MemOperand(a0, offsetof(Test, c)));
  __ Ld_d(a6, MemOperand(a0, offsetof(Test, rt)));
  __ li(t0, 1);
  __ li(t1, 1);
  __ li(t2, 1);
  __ li(t3, 1);
  __ St_d(t0, MemOperand(a0, offsetof(Test, bold)));
  __ St_d(t1, MemOperand(a0, offsetof(Test, bold1)));
  __ St_w(t2, MemOperand(a0, offsetof(Test, dold)));
  __ St_w(t3, MemOperand(a0, offsetof(Test, dold1)));
  __ Movz(t0, a4, a6);
  __ Movn(t1, a4, a6);
  __ Movz(t2, a5, a6);
  __ Movn(t3, a5, a6);
  __ St_d(t0, MemOperand(a0, offsetof(Test, b)));
  __ St_d(t1, MemOperand(a0, offsetof(Test, b1)));
  __ St_w(t2, MemOperand(a0, offsetof(Test, d)));
  __ St_w(t3, MemOperand(a0, offsetof(Test, d1)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputs_D[i];
    test.c = inputs_W[i];

    test.rt = 1;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.b, test.bold);
    CHECK_EQ(test.d, test.dold);
    CHECK_EQ(test.b1, outputs_D[i]);
    CHECK_EQ(test.d1, outputs_W[i]);

    test.rt = 0;
    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(test.b, outputs_D[i]);
    CHECK_EQ(test.d, outputs_W[i]);
    CHECK_EQ(test.b1, test.bold1);
    CHECK_EQ(test.d1, test.dold1);
  }
}

TEST(macro_instructions1) {
  // Test 32bit calculate instructions macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label exit, error;

  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, static_cast<int32_t>(0xFFFFFFFC));
  __ li(t1, static_cast<int32_t>(0xFFFFEDCC));
  __ li(t2, static_cast<int32_t>(0xEDCBA988));
  __ li(t3, static_cast<int32_t>(0x80000000));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ add_w(a2, a7, t1);
  __ Add_w(a3, t1, a7);
  __ Branch(&error, ne, a2, Operand(a3));
  __ Add_w(t4, t1, static_cast<int32_t>(0x7FFFFFFF));
  __ Branch(&error, ne, a2, Operand(t4));
  __ addi_w(a2, a6, 0x800);
  __ Add_w(a3, a6, 0xFFFFF800);
  __ Branch(&error, ne, a2, Operand(a3));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ mul_w(a2, t1, a7);
  __ Mul_w(a3, t1, a7);
  __ Branch(&error, ne, a2, Operand(a3));
  __ Mul_w(t4, t1, static_cast<int32_t>(0x7FFFFFFF));
  __ Branch(&error, ne, a2, Operand(t4));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ mulh_w(a2, t1, a7);
  __ Mulh_w(a3, t1, a7);
  __ Branch(&error, ne, a2, Operand(a3));
  __ Mulh_w(t4, t1, static_cast<int32_t>(0x7FFFFFFF));
  __ Branch(&error, ne, a2, Operand(t4));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mulh_wu(a2, a4, static_cast<int32_t>(0xFFFFEDCC));
  __ Branch(&error, ne, a2, Operand(0x3));
  __ Mulh_wu(a3, a4, t1);
  __ Branch(&error, ne, a3, Operand(0x3));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ div_w(a2, a7, t2);
  __ Div_w(a3, a7, t2);
  __ Branch(&error, ne, a2, Operand(a3));
  __ Div_w(t4, a7, static_cast<int32_t>(0xEDCBA988));
  __ Branch(&error, ne, a2, Operand(t4));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Div_wu(a2, a7, a5);
  __ Branch(&error, ne, a2, Operand(0x70821));
  __ Div_wu(a3, t0, static_cast<int32_t>(0x00001234));
  __ Branch(&error, ne, a3, Operand(0xE1042));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mod_w(a2, a6, a5);
  __ Branch(&error, ne, a2, Operand(0xDA8));
  __ Mod_w(a3, t2, static_cast<int32_t>(0x00001234));
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFFFFFFF258));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mod_wu(a2, a6, a5);
  __ Branch(&error, ne, a2, Operand(0xDA8));
  __ Mod_wu(a3, t2, static_cast<int32_t>(0x00001234));
  __ Branch(&error, ne, a3, Operand(0xF0));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(macro_instructions2) {
  // Test 64bit calculate instructions macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label exit, error;

  __ li(a4, 0x17312);
  __ li(a5, 0x1012131415161718);
  __ li(a6, 0x51F4B764A26E7412);
  __ li(a7, 0x7FFFFFFFFFFFFFFF);
  __ li(t0, static_cast<int64_t>(0xFFFFFFFFFFFFF547));
  __ li(t1, static_cast<int64_t>(0xDF6B8F35A10E205C));
  __ li(t2, static_cast<int64_t>(0x81F25A87C4236841));
  __ li(t3, static_cast<int64_t>(0x8000000000000000));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ add_d(a2, a7, t1);
  __ Add_d(a3, t1, a7);
  __ Branch(&error, ne, a2, Operand(a3));
  __ Add_d(t4, t1, Operand(0x7FFFFFFFFFFFFFFF));
  __ Branch(&error, ne, a2, Operand(t4));
  __ addi_d(a2, a6, 0x800);
  __ Add_d(a3, a6, Operand(0xFFFFFFFFFFFFF800));
  __ Branch(&error, ne, a2, Operand(a3));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mul_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0xdbe6a8729a547fb0));
  __ Mul_d(a3, t0, Operand(0xDF6B8F35A10E205C));
  __ Branch(&error, ne, a3, Operand(0x57ad69f40f870584));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mulh_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x52514c6c6b54467));
  __ Mulh_d(a3, t0, Operand(0xDF6B8F35A10E205C));
  __ Branch(&error, ne, a3, Operand(0x15d));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Div_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ Div_d(a3, t1, Operand(0x17312));
  __ Branch(&error, ne, a3, Operand(0xffffe985f631e6d9));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Div_du(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ Div_du(a3, t1, 0x17312);
  __ Branch(&error, ne, a3, Operand(0x9a22ffd3973d));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mod_d(a2, a6, a4);
  __ Branch(&error, ne, a2, Operand(0x13558));
  __ Mod_d(a3, t2, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(0xfffffffffffffb0a));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Mod_du(a2, a6, a4);
  __ Branch(&error, ne, a2, Operand(0x13558));
  __ Mod_du(a3, t2, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(0x81f25a87c4236841));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(macro_instructions3) {
  // Test 64bit calculate instructions macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label exit, error;

  __ li(a4, 0x17312);
  __ li(a5, 0x1012131415161718);
  __ li(a6, 0x51F4B764A26E7412);
  __ li(a7, 0x7FFFFFFFFFFFFFFF);
  __ li(t0, static_cast<int64_t>(0xFFFFFFFFFFFFF547));
  __ li(t1, static_cast<int64_t>(0xDF6B8F35A10E205C));
  __ li(t2, static_cast<int64_t>(0x81F25A87C4236841));
  __ li(t3, static_cast<int64_t>(0x8000000000000000));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ And(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0x1310));
  __ And(a3, a6, Operand(0x7FFFFFFFFFFFFFFF));
  __ Branch(&error, ne, a3, Operand(0x51F4B764A26E7412));
  __ andi(a2, a6, 0xDCB);
  __ And(a3, a6, Operand(0xDCB));
  __ Branch(&error, ne, a3, Operand(a2));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Or(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffff55f));
  __ Or(a3, t2, Operand(0x8000000000000000));
  __ Branch(&error, ne, a3, Operand(0x81f25a87c4236841));
  __ ori(a2, a5, 0xDCB);
  __ Or(a3, a5, Operand(0xDCB));
  __ Branch(&error, ne, a2, Operand(a3));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Orn(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xffffffffffffffe7));
  __ Orn(a3, t2, Operand(0x81F25A87C4236841));
  __ Branch(&error, ne, a3, Operand(0xffffffffffffffff));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Xor(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x209470ca5ef1d51b));
  __ Xor(a3, t2, Operand(0x8000000000000000));
  __ Branch(&error, ne, a3, Operand(0x1f25a87c4236841));
  __ Xor(a2, t2, Operand(0xDCB));
  __ Branch(&error, ne, a2, Operand(0x81f25a87c423658a));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Nor(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0xefedecebeae888e5));
  __ Nor(a3, a6, Operand(0x7FFFFFFFFFFFFFFF));
  __ Branch(&error, ne, a3, Operand(0x8000000000000000));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Andn(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0x16002));
  __ Andn(a3, a6, Operand(0x7FFFFFFFFFFFFFFF));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Orn(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xffffffffffffffe7));
  __ Orn(a3, t2, Operand(0x8000000000000000));
  __ Branch(&error, ne, a3, Operand(0xffffffffffffffff));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Neg(a2, a7);
  __ Branch(&error, ne, a2, Operand(0x8000000000000001));
  __ Neg(a3, t0);
  __ Branch(&error, ne, a3, Operand(0xAB9));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Slt(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ Slt(a3, a7, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0)));
  __ Slt(a3, a4, 0x800);
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Sle(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ Sle(a3, t0, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0x1)));
  __ Sle(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Sleu(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ Sleu(a3, t0, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0x1)));
  __ Sleu(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0x1)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Sge(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ Sge(a3, t0, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0x1)));
  __ Sge(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0x1)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Sgeu(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ Sgeu(a3, t0, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0x1)));
  __ Sgeu(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Sgt(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ Sgt(a3, t0, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0)));
  __ Sgt(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0x1)));

  __ or_(a2, zero_reg, zero_reg);
  __ or_(a3, zero_reg, zero_reg);
  __ Sgtu(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ Sgtu(a3, t0, Operand(0xFFFFFFFFFFFFF547));
  __ Branch(&error, ne, a3, Operand(static_cast<int64_t>(0)));
  __ Sgtu(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(Rotr_w) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct T {
    int32_t input;
    int32_t result_rotr_0;
    int32_t result_rotr_4;
    int32_t result_rotr_8;
    int32_t result_rotr_12;
    int32_t result_rotr_16;
    int32_t result_rotr_20;
    int32_t result_rotr_24;
    int32_t result_rotr_28;
    int32_t result_rotr_32;
    int32_t result_rotri_0;
    int32_t result_rotri_4;
    int32_t result_rotri_8;
    int32_t result_rotri_12;
    int32_t result_rotri_16;
    int32_t result_rotri_20;
    int32_t result_rotri_24;
    int32_t result_rotri_28;
    int32_t result_rotri_32;
  };
  T t;

  __ Ld_w(a4, MemOperand(a0, offsetof(T, input)));

  __ Rotr_w(a5, a4, 0);
  __ Rotr_w(a6, a4, 0x04);
  __ Rotr_w(a7, a4, 0x08);
  __ Rotr_w(t0, a4, 0x0C);
  __ Rotr_w(t1, a4, 0x10);
  __ Rotr_w(t2, a4, -0x0C);
  __ Rotr_w(t3, a4, -0x08);
  __ Rotr_w(t4, a4, -0x04);
  __ Rotr_w(t5, a4, 0x20);
  __ St_w(a5, MemOperand(a0, offsetof(T, result_rotr_0)));
  __ St_w(a6, MemOperand(a0, offsetof(T, result_rotr_4)));
  __ St_w(a7, MemOperand(a0, offsetof(T, result_rotr_8)));
  __ St_w(t0, MemOperand(a0, offsetof(T, result_rotr_12)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_rotr_16)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_rotr_20)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_rotr_24)));
  __ St_w(t4, MemOperand(a0, offsetof(T, result_rotr_28)));
  __ St_w(t5, MemOperand(a0, offsetof(T, result_rotr_32)));

  __ li(t5, 0);
  __ Rotr_w(a5, a4, t5);
  __ li(t5, 0x04);
  __ Rotr_w(a6, a4, t5);
  __ li(t5, 0x08);
  __ Rotr_w(a7, a4, t5);
  __ li(t5, 0x0C);
  __ Rotr_w(t0, a4, t5);
  __ li(t5, 0x10);
  __ Rotr_w(t1, a4, t5);
  __ li(t5, -0x0C);
  __ Rotr_w(t2, a4, t5);
  __ li(t5, -0x08);
  __ Rotr_w(t3, a4, t5);
  __ li(t5, -0x04);
  __ Rotr_w(t4, a4, t5);
  __ li(t5, 0x20);
  __ Rotr_w(t5, a4, t5);

  __ St_w(a5, MemOperand(a0, offsetof(T, result_rotri_0)));
  __ St_w(a6, MemOperand(a0, offsetof(T, result_rotri_4)));
  __ St_w(a7, MemOperand(a0, offsetof(T, result_rotri_8)));
  __ St_w(t0, MemOperand(a0, offsetof(T, result_rotri_12)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_rotri_16)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_rotri_20)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_rotri_24)));
  __ St_w(t4, MemOperand(a0, offsetof(T, result_rotri_28)));
  __ St_w(t5, MemOperand(a0, offsetof(T, result_rotri_32)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.input = 0x12345678;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotr_0);
  CHECK_EQ(static_cast<int32_t>(0x81234567), t.result_rotr_4);
  CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotr_8);
  CHECK_EQ(static_cast<int32_t>(0x67812345), t.result_rotr_12);
  CHECK_EQ(static_cast<int32_t>(0x56781234), t.result_rotr_16);
  CHECK_EQ(static_cast<int32_t>(0x45678123), t.result_rotr_20);
  CHECK_EQ(static_cast<int32_t>(0x34567812), t.result_rotr_24);
  CHECK_EQ(static_cast<int32_t>(0x23456781), t.result_rotr_28);
  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotr_32);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotri_0);
  CHECK_EQ(static_cast<int32_t>(0x81234567), t.result_rotri_4);
  CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotri_8);
  CHECK_EQ(static_cast<int32_t>(0x67812345), t.result_rotri_12);
  CHECK_EQ(static_cast<int32_t>(0x56781234), t.result_rotri_16);
  CHECK_EQ(static_cast<int32_t>(0x45678123), t.result_rotri_20);
  CHECK_EQ(static_cast<int32_t>(0x34567812), t.result_rotri_24);
  CHECK_EQ(static_cast<int32_t>(0x23456781), t.result_rotri_28);
  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotri_32);
}

TEST(Rotr_d) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct T {
    int64_t input;
    int64_t result_rotr_0;
    int64_t result_rotr_8;
    int64_t result_rotr_16;
    int64_t result_rotr_24;
    int64_t result_rotr_32;
    int64_t result_rotr_40;
    int64_t result_rotr_48;
    int64_t result_rotr_56;
    int64_t result_rotr_64;
    int64_t result_rotri_0;
    int64_t result_rotri_8;
    int64_t result_rotri_16;
    int64_t result_rotri_24;
    int64_t result_rotri_32;
    int64_t result_rotri_40;
    int64_t result_rotri_48;
    int64_t result_rotri_56;
    int64_t result_rotri_64;
  };
  T t;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, input)));

  __ Rotr_d(a5, a4, 0);
  __ Rotr_d(a6, a4, 0x08);
  __ Rotr_d(a7, a4, 0x10);
  __ Rotr_d(t0, a4, 0x18);
  __ Rotr_d(t1, a4, 0x20);
  __ Rotr_d(t2, a4, -0x18);
  __ Rotr_d(t3, a4, -0x10);
  __ Rotr_d(t4, a4, -0x08);
  __ Rotr_d(t5, a4, 0x40);
  __ St_d(a5, MemOperand(a0, offsetof(T, result_rotr_0)));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_rotr_8)));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_rotr_16)));
  __ St_d(t0, MemOperand(a0, offsetof(T, result_rotr_24)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_rotr_32)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_rotr_40)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_rotr_48)));
  __ St_d(t4, MemOperand(a0, offsetof(T, result_rotr_56)));
  __ St_d(t5, MemOperand(a0, offsetof(T, result_rotr_64)));

  __ li(t5, 0);
  __ Rotr_d(a5, a4, t5);
  __ li(t5, 0x08);
  __ Rotr_d(a6, a4, t5);
  __ li(t5, 0x10);
  __ Rotr_d(a7, a4, t5);
  __ li(t5, 0x18);
  __ Rotr_d(t0, a4, t5);
  __ li(t5, 0x20);
  __ Rotr_d(t1, a4, t5);
  __ li(t5, -0x18);
  __ Rotr_d(t2, a4, t5);
  __ li(t5, -0x10);
  __ Rotr_d(t3, a4, t5);
  __ li(t5, -0x08);
  __ Rotr_d(t4, a4, t5);
  __ li(t5, 0x40);
  __ Rotr_d(t5, a4, t5);

  __ St_d(a5, MemOperand(a0, offsetof(T, result_rotri_0)));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_rotri_8)));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_rotri_16)));
  __ St_d(t0, MemOperand(a0, offsetof(T, result_rotri_24)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_rotri_32)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_rotri_40)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_rotri_48)));
  __ St_d(t4, MemOperand(a0, offsetof(T, result_rotri_56)));
  __ St_d(t5, MemOperand(a0, offsetof(T, result_rotri_64)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.input = 0x0123456789ABCDEF;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x0123456789ABCDEF), t.result_rotr_0);
  CHECK_EQ(static_cast<int64_t>(0xEF0123456789ABCD), t.result_rotr_8);
  CHECK_EQ(static_cast<int64_t>(0xCDEF0123456789AB), t.result_rotr_16);
  CHECK_EQ(static_cast<int64_t>(0xABCDEF0123456789), t.result_rotr_24);
  CHECK_EQ(static_cast<int64_t>(0x89ABCDEF01234567), t.result_rotr_32);
  CHECK_EQ(static_cast<int64_t>(0x6789ABCDEF012345), t.result_rotr_40);
  CHECK_EQ(static_cast<int64_t>(0x456789ABCDEF0123), t.result_rotr_48);
  CHECK_EQ(static_cast<int64_t>(0x23456789ABCDEF01), t.result_rotr_56);
  CHECK_EQ(static_cast<int64_t>(0x0123456789ABCDEF), t.result_rotr_64);

  CHECK_EQ(static_cast<int64_t>(0x0123456789ABCDEF), t.result_rotri_0);
  CHECK_EQ(static_cast<int64_t>(0xEF0123456789ABCD), t.result_rotri_8);
  CHECK_EQ(static_cast<int64_t>(0xCDEF0123456789AB), t.result_rotri_16);
  CHECK_EQ(static_cast<int64_t>(0xABCDEF0123456789), t.result_rotri_24);
  CHECK_EQ(static_cast<int64_t>(0x89ABCDEF01234567), t.result_rotri_32);
  CHECK_EQ(static_cast<int64_t>(0x6789ABCDEF012345), t.result_rotri_40);
  CHECK_EQ(static_cast<int64_t>(0x456789ABCDEF0123), t.result_rotri_48);
  CHECK_EQ(static_cast<int64_t>(0x23456789ABCDEF01), t.result_rotri_56);
  CHECK_EQ(static_cast<int64_t>(0x0123456789ABCDEF), t.result_rotri_64);
}

TEST(macro_instructions4) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct T {
    double a;
    float b;
    double result_floor_a;
    float result_floor_b;
    double result_ceil_a;
    float result_ceil_b;
    double result_trunc_a;
    float result_trunc_b;
    double result_round_a;
    float result_round_b;
  };
  T t;

  const int kTableLength = 16;

  // clang-format off
  double inputs_d[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      1.7976931348623157E+308, 6.27463370218383111104242366943E-307,
      std::numeric_limits<double>::max() - 0.1,
      std::numeric_limits<double>::infinity()
  };
  float inputs_s[kTableLength] = {
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      1.7976931348623157E+38, 6.27463370218383111104242366943E-37,
      std::numeric_limits<float>::lowest() + 0.6,
      std::numeric_limits<float>::infinity()
      };
  float outputs_round_s[kTableLength] = {
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      1.7976931348623157E+38, 0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
      };
  double outputs_round_d[kTableLength] = {
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      1.7976931348623157E+308, 0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  float outputs_trunc_s[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      1.7976931348623157E+38, 0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_trunc_d[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      1.7976931348623157E+308, 0,
      std::numeric_limits<double>::max() - 1,
      std::numeric_limits<double>::infinity()
  };
  float outputs_ceil_s[kTableLength] = {
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      1.7976931348623157E38, 1,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_ceil_d[kTableLength] = {
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      1.7976931348623157E308, 1,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  float outputs_floor_s[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      1.7976931348623157E38, 0,
      std::numeric_limits<float>::lowest() + 1,
      std::numeric_limits<float>::infinity()
  };
  double outputs_floor_d[kTableLength] = {
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      1.7976931348623157E308, 0,
      std::numeric_limits<double>::max(),
      std::numeric_limits<double>::infinity()
  };
  // clang-format on

  __ Fld_d(f8, MemOperand(a0, offsetof(T, a)));
  __ Fld_s(f9, MemOperand(a0, offsetof(T, b)));
  __ Floor_d(f10, f8);
  __ Floor_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_floor_a)));
  __ Fst_s(f11, MemOperand(a0, offsetof(T, result_floor_b)));
  __ Ceil_d(f10, f8);
  __ Ceil_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_ceil_a)));
  __ Fst_s(f11, MemOperand(a0, offsetof(T, result_ceil_b)));
  __ Trunc_d(f10, f8);
  __ Trunc_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_trunc_a)));
  __ Fst_s(f11, MemOperand(a0, offsetof(T, result_trunc_b)));
  __ Round_d(f10, f8);
  __ Round_s(f11, f9);
  __ Fst_d(f10, MemOperand(a0, offsetof(T, result_round_a)));
  __ Fst_s(f11, MemOperand(a0, offsetof(T, result_round_b)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    t.a = inputs_d[i];
    t.b = inputs_s[i];
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(t.result_floor_a, outputs_floor_d[i]);
    CHECK_EQ(t.result_floor_b, outputs_floor_s[i]);
    CHECK_EQ(t.result_ceil_a, outputs_ceil_d[i]);
    CHECK_EQ(t.result_ceil_b, outputs_ceil_s[i]);
    CHECK_EQ(t.result_trunc_a, outputs_trunc_d[i]);
    CHECK_EQ(t.result_trunc_b, outputs_trunc_s[i]);
    CHECK_EQ(t.result_round_a, outputs_round_d[i]);
    CHECK_EQ(t.result_round_b, outputs_round_s[i]);
  }
}

uint64_t run_ExtractBits(uint64_t source, int pos, int size, bool sign_extend) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  if (sign_extend) {
    __ ExtractBits(t0, a0, a1, size, true);
  } else {
    __ ExtractBits(t0, a0, a1, size);
  }
  __ or_(a0, t0, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<FV>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(source, pos, 0, 0, 0));
  return res;
}

TEST(ExtractBits) {
  CcTest::InitializeVM();

  struct TestCase {
    uint64_t source;
    int pos;
    int size;
    bool sign_extend;
    uint64_t res;
  };

  // clang-format off
  struct TestCase tc[] = {
    //source,    pos, size, sign_extend,              res;
    {0x800,       4,    8,   false,                 0x80},
    {0x800,       4,    8,    true,   0xFFFFFFFFFFFFFF80},
    {0x800,       5,    8,    true,                 0x40},
    {0x40000,     3,   16,   false,               0x8000},
    {0x40000,     3,   16,    true,   0xFFFFFFFFFFFF8000},
    {0x40000,     4,   16,    true,               0x4000},
    {0x200000000, 2,   32,   false,           0x80000000},
    {0x200000000, 2,   32,    true,   0xFFFFFFFF80000000},
    {0x200000000, 3,   32,    true,           0x40000000},
  };
  // clang-format on
  size_t nr_test_cases = sizeof(tc) / sizeof(TestCase);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t result =
        run_ExtractBits(tc[i].source, tc[i].pos, tc[i].size, tc[i].sign_extend);
    CHECK_EQ(tc[i].res, result);
  }
}

uint64_t run_InsertBits(uint64_t dest, uint64_t source, int pos, int size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ InsertBits(a0, a1, a2, size);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<FV>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(dest, source, pos, 0, 0));
  return res;
}

TEST(InsertBits) {
  CcTest::InitializeVM();

  struct TestCase {
    uint64_t dest;
    uint64_t source;
    int pos;
    int size;
    uint64_t res;
  };

  // clang-format off
  struct TestCase tc[] = {
    //dest                   source,  pos, size,                 res;
    {0x11111111,            0x1234,   32,   16,      0x123411111111},
    {0x111111111111,       0xFFFFF,   24,   10,      0x1113FF111111},
    {0x1111111111111111,  0xFEDCBA,   16,    4,  0x11111111111A1111},
  };
  // clang-format on
  size_t nr_test_cases = sizeof(tc) / sizeof(TestCase);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t result =
        run_InsertBits(tc[i].dest, tc[i].source, tc[i].pos, tc[i].size);
    CHECK_EQ(tc[i].res, result);
  }
}

TEST(Popcnt) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct TestCase {
    uint32_t a;
    uint64_t b;
    int expected_a;
    int expected_b;
    int result_a;
    int result_b;
  };
  // clang-format off
  struct TestCase tc[] = {
    {  0x12345678,  0x1122334455667788,  13,  26, 0, 0},
    {      0x1234,            0x123456,   5,   9, 0, 0},
    {  0xFFF00000,  0xFFFF000000000000,  12,  16, 0, 0},
    {  0xFF000012,  0xFFFF000000001234,  10,  21, 0, 0}
  };
  // clang-format on

  __ Ld_w(t0, MemOperand(a0, offsetof(TestCase, a)));
  __ Ld_d(t1, MemOperand(a0, offsetof(TestCase, b)));
  __ Popcnt_w(t2, t0);
  __ Popcnt_d(t3, t1);
  __ St_w(t2, MemOperand(a0, offsetof(TestCase, result_a)));
  __ St_w(t3, MemOperand(a0, offsetof(TestCase, result_b)));
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCase);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    f.Call(&tc[i], 0, 0, 0, 0);
    CHECK_EQ(tc[i].expected_a, tc[i].result_a);
    CHECK_EQ(tc[i].expected_b, tc[i].result_b);
  }
}

TEST(DeoptExitSizeIsFixed) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      buffer->CreateView());
  static_assert(static_cast<int>(kFirstDeoptimizeKind) == 0);
  for (int i = 0; i < kDeoptimizeKindCount; i++) {
    DeoptimizeKind kind = static_cast<DeoptimizeKind>(i);
    Label before_exit;
    masm.bind(&before_exit);
    Builtin target = Deoptimizer::GetDeoptimizationEntry(kind);
    masm.CallForDeoptimization(target, 42, &before_exit, kind, &before_exit,
                               nullptr);
    CHECK_EQ(masm.SizeOfCodeGeneratedSince(&before_exit),
             kind == DeoptimizeKind::kLazy ? Deoptimizer::kLazyDeoptExitSize
                                           : Deoptimizer::kEagerDeoptExitSize);
  }
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```