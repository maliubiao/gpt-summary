Response: The user wants to understand the functionality of the C++ code provided, specifically the fourth part of a seven-part file.

The code seems to be testing assembler instructions for the MIPS64 architecture within the V8 JavaScript engine. It defines several `TEST` functions, each focusing on a specific assembler instruction or a group of related instructions.

Each `TEST` function typically follows these steps:
1. Initializes the V8 virtual machine.
2. Defines a helper function (`run_...`) that assembles a short code snippet using the instruction under test.
3. The helper function executes the generated code.
4. The `TEST` function then calls the helper function with various inputs and asserts that the output matches the expected result.

The code also includes tests for MSA (MIPS SIMD Architecture) instructions.

To illustrate the connection with JavaScript, I need to find an example of how one of these MIPS64 instructions could be used in the implementation of a JavaScript feature. A good candidate would be arithmetic operations or bitwise manipulations.
这是 `v8/test/cctest/test-assembler-mips64.cc` 文件的第 4 部分，它主要专注于测试 MIPS64 架构的汇编器功能，特别是以下几个方面：

1. **算术运算指令的宏指令测试**:
   - `Subu`: 测试无符号减法宏指令，并针对小立即数和大立即数的情况，验证生成的指令序列是否符合预期。
   - `Dsubu`: 测试双字无符号减法宏指令，同样针对不同的立即数值进行测试。

2. **位操作指令测试**:
   - `Dins`: 测试双字插入位字段宏指令。它将一个源寄存器中的一部分位插入到目标寄存器的指定位置。
   - `Ins`: 测试字插入位字段宏指令。
   - `Ext`: 测试位字段提取宏指令。它从源寄存器中提取指定位置和大小的位字段。

3. **MSA (MIPS SIMD 架构) 指令测试**:
   - `MSA_fill_copy`, `MSA_fill_copy_2`, `MSA_fill_copy_3`: 测试 MSA 寄存器的填充和复制指令，包括字节、半字、字和双字的填充，以及与 FPU 寄存器的交互。
   - `MSA_insert`: 测试 MSA 向量元素的插入指令，可以插入字节、半字、字和双字。
   - `MSA_move_v`: 测试 MSA 向量寄存器之间的移动指令。
   - `MSA_sldi`: 测试 MSA 向量寄存器的逻辑左移指令，可以按字节、半字、字和双字进行移位。
   - `MSA_cfc_ctc`: 测试访问 MSA 控制寄存器的指令 (`cfcmsa`, `ctcmsa`)。
   - `MSA_andi_ori_nori_xori`: 测试 MSA 向量与立即数的逻辑运算指令。
   - `MSA_bmnzi_bmzi_bseli`: 测试 MSA 向量的位选择指令。
   - `MSA_shf`: 测试 MSA 向量的 shuffle 指令，可以按字节、半字和字进行 shuffle。
   - `MSA_addvi_subvi`: 测试 MSA 向量与立即数的加减指令。
   - `MSA_maxi_mini`: 测试 MSA 向量与立即数的最大值和最小值指令。
   - `MSA_ceqi_clti_clei`: 测试 MSA 向量与立即数的比较指令（等于、小于、小于等于）。
   - `MSA_pcnt`: 测试 MSA 向量的位计数指令。
   - `MSA_nlzc`: 测试 MSA 向量的前导零计数指令。
   - `MSA_nloc`: 测试 MSA 向量的前导一计数指令。
   - `MSA_fclass`: 测试 MSA 向量的浮点数分类指令。
   - `MSA_ftrunc_s`: 测试 MSA 向量的浮点数截断为整数指令。

**与 JavaScript 的关系及示例**

这些底层的汇编指令是 JavaScript 引擎执行的基础。当 JavaScript 代码被编译或解释执行时，引擎会将高级的 JavaScript 操作转换为底层的机器指令。

例如，考虑 JavaScript 中的减法操作：

```javascript
let a = 10;
let b = 5;
let result = a - b;
```

在 MIPS64 架构下，V8 引擎可能会使用 `subu` 或 `dsubu` 指令来执行这个减法操作。

再比如，JavaScript 中进行位操作时：

```javascript
let x = 0b1010; // 二进制 10
let y = 0b0011; // 二进制 3
let z = x | y;  // 位或运算
```

V8 可能会使用类似 `ori` (用于寄存器或立即数的或运算) 的指令来实现这个位或操作。

对于 MSA 指令，它们通常用于优化 JavaScript 中涉及大量数据并行处理的操作，例如：

```javascript
// 假设有一个 Typed Array
let array1 = new Float32Array([1.0, 2.0, 3.0, 4.0]);
let array2 = new Float32Array([5.0, 6.0, 7.0, 8.0]);
let result = new Float32Array(4);

for (let i = 0; i < array1.length; i++) {
  result[i] = array1[i] + array2[i];
}
```

在这种情况下，V8 引擎在支持 MSA 的 MIPS64 架构上，可能会使用 MSA 的向量加法指令（虽然这个文件中没有直接测试加法指令，但存在其他 MSA 指令的测试，表明引擎在利用 MSA 功能），一次性处理多个浮点数的加法，从而提高性能。

总结来说，这个代码文件是 V8 引擎中用于测试其 MIPS64 汇编器后端正确性的重要组成部分。它确保了生成的机器码能够按照预期的方式工作，从而保证了 JavaScript 代码在 MIPS64 架构上的正确执行和性能。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```
num_instr);
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

TEST(Subu) {
  CcTest::InitializeVM();

  // Test Subu macro-instruction for min_int16 and max_int16 border cases.
  // For subtracting int16 immediate values we use addiu.

  struct TestCaseSubu {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Subu(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSubu tc[] = {
      //              imm, expected_res, num_instr
      {0xFFFFFFFFFFFF8000,       0x8000,         2},  // min_int16
      // The test case above generates ori + addu instruction sequence.
      // We can't have just addiu because -min_int16 > max_int16 so use
      // register. We can load min_int16 to at register with addiu and then
      // subtract at with subu, but now we use ori + addu because -min_int16 can
      // be loaded using ori.
      {0x8000,       0xFFFFFFFFFFFF8000,         1},  // max_int16 + 1
      // Generates addiu
      // max_int16 + 1 is not int16 but -(max_int16 + 1) is, just use addiu.
      {0xFFFFFFFFFFFF7FFF,       0x8001,         2},  // min_int16 - 1
      // Generates ori + addu
      // To load this value to at we need two instructions and another one to
      // subtract, lui + ori + subu. But we can load -value to at using just
      // ori and then add at register with addu.
      {0x8001,       0xFFFFFFFFFFFF7FFF,         2},  // max_int16 + 2
      // Generates ori + subu
      // Not int16 but is uint16, load value to at with ori and subtract with
      // subu.
      {0x00010000,   0xFFFFFFFFFFFF0000,         2},
      // Generates lui + subu
      // Load value using lui to at and subtract with subu.
      {0x00010001,   0xFFFFFFFFFFFEFFFF,         3},
      // Generates lui + ori + subu
      // We have to generate three instructions in this case.
      {0x7FFFFFFF,   0xFFFFFFFF80000001,         3},  // max_int32
      // Generates lui + ori + subu
      {0xFFFFFFFF80000000, 0xFFFFFFFF80000000,   2},  // min_int32
      // The test case above generates lui + subu intruction sequence.
      // The result of 0 - min_int32 eqauls max_int32 + 1, which wraps around to
      // min_int32 again.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseSubu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Subu(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Dsubu(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label code_start;
  __ bind(&code_start);
  __ Dsubu(v0, zero_reg, Operand(imm));
  CHECK_EQ(assm.InstructionsGeneratedSince(&code_start), num_instr);
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

TEST(Dsubu) {
  CcTest::InitializeVM();

  // Test Dsubu macro-instruction for min_int16 and max_int16 border cases.
  // For subtracting int16 immediate values we use daddiu.

  struct TestCaseDsubu {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Dsubu(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseDsubu tc[] = {
      //        imm, expected_res, num_instr
      {0xFFFFFFFFFFFF8000, 0x8000, 2},  // min_int16
      // The test case above generates daddiu + dsubu instruction sequence.
      // We can't have just daddiu because -min_int16 > max_int16 so use
      // register, but we can load min_int16 to at register with daddiu and then
      // subtract at with dsubu.
      {0x8000, 0xFFFFFFFFFFFF8000, 1},  // max_int16 + 1
      // Generates daddiu
      // max_int16 + 1 is not int16 but -(max_int16 + 1) is, just use daddiu.
      {0xFFFFFFFFFFFF7FFF, 0x8001, 2},  // min_int16 - 1
      // Generates ori + daddu
      // To load this value to at we need two instructions and another one to
      // subtract, lui + ori + dsubu. But we can load -value to at using just
      // ori and then dadd at register with daddu.
      {0x8001, 0xFFFFFFFFFFFF7FFF, 2},  // max_int16 + 2
      // Generates ori + dsubu
      // Not int16 but is uint16, load value to at with ori and subtract with
      // dsubu.
      {0x00010000, 0xFFFFFFFFFFFF0000, 2},
      // Generates lui + dsubu
      // Load value using lui to at and subtract with dsubu.
      {0x00010001, 0xFFFFFFFFFFFEFFFF, 3},
      // Generates lui + ori + dsubu
      // We have to generate three instructions in this case.
      {0x7FFFFFFF, 0xFFFFFFFF80000001, 3},  // max_int32
      // Generates lui + ori + dsubu
      {0xFFFFFFFF80000000, 0x0000000080000000, 2},  // min_int32
      // Generates lui + dsubu
      // The result of 0 - min_int32 eqauls max_int32 + 1, which fits into a 64
      // bit register, Dsubu gives a different result here.
      {0x7FFFFFFFFFFFFFFF, 0x8000000000000001, 3},  // max_int64
      // r2 - Generates daddiu + dsrl + dsubu
      // r6 - Generates daddiu + dati + dsubu
      {0x8000000000000000, 0x8000000000000000, 3},  // min_int64
      // The test case above generates:
      // r2 - daddiu + dsll32 + dsubu instruction sequence,
      // r6 - ori + dati + dsubu.
      // The result of 0 - min_int64 eqauls max_int64 + 1, which wraps around to
      // min_int64 again.
      {0xFFFF0000FFFFFFFF, 0x0000FFFF00000001, 4},
      // The test case above generates:
      // r2 - ori + dsll32 + ori + daddu instruction sequence,
      // r6 - daddiu + dahi + dati + dsubu.
      // For r2 loading imm would take more instructions than loading -imm so we
      // can load -imm and add with daddu.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDsubu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Dsubu(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Dins(uint64_t imm, uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, imm);
  __ li(t0, source);
  __ Dins(v0, t0, pos, size);
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

TEST(Dins) {
  CcTest::InitializeVM();

  // Test Dins macro-instruction.

  struct TestCaseDins {
    uint64_t imm;
    uint64_t source;
    uint16_t pos;
    uint16_t size;
    uint64_t expected_res;
  };

  // We load imm to v0 and source to t0 and then call
  // Dins(v0, t0, pos, size) to test cases listed below.
  // clang-format off
  struct TestCaseDins tc[] = {
      // imm, source, pos, size, expected_res
      {0x5555555555555555, 0x1ABCDEF01, 31, 1, 0x55555555D5555555},
      {0x5555555555555555, 0x1ABCDEF02, 30, 2, 0x5555555595555555},
      {0x201234567, 0x1FABCDEFF, 0, 32, 0x2FABCDEFF},
      {0x201234567, 0x7FABCDEFF, 31, 2, 0x381234567},
      {0x800000000, 0x7FABCDEFF, 0, 33, 0x9FABCDEFF},
      {0x1234, 0xABCDABCDABCDABCD, 0, 64, 0xABCDABCDABCDABCD},
      {0xABCD, 0xABCEABCF, 32, 1, 0x10000ABCD},
      {0xABCD, 0xABCEABCF, 63, 1, 0x800000000000ABCD},
      {0x10000ABCD, 0xABC1ABC2ABC3ABC4, 32, 32, 0xABC3ABC40000ABCD},
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseDins);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res,
             run_Dins(tc[i].imm, tc[i].source, tc[i].pos, tc[i].size));
  }
}

uint64_t run_Ins(uint64_t imm, uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, imm);
  __ li(t0, source);
  __ Ins(v0, t0, pos, size);
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

TEST(Ins) {
  CcTest::InitializeVM();

  //       run_Ins(rt_value, rs_value, pos, size),
  //       expected_result
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFFABCDEF01, 31, 1),
           0xFFFFFFFFD5555555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFFABCDEF02, 30, 2),
           0xFFFFFFFF95555555);
  CHECK_EQ(run_Ins(0x0000000001234567, 0xFFFFFFFFFABCDEFF, 0, 32),
           0xFFFFFFFFFABCDEFF);

  // Results with positive sign.
  CHECK_EQ(run_Ins(0x0000000055555550, 0xFFFFFFFF80000001, 0, 1),
           0x0000000055555551);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000040000001, 0, 32),
           0x0000000040000001);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000020000001, 1, 31),
           0x0000000040000003);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80700001, 8, 24),
           0x0000000070000155);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80007001, 16, 16),
           0x0000000070015555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000071, 24, 8),
           0x0000000071555555);
  CHECK_EQ(run_Ins(0x0000000075555555, 0x0000000040000000, 31, 1),
           0x0000000075555555);

  // Results with negative sign.
  CHECK_EQ(run_Ins(0xFFFFFFFF85555550, 0xFFFFFFFF80000001, 0, 1),
           0xFFFFFFFF85555551);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000001, 0, 32),
           0xFFFFFFFF80000001);
  CHECK_EQ(run_Ins(0x0000000055555555, 0x0000000040000001, 1, 31),
           0xFFFFFFFF80000003);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80800001, 8, 24),
           0xFFFFFFFF80000155);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80008001, 16, 16),
           0xFFFFFFFF80015555);
  CHECK_EQ(run_Ins(0x0000000055555555, 0xFFFFFFFF80000081, 24, 8),
           0xFFFFFFFF81555555);
  CHECK_EQ(run_Ins(0x0000000075555555, 0x0000000000000001, 31, 1),
           0xFFFFFFFFF5555555);
}

uint64_t run_Ext(uint64_t source, uint16_t pos, uint16_t size) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ li(v0, 0xFFFFFFFFFFFFFFFF);
  __ li(t0, source);
  __ Ext(v0, t0, pos, size);
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

TEST(Ext) {
  CcTest::InitializeVM();

  // Source values with negative sign.
  //       run_Ext(rs_value, pos, size), expected_result
  CHECK_EQ(run_Ext(0xFFFFFFFF80000001, 0, 1), 0x0000000000000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000001, 0, 32), 0xFFFFFFFF80000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000002, 1, 31), 0x0000000040000001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000100, 8, 24), 0x0000000000800001);
  CHECK_EQ(run_Ext(0xFFFFFFFF80010000, 16, 16), 0x0000000000008001);
  CHECK_EQ(run_Ext(0xFFFFFFFF81000000, 24, 8), 0x0000000000000081);
  CHECK_EQ(run_Ext(0xFFFFFFFF80000000, 31, 1), 0x0000000000000001);

  // Source values with positive sign.
  CHECK_EQ(run_Ext(0x0000000000000001, 0, 1), 0x0000000000000001);
  CHECK_EQ(run_Ext(0x0000000040000001, 0, 32), 0x0000000040000001);
  CHECK_EQ(run_Ext(0x0000000040000002, 1, 31), 0x0000000020000001);
  CHECK_EQ(run_Ext(0x0000000040000100, 8, 24), 0x0000000000400001);
  CHECK_EQ(run_Ext(0x0000000040010000, 16, 16), 0x0000000000004001);
  CHECK_EQ(run_Ext(0x0000000041000000, 24, 8), 0x0000000000000041);
  CHECK_EQ(run_Ext(0x0000000040000000, 31, 1), 0x0000000000000000);
}

TEST(MSA_fill_copy) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t u8;
    uint64_t u16;
    uint64_t u32;
    uint64_t s8;
    uint64_t s16;
    uint64_t s32;
    uint64_t s64;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0x9E7689ACA512B683);

    __ fill_b(w0, t0);
    __ fill_h(w2, t0);
    __ fill_w(w4, t0);
    __ fill_d(w6, t0);
    __ copy_u_b(t1, w0, 11);
    __ sd(t1, MemOperand(a0, offsetof(T, u8)));
    __ copy_u_h(t1, w2, 6);
    __ sd(t1, MemOperand(a0, offsetof(T, u16)));
    __ copy_u_w(t1, w4, 3);
    __ sd(t1, MemOperand(a0, offsetof(T, u32)));

    __ copy_s_b(t1, w0, 8);
    __ sd(t1, MemOperand(a0, offsetof(T, s8)));
    __ copy_s_h(t1, w2, 5);
    __ sd(t1, MemOperand(a0, offsetof(T, s16)));
    __ copy_s_w(t1, w4, 1);
    __ sd(t1, MemOperand(a0, offsetof(T, s32)));
    __ copy_s_d(t1, w6, 0);
    __ sd(t1, MemOperand(a0, offsetof(T, s64)));

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(0x83u, t.u8);
  CHECK_EQ(0xB683u, t.u16);
  CHECK_EQ(0xA512B683u, t.u32);
  CHECK_EQ(0xFFFFFFFFFFFFFF83u, t.s8);
  CHECK_EQ(0xFFFFFFFFFFFFB683u, t.s16);
  CHECK_EQ(0xFFFFFFFFA512B683u, t.s32);
  CHECK_EQ(0x9E7689ACA512B683u, t.s64);
}

TEST(MSA_fill_copy_2) {
  // Similar to MSA_fill_copy test, but also check overlaping between MSA and
  // FPU registers with same numbers
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t d0;
    uint64_t d1;
  };
  T t[2];

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0xAAAAAAAAAAAAAAAA);
    __ li(t1, 0x5555555555555555);

    __ fill_d(w0, t0);
    __ fill_d(w2, t0);

    __ Move(f0, t1);
    __ Move(f2, t1);

#define STORE_MSA_REG(w_reg, base, scratch)          \
  __ copy_s_d(scratch, w_reg, 0);                    \
  __ sd(scratch, MemOperand(base, offsetof(T, d0))); \
  __ copy_s_d(scratch, w_reg, 1);                    \
  __ sd(scratch, MemOperand(base, offsetof(T, d1)));

    STORE_MSA_REG(w0, a0, t2)
    STORE_MSA_REG(w2, a1, t2)
#undef STORE_MSA_REG

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F5>::FromCode(isolate, *code);

  f.Call(&t[0], &t[1], 0, 0, 0);

  CHECK_EQ(0x5555555555555555, t[0].d0);
  CHECK_EQ(0xAAAAAAAAAAAAAAAA, t[0].d1);
  CHECK_EQ(0x5555555555555555, t[1].d0);
  CHECK_EQ(0xAAAAAAAAAAAAAAAA, t[1].d1);
}

TEST(MSA_fill_copy_3) {
  // Similar to MSA_fill_copy test, but also check overlaping between MSA and
  // FPU registers with same numbers
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t d0;
    uint64_t d1;
  };
  T t[2];

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  {
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    __ li(t0, 0xAAAAAAAAAAAAAAAA);
    __ li(t1, 0x5555555555555555);

    __ Move(f0, t0);
    __ Move(f2, t0);

    __ fill_d(w0, t1);
    __ fill_d(w2, t1);

    __ Sdc1(f0, MemOperand(a0, offsetof(T, d0)));
    __ Sdc1(f2, MemOperand(a1, offsetof(T, d0)));

    __ jr(ra);
    __ nop();
  }

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F5>::FromCode(isolate, *code);

  f.Call(&t[0], &t[1], 0, 0, 0);

  CHECK_EQ(0x5555555555555555, t[0].d0);
  CHECK_EQ(0x5555555555555555, t[1].d0);
}


template <typename T>
void run_msa_insert(int64_t rs_value, int n, msa_reg_t* w) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  __ li(t0, -1);
  __ li(t1, rs_value);
  __ fill_w(w0, t0);

  if (std::is_same<T, int8_t>::value) {
    DCHECK_LT(n, 16);
    __ insert_b(w0, n, t1);
  } else if (std::is_same<T, int16_t>::value) {
    DCHECK_LT(n, 8);
    __ insert_h(w0, n, t1);
  } else if (std::is_same<T, int32_t>::value) {
    DCHECK_LT(n, 4);
    __ insert_w(w0, n, t1);
  } else if (std::is_same<T, int64_t>::value) {
    DCHECK_LT(n, 2);
    __ insert_d(w0, n, t1);
  } else {
    UNREACHABLE();
  }

  store_elements_of_vector(&assm, w0, a0);

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

  f.Call(w, 0, 0, 0, 0);
}

TEST(MSA_insert) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseInsert {
    uint64_t input;
    int n;
    uint64_t exp_res_lo;
    uint64_t exp_res_hi;
  };

  // clang-format off
  struct TestCaseInsert tc_b[] = {
    // input, n,          exp_res_lo,          exp_res_hi
    {  0xA2, 13, 0xFFFFFFFFFFFFFFFFu, 0xFFFFA2FFFFFFFFFFu},
    {  0x73, 10, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFF73FFFFu},
    {0x3494,  5, 0xFFFF94FFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu},
    {0xA6B8,  1, 0xFFFFFFFFFFFFB8FFu, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format off

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int8_t>(tc_b[i].input, tc_b[i].n, &res);
    CHECK_EQ(tc_b[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_b[i].exp_res_hi, res.d[1]);
  }

  // clang-format off
  struct TestCaseInsert tc_h[] = {
    // input, n,          exp_res_lo,          exp_res_hi
    {0x85A2,  7, 0xFFFFFFFFFFFFFFFFu, 0x85A2FFFFFFFFFFFFu},
    {0xE873,  5, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFE873FFFFu},
    {0x3494,  3, 0x3494FFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu},
    {0xA6B8,  1, 0xFFFFFFFFA6B8FFFFu, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc_h) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int16_t>(tc_h[i].input, tc_h[i].n, &res);
    CHECK_EQ(tc_h[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_h[i].exp_res_hi, res.d[1]);
  }

  // clang-format off
  struct TestCaseInsert tc_w[] = {
    //     input, n,          exp_res_lo,          exp_res_hi
    {0xD2F085A2u, 3, 0xFFFFFFFFFFFFFFFFu, 0xD2F085A2FFFFFFFFu},
    {0x4567E873u, 2, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFF4567E873u},
    {0xACDB3494u, 1, 0xACDB3494FFFFFFFFu, 0xFFFFFFFFFFFFFFFFu},
    {0x89ABA6B8u, 0, 0xFFFFFFFF89ABA6B8u, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc_w) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int32_t>(tc_w[i].input, tc_w[i].n, &res);
    CHECK_EQ(tc_w[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_w[i].exp_res_hi, res.d[1]);
  }

  // clang-format off
  struct TestCaseInsert tc_d[] = {
    //            input, n,          exp_res_lo,          exp_res_hi
    {0xF35862E13E38F8B0, 1, 0xFFFFFFFFFFFFFFFFu, 0xF35862E13E38F8B0},
    {0x4F41FFDEF2BFE636, 0,  0x4F41FFDEF2BFE636, 0xFFFFFFFFFFFFFFFFu}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseInsert); ++i) {
    msa_reg_t res;
    run_msa_insert<int64_t>(tc_d[i].input, tc_d[i].n, &res);
    CHECK_EQ(tc_d[i].exp_res_lo, res.d[0]);
    CHECK_EQ(tc_d[i].exp_res_hi, res.d[1]);
  }
}

void run_msa_ctc_cfc(uint64_t value) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);

  MSAControlRegister msareg = {kMSACSRRegister};
  __ li(t0, value);
  __ li(t2, 0l);
  __ cfcmsa(t1, msareg);
  __ ctcmsa(msareg, t0);
  __ cfcmsa(t2, msareg);
  __ ctcmsa(msareg, t1);
  __ sd(t2, MemOperand(a0, 0));
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

  uint64_t res;
  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(
      base::bit_cast<uint64_t>(static_cast<int64_t>(
          base::bit_cast<int32_t>(static_cast<uint32_t>(value & 0x0167FFFF)))),
      res);
}

TEST(MSA_move_v) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t[] = {{0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x1E86678B52F8E1FF,
            0x706E51290AC76FB9},
           {0x4414AED7883FFD18, 0x047D183A06B67016, 0x4EF258CF8D822870,
            0x2686B73484C2E843},
           {0xD38FF9D048884FFC, 0x6DC63A57C0943CA7, 0x8520CA2F3E97C426,
            0xA9913868FB819C59}};

  for (unsigned i = 0; i < arraysize(t); ++i) {
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    CpuFeatureScope fscope(&assm, MIPS_SIMD);

    load_elements_of_vector(&assm, &t[i].ws_lo, w0, t0, t1);
    load_elements_of_vector(&assm, &t[i].wd_lo, w2, t0, t1);
    __ move_v(w2, w0);
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
    f.Call(&t[i].wd_lo, 0, 0, 0, 0);
    CHECK_EQ(t[i].ws_lo, t[i].wd_lo);
    CHECK_EQ(t[i].ws_hi, t[i].wd_hi);
  }
}

template <typename ExpectFunc, typename OperFunc>
void run_msa_sldi(OperFunc GenerateOperation,
                  ExpectFunc GenerateExpectedResult) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t ws_lo;
    uint64_t ws_hi;
    uint64_t wd_lo;
    uint64_t wd_hi;
  };
  T t[] = {{0x20B9CC4F1A83E0C5, 0xA27E1B5F2F5BB18A, 0x1E86678B52F8E1FF,
            0x706E51290AC76FB9},
           {0x4414AED7883FFD18, 0x047D183A06B67016, 0x4EF258CF8D822870,
            0x2686B73484C2E843},
           {0xD38FF9D048884FFC, 0x6DC63A57C0943CA7, 0x8520CA2F3E97C426,
            0xA9913868FB819C59}};
  uint64_t res[2];

  for (unsigned i = 0; i < arraysize(t); ++i) {
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    CpuFeatureScope fscope(&assm, MIPS_SIMD);
    load_elements_of_vector(&assm, &t[i].ws_lo, w0, t0, t1);
    load_elements_of_vector(&assm, &t[i].wd_lo, w2, t0, t1);
    GenerateOperation(assm);
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
    f.Call(&res[0], 0, 0, 0, 0);
    GenerateExpectedResult(reinterpret_cast<uint8_t*>(&t[i].ws_lo),
                           reinterpret_cast<uint8_t*>(&t[i].wd_lo));
    CHECK_EQ(res[0], t[i].wd_lo);
    CHECK_EQ(res[1], t[i].wd_hi);
  }
}

TEST(MSA_sldi) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;
  CcTest::InitializeVM();

#define SLDI_DF(s, k)                \
  uint8_t v[32];                     \
  for (unsigned i = 0; i < s; i++) { \
    v[i] = ws[s * k + i];            \
    v[i + s] = wd[s * k + i];        \
  }                                  \
  for (unsigned i = 0; i < s; i++) { \
    wd[s * k + i] = v[i + n];        \
  }

  for (int n = 0; n < 16; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_b(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   SLDI_DF(kMSARegSize / sizeof(int8_t) / kBitsPerByte, 0)
                 });
  }

  for (int n = 0; n < 8; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_h(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   for (int k = 0; k < 2; ++k) {
                     SLDI_DF(kMSARegSize / sizeof(int16_t) / kBitsPerByte, k)
                   }
                 });
  }

  for (int n = 0; n < 4; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_w(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   for (int k = 0; k < 4; ++k) {
                     SLDI_DF(kMSARegSize / sizeof(int32_t) / kBitsPerByte, k)
                   }
                 });
  }

  for (int n = 0; n < 2; ++n) {
    run_msa_sldi([n](MacroAssembler& assm) { __ sldi_d(w2, w0, n); },
                 [n](uint8_t* ws, uint8_t* wd) {
                   for (int k = 0; k < 8; ++k) {
                     SLDI_DF(kMSARegSize / sizeof(int64_t) / kBitsPerByte, k)
                   }
                 });
  }
#undef SLDI_DF
}

TEST(MSA_cfc_ctc) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const uint64_t mask_without_cause = 0xFFFFFFFFFF9C0FFF;
  const uint64_t mask_always_zero = 0x0167FFFF;
  const uint64_t mask_enables = 0x0000000000000F80;
  uint64_t test_case[] = {0x30C6F6352D5EDE31, 0xEFC9FED507955425,
                          0x64F2A3FF15B7DBE3, 0x6AA069352BF8BC37,
                          0x7EA7AB2AE6AAE923, 0xA10F5D4C24D0F68D,
                          0x6DD14C9441AFA84C, 0xC366373B2D6BF64F,
                          0x6B35FB04925014BD, 0x9E3EA39A4DBA7E61};
  for (unsigned i = 0; i < arraysize(test_case); i++) {
    // Setting enable bits and corresponding cause bits could result in
    // exception raised and this prevents that from happening
    test_case[i] = (~test_case[i] & mask_enables) << 5 |
                   (test_case[i] & mask_without_cause);
    run_msa_ctc_cfc(test_case[i] & mask_always_zero);
  }
}

struct ExpResShf {
  uint8_t i8;
  uint64_t lo;
  uint64_t hi;
};

void run_msa_i8(SecondaryField opcode, uint64_t ws_lo, uint64_t ws_hi,
                uint8_t i8) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;
  uint64_t wd_lo = 0xF35862E13E38F8B0;
  uint64_t wd_hi = 0x4F41FFDEF2BFE636;

#define LOAD_W_REG(lo, hi, w_reg) \
  __ li(t0, lo);                  \
  __ li(t1, hi);                  \
  __ insert_d(w_reg, 0, t0);      \
  __ insert_d(w_reg, 1, t1);

  LOAD_W_REG(ws_lo, ws_hi, w0)

  switch (opcode) {
    case ANDI_B:
      __ andi_b(w2, w0, i8);
      break;
    case ORI_B:
      __ ori_b(w2, w0, i8);
      break;
    case NORI_B:
      __ nori_b(w2, w0, i8);
      break;
    case XORI_B:
      __ xori_b(w2, w0, i8);
      break;
    case BMNZI_B:
      LOAD_W_REG(wd_lo, wd_hi, w2);
      __ bmnzi_b(w2, w0, i8);
      break;
    case BMZI_B:
      LOAD_W_REG(wd_lo, wd_hi, w2);
      __ bmzi_b(w2, w0, i8);
      break;
    case BSELI_B:
      LOAD_W_REG(wd_lo, wd_hi, w2);
      __ bseli_b(w2, w0, i8);
      break;
    case SHF_B:
      __ shf_b(w2, w0, i8);
      break;
    case SHF_H:
      __ shf_h(w2, w0, i8);
      break;
    case SHF_W:
      __ shf_w(w2, w0, i8);
      break;
    default:
      UNREACHABLE();
  }

  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

#undef LOAD_W_REG

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  uint64_t mask = i8 * 0x0101010101010101ull;
  switch (opcode) {
    case ANDI_B:
      CHECK_EQ(ws_lo & mask, res.d[0]);
      CHECK_EQ(ws_hi & mask, res.d[1]);
      break;
    case ORI_B:
      CHECK_EQ(ws_lo | mask, res.d[0]);
      CHECK_EQ(ws_hi | mask, res.d[1]);
      break;
    case NORI_B:
      CHECK_EQ(~(ws_lo | mask), res.d[0]);
      CHECK_EQ(~(ws_hi | mask), res.d[1]);
      break;
    case XORI_B:
      CHECK_EQ(ws_lo ^ mask, res.d[0]);
      CHECK_EQ(ws_hi ^ mask, res.d[1]);
      break;
    case BMNZI_B:
      CHECK_EQ((ws_lo & mask) | (wd_lo & ~mask), res.d[0]);
      CHECK_EQ((ws_hi & mask) | (wd_hi & ~mask), res.d[1]);
      break;
    case BMZI_B:
      CHECK_EQ((ws_lo & ~mask) | (wd_lo & mask), res.d[0]);
      CHECK_EQ((ws_hi & ~mask) | (wd_hi & mask), res.d[1]);
      break;
    case BSELI_B:
      CHECK_EQ((ws_lo & ~wd_lo) | (mask & wd_lo), res.d[0]);
      CHECK_EQ((ws_hi & ~wd_hi) | (mask & wd_hi), res.d[1]);
      break;
    case SHF_B: {
      struct ExpResShf exp_b[] = {
          //  i8,             exp_lo,             exp_hi
          {0xFFu, 0x11111111B9B9B9B9, 0xF7F7F7F7C8C8C8C8},
          {0x0u, 0x62626262DFDFDFDF, 0xD6D6D6D6C8C8C8C8},
          {0xE4u, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636},
          {0x1Bu, 0x1B756911C3D9A7B9, 0xAE94A5F79C8AEFC8},
          {0xB1u, 0x662B6253E8C4DF12, 0x0D3AD6803F8BC88B},
          {0x4Eu, 0x62E1F358F8B03E38, 0xFFDE4F41E636F2BF},
          {0x27u, 0x1B697511C3A7D9B9, 0xAEA594F79CEF8AC8}};
      for (size_t i = 0; i < sizeof(exp_b) / sizeof(ExpResShf); ++i) {
        if (exp_b[i].i8 == i8) {
          CHECK_EQ(exp_b[i].lo, res.d[0]);
          CHECK_EQ(exp_b[i].hi, res.d[1]);
        }
      }
    } break;
    case SHF_H: {
      struct ExpResShf exp_h[] = {
          //  i8,             exp_lo,             exp_hi
          {0xFFu, 0x1169116911691169, 0xF7A5F7A5F7A5F7A5},
          {0x0u, 0x12DF12DF12DF12DF, 0x8BC88BC88BC88BC8},
          {0xE4u, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636},
          {0x1Bu, 0xD9C3B9A7751B1169, 0x8A9CC8EF94AEF7A5},
          {0xB1u, 0x53622B6612DFC4E8, 0x80D63A0D8BC88B3F},
          {0x4Eu, 0x3E38F8B0F35862E1, 0xF2BFE6364F41FFDE},
          {0x27u, 0xD9C3751BB9A71169, 0x8A9C94AEC8EFF7A5}};
      for (size_t i = 0; i < sizeof(exp_h) / sizeof(ExpResShf); ++i) {
        if (exp_h[i].i8 == i8) {
          CHECK_EQ(exp_h[i].lo, res.d[0]);
          CHECK_EQ(exp_h[i].hi, res.d[1]);
        }
      }
    } break;
    case SHF_W: {
      struct ExpResShf exp_w[] = {
          //  i8,             exp_lo,             exp_hi
          {0xFFu, 0xF7A594AEF7A594AE, 0xF7A594AEF7A594AE},
          {0x0u, 0xC4E812DFC4E812DF, 0xC4E812DFC4E812DF},
          {0xE4u, 0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636},
          {0x1Bu, 0xC8EF8A9CF7A594AE, 0xB9A7D9C31169751B},
          {0xB1u, 0xC4E812DF2B665362, 0x8B3F8BC83A0D80D6},
          {0x4Eu, 0x4F41FFDEF2BFE636, 0xF35862E13E38F8B0},
          {0x27u, 0x1169751BF7A594AE, 0xB9A7D9C3C8EF8A9C}};
      for (size_t i = 0; i < sizeof(exp_w) / sizeof(ExpResShf); ++i) {
        if (exp_w[i].i8 == i8) {
          CHECK_EQ(exp_w[i].lo, res.d[0]);
          CHECK_EQ(exp_w[i].hi, res.d[1]);
        }
      }
    } break;
    default:
      UNREACHABLE();
  }
}

struct TestCaseMsaI8 {
  uint64_t input_lo;
  uint64_t input_hi;
  uint8_t i8;
};

TEST(MSA_andi_ori_nori_xori) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI8 tc[] = {
    //         input_lo,           input_hi,    i8
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0xFFu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0u},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x3Bu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0xD9u}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI8); ++i) {
    run_msa_i8(ANDI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(ORI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(NORI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(XORI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
  }
}

TEST(MSA_bmnzi_bmzi_bseli) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI8 tc[] = {
    //         input_lo,           input_hi,    i8
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0xFFu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0u},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x3Bu},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0xD9u}
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI8); ++i) {
    run_msa_i8(BMNZI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(BMZI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(BSELI_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
  }
}

TEST(MSA_shf) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI8 tc[] = {
      //          input_lo,           input_hi,    i8
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0xFFu},  // 3333
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0u},   // 0000
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0xE4u},  // 3210
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x1Bu},  // 0123
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0xB1u},  // 2301
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x4Eu},  // 1032
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x27u}   // 0213
  };
  // clang-format on

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI8); ++i) {
    run_msa_i8(SHF_B, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(SHF_H, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
    run_msa_i8(SHF_W, tc[i].input_lo, tc[i].input_hi, tc[i].i8);
  }
}

struct TestCaseMsaI5 {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint32_t i5;
};

template <typename InstFunc, typename OperFunc>
void run_msa_i5(struct TestCaseMsaI5* input, bool i5_sign_ext,
                InstFunc GenerateI5InstructionFunc,
                OperFunc GenerateOperationFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;
  int32_t i5 =
      i5_sign_ext ? static_cast<int32_t>(input->i5 << 27) >> 27 : input->i5;

  load_elements_of_vector(&assm, &(input->ws_lo), w0, t0, t1);

  GenerateI5InstructionFunc(assm, i5);

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

  CHECK_EQ(GenerateOperationFunc(input->ws_lo, input->i5), res.d[0]);
  CHECK_EQ(GenerateOperationFunc(input->ws_hi, input->i5), res.d[1]);
}

TEST(MSA_addvi_subvi) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI5 tc[] = {
    //            ws_lo,              ws_hi,         i5
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x0000001F},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0000000F},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x00000005},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x00000010},
    {0xFFAB807F807FFFCD, 0x7F23FF80FF567F80, 0x0000000F},
    {0x80FFEFFF7F12807F, 0x807F80FF7FDEFF78, 0x00000010}
  };
// clang-format on

#define ADDVI_DF(lanes, mask)                               \
  uint64_t res = 0;                                         \
  for (int i = 0; i < lanes / 2; ++i) {                     \
    int shift = (kMSARegSize / lanes) * i;                  \
    res |= ((((ws >> shift) & mask) + i5) & mask) << shift; \
  }                                                         \
  return res

#define SUBVI_DF(lanes, mask)                               \
  uint64_t res = 0;                                         \
  for (int i = 0; i < lanes / 2; ++i) {                     \
    int shift = (kMSARegSize / lanes) * i;                  \
    res |= ((((ws >> shift) & mask) - i5) & mask) << shift; \
  }                                                         \
  return res

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI5); ++i) {
    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_b(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesByte, UINT8_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_h(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesHalf, UINT16_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_w(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesWord, UINT32_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ addvi_d(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { ADDVI_DF(kMSALanesDword, UINT64_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_b(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesByte, UINT8_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_h(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesHalf, UINT16_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_w(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesWord, UINT32_MAX); });

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ subvi_d(w2, w0, i5); },
        [](uint64_t ws, uint32_t i5) { SUBVI_DF(kMSALanesDword, UINT64_MAX); });
  }
#undef ADDVI_DF
#undef SUBVI_DF
}

TEST(MSA_maxi_mini) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  // clang-format off
  struct TestCaseMsaI5 tc[] = {
    //            ws_lo,              ws_hi,         i5
    {0x7F80FF3480FF7F00, 0x8D7FFF80FF7F6780, 0x0000001F},
    {0x7F80FF3480FF7F00, 0x8D7FFF80FF7F6780, 0x0000000F},
    {0x7F80FF3480FF7F00, 0x8D7FFF80FF7F6780, 0x00000010},
    {0x80007FFF91DAFFFF, 0x7FFF8000FFFF5678, 0x0000001F},
    {0x80007FFF91DAFFFF, 0x7FFF8000FFFF5678, 0x0000000F},
    {0x80007FFF91DAFFFF, 0x7FFF8000FFFF5678, 0x00000010},
    {0x7FFFFFFF80000000, 0x12345678FFFFFFFF, 0x0000001F},
    {0x7FFFFFFF80000000, 0x12345678FFFFFFFF, 0x0000000F},
    {0x7FFFFFFF80000000, 0x12345678FFFFFFFF, 0x00000010},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x0000001F},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x0000000F},
    {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x00000010},
    {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x00000015},
    {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x00000009},
    {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x00000003}
  };
// clang-format on

#define MAXI_MINI_S_DF(lanes, mask, func)                                     \
  [](uint64_t ws, uint32_t ui5) {                                             \
    uint64_t res = 0;                                                         \
    int64_t i5 = ArithmeticShiftRight(static_cast<int64_t>(ui5) << 59, 59);   \
    int elem_size = kMSARegSize / lanes;                                      \
    for (int i = 0; i < lanes / 2; ++i) {                                     \
      int shift = elem_size * i;                                              \
      int64_t elem =                                                          \
          static_cast<int64_t>(((ws >> shift) & mask) << (64 - elem_size)) >> \
          (64 - elem_size);                                                   \
      res |= static_cast<uint64_t>(func(elem, i5) & mask) << shift;           \
    }                                                                         \
    return res;                                                               \
  }

#define MAXI_MINI_U_DF(lanes, mask, func)                              \
  [](uint64_t ws, uint32_t ui5) {                                      \
    uint64_t res = 0;                                                  \
    int elem_size = kMSARegSize / lanes;                               \
    for (int i = 0; i < lanes / 2; ++i) {                              \
      int shift = elem_size * i;                                       \
      uint64_t elem = (ws >> shift) & mask;                            \
      res |= (func(elem, static_cast<uint64_t>(ui5)) & mask) << shift; \
    }                                                                  \
    return res;                                                        \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI5); ++i) {
    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_b(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesByte, UINT8_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_h(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesHalf, UINT16_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_w(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesWord, UINT32_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_s_d(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesDword, UINT64_MAX, std::max));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_b(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesByte, UINT8_MAX, std::min));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_h(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesHalf, UINT16_MAX, std::min));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_w(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesWord, UINT32_MAX, std::min));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ mini_s_d(w2, w0, i5); },
        MAXI_MINI_S_DF(kMSALanesDword, UINT64_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_b(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesByte, UINT8_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_h(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesHalf, UINT16_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_w(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesWord, UINT32_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ maxi_u_d(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesDword, UINT64_MAX, std::max));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_b(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesByte, UINT8_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_h(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesHalf, UINT16_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_w(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesWord, UINT32_MAX, std::min));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ mini_u_d(w2, w0, i5); },
        MAXI_MINI_U_DF(kMSALanesDword, UINT64_MAX, std::min));
  }
#undef MAXI_MINI_S_DF
#undef MAXI_MINI_U_DF
}

TEST(MSA_ceqi_clti_clei) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsaI5 tc[] = {
      {0xFF69751BB9A7D9C3, 0xF7A594AEC8FF8A9C, 0x0000001F},
      {0xE669FFFFB9A7D9C3, 0xF7A594AEFFFF8A9C, 0x0000001F},
      {0xFFFFFFFFB9A7D9C3, 0xF7A594AEFFFFFFFF, 0x0000001F},
      {0x2B0B5362C4E812DF, 0x3A0D80D68B3F0BC8, 0x0000000B},
      {0x2B66000BC4E812DF, 0x3A0D000B8B3F8BC8, 0x0000000B},
      {0x0000000BC4E812DF, 0x3A0D80D60000000B, 0x0000000B},
      {0xF38062E13E38F8B0, 0x8041FFDEF2BFE636, 0x00000010},
      {0xF35880003E38F8B0, 0x4F41FFDEF2BF8000, 0x00000010},
      {0xF35862E180000000, 0x80000000F2BFE636, 0x00000010},
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x00000015},
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x00000009},
      {0xF30062E13E38F800, 0x4F00FFDEF2BF0036, 0x00000000}};

#define CEQI_CLTI_CLEI_S_DF(lanes, mask, func)                                \
  [](uint64_t ws, uint32_t ui5) {                                             \
    uint64_t res = 0;                                                         \
    int elem_size = kMSARegSize / lanes;                                      \
    int64_t i5 = ArithmeticShiftRight(static_cast<int64_t>(ui5) << 59, 59);   \
    for (int i = 0; i < lanes / 2; ++i) {                                     \
      int shift = elem_size * i;                                              \
      int64_t elem =                                                          \
          static_cast<int64_t>(((ws >> shift) & mask) << (64 - elem_size)) >> \
          (64 - elem_size);                                                   \
      res |= static_cast<uint64_t>((func)&mask) << shift;                     \
    }                                                                         \
    return res;                                                               \
  }

#define CEQI_CLTI_CLEI_U_DF(lanes, mask, func) \
  [](uint64_t ws, uint64_t ui5) {              \
    uint64_t res = 0;                          \
    int elem_size = kMSARegSize / lanes;       \
    for (int i = 0; i < lanes / 2; ++i) {      \
      int shift = elem_size * i;               \
      uint64_t elem = (ws >> shift) & mask;    \
      res |= ((func)&mask) << shift;           \
    }                                          \
    return res;                                \
  }

  for (size_t i = 0; i < sizeof(tc) / sizeof(TestCaseMsaI5); ++i) {
    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_b(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesByte, UINT8_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_h(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesHalf, UINT16_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_w(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesWord, UINT32_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(&tc[i], true,
               [](MacroAssembler& assm, int32_t i5) { __ ceqi_d(w2, w0, i5); },
               CEQI_CLTI_CLEI_S_DF(kMSALanesDword, UINT64_MAX,
                                   !Compare(elem, i5) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, i5) == -1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, i5) == -1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, i5) == -1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clti_s_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, i5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, i5) != 1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, i5) != 1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, i5) != 1) ? -1u : 0u));

    run_msa_i5(
        &tc[i], true,
        [](MacroAssembler& assm, int32_t i5) { __ clei_s_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_S_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, i5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clti_u_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, ui5) == -1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_b(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesByte, UINT8_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_h(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesHalf, UINT16_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_w(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesWord, UINT32_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));

    run_msa_i5(
        &tc[i], false,
        [](MacroAssembler& assm, int32_t i5) { __ clei_u_d(w2, w0, i5); },
        CEQI_CLTI_CLEI_U_DF(kMSALanesDword, UINT64_MAX,
                            (Compare(elem, ui5) != 1) ? -1ull : 0ull));
  }
#undef CEQI_CLTI_CLEI_S_DF
#undef CEQI_CLTI_CLEI_U_DF
}

struct TestCaseMsa2R {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint64_t exp_res_lo;
  uint64_t exp_res_hi;
};

template <typename Func>
void run_msa_2r(const struct TestCaseMsa2R* input,
                Func Generate2RInstructionFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(&assm, reinterpret_cast<const uint64_t*>(input), w0,
                          t0, t1);
  Generate2RInstructionFunc(assm);
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

  CHECK_EQ(input->exp_res_lo, res.d[0]);
  CHECK_EQ(input->exp_res_hi, res.d[1]);
}

TEST(MSA_pcnt) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2R tc_b[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0808080808080808, 0x0808080808080808},
                                 {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C,
                                  0x0204050405050504, 0x0704030503070304},
                                 {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8,
                                  0x0404040303040207, 0x0403010504060403},
                                 {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636,
                                  0x0603030405030503, 0x0502080605070504}};

  struct TestCaseMsa2R tc_h[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0010001000100010, 0x0010001000100010},
                                 {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C,
                                  0x00060009000A0009, 0x000B0008000A0007},
                                 {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8,
                                  0x0008000700070009, 0x00070006000A0007},
                                 {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636,
                                  0x0009000700080008, 0x0007000E000C0009}};

  struct TestCaseMsa2R tc_w[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0000002000000020, 0x0000002000000020},
                                 {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C,
                                  0x0000000F00000013, 0x0000001300000011},
                                 {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8,
                                  0x0000000F00000010, 0x0000000D00000011},
                                 {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636,
                                  0x0000001000000010, 0x0000001500000015}};

  struct TestCaseMsa2R tc_d[] = {
      // ws_lo, ws_hi, exp_res_lo, exp_res_hi
      {0x0000000000000000, 0x0000000000000000, 0, 0},
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x40, 0x40},
      {0x1169751BB9A7D9C3, 0xF7A594AEC8EF8A9C, 0x22, 0x24},
      {0x2B665362C4E812DF, 0x3A0D80D68B3F8BC8, 0x1F, 0x1E},
      {0xF35862E13E38F8B0, 0x4F41FFDEF2BFE636, 0x20, 0x2A}};

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseMsa2R); ++i) {
    run_msa_2r(&tc_b[i], [](MacroAssembler& assm) { __ pcnt_b(w2, w0); });
    run_msa_2r(&tc_h[i], [](MacroAssembler& assm) { __ pcnt_h(w2, w0); });
    run_msa_2r(&tc_w[i], [](MacroAssembler& assm) { __ pcnt_w(w2, w0); });
    run_msa_2r(&tc_d[i], [](MacroAssembler& assm) { __ pcnt_d(w2, w0); });
  }
}

TEST(MSA_nlzc) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2R tc_b[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000,
                                  0x0808080808080808, 0x0808080808080808},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
                                 {0x1169350B07030100, 0x7F011402381F0A6C,
                                  0x0301020405060708, 0x0107030602030401},
                                 {0x010806003478121F, 0x03013016073F7B08,
                                  0x0704050802010303, 0x0607020305020104},
                                 {0x0168321100083803, 0x07113F03013F1676,
                                  0x0701020308040206, 0x0503020607020301}};

  struct TestCaseMsa2R tc_h[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000,
                                  0x0010001000100010, 0x0010001000100010},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
                                 {0x00010007000A003C, 0x37A5001E00010002,
                                  0x000F000D000C000A, 0x0002000B000F000E},
                                 {0x0026066200780EDF, 0x003D0003000F00C8,
                                  0x000A000500090004, 0x000A000E000C0008},
                                 {0x335807E100480030, 0x01410FDE12BF5636,
                                  0x000200050009000A, 0x0007000400030001}};

  struct TestCaseMsa2R tc_w[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0x0000000000000000, 0x0000000000000000,
                                  0x0000002000000020, 0x0000002000000020},
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
                                 {0x00000005000007C3, 0x000014AE00006A9C,
                                  0x0000001D00000015, 0x0000001300000011},
                                 {0x00009362000112DF, 0x000380D6003F8BC8,
                                  0x000000100000000F, 0x0000000E0000000A},
                                 {0x135862E17E38F8B0, 0x0061FFDE03BFE636,
                                  0x0000000300000001, 0x0000000900000006}};

  struct TestCaseMsa2R tc_d[] = {
      // ws_lo, ws_hi, exp_res_lo, exp_res_hi
      {0x0000000000000000, 0x0000000000000000, 0x40, 0x40},
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0},
      {0x000000000000014E, 0x00000000000176DA, 0x37, 0x2F},
      {0x00000062C4E812DF, 0x000065D68B3F8BC8, 0x19, 0x11},
      {0x00000000E338F8B0, 0x0754534ACAB32654, 0x20, 0x5}};

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseMsa2R); ++i) {
    run_msa_2r(&tc_b[i], [](MacroAssembler& assm) { __ nlzc_b(w2, w0); });
    run_msa_2r(&tc_h[i], [](MacroAssembler& assm) { __ nlzc_h(w2, w0); });
    run_msa_2r(&tc_w[i], [](MacroAssembler& assm) { __ nlzc_w(w2, w0); });
    run_msa_2r(&tc_d[i], [](MacroAssembler& assm) { __ nlzc_d(w2, w0); });
  }
}

TEST(MSA_nloc) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  struct TestCaseMsa2R tc_b[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0808080808080808, 0x0808080808080808},
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xEE96CAF4F8FCFEFF, 0x80FEEBFDC7E0F593,
                                  0x0301020405060708, 0x0107030602030401},
                                 {0xFEF7F9FFCB87EDE0, 0xFCFECFE9F8C084F7,
                                  0x0704050802010303, 0x0607020305020104},
                                 {0xFE97CDEEFFF7C7FC, 0xF8EEC0FCFEC0E989,
                                  0x0701020308040206, 0x0503020607020301}};

  struct TestCaseMsa2R tc_h[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0010001000100010, 0x0010001000100010},
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFEFFF8FFF5FFC3, 0xC85AFFE1FFFEFFFD,
                                  0x000F000D000C000A, 0x0002000B000F000E},
                                 {0xFFD9F99DFF87F120, 0xFFC2FFFCFFF0FF37,
                                  0x000A000500090004, 0x000A000E000C0008},
                                 {0xCCA7F81EFFB7FFCF, 0xFEBEF021ED40A9C9,
                                  0x000200050009000A, 0x0007000400030001}};

  struct TestCaseMsa2R tc_w[] = {// ws_lo, ws_hi, exp_res_lo, exp_res_hi
                                 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                  0x0000002000000020, 0x0000002000000020},
                                 {0x0000000000000000, 0x0000000000000000, 0, 0},
                                 {0xFFFFFFFAFFFFF83C, 0xFFFFEB51FFFF9563,
                                  0x0000001D00000015, 0x0000001300000011},
                                 {0xFFFF6C9DFFFEED20, 0xFFFC7F29FFC07437,
                                  0x000000100000000F, 0x0000000E0000000A},
                                 {0xECA79D1E81C7074F, 0xFF9E0021FC4019C9,
                                  0x0000000300000001, 0x0000000900000006}};

  struct TestCaseMsa2R tc_d[] = {
      // ws_lo, ws_hi, exp_res_lo, exp_res_hi
      {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x40, 0x40},
      {0x0000000000000000, 0x0000000000000000, 0, 0},
      {0xFFFFFFFFFFFFFEB1, 0xFFFFFFFFFFFE8925, 0x37, 0x2F},
      {0xFFFFFF9D3B17ED20, 0xFFFF9A2974C07437, 0x19, 0x11},
      {0xFFFFFFFF1CC7074F, 0xF8ABACB5354CD9AB, 0x20, 0x5}};

  for (size_t i = 0; i < sizeof(tc_b) / sizeof(TestCaseMsa2R); ++i) {
    run_msa_2r(&tc_b[i], [](MacroAssembler& assm) { __ nloc_b(w2, w0); });
    run_msa_2r(&tc_h[i], [](MacroAssembler& assm) { __ nloc_h(w2, w0); });
    run_msa_2r(&tc_w[i], [](MacroAssembler& assm) { __ nloc_w(w2, w0); });
    run_msa_2r(&tc_d[i], [](MacroAssembler& assm) { __ nloc_d(w2, w0); });
  }
}

struct TestCaseMsa2RF_F_U {
  float ws1;
  float ws2;
  float ws3;
  float ws4;
  uint32_t exp_res_1;
  uint32_t exp_res_2;
  uint32_t exp_res_3;
  uint32_t exp_res_4;
};

struct TestCaseMsa2RF_D_U {
  double ws1;
  double ws2;
  uint64_t exp_res_1;
  uint64_t exp_res_2;
};

TEST(MSA_fclass) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

#define BIT(n) (0x1 << n)
#define SNAN_BIT BIT(0)
#define QNAN_BIT BIT(1)
#define NEG_INFINITY_BIT BIT((2))
#define NEG_NORMAL_BIT BIT(3)
#define NEG_SUBNORMAL_BIT BIT(4)
#define NEG_ZERO_BIT BIT(5)
#define POS_INFINITY_BIT BIT(6)
#define POS_NORMAL_BIT BIT(7)
#define POS_SUBNORMAL_BIT BIT(8)
#define POS_ZERO_BIT BIT(9)

  const float inf_float = std::numeric_limits<float>::infinity();
  const double inf_double = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa2RF_F_U tc_s[] = {
      {1.f, -0.00001, 208e10f, -34.8e-30f, POS_NORMAL_BIT, NEG_NORMAL_BIT,
       POS_NORMAL_BIT, NEG_NORMAL_BIT},
      {inf_float, -inf_float, 0, -0.f, POS_INFINITY_BIT, NEG_INFINITY_BIT,
       POS_ZERO_BIT, NEG_ZERO_BIT},
      {3.036e-40f, -6.392e-43f, 1.41e-45f, -1.17e-38f, POS_SUBNORMAL_BIT,
       NEG_SUBNORMAL_BIT, POS_SUBNORMAL_BIT, NEG_SUBNORMAL_BIT}};

  const struct TestCaseMsa2RF_D_U tc_d[] = {
      {1., -0.00000001, POS_NORMAL_BIT, NEG_NORMAL_BIT},
      {208e10, -34.8e-300, POS_NORMAL_BIT, NEG_NORMAL_BIT},
      {inf_double, -inf_double, POS_INFINITY_BIT, NEG_INFINITY_BIT},
      {0, -0., POS_ZERO_BIT, NEG_ZERO_BIT},
      {1.036e-308, -6.392e-309, POS_SUBNORMAL_BIT, NEG_SUBNORMAL_BIT},
      {1.41e-323, -3.17e208, POS_SUBNORMAL_BIT, NEG_NORMAL_BIT}};

  for (size_t i = 0; i < sizeof(tc_s) / sizeof(TestCaseMsa2RF_F_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_s[i]),
               [](MacroAssembler& assm) { __ fclass_w(w2, w0); });
  }
  for (size_t i = 0; i < sizeof(tc_d) / sizeof(TestCaseMsa2RF_D_U); ++i) {
    run_msa_2r(reinterpret_cast<const TestCaseMsa2R*>(&tc_d[i]),
               [](MacroAssembler& assm) { __ fclass_d(w2, w0); });
  }

#undef BIT
#undef SNAN_BIT
#undef QNAN_BIT
#undef NEG_INFINITY_BIT
#undef NEG_NORMAL_BIT
#undef NEG_SUBNORMAL_BIT
#undef NEG_ZERO_BIT
#undef POS_INFINITY_BIT
#undef POS_NORMAL_BIT
#undef POS_SUBNORMAL_BIT
#undef POS_ZERO_BIT
}

struct TestCaseMsa2RF_F_I {
  float ws1;
  float ws2;
  float ws3;
  float ws4;
  int32_t exp_res_1;
  int32_t exp_res_2;
  int32_t exp_res_3;
  int32_t exp_res_4;
};

struct TestCaseMsa2RF_D_I {
  double ws1;
  double ws2;
  int64_t exp_res_1;
  int64_t exp_res_2;
};

TEST(MSA_ftrunc_s) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::Initi
```