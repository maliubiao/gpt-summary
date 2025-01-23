Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-macro-assembler-loong64.cc`.
The request specifies that it is the first part of a two-part file and asks to identify its functionality and its relation to JavaScript.

The filename suggests that it contains tests for the macro assembler on the LoongArch 64-bit architecture. Macro assemblers are used to generate machine code. V8 is the JavaScript engine used in Chrome and Node.js, and it compiles JavaScript code to machine code for efficient execution. Therefore, this file likely tests the correctness of the generated LoongArch assembly code produced by V8's macro assembler.

To illustrate the connection with JavaScript, I can create a simple JavaScript example and explain how the assembly code being tested might be involved in its execution. For instance, arithmetic operations in JavaScript will eventually be translated into corresponding machine code instructions.

The tests seem to cover various LoongArch instructions and functionalities, including:
- Byte swapping
- Loading constants
- Jump tables (for switch statements or similar control flow)
- Arithmetic and logical instructions (ALSL, overflow checks, SUB)
- Floating-point operations (conversions, min/max, NaN handling)
- Memory access instructions (loads and stores of different sizes, unaligned access)
- Comparison instructions (SLTU)

Based on this initial analysis, the main function of this file is to test the `MacroAssembler` class in V8 for the LoongArch64 architecture.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试LoongArch 64位架构上的宏汇编器(`MacroAssembler`)的功能。

**主要功能归纳:**

1. **测试宏汇编器的指令生成:**  该文件包含了大量的单元测试，用于验证`MacroAssembler`类是否能够为LoongArch64架构正确生成各种指令。这些测试覆盖了不同的指令类型，包括：
    * **数据处理指令:** 例如字节交换 (`BYTESWAP`)，算术逻辑运算 (`ALSL_W`, `ALSL_D`, `SUB_W`, `SUB_D`)，以及带溢出检测的算术运算 (`AddOverflow_d`, `SubOverflow_d`, `MulOverflow_w`)。
    * **常量加载指令:** 测试加载各种大小的常量 (`LoadConstants`)。
    * **控制流指令:**  测试生成跳转表 (`jump_tables4`, `jump_tables6`)，这对于实现 `switch` 语句等控制结构至关重要。
    * **浮点指令:** 测试单精度和双精度浮点数的转换 (`Ffint_s_uw_Ftintrz_uw_s`等)，以及浮点数的最小值和最大值计算 (`min_max_nan`, `macro_float_minmax_f32`, `macro_float_minmax_f64`)。
    * **内存访问指令:** 测试加载和存储不同大小的数据 (`Ld_b`, `Ld_h`, `Ld_w`, `Ld_d`, `Fld_s`, `Fld_d`)，包括处理未对齐的内存访问 (`Unaligned`相关的测试)。
    * **比较指令:** 测试无符号小于比较指令 (`Sltu`)。
2. **验证生成的机器码的正确性:**  每个测试用例都会生成一段LoongArch64的机器码，然后通过执行这段代码并检查结果是否符合预期来验证宏汇编器生成的指令是否正确。
3. **模拟器环境:**  这些测试通常在V8的模拟器环境下运行，允许在没有实际LoongArch64硬件的情况下进行测试。

**与JavaScript的关系及JavaScript示例:**

宏汇编器是V8将JavaScript代码编译成机器码的关键组件。当V8执行JavaScript代码时，它会将JavaScript代码翻译成一系列的机器指令，这些指令由宏汇编器生成。

例如，考虑以下简单的JavaScript代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

当V8执行这段代码时，`add` 函数中的加法操作 `a + b`  最终会被编译成LoongArch64的加法指令。  `test-macro-assembler-loong64.cc` 中的一些测试用例可能会测试类似以下的操作：

```c++
TEST(Addition) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Add_d(a2, a0, a1); // 假设 a0 和 a1 存储了 JavaScript 传递的参数 a 和 b
  __ or_(a0, a2, zero_reg); // 将结果存储到 a0，用于返回

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  int64_t arg1 = 5;
  int64_t arg2 = 10;
  int64_t result = reinterpret_cast<int64_t>(f.Call(arg1, arg2, 0, 0, 0));
  CHECK_EQ(15, result);
}
```

在这个简化的C++测试示例中，`__ Add_d(a2, a0, a1)` 模拟了宏汇编器生成LoongArch64的加法指令，用于执行JavaScript中的加法运算。  `test-macro-assembler-loong64.cc` 中的实际测试会更加复杂和全面，覆盖各种不同的数据类型、边界情况和指令组合，以确保宏汇编器在各种场景下都能生成正确的机器码，从而保证JavaScript代码的正确执行。

总而言之，`v8/test/cctest/test-macro-assembler-loong64.cc` (第一部分) 的功能是 **测试V8 JavaScript引擎在LoongArch64架构上的宏汇编器，验证其生成机器码的正确性，这直接关系到JavaScript代码在该架构上的高效且正确的执行。**

### 提示词
```
这是目录为v8/test/cctest/test-macro-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>

#include <iostream>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/compiler/access-builder.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/simulator.h"
#include "src/objects/objects-inl.h"
#include "src/utils/ostreams.h"
#include "test/cctest/cctest.h"
#include "test/common/assembler-tester.h"

namespace v8 {
namespace internal {

// TODO(LOONG64): Refine these signatures per test case.
using FV = void*(int64_t x, int64_t y, int p2, int p3, int p4);
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ masm->

TEST(BYTESWAP) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t s8;
    uint64_t s4;
    uint64_t u4;
  };

  T t;
  // clang-format off
  uint64_t test_values[] = {0x5612FFCD9D327ACC,
                            0x781A15C3,
                            0xFCDE,
                            0x9F,
                            0xC81A15C3,
                            0x8000000000000000,
                            0xFFFFFFFFFFFFFFFF,
                            0x0000000080000000,
                            0x0000000000008000};
  // clang-format on
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);

  MacroAssembler* masm = &assembler;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, s8)));
  __ ByteSwap(a4, a4, 8);
  __ St_d(a4, MemOperand(a0, offsetof(T, s8)));

  __ Ld_d(a4, MemOperand(a0, offsetof(T, s4)));
  __ ByteSwap(a4, a4, 4);
  __ St_d(a4, MemOperand(a0, offsetof(T, s4)));

  __ Ld_d(a4, MemOperand(a0, offsetof(T, u4)));
  __ ByteSwap(a4, a4, 4);
  __ St_d(a4, MemOperand(a0, offsetof(T, u4)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  for (size_t i = 0; i < arraysize(test_values); i++) {
    int32_t in_s4 = static_cast<int32_t>(test_values[i]);
    uint32_t in_u4 = static_cast<uint32_t>(test_values[i]);

    t.s8 = test_values[i];
    t.s4 = static_cast<uint64_t>(in_s4);
    t.u4 = static_cast<uint64_t>(in_u4);

    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(ByteReverse<uint64_t>(test_values[i]), t.s8);
    CHECK_EQ(ByteReverse<int32_t>(in_s4), static_cast<int32_t>(t.s4));
    CHECK_EQ(ByteReverse<uint32_t>(in_u4), static_cast<uint32_t>(t.u4));
  }
}

TEST(LoadConstants) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  int64_t refConstants[64];
  int64_t result[64];

  int64_t mask = 1;
  for (int i = 0; i < 64; i++) {
    refConstants[i] = ~(mask << i);
  }

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ or_(a4, a0, zero_reg);
  for (int i = 0; i < 64; i++) {
    // Load constant.
    __ li(a5, Operand(refConstants[i]));
    __ St_d(a5, MemOperand(a4, zero_reg));
    __ Add_d(a4, a4, Operand(kSystemPointerSize));
  }

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);
  (void)f.Call(reinterpret_cast<int64_t>(result), 0, 0, 0, 0);
  // Check results.
  for (int i = 0; i < 64; i++) {
    CHECK(refConstants[i] == result[i]);
  }
}

TEST(jump_tables4) {
  // Similar to test-assembler-loong64 jump_tables1, with extra test for branch
  // trampoline required before emission of the dd table (where trampolines are
  // blocked), and proper transition to long-branch mode.
  // Regression test for v8:4294.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];
  Label near_start, end, done;

  __ Push(ra);
  __ xor_(a2, a2, a2);

  __ Branch(&end);
  __ bind(&near_start);

  for (int i = 0; i < 32768 - 256; ++i) {
    __ Add_d(a2, a2, 1);
  }

  __ GenerateSwitchTable(a0, kNumCases,
                         [&labels](size_t i) { return labels + i; });

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ li(a2, values[i]);
    __ Branch(&done);
  }

  __ bind(&done);
  __ Pop(ra);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  __ bind(&end);
  __ Branch(&near_start);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
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

TEST(jump_tables6) {
  // Similar to test-assembler-loong64 jump_tables1, with extra test for branch
  // trampoline required after emission of the dd table (where trampolines are
  // blocked). This test checks if number of really generated instructions is
  // greater than number of counted instructions from code, as we are expecting
  // generation of trampoline in this case
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kSwitchTableCases = 80;

  const int kMaxBranchOffset = (1 << (18 - 1)) - 1;
  const int kTrampolineSlotsSize = Assembler::kTrampolineSlotsSize;
  const int kSwitchTablePrologueSize = MacroAssembler::kSwitchTablePrologueSize;

  const int kMaxOffsetForTrampolineStart =
      kMaxBranchOffset - 16 * kTrampolineSlotsSize;
  const int kFillInstr = (kMaxOffsetForTrampolineStart / kInstrSize) -
                         (kSwitchTablePrologueSize + kSwitchTableCases) - 20;

  int values[kSwitchTableCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kSwitchTableCases];
  Label near_start, end, done;

  __ Push(ra);
  __ xor_(a2, a2, a2);

  int offs1 = masm->pc_offset();
  int gen_insn = 0;

  __ Branch(&end);
  gen_insn += 1;
  __ bind(&near_start);

  for (int i = 0; i < kFillInstr; ++i) {
    __ Add_d(a2, a2, 1);
  }
  gen_insn += kFillInstr;

  __ GenerateSwitchTable(a0, kSwitchTableCases,
                         [&labels](size_t i) { return labels + i; });
  gen_insn += (kSwitchTablePrologueSize + kSwitchTableCases);

  for (int i = 0; i < kSwitchTableCases; ++i) {
    __ bind(&labels[i]);
    __ li(a2, values[i]);
    __ Branch(&done);
  }
  gen_insn += 3 * kSwitchTableCases;

  // If offset from here to first branch instr is greater than max allowed
  // offset for trampoline ...
  CHECK_LT(kMaxOffsetForTrampolineStart, masm->pc_offset() - offs1);
  // ... number of generated instructions must be greater then "gen_insn",
  // as we are expecting trampoline generation
  CHECK_LT(gen_insn, (masm->pc_offset() - offs1) / kInstrSize);

  __ bind(&done);
  __ Pop(ra);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  __ bind(&end);
  __ Branch(&near_start);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  for (int i = 0; i < kSwitchTableCases; ++i) {
    int64_t res = reinterpret_cast<int64_t>(f.Call(i, 0, 0, 0, 0));
    ::printf("f(%d) = %" PRId64 "\n", i, res);
    CHECK_EQ(values[i], res);
  }
}

static uint64_t run_alsl_w(uint32_t rj, uint32_t rk, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Alsl_w(a2, a0, a1, sa);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rj, rk, 0, 0, 0));

  return res;
}

TEST(ALSL_W) {
  CcTest::InitializeVM();
  struct TestCaseAlsl {
    int32_t rj;
    int32_t rk;
    uint8_t sa;
    uint64_t expected_res;
  };
  // clang-format off
  struct TestCaseAlsl tc[] = {// rj, rk, sa, expected_res
                             {0x1, 0x4, 1, 0x6},
                             {0x1, 0x4, 2, 0x8},
                             {0x1, 0x4, 3, 0xC},
                             {0x1, 0x4, 4, 0x14},
                             {0x1, 0x4, 5, 0x24},
                             {0x1, 0x0, 1, 0x2},
                             {0x1, 0x0, 2, 0x4},
                             {0x1, 0x0, 3, 0x8},
                             {0x1, 0x0, 4, 0x10},
                             {0x1, 0x0, 5, 0x20},
                             {0x0, 0x4, 1, 0x4},
                             {0x0, 0x4, 2, 0x4},
                             {0x0, 0x4, 3, 0x4},
                             {0x0, 0x4, 4, 0x4},
                             {0x0, 0x4, 5, 0x4},

                             // Shift overflow.
                             {INT32_MAX, 0x4, 1, 0x2},
                             {INT32_MAX >> 1, 0x4, 2, 0x0},
                             {INT32_MAX >> 2, 0x4, 3, 0xFFFFFFFFFFFFFFFC},
                             {INT32_MAX >> 3, 0x4, 4, 0xFFFFFFFFFFFFFFF4},
                             {INT32_MAX >> 4, 0x4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {0x1, INT32_MAX - 1, 1, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 3, 2, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 7, 3, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 15, 4, 0xFFFFFFFF80000000},
                             {0x1, INT32_MAX - 31, 5, 0xFFFFFFFF80000000},

                             // Addition overflow.
                             {0x1, -2, 1, 0x0},
                             {0x1, -4, 2, 0x0},
                             {0x1, -8, 3, 0x0},
                             {0x1, -16, 4, 0x0},
                             {0x1, -32, 5, 0x0}};
  // clang-format on
  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAlsl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_alsl_w(tc[i].rj, tc[i].rk, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Alsl_w(a0, %x, %x, %hhu)\n",
           tc[i].expected_res, res, tc[i].rj, tc[i].rk, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

static uint64_t run_alsl_d(uint64_t rj, uint64_t rk, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Alsl_d(a2, a0, a1, sa);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rj, rk, 0, 0, 0));

  return res;
}

TEST(ALSL_D) {
  CcTest::InitializeVM();
  struct TestCaseAlsl {
    int64_t rj;
    int64_t rk;
    uint8_t sa;
    uint64_t expected_res;
  };
  // clang-format off
  struct TestCaseAlsl tc[] = {// rj, rk, sa, expected_res
                             {0x1, 0x4, 1, 0x6},
                             {0x1, 0x4, 2, 0x8},
                             {0x1, 0x4, 3, 0xC},
                             {0x1, 0x4, 4, 0x14},
                             {0x1, 0x4, 5, 0x24},
                             {0x1, 0x0, 1, 0x2},
                             {0x1, 0x0, 2, 0x4},
                             {0x1, 0x0, 3, 0x8},
                             {0x1, 0x0, 4, 0x10},
                             {0x1, 0x0, 5, 0x20},
                             {0x0, 0x4, 1, 0x4},
                             {0x0, 0x4, 2, 0x4},
                             {0x0, 0x4, 3, 0x4},
                             {0x0, 0x4, 4, 0x4},
                             {0x0, 0x4, 5, 0x4},

                             // Shift overflow.
                             {INT64_MAX, 0x4, 1, 0x2},
                             {INT64_MAX >> 1, 0x4, 2, 0x0},
                             {INT64_MAX >> 2, 0x4, 3, 0xFFFFFFFFFFFFFFFC},
                             {INT64_MAX >> 3, 0x4, 4, 0xFFFFFFFFFFFFFFF4},
                             {INT64_MAX >> 4, 0x4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {0x1, INT64_MAX - 1, 1, 0x8000000000000000},
                             {0x1, INT64_MAX - 3, 2, 0x8000000000000000},
                             {0x1, INT64_MAX - 7, 3, 0x8000000000000000},
                             {0x1, INT64_MAX - 15, 4, 0x8000000000000000},
                             {0x1, INT64_MAX - 31, 5, 0x8000000000000000},

                             // Addition overflow.
                             {0x1, -2, 1, 0x0},
                             {0x1, -4, 2, 0x0},
                             {0x1, -8, 3, 0x0},
                             {0x1, -16, 4, 0x0},
                             {0x1, -32, 5, 0x0}};
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseAlsl);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_alsl_d(tc[i].rj, tc[i].rk, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Dlsa(v0, %" PRIx64 ", %" PRIx64
           ", %hhu)\n",
           tc[i].expected_res, res, tc[i].rj, tc[i].rk, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}
// clang-format off
static const std::vector<uint32_t> ffint_ftintrz_uint32_test_values() {
  static const uint32_t kValues[] = {0x00000000, 0x00000001, 0x00FFFF00,
                                     0x7FFFFFFF, 0x80000000, 0x80000001,
                                     0x80FFFF00, 0x8FFFFFFF, 0xFFFFFFFF};
  return std::vector<uint32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> ffint_ftintrz_int32_test_values() {
  static const int32_t kValues[] = {
      static_cast<int32_t>(0x00000000), static_cast<int32_t>(0x00000001),
      static_cast<int32_t>(0x00FFFF00), static_cast<int32_t>(0x7FFFFFFF),
      static_cast<int32_t>(0x80000000), static_cast<int32_t>(0x80000001),
      static_cast<int32_t>(0x80FFFF00), static_cast<int32_t>(0x8FFFFFFF),
      static_cast<int32_t>(0xFFFFFFFF)};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<uint64_t> ffint_ftintrz_uint64_test_values() {
  static const uint64_t kValues[] = {
      0x0000000000000000, 0x0000000000000001, 0x0000FFFFFFFF0000,
      0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x8000000000000001,
      0x8000FFFFFFFF0000, 0x8FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int64_t> ffint_ftintrz_int64_test_values() {
  static const int64_t kValues[] = {static_cast<int64_t>(0x0000000000000000),
                                    static_cast<int64_t>(0x0000000000000001),
                                    static_cast<int64_t>(0x0000FFFFFFFF0000),
                                    static_cast<int64_t>(0x7FFFFFFFFFFFFFFF),
                                    static_cast<int64_t>(0x8000000000000000),
                                    static_cast<int64_t>(0x8000000000000001),
                                    static_cast<int64_t>(0x8000FFFFFFFF0000),
                                    static_cast<int64_t>(0x8FFFFFFFFFFFFFFF),
                                    static_cast<int64_t>(0xFFFFFFFFFFFFFFFF)};
  return std::vector<int64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}
// clang-format on

// Helper macros that can be used in FOR_INT32_INPUTS(i) { ... *i ... }
#define FOR_INPUTS(ctype, itype, var, test_vector)           \
  std::vector<ctype> var##_vec = test_vector();              \
  for (std::vector<ctype>::iterator var = var##_vec.begin(); \
       var != var##_vec.end(); ++var)

#define FOR_INPUTS2(ctype, itype, var, var2, test_vector)  \
  std::vector<ctype> var##_vec = test_vector();            \
  std::vector<ctype>::iterator var;                        \
  std::vector<ctype>::reverse_iterator var2;               \
  for (var = var##_vec.begin(), var2 = var##_vec.rbegin(); \
       var != var##_vec.end(); ++var, ++var2)

#define FOR_ENUM_INPUTS(var, type, test_vector) \
  FOR_INPUTS(enum type, type, var, test_vector)
#define FOR_STRUCT_INPUTS(var, type, test_vector) \
  FOR_INPUTS(struct type, type, var, test_vector)
#define FOR_INT32_INPUTS(var, test_vector) \
  FOR_INPUTS(int32_t, int32, var, test_vector)
#define FOR_INT32_INPUTS2(var, var2, test_vector) \
  FOR_INPUTS2(int32_t, int32, var, var2, test_vector)
#define FOR_INT64_INPUTS(var, test_vector) \
  FOR_INPUTS(int64_t, int64, var, test_vector)
#define FOR_UINT32_INPUTS(var, test_vector) \
  FOR_INPUTS(uint32_t, uint32, var, test_vector)
#define FOR_UINT64_INPUTS(var, test_vector) \
  FOR_INPUTS(uint64_t, uint64, var, test_vector)

template <typename RET_TYPE, typename IN_TYPE, typename Func>
RET_TYPE run_CVT(IN_TYPE x, Func GenerateConvertInstructionFunc) {
  using F_CVT = RET_TYPE(IN_TYPE x0, int x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;

  GenerateConvertInstructionFunc(masm);
  __ movfr2gr_d(a2, f9);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);

  return reinterpret_cast<RET_TYPE>(f.Call(x, 0, 0, 0, 0));
}

TEST(Ffint_s_uw_Ftintrz_uw_s) {
  CcTest::InitializeVM();
  FOR_UINT32_INPUTS(i, ffint_ftintrz_uint32_test_values) {
    uint32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_s_uw(f8, a0);
      __ movgr2frh_w(f9, zero_reg);
      __ Ftintrz_uw_s(f9, f8, f10);
    };
    CHECK_EQ(static_cast<float>(input), run_CVT<uint32_t>(input, fn));
  }
}

TEST(Ffint_s_ul_Ftintrz_ul_s) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, ffint_ftintrz_uint64_test_values) {
    uint64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_s_ul(f8, a0);
      __ Ftintrz_ul_s(f9, f8, f10, a2);
    };
    CHECK_EQ(static_cast<float>(input), run_CVT<uint64_t>(input, fn));
  }
}

TEST(Ffint_d_uw_Ftintrz_uw_d) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, ffint_ftintrz_uint64_test_values) {
    uint32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_d_uw(f8, a0);
      __ movgr2frh_w(f9, zero_reg);
      __ Ftintrz_uw_d(f9, f8, f10);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<uint32_t>(input, fn));
  }
}

TEST(Ffint_d_ul_Ftintrz_ul_d) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, ffint_ftintrz_uint64_test_values) {
    uint64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Ffint_d_ul(f8, a0);
      __ Ftintrz_ul_d(f9, f8, f10, a2);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<uint64_t>(input, fn));
  }
}

TEST(Ffint_d_l_Ftintrz_l_ud) {
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i, ffint_ftintrz_int64_test_values) {
    int64_t input = *i;
    uint64_t abs_input = (input >= 0 || input == INT64_MIN) ? input : -input;
    auto fn = [](MacroAssembler* masm) {
      __ movgr2fr_d(f8, a0);
      __ ffint_d_l(f10, f8);
      __ Ftintrz_l_ud(f9, f10, f11);
    };
    CHECK_EQ(static_cast<double>(abs_input), run_CVT<uint64_t>(input, fn));
  }
}

TEST(ffint_d_l_Ftint_l_d) {
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i, ffint_ftintrz_int64_test_values) {
    int64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ movgr2fr_d(f8, a0);
      __ ffint_d_l(f10, f8);
      __ Ftintrz_l_d(f9, f10);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<int64_t>(input, fn));
  }
}

TEST(ffint_d_w_Ftint_w_d) {
  CcTest::InitializeVM();
  FOR_INT32_INPUTS(i, ffint_ftintrz_int32_test_values) {
    int32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ movgr2fr_w(f8, a0);
      __ ffint_d_w(f10, f8);
      __ Ftintrz_w_d(f9, f10);
      __ movfr2gr_s(a4, f9);
      __ movgr2fr_d(f9, a4);
    };
    CHECK_EQ(static_cast<double>(input), run_CVT<int64_t>(input, fn));
  }
}


static const std::vector<int64_t> overflow_int64_test_values() {
  // clang-format off
  static const int64_t kValues[] = {static_cast<int64_t>(0xF000000000000000),
                                    static_cast<int64_t>(0x0000000000000001),
                                    static_cast<int64_t>(0xFF00000000000000),
                                    static_cast<int64_t>(0x0000F00111111110),
                                    static_cast<int64_t>(0x0F00001000000000),
                                    static_cast<int64_t>(0x991234AB12A96731),
                                    static_cast<int64_t>(0xB0FFFF0F0F0F0F01),
                                    static_cast<int64_t>(0x00006FFFFFFFFFFF),
                                    static_cast<int64_t>(0xFFFFFFFFFFFFFFFF)};
  // clang-format on
  return std::vector<int64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(OverflowInstructions) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  struct T {
    int64_t lhs;
    int64_t rhs;
    int64_t output_add1;
    int64_t output_add2;
    int64_t output_sub1;
    int64_t output_sub2;
    int64_t output_mul1;
    int64_t output_mul2;
    int64_t overflow_add1;
    int64_t overflow_add2;
    int64_t overflow_sub1;
    int64_t overflow_sub2;
    int64_t overflow_mul1;
    int64_t overflow_mul2;
  };
  T t;

  FOR_INT64_INPUTS(i, overflow_int64_test_values) {
    FOR_INT64_INPUTS(j, overflow_int64_test_values) {
      int64_t ii = *i;
      int64_t jj = *j;
      int64_t expected_add, expected_sub;
      int32_t ii32 = static_cast<int32_t>(ii);
      int32_t jj32 = static_cast<int32_t>(jj);
      int32_t expected_mul;
      int64_t expected_add_ovf, expected_sub_ovf, expected_mul_ovf;
      MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
      MacroAssembler* masm = &assembler;

      __ ld_d(t0, a0, offsetof(T, lhs));
      __ ld_d(t1, a0, offsetof(T, rhs));

      __ AddOverflow_d(t2, t0, Operand(t1), t3);
      __ st_d(t2, a0, offsetof(T, output_add1));
      __ st_d(t3, a0, offsetof(T, overflow_add1));
      __ or_(t3, zero_reg, zero_reg);
      __ AddOverflow_d(t0, t0, Operand(t1), t3);
      __ st_d(t0, a0, offsetof(T, output_add2));
      __ st_d(t3, a0, offsetof(T, overflow_add2));

      __ ld_d(t0, a0, offsetof(T, lhs));
      __ ld_d(t1, a0, offsetof(T, rhs));

      __ SubOverflow_d(t2, t0, Operand(t1), t3);
      __ st_d(t2, a0, offsetof(T, output_sub1));
      __ st_d(t3, a0, offsetof(T, overflow_sub1));
      __ or_(t3, zero_reg, zero_reg);
      __ SubOverflow_d(t0, t0, Operand(t1), t3);
      __ st_d(t0, a0, offsetof(T, output_sub2));
      __ st_d(t3, a0, offsetof(T, overflow_sub2));

      __ ld_d(t0, a0, offsetof(T, lhs));
      __ ld_d(t1, a0, offsetof(T, rhs));
      __ slli_w(t0, t0, 0);
      __ slli_w(t1, t1, 0);

      __ MulOverflow_w(t2, t0, Operand(t1), t3);
      __ st_d(t2, a0, offsetof(T, output_mul1));
      __ st_d(t3, a0, offsetof(T, overflow_mul1));
      __ or_(t3, zero_reg, zero_reg);
      __ MulOverflow_w(t0, t0, Operand(t1), t3);
      __ st_d(t0, a0, offsetof(T, output_mul2));
      __ st_d(t3, a0, offsetof(T, overflow_mul2));

      __ jirl(zero_reg, ra, 0);

      CodeDesc desc;
      masm->GetCode(isolate, &desc);
      Handle<Code> code =
          Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
      auto f = GeneratedCode<F3>::FromCode(isolate, *code);
      t.lhs = ii;
      t.rhs = jj;
      f.Call(&t, 0, 0, 0, 0);

      expected_add_ovf = base::bits::SignedAddOverflow64(ii, jj, &expected_add);
      expected_sub_ovf = base::bits::SignedSubOverflow64(ii, jj, &expected_sub);
      expected_mul_ovf =
          base::bits::SignedMulOverflow32(ii32, jj32, &expected_mul);

      CHECK_EQ(expected_add_ovf, t.overflow_add1 < 0);
      CHECK_EQ(expected_sub_ovf, t.overflow_sub1 < 0);
      CHECK_EQ(expected_mul_ovf, t.overflow_mul1 != 0);

      CHECK_EQ(t.overflow_add1, t.overflow_add2);
      CHECK_EQ(t.overflow_sub1, t.overflow_sub2);
      CHECK_EQ(t.overflow_mul1, t.overflow_mul2);

      CHECK_EQ(expected_add, t.output_add1);
      CHECK_EQ(expected_add, t.output_add2);
      CHECK_EQ(expected_sub, t.output_sub1);
      CHECK_EQ(expected_sub, t.output_sub2);
      if (!expected_mul_ovf) {
        CHECK_EQ(expected_mul, t.output_mul1);
        CHECK_EQ(expected_mul, t.output_mul2);
      }
    }
  }
}

TEST(min_max_nan) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct TestFloat {
    double a;
    double b;
    double c;
    double d;
    float e;
    float f;
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
  double inputsa[kTableLength] = {dnan,  3.0,  -0.0, 0.0,  42.0, dinf, dminf,
                                  dinf, dnan, 3.0,  dinf, dnan, dnan};
  double inputsb[kTableLength] = {dnan,   2.0, 0.0,  -0.0, dinf, 42.0, dinf,
                                  dminf, 3.0, dnan, dnan, dinf, dnan};
  double outputsdmin[kTableLength] = {dnan,  2.0,   -0.0,  -0.0, 42.0,
                                      42.0, dminf, dminf, dnan, dnan,
                                      dnan, dnan,  dnan};
  double outputsdmax[kTableLength] = {dnan,  3.0,  0.0,  0.0,  dinf, dinf, dinf,
                                      dinf, dnan, dnan, dnan, dnan, dnan};

  float inputse[kTableLength] = {2.0,  3.0,  -0.0, 0.0,  42.0, finf, fminf,
                                 finf, fnan, 3.0,  finf, fnan, fnan};
  float inputsf[kTableLength] = {3.0,   2.0, 0.0,  -0.0, finf, 42.0, finf,
                                 fminf, 3.0, fnan, fnan, finf, fnan};
  float outputsfmin[kTableLength] = {2.0,   2.0,  -0.0, -0.0, 42.0, 42.0, fminf,
                                     fminf, fnan, fnan, fnan, fnan, fnan};
  float outputsfmax[kTableLength] = {3.0,  3.0,  0.0,  0.0,  finf, finf, finf,
                                     finf, fnan, fnan, fnan, fnan, fnan};

  // clang-format on
  auto handle_dnan = [masm](FPURegister dst, Label* nan, Label* back) {
    __ bind(nan);
    __ LoadRoot(t8, RootIndex::kNanValue);
    __ Fld_d(dst,
             FieldMemOperand(
                 t8, compiler::AccessBuilder::ForHeapNumberValue().offset));
    __ Branch(back);
  };

  auto handle_snan = [masm, fnan](FPURegister dst, Label* nan, Label* back) {
    __ bind(nan);
    __ Move(dst, fnan);
    __ Branch(back);
  };

  Label handle_mind_nan, handle_maxd_nan, handle_mins_nan, handle_maxs_nan;
  Label back_mind_nan, back_maxd_nan, back_mins_nan, back_maxs_nan;

  __ Push(s6);
#ifdef V8_COMPRESS_POINTERS
  __ Push(s8);
#endif
  __ InitializeRootRegister();
  __ Fld_d(f8, MemOperand(a0, offsetof(TestFloat, a)));
  __ Fld_d(f9, MemOperand(a0, offsetof(TestFloat, b)));
  __ Fld_s(f10, MemOperand(a0, offsetof(TestFloat, e)));
  __ Fld_s(f11, MemOperand(a0, offsetof(TestFloat, f)));
  __ Float64Min(f12, f8, f9, &handle_mind_nan);
  __ bind(&back_mind_nan);
  __ Float64Max(f13, f8, f9, &handle_maxd_nan);
  __ bind(&back_maxd_nan);
  __ Float32Min(f14, f10, f11, &handle_mins_nan);
  __ bind(&back_mins_nan);
  __ Float32Max(f15, f10, f11, &handle_maxs_nan);
  __ bind(&back_maxs_nan);
  __ Fst_d(f12, MemOperand(a0, offsetof(TestFloat, c)));
  __ Fst_d(f13, MemOperand(a0, offsetof(TestFloat, d)));
  __ Fst_s(f14, MemOperand(a0, offsetof(TestFloat, g)));
  __ Fst_s(f15, MemOperand(a0, offsetof(TestFloat, h)));
#ifdef V8_COMPRESS_POINTERS
  __ Pop(s8);
#endif
  __ Pop(s6);
  __ jirl(zero_reg, ra, 0);

  handle_dnan(f12, &handle_mind_nan, &back_mind_nan);
  handle_dnan(f13, &handle_maxd_nan, &back_maxd_nan);
  handle_snan(f14, &handle_mins_nan, &back_mins_nan);
  handle_snan(f15, &handle_maxs_nan, &back_maxs_nan);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  for (int i = 0; i < kTableLength; i++) {
    test.a = inputsa[i];
    test.b = inputsb[i];
    test.e = inputse[i];
    test.f = inputsf[i];

    f.Call(&test, 0, 0, 0, 0);
    CHECK_EQ(0, memcmp(&test.c, &outputsdmin[i], sizeof(test.c)));
    CHECK_EQ(0, memcmp(&test.d, &outputsdmax[i], sizeof(test.d)));
    CHECK_EQ(0, memcmp(&test.g, &outputsfmin[i], sizeof(test.g)));
    CHECK_EQ(0, memcmp(&test.h, &outputsfmax[i], sizeof(test.h)));
  }
}

template <typename IN_TYPE, typename Func>
bool run_Unaligned(char* memory_buffer, int32_t in_offset, int32_t out_offset,
                   IN_TYPE value, Func GenerateUnalignedInstructionFunc) {
  using F_CVT = int32_t(char* x0, int x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;
  IN_TYPE res;

  GenerateUnalignedInstructionFunc(masm, in_offset, out_offset);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);

  MemCopy(memory_buffer + in_offset, &value, sizeof(IN_TYPE));
  f.Call(memory_buffer, 0, 0, 0, 0);
  MemCopy(&res, memory_buffer + out_offset, sizeof(IN_TYPE));

  return res == value;
}

static const std::vector<uint64_t> unsigned_test_values() {
  // clang-format off
  static const uint64_t kValues[] = {
      0x2180F18A06384414, 0x000A714532102277, 0xBC1ACCCF180649F0,
      0x8000000080008000, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
  };
  // clang-format on
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset() {
  static const int32_t kValues[] = {// value, offset
                                    -132 * KB, -21 * KB, 0, 19 * KB, 135 * KB};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset_increment() {
  static const int32_t kValues[] = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(Ld_b) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_b(a2, MemOperand(a0, in_offset));
          __ St_b(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_b(a0, MemOperand(a0, in_offset));
          __ St_b(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_bu(a0, MemOperand(a0, in_offset));
          __ St_b(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_bu(a2, MemOperand(a0, in_offset));
          __ St_b(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_4));
      }
    }
  }
}

TEST(Ld_b_bitextension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ld_b(t0, MemOperand(a0, in_offset));
          __ Ld_bu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ srai_w(t0, t0, 7);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ srai_w(t1, t1, 7);
          __ Branch(&fail, ne, t1, Operand(1));
          __ srai_w(t0, t0, 7);
          __ addi_d(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ld_b(t0, MemOperand(a0, in_offset));
          __ St_b(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ St_b(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn));
      }
    }
  }
}

TEST(Ld_h) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_h(a2, MemOperand(a0, in_offset));
          __ St_h(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_h(a0, MemOperand(a0, in_offset));
          __ St_h(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_hu(a0, MemOperand(a0, in_offset));
          __ St_h(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_hu(a2, MemOperand(a0, in_offset));
          __ St_h(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_4));
      }
    }
  }
}

TEST(Ld_h_bitextension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ld_h(t0, MemOperand(a0, in_offset));
          __ Ld_hu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ srai_w(t0, t0, 15);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ srai_w(t1, t1, 15);
          __ Branch(&fail, ne, t1, Operand(1));
          __ srai_w(t0, t0, 15);
          __ addi_d(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ld_h(t0, MemOperand(a0, in_offset));
          __ St_h(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ St_h(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn));
      }
    }
  }
}

TEST(Ld_w) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint32_t value = static_cast<uint32_t>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_w(a2, MemOperand(a0, in_offset));
          __ St_w(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_w(a0, MemOperand(a0, in_offset));
          __ St_w(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true,
                 run_Unaligned<uint32_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_wu(a2, MemOperand(a0, in_offset));
          __ St_w(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_wu(a0, MemOperand(a0, in_offset));
          __ St_w(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true,
                 run_Unaligned<uint32_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_4));
      }
    }
  }
}

TEST(Ld_w_extension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint32_t value = static_cast<uint32_t>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ld_w(t0, MemOperand(a0, in_offset));
          __ Ld_wu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ srai_d(t0, t0, 31);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ srai_d(t1, t1, 31);
          __ Branch(&fail, ne, t1, Operand(1));
          __ srai_d(t0, t0, 31);
          __ addi_d(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ld_w(t0, MemOperand(a0, in_offset));
          __ St_w(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ St_w(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn));
      }
    }
  }
}

TEST(Ld_d) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint64_t value = *i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_d(a2, MemOperand(a0, in_offset));
          __ St_d(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint64_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_d(a0, MemOperand(a0, in_offset));
          __ St_d(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true,
                 run_Unaligned<uint64_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_2));
      }
    }
  }
}

TEST(Fld_s) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        float value = static_cast<float>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          __ Fld_s(f0, MemOperand(a0, in_offset));
          __ Fst_s(f0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<float>(buffer_middle, in_offset,
                                            out_offset, value, fn));
      }
    }
  }
}

TEST(Fld_d) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        double value = static_cast<double>(*i);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          __ Fld_d(f0, MemOperand(a0, in_offset));
          __ Fst_d(f0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<double>(buffer_middle, in_offset,
                                             out_offset, value, fn));
      }
    }
  }
}

static const std::vector<uint64_t> sltu_test_values() {
  // clang-format off
  static const uint64_t kValues[] = {
      0,
      1,
      0x7FE,
      0x7FF,
      0x800,
      0x801,
      0xFFE,
      0xFFF,
      0xFFFFFFFFFFFFF7FE,
      0xFFFFFFFFFFFFF7FF,
      0xFFFFFFFFFFFFF800,
      0xFFFFFFFFFFFFF801,
      0xFFFFFFFFFFFFFFFE,
      0xFFFFFFFFFFFFFFFF,
  };
  // clang-format on
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

template <typename Func>
bool run_Sltu(uint64_t rj, uint64_t rk, Func GenerateSltuInstructionFunc) {
  using F_CVT = int64_t(uint64_t x0, uint64_t x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;

  GenerateSltuInstructionFunc(masm, rk);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(rj, rk, 0, 0, 0));
  return res == 1;
}

TEST(Sltu) {
  CcTest::InitializeVM();

  FOR_UINT64_INPUTS(i, sltu_test_values) {
    FOR_UINT64_INPUTS(j, sltu_test_values) {
      uint64_t rj = *i;
      uint64_t rk = *j;

      auto fn_1 = [](MacroAssembler* masm, uint64_t imm) {
        __ Sltu(a2, a0, Operand(imm));
      };
      CHECK_EQ(rj < rk, run_Sltu(rj, rk, fn_1));

      auto fn_2 = [](MacroAssembler* masm, uint64_t imm) {
        __ Sltu(a2, a0, a1);
      };
      CHECK_EQ(rj < rk, run_Sltu(rj, rk, fn_2));
    }
  }
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F4> GenerateMacroFloat32MinMax(MacroAssembler* masm) {
  T a = T::from_code(8);   // f8
  T b = T::from_code(9);   // f9
  T c = T::from_code(10);  // f10

  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

#define FLOAT_MIN_MAX(fminmax, res, x, y, done, ool, res_field) \
  __ Fld_s(x, MemOperand(a0, offsetof(Inputs, src1_)));         \
  __ Fld_s(y, MemOperand(a0, offsetof(Inputs, src2_)));         \
  __ fminmax(res, x, y, &ool);                                  \
  __ bind(&done);                                               \
  __ Fst_s(a, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float32Min, a, b, c, done_min_abc, ool_min_abc, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float32Min, a, a, b, done_min_aab, ool_min_aab, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float32Min, a, b, a, done_min_aba, ool_min_aba, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float32Max, a, b, c, done_max_abc, ool_max_abc, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float32Max, a, a, b, done_max_aab, ool_max_aab, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float32Max, a, b, a, done_max_aba, ool_max_aba, max_aba_);

#undef FLOAT_MIN_MAX

  __ jirl(zero_reg, ra, 0);

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ Float32MinOutOfLine(a, b, c);
  __ Branch(&done_min_abc);

  __ bind(&ool_min_aab);
  __ Float32MinOutOfLine(a, a, b);
  __ Branch(&done_min_aab);

  __ bind(&ool_min_aba);
  __ Float32MinOutOfLine(a, b, a);
  __ Branch(&done_min_aba);

  __ bind(&ool_max_abc);
  __ Float32MaxOutOfLine(a, b, c);
  __ Branch(&done_max_abc);

  __ bind(&ool_max_aab);
  __ Float32MaxOutOfLine(a, a, b);
  __ Branch(&done_max_aab);

  __ bind(&ool_max_aba);
  __ Float32MaxOutOfLine(a, b, a);
  __ Branch(&done_max_aba);

  CodeDesc desc;
  masm->GetCode(masm->isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(masm->isolate(), desc, CodeKind::FOR_TESTING)
          .Build();
#ifdef DEBUG
  Print(*code);
#endif
  return GeneratedCode<F4>::FromCode(masm->isolate(), *code);
}

TEST(macro_float_minmax_f32) {
  // Test the Float32Min and Float32Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Inputs {
    float src1_;
    float src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  GeneratedCode<F4> f =
      GenerateMacroFloat32MinMax<FPURegister, Inputs, Results>(masm);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  float nan_a = std::numeric_limits<float>::quiet_NaN();
  float nan_b = std::numeric_limits<float>::quiet_NaN();

  CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(0.0f, -1.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
  CHECK_MINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
  CHECK_MINMAX(0.0f, 1.0f, 0.0f, 1.0f);
  CHECK_MINMAX(1.0f, 0.0f, 0.0f, 1.0f);

  CHECK_MINMAX(0.0f, 0.0f, 0.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
  CHECK_MINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
  CHECK_MINMAX(0.0f, -0.0f, -0.0f, 0.0f);

  CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0f, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F4> GenerateMacroFloat64MinMax(MacroAssembler* masm) {
  T a = T::from_code(8);   // f8
  T b = T::from_code(9);   // f9
  T c = T::from_code(10);  // f10

  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

#define FLOAT_MIN_MAX(fminmax, res, x, y, done, ool, res_field) \
  __ Fld_d(x, MemOperand(a0, offsetof(Inputs, src1_)));         \
  __ Fld_d(y, MemOperand(a0, offsetof(Inputs, src2_)));         \
  __ fminmax(res, x, y, &ool);                                  \
  __ bind(&done);                                               \
  __ Fst_d(a, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float64Min, a, b, c, done_min_abc, ool_min_abc, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float64Min, a, a, b, done_min_aab, ool_min_aab, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float64Min, a, b, a, done_min_aba, ool_min_aba, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float64Max, a, b, c, done_max_abc, ool_max_abc, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float64Max, a, a, b, done_max_aab, ool_max_aab, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float64Max, a, b, a, done_max_aba, ool_max_aba, max_aba_);

#undef FLOAT_MIN_MAX

  __ jirl(zero_reg, ra, 0);

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ Float64MinOutOfLine(a, b, c);
  __ Branch(&done_min_abc);

  __ bind(&ool_min_aab);
  __ Float64MinOutOfLine(a, a, b);
  __ Branch(&done_min_aab);

  __ bind(&ool_min_aba);
  __ Float64MinOutOfLine(a, b, a);
  __ Branch(&done_min_aba);

  __ bind(&ool_max_abc);
  __ Float64MaxOutOfLine(a, b, c);
  __ Branch(&done_max_abc);

  __ bind(&ool_max_aab);
  __ Float64MaxOutOfLine(a, a, b);
  __ Branch(&done_max_aab);

  __ bind(&ool_max_aba);
  __ Float64MaxOutOfLine(a, b, a);
  __ Branch(&done_max_aba);

  CodeDesc desc;
  masm->GetCode(masm->isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(masm->isolate(), desc, CodeKind::FOR_TESTING)
          .Build();
#ifdef DEBUG
  Print(*code);
#endif
  return GeneratedCode<F4>::FromCode(masm->isolate(), *code);
}

TEST(macro_float_minmax_f64) {
  // Test the Float64Min and Float64Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Inputs {
    double src1_;
    double src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  GeneratedCode<F4> f =
      GenerateMacroFloat64MinMax<DoubleRegister, Inputs, Results>(masm);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  double nan_a = std::numeric_limits<double>::quiet_NaN();
  double nan_b = std::numeric_limits<double>::quiet_NaN();

  CHECK_MINMAX(1.0, -1.0, -1.0, 1.0);
  CHECK_MINMAX(-1.0, 1.0, -1.0, 1.0);
  CHECK_MINMAX(0.0, -1.0, -1.0, 0.0);
  CHECK_MINMAX(-1.0, 0.0, -1.0, 0.0);
  CHECK_MINMAX(-0.0, -1.0, -1.0, -0.0);
  CHECK_MINMAX(-1.0, -0.0, -1.0, -0.0);
  CHECK_MINMAX(0.0, 1.0, 0.0, 1.0);
  CHECK_MINMAX(1.0, 0.0, 0.0, 1.0);

  CHECK_MINMAX(0.0, 0.0, 0.0, 0.0);
  CHECK_MINMAX(-0.0, -0.0, -0.0, -0.0);
  CHECK_MINMAX(-0.0, 0.0, -0.0, 0.0);
  CHECK_MINMAX(0.0, -0.0, -0.0, 0.0);

  CHECK_MINMAX(0.0, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

uint64_t run_Sub_w(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label code_start;
  __ bind(&code_start);
  __ Sub_w(a2, zero_reg, Operand(imm));
  CHECK_EQ(masm->InstructionsGeneratedSince(&code_start), num_instr);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(SUB_W) {
  CcTest::InitializeVM();

  // Test Subu macro-instruction for min_int12 and max_int12 border cases.
  // For subtracting int16 immediate values we use addiu.

  struct TestCaseSub {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Sub_w(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSub tc[] = {
      //              imm, expected_res, num_instr
      {0xFFFFFFFFFFFFF800,        0x800,         2},  // min_int12
      // The test case above generates ori + add_w instruction sequence.
      // We can't have just addi_ because -min_int12 > max_int12 so use
      // register. We can load min_int12 to at register with addi_w and then
      // subtract at with sub_w, but now we use ori + add_w because -min_int12
      // can be loaded using ori.
      {0x800,        0xFFFFFFFFFFFFF800,         1},  // max_int12 + 1
      // Generates addi_w
      // max_int12 + 1 is not int12 but -(max_int12 + 1) is, just use addi_w.
      {0xFFFFFFFFFFFFF7FF,        0x801,         2},  // min_int12 - 1
      // Generates ori + add_w
      // To load this value to at we need two instructions and another one to
      // subtract, lu12i + ori + sub_w. But we can load -value to at using just
      // ori and then add at register with add_w.
      {0x801,        0xFFFFFFFFFFFFF7FF,         2},  // max_int12 + 2
      // Generates ori + sub_w
      // Not int12 but is uint12, load value to at with ori and subtract with
      // sub_w.
      {0x00010000,   0xFFFFFFFFFFFF0000,         2},
      // Generates lu12i_w + sub_w
      // Load value using lui to at and subtract with subu.
      {0x00010001,   0xFFFFFFFFFFFEFFFF,         3},
      // Generates lu12i + ori + sub_w
      // We have to generate three instructions in this case.
      {0x7FFFFFFF,   0xFFFFFFFF80000001,         3},  // max_int32
      // Generates lu12i_w + ori + sub_w
      {0xFFFFFFFF80000000, 0xFFFFFFFF80000000,   2},  // min_int32
      // The test case above generates lu12i + sub_w intruction sequence.
      // The result of 0 - min_int32 eqauls max_int32 + 1, which wraps around to
      // min_int32 again.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseSub);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Sub_w(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Sub_d(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label code_start;
  __ bind(&code_start);
  __ Sub_d(a2, zero_reg, Operand(imm));
  CHECK_EQ(masm->InstructionsGeneratedSince(&code_start), num_instr);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(SUB_D) {
  CcTest::InitializeVM();

  // Test Sub_d macro-instruction for min_int12 and max_int12 border cases.
  // For subtracting int12 immediate values we use addi_d.

  struct TestCaseSub {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };
  // We call Sub(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSub tc[] = {
      //              imm,       expected_res,  num_instr
      {0xFFFFFFFFFFFFF800,              0x800,         2},  // min_int12
      // The test case above generates addi_d instruction.
      // This is int12 value and we can load it using just addi_d.
      {             0x800, 0xFFFFFFFFFFFFF800,         1},  // max_int12 + 1
      // Generates addi_d
      // max_int12 + 1 is not int12 but is uint12, just
```