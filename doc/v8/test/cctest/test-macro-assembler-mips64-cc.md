Response:
The user wants a summary of the provided C++ code, which is a V8 test file for the MIPS64 architecture's macro assembler.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `test-macro-assembler-mips64.cc` and the import of `macro-assembler.h` strongly suggest this file tests the functionality of the MIPS64 macro assembler in V8. The `TEST(...)` macros confirm it's a unit test file.

2. **Examine the included headers:** The headers provide clues about the functionalities being tested:
    * `assembler-inl.h`, `macro-assembler.h`: Core assembly generation.
    * `codegen/`: General code generation aspects.
    * `compiler/`, `deoptimizer/`:  More complex code generation and optimization-related features, suggesting tests for more advanced assembler capabilities.
    * `execution/simulator.h`: Hints at the ability to run the generated code within a simulator, which is common for testing assembly code.
    * `objects/objects-inl.h`: Interaction with V8's object model, likely involving assembly instructions that manipulate V8 objects.
    * `test/cctest/cctest.h`, `test/common/assembler-tester.h`:  V8's testing framework.

3. **Analyze the `TEST(...)` blocks:**  Each `TEST(...)` block represents a specific test case. Look for the operations performed within each test:
    * **`BYTESWAP`:** Tests byte swapping instructions (`ByteSwapSigned`, `ByteSwapUnsigned`).
    * **`LoadConstants`:**  Tests loading immediate values into registers (`li`).
    * **`LoadAddress`:** Tests loading the address of a label into a register. This likely involves PC-relative addressing.
    * **`jump_tables4`, `jump_tables5`, `jump_tables6`:** These test the generation of jump tables (`GenerateSwitchTable`), potentially involving branch trampolines for handling large offsets. The comments mention regression tests for specific V8 issues.
    * **`Lsa`, `Dlsa`:**  Test the "Load Scaled Address" instructions.
    * **`Cvt_s_uw_Trunc_uw_s`, `Cvt_s_ul_Trunc_ul_s`, `Cvt_d_ul_Trunc_ul_d`, `cvt_d_l_Trunc_l_d`, `cvt_d_l_Trunc_l_ud`, `cvt_d_w_Trunc_w_d`:** These test floating-point conversion and truncation instructions.
    * **`OverflowInstructions`:** Tests instructions that detect arithmetic overflow (`DaddOverflow`, `DsubOverflow`, `MulOverflow`).
    * **`min_max_nan`:** Tests floating-point min/max instructions, paying attention to NaN handling.

4. **Infer overall functionality:** Based on the individual tests, the file's primary function is to verify the correctness of various MIPS64 assembly instructions as implemented in V8's macro assembler. This includes:
    * Basic data manipulation (byte swapping).
    * Loading constants and addresses.
    * Control flow (jumps, branches, jump tables).
    * Arithmetic operations with overflow detection.
    * Floating-point conversions, truncation, and min/max operations.

5. **Address specific questions:**
    * **`.tq` suffix:** The code explicitly checks for this. The answer is "No".
    * **Relationship to JavaScript:**  Macro assemblers are used in JIT compilers to generate native machine code from JavaScript. The tested instructions are fundamental to implementing JavaScript operations efficiently.
    * **Code logic reasoning (example: `BYTESWAP`):** Explain the input, the assembly instructions' purpose, and the expected output.
    * **Common programming errors:**  Relate the tested instructions to potential pitfalls like endianness issues (byte swapping) or incorrect address calculations (load address, Lsa/Dlsa).

6. **Structure the summary:** Organize the information logically, starting with the main purpose and then detailing the specific functionalities tested. Address each of the user's explicit questions.

7. **Review and refine:** Ensure the summary is accurate, clear, and concise. Check for any missing information or areas that could be explained better. For example, explicitly mention that this is *testing* the assembler, not *using* it for core V8 functionality directly. Emphasize the architecture-specific nature of the tests.
```cpp
// Copyright 2013 the V8 project authors. All rights reserved.
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

// TODO(mips64): Refine these signatures per test case.
using FV = void*(int64_t x, int64_t y, int p2, int p3, int p4);
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ masm->

TEST(BYTESWAP) {
  DCHECK(kArchVariant == kMips64r6 || kArchVariant == kMips64r2);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t s8;
    uint64_t s4;
    uint64_t s2;
    uint64_t u4;
    uint64_t u2;
  };

  T t;
  uint64_t test_values[] = {0x5612FFCD9D327ACC,
                            0x781A15C3,
                            0xFCDE,
                            0x9F,
                            0xC81A15C3,
                            0x8000000000000000,
                            0xFFFFFFFFFFFFFFFF,
                            0x0000000080000000,
                            0x0000000000008000};

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);

  MacroAssembler* masm = &assembler;

  __ Ld(a4, MemOperand(a0, offsetof(T, s8)));
  __ nop();
  __ ByteSwapSigned(a4, a4, 8);
  __ Sd(a4, MemOperand(a0, offsetof(T, s8)));

  __ Ld(a4, MemOperand(a0, offsetof(T, s4)));
  __ nop();
  __ ByteSwapSigned(a4, a4, 4);
  __ Sd(a4, MemOperand(a0, offsetof(T, s4)));

  __ Ld(a4, MemOperand(a0, offsetof(T, s2)));
  __ nop();
  __ ByteSwapSigned(a4, a4, 2);
  __ Sd(a4, MemOperand(a0, offsetof(T, s2)));

  __ Ld(a4, MemOperand(a0, offsetof(T, u4)));
  __ nop();
  __ ByteSwapUnsigned(a4, a4, 4);
  __ Sd(a4, MemOperand(a0, offsetof(T, u4)));

  __ Ld(a4, MemOperand(a0, offsetof(T, u2)));
  __ nop();
  __ ByteSwapUnsigned(a4, a4, 2);
  __ Sd(a4, MemOperand(a0, offsetof(T, u2)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  for (size_t i = 0; i < arraysize(test_values); i++) {
    int32_t in_s4 = static_cast<int32_t>(test_values[i]);
    int16_t in_s2 = static_cast<int16_t>(test_values[i]);
    uint32_t in_u4 = static_cast<uint32_t>(test_values[i]);
    uint16_t in_u2 = static_cast<uint16_t>(test_values[i]);

    t.s8 = test_values[i];
    t.s4 = static_cast<uint64_t>(in_s4);
    t.s2 = static_cast<uint64_t>(in_s2);
    t.u4 = static_cast<uint64_t>(in_u4);
    t.u2 = static_cast<uint64_t>(in_u2);

    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(ByteReverse<uint64_t>(test_values[i]), t.s8);
    CHECK_EQ(ByteReverse<int32_t>(in_s4), static_cast<int32_t>(t.s4));
    CHECK_EQ(ByteReverse<int16_t>(in_s2), static_cast<int16_t>(t.s2));
    CHECK_EQ(ByteReverse<uint32_t>(in_u4), static_cast<uint32_t>(t.u4));
    CHECK_EQ(ByteReverse<uint16_t>(in_u2), static_cast<uint16_t>(t.u2));
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

  __ mov(a4, a0);
  for (int i = 0; i < 64; i++) {
    // Load constant.
    __ li(a5, Operand(refConstants[i]));
    __ Sd(a5, MemOperand(a4));
    __ Daddu(a4, a4, Operand(kPointerSize));
  }

  __ jr(ra);
  __ nop();

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

TEST(LoadAddress) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;
  Label to_jump, skip;
  __ mov(a4, a0);

  __ Branch(&skip);
  __ bind(&to_jump);
  __ nop();
  __ nop();
  __ jr(ra);
  __ nop();
  __ bind(&skip);
  __ li(a4, Operand(masm->jump_address(&to_jump)), ADDRESS_LOAD);
  int check_size = masm->InstructionsGeneratedSince(&skip);
  CHECK_EQ(4, check_size);
  __ jr(a4);
  __ nop();
  __ stop();
  __ stop();
  __ stop();
  __ stop();
  __ stop();

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);
  (void)f.Call(0, 0, 0, 0, 0);
  // Check results.
}

TEST(jump_tables4) {
  // Similar to test-assembler-mips jump_tables1, with extra test for branch
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
  __ mov(v0, zero_reg);

  __ Branch(&end);
  __ bind(&near_start);

  // Generate slightly less than 32K instructions, which will soon require
  // trampoline for branch distance fixup.
  for (int i = 0; i < 32768 - 256; ++i) {
    __ addiu(v0, v0, 1);
  }

  __ GenerateSwitchTable(a0, kNumCases,
                         [&labels](size_t i) { return labels + i; });

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ li(v0, values[i]);
    __ Branch(&done);
  }

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

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

TEST(jump_tables5) {
  if (kArchVariant != kMips64r6) return;

  // Similar to test-assembler-mips jump_tables1, with extra test for emitting a
  // compact branch instruction before emission of the dd table.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];
  Label done;

  __ Push(ra);

  // Opposite of Align(8) as we have unaligned number of instructions in the
  // following block before the first dd().
  if ((masm->pc_offset() & 7) == 0) {
    __ nop();
  }

  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6 + 1);

    __ addiupc(at, 6 + 1);
    __ Dlsa(at, at, a0, 3);
    __ Ld(at, MemOperand(at));
    __ jalr(at);
    __ nop();  // Branch delay slot nop.
    __ bc(&done);
    // A nop instruction must be generated by the forbidden slot guard
    // (Assembler::dd(Label*)) so the first label goes to an 8 bytes aligned
    // location.
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ li(v0, values[i]);
    __ jr(ra);
    __ nop();
  }

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

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
  // Similar to test-assembler-mips jump_tables1, with extra test for branch
  // trampoline required after emission of the dd table (where trampolines are
  // blocked). This test checks if number of really generated instructions is
  // greater than number of counted instructions from code, as we are expecting
  // generation of trampoline in this case (when number of kFillInstr
  // instructions is close to 32K)
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kSwitchTableCases = 40;

  const int kMaxBranchOffset = Assembler::kMaxBranchOffset;
  const int kTrampolineSlotsSize = Assembler::kTrampolineSlotsSize;
  const int kSwitchTablePrologueSize = MacroAssembler::kSwitchTablePrologueSize;

  const int kMaxOffsetForTrampolineStart =
      kMaxBranchOffset - 16 * kTrampolineSlotsSize;
  const int kFillInstr = (kMaxOffsetForTrampolineStart / kInstrSize) -
                         (kSwitchTablePrologueSize + 2 * kSwitchTableCases) -
                         20;

  int values[kSwitchTableCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kSwitchTableCases];
  Label near_start, end, done;

  __ Push(ra);
  __ mov(v0, zero_reg);

  int offs1 = masm->pc_offset();
  int gen_insn = 0;

  __ Branch(&end);
  gen_insn += Assembler::IsCompactBranchSupported() ? 1 : 2;
  __ bind(&near_start);

  // Generate slightly less than 32K instructions, which will soon require
  // trampoline for branch distance fixup.
  for (int i = 0; i < kFillInstr; ++i) {
    __ addiu(v0, v0, 1);
  }
  gen_insn += kFillInstr;

  __ GenerateSwitchTable(a0, kSwitchTableCases,
                         [&labels](size_t i) { return labels + i; });
  gen_insn += (kSwitchTablePrologueSize + 2 * kSwitchTableCases);

  for (int i = 0; i < kSwitchTableCases; ++i) {
    __ bind(&labels[i]);
    __ li(v0, values[i]);
    __ Branch(&done);
  }
  gen_insn +=
      ((Assembler::IsCompactBranchSupported() ? 3 : 4) * kSwitchTableCases);

  // If offset from here to first branch instr is greater than max allowed
  // offset for trampoline ...
  CHECK_LT(kMaxOffsetForTrampolineStart, masm->pc_offset() - offs1);
  // ... number of generated instructions must be greater then "gen_insn",
  // as we are expecting trampoline generation
  CHECK_LT(gen_insn, (masm->pc_offset() - offs1) / kInstrSize);

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

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

static uint64_t run_lsa(uint32_t rt, uint32_t rs, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Lsa(v0, a0, a1, sa);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rt, rs, 0, 0, 0));

  return res;
}

TEST(Lsa) {
  CcTest::InitializeVM();
  struct TestCaseLsa {
    int32_t rt;
    int32_t rs;
    uint8_t sa;
    uint64_t expected_res;
  };

  struct TestCaseLsa tc[] = {// rt, rs, sa, expected_res
                             {0x4, 0x1, 1, 0x6},
                             {0x4, 0x1, 2, 0x8},
                             {0x4, 0x1, 3, 0xC},
                             {0x4, 0x1, 4, 0x14},
                             {0x4, 0x1, 5, 0x24},
                             {0x0, 0x1, 1, 0x2},
                             {0x0, 0x1, 2, 0x4},
                             {0x0, 0x1, 3, 0x8},
                             {0x0, 0x1, 4, 0x10},
                             {0x0, 0x1, 5, 0x20},
                             {0x4, 0x0, 1, 0x4},
                             {0x4, 0x0, 2, 0x4},
                             {0x4, 0x0, 3, 0x4},
                             {0x4, 0x0, 4, 0x4},
                             {0x4, 0x0, 5, 0x4},

                             // Shift overflow.
                             {0x4, INT32_MAX, 1, 0x2},
                             {0x4, INT32_MAX >> 1, 2, 0x0},
                             {0x4, INT32_MAX >> 2, 3, 0xFFFFFFFFFFFFFFFC},
                             {0x4, INT32_MAX >> 3, 4, 0xFFFFFFFFFFFFFFF4},
                             {0x4, INT32_MAX >> 4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {INT32_MAX - 1, 0x1, 1, 0xFFFFFFFF80000000},
                             {INT32_MAX - 3, 0x1, 2, 0xFFFFFFFF80000000},
                             {INT32_MAX - 7, 0x1, 3, 0xFFFFFFFF80000000},
                             {INT32_MAX - 15, 0x1, 4, 0xFFFFFFFF80000000},
                             {INT32_MAX - 31, 0x1, 5, 0xFFFFFFFF80000000},

                             // Addition overflow.
                             {-2, 0x1, 1, 0x0},
                             {-4, 0x1, 2, 0x0},
                             {-8, 0x1, 3, 0x0},
                             {-16, 0x1, 4, 0x0},
                             {-32, 0x1, 5, 0x0}};

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLsa);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_lsa(tc[i].rt, tc[i].rs, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Lsa(v0, %x, %x, %hhu)\n",
           tc[i].expected_res, res, tc[i].rt, tc[i].rs, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

static uint64_t run_dlsa(uint64_t rt, uint64_t rs, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Dlsa(v0, a0, a1, sa);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rt, rs, 0, 0, 0));

  return res;
}

TEST(Dlsa) {
  CcTest::InitializeVM();
  struct TestCaseLsa {
    int64_t rt;
    int64_t rs;
    uint8_t sa;
    uint64_t expected_res;
  };

  struct TestCaseLsa tc[] = {// rt, rs, sa, expected_res
                             {0x4, 0x1, 1, 0x6},
                             {0x4, 0x1, 2, 0x8},
                             {0x4, 0x1, 3, 0xC},
                             {0x4, 0x1, 4, 0x14},
                             {0x4, 0x1, 5, 0x24},
                             {0x0, 0x1, 1, 0x2},
                             {0x0, 0x1, 2, 0x4},
                             {0x0, 0x1, 3, 0x8},
                             {0x0, 0x1, 4, 0x10},
                             {0x0, 0x1, 5, 0x20},
                             {0x4, 0x0, 1, 0x4},
                             {0x4, 0x0, 2, 0x4},
                             {0x4, 0x0, 3, 0x4},
                             {0x4, 0x0, 4, 0x4},
                             {0x4, 0x0, 5, 0x4},

                             // Shift overflow.
                             {0x4, INT64_MAX, 1, 0x2},
                             {0x4, INT64_MAX >> 1, 2, 0x0},
                             {0x4, INT64_MAX >> 2, 3, 0xFFFFFFFFFFFFFFFC},
                             {0x4, INT64_MAX >> 3, 4, 0xFFFFFFFFFFFFFFF4},
                             {0x4, INT64_MAX >> 4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {INT64_MAX - 1, 0x1, 1, 0x8000000000000000},
                             {INT64_MAX - 3, 0x1, 2, 0x8000000000000000},
                             {INT64_MAX - 7, 0x1, 3, 0x8000000000000000},
                             {INT64_MAX - 15, 0x1, 4, 0x8000000000000000},
                             {INT64_MAX - 31, 0x1, 5, 0x8000000000000000},

                             // Addition overflow.
                             {-2, 0x1, 1, 0x0},
                             {-4, 0x1, 2, 0x0},
                             {-8, 0x1, 3, 0x0},
                             {-16, 0x1, 4, 0x0},
                             {-32, 0x1, 5, 0x0}};

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLsa);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_dlsa(tc[i].rt, tc[i].rs, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Dlsa(v0, %" PRIx64 ", %" PRIx64
           ", %hhu)\n",
           tc[i].expected_res, res, tc[i].rt, tc[i].rs, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

static const std
Prompt: 
```
这是目录为v8/test/cctest/test-macro-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
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

// TODO(mips64): Refine these signatures per test case.
using FV = void*(int64_t x, int64_t y, int p2, int p3, int p4);
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ masm->

TEST(BYTESWAP) {
  DCHECK(kArchVariant == kMips64r6 || kArchVariant == kMips64r2);
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint64_t s8;
    uint64_t s4;
    uint64_t s2;
    uint64_t u4;
    uint64_t u2;
  };

  T t;
  uint64_t test_values[] = {0x5612FFCD9D327ACC,
                            0x781A15C3,
                            0xFCDE,
                            0x9F,
                            0xC81A15C3,
                            0x8000000000000000,
                            0xFFFFFFFFFFFFFFFF,
                            0x0000000080000000,
                            0x0000000000008000};

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);

  MacroAssembler* masm = &assembler;

  __ Ld(a4, MemOperand(a0, offsetof(T, s8)));
  __ nop();
  __ ByteSwapSigned(a4, a4, 8);
  __ Sd(a4, MemOperand(a0, offsetof(T, s8)));

  __ Ld(a4, MemOperand(a0, offsetof(T, s4)));
  __ nop();
  __ ByteSwapSigned(a4, a4, 4);
  __ Sd(a4, MemOperand(a0, offsetof(T, s4)));

  __ Ld(a4, MemOperand(a0, offsetof(T, s2)));
  __ nop();
  __ ByteSwapSigned(a4, a4, 2);
  __ Sd(a4, MemOperand(a0, offsetof(T, s2)));

  __ Ld(a4, MemOperand(a0, offsetof(T, u4)));
  __ nop();
  __ ByteSwapUnsigned(a4, a4, 4);
  __ Sd(a4, MemOperand(a0, offsetof(T, u4)));

  __ Ld(a4, MemOperand(a0, offsetof(T, u2)));
  __ nop();
  __ ByteSwapUnsigned(a4, a4, 2);
  __ Sd(a4, MemOperand(a0, offsetof(T, u2)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  for (size_t i = 0; i < arraysize(test_values); i++) {
    int32_t in_s4 = static_cast<int32_t>(test_values[i]);
    int16_t in_s2 = static_cast<int16_t>(test_values[i]);
    uint32_t in_u4 = static_cast<uint32_t>(test_values[i]);
    uint16_t in_u2 = static_cast<uint16_t>(test_values[i]);

    t.s8 = test_values[i];
    t.s4 = static_cast<uint64_t>(in_s4);
    t.s2 = static_cast<uint64_t>(in_s2);
    t.u4 = static_cast<uint64_t>(in_u4);
    t.u2 = static_cast<uint64_t>(in_u2);

    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(ByteReverse<uint64_t>(test_values[i]), t.s8);
    CHECK_EQ(ByteReverse<int32_t>(in_s4), static_cast<int32_t>(t.s4));
    CHECK_EQ(ByteReverse<int16_t>(in_s2), static_cast<int16_t>(t.s2));
    CHECK_EQ(ByteReverse<uint32_t>(in_u4), static_cast<uint32_t>(t.u4));
    CHECK_EQ(ByteReverse<uint16_t>(in_u2), static_cast<uint16_t>(t.u2));
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

  __ mov(a4, a0);
  for (int i = 0; i < 64; i++) {
    // Load constant.
    __ li(a5, Operand(refConstants[i]));
    __ Sd(a5, MemOperand(a4));
    __ Daddu(a4, a4, Operand(kPointerSize));
  }

  __ jr(ra);
  __ nop();

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


TEST(LoadAddress) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;
  Label to_jump, skip;
  __ mov(a4, a0);

  __ Branch(&skip);
  __ bind(&to_jump);
  __ nop();
  __ nop();
  __ jr(ra);
  __ nop();
  __ bind(&skip);
  __ li(a4, Operand(masm->jump_address(&to_jump)), ADDRESS_LOAD);
  int check_size = masm->InstructionsGeneratedSince(&skip);
  CHECK_EQ(4, check_size);
  __ jr(a4);
  __ nop();
  __ stop();
  __ stop();
  __ stop();
  __ stop();
  __ stop();


  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);
  (void)f.Call(0, 0, 0, 0, 0);
  // Check results.
}


TEST(jump_tables4) {
  // Similar to test-assembler-mips jump_tables1, with extra test for branch
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
  __ mov(v0, zero_reg);

  __ Branch(&end);
  __ bind(&near_start);

  // Generate slightly less than 32K instructions, which will soon require
  // trampoline for branch distance fixup.
  for (int i = 0; i < 32768 - 256; ++i) {
    __ addiu(v0, v0, 1);
  }

  __ GenerateSwitchTable(a0, kNumCases,
                         [&labels](size_t i) { return labels + i; });

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ li(v0, values[i]);
    __ Branch(&done);
  }

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

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


TEST(jump_tables5) {
  if (kArchVariant != kMips64r6) return;

  // Similar to test-assembler-mips jump_tables1, with extra test for emitting a
  // compact branch instruction before emission of the dd table.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kNumCases = 512;
  int values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kNumCases];
  Label done;

  __ Push(ra);

  // Opposite of Align(8) as we have unaligned number of instructions in the
  // following block before the first dd().
  if ((masm->pc_offset() & 7) == 0) {
    __ nop();
  }

  {
    __ BlockTrampolinePoolFor(kNumCases * 2 + 6 + 1);

    __ addiupc(at, 6 + 1);
    __ Dlsa(at, at, a0, 3);
    __ Ld(at, MemOperand(at));
    __ jalr(at);
    __ nop();  // Branch delay slot nop.
    __ bc(&done);
    // A nop instruction must be generated by the forbidden slot guard
    // (Assembler::dd(Label*)) so the first label goes to an 8 bytes aligned
    // location.
    for (int i = 0; i < kNumCases; ++i) {
      __ dd(&labels[i]);
    }
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ bind(&labels[i]);
    __ li(v0, values[i]);
    __ jr(ra);
    __ nop();
  }

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

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
  // Similar to test-assembler-mips jump_tables1, with extra test for branch
  // trampoline required after emission of the dd table (where trampolines are
  // blocked). This test checks if number of really generated instructions is
  // greater than number of counted instructions from code, as we are expecting
  // generation of trampoline in this case (when number of kFillInstr
  // instructions is close to 32K)
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  const int kSwitchTableCases = 40;

  const int kMaxBranchOffset = Assembler::kMaxBranchOffset;
  const int kTrampolineSlotsSize = Assembler::kTrampolineSlotsSize;
  const int kSwitchTablePrologueSize = MacroAssembler::kSwitchTablePrologueSize;

  const int kMaxOffsetForTrampolineStart =
      kMaxBranchOffset - 16 * kTrampolineSlotsSize;
  const int kFillInstr = (kMaxOffsetForTrampolineStart / kInstrSize) -
                         (kSwitchTablePrologueSize + 2 * kSwitchTableCases) -
                         20;

  int values[kSwitchTableCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  Label labels[kSwitchTableCases];
  Label near_start, end, done;

  __ Push(ra);
  __ mov(v0, zero_reg);

  int offs1 = masm->pc_offset();
  int gen_insn = 0;

  __ Branch(&end);
  gen_insn += Assembler::IsCompactBranchSupported() ? 1 : 2;
  __ bind(&near_start);

  // Generate slightly less than 32K instructions, which will soon require
  // trampoline for branch distance fixup.
  for (int i = 0; i < kFillInstr; ++i) {
    __ addiu(v0, v0, 1);
  }
  gen_insn += kFillInstr;

  __ GenerateSwitchTable(a0, kSwitchTableCases,
                         [&labels](size_t i) { return labels + i; });
  gen_insn += (kSwitchTablePrologueSize + 2 * kSwitchTableCases);

  for (int i = 0; i < kSwitchTableCases; ++i) {
    __ bind(&labels[i]);
    __ li(v0, values[i]);
    __ Branch(&done);
  }
  gen_insn +=
      ((Assembler::IsCompactBranchSupported() ? 3 : 4) * kSwitchTableCases);

  // If offset from here to first branch instr is greater than max allowed
  // offset for trampoline ...
  CHECK_LT(kMaxOffsetForTrampolineStart, masm->pc_offset() - offs1);
  // ... number of generated instructions must be greater then "gen_insn",
  // as we are expecting trampoline generation
  CHECK_LT(gen_insn, (masm->pc_offset() - offs1) / kInstrSize);

  __ bind(&done);
  __ Pop(ra);
  __ jr(ra);
  __ nop();

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

static uint64_t run_lsa(uint32_t rt, uint32_t rs, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Lsa(v0, a0, a1, sa);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F1>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rt, rs, 0, 0, 0));

  return res;
}


TEST(Lsa) {
  CcTest::InitializeVM();
  struct TestCaseLsa {
    int32_t rt;
    int32_t rs;
    uint8_t sa;
    uint64_t expected_res;
  };

  struct TestCaseLsa tc[] = {// rt, rs, sa, expected_res
                             {0x4, 0x1, 1, 0x6},
                             {0x4, 0x1, 2, 0x8},
                             {0x4, 0x1, 3, 0xC},
                             {0x4, 0x1, 4, 0x14},
                             {0x4, 0x1, 5, 0x24},
                             {0x0, 0x1, 1, 0x2},
                             {0x0, 0x1, 2, 0x4},
                             {0x0, 0x1, 3, 0x8},
                             {0x0, 0x1, 4, 0x10},
                             {0x0, 0x1, 5, 0x20},
                             {0x4, 0x0, 1, 0x4},
                             {0x4, 0x0, 2, 0x4},
                             {0x4, 0x0, 3, 0x4},
                             {0x4, 0x0, 4, 0x4},
                             {0x4, 0x0, 5, 0x4},

                             // Shift overflow.
                             {0x4, INT32_MAX, 1, 0x2},
                             {0x4, INT32_MAX >> 1, 2, 0x0},
                             {0x4, INT32_MAX >> 2, 3, 0xFFFFFFFFFFFFFFFC},
                             {0x4, INT32_MAX >> 3, 4, 0xFFFFFFFFFFFFFFF4},
                             {0x4, INT32_MAX >> 4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {INT32_MAX - 1, 0x1, 1, 0xFFFFFFFF80000000},
                             {INT32_MAX - 3, 0x1, 2, 0xFFFFFFFF80000000},
                             {INT32_MAX - 7, 0x1, 3, 0xFFFFFFFF80000000},
                             {INT32_MAX - 15, 0x1, 4, 0xFFFFFFFF80000000},
                             {INT32_MAX - 31, 0x1, 5, 0xFFFFFFFF80000000},

                             // Addition overflow.
                             {-2, 0x1, 1, 0x0},
                             {-4, 0x1, 2, 0x0},
                             {-8, 0x1, 3, 0x0},
                             {-16, 0x1, 4, 0x0},
                             {-32, 0x1, 5, 0x0}};

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLsa);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_lsa(tc[i].rt, tc[i].rs, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Lsa(v0, %x, %x, %hhu)\n",
           tc[i].expected_res, res, tc[i].rt, tc[i].rs, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}


static uint64_t run_dlsa(uint64_t rt, uint64_t rs, int8_t sa) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  __ Dlsa(v0, a0, a1, sa);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assembler.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<FV>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(rt, rs, 0, 0, 0));

  return res;
}


TEST(Dlsa) {
  CcTest::InitializeVM();
  struct TestCaseLsa {
    int64_t rt;
    int64_t rs;
    uint8_t sa;
    uint64_t expected_res;
  };

  struct TestCaseLsa tc[] = {// rt, rs, sa, expected_res
                             {0x4, 0x1, 1, 0x6},
                             {0x4, 0x1, 2, 0x8},
                             {0x4, 0x1, 3, 0xC},
                             {0x4, 0x1, 4, 0x14},
                             {0x4, 0x1, 5, 0x24},
                             {0x0, 0x1, 1, 0x2},
                             {0x0, 0x1, 2, 0x4},
                             {0x0, 0x1, 3, 0x8},
                             {0x0, 0x1, 4, 0x10},
                             {0x0, 0x1, 5, 0x20},
                             {0x4, 0x0, 1, 0x4},
                             {0x4, 0x0, 2, 0x4},
                             {0x4, 0x0, 3, 0x4},
                             {0x4, 0x0, 4, 0x4},
                             {0x4, 0x0, 5, 0x4},

                             // Shift overflow.
                             {0x4, INT64_MAX, 1, 0x2},
                             {0x4, INT64_MAX >> 1, 2, 0x0},
                             {0x4, INT64_MAX >> 2, 3, 0xFFFFFFFFFFFFFFFC},
                             {0x4, INT64_MAX >> 3, 4, 0xFFFFFFFFFFFFFFF4},
                             {0x4, INT64_MAX >> 4, 5, 0xFFFFFFFFFFFFFFE4},

                             // Signed addition overflow.
                             {INT64_MAX - 1, 0x1, 1, 0x8000000000000000},
                             {INT64_MAX - 3, 0x1, 2, 0x8000000000000000},
                             {INT64_MAX - 7, 0x1, 3, 0x8000000000000000},
                             {INT64_MAX - 15, 0x1, 4, 0x8000000000000000},
                             {INT64_MAX - 31, 0x1, 5, 0x8000000000000000},

                             // Addition overflow.
                             {-2, 0x1, 1, 0x0},
                             {-4, 0x1, 2, 0x0},
                             {-8, 0x1, 3, 0x0},
                             {-16, 0x1, 4, 0x0},
                             {-32, 0x1, 5, 0x0}};

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseLsa);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_dlsa(tc[i].rt, tc[i].rs, tc[i].sa);
    PrintF("0x%" PRIx64 " =? 0x%" PRIx64 " == Dlsa(v0, %" PRIx64 ", %" PRIx64
           ", %hhu)\n",
           tc[i].expected_res, res, tc[i].rt, tc[i].rs, tc[i].sa);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

static const std::vector<uint32_t> cvt_trunc_uint32_test_values() {
  static const uint32_t kValues[] = {0x00000000, 0x00000001, 0x00FFFF00,
                                     0x7FFFFFFF, 0x80000000, 0x80000001,
                                     0x80FFFF00, 0x8FFFFFFF, 0xFFFFFFFF};
  return std::vector<uint32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> cvt_trunc_int32_test_values() {
  static const int32_t kValues[] = {
      static_cast<int32_t>(0x00000000), static_cast<int32_t>(0x00000001),
      static_cast<int32_t>(0x00FFFF00), static_cast<int32_t>(0x7FFFFFFF),
      static_cast<int32_t>(0x80000000), static_cast<int32_t>(0x80000001),
      static_cast<int32_t>(0x80FFFF00), static_cast<int32_t>(0x8FFFFFFF),
      static_cast<int32_t>(0xFFFFFFFF)};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<uint64_t> cvt_trunc_uint64_test_values() {
  static const uint64_t kValues[] = {
      0x0000000000000000, 0x0000000000000001, 0x0000FFFFFFFF0000,
      0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x8000000000000001,
      0x8000FFFFFFFF0000, 0x8FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int64_t> cvt_trunc_int64_test_values() {
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
RET_TYPE run_Cvt(IN_TYPE x, Func GenerateConvertInstructionFunc) {
  using F_CVT = RET_TYPE(IN_TYPE x0, int x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;

  GenerateConvertInstructionFunc(masm);
  __ dmfc1(v0, f2);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);

  return reinterpret_cast<RET_TYPE>(f.Call(x, 0, 0, 0, 0));
}

TEST(Cvt_s_uw_Trunc_uw_s) {
  CcTest::InitializeVM();
  FOR_UINT32_INPUTS(i, cvt_trunc_uint32_test_values) {
    uint32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Cvt_s_uw(f0, a0);
      __ mthc1(zero_reg, f2);
      __ Trunc_uw_s(f2, f0, f1);
    };
    CHECK_EQ(static_cast<float>(input), run_Cvt<uint64_t>(input, fn));
  }
}

TEST(Cvt_s_ul_Trunc_ul_s) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, cvt_trunc_uint64_test_values) {
    uint64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Cvt_s_ul(f0, a0);
      __ Trunc_ul_s(f2, f0, f1, v0);
    };
    CHECK_EQ(static_cast<float>(input), run_Cvt<uint64_t>(input, fn));
  }
}

TEST(Cvt_d_ul_Trunc_ul_d) {
  CcTest::InitializeVM();
  FOR_UINT64_INPUTS(i, cvt_trunc_uint64_test_values) {
    uint64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ Cvt_d_ul(f0, a0);
      __ Trunc_ul_d(f2, f0, f1, v0);
    };
    CHECK_EQ(static_cast<double>(input), run_Cvt<uint64_t>(input, fn));
  }
}

TEST(cvt_d_l_Trunc_l_d) {
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i, cvt_trunc_int64_test_values) {
    int64_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ dmtc1(a0, f4);
      __ cvt_d_l(f0, f4);
      __ Trunc_l_d(f2, f0);
    };
    CHECK_EQ(static_cast<double>(input), run_Cvt<int64_t>(input, fn));
  }
}

TEST(cvt_d_l_Trunc_l_ud) {
  CcTest::InitializeVM();
  FOR_INT64_INPUTS(i, cvt_trunc_int64_test_values) {
    int64_t input = *i;
    uint64_t abs_input = (input >= 0 || input == INT64_MIN) ? input : -input;
    auto fn = [](MacroAssembler* masm) {
      __ dmtc1(a0, f4);
      __ cvt_d_l(f0, f4);
      __ Trunc_l_ud(f2, f0, f6);
    };
    CHECK_EQ(static_cast<double>(abs_input), run_Cvt<uint64_t>(input, fn));
  }
}

TEST(cvt_d_w_Trunc_w_d) {
  CcTest::InitializeVM();
  FOR_INT32_INPUTS(i, cvt_trunc_int32_test_values) {
    int32_t input = *i;
    auto fn = [](MacroAssembler* masm) {
      __ mtc1(a0, f4);
      __ cvt_d_w(f0, f4);
      __ Trunc_w_d(f2, f0);
      __ mfc1(v1, f2);
      __ dmtc1(v1, f2);
    };
    CHECK_EQ(static_cast<double>(input), run_Cvt<int64_t>(input, fn));
  }
}

static const std::vector<int64_t> overflow_int64_test_values() {
  static const int64_t kValues[] = {static_cast<int64_t>(0xF000000000000000),
                                    static_cast<int64_t>(0x0000000000000001),
                                    static_cast<int64_t>(0xFF00000000000000),
                                    static_cast<int64_t>(0x0000F00111111110),
                                    static_cast<int64_t>(0x0F00001000000000),
                                    static_cast<int64_t>(0x991234AB12A96731),
                                    static_cast<int64_t>(0xB0FFFF0F0F0F0F01),
                                    static_cast<int64_t>(0x00006FFFFFFFFFFF),
                                    static_cast<int64_t>(0xFFFFFFFFFFFFFFFF)};
  return std::vector<int64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(OverflowInstructions) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  struct T {
    int64_t lhs;
    int64_t rhs;
    int64_t output_add;
    int64_t output_add2;
    int64_t output_sub;
    int64_t output_sub2;
    int64_t output_mul;
    int64_t output_mul2;
    int64_t overflow_add;
    int64_t overflow_add2;
    int64_t overflow_sub;
    int64_t overflow_sub2;
    int64_t overflow_mul;
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

      __ ld(t0, MemOperand(a0, offsetof(T, lhs)));
      __ ld(t1, MemOperand(a0, offsetof(T, rhs)));

      __ DaddOverflow(t2, t0, Operand(t1), t3);
      __ sd(t2, MemOperand(a0, offsetof(T, output_add)));
      __ sd(t3, MemOperand(a0, offsetof(T, overflow_add)));
      __ mov(t3, zero_reg);
      __ DaddOverflow(t0, t0, Operand(t1), t3);
      __ sd(t0, MemOperand(a0, offsetof(T, output_add2)));
      __ sd(t3, MemOperand(a0, offsetof(T, overflow_add2)));

      __ ld(t0, MemOperand(a0, offsetof(T, lhs)));
      __ ld(t1, MemOperand(a0, offsetof(T, rhs)));

      __ DsubOverflow(t2, t0, Operand(t1), t3);
      __ sd(t2, MemOperand(a0, offsetof(T, output_sub)));
      __ sd(t3, MemOperand(a0, offsetof(T, overflow_sub)));
      __ mov(t3, zero_reg);
      __ DsubOverflow(t0, t0, Operand(t1), t3);
      __ sd(t0, MemOperand(a0, offsetof(T, output_sub2)));
      __ sd(t3, MemOperand(a0, offsetof(T, overflow_sub2)));

      __ ld(t0, MemOperand(a0, offsetof(T, lhs)));
      __ ld(t1, MemOperand(a0, offsetof(T, rhs)));
      __ sll(t0, t0, 0);
      __ sll(t1, t1, 0);

      __ MulOverflow(t2, t0, Operand(t1), t3);
      __ sd(t2, MemOperand(a0, offsetof(T, output_mul)));
      __ sd(t3, MemOperand(a0, offsetof(T, overflow_mul)));
      __ mov(t3, zero_reg);
      __ MulOverflow(t0, t0, Operand(t1), t3);
      __ sd(t0, MemOperand(a0, offsetof(T, output_mul2)));
      __ sd(t3, MemOperand(a0, offsetof(T, overflow_mul2)));

      __ jr(ra);
      __ nop();

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

      CHECK_EQ(expected_add_ovf, t.overflow_add < 0);
      CHECK_EQ(expected_sub_ovf, t.overflow_sub < 0);
      CHECK_EQ(expected_mul_ovf, t.overflow_mul != 0);

      CHECK_EQ(t.overflow_add, t.overflow_add2);
      CHECK_EQ(t.overflow_sub, t.overflow_sub2);
      CHECK_EQ(t.overflow_mul, t.overflow_mul2);

      CHECK_EQ(expected_add, t.output_add);
      CHECK_EQ(expected_add, t.output_add2);
      CHECK_EQ(expected_sub, t.output_sub);
      CHECK_EQ(expected_sub, t.output_sub2);
      if (!expected_mul_ovf) {
        CHECK_EQ(expected_mul, t.output_mul);
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
  const float fminf = std::numeric_limits<float>::infinity();
  const int kTableLength = 13;

  double inputsa[kTableLength] = {2.0,  3.0,  -0.0, 0.0,  42.0, dinf, dminf,
                                  dinf, dnan, 3.0,  dinf, dnan, dnan};
  double inputsb[kTableLength] = {3.0,   2.0, 0.0,  -0.0, dinf, 42.0, dinf,
                                  dminf, 3.0, dnan, dnan, dinf, dnan};
  double outputsdmin[kTableLength] = {2.0,  2.0,   -0.0,  -0.0, 42.0,
                                      42.0, dminf, dminf, dnan, dnan,
                                      dnan, dnan,  dnan};
  double outputsdmax[kTableLength] = {3.0,  3.0,  0.0,  0.0,  dinf, dinf, dinf,
                                      dinf, dnan, dnan, dnan, dnan, dnan};

  float inputse[kTableLength] = {2.0,  3.0,  -0.0, 0.0,  42.0, finf, fminf,
                                 finf, fnan, 3.0,  finf, fnan, fnan};
  float inputsf[kTableLength] = {3.0,   2.0, 0.0,  -0.0, finf, 42.0, finf,
                                 fminf, 3.0, fnan, fnan, finf, fnan};
  float outputsfmin[kTableLength] = {2.0,   2.0,  -0.0, -0.0, 42.0, 42.0, fminf,
                                     fminf, fnan, fnan, fnan, fnan, fnan};
  float outputsfmax[kTableLength] = {3.0,  3.0,  0.0,  0.0,  finf, finf, finf,
                                     finf, fnan, fnan, fnan, fnan, fnan};

  auto handle_dnan = [masm](FPURegister dst, Label* nan, Label* back) {
    __ bind(nan);
    __ LoadRoot(t8, RootIndex::kNanValue);
    __ Ldc1(dst, FieldMemOperand(
                     t8, compiler::AccessBuilder::ForHeapNumberValue().offset));
    __ Branch(back);
  };

  auto handle_snan = [masm, fnan](FPURegister dst, Label* nan, Label* back) {
    __ bind(nan);
   
"""


```