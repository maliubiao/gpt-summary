Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's testing framework. The file `v8/test/cctest/test-assembler-mips64.cc` suggests that it contains tests for the MIPS64 assembler within V8.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file is a C++ source file within V8's testing directory (`test/cctest`). The name includes "assembler" and "mips64", strongly indicating it's testing the code generation capabilities for the MIPS64 architecture. The `TEST()` macros confirm that it's using V8's testing framework.

2. **Examine the includes:** The included headers (`assembler-inl.h`, `macro-assembler.h`, `disassembler.h`, `simulator.h`) reinforce the idea that this code directly deals with low-level code generation and execution simulation.

3. **Analyze the `TEST()` blocks:**  Each `TEST(MIPS...)` block represents an individual test case. The code within each block typically follows this pattern:
    * Initialization (`CcTest::InitializeVM()`, `Isolate*`, `HandleScope`).
    * Creation of a `MacroAssembler` object.
    * A sequence of MIPS64 assembly instructions written using the `__` macro (which expands to `assm.`).
    * Calls to `assm.GetCode()` to generate executable code.
    * Creation of a function pointer using `GeneratedCode`.
    * Execution of the generated code with specific input values.
    * Assertions (`CHECK_EQ`) to verify the output.

4. **Infer the high-level function:** Based on the structure of the test cases, the file's main function is to **test the correctness of the MIPS64 assembler in V8.** It does this by generating small snippets of assembly code and then executing them to ensure they produce the expected results.

5. **Address specific user questions:**

    * **.tq extension:** The code is C++, not Torque. Point this out explicitly.
    * **Relationship to JavaScript:** Although this code tests the *assembler*, which is used to generate the low-level code that *runs* JavaScript, this specific test file does *not* contain any JavaScript code or directly execute it. The connection is that a working assembler is crucial for V8 to execute JavaScript efficiently on MIPS64. Give a conceptual JavaScript example to illustrate what the generated assembly code might be used for *under the hood*.
    * **Code logic reasoning:**  Pick a simple test case (like `TEST(MIPS0)`) and explain the assembly instructions and their expected outcome for given inputs. This demonstrates how the tests work. Provide input and expected output.
    * **Common programming errors:** Think about the types of errors that could occur when writing assembly code or using an assembler: incorrect instruction usage, register allocation issues, logic errors in the assembly sequence. Provide an example related to incorrect register usage.

6. **Summarize the functionality:** Combine the observations into a concise summary that answers the main question.

7. **Consider the "part 1 of 13" information:** Since this is just the first part, acknowledge that the entire file likely contains a more comprehensive set of tests covering a wider range of MIPS64 instructions and scenarios. This sets the stage for understanding the purpose of the subsequent parts.

8. **Review and refine:**  Ensure the explanation is clear, accurate, and addresses all aspects of the user's request. Use clear language and avoid overly technical jargon where possible. For example, explain the purpose of `CHECK_EQ`.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
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

#include <iostream>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc.
// TODO(mips64): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.

TEST(MIPS0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Addition.
  __ addu(v0, a0, a1);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));
  CHECK_EQ(0xABCL, res);
}

TEST(MIPS1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label L, C;

  __ mov(a1, a0);
  __ li(v0, 0l);
  __ b(&C);
  __ nop();

  __ bind(&L);
  __ addu(v0, v0, a1);
  __ addiu(a1, a1, -1);

  __ bind(&C);
  __ xori(v1, a1, 0);
  __ Branch(&L, ne, v1, Operand((int64_t)0));
  __ nop();

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(50, 0, 0, 0, 0));
  CHECK_EQ(1275L, res);
}

TEST(MIPS2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  // ----- Test all instructions.

  // Test lui, ori, and addiu, used in the li pseudo-instruction.
  // This way we can then safely load registers with chosen values.

  __ ori(a4, zero_reg, 0);
  __ lui(a4, 0x1234);
  __ ori(a4, a4, 0);
  __ ori(a4, a4, 0x0F0F);
  __ ori(a4, a4, 0xF0F0);
  __ addiu(a5, a4, 1);
  __ addiu(a6, a5, -0x10);

  // Load values in temporary registers.
  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, 0xFFFFFFFC);
  __ li(t1, 0xFFFFEDCC);
  __ li(t2, 0xEDCBA988);
  __ li(t3, 0x80000000);

  // SPECIAL class.
  __ srl(v0, a6, 8);    // 0x00123456
  __ sll(v0, v0, 11);   // 0x91A2B000
  __ sra(v0, v0, 3);    // 0xF2345600
  __ srav(v0, v0, a4);  // 0xFF234560
  __ sllv(v0, v0, a4);  // 0xF2345600
  __ srlv(v0, v0, a4);  // 0x0F234560
  __ Branch(&error, ne, v0, Operand(0x0F234560));
  __ nop();

  __ addu(v0, a4, a5);  // 0x00001238
  __ subu(v0, v0, a4);  // 0x00001234
  __ Branch(&error, ne, v0, Operand(0x00001234));
  __ nop();
  __ addu(v1, a7, a4);  // 32bit addu result is sign-extended into 64bit reg.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000003));
  __ nop();
  __ subu(v1, t3, a4);  // 0x7FFFFFFC
  __ Branch(&error, ne, v1, Operand(0x7FFFFFFC));
  __ nop();

  __ and_(v0, a5, a6);  // 0x0000000000001230
  __ or_(v0, v0, a5);   // 0x0000000000001234
  __ xor_(v0, v0, a6);  // 0x000000001234444C
  __ nor(v0, v0, a6);   // 0xFFFFFFFFEDCBA987
  __ Branch(&error, ne, v0, Operand(0xFFFFFFFFEDCBA983));
  __ nop();

  // Shift both 32bit number to left, to preserve meaning of next comparison.
  __ dsll32(a7, a7, 0);
  __ dsll32(t3, t3, 0);

  __ slt(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();
  __ sltu(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();

  // Restore original values in registers.
  __ dsrl32(a7, a7, 0);
  __ dsrl32(t3, t3, 0);
  // End of SPECIAL class.

  __ addiu(v0, zero_reg, 0x7421);  // 0x00007421
  __ addiu(v0, v0, -0x1);          // 0x00007420
  __ addiu(v0, v0, -0x20);         // 0x00007400
  __ Branch(&error, ne, v0, Operand(0x00007400));
  __ nop();
  __ addiu(v1, a7, 0x1);  // 0x80000000 - result is sign-extended.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000000));
  __ nop();

  __ slti(v0, a5, 0x00002000);  // 0x1
  __ slti(v0, v0, 0xFFFF8000);  // 0x0
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();
  __ sltiu(v0, a5, 0x00002000);  // 0x1
  __ sltiu(v0, v0, 0x00008000);  // 0x1
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();

  __ andi(v0, a5, 0xF0F0);  // 0x00001030
  __ ori(v0, v0, 0x8A00);   // 0x00009A30
  __ xori(v0, v0, 0x83CC);  // 0x000019FC
  __ Branch(&error, ne, v0, Operand(0x000019FC));
  __ nop();
  __ lui(v1, 0x8123);  // Result is sign-extended into 64bit register.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF81230000));
  __ nop();

  // Bit twiddling instructions & conditional moves.
  // Uses a4-t3 as set above.
  __ Clz(v0, a4);       // 29
  __ Clz(v1, a5);       // 19
  __ addu(v0, v0, v1);  // 48
  __ Clz(v1, a6);       // 3
  __ addu(v0, v0, v1);  // 51
  __ Clz(v1, t3);       // 0
  __ addu(v0, v0, v1);  // 51
  __ Branch(&error, ne, v0, Operand(51));
  __ Movn(a0, a7, a4);  // Move a0<-a7 (a4 is NOT 0).
  __ Ins(a0, a5, 12, 8);  // 0x7FF34FFF
  __ Branch(&error, ne, a0, Operand(0x7FF34FFF));
  __ Movz(a0, t2, t3);    // a0 not updated (t3 is NOT 0).
  __ Ext(a1, a0, 8, 12);  // 0x34F
  __ Branch(&error, ne, a1, Operand(0x34F));
  __ Movz(a0, t2, v1);    // a0<-t2, v0 is 0, from 8 instr back.
  __ Branch(&error, ne, a0, Operand(t2));

  // Everything was correctly executed. Load the expected result.
  __ li(v0, 0x31415926);
  __ b(&exit);
  __ nop();

  __ bind(&error);
  // Got an error. Return a wrong result.
  __ li(v0, 666);

  __ bind(&exit);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(MIPS3) {
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
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Double precision floating point instructions.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  __ add_d(f8, f4, f6);
  __ Sdc1(f8, MemOperand(a0, offsetof(T, c)));  // c = a + b.

  __ mov_d(f10, f8);  // c
  __ neg_d(f12, f6);  // -b
  __ sub_d(f10, f10, f12);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, d)));  // d = c - (-b).

  __ Sdc1(f4, MemOperand(a0, offsetof(T, b)));  // b = a.

  __ li(a4, 120);
  __ mtc1(a4, f14);
  __ cvt_d_w(f14, f14);   // f14 = 120.0.
  __ mul_d(f10, f10, f14);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, e)));  // e = d * 120 = 1.8066e16.

  __ div_d(f12, f10, f4);
  __ Sdc1(f12, MemOperand(a0, offsetof(T, f)));  // f = e / a = 120.44.

  __ sqrt_d(f14, f12);
  __ Sdc1(f14, MemOperand(a0, offsetof(T, g)));
  // g = sqrt(f) = 10.97451593465515908537

  if (kArchVariant == kMips64r2) {
    __ Ldc1(f4, MemOperand(a0, offsetof(T, h)));
    __ Ldc1(f6, MemOperand(a0, offsetof(T, i)));
    __ Madd_d(f14, f6, f4, f6, f8);
    __ Sdc1(f14, MemOperand(a0, offsetof(T, h)));
  }

  // Single precision floating point instructions.
  __ Lwc1(f4, MemOperand(a0, offsetof(T, fa)));
  __ Lwc1(f6, MemOperand(a0, offsetof(T, fb)));
  __ add_s(f8, f4, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(T, fc)));  // fc = fa + fb.

  __ neg_s(f10, f6);  // -fb
  __ sub_s(f10, f8, f10);
  __ Swc1(f10, MemOperand(a0, offsetof(T, fd)));  // fd = fc - (-fb).

  __ Swc1(f4, MemOperand(a0, offsetof(T, fb)));  // fb = fa.

  __ li(t0, 120);
  __ mtc1(t0, f14);
  __ cvt_s_w(f14, f14);   // f14 = 120.0.
  __ mul_s(f10, f10, f14);
  __ Swc1(f10, MemOperand(a0, offsetof(T, fe)));  // fe = fd * 120

  __ div_s(f12, f10, f4);
  __ Swc1(f12, MemOperand(a0, offsetof(T, ff)));  // ff = fe / fa

  __ sqrt_s(f14, f12);
  __ Swc1(f14, MemOperand(a0, offsetof(T, fg)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
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
  if (kArchVariant == kMips64r2) {
    CHECK_EQ(6.875, t.h);
  }
  // Expected single results.
  CHECK_EQ(1.5e6, t.fa);
  CHECK_EQ(1.5e6, t.fb);
  CHECK_EQ(1.5275e06, t.fc);
  CHECK_EQ(1.5550e06, t.fd);
  CHECK_EQ(1.866e08, t.fe);
  CHECK_EQ(124.40000152587890625, t.ff);
  CHECK_EQ(11.1534748077392578125, t.fg);
}

TEST(MIPS4) {
  // Test moves between floating point and integer registers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    int64_t high;
    int64_t low;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f5, MemOperand(a0, offsetof(T, b)));

  // Swap f4 and f5, by using 3 integer registers, a4-a6,
  // both two 32-bit chunks, and one 64-bit chunk.
  // mXhc1 is mips32/64-r2 only, not r1,
  // but we will not support r1 in practice.
  __ mfc1(a4, f4);
  __ mfhc1(a5, f4);
  __ dmfc1(a6, f5);

  __ mtc1(a4, f5);
  __ mthc1(a5, f5);
  __ dmtc1(a6, f4);

  // Store the swapped f4 and f5 back to memory.
  __ Sdc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Sdc1(f5, MemOperand(a0, offsetof(T, c)));

  // Test sign extension of move operations from coprocessor.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, d)));
  __ mfhc1(a4, f4);
  __ mfc1(a5, f4);

  __ Sd(a4, MemOperand(a0, offsetof(T, high)));
  __ Sd(a5, MemOperand(a0, offsetof(T, low)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(2.75e11, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFC25001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFBF800000L), t.low);
}

TEST(MIPS5) {
  // Test conversions between doubles and integers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    int i;
    int j;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Load all structure elements to registers.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  __ Lw(a4, MemOperand(a0, offsetof(T, i)));
  __ Lw(a5, MemOperand(a0, offsetof(T, j)));

  // Convert double in f4 to int in element i.
  __ cvt_w_d(f8, f4);
  __ mfc1(a6, f8);
  __ Sw(a6, MemOperand(a0, offsetof(T, i)));

  // Convert double in f6 to int in element j.
  __ cvt_w_d(f10, f6);
  __ mfc1(a7, f10);
  __ Sw(a7, MemOperand(a0, offsetof(T, j)));

  // Convert int in original i (a4) to double in a.
  __ mtc1(a4, f12);
  __ cvt_d_w(f0, f12);
  __ Sdc1(f0, MemOperand(a0, offsetof(T, a)));

  // Convert int in original j (a5) to double in b.
  __ mtc1(a5, f14);
  __ cvt_d_w(f2, f14);
  __ Sdc1(f2, MemOperand(a0, offsetof(T, b)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e4;
  t.b = 2.75e8;
  t.i = 12345678;
  t.j = -100000;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(12345678.0, t.a);
  CHECK_EQ(-100000.0, t.b);
  CHECK_EQ(15000, t.i);
  CHECK_EQ(275000000, t.j);
}

TEST(MIPS6) {
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
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Basic word load/store.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a4, MemOperand(a0, offsetof(T, r1)));

  // lh with positive data.
  __ Lh(a5, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r2)));

  // lh with negative data.
  __ Lh(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r3)));

  // lhu with negative data.
  __ Lhu(a7, MemOperand(a0, offsetof(T, si)));
  __ Sw(a7, MemOperand(a0, offsetof(T, r4)));

  // Lb with negative data.
  __ Lb(t0, MemOperand(a0, offsetof(T, si)));
  __ Sw(t0, MemOperand(a0, offsetof(T, r5)));

  // sh writes only 1/2 of word.
  __ lui(t1, 0x3333);
  __ ori(t1, t1, 0x3333);
  __ Sw(t1, MemOperand(a0, offsetof(T, r6)));
  __ Lhu(t1, MemOperand(a0, offsetof(T, si)));
  __ Sh(t1, MemOperand(a0, offsetof(T, r6)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.ui = 0x
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共13部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
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

#include <iostream>

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc.
// TODO(mips64): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.

TEST(MIPS0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Addition.
  __ addu(v0, a0, a1);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));
  CHECK_EQ(0xABCL, res);
}


TEST(MIPS1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label L, C;

  __ mov(a1, a0);
  __ li(v0, 0l);
  __ b(&C);
  __ nop();

  __ bind(&L);
  __ addu(v0, v0, a1);
  __ addiu(a1, a1, -1);

  __ bind(&C);
  __ xori(v1, a1, 0);
  __ Branch(&L, ne, v1, Operand((int64_t)0));
  __ nop();

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(50, 0, 0, 0, 0));
  CHECK_EQ(1275L, res);
}


TEST(MIPS2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  // ----- Test all instructions.

  // Test lui, ori, and addiu, used in the li pseudo-instruction.
  // This way we can then safely load registers with chosen values.

  __ ori(a4, zero_reg, 0);
  __ lui(a4, 0x1234);
  __ ori(a4, a4, 0);
  __ ori(a4, a4, 0x0F0F);
  __ ori(a4, a4, 0xF0F0);
  __ addiu(a5, a4, 1);
  __ addiu(a6, a5, -0x10);

  // Load values in temporary registers.
  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, 0xFFFFFFFC);
  __ li(t1, 0xFFFFEDCC);
  __ li(t2, 0xEDCBA988);
  __ li(t3, 0x80000000);

  // SPECIAL class.
  __ srl(v0, a6, 8);    // 0x00123456
  __ sll(v0, v0, 11);   // 0x91A2B000
  __ sra(v0, v0, 3);    // 0xF2345600
  __ srav(v0, v0, a4);  // 0xFF234560
  __ sllv(v0, v0, a4);  // 0xF2345600
  __ srlv(v0, v0, a4);  // 0x0F234560
  __ Branch(&error, ne, v0, Operand(0x0F234560));
  __ nop();

  __ addu(v0, a4, a5);  // 0x00001238
  __ subu(v0, v0, a4);  // 0x00001234
  __ Branch(&error, ne, v0, Operand(0x00001234));
  __ nop();
  __ addu(v1, a7, a4);  // 32bit addu result is sign-extended into 64bit reg.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000003));
  __ nop();
  __ subu(v1, t3, a4);  // 0x7FFFFFFC
  __ Branch(&error, ne, v1, Operand(0x7FFFFFFC));
  __ nop();

  __ and_(v0, a5, a6);  // 0x0000000000001230
  __ or_(v0, v0, a5);   // 0x0000000000001234
  __ xor_(v0, v0, a6);  // 0x000000001234444C
  __ nor(v0, v0, a6);   // 0xFFFFFFFFEDCBA987
  __ Branch(&error, ne, v0, Operand(0xFFFFFFFFEDCBA983));
  __ nop();

  // Shift both 32bit number to left, to preserve meaning of next comparison.
  __ dsll32(a7, a7, 0);
  __ dsll32(t3, t3, 0);

  __ slt(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();
  __ sltu(v0, t3, a7);
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();

  // Restore original values in registers.
  __ dsrl32(a7, a7, 0);
  __ dsrl32(t3, t3, 0);
  // End of SPECIAL class.

  __ addiu(v0, zero_reg, 0x7421);  // 0x00007421
  __ addiu(v0, v0, -0x1);          // 0x00007420
  __ addiu(v0, v0, -0x20);         // 0x00007400
  __ Branch(&error, ne, v0, Operand(0x00007400));
  __ nop();
  __ addiu(v1, a7, 0x1);  // 0x80000000 - result is sign-extended.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF80000000));
  __ nop();

  __ slti(v0, a5, 0x00002000);  // 0x1
  __ slti(v0, v0, 0xFFFF8000);  // 0x0
  __ Branch(&error, ne, v0, Operand(zero_reg));
  __ nop();
  __ sltiu(v0, a5, 0x00002000);  // 0x1
  __ sltiu(v0, v0, 0x00008000);  // 0x1
  __ Branch(&error, ne, v0, Operand(0x1));
  __ nop();

  __ andi(v0, a5, 0xF0F0);  // 0x00001030
  __ ori(v0, v0, 0x8A00);   // 0x00009A30
  __ xori(v0, v0, 0x83CC);  // 0x000019FC
  __ Branch(&error, ne, v0, Operand(0x000019FC));
  __ nop();
  __ lui(v1, 0x8123);  // Result is sign-extended into 64bit register.
  __ Branch(&error, ne, v1, Operand(0xFFFFFFFF81230000));
  __ nop();

  // Bit twiddling instructions & conditional moves.
  // Uses a4-t3 as set above.
  __ Clz(v0, a4);       // 29
  __ Clz(v1, a5);       // 19
  __ addu(v0, v0, v1);  // 48
  __ Clz(v1, a6);       // 3
  __ addu(v0, v0, v1);  // 51
  __ Clz(v1, t3);       // 0
  __ addu(v0, v0, v1);  // 51
  __ Branch(&error, ne, v0, Operand(51));
  __ Movn(a0, a7, a4);  // Move a0<-a7 (a4 is NOT 0).
  __ Ins(a0, a5, 12, 8);  // 0x7FF34FFF
  __ Branch(&error, ne, a0, Operand(0x7FF34FFF));
  __ Movz(a0, t2, t3);    // a0 not updated (t3 is NOT 0).
  __ Ext(a1, a0, 8, 12);  // 0x34F
  __ Branch(&error, ne, a1, Operand(0x34F));
  __ Movz(a0, t2, v1);    // a0<-t2, v0 is 0, from 8 instr back.
  __ Branch(&error, ne, a0, Operand(t2));

  // Everything was correctly executed. Load the expected result.
  __ li(v0, 0x31415926);
  __ b(&exit);
  __ nop();

  __ bind(&error);
  // Got an error. Return a wrong result.
  __ li(v0, 666);

  __ bind(&exit);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0xC, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}


TEST(MIPS3) {
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
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Double precision floating point instructions.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  __ add_d(f8, f4, f6);
  __ Sdc1(f8, MemOperand(a0, offsetof(T, c)));  // c = a + b.

  __ mov_d(f10, f8);  // c
  __ neg_d(f12, f6);  // -b
  __ sub_d(f10, f10, f12);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, d)));  // d = c - (-b).

  __ Sdc1(f4, MemOperand(a0, offsetof(T, b)));  // b = a.

  __ li(a4, 120);
  __ mtc1(a4, f14);
  __ cvt_d_w(f14, f14);   // f14 = 120.0.
  __ mul_d(f10, f10, f14);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, e)));  // e = d * 120 = 1.8066e16.

  __ div_d(f12, f10, f4);
  __ Sdc1(f12, MemOperand(a0, offsetof(T, f)));  // f = e / a = 120.44.

  __ sqrt_d(f14, f12);
  __ Sdc1(f14, MemOperand(a0, offsetof(T, g)));
  // g = sqrt(f) = 10.97451593465515908537

  if (kArchVariant == kMips64r2) {
    __ Ldc1(f4, MemOperand(a0, offsetof(T, h)));
    __ Ldc1(f6, MemOperand(a0, offsetof(T, i)));
    __ Madd_d(f14, f6, f4, f6, f8);
    __ Sdc1(f14, MemOperand(a0, offsetof(T, h)));
  }

  // Single precision floating point instructions.
  __ Lwc1(f4, MemOperand(a0, offsetof(T, fa)));
  __ Lwc1(f6, MemOperand(a0, offsetof(T, fb)));
  __ add_s(f8, f4, f6);
  __ Swc1(f8, MemOperand(a0, offsetof(T, fc)));  // fc = fa + fb.

  __ neg_s(f10, f6);  // -fb
  __ sub_s(f10, f8, f10);
  __ Swc1(f10, MemOperand(a0, offsetof(T, fd)));  // fd = fc - (-fb).

  __ Swc1(f4, MemOperand(a0, offsetof(T, fb)));  // fb = fa.

  __ li(t0, 120);
  __ mtc1(t0, f14);
  __ cvt_s_w(f14, f14);   // f14 = 120.0.
  __ mul_s(f10, f10, f14);
  __ Swc1(f10, MemOperand(a0, offsetof(T, fe)));  // fe = fd * 120

  __ div_s(f12, f10, f4);
  __ Swc1(f12, MemOperand(a0, offsetof(T, ff)));  // ff = fe / fa

  __ sqrt_s(f14, f12);
  __ Swc1(f14, MemOperand(a0, offsetof(T, fg)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
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
  if (kArchVariant == kMips64r2) {
    CHECK_EQ(6.875, t.h);
  }
  // Expected single results.
  CHECK_EQ(1.5e6, t.fa);
  CHECK_EQ(1.5e6, t.fb);
  CHECK_EQ(1.5275e06, t.fc);
  CHECK_EQ(1.5550e06, t.fd);
  CHECK_EQ(1.866e08, t.fe);
  CHECK_EQ(124.40000152587890625, t.ff);
  CHECK_EQ(11.1534748077392578125, t.fg);
}


TEST(MIPS4) {
  // Test moves between floating point and integer registers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    int64_t high;
    int64_t low;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f5, MemOperand(a0, offsetof(T, b)));

  // Swap f4 and f5, by using 3 integer registers, a4-a6,
  // both two 32-bit chunks, and one 64-bit chunk.
  // mXhc1 is mips32/64-r2 only, not r1,
  // but we will not support r1 in practice.
  __ mfc1(a4, f4);
  __ mfhc1(a5, f4);
  __ dmfc1(a6, f5);

  __ mtc1(a4, f5);
  __ mthc1(a5, f5);
  __ dmtc1(a6, f4);

  // Store the swapped f4 and f5 back to memory.
  __ Sdc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Sdc1(f5, MemOperand(a0, offsetof(T, c)));

  // Test sign extension of move operations from coprocessor.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, d)));
  __ mfhc1(a4, f4);
  __ mfc1(a5, f4);

  __ Sd(a4, MemOperand(a0, offsetof(T, high)));
  __ Sd(a5, MemOperand(a0, offsetof(T, low)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e22;
  t.b = 2.75e11;
  t.c = 17.17;
  t.d = -2.75e11;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(2.75e11, t.a);
  CHECK_EQ(2.75e11, t.b);
  CHECK_EQ(1.5e22, t.c);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFC25001D1L), t.high);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFBF800000L), t.low);
}


TEST(MIPS5) {
  // Test conversions between doubles and integers.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    int i;
    int j;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Load all structure elements to registers.
  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  __ Lw(a4, MemOperand(a0, offsetof(T, i)));
  __ Lw(a5, MemOperand(a0, offsetof(T, j)));

  // Convert double in f4 to int in element i.
  __ cvt_w_d(f8, f4);
  __ mfc1(a6, f8);
  __ Sw(a6, MemOperand(a0, offsetof(T, i)));

  // Convert double in f6 to int in element j.
  __ cvt_w_d(f10, f6);
  __ mfc1(a7, f10);
  __ Sw(a7, MemOperand(a0, offsetof(T, j)));

  // Convert int in original i (a4) to double in a.
  __ mtc1(a4, f12);
  __ cvt_d_w(f0, f12);
  __ Sdc1(f0, MemOperand(a0, offsetof(T, a)));

  // Convert int in original j (a5) to double in b.
  __ mtc1(a5, f14);
  __ cvt_d_w(f2, f14);
  __ Sdc1(f2, MemOperand(a0, offsetof(T, b)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.a = 1.5e4;
  t.b = 2.75e8;
  t.i = 12345678;
  t.j = -100000;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(12345678.0, t.a);
  CHECK_EQ(-100000.0, t.b);
  CHECK_EQ(15000, t.i);
  CHECK_EQ(275000000, t.j);
}


TEST(MIPS6) {
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
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Basic word load/store.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a4, MemOperand(a0, offsetof(T, r1)));

  // lh with positive data.
  __ Lh(a5, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r2)));

  // lh with negative data.
  __ Lh(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r3)));

  // lhu with negative data.
  __ Lhu(a7, MemOperand(a0, offsetof(T, si)));
  __ Sw(a7, MemOperand(a0, offsetof(T, r4)));

  // Lb with negative data.
  __ Lb(t0, MemOperand(a0, offsetof(T, si)));
  __ Sw(t0, MemOperand(a0, offsetof(T, r5)));

  // sh writes only 1/2 of word.
  __ lui(t1, 0x3333);
  __ ori(t1, t1, 0x3333);
  __ Sw(t1, MemOperand(a0, offsetof(T, r6)));
  __ Lhu(t1, MemOperand(a0, offsetof(T, si)));
  __ Sh(t1, MemOperand(a0, offsetof(T, r6)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.ui = 0x11223344;
  t.si = 0x99AABBCC;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x11223344), t.r1);
  if (kArchEndian == kLittle)  {
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


TEST(MIPS7) {
  // Test floating point compare and branch instructions.
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
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles t.a ... t.f.
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label neither_is_nan, less_than, outa_here;

  __ Ldc1(f4, MemOperand(a0, offsetof(T, a)));
  __ Ldc1(f6, MemOperand(a0, offsetof(T, b)));
  if (kArchVariant != kMips64r6) {
    __ c(UN, D, f4, f6);
    __ bc1f(&neither_is_nan);
  } else {
    __ cmp(UN, L, f2, f4, f6);
    __ bc1eqz(&neither_is_nan, f2);
  }
  __ nop();
  __ Sw(zero_reg, MemOperand(a0, offsetof(T, result)));
  __ Branch(&outa_here);

  __ bind(&neither_is_nan);

  if (kArchVariant == kMips64r6) {
    __ cmp(OLT, L, f2, f6, f4);
    __ bc1nez(&less_than, f2);
  } else {
    __ c(OLT, D, f6, f4, 2);
    __ bc1t(&less_than, 2);
  }

  __ nop();
  __ Sw(zero_reg, MemOperand(a0, offsetof(T, result)));
  __ Branch(&outa_here);

  __ bind(&less_than);
  __ Addu(a4, zero_reg, Operand(1));
  __ Sw(a4, MemOperand(a0, offsetof(T, result)));  // Set true.

  // This test-case should have additional tests.

  __ bind(&outa_here);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
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


TEST(MIPS8) {
  if (kArchVariant == kMips64r2) {
    // Test ROTR and ROTRV instructions.
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);

    struct T {
      int32_t input;
      int32_t result_rotr_4;
      int32_t result_rotr_8;
      int32_t result_rotr_12;
      int32_t result_rotr_16;
      int32_t result_rotr_20;
      int32_t result_rotr_24;
      int32_t result_rotr_28;
      int32_t result_rotrv_4;
      int32_t result_rotrv_8;
      int32_t result_rotrv_12;
      int32_t result_rotrv_16;
      int32_t result_rotrv_20;
      int32_t result_rotrv_24;
      int32_t result_rotrv_28;
    };
    T t;

    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    // Basic word load.
    __ Lw(a4, MemOperand(a0, offsetof(T, input)));

    // ROTR instruction (called through the Ror macro).
    __ Ror(a5, a4, 0x0004);
    __ Ror(a6, a4, 0x0008);
    __ Ror(a7, a4, 0x000C);
    __ Ror(t0, a4, 0x0010);
    __ Ror(t1, a4, 0x0014);
    __ Ror(t2, a4, 0x0018);
    __ Ror(t3, a4, 0x001C);

    // Basic word store.
    __ Sw(a5, MemOperand(a0, offsetof(T, result_rotr_4)));
    __ Sw(a6, MemOperand(a0, offsetof(T, result_rotr_8)));
    __ Sw(a7, MemOperand(a0, offsetof(T, result_rotr_12)));
    __ Sw(t0, MemOperand(a0, offsetof(T, result_rotr_16)));
    __ Sw(t1, MemOperand(a0, offsetof(T, result_rotr_20)));
    __ Sw(t2, MemOperand(a0, offsetof(T, result_rotr_24)));
    __ Sw(t3, MemOperand(a0, offsetof(T, result_rotr_28)));

    // ROTRV instruction (called through the Ror macro).
    __ li(t3, 0x0004);
    __ Ror(a5, a4, t3);
    __ li(t3, 0x0008);
    __ Ror(a6, a4, t3);
    __ li(t3, 0x000C);
    __ Ror(a7, a4, t3);
    __ li(t3, 0x0010);
    __ Ror(t0, a4, t3);
    __ li(t3, 0x0014);
    __ Ror(t1, a4, t3);
    __ li(t3, 0x0018);
    __ Ror(t2, a4, t3);
    __ li(t3, 0x001C);
    __ Ror(t3, a4, t3);

    // Basic word store.
    __ Sw(a5, MemOperand(a0, offsetof(T, result_rotrv_4)));
    __ Sw(a6, MemOperand(a0, offsetof(T, result_rotrv_8)));
    __ Sw(a7, MemOperand(a0, offsetof(T, result_rotrv_12)));
    __ Sw(t0, MemOperand(a0, offsetof(T, result_rotrv_16)));
    __ Sw(t1, MemOperand(a0, offsetof(T, result_rotrv_20)));
    __ Sw(t2, MemOperand(a0, offsetof(T, result_rotrv_24)));
    __ Sw(t3, MemOperand(a0, offsetof(T, result_rotrv_28)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.input = 0x12345678;
    f.Call(&t, 0x0, 0, 0, 0);
    CHECK_EQ(static_cast<int32_t>(0x81234567), t.result_rotr_4);
    CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotr_8);
    CHECK_EQ(static_cast<int32_t>(0x67812345), t.result_rotr_12);
    CHECK_EQ(static_cast<int32_t>(0x56781234), t.result_rotr_16);
    CHECK_EQ(static_cast<int32_t>(0x45678123), t.result_rotr_20);
    CHECK_EQ(static_cast<int32_t>(0x34567812), t.result_rotr_24);
    CHECK_EQ(static_cast<int32_t>(0x23456781), t.result_rotr_28);

    CHECK_EQ(static_cast<int32_t>(0x81234567), t.result_rotrv_4);
    CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotrv_8);
    CHECK_EQ(static_cast<int32_t>(0x67812345), t.result_rotrv_12);
    CHECK_EQ(static_cast<int32_t>(0x56781234), t.result_rotrv_16);
    CHECK_EQ(static_cast<int32_t>(0x45678123), t.result_rotrv_20);
    CHECK_EQ(static_cast<int32_t>(0x34567812), t.result_rotrv_24);
    CHECK_EQ(static_cast<int32_t>(0x23456781), t.result_rotrv_28);
  }
}


TEST(MIPS9) {
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
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  USE(code);
}


TEST(MIPS10) {
  // Test conversions between doubles and long integers.
  // Test hos the long ints map to FP regs pairs.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double a_converted;
    double b;
    int32_t dbl_mant;
    int32_t dbl_exp;
    int32_t long_hi;
    int32_t long_lo;
    int64_t long_as_int64;
    int32_t b_long_hi;
    int32_t b_long_lo;
    int64_t b_long_as_int64;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  if (kArchVariant == kMips64r2) {
    // Rewritten for FR=1 FPU mode:
    //  -  32 FP regs of 64-bits each, no odd/even pairs.
    //  -  Note that cvt_l_d/cvt_d_l ARE legal in FR=1 mode.
    // Load all structure elements to registers.
    __ Ldc1(f0, MemOperand(a0, offsetof(T, a)));

    // Save the raw bits of the double.
    __ mfc1(a4, f0);
    __ mfhc1(a5, f0);
    __ Sw(a4, MemOperand(a0, offsetof(T, dbl_mant)));
    __ Sw(a5, MemOperand(a0, offsetof(T, dbl_exp)));

    // Convert double in f0 to long, save hi/lo parts.
    __ cvt_l_d(f0, f0);
    __ mfc1(a4, f0);  // f0 LS 32 bits of long.
    __ mfhc1(a5, f0);  // f0 MS 32 bits of long.
    __ Sw(a4, MemOperand(a0, offsetof(T, long_lo)));
    __ Sw(a5, MemOperand(a0, offsetof(T, long_hi)));

    // Combine the high/low ints, convert back to double.
    __ dsll32(a6, a5, 0);  // Move a5 to high bits of a6.
    __ or_(a6, a6, a4);
    __ dmtc1(a6, f1);
    __ cvt_d_l(f1, f1);
    __ Sdc1(f1, MemOperand(a0, offsetof(T, a_converted)));

    // Convert the b long integers to double b.
    __ Lw(a4, MemOperand(a0, offsetof(T, b_long_lo)));
    __ Lw(a5, MemOperand(a0, offsetof(T, b_long_hi)));
    __ mtc1(a4, f8);  // f8 LS 32-bits.
    __ mthc1(a5, f8);  // f8 MS 32-bits.
    __ cvt_d_l(f10, f8);
    __ Sdc1(f10, MemOperand(a0, offsetof(T, b)));

    // Convert double b back to long-int.
    __ Ldc1(f31, MemOperand(a0, offsetof(T, b)));
    __ cvt_l_d(f31, f31);
    __ dmfc1(a7, f31);
    __ Sd(a7, MemOperand(a0, offsetof(T, b_long_as_int64)));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.a = 2.147483647e9;       // 0x7FFFFFFF -> 0x41DFFFFFFFC00000 as double.
    t.b_long_hi = 0x000000FF;  // 0xFF00FF00FF -> 0x426FE01FE01FE000 as double.
    t.b_long_lo = 0x00FF00FF;
    f.Call(&t, 0, 0, 0, 0);

    CHECK_EQ(static_cast<int32_t>(0x41DFFFFF), t.dbl_exp);
    CHECK_EQ(static_cast<int32_t>(0xFFC00000), t.dbl_mant);
    CHECK_EQ(0, t.long_hi);
    CHECK_EQ(static_cast<int32_t>(0x7FFFFFFF), t.long_lo);
    CHECK_EQ(2.147483647e9, t.a_converted);

    // 0xFF00FF00FF -> 1.095233372415e12.
    CHECK_EQ(1.095233372415e12, t.b);
    CHECK_EQ(static_cast<int64_t>(0xFF00FF00FF), t.b_long_as_int64);
  }
}


TEST(MIPS11) {
  // Do not run test on MIPS64r6, as these instructions are removed.
  if (kArchVariant != kMips64r6) {
    // Test LWL, LWR, SWL and SWR instructions.
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);

    struct T {
      int32_t reg_init;
      int32_t mem_init;
      int32_t lwl_0;
      int32_t lwl_1;
      int32_t lwl_2;
      int32_t lwl_3;
      int32_t lwr_0;
      int32_t lwr_1;
      int32_t lwr_2;
      int32_t lwr_3;
      int32_t swl_0;
      int32_t swl_1;
      int32_t swl_2;
      int32_t swl_3;
      int32_t swr_0;
      int32_t swr_1;
      int32_t swr_2;
      int32_t swr_3;
    };
    T t;

    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    // Test all combinations of LWL and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, lwl_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a5, MemOperand(a0, offsetof(T, mem_init) + 1));
    __ Sw(a5, MemOperand(a0, offsetof(T, lwl_1)));

    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a6, MemOperand(a0, offsetof(T, mem_init) + 2));
    __ Sw(a6, MemOperand(a0, offsetof(T, lwl_2)));

    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ lwl(a7, MemOperand(a0, offsetof(T, mem_init) + 3));
    __ Sw(a7, MemOperand(a0, offsetof(T, lwl_3)));

    // Test all combinations of LWR and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, lwr_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a5, MemOperand(a0, offsetof(T, mem_init) + 1));
    __ Sw(a5, MemOperand(a0, offsetof(T, lwr_1)));

    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a6, MemOperand(a0, offsetof(T, mem_init) + 2));
    __ Sw(a6, MemOperand(a0, offsetof(T, lwr_2)));

    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ lwr(a7, MemOperand(a0, offsetof(T, mem_init) + 3));
    __ Sw(a7, MemOperand(a0, offsetof(T, lwr_3)));

    // Test all combinations of SWL and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, swl_0)));
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a4, MemOperand(a0, offsetof(T, swl_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a5, MemOperand(a0, offsetof(T, swl_1)));
    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a5, MemOperand(a0, offsetof(T, swl_1) + 1));

    __ Lw(a6, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a6, MemOperand(a0, offsetof(T, swl_2)));
    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a6, MemOperand(a0, offsetof(T, swl_2) + 2));

    __ Lw(a7, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a7, MemOperand(a0, offsetof(T, swl_3)));
    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ swl(a7, MemOperand(a0, offsetof(T, swl_3) + 3));

    // Test all combinations of SWR and vAddr.
    __ Lw(a4, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a4, MemOperand(a0, offsetof(T, swr_0)));
    __ Lw(a4, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a4, MemOperand(a0, offsetof(T, swr_0)));

    __ Lw(a5, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a5, MemOperand(a0, offsetof(T, swr_1)));
    __ Lw(a5, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a5, MemOperand(a0, offsetof(T, swr_1) + 1));

    __ Lw(a6, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a6, MemOperand(a0, offsetof(T, swr_2)));
    __ Lw(a6, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a6, MemOperand(a0, offsetof(T, swr_2) + 2));

    __ Lw(a7, MemOperand(a0, offsetof(T, mem_init)));
    __ Sw(a7, MemOperand(a0, offsetof(T, swr_3)));
    __ Lw(a7, MemOperand(a0, offsetof(T, reg_init)));
    __ swr(a7, MemOperand(a0, offsetof(T, swr_3) + 3));

    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    t.reg_init = 0xAABBCCDD;
    t.mem_init = 0x11223344;

    f.Call(&t, 0, 0, 0, 0);

    if (kArchEndian == kLittle) {
      CHECK_EQ(static_cast<int32_t>(0x44BBCCDD), t.lwl_0);
      CHECK_EQ(static_cast<int32_t>(0x3344CCDD), t.lwl_1);
      CHECK_EQ(static_cast<int32_t>(0x223344DD), t.lwl_2);
      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwl_3);

      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwr_0);
      CHECK_EQ(static_cast<int32_t>(0xAA112233), t.lwr_1);
      CHECK_EQ(static_cast<int32_t>(0xAABB1122), t.lwr_2);
      CHECK_EQ(static_cast<int32_t>(0xAABBCC11), t.lwr_3);

      CHECK_EQ(static_cast<int32_t>(0x112233AA), t.swl_0);
      CHECK_EQ(static_cast<int32_t>(0x1122AABB), t.swl_1);
      CHECK_EQ(static_cast<int32_t>(0x11AABBCC), t.swl_2);
      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swl_3);

      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swr_0);
      CHECK_EQ(static_cast<int32_t>(0xBBCCDD44), t.swr_1);
      CHECK_EQ(static_cast<int32_t>(0xCCDD3344), t.swr_2);
      CHECK_EQ(static_cast<int32_t>(0xDD223344), t.swr_3);
    } else {
      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwl_0);
      CHECK_EQ(static_cast<int32_t>(0x223344DD), t.lwl_1);
      CHECK_EQ(static_cast<int32_t>(0x3344CCDD), t.lwl_2);
      CHECK_EQ(static_cast<int32_t>(0x44BBCCDD), t.lwl_3);

      CHECK_EQ(static_cast<int32_t>(0xAABBCC11), t.lwr_0);
      CHECK_EQ(static_cast<int32_t>(0xAABB1122), t.lwr_1);
      CHECK_EQ(static_cast<int32_t>(0xAA112233), t.lwr_2);
      CHECK_EQ(static_cast<int32_t>(0x11223344), t.lwr_3);

      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swl_0);
      CHECK_EQ(static_cast<int32_t>(0x11AABBCC), t.swl_1);
      CHECK_EQ(static_cast<int32_t>(0x1122AABB), t.swl_2);
      CHECK_EQ(static_cast<int32_t>(0x112233AA), t.swl_3);

      CHECK_EQ(static_cast<int32_t>(0xDD223344), t.swr_0);
      CHECK_EQ(static_cast<int32_t>(0xCCDD3344), t.swr_1);
      CHECK_EQ(static_cast<int32_t>(0xBBCCDD44), t.swr_2);
      CHECK_EQ(static_cast<int32_t>(0xAABBCCDD), t.swr_3);
    }
  }
}


TEST(MIPS12) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int32_t x;
    int32_t y;
    int32_t y1;
    int32_t y2;
    int32_t y3;
    int32_t y4;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ mov(t2, fp);  // Save frame pointer.
  __ mov(fp, a0);  // Access struct T by fp.
  __ Lw(a4, MemOperand(a0, offsetof(T, y)));
  __ Lw(a7, MemOperand(a0, offsetof(T, y4)));

  __ addu(a5, a4, a7);
  __ subu(t0, a4, a7);
  __ nop();
  __ push(a4);  // These instructions dis
"""


```