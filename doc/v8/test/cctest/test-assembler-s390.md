Response: The user wants me to analyze a C++ source code file and summarize its functionality.
The file is located at `v8/test/cctest/test-assembler-s390.cc` and seems to contain tests for the assembler on the s390 architecture within the V8 JavaScript engine project.

Therefore, the core functionality of this file is to **test the s390 assembler by generating and executing machine code snippets**.

If there's a relation to JavaScript, it would be in the sense that the tested assembler is used by V8 to compile JavaScript code into native machine code for the s390 architecture.

To demonstrate the connection with JavaScript, I can create a simple JavaScript function and explain how the assembler (or similar low-level components) within V8 would handle its execution on s390.
这个C++源代码文件 `v8/test/cctest/test-assembler-s390.cc` 的主要功能是 **测试 V8 JavaScript 引擎在 s390 架构上的汇编器 (Assembler)**。

具体来说，这个文件包含了一系列的单元测试，每个测试都生成一段简短的 s390 汇编代码，然后执行这段代码并验证其结果是否符合预期。这些测试覆盖了 s390 架构上各种汇编指令的使用，例如：

* **算术运算:**  加法 (`ar`, `agr`, `ahi`, `aghi`)，减法 (`sr`, `sgr`)，乘法 (`mr_z`, `msrkc`, `msgrkc`)，除法 (`dr`)
* **逻辑运算:** 与 (`nr`, `ngr`)，或 (`or_z`, `ogr`)，异或 (`xr`, `xgr`)
* **数据加载和存储:**  加载立即数 (`lhi`, `llilf`, `iilf`, `iihf`, `lgfi`)，加载和存储寄存器 (`lr`, `lgr`)，存储到内存 (`stm`)，从内存加载 (`lay`, `a`, `ay`)
* **分支控制:** 无条件跳转 (`b`)，条件跳转 (`brc`, `brcl`, `beq`, `bne`, `ble`, `bgt`)，循环跳转 (`brxh`, `brxhg`)
* **位操作:**  位移 (`slag`, `sll`)，位测试 (`tmhh`, `tmhl`)
* **浮点运算:** (`cdfbr`, `cfdbr`, `adbr`)
* **向量指令:** (以 `v` 开头的指令，例如 `vrepi`, `va`, `vs` 等)，这些指令测试了 s390 架构的向量扩展功能。
* **其他指令:**  例如用于函数描述符的指令 (`function_descriptor`)，以及一些特殊的指令（例如 `msrkc`, `msgrkc` 需要特定的 CPU 特性支持）。

**与 JavaScript 的关系以及示例：**

V8 引擎负责将 JavaScript 代码编译成可以在特定硬件平台上执行的机器码。在这个过程中，汇编器扮演着关键角色，它将 V8 内部的中间表示 (IR) 转换成目标机器（例如 s390）的汇编指令。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

console.log(add(3, 4));
```

当 V8 编译这段 JavaScript 代码并在 s390 架构上执行时，其内部的汇编器可能会生成类似于 `test-assembler-s390.cc` 中 `TEST(0)` 部分的代码：

```assembly
  lhi(r1, Operand(3));    // 将立即数 3 加载到寄存器 r1 (对应参数 a)
  llilf(r2, Operand(4));  // 将立即数 4 加载到寄存器 r2 (对应参数 b)
  ar(r2, r1);             // 将 r1 和 r2 的值相加，结果存回 r2
  b(r14);                 // 返回 (r14 通常是返回地址寄存器)
```

在这个简化的例子中：

* `lhi(r1, Operand(3))` 类似于在 JavaScript 中将 `a` 的值 (3) 放入一个寄存器。
* `llilf(r2, Operand(4))` 类似于将 `b` 的值 (4) 放入另一个寄存器。
* `ar(r2, r1)`  执行实际的加法 `a + b`，并将结果存储在寄存器 `r2` 中。
* `b(r14)`  表示函数执行完毕，将结果返回。

`test-assembler-s390.cc` 中的 `TEST(0)` 实际上就是用 C++ 代码模拟了上述汇编过程，并验证了 `ar` 指令的正确性。它创建了一个执行上面汇编代码的函数，然后调用该函数并断言其返回值为 7。

**总结来说，`v8/test/cctest/test-assembler-s390.cc` 通过编写和执行汇编代码测试用例，确保 V8 在 s390 架构上能够正确地生成和执行机器码，从而保证 JavaScript 代码在该平台上的正确运行。**

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-s390.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
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

#include "src/init/v8.h"

#include "src/codegen/macro-assembler.h"
#include "src/codegen/s390/assembler-s390-inl.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "test/cctest/cctest.h"
#include "test/common/assembler-tester.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc.
// TODO(s390): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p0, int p1, int p2, int p3, int p4);
using F4 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.

// Simple add parameter 1 to parameter 2 and return
TEST(0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ lhi(r1, Operand(3));    // test 4-byte instr
  __ llilf(r2, Operand(4));  // test 6-byte instr
  __ lgr(r2, r2);            // test 2-byte opcode
  __ ar(r2, r1);             // test 2-byte instr
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(3, 4, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(7, static_cast<int>(res));
}

// Loop 100 times, adding loop counter to result
TEST(1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label L, C;

#if defined(_AIX)
  __ function_descriptor();
#endif

  __ lr(r3, r2);
  __ lhi(r2, Operand(0, RelocInfo::NO_INFO));
  __ b(&C);

  __ bind(&L);
  __ ar(r2, r3);
  __ ahi(r3, Operand(-1 & 0xFFFF));

  __ bind(&C);
  __ cfi(r3, Operand(0, RelocInfo::NO_INFO));
  __ bne(&L);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(100, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(5050, static_cast<int>(res));
}

TEST(2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});
  Label L, C;

#if defined(_AIX)
  __ function_descriptor();
#endif

  __ lgr(r3, r2);
  __ lhi(r2, Operand(1));
  __ b(&C);

  __ bind(&L);
  __ lr(r5, r2);    // Set up muliplicant in R4:R5
  __ mr_z(r4, r3);  // this is actually R4:R5 = R5 * R2
  __ lr(r2, r5);
  __ ahi(r3, Operand(-1 & 0xFFFF));

  __ bind(&C);
  __ cfi(r3, Operand(0, RelocInfo::NO_INFO));
  __ bne(&L);
  __ b(r14);

  // some relocated stuff here, not executed
  __ RecordComment("dead code, just testing relocations");
  __ iilf(r0, Operand(isolate->factory()->true_value()));
  __ RecordComment("dead code, just testing immediate operands");
  __ iilf(r0, Operand(-1));
  __ iilf(r0, Operand(0xFF000000));
  __ iilf(r0, Operand(0xF0F0F0F0));
  __ iilf(r0, Operand(0xFFF0FFFF));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(10, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(3628800, static_cast<int>(res));
}

TEST(3) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ ar(r14, r13);
  __ sr(r14, r13);
  __ mr_z(r14, r13);
  __ dr(r14, r13);
  __ or_z(r14, r13);
  __ nr(r14, r13);
  __ xr(r14, r13);

  __ agr(r14, r13);
  __ sgr(r14, r13);
  __ ogr(r14, r13);
  __ ngr(r14, r13);
  __ xgr(r14, r13);

  __ ahi(r13, Operand(123));
  __ aghi(r13, Operand(123));
  __ stm(r1, r2, MemOperand(r3, r0, 123));
  __ slag(r1, r2, Operand(123));
  __ lay(r1, MemOperand(r2, r3, -123));
  __ a(r13, MemOperand(r1, r2, 123));
  __ ay(r13, MemOperand(r1, r2, 123));
  __ brc(Condition(14), Operand(123));
  __ brc(Condition(14), Operand(-123));
  __ brcl(Condition(14), Operand(123));
  __ brcl(Condition(14), Operand(-123));
  __ iilf(r13, Operand(123456789));
  __ iihf(r13, Operand(-123456789));
  __ mvc(MemOperand(r0, 123), MemOperand(r4, 567), Operand(88));
  __ sll(r13, Operand(10));

  uint8_t* bufPos = assm.buffer_pos();
  ::printf("buffer position = %p", static_cast<void*>(bufPos));
  ::fflush(stdout);
  // OS::DebugBreak();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  USE(code);
  ::exit(0);
}

#if 0
TEST(4) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label L2, L3, L4;

  __ chi(r2, Operand(10));
  __ ble(&L2);
  __ lr(r2, r4);
  __ ar(r2, r3);
  __ b(&L3);

  __ bind(&L2);
  __ chi(r2, Operand(5));
  __ bgt(&L4);

  __ lhi(r2, Operand::Zero());
  __ b(&L3);

  __ bind(&L4);
  __ lr(r2, r3);
  __ sr(r2, r4);

  __ bind(&L3);
  __ lgfr(r2, r3);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = isolate->factory()->NewCode(
      desc, CodeKind::FOR_TESTING, Handle<Code>());
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(
      f.Call(3, 4, 3, 0, 0));
  ::printf("f() = %" V8PRIdPTR "\n", res);
  CHECK_EQ(4, static_cast<int>(res));
}


// Test ExtractBitRange
TEST(5) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ mov(r2, Operand(0x12345678));
  __ ExtractBitRange(r3, r2, 3, 2);
  __ lgfr(r2, r3);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = isolate->factory()->NewCode(
      desc, CodeKind::FOR_TESTING, Handle<Code>());
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res =
    reinterpret_cast<intptr_t>(f.Call(3, 4, 3, 0, 0));
  ::printf("f() = %" V8PRIdPTR "\n", res);
  CHECK_EQ(2, static_cast<int>(res));
}


// Test JumpIfSmi
TEST(6) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label yes;

  __ mov(r2, Operand(0x12345678));
  __ JumpIfSmi(r2, &yes);
  __ beq(&yes);
  __ Load(r2, Operand::Zero());
  __ b(r14);
  __ bind(&yes);
  __ Load(r2, Operand(1));
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = isolate->factory()->NewCode(
      desc, CodeKind::FOR_TESTING, Handle<Code>());
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res =
    reinterpret_cast<intptr_t>(f.Call(3, 4, 3, 0, 0));
  ::printf("f() = %" V8PRIdPTR "\n", res);
  CHECK_EQ(1, static_cast<int>(res));
}


// Test fix<->floating point conversion.
TEST(7) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label yes;

  __ mov(r3, Operand(0x1234));
  __ cdfbr(d1, r3);
  __ ldr(d2, d1);
  __ adbr(d1, d2);
  __ cfdbr(Condition(0), r2, d1);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = isolate->factory()->NewCode(
      desc, CodeKind::FOR_TESTING, Handle<Code>());
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res =
    reinterpret_cast<intptr_t>(f.Call(3, 4, 3, 0, 0));
  ::printf("f() = %" V8PRIdPTR "\n", res);
  CHECK_EQ(0x2468, static_cast<int>(res));
}


// Test DSGR
TEST(8) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  // Zero upper bits of r3/r4
  __ llihf(r3, Operand::Zero());
  __ llihf(r4, Operand::Zero());
  __ mov(r3, Operand(0x0002));
  __ mov(r4, Operand(0x0002));
  __ dsgr(r2, r4);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = isolate->factory()->NewCode(
      desc, CodeKind::FOR_TESTING, Handle<Code>());
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res =
    reinterpret_cast<intptr_t>(f.Call(100, 0,
                                                   0, 0, 0));
  ::printf("f() = %" V8PRIdPTR  "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}


// Test LZDR
TEST(9) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ lzdr(d4);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code = isolate->factory()->NewCode(
      desc, CodeKind::FOR_TESTING, Handle<Code>());
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res =
    reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIdPTR  "\n", res);
}
#endif

// Test msrkc and msgrkc
TEST(10) {
  if (!CpuFeatures::IsSupported(MISC_INSTR_EXT2)) {
    return;
  }

  ::printf("MISC_INSTR_EXT2 is enabled.\n");

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label ok, failed;

  {  // test 1: msrkc
    __ lgfi(r2, Operand(3));
    __ lgfi(r3, Operand(4));
    __ msrkc(r1, r2, r3);                                  // 3 * 4
    __ b(static_cast<Condition>(le | overflow), &failed);  // test failed.
    __ chi(r1, Operand(12));
    __ bne(&failed);  // test failed.

    __ lgfi(r2, Operand(-3));
    __ lgfi(r3, Operand(4));
    __ msrkc(r1, r2, r3);                                  // -3 * 4
    __ b(static_cast<Condition>(ge | overflow), &failed);  // test failed.
    __ chi(r1, Operand(-12));
    __ bne(&failed);  // test failed.

    __ iilf(r2, Operand(0x80000000));
    __ lgfi(r3, Operand(-1));
    __ msrkc(r1, r2, r3);       // INT_MIN * -1
    __ b(nooverflow, &failed);  // test failed.
    __ cfi(r1, Operand(0x80000000));
    __ bne(&failed);  // test failed.
  }

  {  // test 1: msgrkc
    __ lgfi(r2, Operand(3));
    __ lgfi(r3, Operand(4));
    __ msgrkc(r1, r2, r3);                                 // 3 * 4
    __ b(static_cast<Condition>(le | overflow), &failed);  // test failed.
    __ chi(r1, Operand(12));
    __ bne(&failed);  // test failed.

    __ lgfi(r2, Operand(-3));
    __ lgfi(r3, Operand(4));
    __ msgrkc(r1, r2, r3);                                 // -3 * 4
    __ b(static_cast<Condition>(ge | overflow), &failed);  // test failed.
    __ chi(r1, Operand(-12));
    __ bne(&failed);  // test failed.

    __ lgfi(r2, Operand::Zero());
    __ iihf(r2, Operand(0x80000000));
    __ lgfi(r3, Operand(-1));
    __ msgrkc(r1, r2, r3);      // INT_MIN * -1
    __ b(nooverflow, &failed);  // test failed.
    __ cgr(r1, r2);
    __ bne(&failed);  // test failed.
  }

  __ bind(&ok);
  __ lgfi(r2, Operand::Zero());
  __ b(r14);  // test done.

  __ bind(&failed);
  __ lgfi(r2, Operand(1));
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(3, 4, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}


// brxh
TEST(11) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  Label ok, failed, continue1, continue2;
  // r1 - operand; r3 - inc / test val
  __ lgfi(r1, Operand(1));
  __ lgfi(r3, Operand(1));
  __ brxh(r1, r3, &continue1);
  __ b(&failed);

  __ bind(&continue1);
  __ lgfi(r1, Operand(-2));
  __ lgfi(r3, Operand(1));
  __ brxh(r1, r3, &failed);
  __ brxh(r1, r3, &failed);
  __ brxh(r1, r3, &failed);
  __ brxh(r1, r3, &continue2);
  __ b(&failed);

  //r1 - operand; r4 - inc; r5 - test val
  __ bind(&continue2);
  __ lgfi(r1, Operand(-2));
  __ lgfi(r4, Operand(1));
  __ lgfi(r5, Operand(-1));
  __ brxh(r1, r4, &failed);
  __ brxh(r1, r4, &ok);
  __ b(&failed);

  __ bind(&ok);
  __ lgfi(r2, Operand::Zero());
  __ b(r14);  // test done.

  __ bind(&failed);
  __ lgfi(r2, Operand(1));
  __ b(r14);  // test done.

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIdPTR  "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}


// brxhg
TEST(12) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  Label ok, failed, continue1, continue2;
  // r1 - operand; r3 - inc / test val
  __ lgfi(r1, Operand(1));
  __ lgfi(r3, Operand(1));
  __ brxhg(r1, r3, &continue1);
  __ b(&failed);

  __ bind(&continue1);
  __ lgfi(r1, Operand(-2));
  __ lgfi(r3, Operand(1));
  __ brxhg(r1, r3, &failed);
  __ brxhg(r1, r3, &failed);
  __ brxhg(r1, r3, &failed);
  __ brxhg(r1, r3, &continue2);
  __ b(&failed);

  //r1 - operand; r4 - inc; r5 - test val
  __ bind(&continue2);
  __ lgfi(r1, Operand(-2));
  __ lgfi(r4, Operand(1));
  __ lgfi(r5, Operand(-1));
  __ brxhg(r1, r4, &failed);
  __ brxhg(r1, r4, &ok);
  __ b(&failed);

  __ bind(&ok);
  __ lgfi(r2, Operand::Zero());
  __ b(r14);  // test done.

  __ bind(&failed);
  __ lgfi(r2, Operand(1));
  __ b(r14);  // test done.

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIdPTR  "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}

// vector basics
TEST(13) {
  // check if the VECTOR_FACILITY is supported
  if (!CpuFeatures::IsSupported(VECTOR_FACILITY)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label done, error;

  // vector loads, replicate, and arithmetics
  __ vrepi(d2, Operand(100), Condition(2));
  __ lay(sp, MemOperand(sp, -4));
  __ sty(r3, MemOperand(sp));
  __ vlrep(d3, MemOperand(sp), Condition(2));
  __ lay(sp, MemOperand(sp, 4));
  __ vlvg(d4, r2, MemOperand(r0, 2), Condition(2));
  __ vrep(d4, d4, Operand(2), Condition(2));
  __ lay(sp, MemOperand(sp, -kSimd128Size));
  __ vst(d4, MemOperand(sp), Condition(0));
  __ va(d2, d2, d3, Condition(0), Condition(0), Condition(2));
  __ vl(d3, MemOperand(sp), Condition(0));
  __ lay(sp, MemOperand(sp, kSimd128Size));
  __ vs(d2, d2, d3, Condition(0), Condition(0), Condition(2));
  __ vml(d3, d3, d2, Condition(0), Condition(0), Condition(2));
  __ lay(sp, MemOperand(sp, -4));
  __ vstef(d3, MemOperand(sp), Condition(3));
  __ vlef(d2, MemOperand(sp), Condition(0));
  __ lay(sp, MemOperand(sp, 4));
  __ vlgv(r2, d2, MemOperand(r0, 0), Condition(2));
  __ cfi(r2, Operand(15000));
  __ bne(&error);
  __ vrepi(d2, Operand(-30), Condition(3));
  __ vlc(d2, d2, Condition(0), Condition(0), Condition(3));
  __ vlgv(r2, d2, MemOperand(r0, 1), Condition(3));
  __ lgfi(r1, Operand(-30));
  __ lcgr(r1, r1);
  __ cgr(r1, r2);
  __ bne(&error);
  __ lgfi(r2, Operand(0));
  __ b(&done);
  __ bind(&error);
  __ lgfi(r2, Operand(1));
  __ bind(&done);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(50, 250, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}


// vector sum, packs, unpacks
TEST(14) {
  // check if the VECTOR_FACILITY is supported
  if (!CpuFeatures::IsSupported(VECTOR_FACILITY)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label done, error;

  // vector sum word and doubleword
  __ vrepi(d2, Operand(100), Condition(2));
  __ vsumg(d1, d2, d2, Condition(0), Condition(0), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(3));
  __ cfi(r2, Operand(300));
  __ bne(&error);
  __ vrepi(d1, Operand(0), Condition(1));
  __ vrepi(d2, Operand(75), Condition(1));
  __ vsum(d1, d2, d1, Condition(0), Condition(0), Condition(1));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(2));
  __ cfi(r2, Operand(150));
  __ bne(&error);
  // vector packs
  __ vrepi(d1, Operand(200), Condition(2));
  __ vpk(d1, d1, d1, Condition(0), Condition(0), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 5), Condition(1));
  __ cfi(r2, Operand(200));
  __ bne(&error);
  __ vrepi(d2, Operand(30), Condition(1));
  __ vpks(d1, d1, d2, Condition(0), Condition(1));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(0));
  __ vlgv(r3, d1, MemOperand(r0, 8), Condition(0));
  __ ar(r2, r3);
  __ cfi(r2, Operand(157));
  __ bne(&error);
  __ vrepi(d1, Operand(270), Condition(1));
  __ vrepi(d2, Operand(-30), Condition(1));
  __ vpkls(d1, d1, d2, Condition(0), Condition(1));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(0));
  __ vlgv(r3, d1, MemOperand(r0, 8), Condition(0));
  __ cfi(r2, Operand(255));
  __ bne(&error);
  __ cfi(r3, Operand(255));
  __ bne(&error);
  // vector unpacks
  __ vrepi(d1, Operand(50), Condition(2));
  __ lgfi(r1, Operand(10));
  __ lgfi(r2, Operand(20));
  __ vlvg(d1, r1, MemOperand(r0, 0), Condition(2));
  __ vlvg(d1, r2, MemOperand(r0, 2), Condition(2));
  __ vuph(d2, d1, Condition(0), Condition(0), Condition(2));
  __ vupl(d1, d1, Condition(0), Condition(0), Condition(2));
  __ va(d1, d1, d2, Condition(0), Condition(0), Condition(3));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(3));
  __ vlgv(r3, d1, MemOperand(r0, 1), Condition(3));
  __ ar(r2, r3);
  __ cfi(r2, Operand(130));
  __ bne(&error);
  __ vrepi(d1, Operand(-100), Condition(2));
  __ vuplh(d2, d1, Condition(0), Condition(0), Condition(2));
  __ vupll(d1, d1, Condition(0), Condition(0), Condition(2));
  __ va(d1, d1, d1, Condition(0), Condition(0), Condition(3));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(3));
  __ cfi(r2, Operand(0x1ffffff38));
  __ bne(&error);
  __ lgfi(r2, Operand(0));
  __ b(&done);
  __ bind(&error);
  __ lgfi(r2, Operand(1));
  __ bind(&done);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}

// vector comparisons
TEST(15) {
  // check if the VECTOR_FACILITY is supported
  if (!CpuFeatures::IsSupported(VECTOR_FACILITY)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label done, error;

  // vector max and min
  __ vrepi(d2, Operand(-50), Condition(2));
  __ vrepi(d3, Operand(40), Condition(2));
  __ vmx(d1, d2, d3, Condition(0), Condition(0), Condition(2));
  __ vlgv(r1, d1, MemOperand(r0, 0), Condition(2));
  __ vmnl(d1, d2, d3, Condition(0), Condition(0), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(2));
  __ cgr(r1, r2);
  __ vmxl(d1, d2, d3, Condition(0), Condition(0), Condition(2));
  __ vlgv(r1, d1, MemOperand(r0, 0), Condition(2));
  __ vmn(d1, d2, d3, Condition(0), Condition(0), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(2));
  __ cgr(r1, r2);
  __ bne(&error);
  // vector comparisons
  __ vlr(d4, d3, Condition(0), Condition(0), Condition(0));
  __ vceq(d1, d3, d4, Condition(0), Condition(2));
  __ vlgv(r1, d1, MemOperand(r0, 0), Condition(2));
  __ vch(d1, d2, d3, Condition(0), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(2));
  __ vchl(d1, d2, d3, Condition(0), Condition(2));
  __ vlgv(r3, d1, MemOperand(r0, 0), Condition(2));
  __ ar(r2, r3);
  __ cgr(r1, r2);
  __ bne(&error);
  // vector bitwise ops
  __ vrepi(d2, Operand(0), Condition(2));
  __ vn(d1, d2, d3, Condition(0), Condition(0), Condition(0));
  __ vceq(d1, d1, d2, Condition(0), Condition(2));
  __ vlgv(r1, d1, MemOperand(r0, 0), Condition(2));
  __ vo(d1, d2, d3, Condition(0), Condition(0), Condition(0));
  __ vx(d1, d1, d2, Condition(0), Condition(0), Condition(0));
  __ vceq(d1, d1, d3, Condition(0), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(2));
  __ cgr(r1, r2);
  __ bne(&error);
  // vector bitwise shift
  __ vceq(d1, d1, d1, Condition(0), Condition(2));
  __ vesra(d1, d1, MemOperand(r0, 5), Condition(2));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(2));
  __ cgr(r3, r2);
  __ bne(&error);
  __ lgfi(r1, Operand(0xfffff895));
  __ vlvg(d1, r1, MemOperand(r0, 0), Condition(3));
  __ vrep(d1, d1, Operand(0), Condition(3));
  __ slag(r1, r1, Operand(10));
  __ vesl(d1, d1, MemOperand(r0, 10), Condition(3));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(3));
  __ cgr(r1, r2);
  __ bne(&error);
  __ srlg(r1, r1, Operand(10));
  __ vesrl(d1, d1, MemOperand(r0, 10), Condition(3));
  __ vlgv(r2, d1, MemOperand(r0, 0), Condition(3));
  __ cgr(r1, r2);
  __ bne(&error);
  __ lgfi(r2, Operand(0));
  __ b(&done);
  __ bind(&error);
  __ lgfi(r2, Operand(1));
  __ bind(&done);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}

// vector select and test mask
TEST(16) {
  // check if the VECTOR_FACILITY is supported
  if (!CpuFeatures::IsSupported(VECTOR_FACILITY)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label done, error;

  // vector select
  __ vrepi(d1, Operand(0x1011), Condition(1));
  __ vrepi(d2, Operand(0x4343), Condition(1));
  __ vrepi(d3, Operand(0x3434), Condition(1));
  __ vsel(d1, d2, d3, d1, Condition(0), Condition(0));
  __ vlgv(r2, d1, MemOperand(r0, 2), Condition(1));
  __ cfi(r2, Operand(0x2425));
  __ bne(&error);
  // vector test mask
  __ vtm(d2, d1, Condition(0), Condition(0), Condition(0));
  __ b(Condition(0x1), &error);
  __ b(Condition(0x8), &error);
  __ lgfi(r2, Operand(0));
  __ b(&done);
  __ bind(&error);
  __ lgfi(r2, Operand(1));
  __ bind(&done);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}

// vector fp instructions
TEST(17) {
  // check if the VECTOR_FACILITY is supported
  if (!CpuFeatures::IsSupported(VECTOR_FACILITY)) {
    return;
  }

  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label done, error;

  // vector fp arithmetics
  __ cdgbr(d1, r3);
  __ ldr(d2, d1);
  __ vfa(d1, d1, d2, Condition(0), Condition(0), Condition(3));
  __ cdgbr(d3, r2);
  __ vfm(d1, d1, d3, Condition(0), Condition(0), Condition(3));
  __ vfs(d1, d1, d2, Condition(0), Condition(0), Condition(3));
  __ vfd(d1, d1, d3, Condition(0), Condition(0), Condition(3));
  __ vfsq(d1, d1, Condition(0), Condition(0), Condition(3));
  __ cgdbr(Condition(4), r2, d1);
  __ cgfi(r2, Operand(0x8));
  __ bne(&error);
  // vector fp comparisons
  __ cdgbra(Condition(4), d1, r3);
  __ ldr(d2, d1);
  __ vfa(d1, d1, d2, Condition(0), Condition(0), Condition(3));
#ifdef VECTOR_ENHANCE_FACILITY_1
  __ vfmin(d3, d1, d2, Condition(1), Condition(0), Condition(3));
  __ vfmax(d4, d1, d2, Condition(1), Condition(0), Condition(3));
#else
  __ vlr(d3, d2, Condition(0), Condition(0), Condition(0));
  __ vlr(d4, d1, Condition(0), Condition(0), Condition(0));
#endif
  __ vfch(d5, d4, d3, Condition(0), Condition(0), Condition(3));
  __ vfche(d3, d3, d4, Condition(0), Condition(0), Condition(3));
  __ vfce(d4, d1, d4, Condition(0), Condition(0), Condition(3));
  __ va(d3, d3, d4, Condition(0), Condition(0), Condition(3));
  __ vs(d3, d3, d5, Condition(0), Condition(0), Condition(3));
  __ vlgv(r2, d3, MemOperand(r0, 0), Condition(3));
  // vector fp sign ops
  __ lgfi(r1, Operand(-0x50));
  __ cdgbra(Condition(4), d1, r1);
  __ vfpso(d1, d1, Condition(0), Condition(0), Condition(3));
  __ vfi(d1, d1, Condition(5), Condition(0), Condition(3));
  __ vlgv(r1, d1, MemOperand(r0, 0), Condition(3));
  __ agr(r2, r1);
  __ srlg(r2, r2, Operand(32));
  __ cgfi(r2, Operand(0x40540000));
  __ bne(&error);
  __ lgfi(r2, Operand(0));
  __ b(&done);
  __ bind(&error);
  __ lgfi(r2, Operand(1));
  __ bind(&done);
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0x2, 0x30, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}

//TMHH, TMHL
TEST(18) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  Label done, error;
  Label continue1, continue2, continue3, continue4;
  Label continue5, continue6, continue7, continue8, continue9;

  // selected bits all 0
  __ lgfi(r1, Operand(0));
  __ tmhh(r1, Operand(1));
  __ beq(&continue1); //8
  __ b(&error);

  __ bind(&continue1);
  __ tmhl(r1, Operand(1));
  __ beq(&continue2); //8
  __ b(&error);

  // mask = 0
  __ bind(&continue2);
  __ lgfi(r1, Operand(-1));
  __ tmhh(r1, Operand(0));
  __ beq(&continue3);  //8
  __ b(&error);

  __ bind(&continue3);
  __ tmhh(r1, Operand(0));
  __ beq(&continue4);  //8
  __ b(&error);

  // selected bits all 1
  __ bind(&continue4);
  __ tmhh(r1, Operand(1));
  __ b(Condition(1), &continue5); //1
  __ b(&error);

  __ bind(&continue5);
  __ tmhl(r1, Operand(1));
  __ b(Condition(1), &continue6); //1
  __ b(&error);

  // leftmost = 1
  __ bind(&continue6);
  __ lgfi(r1, Operand(0xF000F000));
  __ slag(r2, r1, Operand(32));
  __ tmhh(r2, Operand(0xFFFF));
  __ b(Condition(2), &done); //2
  __ b(&error);

  __ bind(&continue7);
  __ tmhl(r1, Operand(0xFFFF));
  __ b(Condition(2), &continue8); //2
  __ b(&error);

  // leftmost = 0
  __ bind(&continue8);
  __ lgfi(r1, Operand(0x0FF00FF0));
  __ slag(r2, r1, Operand(32));
  __ tmhh(r2, Operand(0xFFFF));
  __ b(Condition(4), &done); //4
  __ b(&error);

  __ bind(&continue9);
  __ tmhl(r1, Operand(0xFFFF));
  __ b(Condition(4), &done); //4
  __ b(&error);

  __ bind(&error);
  __ lgfi(r2, Operand(1));
  __ b(r14);

  __ bind(&done);
  __ lgfi(r2, Operand::Zero());
  __ b(r14);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  Print(*code);
#endif
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  // f.Call(reg2, reg3, reg4, reg5, reg6) -> set the register value
  intptr_t res = reinterpret_cast<intptr_t>(f.Call(0, 0, 0, 0, 0));
  ::printf("f() = %" V8PRIxPTR "\n", res);
  CHECK_EQ(0, static_cast<int>(res));
}

#undef __

}  // namespace internal
}  // namespace v8

"""

```