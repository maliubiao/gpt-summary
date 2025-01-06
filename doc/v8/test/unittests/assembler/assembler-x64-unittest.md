Response: The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/assembler/assembler-x64-unittest.cc`. They also want an example of how this relates to JavaScript functionality if applicable.

**Plan:**

1. **Identify the core purpose:** The file name suggests it's about testing the x64 assembler.
2. **Analyze the code structure:** Look for common patterns like `TEST_F`, register definitions, and assembler instructions.
3. **Summarize the functionality:** Describe what the tests are doing in general terms.
4. **Connect to JavaScript (if possible):** Explain how the assembler relates to the execution of JavaScript code.
5. **Provide a JavaScript example:** Illustrate the connection with a simple JavaScript snippet.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试x64架构下的汇编器 (`Assembler`) 的功能。

**功能归纳:**

该文件包含了一系列的单元测试，用于验证x64汇编器能够正确地生成各种机器指令，并且这些指令在执行时能够产生预期的结果。  这些测试覆盖了以下几个方面的汇编指令：

*   **基本操作:**  例如，数据移动 (`movq`)、返回 (`ret`)、空操作 (`nop`)。
*   **栈操作:**  例如，压栈 (`pushq`)、出栈 (`popq`)。
*   **算术运算:** 例如，加法 (`addq`)、减法 (`subq`)、乘法 (`imulq`)、位或 (`orl`)、异或 (`xorl`)。
*   **比较操作:** 例如，比较字节 (`cmpb`)。
*   **位测试操作:** 例如，`testb`, `testw`, `testq`。
*   **交换操作:** 例如，`xchgl`。
*   **循环移位操作:** 例如，`roll`。
*   **控制流操作:** 例如，跳转 (`jmp`)、条件跳转 (`j`)。
*   **内存操作:**  通过 `Operand` 类测试对内存地址的读写。
*   **多字节 `nop` 指令:** 测试生成指定长度的空操作指令。
*   **SSE/AVX 指令集测试:**  测试单精度和双精度浮点运算指令，例如 `addps`, `mulps`, `divps`, `addsd`, `mulsd`, `divsd`，以及 FMA 指令 (`vfmaddsd`, `vfmsubsd` 等)。
*   **BMI1/BMI2/LZCNT/POPCNT 指令集测试:** 测试这些位操作扩展指令集的功能。
*   **标签链接:** 测试在指令内部正确链接标签。
*   **操作数寄存器依赖性:** 验证 `Operand` 类是否正确跟踪寄存器的使用。

**与 JavaScript 的关系及 JavaScript 举例:**

V8 引擎在执行 JavaScript 代码时，需要将 JavaScript 代码编译成机器码才能在 CPU 上运行。 `Assembler` 类是 V8 中负责生成这些机器码的核心组件之一。  `assembler-x64-unittest.cc` 中测试的汇编指令是 JavaScript 代码最终被转化为机器码的基础。

例如，考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 3);
```

当 V8 引擎执行这段代码时，`add` 函数会被编译成一系列的机器指令。 其中，加法操作 `a + b` 可能会被编译成类似于测试文件中 `AssemblerX64ArithmeticOperations` 测试用例中生成的汇编代码：

```assembly
  movq rax, rsi  // 将第二个参数 (b) 移动到 rax 寄存器 (通常用于存储返回值)
  addq rax, rdi  // 将第一个参数 (a) 加到 rax 寄存器上
  ret 0         // 返回 rax 中的结果
```

在这个例子中：

*   `movq` 指令对应于测试文件中的 `TEST_F(AssemblerX64Test, AssemblerX64ReturnOperation)` 和其他涉及数据移动的测试。
*   `addq` 指令对应于测试文件中的 `TEST_F(AssemblerX64Test, AssemblerX64ArithmeticOperations)`。
*   `ret` 指令对应于测试文件中的 `TEST_F(AssemblerX64Test, AssemblerX64ReturnOperation)`。

**总结:**

`assembler-x64-unittest.cc` 通过编写各种汇编代码片段并执行它们，来确保 V8 引擎的 x64 汇编器能够正确生成指令，从而保证 JavaScript 代码能够被高效且正确地编译和执行。  它不直接操作 JavaScript 的高级概念，而是专注于底层机器指令的生成和验证。

Prompt: 
```
这是目录为v8/test/unittests/assembler/assembler-x64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 the V8 project authors. All rights reserved.
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

#include <cstdlib>
#include <cstring>
#include <iostream>

#include "include/v8-function.h"
#include "src/base/numbers/double.h"
#include "src/base/platform/platform.h"
#include "src/base/utils/random-number-generator.h"
#include "src/codegen/macro-assembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/objects/objects-inl.h"
#include "src/utils/ostreams.h"
#include "test/common/assembler-tester.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

// Test the x64 assembler by compiling some simple functions into
// a buffer and executing them.  These tests do not initialize the
// V8 library, create a context, or use any V8 objects.
// The AMD64 calling convention is used, with the first six arguments
// in RDI, RSI, RDX, RCX, R8, and R9, and floating point arguments in
// the XMM registers.  The return value is in RAX.
// This calling convention is used on Linux, with GCC, and on Mac OS,
// with GCC.  A different convention is used on 64-bit windows,
// where the first four integer arguments are passed in RCX, RDX, R8 and R9.

using AssemblerX64Test = TestWithIsolate;

using F0 = int();
using F1 = int(int64_t x);
using F2 = int(int64_t x, int64_t y);
using F3 = unsigned(double x);
using F4 = uint64_t(uint64_t* x, uint64_t* y);
using F5 = uint64_t(uint64_t x);

#ifdef _WIN64
static const Register arg1 = rcx;
static const Register arg2 = rdx;
#else
static const Register arg1 = rdi;
static const Register arg2 = rsi;
#endif

#define __ masm.

TEST_F(AssemblerX64Test, AssemblerX64ReturnOperation) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a simple function that copies argument 2 and returns it.
  __ movq(rax, arg2);
  __ nop();
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(3, 2);
  CHECK_EQ(2, result);
}

TEST_F(AssemblerX64Test, AssemblerX64StackOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a simple function that copies argument 2 and returns it.
  // We compile without stack frame pointers, so the gdb debugger shows
  // incorrect stack frames when debugging this function (which has them).
  __ pushq(rbp);
  __ movq(rbp, rsp);
  __ pushq(arg2);  // Value at (rbp - 8)
  __ pushq(arg2);  // Value at (rbp - 16)
  __ pushq(arg1);  // Value at (rbp - 24)
  __ popq(rax);
  __ popq(rax);
  __ popq(rax);
  __ popq(rbp);
  __ nop();
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(3, 2);
  CHECK_EQ(2, result);
}

TEST_F(AssemblerX64Test, AssemblerX64ArithmeticOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a simple function that adds arguments returning the sum.
  __ movq(rax, arg2);
  __ addq(rax, arg1);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(3, 2);
  CHECK_EQ(5, result);
}

TEST_F(AssemblerX64Test, AssemblerX64CmpbOperation) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a function that compare argument byte returing 1 if equal else 0.
  // On Windows, it compares rcx with rdx which does not require REX prefix;
  // on Linux, it compares rdi with rsi which requires REX prefix.

  Label done;
  __ movq(rax, Immediate(1));
  __ cmpb(arg1, arg2);
  __ j(equal, &done);
  __ movq(rax, Immediate(0));
  __ bind(&done);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(0x1002, 0x2002);
  CHECK_EQ(1, result);
  result = f.Call(0x1002, 0x2003);
  CHECK_EQ(0, result);
}

TEST_F(AssemblerX64Test, AssemblerX64ImulOperation) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a simple function that multiplies arguments returning the high
  // word.
  __ movq(rax, arg2);
  __ imulq(arg1);
  __ movq(rax, rdx);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(3, 2);
  CHECK_EQ(0, result);
  result = f.Call(0x100000000l, 0x100000000l);
  CHECK_EQ(1, result);
  result = f.Call(-0x100000000l, 0x100000000l);
  CHECK_EQ(-1, result);
}

TEST_F(AssemblerX64Test, AssemblerX64testbwqOperation) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ pushq(rbx);
  __ pushq(rdi);
  __ pushq(rsi);
  __ pushq(r12);
  __ pushq(r13);
  __ pushq(r14);
  __ pushq(r15);

  // Assemble a simple function that tests testb and testw
  Label bad;
  Label done;

  // Test immediate testb and testw
  __ movq(rax, Immediate(2));
  __ movq(rbx, Immediate(4));
  __ movq(rcx, Immediate(8));
  __ movq(rdx, Immediate(16));
  __ movq(rsi, Immediate(32));
  __ movq(rdi, Immediate(64));
  __ movq(r10, Immediate(128));
  __ movq(r11, Immediate(0));
  __ movq(r12, Immediate(0));
  __ movq(r13, Immediate(0));
  __ testb(rax, Immediate(2));
  __ j(zero, &bad);
  __ testb(rbx, Immediate(4));
  __ j(zero, &bad);
  __ testb(rcx, Immediate(8));
  __ j(zero, &bad);
  __ testb(rdx, Immediate(16));
  __ j(zero, &bad);
  __ testb(rsi, Immediate(32));
  __ j(zero, &bad);
  __ testb(rdi, Immediate(64));
  __ j(zero, &bad);
  __ testb(r10, Immediate(128));
  __ j(zero, &bad);
  __ testw(rax, Immediate(2));
  __ j(zero, &bad);
  __ testw(rbx, Immediate(4));
  __ j(zero, &bad);
  __ testw(rcx, Immediate(8));
  __ j(zero, &bad);
  __ testw(rdx, Immediate(16));
  __ j(zero, &bad);
  __ testw(rsi, Immediate(32));
  __ j(zero, &bad);
  __ testw(rdi, Immediate(64));
  __ j(zero, &bad);
  __ testw(r10, Immediate(128));
  __ j(zero, &bad);

  // Test reg, reg testb and testw
  __ movq(rax, Immediate(2));
  __ movq(rbx, Immediate(2));
  __ testb(rax, rbx);
  __ j(zero, &bad);
  __ movq(rbx, Immediate(4));
  __ movq(rax, Immediate(4));
  __ testb(rbx, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(8));
  __ testb(rcx, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(16));
  __ testb(rdx, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(32));
  __ testb(rsi, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(64));
  __ testb(rdi, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(128));
  __ testb(r10, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(2));
  __ movq(rbx, Immediate(2));
  __ testw(rax, rbx);
  __ j(zero, &bad);
  __ movq(rbx, Immediate(4));
  __ movq(rax, Immediate(4));
  __ testw(rbx, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(8));
  __ testw(rcx, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(16));
  __ testw(rdx, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(32));
  __ testw(rsi, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(64));
  __ testw(rdi, rax);
  __ j(zero, &bad);
  __ movq(rax, Immediate(128));
  __ testw(r10, rax);
  __ j(zero, &bad);

  // Test diffrrent extended register coding combinations.
  __ movq(rax, Immediate(5));
  __ movq(r11, Immediate(5));
  __ testb(r11, rax);
  __ j(zero, &bad);
  __ testb(rax, r11);
  __ j(zero, &bad);
  __ testw(r11, rax);
  __ j(zero, &bad);
  __ testw(rax, r11);
  __ j(zero, &bad);
  __ movq(r11, Immediate(3));
  __ movq(r12, Immediate(3));
  __ movq(rdi, Immediate(3));
  __ testb(r12, rdi);
  __ j(zero, &bad);
  __ testb(rdi, r12);
  __ j(zero, &bad);
  __ testb(r12, r11);
  __ j(zero, &bad);
  __ testb(r11, r12);
  __ j(zero, &bad);
  __ testw(r12, r11);
  __ j(zero, &bad);
  __ testw(r11, r12);
  __ j(zero, &bad);

  // Test sign-extended imediate tests
  __ movq(r11, Immediate(2));
  __ shlq(r11, Immediate(32));
  __ testq(r11, Immediate(-1));
  __ j(zero, &bad);

  // All tests passed
  __ movq(rax, Immediate(1));
  __ jmp(&done);

  __ bind(&bad);
  __ movq(rax, Immediate(0));
  __ bind(&done);

  __ popq(r15);
  __ popq(r14);
  __ popq(r13);
  __ popq(r12);
  __ popq(rsi);
  __ popq(rdi);
  __ popq(rbx);

  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(0, 0);
  CHECK_EQ(1, result);
}

TEST_F(AssemblerX64Test, AssemblerX64XchglOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(rax, Operand(arg1, 0));
  __ movq(r11, Operand(arg2, 0));
  __ xchgl(rax, r11);
  __ movq(Operand(arg1, 0), rax);
  __ movq(Operand(arg2, 0), r11);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint64_t left = 0x1000'0000'2000'0000;
  uint64_t right = 0x3000'0000'4000'0000;
  auto f = GeneratedCode<F4>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(&left, &right);
  CHECK_EQ(0x0000'0000'4000'0000, left);
  CHECK_EQ(0x0000'0000'2000'0000, right);
  USE(result);
}

TEST_F(AssemblerX64Test, AssemblerX64OrlOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(rax, Operand(arg2, 0));
  __ orl(Operand(arg1, 0), rax);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint64_t left = 0x1000'0000'2000'0000;
  uint64_t right = 0x3000'0000'4000'0000;
  auto f = GeneratedCode<F4>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(&left, &right);
  CHECK_EQ(0x1000'0000'6000'0000, left);
  USE(result);
}

TEST_F(AssemblerX64Test, AssemblerX64RollOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(rax, arg1);
  __ roll(rax, Immediate(1));
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint64_t src = 0x1000'0000'C000'0000;
  auto f = GeneratedCode<F5>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(src);
  CHECK_EQ(0x0000'0000'8000'0001, result);
}

TEST_F(AssemblerX64Test, AssemblerX64SublOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(rax, Operand(arg2, 0));
  __ subl(Operand(arg1, 0), rax);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint64_t left = 0x1000'0000'2000'0000;
  uint64_t right = 0x3000'0000'4000'0000;
  auto f = GeneratedCode<F4>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(&left, &right);
  CHECK_EQ(0x1000'0000'E000'0000, left);
  USE(result);
}

TEST_F(AssemblerX64Test, AssemblerX64TestlOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Set rax with the ZF flag of the testl instruction.
  Label done;
  __ movq(rax, Immediate(1));
  __ movq(r11, Operand(arg2, 0));
  __ testl(Operand(arg1, 0), r11);
  __ j(zero, &done, Label::kNear);
  __ movq(rax, Immediate(0));
  __ bind(&done);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint64_t left = 0x1000'0000'2000'0000;
  uint64_t right = 0x3000'0000'0000'0000;
  auto f = GeneratedCode<F4>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(&left, &right);
  CHECK_EQ(1u, result);
}

TEST_F(AssemblerX64Test, AssemblerX64TestwOperations) {
  using F = uint16_t(uint16_t * x);

  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Set rax with the ZF flag of the testl instruction.
  Label done;
  __ movq(rax, Immediate(1));
  __ testw(Operand(arg1, 0), Immediate(0xF0F0));
  __ j(not_zero, &done, Label::kNear);
  __ movq(rax, Immediate(0));
  __ bind(&done);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint16_t operand = 0x8000;
  auto f = GeneratedCode<F>::FromBuffer(i_isolate(), buffer->start());
  uint16_t result = f.Call(&operand);
  CHECK_EQ(1u, result);
}

TEST_F(AssemblerX64Test, AssemblerX64XorlOperations) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  __ movq(rax, Operand(arg2, 0));
  __ xorl(Operand(arg1, 0), rax);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  uint64_t left = 0x1000'0000'2000'0000;
  uint64_t right = 0x3000'0000'6000'0000;
  auto f = GeneratedCode<F4>::FromBuffer(i_isolate(), buffer->start());
  uint64_t result = f.Call(&left, &right);
  CHECK_EQ(0x1000'0000'4000'0000, left);
  USE(result);
}

TEST_F(AssemblerX64Test, AssemblerX64MemoryOperands) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a simple function that copies argument 2 and returns it.
  __ pushq(rbp);
  __ movq(rbp, rsp);

  __ pushq(arg2);  // Value at (rbp - 8)
  __ pushq(arg2);  // Value at (rbp - 16)
  __ pushq(arg1);  // Value at (rbp - 24)

  const int kStackElementSize = 8;
  __ movq(rax, Operand(rbp, -3 * kStackElementSize));
  __ popq(arg2);
  __ popq(arg2);
  __ popq(arg2);
  __ popq(rbp);
  __ nop();
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(3, 2);
  CHECK_EQ(3, result);
}

TEST_F(AssemblerX64Test, AssemblerX64ControlFlow) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble a simple function that copies argument 1 and returns it.
  __ pushq(rbp);

  __ movq(rbp, rsp);
  __ movq(rax, arg1);
  Label target;
  __ jmp(&target);
  __ movq(rax, arg2);
  __ bind(&target);
  __ popq(rbp);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F2>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call(3, 2);
  CHECK_EQ(3, result);
}

TEST_F(AssemblerX64Test, AssemblerX64LoopImmediates) {
  auto buffer = AllocateAssemblerBuffer();
  Assembler masm(AssemblerOptions{}, buffer->CreateView());

  // Assemble two loops using rax as counter, and verify the ending counts.
  Label Fail;
  __ movq(rax, Immediate(-3));
  Label Loop1_test;
  Label Loop1_body;
  __ jmp(&Loop1_test);
  __ bind(&Loop1_body);
  __ addq(rax, Immediate(7));
  __ bind(&Loop1_test);
  __ cmpq(rax, Immediate(20));
  __ j(less_equal, &Loop1_body);
  // Did the loop terminate with the expected value?
  __ cmpq(rax, Immediate(25));
  __ j(not_equal, &Fail);

  Label Loop2_test;
  Label Loop2_body;
  __ movq(rax, Immediate(0x11FEED00));
  __ jmp(&Loop2_test);
  __ bind(&Loop2_body);
  __ addq(rax, Immediate(-0x1100));
  __ bind(&Loop2_test);
  __ cmpq(rax, Immediate(0x11FE8000));
  __ j(greater, &Loop2_body);
  // Did the loop terminate with the expected value?
  __ cmpq(rax, Immediate(0x11FE7600));
  __ j(not_equal, &Fail);

  __ movq(rax, Immediate(1));
  __ ret(0);
  __ bind(&Fail);
  __ movq(rax, Immediate(0));
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate(), &desc);
  buffer->MakeExecutable();
  // Call the function from C++.
  auto f = GeneratedCode<F0>::FromBuffer(i_isolate(), buffer->start());
  int result = f.Call();
  CHECK_EQ(1, result);
}

TEST_F(AssemblerX64Test, OperandRegisterDependency) {
  int offsets[4] = {0, 1, 0xFED, 0xBEEFCAD};
  for (int i = 0; i < 4; i++) {
    int offset = offsets[i];
    CHECK(Operand(rax, offset).AddressUsesRegister(rax));
    CHECK(!Operand(rax, offset).AddressUsesRegister(r8));
    CHECK(!Operand(rax, offset).AddressUsesRegister(rcx));

    CHECK(Operand(rax, rax, times_1, offset).AddressUsesRegister(rax));
    CHECK(!Operand(rax, rax, times_1, offset).AddressUsesRegister(r8));
    CHECK(!Operand(rax, rax, times_1, offset).AddressUsesRegister(rcx));

    CHECK(Operand(rax, rcx, times_1, offset).AddressUsesRegister(rax));
    CHECK(Operand(rax, rcx, times_1, offset).AddressUsesRegister(rcx));
    CHECK(!Operand(rax, rcx, times_1, offset).AddressUsesRegister(r8));
    CHECK(!Operand(rax, rcx, times_1, offset).AddressUsesRegister(r9));
    CHECK(!Operand(rax, rcx, times_1, offset).AddressUsesRegister(rdx));
    CHECK(!Operand(rax, rcx, times_1, offset).AddressUsesRegister(rsp));

    CHECK(Operand(rsp, offset).AddressUsesRegister(rsp));
    CHECK(!Operand(rsp, offset).AddressUsesRegister(rax));
    CHECK(!Operand(rsp, offset).AddressUsesRegister(r15));

    CHECK(Operand(rbp, offset).AddressUsesRegister(rbp));
    CHECK(!Operand(rbp, offset).AddressUsesRegister(rax));
    CHECK(!Operand(rbp, offset).AddressUsesRegister(r13));

    CHECK(Operand(rbp, rax, times_1, offset).AddressUsesRegister(rbp));
    CHECK(Operand(rbp, rax, times_1, offset).AddressUsesRegister(rax));
    CHECK(!Operand(rbp, rax, times_1, offset).AddressUsesRegister(rcx));
    CHECK(!Operand(rbp, rax, times_1, offset).AddressUsesRegister(r13));
    CHECK(!Operand(rbp, rax, times_1, offset).AddressUsesRegister(r8));
    CHECK(!Operand(rbp, rax, times_1, offset).AddressUsesRegister(rsp));

    CHECK(Operand(rsp, rbp, times_1, offset).AddressUsesRegister(rsp));
    CHECK(Operand(rsp, rbp, times_1, offset).AddressUsesRegister(rbp));
    CHECK(!Operand(rsp, rbp, times_1, offset).AddressUsesRegister(rax));
    CHECK(!Operand(rsp, rbp, times_1, offset).AddressUsesRegister(r15));
    CHECK(!Operand(rsp, rbp, times_1, offset).AddressUsesRegister(r13));
  }
}

TEST_F(AssemblerX64Test, AssemblerX64LabelChaining) {
  // Test chaining of label usages within instructions (issue 1644).

  Assembler masm(AssemblerOptions{});

  Label target;
  __ j(equal, &target);
  __ j(not_equal, &target);
  __ bind(&target);
  __ nop();
}

TEST_F(AssemblerX64Test, AssemblerMultiByteNop) {
  uint8_t buffer[1024];
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  __ pushq(rbx);
  __ pushq(rcx);
  __ pushq(rdx);
  __ pushq(rdi);
  __ pushq(rsi);
  __ movq(rax, Immediate(1));
  __ movq(rbx, Immediate(2));
  __ movq(rcx, Immediate(3));
  __ movq(rdx, Immediate(4));
  __ movq(rdi, Immediate(5));
  __ movq(rsi, Immediate(6));
  for (int i = 0; i < 16; i++) {
    int before = masm.pc_offset();
    __ Nop(i);
    CHECK_EQ(masm.pc_offset() - before, i);
  }

  Label fail;
  __ cmpq(rax, Immediate(1));
  __ j(not_equal, &fail);
  __ cmpq(rbx, Immediate(2));
  __ j(not_equal, &fail);
  __ cmpq(rcx, Immediate(3));
  __ j(not_equal, &fail);
  __ cmpq(rdx, Immediate(4));
  __ j(not_equal, &fail);
  __ cmpq(rdi, Immediate(5));
  __ j(not_equal, &fail);
  __ cmpq(rsi, Immediate(6));
  __ j(not_equal, &fail);
  __ movq(rax, Immediate(42));
  __ popq(rsi);
  __ popq(rdi);
  __ popq(rdx);
  __ popq(rcx);
  __ popq(rbx);
  __ ret(0);
  __ bind(&fail);
  __ movq(rax, Immediate(13));
  __ popq(rsi);
  __ popq(rdi);
  __ popq(rdx);
  __ popq(rcx);
  __ popq(rbx);
  __ ret(0);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F0>::FromCode(isolate, *code);
  int res = f.Call();
  CHECK_EQ(42, res);
}

#ifdef __GNUC__
#define ELEMENT_COUNT 4u

void DoSSE2(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  uint8_t buffer[1024];

  CHECK(info[0]->IsArray());
  v8::Local<v8::Array> vec = v8::Local<v8::Array>::Cast(info[0]);
  CHECK_EQ(ELEMENT_COUNT, vec->Length());

  Isolate* i_isolate = reinterpret_cast<v8::internal::Isolate*>(isolate);
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));

  // Remove return address from the stack for fix stack frame alignment.
  __ popq(rcx);

  // Store input vector on the stack.
  for (unsigned i = 0; i < ELEMENT_COUNT; i++) {
    __ movl(rax, Immediate(vec->Get(context, i)
                               .ToLocalChecked()
                               ->Int32Value(context)
                               .FromJust()));
    __ shlq(rax, Immediate(0x20));
    __ orq(rax, Immediate(vec->Get(context, ++i)
                              .ToLocalChecked()
                              ->Int32Value(context)
                              .FromJust()));
    __ pushq(rax);
  }

  // Read vector into a xmm register.
  __ xorps(xmm0, xmm0);
  __ movdqa(xmm0, Operand(rsp, 0));
  // Create mask and store it in the return register.
  __ movmskps(rax, xmm0);

  // Remove unused data from the stack.
  __ addq(rsp, Immediate(ELEMENT_COUNT * sizeof(int32_t)));
  // Restore return address.
  __ pushq(rcx);

  __ ret(0);

  CodeDesc desc;
  masm.GetCode(i_isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(i_isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F0>::FromCode(i_isolate, *code);
  int res = f.Call();
  info.GetReturnValue().Set(v8::Integer::New(isolate, res));
}

TEST_F(AssemblerX64Test, StackAlignmentForSSE2) {
  CHECK_EQ(0, v8::base::OS::ActivationFrameAlignment() % 16);

  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->Set(isolate, "do_sse2",
                       v8::FunctionTemplate::New(isolate, DoSSE2));

  v8::Local<v8::Context> context =
      v8::Context::New(isolate, nullptr, global_template);
  v8::Context::Scope context_scope(context);
  TryRunJS(
      "function foo(vec) {"
      "  return do_sse2(vec);"
      "}");

  v8::Local<v8::Object> global_object = context->Global();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      global_object->Get(context, NewString("foo")).ToLocalChecked());

  int32_t vec[ELEMENT_COUNT] = {-1, 1, 1, 1};
  v8::Local<v8::Array> v8_vec = v8::Array::New(isolate, ELEMENT_COUNT);
  for (unsigned i = 0; i < ELEMENT_COUNT; i++) {
    v8_vec->Set(context, i, v8::Number::New(isolate, vec[i])).FromJust();
  }

  v8::Local<v8::Value> args[] = {v8_vec};
  v8::Local<v8::Value> result =
      foo->Call(context, global_object, 1, args).ToLocalChecked();

  // The mask should be 0b1000.
  CHECK_EQ(8, result->Int32Value(context).FromJust());
}

#undef ELEMENT_COUNT
#endif  // __GNUC__

TEST_F(AssemblerX64Test, AssemblerX64Extractps) {
  if (!CpuFeatures::IsSupported(SSE4_1)) return;

  uint8_t buffer[256];
  Isolate* isolate = i_isolate();
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope2(&masm, SSE4_1);
    __ extractps(rax, xmm0, 0x1);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  uint64_t value1 = 0x1234'5678'8765'4321;
  CHECK_EQ(0x12345678u, f.Call(base::uint64_to_double(value1)));
  uint64_t value2 = 0x8765'4321'1234'5678;
  CHECK_EQ(0x87654321u, f.Call(base::uint64_to_double(value2)));
}

using F6 = int(float x, float y);
TEST_F(AssemblerX64Test, AssemblerX64SSE) {
  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    __ shufps(xmm0, xmm0, 0x0);  // brocast first argument
    __ shufps(xmm1, xmm1, 0x0);  // brocast second argument
    __ movaps(xmm2, xmm1);
    __ addps(xmm2, xmm0);
    __ mulps(xmm2, xmm1);
    __ subps(xmm2, xmm0);
    __ divps(xmm2, xmm1);
    __ cvttss2si(rax, xmm2);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F6>::FromCode(isolate, *code);
  CHECK_EQ(2, f.Call(1.0, 2.0));
}

TEST_F(AssemblerX64Test, AssemblerX64SSE3) {
  if (!CpuFeatures::IsSupported(SSE3)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, SSE3);
    __ shufps(xmm0, xmm0, 0x0);  // brocast first argument
    __ shufps(xmm1, xmm1, 0x0);  // brocast second argument
    __ haddps(xmm1, xmm0);
    __ cvttss2si(rax, xmm1);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F6>::FromCode(isolate, *code);
  CHECK_EQ(4, f.Call(1.0, 2.0));
}

using F7 = int(double x, double y, double z);
TEST_F(AssemblerX64Test, AssemblerX64FMA_sd) {
  if (!CpuFeatures::IsSupported(FMA3)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, FMA3);
    Label exit;
    // argument in xmm0, xmm1 and xmm2
    // xmm0 * xmm1 + xmm2
    __ movaps(xmm3, xmm0);
    __ mulsd(xmm3, xmm1);
    __ addsd(xmm3, xmm2);  // Expected result in xmm3

    __ AllocateStackSpace(kDoubleSize);  // For memory operand
    // vfmadd132sd
    __ movl(rax, Immediate(1));  // Test number
    __ movaps(xmm8, xmm0);
    __ vfmadd132sd(xmm8, xmm2, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfmadd213sd(xmm8, xmm0, xmm2);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfmadd231sd(xmm8, xmm0, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfmadd132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfmadd132sd(xmm8, xmm2, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movsd(Operand(rsp, 0), xmm2);
    __ vfmadd213sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfmadd231sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // xmm0 * xmm1 - xmm2
    __ movaps(xmm3, xmm0);
    __ mulsd(xmm3, xmm1);
    __ subsd(xmm3, xmm2);  // Expected result in xmm3

    // vfmsub132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfmsub132sd(xmm8, xmm2, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfmsub213sd(xmm8, xmm0, xmm2);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfmsub231sd(xmm8, xmm0, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfmsub132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfmsub132sd(xmm8, xmm2, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movsd(Operand(rsp, 0), xmm2);
    __ vfmsub213sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfmsub231sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // - xmm0 * xmm1 + xmm2
    __ movaps(xmm3, xmm0);
    __ mulsd(xmm3, xmm1);
    __ Move(xmm4, static_cast<uint64_t>(1) << 63);
    __ xorpd(xmm3, xmm4);
    __ addsd(xmm3, xmm2);  // Expected result in xmm3

    // vfnmadd132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfnmadd132sd(xmm8, xmm2, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfnmadd213sd(xmm8, xmm0, xmm2);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfnmadd231sd(xmm8, xmm0, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfnmadd132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfnmadd132sd(xmm8, xmm2, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movsd(Operand(rsp, 0), xmm2);
    __ vfnmadd213sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfnmadd231sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // - xmm0 * xmm1 - xmm2
    __ movaps(xmm3, xmm0);
    __ mulsd(xmm3, xmm1);
    __ Move(xmm4, static_cast<uint64_t>(1) << 63);
    __ xorpd(xmm3, xmm4);
    __ subsd(xmm3, xmm2);  // Expected result in xmm3

    // vfnmsub132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfnmsub132sd(xmm8, xmm2, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfnmsub213sd(xmm8, xmm0, xmm2);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfnmsub231sd(xmm8, xmm0, xmm1);
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfnmsub132sd
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfnmsub132sd(xmm8, xmm2, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub213sd
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movsd(Operand(rsp, 0), xmm2);
    __ vfnmsub213sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231sd
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movsd(Operand(rsp, 0), xmm1);
    __ vfnmsub231sd(xmm8, xmm0, Operand(rsp, 0));
    __ ucomisd(xmm8, xmm3);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize));
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F7>::FromCode(isolate, *code);
  CHECK_EQ(
      0, f.Call(0.000092662107262076, -2.460774966188315, -1.0958787393627414));
}

using F8 = int(float x, float y, float z);
TEST_F(AssemblerX64Test, AssemblerX64FMA_ss) {
  if (!CpuFeatures::IsSupported(FMA3)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, FMA3);
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    // xmm0 * xmm1 + xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ addss(xmm3, xmm2);  // Expected result in xmm3

    __ AllocateStackSpace(kDoubleSize);  // For memory operand
    // vfmadd132ss
    __ movl(rax, Immediate(1));  // Test number
    __ movaps(xmm8, xmm0);
    __ vfmadd132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfmadd213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfmadd231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfmadd132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmadd132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfmadd213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmadd231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // xmm0 * xmm1 - xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ subss(xmm3, xmm2);  // Expected result in xmm3

    // vfmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfmsub132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfmsub213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfmsub231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmsub132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfmsub213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfmsub231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // - xmm0 * xmm1 + xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ Move(xmm4, static_cast<uint32_t>(1) << 31);
    __ xorps(xmm3, xmm4);
    __ addss(xmm3, xmm2);  // Expected result in xmm3

    // vfnmadd132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfnmadd132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfnmadd213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfnmadd231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfnmadd132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmadd132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfnmadd213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmadd231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmadd231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // - xmm0 * xmm1 - xmm2
    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ Move(xmm4, static_cast<uint32_t>(1) << 31);
    __ xorps(xmm3, xmm4);
    __ subss(xmm3, xmm2);  // Expected result in xmm3

    // vfnmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ vfnmsub132ss(xmm8, xmm2, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfmsub213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ vfnmsub213ss(xmm8, xmm0, xmm2);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ vfnmsub231ss(xmm8, xmm0, xmm1);
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    // vfnmsub132ss
    __ incq(rax);
    __ movaps(xmm8, xmm0);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmsub132ss(xmm8, xmm2, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub213ss
    __ incq(rax);
    __ movaps(xmm8, xmm1);
    __ movss(Operand(rsp, 0), xmm2);
    __ vfnmsub213ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);
    // vfnmsub231ss
    __ incq(rax);
    __ movaps(xmm8, xmm2);
    __ movss(Operand(rsp, 0), xmm1);
    __ vfnmsub231ss(xmm8, xmm0, Operand(rsp, 0));
    __ ucomiss(xmm8, xmm3);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize));
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F8>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call(9.26621069e-05f, -2.4607749f, -1.09587872f));
}

TEST_F(AssemblerX64Test, AssemblerX64SSE_ss) {
  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    __ movl(rax, Immediate(0));

    __ movaps(xmm3, xmm0);
    __ maxss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(1));

    __ movaps(xmm3, xmm1);
    __ minss(xmm3, xmm2);
    __ ucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(2));

    __ movaps(xmm3, xmm2);
    __ subss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm0);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(3));

    __ movaps(xmm3, xmm0);
    __ addss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(4));

    __ movaps(xmm3, xmm0);
    __ mulss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(5));

    __ movaps(xmm3, xmm0);
    __ divss(xmm3, xmm1);
    __ mulss(xmm3, xmm2);
    __ mulss(xmm3, xmm1);
    __ ucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(6));

    // result in eax
    __ bind(&exit);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F8>::FromCode(isolate, *code);
  int res = f.Call(1.0f, 2.0f, 3.0f);
  PrintF("f(1,2,3) = %d\n", res);
  CHECK_EQ(6, res);
}

TEST_F(AssemblerX64Test, AssemblerX64AVX_ss) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope avx_scope(&masm, AVX);
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    __ subq(rsp, Immediate(kDoubleSize * 2));  // For memory operand

    __ movl(rdx, Immediate(0xC2F64000));  // -123.125
    __ vmovd(xmm4, rdx);
    __ vmovss(Operand(rsp, 0), xmm4);
    __ vmovss(xmm5, Operand(rsp, 0));
    __ vmovaps(xmm6, xmm5);
    __ vmovd(rcx, xmm6);
    __ cmpl(rcx, rdx);
    __ movl(rax, Immediate(9));
    __ j(not_equal, &exit);

    __ movl(rax, Immediate(0));
    __ vmaxss(xmm3, xmm0, xmm1);
    __ vucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(1));

    __ vminss(xmm3, xmm1, xmm2);
    __ vucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(2));

    __ vsubss(xmm3, xmm2, xmm1);
    __ vucomiss(xmm3, xmm0);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(3));

    __ vaddss(xmm3, xmm0, xmm1);
    __ vucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(4));

    __ vmulss(xmm3, xmm0, xmm1);
    __ vucomiss(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(5));

    __ vdivss(xmm3, xmm0, xmm1);
    __ vmulss(xmm3, xmm3, xmm2);
    __ vmulss(xmm3, xmm3, xmm1);
    __ vucomiss(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(6));

    // result in eax
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize * 2));
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F8>::FromCode(isolate, *code);
  int res = f.Call(1.0f, 2.0f, 3.0f);
  PrintF("f(1,2,3) = %d\n", res);
  CHECK_EQ(6, res);
}

TEST_F(AssemblerX64Test, AssemblerX64AVX_sd) {
  if (!CpuFeatures::IsSupported(AVX)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  Assembler masm(AssemblerOptions{},
                 ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope avx_scope(&masm, AVX);
    Label exit;
    // arguments in xmm0, xmm1 and xmm2
    __ subq(rsp, Immediate(kDoubleSize * 2));  // For memory operand
    __ movl(rax, Immediate(0));

    __ vmaxsd(xmm4, xmm0, xmm1);
    __ vmovsd(Operand(rsp, kDoubleSize), xmm4);
    __ vmovsd(xmm5, Operand(rsp, kDoubleSize));
    __ vmovsd(xmm6, xmm6, xmm5);
    __ vmovapd(xmm3, xmm6);

    // Test vcvtss2sd & vcvtsd2ss
    __ movl(rax, Immediate(9));
    __ movq(rdx, uint64_t{0x426D1A0000000000});
    __ movq(Operand(rsp, 0), rdx);
    __ vcvtsd2ss(xmm6, xmm6, Operand(rsp, 0));
    __ vcvtss2sd(xmm7, xmm6, xmm6);
    __ vcvtsd2ss(xmm8, xmm7, xmm7);
    __ vmovss(Operand(rsp, 0), xmm8);
    __ vcvtss2sd(xmm9, xmm8, Operand(rsp, 0));
    __ vmovq(rcx, xmm9);
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vcvttsd2si
    __ movl(rax, Immediate(10));
    __ movl(rdx, Immediate(123));
    __ vcvtlsi2sd(xmm6, xmm6, rdx);
    __ vcvttsd2si(rcx, xmm6);
    __ cmpl(rcx, rdx);
    __ j(not_equal, &exit);
    __ xorl(rcx, rcx);
    __ vmovsd(Operand(rsp, 0), xmm6);
    __ vcvttsd2si(rcx, Operand(rsp, 0));
    __ cmpl(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vcvttsd2siq
    __ movl(rax, Immediate(11));
    __ movq(rdx, uint64_t{0x426D1A94A2000000});  // 1.0e12
    __ vmovq(xmm6, rdx);
    __ vcvttsd2siq(rcx, xmm6);
    __ movq(rdx, uint64_t{1000000000000});
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);
    __ xorq(rcx, rcx);
    __ vmovsd(Operand(rsp, 0), xmm6);
    __ vcvttsd2siq(rcx, Operand(rsp, 0));
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vmovmskpd
    __ movl(rax, Immediate(12));
    __ movq(rdx, uint64_t{0x426D1A94A2000000});  // 1.0e12
    __ vmovq(xmm6, rdx);
    __ movq(rdx, uint64_t{0xC26D1A94A2000000});  // -1.0e12
    __ vmovq(xmm7, rdx);
    __ shufps(xmm6, xmm7, 0x44);
    __ vmovmskpd(rdx, xmm6);
    __ cmpl(rdx, Immediate(2));
    __ j(not_equal, &exit);

    // Test vpcmpeqd
    __ movq(rdx, uint64_t{0x0123456789ABCDEF});
    __ movq(rcx, uint64_t{0x0123456788888888});
    __ vmovq(xmm6, rdx);
    __ vmovq(xmm7, rcx);
    __ vpcmpeqd(xmm8, xmm6, xmm7);
    __ vmovq(rdx, xmm8);
    __ movq(rcx, uint64_t{0xFFFFFFFF00000000});
    __ cmpq(rcx, rdx);
    __ movl(rax, Immediate(13));
    __ j(not_equal, &exit);

    // Test vpsllq, vpsrlq
    __ movl(rax, Immediate(13));
    __ movq(rdx, uint64_t{0x0123456789ABCDEF});
    __ vmovq(xmm6, rdx);
    __ vpsrlq(xmm7, xmm6, 4);
    __ vmovq(rdx, xmm7);
    __ movq(rcx, uint64_t{0x00123456789ABCDE});
    __ cmpq(rdx, rcx);
    __ j(not_equal, &exit);
    __ vpsllq(xmm7, xmm6, 12);
    __ vmovq(rdx, xmm7);
    __ movq(rcx, uint64_t{0x3456789ABCDEF000});
    __ cmpq(rdx, rcx);
    __ j(not_equal, &exit);

    // Test vandpd, vorpd, vxorpd
    __ movl(rax, Immediate(14));
    __ movl(rdx, Immediate(0x00FF00FF));
    __ movl(rcx, Immediate(0x0F0F0F0F));
    __ vmovd(xmm4, rdx);
    __ vmovd(xmm5, rcx);
    __ vandpd(xmm6, xmm4, xmm5);
    __ vmovd(rdx, xmm6);
    __ cmpl(rdx, Immediate(0x000F000F));
    __ j(not_equal, &exit);
    __ vorpd(xmm6, xmm4, xmm5);
    __ vmovd(rdx, xmm6);
    __ cmpl(rdx, Immediate(0x0FFF0FFF));
    __ j(not_equal, &exit);
    __ vxorpd(xmm6, xmm4, xmm5);
    __ vmovd(rdx, xmm6);
    __ cmpl(rdx, Immediate(0x0FF00FF0));
    __ j(not_equal, &exit);

    // Test vsqrtsd
    __ movl(rax, Immediate(15));
    __ movq(rdx, uint64_t{0x4004000000000000});  // 2.5
    __ vmovq(xmm4, rdx);
    __ vmulsd(xmm5, xmm4, xmm4);
    __ vmovsd(Operand(rsp, 0), xmm5);
    __ vsqrtsd(xmm6, xmm5, xmm5);
    __ vmovq(rcx, xmm6);
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);
    __ vsqrtsd(xmm7, xmm7, Operand(rsp, 0));
    __ vmovq(rcx, xmm7);
    __ cmpq(rcx, rdx);
    __ j(not_equal, &exit);

    // Test vroundsd
    __ movl(rax, Immediate(16));
    __ movq(rdx, uint64_t{0x4002000000000000});  // 2.25
    __ vmovq(xmm4, rdx);
    __ vroundsd(xmm5, xmm4, xmm4, kRoundUp);
    __ movq(rcx, uint64_t{0x4008000000000000});  // 3.0
    __ vmovq(xmm6, rcx);
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);

    // Test vcvtlsi2sd
    __ movl(rax, Immediate(17));
    __ movl(rdx, Immediate(6));
    __ movq(rcx, uint64_t{0x4018000000000000});  // 6.0
    __ vmovq(xmm5, rcx);
    __ vcvtlsi2sd(xmm6, xmm6, rdx);
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);
    __ movl(Operand(rsp, 0), rdx);
    __ vcvtlsi2sd(xmm7, xmm7, Operand(rsp, 0));
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);

    // Test vcvtqsi2sd
    __ movl(rax, Immediate(18));
    __ movq(rdx, uint64_t{0x2000000000000000});  // 2 << 0x3C
    __ movq(rcx, uint64_t{0x43C0000000000000});
    __ vmovq(xmm5, rcx);
    __ vcvtqsi2sd(xmm6, xmm6, rdx);
    __ vucomisd(xmm5, xmm6);
    __ j(not_equal, &exit);

    // Test vcvtsd2si
    __ movl(rax, Immediate(19));
    __ movq(rdx, uint64_t{0x4018000000000000});  // 6.0
    __ vmovq(xmm5, rdx);
    __ vcvtsd2si(rcx, xmm5);
    __ cmpl(rcx, Immediate(6));
    __ j(not_equal, &exit);

    __ movq(rdx, uint64_t{0x3FF0000000000000});  // 1.0
    __ vmovq(xmm7, rdx);
    __ vmulsd(xmm1, xmm1, xmm7);
    __ movq(Operand(rsp, 0), rdx);
    __ vmovq(xmm6, Operand(rsp, 0));
    __ vmulsd(xmm1, xmm1, xmm6);

    __ vucomisd(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(1));

    __ vminsd(xmm3, xmm1, xmm2);
    __ vucomisd(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(2));

    __ vsubsd(xmm3, xmm2, xmm1);
    __ vucomisd(xmm3, xmm0);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(3));

    __ vaddsd(xmm3, xmm0, xmm1);
    __ vucomisd(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(4));

    __ vmulsd(xmm3, xmm0, xmm1);
    __ vucomisd(xmm3, xmm1);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(5));

    __ vdivsd(xmm3, xmm0, xmm1);
    __ vmulsd(xmm3, xmm3, xmm2);
    __ vmulsd(xmm3, xmm3, xmm1);
    __ vucomisd(xmm3, xmm2);
    __ j(parity_even, &exit);
    __ j(not_equal, &exit);
    __ movl(rax, Immediate(6));

    // result in eax
    __ bind(&exit);
    __ addq(rsp, Immediate(kDoubleSize * 2));
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F7>::FromCode(isolate, *code);
  int res = f.Call(1.0, 2.0, 3.0);
  PrintF("f(1,2,3) = %d\n", res);
  CHECK_EQ(6, res);
}

TEST_F(AssemblerX64Test, AssemblerX64BMI1) {
  if (!CpuFeatures::IsSupported(BMI1)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[1024];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, BMI1);
    Label exit;

    __ movq(rcx, uint64_t{0x1122334455667788});  // source operand
    __ pushq(rcx);                               // For memory operand

    // andn
    __ movq(rdx, uint64_t{0x1000000020000000});

    __ movl(rax, Immediate(1));  // Test number
    __ andnq(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0122334455667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ andnq(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0122334455667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ andnl(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0000000055667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ andnl(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000055667788});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // bextr
    __ movq(rdx, uint64_t{0x0000000000002808});

    __ incq(rax);
    __ bextrq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000003344556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bextrq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000003344556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bextrl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000000556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bextrl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000000556677});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // blsi
    __ incq(rax);
    __ blsiq(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsiq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsil(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsil(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000008});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // blsmsk
    __ incq(rax);
    __ blsmskq(r8, rcx);
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsmskq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsmskl(r8, rcx);
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsmskl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000000F});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // blsr
    __ incq(rax);
    __ blsrq(r8, rcx);
    __ movq(r9, uint64_t{0x1122334455667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsrq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x1122334455667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsrl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000055667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ blsrl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000055667780});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // tzcnt
    __ incq(rax);
    __ tzcntq(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ tzcntq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ tzcntl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ tzcntl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F0>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call());
}

TEST_F(AssemblerX64Test, AssemblerX64LZCNT) {
  if (!CpuFeatures::IsSupported(LZCNT)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, LZCNT);
    Label exit;

    __ movq(rcx, uint64_t{0x1122334455667788});  // source operand
    __ pushq(rcx);                               // For memory operand

    __ movl(rax, Immediate(1));  // Test number
    __ lzcntq(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ lzcntq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000003});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ lzcntl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000001});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ lzcntl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000001});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F0>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call());
}

TEST_F(AssemblerX64Test, AssemblerX64POPCNT) {
  if (!CpuFeatures::IsSupported(POPCNT)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[256];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, POPCNT);
    Label exit;

    __ movq(rcx, uint64_t{0x1111111111111100});  // source operand
    __ pushq(rcx);                               // For memory operand

    __ movl(rax, Immediate(1));  // Test number
    __ popcntq(r8, rcx);
    __ movq(r9, uint64_t{0x000000000000000E});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ popcntq(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000000E});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ popcntl(r8, rcx);
    __ movq(r9, uint64_t{0x0000000000000006});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ popcntl(r8, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000000000006});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ xorl(rax, rax);
    __ bind(&exit);
    __ popq(rcx);
    __ ret(0);
  }

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  DirectHandle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  StdoutStream os;
  Print(*code, os);
#endif

  auto f = GeneratedCode<F0>::FromCode(isolate, *code);
  CHECK_EQ(0, f.Call());
}

TEST_F(AssemblerX64Test, AssemblerX64BMI2) {
  if (!CpuFeatures::IsSupported(BMI2)) return;

  Isolate* isolate = i_isolate();
  HandleScope scope(isolate);
  uint8_t buffer[2048];
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      ExternalAssemblerBuffer(buffer, sizeof(buffer)));
  {
    CpuFeatureScope fscope(&masm, BMI2);
    Label exit;
    __ pushq(rbx);                               // save rbx
    __ movq(rcx, uint64_t{0x1122334455667788});  // source operand
    __ pushq(rcx);                               // For memory operand

    // bzhi
    __ movq(rdx, uint64_t{0x0000000000000009});

    __ movl(rax, Immediate(1));  // Test number
    __ bzhiq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bzhiq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bzhil(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ bzhil(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000000000188});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // mulx
    __ movq(rdx, uint64_t{0x0000000000001000});

    __ incq(rax);
    __ mulxq(r8, r9, rcx);
    __ movq(rbx, uint64_t{0x0000000000000112});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x2334455667788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ mulxq(r8, r9, Operand(rsp, 0));
    __ movq(rbx, uint64_t{0x0000000000000112});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x2334455667788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ mulxl(r8, r9, rcx);
    __ movq(rbx, uint64_t{0x0000000000000556});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x0000000067788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ mulxl(r8, r9, Operand(rsp, 0));
    __ movq(rbx, uint64_t{0x0000000000000556});  // expected result
    __ cmpq(r8, rbx);
    __ j(not_equal, &exit);
    __ movq(rbx, uint64_t{0x0000000067788000});  // expected result
    __ cmpq(r9, rbx);
    __ j(not_equal, &exit);

    // pdep
    __ movq(rdx, uint64_t{0xFFFFFFFFFFFFFFF0});

    __ incq(rax);
    __ pdepq(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x1122334455667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pdepq(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x1122334455667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pdepl(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0000000055667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pdepl(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000055667400});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // pext
    __ movq(rdx, uint64_t{0xFFFFFFFFFFFFFFF0});

    __ incq(rax);
    __ pextq(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x0000000003FFFFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pextq(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x0000000003FFFFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pextl(r8, rdx, rcx);
    __ movq(r9, uint64_t{0x000000000000FFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ pextl(r8, rdx, Operand(rsp, 0));
    __ movq(r9, uint64_t{0x000000000000FFFE});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // sarx
    __ movq(rdx, uint64_t{0x0000000000000004});

    __ incq(rax);
    __ sarxq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ sarxq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ sarxl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ sarxl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // shlx
    __ movq(rdx, uint64_t{0x0000000000000004});

    __ incq(rax);
    __ shlxq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x1223344556677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shlxq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x1223344556677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shlxl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000056677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shlxl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000056677880});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // shrx
    __ movq(rdx, uint64_t{0x0000000000000004});

    __ incq(rax);
    __ shrxq(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shrxq(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0112233445566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shrxl(r8, rcx, rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    __ incq(rax);
    __ shrxl(r8, Operand(rsp, 0), rdx);
    __ movq(r9, uint64_t{0x0000000005566778});  // expected result
    __ cmpq(r8, r9);
    __ j(not_equal, &exit);

    // rorx
    __ incq(rax);
"""


```