Response:
The user wants me to analyze a C++ source code file for V8's x64 assembler unit tests. I need to identify its functionalities, consider if it were a Torque file, explore its relation to JavaScript, provide examples with assumptions, point out potential programming errors, and finally summarize its purpose.

Here's a breakdown of the requested analysis:

1. **Functionality Listing:**  Examine the code to understand what specific assembler instructions and scenarios are being tested.
2. **Torque Consideration:** Check the file extension and clarify that `.cc` signifies C++ and not Torque (`.tq`).
3. **JavaScript Relevance:**  Determine if the tested assembler functionalities are directly related to how JavaScript features are implemented. If so, provide a JavaScript example.
4. **Code Logic Inference:** Select a test case, define hypothetical inputs, and predict the corresponding output based on the assembler code.
5. **Common Programming Errors:** Identify potential pitfalls that developers might encounter when working with assemblers or low-level code, relating them to the test cases.
6. **Summary:**  Provide a concise overview of the file's purpose.
这是V8 JavaScript引擎中用于测试x64架构汇编器功能的C++单元测试文件。它主要用于验证`Assembler`类在生成x64机器码时的正确性。

以下是该文件的功能点归纳：

1. **汇编指令测试:**  该文件包含了大量的测试用例，用于测试各种x64汇编指令的功能，例如：
    * **数据传输指令:** `movq`, `pushq`, `popq`
    * **算术运算指令:** `addq`, `imulq`, `subl`, `orl`, `xorl`
    * **比较指令:** `cmpb`, `testb`, `testw`, `testl`
    * **控制流指令:** `jmp`, `j(condition)`, `ret`
    * **位操作指令:** `roll`
    * **交换指令:** `xchgl`
    * **SSE/SSE2/SSE3/SSE4.1/FMA3 指令:**  例如 `movdqa`, `xorps`, `movmskps`, `shufps`, `haddps`, `extractps`, `mulsd`, `addsd`, `vfmadd132sd` 等（取决于启用的CPU特性）。
    * **多字节 `nop` 指令:** 用于填充代码，确保特定位置的代码对齐。

2. **函数调用约定测试:**  测试用例中定义了不同的函数签名 (`F0`, `F1`, `F2` 等)，并根据AMD64调用约定（Linux/macOS 和 Windows 略有不同）传递参数和获取返回值，以此来验证汇编器是否正确处理函数调用。

3. **内存操作测试:**  测试用例演示了如何使用 `Operand` 类来访问内存中的数据，包括基于寄存器和偏移量的寻址方式。

4. **控制流测试:**  通过使用 `Label` 和条件跳转指令，测试汇编器生成正确控制流的能力。

5. **立即数操作测试:**  测试用例包含了使用立即数的各种算术和比较操作。

6. **寄存器依赖性测试:**  `OperandRegisterDependency` 测试用例明确验证了 `Operand` 类是否能正确识别操作数中使用的寄存器。

7. **标签链接测试:**  `AssemblerX64LabelChaining` 测试用例用于验证在指令内部正确链接标签的功能。

8. **SSE/AVX 指令测试 (如果 CPU 支持):**  代码中包含针对SSE、SSE2、SSE3、SSE4.1 和 FMA3 指令的测试用例，用于验证浮点运算和SIMD指令的正确性。

**关于文件扩展名和 Torque：**

`v8/test/unittests/assembler/assembler-x64-unittest.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。 Torque 文件的扩展名通常是 `.tq`。

**与 JavaScript 功能的关系：**

`assembler-x64-unittest.cc` 中测试的汇编指令是 V8 引擎将 JavaScript 代码编译成机器码的基础。 几乎所有的 JavaScript 功能，最终都会通过底层的机器码指令来实现。

**JavaScript 示例：**

例如，测试用例 `AssemblerX64ArithmeticOperations` 测试了 `addq` 指令。 这与 JavaScript 中的加法运算直接相关。

```javascript
function add(a, b) {
  return a + b;
}

console.log(add(3, 2)); // 输出 5
```

当 V8 编译 `add` 函数时，它可能会生成类似于测试用例中 `AssemblerX64ArithmeticOperations` 的汇编代码，使用 `addq` 指令将 `a` 和 `b` 相加。

**代码逻辑推理：**

考虑 `AssemblerX64ReturnOperation` 测试用例：

**假设输入:** 调用该汇编代码生成的函数，第一个参数为 3，第二个参数为 2。

**汇编代码逻辑:**
```assembly
  __ movq(rax, arg2); // 将第二个参数 (arg2) 的值移动到 rax 寄存器
  __ nop();          // 空操作，不执行任何动作
  __ ret(0);          // 从函数返回，rax 寄存器中的值作为返回值
```

**预期输出:**  函数将返回第二个参数的值，即 `2`。  `CHECK_EQ(2, result);` 这行代码验证了这一点。

**用户常见的编程错误：**

1. **栈溢出/栈下溢:**  在 `AssemblerX64StackOperations` 测试用例中使用了 `pushq` 和 `popq`。 用户在手动编写汇编代码时，容易忘记 `push` 和 `pop` 的配对，导致栈指针不平衡，最终可能导致程序崩溃。

   **错误示例 (C++ 风格的伪汇编):**
   ```c++
   void my_function() {
       // 错误：push 比 pop 多
       __ pushq(rax);
       __ pushq(rbx);
       __ ret(0);
   }
   ```
   这种错误会导致函数返回时栈指针指向错误的位置。

2. **寄存器使用错误:**  在汇编编程中，错误地使用或覆盖寄存器是常见的错误。 例如，忘记保存调用者保存的寄存器 (caller-saved registers) 的值，可能会导致调用者程序状态损坏。

   **错误示例 (C++ 风格的伪汇编):**
   ```c++
   int my_function(int arg) {
       // 错误：没有保存 rbx，但可能被调用者使用
       __ movq(rbx, Immediate(10));
       __ movq(rax, arg);
       __ addq(rax, rbx);
       __ ret(0);
   }
   ```
   如果调用 `my_function` 的代码也使用了 `rbx` 寄存器，那么 `my_function` 的操作可能会意外地修改 `rbx` 的值，导致调用者出现错误。

3. **条件跳转错误:**  错误地使用条件跳转指令，例如条件判断错误或者跳转目标错误，会导致程序执行流程错误。

   **错误示例 (C++ 风格的伪汇编):**
   ```c++
   int my_function(int arg) {
       Label positive;
       __ cmpq(arg, Immediate(0));
       // 错误：应该跳转到 positive，但写成了 negative
       __ j(less, &positive);
       __ movq(rax, Immediate(-1)); // 如果为负数
       __ ret(0);
       __ bind(&positive);
       __ movq(rax, Immediate(1));  // 如果为正数或零
       __ ret(0);
   }
   ```
   在这个例子中，负数应该跳转到标记为 `positive` 的代码块，但代码错误地实现了。

**功能归纳（第1部分）：**

这部分代码主要定义了一些基础的x64汇编指令的单元测试。 它涵盖了基本的数据操作、算术运算、比较、控制流以及部分栈操作的测试。 这些测试用例旨在验证 V8 的 x64 汇编器能够正确地生成这些基本指令的机器码，为更复杂的 JavaScript 功能实现奠定基础。

Prompt: 
```
这是目录为v8/test/unittests/assembler/assembler-x64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/assembler-x64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

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
    __ movaps(xm
"""


```